"""Scanner agent API.

Agents are lightweight processes that run ON a machine with Layer-2 access to
the target LAN (the only place ARP/macvlan + SYN + exact -O OS detection work).
They poll for queued scan jobs, execute nmap locally, stream console lines into
the same live feed as in-worker scans, and POST structured results back here.

This is the migration path away from the SSH host-nmap bridge: no remote shell
required, agents register once with an API key and can run anywhere (Linux,
Windows/macOS with Npcap, or a Docker container with --network=host).
"""
import hashlib
import secrets
import threading
from datetime import datetime, timezone
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select, delete, cast
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import Agent, AgentTask, Scan, Host, Port, SNMPInfo, AuditLog, User
from ..schemas import (
    AgentCreate, AgentOut, AgentKeyOut, AgentHeartbeatIn, AgentTaskOut,
    AgentLogIn, AgentResultIn,
)
from ..auth import get_current_user
from ..websocket import manager

router = APIRouter(prefix="/api/agents", tags=["agents"])

ONLINE_WINDOW_SECONDS = 90


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


async def get_agent(
    x_api_key: Optional[str] = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    result = await db.execute(select(Agent).where(Agent.api_key_hash == _hash_key(x_api_key)))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if agent.status == "disabled":
        raise HTTPException(status_code=403, detail="Agent disabled")
    return agent


def _live_status(agent: Agent) -> str:
    if agent.status == "disabled":
        return "disabled"
    if agent.last_seen and (datetime.now(timezone.utc) - agent.last_seen).total_seconds() <= ONLINE_WINDOW_SECONDS:
        return "online"
    return "offline"


@router.post("", response_model=AgentKeyOut, status_code=201)
async def create_agent(
    data: AgentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing = (await db.execute(select(Agent).where(Agent.name == data.name))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="An agent with that name already exists")
    key = secrets.token_urlsafe(32)
    agent = Agent(
        name=data.name,
        api_key_hash=_hash_key(key),
        subnets=data.subnets or [],
        notes=data.notes,
        created_by=current_user.id,
        status="offline",
    )
    db.add(agent)
    db.add(AuditLog(
        user_id=current_user.id,
        action="agent_created",
        detail={"name": data.name, "subnets": data.subnets},
    ))
    await db.commit()
    await db.refresh(agent)
    return AgentKeyOut(id=agent.id, name=agent.name, api_key=key)


@router.get("", response_model=list[AgentOut])
async def list_agents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    agents = (await db.execute(select(Agent).order_by(Agent.created_at))).scalars().all()
    out = []
    for a in agents:
        out.append(AgentOut(
            id=a.id,
            name=a.name,
            status=_live_status(a),
            last_seen=a.last_seen,
            version=a.version,
            hostname=a.hostname,
            os=a.os,
            subnets=a.subnets or [],
            capabilities=a.capabilities or [],
            notes=a.notes,
            created_at=a.created_at,
        ))
    return out


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "pentester"):
        raise HTTPException(status_code=403, detail="Only admins/pentesters can delete agents")
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    await db.execute(delete(AgentTask).where(AgentTask.agent_id == agent_id))
    await db.delete(agent)
    db.add(AuditLog(user_id=current_user.id, action="agent_deleted", detail={"name": agent.name}))
    await db.commit()
    return None


@router.post("/heartbeat")
async def heartbeat(
    data: AgentHeartbeatIn,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
):
    agent.last_seen = datetime.now(timezone.utc)
    agent.status = "online"
    if data.version:
        agent.version = data.version
    if data.hostname:
        agent.hostname = data.hostname
    if data.os:
        agent.os = data.os
    if data.subnets:
        agent.subnets = data.subnets
    if data.capabilities:
        agent.capabilities = data.capabilities
    await db.commit()
    return {"ok": True, "server_time": datetime.now(timezone.utc).isoformat(), "agent_id": str(agent.id)}


@router.get("/tasks/next", response_model=Optional[AgentTaskOut])
async def claim_next_task(
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
):
    task = (await db.execute(
        select(AgentTask)
        .where(AgentTask.agent_id == agent.id, AgentTask.status == "queued")
        .order_by(AgentTask.created_at)
    )).scalars().first()
    if not task:
        return None
    scan = (await db.execute(select(Scan).where(Scan.id == task.scan_id))).scalar_one_or_none()
    if not scan:
        return None
    task.status = "claimed"
    task.claimed_at = datetime.now(timezone.utc)
    scan.status = "agent_running"
    await db.commit()
    await manager.broadcast(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "info",
        "line": f"--- Agent '{agent.name}' claimed this scan (L2-capable execution) ---",
    })

    # Re-verify context: the agent needs the previously-down host IPs and the
    # already-scanned port range so it only re-checks down hosts and sweeps the
    # unscanned (leftover) ports, merging into the same scan with no duplication.
    reverify_ctx = None
    if scan.kind == "reverify":
        down_rows = (await db.execute(select(Host).where(
            Host.scan_id == scan.id, Host.status != "up"
        ))).scalars().all()
        up_rows = (await db.execute(select(Host).where(
            Host.scan_id == scan.id, Host.status == "up"
        ))).scalars().all()
        reverify_ctx = {
            "down_ips": [str(h.ip) for h in down_rows],
            "up_ips": [str(h.ip) for h in up_rows],
            "already_ports": scan.port_range,
            "protocol": scan.protocol,
        }

    return AgentTaskOut(
        id=task.id,
        scan_id=task.scan_id,
        status="claimed",
        targets=task.targets or scan.targets,
        profile=scan.profile,
        port_range=scan.port_range,
        protocol=scan.protocol,
        kind=scan.kind,
        reverify=reverify_ctx,
    )


@router.get("/tasks/{task_id}/state")
async def task_state(
    task_id: uuid.UUID,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
):
    task = (await db.execute(
        select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
    )).scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    paused = False
    try:
        from ..websocket import _redis_client
        rc = _redis_client()
        paused = bool(rc.exists(f"scan:paused:{task.scan_id}"))
        rc.close()
    except Exception:
        pass
    scan = (await db.execute(select(Scan).where(Scan.id == task.scan_id))).scalar_one_or_none()
    stopped = bool(scan and scan.status == "stopped")
    return {"paused": paused, "stopped": stopped}


@router.post("/tasks/{task_id}/log")
async def agent_log(
    task_id: uuid.UUID,
    data: AgentLogIn,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
):
    task = (await db.execute(
        select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
    )).scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    line = data.line
    if data.level == "cmd":
        line = f"[{agent.name}] $ {line}"
    from ..services.scan_worker import append_console_log
    append_console_log(task.scan_id, line, data.level)
    await manager.broadcast(str(task.scan_id), {
        "type": "cmd_log", "scan_id": str(task.scan_id), "level": data.level, "line": line[:500],
    })
    return {"ok": True}


def _run_post_analysis(scan_id: str, completed: bool, error: str = ""):
    """Finalise a scan after the agent posts its results: re-classify hosts,
    run risk rules + topology capture, then mark the scan complete/failed.
    Runs in a background thread because these helpers use the sync session."""
    import traceback
    from ..services.db import SessionLocal
    from ..services.scanners import snmp_walk as _snmp_walk
    from ..services.scan_worker import run_risk_rules, capture_topology, classify_device_type
    try:
        with SessionLocal() as sdb:
            scan = sdb.get(Scan, uuid.UUID(scan_id))
            if not scan:
                return
            if completed:
                for host in scan.hosts:
                    if host.status == "up":
                        ip = str(host.ip)
                        # SNMP enrichment matching the in-worker fingerprint path:
                        # probe UDP 161 (and best-effort on unknown/network gear)
                        # so agent scans also get sysDescr/sysName/vendor/OS hints.
                        probed = sdb.execute(select(Port).where(
                            Port.host_id == host.id,
                            Port.port == 161,
                            Port.protocol == "udp",
                        )).scalar_one_or_none()
                        if probed or host.device_type in ("unknown", "network_gear", "router"):
                            snmp_info = _snmp_walk(ip, "public")
                            if snmp_info:
                                existing = sdb.execute(
                                    select(SNMPInfo).where(SNMPInfo.host_id == host.id)
                                ).scalar_one_or_none()
                                if not existing:
                                    sdb.add(SNMPInfo(
                                        host_id=host.id,
                                        sys_descr=snmp_info.get("sys_descr"),
                                        sys_name=snmp_info.get("sys_name"),
                                        sys_location=snmp_info.get("sys_location"),
                                        sys_objectid=snmp_info.get("sys_objectid"),
                                        sys_uptime=snmp_info.get("uptime"),
                                        default_community_found=True,
                                    ))
                                if snmp_info.get("sys_name") and not host.hostname:
                                    host.hostname = snmp_info["sys_name"]
                                if snmp_info.get("vendor") and not host.vendor:
                                    host.vendor = snmp_info["vendor"]
                                if snmp_info.get("sys_descr") and (
                                    not host.os_guess
                                    or host.os_guess.startswith("Most probably")
                                    or (host.os_confidence or 100) < 60
                                ):
                                    host.os_guess = snmp_info["sys_descr"][:200]
                                    host.os_confidence = 60 if host.os_guess else host.os_confidence
                    classify_device_type(host)
                sdb.commit()
                run_risk_rules(sdb, scan)
                capture_topology(sdb, scan)
                sdb.add(AuditLog(
                    engagement_id=scan.engagement_id,
                    scan_id=scan.id,
                    action="scan_completed",
                    detail={"hosts": scan.hosts_discovered, "via": "agent"},
                ))
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_pct = 100
                sdb.commit()
            else:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_pct = 100
                sdb.commit()
        manager.broadcast_sync(scan_id, {
            "type": "scan_completed" if completed else "scan_failed",
            "scan_id": scan_id, "error": error or None,
        })
        manager.broadcast_sync(scan_id, {
            "type": "cmd_log", "scan_id": scan_id, "level": "info",
            "line": "=== Scan completed via agent ===" if completed else f"=== Scan FAILED via agent: {error} ===",
        })
    except Exception:
        traceback.print_exc()


@router.post("/tasks/{task_id}/result")
async def agent_result(
    task_id: uuid.UUID,
    data: AgentResultIn,
    agent: Agent = Depends(get_agent),
    db: AsyncSession = Depends(get_db),
):
    task = (await db.execute(
        select(AgentTask).where(AgentTask.id == task_id, AgentTask.agent_id == agent.id)
    )).scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    scan = (await db.execute(select(Scan).where(Scan.id == task.scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if data.status == "failed":
        task.status = "failed"
        task.error = data.error
        task.completed_at = datetime.now(timezone.utc)
        await db.commit()
        _run_post_analysis(str(scan.id), completed=False, error=data.error or "")
        return {"ok": True}

    existing = {str(h.ip): h for h in (await db.execute(
        select(Host).where(Host.scan_id == scan.id)
    )).scalars().all()}

    partial = data.status == "partial"
    up_count = 0
    open_ports_total = 0
    for hd in data.hosts:
        host = existing.get(hd.ip)
        if not host:
            host = Host(scan_id=scan.id, ip=hd.ip, status=hd.status or "up",
                        discovery_method=["agent"])
            db.add(host)
            await db.flush()
            existing[hd.ip] = host
        if "agent" not in (host.discovery_method or []):
            host.discovery_method = list(host.discovery_method or []) + ["agent"]
        host.status = hd.status or "up"
        if hd.mac:
            host.mac = hd.mac
        if hd.vendor:
            host.vendor = hd.vendor
        if hd.hostname:
            host.hostname = hd.hostname
        if hd.device_type:
            host.device_type = hd.device_type
        if hd.os_guess:
            host.os_guess = hd.os_guess
        if hd.os_confidence is not None:
            host.os_confidence = hd.os_confidence

        # Merge ports additively for every scan kind. A confirmed open port is
        # scan-truth and must survive even if a later verification re-probe
        # races the device to sleep and reports it closed. Updates refine
        # service/version/banner but never delete a port already recorded.
        cur_ports = {p.port: p for p in (await db.execute(
            select(Port).where(Port.host_id == host.id)
        )).scalars().all()}
        for p in hd.ports:
            row = cur_ports.get(p.port)
            if row is None:
                row = Port(host_id=host.id, port=p.port, protocol=p.protocol,
                           state=p.state, service=p.service, version=p.version,
                           banner=p.banner)
                db.add(row)
                cur_ports[p.port] = row
            else:
                if p.service:
                    row.service = p.service
                if p.version:
                    row.version = p.version
                if p.banner:
                    row.banner = p.banner
                if p.state == "open" or row.state != "closed":
                    row.state = "open"
            open_ports_total += 1

        if hd.snmp and (hd.snmp.sys_descr or hd.snmp.sys_name or hd.snmp.sys_objectid):
            snmp = (await db.execute(select(SNMPInfo).where(SNMPInfo.host_id == host.id))).scalar_one_or_none()
            if not snmp:
                snmp = SNMPInfo(host_id=host.id)
                db.add(snmp)
                await db.flush()
            snmp.sys_descr = hd.snmp.sys_descr
            snmp.sys_name = hd.snmp.sys_name
            snmp.sys_location = hd.snmp.sys_location
            snmp.sys_objectid = hd.snmp.sys_objectid
            snmp.default_community_found = hd.snmp.default_community_found

        if host.status == "up":
            up_count += 1

        if not partial or hd.ports or hd.os_guess:
            # Stream each live host to the Activity feed as it gains findings
            # (ports streamed in from Phase-2, fingerprints from Phase-3 arrive
            # live during the scan, not only at finalisation).
            await manager.broadcast(str(scan.id), {
                "type": "host_updated",
                "scan_id": str(scan.id),
                "host_id": str(host.id),
                "ip": hd.ip,
                "ports": [p.port for p in hd.ports],
                "mac": hd.mac,
                "vendor": hd.vendor,
                "device_type": hd.device_type or host.device_type,
                "os_guess": hd.os_guess or host.os_guess,
            })

    # Always keep the authoritative up-host count from the DB. The agent streams
    # per-host/host-batch partial posts, and the final "completed" post carries an
    # (often empty) host list, so using this batch's up_count here would reset the
    # running total (e.g. to 0 on an empty finalising post).
    scan.hosts_discovered = len((await db.execute(select(Host).where(
        Host.scan_id == scan.id, Host.status == "up"
    ))).scalars().all())
    if partial:
        # Incremental update: keep the scan running on the agent; save what the
        # agent has finished so far and surface it live without finalising.
        # Progress comes from the agent's own exact phase-based value (monotonic,
        # max-guarded so it never regresses e.g. 30% -> 20%).
        if data.progress is not None:
            scan.progress_pct = max(scan.progress_pct, min(89, int(data.progress)))
        else:
            scan.progress_pct = max(scan.progress_pct,
                                    min(89, int(20 + 60 * up_count / max(scan.hosts_total_in_scope, 1))))
        task.status = "in_progress"
        await db.commit()
        try:
            await manager.broadcast(str(scan.id), {
                "type": "cmd_log", "scan_id": str(scan.id), "level": "info",
                "line": f"Agent progress: {scan.hosts_discovered} host(s) discovered, {scan.progress_pct}%",
            })
        except Exception:
            pass
        return {"ok": True, "partial": True}

    scan.status = "analyzing"
    scan.progress_pct = 90
    if scan.kind == "reverify":
        scan.verified_at = datetime.now(timezone.utc)
    task.status = "succeeded"
    task.completed_at = datetime.now(timezone.utc)
    await db.commit()

    await manager.broadcast(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "info",
        "line": f"Agent result received: {len(data.hosts)} hosts, {open_ports_total} open ports",
    })
    threading.Thread(target=_run_post_analysis, args=(str(scan.id), True), daemon=True).start()
    return {"ok": True}