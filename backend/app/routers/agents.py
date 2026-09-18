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
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import PlainTextResponse
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
from ..websocket import manager, _redis_client
from ..services import settings as settings_svc

router = APIRouter(prefix="/api/agents", tags=["agents"])

ONLINE_WINDOW_SECONDS = 90  # default; overridden per-request by the settings cache


# The scanner_agent.py source served to agents for remote self-update. The
# backend image mounts ./agent read-only at /app/agent (docker-compose).
_AGENT_SCRIPT = Path(os.environ.get("AGENT_SCRIPT_PATH", "/app/agent/scanner_agent.py"))
_agent_version_cache = {"version": None}


def _agent_script_source() -> Optional[str]:
    try:
        return _AGENT_SCRIPT.read_text(encoding="utf-8")
    except Exception:
        return None


def _agent_script_current_version() -> str:
    if _agent_version_cache["version"] is None:
        src = _agent_script_source()
        m = re.search(r'^VERSION\s*=\s*"([^"]+)"', src or "", re.M)
        _agent_version_cache["version"] = m.group(1) if m else "unknown"
    return _agent_version_cache["version"]


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


from ..services.identity import identity_hostname  # noqa: E402  (single source of truth)


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
    window = settings_svc.get_int("agent.online_window_seconds", ONLINE_WINDOW_SECONDS)
    if agent.last_seen and (datetime.now(timezone.utc) - agent.last_seen).total_seconds() <= window:
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
            current_version=_agent_script_current_version(),
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


@router.get("/{agent_id}/health")
async def agent_health(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Live health snapshot for the Agents page (repair mode).

    Reads the last heartbeat the server received; `live` is computed the same
    way as the list view so the UI can show exactly why an agent looks broken
    (offline vs stale vs disabled) before offering one-click repair.
    """
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    now = datetime.now(timezone.utc)
    age = None if not agent.last_seen else (now - agent.last_seen).total_seconds()
    return {
        "id": str(agent.id),
        "name": agent.name,
        "live": _live_status(agent),
        "status": agent.status,
        "last_seen": agent.last_seen.isoformat() if agent.last_seen else None,
        "age_seconds": round(age, 1) if age is not None else None,
        "version": agent.version,
        "hostname": agent.hostname,
        "os": agent.os,
        "subnets": agent.subnets or [],
        "capabilities": agent.capabilities or [],
        "notes": agent.notes,
        "current_version": _agent_script_current_version(),
        "server_time": now.isoformat(),
    }


@router.post("/{agent_id}/reset-key", response_model=AgentKeyOut)
async def reset_agent_key(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Rotate an agent's API key: the old key stops working immediately and a
    fresh one is returned (shown once). Use this to 'repair' an agent whose key
    leaked, or to kick an existing install off the server."""
    if current_user.role not in ("admin", "pentester"):
        raise HTTPException(status_code=403, detail="Only admins/pentesters can reset agent keys")
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    new_key = secrets.token_urlsafe(32)
    # Since the hash below is swapped immediately, the OLD key stops working
    # right away. The pending rotation is published to Redis so the agent can
    # exchange its old key for the new one on its next poll (grace window).
    old_hash = agent.api_key_hash
    agent.api_key_hash = _hash_key(new_key)
    rc = _redis_client()
    try:
        rc.set(f"agent:key_new:{agent.id}", new_key, ex=300)
        rc.set(f"agent:key_old:{agent.id}", old_hash, ex=300)
    finally:
        rc.close()
    db.add(AuditLog(
        user_id=current_user.id,
        action="agent_key_rotated",
        detail={"name": agent.name, "id": str(agent.id)},
    ))
    await db.commit()
    return AgentKeyOut(id=agent.id, name=agent.name, api_key=new_key)


def _claim_pending_rotation(agent_id: uuid.UUID, presented_key: Optional[str]) -> Optional[str]:
    """Give the agent the new key if it still presents the pre-rotation key.

    Used by the key-sync endpoint: the old key is invalid against the DB the
    moment rotation happens, but the pending rotation record (old-hash + new
    plaintext, both TTL'd) lets exactly that old key redeem the new one once.
    Returns the new key, or None when there is nothing redeemable.
    """
    rc = _redis_client()
    try:
        stored_old = rc.get(f"agent:key_old:{agent_id}")
        if not stored_old or not presented_key:
            return None
        if not hmac.compare_digest(stored_old, _hash_key(presented_key)):
            return None
        new_key = rc.get(f"agent:key_new:{agent_id}")
        if not new_key:
            return None
        rc.delete(f"agent:key_old:{agent_id}", f"agent:key_new:{agent_id}")
        return new_key
    finally:
        rc.close()


@router.post("/key/sync")
async def agent_key_sync(
    agent_id: uuid.UUID,
    x_api_key: str = Header(default=None),
):
    """Agent-side counterpart of key rotation: redeem the new API key with the
    old one during the 5-minute grace window after reset-key is clicked (the old
    key is otherwise already revoked). The agent persists the returned key and
    uses it for all subsequent polls."""
    new_key = _claim_pending_rotation(agent_id, x_api_key)
    if new_key is None:
        raise HTTPException(status_code=401, detail="No pending key rotation for this agent/key")
    return {"api_key": new_key}


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
    # A pending restart request (issued from the Agents page) is claimed here so
    # the agent can self-restart on its next poll.
    restart_requested = False
    update_requested = False
    rc = _redis_client()
    try:
        if rc.exists(f"agent:restart:{agent.id}"):
            rc.delete(f"agent:restart:{agent.id}")
            restart_requested = True
        if rc.exists(f"agent:update:{agent.id}"):
            rc.delete(f"agent:update:{agent.id}")
            update_requested = True
    finally:
        rc.close()
    return {
        "ok": True,
        "server_time": datetime.now(timezone.utc).isoformat(),
        "agent_id": str(agent.id),
        "restart_requested": restart_requested,
        "update_requested": update_requested,
    }


@router.post("/{agent_id}/restart")
async def request_agent_restart(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ask an agent to restart itself.

    Agents only ever dial out to the server, so the server can't push a
    restart. Instead a short-lived flag is stored in Redis and the agent picks
    it up on its next heartbeat, then exits (its supervisor relaunches it).
    Useful after deploying agent code updates or clearing a wedged process.
    """
    if current_user.role not in ("admin", "pentester"):
        raise HTTPException(status_code=403, detail="Only admins/pentesters can restart agents")
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    rc = _redis_client()
    try:
        rc.set(f"agent:restart:{agent.id}", "1", ex=300)
    finally:
        rc.close()
    db.add(AuditLog(
        user_id=current_user.id,
        action="agent_restart_requested",
        detail={"name": agent.name, "id": str(agent.id)},
    ))
    await db.commit()
    return {"ok": True, "requested": True, "name": agent.name}


@router.post("/{agent_id}/update")
async def request_agent_update(
    agent_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ask an agent to pull the latest scanner_agent.py and self-update.

    Same heart-beat flag pattern as restart: the agent sees the request, fetches
    /api/agents/script, replaces its own file atomically, then re-execs so the
    new code takes over under the same supervisor.
    """
    if current_user.role not in ("admin", "pentester"):
        raise HTTPException(status_code=403, detail="Only admins/pentesters can update agents")
    agent = (await db.execute(select(Agent).where(Agent.id == agent_id))).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    rc = _redis_client()
    try:
        rc.set(f"agent:update:{agent.id}", "1", ex=300)
    finally:
        rc.close()
    db.add(AuditLog(
        user_id=current_user.id,
        action="agent_update_requested",
        detail={"name": agent.name, "id": str(agent.id)},
    ))
    await db.commit()
    return {
        "ok": True, "requested": True, "name": agent.name,
        "current_version": _agent_script_current_version(),
    }


@router.get("/script")
async def agent_script(agent: Agent = Depends(get_agent)):
    """Serve the current scanner_agent.py so an agent can update itself in
    place. Only reachable with a live agent key."""
    src = _agent_script_source()
    if src is None:
        raise HTTPException(status_code=404, detail="Agent script not available on server")
    return PlainTextResponse(src, media_type="text/x-python")


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
        # Non-scan re-verify options (check_new_hosts etc.) are cached in redis
        # by the reverify endpoint; fold them into the context the agent sees.
        check_new_hosts = False
        try:
            rc = _redis_client()
            raw = rc.get(f"scan:reverify:cfg:{scan.id}")
            rc.delete(f"scan:reverify:cfg:{scan.id}")
            rc.close()
            if raw:
                rcfg = json.loads(raw)
                check_new_hosts = bool(rcfg.get("check_new_hosts", False))
        except Exception:
            pass
        reverify_ctx["check_new_hosts"] = check_new_hosts

    return AgentTaskOut(
        id=task.id,
        scan_id=task.scan_id,
        status="claimed",
        targets=task.targets or scan.targets,
        profile=scan.profile,
        port_range=scan.port_range,
        protocol=scan.protocol,
        kind=scan.kind,
        mode=scan.mode,
        reverify=reverify_ctx,
        workers=settings_svc.get_int("agent.workers", 5),
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
        # Agent lines already include a leading "$ " for command lines; strip it
        # before adding the agent prefix. The frontend adds a single "$ " prompt
        # itself, so keeping the second one would yield "$ $ nmap".
        if line.startswith("$ "):
            line = line[2:]
        line = f"[{agent.name}] {line}"
    from ..services.scan_worker import append_console_log
    append_console_log(task.scan_id, line, data.level)
    await manager.broadcast(str(task.scan_id), {
        "type": "cmd_log", "scan_id": str(task.scan_id), "level": data.level, "line": line[:500],
    })
    return {"ok": True}


def _deliver_agent_hosts(scan_id: str, host_ids: list):
    """Post-commit host_discovered webhook delivery (background thread, sync session)."""
    import logging
    logger = logging.getLogger(__name__)
    try:
        from ..services.db import SessionLocal
        from ..services.webhook import deliver_host_discovered
        from ..models import Host as SyncHost, Scan as SyncScan, Engagement as SyncEng
        with SessionLocal() as s:
            scan = s.get(SyncScan, uuid.UUID(scan_id))
            engagement = s.get(SyncEng, scan.engagement_id) if scan else None
            for hid in host_ids:
                try:
                    host = s.get(SyncHost, uuid.UUID(hid))
                    if host:
                        deliver_host_discovered(s, host, scan=scan, engagement=engagement)
                except Exception:
                    continue  # delivery is best-effort per host
    except Exception:
        logger.exception("host_discovered webhook delivery failed")


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
                from concurrent.futures import ThreadPoolExecutor as _SMPool
                # Discovery-only scans are a full ARP/L3/TCP discovery pass
                # (agent runs nmap port scan + banner grab + OS) but skip only
                # the findings pipeline (container NSE pass + risk rules).
                discovery_only = scan.mode == "discovery"
                for host in scan.hosts:
                    classify_device_type(host)
                # Identify the hosts to probe, then run the SNMP walks
                # concurrently (each walk can block ~1-2s on a silent target) so
                # finalisation isn't a long serial tail. Results are applied on
                # the main thread so the session objects are only touched there.
                probes = []
                for host in scan.hosts:
                    if host.status != "up":
                        continue
                    ip = str(host.ip)
                    # SNMP enrichment matching the in-worker fingerprint path:
                    # probe UDP 161 (and best-effort on unknown/network gear)
                    # so agent scans also get sysDescr/sysName/vendor/OS hints.
                    probed = sdb.execute(select(Port).where(
                        Port.host_id == host.id,
                        Port.port == 161,
                        Port.protocol == "udp",
                    )).scalar_one_or_none()
                    if probed or host.device_type in ("unknown", "network_gear", "router", "firewall", "wireless_access_point", "switch"):
                        probes.append((str(host.id), ip))
                host_by_id = {str(h.id): h for h in scan.hosts}
                snmp_community = settings_svc.get("nmap.snmp_community", "public")
                snmp_timeout = settings_svc.get_float("nmap.snmp_timeout", 3.0)

                def _snmp_probe(item):
                    hid, ip = item
                    try:
                        return hid, _snmp_walk(ip, snmp_community, snmp_timeout)
                    except Exception:
                        return hid, None

                if probes:
                    with _SMPool(max_workers=min(8, len(probes))) as pool:
                        for hid, snmp_info in pool.map(_snmp_probe, probes):
                            host = host_by_id.get(hid)
                            if not host or not snmp_info:
                                continue
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
                # Container nmap fingerprint + NSE pass on the agent-confirmed
                # open ports so agent scans also get structured NSE findings
                # (weak TLS, SMB signing, anonymous FTP, web surface, OS refresh)
                # stored under scan_output/<scan>/fingerprint_<ip>.xml. Skipped
                # for passive_only profiles, discovery-only scans (no findings
                # wanted there) AND for re-verify passes: the agent already
                # deep-scanned the same ports (and any reverify-hidden ones)
                # with its own NSE script set, so re-running the full container
                # fingerprint here would duplicate that work and stall
                # finalisation for minutes.
                if (not discovery_only
                        and getattr(scan, "profile", "full") != "passive_only"
                        and scan.kind != "reverify"):
                    up_hosts = [h for h in scan.hosts if h.status == "up"]
                    if up_hosts:
                        from ..services.scan_worker import fingerprint_open_ports
                        # probe=False: the agent already ran full -sV/-O service
                        # fingerprinting, so this is a packed NSE-evidence pass
                        # over known-open ports -- avoid duplicating the probe
                        # work and stalling finalisation for minutes.
                        fingerprint_open_ports(sdb, scan, up_hosts, probe=False)
                sdb.commit()
                if not discovery_only:
                    run_risk_rules(sdb, scan)
                # Topology is part of the report (kept for discovery-only too).
                capture_topology(sdb, scan)
                sdb.add(AuditLog(
                    engagement_id=scan.engagement_id,
                    scan_id=scan.id,
                    action="scan_completed",
                    detail={"hosts": scan.hosts_discovered, "via": "agent",
                            "mode": scan.mode},
                ))
                scan.status = "completed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_pct = 100
                from ..services.scan_worker import _snapshot_pass
                _snapshot_pass(sdb, scan)
                sdb.commit()
                from ..services.scan_worker import _deliver_scan_completed_webhook
                _deliver_scan_completed_webhook(sdb, scan)
            else:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress_pct = 100
                sdb.commit()
        manager.broadcast_sync(scan_id, {
            "type": "scan_completed" if completed else "scan_failed",
            "scan_id": scan_id, "error": error or None,
            "progress_pct": 100 if completed else scan.progress_pct,
            "hosts_discovered": scan.hosts_discovered if completed else None,
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

    def _by_identity():
        m = {}
        for h in existing.values():
            p = identity_hostname(h.hostname)
            if p:
                m.setdefault(p, h)
        return m
    by_identity = _by_identity()

    partial = data.status == "partial"
    up_count = 0
    open_ports_total = 0
    newly_created_up = []
    for hd in data.hosts:
        host = existing.get(hd.ip)
        if not host:
            # Same non-generic published hostname as a host already in this
            # scan = the same physical device seen on another interface /
            # privacy-MAC. Fold the new address and MAC into that row instead
            # of creating a duplicate Host for the report.
            prof = identity_hostname(hd.hostname)
            canon = by_identity.get(prof) if prof else None
            if canon is not None:
                host = canon
                sec = [str(x) for x in (list(host.secondary_ips) if host.secondary_ips else [])]
                if hd.ip not in sec:
                    sec.append(hd.ip)
                host.secondary_ips = sec
                macs = list(host.macs or [])
                if not any(hd.mac and m == hd.mac for m in macs + [str(host.mac or "").lower()]):
                    if hd.mac:
                        macs.append(hd.mac)
                host.macs = macs
                existing[hd.ip] = canon  # later batches keep routing here
            else:
                host = Host(scan_id=scan.id, ip=hd.ip, status=hd.status or "up",
                            discovery_method=["agent"])
                db.add(host)
                await db.flush()
                existing[hd.ip] = host
                if host.status == "up":
                    newly_created_up.append(host)
                by_identity = _by_identity()
        if "agent" not in (host.discovery_method or []):
            host.discovery_method = list(host.discovery_method or []) + ["agent"]
        host.status = hd.status or "up"
        if hd.mac and not host.mac:
            host.mac = hd.mac  # keep the primary (first-seen) MAC, history lives in macs
        if hd.vendor and not host.vendor:
            host.vendor = hd.vendor
        if hd.hostname:
            host.hostname = hd.hostname
        if hd.device_type:
            # Prefer an existing specific type over a generic hint arriving later
            # (keeps e.g. "mobile" after an alias posts with device_type "unknown").
            if not host.device_type or host.device_type == "unknown":
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

    if newly_created_up:
        threading.Thread(
            target=_deliver_agent_hosts,
            args=(str(scan.id), [str(h.id) for h in newly_created_up]),
            daemon=True,
        ).start()

    await manager.broadcast(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "info",
        "line": f"Agent result received: {len(data.hosts)} hosts, {open_ports_total} open ports",
    })
    threading.Thread(target=_run_post_analysis, args=(str(scan.id), True), daemon=True).start()
    return {"ok": True}