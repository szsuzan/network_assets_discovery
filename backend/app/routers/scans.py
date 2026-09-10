from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, Text, cast, func, or_
from sqlalchemy.orm import selectinload
from sqlalchemy.dialects.postgresql import INET
from datetime import datetime, timezone
from sqlalchemy import select
from typing import List, Optional
import uuid

def _host_ip_eq(host_ip: str):
    """Compare an INET column against a string IP by casting the string to inet."""
    return cast(host_ip, INET)

from ..database import get_db
from ..models import User, Engagement, Scan, Host, Port, SNMPInfo, Finding, FindingAudit, AuditLog
from ..schemas import (
    ScanCreate, ReverifyIn, ScanOut, HostOut, HostDetail, HostPatch,
    FindingOut, FindingPatch, FindingAuditOut, RiskRuleOut, RiskRulePatch,
    TopologyOut, DiffResult
)
from ..auth import get_current_user
from ..scope_utils import validate_targets_in_scope, count_hosts_in_scope
from ..services.scan_worker import run_scan, read_console_log, _dispatch_run
from ..services import settings as settings_svc

router = APIRouter(prefix="/api", tags=["scans"])

@router.post("/engagements/{engagement_id}/scans", response_model=ScanOut, status_code=201)
async def start_scan(
    engagement_id: uuid.UUID,
    data: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    
    try:
        validate_targets_in_scope(data.targets, engagement.authorized_scope)
    except ValueError as e:
        db.add(AuditLog(
            user_id=current_user.id,
            engagement_id=engagement.id,
            action="scope_rejected",
            detail={"targets": data.targets, "error": str(e)}
        ))
        await db.commit()
        raise HTTPException(status_code=422, detail=str(e))
    
    # Settings-driven defaults when the request omits them (the Settings page
    # centralises these for every scan type/method).
    profile = data.profile or await settings_svc.aget(db, "scan.default_profile", "quick")
    port_range = data.port_range or await settings_svc.aget(db, "scan.default_port_range", "1-10000")
    protocol = data.protocol or await settings_svc.aget(db, "scan.default_protocol", "tcp")
    
    scan = Scan(
        engagement_id=engagement.id,
        targets=data.targets,
        profile=profile,
        port_range=port_range,
        protocol=protocol,
        status="queued",
        hosts_total_in_scope=count_hosts_in_scope(data.targets),
        started_by=current_user.id
    )
    db.add(scan)
    
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=engagement.id,
        scan_id=scan.id,
        action="scan_started",
        detail={"targets": data.targets, "profile": profile}
    ))
    
    await db.commit()
    await db.refresh(scan)
    
    # Queue the scan job. Fresh unique task id (the scan id may already have
    # been revoked by a stop, and celery discards re-used revoked ids) recorded
    # in redis so the distributed stop still revokes the running task.
    _dispatch_run(str(scan.id))
    
    return scan

@router.post("/scans/{scan_id}/reverify", response_model=ScanOut)
async def reverify_scan(
    scan_id: uuid.UUID,
    data: ReverifyIn = ReverifyIn(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Re-verify an already-finished scan in place.

    Only touches what the initial scan did NOT cover:
      * hosts the initial scan marked 'down'/'scope' (re-check if they are really
        down, and if any now respond, run the full pipeline on those hosts)
      * ports the initial scan did not check (a residual sweep of the leftover
        range on the up hosts)

    Newly found hosts/ports/findings are upserted into the SAME scan record so
    there is a single authoritative report with no duplicates.
    """
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in ("queued", "discovering", "scanning", "fingerprinting",
                       "analyzing", "agent_running", "paused"):
        raise HTTPException(status_code=409, detail="Scan is still running; wait for it to finish before re-verifying")

    # Settings-driven defaults for re-verify behaviour (Settings page).
    recheck_down = data.recheck_down_hosts
    if recheck_down is None:
        recheck_down = await settings_svc.aget(db, "reverify.recheck_down_hosts", True)
    sweep_ports = data.sweep_remaining_ports
    if sweep_ports is None:
        sweep_ports = await settings_svc.aget(db, "reverify.sweep_remaining_ports", True)
    min_gap = int(await settings_svc.aget(db, "reverify.min_interval_seconds", 0) or 0)
    now = datetime.now(timezone.utc)
    if scan.completed_at and min_gap > 0:
        idle = (now - scan.completed_at).total_seconds()
        if idle < min_gap:
            raise HTTPException(
                status_code=429,
                detail=f"Re-verify too soon: wait {max(1, int(min_gap - idle))}s between re-scans "
                       f"(Settings > Re-scan)",
            )

    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=scan.engagement_id,
        scan_id=scan.id,
        action="scan_reverify",
        detail={
            "recheck_down_hosts": recheck_down,
            "sweep_remaining_ports": sweep_ports,
            "port_range": data.port_range,
        }
    ))

    scan.kind = "reverify"
    scan.status = "queued"
    scan.reverify_started_at = now
    # Idle time between passes (previously completed_at -> now) is not active
    # run time, so accumulate it and let the UI deduct it from the total.
    if scan.completed_at is not None:
        paused = max(0, int((scan.reverify_started_at - scan.completed_at).total_seconds()))
        scan.total_paused_seconds += paused
    scan.completed_at = None
    scan.progress_pct = 0

    await db.commit()
    await db.refresh(scan)

    # Pass the reverify options along as task args; the worker uses them to run
    # only the unscanned portion (down hosts + leftover ports) and merges the
    # results into this same scan record. Values already resolved against the
    # settings defaults above, so they are always explicit.
    reverify_cfg = {
        "port_range": data.port_range,
        "recheck_down_hosts": bool(recheck_down),
        "sweep_remaining_ports": bool(sweep_ports),
    }
    _dispatch_run(str(scan.id), reverify_cfg)
    return scan

@router.get("/scans/{scan_id}/logs", response_model=List[dict])
async def scan_logs(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")
    return read_console_log(scan_id)

@router.get("/scans/{scan_id}/activity", response_model=List[dict])
async def scan_activity(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from ..services.activity import read_activity
    return read_activity(str(scan_id))

@router.get("/scans/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    open_count = await db.execute(
        select(func.count()).select_from(Port).join(Host, Host.id == Port.host_id)
        .where(Host.scan_id == scan.id, Port.state == "open")
    )
    scan.open_ports_count = open_count.scalar_one() or 0
    return scan

@router.post("/scans/{scan_id}/pause", response_model=ScanOut)
async def pause_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in ("completed", "failed", "stopped"):
        raise HTTPException(status_code=400, detail="Scan already finished")

    scan.status = "paused"
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=scan.engagement_id,
        scan_id=scan.id,
        action="scan_paused",
        detail={}
    ))
    await db.commit()

    from ..websocket import _redis_client, manager
    try:
        rc = _redis_client()
        rc.set(f"scan:paused:{scan.id}", "1", ex=24 * 3600)
        rc.close()
    except Exception:
        pass
    manager.broadcast_sync(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "warn",
        "line": "=== Scan PAUSED (worker suspends between steps; Resume to continue) ===",
    })
    manager.broadcast_sync(str(scan.id), {"type": "scan_paused", "scan_id": str(scan.id)})

    await db.refresh(scan)
    return scan


@router.post("/scans/{scan_id}/resume", response_model=ScanOut)
async def resume_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "paused":
        raise HTTPException(status_code=400, detail="Scan is not paused")

    # Restore an active state; the worker republishes the exact phase status as
    # it proceeds.
    scan.status = "scanning"
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=scan.engagement_id,
        scan_id=scan.id,
        action="scan_resumed",
        detail={}
    ))
    await db.commit()

    from ..websocket import _redis_client, manager
    try:
        rc = _redis_client()
        rc.delete(f"scan:paused:{scan.id}")
        rc.close()
    except Exception:
        pass
    manager.broadcast_sync(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "info",
        "line": "=== Scan RESUMED ===",
    })
    manager.broadcast_sync(str(scan.id), {"type": "scan_resumed", "scan_id": str(scan.id)})

    await db.refresh(scan)
    return scan


@router.delete("/scans/{scan_id}", response_model=ScanOut)
async def stop_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan.status = "stopped"
    scan.completed_at = datetime.now(timezone.utc)
    
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=scan.engagement_id,
        scan_id=scan.id,
        action="scan_stopped",
        detail={}
    ))
    
    await db.commit()
    
    # Global kill switch: revoke the queued/running Celery task and any spawned subprocesses.
    from ..services.scan_worker import cancel_scan
    cancel_scan(str(scan.id))

    from ..websocket import manager
    manager.broadcast_sync(str(scan.id), {
        "type": "cmd_log", "scan_id": str(scan.id), "level": "warn",
        "line": "=== Scan STOPPED by user ===",
    })
    manager.broadcast_sync(str(scan.id), {"type": "scan_stopped", "scan_id": str(scan.id), "progress_pct": scan.progress_pct})

    await db.refresh(scan)
    return scan

# Canonical device_type queried from the UI/API -> all legacy spellings the DB
# may still hold, so filters like device_type=ip_camera match rows stored as
# 'camera' (pre-granular-taxonomy scans).
DEVICE_TYPE_ALIASES = {
    "router": {"router", "gateway", "network_gear"},
    "smartphone": {"smartphone", "mobile"},
    "physical_server": {"physical_server", "server"},
    "ip_camera": {"ip_camera", "camera", "ipcam", "ip-cam", "cctv", "nvr", "dvr"},
    "unidentified": {"unidentified", "unknown"},
    "smart_speaker": {"smart_speaker", "virtual_assistant"},
    "iot": {"iot", "smart_appliance"},
    "conference": {"conference", "media_system"},
    "smart_tv": {"smart_tv", "streaming_device"},
    "voip_phone": {"voip_phone", "voip"},
    "printer": {"printer", "network_printer", "copier"},
    "nas": {"nas", "network_attached_storage"},
    "rogue": {"rogue", "rogue_device"},
}


@router.get("/scans/{scan_id}/hosts", response_model=List[HostOut])
async def list_hosts(
    scan_id: uuid.UUID,
    filter_status: Optional[str] = "up",
    device_type: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    response: Response = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from sqlalchemy import func
    query = select(Host).where(Host.scan_id == scan_id)
    
    if filter_status:
        query = query.where(Host.status == filter_status)
    if device_type:
        dev_values = DEVICE_TYPE_ALIASES.get(device_type, {device_type})
        query = query.where(Host.device_type.in_(dev_values))
    if search:
        like = f"%{search.lower()}%"
        query = query.where(
            func.lower(Host.ip.cast(Text)).like(like) |
            func.lower(func.coalesce(Host.mac.cast(Text), "")).like(like) |
            func.lower(func.coalesce(Host.hostname, "")).like(like) |
            func.lower(func.coalesce(Host.vendor, "")).like(like)
        )
    
    total = await db.execute(select(func.count()).select_from(query.subquery()))
    total_count = total.scalar_one()
    
    query = query.order_by(Host.ip).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    
    response.headers["X-Total-Count"] = str(total_count)
    response.headers["X-Page"] = str(page)
    response.headers["X-Page-Size"] = str(page_size)
    
    return result.scalars().all()

@router.get("/scans/{scan_id}/hosts/{host_ip}", response_model=HostDetail)
async def get_host_detail(
    scan_id: uuid.UUID,
    host_ip: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Host)
        .options(selectinload(Host.ports), selectinload(Host.snmp))
        .where(
            Host.scan_id == scan_id,
            or_(Host.ip == _host_ip_eq(host_ip),
                Host.secondary_ips.contains([host_ip])),
        )
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    host_data = HostDetail.model_validate(host)
    host_data.snmp = {
        "sys_descr": host.snmp.sys_descr if host.snmp else None,
        "sys_name": host.snmp.sys_name if host.snmp else None,
        "sys_location": host.snmp.sys_location if host.snmp else None,
        "default_community_found": host.snmp.default_community_found if host.snmp else False
    } if host.snmp else None
    return host_data

@router.patch("/scans/{scan_id}/hosts/{host_ip}", response_model=HostOut)
async def patch_host(
    scan_id: uuid.UUID,
    host_ip: str,
    data: HostPatch,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(Host).where(
            Host.scan_id == scan_id,
            or_(Host.ip == _host_ip_eq(host_ip),
                Host.secondary_ips.contains([host_ip])),
        )
    )
    host = result.scalar_one_or_none()
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    
    patch_data = data.model_dump(exclude_unset=True)
    for key, value in patch_data.items():
        setattr(host, key, value)
    
    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=None,
        scan_id=scan_id,
        action="host_annotated",
        detail={"ip": host_ip, "changes": patch_data}
    ))
    
    await db.commit()
    await db.refresh(host)
    return host

@router.get("/scans/{scan_id}/topology", response_model=TopologyOut)
async def get_topology(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = (await db.execute(select(Scan).where(Scan.id == scan_id))).scalar_one_or_none()
    hosts_result = await db.execute(select(Host).where(Host.scan_id == scan_id, Host.status == "up"))
    hosts = hosts_result.scalars().all()
    find_host_findings = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = find_host_findings.scalars().all()

    from ..services.topology import compute_topology
    nodes, edges = compute_topology(scan, hosts, findings)
    return TopologyOut(nodes=nodes, edges=edges)

@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
async def list_findings(
    scan_id: uuid.UUID,
    severity: Optional[str] = None,
    finding_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Finding, Host).join(Host, Finding.host_id == Host.id, isouter=True).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_type:
        query = query.where(Finding.type == finding_type)
    
    result = await db.execute(query)
    findings = []
    for f, host in result.all():
        finding_dict = FindingOut.model_validate(f).model_dump()
        finding_dict["host_ip"] = str(host.ip) if host else None
        finding_dict["host_hostname"] = host.hostname if host else None
        finding_dict["host_device_type"] = host.device_type if host else None
        finding_dict["host_mac"] = str(host.mac) if host and host.mac else None
        findings.append(FindingOut(**finding_dict))
    return findings

@router.patch("/findings/{finding_id}", response_model=FindingOut)
async def patch_finding(
    finding_id: uuid.UUID,
    data: FindingPatch,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Fields whose analyst changes go into the audit trail.
    audited_fields = {"status", "included_in_report", "severity", "cvss_score", "cvss_vector", "cwe"}

    patch_data = data.model_dump(exclude_unset=True)
    changes = []
    for key, value in patch_data.items():
        old = getattr(finding, key, None)
        new = value
        if old == new:
            continue
        setattr(finding, key, new)
        if key in audited_fields:
            changes.append({"field": key, "old_value": old, "new_value": new})
            db.add(FindingAudit(
                finding_id=finding.id,
                user_id=current_user.id,
                action="updated",
                field=key,
                old_value=str(old) if old is not None else None,
                new_value=str(new) if new is not None else None,
            ))

    finding.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(finding)

    if changes:
        import threading
        threading.Thread(
            target=_deliver_finding_update,
            args=(finding.id, current_user.id, changes),
            daemon=True,
        ).start()
    return finding

def _deliver_finding_update(finding_id, user_id, changes):
    """Post-commit webhook delivery in a background thread (sync session)."""
    from ..services.db import SessionLocal
    from ..services.webhook import deliver_finding_updated
    try:
        with SessionLocal() as s:
            from ..models import Finding as SyncFinding, Host as SyncHost, Scan as SyncScan, Engagement as SyncEng, User as SyncUser
            f = s.get(SyncFinding, finding_id)
            if not f:
                return
            host = s.get(SyncHost, f.host_id) if f.host_id else None
            scan = s.get(SyncScan, f.scan_id) if f.scan_id else None
            engagement = s.get(SyncEng, scan.engagement_id) if scan else None
            actor = s.get(SyncUser, user_id)
            deliver_finding_updated(s, f, host, scan, engagement, actor, changes=changes)
    except Exception:
        import logging
        logging.getLogger(__name__).exception("finding_updated webhook delivery failed")

@router.get("/scans/{scan_id}/findings/{finding_id}/audit", response_model=List[FindingAuditOut])
async def finding_audit(
    scan_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(
        select(FindingAudit)
        .where(FindingAudit.finding_id == finding_id)
        .order_by(FindingAudit.created_at.asc())
    )
    return result.scalars().all()

@router.get("/scans/{scan_id}/diff/{other_scan_id}", response_model=DiffResult)
async def diff_scans(
    scan_id: uuid.UUID,
    other_scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    base_result = await db.execute(select(Host).where(Host.scan_id == scan_id))
    other_result = await db.execute(select(Host).where(Host.scan_id == other_scan_id))
    
    base_hosts = {str(h.ip): h for h in base_result.scalars().all()}
    other_hosts = {str(h.ip): h for h in other_result.scalars().all()}
    
    new_hosts = [host_to_dict(h) for ip, h in other_hosts.items() if ip not in base_hosts]
    missing_hosts = [host_to_dict(h) for ip, h in base_hosts.items() if ip not in other_hosts]
    
    changed_ports = []
    for ip, h in base_hosts.items():
        if ip in other_hosts:
            base_ports = await get_host_ports(db, h.id)
            other_ports = await get_host_ports(db, other_hosts[ip].id)
            if set(base_ports) != set(other_ports):
                changed_ports.append({"ip": ip, "before": base_ports, "after": other_ports})
    
    base_findings = await get_scan_findings(db, scan_id)
    other_findings = await get_scan_findings(db, other_scan_id)
    
    changed_findings = {
        "new": [f for f in other_findings if f not in base_findings],
        "resolved": [f for f in base_findings if f not in other_findings]
    }
    
    return DiffResult(
        new_hosts=new_hosts,
        missing_hosts=missing_hosts,
        changed_ports=changed_ports,
        changed_findings=changed_findings
    )

def host_to_dict(h: Host) -> dict:
    return {
        "id": str(h.id),
        "ip": str(h.ip),
        "mac": str(h.mac) if h.mac else None,
        "vendor": h.vendor,
        "hostname": h.hostname,
        "device_type": h.device_type,
        "os_guess": h.os_guess,
        "status": h.status,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None
    }

async def get_host_ports(db: AsyncSession, host_id: uuid.UUID) -> list:
    result = await db.execute(select(Port).where(Port.host_id == host_id))
    return sorted([f"{p.port}/{p.protocol}" for p in result.scalars().all()])

async def get_scan_findings(db: AsyncSession, scan_id: uuid.UUID) -> list:
    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    return sorted([f"{f.type}:{f.host_id}:{f.port}" for f in result.scalars().all()])

@router.get("/scans/{scan_id}/risk-rules", response_model=List[RiskRuleOut])
async def list_risk_rules(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..services.risk_rules import merged_rules, to_json
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return to_json(merged_rules(scan.risk_rules))

@router.put("/scans/{scan_id}/risk-rules", response_model=List[RiskRuleOut])
async def update_risk_rules(
    scan_id: uuid.UUID,
    rules: List[RiskRulePatch],
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from ..services.risk_rules import merged_rules, to_json, store_overrides
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.risk_rules = store_overrides(scan.risk_rules, [r.model_dump() for r in rules])
    await db.commit()
    await db.refresh(scan)
    return to_json(merged_rules(scan.risk_rules))

@router.post("/scans/{scan_id}/reanalyze", status_code=202)
async def reanalyze_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    from starlette.concurrency import run_in_threadpool
    from ..services.scan_worker import run_risk_rules
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("completed", "error"):
        raise HTTPException(status_code=409, detail="Scan is still running")

    await db.execute(delete(Finding).where(Finding.scan_id == scan_id))
    await db.commit()

    def _run():
        from ..services.db import SessionLocal
        with SessionLocal() as s:
            s.expire_all()
            sc = s.get(Scan, scan_id)
            run_risk_rules(s, sc)

    await run_in_threadpool(_run)
    return {"status": "ok", "detail": "Risk analysis re-applied"}

@router.websocket("/ws/scans/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    from ..websocket import manager
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
