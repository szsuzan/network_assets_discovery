from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, Text, cast
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
from ..models import User, Engagement, Scan, Host, Port, SNMPInfo, Finding, AuditLog
from ..schemas import (
    ScanCreate, ReverifyIn, ScanOut, HostOut, HostDetail, HostPatch,
    FindingOut, FindingPatch, TopologyOut, DiffResult
)
from ..auth import get_current_user
from ..scope_utils import validate_targets_in_scope, count_hosts_in_scope
from ..services.scan_worker import run_scan, read_console_log

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
    
    scan = Scan(
        engagement_id=engagement.id,
        targets=data.targets,
        profile=data.profile,
        port_range=data.port_range,
        protocol=data.protocol,
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
        detail={"targets": data.targets, "profile": data.profile}
    ))
    
    await db.commit()
    await db.refresh(scan)
    
    # Queue the scan job. Use the scan UUID as the Celery task id so the
    # distributed stop (revoke) actually matches and kills the running task.
    run_scan.apply_async(args=[str(scan.id)], task_id=str(scan.id))
    
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

    db.add(AuditLog(
        user_id=current_user.id,
        engagement_id=scan.engagement_id,
        scan_id=scan.id,
        action="scan_reverify",
        detail={
            "recheck_down_hosts": data.recheck_down_hosts,
            "sweep_remaining_ports": data.sweep_remaining_ports,
            "port_range": data.port_range,
        }
    ))

    scan.kind = "reverify"
    scan.status = "queued"
    scan.started_at = datetime.now(timezone.utc)
    scan.completed_at = None
    scan.progress_pct = 0

    await db.commit()
    await db.refresh(scan)

    # Pass the reverify options along as task args; the worker uses them to run
    # only the unscanned portion (down hosts + leftover ports) and merges the
    # results into this same scan record.
    reverify_cfg = {
        "port_range": data.port_range,
        "recheck_down_hosts": data.recheck_down_hosts,
        "sweep_remaining_ports": data.sweep_remaining_ports,
    }
    run_scan.apply_async(args=[str(scan.id), reverify_cfg], task_id=str(scan.id))
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
    manager.broadcast_sync(str(scan.id), {"type": "scan_stopped", "scan_id": str(scan.id)})

    await db.refresh(scan)
    return scan

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
        query = query.where(Host.device_type == device_type)
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
        .where(Host.scan_id == scan_id, Host.ip == _host_ip_eq(host_ip))
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
        select(Host).where(Host.scan_id == scan_id, Host.ip == _host_ip_eq(host_ip))
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
    
    finding_by_host = {}
    for f in findings:
        if f.host_id not in finding_by_host:
            finding_by_host[f.host_id] = "info"
        sev_order = {"critical": 4, "concerning": 3, "notable": 2, "info": 1}
        if sev_order.get(f.severity, 0) > sev_order.get(finding_by_host[f.host_id], 0):
            finding_by_host[f.host_id] = f.severity

    # --- Subnet zones inferred from the scan targets ----------------------- #
    import ipaddress
    zone_nets = []
    for t in (scan.targets if scan else []):
        try:
            net = ipaddress.ip_network(str(t), strict=False)
        except ValueError:
            continue
        # Plain single-address target parses to a /32 (/128) host network —
        # widen it to the implied subnet the host lives on.
        if net.prefixlen == 32 or net.prefixlen == 128:
            ip = net.network_address
            net = ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64",
                                       strict=False)
        zone_nets.append(net)

    def _zone_key(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        for net in zone_nets:
            if ip in net:
                return str(net)
        # Fallback zone derived from the host's own address.
        return str(ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64",
                                        strict=False))

    group: dict = {}
    for h in hosts:
        group.setdefault(_zone_key(ipaddress.ip_address(str(h.ip))), []).append(h)

    def _gw_ip_for(net: ipaddress.IPv4Network | ipaddress.IPv6Network):
        """Usable gateway candidates (.1 / last usable) for IPv4 /24-ish nets."""
        if net.version != 4 or net.prefixlen > 24:
            return None
        return str(net.network_address + 1)

    zone_nodes = []
    gw_hosts: dict = {}  # zkey -> gateway host object (up host at .1/.254 or router/network_gear)
    for zkey, hs in sorted(group.items(), key=lambda kv: kv[0]):
        net = ipaddress.ip_network(zkey)
        any_ip = _gw_ip_for(net)
        gw_candidates = [h for h in hs if h.device_type in ("network_gear", "router")]
        if any_ip:
            gw_candidates = ([h for h in hs if str(h.ip) == any_ip] or
                             [h for h in hs if str(h.ip).rsplit(".", 1)[0] + ".254" == str(h.ip)] or
                             gw_candidates)
        gw = gw_candidates[0] if gw_candidates else None
        if gw:
            gw_hosts[zkey] = gw
        sev = max((sev_order.get(finding_by_host.get(h.id, "info"), 1) for h in hs), default=1)
        label = zkey.replace("/", " mask ")
        zone_nodes.append({
            "id": "zone:" + zkey,
            "kind": "zone",
            "label": label,
            "ip": any_ip if gw and not gw_hosts.get(zkey) is None else None,
            "host_count": len(hs),
            "device_type": "router" if gw else None,
            "severity": next(s for s, o in [("critical", 4), ("concerning", 3), ("notable", 2), ("info", 1)]
                             if o == sev),
        })

    nodes = list(zone_nodes)
    nodes.append({"id": "internet", "kind": "internet", "label": "Internet"})

    # A host may itself be a zone gateway (AP/router). Host node ids use the IP
    # string so every edge (which references IPs) resolves to a real node.
    gw_by_zone: dict = {}  # zkey -> gateway host
    for zkey, gw in gw_hosts.items():
        gw_by_zone[zkey] = gw

    for h in hosts:
        is_gw = any(gw is h for gw in gw_hosts.values())
        nodes.append({
            "id": str(h.ip),
            "kind": "host",
            "ip": str(h.ip),
            "label": h.hostname or str(h.ip),
            "device_type": h.device_type,
            "severity": finding_by_host.get(h.id, "info"),
            "is_gateway": is_gw,
        })

    edges = []
    for zkey, hs in group.items():
        gw = gw_by_zone.get(zkey)
        if gw:
            # The gateway is the physical link between internet and subnet:
            # it connects up to the internet and down into the zone.
            edges.append({"source": "internet", "target": str(gw.ip), "type": "gateway"})
            edges.append({"source": str(gw.ip), "target": "zone:" + zkey, "type": "in_subnet"})
        else:
            # No gateway host identified: the zone still ties up to the internet.
            edges.append({"source": "zone:" + zkey, "target": "internet", "type": "gateway"})
        # Every host (incl. the gateway) lives inside its subnet zone.
        for h in hs:
            edges.append({"source": str(h.ip), "target": "zone:" + zkey, "type": "in_subnet"})

    return TopologyOut(nodes=nodes, edges=edges)

@router.get("/scans/{scan_id}/findings", response_model=List[FindingOut])
async def list_findings(
    scan_id: uuid.UUID,
    severity: Optional[str] = None,
    finding_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = select(Finding, Host.ip).join(Host, Finding.host_id == Host.id, isouter=True).where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_type:
        query = query.where(Finding.type == finding_type)
    
    result = await db.execute(query)
    findings = []
    for f, ip in result.all():
        finding_dict = FindingOut.model_validate(f).model_dump()
        finding_dict["host_ip"] = str(ip) if ip else None
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
    
    patch_data = data.model_dump(exclude_unset=True)
    for key, value in patch_data.items():
        setattr(finding, key, value)
    
    await db.commit()
    await db.refresh(finding)
    return finding

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

@router.websocket("/ws/scans/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    from ..websocket import manager
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
