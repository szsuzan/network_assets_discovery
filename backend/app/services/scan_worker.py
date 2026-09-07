import ipaddress
import json
import re
import shlex
import socket
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import select, cast
from sqlalchemy.dialects.postgresql import INET
from .db import SessionLocal
from . import scanners
from ..models import Scan, Host, Port, SNMPInfo, Finding, AuditLog, TopologyEdge, Agent, AgentTask
from ..websocket import manager
from ..celery_app import celery_app


# Raw nmap XML per scan/phase is stashed under backend/scan_output/<scan_id>/ so
# it can be re-processed or included in reports without re-running the scan.
SCAN_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "scan_output"


def _console_log_file(scan_id) -> Path:
    """Persistent per-scan console log path. Used so the LiveScan console can
    replay the full history (including the initial scan's lines) even after a
    re-verify pass or a fresh page load, instead of only what arrives live."""
    d = SCAN_OUTPUT_DIR / str(scan_id)
    return d / "console.log"


def append_console_log(scan_id, line: str, level: str = "info"):
    """Append a console line to the scan's persistent log file. Best-effort."""
    try:
        p = _console_log_file(scan_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now(timezone.utc).isoformat()}][{level}] {line}\n")
    except Exception:
        pass


def read_console_log(scan_id) -> list:
    """Return the scan's persisted console log as [{ts, level, line}, ...]."""
    import re as _re
    try:
        p = _console_log_file(scan_id)
        if not p.exists():
            return []
        out = []
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw:
                continue
            # format: [iso][level] line
            m = _re.match(r"^\[([^\]]+)\]\[([^\]]*)\]\s?(.*)$", raw)
            if m:
                out.append({"ts": m.group(1), "level": m.group(2) or "info", "line": m.group(3)})
            else:
                out.append({"ts": None, "level": "info", "line": raw})
        return out
    except Exception:
        return []


def _wait_if_paused(scan: Scan):
    """Cooperatively suspend the scan between subprocess steps while paused.

    The pause endpoint sets a shared Redis key; workers poll it before each new
    subprocess launch (and between phase boundaries) so a scan can be paused
    without killing already-running nmap processes. Each check is a cheap
    1.5s-sleep when paused and a single EXISTS otherwise.
    """
    try:
        from ..websocket import _redis_client
        rc = _redis_client()
    except Exception:
        return
    try:
        key = f"scan:paused:{scan.id}"
        while rc.exists(key):
            time.sleep(1.5)
    finally:
        try:
            rc.close()
        except Exception:
            pass


class ScanStopped(Exception):
    """Raised when a scan was intentionally stopped. Aborts remaining phases
    without marking the scan failed."""


def _raise_if_stopped(scan: Scan):
    """Check the authoritative scan status and abort if the user stopped it.

    Stop is a hard state the user sets on the Scan row. Under Celery, revoke
    with terminate can race the phase transitions, so each phase re-reads the
    status and bails here instead of overwriting 'stopped' with a phase state.
    """
    try:
        with SessionLocal() as _db:
            row = _db.execute(select(Scan).where(Scan.id == scan.id)).scalar_one_or_none()
            if row and row.status == "stopped":
                raise ScanStopped()
    except ScanStopped:
        raise
    except Exception:
        pass


def _save_scan_output(scan: Scan, phase: str, ip: str, content: str):
    try:
        d = SCAN_OUTPUT_DIR / str(scan.id)
        d.mkdir(parents=True, exist_ok=True)
        safe = (ip or "all").replace("/", "_").replace(":", "_")
        (d / f"{phase}_{safe}.xml").write_text(content or "", encoding="utf-8")
    except Exception:
        pass


def _write_scan_manifest(scan: Scan):
    """Small JSON manifest next to the raw XML so reports know what was run."""
    try:
        d = SCAN_OUTPUT_DIR / str(scan.id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "scan.json").write_text(json.dumps({
            "scan_id": str(scan.id),
            "targets": scan.targets,
            "profile": scan.profile,
            "port_range": scan.port_range,
            "protocol": getattr(scan, "protocol", "tcp"),
            "started_at": (scan.started_at or datetime.now(timezone.utc)).isoformat(),
        }, indent=2), encoding="utf-8")
    except Exception:
        pass

PROFILE_TIMING = {
    "quick": "-T4",
    "full": "-T3",
    "stealth": "-T1",
    "passive_only": "",
}

# --------------------------------------------------------------------------- #
# Service-aware NSE script selection
#
# Instead of one blanket --script set, the fingerprint phase picks scripts
# matching each open port so every host only runs relevant, *safe* scripts
# (plus the "default" =-sC set). Values map port -> comma-separated safe NSE ids.
# --------------------------------------------------------------------------- #

_HTTP_NSE = "http-title,http-headers,http-methods,http-server-header,http-enum,http-generator"
_SMB_NSE = ("smb-protocols,smb-security-mode,smb2-security-mode,"
            "smb-enum-shares,smb-os-discovery,smb2-capabilities")

PORT_NSE_SCRIPTS = {
    20:  "ftp-anon,ftp-syst",
    21:  "ftp-anon,ftp-syst",
    22:  "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods",
    23:  "telnet-encryption,telnet-ntlm-info",
    53:  "dns-nsid,dns-mx",
    80:  _HTTP_NSE,
    111: "rpc-info",
    123: "ntp-info",
    135: "msrpc-enum",
    137: "nbstat",
    139: _SMB_NSE,
    161: "snmp-info",
    389: "ldap-rootdse",
    443: _HTTP_NSE + ",ssl-cert",
    445: _SMB_NSE,
    515: "cups-queue-info",
    554: "rtsp-methods",
    631: "cups-queue-info",
    993: "ssl-cert,imap-ntlm-info",
    995: "ssl-cert",
    3269: "msrpc-enum",
    3306: "mysql-info,mysql-enum",
    3389: "rdp-enum-encryption,rdp-ntlm-info",
    5432: "",
    5900: "vnc-info",
    6379: "redis-info",
    8000: _HTTP_NSE,
    8009: "ajp-header",
    8080: _HTTP_NSE,
    8443: _HTTP_NSE + ",ssl-cert",
    8834: _HTTP_NSE,
    27017: "mongodb-info",
}


def _nse_scripts_for_ports(open_ports) -> str:
    """Build a per-host '--script a,b,...' list from its open ports.

    Always includes `default` (=-sC) as the baseline, then appends each
    service-appropriate script set in ascending port order, deduplicated.
    Unknown/misc ports simply get the default set.
    """
    scripts = ["default"]
    seen = set()
    for p in sorted(open_ports):
        for s in PORT_NSE_SCRIPTS.get(p, "").split(","):
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                scripts.append(s)
    return ",".join(scripts)

def cancel_scan(scan_id: str):
    """Global kill switch: revoke a queued/running scan task so subprocesses are
    terminated.

    The Celery revoke is synchronous and blocks for up to ~10s while it talks to
    the broker, which makes the stop/delete endpoint feel stuck (and does nothing
    useful for agent-delegated scans, which do not run in Celery). It is therefore
    fired on a daemon thread so the API returns immediately after the scan row is
    already marked 'stopped'.
    """
    def _revoke():
        import time as _time
        try:
            celery_app.control.revoke(scan_id, terminate=True, signal="SIGKILL")
        except Exception:
            pass
    threading.Thread(target=_revoke, daemon=True).start()

@celery_app.task(bind=True)
def run_scan(self, scan_id: str, reverify_cfg: dict = None):
    scan_uuid = uuid.UUID(scan_id)

    with SessionLocal() as db:
        result = db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        if scan.kind == "reverify":
            _run_reverify_scan(db, scan, reverify_cfg or {})
            return

        scan.status = "discovering"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        manager.broadcast_sync(scan_id, {"type": "scan_started", "scan_id": scan_id})
        _emit_log(scan, f"=== Scan started (id={scan_id}, targets={', '.join(scan.targets)}, " +
                         f"profile={scan.profile}, protocol={getattr(scan, 'protocol', 'tcp')}) ===")
        _write_scan_manifest(scan)

        # If a live L2 scanner agent covers the targets, hand the whole scan to
        # it rather than running in this container (which lacks ARP/L2). The
        # agent's result endpoint finishes the scan. Nothing after this runs
        # for delegated scans.
        if _delegate_to_agent(db, scan):
            return

        _emit_log(
            scan,
            "No online L2-capable agent covers the targets — falling back to "
            "L3 container scan (open ports only; MAC/vendor/OS unavailable). "
            "Deploy a scanner agent on the LAN to enable full Layer-2 results.",
            level="warn",
        )

        try:
            _emit_log(scan, "--- Phase 0/3: Host discovery (CIDR expansion + probes) ---")
            _wait_if_paused(scan)
            host_rows = discover_hosts(db, scan)
            _emit_log(scan, f"--- Discovery complete: {len(host_rows)} hosts registered ---")
            _raise_if_stopped(scan)
            scan.status = "scanning"
            db.commit()

            if scan.profile != "passive_only":
                # Phase 1: re-verify "down" hosts with nmap -sn. Only useful
                # when discovery had real Layer-2 (ARP returned data). The
                # container has no L2 (Docker NAT), and L3 nmap -sn is
                # unreliable -- routers/tunnels proxy-ARP/RST so every address
                # reports "up", promoting all scope hosts. TCP probe
                # confirmation is the ground truth, so this is always skipped.
                _emit_log(scan, "--- Phase 1/3: skipped (no L2/ARP data - nmap -sn unreliable; keeping probe-confirmed hosts) ---")

                # Phase 2: fast connect (no -sV/-sC/-O) port scan on UP hosts
                # only -> produce the open-port list for each host.
                _wait_if_paused(scan)
                _emit_log(scan, "--- Phase 2/3: Port scan (connect, no fingerprint) ---")
                port_scan_hosts(db, scan, host_rows)

                # Phase 3: deep service/OS fingerprint only on the ports that
                # were found open (fast, targets far fewer ports than a full
                # -sV sweep over every host).
                _raise_if_stopped(scan)
                scan.status = "fingerprinting"
                db.commit()
                _wait_if_paused(scan)
                _emit_log(scan, "--- Phase 3/3: Service fingerprinting (open ports only) ---")
                fingerprint_open_ports(db, scan, host_rows)

            _raise_if_stopped(scan)
            _wait_if_paused(scan)
            fingerprint_hosts(db, scan, host_rows)
            _raise_if_stopped(scan)
            scan.status = "analyzing"
            db.commit()
            _emit_log(scan, "--- Analyzing: risk rules + topology ---")
            run_risk_rules(db, scan)
            capture_topology(db, scan)

            _raise_if_stopped(scan)
            db.add(AuditLog(
                engagement_id=scan.engagement_id,
                scan_id=scan.id,
                action="scan_completed",
                detail={"hosts": scan.hosts_discovered}
            ))
            db.commit()

            scan.status = "completed"
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress_pct = 100
            db.commit()
            _emit_log(scan, f"=== Scan completed: {scan.hosts_discovered} hosts ===", level="info")
            manager.broadcast_sync(scan_id, {"type": "scan_completed", "scan_id": scan_id})
        except ScanStopped:
            # Intentionally stopped: keep the authoritative 'stopped' state and
            # the UTC completed_at the user's stop set. Do not mark failed.
            _emit_log(scan, "=== Scan stopped (phases aborted) ===", level="warn")
            manager.broadcast_sync(scan_id, {"type": "scan_stopped", "scan_id": scan_id})
        except Exception as e:
            import traceback
            traceback.print_exc()
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            _emit_log(scan, f"=== Scan FAILED: {e} ===", level="err")
            manager.broadcast_sync(scan_id, {"type": "scan_failed", "scan_id": scan_id, "error": str(e)})


# --------------------------------------------------------------------------- #
# Re-verify scan
#
# A re-verify re-opens an already-finished Scan and ONLY re-examines what the
# original pass did not cover:
#   * hosts originally marked "down"/scope-only  -> re-check liveness (ARP/L3);
#     if any now respond, run the full pipeline on them
#   * ports the original scan.logged range did not cover -> residual sweep on
#     the up hosts to surface "hidden" ports (e.g. services that listen after
#     a host came back, or high ports outside the original range)
# Everything is merged into the SAME Scan row (upsert by ip / host_id+port) so
# the final report is a single authoritative, duplicate-free inventory.
# --------------------------------------------------------------------------- #

def _range_to_ports(port_range: str) -> set:
    """Expand an nmap-style range ('1-10000' / '22,80,443-445') to a set of ints.

    Used to compute which ports the original scan already covered so re-verify
    can target only the *unscanned* leftover ports. Bounded to 65535 ports.
    """
    ports = set()
    if not port_range:
        return ports
    try:
        for part in str(port_range).replace(" ", "").split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo_s, _, hi_s = part.partition("-")
                lo, hi = int(lo_s), int(hi_s)
                ports.update(range(max(1, lo), min(65535, hi) + 1))
            else:
                p = int(part)
                if 0 < p <= 65535:
                    ports.add(p)
    except Exception:
        pass
    return ports


def _leftover_ports(scan_ports: set) -> str:
    """Return the complement of the originally-scanned ports (1-65535) as an
    nmap-style range string, for the re-verify residual sweep."""
    full = set(range(1, 65536))
    leftover = sorted(full - scan_ports)
    if not leftover:
        return ""
    # pack into ranges
    parts = []
    start = prev = leftover[0]
    for p in leftover[1:]:
        if p == prev + 1:
            prev = p
            continue
        parts.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = p
    parts.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(parts)


def _merge_host_ports(db, scan: Scan, ip: str, ports: list):
    """Upsert open ports into an existing/recorded host WITHOUT duplicating.

    Keyed on (host_id, port, protocol): an existing row keeps its identity and
    gets its service/version/banner refreshed; a genuinely new port is created.
    Returns the Host row so callers can broadcast a live host_updated event.
    """
    host = (db.execute(select(Host).where(Host.scan_id == scan.id, cast(Host.ip, INET) == ip))
            ).scalar_one_or_none()
    if not host:
        return None
    existing = {p.port: p for p in db.execute(
        select(Port).where(Port.host_id == host.id)).scalars().all()}
    for pinfo in ports:
        port = int(pinfo.get("port", 0))
        proto = pinfo.get("protocol", "tcp")
        row = existing.get(port)
        if row is None:
            row = Port(
                host_id=host.id, port=port, protocol=proto,
                state=pinfo.get("state", "open"),
                service=pinfo.get("service"),
                version=pinfo.get("version"),
                banner=pinfo.get("banner"),
            )
            db.add(row)
            existing[port] = row
        else:
            if pinfo.get("service"):
                row.service = pinfo["service"]
            if pinfo.get("version"):
                row.version = pinfo["version"]
            if pinfo.get("banner"):
                row.banner = pinfo["banner"]
            row.state = "open"
    return host


def _run_reverify_scan(db, scan: Scan, cfg: dict = None):
    """Execute a re-verify pass on an already-completed Scan (same row).

    Merges findings in place, so the report at the same scan id reflects the
    new hosts / hidden ports with no duplicate rows.
    """
    cfg = cfg or {}
    recheck_down = cfg.get("recheck_down_hosts", True)
    sweep_ports = cfg.get("sweep_remaining_ports", True)
    override_range = cfg.get("port_range")

    scan.status = "reverifying"
    scan.started_at = datetime.now(timezone.utc)
    scan.completed_at = None
    scan.progress_pct = 0
    db.commit()
    _emit_log(scan, "=== Re-verify scan started (unscanned ports + down hosts only) ===")
    manager.broadcast_sync(str(scan.id), {"type": "scan_reverifying", "scan_id": str(scan.id)})

    # Prefer the L2 scanner agent (ARP -> MAC/vendor, SYN + -O) when one covers
    # the network; it runs the same down-host + leftover-port re-verify and the
    # agent result endpoint merges the findings into this scan row.
    if _delegate_to_agent(db, scan):
        return

    try:
        existing_hosts = db.execute(select(Host).where(Host.scan_id == scan.id)).scalars().all()
        up_ips = {str(h.ip) for h in existing_hosts if h.status == "up"}
        down_rows = [h for h in existing_hosts if h.status != "up"]

        # ---- Phase A: re-check hosts that were marked down ----
        newly_up = []
        if recheck_down and down_rows:
            _wait_if_paused(scan)
            _emit_log(scan, f"--- Re-checking {len(down_rows)} host(s) previously marked down ---")
            _raise_if_stopped(scan)
            candidates = [str(h.ip) for h in down_rows]
            alive = _probe_alive(candidates) if candidates else set()
            _emit_log(scan, f"  {len(alive)} previously-down host(s) now responding", level="out")
            for row in down_rows:
                ip = str(row.ip)
                if ip in alive:
                    row.status = "up"
                    if "tcp_probe" not in (row.discovery_method or []):
                        row.discovery_method = list(row.discovery_method or []) + ["tcp_probe"]
                    newly_up.append(row)
                    scan.hosts_discovered += 1
                    manager.broadcast_sync(str(scan.id), {
                        "type": "host_updated", "host_id": str(row.id), "ip": ip,
                        "status": "up", "device_type": row.device_type,
                    })
            db.commit()

            if newly_up:
                _raise_if_stopped(scan)
                _emit_log(scan, "--- Port scan + fingerprint on newly-up hosts ---")
                _wait_if_paused(scan)
                port_scan_hosts(db, scan, newly_up)
                _raise_if_stopped(scan)
                scan.status = "fingerprinting"
                db.commit()
                _wait_if_paused(scan)
                fingerprint_open_ports(db, scan, newly_up)
                fingerprint_hosts(db, scan, newly_up)

        # ---- Phase B: residual sweep of unscanned ports on up hosts ----
        if sweep_ports:
            _wait_if_paused(scan)
            # Determine the sweep range: an explicit override, else the ports the
            # original scan did NOT already check (complement of the stored range).
            if override_range:
                sweep_spec = override_range
            else:
                already = _range_to_ports(scan.port_range)
                sweep_spec = _leftover_ports(already)
            _raise_if_stopped(scan)
            up_hosts = db.execute(select(Host).where(
                Host.scan_id == scan.id, Host.status == "up")).scalars().all()
            if sweep_spec and up_hosts:
                _emit_log(scan, f"--- Residual port sweep {sweep_spec} on {len(up_hosts)} up host(s) ---")
                saved_range = scan.port_range
                scan.port_range = sweep_spec
                db.commit()
                # Quick open-port discovery on the leftover range only (no
                # fingerprint) - merge new open ports without duplication.
                result_by_id, _os, _sos = _scan_port_foreach_host(
                    db, scan, up_hosts, "ports", max_concurrency=8)
                scan.port_range = saved_range
                db.commit()

                new_open = []  # (host, ports) where ports are newly discovered
                for host in up_hosts:
                    ports = result_by_id.get(host.id, [])
                    if not ports:
                        continue
                    before = {p.port for p in db.execute(
                        select(Port).where(Port.host_id == host.id)).scalars().all()}
                    merged_host = _merge_host_ports(db, scan, str(host.ip), ports)
                    if merged_host:
                        after = {p.port for p in db.execute(
                            select(Port).where(Port.host_id == host.id)).scalars().all()}
                        fresh = sorted(after - before)
                        if fresh:
                            new_open.append((merged_host, fresh))
                            _emit_log(scan, f"  {str(host.ip)}: hidden port(s) found {','.join(map(str, fresh))}", level="out")
                db.commit()

                # Fingerprint only the newly-discovered hidden ports.
                if new_open:
                    _raise_if_stopped(scan)
                    scan.status = "fingerprinting"
                    db.commit()
                    _wait_if_paused(scan)
                    _emit_log(scan, "--- Fingerprinting newly-found hidden ports ---")
                    for host, fresh_ports in new_open:
                        _raise_if_stopped(scan)
                        _wait_if_paused(scan)
                        port_list = ",".join(map(str, fresh_ports))
                        script_set = _nse_scripts_for_ports(fresh_ports)
                        cmd = (f"nmap -sT -sV -O {PROFILE_TIMING.get(scan.profile, '-T4')} "
                               f"--version-intensity 7 --script {script_set} "
                               f"--host-timeout 300s -p {port_list} {host.ip} -oX -")
                        out = _run_streamed(scan, cmd, 360)
                        parsed = parse_rustscan_output(out)
                        merged = _merge_host_ports(db, scan, str(host.ip), parsed)
                        if merged:
                            classify_device_type(merged)
                        db.commit()

        _raise_if_stopped(scan)
        _wait_if_paused(scan)

        # ---- Re-run risk rules + topology so the final report is current ----
        # Deleting + re-adding findings would churn existing ones, so only run
        # for newly-up hosts; topology is recomputed wholesale (deduped).
        if newly_up:
            run_risk_rules(db, scan)
        db.execute(select(Scan))

        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.verified_at = datetime.now(timezone.utc)
        scan.progress_pct = 100
        db.commit()
        _emit_log(scan, f"=== Re-verify complete: {scan.hosts_discovered} hosts, report updated (no duplicates) ===")
        manager.broadcast_sync(str(scan.id), {"type": "scan_completed", "scan_id": str(scan.id)})
    except ScanStopped:
        _emit_log(scan, "=== Re-verify stopped ===", level="warn")
        manager.broadcast_sync(str(scan.id), {"type": "scan_stopped", "scan_id": str(scan.id)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        _emit_log(scan, f"=== Re-verify FAILED: {e} ===", level="err")
        manager.broadcast_sync(str(scan.id), {"type": "scan_failed", "scan_id": str(scan.id), "error": str(e)})


# Ports tried for a quick TCP aliveness probe. Ordered by common admin/service
# ports; hitting any one confirms a host responds without a full scan.
PROBE_PORTS = [80, 443, 22, 445, 3389, 23, 53, 8080, 8443, 515, 631, 135, 139]

# Ports that are commonly firewalled/closed yet still used to infer aliveness.
_CONFIRM_PORTS = [80, 443, 22, 445]


def _expand_targets(targets: list) -> list:
    ips = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            ips.append(t)
            continue
        if net.num_addresses == 1:
            ips.append(str(net.network_address))
        else:
            for host in net.hosts():
                ips.append(str(host))
    return ips


def _hosts_from_sn_xml(xml_output: str) -> list:
    """Parse host-native `nmap -sn -oX -` XML into [{ip, mac, vendor}, ...].

    Returns only hosts reported as 'up' (those nmap confirmed via ARP/ping on
    the host that has real L2). MAC/vendor come from nmap's address lines.
    """
    hosts = []
    if not xml_output or not xml_output.strip():
        return hosts
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return hosts

    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        entry = {"ip": None, "mac": None, "vendor": None}
        for addr in host_el.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4" and not entry["ip"]:
                entry["ip"] = addr.get("addr")
            elif atype == "mac":
                entry["mac"] = addr.get("addr")
                entry["vendor"] = addr.get("vendor")
        if entry["ip"]:
            hosts.append(entry)
    return hosts


def _tcp_probe(ip: str, timeout: float = 1.0) -> bool:
    """Return True if the host completes a TCP handshake on any probe port."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _probe_alive(candidates: list, timeout: float = 1.0, max_workers: int = 64) -> set:
    """Concurrently TCP-probe candidate IPs, returning only reachable ones."""
    alive = set()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_tcp_probe, ip, timeout): ip for ip in candidates}
        for fut in futures:
            if fut.result():
                alive.add(futures[fut])
    return alive


def discover_hosts(db, scan: Scan) -> list:
    hosts = []

    # The backend container runs on Docker's virtual network, so it has no
    # Layer-2 access to the target LAN — ARP/LLDP discovery never yields data
    # here. Real L2 discovery (MAC/vendor/OS) is provided by a scanner agent on
    # the LAN; this worker always uses L3 TCP probing to confirm liveness.
    _emit_log(scan, "L3-only discovery (ARP/LLDP unavailable from container)", level="info")

    # 1) Expand every target (including CIDRs) into concrete host IPs.
    candidate_ips = _expand_targets(scan.targets)

    # 2) Confirm liveness via a quick TCP probe. In routed/NAT environments ARP
    #    is usually unavailable, so a TCP connect probe is the reliable signal.
    #    If a host answers any probe port it's listed as up; otherwise it's
    #    still registered as a scope host so the inventory reflects the target.
    _emit_log(scan, f"  probing {len(candidate_ips)} candidate(s) with TCP for liveness", level="info")
    alive_ips = _probe_alive(candidate_ips) if candidate_ips else set()

    seen_ips = set()
    def _register(ip: str, mac: str = None, vendor: str = None,
                  method: list = None, status: str = "up"):
        nonlocal hosts
        if ip in seen_ips:
            return
        seen_ips.add(ip)
        host = Host(
            scan_id=scan.id,
            ip=ip,
            mac=mac,
            hostname=None,
            vendor=vendor,
            status=status,
            device_type="unknown",
            discovery_method=method or ["scope"],
            tags=[],
            notes=""
        )
        db.add(host)
        hosts.append(host)
        scan.hosts_discovered = sum(1 for h in hosts if h.status == "up")
        scan.progress_pct = min(20, int(scan.hosts_discovered / max(scan.hosts_total_in_scope, 1) * 20))
        db.flush()
        if host.status == "up":
            manager.broadcast_sync(str(scan.id), {
                "type": "host_discovered",
                "host_id": str(host.id),
                "ip": ip,
                "up": True
            })

    # Register every expanded candidate: confirmed-alive ones are marked up,
    # the rest are kept as scope entries with status="down" so the inventory
    # still mirrors the target network without being reported as discoveries.
    for ip in candidate_ips:
        if ip in seen_ips:
            continue
        if ip in alive_ips and ip not in seen_ips:
            _register(ip, method=["tcp_probe"], status="up")
        elif ip not in seen_ips:
            _register(ip, method=["scope"], status="down")

    db.commit()
    return hosts

def _emit_log(scan, line: str, level: str = "info"):
    """Broadcast a console log line to any live-scan WebSocket subscribers and
    persist it to the scan's console log file so it survives page reloads and
    re-verify passes."""
    append_console_log(scan.id, line, level)
    try:
        manager.broadcast_sync(str(scan.id), {
            "type": "cmd_log",
            "scan_id": str(scan.id),
            "level": level,
            "line": line
        })
    except Exception:
        pass


def _run_streamed(scan, cmd: str, timeout: int = 60) -> str:
    """Run a command while streaming its live stderr output to the console.

    stderr carries nmap's human-readable progress (hosts found, ports opening),
    so it is forwarded to the WS console as it happens instead of after the
    process exits. Full stdout is captured and returned so callers can parse
    the XML/JSON payload. Returns "" on launch failure or timeout.
    """
    _emit_log(scan, f"$ {cmd}", level="cmd")
    try:
        proc = subprocess.Popen(
            shlex.split(cmd),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, errors="replace"
        )
    except Exception:
        return ""

    out_sink = []
    def pump_out():
        for raw in proc.stdout:
            out_sink.append(raw)
    def pump_err():
        for raw in proc.stderr:
            line = raw.rstrip()
            if line:
                _emit_log(scan, line, level="out")

    try:
        t_out = threading.Thread(target=pump_out, daemon=True)
        t_err = threading.Thread(target=pump_err, daemon=True)
        t_out.start()
        t_err.start()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
        return ""

    try:
        proc.wait(timeout=timeout)
        t_out.join(timeout=5)
        t_err.join(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        proc.wait()
        _emit_log(scan, f"[timeout after {timeout}s]", level="warn")
        return ""
    return "".join(out_sink)


def _nmap_run(scan, cmd: str, timeout: int = 60) -> list:
    """Run an nmap command returning parsed open ports, or [] on failure.

    Streams the command line and live progress output to the console via WS,
    then a concise per-host/per-port summary once the command completes.
    """
    out = _run_streamed(scan, cmd, timeout)
    if not out:
        return []
    _emit_summary(scan, out)
    return parse_rustscan_output(out)


def _emit_summary(scan, xml_output: str):
    """Render concise per-host/per-port summary lines from nmap XML output."""
    if not xml_output or not xml_output.strip():
        return
    try:
        import xml.etree.ElementTree as _ET
        root = _ET.fromstring(xml_output)
    except Exception:
        return

    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        status = host.find("status")
        state = status.get("state") if status is not None else "?"
        ports = host.findall(".//port")
        open_ports = [
            p for p in ports
            if (p.find("state") is not None and p.find("state").get("state") == "open")
        ]
        if not open_ports:
            _emit_log(scan, f"  {ip} ({state}) - no open ports", level="out")
            continue
        for p in open_ports:
            portid = p.get("portid")
            proto = p.get("protocol")
            svc = p.find("service")
            name = svc.get("name") if svc is not None else "?"
            ver = svc.get("version") if svc is not None else ""
            _emit_log(scan, f"  {ip}: {portid}/{proto} open  {name} {ver}".rstrip(), level="out")




def _delegate_to_agent(db, scan: Scan) -> bool:
    """Assign the scan to a live scanner agent whose local subnets cover the
    targets. Agents have real Layer-2 access (ARP -> MAC/vendor, SYN + -O ->
    exact OS) and run the scan autonomously; the worker returns immediately and
    the agent's result endpoint finishes the scan. Returns False when no agent
    is available, leaving the legacy in-worker execution to run.
    """
    try:
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(_tz.utc)
        online = []
        for agent in db.execute(select(Agent).where(Agent.status != "disabled")).scalars().all():
            if agent.last_seen and (now - agent.last_seen).total_seconds() > 90:
                continue
            online.append(agent)
        if not online:
            return False

        # A candidate agent must cover every target with one of its reported
        # locally-attached subnets (supernet of the target address/network).
        target_nets = []
        for t in scan.targets:
            try:
                target_nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                target_nets.append(ipaddress.ip_network(f"{t}/32", strict=False))

        for agent in sorted(online, key=lambda a: a.last_seen, reverse=True):
            agent_subnets = []
            for s in agent.subnets or []:
                try:
                    agent_subnets.append(ipaddress.ip_network(s, strict=False))
                except ValueError:
                    continue
            if not agent_subnets:
                continue
            if all(any(sub.supernet_of(tn) for sub in agent_subnets) for tn in target_nets):
                task = AgentTask(scan_id=scan.id, agent_id=agent.id, status="queued", targets=scan.targets)
                db.add(task)
                scan.status = "agent_running"
                scan.progress_pct = 5
                db.commit()
                _emit_log(
                    scan,
                    f"--- Delegating scan to scanner agent '{agent.name}' "
                    f"{('(' + agent.hostname + ')') if agent.hostname else ''} "
                    f"— L2-capable, subnets {', '.join(str(s) for s in agent_subnets)} ---",
                    level="info",
                )
                manager.broadcast_sync(str(scan.id), {
                    "type": "scan_delegated", "scan_id": str(scan.id), "agent": agent.name,
                })
                return True
    except Exception:
        import traceback
        traceback.print_exc()
    return False


def _scan_port_foreach_host(db, scan: Scan, hosts: list, phase: str,
                            max_concurrency: int = 10):
    """Run Phase 2/3 nmap per host, concurrently, streaming live results.

    Returns (results, os_map) where results maps host_id -> [open_ports] and
    os_map maps host_id -> (os_guess, accuracy) from the fingerprint phase.
    `phase` is "ports" or "fingerprint" to control the flags.

    Threads never touch the shared DB session: for fingerprinting, the open-port
    target list is resolved on the main thread and passed in; the resulting
    enrichment is applied by the caller after all threads complete.
    """
    profile_timing = PROFILE_TIMING.get(scan.profile, "-T4")
    proto = getattr(scan, "protocol", "tcp") or "tcp"
    port_spec = f"-p {scan.port_range}" if getattr(scan, "port_range", None) else ""

    confirmed = [h for h in hosts if h.status == "up"]
    if not confirmed:
        _emit_log(scan, "  no up hosts to scan -- skipping", level="info")
        return {}, {}

    # Resolve per-host working set on the main thread (DB-safe).
    work = {}  # host_id -> (host, args, timeout)
    for h in confirmed:
        ip = str(h.ip)
        if phase == "ports":
            # Fast phase: connect scan at high rate on L3 (the container has no
            # L2/SYN here; L2/SYN+OS is provided by a scanner agent instead).
            # --host-timeout keeps one stuck host from stalling the phase.
            scan_mode = "-sU" if proto == "udp" else "-sT"
            extra = "--min-rate 500 --host-timeout 75s" if proto != "udp" else ""
            args = f"{scan_mode} {profile_timing} {extra} {port_spec} --open {ip}"
            timeout = 90
        else:  # fingerprint only on already-open ports
            open_ports = [p for p in db.execute(
                select(Port).where(Port.host_id == h.id)).scalars().all()
                if p.state == "open"]
            if not open_ports:
                continue
            port_list = ",".join(str(p.port) for p in open_ports)
            script_set = _nse_scripts_for_ports([p.port for p in open_ports])
            if proto == "udp":
                scan_mode = "-sU -sV"
                extra = f"--script {script_set}"
            else:
                # Deepest script set that still completes in time. The
                # "discovery"/"safe" categories add slow broadcast prescripts
                # (broadcast-dhcp-discover etc.) that eat the whole host budget
                # before ports/service/-O results are flushed, so scripts are
                # chosen per-port from the safe set (-sC plus service-aware ids).
                scan_mode = "-sT -sV -O"
                extra = (f"--version-intensity 7 --script {script_set} "
                         "--host-timeout 300s")
            args = f"{scan_mode} {profile_timing} {extra} -p {port_list} {ip}"
            timeout = 360
        # --stats-every gives live progress ticks from the host
        stats = "" if profile_timing == "" else "--stats-every 5s"
        work[h.id] = (h, f"{args} {stats}".strip(), timeout)

    if not work:
        return {}, {}, {}

    results = {}
    os_map = {}
    script_os_map = {}
    total = len(work)
    done_count = 0

    def _one(item):
        _wait_if_paused(scan)
        host, args, timeout = item
        cmd = f"nmap {args} -oX -".strip()
        out = _run_streamed(scan, cmd, timeout)
        _save_scan_output(scan, phase, str(host.ip), out)
        ports = parse_rustscan_output(out)
        os_guess, os_conf, scripts_os = None, None, None
        if phase == "fingerprint":
            os_guess, os_conf = parse_os_from_xml(out)
            scripts_os = parse_os_from_scripts(out)
        return host.id, ports, os_guess, os_conf, scripts_os

    with ThreadPoolExecutor(max_workers=min(max_concurrency, len(work))) as pool:
        for hid, ports, os_guess, os_conf, scripts_os in pool.map(_one, list(work.values())):
            h = next((hh for hh in confirmed if hh.id == hid), None)
            if not h:
                continue
            results[hid] = ports
            if os_guess:
                os_map[hid] = (os_guess, os_conf)
            if scripts_os:
                script_os_map[hid] = scripts_os
            done_count += 1
            _emit_log(scan, f"  {str(h.ip)}: {len(ports)} open port(s) ({phase})", level="out")
            # live per-host result, plus a rolling phase progress
            if phase == "ports":
                scan.progress_pct = min(70, 20 + int(done_count / total * 50))
            else:
                scan.progress_pct = min(90, 70 + int(done_count / total * 20))
            try:
                db.flush()
                db.commit()
            except Exception:
                pass
            manager.broadcast_sync(str(scan.id), {
                "type": "host_updated",
                "host_id": str(hid),
                "ip": str(h.ip),
                "ports": ports,
                "os_guess": os_guess,
                "phase": phase
            })
            manager.broadcast_sync(str(scan.id), {
                "type": "scan_progress",
                "scan_id": str(scan.id),
                "progress_pct": scan.progress_pct,
                "hosts_discovered": scan.hosts_discovered
            })
    return results, os_map, script_os_map


def port_scan_hosts(db, scan: Scan, hosts: list):
    """Fast nmap connect scan (no -sV/-sC/-O) producing open ports per host.

    Runs only on hosts marked up/confirmed, concurrently across hosts, and
    records each open port WITHOUT service detail. Service detail is layered on
    later by fingerprint_open_ports. Live per-host results are broadcast as they
    complete so the UI updates incrementally instead of all at once.
    """
    confirmed = [h for h in hosts if h.status == "up"]
    if not confirmed:
        _emit_log(scan, "  no up hosts to port-scan -- skipping", level="info")
        return

    result_by_id, _os, _sos = _scan_port_foreach_host(db, scan, hosts, "ports")

    for host in confirmed:
        ports = result_by_id.get(host.id, [])
        for p in ports:
            db.add(Port(
                host_id=host.id,
                port=p["port"],
                protocol=p.get("protocol", "tcp"),
                state=p.get("state", "open"),
                service=None,
                version=None,
                banner=None
            ))
    db.flush()
    db.commit()


def fingerprint_open_ports(db, scan: Scan, hosts: list):
    """Deep -sV -sC -O fingerprinting ONLY on ports already found open.

    Constrains the heavy service scan to (<ip>,<port>) pairs that are actually
    open, so it finishes fast instead of sweeping every host's full range with
    version detection. Runs concurrently per host with live result streaming.
    """
    result_by_id, os_map, script_os_map = _scan_port_foreach_host(db, scan, hosts, "fingerprint")

    for host in hosts:
        if host.status != "up":
            continue
        open_ports = [p for p in db.execute(
            select(Port).where(Port.host_id == host.id)).scalars().all()
            if p.state == "open"]
        if not open_ports:
            continue
        # Exact OS from NSE scripts wins; nmap -O osmatch/osclass is the fallback.
        scripts_os = script_os_map.get(host.id, (None, 0))
        if scripts_os[0]:
            host.os_guess = scripts_os[0][:200]
            host.os_confidence = scripts_os[1] or host.os_confidence
        else:
            os_guess, os_conf = os_map.get(host.id, (None, None))
            if os_guess:
                host.os_guess = os_guess[:200]
                host.os_confidence = os_conf or host.os_confidence
        enriched_map = {p["port"]: p for p in result_by_id.get(host.id, [])}
        for p in open_ports:
            if p.port in enriched_map:
                info = enriched_map[p.port]
                p.service = info.get("service")
                p.version = info.get("version")
                p.banner = info.get("banner")
    db.commit()


def parse_rustscan_output(nmap_output: str) -> list:
    """Parse Nmap open ports from XML, falling back to the plain table."""
    ports = []
    if not nmap_output or not nmap_output.strip():
        return ports
    try:
        root = ET.fromstring(nmap_output)
    except ET.ParseError:
        root = None

    if root is not None:
        for host in root.findall("host"):
            for port_elem in host.findall(".//port"):
                port_info = {
                    "port": int(port_elem.get("portid", 0)),
                    "protocol": port_elem.get("protocol", "tcp"),
                    "service": None,
                    "version": None,
                    "banner": None,
                    "state": "open"
                }
                state_elem = port_elem.find("state")
                if state_elem is not None:
                    port_info["state"] = state_elem.get("state", "open")

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    port_info["service"] = service_elem.get("name")
                    port_info["version"] = service_elem.get("version")

                banner = ""
                script_outs = []
                for elem in port_elem.iter():
                    if elem.tag == "banner" and elem.text:
                        banner = elem.text.strip()[:500]
                    elif elem.tag == "script" and elem.get("output"):
                        script_outs.append(elem.get("output"))
                if script_outs:
                    combined = " || ".join(script_outs)[:500]
                    banner = combined if not banner else f"{banner} | {combined}"
                port_info["banner"] = banner or None
                ports.append(port_info)

    if ports:
        return ports

    # Fallback: the human-readable "PORT STATE SERVICE" table nmap prints
    # when NOT given -oX (e.g. ad-hoc runs or old raw output).
    for line in nmap_output.splitlines():
        m = re.match(r"^(\d+)/(udp|tcp)\s+(\w+)\s+(.*)$", line.strip())
        if not m:
            continue
        port_num, proto, state, rest = m.groups()
        if state != "open":
            continue
        svc = rest.split()
        ports.append({
            "port": int(port_num),
            "protocol": proto,
            "service": svc[0] if svc else None,
            "version": None,
            "banner": None,
            "state": state,
        })
    return ports

def parse_os_from_xml(xml_output: str):
    """Extract the best OS guess from Nmap -O XML.

    Returns (os_name, accuracy) or (None, None). A confident <osmatch> (>=75%)
    is used verbatim; otherwise the highest-accuracy <osclass> family is turned
    into a "Most probably running <vendor> <family> <gen>" label so the UI can
    show a best-effort guess instead of pretending to know nothing.
    """
    if not xml_output or not xml_output.strip():
        return None, None
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return None, None

    def _acc(el, default=-1):
        try:
            return int(el.get("accuracy", "0") or 0)
        except (TypeError, ValueError):
            return default

    best_name, best_acc = None, -1
    for host in root.findall("host"):
        os_el = host.find("os")
        if os_el is None:
            continue
        candidates = []
        for osmatch in os_el.findall("osmatch"):
            name = (osmatch.get("name") or "").strip()
            acc = _acc(osmatch, 0)
            if name and acc >= 75:
                candidates.append((name, acc))
        if not candidates:
            for osclass in os_el.findall("osclass"):
                vendor = (osclass.get("vendor") or "").strip()
                family = (osclass.get("osfamily") or "").strip()
                gen = (osclass.get("osgen") or "").strip()
                acc = _acc(osclass, 100)
                if family:
                    parts = [p for p in (vendor, family, gen) if p]
                    candidates.append(("Most probably " + " ".join(parts), max(acc, 0)))
        if candidates:
            name, acc = max(candidates, key=lambda c: c[1])
            if acc > best_acc:
                best_name, best_acc = name, acc
    if best_name:
        return best_name[:200], max(best_acc, 0)
    return None, None


def parse_os_from_scripts(xml_output: str):
    """Extract EXACT OS details from NSE script output.

    NSE scripts such as smb-os-discovery and rdp-ntlm-info often report the real
    OS/build (e.g. "Windows 11 Pro 10.0.22621 (Build 22621)"), which is more
    precise than nmap -O's osmatch. Returns (os_str, confidence) or None.
    Priority: SMB > RDP > SNMP > FTP.
    """
    if not xml_output or not xml_output.strip():
        return None
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return None

    def _clean(s):
        s = re.sub(r"\s+", " ", s or "")
        s = s.replace(" N/A", "")
        s = re.sub(r"\s*\(\s*Build\s+", " (Build ", s)
        return s.strip(" .,")

    def from_smb(run_el):
        # Legacy: output="OS: Windows 10 Pro 19042 Build 19042"
        for line in (run_el.get("output") or "").splitlines():
            m = re.search(r"\bOS:\s*(.+)$", line.strip())
            if m:
                val = _clean(m.group(1))
                if any(k in val.lower() for k in ("windows", "linux", "unix", "samba", "apple", "mac")):
                    return val
        # Modern: <elem key="OS">Windows 11 Pro 23H2 ...
        for el in run_el.iter():
            if el.tag == "elem" and (el.get("key") or "").lower() in ("os", "os version"):
                val = _clean(el.text)
                if val:
                    return val
        return None

    def from_rdp(run_el):
        product, osv = None, None
        for line in (run_el.get("output") or "").splitlines():
            m = re.search(r"Product:\s*(.+)$", line.strip())
            if m:
                product = _clean(m.group(1))
            m = re.search(r"OS[_\s]*Version:\s*(.+)$", line.strip())
            if m:
                osv = _clean(m.group(1))
        for el in run_el.iter():
            if el.tag == "elem":
                key = (el.get("key") or "").lower()
                if key == "product" and not product:
                    product = _clean(el.text)
                elif key in ("os version", "os_version", "os build") and not osv:
                    osv = _clean(el.text)
        if product or osv:
            if product and osv:
                return f"{product} {osv}"
            return product or osv
        return None

    def from_snmp(run_el):
        for line in (run_el.get("output") or "").splitlines():
            l = line.strip()
            if l.lower().startswith("system description"):
                val = _clean(l.partition(":")[2])
                if val:
                    return val[:200]
        return None

    def from_ftp(run_el):
        m = re.search(r"Syst:\s*(.+)$", (run_el.get("output") or ""), re.M)
        if m:
            val = _clean(m.group(1))
            if val and not val.lower().startswith("type"):
                return val
        return None

    # script id -> (priority, extractor, confidence)
    handlers = [
        ("smb-os-discovery", from_smb, 100),
        ("rdp-ntlm-info", from_rdp, 100),
        ("snmp-info", from_snmp, 80),
        ("ftp-syst", from_ftp, 70),
    ]
    best = None
    for script_el in root.iter("script"):
        sid = script_el.get("id") or ""
        for name, fn, conf in handlers:
            if sid == name:
                val = fn(script_el)
                if val:
                    if best is None or conf > best[1]:
                        best = (val[:200], conf)
    return best  # (os_str, confidence) or None

def fingerprint_hosts(db, scan: Scan, hosts: list):
    for host in hosts:
        if host.status != "up":
            continue
        ip = str(host.ip)

        # SNMP check for UDP 161 (and best-effort even without a confirmed port
        # since SNMP is connectionless and common on network gear).
        probed = db.execute(select(Port).where(
            Port.host_id == host.id, Port.port == 161, Port.protocol == "udp"
        )).scalar_one_or_none()

        if probed or host.device_type in ("unknown", "network_gear", "router"):
            snmp_info = scanners.snmp_walk(ip, "public")
            if snmp_info:
                db.add(SNMPInfo(
                    host_id=host.id,
                    sys_descr=snmp_info.get("sys_descr"),
                    sys_name=snmp_info.get("sys_name"),
                    sys_location=snmp_info.get("sys_location"),
                    sys_objectid=snmp_info.get("sys_objectid"),
                    sys_uptime=snmp_info.get("uptime"),
                    default_community_found=True
                ))
                if snmp_info.get("sys_name") and not host.hostname:
                    host.hostname = snmp_info["sys_name"]
                if snmp_info.get("vendor") and not host.vendor:
                    host.vendor = snmp_info["vendor"]
                if snmp_info.get("sys_descr"):
                    # Keep an already-exact OS (NSE/-O) rather than a long generic
                    # sysDescr like "Hardware: x86_64, Software: ...".
                    if not host.os_guess or host.os_guess.startswith("Most probably") or (host.os_confidence or 100) < 60:
                        host.os_guess = snmp_info["sys_descr"][:200]
                        host.os_confidence = 60 if host.os_guess else host.os_confidence

        # Reverse-DNS hostname fallback when SNMP never provided one. Bounded to
        # a handful of hosts so a dead resolver can't stall the scan.
        if not host.hostname and len([h for h in hosts if h.status == "up"]) <= 60:
            try:
                hn = socket.gethostbyaddr(str(host.ip))[0]
                if hn and hn != str(host.ip):
                    host.hostname = hn[:255]
            except Exception:
                pass

        classify_device_type(host)
        scan.progress_pct = min(90, 70 + int((hosts.index(host) + 1) / max(len(hosts), 1) * 20))
        manager.broadcast_sync(str(scan.id), {
            "type": "host_updated",
            "host_id": str(host.id),
            "ip": ip,
            "device_type": host.device_type
        })
    db.commit()

# --------------------------------------------------------------------------- #
# Device-type classification
# --------------------------------------------------------------------------- #

def classify_device_type(host: Host):
    """Heuristic classification based on MAC vendor, hostname, OS hint and open
    ports. Ordered so specific devices (cameras, fingerprint/access-control
    terminals, NAS, printers, VMs) win over generic server/workstation guesses.

    Emits a granular taxonomy (router/switch/firewall/AP, laptop vs phone/tablet,
    physical_server vs virtual_machine, smart TV/speaker, VoIP...) so hosts are
    no longer lumped into coarse "mobile"/"network_gear" buckets. Apple/Android
    hosts are only classified as phones/tablets when the name/OS actually says
    so -- MacBooks and Chromebooks are laptops, never "mobile"."""
    standard_ips = ["192.168.1.1", "10.0.0.1", "192.168.0.1", "10.0.1.1", "172.16.0.1"]
    vendor = (host.vendor or "").lower()
    hostname = (host.hostname or "").lower()
    os_guess = (host.os_guess or "").lower()
    ports = {p.port for p in host.ports if p.state == "open"}
    mac = (host.mac or "").lower()
    last_octet = str(host.ip).rsplit(".", 1)[-1]
    admin_ports = {22, 80, 443, 445, 139, 3389, 3306, 5432, 6379, 8000, 8080, 8443, 3000}

    # Gateway/router hosts by well-known address first.
    if str(host.ip) in standard_ips:
        host.device_type = "router"
        return

    # --- printers / copiers ------------------------------------------------
    # JetDirect/RAW (9100), IPP (631) and LPD (515) are the classic proof.
    if any(v in vendor for v in ("brother", "canon", "epson", "kyocera", "ricoh",
                                 "lexmark", "xerox", "zebra", "okidata", "oki data",
                                 "oki electric", "oki printing", "minolta",
                                 "konica", "fuji xerox")) \
       or "print" in vendor or "print" in hostname \
       or bool(ports & {9100, 631, 515, 6001}):
        host.device_type = "printer"
        return

    # Nominal gateway addresses (first/last of the subnet) answering DNS/DHCP
    # are almost certainly routers/ONTs.
    if last_octet in ("1", "254") and ports & {53, 67, 68, 546, 547}:
        host.device_type = "router"
        return

    # --- routers / modems / ONTs by name ------------------------------------
    if any(kw in hostname for kw in ("router", "gateway", "modem", "ont-", "-ont",
                                     "gpon", "fritzbox", "network-hub")):
        host.device_type = "router"
        return

    # --- firewalls -----------------------------------------------------------
    if any(v in vendor for v in ("fortinet", "fortigate", "paloalto", "palo alto",
                                 "sonicwall", "sophos", "checkpoint", "pfsense",
                                 "opnsense", "watchguard", "barracuda", "cyberoam")) \
       or any(kw in hostname for kw in ("firewall", "fw-", "sandgate")):
        host.device_type = "firewall"
        return

    # --- wireless access points / range extenders ----------------------------
    if any(v in vendor for v in ("ruckus", "aerohive", "cambium", "radwin", "mimosa",
                                 "engenius", "airties", "hnc")) \
       or any(kw in hostname for kw in ("access point", "ap-", "uap-", "wireless",
                                        "wifi", "hotspot", "repeater", "extender", "mesh-")):
        host.device_type = "wireless_access_point"
        return

    # --- switches ------------------------------------------------------------
    if "switch" in vendor or "switch" in hostname \
       or any(v in vendor for v in ("cisco", "juniper", "extreme", "brocade",
                                    "force10", "arista", "mellanox")):
        host.device_type = "switch"
        return

    # --- SOHO / CPE network gear that is primarily router-shaped -------------
    if any(v in vendor for v in ("mikrotik", "d-link", "netgear", "tp-link", "tplink",
                                 "linksys", "tenda", "totolink", "avm", "zyxel",
                                 "alphion", "fiberhome", "utstarcom", "innacomm",
                                 "aztech", "ubiquiti", "sagem", "sagemcom",
                                 "technicolor", "aiptonet", "tahoe", "nokia")) \
       or any(kw in hostname for kw in ("-router", "router-", "ont", "modem")) \
       or any(x in os_guess for x in ("openwrt", "dd-wrt", "ddwrt", "tomato")):
        host.device_type = "router"
        return

    # --- IP cameras / NVRs / CCTV --------------------------------------------
    # Classic CCTV vendors plus tell-tale ports: RTSP (554/8554), Dahua TCP
    # (37777/34567), ONVIF discovery (3702/8899).
    if any(v in vendor for v in (
        "hikvision", "dahua", "axis", "foscam", "reolink", "amcrest",
        "orei", "annke", "avertx", "vstarcam", "wanscam", "cctv", "nvr", "dvr",
        "uniview", "zhejiang", "hunt", "imou", "tplink ipc", "arlo",
    )) or any(kw in hostname for kw in ("cam", "cctv", "nvr", "dvr", "ipcam", "ip-cam",
                                        "ipc-", "arlo")):
        host.device_type = "camera"
        return
    if ports & {554, 8554, 37777, 34567, 8899}:
        host.device_type = "camera"
        return

    # --- fingerprint / biometric / door-access terminals ---------------------
    # ZKTeco/Realtime attendance machines are the classic case (ports 4370/4371
    # TTL, 8091 web, 8000 admin).
    if any(v in vendor for v in (
        "zkt", "zkteco", "biometric", "fingerprint", "fingertime", "realtime",
        "suprema", "idteck", "essl", "verge", "palmary", "ahan", "anviz",
        "finger max", "door", "access control",
    )) or any(kw in hostname for kw in ("finger", "biometric", "access", "attendance",
                                        "door", "zk")):
        host.device_type = "access_control"
        return
    if ports & {4370, 4371, 8091}:
        host.device_type = "access_control"
        return

    # --- NAS -----------------------------------------------------------------
    if any(v in vendor for v in ("synology", "qnap", "asustor", "westerndigital", "wd ",
                                 "buffalo", "thecus", "netgear readynas", "nas")) \
       or "nas" in hostname:
        host.device_type = "nas"
        return

    # --- virtual machines by MAC OUI / vendor / OS ---------------------------
    vm_mac_prefixes = ("00:50:56", "00:0c:29", "00:05:69", "00:16:3e",
                       "52:54:00", "00:15:5d", "00:1c:14", "00:03:ff")
    if mac.startswith(vm_mac_prefixes) \
       or any(v in vendor for v in ("vmware", "xensource", "xen", "qemu", "parallels",
                                    "citrix", "realmode", "virtualbox")) \
       or any(x in os_guess for x in ("vmware", "hyper-v", "xen", "proxmox", " kvm",
                                      "qemu", "virtual machine", "virtualbox")):
        host.device_type = "virtual_machine"
        return

    # --- VoIP phones / handsets ----------------------------------------------
    if ports & {5060, 5061} \
       or any(v in vendor for v in ("polycom", "yealink", "grandstream", "snom",
                                    "obihai", "fanvil", "mitel", "avaya", "nortel",
                                    "cisco spa", "cisco cp-", "gigaset")) \
       or any(kw in hostname for kw in ("sip", "voip", "ipphone", "ip-phone", "yealink",
                                        "polycom", "grandstream", "ext-")):
        host.device_type = "voip_phone"
        return

    # --- virtual assistants / smart speakers ---------------------------------
    if any(kw in hostname for kw in ("echo", "alexa", "sonos", "nest mini", "google home",
                                     "google mini", "jbl", "harman kardon", "i home")) \
       or any(v in vendor for v in ("sonos", "alexa", "harman kardon")):
        host.device_type = "smart_speaker"
        return

# --- smart TVs / streaming sticks ----------------------------------------
    # Soft hostname TV evidence is demoted when the OS clearly says otherwise
    # (a Windows box named "<something>tv" is not a smart TV).
    if (any(x in os_guess for x in ("webos", "tizen", "vidaa", "smart tv", "android tv",
                                   "tvos", "netcast", "roku", "fire os", "google tv",
                                   "chromecast", "smart-tv")) \
        or any(kw in hostname for kw in ("tv-", "bravia", "roku", "fire tv", "apple tv",
                                         "chromecast", "nvidia shield", "amazon fire",
                                         "tivo", "smarttv", "smart tv", "android tv")) \
        or ("tv" in hostname and any(v in vendor for v in ("samsung", "lg", "sony",
                                                           "hisense", "tcl", "vizio",
                                                           "panasonic", "sharp")))) \
       and not any(x in os_guess for x in ("windows", "mac os", "macos", "darwin")):
        host.device_type = "smart_tv"
        return

    # --- conference / media systems ------------------------------------------
    if any(kw in hostname for kw in ("conference", "videoconf", "vc-", "meeting",
                                     "codec", "poly studio", "poly trio", "logitech",
                                     "neat", "teams room", "zoom room")) \
       or any(v in vendor for v in ("logitech", "neat", "birddog", "yasnoy",
                                    "cisco telepresence")):
        host.device_type = "conference"
        return

    # --- Apple devices -------------------------------------------------------
    # Never blindly "mobile": MacBooks are laptops, Macs are desktops. Only the
    # name/OS makes a phone or tablet obvious.
    if "apple" in vendor:
        if "ipad" in hostname or "ipod" in hostname:
            host.device_type = "tablet"
        elif "iphone" in hostname:
            host.device_type = "smartphone"
        elif "apple tv" in hostname or "tvos" in os_guess:
            host.device_type = "smart_tv"
        elif "macbook" in hostname:
            host.device_type = "laptop"
        elif any(kw in hostname for kw in ("imac", "mac mini", "mac pro", "mac studio",
                                           "mac-mini", "mac-pro", "mac-studio")):
            host.device_type = "workstation"
        elif any(x in os_guess for x in ("mac os", "darwin", "osx", "macos")):
            host.device_type = "laptop"  # Apple desktops/laptops both show Darwin
        else:
            host.device_type = "smartphone"  # no clue: phones dominate Apple unknowns
        return

    # --- Chromebooks are laptops, not phones ----------------------------------
    if any(x in os_guess for x in ("chromeos", "chromium os", "chrome os")) \
       or "chromebook" in hostname:
        host.device_type = "laptop"
        return

    # --- macOS/darwin behind privacy-randomised MACs -------------------------
    # Privacy MACs erase the vendor OUI, but the OS string still says it is an
    # Apple device. AirPlay hosts (49152/62078) are laptops, never "servers".
    if ports and any(x in os_guess for x in ("mac os", "macos", "darwin", "osx")):
        if "ipad" in os_guess:
            host.device_type = "tablet"
        elif "iphone" in os_guess or ("ios" in os_guess and "mac" not in os_guess):
            host.device_type = "smartphone"
        elif len(ports & admin_ports) >= 2:
            host.device_type = "physical_server"  # genuine Mac server behind admin ports
        else:
            host.device_type = "laptop"
        return

    # --- other phones / tablets ------------------------------------------------
    # Soft phone evidence (an mDNS hostname like "Android_XXX" or a phone-OEM
    # vendor) is only trusted when the OS does not contradict it. A privacy-MAC
    # box named "Android" that the stack fingerprints as OpenWrt / tvOS is far
    # more likely to be a TV stick or embedded device, not a handset.
    _os_phone_contradict = ("windows", "mac os", "macos", "darwin", "tvos", "webos",
                            "tizen", "vidaa", "openwrt", "dd-wrt", "ddwrt", "tomato",
                            "routeros", "fritz!", "freebsd", "netbsd", "openbsd",
                            "solaris", "vxworks", "chromeos")
    phone_vendors = ("samsung", "oppo", "vivo", "oneplus", "xiaomi", "huawei", "honor",
                     "realme", "motorola", "moto", "poco", "nothing", "google")
    android_hostname = hostname.startswith(("android", "pixel", "redmi", "xiaomi", "oppo",
                                            "vivo", "motorola", "moto", "samsung", "sm-",
                                            "huawei", "honor", "nokia", "iphone", "ipad",
                                            "ipod")) or "galaxy" in hostname
    if (any(v in vendor for v in phone_vendors) or android_hostname) \
       and not any(x in os_guess for x in _os_phone_contradict):
        if "tab" in hostname or hostname.startswith("sm-t") or "galaxy tab" in hostname \
           or "kindle" in hostname or "ipad" in hostname:
            host.device_type = "tablet"
        else:
            host.device_type = "smartphone"
        return

    # --- laptops / desktops by obvious hostname -------------------------------
    if any(kw in hostname for kw in ("laptop", "notebook", "ultrabook", "thinkpad",
                                     "thinkbook", "latitude", "xps", "elitebook",
                                     "probook", "vivobook", "aspire", "inspiron",
                                     "satellite", "macbook", "ideapad", "nb-",
                                     "surface pro", "surface laptop")):
        host.device_type = "laptop"
        return
    if any(kw in hostname for kw in ("desktop", "tower", "optiplex", "precision", "sff",
                                     "mini pc", "all-in-one", "gaming pc")):
        host.device_type = "workstation"
        return

    # --- IoT / smart home ------------------------------------------------------
    if any(v in vendor for v in ("esp", "smartsocket", "smartplug", "smart home", "tuya",
                                 "aqara", "xiaomi mi", "wemo", "philips", "signify",
                                 "espressif", "sonoff", "wirenboard", "shelly", "tasmota")) \
       or any(kw in hostname for kw in ("smartplug", "smartsocket", "smart plug", "hue ",
                                        "thermostat", "sensor", "zigbee", "zwave")):
        host.device_type = "iot"
        return

    # --- server-ish hosts: OS plus a couple of admin ports -------------------
    if len(ports & admin_ports) >= 2 or bool({445, 139} & ports) or bool(ports & {3306, 5432, 6379}):
        host.device_type = "physical_server"
        return
    # An OS string alone is NOT enough to call a host a server. On hosts with no
    # open ports the -O fingerprint is a bare TCP-stack guess, and phone stacks
    # frequently mis-guess as ancient Linux kernels. Require an open port.
    if ports and any(x in os_guess for x in ("windows", "linux", "debian", "ubuntu",
                                             "centos", "red hat", "unix", "bsd", "darwin",
                                             "freebsd")):
        host.device_type = "physical_server"
        return

    # --- personal-computer brands are workstations by default ------------------
    if any(v in vendor for v in ("dell", "lenovo", "hewlett", "hp", "acer", "toshiba",
                                 "fujitsu", "razer", "gigabyte", "msi", "micro-star")) \
       or ("microsoft" in vendor and "surface" in hostname):
        host.device_type = "workstation"
        return

    host.device_type = "unknown"

def run_risk_rules(db, scan: Scan):
    result = db.execute(select(Host).where(Host.scan_id == scan.id))
    hosts = result.scalars().all()

    for host in hosts:
        if host.status != "up":
            continue
        host_ports = db.execute(select(Port).where(Port.host_id == host.id))
        ports = host_ports.scalars().all()

        # Rule: Default SNMP community found
        snmp = db.execute(select(SNMPInfo).where(SNMPInfo.host_id == host.id))
        snmp_row = snmp.scalar_one_or_none()
        if snmp_row and snmp_row.default_community_found:
            db.add(Finding(
                scan_id=scan.id,
                host_id=host.id,
                severity="notable",
                type="default_credentials",
                title=f"Default SNMP community string in use on {str(host.ip)}",
                description="The device responds to the default SNMP community string 'public', allowing unauthenticated read access to system information.",
                recommendation="Change the SNMP community string to a non-default value and restrict SNMP access to trusted management hosts.",
                cve_refs=[],
                port=161
            ))

        # Rule: Common unencrypted protocols
        insecure_ports = {
            23: ("Telnet", "concerning"),
            21: ("FTP", "notable"),
            80: ("HTTP (unencrypted)", "notable"),
            445: ("SMB", "info")
        }

        for p in ports:
            if p.port in insecure_ports:
                name, sev = insecure_ports[p.port]
                db.add(Finding(
                    scan_id=scan.id,
                    host_id=host.id,
                    severity=sev,
                    type="unencrypted_protocol",
                    title=f"{name} enabled on {str(host.ip)} port {p.port}",
                    description=f"Host is running {name} which transmits data in clear text.",
                    recommendation=f"Replace {name} with an encrypted alternative (SSH/HTTPS).",
                    cve_refs=[],
                    port=p.port
                ))

        # Rule: Known outdated software (from banner parsing)
        for p in ports:
            if p.version and p.service:
                if is_outdated_version(p.service, p.version):
                    db.add(Finding(
                        scan_id=scan.id,
                        host_id=host.id,
                        severity="concerning",
                        type="eol_software",
                        title=f"Potentially outdated {p.service} on {str(host.ip)} port {p.port}",
                        description=f"{p.service} version {p.version} may contain known vulnerabilities.",
                        recommendation=f"Upgrade {p.service} to a currently supported version.",
                        cve_refs=[],
                        port=p.port
                    ))

        # Rule: Exposed admin panels
        for p in ports:
            if p.service and p.service in ("http", "https", "http-alt"):
                db.add(Finding(
                    scan_id=scan.id,
                    host_id=host.id,
                    severity="concerning",
                    type="exposed_admin_panel",
                    title=f"Web service exposed on {str(host.ip)} port {p.port}",
                    description="A web service is listening. Administrative login pages should be checked for default credentials.",
                    recommendation="Validate web application access controls and change all default credentials.",
                    cve_refs=[],
                    port=p.port
                ))

        host.last_seen = datetime.now(timezone.utc)

    db.commit()

    # Broadcast one aggregate finding event so the live feed reflects risk analysis completion
    manager.broadcast_sync(str(scan.id), {
        "type": "finding_added",
        "scan_id": str(scan.id)
    })

def is_outdated_version(service: str, version: str) -> bool:
    KNOWN_OUTDATED = {
        "openssh": ["6.0", "7.0", "7.9"],
        "apache": ["2.2", "2.4"],
        "microsoft": ["2012", "2008"],
        "vsftpd": ["2.3.4"]
    }
    service = service.lower()
    for key, versions in KNOWN_OUTDATED.items():
        if key in service and any(v in version for v in versions):
            return True
    return False

def capture_topology(db, scan: Scan):
    # In production: passive CDP/LLDP sniffing + traceroute.
    # Seed with a simple host adjacency chain as a placeholder. Nodes are per-host
    # IPs, so a target that is a CIDR string (or a self-loop on single-IP scans)
    # would reference a non-existent node -- avoid both by chaining hosts only.
    result = db.execute(select(Host).where(Host.scan_id == scan.id))
    hosts = [h for h in result.scalars().all() if h.status == "up"]

    for i in range(len(hosts) - 1):
        db.add(TopologyEdge(
            scan_id=scan.id,
            source_ip=str(hosts[i].ip),
            target_ip=str(hosts[i + 1].ip),
            edge_type="l2_adjacency"
        ))
    db.commit()
