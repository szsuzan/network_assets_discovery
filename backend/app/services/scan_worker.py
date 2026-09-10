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
from sqlalchemy import select, cast, delete, func
from sqlalchemy.dialects.postgresql import INET
from .db import SessionLocal
from . import scanners
from . import settings as settings_svc
from ..models import Scan, Host, Port, SNMPInfo, Finding, AuditLog, TopologyEdge, Agent, AgentTask
from ..websocket import manager
from ..celery_app import celery_app


# Raw nmap XML per scan/phase is stashed under backend/scan_output/<scan_id>/ so
# it can be re-processed or included in reports without re-running the scan.
SCAN_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "scan_output"


_console_log_lock = threading.Lock()


def _console_log_file(scan_id) -> Path:
    """Persistent per-scan console log path. Used so the LiveScan console can
    replay the full history (including the initial scan's lines) even after a
    re-verify pass or a fresh page load, instead of only what arrives live."""
    d = SCAN_OUTPUT_DIR / str(scan_id)
    return d / "console.log"


def append_console_log(scan_id, line: str, level: str = "info"):
    """Append a console line to the scan's persistent log file. Best-effort.

    The whole append (format + single write) is guarded by a process-wide lock:
    Python's append-mode open() records EOF at open time, so concurrent threads
    (parallel fingerprint workers) would otherwise interleave mid-line.
    """
    try:
        p = _console_log_file(scan_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        entry = f"[{datetime.now(timezone.utc).isoformat()}][{level}] {line}\n"
        with _console_log_lock:
            with open(p, "a", encoding="utf-8") as f:
                f.write(entry)
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
_SSL_NSE = ",ssl-cert,ssl-enum-ciphers"
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
    443: _HTTP_NSE + _SSL_NSE,
    445: _SMB_NSE,
    515: "cups-queue-info",
    554: "rtsp-methods",
    631: "cups-queue-info",
    636: "ssl-cert,ssl-enum-ciphers",
    993: "ssl-cert,ssl-enum-ciphers,imap-ntlm-info",
    995: "ssl-cert,ssl-enum-ciphers",
    3269: "msrpc-enum",
    3306: "mysql-info,mysql-enum,mysql-empty-password",
3389: "rdp-enum-encryption,rdp-ntlm-info",
     # no dedicated postgres NSE ships with nmap; 5432 inherits the default set
     5900: "vnc-info",
    6379: "redis-info",
    8000: _HTTP_NSE,
    8009: "ajp-header",
    8080: _HTTP_NSE,
    8443: _HTTP_NSE + _SSL_NSE,
    8834: _HTTP_NSE,
    27017: "mongodb-info",
}


def _nse_scripts_for_ports(open_ports) -> str:
    """Build a per-host '--script a,b,...' list from its open ports.

    Always includes `default` (=-sC) as the baseline, then appends each
    service-appropriate script set in ascending port order, deduplicated.
    Unknown/misc ports simply get the default set. Extra per-port scripts from
    the Settings page (nmap.port_scripts) are merged over the built-in table.
    """
    mapping = PORT_NSE_SCRIPTS
    override = settings_svc.get("nmap.port_scripts") or {}
    if override:
        mapping = {**PORT_NSE_SCRIPTS}
        for port, scripts in override.items():
            try:
                mapping[int(port)] = str(scripts)
            except (TypeError, ValueError):
                continue
    scripts = ["default"]
    seen = set()
    for p in sorted(open_ports):
        for s in mapping.get(p, "").split(","):
            s = s.strip()
            if s and s not in seen:
                seen.add(s)
                scripts.append(s)
    return ",".join(scripts)

def cancel_scan(scan_id: str):
    """Global kill switch: revoke a queued/running scan task so subprocesses are
    terminated.

    Tasks are dispatched with a fresh, unique Celery task id (recorded in redis)
    because re-using the scan id is unsafe: once a scan id has been revoked by a
    stop, celery silently discards every later task that reuses it — which left
    re-verify passes permanently stuck at 'queued'. See _dispatch_run.

    The Celery revoke is synchronous and blocks for up to ~10s while it talks to
    the broker, which makes the stop/delete endpoint feel stuck (and does nothing
    useful for agent-delegated scans, which do not run in Celery). It is therefore
    fired on a daemon thread so the API returns immediately after the scan row is
    already marked 'stopped'.
    """
    def _revoke():
        import time as _time
        task_ids = [scan_id]
        try:
            from ..websocket import _redis_client
            rc = _redis_client()
            v = rc.get(f"scan:task:{scan_id}")
            if v:
                task_ids.append(v.decode())
            rc.close()
        except Exception:
            pass
        for tid in task_ids:
            try:
                celery_app.control.revoke(tid, terminate=True, signal="SIGKILL")
            except Exception:
                pass
    threading.Thread(target=_revoke, daemon=True).start()


def _dispatch_run(scan_id: str, reverify_cfg: dict = None):
    """Queue a scan job against a FRESH Celery task id.

    Using the scan id as the task id worked for first runs but breaks re-verify:
    a stopped scan is revoked by id and celery never re-accepts that id, so the
    reverify of a resumed/stopped scan was silently discarded (stuck 'queued').
    The fresh id is recorded under `scan:task:<scan_id>` so the distributed stop
    (revoke) can still match and kill the running task.
    """
    args = [str(scan_id)] if reverify_cfg is None else [str(scan_id), reverify_cfg]
    task_uuid = str(uuid.uuid4())
    run_scan.apply_async(args=args, task_id=task_uuid)
    try:
        from ..websocket import _redis_client
        rc = _redis_client()
        rc.set(f"scan:task:{scan_id}", task_uuid, ex=86400)
        rc.close()
    except Exception:
        pass
    return task_uuid

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
        scan.reverify_started_at = None
        scan.total_paused_seconds = 0
        db.commit()

        manager.broadcast_sync(scan_id, {"type": "scan_started", "scan_id": scan_id, "targets": scan.targets})
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
            _snapshot_pass(db, scan)
            db.commit()
            _emit_log(scan, f"=== Scan completed: {scan.hosts_discovered} hosts ===", level="info")
            manager.broadcast_sync(scan_id, {"type": "scan_completed", "scan_id": scan_id, "progress_pct": 100, "hosts_discovered": scan.hosts_discovered})
        except ScanStopped:
            # Intentionally stopped: keep the authoritative 'stopped' state and
            # the UTC completed_at the user's stop set. Do not mark failed.
            _emit_log(scan, "=== Scan stopped (phases aborted) ===", level="warn")
            manager.broadcast_sync(scan_id, {"type": "scan_stopped", "scan_id": scan_id, "progress_pct": scan.progress_pct})
        except Exception as e:
            import traceback
            traceback.print_exc()
            scan.status = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            _emit_log(scan, f"=== Scan FAILED: {e} ===", level="err")
            manager.broadcast_sync(scan_id, {"type": "scan_failed", "scan_id": scan_id, "error": str(e), "progress_pct": scan.progress_pct})


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
    recheck_down = cfg.get("recheck_down_hosts")
    if recheck_down is None:
        recheck_down = settings_svc.get_bool("reverify.recheck_down_hosts", True)
    sweep_ports = cfg.get("sweep_remaining_ports")
    if sweep_ports is None:
        sweep_ports = settings_svc.get_bool("reverify.sweep_remaining_ports", True)
    override_range = cfg.get("port_range")

    scan.status = "reverifying"
    if scan.reverify_started_at is None:
        scan.reverify_started_at = datetime.now(timezone.utc)
    scan.completed_at = None
    scan.progress_pct = 0
    db.commit()
    _emit_log(scan, "=== Re-verify scan started (unscanned ports + down hosts only) ===")
    manager.broadcast_sync(str(scan.id), {"type": "scan_reverifying", "scan_id": str(scan.id),
                              "reverify_started_at": scan.reverify_started_at.isoformat()})

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
                        fp_tmo = settings_svc.get_int("execution.fingerprint_host_timeout", 300)
                        cmd = (f"nmap -sT -sV -O {PROFILE_TIMING.get(scan.profile, '-T4')} "
                               f"--version-intensity 7 --script {script_set} "
                               f"--host-timeout {fp_tmo}s -p {port_list} {host.ip} -oX -")
                        out = _run_streamed(scan, cmd, fp_tmo + 60)
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
        _snapshot_pass(db, scan)
        db.commit()
        _emit_log(scan, f"=== Re-verify complete: {scan.hosts_discovered} hosts, report updated (no duplicates) ===")
        manager.broadcast_sync(str(scan.id), {"type": "scan_completed", "scan_id": str(scan.id), "progress_pct": 100, "hosts_discovered": scan.hosts_discovered})
    except ScanStopped:
        _emit_log(scan, "=== Re-verify stopped ===", level="warn")
        manager.broadcast_sync(str(scan.id), {"type": "scan_stopped", "scan_id": str(scan.id), "progress_pct": scan.progress_pct})
    except Exception as e:
        import traceback
        traceback.print_exc()
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        _emit_log(scan, f"=== Re-verify FAILED: {e} ===", level="err")
        manager.broadcast_sync(str(scan.id), {"type": "scan_failed", "scan_id": str(scan.id), "error": str(e), "progress_pct": scan.progress_pct})


# Ports tried for a quick TCP aliveness probe. Ordered by common admin/service
# ports; hitting any one confirms a host responds without a full scan.
PROBE_PORTS = [80, 443, 22, 445, 3389, 23, 53, 8080, 8443, 515, 631, 135, 139]

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


def _tcp_probe(ip: str, timeout: float = 1.0) -> bool:
    """Return True if the host completes a TCP handshake on any probe port."""
    for port in PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _probe_alive(candidates: list, timeout: float = None, max_workers: int = 64) -> set:
    """Concurrently TCP-probe candidate IPs, returning only reachable ones."""
    if timeout is None:
        timeout = settings_svc.get_float("execution.tcp_probe_timeout", 1.0)
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


def _delegate_to_agent(db, scan: Scan) -> bool:
    """Assign the scan to a live scanner agent whose local subnets cover the
    targets. Agents have real Layer-2 access (ARP -> MAC/vendor, SYN + -O ->
    exact OS) and run the scan autonomously; the worker returns immediately and
    the agent's result endpoint finishes the scan. Returns False when no agent
    is available, leaving the legacy in-worker execution to run.
    """
    try:
        if not settings_svc.get_bool("agent.delegation_enabled", True):
            # Master switch in the Settings page turns agent delegation off for
            # every scan / re-verify method; always run in the worker instead.
            return False
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(_tz.utc)
        window = settings_svc.get_int("agent.online_window_seconds", 90)
        online = []
        for agent in db.execute(select(Agent).where(Agent.status != "disabled")).scalars().all():
            if agent.last_seen and (now - agent.last_seen).total_seconds() > window:
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
                            max_concurrency: int = None):
    """Run Phase 2/3 nmap per host, concurrently, streaming live results.

    Returns (results, os_map) where results maps host_id -> [open_ports] and
    os_map maps host_id -> (os_guess, accuracy) from the fingerprint phase.
    `phase` is "ports" or "fingerprint" to control the flags.

    Threads never touch the shared DB session: for fingerprinting, the open-port
    target list is resolved on the main thread and passed in; the resulting
    enrichment is applied by the caller after all threads complete.
    """
    if max_concurrency is None:
        max_concurrency = settings_svc.get_int("execution.phase2_concurrency", 10)
    p2_min_rate = settings_svc.get_int("execution.phase2_min_rate", 500)
    p2_host_timeout = settings_svc.get_int("execution.phase2_host_timeout", 75)
    fp_host_timeout = settings_svc.get_int("execution.fingerprint_host_timeout", 300)
    profile_timing = PROFILE_TIMING.get(scan.profile, "-T4")
    proto = getattr(scan, "protocol", "tcp") or "tcp"
    port_spec = f"-p {scan.port_range}" if getattr(scan, "port_range", None) else ""

    confirmed = [h for h in hosts if h.status == "up"]
    if not confirmed:
        _emit_log(scan, "  no up hosts to scan -- skipping", level="info")
        return {}, {}, {}

    # Resolve per-host working set on the main thread (DB-safe).
    work = {}  # host_id -> (host, args, timeout)
    for h in confirmed:
        ip = str(h.ip)
        if phase == "ports":
            # Fast phase: connect scan at high rate on L3 (the container has no
            # L2/SYN here; L2/SYN+OS is provided by a scanner agent instead).
            # --host-timeout keeps one stuck host from stalling the phase.
            scan_mode = "-sU" if proto == "udp" else "-sT"
            extra = f"--min-rate {p2_min_rate} --host-timeout {p2_host_timeout}s" if proto != "udp" else ""
            args = f"{scan_mode} {profile_timing} {extra} {port_spec} --open {ip}"
            timeout = p2_host_timeout + 15
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
                         f"--host-timeout {fp_host_timeout}s")
            args = f"{scan_mode} {profile_timing} {extra} -p {port_list} {ip}"
            timeout = fp_host_timeout + 60
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
            # live per-host result, plus a rolling phase progress (never
            # regresses an already-higher value written by an earlier phase)
            if phase == "ports":
                scan.progress_pct = max(scan.progress_pct, min(70, 20 + int(done_count / total * 50)))
            else:
                scan.progress_pct = max(scan.progress_pct, min(90, 70 + int(done_count / total * 20)))
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
            snmp_info = scanners.snmp_walk(
                ip,
                settings_svc.get("nmap.snmp_community", "public"),
                settings_svc.get_float("nmap.snmp_timeout", 3.0),
            )
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
    """Heuristic classifier over every probe datapoint the platform collects.

    Signal order (highest first):
      * open services/ports (JetDirect/IPP/LPD -> printer, SIP -> VoIP,
        RTSP/Dahua -> camera, ZKTeco TTL -> access control),
      * the *name* the device publishes itself -- mDNS hostname/instance
        ("HP Officejet Pro 9010", "OnePlus Nord CE 3 5G", "Android_XXXX"),
        SNMP sysDescr/sysName/sysLocation, and service banners/versions,
      * MAC OUI manufacturer + well-known gateway addresses,
      * the Nmap OS fingerprint (last resort): -O routinely mislabels a
        handset's stack as a router/WAP and printer stacks as plain Linux.

    A host that names itself a phone/tablet/printer is typed that way even when
    the OS guess disagrees, because published names are far more reliable."""

    def _any(frags, text):
        return any(f in text for f in frags)

    standard_ips = ["192.168.1.1", "10.0.0.1", "192.168.0.1", "10.0.1.1", "172.16.0.1"]
    vendor = (host.vendor or "").lower()
    hostname = (host.hostname or "").lower()
    os_guess = (host.os_guess or "").lower()
    ports = {p.port for p in host.ports if p.state == "open"}
    mac = (host.mac or "").lower()
    last_octet = str(host.ip).rsplit(".", 1)[-1]
    admin_ports = {22, 80, 443, 445, 139, 3389, 3306, 5432, 6379, 8000, 8080, 8443, 3000}
    # Consumer/CPE gateways, PON/ONT makers and the like. Vendors here are
    # router-shaped even at non-nominal addresses, and (with the address rule
    # below) identify the default gateway when it only exposes admin ports.
    cpe_vendors = ("mikrotik", "d-link", "netgear", "tp-link", "tplink", "linksys",
                   "tenda", "totolink", "avm", "fritz", "zyxel", "ubiquiti",
                   "sagem", "technicolor", "nokia", "huawei", "zte",
                   "taicang t&w", "t&w electronics", "alphion", "fiberhome",
                   "utstarcom", "gongjin", "shenzhen gongjin", "proscend",
                   "raisecom", "sumavision")

    # -- aggregate every textual datapoint we have on this host --------------
    snmp_name = snmp_descr = snmp_loc = ""
    try:
        snmp_rec = getattr(host, "snmp", None)
        if snmp_rec is not None:
            snmp_name = snmp_rec.sys_name or ""
            snmp_descr = snmp_rec.sys_descr or ""
            snmp_loc = snmp_rec.sys_location or ""
    except Exception:
        pass
    service_parts = []
    for p in host.ports:
        if p.state != "open":
            continue
        for bit in (p.service, p.version, p.banner):
            if bit:
                service_parts.append(str(bit))
    name_text = " ".join(x.lower() for x in (hostname, snmp_name, snmp_descr, snmp_loc) if x)
    all_text = " ".join(x for x in (name_text, " ".join(service_parts).lower()) if x)

    # Gateway/router hosts by well-known address first.
    if str(host.ip) in standard_ips:
        host.device_type = "router"
        return

# --- printers / copiers ------------------------------------------------
    # JetDirect/RAW (9100), IPP (631) and LPD (515) are the classic proof; the
    # device's own published name (mDNS instance, sysDescr, banner) catches the
    # rest -- including models whose brand+family is not the word "print", e.g.
    # "HP Officejet Pro 9010", "Brother MFC-L3750", "Epson EcoTank ET-2850".
    printer_vendors = ("brother", "canon", "epson", "kyocera", "ricoh", "lexmark",
                       "xerox", "zebra", "okidata", "oki data", "oki electric",
                       "oki printing", "minolta", "konica", "fuji xerox",
                       "hewlett", "hp")
    printer_names = ("officejet", "laserjet", "deskjet", "designjet", "inkjet",
                     "pagewide", "photosmart", "ecotank", "surecolor", "multifunction",
                     "workcentre", "workcenter", "docuprint", "bizhub", "magicolor",
                     "imageclass", "pixma", "prograf", "stylus", "dcp-", "mfc-",
                     "hl-", "laser", "plotter", "scanner", "print", "printer", "mfp")
    if _any(printer_names, all_text) \
       or any(v in vendor for v in printer_vendors) \
       or bool(ports & {9100, 631, 515, 6001}):
        host.device_type = "printer"
        return

    # --- phones / tablets by their own published name -----------------------
    # Android/iOS handsets publicly identify as "Android_XXXX", "OnePlus Nord CE
    # 3 5G", "SM-G991B" or "iPhone 14" -- far more trustworthy than the -O stack
    # guess that so often calls a handset's stack a WAP/router. Excluded: names
    # that self-describe fixed hardware (TV/stick/speaker/projector, network or
    # imaging gear), which phones never do.
    phone_names = ("android", "iphone", "ipad", "ipod", "pixel", "galaxy", "redmi",
                   "oneplus", "poco", "realme", "xiaomi", "oppo", "vivo", "huawei",
                   "honor", "infinix", "tecno", "itel", "fairphone", "nothing",
                   "xperia", "motorola", "moto ", "sm-g", "sm-n", "sm-a", "sm-s",
                   "sm-m", "sm-f", "sm-t", "matepad")
    tablet_names = ("ipad", "ipod", "tablet", "kindle", "fire tablet", "sm-t",
                    "galaxy tab", "matepad", "mi pad", "yoga tab")
    nonphone_names = ("tv", "chromecast", "roku", "shield", "stick", "dongle",
                      "box", "fire stick", "fire tv", "soundbar", "projector",
                      "speaker", "alexa", "echo", "homepod", "router", "gateway",
                      "modem", "gpon", "ont", "switch", "access point", "wap",
                      "wireless", "wifi", "wi-fi", "extender", "repeater", "mesh",
                      "ap-", "cctv", "camera", "nvr", "dvr", "printer", "scan",
                      "nas", "ipcam")
    if _any(phone_names, name_text) and not _any(nonphone_names, name_text):
        if _any(tablet_names, name_text):
            host.device_type = "tablet"
        else:
            host.device_type = "smartphone"
        return

    # --- Apple computers by their own published name -------------------------
    # Privacy MACs erase the Apple OUI and a MacBook advertises the same
    # AirPlay/_device-info mDNS services as an iPhone, so without this a MacBook
    # Air can be mis-typed a smartphone. The published name settles it before
    # the "mobile" service hint can.
    mac_laptop_names = ("macbook", "mac book", "macbook air", "mac air")
    mac_desktop_names = ("imac", "mac mini", "mac pro", "mac studio",
                         "mac-mini", "mac-pro", "mac-studio")
    if _any(mac_laptop_names, name_text):
        host.device_type = "laptop"
        return
    if _any(mac_desktop_names, name_text):
        host.device_type = "workstation"
        return

    # --- probe/service identity hints from mDNS / NSE ------------------------
    # The scanner agent already reports *service-level* identity for this host
    # ("_ipp"._printer._adisk._smb._ssh._meshcop...) and it is the strongest
    # datapoint we have -- trust it unless open ports contradict it (a Linux
    # box that also runs _smb and 445 is a server, not a NAS).
    _hint = (host.device_type or "").strip().lower()
    if _hint == "printer":
        host.device_type = "printer"
        return
    if _hint == "nas" and not ({445, 139} & ports):
        host.device_type = "nas"
        return
    if _hint == "network_gear":
        host.device_type = "router"
        return
    if _hint == "mobile" \
       and not any(x in os_guess for x in ("tvos", "webos", "tizen", "vidaa",
                                           "android tv", "openwrt", "dd-wrt", "tomato",
                                           "routeros", "fritz!", "vxworks", "chromeos",
                                           "macos", "mac os", "darwin", "osx")):
        host.device_type = "smartphone"
        return
    if _hint == "server" and not ({445, 139} & ports):
        host.device_type = "physical_server"
        return

    # Nominal gateway addresses (first/last of the subnet). Most routers/ONTs
    # keep an SSH + web admin UI open and do NOT expose a DNS/DHCP listener, so
    # accept admin ports here instead of only 53/67/68. Desktop OS fingerprints
    # (Windows/macOS) are never the gateway and fall through to the PC rules.
    if last_octet in ("1", "254") \
       and (ports & {53, 67, 68, 546, 547, 80, 443, 22, 161, 8080, 8443}
            or any(v in vendor for v in cpe_vendors)) \
       and not any(x in os_guess for x in ("windows", "mac os", "macos", "darwin", "chromeos")):
        host.device_type = "router"
        return

    # --- routers / modems / ONTs by name ------------------------------------
    if _any(("router", "gateway", "modem", "ont-", "-ont", "gpon", "fritzbox",
             "network-hub"), name_text):
        host.device_type = "router"
        return

    # --- firewalls -----------------------------------------------------------
    if any(v in vendor for v in ("fortinet", "fortigate", "paloalto", "palo alto",
                                 "sonicwall", "sophos", "checkpoint", "pfsense",
                                 "opnsense", "watchguard", "barracuda", "cyberoam")) \
       or any(kw in name_text for kw in ("firewall", "fw-", "sandgate")):
        host.device_type = "firewall"
        return

    # --- wireless access points / range extenders ----------------------------
    if any(v in vendor for v in ("ruckus", "aerohive", "cambium", "radwin", "mimosa",
                                 "engenius", "airties", "hnc")) \
       or any(kw in name_text for kw in ("access point", "ap-", "uap-", "wireless",
                                         "wifi", "hotspot", "repeater", "extender",
                                         "mesh-")):
        host.device_type = "wireless_access_point"
        return

    # --- switches ------------------------------------------------------------
    if "switch" in vendor or "switch" in name_text \
       or any(v in vendor for v in ("cisco", "juniper", "extreme", "brocade",
                                    "force10", "arista", "mellanox")):
        host.device_type = "switch"
        return

    # --- SOHO / CPE network gear that is primarily router-shaped -------------
    if any(v in vendor for v in ("mikrotik", "d-link", "netgear", "tp-link", "tplink",
                                 "linksys", "tenda", "totolink", "avm", "zyxel",
                                 "alphion", "fiberhome", "utstarcom", "innacomm",
                                 "aztech", "ubiquiti", "sagem", "sagemcom",
                                 "technicolor", "aiptonet", "tahoe", "nokia",
                                 "taicang t&w", "t&w electronics", "gongjin",
                                 "proscend", "raisecom", "sumavision", "huawei", "zte")) \
       or any(kw in name_text for kw in ("-router", "router-", "ont", "modem")) \
       or any(x in os_guess for x in ("openwrt", "dd-wrt", "ddwrt", "tomato")):
        host.device_type = "router"
        return

    # --- IP cameras / NVRs / CCTV --------------------------------------------
    # Classic CCTV vendors plus tell-tale ports: RTSP (554/8554), Dahua TCP
    # (37777/34567), ONVIF discovery (3702/8899).
    camera_vendors = (
        "hikvision", "dahua", "axis", "foscam", "reolink", "amcrest",
        "orei", "annke", "avertx", "vstarcam", "wanscam", "cctv", "nvr", "dvr",
        "uniview", "zhejiang", "hunt", "imou", "tplink ipc", "arlo",
    )
    if any(v in vendor for v in camera_vendors) \
       or any(kw in name_text for kw in ("cam", "cctv", "nvr", "dvr", "ipcam",
                                         "ip-cam", "ipc-", "arlo")):
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
    )) or any(kw in name_text for kw in ("finger", "biometric", "access", "attendance",
                                         "door", "zk")):
        host.device_type = "access_control"
        return
    if ports & {4370, 4371, 8091}:
        host.device_type = "access_control"
        return

    # --- NAS -----------------------------------------------------------------
    if any(v in vendor for v in ("synology", "qnap", "asustor", "westerndigital", "wd ",
                                 "buffalo", "thecus", "netgear readynas", "nas")) \
       or any(kw in name_text for kw in ("nas", "my cloud", "mycloud", "cloudstation",
                                         "time capsule", "readynas")):
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
       or any(kw in name_text for kw in ("sip", "voip", "ipphone", "ip-phone", "yealink",
                                         "polycom", "grandstream", "ext-")):
        host.device_type = "voip_phone"
        return

    # --- virtual assistants / smart speakers ---------------------------------
    if any(kw in name_text for kw in ("echo", "alexa", "sonos", "nest mini", "google home",
                                      "google mini", "nest audio", "jbl", "harman kardon",
                                      "i home")) \
       or any(v in vendor for v in ("sonos", "alexa", "harman kardon")):
        host.device_type = "smart_speaker"
        return

# --- smart TVs / streaming sticks ----------------------------------------
    # Soft hostname TV evidence is demoted when the OS clearly says otherwise
    # (a Windows box named "<something>tv" is not a smart TV).
    if (any(x in os_guess for x in ("webos", "tizen", "vidaa", "smart tv", "android tv",
                                   "tvos", "netcast", "roku", "fire os", "google tv",
                                   "chromecast", "smart-tv")) \
        or any(kw in name_text for kw in ("tv-", "bravia", "roku", "fire tv", "apple tv",
                                          "chromecast", "nvidia shield", "amazon fire",
                                          "tivo", "smarttv", "smart tv", "android tv",
                                          "media box", "mi box", "droidbox", "box")) \
        or ("tv" in name_text and any(v in vendor for v in ("samsung", "lg", "sony",
                                                            "hisense", "tcl", "vizio",
                                                            "panasonic", "sharp")))) \
       and not any(x in os_guess for x in ("windows", "mac os", "macos", "darwin")):
        host.device_type = "smart_tv"
        return

    # --- conference / media systems ------------------------------------------
    if any(kw in name_text for kw in ("conference", "videoconf", "vc-", "meeting",
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

    # --- router-ish devices from the OS fingerprint -------------------------
    # -O nicknames whole products ("3Com OfficeConnect 3CRWER100-75 wireless
    # broadband router"); nothing later would catch those, so type them here.
    if any(x in os_guess for x in ("wireless bro", "router", "officeconnect",
                                   "access point", "gateway")) \
       or any(x in os_guess for x in ("cable modem", "wifi", "wi-fi")):
        host.device_type = "wireless_access_point"
        return

    # --- phones / tablets / TV sticks purely from the OS fingerprint ---------
    # Privacy-randomised MACs erase the vendor and the hostname may never
    # surface, but the -O stack fingerprint still says iOS/Android/tvOS. Type
    # those instead of falling through to "physical_server". Android TV and
    # Apple TV are typed smart_tv; ambiguous "iOS or tvOS" guesses go phone.
    if hostname and ("macbook" in hostname or "mac book" in hostname
                     or " mac air" in hostname or " mac mini" in hostname
                     or " mac pro" in hostname):
        host.device_type = "laptop"  # mDNS name beats the "iOS" OS mislabel
        return
    if hostname and ("iphone" in hostname or "ipod" in hostname):
        host.device_type = "smartphone"
        return
    if hostname and "ipad" in hostname:
        host.device_type = "tablet"
        return
    if "ipad" in os_guess or "ipados" in os_guess:
        host.device_type = "tablet"
        return
    if "iphone" in os_guess or ("ios" in os_guess and "mac" not in os_guess) \
       or os_guess.startswith("ios"):
        host.device_type = "smartphone"
        return
    if "tvos" in os_guess or "apple tv" in os_guess:
        host.device_type = "smart_tv"
        return
    if "android" in os_guess:
        if "android tv" in os_guess or "androidtv" in os_guess:
            host.device_type = "smart_tv"
        else:
            host.device_type = "smartphone"
        return

    # --- Chromebooks are laptops, not phones ----------------------------------
    if any(x in os_guess for x in ("chromeos", "chromium os", "chrome os")) \
       or "chromebook" in hostname:
        host.device_type = "laptop"
        return

    # --- macOS/darwin behind privacy-randomised MACs -------------------------
    # Privacy MACs erase the vendor OUI, but the OS string still says it is an
    # Apple device (a bare TCP-stack -O guess is enough). AirPlay hosts
    # (49152/62078) are laptops, never "servers".
    if any(x in os_guess for x in ("mac os", "macos", "darwin", "osx")):
        if "ipad" in os_guess:
            host.device_type = "tablet"
        elif "iphone" in os_guess or ("ios" in os_guess and "mac" not in os_guess):
            host.device_type = "smartphone"
        elif len(ports & admin_ports) >= 2:
            host.device_type = "physical_server"  # genuine Mac server behind admin ports
        else:
            host.device_type = "laptop"
        return

    # --- other phones / tablets by MAC-vendor OUI ---------------------------
    # The early name-based check catches self-described handsets; here the OUI
    # vendor alone is enough, still gated so a phone-vendor chip that runs a
    # TV/embedded OS (tvOS, WebOS, OpenWrt, RouterOS...) isn't typed a handset.
    _os_phone_contradict = ("windows", "mac os", "macos", "darwin", "tvos", "webos",
                            "tizen", "vidaa", "openwrt", "dd-wrt", "ddwrt", "tomato",
                            "routeros", "fritz!", "freebsd", "netbsd", "openbsd",
                            "solaris", "vxworks", "chromeos")
    phone_vendors = ("samsung", "oppo", "vivo", "oneplus", "xiaomi", "huawei", "honor",
                     "realme", "motorola", "moto", "poco", "nothing", "google")
    if any(v in vendor for v in phone_vendors) \
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

def _host_label(host: Host) -> str:
    """Short 'ip (hostname · device)' context used in finding titles so reports
    reflect the hostname/device-type enrichment the scan pipeline now produces."""
    parts = [str(host.ip)]
    if host.hostname:
        parts.append(host.hostname)
    if host.device_type and host.device_type not in ("unknown", "unidentified"):
        parts.append(host.device_type)
    return " · ".join(parts)


def _nse_xml_for_host(scan, host) -> str:
    """Re-assemble the raw NSE-bearing XML nmap produced for this host across
    phases. Finding rules consume it as evidence; absent files (e.g. hosts only
    seen by an L2 agent with no container nmap pass) yield empty output."""
    try:
        ip_safe = str(host.ip).replace("/", "_").replace(":", "_")
        base = SCAN_OUTPUT_DIR / str(scan.id)
        parts = []
        for name in (f"fingerprint_{ip_safe}.xml", f"nse_{ip_safe}.xml", f"ports_{ip_safe}.xml"):
            p = base / name
            if p.exists():
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
        return "\n".join(parts)
    except Exception:
        return ""


def _apply_meta(f: Finding, finding_type: str):
    """Stamp CWE + CVSS reference metadata onto a finding by its type."""
    try:
        from .nse_engine import FINDING_META
        cwe, score, vector = FINDING_META.get(finding_type, ("", None, None))
        f.cwe = cwe or None
        f.cvss_score = score
        f.cvss_vector = vector or None
    except Exception:
        pass


def _snapshot_pass(db, scan: Scan):
    """Record one completed scan pass (initial discover or re-verify) with its
    own duration plus the committed host/port counts, so the UI can show the
    value differences between passes (initial -> re-verify -> re-verify...).

    Idempotent: a pass whose (started_at, completed_at) already appears as the
    last history entry is skipped (e.g. if a worker retries finalisation).
    """
    try:
        start = scan.reverify_started_at if (scan.kind == "reverify" and scan.reverify_started_at) else scan.started_at
        end = scan.completed_at
        if not start or not end:
            return
        port_count = db.execute(
            select(func.count()).select_from(Port).join(Host, Host.id == Port.host_id)
            .where(Host.scan_id == scan.id, Port.state == "open")
        ).scalar_one() or 0
        history = list(scan.pass_history or [])
        if (history and history[-1].get("started_at") == start.isoformat()
                and history[-1].get("completed_at") == end.isoformat()):
            return
        history.append({
            "index": len(history),
            "kind": scan.kind if scan.kind in ("discover", "reverify") else "discover",
            "started_at": start.isoformat(),
            "completed_at": end.isoformat(),
            "duration": max(0, int((end - start).total_seconds())),
            "hosts": scan.hosts_discovered or 0,
            "ports": port_count,
        })
        scan.pass_history = history
    except Exception:
        return  # snapshotting is best-effort


def run_risk_rules(db, scan: Scan):
    from . import nse_engine
    from .risk_rules import merged_rules, rule_enabled, effective_severity

    cfg = merged_rules(scan.risk_rules)

    result = db.execute(select(Host).where(Host.scan_id == scan.id))
    hosts = result.scalars().all()

    created_findings: list = []

    def _on(key: str) -> bool:
        return rule_enabled(cfg, key)

    def _sev(key: str, current: str) -> str:
        return effective_severity(cfg, key, current)

    # Existing rows are upserted so re-verify passes that re-run risk rules
    # refresh findings instead of piling up duplicate (host, type, port) rows.
    existing_rows = db.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all()
    existing_by_key: dict = {}
    for frow in existing_rows:
        existing_by_key.setdefault((str(frow.host_id), frow.type, frow.port), frow)

    def _upsert(ftype: str, severity: str, port, title, description,
                recommendation, cwe=None, cvss_score=None, cvss_vector=None,
                evidence=None, cve_refs=None):
        ex = existing_by_key.get((str(host.id), ftype, port))
        if ex is not None:
            ex.severity = severity
            ex.title = title
            ex.description = description
            ex.recommendation = recommendation
            ex.port = port
            ex.evidence = evidence
            ex.cve_refs = cve_refs or ex.cve_refs or []
            ex.cwe = cwe
            ex.cvss_score = cvss_score
            ex.cvss_vector = cvss_vector
            ex.included_in_report = True
            ex.updated_at = datetime.now(timezone.utc)
            created_findings.append(ex)
            return ex
        f = Finding(
            scan_id=scan.id,
            host_id=host.id,
            severity=severity,
            type=ftype,
            title=title,
            description=description,
            recommendation=recommendation,
            cve_refs=cve_refs or [],
            port=port,
            evidence=evidence,
            cwe=cwe,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
        )
        db.add(f)
        created_findings.append(f)
        return f

    for host in hosts:
        if host.status != "up":
            continue
        host_ports = db.execute(select(Port).where(Port.host_id == host.id))
        ports = host_ports.scalars().all()
        open_ports = {p.port for p in ports if p.state == "open"}
        label = _host_label(host)

        # Keys already added this pass (type, port) — prevents duplicates between
        # the NSE evidence rules and the port/service heuristics.
        found: set = set()

        def _add(ftype: str, severity: str, port, title, description,
                 recommendation, cwe=None, cvss_score=None, cvss_vector=None,
                 evidence=None, cve_refs=None):
            key = (ftype, port)
            if key in found:
                return
            found.add(key)
            _apply_meta_vals = {"cwe": cwe, "cvss_score": cvss_score, "cvss_vector": cvss_vector}
            _upsert(
                ftype, severity, port, title, description, recommendation,
                cwe=_apply_meta_vals["cwe"],
                cvss_score=_apply_meta_vals["cvss_score"],
                cvss_vector=_apply_meta_vals["cvss_vector"],
                evidence=evidence,
                cve_refs=cve_refs,
            )

        # ---- NSE evidence rules ------------------------------------------
        # Everything Nmap/NSE actually *reported* becomes a finding here, with
        # the raw script output kept as evidence. Port/service heuristics then
        # only fill gaps NSE did not cover.
        nse_xml = _nse_xml_for_host(scan, host)
        nse_web = {}
        if nse_xml:
            nse_res = nse_engine.nse_findings_for_host(scan.id, host, label, nse_xml)
            nse_web = nse_res["web"]
            for fd in nse_res["findings"]:
                if not _on(fd["type"]):
                    continue
                _add(fd["type"], _sev(fd["type"], fd["severity"]), fd["port"], fd["title"],
                     fd["description"], fd["recommendation"],
                     cwe=fd.get("cwe"), cvss_score=fd.get("cvss_score"),
                     cvss_vector=fd.get("cvss_vector"), evidence=fd.get("evidence"))

        # ---- Rule: Default SNMP community found ---------------------------
        if _on("default_credentials"):
            snmp = db.execute(select(SNMPInfo).where(SNMPInfo.host_id == host.id))
            snmp_row = snmp.scalar_one_or_none()
            if snmp_row and snmp_row.default_community_found:
                f = _upsert(
                    "default_credentials",
                    _sev("default_credentials", "notable"),
                    161,
                    f"Default SNMP community string in use on {label}",
                    "The device responds to the default SNMP community string 'public', allowing unauthenticated read access to system information.",
                    "Change the SNMP community string to a non-default value and restrict SNMP access to trusted management hosts.",
                )
                _apply_meta(f, "default_credentials")
                found.add(("default_credentials", 161))

        # ---- Rule: Common unencrypted protocols ----------------------------
        # HTTP ports are handled by the web NSE rules below, never here. SIP on
        # a VoIP handset is expected for the class but still unencrypted.
        if _on("unencrypted_protocol"):
            insecure_ports = {
                23: ("Telnet", "concerning"),
                21: ("FTP", "notable"),
                445: ("SMB", "info"),
            }
            if host.device_type == "voip_phone":
                insecure_ports[5060] = ("SIP (unencrypted)", "notable")

            for p in ports:
                if p.state != "open" or p.port not in insecure_ports:
                    continue
                name, sev = insecure_ports[p.port]
                f = _upsert(
                    "unencrypted_protocol",
                    _sev("unencrypted_protocol", sev),
                    p.port,
                    f"{name} enabled on {label} port {p.port}",
                    f"Host is running {name} which transmits data in clear text.",
                    f"Replace {name} with an encrypted alternative (SSH/HTTPS/SRTP).",
                )
                _apply_meta(f, "unencrypted_protocol")
                found.add(("unencrypted_protocol", p.port))

        # ---- Rule: Unencrypted RTSP video / media streams -------------------
        if _on("unencrypted_video") and host.device_type in ("camera", "smart_tv", "conference", "iot"):
            rtsp_ports = [p for p in ports if p.state == "open" and
                          (p.port in (554, 8554) or (p.service or "").lower() == "rtsp")]
            for p in rtsp_ports:
                f = _upsert(
                    "unencrypted_video",
                    _sev("unencrypted_video", "concerning"),
                    p.port,
                    f"Unencrypted RTSP video stream on {label} port {p.port}",
                    f"The host serves raw RTSP on port {p.port}; captured traffic exposes the live feed unencrypted and typically unauthenticated to LAN clients.",
                    "Move video delivery to RTSPS/SRTP or a restricted management VLAN, and require authentication for stream access.",
                )
                _apply_meta(f, "unencrypted_video")
                found.add(("unencrypted_video", p.port))

        # ---- Rule: Known outdated software (from banner parsing) -------------
        if _on("eol_software"):
            for p in ports:
                if p.version and p.service and is_outdated_version(p.service, p.version):
                    f = _upsert(
                        "eol_software",
                        _sev("eol_software", "concerning"),
                        p.port,
                        f"Potentially outdated {p.service} on {label} port {p.port}",
                        f"{p.service} version {p.version} may contain known vulnerabilities.",
                        f"Upgrade {p.service} to a currently supported version.",
                    )
                    _apply_meta(f, "eol_software")
                    found.add(("eol_software", p.port))

        # ---- Web surface rule (NSE evidence first, port fallback) ------------
        # NSE http-title/http-enum already produced exposed_admin_panel /
        # web_service_exposed findings above. Any open http service NSE did not
        # cover (no script results) still gets a light web_service_exposed row so
        # the report documents the full web surface even on odd ports.
        if _on("web_service_exposed"):
            web_ports = {p.port for p in ports if p.state == "open"
                         and p.service in ("http", "https", "http-alt")}
            for wport in web_ports:
                if wport in nse_web:
                    continue  # NSE already voted on this port
                f = _upsert(
                    "web_service_exposed",
                    _sev("web_service_exposed", "info"),
                    wport,
                    f"Web service exposed on {label} port {wport}",
                    "A web service is listening on this port; confirm TLS and access controls.",
                    "Ensure the web service is patched, uses TLS, and is access-controlled.",
                    cve_refs=[],
                )
                _apply_meta(f, "web_service_exposed")
                found.add(("web_service_exposed", wport))

        host.last_seen = datetime.now(timezone.utc)

    db.commit()

    # Deliver finding_created webhook events for anything generated this pass.
    try:
        from .webhook import has_subscribers, deliver_finding_created
        if created_findings and has_subscribers(db, "finding_created"):
            engagement = None
            try:
                from ..models import Engagement
                engagement = db.execute(
                    select(Engagement).where(Engagement.id == scan.engagement_id)
                ).scalar_one_or_none()
            except Exception:
                pass
            host_by_id = {str(h.id): h for h in hosts}
            for fobj in created_findings:
                try:
                    deliver_finding_created(
                        db, fobj,
                        host=host_by_id.get(str(fobj.host_id)),
                        scan=scan, engagement=engagement,
                    )
                except Exception:
                    continue  # delivery is best-effort per finding
    except Exception:
        pass

    # Broadcast one aggregate finding event so the live feed reflects risk analysis completion
    try:
        by_sev = {s: 0 for s in ("critical", "concerning", "notable", "info")}
        total = 0
        for fobj in db.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        ).scalars().all():
            by_sev[fobj.severity] = by_sev.get(fobj.severity, 0) + 1
            total += 1
        manager.broadcast_sync(str(scan.id), {
            "type": "finding_added",
            "scan_id": str(scan.id),
            "count": total,
            "by_severity": by_sev,
            "hosts_discovered": scan.hosts_discovered,
        })
    except Exception:
        manager.broadcast_sync(str(scan.id), {
            "type": "finding_added",
            "scan_id": str(scan.id),
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

    db.execute(delete(TopologyEdge).where(TopologyEdge.scan_id == scan.id))

    for i in range(len(hosts) - 1):
        db.add(TopologyEdge(
            scan_id=scan.id,
            source_ip=str(hosts[i].ip),
            target_ip=str(hosts[i + 1].ip),
            edge_type="l2_adjacency"
        ))
    db.commit()
