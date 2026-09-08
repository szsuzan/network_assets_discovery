"""Persistent per-scan activity feed.

Mirrors the console-log approach (backend/scan_output/<scan_id>/console.log) with
a JSONL file so the LiveScan activity feed survives page reloads and re-verify
passes instead of being limited to what arrived over the WebSocket while the page
was open.

Events are persisted exactly once from `ConnectionManager.broadcast_sync`, which
is the single funnel every scan event passes through (Celery worker and API alike).
"""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

SCAN_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "scan_output"

# High-frequency/noisy events that are still useful live (progress ticks,
# raw nmap command output) are not replayed into the activity timeline.
ACTIVITY_EVENT_TYPES = {
    "scan_started",
    "scan_paused",
    "scan_resumed",
    "scan_reverifying",
    "scan_delegated",
    "scan_completed",
    "scan_failed",
    "scan_stopped",
    "host_discovered",
    "host_updated",
    "finding_added",
}

MAX_LINES = 1200
TRIM_TO = 1000


def _activity_file(scan_id) -> Path:
    d = SCAN_OUTPUT_DIR / str(scan_id)
    return d / "activity.jsonl"


def append_activity(scan_id, event: dict):
    """Append a scan event to the activity feed. Best-effort; no-op for event
    types that are too noisy for a timeline."""
    if event.get("type") not in ACTIVITY_EVENT_TYPES:
        return
    try:
        line = {**event}
        if not line.get("ts"):
            line["ts"] = datetime.now(timezone.utc).isoformat()
        p = _activity_file(scan_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
        # Bound the file so long scans don't accumulate unbounded history.
        if _line_count(p) > MAX_LINES:
            _trim(p)
    except Exception:
        pass


def _line_count(p: Path) -> int:
    try:
        return sum(1 for _ in open(p, "r", encoding="utf-8"))
    except Exception:
        return 0


def _trim(p: Path):
    try:
        with open(p, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > TRIM_TO:
            with open(p, "w", encoding="utf-8") as f:
                f.writelines(lines[-TRIM_TO:])
    except Exception:
        pass


def read_activity(scan_id) -> list:
    """Return the scan's persisted activity feed as a list of event dicts."""
    out = _read_activity_file(scan_id)
    if out:
        return out
    # Scans that finished before activity persistence existed (or ran fully via
    # an agent) have no JSONL. Derive a minimal timeline from the console log so
    # the feed is never blank, and persist it for the next read.
    replay = _replay_from_console(scan_id)
    if replay:
        try:
            p = _activity_file(scan_id)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                for ev in replay:
                    f.write(json.dumps(ev) + "\n")
        except Exception:
            pass
    return replay


def _read_activity_file(scan_id) -> list:
    try:
        p = _activity_file(scan_id)
        if not p.exists():
            return []
        out = []
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except Exception:
                continue
            if isinstance(ev, dict) and ev.get("type"):
                out.append(ev)
        return out
    except Exception:
        return []


# console.log phase lines -> (event type, regex capturing fields)
_RE_START = re.compile(r"=== Scan started \(id=[^,]+,\s+targets=(?P<targets>[^,]+),")
_RE_DELEGATE = re.compile(r"Delegating scan to scanner agent '(?P<agent>[^']+)'")
_RE_HOST_UPD = re.compile(r"(?P<ip>[\d.]+):\s+(?P<ports>\d+) open port\(s\) \(fingerprint\)")
_RE_AGENT_DONE = re.compile(r"=== Agent scan done: (?P<hosts>\d+) hosts reported ===")
_RE_COMPLETE = re.compile(r"=== (?:Re-verify complete|Scan completed): (?P<hosts>\d+) hosts")
_RE_FAILED = re.compile(r"=== (?:Re-verify FAILED|Scan FAILED):")
_RE_STOPPED = re.compile(r"=== (?:Re-verify stopped|Scan stopped)")


def _replay_from_console(scan_id) -> list:
    """Build a minimal activity timeline for a finished scan from its console
    log, so previously-completed scans still show a sensible history.

    Terminal events (completed/failed/stopped) are always placed at the end so
    the timeline reads top-down as STARTED → UPDATED → … → COMPLETED, matching
    how a live feed would have unfolded."""
    try:
        from .scan_worker import read_console_log
        started = None
        events = []
        terminal = None
        last_ts = None
        agent_hosts = None

        for line in read_console_log(scan_id):
            text = line.get("line") or ""
            ts = line.get("ts") or datetime.now(timezone.utc).isoformat()
            last_ts = ts

            if terminal:
                continue  # nothing after the terminal line matters

            if started is None:
                m = _RE_START.search(text)
                if m:
                    try:
                        targets = [t.strip().strip("'\"") for t in m.group("targets").split(",")]
                    except Exception:
                        targets = None
                    started = {"type": "scan_started", "ts": ts, "scan_id": str(scan_id)}
                    if targets:
                        started["targets"] = targets
                    events.append(started)
                    continue

            m = _RE_DELEGATE.search(text)
            if m:
                events.append({"type": "scan_delegated", "ts": ts, "scan_id": str(scan_id), "agent": m.group("agent")})
                continue
            m = _RE_AGENT_DONE.search(text)
            if m:
                agent_hosts = int(m.group("hosts"))
                continue
            m = _RE_HOST_UPD.search(text)
            if m:
                events.append({
                    "type": "host_updated",
                    "ts": ts,
                    "scan_id": str(scan_id),
                    "ip": m.group("ip"),
                    "ports_count": int(m.group("ports")),
                })
                continue
            m = _RE_COMPLETE.search(text)
            if m:
                terminal = {"type": "scan_completed", "ts": ts, "scan_id": str(scan_id),
                            "hosts_discovered": int(m.group("hosts")), "progress_pct": 100}
                continue
            m = _RE_FAILED.search(text)
            if m:
                terminal = {"type": "scan_failed", "ts": ts, "scan_id": str(scan_id)}
                continue
            m = _RE_STOPPED.search(text)
            if m:
                terminal = {"type": "scan_stopped", "ts": ts, "scan_id": str(scan_id)}
                continue

        if terminal is None and (events or agent_hosts):
            # Agent-delegated scans log no real completion line: synthesize one
            # at the final console timestamp (same 100% the DB records).
            terminal = {"type": "scan_completed", "ts": last_ts, "scan_id": str(scan_id),
                        "hosts_discovered": agent_hosts, "progress_pct": 100}
        if terminal is not None:
            events.append(terminal)
        return events
    except Exception:
        return []