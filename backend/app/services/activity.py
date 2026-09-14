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
import threading
from datetime import datetime, timezone
from pathlib import Path

SCAN_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "scan_output"

# High-frequency/noisy events that are still useful live (progress ticks,
# raw nmap command output) are not replayed into the activity timeline.
# scan_progress is persisted but throttled (see _should_persist_progress);
# scan_phase entries are derived from console phase markers.
ACTIVITY_EVENT_TYPES = {
    "scan_started",
    "scan_paused",
    "scan_resumed",
    "scan_reverifying",
    "scan_delegated",
    "scan_completed",
    "scan_failed",
    "scan_stopped",
    "scan_progress",
    "scan_phase",
    "host_discovered",
    "host_updated",
    "finding_added",
}

MAX_LINES = 1200
TRIM_TO = 1000

# Throttling state for scan_progress persistence (per-process, keyed by scan).
_PROGRESS_LOCK = threading.Lock()
_LAST_PROGRESS: dict = {}  # scan_id -> (persisted_pct, persisted_iso)

# Minimal throttled progress ladder so a reloaded timeline still shows the
# shape of the scan without one row per percent tick.
_PROGRESS_STEPS = (0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75, 80, 85, 90, 95, 100)

# Console markers that announce phase transitions. Seen both from the package
# container ("--- Phase 2/3: Port scan ---") and from scanner agents via their
# streamed output line ("Phase 2/3: fast port scan (-sS) ..."). Each becomes a
# scan_phase timeline entry so reloaded feeds are not a wall of raw host events.
_PHASE_LINE = re.compile(
    r"(?:---\s*)?Phase\s+(?P<index>\d+)\s*/\s*(?P<total>\d+):\s*(?P<label>.+?)(?:\s+---\s*)?$",
    re.I,
)
_PHASE_COUNT_LINE = re.compile(r"Phase\s+\d+\s*/\s*\d+ done:\s*(?P<label>.+)$", re.I)
_PHASE_OTHER = [
    (re.compile(r"^---\s*Analyzing:\s*(?P<label>.+)\s*---$", re.I), None, None, None),
    (re.compile(r"^=== Agent scan started.*===$"), None, None, "Agent scan started (delegated)"),
    (re.compile(r"=== Agent scan done:\s*(?P<label>\d+ hosts reported)\s*==="), None, None, None),
    (re.compile(r"^---\s*Fingerprinting newly-found hidden ports\s*---$"), None, None, "Fingerprinting newly-found hidden ports"),
    (re.compile(r"^=== Re-verify scan started\s*==="), None, None, "Re-verify scan started"),
    (re.compile(r"^---\s*Phase 0/3:\s*(?P<label>.+?)\s*---$", re.I), "0", "3", None),
]


def _phase_from_console_line(line: str):
    """Map a console phase marker to a scan_phase timeline event, or None."""
    text = (line or "").strip()
    if not text:
        return None
    for regex, idx, total, static in _PHASE_OTHER:
        m = regex.search(text)
        if m:
            label = (m.group("label") if "label" in (m.groupdict() or {}) else "") or ""
            label = label.strip() or static or text.strip(" =-·")
            return {
                "type": "scan_phase",
                "scan_id": None,
                "label": label,
                "index": idx,
                "total": total,
            }
    m = _PHASE_LINE.search(text)
    if not m:
        m = _PHASE_COUNT_LINE.search(text)
    if m:
        label = m.group("label").strip()
        if "done:" in line.lower():
            label = f"{label} (complete)"
        return {
            "type": "scan_phase",
            "scan_id": None,
            "label": label,
            "index": m.groupdict().get("index"),
            "total": m.groupdict().get("total"),
        }
    return None


def _activity_file(scan_id) -> Path:
    d = SCAN_OUTPUT_DIR / str(scan_id)
    return d / "activity.jsonl"


def append_activity(scan_id, event: dict):
    """Append a scan event to the activity feed. Best-effort; no-op for event
    types that are too noisy for a timeline. Console lines that announce a scan
    phase are persisted as compact scan_phase timeline entries."""
    ev_type = event.get("type")
    if ev_type == "cmd_log":
        phase = _phase_from_console_line(event.get("line") or "")
        if not phase:
            return
        _append_line(scan_id, {**phase, "scan_id": str(scan_id), "ts": event.get("ts")})
        return
    if ev_type not in ACTIVITY_EVENT_TYPES:
        return
    if ev_type == "scan_progress" and not _should_persist_progress(scan_id, event):
        return
    try:
        line = {**event}
        if not line.get("ts"):
            line["ts"] = datetime.now(timezone.utc).isoformat()
        line.pop("_persisted", None)
        _append_line(scan_id, line)
    except Exception:
        pass


def _should_persist_progress(scan_id, event) -> bool:
    """Persist progress only at staircase milestones (every 5 points), always
    at 100, and never more often than once per 10s to keep the feed tidy."""
    try:
        pct = int(event.get("progress_pct") or 0)
    except Exception:
        return False
    if pct >= 100:
        return True
    try:
        with _PROGRESS_LOCK:
            last_pct, last_ts = _LAST_PROGRESS.get(str(scan_id), (None, None))
            if last_ts:
                try:
                    last_dt = datetime.fromisoformat(last_ts)
                except Exception:
                    last_dt = None
                if last_dt and (datetime.now(timezone.utc) - last_dt).total_seconds() < 10:
                    return False
            step = max(p for p in _PROGRESS_STEPS if p <= pct)
            if last_pct is not None and step <= last_pct:
                return False
            _LAST_PROGRESS[str(scan_id)] = (step, datetime.now(timezone.utc).isoformat())
            return True
    except Exception:
        return True


def _append_line(scan_id, line: dict):
    try:
        p = _activity_file(scan_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
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
        # Backfill phase/progress anchors for scans whose JSONL predates the
        # scan_phase/scan_progress extensions (or that ran before this code).
        if not any(e.get("type") in ("scan_phase", "scan_progress") for e in out):
            merged = _merge_backfill(scan_id, out)
            if merged and len(merged) > len(out):
                try:
                    p = _activity_file(scan_id)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    with open(p, "w", encoding="utf-8") as f:
                        for ev in merged:
                            f.write(json.dumps(ev) + "\n")
                except Exception:
                    pass
                return merged
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


def _merge_backfill(scan_id, existing: list) -> list:
    """Merge console-derived phase/progress anchors into an existing feed that
    predates those event types, keeping event type + timestamp order."""
    derived = _replay_phases_from_console(scan_id)
    if not derived:
        return existing
    seen = set()
    for e in existing:
        key = (e.get("type"), e.get("ts"), e.get("ip") or e.get("host_id") or e.get("label") or "")
        seen.add(key)
    merged = list(existing)
    added = 0
    for e in derived:
        key = (e.get("type"), e.get("ts"), e.get("ip") or e.get("host_id") or e.get("label") or "")
        if key in seen:
            continue
        seen.add(key)
        merged.append(e)
        added += 1
    merged.sort(key=lambda e: e.get("ts") or "")
    return merged if added else existing


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


def _replay_phases_from_console(scan_id) -> list:
    """Derive scan_phase timeline entries from a scan's console log phase
    markers, in log order. Used to backfill feeds that predate the phase or
    progress event types."""
    try:
        from .scan_worker import read_console_log
        phases = []
        for line in read_console_log(scan_id):
            text = line.get("line") or ""
            ts = line.get("ts") or datetime.now(timezone.utc).isoformat()
            ph = _phase_from_console_line(text)
            if ph:
                ev = {**ph, "scan_id": str(scan_id), "ts": ts}
                phases.append(ev)
        # De-dupe consecutive identical labels under a single timestamp burst
        # (e.g. agent echoes the phase line once it starts and again when done).
        return phases
    except Exception:
        return []


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
        # Interleave console-derived phase anchors at their real timestamps so a
        # reloaded timeline carries the same phase structure a live feed shows.
        phases = _replay_phases_from_console(scan_id)
        if phases:
            events.extend(phases)
            events.sort(key=lambda e: e.get("ts") or "")
        return events
    except Exception:
        return []