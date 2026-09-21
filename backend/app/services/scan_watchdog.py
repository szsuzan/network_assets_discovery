import asyncio
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from .db import SessionLocal
from ..models import Scan

# States that require live progress. Paused is deliberately excluded: a paused
# scan legitimately stays paused until the user resumes it.
ACTIVE_STATES = (
    "queued", "discovering", "scanning", "fingerprinting",
    "analyzing", "agent_running", "reverifying",
)

LOOP_INTERVAL_SECONDS = 60
DEFAULT_STALL_SECONDS = 20 * 60

# Some states take longer before work is visible. Queued scans waiting for a
# free worker get a wider berth so a healthy backlog isn't mistaken for a hang.
_STATE_MULTIPLIER = {
    "queued": 2,
    "agent_running": 2,
}


def _scan_dir(scan_id: str) -> Path:
    from .scan_worker import SCAN_OUTPUT_DIR
    return SCAN_OUTPUT_DIR / str(scan_id)


def _last_activity(scan: Scan, now: datetime) -> datetime:
    """Most recent evidence of live work: newest file mtime in the scan's output
    dir (console log, activity feed, per-host XML). Everything that actually
    advances a scan writes to that dir, so a frozen mtime means no progress.
    Falls back to the scan's own timestamps when nothing has been written yet.
    """
    base = _scan_dir(str(scan.id))
    newest = None
    try:
        if base.is_dir():
            for child in base.iterdir():
                try:
                    m = datetime.fromtimestamp(child.stat().st_mtime, tz=timezone.utc)
                    newest = m if newest is None else max(newest, m)
                except Exception:
                    continue
    except Exception:
        pass
    if newest is not None:
        return newest
    ref = scan.started_at or scan.created_at
    return ref if ref else now


def _reap_once() -> None:
    stale_after = DEFAULT_STALL_SECONDS
    try:
        from . import settings as settings_svc
        stale_after = settings_svc.get_int("execution.stall_timeout_seconds", DEFAULT_STALL_SECONDS)
    except Exception:
        pass

    now = datetime.now(timezone.utc)
    with SessionLocal() as sdb:
        rows = sdb.execute(select(Scan).where(Scan.status.in_(ACTIVE_STATES))).scalars().all()
        for scan in rows:
            idle = (now - _last_activity(scan, now)).total_seconds()
            threshold = stale_after * _STATE_MULTIPLIER.get(scan.status, 1)
            if idle > threshold:
                from .scan_worker import mark_scan_failed
                mark_scan_failed(
                    scan.id,
                    f"scan stalled (no progress for {int(idle)}s); auto-failed by watchdog",
                )


async def watchdog_loop() -> None:
    while True:
        try:
            _reap_once()
        except Exception:
            import traceback
            traceback.print_exc()
        await asyncio.sleep(LOOP_INTERVAL_SECONDS)


def start_watchdog(app) -> None:
    """Begin the periodic stuck-scan sweeper. Kept as a module-level task so the
    reloader does not spawn a fresh loop on every app worker restart."""
    if getattr(start_watchdog, "_task", None) is not None:
        return
    start_watchdog._task = asyncio.get_event_loop().create_task(watchdog_loop())