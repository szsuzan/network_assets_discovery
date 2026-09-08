"""Idempotent SQL migration runner.

Applied automatically at backend startup (see app.main). Each migration runs
inside its own transaction and is recorded in `schema_version`; re-running the
runner is a cheap no-op because already-applied versions are skipped. Files are
ordered numerically (001, 002, ...).
"""
import logging
import os
import re
from pathlib import Path

import psycopg2

from ..config import get_settings

log = logging.getLogger("migrations")

# backend/app/services → backend/app  → migrations folder lives one level above
# the app package at <repo>/database/migrations. Overridable for containers that
# mount it elsewhere (e.g. /app/database/migrations).
MIGRATIONS_DIR = Path(
    os.environ.get(
        "MIGRATIONS_DIR",
        str(Path(__file__).resolve().parents[2] / "database" / "migrations"),
    )
)

_NUM_RE = re.compile(r"^(\d+)_")


def _versions_applied(conn) -> set:
    with conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_version ("
            "  version TEXT PRIMARY KEY,"
            "  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        )
        conn.commit()
        cur.execute("SELECT version FROM schema_version")
        return {row[0] for row in cur.fetchall()}


def _pending(conn) -> list:
    applied = _versions_applied(conn)
    if not MIGRATIONS_DIR.is_dir():
        log.warning("migrations dir not found: %s", MIGRATIONS_DIR)
        return []
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    pending = []
    for f in files:
        m = _NUM_RE.match(f.name)
        if not m:
            continue
        version = m.group(1)
        if version in applied:
            log.debug("skip %s (already applied)", f.name)
            continue
        pending.append((version, f))
    return pending


def run_migrations() -> None:
    """Apply pending migration files against the sync DB engine."""
    from ..services.db import sync_engine

    conn = sync_engine.raw_connection()
    try:
        for version, f in _pending(conn):
            sql = f.read_text(encoding="utf-8")
            log.info("applying migration %s", f.name)
            with conn.cursor() as cur:
                try:
                    cur.execute(sql)
                    cur.execute("INSERT INTO schema_version (version) VALUES (%s)", (version,))
                except Exception:
                    conn.rollback()
                    raise
            conn.commit()
        remaining = _pending(conn)
        if not remaining:
            log.info("migrations: up to date")
    finally:
        conn.close()