"""Global application settings.

Storage: a `system_settings` key/value table (JSONB values). The authoritative
list of keys, their human description and their default lives in
`SETTINGS_CATALOG` below — rows in the table override the catalog default.

Two access patterns:

  * Async routers call the `aget`/`table` helpers with their request session.
  * The sync Celery/Celery worker paths (scan_worker, agents post-analysis)
    use the `get`/`get_int`/`get_bool`/`get_float` helpers, which read through a
    small TTL cache so a long scan does not hit the DB on every nmap loop.
"""
from datetime import datetime, timezone
from time import monotonic

from sqlalchemy import select

from ..models import SystemSetting

# --------------------------------------------------------------------------- #
# Catalog
# --------------------------------------------------------------------------- #
# category_label -> human heading for the Settings page (grouped, in order).
CATEGORY_LABELS = [
    ("scan", "Scan defaults"),
    ("execution", "Scan execution"),
    ("agent", "Agent delegation"),
    ("reverify", "Re-scan (re-verify)"),
    ("nmap", "Nmap / NSE / SNMP"),
]


def _s(key, category, label, description, type, default, options=None):
    return {
        "key": key,
        "category": category,
        "label": label,
        "description": description,
        "type": type,
        "default": default,
        "options": options,
    }


SETTINGS_CATALOG = [
    _s("scan.default_profile", "scan", "Default scan profile",
       "Profile the New Scan form (and the API when no profile is sent) starts with. "
       "quick/full/stealth scan top-1000/top-10000 at increasing throttle; passive_only runs no active probes.",
       "select", "quick", options=["quick", "full", "stealth", "passive_only"]),
    _s("scan.default_port_range", "scan", "Default port range",
       "Port range the New Scan form (and the API when none is sent) starts with, e.g. '1-10000'.",
       "text", "1-10000"),
    _s("scan.default_protocol", "scan", "Default protocol",
       "TCP or UDP for the default scan method.", "select", "tcp", options=["tcp", "udp"]),

    _s("execution.phase2_concurrency", "execution", "Port-scan concurrency",
       "Parallel per-host nmap processes in the container port-scan phase (Phase 2).",
       "number", 10),
    _s("execution.phase2_min_rate", "execution", "Port-scan min-rate",
       "nmap --min-rate for the container Phase 2 connect scan (packets/sec).",
       "number", 500),
    _s("execution.phase2_host_timeout", "execution", "Port-scan host timeout (s)",
       "nmap --host-timeout for the container Phase 2 scan; caps how long one slow host can stall the phase.",
       "number", 75),
    _s("execution.fingerprint_host_timeout", "execution", "Fingerprint host timeout (s)",
       "nmap --host-timeout for the container -sV/-O fingerprint phase.",
       "number", 300),
    _s("execution.tcp_probe_timeout", "execution", "Liveness probe timeout (s)",
       "Per-port connect timeout in the quick TCP liveness probe.",
       "number", 1.0),

    _s("agent.delegation_enabled", "agent", "Agent delegation",
       "Master switch: hand scans/re-verifies to a registered scanner agent when one "
       "covers the target LAN (ARP + SYN + exact -O). Off forces in-worker scanning.",
       "boolean", True),
    _s("agent.online_window_seconds", "agent", "Agent heartbeat window (s)",
       "How recently an agent must have heartbeated to be considered online/delegatable.",
       "number", 90),
    _s("agent.workers", "agent", "Agent parallel workers",
       "Per-host nmap concurrency used by the agent on scans and re-verifies.",
       "number", 5),

    _s("reverify.recheck_down_hosts", "reverify", "Re-check down hosts",
       "Default for re-scan: re-ARP/TCP-probe hosts that the previous pass marked down.",
       "boolean", True),
    _s("reverify.sweep_remaining_ports", "reverify", "Sweep remaining ports",
       "Default for re-scan: probe ports the previous pass did not already check on up hosts.",
       "boolean", True),
    _s("reverify.min_interval_seconds", "reverify", "Minimum re-scan interval (s)",
       "Minimum idle gap required before a new re-verify can start (0 disables the check).",
       "number", 0),

    _s("nmap.port_scripts", "nmap", "Extra per-port NSE scripts",
       "JSON map of port -> extra comma-separated NSE script ids merged over the built-in "
       "per-port script table (e.g. {\"8080\": \"http-title,http-methods\"}).",
       "json", {}),
    _s("nmap.snmp_community", "nmap", "SNMP community",
       "Community string used for SNMP system enumeration.", "text", "public"),
    _s("nmap.snmp_timeout", "nmap", "SNMP timeout (s)",
       "Per-OID timeout for SNMP system enumeration.", "number", 3.0),
]

CATALOG_BY_KEY = {c["key"]: c for c in SETTINGS_CATALOG}


# --------------------------------------------------------------------------- #
# Validation / coercion (writes)
# --------------------------------------------------------------------------- #
def coerce_value(key: str, value):
    spec = CATALOG_BY_KEY.get(key)
    if spec is None:
        raise KeyError(f"unknown setting '{key}'")
    t = spec["type"]
    if t == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if t == "number":
        f = float(value)
        return int(f) if float(f).is_integer() else f
    if t == "select":
        if value not in (spec.get("options") or []):
            raise ValueError(f"'{key}' must be one of {', '.join(spec['options'])}")
        return value
    if t == "json":
        if isinstance(value, str):
            import json as _json
            return _json.loads(value)
        return value
    return value


async def set_values(db, updates: dict) -> None:
    """Validate + upsert the given key/value pairs (values are coerced to the
    catalog type). Raises KeyError/ValueError on invalid input."""
    rows = {r.key: r for r in (await db.execute(select(SystemSetting))).scalars().all()}
    for key, value in updates.items():
        value = coerce_value(key, value)
        row = rows.get(key)
        if row is None:
            db.add(SystemSetting(key=key, value=value))
        else:
            row.value = value
            row.updated_at = datetime.now(timezone.utc)
    await db.commit()
    invalidate_cache(list(updates))


async def asnapshot(db) -> list[dict]:
    rows = {r.key: r.value for r in (await db.execute(select(SystemSetting))).scalars().all()}
    out = []
    for cat_code, cat_name in CATEGORY_LABELS:
        for c in SETTINGS_CATALOG:
            if c["category"] != cat_code:
                continue
            item = dict(c)
            item["category_label"] = cat_name
            item["value"] = rows.get(c["key"], c["default"])
            out.append(item)
    return out


async def aget(db, key: str, default=None):
    if key not in CATALOG_BY_KEY:
        return default
    row = (await db.execute(select(SystemSetting).where(SystemSetting.key == key))).scalar_one_or_none()
    return row.value if row else default


# --------------------------------------------------------------------------- #
# Sync cache for worker paths (Celery tasks run sync SQLAlchemy sessions)
# --------------------------------------------------------------------------- #
_CACHE: dict[str, tuple] = {}
_CACHE_TTL = 8.0


def _load_cache():
    try:
        from ..database import SessionLocal
        s = SessionLocal()
        try:
            rows = s.execute(select(SystemSetting)).scalars().all()
        finally:
            s.close()
    except Exception:
        return
    exp = monotonic() + _CACHE_TTL
    live = {r.key for r in rows}
    for r in rows:
        _CACHE[r.key] = (r.value, exp)
    for k in list(_CACHE):
        if k not in live:
            del _CACHE[k]


def _raw(key: str, default=None):
    entry = _CACHE.get(key)
    if entry is None or entry[1] < monotonic():
        _load_cache()
        entry = _CACHE.get(key)
    if entry is None:
        return default
    return entry[0]


def invalidate_cache(keys=None):
    if keys is None:
        _CACHE.clear()
    else:
        for k in keys:
            _CACHE.pop(k, None)


def get(key: str, default=None):
    if key not in CATALOG_BY_KEY:
        return default
    return _raw(key, default)


def get_int(key: str, default: int):
    spec = CATALOG_BY_KEY.get(key)
    if not spec or spec["type"] not in ("number",):
        return default
    v = _raw(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return int(default)


def get_float(key: str, default: float):
    spec = CATALOG_BY_KEY.get(key)
    if not spec or spec["type"] != "number":
        return default
    v = _raw(key, default)
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(default)


def get_bool(key: str, default: bool):
    spec = CATALOG_BY_KEY.get(key)
    if not spec or spec["type"] != "boolean":
        return default
    v = _raw(key, default)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on")
    return bool(v)