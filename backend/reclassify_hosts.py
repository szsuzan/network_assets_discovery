"""Re-run device classification over existing hosts.

Usage (inside the backend container):
    python reclassify_hosts.py [scan_id]

Prints before/after type histograms. Idempotent and safe to re-run.
"""
import sys
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models import Host
from app.services.db import SessionLocal
from app.services.scan_worker import classify_device_type


def histogram(hosts):
    counts = {}
    for h in hosts:
        key = h.device_type or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def main():
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None
    query = select(Host).options(selectinload(Host.ports))
    if scan_id:
        query = query.where(Host.scan_id == UUID(scan_id))

    with SessionLocal() as db:
        hosts = db.scalars(query).all()
        before = histogram(hosts)
        changed = 0
        for h in hosts:
            old = h.device_type
            classify_device_type(h)
            if h.device_type != old:
                changed += 1
        db.commit()
        after = histogram(hosts)

    print(f"{len(hosts)} hosts ({scan_id or 'all scans'}): {changed} reclassified")
    print("Before:", before)
    print("After: ", after)


if __name__ == "__main__":
    main()