"""Collapse duplicate hosts into one canonical row, then re-classify the scan.

A physical device seen on several IPs (Wi-Fi + Ethernet, privacy MAC rotation,
dual-stack) creates one Host row per IP. This script folds every group that
shares a non-generic published hostname into a single canonical Host: ports,
SNMP and findings are moved to the canonical row, extra IPs go into
Host.secondary_ips and MACs into Host.macs, and the sub-rows are deleted.
It then re-runs device classification (also fixing gateway typing) and risk
rules so the report reflects the collapsed inventory.

Usage (inside the backend container):
    python merge_duplicate_hosts.py [scan_id]

Prints merged groups and a before/after histogram. Idempotent: groups of one
are left untouched.
"""
import sys
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.models import Host, Finding, Scan
from app.services.db import SessionLocal
from app.services.identity import identity_hostname
from app.services.scan_worker import (
    classify_device_type, run_risk_rules, capture_topology,
)


def histogram(hosts):
    counts = {}
    for h in hosts:
        key = h.device_type or "unknown"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def resolve_scan(db):
    scan_id = sys.argv[1] if len(sys.argv) > 1 else None
    if scan_id:
        return db.scalar(select(Scan).where(Scan.id == UUID(scan_id)))
    return db.scalar(select(Scan).order_by(Scan.started_at.desc()).limit(1))


def main():
    with SessionLocal() as db:
        scan = resolve_scan(db)
        if not scan:
            print("no scan found")
            return

        hosts = db.scalars(
            select(Host)
            .options(selectinload(Host.ports), selectinload(Host.snmp))
            .where(Host.scan_id == scan.id)
        ).all()
        before = histogram(hosts)
        n_before = len(hosts)

        groups = {}
        for h in hosts:
            p = identity_hostname(h.hostname)
            if p:
                groups.setdefault(p, []).append(h)

        merged = 0
        ports_moved = 0
        findings_moved = 0

        def _rank(h):
            rich = 0 if (h.device_type and h.device_type != "unknown") else 1
            return (rich, str(h.ip))

        for prof, members in groups.items():
            if len(members) < 2:
                continue
            members.sort(key=_rank)
            canon = members[0]
            for sub in members[1:]:
                canon_ports = {(p.port, p.protocol): p for p in canon.ports}
                for p in list(sub.ports):
                    key = (p.port, p.protocol)
                    cp = canon_ports.get(key)
                    if cp is None:
                        p.host_id = canon.id
                        canon.ports.append(p)
                        canon_ports[key] = p
                        ports_moved += 1
                    else:
                        if cp.state != "open" and p.state == "open":
                            cp.state = "open"
                        if p.service and not cp.service:
                            cp.service = p.service
                        if p.version and not cp.version:
                            cp.version = p.version
                        if p.banner and not cp.banner:
                            cp.banner = p.banner
                        db.delete(p)

                if sub.snmp:
                    if canon.snmp is None:
                        sub.snmp.host_id = canon.id
                        canon.snmp = sub.snmp
                    else:
                        db.delete(sub.snmp)

                res = db.execute(
                    update(Finding).where(Finding.host_id == sub.id).values(host_id=canon.id)
                )
                findings_moved += res.rowcount or 0

                sec = [str(x) for x in (list(canon.secondary_ips) if canon.secondary_ips else [])]
                if str(sub.ip) not in sec:
                    sec.append(str(sub.ip))
                canon.secondary_ips = sec

                macs = list(canon.macs or [])
                if sub.mac and str(sub.mac).lower() not in macs \
                   and str(canon.mac or "").lower() != str(sub.mac).lower():
                    macs.append(str(sub.mac))
                canon.macs = macs
                if sub.mac and not canon.mac:
                    canon.mac = sub.mac
                if sub.vendor and not canon.vendor:
                    canon.vendor = sub.vendor
                if sub.os_guess and not canon.os_guess:
                    canon.os_guess = sub.os_guess
                    canon.os_confidence = sub.os_confidence
                if sub.status == "up":
                    canon.status = "up"

                db.delete(sub)
                merged += 1
                print(f"  merged {prof}: {str(sub.ip)} -> {str(canon.ip)}")

        # Re-classify everything now identity is collapsed (also fixes gateway
        # typing), recompute risk findings and persist topology.
        hosts = db.scalars(
            select(Host)
            .options(selectinload(Host.ports), selectinload(Host.snmp))
            .where(Host.scan_id == scan.id)
        ).all()
        changed = 0
        for h in hosts:
            old = h.device_type
            classify_device_type(h)
            if h.device_type != old:
                changed += 1
        scan.hosts_discovered = sum(1 for h in hosts if h.status == "up")
        run_risk_rules(db, scan)
        capture_topology(db, scan)
        db.commit()

        after_hosts = db.scalars(
            select(Host).where(Host.scan_id == scan.id)
        ).all()
        after = histogram(after_hosts)

    print(f"scan {scan.id} ({scan.targets}): {n_before} -> {len(after_hosts)} hosts, "
          f"{merged} merged, {ports_moved} ports moved, {findings_moved} findings moved, "
          f"{changed} reclassified")
    print("Before:", before)
    print("After: ", after)


if __name__ == "__main__":
    main()