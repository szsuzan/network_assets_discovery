import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from ..database import get_db
from ..models import User, Scan, Host, Port, Finding, SNMPInfo, Engagement
from ..auth import get_current_user

router = APIRouter(prefix="/api/scans", tags=["exports"])

@router.get("/{scan_id}/export")
async def export_scan(
    scan_id: uuid.UUID,
    format: str = "json",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    hosts_result = await db.execute(select(Host).where(Host.scan_id == scan_id))
    hosts = [h for h in hosts_result.scalars().all() if h.status == "up"]
    
    findings_result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    host_by_id = {str(h.id): h for h in hosts}

    if format == "json":
        data = {
            "scan": {
                "id": str(scan.id),
                "targets": scan.targets,
                "profile": scan.profile,
                "port_range": scan.port_range,
                "status": scan.status,
                "kind": scan.kind,
                "hosts_total_in_scope": scan.hosts_total_in_scope,
                "hosts_discovered": scan.hosts_discovered,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "verified_at": scan.verified_at.isoformat() if scan.verified_at else None,
            },
            "hosts": [host_to_json(h) for h in hosts],
            "findings": [finding_to_json(f, host_by_id.get(str(f.host_id))) for f in findings]
        }
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'}
        )
    
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Device Type", "OS Guess", "OS Confidence",
                         "Status", "Discovery", "Ports", "Findings"])

        ports_map = {}
        for h in hosts:
            ports_result = await db.execute(select(Port).where(Port.host_id == h.id))
            ports_map[str(h.id)] = ", ".join(
                f"{p.port}/{p.protocol}({p.service or ''})" for p in ports_result.scalars().all()
            )
        
        findings_map = {}
        for f in findings:
            key = str(f.host_id) if f.host_id else ""
            suffix = f"{'' if f.included_in_report else ' [excluded]'}[{f.status}]"
            findings_map.setdefault(key, []).append(f"{f.severity}:{f.title}{suffix}")
        
        for h in hosts:
            writer.writerow([
                str(h.ip),
                str(h.mac) if h.mac else "",
                h.vendor or "",
                h.hostname or "",
                h.device_type or "",
                h.os_guess or "",
                h.os_confidence or "",
                h.status,
                ", ".join(h.discovery_method or []),
                ports_map.get(str(h.id), ""),
                "; ".join(findings_map.get(str(h.id), []))
            ])
        
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.csv"'}
        )
    
    elif format == "pdf":
        from ..services.report_generator import generate_report
        ports_lookup = {}
        for h in hosts:
            ports_result = await db.execute(select(Port).where(Port.host_id == h.id))
            ports_lookup[str(h.id)] = list(ports_result.scalars().all())
        eng_result = await db.execute(select(Engagement).where(Engagement.id == scan.engagement_id))
        engagement = eng_result.scalar_one_or_none()
        pdf_content = generate_report(scan, hosts, findings, ports_lookup, engagement)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="scan-report-{scan_id}.pdf"'}
        )
    
    raise HTTPException(status_code=400, detail="Invalid format. Use json, csv, or pdf.")

def host_to_json(h: Host) -> dict:
    return {
        "id": str(h.id),
        "ip": str(h.ip),
        "mac": str(h.mac) if h.mac else None,
        "vendor": h.vendor,
        "hostname": h.hostname,
        "device_type": h.device_type,
        "os_guess": h.os_guess,
        "os_confidence": h.os_confidence,
        "discovery_method": h.discovery_method or [],
        "status": h.status,
        "tags": h.tags or [],
        "notes": h.notes,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None
    }

def finding_to_json(f: Finding, host: Host = None) -> dict:
    return {
        "id": str(f.id),
        "scan_id": str(f.scan_id),
        "host_id": str(f.host_id) if f.host_id else None,
        "host_ip": str(host.ip) if host else None,
        "host_hostname": host.hostname if host else None,
        "host_device_type": host.device_type if host else None,
        "host_mac": str(host.mac) if host and host.mac else None,
        "severity": f.severity,
        "status": f.status,
        "type": f.type,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "cve_refs": f.cve_refs,
        "cwe": f.cwe,
        "cvss_score": f.cvss_score,
        "cvss_vector": f.cvss_vector,
        "port": f.port,
        "included_in_report": f.included_in_report,
        "notes": f.notes,
        "evidence": f.evidence,
    }
