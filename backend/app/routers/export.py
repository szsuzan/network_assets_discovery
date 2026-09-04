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
    
    if format == "json":
        data = {
            "scan": {
                "id": str(scan.id),
                "targets": scan.targets,
                "profile": scan.profile,
                "status": scan.status
            },
            "hosts": [host_to_json(h) for h in hosts],
            "findings": [finding_to_json(f) for f in findings]
        }
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'}
        )
    
    elif format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["IP", "MAC", "Vendor", "Hostname", "Device Type", "OS Guess", "Status", "Ports", "Findings"])
        
        ports_map = {}
        for h in hosts:
            ports_result = await db.execute(select(Port).where(Port.host_id == h.id))
            ports_map[str(h.id)] = ", ".join(
                f"{p.port}/{p.protocol}" for p in ports_result.scalars().all()
            )
        
        findings_map = {}
        for f in findings:
            key = str(f.host_id) if f.host_id else ""
            findings_map.setdefault(key, []).append(f"{f.severity}:{f.title}")
        
        for h in hosts:
            writer.writerow([
                str(h.ip),
                str(h.mac) if h.mac else "",
                h.vendor or "",
                h.hostname or "",
                h.device_type or "",
                h.os_guess or "",
                h.status,
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
        pdf_content = generate_report(scan, hosts, findings, ports_lookup)
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
        "status": h.status,
        "tags": h.tags,
        "notes": h.notes
    }

def finding_to_json(f: Finding) -> dict:
    return {
        "id": str(f.id),
        "severity": f.severity,
        "type": f.type,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "cve_refs": f.cve_refs,
        "port": f.port
    }
