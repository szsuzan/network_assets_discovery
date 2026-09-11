"""Offline NVD CPE -> CVE catalog and matcher.

Import NVD CVE JSON (both the devel API shape ``{"vulnerabilities": [...]}``
and the classic feed shape ``{"CVE_Items": [...]}``) into ``cve_catalog`` /
``cve_catalog_cpe``. At analysis time ``match_cve_catalog`` compares each
fingerprinted port CPE against the stored rows without any network call.
"""
import json
import re
from sqlalchemy import select

from ..models import CVECatalog, CVECatalogCPE

_NVD_SCORE_KEYS = ("baseScore", "baseMetricScore", "impactScore")


def normalize_cpe(cpe: str) -> dict | None:
    """Parse a CPE 2.2 (``cpe:/a:v:p:...``) or CPE 2.3 (``cpe:2.3:a:...``)
    URI into {part, vendor, product, version}. Returns None when unparsable."""
    if not cpe:
        return None
    cpe = cpe.strip()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition...
        if len(parts) < 6:
            return None
        return {
            "part": parts[2] or "*",
            "vendor": parts[3] if len(parts) > 3 and parts[3] != "*" else "",
            "product": parts[4] if len(parts) > 4 and parts[4] != "*" else "",
            "version": parts[5] if len(parts) > 5 and parts[5] not in ("*", "") else None,
        }
    # CPE 2.2: cpe:/<part>:<vendor>:<product>:<version>:...
    m = re.match(r"^cpe:/(.+)$", cpe)
    if not m:
        return None
    parts = m.group(1).split(":")
    part = parts[0] if parts else ""
    vendor = parts[1] if len(parts) > 1 else ""
    product = parts[2] if len(parts) > 2 else ""
    version = parts[3] if len(parts) > 3 and parts[3] not in ("*", "") else None
    if not vendor and not product:
        return None
    return {
        "part": part or "*",
        "vendor": vendor,
        "product": product,
        "version": version,
    }


def _version_tokens(version: str) -> list:
    """Split a version into comparable numeric/alpha tokens."""
    return [t for t in re.split(r"[._\-+~]", version.strip().lower()) if t]


def _token_int(tok: str):
    m = re.match(r"^(\d+)", tok)
    return int(m.group(1)) if m else None


def version_compare(a: str, b: str) -> int:
    """Compare two version strings -> -1/0/1. Best-effort numeric compare with
    alpha suffix fallback (no pip packaging available in this image)."""
    if a == b:
        return 0
    ta, tb = _version_tokens(a), _version_tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else ""
        y = tb[i] if i < len(tb) else ""
        if not y:
            return 1
        if not x:
            return -1
        ix, iy = _token_int(x), _token_int(y)
        if ix is not None and iy is not None:
            x, y = ix, iy
        if x == y:
            continue
        return 1 if x > y else -1
    return 0


def _cvss_from_metrics(metrics: dict) -> tuple:
    """Extract (score, vector, severity) from NVD 2.0 ``metrics`` or fall back
    to the classic ``impact.baseMetricV3`` block."""
    if isinstance(metrics, dict):
        for kind in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            block = metrics.get(kind)
            if not isinstance(block, list) or not block:
                continue
            cvss = block[0].get("cvssData") or {}
            score = cvss.get("baseScore")
            vector = cvss.get("vectorString")
            severity = _normalize_severity(cvss.get("baseSeverity")
                                           or block[0].get("baseSeverity")
                                           or _score_severity(score))
            if score is not None:
                return float(score), vector, severity
    return None, None, None


_NVD_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "concerning",
    "MEDIUM": "notable",
    "LOW": "info",
    "NONE": "info",
}


def _normalize_severity(sev) -> str | None:
    if not sev:
        return None
    return _NVD_SEVERITY_MAP.get(str(sev).upper()) or sev


def _score_severity(score) -> str | None:
    if score is None:
        return None
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "concerning"
    if score >= 4.0:
        return "notable"
    return "info"


def _cpe_match_rows(node) -> list:
    """Recursively walk an NVD configuration node collecting cpeMatch entries."""
    rows = []
    for cm in (node.get("cpeMatch") or []):
        if not cm.get("vulnerable", True):
            continue
        criteria = cm.get("criteria") or cm.get("cpe23Uri")
        if not criteria:
            continue
        rows.append((criteria, cm))
    for child in (node.get("children") or []):
        rows.extend(_cpe_match_rows(child))
    return rows


def import_nvd_cve(db, cve: dict) -> CVECatalog | None:
    """Upsert one NVD CVE item (2.0 ``vulnerability.cve`` or 1.1 ``cve``)
    into the catalog. Returns the created/updated CVECatalog row."""
    cve_id = (cve.get("id")
              or (cve.get("cve") or {}).get("CVE_data_meta", {}).get("ID")
              or cve.get("cveId"))
    if not cve_id or not cve_id.startswith("CVE-"):
        return None

    existing = db.execute(
        select(CVECatalog).where(CVECatalog.cve_id == cve_id)
    ).scalar_one_or_none()

    # ---- descriptions / titles -----------------------------------------
    descriptions = (cve.get("descriptions")
                    or (cve.get("cve") or {}).get("description", {}).get("description_data", []))
    if isinstance(descriptions, list):
        descriptions = [d.get("value") for d in descriptions
                        if d.get("lang") in ("en", None)]
    description = next((d for d in descriptions if d), None)

    title = None
    if "title" in cve and cve["title"]:
        title = cve["title"]

    # ---- CWE -------------------------------------------------------------
    cwes = []
    for p in (cve.get("weaknesses") or []):
        for w in (p.get("description") or []):
            if w.get("value") and w["value"].startswith("CWE-"):
                cwes.append(w["value"])
    if not cwes:
        problemtype = (cve.get("cve") or {}).get("problemtype", {}).get("problemtype_data", [])
        for p in problemtype:
            for d in (p.get("description") or []):
                if d.get("value") and "CWE" in d["value"]:
                    cwes.append(d["value"])

    # ---- metrics ---------------------------------------------------------
    metrics = cve.get("metrics") or ((cve.get("cve") or {}).get("impact") or {})
    score, vector, severity = _cvss_from_metrics(metrics)
    if score is None:
        impact = (cve.get("cve") or {}).get("impact") or {}
        score, vector, severity = _cvss_from_metrics(impact)
    if severity is None:
        severity = _score_severity(score)

    # ---- references ------------------------------------------------------
    refs = []
    for r in (cve.get("references") or []):
        url = r.get("url")
        if url:
            refs.append(url)
    references = (cve.get("cve") or {}).get("references", {}).get("reference_data", [])
    for r in references:
        if r.get("url"):
            refs.append(r["url"])

    if existing:
        existing.title = title or existing.title
        existing.description = description or existing.description
        existing.cwe = (cwes[0] if cwes else None) or existing.cwe
        existing.cvss_score = score if score is not None else existing.cvss_score
        existing.cvss_vector = vector or existing.cvss_vector
        existing.severity = severity or existing.severity
        existing.reference_urls = list(dict.fromkeys(refs)) or existing.reference_urls
        row = existing
        for old_cpe in list(existing.cpes):
            db.delete(old_cpe)
    else:
        row = CVECatalog(
            cve_id=cve_id,
            title=title,
            description=description or None,
            cwe=cwes[0] if cwes else None,
            cvss_score=score,
            cvss_vector=vector,
            severity=severity,
            reference_urls=list(dict.fromkeys(refs)),
            source="nvd",
        )
        db.add(row)
    db.flush()  # populate row.id for the FK below

    # ---- CPE configuration nodes ---------------------------------------
    config = (cve.get("configurations")
              or (cve.get("cve") or {}).get("configurations"))
    if isinstance(config, dict):
        config = [config]
    nodes = []
    for cfg in (config or []):
        if isinstance(cfg, dict):
            nodes.extend(cfg.get("nodes") or [])
    seen_criteria = set()
    for node in nodes:
        for criteria, cm in _cpe_match_rows(node):
            if criteria in seen_criteria:
                continue
            seen_criteria.add(criteria)
            parsed = normalize_cpe(criteria)
            if not parsed:
                continue
            bound_fields = {
                "version_start_including": cm.get("versionStartIncluding"),
                "version_end_including": cm.get("versionEndIncluding"),
                "version_start_excluding": cm.get("versionStartExcluding"),
                "version_end_excluding": cm.get("versionEndExcluding"),
            }
            explicit_version = parsed["version"]
            has_bounds = any(bound_fields.values())
            match_all = (not explicit_version and not has_bounds)
            db.add(CVECatalogCPE(
                cve_id=row.id,
                part=parsed["part"],
                vendor=parsed["vendor"],
                product=parsed["product"],
                version=explicit_version,
                match_all=match_all,
                cpe23=criteria,
                **{k: v for k, v in bound_fields.items()},
            ))
    # rows with no nodes at all: keep the row (title/desc only).
    db.flush()
    return row


def import_nvd_feed(db, text: str) -> int:
    """Import a full NVD JSON feed or a single-item JSON. Returns rows imported."""
    data = json.loads(text)
    items = data.get("vulnerabilities") or data.get("CVE_Items") or []
    if isinstance(items, dict):
        items = [items]
    count = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        cve_payload = item["cve"] if isinstance(item.get("cve"), dict) else item
        if not (cve_payload.get("id") or cve_payload.get("cveId")):
            continue
        count += 1
        import_nvd_cve(db, cve_payload)
    db.commit()
    return count


def _version_in_range(endpoint_version, row: CVECatalogCPE) -> bool:
    """True when the endpoint's version satisfies this catalog row's bounds.

    A row with match_all=True (no version info in the vuln record) hits any
    endpoint that only identified the (part, vendor, product), which is the
    intended behaviour of 'all versions vulnerable'.
    """
    if not endpoint_version:
        return row.match_all
    if row.match_all:
        return True
    if row.version is not None and version_compare(endpoint_version, row.version) == 0:
        return True
    if row.version_start_including and version_compare(endpoint_version, row.version_start_including) < 0:
        return False
    if row.version_start_excluding and version_compare(endpoint_version, row.version_start_excluding) <= 0:
        return False
    if row.version_end_including and version_compare(endpoint_version, row.version_end_including) > 0:
        return False
    if row.version_end_excluding and version_compare(endpoint_version, row.version_end_excluding) >= 0:
        return False
    return True


def match_cve_catalog(db, endpoint_cpes: list) -> list[dict]:
    """Match a list of CPE strings (as stored on a port) against the catalog.

    Returns list of {cve_id, title, description, severity, cvss_score,
    cvss_vector, cwe, references} sorted by severity/score descending. De-dupes
    by CVE id across multiple matching CPE rows.
    """
    out = {}
    for cpe in endpoint_cpes or []:
        parsed = normalize_cpe(cpe)
        if not parsed:
            continue
        rows = db.execute(
            select(CVECatalogCPE).join(CVECatalog)
            .where(
                CVECatalogCPE.part == parsed["part"],
                CVECatalogCPE.vendor == parsed["vendor"],
                CVECatalogCPE.product == parsed["product"],
            )
        ).scalars().all()
        for row in rows:
            if not _version_in_range(parsed["version"], row):
                continue
            cve = row.cve
            if cve is None:
                continue
            if cve.cve_id in out:
                continue
            out[cve.cve_id] = {
                "cve_id": cve.cve_id,
                "title": cve.title,
                "description": cve.description,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "cvss_vector": cve.cvss_vector,
                "cwe": cve.cwe,
                "reference_urls": cve.reference_urls or [],
            }
    return sorted(out.values(), key=lambda c: (c["cvss_score"] or 0, c["cve_id"]), reverse=True)


def main(argv=None) -> None:
    """CLI: import an NVD JSON/GZ feed file into the catalog.

    Usage: python -m app.services.cve_catalog <file.json[.gz]>
    """
    import gzip
    import sys

    from ..services.db import SessionLocal

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        sys.exit(1)
    path = argv[0]
    with gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, encoding="utf-8") as fh:
        text = fh.read()
    db = SessionLocal()
    try:
        n = import_nvd_feed(db, text)
        print(f"imported {n} CVE record(s) from {path}")
    finally:
        db.close()


if __name__ == "__main__":
    main()