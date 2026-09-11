"""Generate the client-ready discovery report as a PDF via WeasyPrint.

Falls back to a minimal valid PDF if WeasyPrint is not installed (e.g. minimal
deployments) so that the export endpoint never 500s.
"""
import html
from datetime import datetime

SEVERITY_LABEL = {
    "info": "Info",
    "notable": "Notable",
    "concerning": "Concerning",
    "critical": "Critical",
}

SEVERITY_COLOR = {
    "info": "#8B95A1",
    "notable": "#E0B341",
    "concerning": "#E08341",
    "critical": "#E04B4B",
}

DEVICE_TYPE_LABEL = {
    "router": "Router / Gateway",
    "switch": "Switch",
    "firewall": "Firewall",
    "wireless_access_point": "Wireless Access Point",
    "workstation": "Workstation",
    "laptop": "Laptop",
    "smartphone": "Smartphone",
    "tablet": "Tablet",
    "physical_server": "Physical Server",
    "virtual_machine": "Virtual Machine",
    "nas": "NAS",
    "printer": "Network Printer / Copier",
    "voip_phone": "VoIP Phone",
    "conference": "Conference / Media System",
    "smart_tv": "Smart TV / Streaming Device",
    "camera": "IP Camera / NVR",
    "iot": "Smart Appliance / IoT",
    "smart_speaker": "Virtual Assistant / Smart Speaker",
    "unknown": "Unidentified Host",
    "access_control": "Access Control",
    # legacy keys from scans before the granular taxonomy
    "network_gear": "Router / Gateway",
    "mobile": "Smartphone",
    "server": "Physical Server",
    "camera_ip": "IP Camera / NVR",
}

SEVERITY_ORDER = {"critical": 0, "concerning": 1, "notable": 2, "info": 3}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _device_breakdown(hosts):
    counts = {}
    for h in hosts:
        key = DEVICE_TYPE_LABEL.get(h.device_type, "Unknown")
        counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items(), key=lambda x: -x[1])


def _findings_by_severity(findings):
    counts = {"critical": 0, "concerning": 0, "notable": 0, "info": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _risk_index(findings) -> int:
    """0-100 weighted disturbance index so the cover tells a story at a glance."""
    weights = {"critical": 10, "concerning": 6, "notable": 3, "info": 1}
    if not findings:
        return 0
    score = sum(weights.get(f.severity, 1) for f in findings)
    return max(1, min(100, round(score / (10 * len(findings)) * 100)))


FINDING_STATUS_LABEL = {
    "open": "Open",
    "triaged": "Triaged",
    "confirmed": "Confirmed",
    "remediation_in_progress": "In Remediation",
    "retest": "Ready for Retest",
    "resolved": "Resolved",
    "accepted_risk": "Accepted Risk",
    "false_positive": "False Positive",
}

FINDING_STATUS_COLOR = {
    "open": "#6B7280",
    "triaged": "#2563EB",
    "confirmed": "#EA580C",
    "remediation_in_progress": "#D97706",
    "retest": "#9333EA",
    "resolved": "#059669",
    "accepted_risk": "#64748B",
    "false_positive": "#9CA3AF",
}

# Statuses that are excluded from the client-facing summary regardless of the
# analyst's include-in-report toggle.
EXCLUDED_REPORT_STATUSES = {"false_positive"}


def _hosts_in_report(hosts, findings):
    """Map host_id -> worst severity so the inventory shows risk badges."""
    worst = {}
    order = {"critical": 4, "concerning": 3, "notable": 2, "info": 1}
    for f in findings:
        if not f.host_id:
            continue
        key = str(f.host_id)
        cur = order.get(worst.get(key, "info"), 0)
        nxt = order.get(f.severity, 0)
        if nxt > cur:
            worst[key] = f.severity
    return worst


def _host_context(host) -> str:
    """Compact 'ip (hostname · Device)' label used everywhere findings point at
    a specific host, so the report reads clearly after device-type/hostname
    enrichment."""
    parts = [str(host.ip)]
    if getattr(host, "hostname", None):
        parts.append(host.hostname)
    dev = getattr(host, "device_type", None)
    if dev and dev not in ("unknown", "unidentified") and dev in DEVICE_TYPE_LABEL:
        parts.append(DEVICE_TYPE_LABEL[dev])
    return " · ".join(parts)


def _open_ports_for(host, ports_lookup):
    """Return the open Port rows for a host (ports_lookup is keyed by host id)."""
    return [p for p in (ports_lookup or {}).get(str(host.id), []) if getattr(p, "state", "open") == "open"]


def _evidence_text(f) -> str:
    """Render the NSE evidence dict (output/script) as readable text, capped at a sane size."""
    ev = getattr(f, "evidence", None)
    if not ev:
        return ""
    if isinstance(ev, dict):
        script = ev.get("script") or ""
        output = ev.get("output") or ""
        if output and len(str(output)) > 900:
            output = str(output)[:900] + "…"
        return "\n".join(x for x in (str(script), str(output)) if x)
    return str(ev)[:1200]


def _exposure_brief(host, ports):
    """Short exposure tags for a host based on its open ports, eg 'SSH · SMB · HTTP'."""
    tags = []
    by_port = {}
    for p in ports:
        by_port.setdefault(p.port, p)
    if 22 in by_port:
        tags.append("SSH")
    if 21 in by_port:
        tags.append("FTP")
    if 23 in by_port:
        tags.append("Telnet")
    if {139, 445, 3389, 5900} & set(by_port):
        tags.append("Remote-access")
    web = {80, 443, 8000, 8080, 8443, 3000, 5000, 9000} & set(by_port)
    if web:
        tags.append("HTTP(S)")
    if by_port.get(445) or by_port.get(139):
        tags.append("SMB")
    if by_port.get(5432) or by_port.get(3306) or by_port.get(1433) or by_port.get(27017):
        tags.append("Database")
    if by_port.get(53) or by_port.get(67) or by_port.get(68):
        tags.append("Network-svc")
    if 161 in by_port or 162 in by_port:
        tags.append("SNMP")
    return " · ".join(tags) or "—"


def _build_html(scan, hosts, findings, ports_lookup, engagement=None) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    # Only findings explicitly included for the client report are reflected in
    # the summary, severity table, risk badges and finding blocks. Analysts
    # toggle this per-finding on the Findings page; false positives are always
    # kept out of the client-facing summary.
    reported = [
        f for f in findings
        if getattr(f, "included_in_report", True)
        and getattr(f, "status", "open") not in EXCLUDED_REPORT_STATUSES
    ]
    total = max(scan.hosts_total_in_scope or 1, 1)
    coverage = round((scan.hosts_discovered or 0) / total * 100)
    by_sev = _findings_by_severity(reported)
    risk_index = _risk_index(reported)
    breakdown = _device_breakdown(hosts)
    excluded = len(findings) - len(reported)
    named = sum(1 for h in hosts if h.hostname)
    excl_note = f" · {excluded} finding(s) excluded from this report" if excluded else ""

    # ---- Extended scan metrics ------------------------------------------ #
    started = getattr(scan, "started_at", None)
    completed = getattr(scan, "completed_at", None)
    if started and completed:
        dur = max((completed - started).total_seconds(), 0)
        if dur >= 3600:
            dur_txt = f"{int(dur // 3600)}h {int((dur % 3600) // 60)}m {int(dur % 60)}s"
        elif dur >= 60:
            dur_txt = f"{int(dur // 60)}m {int(dur % 60)}s"
        else:
            dur_txt = f"{int(dur)}s"
    else:
        dur_txt = "—"
    open_ports_total = 0
    for h in hosts:
        open_ports_total += len(_open_ports_for(h, ports_lookup))
    hosts_with_findings = {str(f.host_id) for f in reported if f.host_id}
    with_findings = sum(1 for h in hosts if str(h.id) in hosts_with_findings)
    inst_of_scope = (scan.hosts_total_in_scope or 0)
    host_counts = (
        f"{len(hosts)} of {inst_of_scope}" if inst_of_scope else str(len(hosts))
    )

    # ---- Asset inventory table ------------------------------------------ #
    worst = _hosts_in_report(hosts, reported)
    inv_rows = "".join(
        f"""
        <tr>
          <td><span class="badge pill" style="background:{SEVERITY_COLOR.get(worst.get(str(h.id), 'info'), '#8B95A1')}">{SEVERITY_LABEL.get(worst.get(str(h.id), 'info'), '—')}</span></td>
          <td class="mono">{_esc(h.ip)}</td>
          <td>{_esc(h.hostname) if getattr(h, "hostname", None) else '<span class="muted">—</span>'}</td>
          <td>{_esc(DEVICE_TYPE_LABEL.get(getattr(h, "device_type", None), "Unidentified"))}</td>
          <td class="mono">{_esc(h.mac) if getattr(h, "mac", None) else '<span class="muted">—</span>'}</td>
          <td>{_esc(h.vendor) if getattr(h, "vendor", None) else '<span class="muted">—</span>'}</td>
          <td>{_esc(h.os_guess or "—")}</td>
          <td>{cells_for_open_ports(_open_ports_for(h, ports_lookup))}</td>
          <td>{len([f for f in reported if f.host_id and str(f.host_id) == str(h.id)])}</td>
          <td class="nowrap">{_esc(h.last_seen.strftime("%Y-%m-%d %H:%M") if getattr(h, "last_seen", None) else "—")}</td>
        </tr>"""
        for h in sorted(hosts, key=lambda x: (SEVERITY_ORDER.get(worst.get(str(x.id), "info"), 9), str(x.ip)))
    )
    asset_inventory = f"""
  <h2>Asset Inventory</h2>
  <p class="meta">{len(hosts)} asset(s) discovered · {with_findings} with findings · {
      _esc(', '.join(scan.targets))} · snapshots below are per host last-seen</p>
  <table>
    <thead><tr>
      <th style="width:6%">Risk</th><th style="width:13%">IP</th><th style="width:11%">Hostname</th>
      <th style="width:11%">Type</th><th style="width:11%">MAC</th><th style="width:10%">Vendor</th>
      <th style="width:12%">OS</th><th style="width:12%">Open Ports</th><th style="width:7%">Findings</th><th style="width:7%">Last Seen</th>
    </tr></thead>
    <tbody>{inv_rows}</tbody>
  </table>"""

    # ---- Exposure analysis ---------------------------------------------- #
    exposure_rows = []
    for h in sorted(hosts, key=lambda x: str(x.ip)):
        tags = _exposure_brief(h, _open_ports_for(h, ports_lookup))
        if tags == "—":
            continue
        exposure_rows.append(
            f'<tr><td class="mono">{_esc(h.ip)}</td><td>{_esc(DEVICE_TYPE_LABEL.get(getattr(h, "device_type", None), "Unidentified"))}</td><td>{_esc(tags)}</td><td class="mono">{cells_for_open_ports(_open_ports_for(h, ports_lookup))}</td></tr>'
        )
    exposures_html = ""
    if exposure_rows:
        exposures_html = f"""
  <h2>Exposure Analysis</h2>
  <p class="meta">Hosts with reachable network services, grouped by access class. Only hosts in
  the authorized scope were probed; service reachability does not imply a confirmed
  vulnerability.</p>
  <table>
    <thead><tr><th style="width:18%">Host</th><th style="width:20%">Type</th><th style="width:42%">Exposure</th><th style="width:20%">Open Ports</th></tr></thead>
    <tbody>{''.join(exposure_rows)}</tbody>
  </table>"""

    device_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{count}</td></tr>" for name, count in breakdown
    )

    sev_rows = "".join(
        f"""
        <tr>
          <td><span class="badge" style="background:{SEVERITY_COLOR[s]}">{SEVERITY_LABEL[s]}</span></td>
          <td>{by_sev.get(s, 0)}</td>
        </tr>"""
        for s in ("critical", "concerning", "notable", "info")
    )

    device_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{count}</td></tr>" for name, count in breakdown
    )

    finding_blocks = []
    if reported:
        for f in sorted(reported, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            color = SEVERITY_COLOR.get(f.severity, "#8B95A1")
            host_ctx = ""
            if f.host_id:
                for h in hosts:
                    if str(h.id) == str(f.host_id):
                        host_ctx = f'<div class="finding-host mono">Host: {_esc(_host_context(h))}</div>'
                        break
            status = getattr(f, "status", "open")
            status_chip = ""
            if status and status != "open":
                status_chip = f'<span class="badge" style="background:{FINDING_STATUS_COLOR.get(status, "#6B7280")}">{FINDING_STATUS_LABEL.get(status, status)}</span>'
            cve_chips = "".join(
                f'<span class="chip">{_esc(cve)}</span>' for cve in (f.cve_refs or [])
            )
            ev_text = _evidence_text(f)
            evidence_html = ""
            if ev_text:
                evidence_html = (
                    f'<p class="ev-label">Evidence</p>'
                    f'<pre class="evidence">{_esc(ev_text)}</pre>'
                )
            if getattr(f, "port", None):
                port_chip = f'<span class="chip port">port {_esc(f.port)}</span>'
            else:
                port_chip = ""
            cvss_row = ""
            if getattr(f, "cvss_score", None) is not None or getattr(f, "cwe", None):
                bits = []
                if getattr(f, "cvss_score", None) is not None:
                    v = getattr(f, "cvss_vector", None)
                    bits.append(f'CVSS <b>{f.cvss_score:.1f}</b>')
                    if v:
                        bits.append(f'<span class="mono dim">{_esc(v)}</span>')
                if getattr(f, "cwe", None):
                    bits.append(f'<span class="thingy">{_esc(f.cwe)}</span>')
                cvss_row = f'<div class="chips">{" &nbsp; ".join(bits)}</div>'
            finding_blocks.append(f"""
            <div class="finding">
              <div class="finding-head">
                <span class="badge" style="background:{color}">{SEVERITY_LABEL.get(f.severity, f.severity)}</span>
                {status_chip}
                {port_chip}
                <strong>{_esc(f.title)}</strong>
              </div>
              {host_ctx}
              {cvss_row}
              {f"<p>{_esc(f.description)}</p>" if f.description else ""}
              {f'<p class="mono chip-note">{cve_chips}</p>' if cve_chips else ""}
              {evidence_html}
              {f'<p class="rec"><span>Recommendation:</span> {_esc(f.recommendation)}</p>' if f.recommendation else ""}
            </div>""")
    else:
        finding_blocks.append('<p class="muted">No risk findings were generated for this scan.</p>')

    findings_html = "".join(finding_blocks)

    topo_html = ""
    try:
        from .topology import compute_topology, topology_svg_data_uri
        nodes, edges = compute_topology(scan, hosts, findings)
        if nodes and edges:
            uri = topology_svg_data_uri(nodes, edges)
            topo_html = f"""
  <h2>Network Topology</h2>
  <div class="topo-block">
    <img class="topo-img" src="{uri}" alt="Network topology diagram"/>
    <p class="meta">Subnet zones are inferred from the scan targets. Node borders reflect the
    worst finding severity on each host; a gateway connects each zone to the Internet.
    Dash lines link hosts to their subnet.</p>
  </div>"""
    except Exception:
        topo_html = ""

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 18mm 16mm; @bottom-center {{ content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: #8B95A1; }} }}
  body {{ font-family: "Inter", "Helvetica Neue", Arial, sans-serif; color: #1F2430; font-size: 9.5px; line-height: 1.4; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; color: #101623; }}
  h2 {{ font-size: 13.5px; border-bottom: 2px solid #E5E7EB; padding-bottom: 5px; margin: 22px 0 10px; color: #101623; }}
  h3 {{ font-size: 11px; margin: 12px 0 6px; color: #101623; }}
  .subtitle {{ color: #5B6472; font-size: 10.5px; margin-bottom: 5px; }}
  .meta {{ color: #8B95A1; font-size: 8.5px; line-height: 1.6; }}
  .confidential {{ margin-top: 10px; padding: 5px 9px; background: #FFF7ED; border: 1px solid #FED7AA; border-radius: 6px; color: #9A3412; font-size: 8px; }}
  .narrative {{ color: #374151; margin-top: 10px; }}
  .chip {{ display: inline-block; padding: 1px 5px; border: 1px solid #E5A50A; border-radius: 4px; color: #9A5B00; font-size: 8px; }}
  .chip-note {{ margin-top: 4px; }}
  .chips {{ font-size: 8.5px; color: #374151; margin: 2px 0 4px; }}
  .thingy {{ display: inline-block; padding: 1px 5px; border: 1px solid #E5A50A; border-radius: 4px; color: #9A5B00; font-size: 8px; }}
  .dim {{ color: #9CA3AF; font-size: 7px; }}
  .nowrap {{ white-space: nowrap; }}
  .mono {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }}
  table {{ width: 100%; max-width: 100%; border-collapse: collapse; margin: 8px 0; table-layout: fixed; }}
  th, td {{ text-align: left; padding: 4px 6px; border-bottom: 1px solid #E5E7EB; font-size: 8.5px; overflow-wrap: break-word; word-break: break-word; }}
  th {{ background: #F3F4F6; font-weight: 600; color: #374151; }}
  .grid {{ display: flex; flex-wrap: wrap; gap: 10px; }}
  .grid > div {{ flex: 1 1 130px; min-width: 0; }}
  .stat {{ background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; padding: 9px; min-width: 0; }}
  .stat .num {{ font-size: 21px; font-weight: 700; color: #101623; overflow-wrap: break-word; word-break: break-word; }}
  .stat .lbl {{ font-size: 8px; color: #6B7280; text-transform: uppercase; letter-spacing: .4px; }}
  .badge {{ display: inline-block; padding: 1px 6px; border-radius: 4px; color: #fff; font-size: 7.5px; font-weight: 600; text-transform: uppercase; }}
  .badge.pill {{ min-width: 40px; text-align: center; }}
  .chip.port {{ border-color: #94A3B8; color: #475569; }}
  .ev-label {{ font-size: 7.5px; color: #8B95A1; text-transform: uppercase; letter-spacing: .5px; margin: 7px 0 2px; }}
  .evidence {{ background: #0B1220; color: #C9D3E0; border: 1px solid #252F40; border-radius: 6px; padding: 6px 8px; font-size: 7px; line-height: 1.45; white-space: pre-wrap; font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }}
  .finding {{ border: 1px solid #E5E7EB; border-left: 4px solid #8B95A1; border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; }}
  .finding-head {{ margin-bottom: 5px; }}
  .finding-host {{ font-size: 8.5px; color: #6B7280; margin-bottom: 5px; }}
  .finding p {{ margin: 3px 0; color: #374151; }}
  .rec {{ color: #0F766E; }}
  .muted {{ color: #8B95A1; }}
  ul {{ margin: 4px 0 4px 16px; }}
  li {{ margin-bottom: 3px; }}
  .appendix {{ background: #F9FAFB; border-radius: 6px; padding: 10px; }}
  .topo-block {{ margin: 6px 0 4px; }}
  .topo-img {{ width: 100%; }}
</style>
</head>
<body>
  <h1>SubNex Initial Discovery Report</h1>
  <div class="subtitle">Scan of {_esc(', '.join(scan.targets))}</div>
  <div class="meta">
    Client / Engagement: <b>{_esc(getattr(engagement, "client_name", None) or "—")}</b>
    &nbsp;·&nbsp; Scan ID: <span class="mono">{_esc(scan.id)}</span><br>
    Profile: <b>{_esc(scan.profile)}</b> &nbsp;·&nbsp; Port range: <b>{_esc(scan.port_range)}</b>
    &nbsp;·&nbsp; Started: {_esc(scan.started_at.strftime("%Y-%m-%d %H:%M") if getattr(scan, "started_at", None) else "—")}
    &nbsp;·&nbsp; Generated: {now}
  </div>
  <div class="confidential">CONFIDENTIAL — Prepared for authorized security testing. Distribution restricted to the engagement team and client stakeholders.</div>

  <h2>Executive Summary</h2>
  <div class="grid" style="margin-bottom:8px;">
    <div class="stat"><div class="num">{coverage}%</div><div class="lbl">Coverage</div></div>
    <div class="stat"><div class="num">{scan.hosts_discovered or 0}</div><div class="lbl">Hosts Discovered</div></div>
    <div class="stat"><div class="num">{named}</div><div class="lbl">Named Hosts</div></div>
    <div class="stat"><div class="num">{len(reported)}</div><div class="lbl">Findings</div></div>
    <div class="stat"><div class="num">{risk_index}</div><div class="lbl">Risk Index (/100)</div></div>
    <div class="stat"><div class="num">{open_ports_total}</div><div class="lbl">Open Ports</div></div>
  </div>
  <div class="grid" style="margin-bottom:8px;">
    <div class="stat"><div class="num">{host_counts}</div><div class="lbl">Hosts in Scope</div></div>
    <div class="stat"><div class="num">{with_findings}</div><div class="lbl">Hosts w/ Findings</div></div>
    <div class="stat"><div class="num">{dur_txt}</div><div class="lbl">Scan Duration</div></div>
    <div class="stat"><div class="num">{_esc(', '.join(getattr(scan, 'targets', []) or []))}</div><div class="lbl">Scope</div></div>
  </div>
  <p class="narrative">
    This engagement covered <b>{scan.hosts_total_in_scope or 0}</b> in-scope asset(s) at
    {_esc(', '.join(scan.targets))}, of which <b>{scan.hosts_discovered or 0}</b> responded to discovery
    ({coverage}% coverage) across <b>{host_counts}</b> live host(s). The scan enumerated
    <b>{open_ports_total}</b> open port(s) in {dur_txt}. Risk analysis of the discovered assets produced <b>{len(reported)}</b> finding(s):
    {by_sev.get("critical", 0)} critical, {by_sev.get("concerning", 0)} concerning,
    {by_sev.get("notable", 0)} notable and {by_sev.get("info", 0)} informational
    (overall risk index {risk_index}/100). {with_findings} host(s) carry at least one finding;
    highest-risk assets should be remediated first, and each finding below includes
    context, evidence and a recommendation.
  </p>

  <div class="grid">
    <div>
      <h3>Device Breakdown</h3>
      <table>
        <thead><tr><th>Device Type</th><th>Count</th></tr></thead>
        <tbody>{device_rows or '<tr><td colspan="2">No hosts</td></tr>'}</tbody>
      </table>
    </div>
    <div>
      <h3>Findings by Severity</h3>
      <table>
        <thead><tr><th>Severity</th><th>Count</th></tr></thead>
        <tbody>{sev_rows}</tbody>
      </table>
    </div>
  </div>
{exposures_html}
{asset_inventory}
{topo_html}
  <h2>Risk Findings<span class="muted"> ({len(reported)} shown{excl_note})</span></h2>
  {findings_html}

  <h2>Coverage &amp; Limitations</h2>
  <ul>
    <li>Hosts that filter ICMP may not be detected by discovery.</li>
    <li>Passive-only scans do not enumerate open ports.</li>
    <li>OS and banner identification depends on scan timing and host responses.</li>
    <li>Devices using privacy-randomised MAC addresses hide their vendor; hostnames
        are then inferred from mDNS/DHCP service announcements where available.</li>
    <li>Only targets within the engagement's authorized scope were scanned.</li>
  </ul>

  <h2>Methodology &amp; Tools</h2>
  <div class="appendix">
    <p>Assets were discovered and fingerprinted using the following methodology:</p>
    <ul>
      <li><b>Discovery:</b> ARP sweep (local subnets) and TCP SYN probes to common ports (routed subnets), cross-referenced against live Layer-2 scanner agents on the target LAN.</li>
      <li><b>Naming:</b> passive mDNS service enumeration, DHCP/DHCPv6 client traffic and SNMP sysName used to recover hostnames even when MACs are privacy-randomised.</li>
      <li><b>Port scan:</b> Nmap connect/syn scans of the configured port range, with service/version/OS detection (<span class="mono">-sV -sC -O</span>) applied only to open ports.</li>
      <li><b>Fingerprinting:</b> MAC vendor lookup (OUI), SNMP walks on UDP 161, and device-type classification into a granular taxonomy (router/switch/AP, laptop vs. smartphone/tablet, server vs. VM, camera/NVR, smart TV/IoT, VoIP, NAS, printer, access control).</li>
      <li><b>Risk analysis:</b> Nmap NSE evidence (SSL/SSH crypto strength, certificates, SMB signing and shares, anonymous FTP, HTTP method and admin-panel detection, authentication checks) combined with heuristic rules (default SNMP community, unencrypted protocols RTSP/SIP/Telnet/FTP/HTTP/SMB, outdated-software banner matching). Every rule is tunable per scan — operators can disable a rule or override its severity before re-analysis.</li>
    </ul>
    <p>Tools: Nmap, Scapy, pysnmp, Wireshark OUI database.</p>
    <p class="meta">This report is a discovery/fingerprinting artifact for authorized security testing. It contains no exploitation or credential-brute-force activity.</p>
  </div>
</body>
</html>"""


def cells_for_open_ports(ports) -> str:
    if not ports:
        return "—"
    shown = list(ports)[:6]
    extra = len(list(ports)) - len(shown)
    cells = "".join(
        f'<span class="mono">{p.port}/{p.protocol}{("·" + _esc(p.service)) if getattr(p, "service", None) else ""} </span>'
        for p in shown
    )
    if extra > 0:
        cells += f'<span class="mono">+{extra} more</span>'
    return cells


def generate_report(scan, hosts, findings, ports_lookup=None, engagement=None) -> bytes:
    """Render the report to PDF bytes.

    Uses WeasyPrint when available. On any import/failure, returns a minimal
    valid PDF so the export endpoint never crashes.
    """
    if ports_lookup is None:
        ports_lookup = {}

    html_doc = _build_html(scan, hosts, findings, ports_lookup, engagement)

    try:
        from weasyprint import HTML as WeasyHTML
        return WeasyHTML(string=html_doc).write_pdf()
    except Exception:
        return _minimal_pdf()


def _minimal_pdf() -> bytes:
    """Return a tiny valid PDF placeholder if WeasyPrint isn't available."""
    body = b"This report is a placeholder. Install WeasyPrint to generate PDFs."
    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"
    )
    stream = b"BT /F1 12 Tf 72 720 Td (" + body + b") Tj ET"
    objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += str(i).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n"
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += ("%010d 00000 n \n" % off).encode()
    out += b"trailer\n<< /Size " + str(len(objects) + 1).encode() + b" /Root 1 0 R >>\nstartxref\n"
    out += str(xref_pos).encode() + b"\n%%EOF\n"
    return bytes(out)
