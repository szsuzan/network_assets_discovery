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
    "unknown": "Unidentified Host (Private MAC)",
    "access_control": "Access Control",
    # legacy keys from scans before the granular taxonomy
    "network_gear": "Router / Gateway",
    "mobile": "Smartphone",
    "server": "Physical Server",
    "camera_ip": "IP Camera / NVR",
}


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


def _build_html(scan, hosts, findings, ports_lookup) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = max(scan.hosts_total_in_scope or 1, 1)
    coverage = round((scan.hosts_discovered or 0) / total * 100)
    by_sev = _findings_by_severity(findings)
    breakdown = _device_breakdown(hosts)
    worst = _hosts_in_report(hosts, findings)

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

    host_rows = "".join(
        f"""
        <tr>
          <td class="mono">{_esc(h.ip)}</td>
          <td>{_esc(h.hostname or "—")}</td>
          <td>{_esc(DEVICE_TYPE_LABEL.get(h.device_type, h.device_type or "Unknown"))}</td>
          <td>{_esc(h.os_guess or "—")}</td>
          <td>{cells_for_open_ports(ports_lookup.get(str(h.id), []))}</td>
          <td>{_esc(SEVERITY_LABEL.get(worst.get(str(h.id), "info"), "Info"))}</td>
        </tr>"""
        for h in hosts
    )

    finding_blocks = []
    if findings:
        for f in findings:
            color = SEVERITY_COLOR.get(f.severity, "#8B95A1")
            finding_blocks.append(f"""
            <div class="finding">
              <div class="finding-head">
                <span class="badge" style="background:{color}">{SEVERITY_LABEL.get(f.severity, f.severity)}</span>
                <strong>{_esc(f.title)}</strong>
              </div>
              {f"<p>{_esc(f.description)}</p>" if f.description else ""}
              {f'<p class="rec"><span>Recommendation:</span> {_esc(f.recommendation)}</p>' if f.recommendation else ""}
            </div>""")
    else:
        finding_blocks.append('<p class="muted">No risk findings were generated for this scan.</p>')

    findings_html = "".join(finding_blocks)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page {{ size: A4; margin: 18mm 16mm; @bottom-center {{ content: "Page " counter(page) " of " counter(pages); font-size: 9px; color: #8B95A1; }} }}
  body {{ font-family: "Inter", "Helvetica Neue", Arial, sans-serif; color: #1F2430; font-size: 11px; line-height: 1.45; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; color: #101623; }}
  h2 {{ font-size: 16px; border-bottom: 2px solid #E5E7EB; padding-bottom: 6px; margin: 28px 0 12px; color: #101623; }}
  h3 {{ font-size: 13px; margin: 16px 0 8px; color: #101623; }}
  .subtitle {{ color: #5B6472; font-size: 12px; margin-bottom: 6px; }}
  .meta {{ color: #8B95A1; font-size: 10px; }}
  .mono {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #E5E7EB; font-size: 10px; }}
  th {{ background: #F3F4F6; font-weight: 600; color: #374151; }}
  .grid {{ display: flex; gap: 24px; }}
  .grid > div {{ flex: 1; }}
  .stat {{ background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 8px; padding: 12px; }}
  .stat .num {{ font-size: 26px; font-weight: 700; color: #101623; }}
  .stat .lbl {{ font-size: 10px; color: #6B7280; text-transform: uppercase; letter-spacing: .5px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 9px; font-weight: 600; text-transform: uppercase; }}
  .finding {{ border: 1px solid #E5E7EB; border-left: 4px solid #8B95A1; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; }}
  .finding-head {{ margin-bottom: 6px; }}
  .finding p {{ margin: 4px 0; color: #374151; }}
  .rec {{ color: #0F766E; }}
  .muted {{ color: #8B95A1; }}
  ul {{ margin: 6px 0 6px 18px; }}
  li {{ margin-bottom: 4px; }}
  .appendix {{ background: #F9FAFB; border-radius: 6px; padding: 12px; }}
</style>
</head>
<body>
  <h1>Initial Asset Discovery Report</h1>
  <div class="subtitle">Scan of {_esc(', '.join(scan.targets))}</div>
  <div class="meta">Profile: <b>{_esc(scan.profile)}</b> &nbsp;·&nbsp; Port range: <b>{_esc(scan.port_range)}</b> &nbsp;·&nbsp; Generated: {now}</div>

  <h2>Executive Summary</h2>
  <div class="grid" style="margin-bottom:8px;">
    <div class="stat"><div class="num">{coverage}%</div><div class="lbl">Coverage</div></div>
    <div class="stat"><div class="num">{scan.hosts_discovered or 0}</div><div class="lbl">Hosts Discovered</div></div>
    <div class="stat"><div class="num">{scan.hosts_total_in_scope or 0}</div><div class="lbl">Hosts In Scope</div></div>
    <div class="stat"><div class="num">{len(findings)}</div><div class="lbl">Findings</div></div>
  </div>

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

  <h2>Asset Inventory</h2>
  <table>
    <thead>
      <tr><th>IP</th><th>Hostname</th><th>Device Type</th><th>OS Guess</th><th>Open Ports</th><th>Risk</th></tr>
    </thead>
    <tbody>{host_rows or '<tr><td colspan="6">No hosts discovered</td></tr>'}</tbody>
  </table>

  <h2>Risk Findings</h2>
  {findings_html}

  <h2>Coverage &amp; Limitations</h2>
  <ul>
    <li>Hosts that filter ICMP may not be detected by discovery.</li>
    <li>Passive-only scans do not enumerate open ports.</li>
    <li>OS and banner identification depends on scan timing and host responses.</li>
    <li>Only targets within the engagement's authorized scope were scanned.</li>
  </ul>

  <h2>Methodology &amp; Tools</h2>
  <div class="appendix">
    <p>Assets were discovered and fingerprinted using the following methodology:</p>
    <ul>
      <li><b>Discovery:</b> ARP sweep (local subnets) and TCP SYN probes to common ports (routed subnets).</li>
      <li><b>Port scan:</b> Nmap connect/syn scans of the configured port range, with service/version/OS detection (<span class="mono">-sV -sC -O</span>) applied only to open ports.</li>
      <li><b>Fingerprinting:</b> MAC vendor lookup (OUI), SNMP walks on UDP 161, device-type classification heuristic.</li>
      <li><b>Risk analysis:</b> Default SNMP community checks, banner version comparison against a curated outdated-software table, exposed admin panel and unencrypted protocol detection.</li>
    </ul>
    <p>Tools: Nmap, Scapy, pysnmp, Wireshark OUI database.</p>
    <p class="meta">This report is a discovery/fingerprinting artifact for authorized security testing. It contains no exploitation or credential-brute-force activity.</p>
  </div>
</body>
</html>"""


def cells_for_open_ports(ports) -> str:
    if not ports:
        return "—"
    return "".join(f'<span class="mono">{p.port}/{p.protocol} </span>' for p in ports)


def generate_report(scan, hosts, findings, ports_lookup=None) -> bytes:
    """Render the report to PDF bytes.

    Uses WeasyPrint when available. On any import/failure, returns a minimal
    valid PDF so the export endpoint never crashes.
    """
    if ports_lookup is None:
        ports_lookup = {}

    html_doc = _build_html(scan, hosts, findings, ports_lookup)

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
