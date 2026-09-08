"""Topology computation + SVG rendering shared by the API and the PDF report.

`compute_topology` reproduces the zone/star model the API serves so the on-screen
Topology page and the exported report always show the same graph.
"""
import base64
import ipaddress
import re

SEV_COLOR = {
    "critical": "#E04B4B",
    "concerning": "#E08341",
    "notable": "#E0B341",
    "info": "#8B95A1",
}

SEV_ORDER = {"critical": 4, "concerning": 3, "notable": 2, "info": 1}


def compute_topology(scan, hosts, findings) -> tuple[list, list]:
    """Return (nodes, edges) for a scan's hosts/findings.

    Mirrors the API's /topology response so reports stay consistent with the UI.
    """
    finding_by_host: dict = {}
    for f in findings:
        if f.host_id not in finding_by_host:
            finding_by_host[f.host_id] = "info"
        if SEV_ORDER.get(f.severity, 0) > SEV_ORDER.get(finding_by_host[f.host_id], 0):
            finding_by_host[f.host_id] = f.severity

    # Subnet zones inferred from the scan targets
    zone_nets = []
    for t in (scan.targets if scan else []):
        try:
            net = ipaddress.ip_network(str(t), strict=False)
        except ValueError:
            continue
        if net.prefixlen == 32 or net.prefixlen == 128:
            ip = net.network_address
            net = ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64", strict=False)
        zone_nets.append(net)

    def _zone_key(ip) -> str:
        for net in zone_nets:
            if ip in net:
                return str(net)
        return str(ipaddress.ip_network(f"{ip}/24" if ip.version == 4 else f"{ip}/64", strict=False))

    group: dict = {}
    for h in hosts:
        group.setdefault(_zone_key(ipaddress.ip_address(str(h.ip))), []).append(h)

    def _gw_ip_for(net):
        if net.version != 4 or net.prefixlen > 24:
            return None
        return str(net.network_address + 1)

    zone_nodes = []
    gw_hosts: dict = {}
    for zkey, hs in sorted(group.items(), key=lambda kv: kv[0]):
        net = ipaddress.ip_network(zkey)
        any_ip = _gw_ip_for(net)
        gw_candidates = [h for h in hs if h.device_type in ("network_gear", "router")]
        if any_ip:
            gw_candidates = ([h for h in hs if str(h.ip) == any_ip] or
                             [h for h in hs if str(h.ip).rsplit(".", 1)[0] + ".254" == str(h.ip)] or
                             gw_candidates)
        gw = gw_candidates[0] if gw_candidates else None
        if gw:
            gw_hosts[zkey] = gw
        sev = max((SEV_ORDER.get(finding_by_host.get(h.id, "info"), 1) for h in hs), default=1)
        zone_nodes.append({
            "id": "zone:" + zkey,
            "kind": "zone",
            "label": zkey.replace("/", " mask "),
            "host_count": len(hs),
            "device_type": "router" if gw else None,
            "severity": next(s for s, o in SEV_ORDER.items() if o == sev),
        })

    nodes = list(zone_nodes)
    nodes.append({"id": "internet", "kind": "internet", "label": "Internet"})

    gw_by_zone: dict = {}
    for zkey, gw in gw_hosts.items():
        gw_by_zone[zkey] = gw

    for h in hosts:
        is_gw = any(gw is h for gw in gw_hosts.values())
        nodes.append({
            "id": str(h.ip),
            "kind": "host",
            "ip": str(h.ip),
            "label": h.hostname or str(h.ip),
            "device_type": h.device_type,
            "severity": finding_by_host.get(h.id, "info"),
            "is_gateway": is_gw,
        })

    edges = []
    for zkey, hs in group.items():
        gw = gw_by_zone.get(zkey)
        if gw:
            edges.append({"source": "internet", "target": str(gw.ip), "type": "gateway"})
            edges.append({"source": str(gw.ip), "target": "zone:" + zkey, "type": "in_subnet"})
        else:
            edges.append({"source": "zone:" + zkey, "target": "internet", "type": "gateway"})
        for h in hs:
            edges.append({"source": str(h.ip), "target": "zone:" + zkey, "type": "in_subnet"})

    return nodes, edges


def _esc(value) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _truncate(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def render_topology_svg(nodes, edges, cols_per_row: int = 6, col_spacing: int = 100,
                        row_height: int = 72, zone_y: int = 100, margin: int = 60) -> str:
    """Render the topology graph to a self-contained SVG string.

    Layout (top → bottom):
        Internet  (top centre)
            |
        Zone pill(s)   (horizontal row, one per subnet)
            |   |   |
       Host cards    (grid under each zone, wrapping every *cols_per_row* nodes)

    Host borders reflect severity; dashed lines link hosts to their zone.
    Gateway nodes are drawn as normal host cards — the tree simplifies
    Internet→Zone→Hosts for clarity.
    """
    zones = [n for n in nodes if n["kind"] == "zone"]
    hosts = [n for n in nodes if n["kind"] == "host"]

    host_by_zone: dict = {}
    for e in edges:
        if e["type"] == "in_subnet" and e["target"].startswith("zone:"):
            host_by_zone.setdefault(e["target"], []).append(e["source"])
    for k in host_by_zone:
        host_by_zone[k].sort()

    # --- layout ----------------------------------------------------------- #
    pos: dict = {}
    width = max(760, len(zones) * 220 + margin * 2) if zones else 760
    pos["internet"] = (width / 2, 34)

    host_start_y = zone_y + 72
    max_host_rows = 0
    for z in zones:
        kids = host_by_zone.get(z["id"], [])
        rows = (len(kids) + cols_per_row - 1) // cols_per_row if kids else 1
        max_host_rows = max(max_host_rows, rows)

    height = host_start_y + max_host_rows * row_height + 60

    zone_step = (width - margin * 2) / max(len(zones), 1)
    for i, z in enumerate(zones):
        zx = margin + zone_step * (i + 0.5)
        pos[z["id"]] = (zx, zone_y)

        kids = host_by_zone.get(z["id"], [])
        for idx, ip in enumerate(kids):
            row = idx // cols_per_row
            col = idx % cols_per_row
            count_in_row = min(len(kids) - row * cols_per_row, cols_per_row)
            x = zx + (col - (count_in_row - 1) / 2) * col_spacing
            y = host_start_y + row * row_height
            pos[ip] = (x, y)

    # --- draw ------------------------------------------------------------- #
    rows_out = []
    rows_out.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="DejaVu Sans, sans-serif">'
    )

    # edges  (Internet → Zone  +  Zone → Hosts)
    for z in zones:
        zx, zy = pos[z["id"]]
        ix, iy = pos["internet"]
        rows_out.append(
            f'<line x1="{ix:.1f}" y1="{iy:.1f}" x2="{zx:.1f}" y2="{zy:.1f}" '
            f'stroke="#94A3B8" stroke-width="1.4"/>'
        )
        for ip in host_by_zone.get(z["id"], []):
            if ip not in pos:
                continue
            hx, hy = pos[ip]
            rows_out.append(
                f'<line x1="{zx:.1f}" y1="{zy:.1f}" x2="{hx:.1f}" y2="{hy:.1f}" '
                f'stroke="#94A3B8" stroke-width="1.4" stroke-dasharray="5 4" opacity="0.75"/>'
            )

    # zone pills
    for z in zones:
        zx, zy = pos[z["id"]]
        kids = host_by_zone.get(z["id"], [])
        label = _truncate(z["label"], 30)
        rx = max(64, 10 + len(label) * 4.5)
        rows_out.append(
            f'<rect x="{zx-rx/2:.1f}" y="{zy-18:.1f}" width="{rx:.1f}" height="36" rx="16" '
            f'fill="#EEF2F7" stroke="#94A3B8" stroke-width="1.4"/>'
        )
        rows_out.append(
            f'<text x="{zx:.1f}" y="{zy+1:.1f}" text-anchor="middle" font-size="11" '
            f'font-weight="bold" fill="#334155">{_esc(label)}</text>'
        )
        rows_out.append(
            f'<text x="{zx:.1f}" y="{zy+16:.1f}" text-anchor="middle" font-size="9" '
            f'fill="#64748B">{len(kids)} host(s)</text>'
        )

    # host cards  (hostname  ·  IP  ·  device type)
    rw = min(120, col_spacing - 8)
    rh = 38
    for n in hosts:
        ip = n["ip"]
        if ip not in pos:
            continue
        x, y = pos[ip]
        color = SEV_COLOR.get(n.get("severity", "info"), "#8B95A1")
        rows_out.append(
            f'<rect x="{x-rw/2:.1f}" y="{y-rh/2:.1f}" width="{rw}" height="{rh}" rx="8" '
            f'fill="#FFFFFF" stroke="{color}" stroke-width="2"/>'
        )
        hostname = _truncate(n.get("label") or ip, 20)
        rows_out.append(
            f'<text x="{x:.1f}" y="{y-5:.1f}" text-anchor="middle" font-size="10" '
            f'font-weight="bold" fill="#1F2430">{_esc(hostname)}</text>'
        )
        rows_out.append(
            f'<text x="{x:.1f}" y="{y+10:.1f}" text-anchor="middle" font-size="8" '
            f'fill="#475569" font-family="DejaVu Sans Mono, monospace">{_esc(ip)}</text>'
        )
        dev = (n.get("device_type") or "unknown").replace("_", " ")
        if dev not in ("unknown", "unidentified"):
            rows_out.append(
                f'<text x="{x:.1f}" y="{y+22:.1f}" text-anchor="middle" font-size="7.5" '
                f'fill="#94A3B8">{_esc(dev)}</text>'
            )

    # internet node
    ix, iy = pos["internet"]
    rows_out.append(
        f'<ellipse cx="{ix:.1f}" cy="{iy:.1f}" rx="42" ry="17" fill="#E0E7FF" '
        f'stroke="#6366F1" stroke-width="1.6"/>'
    )
    rows_out.append(
        f'<text x="{ix:.1f}" y="{iy+4:.1f}" text-anchor="middle" font-size="11" '
        f'font-weight="bold" fill="#3730A3">Internet</text>'
    )

    # legend (bottom)
    lx, ly = 10, height - 16
    for i, (sev, col) in enumerate(
        [("Critical", "#E04B4B"), ("Concerning", "#E08341"),
         ("Notable", "#E0B341"), ("Info", "#8B95A1")]
    ):
        x = lx + i * 100
        rows_out.append(
            f'<rect x="{x:.1f}" y="{ly-8:.1f}" width="9" height="9" rx="2" fill="{col}"/>'
        )
        rows_out.append(
            f'<text x="{x+14:.1f}" y="{ly:.1f}" font-size="9" fill="#475569">{sev}</text>'
        )
    rows_out.append("</svg>")
    return "\n".join(rows_out)


def topology_svg_data_uri(nodes, edges) -> str:
    svg = render_topology_svg(nodes, edges)
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()