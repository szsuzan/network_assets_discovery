# Network Asset Discovery Platform — Master Build Prompt

A single reference document covering database schema, backend, and frontend for a professional-grade network asset discovery tool for penetration testing engagements. Built to be internally consistent — same data model referenced everywhere.

---

## 1. Project Overview

**Purpose:** A tool a pentester runs at the start of a client engagement to discover all live assets on an in-scope network, fingerprint each host (IP, MAC, vendor, device type, OS, open ports/services), map network topology, surface risk-relevant findings, and produce a client-ready initial discovery report.

**Explicitly out of scope for this entire system:** exploitation, credential brute-forcing, or any attack-execution capability. This is a discovery, fingerprinting, and reporting platform only. Exploitation tooling (e.g., Metasploit) is a separate, independently operated system.

**Architecture:**
```
┌─────────────────┐      REST + WebSocket      ┌──────────────────────┐
│  React Frontend │ ◄────────────────────────► │  FastAPI Backend      │
│  (Lovable/Bolt)  │                            │  + Scan Orchestrator  │
└─────────────────┘                            └──────────┬───────────┘
                                                            │
                                    ┌───────────────────────┼───────────────────────┐
                                    ▼                       ▼                       ▼
                              RustScan/Nmap             Scapy (ARP/            PostgreSQL
                              (port scan)              CDP/LLDP/passive)      (persistence)
                                                            │
                                                      pysnmp (SNMP walk)
```

---

## 2. Database Schema (PostgreSQL)

```sql
-- Users (even for a solo pentester, keep this — you'll want it when working in a team)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'pentester', -- pentester | admin
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Engagements: every scan belongs to a client engagement, never a bare scan
CREATE TABLE engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_name TEXT NOT NULL,
    engagement_name TEXT NOT NULL,
    authorized_scope TEXT[] NOT NULL,      -- e.g. ['10.0.0.0/24', '192.168.1.0/24']
    start_date DATE,
    end_date DATE,
    status TEXT NOT NULL DEFAULT 'active', -- active | completed | archived
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Scan jobs
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES engagements(id) NOT NULL,
    targets TEXT[] NOT NULL,
    profile TEXT NOT NULL,                 -- quick | full | stealth | passive_only
    port_range TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', -- queued|discovering|scanning|fingerprinting|analyzing|completed|stopped|failed
    hosts_total_in_scope INT DEFAULT 0,
    hosts_discovered INT DEFAULT 0,
    progress_pct INT DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    started_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Discovered hosts (one row per host per scan, so history is preserved across re-scans)
CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    ip INET NOT NULL,
    mac MACADDR,
    vendor TEXT,
    hostname TEXT,
    device_type TEXT,                      -- server|workstation|network_gear|printer|iot|mobile|unknown
    os_guess TEXT,
    os_confidence INT,
    status TEXT NOT NULL,                  -- up|down|filtered
    discovery_method TEXT[],
    first_seen TIMESTAMPTZ DEFAULT now(),
    last_seen TIMESTAMPTZ DEFAULT now(),
    notes TEXT DEFAULT '',
    tags TEXT[] DEFAULT '{}',
    UNIQUE(scan_id, ip)
);

-- Open ports/services per host
CREATE TABLE ports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE NOT NULL,
    port INT NOT NULL,
    protocol TEXT NOT NULL,                -- tcp|udp
    state TEXT NOT NULL,                   -- open|filtered|closed
    service TEXT,
    version TEXT,
    banner TEXT
);

-- SNMP data per host
CREATE TABLE snmp_info (
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE PRIMARY KEY,
    sys_descr TEXT,
    sys_name TEXT,
    sys_location TEXT,
    default_community_found BOOLEAN DEFAULT false
);

-- Risk findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    host_id UUID REFERENCES hosts(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,                -- info|notable|concerning|critical
    type TEXT NOT NULL,                    -- default_credentials|eol_software|exposed_admin_panel|unencrypted_protocol|unexpected_exposure
    title TEXT NOT NULL,
    description TEXT,
    recommendation TEXT,
    cve_refs TEXT[],
    port INT,
    included_in_report BOOLEAN DEFAULT true
);

-- Topology edges (subnet adjacency, CDP/LLDP links, traceroute hops)
CREATE TABLE topology_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) NOT NULL,
    source_ip INET NOT NULL,
    target_ip INET NOT NULL,
    edge_type TEXT NOT NULL                -- l2_adjacency|cdp_lldp|traceroute_hop
);

-- Audit log — every scan action, who/what/when. Non-negotiable for pentest tooling.
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    engagement_id UUID REFERENCES engagements(id),
    scan_id UUID REFERENCES scans(id),
    action TEXT NOT NULL,                  -- scan_started|scan_stopped|scope_rejected|export_generated|host_annotated
    detail JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_hosts_scan_id ON hosts(scan_id);
CREATE INDEX idx_ports_host_id ON ports(host_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_topology_scan_id ON topology_edges(scan_id);
```

**Scan diffing note:** because `hosts` rows are per-scan rather than a single mutable table, comparing two scans within the same engagement is just a query joining on `ip`/`mac` across `scan_id`s — this gives you "what's new/changed/gone since last scan" for free, which matters on multi-day engagements.

---

## 3. Backend Build Prompt

**Stack:** Python 3.11+, FastAPI, PostgreSQL, Redis + Celery (background scan jobs), WebSockets for live updates, JWT auth.

**Scanning tools wrapped as services:**
- **RustScan** — fast full-range port sweep, chained directly into Nmap for service detail (`rustscan -a <targets> -r <ports> --ulimit 5000 -- -sV -sC -O`)
- **Nmap** — service/version detection, OS fingerprinting, NSE scripts, invoked via subprocess with XML output parsed by `xml.etree.ElementTree` (more reliable than `python-nmap` for structured parsing at scale)
- **Scapy** — ARP sweeps for on-LAN discovery, passive CDP/LLDP capture for topology, mDNS/LLMNR passive listening
- **pysnmp** — SNMP v1/v2c walks; check default community strings (`public`, `private`) as a specific, flagged test
- **manuf (Wireshark OUI DB)** — MAC → vendor resolution
- **WeasyPrint** or **wkhtmltopdf** — render the HTML report template to PDF for export

### Authentication
- JWT-based auth (`/api/auth/login`, `/api/auth/refresh`)
- All scan/engagement endpoints require a valid token
- Role check: only `admin` can delete engagements; any authenticated `pentester` can create/run scans within engagements they're assigned to

### API endpoints

```
POST   /api/auth/login
POST   /api/engagements                     create engagement (client name, scope, dates)
GET    /api/engagements                     list engagements
GET    /api/engagements/{id}                engagement detail + its scans

POST   /api/engagements/{id}/scans          start scan (validated against engagement's authorized_scope)
GET    /api/scans/{id}                      scan status/summary
DELETE /api/scans/{id}                      stop scan
GET    /api/scans/{id}/hosts                paginated, filterable host list
GET    /api/scans/{id}/hosts/{ip}           full host detail
PATCH  /api/scans/{id}/hosts/{ip}           update notes/tags
GET    /api/scans/{id}/topology             graph nodes + edges
GET    /api/scans/{id}/findings             findings list
PATCH  /api/findings/{id}                   toggle included_in_report, edit recommendation
GET    /api/scans/{id}/diff/{other_scan_id} diff two scans in the same engagement
GET    /api/scans/{id}/export?format=json|csv|pdf

WS     /ws/scans/{id}                       live events: host_discovered, host_updated, finding_added, progress, scan_completed
```

### Scan pipeline (five stages, each streamed to WebSocket as it completes per host)

1. **Scope validation** — reject the scan job outright if any target falls outside `engagement.authorized_scope`. Log the rejection to `audit_log` regardless of outcome.
2. **Discovery** — Scapy ARP sweep for local subnets; TCP SYN probes to common ports (80/443/22/445/3389) for routed subnets; ICMP as a supplementary-only signal.
3. **Port scan** — RustScan full-range sweep on live hosts → Nmap deep scan (`-sV -sC -O`) on the ports RustScan found open.
4. **Fingerprinting & risk analysis** — MAC vendor lookup, SNMP walk on hosts with 161/udp open, device-type classification heuristic (combine MAC vendor + open ports + banner content), and the finding rules: default SNMP community, banner version against a curated "known outdated/vulnerable" lookup table, unauthenticated web admin panel detection (pattern-match common admin login paths), Telnet/FTP presence, unexpected cross-segment exposure.
5. **Topology capture** — passive CDP/LLDP sniff running concurrently with the scan window; traceroute for inter-subnet hop paths.

### Safety / throttling (important — don't skip this)
- **Scan profile controls request rate**, not just port count: `stealth` = heavily throttled (protects fragile OT/IoT devices that can crash under aggressive scanning — this is a real, well-documented failure mode, not a theoretical one); `quick`/`full` = normal Nmap timing templates (`-T2` through `-T4`).
- Provide a **global kill switch** endpoint (`DELETE /api/scans/{id}`) that cleanly terminates subprocesses, not just marks the DB row stopped.
- Rate-limit SNMP/banner-grab attempts per host to avoid tripping IDS/IPS or triggering account lockouts on hosts with authentication attempts logged.

### Report generation
- HTML template → PDF via WeasyPrint, containing: executive summary (coverage %, device breakdown chart, findings-by-severity chart), asset inventory table, topology diagram (rendered server-side as SVG or exported from frontend and embedded), findings list with recommendations, coverage & limitations section, methodology/tools-used appendix.

---

## 4. Frontend Build Prompt (for Lovable / Bolt)

**Stack:** React + TypeScript + Tailwind CSS, TanStack Query (REST) + TanStack Table (virtualized inventory table), `react-force-graph` or `d3.js` (topology), `recharts` (report charts), native WebSocket client, JWT stored in memory/httpOnly cookie via backend auth flow.

### Screens

**Login** — simple email/password form against `/api/auth/login`.

**Engagements List** — table of client engagements (name, status, scope, date range, scan count). "New Engagement" form captures client name, authorized scope (CIDR list input), dates.

**Engagement Detail** — list of scans within this engagement, "New Scan" action, and a **scan comparison** picker (select two scans → view diff: new hosts, missing hosts, changed ports/findings since last time).

**New Scan Setup** — target input (defaults to engagement's authorized scope, editable only within that scope), profile selector (Quick/Full/Stealth/Passive-only) with a plain-language note on what stealth trades off (slower, safer for fragile devices), port range selector, scope-confirmation checkbox, Start button.

**Live Scan View** — WebSocket-driven counters (hosts discovered, up, open ports, elapsed time), progress bar, live activity feed, newly arrived rows highlighted briefly, Stop button.

**Asset Inventory Table** — IP, MAC, Vendor, Hostname, Device Type (icon), OS Guess + confidence, Open Ports (expandable), highest Risk badge, Last Seen, Status; global search, per-column filters, sort, row click → detail drawer, bulk export/tag.

**Network Topology Map** — force-directed graph, device-type icons, risk-severity node coloring, subnet clustering with collapse, edge styling by type, legend, zoom/pan/fit-to-screen, click node → detail drawer.

**Host Detail Drawer** — full host info, ports table, SNMP block, risk flags, editable notes/tags (PATCH to backend), first/last seen timeline, re-scan action.

**Findings Summary** — severity-sorted list/cards, group-by (severity/type/host), per-finding include-in-report toggle, editable recommendation text.

**Report/Export View** — executive summary (coverage %, donut chart of device types, bar chart of findings by severity), coverage & limitations panel, port/service statistics, editable prioritized next-steps list, export buttons (JSON/CSV raw, PDF formatted report calling the backend's export endpoint).

### Design system
- Dark theme default, light toggle
- Monospace (JetBrains Mono) for IPs/MACs/hostnames; sans-serif (Inter) for UI chrome
- Severity colors used everywhere consistently: info `#8B95A1`, notable `#E0B341`, concerning `#E08341`, critical `#E04B4B`
- Distinct icon per device type across table, topology, and drawer
- Dense, scanable layout (Linear/Grafana density level, not marketing-site whitespace)
- Responsive to tablet width minimum; desktop-first

### Explicitly out of scope
No exploitation, credential brute-force, or attack-trigger UI anywhere in this application.

---

## 5. Non-Functional Requirements

- **Deployment:** Docker Compose with services for `backend`, `frontend`, `postgres`, `redis`; `.env` for secrets (DB creds, JWT secret) — never hardcoded.
- **Performance:** virtualized frontend tables and paginated backend endpoints to handle 1,000+ host scans without UI lag.
- **Security of the tool itself:** JWT expiry + refresh, password hashing via `bcrypt`/`argon2`, HTTPS-only in any non-local deployment, audit log retained for the life of the engagement at minimum.
- **Data retention:** engagements marked `archived` should have raw scan data exportable then purgeable, since client network data is sensitive and shouldn't linger indefinitely.

---

## 6. Build Order (recommended)

1. Database schema + FastAPI skeleton with auth and engagement/scan CRUD (mock scan data, no real scanning yet)
2. Frontend in Lovable/Bolt against the mocked API — validates the full contract end-to-end before real scanning is wired in
3. Integrate RustScan → Nmap pipeline, replace mock data with real scan output
4. Add Scapy passive discovery + topology capture
5. Add SNMP walk + risk-finding rule engine
6. Add report generation (PDF export)
7. Add scan diffing between engagements' scans last, once the core loop is solid