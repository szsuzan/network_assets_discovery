# Network Asset Discovery Platform

A professional-grade network asset discovery tool for penetration testing engagements. Discovers live assets on an in-scope network, fingerprints each host, maps network topology, surfaces risk-relevant findings, and produces a client-ready initial discovery report.

> **Out of scope for this entire system:** exploitation, credential brute-forcing, or any attack-execution capability. This is a *discovery, fingerprinting, and reporting* platform only.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Quick start (start-all / stop-all)](#quick-start)
3. [Manual start (docker compose)](#manual-start-docker-compose)
4. [Scanner agents (full Layer-2 discovery)](#scanner-agents)
5. [Using the platform](#using-the-platform)
6. [Scan pipeline](#scan-pipeline)
7. [REST API reference](#rest-api)
8. [WebSocket live feed](#websocket-live-feed)
9. [Frontend screens](#frontend-screens)
10. [Safety / throttling](#safety--throttling)
11. [Security of the tool itself](#security-of-the-tool-itself)
12. [Data model](#data-model)
13. [Troubleshooting](#troubleshooting)
14. [Project layout](#project-layout)

---

## Architecture

```
┌─────────────────┐      REST + WebSocket      ┌──────────────────────┐
│  React Frontend │ ◄────────────────────────► │  FastAPI Backend      │
│                 │                            │  + Scan Orchestrator  │
└─────────────────┘                            └──────────┬───────────┘
                                                          │
        ┌─────────────────────────────────────────────────┼─────────────────────┐
        ▼                                                 ▼                     ▼
┌──────────────┐   HTTPS + API key              Nmap (container,      PostgreSQL
│ scanner-agent│ ◄──────────────────            L3 fallback) +        (persistence)
│ on target LAN│   claims tasks, posts results   Redis/Celery broker
│ ARP + SYN -O │                                 + WebSocket relay
└──────────────┘
```

- **Frontend:** React + TypeScript + Tailwind CSS, TanStack Query + TanStack Table, `react-force-graph` (topology), `recharts` (report charts), native WebSocket client.
- **Backend:** Python 3.11+, FastAPI, PostgreSQL (async SQLAlchemy), Redis + Celery (background scan jobs), WebSockets for live updates, JWT auth.
- **Scanning tools:** Nmap (TCP/UDP port scans + service/OS fingerprinting) runs either in-container (L3-only) or, preferably, on a **scanner agent** placed on the target LAN for full Layer-2 (ARP → MAC/vendor + raw-SYN/`-O` → exact OS). **Scapy** (optional, agent-side) passively fingerprints the LAN without touching a single host: DHCP vendor-class-ID → brand/OS, ARP → IP↔MAC, and CDP/LLDP → network-gear identity (switch/AP/router platform + capabilities). Scapy is best-effort: `pip install scapy` (+ Npcap on Windows) enables it, otherwise the agent scans actively only. pysnmp/SNMP (walks), `manuf`/OUI (MAC→vendor).

The stack runs five services:

| Service | Purpose | Local port |
|---------|---------|-----------|
| `postgres` | Database (auto-applies schema on first boot) | 5432 |
| `redis` | Celery message broker + pause/stop state | 6379 |
| `backend` | FastAPI REST + WebSocket API | 8000 |
| `celery_worker` | Runs scan jobs in the background | — |
| `frontend` | React UI (built static site) | 3000 |

> **Networking note:** if you want a scan to actually find live hosts, run the stack on a machine/interface that can reach the target subnet. A VPN that cannot route to the target LAN will still let the scan *run*, but it will report no live hosts / no open ports.

---

## Quick start

### Start everything

From the project root, run:

```powershell
powershell -ExecutionPolicy Bypass -File start-all.ps1
```

This does, in order:

1. Starts the Docker Compose stack (`postgres`, `redis`, `backend`, `celery_worker`, `frontend`) — `docker compose up -d`
2. Waits for the backend API to become ready (~up to 60 s, health-polled)
3. Starts the LAN scanner agent as a background process

Data is **preserved across restarts** (`docker compose down` is never called with `-v`). The script is **idempotent** — re-running it is safe.

Once started:

- **Web UI:** <http://localhost:3000>
- **API docs (Swagger):** <http://localhost:8000/docs>
- **Health check:** <http://localhost:8000/health> → `{"status":"ok"}`

### Stop everything

```powershell
powershell -ExecutionPolicy Bypass -File stop-all.ps1
```

This stops the LAN scanner agent first, then brings the Compose stack down **without** `-v`, so the Postgres data volume and all stored scans/hosts/findings are **preserved**. Idempotent — safe to run even if things are already stopped.

### First login

The stack ships with a **demo admin user**. On a fresh database, seed it once:

```powershell
docker compose exec backend python seed.py
```

| Field | Value |
|-------|-------|
| Email | `demo@pentest.local` |
| Password | `password123` |

The UI redirects to `/login` if you aren't authenticated.

---

## Manual start (docker compose)

Same result as `start-all.ps1` step 1, without the agent:

```bash
docker compose up -d --build
```

Verify everything is healthy:

```bash
docker compose ps
```

Expected: `postgres` and `redis` show `(healthy)`; the rest show `Up`.

**Layer-2 note:** all containers run inside Docker's own virtual network. They are reachable from your LAN but are **not** on the target subnet's broadcast segment — so by default the container can only do Layer-3 (TCP/UDP) scanning. To get **ARP → MAC/vendor and exact OS detection**, deploy a [scanner agent](#scanner-agents) on a machine that sits on the target LAN. Without an agent, scans run L3-only and MAC/vendor/OS fields stay blank (that is correct behaviour, not a bug).

### Local development (no Docker)

Backend:

```bash
cd backend
pip install -r requirements.txt
# set DATABASE_URL, REDIS_URL, JWT_SECRET in environment or backend/.env
python seed.py           # creates tables + demo user (requires running Postgres)
uvicorn app.main:app --reload --port 8000
celery -A app.services.scan_worker worker --loglevel=info
```

Frontend:

```bash
cd frontend
npm install
npm run dev    # http://localhost:3000
```

Frontend requires `nmap` installed on the host for non-containerized local scanning.

---

## Scanner agents

> **Why agents?** The Docker stack runs inside its own virtual network, so it cannot see ARP or do raw-SYN / `-O` OS fingerprinting against a real LAN.

The **scanner agent** is a small, self-contained CLI in `agent/` that you run **on any machine that sits on the target LAN**. It performs discovery + port scan + fingerprint **locally** (where ARP → MAC/vendor and `-O` → exact OS actually work) and reports results back over **HTTPS using an API key** — no remote shell, no SSH host involved.

### Register an agent

1. Open **Agents** (top nav).
2. Click **Create agent**; give it a unique **name**, the **subnets** it can reach at Layer-2 (comma-separated, e.g. `192.168.1.0/24`), and optional notes.
3. Copy the **one-time API key** shown (it's only displayed once).

### Run the agent

On the LAN machine (Windows/macOS/Linux with **nmap** installed; Windows needs **Npcap**):

```bash
python agent/scanner_agent.py --server http://<SERVER_IP>:8000 --name my-lan \
  --api-key <KEY> --subnets 192.168.1.0/24
```

Or as a container on a Linux LAN host (host networking + raw sockets = real L2):

```bash
docker build -t scanner-agent -f agent/Dockerfile .
docker run -d --network=host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e SCANNER_AGENT_KEY=<KEY> \
  scanner-agent --server http://<SERVER_IP>:8000 --name my-lan
```

The agent heartbeats every few seconds. Once it's **online**, new scans whose targets fall inside its subnets are **automatically delegated to it** — no config change needed. It streams console lines into the same live feed as in-worker scans and its results flow through the same risk / topology / report pipeline.

> **`--connect` flag:** if your user can't do raw SYN scans (no root / no Npcap), add `--connect` to use TCP connect scans instead. On Windows with Npcap, omit it to get SYN + full OS fingerprinting.

### Passive fingerprinting (optional, needs Scapy)

While the agent runs it also **passively sniffs** on its LAN-facing interface and
harvests identity evidence the active scans would miss, then folds it into the
host records it posts (so the server's classifier uses it like any other
hostname/vendor/OS evidence):

- **DHCP** — the hostname and vendor-class-id devices advertise while leasing an
  address. This names privacy-MAC phones/tablets (their OUI is randomised away)
  and reveals brand/OS for printers, routers, cameras and NAS.
- **ARP** — real IP ↔ MAC bindings for devices whose radios ignore the broadcast
  ARP ping nmap sends.
- **CDP / LLDP** — network gear announces itself: switch/AP/router identity,
  platform, software version, and authoritative system capabilities. A switch
  that never answers L3 probes is still named and classified.

Enable it by installing `scapy` in the agent's interpreter (Npcap required on
Windows). If it's missing, the agent logs once and continues active-only — it is
always best-effort. Passive evidence is merged **fill-if-blank**: a stronger
`nmap -O` / SNMP result always wins.

**Verified behaviour** (end-to-end run against this LAN): an agent on the Windows host produced results the L3-only container never could — a real **OS** (`Microsoft Windows 11 23H2`) + 10 open ports (SMB 445, postgres, redis, etc.) on one target, and a real **MAC + vendor** (`6c:f1:7e` → Zhejiang Uniview) on an IP camera target.

---

## Using the platform

### Create an engagement

An **engagement** bundles a client, a time window, and — critically — the **authorized scope** (CIDR ranges) that scans are allowed to touch.

1. On the **Engagements** page (`/`), click **New Engagement**.
2. Fill in **Client name**, **Engagement name**, **Authorized scope** (one or more CIDRs, e.g. `10.0.0.0/24, 192.168.1.0/24`), and optional start/end dates.
3. Click **Create**.

> Security: any scan target *outside* this scope is rejected server-side with an HTTP `422` and logged to `audit_log` as `scope_rejected`.

### Start a scan

1. On the **Engagement Detail** page (`/engagements/:engagementId`), find the **Start Scan** section.
2. Enter **targets** — ideally IPs reachable from the current network, e.g. `10.0.0.5` or `10.0.0.0/24`.
3. Pick a **profile**:

   | Profile | Behavior |
   |---------|----------|
   | `quick` | Fast (`-T4`) — good default for speed. |
   | `full` | Thorough (`-T3`) deep service/OS scan. |
   | `stealth` | Heavily throttled (`-T1`) — for fragile OT/IoT devices. |
   | `passive_only` | No port scanning — discovery + SNMP/topology only. |

4. Set a **port range** (e.g. `1-1000` or `1-65535`) and click **Start Scan**.

The UI navigates to the **Live Scan view**; a Celery job is queued and picked up by the worker automatically (or delegated to an online agent whose subnets cover the targets).

### Watch a live scan

The **Live Scan** screen shows a WebSocket-driven real-time feed: discovery/port-scan progress, host counters, a scrolling **activity feed** (every entry carries its own server-assigned timestamp, so replayed buffered events keep their real times), a scrolling **console pane** with the exact `nmap` commands, and **Pause / Resume / Stop** controls.

### Review results

- **Inventory** — virtualized table of every host (IP, MAC, vendor, hostname, device type, OS guess, open ports, risk, tags). Search / filter / sort, bulk tag and bulk export.
- **Host Detail** — click any host IP: full attributes, open-ports table with service/version/banner, SNMP block, editable notes & tags.
- **Topology** — force-directed graph: nodes colored by risk severity, dashed **subnet-zone rings** plus an internet/edge cloud node, device-type icons, gray `in_subnet`, amber dashed `gateway`, and cyan `l2` links, zoom/pan/drag, responsive canvas.
- **Findings** — severity-sorted findings (default SNMP community, unencrypted protocols, outdated software, exposed admin panels); group by severity/type/host, toggle include-in-report, edit recommendations.
- **Diff two scans** — pick an A/B scan pair to see `+` new hosts, `−` gone hosts, `~` changed ports, and new/resolved findings. Tracks what changed since the last scan.
- **Report / Export** — executive summary, device + severity charts, coverage & limitations; export **JSON**, **CSV**, or a WeasyPrint-rendered **PDF** client report.

---

## Scan pipeline

### Lifecycle

```
queued → discovering → scanning → fingerprinting → analyzing → completed
                                        │
                                        └ (or) failed / stopped
```

When an online scanner agent covers the targets, the scan is **delegated** instead:

```
queued → agent_running → (agent executes) → analyzing → completed / failed
```

| Status | Meaning |
|---|---|
| `queued` | Scan row created, Celery task submitted |
| `agent_running` | Scan handed to a scanner agent; its logs/results drive completion |
| `discovering` | Phase 0 — host discovery (CIDR expansion + probes) |
| `scanning` | Phases 1–2 — re-verification + port scan |
| `fingerprinting` | Phase 3 — deep service/OS fingerprint on open ports |
| `paused` | User paused; progress frozen between phases (worker or agent) |
| `analyzing` | Risk rules + topology + final DB persistence |
| `completed` | Done, `progress_pct = 100` |

### Profiles and nmap timing

The `profile` only changes the nmap timing template (`-T*`); everything else is identical.

| Profile | `-T` flag | When to use |
|---|---|---|
| `quick` | `-T4` | Fast top-1000 sweep, standard engagements |
| `full` | `-T3` | Comprehensive top-10000 scan, deep fingerprinting |
| `stealth` | `-T1` | Heavily throttled; safe for fragile OT/IoT devices |
| `passive_only` | *(none)* | No active port scanning — discovery + SNMP only, zero footprint |

### Phase 0 — Host discovery

1. **Expand targets** into concrete IPv4 addresses (`/24` → 254 usable IPs; network `.0` and broadcast `.255` excluded; `/31`/`/32` kept whole).
2. **L2-first, L3-fallback** — if an online agent's subnets cover the targets, the scan is delegated (real ARP → MAC/vendor). Otherwise it warns (`No online L2-capable agent covers the targets — falling back to L3 container scan…`) and proceeds L3-only.
3. **Liveness probe** — concurrent TCP connect (64 threads, 1 s timeout) on the probe ports (`80, 443, 22, 445, 3389, 23, 53, 8080, 8443, 515, 631, 135, 139`). Answering hosts are marked `up` (`tcp_probe`); the rest are still registered as `scope` so the inventory mirrors the scan order.
4. **Register hosts** — each emits a `host_discovered` WS event.

### Phase 1 — Re-verify down hosts (skipped)

Always skipped for L3 scans: TCP probes are the ground truth for liveness, and `nmap -sn` on routed subnets is unreliable (routers/tunnels proxy-ARP → false positives). Real L2 discovery and firewalled-host re-checks happen on a **scanner agent** when one is online.

### Phase 2 — Port scan (connect, no fingerprint)

Per confirmed-up host, sequentially. Fast pass that only produces the open-port list:

```bash
nmap -sT <timing> -p <port_range> --open -oX - <ip>     # TCP
nmap -sU <timing> -p <port_range> --open -oX - <ip>     # UDP
```

`--open` keeps output compact; every open port is stored and a `host_updated` WS event with the `ports[]` array fires (this is what the **Open Ports** counter counts). One command per host, 60 s timeout, progress `20% → 70%`.

### Phase 3 — Service fingerprinting (open ports only)

Version detection, default scripts, and OS detection run **only on ports already proven open**:

```bash
nmap -sT -sV -O <timing> -p <ports> --open -oX - <ip>
nmap -sU -sV <timing> -p <ports> --open -oX - <ip>
```

Banners are truncated to 500 chars; timeout 120 s per host.

### Analyzing — risk rules, SNMP, topology

1. **SNMP walk** — `snmpget -v1 -c public -On` against `sysDescr/sysName/sysLocation/sysObjectID/sysUpTime`. Success stores the fields, infers vendor from the `sysObjectID` prefix, marks `default_community_found=True` (a finding), and contributes to device-type classification.
2. **Risk rules** (`run_risk_rules`) — default SNMP community; banner/version vs. a curated outdated-software table (`KNOWN_OUTDATED`); exposed admin panels (SSH/Telnet/admin-web on gateways); unencrypted protocols (Telnet/FTP/HTTP/SMB on internet-facing hosts).
3. **Topology** (`capture_topology`) — hosts are chained into `l2_adjacency` edges (no self-loops, no CIDR-string nodes); subnet-zone + gateway detection produces the amber internet edges on the graph.

Finally `scan_completed` fires; raw nmap XML per scan/phase is stashed under `backend/scan_output/<scan_id>/` (runtime artifact, regenerated on each scan).

### Live console

Commands and output stream **live** (nmap runs via `Popen`; stderr is forwarded line-by-line to Redis → WS). Console lines: green start banner, cyan command, gray nmap progress/summary, amber `[timeout after 60s]`, red `=== Scan FAILED ===`. Timeouts kill the process; the panel auto-scrolls.

### Device-type classification

Each host is classified into one of 20 canonical types (smartphone, laptop, printer, ip_camera, router, switch, physical_server, vm_server, nas, iot_*, etc.) from its MAC OUI/vendor plus the set of **open** ports. Manual override is available in the Host Detail drawer (PATCH).

---

## REST API

Base URL: `http://localhost:8000` (Swagger at `/docs`). Endpoints marked 🔒 require `Authorization: Bearer <token>`; agent endpoints marked ⚙️ use the agent API key via the `X-Api-Key` header.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login → returns `access_token` + `role` (no token needed) |
| `POST` | `/api/auth/refresh` | Refresh token flow (returns 501 by design) |

### Engagements

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/engagements` | Create engagement (with authorized scope) 🔒 |
| `GET` | `/api/engagements` | List engagements 🔒 |
| `GET` | `/api/engagements/{engagement_id}` | Get one engagement 🔒 |
| `GET` | `/api/engagements/{engagement_id}/scans` | List scans 🔒 |
| `DELETE` | `/api/engagements/{engagement_id}` | Delete engagement (admin) 🔒 |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/engagements/{engagement_id}/scans` | Start a scan (`targets`, `profile`, `port_range`) 🔒 |
| `GET` | `/api/scans/{scan_id}` | Get scan status/progress 🔒 |
| `DELETE` | `/api/scans/{scan_id}` | Stop / kill a scan 🔒 |
| `POST` | `/api/scans/{scan_id}/pause` | Pause a scan 🔒 |
| `POST` | `/api/scans/{scan_id}/resume` | Resume a paused scan 🔒 |
| `POST` | `/api/scans/{scan_id}/reverify` | Re-verify a completed scan (down hosts + unscanned ports) 🔒 |
| `GET` | `/api/scans/{scan_id}/hosts` | List hosts (paginated, searchable) 🔒 |
| `GET` | `/api/scans/{scan_id}/hosts/{host_ip}` | Host detail incl. ports + SNMP 🔒 |
| `PATCH` | `/api/scans/{scan_id}/hosts/{host_ip}` | Annotate host (notes/tags/etc.) 🔒 |
| `GET` | `/api/scans/{scan_id}/topology` | Topology nodes + edges 🔒 |
| `GET` | `/api/scans/{scan_id}/findings` | List findings 🔒 |
| `PATCH` | `/api/findings/{finding_id}` | Toggle include-in-report / edit 🔒 |
| `GET` | `/api/scans/{scan_id}/diff/{other_scan_id}` | Compare two scans 🔒 |

### Export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/scans/{scan_id}/export?format=json` | JSON export 🔒 |
| `GET` | `/api/scans/{scan_id}/export?format=csv` | CSV export 🔒 |
| `GET` | `/api/scans/{scan_id}/export?format=pdf` | PDF client report 🔒 |

### Agent API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/agents` | Register an agent → returns the one-time API key 🔒 |
| `GET` | `/api/agents` | List agents with live status 🔒 |
| `DELETE` | `/api/agents/{agent_id}` | Remove an agent 🔒 |
| `POST` | `/api/agents/heartbeat` | Agent liveness + capability report ⚙️ |
| `GET` | `/api/agents/tasks/next` | Poll & claim the next queued scan task ⚙️ |
| `GET` | `/api/agents/tasks/{task_id}/state` | Check paused/stopped state ⚙️ |
| `POST` | `/api/agents/tasks/{task_id}/log` | Stream a console line to the live feed ⚙️ |
| `POST` | `/api/agents/tasks/{task_id}/result` | Submit scan results (hosts, ports, OS, SNMP) ⚙️ |

### Example: start a scan (PowerShell)

```powershell
# 1. Login
$login = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/login" `
  -Method Post -ContentType "application/json" `
  -Body (@{ email="demo@pentest.local"; password="password123" } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.access_token)" }

# 2. Start a scan on an engagement
$eng = "<ENGAGEMENT_UUID>"
$body = @{ targets = @("10.0.0.5"); profile = "quick"; port_range = "1-1000" } | ConvertTo-Json
$scan = Invoke-RestMethod -Uri "http://localhost:8000/api/engagements/$eng/scans" `
  -Method Post -Headers $headers -ContentType "application/json" -Body $body
Write-Output "Scan: $($scan.id) status=$($scan.status)"

# 3. Poll status
$s = Invoke-RestMethod -Uri "http://localhost:8000/api/scans/$($scan.id)" -Headers $headers
Write-Output "status=$($s.status) progress=$($s.progress_pct)% hosts=$($s.hosts_discovered)"

# 4. Export the PDF report
Invoke-WebRequest -Uri "http://localhost:8000/api/scans/$($scan.id)/export?format=pdf" `
  -Headers $headers -OutFile "report-$($scan.id).pdf"
```

---

## WebSocket live feed

Connect to `ws://localhost:8000/ws/scans/{scan_id}` (swap `http` → `ws`) to receive live scan events:

```json
{"type": "scan_started", "scan_id": "..."}
{"type": "host_discovered", "host": {"id": "...", "ip": "10.0.0.5"}}
{"type": "host_updated", "host_id": "...", "ip": "...", "ports": [...]}
{"type": "finding_added", "scan_id": "..."}
{"type": "scan_delegated", "scan_id": "...", "agent": "my-lan"}
{"type": "scan_completed", "scan_id": "..."}
{"type": "scan_failed", "scan_id": "...", "error": "..."}
```

Every event also carries a `ts` (ISO-8601 server timestamp) applied at emission — even buffered replays on connect show their real times in the UI's activity feed. The **Live Scan** screen consumes exactly this feed.

---

## Frontend screens

- **Login** — JWT email/password.
- **Engagements List** — create/list client engagements with authorized scope.
- **Engagement Detail** — scan list, New Scan setup, re-verify, two-scan diff picker.
- **Live Scan View** — WebSocket counters, progress, timestamped activity feed, console pane, Pause/Resume/Stop, re-verify view.
- **Asset Inventory** — virtualized table (IP, MAC, vendor, device type, OS, ports, risk, tags), search/filter/sort, bulk export/tag.
- **Network Topology** — force-directed graph with severity coloring, device-type icons, subnet-zone rings, gateway/internet edges, responsive sizing, zoom/pan.
- **Host Detail Drawer** — full host info, ports table (service/version/banner), SNMP block, editable notes/tags.
- **Findings Summary** — severity-sorted, group-by (severity/type/host), include-in-report toggles, editable recommendations.
- **Agents** — register/manage scanner agents, one-time keys, live online/offline status, run instructions.
- **Report/Export** — executive summary, device + severity charts, coverage & limitations, export JSON/CSV/PDF.

---

## Safety / throttling

- **Scan profiles control request rate**, not just port count: `stealth` is heavily throttled to protect fragile OT/IoT devices that can crash under aggressive scanning.
- **Kill switch** — `DELETE /api/scans/{id}` revokes the Celery task and terminates subprocesses (`terminate=True`); **pause/resume** hold scans cooperatively between phases (Redis flag, also honored by agent-delegated scans).
- Scope is validated server-side against the engagement's `authorized_scope`.

## Security of the tool itself

- JWT expiry + role checks (only `admin` can delete engagements).
- Passwords hashed with bcrypt.
- HTTPS-only in any non-local deployment.
- `audit_log` retained for the life of the engagement — every scan action is recorded.
- `archived` engagements can have raw scan data exported then purged.
- Keep `.env` out of version control (already gitignored); rotate any agent API keys that ever leave a trusted machine.

---

## Data model

The full PostgreSQL schema is in `database/migrations/001_init.sql`. Key design decision: **`hosts` rows are per-scan** (not a single mutable table), so scan-to-scan diffing ("what's new/changed/gone since last scan") is just a query joining on `ip`/`mac` across `scan_id`s.

Core entities: `users`, `engagements`, `scans`, `hosts`, `ports`, `snmp_info`, `findings`, `topology_edges`, `audit_log`, `agents`, `agent_tasks`.

---

## Troubleshooting

### "I started a scan but it found nothing / no ports"

- Confirm the target is **reachable** from the current network. On a VPN that can't route to the LAN, the scan completes but returns no live hosts.
- Try a **single IP** you know is up, `quick` profile, small port range.
- Check the worker log: `docker compose logs -f celery_worker`.

### "A scan is stuck in `queued`"

The Celery worker isn't processing. Confirm it's up (`docker compose ps`), inspect logs, and restart if stale: `docker compose restart celery_worker`.

### "Out-of-scope target rejected"

Expected and by design — the API returns `422` with `Targets outside authorized scope: <ip>` and logs it. Widen the engagement's authorized scope first if the host is genuinely in scope.

### "MAC / Vendor / Hostname / OS are all empty"

The container runs on Docker's virtual network, so it has no Layer-2 access — no ARP → no MAC/vendor, and heavily-filtered connect scans may produce no `-O` match. **Fix:** deploy a [scanner agent](#scanner-agents) on the LAN; scans targeting its subnets are delegated automatically and return real data.

### "The scan used the L3 container fallback / no agent took it"

Agents are only used when one is **online** and its **subnets cover the targets**. Check the **Agents** page — it must show `online` (heartbeats every few seconds) and list the target's subnet. Confirm the agent host can route to the target LAN.

### "I changed backend code — do I need to rebuild?"

- **Python/code-only changes:** `./backend` is volume-mounted; uvicorn runs with `--reload`, so backend changes apply on save. Restart `celery_worker` to pick up worker code changes.
- **Dependency / Dockerfile changes:** rebuild with `docker compose up -d --build`.

### "The scan found the host but it's type `unknown`"

Device type is inferred from MAC vendor and open ports. A host that didn't answer ARP/SNMP with identifiable traits may stay `unknown` — that's normal. You can set the type manually in the Host Detail drawer.

### "I see the harmless bcrypt warning in logs"

`(trapped) error reading bcrypt version` is a known passlib/bcrypt version mismatch. Login + hashing still work; safe to ignore.

### Frontend topology looks broken after `npm install`

`react-force-graph` is patched at install time by `frontend/patch-force-graph.mjs` (wired as the package `postinstall` script and copied into the Docker image). **Never edit `node_modules/force-graph/` directly** — the patch chain also runs `patch-force-graph.mjs` in the frontend Docker build.

---

## Project layout

```
.
├── docker-compose.yml              # 5-service stack
├── .env.example                    # template for secrets (POSTGRES_*, JWT_SECRET, ...)
├── start-all.ps1                   # start stack + agent (quick start)
├── stop-all.ps1                    # stop agent + stack, data preserved
├── start-scanner-agent.ps1         # start the LAN agent as a background process
├── stop-scanner-agent.ps1          # stop the LAN agent
├── agent/
│   ├── scanner_agent.py            # distributable LAN L2 scanner (CLI)
│   └── Dockerfile                  # containerized agent (Linux, host-net)
├── database/migrations/001_init.sql  # PostgreSQL schema (applied on first boot)
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── seed.py                     # creates tables + demo admin user
│   ├── reclassify_hosts.py         # one-off device-type reclassifier for existing scans
│   └── app/
│       ├── main.py                 # FastAPI app + CORS + routers
│       ├── config.py               # settings (env-driven)
│       ├── database.py             # async SQLAlchemy engine
│       ├── models.py               # ORM models
│       ├── schemas.py              # Pydantic schemas
│       ├── auth.py                 # JWT auth helpers
│       ├── scope_utils.py          # CIDR in-scope validation
│       ├── websocket.py            # connection manager (+ event timestamps)
│       ├── routers/                # auth, engagements, scans, agents, export
│       └── services/               # scan_worker (Celery + pipeline + delegation),
│                                   # scanners, report_generator
└── frontend/
    ├── Dockerfile
    ├── package.json
    ├── patch-force-graph.mjs       # postinstall force-graph patch (do not hand-edit node_modules)
    └── src/
        ├── hooks/useApi.ts         # TanStack Query hooks (+ agents)
        ├── lib/                    # api client, types (device taxonomy), graph analysis, theme
        ├── components/             # Layout, badges, ScanNav, TopologyMinimap, SeverityBadge
        └── pages/                  # Login, Engagements, EngagementDetail, LiveScan,
                                    # AssetInventory, HostDrawer, Topology, Findings, Report, Agents
```