# Network Asset Discovery Platform — User Walkthrough

A step-by-step guide to using the platform from start to finish: standing up the
stack, logging in, scoping an engagement, running a scan, reviewing inventory,
topology, findings, and exporting a client-ready report — plus the full REST /
WebSocket API and troubleshooting.

> **Platform scope (important):** This is a *discovery, fingerprinting, and
> reporting* tool for authorized security testing. It does **not** exploit,
> brute-force credentials, or otherwise attack hosts. Only hosts inside an
> engagement's authorized scope are ever scanned.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Start the stack](#2-start-the-stack)
3. [First login (and seeding the demo user)](#3-first-login)
4. [Create an engagement](#4-create-an-engagement)
5. [Start your first scan](#5-start-your-first-scan)
6. [Watch a live scan](#6-watch-a-live-scan)
7. [Review the asset inventory](#7-review-the-asset-inventory)
8. [Inspect a host detail](#8-inspect-a-host-detail)
9. [Explore network topology](#9-explore-network-topology)
10. [Review findings](#10-review-findings)
11. [Diff two scans](#11-diff-two-scans)
12. [Generate & export the report](#12-generate--export-the-report)
13. [Scanner agents (full Layer-2 discovery)](#13-scanner-agents-full-layer-2-discovery)
14. [Stop / pause / resume a scan](#14-stop--pause--resume-a-scan)
15. [The REST API (reference)](#15-the-rest-api-reference)
16. [WebSocket live feed](#16-websocket-live-feed)
17. [Common workflows & troubleshooting](#17-common-workflows--troubleshooting)
18. [Where things live on disk](#18-where-things-live-on-disk)

---

## 1. Prerequisites

- **Docker + Docker Compose** (Docker Desktop works on Windows/macOS). On Windows,
  ensure **WSL2/virtualization** is enabled so the Docker engine actually starts.
- The repo contains the full stack; no separate runtime installs are needed
  because everything runs inside containers.

> **Networking note:** if you want a scan to actually find live hosts, run the
> stack on a machine/interface that can reach the target subnet. A VPN that
> cannot route to the target LAN will still let the scan *run*, but it will
> report no live hosts / no open ports.

---

## 2. Start the stack

From the project root, run:

```bash
docker compose up -d --build
```

This builds (first time only) and starts **one container per service**:

| Service | Purpose | Local port |
|---------|---------|-----------|
| `postgres` | Database (auto-applies schema on first boot) | 5432 |
| `redis` | Celery message broker + pause/stop state | 6379 |
| `backend` | FastAPI REST + WebSocket API | 8000 |
| `celery_worker` | Runs scan jobs in the background | — |
| `frontend` | React UI (built static site) | 3000 |

> **Layer-2 note:** all of these containers run inside Docker's own virtual
> network. They are reachable from your LAN but are **not** on the target
> subnet's broadcast segment — so by default the container can only do
> Layer-3 (TCP/UDP) scanning. To get **ARP → MAC/vendor and exact OS
> detection**, deploy a [scanner agent](#13-scanner-agents-full-layer-2-discovery)
> on a machine that sits on the target LAN. Without an agent, scans run
> L3-only and MAC/vendor/OS fields stay blank (that is correct behaviour, not
> a bug).

Verify everything is healthy:

```bash
docker compose ps
```

Expected: `postgres` and `redis` show `(healthy)`; the rest show `Up`.

> **Tip:** if the `docker` CLI isn't on your PATH (common with Docker Desktop on
> Windows), either run from PowerShell as:
> ```powershell
> $env:PATH = "C:\Users\sths2\AppData\Local\Programs\DockerDesktop\resources\bin;" + $env:PATH
> ```
> or use the full path to `docker.exe`.

---

## 3. First login

The stack ships with a **demo admin user**. If the database was just created
fresh, seed it once:

```bash
docker compose exec backend python seed.py
```

Then open the UI:

- **Frontend:** <http://localhost:3000>
- **API docs (Swagger):** <http://localhost:8000/docs>
- **Health check:** <http://localhost:8000/health> → `{"status":"ok"}`

**Login credentials:**

| Field | Value |
|-------|-------|
| Email | `demo@pentest.local` |
| Password | `password123` |

The UI redirects to `/login` if you aren't authenticated.

---

## 4. Create an engagement

An **engagement** bundles a client, a time window, and — critically — the
**authorized scope** (CIDR ranges) that scans are allowed to touch.

In the UI:

1. On the **Engagements** page (`/`), click **New Engagement**.
2. Fill in:
   - **Client name** — e.g. `Acme Corp`
   - **Engagement name** — e.g. `2026 Q3 Infrastructure Assessment`
   - **Authorized scope** — one or more CIDRs, e.g. `10.0.0.0/24, 192.168.1.0/24`
   - **Start / End dates** (optional) and **status** (`active` by default).
3. Click **Create**.

> Security: any scan target *outside* this scope is rejected server-side with an
> HTTP `422` and logged to `audit_log` as `scope_rejected`.

---

## 5. Start your first scan

A **scan** runs the full 5-stage pipeline against targets within an engagement.

1. On the **Engagement Detail** page (`/engagements/:engagementId`), find the
   **Start Scan** section.
2. Enter **targets** — ideally IPs reachable from the current network — e.g.
   `10.0.0.5` or a subnet `10.0.0.0/24`.
3. Pick a **profile**:

   | Profile | Behavior |
   |---------|----------|
   | `quick` | Fast (`-T4`) — good default for speed. |
   | `full` | Thorough (`-T3`) deep service/OS scan. |
   | `stealth` | Heavily throttled (`-T1`) — for fragile OT/IoT devices. |
   | `passive_only` | No port scanning — discovery + SNMP/topology only. |

4. Set a **port range** (e.g. `1-1000` or `1-65535`).
5. Click **Start Scan**.

The UI navigates to the **Live Scan view**; a Celery job is queued and picked up
by the worker automatically.

---

## 6. Watch a live scan

The **Live Scan** screen (`/engagements/:engagementId/scans/:scanId/live`) shows
a **WebSocket-driven** real-time feed:

- Discovery / port-scan progress percentage
- Host counters (discovered, in scope)
- A scrolling **activity feed** of events — every entry carries its own
  server-assigned timestamp, so replayed buffered events keep their real times
- A scrolling **console** pane showing the exact `nmap` commands being run
- **Pause / Resume / Stop** controls (see
  [§14 stop / pause / resume](#14-stop--pause--resume-a-scan))

Events you may see stream in: `scan_started`, `host_discovered`,
`host_updated`, `finding_added`, `scan_completed`, `scan_failed`, and — when a
[scanner agent](#13-scanner-agents-full-layer-2-discovery) takes over —
`scan_delegated` plus agent-prefixed console lines.

When the scan finishes, its status becomes `completed`. If the target is
unreachable (e.g. wrong network/VPN), the pipeline still completes but reports
hosts with no open ports and no findings — see
[troubleshooting](#17-common-workflows--troubleshooting).

---

## 7. Review the asset inventory

Open **Inventory** (`/engagements/:engagementId/scans/:scanId/inventory`).

This is a **virtualized table** of every host discovered in that scan:

- Columns: IP, MAC, vendor, hostname, device type, OS guess, open ports, risk, tags
- **Search** by IP/vendor/OS; **filter** by device type/status
- **Sort** any column
- Select rows to **bulk tag** or **bulk export**

Useful for spot-checking that the scan found what you expected.

---

## 8. Inspect a host detail

Click any host IP (or open
`/engagements/:engagementId/scans/:scanId/host/:hostIp`) for the **Host Detail
drawer**:

- Full host attributes (IP, MAC, vendor, device type, OS guess + confidence)
- **Open ports** table (port/protocol/state/service/version/banner)
- **SNMP block** if the device answered a walk on `161/udp`
- **Editable notes & tags** — annotate findings as you verify them (saved to
  `audit_log` as `host_annotated`)

---

## 9. Explore network topology

Open **Topology** (`/engagements/:engagementId/scans/:scanId/topology`).

A **force-directed graph** visualizes the discovered network:

- Nodes = hosts, colored by **risk severity**
- **Dashed subnet-zone rings** grouping hosts in the same CIDR (ring radius scales
  with host count), plus an Internet/edge cloud node
- Device-type icons and per-link styling:
  - gray `in_subnet` links (host → zone)
  - amber dashed `gateway` link (zone → internet)
  - cyan `l2` links between adjacent hosts
- **Zoom / pan / drag** to explore; hover nodes for details
- The canvas **resizes responsively** to fill its container

> L2 topology is best-effort: without a LAN-side
> [scanner agent](#13-scanner-agents-full-layer-2-discovery) there is no ARP/L2
> data, so the graph shows zone + gateway structure rather than rich L2
> adjacencies.

---

## 10. Review findings

Open **Findings** (`/engagements/:engagementId/scans/:scanId/findings`).

The risk engine auto-generates findings such as:

- **Default SNMP community string** in use
- **Unencrypted protocols** (Telnet/FTP/HTTP/SMB)
- **Potentially outdated software** (banner version vs. curated table)
- **Exposed admin panels** (web services)

You can:

- **Sort/group** by severity, type, or host
- **Toggle "include in report"** per finding
- **Edit** recommendations / titles
- See severity badges: `critical`, `concerning`, `notable`, `info`

---

## 11. Diff two scans

On the **Engagement Detail** page there's a **Compare** picker: choose two scans
(A vs B). The result shows:

- **+ new** hosts (in B, not in A)
- **− gone** hosts (in A, not in B)
- **~ changed** ports (open ports that differ)
- **new / resolved** findings between the two

This is how you track *what changed since the last scan* — ideal for
initial-vs-rebaseline comparisons between visits.

---

## 12. Generate & export the report

Open **Report** (`/engagements/:engagementId/scans/:scanId/report`).

The **client-ready initial discovery report** includes:

- Executive summary + coverage / host / findings statistics
- **Device breakdown** and **findings by severity** charts
- Full **asset inventory** table
- **Risk findings** (respects your include-in-report toggles)
- Coverage & limitations, methodology & tools appendix

**Export formats** (also available via API, see below):

- **JSON** — structured data
- **CSV** — spreadsheet-friendly asset list
- **PDF** — the formatted client report (rendered with WeasyPrint)

Click the export button to download.

---

## 13. Scanner agents (full Layer-2 discovery)

> **Why agents?** The Docker stack runs inside its own virtual network, so it
> cannot see ARP or do raw-SYN / `-O` OS fingerprinting against a real LAN.

The **scanner agent** is a small, self-contained program you
run **on any machine that sits on the target LAN**. It performs discovery + port
scan + fingerprint **locally** (where ARP → MAC/vendor and `-O` → exact OS
actually work) and reports results back over HTTPS using an **API key** — no
remote shell, no SSH host involved.

```
Docker stack (web/API/DB/worker)  <—— HTTPS polling + API key ——>  scanner-agent
       manages UI, risk, topology, reports        on a LAN-connected machine
                                                  (nmap -sn ARP, -sS/-sT -sV -O,
                                                   SNMP, HTTP banners)
```

### Register an agent

1. Open **Agents** (top nav).
2. Click **Create agent**; give it a unique **name**, the **subnets** it can reach
   at Layer-2 (comma-separated, e.g. `192.168.1.0/24`), and optional notes.
3. Copy the **one-time API key** shown (it's only displayed once).

### Run the agent

On the LAN machine (Windows/macOS/Linux with **nmap** installed; Windows needs
**Npcap**):

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

The agent heartbeats every few seconds. Once it's **online**, new scans whose
targets fall inside its subnets are **automatically delegated to it** — no config
change needed. It streams console lines into the same live feed as in-worker
scans and its results flow through the same risk / topology / report pipeline.

> **`--connect` flag:** if your user can't do raw SYN scans (no root / no Npcap),
> add `--connect` to use TCP connect scans instead. On Windows with Npcap,
> omit it to get SYN + full OS fingerprinting.

### Verified behaviour

In an end-to-end run against this LAN, an agent on the Windows host produced
results the L3-only container never could: a real **OS** (`Microsoft Windows 11
23H2`) + 10 open ports (SMB 445, postgresql, redis, etc.) on one target, and a
real **MAC + vendor** (`6c:f1:7e` → Zhejiang Uniview) on an IP camera target.

---

## 14. Stop / pause / resume a scan

### Stop (kill switch)

The **global kill switch** immediately halts a scan and **terminates the
subprocess** (Nmap), not just the DB row:

- **UI:** click **Stop** on the Live Scan screen or in the scan's row.
- **API:** `DELETE /api/scans/{scan_id}` — revokes the Celery task with
  `terminate=True` so child processes are killed. For agent-delegated scans, the
  agent polls a task-state endpoint and aborts cleanly.

### Pause / resume

- **Pause** holds a scan cooperatively between pipeline phases / subprocess
  steps (a Redis flag is polled by the worker; agent scans poll the same state).
  Progress stays frozen at `paused`.
- **Resume** clears the flag and the scan continues to completion.

Both are available on the Live Scan screen and in the scan list's Actions column.

---

## 15. The REST API (reference)

Base URL: `http://localhost:8000` (see Swagger at `/docs`). All endpoints below
marked 🔒 require `Authorization: Bearer <token>`. Agent endpoints marked ⚙️ use
the agent's API key via the `X-Api-Key` header.

### Auth

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login → returns `access_token` + `role` 🔒-free |
| `POST` | `/api/auth/refresh` | Refresh token flow (stub — returns 501 by design) |

### Engagements

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/engagements` | Create engagement (with authorized scope) 🔒 |
| `GET` | `/api/engagements` | List engagements 🔒 |
| `GET` | `/api/engagements/{engagement_id}` | Get one engagement 🔒 |
| `GET` | `/api/engagements/{engagement_id}/scans` | List scans for an engagement 🔒 |
| `DELETE` | `/api/engagements/{engagement_id}` | Delete engagement (admin) 🔒 |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/engagements/{engagement_id}/scans` | Start a scan (body: `targets`, `profile`, `port_range`) 🔒 |
| `GET` | `/api/scans/{scan_id}` | Get scan status/progress 🔒 |
| `DELETE` | `/api/scans/{scan_id}` | Stop / kill a scan 🔒 |
| `POST` | `/api/scans/{scan_id}/pause` | Pause a scan 🔒 |
| `POST` | `/api/scans/{scan_id}/resume` | Resume a paused scan 🔒 |
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

## 16. WebSocket live feed

Connect to `ws://localhost:8000/ws/scans/{scan_id}` (replace `http` with `ws`)
to receive live scan events:

```json
{"type": "scan_started", "scan_id": "..."}
{"type": "host_discovered", "host": {"id": "...", "ip": "10.0.0.5"}}
{"type": "host_updated", "host_id": "...", "ip": "...", "ports": [...]}
{"type": "finding_added", "scan_id": "..."}
{"type": "scan_delegated", "scan_id": "...", "agent": "my-lan"}
{"type": "scan_completed", "scan_id": "..."}
{"type": "scan_failed", "scan_id": "...", "error": "..."}
```

Every event also carries a `ts` (ISO-8601 server timestamp) applied at emission
— so even events replayed from the in-memory buffer on connect show their real
times in the UI's activity feed.

The UI's **Live Scan** screen consumes exactly this feed.

---

## 17. Common workflows & troubleshooting

### "I started a scan but it found nothing / no ports"

- Confirm the target is **reachable** from the current network. If you're on a
  VPN that can't route to the LAN, the scan completes but returns no live hosts.
- Try a **single IP** that you know is up, on a `quick` profile, with a small
  port range for a fast check.
- Check the worker log for errors:
  ```bash
  docker compose logs -f celery_worker
  ```

### "I see the harmless bcrypt warning in logs"

`(trapped) error reading bcrypt version` is a known passlib/bcrypt version
mismatch. Login + hashing still work; it is safe to ignore.

### "A scan is stuck in `queued`"

The Celery worker isn't processing. Confirm it's up and healthy:
```bash
docker compose ps
docker compose logs -f celery_worker
```
If the worker was restarted with stale code, restart it:
```bash
docker compose restart celery_worker
```

### "Out-of-scope target rejected"

That's expected and by design — the API returns `422` with
`Targets outside authorized scope: <ip>` and logs it. Widen the engagement's
authorized scope first if the host is genuinely in scope.

### "MAC / Vendor / Hostname / OS are all empty"

The container runs on Docker's virtual network, so it has no Layer-2 access to
the target LAN — no ARP → no MAC/vendor, and heavily-filtered connect scans may
produce no `-O` OS match. This is expected. **Fix:** deploy a
[scanner agent](#13-scanner-agents-full-layer-2-discovery) on a machine on the
LAN; scans targeting its subnets are automatically delegated to it and return
real MAC, vendor, hostname (reverse-DNS/SNMP) and OS data.

### "The scan used the L3 container fallback / no agent took it"

Agents are only used when one is **online** and its reported **subnets cover the
targets**. If none does, the scan falls back to in-container execution. Check
the **Agents** page — the agent must show `online` (heartbeats every few
seconds) and list the target's subnet. Also confirm the agent host can actually
route to the target LAN.

### "I changed backend code — do I need to rebuild?"

- **Python/code-only changes:** the `./backend` folder is volume-mounted into
  the containers; uvicorn runs with `--reload`, so backend changes apply on
  save. Restart `celery_worker` to pick up worker code changes.
- **Dependency / Dockerfile changes** (new pip/apt packages): rebuild:
  ```bash
  docker compose up -d --build
  ```

### "The scan found the host but it's type `unknown`"

Device type is inferred from MAC vendor and open ports. A host that didn't
answer ARP/SNMP with identifiable traits may stay `unknown` — that's normal.
You can set the type manually via the Host Detail drawer (PATCH).

---

## 18. Where things live on disk

```
.
├── docker-compose.yml                  # 5-service stack definition
├── .env / .env.example                 # secrets (POSTGRES_*, JWT_SECRET, ...)
├── WALKTHROUGH.md                      # this file
├── README.md                           # project overview + architecture
├── agent/
│   ├── scanner_agent.py                # distributable LAN L2 scanner (CLI)
│   └── Dockerfile                      # containerized agent (Linux, host-net)
├── database/migrations/001_init.sql    # PostgreSQL schema (applied on first boot)
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── seed.py                         # creates tables + demo admin user
│   └── app/
│       ├── main.py                     # FastAPI app + CORS + routers
│       ├── config.py / database.py / models.py / schemas.py
│       ├── auth.py / scope_utils.py / websocket.py
│       ├── routers/                    # auth, engagements, scans, agents, export
│       │   └── agents.py               # agent register/tasks/log/result API
│       └── services/
│           ├── scan_worker.py          # Celery + pipeline + scan delegation
│           ├── scanners.py             # Scapy ARP, SNMP, MAC vendor
│           └── report_generator.py     # WeasyPrint PDF report
└── frontend/
    ├── Dockerfile
    └── src/
        ├── App.tsx                     # routes / auth guard
        ├── hooks/useApi.ts             # TanStack Query hooks
        └── pages/                      # Login, Engagements, EngagementDetail,
                                        # LiveScan, AssetInventory, HostDrawer,
                                        # Topology, Findings, Report, Agents
```
