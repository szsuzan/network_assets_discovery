# Network Asset Discovery Platform

A professional-grade network asset discovery tool for penetration testing engagements. Discovers live assets on an in-scope network, fingerprints each host, maps network topology, surfaces risk-relevant findings, and produces a client-ready initial discovery report.

> **Out of scope for this entire system:** exploitation, credential brute-forcing, or any attack-execution capability. This is a *discovery, fingerprinting, and reporting* platform only.

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
- **Scanning tools:** Nmap (TCP/UDP port scans + service/OS fingerprinting) runs either in-container (L3-only) or, preferably, on a **scanner agent** placed on the target LAN for full Layer-2 (ARP → MAC/vendor + raw-SYN/`-O` → exact OS). Scapy (ARP/CDP/LLDP passive), pysnmp/SNMP (walks), `manuf`/OUI (MAC→vendor).

## Layer-2 scanning & scanner agents

The Docker stack runs on its own virtual network, so the in-container scanner can
only reach the LAN at Layer-3 (TCP/UDP) — it cannot see ARP or do raw-SYN OS
fingerprinting. The **scanner agent** solves this: a small self-contained CLI in
`agent/` that you run on any machine attached to the target LAN. It performs
discovery/port-scan/fingerprint locally (real MAC/vendor, real OS) and streams
results back over HTTPS using an API key — no remote shell required, so
migration/distribution is trivial.

```bash
python agent/scanner_agent.py --server http://<SERVER_IP>:8000 --name my-lan \
  --api-key <KEY> --subnets 192.168.1.0/24
```

Register the agent on the **Agents** page first to obtain its one-time key. When
an agent is online and its subnets cover the scan targets, scans are
automatically delegated to it; otherwise the container's L3 fallback runs.
See `WALKTHROUGH.md` §13 for full details.

## Prerequisites

- Docker + Docker Compose
- `nmap` installed on the host for non-containerized local scanning

## Getting Started

1. **Configure secrets** — copy the environment template:
   ```
   cp .env.example .env
   ```
   Edit `JWT_SECRET` with a strong random value before any non-local deployment.

2. **Start the stack:**
   ```
   docker compose up --build
   ```
   This starts `postgres` (auto-applies `database/migrations/001_init.sql`), `redis`, the `backend` API, a `celery_worker`, and the `frontend`.

3. **Access the apps:**
   - Frontend: http://localhost:3000
   - Backend API docs (Swagger): http://localhost:8000/docs
   - Health check: http://localhost:8000/health

4. **Create the demo user** (admin) when the stack is up:
   ```
   docker compose exec backend python seed.py
   ```
   Login with `demo@pentest.local` / `password123`.

## Local Development (no Docker)

Backend:
```
cd backend
pip install -r requirements.txt
# set DATABASE_URL, REDIS_URL, JWT_SECRET in environment or backend/.env
python seed.py           # creates tables + demo user (requires running Postgres)
uvicorn app.main:app --reload --port 8000
celery -A app.services.scan_worker worker --loglevel=info
```

Frontend:
```
cd frontend
npm install
npm run dev    # http://localhost:3000
```

## Data Model

The full PostgreSQL schema is in `database/migrations/001_init.sql`. Key design decision: **`hosts` rows are per-scan** (not a single mutable table), so scan-to-scan diffing ("what's new/changed/gone since last scan") is just a query joining on `ip`/`mac` across `scan_id`s.

Core entities: `users`, `engagements`, `scans`, `hosts`, `ports`, `snmp_info`, `findings`, `topology_edges`, `audit_log`, `agents`, `agent_tasks`.

## Scan Pipeline

1. **Scope validation** — any target outside `engagement.authorized_scope` rejects the job and writes an `audit_log` entry.
2. **Orchestration** — the worker checks for a live [scanner agent](#layer-2-scanning--scanner-agents) whose subnets cover the targets and, if one exists, **delegates the whole scan to it** (it streams logs and posts results through the same pipeline). Otherwise it falls back to in-container execution.
3. **Discovery** — Scapy ARP sweep for local subnets (agent/L2 only); TCP SYN probes for routed subnets; ICMP supplementary. MAC/vendor comes from real ARP when an agent is used.
4. **Port scan** — Nmap connect/syn scans of the configured port range, then Nmap deep scan (`-sV -sC -O`) on open ports. NSE script outputs (HTTP headers, RTSP methods, SMB, SSH, Redis info…) are captured into the port banner.
5. **Fingerprinting & risk analysis** — MAC vendor lookup, SNMP walk on 161/udp, reverse-DNS hostname fallback, device-type classification, and finding rules (default SNMP community, outdated software, exposed admin panels, unencrypted protocols).
6. **Topology capture** — subnet-zone clustering + gateway detection (amber route to internet), passive CDP/LLDP sniffing + traceroute hops.

Each stage is streamed to the client over WebSocket (`host_discovered`, `host_updated`, `finding_added`, `progress`, `scan_completed`); every event carries a server-assigned timestamp so buffered replays keep real times. Scans can be **paused / resumed / stopped** from the UI or API.

## Frontend Screens

- **Login** — JWT email/password.
- **Engagements List** — create/list client engagements with authorized scope.
- **Engagement Detail** — scan list, New Scan setup, two-scan comparison picker (diff).
- **Live Scan View** — WebSocket-driven counters, progress, activity feed with per-entry timestamps, console pane, Pause/Resume/Stop.
- **Asset Inventory** — virtualized table (IP, MAC, vendor, device type, OS, ports, risk, tags), search/filter/sort, bulk export/tag.
- **Network Topology** — force-directed graph with severity coloring, subnet-zone rings, gateway/internet edges, responsive sizing, zoom/pan.
- **Host Detail Drawer** — full host info, ports table (service/version/banner from NSE + nmap), SNMP block, editable notes/tags.
- **Findings Summary** — severity-sorted, group-by (severity/type/host), include-in-report toggles, editable recommendations.
- **Agents** — register/manage [scanner agents](#layer-2-scanning--scanner-agents), one-time keys, live online/offline status, run instructions.
- **Report/Export** — executive summary, device + severity charts, coverage & limitations, export JSON/CSV/PDF.

## Safety / Throttling

- **Scan profiles control request rate**, not just port count: `stealth` is heavily throttled to protect fragile OT/IoT devices that can crash under aggressive scanning.
- **Kill switch** — `DELETE /api/scans/{id}` revokes the Celery task and terminates subprocesses (`terminate=True`); **pause/resume** hold scans cooperatively between phases (Redis flag, also honored by agent-delegated scans).
- Scope is validated server-side against the engagement's `authorized_scope`.

## Security of the Tool Itself

- JWT expiry + role checks (only `admin` can delete engagements).
- Passwords hashed with bcrypt.
- HTTPS-only in any non-local deployment.
- `audit_log` retained for the life of the engagement — every scan action is recorded.
- `archived` engagements can have raw scan data exported then purged.

## Project Layout

```
.
├── docker-compose.yml
├── .env.example
├── agent/
│   ├── scanner_agent.py                # distributable LAN L2 scanner (CLI)
│   └── Dockerfile                      # containerized agent (Linux, host-net)
├── database/migrations/001_init.sql   # PostgreSQL schema
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── seed.py                        # creates demo user
│   └── app/
│       ├── main.py                    # FastAPI app + CORS + routers
│       ├── config.py                  # settings (env-driven)
│       ├── database.py                # async SQLAlchemy engine
│       ├── models.py                  # ORM models
│       ├── schemas.py                 # Pydantic schemas
│       ├── auth.py                    # JWT auth helpers
│       ├── scope_utils.py             # CIDR in-scope validation
│       ├── websocket.py               # connection manager (+ event timestamps)
│       ├── routers/                   # auth, engagements, scans, agents, export
│       └── services/                  # scan_worker (Celery + pipeline + delegation),
│                                      # scanners, report_generator
└── frontend/
    ├── Dockerfile
    ├── package.json
    └── src/
        ├── hooks/useApi.ts            # TanStack Query hooks (+ agents)
        ├── lib/                       # api client, types, theme
        ├── components/                # Layout, badges, scan nav
        └── pages/                     # Login, Engagements, LiveScan, Inventory,
                                       # Topology, Findings, Report, HostDrawer, Agents
```
