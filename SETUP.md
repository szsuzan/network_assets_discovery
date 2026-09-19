# SubNex — Setup & Installation

This guide walks through installing and running SubNex from a fresh `git clone`
on **Windows, macOS, or Linux**. Every step is written to work on any host; OS
specifics are called out inline.

Two deployment styles:

1. **Docker stack (required)** — Postgres, Redis, and the FastAPI backend (which
   also runs the Celery scan worker and serves the built web UI). This is how
   the whole service layer runs everywhere.
2. **Scanner agent (recommended, optional)** — a small Python CLI run *on a
   machine that sits on the target LAN*. It does real Layer-2 discovery
   (ARP → MAC/vendor, nmap `-O` → exact OS), which the Docker container cannot
   do from its own virtual network.

---

## 1. Prerequisites per OS

### Git

| OS | How to install |
|----|----------------|
| Windows | [git-scm.com](https://git-scm.com/download/win) — accepts the defaults (includes Git Bash) |
| macOS | `xcode-select --install` (installs Git + compilers), or [git-scm.com](https://git-scm.com/download/mac) |
| Linux (Debian/Ubuntu) | `sudo apt update && sudo apt install -y git` |
| Linux (Fedora) | `sudo dnf install -y git` |

### Docker

| OS | How to install | Verify |
|----|----------------|--------|
| Windows | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (WSL 2 backend — the default), then start it from the Start menu | `docker version` |
| macOS | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Apple Silicon: the ARM build) | `docker version` |
| Linux (Debian/Ubuntu) | `sudo apt install -y docker.io docker-compose-v2 && sudo usermod -aG docker $USER && newgrp docker` | `docker compose version` |
| Linux (Fedora) | `sudo dnf install -y docker docker-compose && sudo systemctl enable --now docker && sudo usermod -aG docker $USER && newgrp docker` | `docker compose version` |
| Any (alternative) | [Rancher Desktop](https://rancherdesktop.io/) or [Colima](https://github.com/abiosoft/colima) (`colima start`) | `docker version` |

> The Compose stack needs **Compose v2**. Recent Docker Desktop ships it; on
> Linux install the `docker-compose-v2` package (or `docker-compose-plugin` on
> Fedora) so `docker compose` (with a space) works.

### Node.js ≥ 18 + npm (build the web UI)

| OS | How to install | Verify |
|----|----------------|--------|
| Windows | `winget install OpenJS.NodeJS.LTS` or [nodejs.org](https://nodejs.org/) | `node -v` |
| macOS | `brew install node` ([Homebrew](https://brew.sh) first) | `node -v` |
| Linux (Debian/Ubuntu) | `sudo apt install -y nodejs npm` (Node 18+ from the repos on recent distros; otherwise [NodeSource](https://github.com/nodesource/distributions)) | `node -v && npm -v` |
| Linux (Fedora) | `sudo dnf install -y nodejs npm` | `node -v && npm -v` |

If your distro ships an older Node, use the [NodeSource installer](https://github.com/nodesource/distributions):
`curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs`

### Python ≥ 3.11 (only for the scanner agent / local backend dev)

| OS | How to install | Verify |
|----|----------------|--------|
| Windows | `winget install Python.Python.3.11` or [python.org](https://www.python.org/downloads/) (tick "Add python.exe to PATH") | `python --version` |
| macOS | `brew install python@3.11` | `python3 --version` |
| Linux (Debian/Ubuntu) | `sudo apt install -y python3 python3-venv python3-pip` | `python3 --version` |
| Linux (Fedora) | `sudo dnf install -y python3 python3-pip` | `python3 --version` |

### Nmap + capture libs (only for the scanner agent)

Nmap runs **inside** the Docker images for container-side scanning; the host
only needs it when you run the agent directly (not in a container).

| OS | How to install |
|----|----------------|
| Windows | [nmap.org](https://nmap.org/download.html) installer (includes Npcap — accept the "install Npcap in WinPcap API-compatible mode" default); SYN scans need **running as admin** or the agent's `--connect` flag |
| macOS | `brew install nmap` (+ `brew install libpcap` is already satisfied by macOS libpcap) |
| Linux (Debian/Ubuntu) | `sudo apt install -y nmap libpcap-dev` |
| Linux (Fedora) | `sudo dnf install -y nmap` |

Optional agent-side passive fingerprinting needs Scapy:
`pip install scapy` (Windows: [Npcap](https://npcap.com) must be installed; on
macOS/Linux libpcap suffices). Without Scapy the agent continues active-only.

---

## 2. Clone the repository

```bash
git clone https://github.com/szsuzan/network_assets_discovery.git
cd network_assets_discovery
```

The product is **SubNex**; the repo keep its GitHub name `network_assets_discovery`.

---

## 3. Create `.env` with real secrets (required)

The Compose stack intentionally has **no placeholder secrets** — it will not
start (`${VAR:?…}` fail-fast) unless `POSTGRES_PASSWORD` and `JWT_SECRET` are
set. `.env` is gitignored and never committed.

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env
```

**macOS / Linux:**

```bash
cp .env.example .env
```

Then generate two strong random secrets and paste them into `.env`:

```bash
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(48))"
```

Example final `.env`:

```
POSTGRES_USER=pentest
POSTGRES_PASSWORD=aH6x...          # from the first token_urlsafe output
POSTGRES_DB=subnex
JWT_SECRET=5FqY...                 # from the second token_urlsafe output
JWT_ALGORITHM=HS256
JWT_EXPIRY_MINUTES=60
```

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_USER` | `pentest` | Postgres role (used to build `DATABASE_URL`) |
| `POSTGRES_PASSWORD` | *(required)* | Postgres password |
| `POSTGRES_DB` | `subnex` | Postgres database name |
| `JWT_SECRET` | *(required, ≥ 16 chars)* | Auth token signing key — backend refuses a placeholder |
| `JWT_ALGORITHM` / `JWT_EXPIRY_MINUTES` | `HS256` / `60` | Token settings |

---

## 4. Start the stack

### Option A — one-command scripts (Windows)

From an elevated PowerShell in the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File start-all.ps1
```

This builds the UI the first time, starts Docker Desktop if needed (waits up to
~120 s), brings up the Compose stack, waits for the backend health check, then
starts the LAN agent (requires `SCANNER_AGENT_KEY` or `%TEMP%\opencode\new_agent_key.txt`).

### Option B — one-command scripts (macOS / Linux / WSL)

```bash
chmod +x start-all.sh stop-all.sh start-scanner-agent.sh stop-scanner-agent.sh
./start-all.sh
```

Identical flow to Option A. The scan agent step is optional in the bash script
(it reports and continues if no key is configured); set the key first if you
want it started automatically:

```bash
export SCANNER_AGENT_KEY="<key from the Agents page>"
./start-all.sh
```

### Option C — manual, any OS (same result, no agent)

```bash
cd frontend && npm install && npm run build && cd ..   # build the UI once
docker compose up -d --build                            # start the stack
docker compose ps                                       # postgres+redis (healthy), backend (Up)
```

**What happens automatically at first boot:** the backend applies the single
`database/migrations/001_init.sql` (the full v1 schema, squashed from the earlier
001–018 chain) and records the version in `schema_version`; it also creates the
demo admin user **only when the database has no users yet**. No manual `psql` /
`seed.py` steps are needed.

---

## 5. First login and first scan

1. Open <http://localhost:8000>.
2. Log in with the bootstrap account **`demo@pentest.local` / `password123`**.
   The first login forces you to set your own password before anything unlocks.
   Write it down — the bootstrap password stops working after the change.
3. **Engagements → New Engagement** → add your network to **Authorized scope**
   (e.g. `192.168.1.0/24`).
4. **Engagement Detail → Start Scan** → target an IP/CIDR inside that scope,
   pick a profile (`quick` is the usual default), set a port range, and watch
   the live feed.
5. Results appear under **Inventory**, **Topology**, **Findings**; export a
   client report under **Report/Export** (JSON/CSV/PDF).

> **Networking note:** the scan host must be able to *reach* the target network.
> Behind a VPN that cannot route to the LAN, scans complete but return no live
> hosts. Without an agent the container is Layer-3-only: ARP/MAC/vendor/OS stay
> blank (correct behaviour, not a bug).

---

## 6. (Recommended) Add a scanner agent

Agent-delegated scans get real Layer-2 discovery: ARP → MAC/vendor, `nmap -O`,
and passive sniffing (DHCP/mDNS/NBNS/SSDP/LLDP-CDP) for hosts that hide behind
firewalled TCP. Register one on a machine that sits on the target LAN.

1. Open **Agents** → **Create agent** → give it a name, the **subnets** it
   reaches at L2 (e.g. `192.168.1.0/24`), and copy the **one-time API key**
   (shown only once).
2. Run it on the LAN machine:

   ```bash
   # Linux/macOS (direct)
   export SCANNER_AGENT_KEY="<KEY>"
   python3 agent/scanner_agent.py --server http://<SERVER_IP>:8000 \
       --name my-lan --subnets 192.168.1.0/24

   # or as a container on a Linux LAN host (host networking = real L2)
   docker build -t scanner-agent -f agent/Dockerfile .
   docker run -d --network=host --name scanner-agent \
     --cap-add NET_RAW --cap-add NET_ADMIN \
     -e SCANNER_AGENT_KEY=<KEY> \
     scanner-agent --server http://<SERVER_IP>:8000 --name my-lan
   ```

3. The agent heartbeats every few seconds. Once **online**, scans whose targets
   fall inside its subnets are **automatically delegated** to it.

> **Windows agent:** use `start-scanner-agent.ps1` (reads
> `SCANNER_AGENT_KEY` env or the local key file; no argv exposure), or run
> `python agent\scanner_agent.py --connect` if you don't run as admin / have
> Npcap (SYN scans with Npcap need admin; `--connect` needs nothing extra).

---

## 7. Stopping (data preserved)

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File stop-all.ps1     # agent + stack
```

```bash
# macOS / Linux / WSL
./stop-all.sh                                            # agent + stack
```

```bash
# Any OS — stack only (no -v, data kept)
docker compose down
```

`compose down` is always run **without** `-v`, so the Postgres data volume and
all stored scans/hosts/findings survive restarts.

---

## Common problems

| Symptom | Fix |
|---------|-----|
| `docker compose up` fails: "Variable ... is not set" | `.env` missing/empty — see step 3 |
| Backend restarts / `ValueError: JWT_SECRET must be...` | `JWT_SECRET` is a placeholder or < 16 chars |
| Scan found nothing | Host is not reachable from the current network (VPN), or target outside the engagement's authorized scope |
| MAC/vendor/OS all empty | No agent covers the targets → container is L3-only. Deploy an agent on the LAN |
| Scan stuck in `queued` | Worker down — `docker compose ps`, then `docker compose restart backend` |
| Agent shows offline / not delegated | Check the Agents page shows `online`; agent subnets must cover the targets; agent can be polled with `--interval` (default 10 s) |
| `(trapped) error reading bcrypt version` in logs | Known passlib/bcrypt version mismatch — harmless; login works |
| Topology looks broken after `npm install` | Re-run `npm run build` from `frontend/` (never hand-edit `node_modules/force-graph/`) |

## Host access references

- Web UI + API: <http://localhost:8000>
- Swagger: <http://localhost:8000/docs>
- Health: <http://localhost:8000/health> → `{"status":"ok"}`
- Postgres inside the stack: `docker compose exec postgres psql -U pentest -d subnex`