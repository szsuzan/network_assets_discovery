"""Self-service agent download.

The scanner agent must be runnable on a machine that has never seen the SubNex
repository — a fresh laptop on the target LAN, a rebuilt hypervisor, a migrated
box. Requiring ``git clone`` (or a pre-built Docker image) just to start an agent
is the single biggest reason agents never get deployed.

So the server ships the agent itself: ``GET /api/agent/bundle`` returns a zip of
the runtime sources. The agent is pure standard library (scapy is an optional
lazy import for the passive fingerprinter and degrades cleanly when missing), so
a target box only needs Python 3.9+ and nothing from PyPI.

This endpoint is intentionally unauthenticated. It carries no secret and no
tenant data — just source code the operator is already entitled to run — and it
has to stay reachable before the target machine holds any credentials.
"""
import io
import os
import zipfile

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/agent", tags=["agent-bundle"])

#: Runtime files the agent needs to start. Deliberately excludes __pycache__ and
#: anything build-time-only.
BUNDLE_FILES = ("agentctl.py", "scanner_agent.py", "Dockerfile")

#: agent/ is bind-mounted at /app/agent in compose, and baked into the image at
#: the same path, so one relative lookup covers both deployment styles. The env
#: var exists only as an escape hatch for unusual layouts.
_AGENT_DIR = os.environ.get("AGENT_DIR", "/app/agent")

_README = """SubNex scanner agent
====================

Contents
--------
  agentctl.py       supervisor + key store (stdlib only)
  scanner_agent.py  the worker (stdlib only, optional scapy for passive sniffing)

Quick start
-----------
  # 1. start (auto-detects its own LAN ranges, restarts on crash)
  SCANNER_AGENT_KEY="<KEY>" python3 agentctl.py run \\
      --server http://<SERVER>:8000 --name <NAME>

  # 2. survive reboots (systemd unit on Linux, Startup folder on Windows)
  python3 agentctl.py install

  # 3. check it is alive
  python3 agentctl.py status

Requirements
------------
  Python 3.9+ and nmap on PATH. No pip packages required.
  Optional: pip install scapy  -> enables the passive DHCP/ARP/CDP/LLDP fingerprinter
  Optional: Npcap on Windows    -> required for raw-socket and passive modes

Layer-2 note
------------
  Raw sockets (ARP, SYN, passive sniffing) need privileges:
    Linux    : run as root, or grant CAP_NET_RAW + CAP_NET_ADMIN
    Windows  : run the terminal as Administrator
  Without privileges the agent still runs, but degrades to TCP connect scans
  and cannot report MAC/vendor/OS.
"""


def _agent_dir() -> str:
    if os.path.isdir(_AGENT_DIR):
        return _AGENT_DIR
    # Fall back to a sibling agent/ dir so `python -m uvicorn` from backend/
    # works during development.
    fallback = os.path.join(os.path.dirname(_AGENT_DIR), "agent")
    if os.path.isdir(fallback):
        return fallback
    raise HTTPException(status_code=500, detail="Agent sources not found on server")


@router.get("/bundle")
async def agent_bundle():
    """Return the agent sources as a zip archive."""
    directory = _agent_dir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in BUNDLE_FILES:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    zf.writestr(name, fh.read())
        zf.writestr("README.txt", _README)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="subnex-agent.zip"',
            "Cache-Control": "no-store",
        },
    )