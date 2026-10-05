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
  #    Linux / macOS -- sudo is REQUIRED for Layer-2 data. The key must come
  #    AFTER sudo, because sudo strips a leading environment variable.
  sudo SCANNER_AGENT_KEY="<KEY>" python3 agentctl.py run \\
      --server http://<SERVER>:8000 --name <NAME>

  #    Windows -- open PowerShell as Administrator (right-click -> Run as
  #    administrator), then:
  #    $env:SCANNER_AGENT_KEY="<KEY>"; python agentctl.py run \\
  #        --server http://<SERVER>:8000 --name <NAME>

  # 2. survive reboots
  #    Linux   : systemd user unit (re-elevates via sudo inside ExecStart)
  #    macOS   : LaunchAgent -- CANNOT elevate, so it returns l2-degraded
  #              after a reboot. For Layer-2 across reboots, run step 1 from
  #              a root shell instead.
  #    Windows : scheduled task
  sudo python3 agentctl.py install       # or: python agentctl.py install (as admin on Windows)

  # 3. check it is alive
  sudo python3 agentctl.py status

  # 4. fully remove everything (run after deleting the agent in the UI)
  sudo python3 agentctl.py purge

Requirements
------------
  Python 3.9+ and nmap on PATH. No pip packages required.
  Optional: pip install scapy  -> enables the passive DHCP/ARP/CDP/LLDP fingerprinter
              (needs Npcap on Windows; needs root on macOS, where libpcap
               alone is not enough for BPF capture)

No privileges available?
-----------------------
  Add --connect to the run command. That switches nmap to TCP connect
  scanning, which needs no elevation at all and still finds open ports --
  it just cannot report MAC addresses or guess the OS:

    python agentctl.py run --server http://<SERVER>:8000 --name <NAME> --connect

Layer-2 note
------------
  Raw sockets (ARP, SYN, passive sniffing) need privileges:
    Linux    : run as root (uid 0). CAP_NET_RAW alone is not enough, because
               nmap itself requires uid 0 unless passed --privileged.
    macOS    : run as root. sudo is required even for ARP.
    Windows  : run the terminal as Administrator.
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