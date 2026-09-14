#!/usr/bin/env bash
# =============================================================================
#  start-all.sh
#  Cross-platform counterpart of start-all.ps1 (Linux / macOS / WSL).
#  Clean startup of the SubNex stack:
#    1. Docker engine  (must be running; e.g. Docker Desktop / Docker Engine)
#    2. Docker Compose stack (postgres, redis, backend = API + Celery worker
#       + built web UI served on the same port)
#    3. LAN scanner agent     (once the backend is ready)
#
#  Data is preserved across restarts (compose is never brought down with -v here).
#  Idempotent - re-running is safe.
#  Run:  ./start-all.sh
#  Tip:  chmod +x start-all.sh first, or invoke with `bash start-all.sh`.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_PROBE="http://localhost:8000/docs"
DC="${DOCKER_BIN:-docker}"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found on PATH. Install Docker first." >&2; exit 1; }

echo "=== [1/5] Ensuring Docker engine is running ... ==="
if ! "$DC" info >/dev/null 2>&1; then
    echo "  Docker engine is down. Start it (e.g. 'open -a Docker' on macOS,"
    echo "  'sudo systemctl start docker' on Linux, or Docker Desktop on Windows/WSL),"
    echo "  wait for it to become ready, then re-run this script."
    exit 1
fi
echo "  Docker engine is up."

echo "=== [2/5] Building web UI (skipped if already built) ... ==="
if [ ! -f "$ROOT/frontend/dist/index.html" ] || [ "${FORCE_UI_BUILD:-0}" = "1" ]; then
  ( cd "$ROOT/frontend" && npm install --no-audit --no-fund && npm run build )
else
  echo "  web UI already built (frontend/dist present); set FORCE_UI_BUILD=1 to rebuild"
fi

echo "=== [3/5] Starting Docker Compose stack ... ==="
[ -f "$ROOT/docker-compose.yml" ] || { echo "ERROR: docker-compose.yml not found in $ROOT" >&2; exit 1; }
( cd "$ROOT" && "$DC" compose up -d --build )

echo ""
echo "=== [4/5] Waiting for backend to become ready ... ==="
tries=0
ready=0
until [ "$ready" = "1" ]; do
  tries=$(( tries + 1 ))
  if curl -fsSI --max-time 3 "$BACKEND_PROBE" >/dev/null 2>&1; then
    ready=1
  elif [ "$tries" -ge 20 ]; then
    echo "ERROR: backend did not become ready within ~60s." >&2
    echo "Check:  docker compose ps   |   docker compose logs backend" >&2
    exit 1
  else
    echo "  waiting for backend at $BACKEND_PROBE ... (${tries}x3s)"
    sleep 3
  fi
done
echo "  backend is up."

echo ""
echo "=== [5/5] Starting LAN scanner agent ... ==="
if [ -f "$ROOT/start-scanner-agent.sh" ]; then
  bash "$ROOT/start-scanner-agent.sh" || echo "  (no agent started - see messages above; this is optional)"
else
  echo "  start-scanner-agent.sh not found - skipping agent."
fi

echo ""
echo "=== Startup complete ==="
echo "  Web UI  : http://localhost:8000  (API + built web UI on the same port)"
echo "  This terminal can be closed; the stack and agent keep running."
echo "  To shut everything down later:  ./stop-all.sh"