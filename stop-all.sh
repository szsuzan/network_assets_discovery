#!/usr/bin/env bash
# =============================================================================
#  stop-all.sh
#  Cross-platform counterpart of stop-all.ps1 (Linux / macOS / WSL).
#  Clean shutdown of the SubNex stack:
#    1. LAN scanner agent  (background python process)
#    2. Docker Compose stack (postgres, redis, backend = API + Celery worker + UI)
#
#  SAFETY: uses `docker compose down` WITHOUT -v, so the Postgres data volume
#  (postgres_data) and all stored scans/hosts/findings are PRESERVED.
#  Idempotent - safe to run even if the stack is already stopped.
#  Run:  ./stop-all.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DC="${DOCKER_BIN:-docker}"

command -v docker >/dev/null 2>&1 || { echo "WARNING: docker not found on PATH - nothing to stop." >&2; exit 1; }

echo "=== [1/2] Stopping LAN scanner agent ... ==="
if [ -f "$ROOT/stop-scanner-agent.sh" ]; then
  bash "$ROOT/stop-scanner-agent.sh" || true
else
  echo "  stop-scanner-agent.sh not found - skipping agent."
fi

echo ""
echo "=== [2/2] Stopping Docker Compose stack (data preserved) ... ==="

if ! "$DC" info >/dev/null 2>&1; then
  echo "ERROR: Docker engine is not running. Start it first." >&2
  exit 1
fi

( cd "$ROOT" && "$DC" compose down ) || { echo "ERROR: docker compose down failed." >&2; exit 1; }

# Remove leftover project containers (any started outside compose, e.g. a
# manual `docker run` of the frontend). Compose-down only knows its own
# containers, and such leftovers would cause name conflicts on the next `up`.
leftover="$("$DC" ps -a --filter 'name=subnex-' --format '{{.Names}}' 2>/dev/null || true)"
if [ -n "$leftover" ]; then
  for c in $leftover; do
    echo "  removing leftover container $c"
    "$DC" rm -f "$c" >/dev/null 2>&1 || echo "  WARNING: could not remove $c" >&2
  done
else
  echo "  no leftover project containers"
fi

echo ""
echo "=== All stopped. Postgres data preserved (compose down WITHOUT -v). ==="
echo "To bring everything back up, run:  ./start-all.sh"