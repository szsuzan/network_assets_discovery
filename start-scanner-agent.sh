#!/usr/bin/env bash
# =============================================================================
#  start-scanner-agent.sh
#  Cross-platform counterpart of start-scanner-agent.ps1 (Linux / macOS / WSL).
#  Starts the LAN scanner agent as a background process. The agent advertises
#  L2/ARP coverage over the configured subnet(s) so scans delegate to it (full
#  ARP MAC/vendor + nmap -O) instead of falling back to L3 container scans.
#
#  Idempotent: stops any existing agent first, then starts a fresh one.
#
#  Configuration (all optional, via environment variables):
#    SCANNER_AGENT_KEY      agent API key (from the Agents page; required)
#    SCANNER_AGENT_API_KEY  alias for the above
#    SCANNER_AGENT_SERVER   default http://localhost:8000
#    SCANNER_AGENT_NAME     default lan-agent
#    SCANNER_AGENT_SUBNETS  comma-separated L2 subnets, default 192.168.1.0/24
#
#  Run:  ./start-scanner-agent.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PY="${AGENT_PY:-$ROOT/agent/scanner_agent.py}"

SERVER="${SCANNER_AGENT_SERVER:-http://localhost:8000}"
NAME="${SCANNER_AGENT_NAME:-lan-agent}"
SUBNETS="${SCANNER_AGENT_SUBNETS:-192.168.1.0/24}"

PIDDIR="${TMPDIR:-/tmp}/subnex"
PIDFILE="$PIDDIR/agent.pid"
OUTLOG="$PIDDIR/agent_out.log"
ERRLOG="$PIDDIR/agent_err.log"

# API key resolution order: 1) SCANNER_AGENT_KEY, 2) SCANNER_AGENT_API_KEY,
# 3) a local key file (~/.subnex/agent_key), 4) legacy ~/.subnex_agent_key.
# Keeps the secret out of argv.
API_KEY="${SCANNER_AGENT_KEY:-}"
if [ -z "$API_KEY" ] && [ -n "${SCANNER_AGENT_API_KEY:-}" ]; then
  API_KEY="$SCANNER_AGENT_API_KEY"
fi
if [ -z "$API_KEY" ] && [ -f "$HOME/.subnex/agent_key" ]; then
  API_KEY="$(tr -d '[:space:]' < "$HOME/.subnex/agent_key")"
fi
if [ -z "$API_KEY" ] && [ -f "$HOME/.subnex_agent_key" ]; then
  API_KEY="$(tr -d '[:space:]' < "$HOME/.subnex_agent_key")"
fi

if [ -z "$API_KEY" ]; then
  echo "ERROR: agent API key not found. Set env SCANNER_AGENT_KEY, or place the key in:" >&2
  echo "  $HOME/.subnex_agent_key" >&2
  exit 1
fi

echo "=== Stopping any existing agent ... ==="
if [ -f "$PIDFILE" ]; then
  OLD_PID="$(tr -d '[:space:]' < "$PIDFILE")"
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" >/dev/null 2>&1; then
    echo "  stopping agent PID $OLD_PID"
    kill "$OLD_PID" >/dev/null 2>&1 || true
    sleep 2
    kill -9 "$OLD_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$PIDFILE"
fi
# Fallback sweep: any lingering scanner_agent.py running from this repo.
for p in $(pgrep -f "scanner_agent.py" 2>/dev/null || true); do
  echo "  stopping stray agent PID $p"
  kill "$p" >/dev/null 2>&1 || true
done
sleep 2

echo "=== Starting LAN scanner agent ... ==="
mkdir -p "$PIDDIR"
: > "$OUTLOG"
: > "$ERRLOG"

# Hand the key over via the inherited environment (SCANNER_AGENT_KEY) instead of
# an --api-key argv flag so it never shows up in process listings.
SCANNER_AGENT_KEY="$API_KEY" \
  nohup python3 -u "$AGENT_PY" --server "$SERVER" --name "$NAME" --subnets "$SUBNETS" \
    >> "$OUTLOG" 2>> "$ERRLOG" &
AGENT_PID=$!
echo "$AGENT_PID" > "$PIDFILE"

sleep 5
if ! kill -0 "$AGENT_PID" >/dev/null 2>&1; then
  echo "Agent failed to start. stderr:" >&2
  tail -20 "$ERRLOG" >&2 || true
  rm -f "$PIDFILE"
  exit 1
fi

echo "Agent started. PID: $AGENT_PID" 
echo "  stdout log: $OUTLOG"
echo "  stderr log: $ERRLOG"
echo "  PID file  : $PIDFILE"
echo ""
echo "Verify it is online on the Agents page (server: $SERVER)."
echo "Stop it later with:  ./stop-scanner-agent.sh"