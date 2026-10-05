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
#    SCANNER_AGENT_SUBNETS  comma-separated L2 subnets. Empty by default, which
#                           lets the agent auto-detect its own interfaces. Only
#                           set this if auto-detection is wrong for your host.
#    SCANNER_AGENT_NO_SUDO  set to 1 to skip the automatic elevation (you will
#                           get TCP-connect scans only: no MAC/vendor/OS)
#
#  Run:  ./start-scanner-agent.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_PY="${AGENT_PY:-$ROOT/agent/scanner_agent.py}"

SERVER="${SCANNER_AGENT_SERVER:-http://localhost:8000}"
NAME="${SCANNER_AGENT_NAME:-lan-agent}"
SUBNETS="${SCANNER_AGENT_SUBNETS:-}"

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

SUBNET_ARG=()
if [ -n "$SUBNETS" ]; then
  SUBNET_ARG=(--subnets "$SUBNETS")
else
  echo "  subnets: auto-detect from local interfaces"
fi

# Hand the key over via the inherited environment (SCANNER_AGENT_KEY) instead of
# an --api-key argv flag so it never shows up in process listings.
if [ "${SCANNER_AGENT_NO_SUDO:-0}" = "1" ]; then
  echo "=== Starting LAN scanner agent (unprivileged) ==="
  echo "  note: no MAC/vendor/OS will be reported; use --connect for L3 coverage"
  SCANNER_AGENT_KEY="$API_KEY" \
    nohup python3 -u "$AGENT_PY" --server "$SERVER" --name "$NAME" ${SUBNET_ARG[@]+"${SUBNET_ARG[@]}"} \
      >> "$OUTLOG" 2>> "$ERRLOG" &
  AGENT_PID=$!
else
  # ARP/SYN scanning and passive sniffing need uid 0. Re-exec under sudo rather
  # than warning and silently producing a degraded agent.
  if [ "$(id -u)" != "0" ]; then
    echo "=== Elevating: Layer-2 scans need root ... ==="
    # Pass the key through the environment; sudo resets it unless we allow it.
    exec sudo --preserve-env=SCANNER_AGENT_KEY,SCANNER_AGENT_API_KEY \
      env SCANNER_AGENT_KEY="$API_KEY" \
      SCANNER_AGENT_NO_SUDO=1 SCANNER_AGENT_SUBNETS="$SUBNETS" \
      "$BASH_SOURCE" "$@"
  fi
  echo "=== Starting LAN scanner agent (root) ==="
  SCANNER_AGENT_KEY="$API_KEY" \
    nohup python3 -u "$AGENT_PY" --server "$SERVER" --name "$NAME" ${SUBNET_ARG[@]+"${SUBNET_ARG[@]}"} \
      >> "$OUTLOG" 2>> "$ERRLOG" &
  AGENT_PID=$!
fi
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