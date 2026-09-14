#!/usr/bin/env bash
# =============================================================================
#  stop-scanner-agent.sh
#  Cross-platform counterpart of stop-scanner-agent.ps1 (Linux / macOS / WSL).
#  Stops the LAN scanner agent process (by recorded PID and any scanner_agent.py
#  process). Idempotent - safe to run even when no agent is running.
#  Run:  ./stop-scanner-agent.sh
# =============================================================================
set -euo pipefail

PIDDIR="${TMPDIR:-/tmp}/subnex"
PIDFILE="$PIDDIR/agent.pid"

echo "=== Stopping LAN scanner agent ... ==="

STOPPED=0
if [ -f "$PIDFILE" ]; then
  PID="$(tr -d '[:space:]' < "$PIDFILE")"
  if [ -n "$PID" ] && kill -0 "$PID" >/dev/null 2>&1; then
    kill "$PID" >/dev/null 2>&1 || true
    sleep 2
    if kill -0 "$PID" >/dev/null 2>&1; then
      kill -9 "$PID" >/dev/null 2>&1 || true
    fi
    echo "  stopped agent PID $PID"
    STOPPED=1
  else
    echo "  no running process for recorded PID $PID"
  fi
  rm -f "$PIDFILE"
else
  echo "  no PID file - skipping"
fi

STRAY=0
for p in $(pgrep -f "scanner_agent.py" 2>/dev/null || true); do
  kill "$p" >/dev/null 2>&1 || true
  echo "  stopped stray agent PID $p"
  STRAY=1
done
if [ "$STRAY" = "0" ]; then
  echo "  no stray agent processes found"
fi

echo "Agent stopped."