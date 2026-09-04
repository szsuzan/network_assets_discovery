# =============================================================================
#  stop-scanner-agent.ps1
#  Stops the LAN scanner agent process (by recorded PID and any scanner_agent.py
#  process). Idempotent - safe to run even when no agent is running.
#  Run:  powershell -ExecutionPolicy Bypass -File stop-scanner-agent.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

$PidFile  = Join-Path $env:TEMP 'opencode\agent_pid.txt'

function Get-RunningAgentPids {
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*scanner_agent.py*' } |
        ForEach-Object { $_.ProcessId }
}

Write-Host '=== Stopping LAN scanner agent ... ===' -ForegroundColor Cyan

if (Test-Path $PidFile) {
    $pidVal = (Get-Content $PidFile -Raw).Trim()
    if ($pidVal) {
        if (Get-Process -Id $pidVal -ErrorAction SilentlyContinue) {
            Stop-Process -Id $pidVal -Force -ErrorAction SilentlyContinue
            Write-Host "  stopped agent PID $pidVal"
        } else {
            Write-Host "  no running process for recorded PID $pidVal"
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
} else {
    Write-Host '  no PID file - skipping'
}

$stray = @(Get-RunningAgentPids)
if ($stray.Count -eq 0) {
    Write-Host '  no stray agent processes found'
} else {
    foreach ($p in $stray) {
        Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
        Write-Host "  stopped stray agent PID $p"
    }
}

Write-Host 'Agent stopped.' -ForegroundColor Green
