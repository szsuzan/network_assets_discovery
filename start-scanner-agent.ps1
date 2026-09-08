# =============================================================================
#  start-scanner-agent.ps1
#  Starts the LAN scanner agent as a background process. The agent advertises
#  L2/ARP coverage over 192.168.1.0/24 so scans delegate to it (full ARP
#  MAC/vendor + nmap -O) instead of falling back to L3 container scans.
#
#  Idempotent: stops any existing agent first, then starts a fresh one.
#  Run:  powershell -ExecutionPolicy Bypass -File start-scanner-agent.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

$AgentPy    = Join-Path $PSScriptRoot 'agent\scanner_agent.py'
$Server     = 'http://localhost:8000'
$Name       = 'lan-agent'
$Subnets    = '192.168.1.0/24'
$PidFile    = Join-Path $env:TEMP 'opencode\agent_pid.txt'
$OutLog     = Join-Path $env:TEMP 'opencode\agent_out.log'
$ErrLog     = Join-Path $env:TEMP 'opencode\agent_err.log'
$KeyFile    = Join-Path $env:TEMP 'opencode\new_agent_key.txt'   # local-only fallback (never committed)

# API key resolution order: 1) SCANNER_AGENT_API_KEY env var, 2) the local key
# file written when the agent was (re)created. Keeps the secret out of the repo.
$ApiKey = ''
if (-not [string]::IsNullOrWhiteSpace($env:SCANNER_AGENT_API_KEY)) {
    $ApiKey = ($env:SCANNER_AGENT_API_KEY).Trim()
} elseif (Test-Path -LiteralPath $KeyFile) {
    $ApiKey = (Get-Content -Raw -LiteralPath $KeyFile).Trim()
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "ERROR: agent API key not found. Set env SCANNER_AGENT_API_KEY, or place the key in:`n  $KeyFile" -ForegroundColor Red
    exit 1
}

function Get-RunningAgentPids {
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*scanner_agent.py*' } |
        ForEach-Object { $_.ProcessId }
}

Write-Host '=== Stopping any existing agent ... ===' -ForegroundColor Cyan
foreach ($p in Get-RunningAgentPids) {
    Write-Host "  stopping agent PID $p"
    Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
}
if (Test-Path $PidFile) { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

if (-not (Test-Path $AgentPy)) {
    Write-Host "ERROR: agent script not found: $AgentPy" -ForegroundColor Red
    exit 1
}

# Ensure log files exist (truncate) before launching.
Set-Content -Path $OutLog -Value '' -NoNewline
Set-Content -Path $ErrLog -Value '' -NoNewline

Write-Host '=== Starting LAN scanner agent ... ===' -ForegroundColor Cyan
$proc = Start-Process -FilePath 'python' `
    -ArgumentList @('-u', "`"$AgentPy`"", '--server', $Server, "--api-key=$ApiKey",
                    '--name', $Name, '--subnets', $Subnets) `
    -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
    -PassThru -WindowStyle Hidden

$proc.Id | Set-Content -Path $PidFile -NoNewline
Start-Sleep -Seconds 5

$alive = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
if (-not $alive) {
    Write-Host "Agent failed to start. stderr:" -ForegroundColor Red
    if (Test-Path $ErrLog) { Get-Content $ErrLog -Tail 20 }
    exit 1
}

Write-Host "Agent started. PID: $($proc.Id)" -ForegroundColor Green
Write-Host '  stdout log:' $OutLog
Write-Host '  stderr log:' $ErrLog
Write-Host '  PID file :' $PidFile
Write-Host ''
Write-Host 'Verify it is online on the Agents page (server: '$Server').' -ForegroundColor Yellow
