# =============================================================================
#  start-scanner-agent.ps1
#  Starts the LAN scanner agent as a background process. The agent advertises
#  L2/ARP coverage over its own LAN ranges (full ARP MAC/vendor + nmap -O) so
#  scans delegate to it instead of falling back to L3 container scans.
#
#  Idempotent: stops any existing agent first, then starts a fresh one.
#
#  Run:  powershell -ExecutionPolicy Bypass -File start-scanner-agent.ps1
#
#  IMPORTANT: Layer-2 scanning (ARP / SYN / passive sniffing) needs an
#  elevated token on Windows. This script refuses to start unelevated unless
#  -Connect is passed, so it can never silently produce a blank-MAC agent.
#  For elevation, re-run the console as Administrator:
#      Start-Process powershell -Verb RunAs -ArgumentList `
#          '-ExecutionPolicy Bypass -File "<path to this file>"'
# =============================================================================
param(
    [string]$Server = '',
    [string]$Name = '',
    [string]$Subnets = '',
    [switch]$Connect,
    [switch]$SkipElevationCheck
)

$ErrorActionPreference = 'Stop'

$AgentPy    = Join-Path $PSScriptRoot 'agent\scanner_agent.py'
$Server     = if ($Server) { $Server } elseif ($env:SCANNER_AGENT_SERVER) { $env:SCANNER_AGENT_SERVER } else { 'http://localhost:8000' }
$Name       = if ($Name) { $Name } elseif ($env:SCANNER_AGENT_NAME) { $env:SCANNER_AGENT_NAME } else { 'lan-agent' }
$Subnets    = if ($Subnets) { $Subnets } elseif ($env:SCANNER_AGENT_SUBNETS) { $env:SCANNER_AGENT_SUBNETS } else { '' }
$PidFile    = Join-Path $env:TEMP 'subnex\agent_pid.txt'
$OutLog     = Join-Path $env:TEMP 'subnex\agent_out.log'
$ErrLog     = Join-Path $env:TEMP 'subnex\agent_err.log'
$RepoKeyFile = Join-Path $PSScriptRoot 'agent_key_local.txt'    # durable, gitignored
$TmpKeyFile  = Join-Path $env:TEMP 'subnex\new_agent_key.txt' # legacy fallback
$AgentCtlDir = Join-Path $env:USERPROFILE '.subnex'
$SubnexKeyFile = Join-Path $AgentCtlDir 'agent_key'            # agentctl-managed

# API key resolution order: 1) SCANNER_AGENT_KEY env var, 2) SCANNER_AGENT_API_KEY
# env var, 3) repo-local agent_key_local.txt, 4) agentctl's ~/.subnex/agent_key,
# 5) the legacy temp key file. Keeps the secret out of the repo AND out of the
# process command line.
$ApiKey = ''
if (-not [string]::IsNullOrWhiteSpace($env:SCANNER_AGENT_KEY)) {
    $ApiKey = ($env:SCANNER_AGENT_KEY).Trim()
} elseif (-not [string]::IsNullOrWhiteSpace($env:SCANNER_AGENT_API_KEY)) {
    $ApiKey = ($env:SCANNER_AGENT_API_KEY).Trim()
} elseif (Test-Path -LiteralPath $RepoKeyFile) {
    $ApiKey = (Get-Content -Raw -LiteralPath $RepoKeyFile).Trim()
} elseif (Test-Path -LiteralPath $SubnexKeyFile) {
    $ApiKey = (Get-Content -Raw -LiteralPath $SubnexKeyFile).Trim()
} elseif (Test-Path -LiteralPath $TmpKeyFile) {
    $ApiKey = (Get-Content -Raw -LiteralPath $TmpKeyFile).Trim()
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    Write-Host "ERROR: agent API key not found. Set env SCANNER_AGENT_KEY, or place the key in:`n  $RepoKeyFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path -LiteralPath $AgentPy)) {
    Write-Host "ERROR: agent script not found: $AgentPy" -ForegroundColor Red
    exit 1
}

# --- Elevation check -------------------------------------------------------
# An unelevated (UAC-filtered) token cannot open raw sockets even when the
# account is a local administrator, so this must test the effective token.
$elevated = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $elevated = $false
}

if (-not $elevated -and -not $Connect -and -not $SkipElevationCheck) {
    Write-Host 'ERROR: this console is not elevated, so ARP/SYN scans and passive' -ForegroundColor Red
    Write-Host '       sniffing are unavailable. The agent would come back as' -ForegroundColor Red
    Write-Host '       "l2-degraded" with no MAC / vendor / OS for every host.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Fix: re-run as Administrator:' -ForegroundColor Yellow
    Write-Host '    Start-Process powershell -Verb RunAs -ArgumentList ''-ExecutionPolicy Bypass -File "<this file>"''' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Or accept an unprivileged, TCP-connect-only agent:' -ForegroundColor Yellow
    Write-Host '    powershell -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Connect' -ForegroundColor Yellow
    exit 1
}

if ($elevated) {
    # Npcap provides wpcap.dll, which nmap needs for raw sockets on Windows.
    $npcap = @(
        (Join-Path $env:SystemRoot 'System32\Npcap\wpcap.dll'),
        (Join-Path $env:SystemRoot 'SysWOW64\Npcap\wpcap.dll')
    ) | Where-Object { Test-Path -LiteralPath $_ }
    if (-not $npcap) {
        Write-Host 'WARNING: Npcap was not detected. ARP/SYN scanning needs it.' -ForegroundColor Yellow
        Write-Host '         Install it from https://npcap.com (free), then restart this agent.' -ForegroundColor Yellow
    }
}

if ($Subnets) {
    Write-Host "  subnets: $Subnets"
} else {
    Write-Host '  subnets: auto-detect from local interfaces'
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

# Ensure log files exist (truncate) before launching.
New-Item -ItemType Directory -Force -Path (Join-Path $env:TEMP 'subnex') | Out-Null
Set-Content -Path $OutLog -Value '' -NoNewline
Set-Content -Path $ErrLog -Value '' -NoNewline

# Build the argument list, omitting --subnets entirely when auto-detecting.
$argList = @('-u', ('"' + $AgentPy + '"'), '--server', $Server, '--name', $Name)
if ($Subnets) {
    $argList += @('--subnets', $Subnets)
}
if ($Connect) {
    $argList += @('--connect')
}

Write-Host '=== Starting LAN scanner agent ... ===' -ForegroundColor Cyan
# Hand the key over via the inherited environment (SCANNER_AGENT_KEY) instead of
# an --api-key argv flag so it never shows up in process listings / CIM snapshots.
$PreviousKey = $env:SCANNER_AGENT_KEY
$env:SCANNER_AGENT_KEY = $ApiKey
try {
    $proc = Start-Process -FilePath 'python' -ArgumentList $argList `
        -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog `
        -PassThru -WindowStyle Hidden
} finally {
    if ($null -eq $PreviousKey) {
        Remove-Item Env:SCANNER_AGENT_KEY -ErrorAction SilentlyContinue
    } else {
        $env:SCANNER_AGENT_KEY = $PreviousKey
    }
}

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
if (-not $elevated -and $Connect) {
    Write-Host 'NOTE: unprivileged TCP-connect mode. MAC addresses, vendors and OS' -ForegroundColor Yellow
    Write-Host '      guesses will be empty by design.' -ForegroundColor Yellow
}
Write-Host 'Verify it is online on the Agents page (server: ' $Server ').' -ForegroundColor Yellow