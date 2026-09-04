# =============================================================================
#  start-all.ps1
#  Clean startup of the Network Asset Discovery stack:
#    1. Docker Compose stack  (postgres, redis, backend, celery worker, frontend)
#    2. LAN scanner agent     (once the backend is ready)
#
#  Data is preserved across restarts (compose is never brought down with -v here).
#  Idempotent - re-running is safe.
#  Run:  powershell -ExecutionPolicy Bypass -File start-all.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

$DC          = 'C:\Users\sths2\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe'
$BackendProbe = 'http://localhost:8000/docs'

if (-not (Test-Path $DC)) {
    Write-Host "ERROR: docker.exe not found at:`n  $DC" -ForegroundColor Red
    Write-Host 'Start Docker Desktop first, then re-run this script.' -ForegroundColor Yellow
    exit 1
}

Write-Host '=== [1/3] Starting Docker Compose stack ... ===' -ForegroundColor Cyan
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path (Join-Path $PSScriptRoot 'docker-compose.yml'))) {
        Write-Host 'ERROR: docker-compose.yml not found in this folder.' -ForegroundColor Red
        exit 1
    }
    & $DC compose up -d
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'ERROR: docker compose up failed.' -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host ''
Write-Host '=== [2/3] Waiting for backend to become ready ... ===' -ForegroundColor Cyan
$tries = 0
do {
    Start-Sleep -Seconds 3
    $tries++
    try {
        $null = Invoke-WebRequest -Uri $BackendProbe -UseBasicParsing -TimeoutSec 3
        $ready = $true
    } catch {
        $ready = $false
    }
    if (-not $ready) {
        Write-Host "  waiting for backend at $BackendProbe ... (${tries}x3s)"
    }
} while (-not $ready -and $tries -lt 20)

if (-not $ready) {
    Write-Host 'ERROR: backend did not become ready within ~60s.' -ForegroundColor Red
    Write-Host 'Check:  docker compose ps   |   docker compose logs backend' -ForegroundColor Yellow
    exit 1
}
Write-Host '  backend is up.'

Write-Host ''
Write-Host '=== [3/3] Starting LAN scanner agent ... ===' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'start-scanner-agent.ps1')

Write-Host ''
Write-Host '=== Startup complete ===' -ForegroundColor Green
Write-Host '  Web UI  : http://localhost:3000 (or the mapped frontend port)'
Write-Host '  This terminal can be closed; the stack and agent keep running.'
Write-Host '  To shut everything down later:  powershell -ExecutionPolicy Bypass -File stop-all.ps1'
