# =============================================================================
#  start-all.ps1
#  Clean startup of the SubNex stack:
#    1. Docker Compose stack  (postgres, redis, backend = API + Celery worker
#       + built web UI served on the same port)
#    2. LAN scanner agent     (once the backend is ready)
#
#  Data is preserved across restarts (compose is never brought down with -v here).
#  Idempotent - re-running is safe.
#  Run:  powershell -ExecutionPolicy Bypass -File start-all.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

# Resolve docker.exe: prefer PATH, fall back to the author's Windows path.
$DC = (Get-Command docker -ErrorAction SilentlyContinue).Source
if (-not $DC) { $DC = 'C:\Users\sths2\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe' }
$BackendProbe = 'http://localhost:8000/docs'

if (-not (Test-Path $DC)) {
    Write-Host "ERROR: docker.exe not found at:`n  $DC" -ForegroundColor Red
    Write-Host 'Start Docker Desktop first, then re-run this script.' -ForegroundColor Yellow
    exit 1
}

Write-Host '=== [1/4] Building web UI (skipped if already built) ... ===' -ForegroundColor Cyan
$FrontendDist = Join-Path $PSScriptRoot 'frontend\dist\index.html'
if (-not (Test-Path $FrontendDist)) {
    Push-Location (Join-Path $PSScriptRoot 'frontend')
    try {
        Write-Host '  npm install + npm run build (first run) ...'
        npm install --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm install failed' }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'npm run build failed' }
    } finally {
        Pop-Location
    }
} else {
    Write-Host '  web UI already built (frontend/dist present); set FORCE_UI_BUILD=1 to rebuild'
}

Write-Host '=== [2/4] Starting Docker Compose stack ... ===' -ForegroundColor Cyan
Push-Location $PSScriptRoot
try {
    if (-not (Test-Path (Join-Path $PSScriptRoot 'docker-compose.yml'))) {
        Write-Host 'ERROR: docker-compose.yml not found in this folder.' -ForegroundColor Red
        exit 1
    }
    & $DC compose up -d --build
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'ERROR: docker compose up failed.' -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

Write-Host ''
Write-Host '=== [3/4] Waiting for backend to become ready ... ===' -ForegroundColor Cyan
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
Write-Host '=== [4/4] Starting LAN scanner agent ... ===' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'start-scanner-agent.ps1')

Write-Host ''
Write-Host '=== Startup complete ===' -ForegroundColor Green
Write-Host '  Web UI  : http://localhost:8000  (API + built web UI on the same port)'
Write-Host '  This terminal can be closed; the stack and agent keep running.'
Write-Host '  To shut everything down later:  powershell -ExecutionPolicy Bypass -File stop-all.ps1'
