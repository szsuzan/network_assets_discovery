# =============================================================================
#  stop-all.ps1
#  Clean shutdown of the Network Asset Discovery stack:
#    1. LAN scanner agent  (background python process)
#    2. Docker Compose stack (postgres, redis, backend, celery worker, frontend)
#
#  SAFETY: uses `docker compose down` WITHOUT -v, so the Postgres data volume
#  (postgres_data) and all stored scans/hosts/findings are PRESERVED.
#  Also removes leftover project containers (e.g. started manually with docker
#  run) so a later `start-all.ps1` never hits a name conflict.
#  Idempotent - safe to run even if the stack is already stopped.
#  Run:  powershell -ExecutionPolicy Bypass -File stop-all.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

$DC          = 'C:\Users\sths2\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe'

if (-not (Test-Path $DC)) {
    Write-Host "WARNING: docker.exe not found at:`n  $DC" -ForegroundColor Red
    Write-Host 'Nothing to stop. Start Docker Desktop, then re-run this script if needed.' -ForegroundColor Yellow
    exit 1
}

Write-Host '=== [1/2] Stopping LAN scanner agent ... ===' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'stop-scanner-agent.ps1')

Write-Host ''
Write-Host '=== [2/2] Stopping Docker Compose stack (data preserved) ... ===' -ForegroundColor Cyan

# Verify the Docker engine is actually reachable before attempting anything.
& $DC info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERROR: Docker engine is not running. Start Docker Desktop first.' -ForegroundColor Red
    exit 1
}

Push-Location $PSScriptRoot
try {
    & $DC compose down
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'ERROR: docker compose down failed (exit code' $LASTEXITCODE').' -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# Remove leftover project containers (any started outside compose, e.g. a
# manual `docker run` of the frontend). Compose-down only knows its own
# containers, and such leftovers would cause name conflicts on the next `up`.
$leftover = @(& $DC ps -a --filter 'name=assetsdiscovery-' --format '{{.Names}}')
if ($leftover.Count -gt 0) {
    foreach ($c in $leftover) {
        Write-Host "  removing leftover container $c"
        & $DC rm -f $c *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  WARNING: could not remove $c" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host '  no leftover project containers'
}

Write-Host ''
Write-Host '=== All stopped. Postgres data preserved (compose down WITHOUT -v). ===' -ForegroundColor Green
Write-Host 'To bring everything back up, run:  powershell -ExecutionPolicy Bypass -File start-all.ps1'