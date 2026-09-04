# =============================================================================
#  stop-all.ps1
#  Clean shutdown of the Network Asset Discovery stack:
#    1. LAN scanner agent  (background python process)
#    2. Docker Compose stack (postgres, redis, backend, celery worker, frontend)
#
#  SAFETY: uses `docker compose down` WITHOUT -v, so the Postgres data volume
#  (postgres_data) and all stored scans/hosts/findings are PRESERVED.
#  Idempotent - safe to run even if things are already stopped.
#  Run:  powershell -ExecutionPolicy Bypass -File stop-all.ps1
# =============================================================================
$ErrorActionPreference = 'Stop'

$DC = 'C:\Users\sths2\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe'

Write-Host '=== [1/2] Stopping LAN scanner agent ... ===' -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'stop-scanner-agent.ps1')

Write-Host ''
Write-Host '=== [2/2] Stopping Docker Compose stack (data preserved) ... ===' -ForegroundColor Cyan
if (-not (Test-Path $DC)) {
    Write-Host "WARNING: docker.exe not found at:`n  $DC" -ForegroundColor Yellow
    Write-Host 'Stack NOT stopped. Check Docker Desktop is installed at that path.' -ForegroundColor Yellow
} else {
    Push-Location $PSScriptRoot
    try {
        & $DC compose down
    } finally {
        Pop-Location
    }
}

Write-Host ''
Write-Host '=== All stopped. Postgres data preserved (compose down WITHOUT -v). ===' -ForegroundColor Green
Write-Host 'To bring everything back up, run:  powershell -ExecutionPolicy Bypass -File start-all.ps1'
