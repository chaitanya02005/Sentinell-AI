$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or is not available in PATH."
}

if (-not (Test-Path ".env")) {
    throw "Missing .env. Create it from .env.example before starting."
}

Write-Host "Starting Sentinell.AI, PostgreSQL, migrations, and health checks..."
docker compose up --build --detach --wait

Write-Host ""
Write-Host "Sentinell.AI is ready: http://127.0.0.1:8000"
Write-Host "Health check: http://127.0.0.1:8000/healthz/"
Write-Host "Logs: docker compose logs -f web"
