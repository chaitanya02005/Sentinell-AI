$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

if (-not (Test-Path ".env.production")) {
    throw "Missing .env.production. Create it from .env.production.example."
}

Write-Host "Validating production Compose configuration..."
docker compose --env-file .env.production -f compose.production.yml config --quiet

Write-Host "Building and starting the production stack..."
docker compose --env-file .env.production -f compose.production.yml up --build --detach --wait

Write-Host ""
Write-Host "Production stack is healthy on the configured WEB_BIND_ADDRESS and WEB_PORT."
Write-Host "Place a TLS reverse proxy in front of the web service before external access."
