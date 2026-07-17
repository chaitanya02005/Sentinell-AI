$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

docker compose down
Write-Host "Sentinell.AI containers stopped. PostgreSQL data volume was preserved."
