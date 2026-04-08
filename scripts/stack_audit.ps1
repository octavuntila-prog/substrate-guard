# Start docker-compose.stack.yml and run doctor + audit (Windows PowerShell)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$compose = @("docker", "compose", "-f", "docker-compose.stack.yml")

Write-Host "Building / starting stack..."
& docker compose -f docker-compose.stack.yml up -d --build

Write-Host "Waiting for Postgres..."
for ($i = 0; $i -lt 60; $i++) {
    & docker compose -f docker-compose.stack.yml exec -T db pg_isready -U guard -d substrate 2>$null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 1
}

Write-Host "Doctor:"
& docker compose -f docker-compose.stack.yml exec -T substrate-guard python -m substrate_guard.cli doctor

Write-Host "Audit:"
& docker compose -f docker-compose.stack.yml exec -T substrate-guard substrate-guard audit @args
exit $LASTEXITCODE
