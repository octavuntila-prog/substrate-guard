# Waits for Docker Engine, then: docker compose build (repo root = parent of scripts/)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "Waiting for Docker Engine (max 5 min)..."
$deadline = (Get-Date).AddMinutes(5)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $v = & docker version 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $v -match "Server:") {
        $ready = $true
        break
    }
    Start-Sleep -Seconds 4
}

if (-not $ready) {
    Write-Host "ERROR: Docker Engine did not become ready. Open Docker Desktop and wait until it is running, then retry."
    exit 1
}

Write-Host "Building image..."
docker compose build
exit $LASTEXITCODE
