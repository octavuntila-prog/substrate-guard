# Start docker-compose.stack.yml and run doctor + audit (Windows PowerShell)
# Requires: Docker Compose v2. Optional: .env with POSTGRES_PASSWORD.
# $env:SKIP_CLEANUP = "1" — leave containers running.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$composeFile = "docker-compose.stack.yml"
$script:StackUp = $false

function Invoke-Teardown {
    if ($env:SKIP_CLEANUP -eq "1") { return }
    if (-not $script:StackUp) { return }
    Write-Host "Tearing down stack..." -ForegroundColor Yellow
    docker compose -f $composeFile down --remove-orphans 2>$null | Out-Null
    $script:StackUp = $false
}

try {
    docker compose -f $composeFile up -d --build
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }
    $script:StackUp = $true

    Write-Host "Waiting for Postgres (max 120s)..."
    $ready = $false
    for ($i = 0; $i -lt 120; $i++) {
        docker compose -f $composeFile exec -T db pg_isready -U guard -d substrate 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) {
        Write-Host "ERROR: Postgres did not become ready in time." -ForegroundColor Red
        docker compose -f $composeFile logs --tail 80 db
        Invoke-Teardown
        exit 1
    }

    Write-Host "Doctor:"
    docker compose -f $composeFile exec -T substrate-guard python -m substrate_guard.cli doctor
    if ($LASTEXITCODE -ne 0) { Invoke-Teardown; exit $LASTEXITCODE }

    Write-Host "Audit:"
    docker compose -f $composeFile exec -T substrate-guard substrate-guard audit @args
    $auditCode = $LASTEXITCODE
    Invoke-Teardown
    exit $auditCode
}
catch {
    Write-Error $_
    if ($script:StackUp) { docker compose -f $composeFile logs --tail 40 db 2>$null }
    Invoke-Teardown
    exit 1
}
