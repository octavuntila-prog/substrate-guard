# Job `test` parity + quick CLI smoke (layers 4-6 + demo) so local = functional end-to-end.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m pytest tests/ -q --tb=short
python tests/smoke_test.py

Write-Host "`n-- CLI demos (non-fatal logging to stderr is OK) --`n"
python -m substrate_guard.cli demo --scenario safe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m substrate_guard.cli comply demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m substrate_guard.cli attest demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m substrate_guard.cli offline demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nOK: CI-equivalent checks + CLI demos passed."
