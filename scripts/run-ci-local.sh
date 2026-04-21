#!/usr/bin/env bash
# Job `test` parity + quick CLI smoke (demo, comply, attest, offline).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install --upgrade pip
pip install -e ".[dev]"
python -m pytest tests/ -q --tb=short
python tests/smoke_test.py

echo ""
echo "-- CLI demos --"
python -m substrate_guard.cli demo --scenario safe
python -m substrate_guard.cli comply demo
python -m substrate_guard.cli attest demo
python -m substrate_guard.cli offline demo

echo ""
echo "OK: CI-equivalent checks + CLI demos passed."
