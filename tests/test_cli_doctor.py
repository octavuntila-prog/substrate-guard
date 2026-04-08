"""substrate-guard doctor — smoke tests."""

from __future__ import annotations

import subprocess
import sys


def test_doctor_exits_zero():
    r = subprocess.run(
        [sys.executable, "-m", "substrate_guard.cli", "doctor"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "substrate-guard" in r.stdout.lower() or "environment" in r.stdout.lower()
    assert "z3-solver" in r.stdout


def test_doctor_json_reserved_returns_nonzero():
    r = subprocess.run(
        [sys.executable, "-m", "substrate_guard.cli", "doctor", "--json"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 2


def test_run_doctor_plain():
    from substrate_guard.diagnostics import run_doctor

    assert run_doctor(json_output=False) == 0
