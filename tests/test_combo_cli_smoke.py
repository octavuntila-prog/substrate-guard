"""End-to-end smoke: unified CLI (substrate_guard.cli) — stack + chain."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = "substrate_guard.cli"


def test_unified_cli_demo_safe_exit_zero():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "demo", "--scenario", "safe"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout


def test_unified_cli_demo_safe_with_chain_exit_zero_and_verified():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "demo", "--scenario", "safe", "--chain"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    out = r.stdout
    assert "Tamper-evident chain" in out
    assert "VERIFIED" in out


def test_unified_cli_help_lists_stack_commands():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "demo" in out
    assert "verify" in out
    assert "stack-benchmark" in out
    assert "comply" in out
    assert "attest" in out
    assert "offline" in out


def test_combo_cli_module_delegates_to_unified_cli():
    """python -m substrate_guard.combo_cli remains valid (delegates to cli)."""
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", "substrate_guard.combo_cli", "demo", "--scenario", "safe"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout


def test_offline_demo_exit_zero():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "offline", "demo"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Layer 6" in r.stdout


def test_attest_demo_exit_zero():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "attest", "demo"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "verify_ok" in r.stdout


def test_comply_demo_exit_zero():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "comply", "demo"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "ZK-SNM" in r.stdout or "commitment_root" in r.stdout


def test_stack_benchmark_exit_zero():
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, "-m", CLI, "stack-benchmark"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Benchmark" in r.stdout or "benchmark" in r.stdout.lower()
