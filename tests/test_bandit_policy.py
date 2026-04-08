"""Enforce Bandit policy (``bandit.yaml``) on ``substrate_guard/`` — fails CI if regressions."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_BANDIT_CFG = _ROOT / "bandit.yaml"
_PACKAGE = _ROOT / "substrate_guard"


def test_bandit_config_present() -> None:
    assert _BANDIT_CFG.is_file(), "bandit.yaml must exist at repository root"


def test_bandit_reports_no_issues_under_policy() -> None:
    bandit_exe = shutil.which("bandit")
    if bandit_exe is None:
        pytest.skip("bandit not installed (pip install -e '.[dev]')")

    cmd = [
        bandit_exe,
        "-c",
        str(_BANDIT_CFG),
        "-r",
        str(_PACKAGE),
        "-q",
        "-f",
        "txt",
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if proc.returncode != 0:
        out = (proc.stdout or "") + (proc.stderr or "")
        pytest.fail(
            "Bandit reported issues under bandit.yaml policy. "
            "Fix the finding or update policy with justification.\n\n" + out
        )
