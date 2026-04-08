"""examples/orchestrator_inject_events.py must run without error."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_orchestrator_inject_example_runs():
    root = Path(__file__).resolve().parents[1]
    script = root / "examples" / "orchestrator_inject_events.py"
    env = {**os.environ, "PYTHONUTF8": "1"}
    r = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "verdict:" in r.stdout
    assert "events_observed:" in r.stdout
