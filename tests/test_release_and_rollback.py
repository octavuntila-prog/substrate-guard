"""Deploy tooling hardening: rollback automation + non-interactive release
(audit 2026-07-17 item #17)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
_NO_BASH = sys.platform == "win32" or shutil.which("bash") is None
pytestmark = pytest.mark.skipif(_NO_BASH, reason="needs POSIX bash")


def _run(script, *args, env_extra=None, cwd=None):
    env = dict(os.environ, **(env_extra or {}))
    r = subprocess.run(
        ["bash", str(SCRIPTS / script), *args],
        env=env, capture_output=True, text=True, timeout=60, cwd=cwd,
    )
    return r.returncode, r.stdout + r.stderr


# ── rollback.sh backup / restore / list / prune ──────────────────────────────

def _seed_install(root: Path) -> dict:
    inst = root / "opt"
    (inst / "substrate_guard").mkdir(parents=True)
    (inst / "scripts").mkdir()
    (inst / "substrate_guard" / "__init__.py").write_text('__version__ = "13.4.2"\n')
    (inst / "substrate_guard" / "marker.txt").write_text("original")
    return {"INSTALL_DIR": str(inst)}


def test_rollback_backup_then_restore_round_trip(tmp_path):
    env = _seed_install(tmp_path)
    inst = Path(env["INSTALL_DIR"])

    code, _ = _run("rollback.sh", "backup", env_extra={**env, "STAMP": "20260718_100000"})
    assert code == 0
    assert (inst / ".backups" / "20260718_100000" / "substrate_guard" / "marker.txt").exists()

    # simulate a bad deploy: corrupt + delete files
    (inst / "substrate_guard" / "marker.txt").write_text("BROKEN")
    (inst / "substrate_guard" / "__init__.py").unlink()

    code, out = _run("rollback.sh", "restore", env_extra=env)
    assert code == 0, out
    assert (inst / "substrate_guard" / "marker.txt").read_text() == "original"
    assert (inst / "substrate_guard" / "__init__.py").exists()   # deleted file came back


def test_rollback_restore_named_snapshot(tmp_path):
    env = _seed_install(tmp_path)
    inst = Path(env["INSTALL_DIR"])
    for stamp, body in (("20260718_100000", "v1"), ("20260718_110000", "v2")):
        (inst / "substrate_guard" / "marker.txt").write_text(body)
        _run("rollback.sh", "backup", env_extra={**env, "STAMP": stamp})
    (inst / "substrate_guard" / "marker.txt").write_text("current")

    code, out = _run("rollback.sh", "restore", "20260718_100000", env_extra=env)
    assert code == 0, out
    assert (inst / "substrate_guard" / "marker.txt").read_text() == "v1"


def test_rollback_prune_keeps_only_KEEP(tmp_path):
    env = _seed_install(tmp_path)
    inst = Path(env["INSTALL_DIR"])
    for stamp in ("20260718_100000", "20260718_110000", "20260718_120000"):
        _run("rollback.sh", "backup", env_extra={**env, "STAMP": stamp, "KEEP": "2"})
    kept = sorted(p.name for p in (inst / ".backups").iterdir() if p.is_dir())
    assert kept == ["20260718_110000", "20260718_120000"], kept   # oldest pruned


def test_rollback_restore_without_snapshot_exits_2(tmp_path):
    env = _seed_install(tmp_path)
    code, out = _run("rollback.sh", "restore", env_extra=env)
    assert code == 2, out


def test_rollback_backup_nothing_installed_exits_2(tmp_path):
    code, out = _run("rollback.sh", "backup",
                     env_extra={"INSTALL_DIR": str(tmp_path / "empty")})
    assert code == 2, out


def test_rollback_usage_error_exits_1(tmp_path):
    code, _ = _run("rollback.sh", "frobnicate", env_extra=_seed_install(tmp_path))
    assert code == 1


# ── deploy.sh wires the backup before overwrite ──────────────────────────────

def test_deploy_calls_rollback_backup_before_overwrite():
    src = (SCRIPTS / "deploy.sh").read_text(encoding="utf-8")
    i_backup = src.find("rollback.sh\" backup")
    i_copy = src.find('cp -r "$PROJECT_DIR/substrate_guard"')
    assert 0 <= i_backup < i_copy, "deploy.sh must snapshot via rollback.sh BEFORE the cp overwrite"
    assert 'INSTALL_DIR="${INSTALL_DIR:-/opt/substrate-guard}"' in src, \
        "deploy.sh install_host INSTALL_DIR must be env-overridable"


# ── release.sh non-interactive gate ──────────────────────────────────────────

def test_release_supports_noninteractive_flag():
    src = (SCRIPTS / "release.sh").read_text(encoding="utf-8")
    assert 'RELEASE_YES="${RELEASE_YES:-0}"' in src
    # every read -p prompt must be guarded by a RELEASE_YES branch
    assert src.count("read -p") == 3, "unexpected prompt count — re-check the guards"
    assert src.count('if [ "$RELEASE_YES" = "1" ]') >= 3, \
        "each interactive prompt must have a RELEASE_YES bypass"


def test_release_yes_does_not_weaken_validation():
    """RELEASE_YES only removes keypresses; the hard validation gates (clean
    tree, on main, version sync) must still be present and unconditional."""
    src = (SCRIPTS / "release.sh").read_text(encoding="utf-8")
    assert 'log_error "Working tree has uncommitted changes"' in src
    assert 'log_error "Not on main branch' in src
    assert "Version mismatch" in src
