"""Regression guards for the deploy/ops scripts (H3).

The production cron must run the CANONICAL cron-audit.sh -- not a frozen heredoc copy
that drifts. Before the fix, setup-cron.sh embedded a stale copy (no HMAC handling, the
buggy 2-way `EXIT_CODE -ne 0 -> VIOLATIONS DETECTED` branch) and deploy.sh never copied
scripts/ to /opt, so the good script was unreachable on a real host. These tests fail if
any of that regresses.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def test_setup_cron_installs_canonical_script_not_a_heredoc():
    src = (SCRIPTS / "setup-cron.sh").read_text(encoding="utf-8")
    assert "<< 'CRONSCRIPT'" not in src, "setup-cron.sh embeds a frozen heredoc copy of cron-audit.sh -- it drifts"
    assert "EXIT_CODE -ne 0" not in src, "the stale 2-way violation branch resurfaced in setup-cron.sh"
    assert 'install -m 755 "$SRC_CRON"' in src, "setup-cron.sh no longer installs the canonical cron-audit.sh"


def test_cron_audit_keeps_hmac_and_distinct_exit_codes():
    src = (SCRIPTS / "cron-audit.sh").read_text(encoding="utf-8")
    assert "HMAC" in src, "cron-audit.sh lost its HMAC-key handling"
    assert "EXIT_CODE -eq 1" in src and "AUDIT ERROR" in src, \
        "cron-audit.sh lost its distinct violation(1)/error(2) exit-code branches"


def test_cron_audit_alerts_on_each_hmac_fatal():
    """M2/M-f: the telegram helper is defined before the FATAL exits, AND EACH HMAC-key
    FATAL path (missing key, insecure perms) calls it before its OWN exit 2 -- not merely
    has a call somewhere in the file. The prior assertion passed even if the missing-key
    block's call was deleted (a sibling call elsewhere satisfied it)."""
    src = (SCRIPTS / "cron-audit.sh").read_text(encoding="utf-8")
    helper = src.find("_send_telegram() {")
    first_fatal = src.find("exit 2")
    assert 0 <= helper < first_fatal, "telegram helper defined AFTER the HMAC FATAL exit -- alert is silent"
    for marker in ("FATAL: HMAC key file missing", "FATAL: HMAC key file has insecure"):
        i = src.find(marker)
        assert i >= 0, f"FATAL marker missing: {marker}"
        block = src[i:src.find("exit 2", i)]  # from this FATAL echo to its own exit 2
        assert '_send_telegram "' in block, f"no telegram alert before exit 2 in the '{marker}' block"


def test_deploy_install_host_copies_scripts_dir():
    src = (SCRIPTS / "deploy.sh").read_text(encoding="utf-8")
    assert 'cp -r "$PROJECT_DIR/scripts" "$INSTALL_DIR/"' in src, \
        "deploy.sh install_host does not copy scripts/ to /opt -- cron-audit.sh never reaches the host"


# ── M-g: EXECUTE the cron script (not grep) and assert real exit codes ──────────────
_CRON = SCRIPTS / "cron-audit.sh"
_NO_BASH = sys.platform == "win32" or shutil.which("bash") is None


def _run_cron(tmp_path, setup_key):
    """Execute cron-audit.sh with all host paths redirected into tmp (env-overridable);
    setup_key prepares or omits the HMAC key. Returns (exit_code, log_text)."""
    log_dir = tmp_path / "log"
    key = tmp_path / "hmac.key"
    setup_key(key)
    env = dict(
        os.environ,
        LOG_DIR=str(log_dir),
        APP_DIR=str(tmp_path / "noapp"),    # no .env -> credential/telegram sourcing skipped
        GUARD_DIR=str(tmp_path / "noguard"),
        HMAC_KEY_FILE=str(key),
    )
    r = subprocess.run(["bash", str(_CRON)], env=env, capture_output=True, timeout=60)
    logs = list(log_dir.glob("cron_*.log"))
    log_text = logs[0].read_text(errors="replace") if logs else ""
    return r.returncode, log_text


@pytest.mark.skipif(_NO_BASH, reason="needs a POSIX bash to execute the cron script")
def test_cron_audit_missing_key_exits_2(tmp_path):
    """M-g (executes the script, not grep): a missing HMAC key -> exit 2 + FATAL log."""
    code, log = _run_cron(tmp_path, setup_key=lambda k: None)  # key absent
    assert code == 2, f"missing key did not exit 2 (got {code})"
    assert "FATAL: HMAC key file missing" in log


@pytest.mark.skipif(_NO_BASH, reason="needs a POSIX bash to execute the cron script")
def test_cron_audit_insecure_perms_exits_2(tmp_path):
    """M-g: a world-readable HMAC key (0644) -> exit 2 + insecure-perms FATAL."""
    def setup(k):
        k.write_text("deadbeef")
        os.chmod(k, 0o644)

    code, log = _run_cron(tmp_path, setup_key=setup)
    assert code == 2, f"insecure-perms key did not exit 2 (got {code})"
    assert "insecure permissions" in log


# ── item #13 (audit 2026-07-17): execute the 0/1/error branches of the wrapper ──────
# The exit-2 HMAC branches above are execute-tested; these cover the remaining
# branches by shimming python3 on PATH so `python3 -m substrate_guard.audit`
# returns a forced exit code (no DB needed). The telegram helper self-no-ops
# (APP_DIR has no .env), so nothing leaves the sandbox.


def _run_cron_with_audit_exit(tmp_path, audit_exit, with_report=False):
    """_run_cron variant with a python3 PATH-shim forcing the audit exit code."""
    log_dir = tmp_path / "log"
    log_dir.mkdir(parents=True, exist_ok=True)
    if with_report:
        (log_dir / "audit_20990101_000000.json").write_text(
            '{"evaluation": {"violations": 3}, "events_generated": 61}'
        )
    guard_dir = tmp_path / "guard"
    guard_dir.mkdir(exist_ok=True)
    key = tmp_path / "hmac.key"
    key.write_text("deadbeef")
    os.chmod(key, 0o600)

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "python3"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-m" ]; then exit ' + str(audit_exit) + "; fi\n"
        'if [ "$1" = "-c" ]; then echo 3; exit 0; fi\n'
        "exit 0\n"
    )
    shim.chmod(0o755)

    env = dict(
        os.environ,
        PATH=f"{shim_dir}{os.pathsep}{os.environ['PATH']}",
        LOG_DIR=str(log_dir),
        APP_DIR=str(tmp_path / "noapp"),
        GUARD_DIR=str(guard_dir),
        HMAC_KEY_FILE=str(key),
    )
    r = subprocess.run(["bash", str(_CRON)], env=env, capture_output=True, timeout=60)
    logs = list(log_dir.glob("cron_*.log"))
    log_text = logs[0].read_text(errors="replace") if logs else ""
    return r.returncode, log_text


@pytest.mark.skipif(_NO_BASH, reason="needs a POSIX bash to execute the cron script")
def test_cron_audit_clean_branch_executes(tmp_path):
    """audit exit 0 -> the clean(0) wrapper branch logs 'Audit clean'."""
    code, log = _run_cron_with_audit_exit(tmp_path, audit_exit=0)
    assert code == 0, f"wrapper must exit 0 on clean audit (got {code})"
    assert "Audit clean" in log
    assert "VIOLATIONS DETECTED" not in log


@pytest.mark.skipif(_NO_BASH, reason="needs a POSIX bash to execute the cron script")
def test_cron_audit_violation_branch_executes(tmp_path):
    """audit exit 1 -> the violation(1) wrapper branch fires (alert path), and
    the wrapper itself still exits 0 (cron alerting is via telegram, not rc)."""
    code, log = _run_cron_with_audit_exit(tmp_path, audit_exit=1, with_report=True)
    assert code == 0, f"wrapper exit (got {code})"
    assert "VIOLATIONS DETECTED" in log
    assert "Audit clean" not in log
    assert "AUDIT ERROR" not in log


@pytest.mark.skipif(_NO_BASH, reason="needs a POSIX bash to execute the cron script")
def test_cron_audit_error_branch_executes(tmp_path):
    """audit exit 2 -> the ERROR branch (DB/config), explicitly NOT the
    violations alert -- the distinction the exit-code contract exists for."""
    code, log = _run_cron_with_audit_exit(tmp_path, audit_exit=2)
    assert code == 0, f"wrapper exit (got {code})"
    assert "AUDIT ERROR (exit 2)" in log
    assert "VIOLATIONS DETECTED" not in log
