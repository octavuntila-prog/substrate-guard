"""Regression guards for the deploy/ops scripts (H3).

The production cron must run the CANONICAL cron-audit.sh -- not a frozen heredoc copy
that drifts. Before the fix, setup-cron.sh embedded a stale copy (no HMAC handling, the
buggy 2-way `EXIT_CODE -ne 0 -> VIOLATIONS DETECTED` branch) and deploy.sh never copied
scripts/ to /opt, so the good script was unreachable on a real host. These tests fail if
any of that regresses.
"""
from pathlib import Path

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


def test_deploy_install_host_copies_scripts_dir():
    src = (SCRIPTS / "deploy.sh").read_text(encoding="utf-8")
    assert 'cp -r "$PROJECT_DIR/scripts" "$INSTALL_DIR/"' in src, \
        "deploy.sh install_host does not copy scripts/ to /opt -- cron-audit.sh never reaches the host"
