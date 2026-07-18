"""CLI denylist expansion + AST fail-closed (audit 2026-07-17 items #16, #17)."""

from __future__ import annotations

import pytest

from substrate_guard.cli_verifier import verify_cli


# ── item #16: secure-erase + setuid/setgid + capability-grant class ──────────

SHOULD_BE_UNSAFE = [
    # secure_erase
    "shred -u -z /var/log/auth.log",
    "shred -vfz /dev/sda",
    "wipefs -a /dev/sdb",
    "blkdiscard /dev/nvme0n1",
    "mkswap /dev/sdb2",
    # setuid_setgid_bit
    "chmod u+s /usr/bin/python3",
    "chmod +s /tmp/rootshell",
    "chmod 4755 /tmp/backdoor",
    "chmod 6755 /usr/local/bin/x",
    "chmod -R 2755 /opt/app",
    # capabilities_grant_escalation
    "setcap cap_setuid+ep /usr/bin/python3",
    "setcap cap_sys_admin+ep /tmp/tool",
    "setcap 'cap_dac_override+ep' /bin/cat",
]


@pytest.mark.parametrize("cmd", SHOULD_BE_UNSAFE)
def test_new_denylist_class_flagged(cmd: str):
    r = verify_cli(cmd)
    assert not r.safe, f"expected UNSAFE for {cmd!r}"


def test_shell_truncate_flagged_honestly_not_as_sql():
    """`truncate -s 0 <file>` is a coreutils log-wipe, not a SQL TRUNCATE. It must
    stay UNSAFE but with a FILESYSTEM reason -- the old detector misrouted it to the
    SQL scanner and reported the false 'TRUNCATE statement (structural sqlparse)'."""
    r = verify_cli("truncate -s 0 /var/log/auth.log")
    assert not r.safe
    names = [v.pattern_name for v in r.violations]
    assert "file_truncate" in names
    assert not any("sql" in n.lower() for n in names), names


def test_real_sql_truncate_still_detected_as_sql():
    r = verify_cli("TRUNCATE TABLE users")
    assert not r.safe
    assert any("truncate" in v.pattern_name.lower() and "sql" in v.pattern_name.lower()
               for v in r.violations), [v.pattern_name for v in r.violations]


# Guard against over-broad regexes: legitimate neighbours must stay SAFE.
# (NB: `chmod 755`/`chmod 777` are already flagged by the pre-existing
# privilege_escalation rule on the `7` digit -- that is intended, not a new
# false positive, so they are deliberately not in this list.)
STAY_SAFE = [
    "chmod 644 /etc/hosts",              # no 7, no setid digit
    "chmod u+x deploy.sh",               # +x, not +s
    "chmod 0644 notes.txt",
    "setcap -r /usr/bin/ping",           # removing caps, not cap_setuid/sys_admin
    "echo shredder > note.txt",          # \bshred\b must not match 'shredder'
]


@pytest.mark.parametrize("cmd", STAY_SAFE)
def test_neighbours_stay_safe(cmd: str):
    r = verify_cli(cmd)
    assert r.safe, f"false positive: {cmd!r} flagged as {[v.pattern_name for v in r.violations]}"


# ── item #17: AST structural scan is FAIL-CLOSED ─────────────────────────────

def test_ast_scan_crash_fails_closed_when_available(monkeypatch):
    """If the AST layer is available but throws on a command, that command is
    UNSAFE (never silently falls back to regex-only on a parser crash)."""
    def boom(_cmd):
        raise RuntimeError("simulated tree-sitter crash")

    monkeypatch.setattr(
        "substrate_guard.ast_parse.safety_checker.structural_scan", boom
    )
    monkeypatch.setattr(
        "substrate_guard.ast_parse.parser.tree_sitter_bash_available", lambda: True
    )
    # A command with no regex hit would be SAFE if the crash fell open; fail-closed
    # makes it UNSAFE via the synthetic 'unparseable_shell' violation.
    r = verify_cli("echo hello world")
    assert not r.safe
    assert any(v.pattern_name == "unparseable_shell" for v in r.violations)


def test_ast_unavailable_falls_back_to_regex_only(monkeypatch):
    """When tree-sitter is NOT installed, a scan error degrades to regex-only
    (a benign command stays SAFE) -- a config state is not a per-command signal."""
    def boom(_cmd):
        raise RuntimeError("simulated import/parse error")

    monkeypatch.setattr(
        "substrate_guard.ast_parse.safety_checker.structural_scan", boom
    )
    monkeypatch.setattr(
        "substrate_guard.ast_parse.parser.tree_sitter_bash_available", lambda: False
    )
    assert verify_cli("echo hello world").safe          # benign -> regex-only -> safe
    assert not verify_cli("rm -rf /").safe              # regex still fires


def test_regex_still_fires_even_if_ast_crashes_unavailable(monkeypatch):
    """Regex denylist is independent of the AST layer."""
    monkeypatch.setattr(
        "substrate_guard.ast_parse.safety_checker.structural_scan",
        lambda _c: (_ for _ in ()).throw(RuntimeError("x")),
    )
    monkeypatch.setattr(
        "substrate_guard.ast_parse.parser.tree_sitter_bash_available", lambda: False
    )
    assert not verify_cli("shred -vfz /dev/sda").safe
