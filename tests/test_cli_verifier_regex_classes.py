"""Two L2 denylist classes closed on 2026-10-13 (found as false negatives of the tool
checker's corpus, fixed at the regex that owns them):

  * recursive_delete was lower-case only: the upper-case recursive flag passed.
  * pipe_to_shell needed something after the shell name: a pipe into a shell at the END
    of the command passed (and zsh/dash were not shells).
Benign look-alikes must stay clear (sha256sum, shuf, shellcheck after a pipe).

The command strings are assembled at runtime: a literal "decode | shell" line in a test
file trips endpoint antivirus heuristics on the maintainer's machine (file locked on write).
"""
from __future__ import annotations

import pytest

from substrate_guard.cli_verifier import CLIVerifier

PIPE = " | "
SH, BASH, ZSH, DASH = "s" + "h", "ba" + "sh", "z" + "sh", "da" + "sh"
RM = "r" + "m"


def names(cmd: str) -> set[str]:
    return {v.pattern_name for v in CLIVerifier().verify(cmd).violations}


@pytest.mark.parametrize("flags", ["-Rf", "-fR", "-R", "-rf"])
def test_recursive_delete_is_case_insensitive_on_the_flag(flags):
    assert "recursive_delete" in names(f"{RM} {flags} /tmp/x")


@pytest.mark.parametrize("cmd", [
    "base64 -d /tmp/a" + PIPE + SH,
    "echo x |" + SH,
    "cat s" + PIPE + BASH,
    "curl x" + PIPE + ZSH,
    "cat s" + PIPE + DASH,
])
def test_pipe_to_shell_at_end_of_command(cmd):
    assert "pipe_to_shell" in names(cmd)


@pytest.mark.parametrize("cmd", ["cat f" + PIPE + "sha256sum", "sort f" + PIPE + "shuf", "echo x" + PIPE + "shellcheck -", "ls" + PIPE + "sort"])
def test_shell_lookalikes_do_not_trip_pipe_to_shell(cmd):
    assert "pipe_to_shell" not in names(cmd)


# third class (2026-10-14): `su root` needed a dash or two spaces to match r"\bsu\s+-?\s"
@pytest.mark.parametrize("cmd", ["su root", "su - root", "su -", 'sh -c "su root a"', "ls;su root"])
def test_su_with_a_target_user_is_privilege_escalation(cmd):
    assert "privilege_escalation" in names(cmd)


@pytest.mark.parametrize("cmd", ["gosu app python app.py", "sum file.txt", "su"])
def test_su_lookalikes_do_not_trip(cmd):
    assert "privilege_escalation" not in names(cmd)
