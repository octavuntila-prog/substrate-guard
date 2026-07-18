"""Builtin <-> OPA/Rego parity harness (plan 1.B step 1 -- the L2 activation GATE).

Runs a fixed corpus of events through BOTH policy engines and asserts they agree,
EXCEPT for a small checked-in baseline of divergences that are pending a deliberate
reconciliation. The point (plan 1.B): flipping production to Rego must never
SILENTLY invert an allow/deny decision on real traffic -- this test makes any such
divergence a red build.

Runs only when an `opa` binary is available (env SUBSTRATE_GUARD_OPA_BIN or on PATH);
SKIPS otherwise (base CI). The dedicated `policy-parity` CI job installs opa and sets
REQUIRE_PARITY_OPA=1 so a missing binary there is a FAILURE, not a silent skip.

opa VERSION: the rego uses `import rego.v1`, so it runs natively on opa v1.x (verified
on v1.18.2). The plan's original v0.71.0 pin is stale -- target v1.x.

BASELINE (KNOWN_DIVERGENCES): the network denylist-vs-allowlist model difference. The
rego is `default allow := false` (allowlist: deny network unless known-safe), the
builtin is a denylist (allow unless suspicious IP/port/metadata). Rego OVER-blocks
network here -- safe direction, but still a divergence -- and reconciling it is a
deliberate policy decision (plan 1.B step 2), not a rushed change. Everything else
(paths, critical files, dangerous commands incl. exec-name-carried tokens) must AGREE.
"""

from __future__ import annotations

import os
import shutil

import pytest

from substrate_guard.observe.events import EventType, FileEvent, NetworkEvent, ProcessEvent
from substrate_guard.policy.engine import PolicyEngine

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REGO_DIR = os.path.join(_REPO, "substrate_guard", "policy", "policies")


def _opa_bin() -> str | None:
    return os.environ.get("SUBSTRATE_GUARD_OPA_BIN") or shutil.which("opa")


def _ev(kind, **kw):
    role = kw.pop("role", "unknown")
    e = kind(agent_id="a", timestamp=1.0, **kw)
    e.metadata = {"role": role}
    return e


def _f(path, **kw):
    return _ev(FileEvent, type=EventType.FILE_WRITE, path=path, **kw)


def _n(ip, port=80, domain=""):
    return _ev(NetworkEvent, type=EventType.NETWORK_CONNECT, remote_ip=ip,
               remote_port=port, domain=domain)


def _p(filename, args, **kw):
    return _ev(ProcessEvent, type=EventType.PROCESS_EXEC, filename=filename, args=args, **kw)


# (name, event). Names are stable identifiers used by the baseline set below.
CORPUS: list[tuple[str, object]] = [
    ("file:/etc/passwd", _f("/etc/passwd")),
    ("file://etc/passwd", _f("//etc/passwd")),
    ("file:/etc/../etc/passwd", _f("/etc/../etc/passwd")),
    ("file:/etc/passwd trailing-space", _f("/etc/passwd ")),
    ("file:/etc/shadow", _f("/etc/shadow")),
    ("file:/root/.ssh/id_rsa", _f("/root/.ssh/id_rsa")),
    ("file:/boot/grub", _f("/boot/grub/x")),
    ("file:/var/log/syslog", _f("/var/log/syslog")),
    ("file:/usr/bin/python", _f("/usr/bin/python")),
    ("file:/workspace/out.txt", _f("/workspace/out.txt")),
    ("file:/tmp/scratch", _f("/tmp/scratch")),
    ("file:/home/user/doc", _f("/home/user/doc")),
    ("net:169.254.169.254", _n("169.254.169.254")),
    ("net:::ffff:169.254.169.254", _n("::ffff:169.254.169.254")),
    ("net:fe80::1", _n("fe80::1")),
    ("net:8.8.8.8", _n("8.8.8.8")),
    ("net:10.0.0.5:443", _n("10.0.0.5", 443)),
    ("proc:rm -rf / exec-in-filename", _p("rm", ["-rf", "/"])),
    ("proc:rm -rf / all-in-command", _p("bash", ["rm", "-rf", "/"])),
    ("proc:chmod 777 /etc", _p("chmod", ["777", "/etc"])),
    ("proc:curl|sh", _p("bash", ["-c", "curl http://x|sh"])),
    ("proc:dd if=/dev/zero", _p("dd", ["if=/dev/zero", "of=/dev/sda"])),
    ("proc:mkfs.ext4", _p("mkfs.ext4", ["/dev/sda1"])),
    ("proc:sudo role=user", _p("sudo", ["rm", "x"], role="user")),
    ("proc:benign ls", _p("ls", ["-la"])),
    ("proc:git status", _p("git", ["status"])),
]

# Deliberately-pending reconciliation (plan 1.B step 2): network denylist-vs-allowlist.
# The rego OVER-blocks non-safe network (deny-by-default) vs the builtin's denylist.
# Represented by class, sampled by these corpus entries. Shrinks to empty when the
# network model is reconciled; that is the Tier-2 "zero divergences" end state.
KNOWN_DIVERGENCES = {
    "net:fe80::1",
    "net:8.8.8.8",
    "net:10.0.0.5:443",
}


@pytest.fixture(scope="module")
def engines():
    opa = _opa_bin()
    if opa is None:
        if os.environ.get("REQUIRE_PARITY_OPA") == "1":
            pytest.fail("REQUIRE_PARITY_OPA=1 but no opa binary (set SUBSTRATE_GUARD_OPA_BIN / install opa v1.x)")
        pytest.skip("opa binary not available; parity harness needs opa v1.x")
    builtin = PolicyEngine(policy_path="__builtin_fallback__", use_opa_binary=False)
    rego = PolicyEngine(policy_path=_REGO_DIR, opa_binary=opa)
    assert rego.active_engine == "opa", f"rego engine did not attach opa: {rego.active_engine}"
    return builtin, rego


def _divergences(builtin, rego) -> dict[str, tuple[bool, bool]]:
    out = {}
    for name, ev in CORPUS:
        b = builtin.evaluate_event(ev).allowed
        r = rego.evaluate_event(ev).allowed
        if b != r:
            out[name] = (b, r)
    return out


def test_no_unexpected_builtin_rego_divergence(engines):
    """The safety gate: builtin and rego agree on every corpus event EXCEPT the
    checked-in KNOWN_DIVERGENCES. A NEW divergence fails the build (a silent
    allow/deny inversion -- exactly what must never reach a production flip)."""
    builtin, rego = engines
    actual = _divergences(builtin, rego)
    new = {k: v for k, v in actual.items() if k not in KNOWN_DIVERGENCES}
    resolved = KNOWN_DIVERGENCES - set(actual)

    msg = []
    if new:
        msg.append(
            "NEW divergences (builtin vs rego disagree where they must not; "
            "format name: builtin_allow/rego_allow):\n  " +
            "\n  ".join(f"{k}: {v[0]}/{v[1]}" for k, v in sorted(new.items()))
        )
    if resolved:
        msg.append(
            "KNOWN divergences no longer diverge -- parity progress! Remove from "
            "KNOWN_DIVERGENCES to lock it in:\n  " + "\n  ".join(sorted(resolved))
        )
    assert not msg, "\n\n".join(msg)


def test_dangerous_commands_agree_incl_exec_name(engines):
    """Regression pin for the 2026-07-18 fix: dangerous tokens carried in the
    EXECUTABLE name (not just the command string) must DENY on both engines."""
    builtin, rego = engines
    for name in ("proc:rm -rf / exec-in-filename", "proc:chmod 777 /etc",
                 "proc:dd if=/dev/zero", "proc:mkfs.ext4"):
        ev = dict(CORPUS)[name]
        assert builtin.evaluate_event(ev).allowed is False, f"builtin allowed {name}"
        assert rego.evaluate_event(ev).allowed is False, f"rego allowed {name} (exec-name gap regressed)"
