"""Extreme fuzz: Guard + ProcessEvent + optional CLI verification (Hypothesis).

Invariants: no uncaught exceptions; policy decision remains boolean.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")
pytest.importorskip("z3")

from hypothesis import HealthCheck, given, settings, strategies as st

from fuzz_helpers import fuzz_max_examples
from substrate_guard.cli_verifier import CLISafetyStatus, verify_cli
from substrate_guard.guard import Guard
from substrate_guard.observe.events import EventType, ProcessEvent

_short = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        min_codepoint=32,
        max_codepoint=0x10FFFF,
    ),
    max_size=80,
)


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)
@given(st.lists(_short, min_size=0, max_size=32))
@pytest.mark.fuzz
def test_fuzz_guard_process_cli_reconstruction_never_raises(args: list[str]):
    """Reconstructed exec line from argv — same path as verify_process_cli in production."""
    g = Guard(
        observe=False,
        policy=None,
        verify=True,
        use_mock=True,
        verify_process_cli=True,
    )
    pe = ProcessEvent(
        type=EventType.PROCESS_EXEC,
        agent_id="fuzz-pe",
        filename="/bin/sh",
        args=args,
        pid=1,
    )
    ge = g.evaluate_event(pe)
    assert ge.policy_decision.allowed in (True, False)
    if ge.verification is not None:
        assert ge.verification.verifier_type == "cli"


@settings(max_examples=fuzz_max_examples(40), deadline=None)
@given(_short)
@pytest.mark.fuzz
def test_fuzz_guard_process_filename_only_never_raises(filename: str):
    g = Guard(
        observe=False,
        policy=None,
        verify=True,
        use_mock=True,
        verify_process_cli=True,
    )
    pe = ProcessEvent(
        type=EventType.PROCESS_EXEC,
        agent_id="fuzz-fn",
        filename=filename or "/bin/true",
        args=[],
        pid=2,
    )
    ge = g.evaluate_event(pe)
    assert ge.policy_decision.allowed in (True, False)


def test_verify_cli_extreme_length_no_crash():
    """Guard truncates at 8k; verifier must still terminate."""
    chunk = "x" * 15000
    r = verify_cli(f"echo {chunk}")
    assert r.status in (CLISafetyStatus.SAFE, CLISafetyStatus.UNSAFE)
    assert r.command.startswith("echo ")


def test_guard_session_report_many_cli_process_events():
    """Volume: many ProcessEvents with verify_process_cli — report counts stay consistent."""
    g = Guard(
        observe=False,
        policy=None,
        verify=True,
        use_mock=True,
        verify_process_cli=True,
    )
    n = 80
    with g.monitor("vol-cli") as session:
        for i in range(n):
            session.inject_and_evaluate(
                ProcessEvent(
                    type=EventType.PROCESS_EXEC,
                    agent_id="vol-cli",
                    filename="/bin/echo",
                    args=["echo", f"ok-{i}"],
                    pid=3000 + i,
                )
            )
    rep = session.report()
    assert rep.events_observed == n
    assert rep.cli_process_verifications == n
    assert rep.formal_verifications >= n
