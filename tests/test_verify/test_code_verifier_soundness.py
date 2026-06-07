"""Soundness regression tests for CodeVerifier.

A sound verifier must NEVER return VERIFIED when the translator dropped a
construct it cannot model — otherwise it proves a property about a strictly
weaker model than the real function. See P0 in docs/AUDIT_COMPLEX_2026-06-07.md.
"""
from __future__ import annotations

from substrate_guard.code_verifier import Spec, verify_code


def test_dropped_loop_does_not_verify():
    """A for-loop is dropped by the translator; the verifier must NOT prove a
    (false) property about the loop-less skeleton. Before the fix this returned
    VERIFIED because the loop body was discarded and `total` stayed 0."""
    src = (
        "def sum_to_n(n: int) -> int:\n"
        "    total = 0\n"
        "    for i in range(n):\n"
        "        total = total + i\n"
        "    return total\n"
    )
    r = verify_code(src, Spec(preconditions=["n == 5"], postconditions=["__return__ == 0"]))
    assert not r.verified, f"loop function wrongly VERIFIED (status={r.status})"


def test_dropped_side_effecting_call_does_not_verify():
    """A bare side-effecting call is not modeled; the verifier must abstain."""
    src = (
        "def f(x: int) -> int:\n"
        "    do_something_dangerous(x)\n"
        "    return x\n"
    )
    r = verify_code(src, Spec(preconditions=["x >= 0"], postconditions=["__return__ >= 0"]))
    assert not r.verified, f"side-effecting call wrongly VERIFIED (status={r.status})"


def test_clean_function_still_verifies():
    """A function entirely within the modeled fragment still returns VERIFIED —
    the abstain-on-drop fix must not over-abstain on clean code."""
    src = (
        "def double(x: int) -> int:\n"
        "    return x + x\n"
    )
    r = verify_code(src, Spec(preconditions=["x >= 0"], postconditions=["__return__ >= 0"]))
    assert r.verified, f"clean function failed to VERIFY (status={r.status})"


def test_floordiv_negative_divisor_correct_semantics():
    """Python floor division on a negative divisor must be modeled correctly:
    7 // -2 == -4 (not Z3's Euclidean -3). The correct spec VERIFIES; the wrong one
    is rejected. Before the fix this was inverted."""
    src = "def f(x: int) -> int:\n    return x // -2\n"
    ok = verify_code(src, Spec(preconditions=["x == 7"], postconditions=["__return__ == -4"]))
    assert ok.verified, f"correct floor-div spec not VERIFIED ({ok.status})"
    bad = verify_code(src, Spec(preconditions=["x == 7"], postconditions=["__return__ == -3"]))
    assert not bad.verified, f"wrong floor-div spec wrongly accepted ({bad.status})"


def test_mod_negative_divisor_correct_semantics():
    """Python modulo takes the divisor's sign: 7 % -3 == -2 (not Z3's +1)."""
    src = "def g(x: int) -> int:\n    return x % -3\n"
    ok = verify_code(src, Spec(preconditions=["x == 7"], postconditions=["__return__ == -2"]))
    assert ok.verified, f"correct mod spec not VERIFIED ({ok.status})"
    bad = verify_code(src, Spec(preconditions=["x == 7"], postconditions=["__return__ == 1"]))
    assert not bad.verified, f"wrong mod spec wrongly accepted ({bad.status})"
