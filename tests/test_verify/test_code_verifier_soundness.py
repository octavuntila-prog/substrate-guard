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


def test_division_by_zero_is_a_violation():
    """A divisor that can be zero must be reported as a violation (Python raises
    ZeroDivisionError), not silently VERIFIED via Z3's unconstrained x/0."""
    src = "def f(x: int) -> int:\n    return 10 // x\n"
    r = verify_code(src, Spec(postconditions=["__return__ >= -100"]))
    assert not r.verified, f"div-by-zero wrongly VERIFIED ({r.status})"


def test_division_safe_when_divisor_nonzero_by_precondition():
    """When the precondition rules out a zero divisor, the function still verifies."""
    src = "def g(x: int) -> int:\n    return 10 // x\n"
    r = verify_code(src, Spec(preconditions=["x >= 1"], postconditions=["__return__ >= 0"]))
    assert r.verified, f"safe division failed to VERIFY ({r.status})"


def test_nested_conditional_return_does_not_verify():
    """A no-else `if` whose body returns on only SOME paths must force an abstain:
    the fall-through continuation (here `return -1`) was otherwise dropped, proving
    a false property. Real f(x) for 5<=x<=50 returns -1 (< 0), violating the spec.
    Residual found by the adversarial verification of commit 3b0d009."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 0:\n"
        "        if x > 100:\n"
        "            return 999\n"
        "    return -1\n"
    )
    r = verify_code(src, Spec(preconditions=["x >= 5", "x <= 50"], postconditions=["__return__ >= 0"]))
    assert not r.verified, f"nested conditional-return wrongly VERIFIED ({r.status})"


def test_asymmetric_if_else_then_returns_does_not_verify():
    """if/else sibling of the no-else partial-return case (commit 0a7fe02): the
    THEN branch returns while the ELSE branch falls through to a continuation
    (`return y`). The old _translate_if returned the then value UNCONDITIONALLY,
    dropping both the branch condition and the fall-through path AND failing to
    record an unsupported construct — a false VERIFIED. Real f(0) == 5 < 10,
    so the spec is violated and the verifier must NOT return VERIFIED."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 0:\n"
        "        return 100\n"
        "    else:\n"
        "        y = 5\n"
        "    return y\n"
    )
    r = verify_code(src, Spec(postconditions=["__return__ >= 10"]))
    assert not r.verified, f"asymmetric if/else (then returns) wrongly VERIFIED ({r.status})"


def test_asymmetric_if_else_else_returns_does_not_verify():
    """Mirror shape: the ELSE branch returns while the THEN branch falls through
    to the continuation (`return y`). Same unsound drop as above. Real f(5) == 5
    < 10, so the spec is violated and the verifier must NOT return VERIFIED."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 0:\n"
        "        y = 5\n"
        "    else:\n"
        "        return 100\n"
        "    return y\n"
    )
    r = verify_code(src, Spec(postconditions=["__return__ >= 10"]))
    assert not r.verified, f"asymmetric if/else (else returns) wrongly VERIFIED ({r.status})"


def test_symmetric_if_else_both_return_still_verifies():
    """Guard against over-abstaining: when BOTH branches return, the if IS
    faithfully modeled as a Z3 If(), so a correct spec must still VERIFY."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 0:\n"
        "        return 100\n"
        "    else:\n"
        "        return 50\n"
    )
    r = verify_code(src, Spec(postconditions=["__return__ >= 10"]))
    assert r.verified, f"symmetric if/else failed to VERIFY ({r.status})"


def test_nested_partial_return_in_branch_does_not_verify():
    """A branch that returns on only SOME sub-paths (an inner if-without-else) while the
    other branch returns: _translate_body yields non-None for BOTH, so the both-return
    merge dropped the fall-through `return 5`. Real f(1)=5 < 10, so the spec is violated
    and the verifier must abstain. Residual found re-verifying commit fc0214d."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 0:\n"
        "        if x > 100:\n"
        "            return 200\n"
        "    else:\n"
        "        return 50\n"
        "    return 5\n"
    )
    r = verify_code(src, Spec(postconditions=["__return__ >= 10"]))
    assert not r.verified, f"nested partial-return wrongly VERIFIED ({r.status})"


def test_function_falling_off_the_end_does_not_verify():
    """A function whose body does not return on all paths falls off the end with an
    implicit `return None` (not modeled). f(0) returns None, violating __return__>=100,
    so the verifier must abstain rather than prove a property over the early returns
    only. Residual found re-verifying commit 1b5e006."""
    src = (
        "def f(x: int) -> int:\n"
        "    if x > 100:\n"
        "        return 200\n"
        "    if x > 50:\n"
        "        return 100\n"
    )
    r = verify_code(src, Spec(postconditions=["__return__ >= 100"]))
    assert not r.verified, f"fall-off-the-end function wrongly VERIFIED ({r.status})"
