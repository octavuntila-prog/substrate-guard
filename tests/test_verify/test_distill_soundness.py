"""Soundness regression for DistillationVerifier.

Dropped exponents and Z3-unknown steps must NOT be reported as part of an
ALL_VALID trace. See P0 in docs/AUDIT_COMPLEX_2026-06-07.md.
"""
from __future__ import annotations

from substrate_guard.distill_verifier import DistillationVerifier


def test_dropped_exponent_not_all_valid():
    """A step with x**12 (exponent outside the modeled 0..10 range) must not be
    accepted. Before the fix the exponent was dropped (x**12 -> x), so the false
    claim x**12 == x verified VALID and the trace reported all_valid."""
    v = DistillationVerifier()
    steps = [
        {"expression": "2 + 2", "value": "4"},   # genuinely valid
        {"expression": "x**12", "value": "x"},   # false for |x| > 1
    ]
    r = v.verify_trace("test", steps)
    assert not r.all_valid, f"dropped-exponent step wrongly reported all_valid ({r.status})"


def test_clean_trace_still_all_valid():
    """A faithfully-modeled valid trace must still report all_valid (the
    abstain/INCONCLUSIVE change must not over-reject clean reasoning)."""
    v = DistillationVerifier()
    steps = [
        {"expression": "2 + 2", "value": "4"},
        {"expression": "3 * 4", "value": "12"},
    ]
    r = v.verify_trace("test", steps)
    assert r.all_valid, f"clean trace failed to report all_valid ({r.status})"


def test_exact_rational_coefficient_not_all_valid():
    """A coefficient that float()s to 1.0 but is NOT 1 must not pass:
    (10**16+1)/10**16 * x == x is FALSE, yet float() collapsed it to 1.0."""
    v = DistillationVerifier()
    r = v.verify_trace("t", [
        {"expression": "(10000000000000001/10000000000000000)*x", "value": "x"},
    ])
    assert not r.all_valid, f"false rational equality wrongly all_valid ({r.status})"


def test_boolean_collapsed_equation_does_not_crash():
    """An equation SymPy collapses to a constant boolean (x = x -> True) must not crash
    the verifier with an AttributeError on eq.lhs."""
    v = DistillationVerifier()
    r = v.verify_trace("t", [{"claim": "x = x -> x = x"}])
    assert r is not None  # returned a verdict instead of raising


def test_power_tower_does_not_dos():
    """A power-tower expression must be rejected quickly, not computed (CPU/memory DoS
    + a 4300-digit int->str ValueError)."""
    import time

    v = DistillationVerifier()
    t0 = time.time()
    r = v.verify_trace("t", [{"expression": "9**9**9", "value": "0"}])
    assert time.time() - t0 < 5, "power-tower took too long (DoS)"
    assert r is not None
