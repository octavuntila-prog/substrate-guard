"""Distill verifier: a Z3 `unknown` on an expression step is UNCHECKED (-> INCONCLUSIVE), never
INVALID. Until 2026-10-14 `_verify_evaluation` folded `unknown` into INVALID — a REFUTED without
a counterexample whose verdict depended on the solver budget (found by the docs-claims verifier
while checking "an UNSAFE verdict always carries a replayable witness")."""
from __future__ import annotations

import pytest

pytest.importorskip("z3")

import z3  # noqa: E402

from substrate_guard import distill_verifier as dv  # noqa: E402
from substrate_guard.distill_verifier import DistillationVerifier, StepStatus, TraceStatus  # noqa: E402


class _UnknownSolver:
    """A Solver whose check() always gives up (as Z3 does on a timeout)."""

    def set(self, *a, **k):
        pass

    def add(self, *a):
        pass

    def check(self):
        return z3.unknown


def test_z3_unknown_on_an_expression_step_is_unchecked_not_invalid(monkeypatch):
    monkeypatch.setattr(dv, "Solver", _UnknownSolver)
    r = DistillationVerifier(timeout_ms=1).verify_trace("t", [{"expression": "x*y + x", "value": "x*(y + 1)"}])
    assert [s.status for s in r.steps] == [StepStatus.UNCHECKED]
    assert "unknown" in (r.steps[0].error or "").lower()
    assert r.status is not TraceStatus.ALL_VALID and not r.all_valid   # never a false ALL_VALID / VERIFIED


def test_real_identity_is_valid_or_unchecked_never_invalid():
    for budget in (1, 2000):
        r = DistillationVerifier(timeout_ms=budget).verify_trace("t", [{"expression": "x*y + x", "value": "x*(y + 1)"}])
        assert r.steps[0].status in (StepStatus.VALID, StepStatus.UNCHECKED), str(r)


def test_real_falsehood_is_still_invalid():
    r = DistillationVerifier(timeout_ms=2000).verify_trace("t", [{"expression": "x**3", "value": "x"}])
    assert r.steps[0].status is StepStatus.INVALID and "counterexample" in (r.steps[0].error or "").lower()
