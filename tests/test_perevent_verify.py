"""L3 per-event formal verification: 4-way verdict, selection, sampling, async, chain
(plan 1.C). See docs/l3-perevent-verify.md and substrate_guard/perevent_verify.py."""

from __future__ import annotations

from concurrent.futures import Future

import pytest

pytest.importorskip("z3")

from substrate_guard.observe.events import EventType, FileEvent
from substrate_guard.perevent_verify import (
    PerEventConfig,
    PerEventVerifier,
    Verdict,
    _map_status_to_verdict,
)

_VERIFIED_CODE = "def my_abs(x: int) -> int:\n    if x >= 0:\n        return x\n    return -x"
_REFUTED_CODE = "def bad_abs(x: int) -> int:\n    return x"   # claims >=0, x=-1 refutes
_ABSTAIN_TOOL = '{"name": "t", "description": "d", "params": []}'   # no operation_template
_SPEC = {"postconditions": ["__return__ >= 0"]}


def _ev(fa=None, agent="orch"):
    e = FileEvent(type=EventType.FILE_WRITE, agent_id=agent, path="/workspace/x.py")
    e.metadata = {"formal_artifact": fa} if fa else {}
    return e


def _art(atype, artifact, spec=None):
    fa = {"type": atype, "artifact": artifact}
    if spec is not None:
        fa["spec"] = spec
    return fa


# --- real verdicts (z3) ------------------------------------------------------

def test_verified_refuted_abstain_real():
    pv = PerEventVerifier(PerEventConfig(timeout_ms=2000))
    pv.submit(_ev(_art("code", _VERIFIED_CODE, _SPEC)))
    pv.submit(_ev(_art("code", _REFUTED_CODE, _SPEC)))
    pv.submit(_ev(_art("tool", _ABSTAIN_TOOL)))
    verdict_for = {}
    for r in pv.drain():
        key = ("verified" if "my_abs" in r.artifact_preview
               else "refuted" if "bad_abs" in r.artifact_preview
               else "abstain")
        verdict_for[key] = r.verdict
    assert verdict_for["verified"] is Verdict.VERIFIED
    assert verdict_for["refuted"] is Verdict.REFUTED
    assert verdict_for["abstain"] is Verdict.ABSTAIN


def test_refuted_carries_counterexample():
    pv = PerEventVerifier(PerEventConfig(timeout_ms=2000))
    pv.submit(_ev(_art("code", _REFUTED_CODE, _SPEC)))
    rec = pv.drain()[0]
    assert rec.verdict is Verdict.REFUTED
    assert "x" in rec.detail and "-1" in rec.detail   # concrete counterexample


def test_broken_artifact_abstains_never_crashes():
    pv = PerEventVerifier(PerEventConfig(timeout_ms=500))
    pv.submit(_ev(_art("code", "@@@ not python @@@")))
    assert pv.drain()[0].verdict is Verdict.ABSTAIN


# --- deterministic verdict mapping (incl TIMEOUT) ----------------------------

class _FakeResult:
    counterexample = None
    error = None

    def __init__(self, status_name):
        self.status = type("S", (), {"name": status_name})()


@pytest.mark.parametrize("status,expected", [
    ("VERIFIED", Verdict.VERIFIED), ("SAFE", Verdict.VERIFIED), ("ALL_VALID", Verdict.VERIFIED),
    ("UNSAFE", Verdict.REFUTED), ("HAS_ERRORS", Verdict.REFUTED),
    ("UNKNOWN", Verdict.ABSTAIN), ("TRANSLATION_ERROR", Verdict.ABSTAIN),
    ("PARSE_ERROR", Verdict.ABSTAIN), ("INCONCLUSIVE", Verdict.ABSTAIN),
])
def test_status_maps_to_verdict(status, expected):
    # fast (well under budget) -> not TIMEOUT
    assert _map_status_to_verdict(_FakeResult(status), 5.0, 300)[0] is expected


def test_abstain_at_budget_becomes_timeout():
    # an abstain-status that consumed ~the whole budget is reported TIMEOUT
    assert _map_status_to_verdict(_FakeResult("UNKNOWN"), 290.0, 300)[0] is Verdict.TIMEOUT
    # a VERIFIED/REFUTED at the budget is NOT relabeled
    assert _map_status_to_verdict(_FakeResult("VERIFIED"), 290.0, 300)[0] is Verdict.VERIFIED


# --- selection + sampling ----------------------------------------------------

def test_selection_skips_non_artifact_events():
    pv = PerEventVerifier()
    assert pv.submit(_ev()) is None                       # no formal_artifact
    assert pv.submit(_ev(_art("code", ""))) is None       # empty artifact
    assert pv.submit(_ev({"type": "python", "artifact": "x"})) is None  # type not enabled
    assert pv.skipped_selection == 3 and pv.submitted == 0
    assert pv.drain() == []


def test_sampling_rate_zero_and_one():
    pv0 = PerEventVerifier(PerEventConfig(sample_rate=0.0))
    assert pv0.submit(_ev(_art("code", _VERIFIED_CODE, _SPEC))) is None
    assert pv0.skipped_sampling == 1 and pv0.submitted == 0

    pv1 = PerEventVerifier(PerEventConfig(sample_rate=1.0, timeout_ms=2000))
    pv1.submit(_ev(_art("code", _VERIFIED_CODE, _SPEC)))
    assert pv1.submitted == 1


def test_sampling_is_deterministic():
    """Same artifact -> same in/out decision every time (hash-based, no RNG)."""
    pv = PerEventVerifier(PerEventConfig(sample_rate=0.5))
    decisions = {pv._sampled_in(_VERIFIED_CODE) for _ in range(5)}
    assert len(decisions) == 1   # stable across repeats


# --- chain recording ---------------------------------------------------------

def test_chain_event_carries_4way_verdict():
    pv = PerEventVerifier(PerEventConfig(timeout_ms=2000))
    pv.submit(_ev(_art("code", _VERIFIED_CODE, _SPEC), agent="agent-9"))
    ce = pv.drain()[0].to_chain_event()
    assert ce["type"] == "formal_verification"
    assert ce["verdict"] == "VERIFIED"          # the 4-way verdict (new)
    assert ce["verified"] is True               # legacy bool (kept, additive)
    assert ce["agent_id"] == "agent-9"
    assert ce["verifier_type"] == "code"


# --- async plumbing (injected executor; process pool in prod, Z3 is thread-unsafe) ---

class _InlineExecutor:
    """Runs the task synchronously but returns a Future -- exercises the async
    submit/drain path cross-platform without a real ProcessPoolExecutor (which would
    re-import + run Z3 in a subprocess)."""

    def submit(self, fn, *a, **k):
        f: Future = Future()
        try:
            f.set_result(fn(*a, **k))
        except Exception as e:  # pragma: no cover
            f.set_exception(e)
        return f

    def shutdown(self, wait=True):
        pass


def test_async_via_injected_executor():
    pv = PerEventVerifier(PerEventConfig(timeout_ms=2000), executor=_InlineExecutor())
    fut = pv.submit(_ev(_art("code", _VERIFIED_CODE, _SPEC)))
    assert isinstance(fut, Future)              # async mode returns a Future
    recs = pv.drain(timeout=5.0)
    assert len(recs) == 1 and recs[0].verdict is Verdict.VERIFIED
    assert pv.pending_count() == 0


# --- Guard wiring: inject path -> verdict recorded in the HMAC chain ----------

def test_guard_inject_path_records_verdict_in_chain():
    from substrate_guard.guard import Guard

    guard = Guard(observe=True, policy="nonexistent/", verify=False, chain=True,
                  hmac_secret="k", source="inject",
                  perevent_verify=PerEventConfig(timeout_ms=2000))
    agent = "orch"
    with guard.monitor(agent) as session:
        e = FileEvent(type=EventType.FILE_WRITE, agent_id=agent, path="/workspace/x.py")
        e.metadata = {"formal_artifact": _art("code", _VERIFIED_CODE, _SPEC)}
        session.inject_and_evaluate(e)

    records = guard.collect_perevent_verdicts()
    assert len(records) == 1 and records[0].verdict is Verdict.VERIFIED

    fv = [en for en in guard._chain.entries if en.event_type == "formal_verification"]
    assert fv, "no formal_verification entry in the chain"
    assert fv[-1].event_data.get("verdict") == "VERIFIED"     # 4-way verdict recorded
    assert guard._chain.verify()[0] is True                   # chain still intact (HMAC)


def test_guard_without_artifact_records_nothing():
    from substrate_guard.guard import Guard

    guard = Guard(observe=True, policy="nonexistent/", verify=False, chain=True,
                  hmac_secret="k", source="inject",
                  perevent_verify=PerEventConfig())
    with guard.monitor("a") as session:
        session.inject_and_evaluate(
            FileEvent(type=EventType.FILE_WRITE, agent_id="a", path="/workspace/plain.txt")
        )
    assert guard.collect_perevent_verdicts() == []            # no artifact -> nothing verified
    fv = [en for en in guard._chain.entries if en.event_type == "formal_verification"]
    assert not fv
