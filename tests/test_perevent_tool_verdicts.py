"""Per-event verdict fidelity for the tool checker (2026-10-13): REFUTED always carries the
instantiated operation + matched literal; an UNKNOWN with reason 'timeout' is TIMEOUT and
any other UNKNOWN reason is ABSTAIN (no elapsed-time heuristic needed); the chain event
records the engine."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("z3")

from substrate_guard.perevent_verify import (  # noqa: E402
    PerEventConfig,
    PerEventVerifier,
    Verdict,
    _map_status_to_verdict,
    verify_one,
)

_DANGEROUS = json.dumps({"name": "cleanup", "params": [{"name": "m", "type": "enum", "enum": ["read", "list"]}],
                         "operation_template": "rm -rf /{m}"})
_SAFE = json.dumps({"name": "lister", "params": [{"name": "d", "type": "enum", "enum": ["docs", "src"]}],
                    "operation_template": "ls -l /workspace/{d}"})
_UNPARSED = json.dumps({"name": "fmt", "params": [{"name": "n", "type": "int", "min": 1, "max": 3}],
                        "operation_template": "tail -n {n:03d}"})
_UNBOUNDED = json.dumps({"name": "sleeper", "params": [{"name": "n", "type": "int"}], "operation_template": "sleep {n}"})


def test_refuted_tool_carries_operation_and_literal():
    rec = verify_one("tool", _DANGEROUS, None, "agent", 300)
    assert rec.verdict is Verdict.REFUTED
    assert "destructive_delete" in rec.detail and "rm -rf /read" in rec.detail
    assert rec.engine == "enumeration"
    assert rec.to_chain_event()["engine"] == "enumeration"


def test_verified_tool():
    rec = verify_one("tool", _SAFE, None, "agent", 300)
    assert rec.verdict is Verdict.VERIFIED and rec.engine == "enumeration"


def test_unparsed_template_abstains_with_reason():
    rec = verify_one("tool", _UNPARSED, None, "agent", 300)
    assert rec.verdict is Verdict.ABSTAIN and "template_unparsed" in rec.detail


def test_unbounded_int_under_small_budget_is_timeout_not_refuted():
    rec = verify_one("tool", _UNBOUNDED, None, "agent", 20)
    assert rec.verdict in (Verdict.TIMEOUT, Verdict.ABSTAIN)
    assert rec.verdict is not Verdict.REFUTED


class _R:
    def __init__(self, status, reason=None, budget_exhausted=False, violations=None):
        self.status = type("S", (), {"name": status})()
        self.reason = reason
        self.budget_exhausted = budget_exhausted
        self.violations = violations or []
        self.counterexample = None
        self.error = None


def test_reason_decides_timeout_vs_abstain_without_elapsed_heuristic():
    assert _map_status_to_verdict(_R("UNKNOWN", reason="timeout"), 5.0, 300)[0] is Verdict.TIMEOUT
    assert _map_status_to_verdict(_R("UNKNOWN", reason="no_template"), 290.0, 300)[0] is Verdict.ABSTAIN
    v, d = _map_status_to_verdict(_R("UNKNOWN", reason="unmodeled_param"), 5.0, 300)
    assert v is Verdict.ABSTAIN and "unmodeled_param" in d


def test_detail_prefers_the_tool_witness():
    r = _R("UNSAFE", violations=[{"pattern": "p", "keyword": " su ", "operation": "su root", "counterexample": {"u": "root"}}])
    v, d = _map_status_to_verdict(r, 1.0, 300)
    assert v is Verdict.REFUTED and d == "p: ' su ' in su root"


def test_unknown_detail_names_the_undecided_pattern_and_z3_version_is_recorded_on_the_z3_engine():
    rec = verify_one("tool", _UNBOUNDED, None, "agent", 60)
    assert rec.verdict in (Verdict.TIMEOUT, Verdict.ABSTAIN) and rec.engine == "z3"
    assert ":" in rec.detail and ("timeout" in rec.detail or "unchecked" in rec.detail)   # "<pattern>: <outcome> (...)"
    ev = rec.to_chain_event()
    assert ev["engine"] == "z3" and ev["z3_version"]
    assert "z3_version" not in verify_one("tool", _SAFE, None, "agent", 300).to_chain_event()


def test_guard_chain_counterexample_carries_the_unknown_reason():
    from substrate_guard.guard import Guard

    guard = Guard(observe=False, policy=None, verify=True, use_mock=True)
    r = guard.verify_artifact(json.dumps({"name": "t", "params": [{"name": "q", "type": "string"}]}), artifact_type="tool")
    assert r.verified is False and "no_template" in (r.counterexample or "")


def test_guard_chain_entry_has_engine(tmp_path):
    from substrate_guard.observe.events import EventType, FileEvent

    pv = PerEventVerifier(PerEventConfig(timeout_ms=300))
    e = FileEvent(type=EventType.FILE_WRITE, agent_id="orch", path="/workspace/x")
    e.metadata = {"formal_artifact": {"type": "tool", "artifact": _DANGEROUS}}
    pv.submit(e)
    ev = pv.drain()[0].to_chain_event()
    assert ev["verdict"] == "REFUTED" and ev["engine"] == "enumeration" and "rm -rf /read" in ev["counterexample"]
