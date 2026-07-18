"""Deterministic row -> events -> policy violation mapping (audit 2026-07-17 item #13).

Postgres-independent companion to test_postgres_ci.py::test_run_audit_violation_
row_exits_1: it pins the SAME row shape that must produce a policy violation, but
through the adapter + engine directly (no DB, no commit semantics). This runs on
every platform, so a regression in the vendor-bridge mapping or the dangerous-path
rule is caught locally -- not only in the CI Postgres job.
"""

from __future__ import annotations

from substrate_guard.constants import BUILTIN_POLICY_PATH
from substrate_guard.integrations.vendor_bridge import PipelineTraceAdapter
from substrate_guard.policy.engine import PolicyEngine

# EXACTLY the row the Postgres violation test inserts.
VIOLATION_ROW = {
    "trace_id": "ci-violation-1",
    "pipeline_run_id": "1",
    "step_index": 1,
    "agent_name": "CI Violation Agent",
    "status": "completed",
    "model_used": None,
    "input_summary": "n/a",
    "output_summary": "wrote config to /etc/passwd then continued",
    "duration_ms": 10,
    "started_at": "2026-07-18T14:00:00",
}


def _violations(row):
    events = PipelineTraceAdapter.db_row_to_events(row)
    engine = PolicyEngine(policy_path=BUILTIN_POLICY_PATH)
    out = []
    for e in events:
        d = engine.evaluate_event(e)
        if not d.allowed:
            out.append(d)
    return events, out


def test_critical_path_in_output_summary_yields_violation():
    events, violations = _violations(VIOLATION_ROW)
    # a FileEvent(FILE_WRITE, /etc/passwd) must be synthesized...
    assert any(
        getattr(e, "path", None) == "/etc/passwd"
        and getattr(getattr(e, "type", None), "value", None) == "file_write"
        for e in events
    ), f"no /etc/passwd file_write event synthesized: {events}"
    # ...and it must be DENIED by the builtin dangerous-paths rule.
    assert violations, "row with /etc/passwd write produced no policy violation"
    reasons = " ".join(r for v in violations for r in v.reasons)
    assert "/etc/passwd" in reasons


def test_benign_row_is_clean():
    """The clean(0) counterpart: an ordinary row must produce no violation."""
    benign = dict(VIOLATION_ROW, trace_id="ci-clean-1",
                  output_summary="processed 3 markets, wrote /workspace/out.json")
    _events, violations = _violations(benign)
    assert not violations, f"benign row unexpectedly flagged: {violations}"
