"""Property-based and bounded-random fuzz on short inputs.

Requires: hypothesis (``pip install -e ".[dev]"``).

Invariants: no uncaught exceptions; outputs stay in expected domains.
"""

from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")
pytest.importorskip("z3")

from hypothesis import given, settings, strategies as st
from hypothesis import HealthCheck

from substrate_guard.audit import build_db_url, parse_json_field
from substrate_guard.cli_verifier import CLISafetyResult, verify_cli, CLISafetyStatus
from substrate_guard.guard import Guard
from substrate_guard.integrations.vendor_bridge import PipelineTraceAdapter
from substrate_guard.observe.events import EventType, FileEvent

from fuzz_helpers import fuzz_max_examples

# Short ASCII / Unicode text — typical “token” scale from LLM fragments
_short_text = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),
        min_codepoint=32,
        max_codepoint=0x10FFFF,
    ),
    max_size=96,
)


@settings(
    max_examples=fuzz_max_examples(120),
    deadline=None,
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)
@given(_short_text)
@pytest.mark.fuzz
def test_fuzz_verify_cli_never_raises_and_status_binary(s: str):
    r = verify_cli(s)
    assert isinstance(r, CLISafetyResult)
    assert r.status in (CLISafetyStatus.SAFE, CLISafetyStatus.UNSAFE)
    assert r.command == s
    assert r.time_ms >= 0.0


@settings(max_examples=fuzz_max_examples(80), deadline=None)
@given(_short_text)
@pytest.mark.fuzz
def test_fuzz_cliverifier_consistent_with_second_call(s: str):
    """Same input → same safety classification (deterministic verifier)."""
    a = verify_cli(s)
    b = verify_cli(s)
    assert a.safe == b.safe
    assert len(a.violations) == len(b.violations)


@settings(max_examples=fuzz_max_examples(100), deadline=None)
@given(st.one_of(st.none(), _short_text, st.dictionaries(st.text(), st.text())))
@pytest.mark.fuzz
def test_fuzz_parse_json_field_total(payload):
    out = parse_json_field(payload)
    # None / dict pass through; str may JSON-decode to scalar (e.g. "0") — see audit.parse_json_field
    if payload is None:
        assert out == {}
    elif isinstance(payload, dict):
        assert isinstance(out, dict)
    else:
        assert isinstance(out, (dict, list, str, int, float, bool))


@settings(max_examples=fuzz_max_examples(80), deadline=None)
@given(
    st.dictionaries(
        keys=st.sampled_from(
            [
                "POSTGRES_USER",
                "POSTGRES_PASSWORD",
                "POSTGRES_HOST",
                "POSTGRES_PORT",
                "POSTGRES_DB",
                "DATABASE_URL",
                "NOISE",
            ]
        ),
        values=_short_text,
        max_size=8,
    )
)
@pytest.mark.fuzz
def test_fuzz_build_db_url_never_raises(env: dict):
    url = build_db_url(env)
    # DATABASE_URL passthrough may be arbitrary string; component-build returns postgresql:// or None
    assert url is None or isinstance(url, str)


@settings(max_examples=fuzz_max_examples(60), deadline=None)
@given(_short_text)
@pytest.mark.fuzz
def test_fuzz_pipeline_trace_adapter_row_never_raises(summary: str):
    row = {
        "id": 1,
        "trace_id": "fuzz",
        "pipeline_run_id": "1",
        "step_index": 1,
        "agent_id": 1,
        "agent_name": "FuzzAgent",
        "status": "completed",
        "model_used": "gpt-4o-mini",
        "input_summary": "in",
        "output_summary": summary,
        "tokens_in": 1,
        "tokens_out": 1,
        "cost_usd": 0.0,
        "duration_ms": 1,
        "error": None,
        "started_at": "2026-01-01T00:00:00+00:00",
        "completed_at": None,
        "confidence": 0.5,
    }
    events = PipelineTraceAdapter.db_row_to_events(row)
    assert isinstance(events, list)


@settings(max_examples=fuzz_max_examples(80), deadline=None)
@given(_short_text)
@pytest.mark.fuzz
def test_fuzz_guard_file_event_never_raises(path: str):
    guard = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)
    ge = guard.evaluate_event(
        FileEvent(type=EventType.FILE_WRITE, path=path, agent_id="fuzz", pid=1)
    )
    assert ge.policy_decision.allowed in (True, False)


@settings(max_examples=fuzz_max_examples(40), deadline=None)
@given(st.lists(_short_text, min_size=0, max_size=12))
@pytest.mark.fuzz
def test_fuzz_verify_cli_batch_concat(lines: list[str]):
    """Multi-line / concatenated junk — still must not crash."""
    cmd = " ; ".join(lines) if lines else ""
    r = verify_cli(cmd)
    assert r.status in (CLISafetyStatus.SAFE, CLISafetyStatus.UNSAFE)
