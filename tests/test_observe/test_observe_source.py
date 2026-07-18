"""Honest 3-way observe source label (plan 1.A: the inject orchestrator path).

The L1 activation via the inject path introduces a THIRD event source between
simulated "mock" and kernel "eBPF": "inject" -- REAL events fed by an orchestrator
via inject_event() (cross-platform, no kernel). These tests pin that injected real
events are labeled "inject", never conflated with simulated "mock" nor falsely
claimed as kernel "eBPF".
"""

from __future__ import annotations

import pytest

from substrate_guard.guard import Guard
from substrate_guard.observe.events import EventType, FileEvent
from substrate_guard.observe.tracer import AgentTracer


def test_tracer_source_three_way():
    assert AgentTracer(source="mock").source == "mock"
    assert AgentTracer(source="inject").source == "inject"
    assert AgentTracer(use_mock=True).source == "mock"
    # "auto" tries eBPF; on this host (Windows / no bcc / non-root) it falls back to mock.
    assert AgentTracer().source in ("mock", "ebpf")


def test_inject_is_not_labeled_mock_or_ebpf():
    t = AgentTracer(source="inject")
    assert t.source == "inject"
    assert t.source != "mock"      # real events must not read as simulated
    assert t.source != "ebpf"      # no kernel here
    # is_mock stays a coarse "not kernel" flag (True for inject AND mock)
    assert t.is_mock is True


def test_bad_source_rejected():
    with pytest.raises(ValueError, match="auto/mock/inject"):
        AgentTracer(source="bogus")


def test_report_observe_source_inject():
    """Guard(source='inject') -> the session report honestly shows observe.source
    'inject', and the injected event is REALLY evaluated (real, not simulated)."""
    guard = Guard(observe=True, policy="nonexistent/", verify=False, source="inject")
    agent = "orchestrator"
    with guard.monitor(agent) as session:
        session.inject_and_evaluate(
            FileEvent(type=EventType.FILE_WRITE, agent_id=agent, path="/etc/passwd")
        )
    report = session.report()
    d = report.to_dict()
    assert report.observe_source == "inject"
    assert d["layers"]["observe"]["source"] == "inject"
    assert report.events_observed == 1          # the injected event was really processed
    assert report.policy_violations == 1        # /etc/passwd write denied (real evaluation)


def test_report_observe_source_mock_for_use_mock():
    guard = Guard(observe=True, policy="nonexistent/", verify=False, use_mock=True)
    with guard.monitor("a") as session:
        session.inject_and_evaluate(
            FileEvent(type=EventType.FILE_WRITE, agent_id="a", path="/workspace/x")
        )
    assert session.report().to_dict()["layers"]["observe"]["source"] == "mock"


def test_audit_cron_path_stays_mock():
    """Regression: the cron audit path (use_mock=True) must still label observe 'mock'
    (batch replay of DB records) -- the 3-way change must not silently relabel it."""
    guard = Guard(observe=True, policy="nonexistent/", verify=False, use_mock=True)
    assert guard._tracer.source == "mock"
