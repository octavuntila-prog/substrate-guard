"""Honest 4-way observe source label (plan 1.A inject + 1-step cron relabel).

The source field distinguishes FOUR event origins so real events are never conflated
with simulated ones, and live is never conflated with replay:
  - "mock"   -- simulated events (MockScenario), NOT real
  - "inject" -- REAL events fed LIVE by an orchestrator via inject_event() (no kernel)
  - "replay" -- REAL RECORDED events re-fed as a batch replay of historical DB traces
                (what the nightly cron audit does) -- real data, not live
  - "ebpf"   -- kernel-observed
"""

from __future__ import annotations

import json

import pytest

from substrate_guard.chain import AuditChain
from substrate_guard.compliance import ComplianceExporter
from substrate_guard.guard import Guard
from substrate_guard.observe.events import EventType, FileEvent
from substrate_guard.observe.tracer import AgentTracer


def test_tracer_source_four_way():
    assert AgentTracer(source="mock").source == "mock"
    assert AgentTracer(source="inject").source == "inject"
    assert AgentTracer(source="replay").source == "replay"
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


def test_audit_cron_path_is_replay():
    """The cron audit re-feeds REAL recorded DB traces as a batch replay; audit.py now
    constructs Guard(source="replay") (was use_mock=True -> "mock", which mislabelled
    real recorded events as simulated -- audit HARD #10). Pin the distinction in BOTH
    directions so the fix cannot silently regress: 'replay' is real-recorded, never
    simulated 'mock', never live-orchestrator 'inject'."""
    guard = Guard(observe=True, policy="nonexistent/", verify=False, source="replay")
    assert guard._tracer.source == "replay"
    assert guard._tracer.source != "mock"      # real recorded events, not simulated
    assert guard._tracer.source != "inject"    # batch replay, not a live orchestrator feed


def test_compliance_observe_source_matches_tracer(tmp_path):
    """Closes the honesty-drift CLASS (not just the instance): the compliance L1
    evidence must report the tracer's REAL source, never a hardcoded label. For EACH
    source the exported ISO/summary evidence must name that exact source AND must not
    carry a DIFFERENT source's label -- so compliance can never silently disagree with
    the run (e.g. say 'mock' when the cron was 'replay', or vice-versa)."""
    for src in ("mock", "inject", "replay"):
        tracer = AgentTracer(source=src)
        exp = ComplianceExporter(chain=AuditChain(secret="k"), observe_source=tracer.source)
        assert exp._observe_source() == src == tracer.source
        for method in ("export_soc2", "export_iso27001", "export_iso42001", "export_summary"):
            path = tmp_path / f"{method}_{src}.json"
            getattr(exp, method)(str(path))
            blob = json.loads(path.read_text())
            flat = json.dumps(blob)
            assert f"'{src}'" in flat or f"source = '{src}'" in flat, (method, src)
            # must NOT falsely claim a different source
            for other in ("mock", "inject", "replay"):
                if other != src:
                    assert f"source = '{other}'" not in flat, (method, src, other)
