"""Integration tests — eBPF observe → OPA decide → Z3 verify pipeline."""

import pytest
import time
from substrate_guard.guard import Guard, GuardSession, SessionReport
from substrate_guard.observe.events import (
    EventType, FileEvent, NetworkEvent, ProcessEvent,
)
from substrate_guard.observe.tracer import MockScenario


@pytest.fixture
def guard():
    """Guard with observe (mock) + policy (builtin) + verify (if z3 available)."""
    return Guard(
        observe=True,
        policy="nonexistent/",  # uses builtin rules
        verify=True,
        use_mock=True,
    )


class TestUnifiedPipeline:
    """Test the full eBPF → OPA → Z3 pipeline."""

    def test_safe_event_passes(self, guard):
        ge = guard.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/workspace/out.py",
                     agent_id="a1", pid=100)
        )
        assert ge.fully_safe
        assert ge.policy_decision.allowed

    def test_dangerous_event_blocked(self, guard):
        ge = guard.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd",
                     agent_id="a1", pid=100)
        )
        assert not ge.fully_safe
        assert ge.policy_decision.denied

    def test_network_exfil_blocked(self, guard):
        ge = guard.evaluate_event(
            NetworkEvent(type=EventType.NETWORK_CONNECT,
                        remote_ip="185.1.1.1", remote_port=4444,
                        agent_id="a1", pid=100)
        )
        assert ge.policy_decision.denied

    def test_safe_network_passes(self, guard):
        ge = guard.evaluate_event(
            NetworkEvent(type=EventType.NETWORK_CONNECT,
                        remote_ip="1.1.1.1", remote_port=443,
                        domain="github.com",
                        agent_id="a1", pid=100)
        )
        assert ge.policy_decision.allowed


class TestGuardSession:
    """Test monitoring sessions."""

    def test_session_basic(self, guard):
        with guard.monitor("agent-test") as session:
            # Inject safe event
            ge = session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py")
            )
            assert ge.fully_safe

        report = session.report()
        assert report.agent_id == "agent-test"
        assert report.events_observed >= 1
        assert report.policy_violations == 0

    def test_session_with_violations(self, guard):
        with guard.monitor("agent-bad") as session:
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd")
            )
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/ok.py")
            )
            session.inject_and_evaluate(
                NetworkEvent(type=EventType.NETWORK_CONNECT,
                            remote_port=31337, remote_ip="1.2.3.4")
            )

        report = session.report()
        assert report.events_observed >= 3
        assert report.policy_violations == 2
        assert report.policy_allowed >= 1

    def test_session_report_dict(self, guard):
        with guard.monitor("agent-x") as session:
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py")
            )

        report = session.report()
        d = report.to_dict()
        assert d["agent_id"] == "agent-x"
        assert "layers" in d
        assert "observe" in d["layers"]
        assert "policy" in d["layers"]
        assert "verify" in d["layers"]

    def test_session_summary_line(self, guard):
        with guard.monitor("agent-y") as session:
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/b.py")
            )

        report = session.report()
        line = report.summary_line()
        assert "SAFE" in line
        assert "agent-y" in line

    def test_session_violations_property(self, guard):
        with guard.monitor("agent-z") as session:
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/etc/shadow")
            )
            session.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/ok.py")
            )

        assert len(session.violations) == 1
        assert session.violations[0].event.path == "/etc/shadow"


class TestScenarioPipeline:
    """Run mock scenarios through the full pipeline."""

    def test_code_gen_scenario(self, guard):
        with guard.monitor("agent-code") as session:
            MockScenario.code_generation(guard._tracer, "agent-code")
            session.process_events()

        report = session.report()
        assert report.events_observed == 4
        # Code gen writes to /workspace — should be mostly safe
        assert report.policy_violations == 0

    def test_malicious_scenario(self, guard):
        with guard.monitor("agent-bad") as session:
            MockScenario.malicious_agent(guard._tracer, "agent-bad")
            session.process_events()

        report = session.report()
        assert report.events_observed == 4
        # /etc/passwd, /etc/shadow, port 4444, curl|sh — all blocked
        assert report.policy_violations >= 3

    def test_prompt_injection_scenario(self, guard):
        with guard.monitor("agent-injected") as session:
            MockScenario.prompt_injection(guard._tracer, "agent-injected")
            session.process_events()

        report = session.report()
        assert report.events_observed == 4
        # sudo, /etc/crontab, port 12345 — blocked
        assert report.policy_violations >= 2

    def test_safe_web_scenario(self, guard):
        with guard.monitor("agent-web") as session:
            MockScenario.safe_web_agent(guard._tracer, "agent-web")
            session.process_events()

        report = session.report()
        assert report.events_observed == 4
        assert report.policy_violations == 0

    def test_resource_abuse_scenario(self, guard):
        with guard.monitor("agent-greedy") as session:
            MockScenario.resource_abuse(guard._tracer, "agent-greedy")
            session.process_events()

        report = session.report()
        assert report.events_observed == 151


class TestGuardLayers:
    """Test individual layer enable/disable."""

    def test_observe_only(self):
        g = Guard(observe=True, policy=None, verify=False, use_mock=True)
        ge = g.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="a1")
        )
        # No policy → allowed by default
        assert ge.policy_decision.allowed

    def test_policy_only(self):
        g = Guard(observe=False, policy="nonexistent/", verify=False)
        ge = g.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="a1")
        )
        assert ge.policy_decision.denied

    def test_all_layers(self):
        g = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)
        assert g._tracer is not None
        assert g._policy is not None


class TestMultiAgent:
    """Test monitoring multiple agents simultaneously."""

    def test_two_agents_separate(self, guard):
        with guard.monitor("agent-A") as sA:
            sA.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py")
            )
            sA.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd")
            )

        with guard.monitor("agent-B") as sB:
            sB.inject_and_evaluate(
                FileEvent(type=EventType.FILE_WRITE, path="/workspace/b.py")
            )

        rA = sA.report()
        rB = sB.report()
        assert rA.policy_violations == 1
        assert rB.policy_violations == 0
