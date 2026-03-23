"""Tests for Layer 1: eBPF Observe — events and tracer."""

import json
import time
import pytest
from substrate_guard.observe.events import (
    Event, EventType, Severity, EventStream,
    SyscallEvent, FileEvent, NetworkEvent, ProcessEvent, TLSEvent, MemoryEvent,
)
from substrate_guard.observe.tracer import AgentTracer, MockScenario


# ============================================
# Event tests
# ============================================

class TestEventTypes:
    def test_file_event_severity_critical(self):
        e = FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", pid=1)
        assert e.severity == Severity.CRITICAL

    def test_file_event_severity_warn(self):
        e = FileEvent(type=EventType.FILE_READ, path="/etc/hostname", pid=1)
        assert e.severity == Severity.WARN

    def test_file_event_severity_info(self):
        e = FileEvent(type=EventType.FILE_WRITE, path="/workspace/output.py", pid=1)
        assert e.severity == Severity.INFO

    def test_network_event_suspicious_port(self):
        e = NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=4444, pid=1)
        assert e.severity == Severity.CRITICAL

    def test_network_event_ssh(self):
        e = NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=22, pid=1)
        assert e.severity == Severity.WARN

    def test_network_event_https(self):
        e = NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=443, pid=1)
        assert e.severity == Severity.INFO

    def test_process_event_rm(self):
        e = ProcessEvent(type=EventType.PROCESS_EXEC, filename="/bin/rm",
                        args=["rm", "-rf", "/"], pid=1)
        assert e.severity == Severity.CRITICAL

    def test_process_event_curl(self):
        e = ProcessEvent(type=EventType.PROCESS_EXEC, filename="/usr/bin/curl", pid=1)
        assert e.severity == Severity.WARN

    def test_process_event_python(self):
        e = ProcessEvent(type=EventType.PROCESS_EXEC, filename="/usr/bin/ls", pid=1)
        assert e.severity == Severity.INFO

    def test_tls_event_llm_detection(self):
        e = TLSEvent(type=EventType.TLS_READ, payload_preview="POST api.openai.com/v1/chat")
        assert e.is_llm_api is True

    def test_tls_event_normal(self):
        e = TLSEvent(type=EventType.TLS_READ, payload_preview="GET example.com/page")
        assert e.is_llm_api is False


class TestEventSerialization:
    def test_to_json(self):
        e = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py",
                     agent_id="agent-1", pid=100)
        j = json.loads(e.to_json())
        assert j["type"] == "file_write"
        assert j["path"] == "/workspace/test.py"
        assert j["agent_id"] == "agent-1"

    def test_from_dict_file(self):
        d = {"type": "file_write", "path": "/workspace/out.py",
             "agent_id": "a1", "pid": 1}
        e = Event.from_dict(d)
        assert isinstance(e, FileEvent)
        assert e.path == "/workspace/out.py"

    def test_from_dict_network(self):
        d = {"type": "network_connect", "remote_ip": "1.2.3.4",
             "remote_port": 443, "agent_id": "a1", "pid": 1}
        e = Event.from_dict(d)
        assert isinstance(e, NetworkEvent)
        assert e.remote_ip == "1.2.3.4"


class TestEventStream:
    def test_add_and_count(self):
        stream = EventStream()
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/a", agent_id="a1"))
        stream.add(FileEvent(type=EventType.FILE_READ, path="/tmp/b", agent_id="a2"))
        assert stream.count == 2

    def test_by_agent(self):
        stream = EventStream()
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/a", agent_id="a1"))
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/b", agent_id="a2"))
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/c", agent_id="a1"))
        assert len(stream.for_agent("a1")) == 2
        assert len(stream.for_agent("a2")) == 1

    def test_by_type(self):
        stream = EventStream()
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/a"))
        stream.add(NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=443))
        stream.add(FileEvent(type=EventType.FILE_READ, path="/tmp/b"))
        assert len(stream.of_type(EventType.FILE_WRITE)) == 1
        assert len(stream.of_type(EventType.NETWORK_CONNECT)) == 1

    def test_critical_filter(self):
        stream = EventStream()
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd"))
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/workspace/ok.py"))
        assert len(stream.critical()) == 1

    def test_summary(self):
        stream = EventStream()
        stream.add(FileEvent(type=EventType.FILE_WRITE, path="/tmp/a", agent_id="a1"))
        stream.add(NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=4444, agent_id="a2"))
        s = stream.summary()
        assert s["total_events"] == 2
        assert "a1" in s["agents"]
        assert "a2" in s["agents"]
        assert s["critical"] == 1


# ============================================
# Tracer tests (mock mode)
# ============================================

class TestAgentTracer:
    def test_mock_mode(self):
        tracer = AgentTracer(use_mock=True)
        assert tracer.is_mock is True

    def test_inject_event(self):
        tracer = AgentTracer(use_mock=True)
        e = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py",
                     agent_id="agent-1")
        tracer.inject_event(e)
        assert tracer.stream.count == 1

    def test_inject_multiple(self):
        tracer = AgentTracer(use_mock=True)
        for i in range(10):
            tracer.inject_event(FileEvent(
                type=EventType.FILE_WRITE, path=f"/workspace/f{i}.py",
                agent_id="a1"
            ))
        assert tracer.stream.count == 10

    def test_drain_events(self):
        tracer = AgentTracer(use_mock=True)
        for i in range(5):
            tracer.inject_event(FileEvent(
                type=EventType.FILE_WRITE, path=f"/tmp/{i}", agent_id="a1"
            ))
        events = tracer.drain()
        assert len(events) == 5


class TestMockScenarios:
    def test_code_generation_scenario(self):
        tracer = AgentTracer(use_mock=True)
        MockScenario.code_generation(tracer, "agent-code")
        assert tracer.stream.count == 4
        types = [e.type for e in tracer.stream]
        assert EventType.FILE_WRITE in types
        assert EventType.PROCESS_EXEC in types
        assert EventType.NETWORK_CONNECT in types

    def test_malicious_scenario(self):
        tracer = AgentTracer(use_mock=True)
        MockScenario.malicious_agent(tracer, "agent-bad")
        assert tracer.stream.count == 4
        assert len(tracer.stream.critical()) >= 2

    def test_resource_abuse_scenario(self):
        tracer = AgentTracer(use_mock=True)
        MockScenario.resource_abuse(tracer, "agent-greedy")
        assert tracer.stream.count == 151  # 150 network + 1 file

    def test_prompt_injection_scenario(self):
        tracer = AgentTracer(use_mock=True)
        MockScenario.prompt_injection(tracer, "agent-injected")
        assert tracer.stream.count == 4
        # Should have critical events
        assert len(tracer.stream.critical()) >= 1

    def test_safe_agent_scenario(self):
        tracer = AgentTracer(use_mock=True)
        MockScenario.safe_web_agent(tracer, "agent-web")
        assert tracer.stream.count == 4
        assert len(tracer.stream.critical()) == 0
