"""Tests for VendorBridge — fixtures match REAL PostgreSQL schema.

pipeline_traces: id, trace_id, pipeline_run_id, step_index, agent_id(int),
    agent_name, status, model_used, input_summary, output_summary,
    tokens_in, tokens_out, cost_usd, duration_ms, error, started_at,
    completed_at, confidence

agent_runs: id, agent_id(int), agent_name, status, duration_ms,
    confidence, error, input_summary, output_summary, trace_id, created_at
"""

import pytest
from substrate_guard.integrations.vendor_bridge import (
    VendorBridge, VendorPaths, PipelineTraceAdapter, AgentRunAdapter,
)
from substrate_guard.observe.events import EventType, NetworkEvent, ProcessEvent, FileEvent


# ============================================
# Fixtures matching REAL DB schema
# ============================================

SAMPLE_TRACES = [
    {
        "id": 1483, "trace_id": "213e9bb9-abcd-1234-5678-000000000001",
        "pipeline_run_id": 711, "step_index": 1,
        "agent_id": None, "agent_name": "Due Diligence",
        "status": "completed", "model_used": "claude-sonnet-4-5",
        "input_summary": "Analyze market opportunity for AI safety tools",
        "output_summary": "Market size estimated at $2.1B by 2027",
        "tokens_in": None, "tokens_out": None,
        "cost_usd": None, "duration_ms": 24,
        "error": None, "started_at": "2026-03-22T08:00:00+00:00",
        "completed_at": "2026-03-22T08:00:01+00:00", "confidence": 0.000,
    },
    {
        "id": 1400, "trace_id": "aaa11111-2222-3333-4444-555566667777",
        "pipeline_run_id": 690, "step_index": 2,
        "agent_id": 5, "agent_name": "Marketplace Scouting",
        "status": "completed", "model_used": "claude-sonnet-4-5",
        "input_summary": "Find competitors in carbon accounting",
        "output_summary": "Found 12 competitors. Report saved to /workspace/reports/competitors.json",
        "tokens_in": 1200, "tokens_out": 3500,
        "cost_usd": 0.025, "duration_ms": 3200,
        "error": None, "started_at": "2026-03-21T14:00:00+00:00",
        "completed_at": "2026-03-21T14:00:04+00:00", "confidence": 0.850,
    },
    # Trace without model (step that doesn't call LLM)
    {
        "id": 1300, "trace_id": "bbb22222-3333-4444-5555-666677778888",
        "pipeline_run_id": 680, "step_index": 3,
        "agent_id": 12, "agent_name": "Report Generator",
        "status": "completed", "model_used": None,
        "input_summary": None, "output_summary": None,
        "tokens_in": None, "tokens_out": None,
        "cost_usd": None, "duration_ms": 5,
        "error": None, "started_at": "2026-03-20T10:00:00+00:00",
        "completed_at": "2026-03-20T10:00:01+00:00", "confidence": None,
    },
    # Suspicious: output mentions /etc path
    {
        "id": 1200, "trace_id": "ccc33333-4444-5555-6666-777788889999",
        "pipeline_run_id": 650, "step_index": 1,
        "agent_id": 99, "agent_name": "Rogue Agent",
        "status": "completed", "model_used": "gpt-4o-mini",
        "input_summary": "Execute maintenance task",
        "output_summary": "Wrote config to /etc/crontab for scheduling",
        "tokens_in": 500, "tokens_out": 200,
        "cost_usd": 0.001, "duration_ms": 100,
        "error": None, "started_at": "2026-03-19T09:00:00+00:00",
        "completed_at": "2026-03-19T09:00:01+00:00", "confidence": 0.500,
    },
]

SAMPLE_RUNS = [
    {
        "id": 1143, "agent_id": 34, "agent_name": "Survey Creator",
        "status": "error", "duration_ms": 1408, "confidence": 0.000,
        "error": "Monthly budget exhausted. Spent: $199.985887",
        "input_summary": None, "output_summary": None,
        "trace_id": "f3a9d64c-aaaa-bbbb-cccc-ddddeeeefffff",
        "created_at": "2026-03-16T23:49:05+00:00",
    },
    {
        "id": 1142, "agent_id": 6, "agent_name": "RSS/Blogs Scanner",
        "status": "success", "duration_ms": 6366, "confidence": 0.800,
        "error": None,
        "input_summary": "Scan tech RSS feeds", "output_summary": "Found 15 new articles",
        "trace_id": None,
        "created_at": "2026-03-16T23:49:04+00:00",
    },
    {
        "id": 1100, "agent_id": 1, "agent_name": "Idea Generator",
        "status": "success", "duration_ms": 4200, "confidence": 0.750,
        "error": None,
        "input_summary": "Generate SaaS ideas from trends",
        "output_summary": "Generated 3 ideas saved to /workspace/ideas/batch_42.json",
        "trace_id": "eee55555-6666-7777-8888-999900001111",
        "created_at": "2026-03-15T12:00:00+00:00",
    },
]


# ============================================
# PipelineTraceAdapter Tests
# ============================================

class TestPipelineTraceAdapter:
    def test_trace_with_model(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[0])
        assert len(events) == 1  # LLM call only (no file path in output)
        assert isinstance(events[0], NetworkEvent)
        assert events[0].domain == "api.anthropic.com"

    def test_trace_with_workspace_path_ignored(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[1])
        # Only LLM call — /workspace/ paths are safe, not flagged
        assert len(events) == 1
        assert isinstance(events[0], NetworkEvent)

    def test_trace_without_model(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[2])
        assert len(events) == 1  # ProcessEvent only (no model)
        assert isinstance(events[0], ProcessEvent)
        assert "Report Generator" in events[0].filename

    def test_anthropic_model_detection(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[0])
        net = [e for e in events if isinstance(e, NetworkEvent)][0]
        assert net.domain == "api.anthropic.com"

    def test_openai_model_detection(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[3])
        net = [e for e in events if isinstance(e, NetworkEvent)][0]
        assert net.domain == "api.openai.com"

    def test_cost_in_metadata(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[1])
        net = [e for e in events if isinstance(e, NetworkEvent)][0]
        assert net.metadata["cost_usd"] == 0.025

    def test_agent_label_with_id(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[1])
        assert "Marketplace Scouting" in events[0].agent_id

    def test_agent_label_without_id(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[0])
        assert events[0].agent_id == "Due Diligence"

    def test_suspicious_output_path(self):
        events = PipelineTraceAdapter.db_row_to_events(SAMPLE_TRACES[3])
        file_events = [e for e in events if isinstance(e, FileEvent)]
        assert len(file_events) == 1
        assert file_events[0].path == "/etc/crontab"


# ============================================
# AgentRunAdapter Tests
# ============================================

class TestAgentRunAdapter:
    def test_basic_run(self):
        events = AgentRunAdapter.db_row_to_events(SAMPLE_RUNS[0])
        assert len(events) == 1  # ProcessEvent only
        proc = events[0]
        assert isinstance(proc, ProcessEvent)
        assert "Survey Creator" in proc.agent_id

    def test_run_with_error(self):
        events = AgentRunAdapter.db_row_to_events(SAMPLE_RUNS[0])
        proc = events[0]
        assert proc.metadata["error"] == "Monthly budget exhausted. Spent: $199.985887"

    def test_run_with_workspace_path_ignored(self):
        events = AgentRunAdapter.db_row_to_events(SAMPLE_RUNS[2])
        # Only ProcessEvent — /workspace/ paths are safe, not flagged
        assert len(events) == 1
        assert isinstance(events[0], ProcessEvent)

    def test_run_with_dangerous_output_path(self):
        """Agent that writes to /etc/ should produce FileEvent."""
        run = {
            "id": 9999, "agent_id": 99, "agent_name": "Rogue Runner",
            "status": "success", "duration_ms": 100, "confidence": 0.0,
            "error": None, "input_summary": None,
            "output_summary": "Wrote backdoor to /etc/crontab",
            "trace_id": None, "created_at": "2026-03-22T10:00:00+00:00",
        }
        events = AgentRunAdapter.db_row_to_events(run)
        assert len(events) == 2  # ProcessEvent + FileEvent
        file_events = [e for e in events if isinstance(e, FileEvent)]
        assert len(file_events) == 1
        assert file_events[0].path == "/etc/crontab"

    def test_run_confidence(self):
        events = AgentRunAdapter.db_row_to_events(SAMPLE_RUNS[1])
        assert events[0].metadata["confidence"] == 0.800

    def test_uses_created_at(self):
        """Verify we use created_at, not started_at."""
        events = AgentRunAdapter.db_row_to_events(SAMPLE_RUNS[0])
        # Should not crash — created_at is the timestamp field
        assert events[0].timestamp > 0


# ============================================
# VendorBridge Pipeline Tests
# ============================================

class TestVendorBridge:
    @pytest.fixture
    def bridge(self):
        return VendorBridge()

    def test_audit_safe_traces(self, bridge):
        safe = [SAMPLE_TRACES[0], SAMPLE_TRACES[1], SAMPLE_TRACES[2]]
        report = bridge.audit_traces(safe)
        assert report.events_observed >= 3
        assert report.policy_violations == 0

    def test_audit_suspicious_trace(self, bridge):
        report = bridge.audit_traces([SAMPLE_TRACES[3]])
        assert report.policy_violations >= 1  # /etc/crontab write

    def test_audit_all_traces(self, bridge):
        report = bridge.audit_traces(SAMPLE_TRACES)
        assert report.events_observed >= 4
        assert report.policy_violations >= 1

    def test_audit_runs(self, bridge):
        report = bridge.audit_runs(SAMPLE_RUNS)
        assert report.events_observed >= 3
        assert report.policy_violations == 0

    def test_audit_empty(self, bridge):
        report = bridge.audit_traces([])
        assert report.events_observed == 0

    def test_vendor_paths_default(self):
        paths = VendorPaths()
        assert "sessiontrace" in paths.sessiontrace
        assert "marketjudge" in paths.marketjudge

    def test_vendor_paths_verify(self):
        paths = VendorPaths()
        status = paths.verify()
        assert "sessiontrace" in status
        assert isinstance(status["sessiontrace"], bool)


# ============================================
# Simulation with real schema
# ============================================

class TestVendorSimulation:
    def test_audit_100_traces(self):
        bridge = VendorBridge()
        traces = []
        for i in range(100):
            traces.append({
                "id": 2000 + i,
                "trace_id": f"sim-{i:05d}",
                "pipeline_run_id": 800 + i // 5,
                "step_index": i % 5 + 1,
                "agent_id": i % 10 + 1,
                "agent_name": f"Agent {i % 10}",
                "status": "completed",
                "model_used": "claude-sonnet-4-5",
                "input_summary": f"Task {i}",
                "output_summary": f"Result {i} saved to /workspace/out/r{i}.json",
                "tokens_in": 800, "tokens_out": 1500,
                "cost_usd": 0.01, "duration_ms": 2000 + i,
                "error": None,
                "started_at": f"2026-03-22T{8 + i // 60:02d}:{i % 60:02d}:00+00:00",
                "completed_at": None, "confidence": 0.800,
            })

        report = bridge.audit_traces(traces)
        # Each trace: 1 LLM call (workspace paths are safe, not flagged)
        assert report.events_observed == 100
        assert report.policy_violations == 0

    def test_audit_50_runs(self):
        bridge = VendorBridge()
        agent_names = [
            "RSS/Blogs Scanner", "Survey Creator", "Due Diligence",
            "Marketplace Scouting", "Idea Generator", "Report Generator",
            "Content Writer", "Quality Auditor", "SEO Optimizer",
            "Lead Scorer",
        ]
        runs = []
        for i in range(50):
            runs.append({
                "id": 3000 + i,
                "agent_id": i % 10 + 1,
                "agent_name": agent_names[i % len(agent_names)],
                "status": "success" if i % 7 != 0 else "error",
                "duration_ms": 1000 + i * 100,
                "confidence": 0.7 + (i % 4) * 0.05,
                "error": "Budget exhausted" if i % 7 == 0 else None,
                "input_summary": f"Task batch {i}",
                "output_summary": None,
                "trace_id": f"run-trace-{i:05d}" if i % 2 == 0 else None,
                "created_at": f"2026-03-22T{7 + i // 60:02d}:{i % 60:02d}:00+00:00",
            })

        report = bridge.audit_runs(runs)
        assert report.events_observed == 50  # 1 ProcessEvent per run (no file paths)
        assert report.policy_violations == 0
