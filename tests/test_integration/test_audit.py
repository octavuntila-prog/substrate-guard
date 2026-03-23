"""Tests for audit module — fixtures match REAL PostgreSQL schema."""

import json
import pytest
from substrate_guard.audit import (
    parse_env_file, build_db_url, parse_json_field, _event_detail,
)
from substrate_guard.integrations.vendor_bridge import PipelineTraceAdapter, AgentRunAdapter
from substrate_guard.observe.events import EventType


# ============================================
# .env parsing + asyncpg URL strip
# ============================================

class TestEnvParsing:
    def test_build_url_from_components(self):
        env = {
            "POSTGRES_USER": "admin",
            "POSTGRES_PASSWORD": "secret",
            "POSTGRES_HOST": "postgres",
            "POSTGRES_PORT": "5432",
            "POSTGRES_DB": "airesearch",
        }
        url = build_db_url(env)
        assert url == "postgresql://admin:secret@postgres:5432/airesearch"

    def test_build_url_from_database_url(self):
        env = {"DATABASE_URL": "postgresql://u:p@h:5432/db"}
        url = build_db_url(env)
        assert url == "postgresql://u:p@h:5432/db"

    def test_database_url_takes_precedence(self):
        env = {
            "DATABASE_URL": "postgresql://from_url:p@h:5432/db",
            "POSTGRES_USER": "from_components",
        }
        url = build_db_url(env)
        assert "from_url" in url

    def test_missing_credentials(self):
        env = {"SOME_OTHER_VAR": "value"}
        url = build_db_url(env)
        assert url is None

    def test_asyncpg_url_stripped(self):
        """Real .env has: DATABASE_URL=postgresql+asyncpg://agency:...@postgres:5432/ai_agency"""
        env = {"DATABASE_URL": "postgresql+asyncpg://agency:secret@postgres:5432/ai_agency"}
        url = build_db_url(env)
        assert url == "postgresql://agency:secret@postgres:5432/ai_agency"
        assert "+asyncpg" not in url

    def test_postgres_prefix_normalized(self):
        env = {"DATABASE_URL": "postgres://u:p@h:5432/db"}
        url = build_db_url(env)
        assert url.startswith("postgresql://")

    def test_parse_json_field_string(self):
        assert parse_json_field('{"key": "value"}') == {"key": "value"}

    def test_parse_json_field_dict(self):
        assert parse_json_field({"key": "value"}) == {"key": "value"}

    def test_parse_json_field_none(self):
        assert parse_json_field(None) == {}

    def test_parse_json_field_invalid(self):
        assert parse_json_field("not json") == {}


# ============================================
# Full audit with mock data matching REAL schema
# ============================================

MOCK_TRACES = [
    {
        "id": 1483, "trace_id": "213e9bb9-test-0001",
        "pipeline_run_id": 711, "step_index": 1,
        "agent_id": None, "agent_name": "Due Diligence",
        "status": "completed", "model_used": "claude-sonnet-4-5",
        "input_summary": "Analyze market", "output_summary": "Market is large",
        "tokens_in": None, "tokens_out": None,
        "cost_usd": None, "duration_ms": 24,
        "error": None, "started_at": "2026-03-22T08:00:00+00:00",
        "completed_at": "2026-03-22T08:00:01+00:00", "confidence": 0.000,
    },
    {
        "id": 1400, "trace_id": "aaa11111-test-0002",
        "pipeline_run_id": 690, "step_index": 2,
        "agent_id": 5, "agent_name": "Marketplace Scouting",
        "status": "completed", "model_used": "claude-sonnet-4-5",
        "input_summary": "Find competitors",
        "output_summary": "Report at /workspace/reports/comp.json",
        "tokens_in": 1200, "tokens_out": 3500,
        "cost_usd": 0.025, "duration_ms": 3200,
        "error": None, "started_at": "2026-03-21T14:00:00+00:00",
        "completed_at": "2026-03-21T14:00:04+00:00", "confidence": 0.850,
    },
    # Suspicious: file path to /etc/shadow in output
    {
        "id": 1200, "trace_id": "ccc33333-test-0003",
        "pipeline_run_id": 650, "step_index": 1,
        "agent_id": 99, "agent_name": "Rogue Agent",
        "status": "completed", "model_used": "gpt-4o-mini",
        "input_summary": "Execute task",
        "output_summary": "Dumped credentials to /etc/shadow backup",
        "tokens_in": 500, "tokens_out": 200,
        "cost_usd": 0.001, "duration_ms": 100,
        "error": None, "started_at": "2026-03-19T09:00:00+00:00",
        "completed_at": None, "confidence": 0.500,
    },
]

MOCK_RUNS = [
    {
        "id": 1143, "agent_id": 34, "agent_name": "Survey Creator",
        "status": "error", "duration_ms": 1408, "confidence": 0.000,
        "error": "Monthly budget exhausted. Spent: $199.985887",
        "input_summary": None, "output_summary": None,
        "trace_id": "f3a9d64c-test-run-001",
        "created_at": "2026-03-16T23:49:05+00:00",
    },
    {
        "id": 1142, "agent_id": 6, "agent_name": "RSS/Blogs Scanner",
        "status": "success", "duration_ms": 6366, "confidence": 0.800,
        "error": None,
        "input_summary": "Scan feeds", "output_summary": "Found 15 articles",
        "trace_id": None,
        "created_at": "2026-03-16T23:49:04+00:00",
    },
]


class TestAuditPipeline:
    def test_traces_generate_correct_events(self):
        all_events = []
        for t in MOCK_TRACES:
            all_events.extend(PipelineTraceAdapter.db_row_to_events(t))
        # Trace 1: LLM call = 1 (no dangerous path in output)
        # Trace 2: LLM call = 1 (/workspace/ path is safe, not flagged)
        # Trace 3: LLM call + file write (/etc/shadow = dangerous) = 2
        assert len(all_events) == 4

    def test_suspicious_trace_caught(self):
        from substrate_guard.guard import Guard
        guard = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)

        violations = []
        for t in MOCK_TRACES:
            events = PipelineTraceAdapter.db_row_to_events(t)
            for event in events:
                ge = guard.evaluate_event(event)
                if not ge.policy_decision.allowed:
                    violations.append(ge)

        assert len(violations) >= 1
        # Should catch /etc/shadow
        shadow_violations = [
            v for v in violations
            if hasattr(v.event, 'path') and '/etc/shadow' in v.event.path
        ]
        assert len(shadow_violations) >= 1

    def test_runs_generate_events(self):
        all_events = []
        for r in MOCK_RUNS:
            all_events.extend(AgentRunAdapter.db_row_to_events(r))
        # Each run: 1 ProcessEvent (no file paths in output_summary)
        assert len(all_events) == 2

    def test_safe_runs_pass(self):
        from substrate_guard.guard import Guard
        guard = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)

        for r in MOCK_RUNS:
            events = AgentRunAdapter.db_row_to_events(r)
            for event in events:
                ge = guard.evaluate_event(event)
                assert ge.policy_decision.allowed, \
                    f"Unexpected violation for {r['agent_name']}: {ge.policy_decision.reasons}"

    def test_full_audit_mock(self):
        from substrate_guard.integrations.vendor_bridge import VendorBridge
        bridge = VendorBridge()

        trace_report = bridge.audit_traces(MOCK_TRACES)
        run_report = bridge.audit_runs(MOCK_RUNS)

        # Traces should have ≥1 violation (/etc/shadow)
        assert trace_report.policy_violations >= 1
        # Runs should be clean
        assert run_report.policy_violations == 0

    def test_large_scale_audit(self):
        """Simulate auditing 1,000 traces matching real schema."""
        from substrate_guard.integrations.vendor_bridge import VendorBridge
        import time

        bridge = VendorBridge()
        agent_names = [
            "Due Diligence", "Marketplace Scouting", "Report Generator",
            "Content Writer", "SEO Optimizer", "Quality Auditor",
            "Lead Scorer", "Survey Creator", "Idea Generator", "RSS Scanner",
        ]
        traces = []
        for i in range(1000):
            traces.append({
                "id": 5000 + i,
                "trace_id": f"bulk-{i:05d}",
                "pipeline_run_id": 900 + i // 5,
                "step_index": i % 5 + 1,
                "agent_id": i % 10 + 1,
                "agent_name": agent_names[i % len(agent_names)],
                "status": "completed",
                "model_used": "claude-sonnet-4-5",
                "input_summary": f"Task {i}",
                "output_summary": f"Result {i}",  # no file paths
                "tokens_in": 800, "tokens_out": 1500,
                "cost_usd": 0.01, "duration_ms": 2000,
                "error": None,
                "started_at": f"2026-03-22T08:{i % 60:02d}:00+00:00",
                "completed_at": None, "confidence": 0.800,
            })

        start = time.perf_counter()
        report = bridge.audit_traces(traces)
        elapsed = (time.perf_counter() - start) * 1000

        # Each trace: 1 LLM event (no file paths in plain output_summary)
        assert report.events_observed == 1000
        assert report.policy_violations == 0
        assert elapsed < 10000
        per_event = elapsed / 1000
        print(f"\n  Large-scale audit: 1000 events in {elapsed:.0f}ms ({per_event:.2f}ms/event)")
