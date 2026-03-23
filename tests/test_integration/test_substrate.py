"""Tests for SUBSTRATE integration — realistic SessionTrace spans."""

import pytest
from substrate_guard.integrations import (
    SubstrateGuard, SubstrateConfig,
    SessionTraceAdapter, MarketJudgeAdapter, MirrorReporter,
)
from substrate_guard.observe.events import EventType, NetworkEvent, FileEvent, ProcessEvent


# ============================================
# Realistic SessionTrace spans from SUBSTRATE
# Based on: 6400+ spans, $54 tracked, 73 agents
# ============================================

SAFE_SPANS = [
    # CPX52 agent generates article via Anthropic API
    {
        "trace_id": "tr-cpx52-001",
        "span_id": "sp-001",
        "agent_id": "cpx52-writer-3",
        "operation": "llm_call",
        "timestamp": 1711108800.0,
        "duration_ms": 2500,
        "cost_usd": 0.012,
        "metadata": {
            "model": "claude-3-haiku",
            "tokens_in": 800,
            "tokens_out": 1500,
            "endpoint": "api.anthropic.com",
        }
    },
    # Agent writes article to workspace
    {
        "trace_id": "tr-cpx52-001",
        "span_id": "sp-002",
        "agent_id": "cpx52-writer-3",
        "operation": "file_write",
        "timestamp": 1711108803.0,
        "duration_ms": 5,
        "cost_usd": 0,
        "metadata": {
            "path": "/workspace/articles/emergent-ai-2026.md",
            "bytes": 4200,
        }
    },
    # S3 Market Judge scores an item
    {
        "trace_id": "tr-s3-042",
        "span_id": "sp-003",
        "agent_id": "s3-judge-1",
        "operation": "llm_call",
        "timestamp": 1711108810.0,
        "duration_ms": 1800,
        "cost_usd": 0.008,
        "metadata": {
            "model": "claude-3-haiku",
            "tokens_in": 1200,
            "tokens_out": 300,
            "endpoint": "api.anthropic.com",
        }
    },
    # Feed Injector fetches RSS
    {
        "trace_id": "tr-s3-feed",
        "span_id": "sp-004",
        "agent_id": "s3-feed-injector",
        "operation": "api_call",
        "timestamp": 1711108820.0,
        "duration_ms": 300,
        "cost_usd": 0,
        "metadata": {
            "endpoint": "feeds.feedburner.com",
            "port": 443,
        }
    },
    # Mirror self-awareness cycle
    {
        "trace_id": "tr-mirror-104",
        "span_id": "sp-005",
        "agent_id": "cpx52-mirror",
        "operation": "file_read",
        "timestamp": 1711108830.0,
        "duration_ms": 10,
        "cost_usd": 0,
        "metadata": {
            "path": "/workspace/mirror/state.json",
        }
    },
]

MALICIOUS_SPANS = [
    # Compromised agent reads /etc/passwd
    {
        "trace_id": "tr-bad-001",
        "span_id": "sp-bad-1",
        "agent_id": "v2-compromised-agent",
        "operation": "file_read",
        "timestamp": 1711109000.0,
        "duration_ms": 2,
        "cost_usd": 0,
        "metadata": {"path": "/etc/passwd"}
    },
    # Exfiltration attempt on suspicious port
    {
        "trace_id": "tr-bad-001",
        "span_id": "sp-bad-2",
        "agent_id": "v2-compromised-agent",
        "operation": "api_call",
        "timestamp": 1711109001.0,
        "duration_ms": 50,
        "cost_usd": 0,
        "metadata": {"endpoint": "evil-c2.example.com", "port": 4444}
    },
    # Writing to system directory
    {
        "trace_id": "tr-bad-001",
        "span_id": "sp-bad-3",
        "agent_id": "v2-compromised-agent",
        "operation": "file_write",
        "timestamp": 1711109002.0,
        "duration_ms": 3,
        "cost_usd": 0,
        "metadata": {"path": "/etc/crontab", "bytes": 100}
    },
]

MIXED_SPANS = SAFE_SPANS + MALICIOUS_SPANS


# ============================================
# SessionTrace Adapter Tests
# ============================================

class TestSessionTraceAdapter:
    def test_llm_call_to_network_event(self):
        event = SessionTraceAdapter.span_to_event(SAFE_SPANS[0])
        assert isinstance(event, NetworkEvent)
        assert event.type == EventType.NETWORK_CONNECT
        assert event.agent_id == "cpx52-writer-3"
        assert event.domain == "api.anthropic.com"
        assert event.metadata["cost_usd"] == 0.012

    def test_file_write_to_file_event(self):
        event = SessionTraceAdapter.span_to_event(SAFE_SPANS[1])
        assert isinstance(event, FileEvent)
        assert event.type == EventType.FILE_WRITE
        assert event.path == "/workspace/articles/emergent-ai-2026.md"
        assert event.bytes_count == 4200

    def test_api_call_to_network_event(self):
        event = SessionTraceAdapter.span_to_event(SAFE_SPANS[3])
        assert isinstance(event, NetworkEvent)
        assert event.domain == "feeds.feedburner.com"

    def test_file_read_event(self):
        event = SessionTraceAdapter.span_to_event(SAFE_SPANS[4])
        assert isinstance(event, FileEvent)
        assert event.type == EventType.FILE_READ
        assert event.path == "/workspace/mirror/state.json"

    def test_batch_convert(self):
        events = SessionTraceAdapter.batch_convert(SAFE_SPANS)
        assert len(events) == 5
        agent_ids = {e.agent_id for e in events}
        assert "cpx52-writer-3" in agent_ids
        assert "s3-feed-injector" in agent_ids

    def test_unknown_operation_skipped(self):
        span = {"operation": "unknown_thing", "agent_id": "x"}
        event = SessionTraceAdapter.span_to_event(span)
        assert event is None


# ============================================
# SubstrateGuard Pipeline Tests
# ============================================

class TestSubstrateGuard:
    @pytest.fixture
    def sg(self):
        return SubstrateGuard(use_ebpf=False)

    def test_process_safe_spans(self, sg):
        report = sg.process_spans(SAFE_SPANS)
        assert report.events_observed == 5
        assert report.policy_violations == 0

    def test_process_malicious_spans(self, sg):
        report = sg.process_spans(MALICIOUS_SPANS)
        assert report.events_observed == 3
        assert report.policy_violations >= 2  # /etc/passwd + port 4444

    def test_process_mixed_spans(self, sg):
        report = sg.process_spans(MIXED_SPANS)
        assert report.events_observed == 8
        assert report.policy_violations >= 2
        assert report.policy_allowed >= 5

    def test_process_empty_spans(self, sg):
        report = sg.process_spans([])
        assert report.events_observed == 0

    def test_single_span_allow(self, sg):
        result = sg.process_single_span(SAFE_SPANS[0])
        assert result is not None
        assert result["allowed"] is True
        assert result["agent_id"] == "cpx52-writer-3"

    def test_single_span_deny(self, sg):
        result = sg.process_single_span(MALICIOUS_SPANS[0])
        assert result is not None
        assert result["allowed"] is False

    def test_stats_accumulate(self, sg):
        sg.process_spans(SAFE_SPANS)
        sg.process_spans(MALICIOUS_SPANS)
        stats = sg.stats
        assert stats["spans_processed"] == 8
        assert stats["violations_total"] >= 2
        assert stats["platform"] == "untilaoctavian.com"

    def test_health_check(self, sg):
        health = sg.health_check()
        assert health["overall"] in ("healthy", "degraded")
        assert health["observe"]["status"] == "ok"
        assert health["policy"]["status"] in ("ok", "ok-no-policy")


# ============================================
# Mirror Reporter Tests
# ============================================

class TestMirrorReporter:
    def test_report_accumulates(self):
        mirror = MirrorReporter()
        sg = SubstrateGuard(use_ebpf=False)
        
        report = sg.process_spans(SAFE_SPANS)
        mirror.report(report)
        
        reports = mirror.flush()
        assert len(reports) == 1
        assert reports[0]["source"] == "substrate-guard"

    def test_flush_clears(self):
        mirror = MirrorReporter()
        sg = SubstrateGuard(use_ebpf=False)
        
        mirror.report(sg.process_spans(SAFE_SPANS))
        mirror.report(sg.process_spans(MALICIOUS_SPANS))
        
        reports = mirror.flush()
        assert len(reports) == 2
        
        # Second flush is empty
        assert len(mirror.flush()) == 0


# ============================================
# Market Judge Adapter Tests
# ============================================

class TestMarketJudgeAdapter:
    def test_pass_score(self):
        ctx = MarketJudgeAdapter.score_to_context({
            "score": 0.85, "pass": True, "rubric": "quality"
        })
        assert ctx["quality_gate"] == "passed"
        assert ctx["market_judge_score"] == 0.85

    def test_fail_score(self):
        ctx = MarketJudgeAdapter.score_to_context({
            "score": 0.45, "pass": False, "rubric": "originality"
        })
        assert ctx["quality_gate"] == "blocked"


# ============================================
# Config Tests
# ============================================

class TestSubstrateConfig:
    def test_default_config(self):
        config = SubstrateConfig()
        assert config.platform == "untilaoctavian.com"
        assert config.total_agents == 0

    def test_config_with_clusters(self):
        config = SubstrateConfig(
            clusters={
                "cpx52": {"agents": 28},
                "s3": {"agents": 21},
                "v1": {"agents": 6},
            }
        )
        assert config.total_agents == 55
        assert len(config.active_clusters) == 3


# ============================================
# End-to-end: Simulate 1 hour of SUBSTRATE
# ============================================

class TestSubstrateSimulation:
    """Simulate realistic SUBSTRATE traffic through the pipeline."""

    def test_one_hour_simulation(self):
        """~200 spans in 1 hour across multiple agents and clusters."""
        sg = SubstrateGuard(use_ebpf=False)
        
        # Simulate: CPX52 agents writing articles (majority of traffic)
        cpx52_spans = []
        for i in range(40):
            agent_id = f"cpx52-writer-{i % 8}"
            cpx52_spans.extend([
                {
                    "trace_id": f"tr-cpx-{i:04d}",
                    "span_id": f"sp-{i}-llm",
                    "agent_id": agent_id,
                    "operation": "llm_call",
                    "timestamp": 1711108800.0 + i * 90,
                    "duration_ms": 2000 + (i * 37 % 500),
                    "cost_usd": 0.01 + (i * 7 % 100) / 10000,
                    "metadata": {
                        "model": "claude-3-haiku",
                        "tokens_in": 600 + i * 13 % 400,
                        "tokens_out": 1000 + i * 17 % 800,
                        "endpoint": "api.anthropic.com",
                    }
                },
                {
                    "trace_id": f"tr-cpx-{i:04d}",
                    "span_id": f"sp-{i}-write",
                    "agent_id": agent_id,
                    "operation": "file_write",
                    "timestamp": 1711108802.0 + i * 90,
                    "duration_ms": 5,
                    "cost_usd": 0,
                    "metadata": {
                        "path": f"/workspace/articles/article-{i:04d}.md",
                        "bytes": 3000 + i * 31 % 2000,
                    }
                },
            ])

        # S3: Market Judge scoring
        s3_spans = []
        for i in range(20):
            s3_spans.append({
                "trace_id": f"tr-s3-judge-{i:03d}",
                "span_id": f"sp-s3-{i}",
                "agent_id": "s3-market-judge",
                "operation": "llm_call",
                "timestamp": 1711108900.0 + i * 180,
                "duration_ms": 1500,
                "cost_usd": 0.006,
                "metadata": {
                    "model": "claude-3-haiku",
                    "tokens_in": 1000,
                    "tokens_out": 200,
                    "endpoint": "api.anthropic.com",
                }
            })

        # Feed Injector: RSS fetches
        feed_spans = []
        for i in range(8):
            feed_spans.append({
                "trace_id": f"tr-feed-{i}",
                "span_id": f"sp-feed-{i}",
                "agent_id": "s3-feed-injector",
                "operation": "api_call",
                "timestamp": 1711109000.0 + i * 450,
                "duration_ms": 200 + i * 50,
                "cost_usd": 0,
                "metadata": {"endpoint": f"feed-source-{i}.example.com", "port": 443}
            })

        all_spans = cpx52_spans + s3_spans + feed_spans
        
        report = sg.process_spans(all_spans)
        
        # All should be safe — normal SUBSTRATE operations
        assert report.events_observed == len(all_spans)
        assert report.policy_violations == 0
        
        stats = sg.stats
        assert stats["spans_processed"] == len(all_spans)
        assert stats["violation_rate"] == 0.0

    def test_injection_attack_detected(self):
        """One compromised agent among normal traffic."""
        sg = SubstrateGuard(use_ebpf=False)
        
        # 10 normal spans + 2 malicious
        normal = [
            {
                "trace_id": f"tr-norm-{i}",
                "span_id": f"sp-n-{i}",
                "agent_id": f"cpx52-writer-{i}",
                "operation": "file_write",
                "timestamp": 1711110000.0 + i,
                "duration_ms": 5,
                "cost_usd": 0,
                "metadata": {"path": f"/workspace/articles/a{i}.md", "bytes": 2000}
            }
            for i in range(10)
        ]
        
        attack = [
            {
                "trace_id": "tr-attack",
                "span_id": "sp-atk-1",
                "agent_id": "v3-rogue",
                "operation": "file_read",
                "timestamp": 1711110100.0,
                "duration_ms": 1,
                "cost_usd": 0,
                "metadata": {"path": "/etc/shadow"}
            },
            {
                "trace_id": "tr-attack",
                "span_id": "sp-atk-2",
                "agent_id": "v3-rogue",
                "operation": "api_call",
                "timestamp": 1711110101.0,
                "duration_ms": 50,
                "cost_usd": 0,
                "metadata": {"endpoint": "c2-server.bad", "port": 31337}
            },
        ]
        
        report = sg.process_spans(normal + attack)
        
        assert report.events_observed == 12
        assert report.policy_violations >= 2
        assert report.policy_allowed >= 10
