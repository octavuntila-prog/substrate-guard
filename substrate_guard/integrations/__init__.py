"""SUBSTRATE Integration — Connect substrate-guard to the live ecosystem.

Bridges the 3-layer verification stack to existing SUBSTRATE services:
- SessionTrace → feeds events to Layer 1 (observe)
- Market Judge  → feeds decisions to Layer 2 (policy)
- hypy          → feeds type violations to Layer 3 (verify)
- Mirror        → receives guard reports for self-awareness loop

Usage:
    from substrate_guard.integrations.substrate import SubstrateGuard
    
    sg = SubstrateGuard(config_path="/opt/substrate-guard/config/substrate.json")
    sg.start()
    
    # Now monitoring all 73 agents through the pipeline
    # Events flow: SessionTrace → Guard → Mirror
"""

from __future__ import annotations

import json
import logging
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..guard import Guard, SessionReport
from ..runtime_env import resolve_verify_process_cli
from ..observe.events import (
    Event, EventType, Severity,
    FileEvent, NetworkEvent, ProcessEvent, SyscallEvent,
)
from ..observe.tracer import AgentTracer
from ..policy.engine import PolicyEngine

logger = logging.getLogger("substrate_guard.substrate")


@dataclass
class SubstrateConfig:
    """Configuration for SUBSTRATE integration."""
    platform: str = "untilaoctavian.com"
    clusters: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    observe: dict = field(default_factory=dict)
    verify_process_cli: bool = False

    @classmethod
    def from_file(cls, path: str | Path) -> "SubstrateConfig":
        data = json.loads(Path(path).read_text())
        return cls(
            platform=data.get("platform", "untilaoctavian.com"),
            clusters=data.get("clusters", {}),
            policy=data.get("policy", {}),
            observe=data.get("observe", {}),
            verify_process_cli=bool(data.get("verify_process_cli", False)),
        )
    
    @property
    def total_agents(self) -> int:
        return sum(c.get("agents", 0) for c in self.clusters.values())
    
    @property
    def active_clusters(self) -> list[str]:
        return [name for name, c in self.clusters.items() if c.get("agents", 0) > 0]


class SessionTraceAdapter:
    """Adapter: SessionTrace spans → substrate-guard events.
    
    SessionTrace is SUBSTRATE's observability layer (6400+ spans, $54 tracked).
    This adapter converts SessionTrace span data into Guard events so they
    flow through the OPA policy engine and Z3 verification.
    
    Expected span format from SessionTrace:
    {
        "trace_id": "...",
        "span_id": "...",
        "agent_id": "agent-7",
        "operation": "llm_call" | "tool_use" | "file_write" | "api_call",
        "timestamp": 1711108800.0,
        "duration_ms": 150,
        "cost_usd": 0.003,
        "metadata": {
            "model": "claude-3-haiku",
            "tokens_in": 500,
            "tokens_out": 200,
            "endpoint": "api.anthropic.com",
            ...
        }
    }
    """

    @staticmethod
    def span_to_event(span: dict) -> Optional[Event]:
        """Convert a SessionTrace span to a Guard event."""
        operation = span.get("operation", "")
        agent_id = span.get("agent_id", "unknown")
        meta = span.get("metadata", {})
        ts = span.get("timestamp", time.time())

        if operation == "llm_call":
            endpoint = meta.get("endpoint", "")
            return NetworkEvent(
                type=EventType.NETWORK_CONNECT,
                agent_id=agent_id,
                timestamp=ts,
                remote_ip="",
                remote_port=443,
                domain=endpoint,
                metadata={
                    "model": meta.get("model", ""),
                    "tokens_in": meta.get("tokens_in", 0),
                    "tokens_out": meta.get("tokens_out", 0),
                    "cost_usd": span.get("cost_usd", 0),
                    "trace_id": span.get("trace_id", ""),
                },
            )
        
        elif operation == "tool_use":
            tool_name = meta.get("tool_name", "")
            return ProcessEvent(
                type=EventType.PROCESS_EXEC,
                agent_id=agent_id,
                timestamp=ts,
                filename=tool_name,
                args=meta.get("tool_args", []),
                comm=tool_name,
                metadata={"trace_id": span.get("trace_id", "")},
            )
        
        elif operation == "file_write":
            return FileEvent(
                type=EventType.FILE_WRITE,
                agent_id=agent_id,
                timestamp=ts,
                path=meta.get("path", ""),
                bytes_count=meta.get("bytes", 0),
                metadata={"trace_id": span.get("trace_id", "")},
            )
        
        elif operation == "file_read":
            return FileEvent(
                type=EventType.FILE_READ,
                agent_id=agent_id,
                timestamp=ts,
                path=meta.get("path", ""),
                metadata={"trace_id": span.get("trace_id", "")},
            )
        
        elif operation == "api_call":
            return NetworkEvent(
                type=EventType.NETWORK_CONNECT,
                agent_id=agent_id,
                timestamp=ts,
                remote_ip="",
                remote_port=meta.get("port", 443),
                domain=meta.get("endpoint", ""),
                metadata={"trace_id": span.get("trace_id", "")},
            )
        
        return None

    @staticmethod
    def batch_convert(spans: list[dict]) -> list[Event]:
        """Convert a batch of SessionTrace spans to events."""
        events = []
        for span in spans:
            event = SessionTraceAdapter.span_to_event(span)
            if event:
                events.append(event)
        return events


class MarketJudgeAdapter:
    """Adapter: Market Judge scoring → substrate-guard policy context.
    
    Market Judge scores 2080+ items with 73% pass rate.
    Its decisions feed into the policy layer as additional context.
    """
    
    @staticmethod
    def score_to_context(judge_result: dict) -> dict:
        """Convert Market Judge result to policy evaluation context."""
        return {
            "market_judge_score": judge_result.get("score", 0),
            "market_judge_pass": judge_result.get("pass", False),
            "market_judge_rubric": judge_result.get("rubric", ""),
            "quality_gate": "passed" if judge_result.get("pass", False) else "blocked",
        }


class MirrorReporter:
    """Reports Guard session results to Mirror (self-awareness loop).
    
    Mirror runs every 30 minutes (103+ cycles). Guard reports feed into
    Mirror's pattern detection for ecosystem-level anomaly awareness.
    """

    def __init__(self, mirror_endpoint: str = "http://localhost:8080/mirror"):
        self._endpoint = mirror_endpoint
        self._reports: list[dict] = []

    def report(self, session_report: SessionReport) -> None:
        """Send a session report to Mirror."""
        payload = {
            "source": "substrate-guard",
            "timestamp": datetime.now().astimezone().isoformat(),
            "report": session_report.to_dict(),
            "summary": session_report.summary_line(),
        }
        self._reports.append(payload)
        
        # In production: POST to Mirror endpoint
        # For now: log and accumulate
        if session_report.policy_violations > 0:
            logger.warning(
                f"Guard report → Mirror: {session_report.summary_line()}"
            )
        else:
            logger.info(
                f"Guard report → Mirror: {session_report.summary_line()}"
            )

    def flush(self) -> list[dict]:
        """Return and clear accumulated reports."""
        reports = self._reports.copy()
        self._reports.clear()
        return reports


class SubstrateGuard:
    """Full integration: substrate-guard × SUBSTRATE ecosystem.
    
    Connects:
    - SessionTrace → Layer 1 (events)
    - OPA policies → Layer 2 (decisions)
    - Z3 verifiers → Layer 3 (proofs)
    - Mirror ← reports
    
    Usage:
        sg = SubstrateGuard()
        # Or: SubstrateGuard(config_path="...", verify_process_cli=True)
        
        # Process SessionTrace spans
        spans = get_recent_spans()  # from your SessionTrace API
        report = sg.process_spans(spans)
        print(report.summary_line())
        
        # Or monitor continuously
        sg.start_monitor()
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        policy_path: Optional[str] = None,
        use_ebpf: bool = True,
        verify_process_cli: Optional[bool] = None,
    ):
        # Load config
        if config_path and Path(config_path).exists():
            self.config = SubstrateConfig.from_file(config_path)
        else:
            self.config = SubstrateConfig()

        vpc = resolve_verify_process_cli(
            verify_process_cli,
            self.config.verify_process_cli,
        )

        # Initialize Guard
        self.guard = Guard(
            observe=use_ebpf,
            policy=policy_path or "nonexistent/",
            verify=True,
            verify_process_cli=vpc,
            use_mock=not use_ebpf,
        )
        
        # Adapters
        self.session_trace = SessionTraceAdapter()
        self.market_judge = MarketJudgeAdapter()
        self.mirror = MirrorReporter()
        
        # Stats
        self._spans_processed = 0
        self._violations_total = 0
        self._start_time = time.time()
        
        logger.info(
            f"SubstrateGuard initialized for {self.config.platform} "
            f"({self.config.total_agents} agents across "
            f"{len(self.config.active_clusters)} clusters)"
        )

    def process_spans(self, spans: list[dict]) -> SessionReport:
        """Process a batch of SessionTrace spans through the full pipeline.
        
        This is the main integration point. Call this with spans from
        SessionTrace and get a GuardReport back.
        """
        # Convert spans → events
        events = self.session_trace.batch_convert(spans)
        
        if not events:
            return SessionReport(
                agent_id="batch",
                duration_s=0,
                events_observed=0,
                policy_violations=0,
                policy_allowed=0,
                formal_verifications=0,
                formal_failures=0,
            )
        
        # Determine agent_id (from first event or mixed)
        agent_ids = set(e.agent_id for e in events)
        agent_label = list(agent_ids)[0] if len(agent_ids) == 1 else f"batch-{len(agent_ids)}-agents"
        
        # Run through pipeline
        with self.guard.monitor(agent_label) as session:
            for event in events:
                session.inject_and_evaluate(event)
        
        report = session.report()
        
        # Update stats
        self._spans_processed += len(spans)
        self._violations_total += report.policy_violations
        
        # Report to Mirror
        self.mirror.report(report)
        
        return report

    def process_single_span(self, span: dict) -> Optional[dict]:
        """Process a single span — returns decision dict or None."""
        event = self.session_trace.span_to_event(span)
        if not event:
            return None
        
        ge = self.guard.evaluate_event(event)
        self._spans_processed += 1
        
        if not ge.policy_decision.allowed:
            self._violations_total += 1
        
        return {
            "allowed": ge.policy_decision.allowed,
            "reasons": ge.policy_decision.reasons,
            "severity": event.severity.value,
            "agent_id": event.agent_id,
            "latency_ms": ge.policy_decision.latency_ms,
        }

    @property
    def stats(self) -> dict:
        uptime = time.time() - self._start_time
        return {
            "platform": self.config.platform,
            "total_agents": self.config.total_agents,
            "active_clusters": self.config.active_clusters,
            "spans_processed": self._spans_processed,
            "violations_total": self._violations_total,
            "violation_rate": (self._violations_total / max(self._spans_processed, 1)),
            "uptime_s": round(uptime, 1),
        }

    def health_check(self) -> dict:
        """Quick health check — verifies all layers are operational."""
        results = {}
        
        # Layer 1: Observe
        try:
            tracer = self.guard._tracer
            results["observe"] = {
                "status": "ok",
                "mode": "mock" if (tracer and tracer.is_mock) else "ebpf" if tracer else "disabled",
            }
        except Exception as e:
            results["observe"] = {"status": "error", "detail": str(e)}
        
        # Layer 2: Policy
        try:
            decision = self.guard._policy.evaluate({
                "agent": {"id": "health-check", "role": "test"},
                "action": {"type": "file_write", "path": "/workspace/test.py"},
                "context": {},
            }) if self.guard._policy else None
            results["policy"] = {
                "status": "ok" if decision and decision.allowed else "ok-no-policy",
                "latency_ms": decision.latency_ms if decision else 0,
            }
        except Exception as e:
            results["policy"] = {"status": "error", "detail": str(e)}
        
        # Layer 3: Z3
        try:
            import z3
            results["verify"] = {"status": "ok", "z3_version": z3.get_version_string()}
        except ImportError:
            results["verify"] = {"status": "unavailable", "detail": "z3-solver not installed"}
        except Exception as e:
            results["verify"] = {"status": "error", "detail": str(e)}
        
        results["overall"] = "healthy" if all(
            r.get("status") in ("ok", "ok-no-policy") for r in results.values()
            if isinstance(r, dict)
        ) else "degraded"
        
        return results
