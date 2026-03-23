"""Real Vendor Adapters — Connect to actual backend/vendor/ packages.

Maps substrate-guard to the real SessionTrace, MarketJudge, and AgentObs
code running in the ai-research-agency backend container.

Server structure (from audit):
    backend/vendor/
    ├── sessiontrace/   (api.py, capture.py, cost.py, perception.py, session.py, span.py, store.py)
    ├── marketjudge/    (scorer.py, rubric.py, allocation.py, oracle_sync.py, api.py)
    ├── agentobs/       (dispatcher.py, escalation.py, rules.py, store.py, stream.py, api.py)
    ├── promptops/
    ├── codeslp/
    ├── edgecompile/
    ├── modelfit/
    └── hypy/

Database (PostgreSQL 16, 43 tables):
    - pipeline_traces (1,483 records)
    - agent_runs (1,132 records)
    - ideas (1,444 records)
    - audit_log (63 records)

Usage:
    # From the FastAPI backend context
    from substrate_guard.integrations.vendor_bridge import VendorBridge

    bridge = VendorBridge(db_url="postgresql://...", vendor_path="/opt/.../vendor")
    report = bridge.audit_recent_runs(hours=1)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Any

from ..observe.events import (
    Event, EventType, FileEvent, NetworkEvent, ProcessEvent,
)
from ..guard import Guard, SessionReport

logger = logging.getLogger("substrate_guard.vendor_bridge")


@dataclass
class VendorPaths:
    """Paths to vendor packages on the server."""
    base: str = "/opt/ai-research-agency/backend"
    sessiontrace: str = ""
    marketjudge: str = ""
    agentobs: str = ""
    guardian: str = ""

    def __post_init__(self):
        if not self.sessiontrace:
            self.sessiontrace = f"{self.base}/vendor/sessiontrace"
        if not self.marketjudge:
            self.marketjudge = f"{self.base}/vendor/marketjudge"
        if not self.agentobs:
            self.agentobs = f"{self.base}/vendor/agentobs"
        if not self.guardian:
            self.guardian = f"{self.base}/meta_agents/guardian"

    def verify(self) -> dict[str, bool]:
        """Check which vendor packages exist on disk."""
        return {
            "sessiontrace": Path(self.sessiontrace).is_dir(),
            "marketjudge": Path(self.marketjudge).is_dir(),
            "agentobs": Path(self.agentobs).is_dir(),
            "guardian": Path(self.guardian).is_dir(),
        }


class PipelineTraceAdapter:
    """Converts pipeline_traces DB records → Guard events.

    Real schema (from server audit):
        pipeline_traces:
            id, trace_id, pipeline_run_id, step_index, agent_id (int),
            agent_name, status, model_used, input_summary, output_summary,
            tokens_in, tokens_out, cost_usd, duration_ms, error,
            started_at, completed_at, confidence
    """

    @staticmethod
    def db_row_to_events(row: dict) -> list[Event]:
        """Convert a pipeline_trace row to Guard events."""
        events = []
        # agent_id is numeric in DB; agent_name is the human-readable label
        agent_name = row.get("agent_name", "unknown")
        agent_id_num = row.get("agent_id")
        agent_label = f"{agent_name}" if not agent_id_num else f"{agent_name}#{agent_id_num}"
        
        ts = row.get("started_at", time.time())
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts).timestamp()
            except (ValueError, TypeError):
                ts = time.time()
        elif hasattr(ts, 'timestamp'):
            ts = ts.timestamp()

        model = row.get("model_used", "") or ""
        cost = float(row.get("cost_usd", 0) or 0)
        tokens_in = row.get("tokens_in", 0) or 0
        tokens_out = row.get("tokens_out", 0) or 0

        # LLM call event (if model was used)
        if model:
            endpoint = "api.anthropic.com" if "claude" in model.lower() else "api.openai.com"
            events.append(NetworkEvent(
                type=EventType.NETWORK_CONNECT,
                agent_id=agent_label,
                timestamp=ts,
                remote_port=443,
                domain=endpoint,
                metadata={
                    "model": model,
                    "cost_usd": cost,
                    "tokens_in": tokens_in,
                    "tokens_out": tokens_out,
                    "pipeline_run_id": row.get("pipeline_run_id", ""),
                    "trace_id": row.get("trace_id", ""),
                },
            ))

        # Check output_summary for dangerous file paths in plain text
        # Only flag system paths — not workspace/business paths like /Anthropic/Azure
        output = row.get("output_summary") or ""
        if isinstance(output, str) and output:
            import re
            DANGEROUS_PREFIXES = r"(/etc/\w+|/root/\w+|/boot/\w+|/dev/\w+|/proc/\w+|/sys/\w+|/var/log/\w+)"
            paths = re.findall(DANGEROUS_PREFIXES, output)
            for path in paths:
                events.append(FileEvent(
                    type=EventType.FILE_WRITE,
                    agent_id=agent_label,
                    timestamp=ts + 0.1,
                    path=path,
                    metadata={"trace_id": row.get("trace_id", "")},
                ))

        # Agent execution event (always — even if no model)
        if not model:
            events.append(ProcessEvent(
                type=EventType.PROCESS_EXEC,
                agent_id=agent_label,
                timestamp=ts,
                filename=f"agent:{agent_name}",
                args=[row.get("status", ""), f"step:{row.get('step_index', 0)}"],
                metadata={
                    "pipeline_run_id": row.get("pipeline_run_id", ""),
                    "trace_id": row.get("trace_id", ""),
                    "duration_ms": row.get("duration_ms", 0),
                },
            ))

        return events


class AgentRunAdapter:
    """Converts agent_runs DB records → Guard events.

    Real schema (from server audit):
        agent_runs:
            id, agent_id (int), agent_name, status, duration_ms,
            confidence, error, input_summary, output_summary,
            trace_id, created_at
    """

    @staticmethod
    def db_row_to_events(row: dict) -> list[Event]:
        """Convert an agent_run row to Guard events."""
        events = []
        agent_name = row.get("agent_name", "unknown")
        agent_id_num = row.get("agent_id", 0)
        agent_label = f"{agent_name}#{agent_id_num}" if agent_id_num else agent_name

        ts = row.get("created_at", time.time())
        if isinstance(ts, str):
            try:
                from datetime import datetime
                ts = datetime.fromisoformat(ts).timestamp()
            except (ValueError, TypeError):
                ts = time.time()
        elif hasattr(ts, 'timestamp'):
            ts = ts.timestamp()

        # Agent execution event
        events.append(ProcessEvent(
            type=EventType.PROCESS_EXEC,
            agent_id=agent_label,
            timestamp=ts,
            filename=f"agent:{agent_name}",
            args=[row.get("status", "")],
            metadata={
                "duration_ms": row.get("duration_ms", 0),
                "confidence": float(row.get("confidence", 0) or 0),
                "run_id": str(row.get("id", "")),
                "trace_id": row.get("trace_id", ""),
                "error": row.get("error", ""),
            },
        ))

        # Check output_summary for dangerous file paths
        output = row.get("output_summary") or ""
        if isinstance(output, str) and output:
            import re
            DANGEROUS_PREFIXES = r"(/etc/\w+|/root/\w+|/boot/\w+|/dev/\w+|/proc/\w+|/sys/\w+|/var/log/\w+)"
            paths = re.findall(DANGEROUS_PREFIXES, output)
            for path in paths:
                events.append(FileEvent(
                    type=EventType.FILE_WRITE,
                    agent_id=agent_label,
                    timestamp=ts + 0.01,
                    path=path,
                    metadata={"run_id": str(row.get("id", ""))},
                ))

        return events


class VendorBridge:
    """Main bridge between substrate-guard and the live backend.

    Connects to PostgreSQL to read pipeline_traces and agent_runs,
    then evaluates them through the Guard pipeline.

    Usage:
        bridge = VendorBridge(db_url="postgresql://user:pass@localhost/airesearch")
        
        # Audit last hour of activity
        report = bridge.audit_recent(hours=1)
        print(report.summary_line())
        
        # Audit specific agent
        report = bridge.audit_agent("scanners/market_scanner", hours=24)
    """

    def __init__(
        self,
        db_url: Optional[str] = None,
        vendor_paths: Optional[VendorPaths] = None,
        guard: Optional[Guard] = None,
    ):
        self._db_url = db_url
        self._vendor = vendor_paths or VendorPaths()
        self._guard = guard or Guard(
            observe=True, policy="nonexistent/", verify=True, use_mock=True
        )
        self._trace_adapter = PipelineTraceAdapter()
        self._run_adapter = AgentRunAdapter()

    def audit_traces(self, traces: list[dict]) -> SessionReport:
        """Audit a list of pipeline_trace records."""
        all_events = []
        for trace in traces:
            all_events.extend(self._trace_adapter.db_row_to_events(trace))

        if not all_events:
            return SessionReport(
                agent_id="audit", duration_s=0,
                events_observed=0, policy_violations=0,
                policy_allowed=0, formal_verifications=0,
                formal_failures=0,
            )

        agent_ids = set(e.agent_id for e in all_events)
        label = list(agent_ids)[0] if len(agent_ids) == 1 else f"audit-{len(traces)}-traces"

        with self._guard.monitor(label) as session:
            for event in all_events:
                session.inject_and_evaluate(event)

        return session.report()

    def audit_runs(self, runs: list[dict]) -> SessionReport:
        """Audit a list of agent_run records."""
        all_events = []
        for run in runs:
            all_events.extend(self._run_adapter.db_row_to_events(run))

        if not all_events:
            return SessionReport(
                agent_id="audit", duration_s=0,
                events_observed=0, policy_violations=0,
                policy_allowed=0, formal_verifications=0,
                formal_failures=0,
            )

        label = f"audit-{len(runs)}-runs"

        with self._guard.monitor(label) as session:
            for event in all_events:
                session.inject_and_evaluate(event)

        return session.report()

    def verify_vendor_packages(self) -> dict:
        """Check which vendor packages are accessible."""
        status = self._vendor.verify()
        status["guard_layers"] = {
            "observe": self._guard._tracer is not None,
            "policy": self._guard._policy is not None,
            "verify": self._guard._z3_available if hasattr(self._guard, '_z3_available') else False,
        }
        return status
