"""Unified Guard — The complete verification stack.

eBPF observes → OPA decides → Z3 proves.

Three levels, from silicon to theorem, in a single pipeline.

Usage:
    guard = Guard(
        observe=True,
        policy="policies/",
        verify=True,
    )
    
    with guard.monitor("agent-7") as session:
        result = agent.run(task="generate sorting function")
        report = session.report()
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Optional, Tuple
from pathlib import Path

from .observe.tracer import AgentTracer
from .observe.events import Event, EventType, Severity, EventStream
from .policy.engine import PolicyEngine, PolicyDecision

logger = logging.getLogger("substrate_guard")


def _format_guard_counterexample(artifact_type: str, result: object) -> Optional[str]:
    """Format verifier-specific failure details for :class:`VerificationResult.counterexample`."""
    if artifact_type == "code":
        from .code_verifier import VerificationResult as CodeVerificationResult

        if isinstance(result, CodeVerificationResult):
            parts: list[str] = []
            if result.error:
                parts.append(str(result.error))
            if result.counterexample:
                cx = result.counterexample
                parts.append(f"inputs={cx.inputs}")
                if cx.description:
                    parts.append(str(cx.description))
            parts.extend(str(w) for w in result.warnings)
            if parts:
                return "; ".join(parts)
            return f"status={result.status.value}"

    if artifact_type == "hw":
        err = getattr(result, "error", None)
        if err:
            return str(err)
        cex = getattr(result, "counterexample", None)
        if cex is not None:
            try:
                return json.dumps(cex, sort_keys=True)
            except (TypeError, ValueError):
                return str(cex)

    return None


def _map_verification_to_guard(
    artifact_type: str,
    result: object,
) -> Tuple[bool, Optional[str]]:
    """Map verifier-specific return values to Guard's ``verified`` flag and counterexample.

    Verifiers return dataclasses (``CLISafetyResult``, ``ToolSafetyResult``, …), not dicts
    with ``{"verified": ...}``. The old ``result.get("verified")`` path was always falsy.
    """
    if isinstance(result, dict):
        return bool(result.get("verified")), result.get("counterexample")

    if artifact_type == "cli":
        from .cli_verifier import CLISafetyResult

        if isinstance(result, CLISafetyResult):
            if result.safe:
                return True, None
            parts = [
                f"{v.pattern_name}: {v.description} [{v.matched_text}]"
                for v in result.violations
            ]
            return False, ("; ".join(parts) if parts else "unsafe_cli_command")

    if artifact_type == "tool":
        safe = getattr(result, "safe", None)
        if safe is not None:
            return bool(safe), (None if safe else str(result))

    if artifact_type in ("code", "hw"):
        verified = getattr(result, "verified", None)
        if verified is not None:
            v = bool(verified)
            if v:
                return True, None
            ce = _format_guard_counterexample(artifact_type, result)
            return False, ce

    if artifact_type == "distill":
        all_valid = getattr(result, "all_valid", None)
        if all_valid is not None:
            return bool(all_valid), (None if all_valid else str(result))

    return False, f"unrecognized verification result: {type(result).__name__}"


def _verification_to_chain_event(vr: "VerificationResult", agent_id: Optional[str]) -> dict:
    """Structured chain entry for auditors: why formal verification passed or failed."""
    return {
        "type": "formal_verification",
        "agent_id": agent_id or "unknown",
        "verifier_type": vr.verifier_type,
        "verified": vr.verified,
        "artifact_preview": vr.artifact,
        "counterexample": vr.counterexample,
        "proof_time_ms": vr.proof_time_ms,
    }


@dataclass
class VerificationResult:
    """Result from Z3 formal verification of a single artifact."""
    verified: bool
    verifier_type: str  # "code", "tool", "cli", "hw", "distill"
    artifact: str  # what was verified
    counterexample: Optional[str] = None
    proof_time_ms: float = 0.0


@dataclass
class GuardEvent:
    """A single event that has passed through all three layers."""
    event: Event
    policy_decision: PolicyDecision
    verification: Optional[VerificationResult] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def fully_safe(self) -> bool:
        if not self.policy_decision.allowed:
            return False
        if self.verification and not self.verification.verified:
            return False
        return True


@dataclass
class SessionReport:
    """Summary of a monitoring session across all three layers."""
    agent_id: str
    duration_s: float
    events_observed: int
    policy_violations: int
    policy_allowed: int
    formal_verifications: int
    formal_failures: int
    events: list[GuardEvent] = field(default_factory=list)
    cost_estimate_usd: float = 0.0

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "duration_s": round(self.duration_s, 2),
            "layers": {
                "observe": {
                    "events": self.events_observed,
                },
                "policy": {
                    "violations": self.policy_violations,
                    "allowed": self.policy_allowed,
                },
                "verify": {
                    "checked": self.formal_verifications,
                    "failures": self.formal_failures,
                },
            },
            "cost_usd": round(self.cost_estimate_usd, 4),
            "verdict": "SAFE" if self.policy_violations == 0 and self.formal_failures == 0
                       else "VIOLATIONS_DETECTED",
        }

    def summary_line(self) -> str:
        verdict = "✅ SAFE" if (self.policy_violations == 0 and 
                               self.formal_failures == 0) else "❌ VIOLATIONS"
        return (
            f"{verdict} | agent={self.agent_id} | "
            f"observed={self.events_observed} | "
            f"policy_violations={self.policy_violations} | "
            f"formal_failures={self.formal_failures} | "
            f"{self.duration_s:.1f}s"
        )


class Guard:
    """The complete verification stack.
    
    Connects three layers:
    - Layer 1 (eBPF): What is the agent actually doing?
    - Layer 2 (OPA/Rego): Does it have permission?
    - Layer 3 (Z3): Is the output mathematically correct?
    
    Args:
        observe: Enable eBPF kernel observation (Layer 1)
        policy: Path to Rego policies or PolicyEngine instance (Layer 2)
        verify: Enable Z3 formal verification (Layer 3)
        use_mock: Force mock mode for eBPF (testing without kernel access)
    """

    def __init__(
        self,
        observe: bool = True,
        policy: str | Path | PolicyEngine | None = None,
        verify: bool = True,
        chain: bool = False,
        hmac_secret: Optional[str] = None,
        use_mock: bool = False,
    ):
        # Layer 1: eBPF Observe
        self._tracer: Optional[AgentTracer] = None
        if observe:
            self._tracer = AgentTracer(use_mock=use_mock)

        # Layer 2: OPA Policy
        self._policy: Optional[PolicyEngine] = None
        if policy is not None:
            if isinstance(policy, PolicyEngine):
                self._policy = policy
            else:
                self._policy = PolicyEngine(policy_path=policy)

        # Layer 3: Z3 Verify
        self._verify = verify
        self._z3_available = False
        if verify:
            try:
                import z3
                self._z3_available = True
            except ImportError:
                logger.warning("z3-solver not installed — Layer 3 disabled")
                self._z3_available = False

        # Layer 4: Tamper-evident chain
        self._chain = None
        if chain:
            from .chain import AuditChain
            self._chain = AuditChain(secret=hmac_secret)

        layers = []
        if self._tracer:
            mode = "mock" if self._tracer.is_mock else "eBPF"
            layers.append(f"observe({mode})")
        if self._policy:
            layers.append("policy(OPA)")
        if self._z3_available:
            layers.append("verify(Z3)")
        if self._chain:
            layers.append("chain(HMAC)")
        logger.info(f"Guard initialized: [{' -> '.join(layers)}]")

    @contextmanager
    def monitor(self, agent_id: str, pid: Optional[int] = None):
        """Context manager for monitoring an agent session.
        
        Usage:
            with guard.monitor("agent-7", pid=1234) as session:
                agent.run(task="...")
                print(session.report())
        """
        session = GuardSession(
            agent_id=agent_id,
            guard=self,
        )
        
        # Start observation
        if self._tracer:
            if pid:
                self._tracer.watch_pid(pid, agent_id)
            self._tracer.start()

        session._start_time = time.time()
        
        try:
            yield session
        finally:
            session._end_time = time.time()
            if self._tracer:
                self._tracer.stop()

    def evaluate_event(self, event: Event) -> GuardEvent:
        """Push a single event through all active layers."""
        # Layer 2: Policy decision
        policy_decision = PolicyDecision(allowed=True)
        if self._policy:
            policy_decision = self._policy.evaluate_event(event)

        # Layer 3: Z3 verification (only for code/tool output events)
        verification = None
        # Z3 verification is triggered explicitly via verify_artifact()
        
        ge = GuardEvent(
            event=event,
            policy_decision=policy_decision,
            verification=verification,
        )

        # Layer 4: Tamper-evident chain
        if self._chain:
            chain_data = event.to_dict() if hasattr(event, 'to_dict') else {"raw": str(event)}
            chain_data["_policy_allowed"] = policy_decision.allowed
            chain_data["_policy_reasons"] = policy_decision.reasons
            self._chain.append(chain_data)

        return ge

    def _append_verification_to_chain(self, vr: VerificationResult, agent_id: Optional[str]) -> None:
        """Record formal verification outcome (including counterexample) in the HMAC audit chain."""
        if not self._chain:
            return
        self._chain.append(_verification_to_chain_event(vr, agent_id))

    def verify_artifact(
        self,
        artifact: str,
        artifact_type: str = "code",
        spec: Any = None,
        *,
        agent_id: Optional[str] = None,
    ) -> VerificationResult:
        """Run Z3 formal verification on an AI-generated artifact.
        
        Args:
            artifact: Code string, tool definition, CLI command, etc.
            artifact_type: One of "code", "tool", "cli", "hw", "distill"
            spec: For ``code``, a dict or :class:`~substrate_guard.code_verifier.Spec`.
                  For ``hw``, a dict or :class:`~substrate_guard.hw_verifier.HWSpec`.
                  Omitted keys use verifier defaults.
            agent_id: Optional agent scope; included in chain export when ``chain=True``.
                Each formal verification appends a ``formal_verification`` entry with
                ``verified``, ``counterexample``, and ``artifact_preview`` for auditors.
        """
        def _out(vr: VerificationResult) -> VerificationResult:
            self._append_verification_to_chain(vr, agent_id)
            return vr

        if not self._z3_available:
            return _out(
                VerificationResult(
                    verified=False,
                    verifier_type=artifact_type,
                    artifact=artifact[:100],
                    counterexample="Z3 not available",
                )
            )

        start = time.perf_counter()
        
        try:
            if artifact_type == "code":
                from .code_verifier import CodeVerifier, Spec, spec_from_mapping

                verifier = CodeVerifier()
                code_spec: Spec = (
                    spec if isinstance(spec, Spec) else spec_from_mapping(spec if isinstance(spec, dict) else None)
                )
                result = verifier.verify(artifact, code_spec)
            elif artifact_type == "tool":
                from .tool_verifier import tool_definition_from_payload, verify_tool

                try:
                    tool_def = tool_definition_from_payload(artifact)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                    elapsed = (time.perf_counter() - start) * 1000
                    return _out(
                        VerificationResult(
                            verified=False,
                            verifier_type="tool",
                            artifact=artifact[:100] if isinstance(artifact, str) else str(artifact)[:100],
                            counterexample=f"Invalid tool payload: {e}",
                            proof_time_ms=elapsed,
                        )
                    )
                result = verify_tool(tool_def)
            elif artifact_type == "cli":
                from .cli_verifier import CLIVerifier
                verifier = CLIVerifier()
                result = verifier.verify(artifact)
            elif artifact_type == "hw":
                from .hw_verifier import HWSpec, HardwareVerifier, hw_spec_from_mapping

                verifier = HardwareVerifier()
                hw_spec: HWSpec = (
                    spec if isinstance(spec, HWSpec) else hw_spec_from_mapping(spec if isinstance(spec, dict) else None)
                )
                result = verifier.verify(artifact, hw_spec)
            elif artifact_type == "distill":
                from .distill_verifier import DistillationVerifier

                verifier = DistillationVerifier()
                result = verifier.verify(artifact)
            else:
                return _out(
                    VerificationResult(
                        verified=False,
                        verifier_type=artifact_type,
                        artifact=artifact[:100],
                        counterexample=f"Unknown verifier type: {artifact_type}",
                    )
                )

            elapsed = (time.perf_counter() - start) * 1000

            verified, counterexample = _map_verification_to_guard(artifact_type, result)

            return _out(
                VerificationResult(
                    verified=verified,
                    verifier_type=artifact_type,
                    artifact=artifact[:100] if isinstance(artifact, str) else str(artifact)[:100],
                    counterexample=counterexample,
                    proof_time_ms=elapsed,
                )
            )

        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return _out(
                VerificationResult(
                    verified=False,
                    verifier_type=artifact_type,
                    artifact=artifact[:100] if isinstance(artifact, str) else str(artifact)[:100],
                    counterexample=f"Verification error: {e}",
                    proof_time_ms=elapsed,
                )
            )


class GuardSession:
    """Active monitoring session for one agent."""

    def __init__(self, agent_id: str, guard: Guard):
        self.agent_id = agent_id
        self._guard = guard
        self._events: list[GuardEvent] = []
        self._start_time = 0.0
        self._end_time = 0.0

    def process_events(self) -> list[GuardEvent]:
        """Process any pending events from the tracer through the pipeline."""
        if not self._guard._tracer:
            return []
        
        raw_events = self._guard._tracer.drain()
        guard_events = []
        
        for event in raw_events:
            if event.agent_id == self.agent_id or event.agent_id == "unknown":
                ge = self._guard.evaluate_event(event)
                self._events.append(ge)
                guard_events.append(ge)
        
        return guard_events

    def inject_and_evaluate(self, event: Event) -> GuardEvent:
        """Inject a synthetic event and evaluate it through the pipeline.
        
        Note: Does NOT add to tracer queue to avoid double-processing.
        The event goes directly through policy evaluation.
        """
        event.agent_id = self.agent_id
        # Add to tracer stream for observability, but drain queue to prevent
        # double-processing in process_events()
        if self._guard._tracer:
            self._guard._tracer.inject_event(event)
            self._guard._tracer.drain()  # clear queue since we evaluate directly
        ge = self._guard.evaluate_event(event)
        self._events.append(ge)
        return ge

    def verify(self, artifact: str, artifact_type: str = "code",
               spec: Any = None) -> VerificationResult:
        """Run Z3 verification on an artifact within this session."""
        return self._guard.verify_artifact(artifact, artifact_type, spec, agent_id=self.agent_id)

    @property
    def violations(self) -> list[GuardEvent]:
        return [e for e in self._events if not e.policy_decision.allowed]

    @property  
    def formal_failures(self) -> list[GuardEvent]:
        return [e for e in self._events 
                if e.verification and not e.verification.verified]

    def report(self) -> SessionReport:
        """Generate session report."""
        self.process_events()  # Drain any remaining events
        
        duration = (self._end_time or time.time()) - self._start_time
        policy_violations = len(self.violations)
        formal_checks = [e for e in self._events if e.verification]
        formal_fails = len(self.formal_failures)

        return SessionReport(
            agent_id=self.agent_id,
            duration_s=duration,
            events_observed=len(self._events),
            policy_violations=policy_violations,
            policy_allowed=len(self._events) - policy_violations,
            formal_verifications=len(formal_checks),
            formal_failures=formal_fails,
            events=self._events,
        )
