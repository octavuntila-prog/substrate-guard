"""L3 per-event formal verification — selective, sampled, async, latency-bounded.

Runs the four SOUND verifiers (code/tool/hw/distill) on artifact-bearing LIVE events,
under an explicit latency budget, producing a 4-way verdict {VERIFIED, REFUTED,
ABSTAIN, TIMEOUT}. This is NOT "Z3 on every event": only events carrying a structured
artifact are candidates, sampling bounds volume, and a small per-artifact Z3 timeout
bounds work. See docs/l3-perevent-verify.md.
"""

from __future__ import annotations

import concurrent.futures as _cf
import hashlib
import logging
import time
from concurrent.futures import Executor, Future
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger("substrate_guard.perevent_verify")

ARTIFACT_TYPES = ("code", "tool", "hw", "distill")


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"   # proof holds on the bounded fragment (nothing dropped)
    REFUTED = "REFUTED"     # concrete counterexample found (artifact unsafe)
    ABSTAIN = "ABSTAIN"     # out-of-domain / unsupported -- not proven, not refuted
    TIMEOUT = "TIMEOUT"     # abstained specifically because the latency budget was hit


# Each verifier declares its own status enum; normalize the names to the 4-way verdict.
_VERIFIED_NAMES = {"VERIFIED", "SAFE", "ALL_VALID"}
_REFUTED_NAMES = {"UNSAFE", "HAS_ERRORS", "INVALID"}
# everything else (UNKNOWN, TRANSLATION_ERROR, PARSE_ERROR, PARSE_FAILURE,
# INCONCLUSIVE, UNCHECKED, ...) is an honest ABSTAIN -- never a false VERIFIED.


@dataclass
class VerdictRecord:
    verdict: Verdict
    artifact_type: str
    artifact_preview: str
    agent_id: str
    detail: str = ""
    elapsed_ms: float = 0.0

    @property
    def verified(self) -> bool:
        return self.verdict is Verdict.VERIFIED

    def to_chain_event(self) -> dict:
        """A ``formal_verification`` chain entry. Carries the 4-way ``verdict`` ADDITIVE
        to the legacy ``verified`` bool (the chain event_data is free-form)."""
        return {
            "type": "formal_verification",
            "agent_id": self.agent_id,
            "verifier_type": self.artifact_type,
            "verified": self.verified,
            "verdict": self.verdict.value,
            "artifact_preview": self.artifact_preview,
            "counterexample": self.detail or None,
            "proof_time_ms": round(self.elapsed_ms, 2),
        }


@dataclass
class PerEventConfig:
    enabled_types: tuple = ARTIFACT_TYPES
    sample_rate: float = 1.0     # 1.0 = verify every candidate; <1 samples deterministically
    timeout_ms: int = 300        # per-artifact Z3 budget (small -> fast ABSTAIN/TIMEOUT)
    max_workers: int = 2


def _extract_detail(result: Any) -> str:
    ce = getattr(result, "counterexample", None)
    if ce is not None:
        return str(ce)[:200]
    err = getattr(result, "error", None)
    if err:
        return str(err)[:200]
    return ""


def _map_status_to_verdict(result: Any, elapsed_ms: float, budget_ms: int) -> tuple[Verdict, str]:
    """Map a verifier's native status enum to the 4-way verdict. An ABSTAIN that
    consumed ~the whole budget is reported as TIMEOUT (budget pressure vs genuine
    out-of-domain)."""
    status = getattr(result, "status", None)
    name = (getattr(status, "name", None) or str(status) or "").upper()
    detail = _extract_detail(result)
    if name in _VERIFIED_NAMES:
        return Verdict.VERIFIED, detail
    if name in _REFUTED_NAMES:
        return Verdict.REFUTED, detail
    if budget_ms and elapsed_ms >= 0.85 * budget_ms:
        return Verdict.TIMEOUT, detail or f"solver latency budget {budget_ms}ms reached"
    return Verdict.ABSTAIN, detail or f"out-of-domain ({name.lower() or 'unknown'})"


def verify_one(artifact_type: str, artifact: str, spec: Any, agent_id: str,
               timeout_ms: int) -> "VerdictRecord":
    """Run one artifact through its verifier under the latency budget and return a
    4-way VerdictRecord. MODULE-LEVEL + returns only picklable primitives, so it is
    safe to run in a ProcessPoolExecutor (Z3 is NOT thread-safe -- process isolation
    is the only safe way to parallelize it; never a ThreadPoolExecutor). Never raises:
    a broken artifact ABSTAINs rather than crashing ingestion."""
    start = time.perf_counter()
    try:
        result = _run_verifier(artifact_type, artifact, spec, timeout_ms)
        elapsed = (time.perf_counter() - start) * 1000
        verdict, detail = _map_status_to_verdict(result, elapsed, timeout_ms)
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        verdict = Verdict.ABSTAIN
        detail = f"verifier error: {type(e).__name__}: {str(e)[:150]}"
    return VerdictRecord(
        verdict=verdict, artifact_type=artifact_type,
        artifact_preview=artifact[:100], agent_id=agent_id,
        detail=detail, elapsed_ms=elapsed,
    )


def _run_verifier(artifact_type: str, artifact: str, spec: Any, timeout_ms: int) -> Any:
    """Construct + run the right verifier with the latency budget; return its native
    result object (which carries a ``.status`` enum)."""
    if artifact_type == "code":
        from .code_verifier import CodeVerifier, Spec, spec_from_mapping
        v = CodeVerifier(timeout_ms=timeout_ms)
        s = spec if isinstance(spec, Spec) else spec_from_mapping(spec if isinstance(spec, dict) else None)
        return v.verify(artifact, s)
    if artifact_type == "tool":
        from .tool_verifier import tool_definition_from_payload, verify_tool
        return verify_tool(tool_definition_from_payload(artifact), timeout_ms=timeout_ms)
    if artifact_type == "hw":
        from .hw_verifier import HardwareVerifier, HWSpec, hw_spec_from_mapping
        v = HardwareVerifier(timeout_ms=timeout_ms)
        s = spec if isinstance(spec, HWSpec) else hw_spec_from_mapping(spec if isinstance(spec, dict) else None)
        return v.verify(artifact, s)
    if artifact_type == "distill":
        from .distill_verifier import DistillationVerifier
        return DistillationVerifier(timeout_ms=timeout_ms).verify(artifact)
    raise ValueError(f"unknown artifact_type {artifact_type!r}")


class PerEventVerifier:
    """Selective, sampled, budget-bounded per-event dispatcher for the 4 verifiers.

    Default is SYNCHRONOUS: ``submit`` runs the verifier inline, bounded by the small
    per-artifact Z3 timeout (so it returns in ~timeout_ms). Because selection + sampling
    make candidates rare, that inline cost is small. For true async (verification off the
    ingestion path) pass a ``concurrent.futures.Executor`` -- it MUST be a
    ``ProcessPoolExecutor`` (Z3 is NOT thread-safe; a ThreadPoolExecutor corrupts the
    solver context). ``verify_one`` is module-level + returns picklable primitives for
    exactly that.
    """

    def __init__(self, config: Optional[PerEventConfig] = None,
                 executor: Optional[Executor] = None):
        self.cfg = config or PerEventConfig()
        self._executor = executor          # None -> synchronous
        self._verdicts: list[VerdictRecord] = []          # sync results awaiting drain
        self._pending: list[tuple[Future, str, str, str]] = []  # (fut, type, preview, agent)
        # counters (auditability of what was verified vs skipped)
        self.submitted = 0
        self.skipped_selection = 0
        self.skipped_sampling = 0

    # --- selection + sampling -------------------------------------------------

    def candidate(self, event: Any) -> Optional[dict]:
        """The event's formal_artifact dict if it is a verify candidate, else None.
        An artifact rides in ``event.metadata['formal_artifact'] =
        {'type','artifact','spec'?}`` -- the orchestrator (inject path) attaches it."""
        meta = getattr(event, "metadata", None) or {}
        fa = meta.get("formal_artifact")
        if not isinstance(fa, dict):
            return None
        if fa.get("type") not in self.cfg.enabled_types:
            return None
        if not fa.get("artifact"):
            return None
        return fa

    def _sampled_in(self, artifact: str) -> bool:
        if self.cfg.sample_rate >= 1.0:
            return True
        if self.cfg.sample_rate <= 0.0:
            return False
        h = int(hashlib.sha256(artifact.encode("utf-8", "replace")).hexdigest()[:8], 16)
        return (h % 1000) < int(round(self.cfg.sample_rate * 1000))

    # --- submit / drain -------------------------------------------------------

    def submit(self, event: Any) -> Optional[Future]:
        """Verify the event's artifact if it is a selected + sampled candidate.
        Synchronous mode: runs inline, stores the verdict for drain(), returns None.
        Async mode (executor set): returns the Future. Skipped events return None."""
        fa = self.candidate(event)
        if fa is None:
            self.skipped_selection += 1
            return None
        artifact = str(fa["artifact"])
        if not self._sampled_in(artifact):
            self.skipped_sampling += 1
            return None
        self.submitted += 1
        agent_id = getattr(event, "agent_id", "unknown")
        if self._executor is None:
            self._verdicts.append(
                verify_one(fa["type"], artifact, fa.get("spec"), agent_id, self.cfg.timeout_ms)
            )
            return None
        fut = self._executor.submit(
            verify_one, fa["type"], artifact, fa.get("spec"), agent_id, self.cfg.timeout_ms
        )
        self._pending.append((fut, fa["type"], artifact[:100], agent_id))
        return fut

    def drain(self, timeout: float = 5.0) -> list[VerdictRecord]:
        """Return all ready verdicts (sync results + async futures done within
        ``timeout`` s) and remove them. Still-pending async futures are LEFT pending
        (see pending_count), never dropped."""
        out = list(self._verdicts)
        self._verdicts.clear()
        if self._pending:
            _cf.wait([p[0] for p in self._pending], timeout=timeout)
            still: list[tuple[Future, str, str, str]] = []
            for fut, atype, preview, agent in self._pending:
                if fut.done():
                    try:
                        out.append(fut.result())
                    except Exception as e:
                        logger.warning("per-event verify future errored: %s", e)
                        out.append(VerdictRecord(
                            verdict=Verdict.ABSTAIN, artifact_type=atype,
                            artifact_preview=preview, agent_id=agent,
                            detail=f"executor error: {str(e)[:120]}",
                        ))
                else:
                    still.append((fut, atype, preview, agent))
            self._pending = still
        return out

    def pending_count(self) -> int:
        return sum(1 for f, *_ in self._pending if not f.done())
