"""Optional L4 wrapper: protected corpus + check AI output text."""

from __future__ import annotations

import logging
from typing import Any, List

from .protocol import ZKSNMProtocol

logger = logging.getLogger("substrate_guard.comply")


class ComplyGuard:
    """Attach ZK-SNM-style checks to a Guard instance (L1-L3)."""

    def __init__(self, guard: Any, config: dict | None = None) -> None:
        config = config or {}
        self.guard = guard
        self.protocol = ZKSNMProtocol(
            threshold=float(config.get("similarity_threshold", 0.85)),
            use_z3=bool(config.get("use_z3", True)),
        )
        self._protected_docs: List[str] = []
        self._committed = False

    def load_protected_content(self, documents: List[str]) -> dict[str, Any]:
        self._protected_docs = documents
        result = self.protocol.commit_training_data(documents)
        self._committed = True
        logger.info(
            "Committed %s protected documents, root=%s...",
            len(documents),
            result["commitment_root"][:16],
        )
        return result

    def check_compliance(self, ai_output: str) -> dict[str, Any]:
        if not self._committed:
            return {"checked": False, "reason": "no_protected_content_loaded"}
        return self.protocol.verify_non_membership(ai_output)

    def process_event(self, event: dict) -> dict[str, Any]:
        result = dict(event)
        output_text = event.get("output", event.get("content", ""))
        if output_text and self._committed:
            compliance = self.check_compliance(str(output_text))
            rdict = compliance.get("result", {})
            result["compliance"] = {
                "verified": rdict.get("verified"),
                "max_similarity": rdict.get("max_similarity"),
                "threshold": rdict.get("threshold"),
            }
        return result

    def status(self) -> dict[str, Any]:
        return {
            "protected_documents": len(self._protected_docs),
            "committed": self._committed,
            "commitment_root": (
                self.protocol.commitment.commit() if self._committed else None
            ),
            "threshold": self.protocol.verifier.threshold,
            "encoder": self.protocol.fingerprinter.protocol_id,
        }
