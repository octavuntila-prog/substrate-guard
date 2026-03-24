"""Comply Guard — Wraps Guard with Layer 4 copyright compliance checking.

Checks if AI agent outputs are too similar to protected content.
When an agent generates text, ComplyGuard verifies it doesn't
semantically match any document in the protected corpus above τ.

Usage:
    guard = ComplyGuard(
        protected_documents=["NYT article 1...", "NYT article 2..."],
        observe=True, policy="policies/", verify=True,
    )
    
    result = guard.check_output("Agent generated this text...")
    if result.is_compliant:
        print("Output is clear")
    else:
        print(f"Output too similar to protected doc {result.closest_index}")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ..guard import Guard, GuardEvent
from ..observe.events import Event
from .protocol import ZKSNMProtocol, ComplianceCertificate
from .verifier import VerificationResult
from .fingerprinter import DEFAULT_THRESHOLD

logger = logging.getLogger("substrate_guard.comply.guard")


@dataclass
class ComplianceCheckResult:
    """Result of a compliance check on an AI output."""
    is_compliant: bool          # True if output is clear
    guard_event: Optional[GuardEvent]  # L1-L3 result
    verification: Optional[VerificationResult]  # L4 result
    certificate: Optional[ComplianceCertificate]  # Compliance cert

    def to_dict(self) -> dict:
        return {
            "is_compliant": self.is_compliant,
            "verification": self.verification.to_dict() if self.verification else None,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


class ComplyGuard:
    """Guard with Layer 4 copyright compliance verification.
    
    Extends the standard Guard pipeline with semantic non-membership
    checking against a corpus of protected documents.
    
    The compliance check works on agent OUTPUT text — verifying that
    what the agent produced doesn't semantically match protected content.
    
    Args:
        protected_documents: List of protected texts to check against.
        protected_embeddings: Pre-computed embeddings (alternative).
        threshold: Cosine similarity threshold (default 0.85).
        model_name: sentence-transformers model.
        **guard_kwargs: Passed to Guard constructor.
    """

    def __init__(
        self,
        protected_documents: Optional[list[str]] = None,
        protected_embeddings: Optional[np.ndarray] = None,
        threshold: float = DEFAULT_THRESHOLD,
        model_name: str = "all-MiniLM-L6-v2",
        **guard_kwargs,
    ):
        # Core Guard (L1 + L2 + L3)
        self._guard = Guard(**guard_kwargs)
        
        # L4: ZK-SNM Protocol
        self._protocol = ZKSNMProtocol(
            model_name=model_name,
            threshold=threshold,
        )
        
        # Commit protected corpus
        if protected_documents:
            self._protocol.commit_training_data(protected_documents)
            self._corpus_size = len(protected_documents)
        elif protected_embeddings is not None:
            self._protocol.commit_embeddings(protected_embeddings)
            self._corpus_size = len(protected_embeddings)
        else:
            self._corpus_size = 0
            logger.warning("ComplyGuard initialized without protected corpus — compliance checks disabled")
        
        self._checks_performed = 0
        self._violations_found = 0

    def check_output(self, output_text: str) -> ComplianceCheckResult:
        """Check if an AI-generated output complies with copyright.
        
        Verifies the output text against the protected corpus.
        Returns COMPLIANT if no protected document is similar above τ.
        """
        if self._corpus_size == 0:
            return ComplianceCheckResult(
                is_compliant=True, guard_event=None,
                verification=None, certificate=None,
            )
        
        # Phase 3: Verify
        result = self._protocol.verify_document(output_text)
        
        # Phase 4: Certify
        cert = self._protocol.generate_certificate(result, query_document=output_text)
        
        self._checks_performed += 1
        if result.is_member:
            self._violations_found += 1
        
        return ComplianceCheckResult(
            is_compliant=not result.is_member,
            guard_event=None,
            verification=result,
            certificate=cert,
        )

    def evaluate_event(self, event: Event) -> GuardEvent:
        """Standard Guard evaluation (L1-L3). L4 is via check_output()."""
        return self._guard.evaluate_event(event)

    def monitor(self, agent_id: str):
        """Delegate to Guard's monitor."""
        return self._guard.monitor(agent_id)

    def compliance_status(self) -> dict:
        return {
            "protocol": self._protocol.status(),
            "checks_performed": self._checks_performed,
            "violations_found": self._violations_found,
            "corpus_size": self._corpus_size,
        }

    @property
    def guard(self) -> Guard:
        return self._guard

    @property
    def protocol(self) -> ZKSNMProtocol:
        return self._protocol
