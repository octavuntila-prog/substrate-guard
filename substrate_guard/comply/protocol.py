"""ZK-SNM Protocol — Orchestrates the four phases of semantic non-membership.

Phase 1: FINGERPRINT — Both parties agree on encoder, compute embeddings
Phase 2: COMMIT     — Provider commits to training data via Merkle tree
Phase 3: VERIFY     — Provider proves no committed doc is similar above τ
Phase 4: CERTIFY    — Generate compliance certificate with evidence

This implements the protocol from:
    "Attribution Without Disclosure" (DOI: 10.5281/zenodo.19185843)

Usage:
    protocol = ZKSNMProtocol()
    
    # Provider commits training data
    protocol.commit_training_data(["doc1...", "doc2...", "doc3..."])
    
    # Rights holder queries
    result = protocol.verify_document("Is my article in your training data?")
    
    # Generate compliance certificate
    cert = protocol.generate_certificate(result)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Optional
from pathlib import Path

import numpy as np

from .fingerprinter import SemanticFingerprinter, DEFAULT_THRESHOLD
from .commitment import TrainingDataCommitment
from .verifier import NonMembershipVerifier, VerificationResult

logger = logging.getLogger("substrate_guard.comply.protocol")


@dataclass
class ComplianceCertificate:
    """Certificate proving non-membership verification was performed."""
    protocol_version: str
    query_hash: str           # SHA-256 of the query document
    commitment_root: str      # Merkle root of training data
    threshold: float
    verdict: str              # "CLEAR" or "VIOLATION"
    max_similarity: float
    documents_checked: int
    encoder_model: str
    z3_confirmed: bool
    verification_backend: str
    timestamp: float
    certificate_hash: str     # Hash of all above fields

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))


class ZKSNMProtocol:
    """Full ZK-SNM protocol for training data compliance.
    
    Orchestrates all four phases:
    1. Fingerprint (encode documents with shared encoder)
    2. Commit (Merkle tree over training embeddings)
    3. Verify (check non-membership above threshold)
    4. Certify (generate compliance evidence)
    
    Args:
        model_name: sentence-transformers model (both parties must agree).
        threshold: Cosine similarity threshold for semantic membership.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        threshold: float = DEFAULT_THRESHOLD,
    ):
        self._fingerprinter = SemanticFingerprinter(model_name=model_name)
        self._threshold = threshold
        self._commitment: Optional[TrainingDataCommitment] = None
        self._verifier: Optional[NonMembershipVerifier] = None
        self._training_docs: int = 0

    # ── Phase 1: Fingerprint ──

    def fingerprint(self, document: str) -> np.ndarray:
        """Phase 1: Fingerprint a document using the agreed encoder."""
        return self._fingerprinter.fingerprint(document)

    def fingerprint_batch(self, documents: list[str]) -> np.ndarray:
        """Phase 1: Fingerprint multiple documents."""
        return self._fingerprinter.fingerprint_batch(documents)

    # ── Phase 2: Commit ──

    def commit_training_data(self, documents: list[str]) -> str:
        """Phase 2: Provider commits to training data.
        
        Fingerprints all documents and builds Merkle tree.
        Returns the public commitment root.
        """
        start = time.perf_counter()
        
        embeddings = self._fingerprinter.fingerprint_batch(documents)
        
        self._commitment = TrainingDataCommitment()
        self._commitment.add_embeddings_batch(embeddings)
        root = self._commitment.commit()
        
        self._verifier = NonMembershipVerifier(self._commitment, self._threshold)
        self._training_docs = len(documents)
        
        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            f"Phase 2 complete: {len(documents)} docs committed in {elapsed:.0f}ms, "
            f"root={root[:16]}..."
        )
        
        return root

    def commit_embeddings(self, embeddings: np.ndarray) -> str:
        """Phase 2 (alternative): Commit pre-computed embeddings."""
        self._commitment = TrainingDataCommitment()
        self._commitment.add_embeddings_batch(embeddings)
        root = self._commitment.commit()
        self._verifier = NonMembershipVerifier(self._commitment, self._threshold)
        self._training_docs = len(embeddings)
        return root

    # ── Phase 3: Verify ──

    def verify_document(self, document: str) -> VerificationResult:
        """Phase 3: Verify that a document is NOT in training data.
        
        Returns CLEAR if no training doc is similar above threshold.
        Returns VIOLATION if a similar document is found.
        """
        if not self._verifier:
            raise RuntimeError("Must commit training data before verification (Phase 2)")
        
        query_embedding = self._fingerprinter.fingerprint(document)
        return self._verifier.verify(query_embedding)

    def verify_embedding(self, query_embedding: np.ndarray) -> VerificationResult:
        """Phase 3 (alternative): Verify with pre-computed embedding."""
        if not self._verifier:
            raise RuntimeError("Must commit training data before verification")
        return self._verifier.verify(query_embedding)

    # ── Phase 4: Certify ──

    def generate_certificate(
        self,
        result: VerificationResult,
        query_document: Optional[str] = None,
    ) -> ComplianceCertificate:
        """Phase 4: Generate a compliance certificate.
        
        The certificate contains all evidence needed for audit:
        - What was queried (hash, not content)
        - What was committed (Merkle root)
        - What threshold was used
        - What the verdict was
        - Whether Z3 confirmed
        """
        query_hash = (
            hashlib.sha256(query_document.encode()).hexdigest()
            if query_document
            else "embedding-only"
        )
        
        # Build certificate
        cert_data = {
            "protocol_version": "ZK-SNM-1.0-prototype",
            "query_hash": query_hash,
            "commitment_root": result.commitment_root,
            "threshold": result.threshold,
            "verdict": "CLEAR" if not result.is_member else "VIOLATION",
            "max_similarity": result.max_similarity,
            "documents_checked": result.documents_checked,
            "encoder_model": self._fingerprinter.model_name,
            "z3_confirmed": result.z3_confirmed,
            "verification_backend": result.verification_backend,
            "timestamp": time.time(),
        }
        
        # Hash the certificate itself for integrity
        canonical = json.dumps(cert_data, sort_keys=True, default=str)
        cert_data["certificate_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        
        return ComplianceCertificate(**cert_data)

    # ── Status ──

    def status(self) -> dict:
        return {
            "encoder": self._fingerprinter.model_name,
            "threshold": self._threshold,
            "training_docs_committed": self._training_docs,
            "commitment_root": self._commitment.root[:16] + "..." if self._commitment and self._commitment.root else None,
            "ready": self._verifier is not None,
            "protocol_version": "ZK-SNM-1.0-prototype",
            "note": "Verification is real. ZK privacy layer requires Halo2/circom (future work).",
        }
