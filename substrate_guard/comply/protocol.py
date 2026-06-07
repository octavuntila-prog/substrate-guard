"""Threshold semantic non-membership over a binding Merkle commitment.

Branded "ZK-SNM" but NOT zero-knowledge: the verifier operates on cleartext
embeddings (true ZK privacy would need a circuit backend — future work). Soundness
is threshold-heuristic and encoder-dependent, not a cryptographic non-membership
proof. See docs/AUDIT_COMPLEX_2026-06-07.md Part 3.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, List

from .commitment import EmbeddingCommitment
from .fingerprinter import DeterministicFingerprinter, SemanticFingerprinter
from .verifier import NonMembershipVerifier


class ZKSNMProtocol:
    """Fingerprint -> Merkle commit -> threshold non-membership check."""

    def __init__(
        self,
        threshold: float = 0.85,
        use_z3: bool = True,
        fingerprinter: DeterministicFingerprinter | SemanticFingerprinter | None = None,
    ) -> None:
        self.fingerprinter = fingerprinter or DeterministicFingerprinter()
        self.commitment = EmbeddingCommitment()
        self.verifier = NonMembershipVerifier(threshold=threshold)
        self.use_z3 = use_z3
        self._committed = False
        self._committed_root: str | None = None

    def commit_training_data(self, documents: List[str]) -> dict[str, Any]:
        embeddings = self.fingerprinter.fingerprint_batch(documents)
        for i in range(len(documents)):
            row = embeddings[i]
            dh = self.fingerprinter.document_hash(documents[i])
            self.commitment.add_embedding(row, doc_hash=dh)
        root = self.commitment.commit()
        self._committed = True
        self._committed_root = root
        return {
            "phase": "commit",
            "commitment_root": root,
            "num_documents": len(documents),
            "encoder": self.fingerprinter.protocol_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_non_membership(self, query_document: str) -> dict[str, Any]:
        if not self._committed:
            raise RuntimeError("No training data committed. Call commit_training_data first.")

        # Bind the verification to the committed corpus: the root recomputed from the
        # embeddings actually being checked must equal the published commitment root.
        # Otherwise a prover could commit corpus A, advertise its root, then verify
        # against a different (e.g. empty) embedding set. (Single-process prototype:
        # this binds at the API level, not against code mutating internals directly.)
        if self.commitment.commit() != self._committed_root:
            raise RuntimeError(
                "Commitment binding failed: the embeddings being verified do not "
                "match the published commitment root."
            )

        query_emb = self.fingerprinter.fingerprint(query_document)
        committed = self.commitment.embeddings

        if self.use_z3:
            result = self.verifier.verify_with_z3(query_emb, committed)
        else:
            result = self.verifier.verify(
                query_emb,
                committed,
                commitment_root=self.commitment.commit(),
            )

        certificate: dict[str, Any] = {
            "protocol": "ZK-SNM",
            "version": "0.1.0",
            "phase": "verify",
            "query_hash": self.fingerprinter.document_hash(query_document),
            "commitment_root": self.commitment.commit(),
            "encoder": self.fingerprinter.protocol_id,
            "threshold": self.verifier.threshold,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": (
                f"Threshold (cosine >= {self.verifier.threshold}) semantic "
                "non-membership over a binding Merkle commitment. NOT zero-knowledge: "
                "the verifier operates on cleartext embeddings (true ZK privacy needs "
                "a circuit backend, future work). The Z3 step is a redundant integer "
                "re-check, not an independent proof. certificate_hash is an unkeyed "
                "integrity checksum, not a tamper-proof MAC."
            ),
        }
        cert_hash = hashlib.sha256(
            json.dumps(certificate, sort_keys=True, default=str).encode()
        ).hexdigest()
        certificate["certificate_hash"] = cert_hash
        return certificate

    def verify_batch(self, query_documents: List[str]) -> dict[str, Any]:
        results = [self.verify_non_membership(d) for d in query_documents]
        verified_count = sum(1 for r in results if r["result"]["verified"])
        return {
            "summary": {
                "total_queries": len(results),
                "verified_non_member": verified_count,
                "violations_found": len(results) - verified_count,
                "commitment_root": self.commitment.commit(),
                "encoder": self.fingerprinter.protocol_id,
                "threshold": self.verifier.threshold,
            },
            "certificates": results,
        }
