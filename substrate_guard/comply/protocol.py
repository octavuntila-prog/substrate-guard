"""ZK-SNM-style protocol: commit corpus embeddings, verify query non-membership."""

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

    def commit_training_data(self, documents: List[str]) -> dict[str, Any]:
        embeddings = self.fingerprinter.fingerprint_batch(documents)
        for i in range(len(documents)):
            row = embeddings[i]
            dh = self.fingerprinter.document_hash(documents[i])
            self.commitment.add_embedding(row, doc_hash=dh)
        root = self.commitment.commit()
        self._committed = True
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
                "Verification: numpy cosine + optional Z3 integer check. "
                "True ZK privacy would need a circuit backend (future work)."
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
