"""Threshold semantic non-membership over a binding Merkle commitment.

Branded "ZK-SNM" but NOT zero-knowledge: the verifier operates on cleartext
embeddings (true ZK privacy would need a circuit backend — future work). Soundness
is threshold-heuristic and encoder-dependent, not a cryptographic non-membership
proof. See docs/AUDIT_COMPLEX_2026-06-07.md Part 3.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, List

from .commitment import EmbeddingCommitment
from .fingerprinter import (
    DeterministicFingerprinter,
    SemanticFingerprinter,
    default_fingerprinter,
)
from .verifier import NonMembershipVerifier


class ThresholdNonMembershipProtocol:
    """Fingerprint -> Merkle commit -> threshold non-membership check.

    Renamed from ``ZKSNMProtocol`` (2026-07-18): the honest name matches what the
    code does — threshold non-membership over a Merkle commitment. "ZK-SNM" is the
    paper-era brand (see the module docstring); a backward-compat alias remains at
    the bottom of this module, and the ``protocol`` field in emitted certificates
    keeps the wire identifier ``"ZK-SNM"`` (changing it would alter every
    certificate hash)."""

    def __init__(
        self,
        threshold: float = 0.85,
        fingerprinter: DeterministicFingerprinter | SemanticFingerprinter | None = None,
        hmac_key: str | None = None,
        use_z3: bool | None = None,
    ) -> None:
        # use_z3 is DEPRECATED and a no-op (2026-07-18, audit item 2.A step 2): the
        # former Z3 step re-evaluated the NumPy dot products as integer CONSTANTS
        # (no free variables), so it could never change the verdict -- decorative,
        # not a proof. Kept only so existing callers don't crash; passing it warns.
        if use_z3 is not None:
            import warnings

            warnings.warn(
                "ThresholdNonMembershipProtocol(use_z3=...) is deprecated and ignored; "
                "the decorative Z3 re-check was removed (it added no soundness).",
                DeprecationWarning,
                stacklevel=2,
            )
        # Default encoder = real semantic (sentence-transformers) when installed,
        # else the deterministic byte-exact fallback (certificates report the truth
        # via the `semantic` field). Explicit fingerprinter always wins.
        self.fingerprinter = fingerprinter or default_fingerprinter()
        self.commitment = EmbeddingCommitment()
        self.verifier = NonMembershipVerifier(threshold=threshold)
        self._hmac_key = hmac_key.encode() if hmac_key else None
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

        result = self.verifier.verify(
            query_emb,
            committed,
            commitment_root=self.commitment.commit(),
        )

        certificate: dict[str, Any] = {
            # Stable WIRE identifier (kept through the 2026-07-18 class rename:
            # certificates are hashed/HMAC'd, so this string must not drift).
            "protocol": "ZK-SNM",
            "version": "0.1.0",
            "phase": "verify",
            "query_hash": self.fingerprinter.document_hash(query_document),
            "commitment_root": self.commitment.commit(),
            "encoder": self.fingerprinter.protocol_id,
            "semantic": bool(getattr(self.fingerprinter, "is_semantic", False)),
            "threshold": self.verifier.threshold,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "note": (
                f"Threshold (cosine >= {self.verifier.threshold}) non-membership over "
                "a binding Merkle commitment. The `semantic` field reflects the encoder: "
                "True for the sentence-transformers encoder (real semantic matching), "
                "False for the deterministic byte-exact fallback (the 'semantic' "
                "guarantee is then vacuous). NOT zero-knowledge: the verifier operates "
                "on cleartext embeddings (true ZK privacy needs a circuit backend, "
                "future work). certificate_hash is an unkeyed checksum unless an "
                "hmac_key is configured (then a keyed HMAC MAC)."
            ),
        }
        cert_bytes = json.dumps(certificate, sort_keys=True, default=str).encode()
        if self._hmac_key is not None:
            # Keyed MAC: tamper-evident (only a holder of the key can recompute it).
            certificate["certificate_hash"] = hmac.new(
                self._hmac_key, cert_bytes, hashlib.sha256
            ).hexdigest()
            certificate["certificate_hash_alg"] = "HMAC-SHA256"
        else:
            # Unkeyed integrity checksum: NOT tamper-proof (anyone can recompute it).
            certificate["certificate_hash"] = hashlib.sha256(cert_bytes).hexdigest()
            certificate["certificate_hash_alg"] = "SHA256 (unkeyed checksum)"
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


# Backward-compat alias: paper-era brand name ("ZK Proofs of Semantic
# Non-Membership", Zenodo 10.5281/zenodo.19185843). Prefer the honest name above.
ZKSNMProtocol = ThresholdNonMembershipProtocol
