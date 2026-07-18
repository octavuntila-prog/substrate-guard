"""Non-membership check: no committed embedding has cosine similarity >= threshold."""

from __future__ import annotations

import time
from typing import Any, List

import numpy as np


class NonMembershipVerifier:
    """Compare query embedding against a list of committed (L2-normalized) embeddings."""

    def __init__(self, threshold: float = 0.85) -> None:
        self.threshold = threshold

    def verify(
        self,
        query_embedding: np.ndarray,
        committed_embeddings: List[np.ndarray],
        commitment_root: str | None = None,
    ) -> dict[str, Any]:
        _ = commitment_root
        start = time.perf_counter()
        q = np.asarray(query_embedding, dtype=np.float64)
        max_sim = -1.0
        max_idx = -1
        violations: list[dict[str, Any]] = []

        for i, emb in enumerate(committed_embeddings):
            e = np.asarray(emb, dtype=np.float64)
            sim = float(np.dot(q, e))
            if sim > max_sim:
                max_sim = sim
                max_idx = i
            if sim >= self.threshold:
                violations.append({"index": i, "similarity": round(sim, 6)})

        elapsed_ms = (time.perf_counter() - start) * 1000

        if violations:
            return {
                "verified": False,
                "reason": "similar_document_found",
                "violations": violations,
                "max_similarity": round(max_sim, 6),
                "max_index": max_idx,
                "threshold": self.threshold,
                "num_checked": len(committed_embeddings),
                "time_ms": round(elapsed_ms, 2),
                "backend": "numpy_cosine",
            }
        return {
            "verified": True,
            "reason": "no_similar_document",
            "max_similarity": round(max_sim, 6),
            "max_index": max_idx,
            "threshold": self.threshold,
            "num_checked": len(committed_embeddings),
            "time_ms": round(elapsed_ms, 2),
            "backend": "numpy_cosine",
        }

    # NOTE (audit 2026-07-17 item 2.A step 2): the former ``verify_with_z3`` was
    # removed. It re-evaluated the NumPy dot products as Z3 integer CONSTANTS
    # (``IntVal(dot) >= IntVal(thr)``, no free variables), so the solver could not
    # change the verdict decided by ``verify()`` -- decorative, not a proof. The
    # honest verifier is the single NumPy cosine pass above.
