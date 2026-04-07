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

    def verify_with_z3(
        self,
        query_embedding: np.ndarray,
        committed_embeddings: List[np.ndarray],
    ) -> dict[str, Any]:
        """Re-check dot(query, emb) < threshold using Z3 on scaled integers (constants only)."""
        numpy_result = self.verify(query_embedding, committed_embeddings)
        try:
            import z3
        except ImportError:
            return {**numpy_result, "z3_skipped": True, "backend": numpy_result["backend"]}

        start = time.perf_counter()
        q = np.asarray(query_embedding, dtype=np.float64)
        SCALE = 10_000
        q_s = [int(round(float(x) * SCALE)) for x in q]
        thr = int(round(self.threshold * SCALE * SCALE))

        z3_sat_violations: list[int] = []
        for i, emb in enumerate(committed_embeddings):
            e = np.asarray(emb, dtype=np.float64)
            e_s = [int(round(float(x) * SCALE)) for x in e]
            dot = sum(a * b for a, b in zip(q_s, e_s))
            sol = z3.Solver()
            sol.add(z3.IntVal(dot) >= z3.IntVal(thr))
            if sol.check() == z3.sat:
                z3_sat_violations.append(i)

        extra_ms = (time.perf_counter() - start) * 1000
        z3_matches_numpy = (len(z3_sat_violations) > 0) == (not numpy_result["verified"])
        return {
            **numpy_result,
            "z3_violation_indices": z3_sat_violations,
            "z3_confirmed": z3_matches_numpy and len(z3_sat_violations) == len(
                numpy_result.get("violations", [])
            ),
            "backend": "numpy_cosine+z3_int",
            "time_ms": round(numpy_result["time_ms"] + extra_ms, 2),
        }
