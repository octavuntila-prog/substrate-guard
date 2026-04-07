"""Semantic fingerprinter: deterministic (CI-friendly) or sentence-transformers (optional)."""

from __future__ import annotations

import hashlib
from typing import List

import numpy as np


class DeterministicFingerprinter:
    """384-dim L2-normalized embedding from SHA-256 expansion (no ML, reproducible)."""

    ENCODER = "deterministic-sha256-v1"
    DIMENSIONS = 384

    def fingerprint(self, document: str) -> np.ndarray:
        raw = np.empty(self.DIMENSIONS, dtype=np.float64)
        for i in range(self.DIMENSIONS):
            h = hashlib.sha256(f"{document}|{i}".encode()).digest()
            v = int.from_bytes(h[:4], "big") / (2**32) * 2.0 - 1.0
            raw[i] = v
        n = float(np.linalg.norm(raw))
        if n < 1e-12:
            out = np.ones(self.DIMENSIONS, dtype=np.float64) / np.sqrt(self.DIMENSIONS)
        else:
            out = raw / n
        return out.astype(np.float32)

    def fingerprint_batch(self, documents: List[str], batch_size: int = 32) -> np.ndarray:
        return np.stack([self.fingerprint(d) for d in documents], axis=0)

    def similarity(self, emb_a: np.ndarray, emb_b: np.ndarray) -> float:
        return float(np.dot(np.asarray(emb_a, dtype=np.float64), np.asarray(emb_b, dtype=np.float64)))

    def document_hash(self, document: str) -> str:
        return hashlib.sha256(document.encode("utf-8")).hexdigest()

    @property
    def protocol_id(self) -> str:
        return f"det:{self.ENCODER}:dim{self.DIMENSIONS}:l2norm"


class SemanticFingerprinter:
    """all-MiniLM-L6-v2 (384-dim) when sentence-transformers is installed."""

    ENCODER = "all-MiniLM-L6-v2"
    DIMENSIONS = 384

    def __init__(self, model_name: str | None = None):
        self._model_name = model_name or self.ENCODER
        self._model = None

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name)
        return self._model

    def fingerprint(self, document: str) -> np.ndarray:
        model = self._get_model()
        embedding = model.encode(document, normalize_embeddings=True)
        return np.asarray(embedding, dtype=np.float32)

    def fingerprint_batch(self, documents: List[str], batch_size: int = 32) -> np.ndarray:
        model = self._get_model()
        embeddings = model.encode(
            documents,
            normalize_embeddings=True,
            batch_size=batch_size,
            show_progress_bar=len(documents) > 100,
        )
        return np.asarray(embeddings, dtype=np.float32)

    def similarity(self, emb_a: np.ndarray, emb_b: np.ndarray) -> float:
        return float(np.dot(np.asarray(emb_a), np.asarray(emb_b)))

    def document_hash(self, document: str) -> str:
        return hashlib.sha256(document.encode("utf-8")).hexdigest()

    @property
    def protocol_id(self) -> str:
        return f"sbert:{self._model_name}:dim{self.DIMENSIONS}:normalized"
