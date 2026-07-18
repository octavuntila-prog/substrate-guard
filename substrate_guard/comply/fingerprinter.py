"""Semantic fingerprinter: deterministic (CI-friendly) or sentence-transformers (optional)."""

from __future__ import annotations

import hashlib
import importlib.util
import logging
from typing import List, Union

import numpy as np

logger = logging.getLogger("substrate_guard.comply")


class DeterministicFingerprinter:
    """384-dim L2-normalized embedding from SHA-256 expansion (no ML, reproducible).

    NON-SEMANTIC: the embedding is a hash of the EXACT document string, so it detects
    only byte-exact duplicates -- two semantically similar but textually different
    documents get unrelated embeddings (cosine ~0). The "semantic non-membership"
    guarantee is therefore VACUOUS under this default encoder; use SemanticFingerprinter
    (sentence-transformers) for real semantic matching.
    """

    ENCODER = "deterministic-sha256-v1"
    DIMENSIONS = 384
    is_semantic = False

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
    is_semantic = True

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


def sentence_transformers_available() -> bool:
    """True if the optional sentence-transformers backend can be imported (cheap
    spec check -- does NOT load the model)."""
    return importlib.util.find_spec("sentence_transformers") is not None


def default_fingerprinter() -> Union["SemanticFingerprinter", "DeterministicFingerprinter"]:
    """The default encoder (audit 2026-07-17 item 2.A step 3).

    Real semantic matching (all-MiniLM-L6-v2) when sentence-transformers is
    installed -- the "activated" configuration where the `semantic` guarantee is
    genuine; otherwise the deterministic byte-exact fallback, whose certificates
    honestly report ``semantic=False``. This makes the default meaningful when the
    ML extra is present without forcing a heavy dependency on the base install.
    """
    if sentence_transformers_available():
        return SemanticFingerprinter()
    logger.info(
        "sentence-transformers not installed; L4 default encoder is the "
        "deterministic byte-exact fallback (certificates report semantic=False). "
        "Install .[comply-ml] for real semantic non-membership."
    )
    return DeterministicFingerprinter()
