"""Semantic Fingerprinter — Document → embedding vector.

Uses sentence-transformers (all-MiniLM-L6-v2) to create semantic
embeddings that are robust to paraphrasing, reformatting, and
partial extraction. Two documents with similar meaning produce
similar vectors, even if the exact words differ.

This is Phase 1 of the ZK-SNM protocol described in:
    "Attribution Without Disclosure" (DOI: 10.5281/zenodo.19185843)

Usage:
    fp = SemanticFingerprinter()
    e1 = fp.fingerprint("The cat sat on the mat")
    e2 = fp.fingerprint("A feline rested on the rug")
    sim = fp.similarity(e1, e2)  # ~0.75
    
    # Batch fingerprinting
    embeddings = fp.fingerprint_batch(["doc1...", "doc2...", "doc3..."])
"""

from __future__ import annotations

import hashlib
import json
import logging
import numpy as np
from typing import Optional, Union

logger = logging.getLogger("substrate_guard.comply.fingerprinter")

DEFAULT_MODEL = "all-MiniLM-L6-v2"
DEFAULT_THRESHOLD = 0.85


class SemanticFingerprinter:
    """Semantic document fingerprinter using sentence-transformers.
    
    Encodes documents into normalized embedding vectors. Cosine similarity
    between two embeddings measures semantic similarity:
    - > 0.85: very likely same content (paraphrase)
    - 0.70-0.85: topically related
    - < 0.50: unrelated
    
    Args:
        model_name: sentence-transformers model identifier.
        device: "cpu", "cuda", or None for auto-detect.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL, device: Optional[str] = None):
        self._model_name = model_name
        self._dimension = None
        self._model = None
        self._device = device
        
        # Lazy load — model is ~90MB
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy-load the model on first use."""
        if self._loaded:
            return
        
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name, device=self._device)
            self._dimension = self._model.get_sentence_embedding_dimension()
            self._loaded = True
            logger.info(f"SemanticFingerprinter loaded: {self._model_name} (dim={self._dimension})")
        except ImportError:
            raise ImportError(
                "sentence-transformers required for Layer 4. "
                "Install: pip install sentence-transformers"
            )

    def fingerprint(self, document: str) -> np.ndarray:
        """Generate a normalized semantic embedding for a document.
        
        Args:
            document: Text content to fingerprint.
            
        Returns:
            Normalized float32 vector of shape (dimension,).
        """
        self._ensure_loaded()
        embedding = self._model.encode(
            document,
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        return embedding.astype(np.float32)

    def fingerprint_batch(self, documents: list[str], batch_size: int = 32) -> np.ndarray:
        """Fingerprint multiple documents efficiently.
        
        Returns:
            Array of shape (n_documents, dimension).
        """
        self._ensure_loaded()
        embeddings = self._model.encode(
            documents,
            normalize_embeddings=True,
            batch_size=batch_size,
            show_progress_bar=False,
        )
        return embeddings.astype(np.float32)

    @staticmethod
    def similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Cosine similarity between two normalized embeddings.
        
        Since embeddings are L2-normalized, cosine similarity = dot product.
        """
        return float(np.dot(a, b))

    @staticmethod
    def similarity_matrix(query: np.ndarray, corpus: np.ndarray) -> np.ndarray:
        """Similarity between a query and all corpus embeddings.
        
        Args:
            query: Single embedding of shape (dimension,).
            corpus: Array of shape (n_documents, dimension).
            
        Returns:
            Array of shape (n_documents,) with similarities.
        """
        return corpus @ query

    @staticmethod
    def embedding_hash(embedding: np.ndarray) -> str:
        """SHA-256 hash of an embedding for Merkle tree leaves."""
        return hashlib.sha256(embedding.tobytes()).hexdigest()

    @property
    def dimension(self) -> int:
        self._ensure_loaded()
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model_name

    def info(self) -> dict:
        return {
            "model": self._model_name,
            "dimension": self._dimension or "not loaded",
            "loaded": self._loaded,
            "default_threshold": DEFAULT_THRESHOLD,
        }
