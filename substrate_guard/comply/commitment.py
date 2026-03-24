"""Training Data Commitment — Merkle tree over embedding hashes.

The model provider commits to their training data embeddings via a
Merkle tree. The root is public; individual embeddings remain private.
This is binding (cannot change data after commitment) and hiding
(commitment reveals nothing about underlying embeddings).

This is Phase 2 of the ZK-SNM protocol.

Usage:
    commitment = TrainingDataCommitment()
    commitment.add_embedding(embedding1)
    commitment.add_embedding(embedding2)
    root = commitment.commit()
    
    # Later: prove non-membership
    path = commitment.get_proof_path(leaf_index)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import numpy as np
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("substrate_guard.comply.commitment")


@dataclass
class MerkleProof:
    """A Merkle inclusion/exclusion proof."""
    leaf_hash: str
    leaf_index: int
    path: list[tuple[str, str]]  # [(hash, "left"|"right"), ...]
    root: str

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash,
            "leaf_index": self.leaf_index,
            "path": self.path,
            "root": self.root,
        }


class TrainingDataCommitment:
    """Merkle tree commitment over training data embeddings.
    
    Each training document is fingerprinted (by SemanticFingerprinter),
    then its embedding hash becomes a leaf in the Merkle tree.
    The root hash is the public commitment.
    
    Args:
        hash_fn: Hash function for tree nodes (default SHA-256).
    """

    def __init__(self):
        self._leaves: list[str] = []  # SHA-256 hashes of embeddings
        self._embeddings: list[np.ndarray] = []  # Raw embeddings (private)
        self._tree: list[list[str]] = []  # Full Merkle tree
        self._committed = False
        self._root: Optional[str] = None

    def add_embedding(self, embedding: np.ndarray):
        """Add a training document embedding to the commitment."""
        if self._committed:
            raise RuntimeError("Cannot add after commitment — tree is sealed")
        
        leaf_hash = hashlib.sha256(embedding.tobytes()).hexdigest()
        self._leaves.append(leaf_hash)
        self._embeddings.append(embedding.copy())

    def add_embeddings_batch(self, embeddings: np.ndarray):
        """Add multiple embeddings at once."""
        for emb in embeddings:
            self.add_embedding(emb)

    def commit(self) -> str:
        """Build Merkle tree and return root hash.
        
        After commit(), no more embeddings can be added.
        """
        if not self._leaves:
            raise ValueError("No embeddings to commit")
        
        self._tree = self._build_tree(self._leaves)
        self._root = self._tree[-1][0]
        self._committed = True
        
        logger.info(
            f"Committed {len(self._leaves)} embeddings, "
            f"root={self._root[:16]}..."
        )
        return self._root

    def _build_tree(self, leaves: list[str]) -> list[list[str]]:
        """Build a full binary Merkle tree from leaves."""
        # Pad to power of 2
        n = len(leaves)
        next_pow2 = 1
        while next_pow2 < n:
            next_pow2 *= 2
        
        padded = leaves + [hashlib.sha256(b"empty").hexdigest()] * (next_pow2 - n)
        
        tree = [padded]
        current = padded
        
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                combined = current[i] + current[i + 1]
                parent = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(parent)
            tree.append(next_level)
            current = next_level
        
        return tree

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """Get a Merkle proof for a specific leaf."""
        if not self._committed:
            raise RuntimeError("Must commit before generating proofs")
        if leaf_index >= len(self._leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")
        
        path = []
        idx = leaf_index
        
        for level in self._tree[:-1]:
            if idx % 2 == 0:
                sibling = level[idx + 1] if idx + 1 < len(level) else level[idx]
                path.append((sibling, "right"))
            else:
                sibling = level[idx - 1]
                path.append((sibling, "left"))
            idx //= 2
        
        return MerkleProof(
            leaf_hash=self._leaves[leaf_index],
            leaf_index=leaf_index,
            path=path,
            root=self._root,
        )

    @staticmethod
    def verify_proof(proof: MerkleProof) -> bool:
        """Verify a Merkle proof against its claimed root."""
        current = proof.leaf_hash
        
        for sibling_hash, direction in proof.path:
            if direction == "left":
                combined = sibling_hash + current
            else:
                combined = current + sibling_hash
            current = hashlib.sha256(combined.encode()).hexdigest()
        
        return current == proof.root

    def get_embedding(self, index: int) -> np.ndarray:
        """Get a stored embedding by index (private operation)."""
        return self._embeddings[index].copy()

    @property
    def root(self) -> Optional[str]:
        return self._root

    @property
    def size(self) -> int:
        return len(self._leaves)

    @property
    def committed(self) -> bool:
        return self._committed

    def summary(self) -> dict:
        return {
            "documents": len(self._leaves),
            "committed": self._committed,
            "root": self._root[:16] + "..." if self._root else None,
            "tree_depth": len(self._tree) if self._tree else 0,
        }
