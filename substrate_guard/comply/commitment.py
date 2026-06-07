"""Merkle commitment over embedding fingerprints (public root, private leaves)."""

from __future__ import annotations

import hashlib
from typing import List, Optional

import numpy as np


# Domain-separation tags (RFC 6962 style): leaves, internal nodes, and the final
# count-bound root live in DISJOINT hash spaces, so an internal-node value can never
# be a valid leaf and two corpora of different sizes cannot share a root.
_LEAF_TAG = b"\x00"
_NODE_TAG = b"\x01"
_ROOT_TAG = b"\x02"


def _leaf_hash(embedding: np.ndarray, doc_hash: str = "") -> str:
    leaf_data = np.asarray(embedding, dtype=np.float32).tobytes()
    if doc_hash:
        leaf_data += doc_hash.encode()
    return hashlib.sha256(_LEAF_TAG + leaf_data).hexdigest()


def _pair_hash(left: str, right: str) -> str:
    # Tagged node hash over the raw 32-byte child digests (unambiguous framing,
    # disjoint from the 0x00 leaf space).
    return hashlib.sha256(_NODE_TAG + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _commit_root(tree_root: str, leaf_count: int) -> str:
    # Bind the leaf count into the published root: two corpora of different sizes
    # (e.g. via odd-leaf duplication) can no longer hash to the same root, and a
    # single leaf's root differs from the leaf itself.
    return hashlib.sha256(
        _ROOT_TAG + leaf_count.to_bytes(8, "big") + bytes.fromhex(tree_root)
    ).hexdigest()


class EmbeddingCommitment:
    """Binary Merkle tree over leaf hashes of embeddings."""

    def __init__(self) -> None:
        self.leaves: List[str] = []
        self.embeddings: List[np.ndarray] = []
        self._root: Optional[str] = None
        self._levels: List[List[str]] = []

    def add_embedding(self, embedding: np.ndarray, doc_hash: str = "") -> None:
        self.leaves.append(_leaf_hash(embedding, doc_hash))
        self.embeddings.append(np.asarray(embedding, dtype=np.float32).copy())
        self._root = None
        self._levels = []

    def add_batch(self, embeddings: np.ndarray) -> None:
        for emb in embeddings:
            self.add_embedding(np.asarray(emb))

    def commit(self) -> str:
        if self._root is not None:
            return self._root
        if not self.leaves:
            self._root = hashlib.sha256(b"empty").hexdigest()
            self._levels = []
            return self._root

        current = list(self.leaves)
        self._levels = [current]
        while len(current) > 1:
            nxt: List[str] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                nxt.append(_pair_hash(left, right))
            self._levels.append(nxt)
            current = nxt
        # Bind the leaf count into the published root.
        self._root = _commit_root(current[0], len(self.leaves))
        return self._root

    def proof_of_inclusion(self, index: int) -> dict:
        if not self.leaves:
            raise IndexError("empty commitment")
        if index < 0 or index >= len(self.leaves):
            raise IndexError(index)
        if not self._levels:
            self.commit()

        path: list[dict[str, str]] = []
        idx = index
        for lev in range(len(self._levels) - 1):
            level = self._levels[lev]
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
            else:
                sibling_idx = idx - 1
            path.append({"sibling": level[sibling_idx], "leaf_idx": str(idx)})
            idx //= 2

        return {
            "leaf_index": index,
            "leaf_hash": self.leaves[index],
            "leaf_count": len(self.leaves),
            "root": self._root,
            "path": path,
        }

    @staticmethod
    def verify_inclusion_proof(
        leaf_hash: str,
        path: list[dict[str, str]],
        root: str,
        leaf_start_idx: int,
        leaf_count: int,
    ) -> bool:
        """Recompute the tree root from the leaf hash and sibling path (bottom-up),
        bind the leaf count, and compare to the published root.

        Contract: ``leaf_hash`` MUST be a genuine leaf digest produced by
        ``_leaf_hash`` (tagged 0x00). Internal-node digests are tagged 0x01 and live
        in a disjoint space, so callers verifying document membership must derive
        ``leaf_hash`` from the document's embedding — never pass an arbitrary hash.
        Returns False on malformed input rather than raising.
        """
        try:
            cur = leaf_hash
            idx = leaf_start_idx
            for step in path:
                sib = step["sibling"]
                if idx % 2 == 0:
                    cur = _pair_hash(cur, sib)
                else:
                    cur = _pair_hash(sib, cur)
                idx //= 2
            return _commit_root(cur, leaf_count) == root
        except (ValueError, KeyError, TypeError):
            return False

    @property
    def size(self) -> int:
        return len(self.leaves)

    def summary(self) -> dict:
        return {
            "root": self.commit(),
            "num_documents": self.size,
            "tree_depth": len(self._levels) if self._levels else 0,
        }
