"""Tests for Merkle commitment over embeddings."""

from __future__ import annotations

import numpy as np

from substrate_guard.comply.commitment import EmbeddingCommitment


def test_commit_single():
    c = EmbeddingCommitment()
    emb = np.random.RandomState(0).randn(384).astype(np.float32)
    emb = emb / np.linalg.norm(emb)
    c.add_embedding(emb)
    r = c.commit()
    assert len(r) == 64


def test_commit_multiple():
    c = EmbeddingCommitment()
    for i in range(4):
        e = np.zeros(384, dtype=np.float32)
        e[i] = 1.0
        c.add_embedding(e)
    root = c.commit()
    assert c.size == 4
    assert len(root) == 64


def test_merkle_root_deterministic():
    c1 = EmbeddingCommitment()
    c2 = EmbeddingCommitment()
    e = np.ones(384, dtype=np.float32) / np.sqrt(384.0)
    c1.add_embedding(e)
    c2.add_embedding(e)
    assert c1.commit() == c2.commit()


def test_different_data_different_root():
    c1 = EmbeddingCommitment()
    c2 = EmbeddingCommitment()
    e1 = np.zeros(384, dtype=np.float32)
    e1[0] = 1.0
    e2 = np.zeros(384, dtype=np.float32)
    e2[1] = 1.0
    c1.add_embedding(e1)
    c2.add_embedding(e2)
    assert c1.commit() != c2.commit()


def test_proof_of_inclusion_roundtrip():
    c = EmbeddingCommitment()
    rng = np.random.RandomState(42)
    for _ in range(3):
        e = rng.randn(384).astype(np.float32)
        e = e / np.linalg.norm(e)
        c.add_embedding(e)
    root = c.commit()
    for i in range(3):
        proof = c.proof_of_inclusion(i)
        ok = EmbeddingCommitment.verify_inclusion_proof(
            proof["leaf_hash"],
            proof["path"],
            proof["root"],
            proof["leaf_index"],
            proof["leaf_count"],
        )
        assert ok, f"index {i}"
        assert proof["root"] == root
        # Wrong leaf count must be rejected (the count is bound into the root).
        bad = EmbeddingCommitment.verify_inclusion_proof(
            proof["leaf_hash"], proof["path"], proof["root"],
            proof["leaf_index"], proof["leaf_count"] + 1,
        )
        assert not bad, f"wrong-count proof accepted at index {i}"


def test_empty_commitment():
    c = EmbeddingCommitment()
    assert c.commit() == __import__("hashlib").sha256(b"empty").hexdigest()


def test_summary():
    c = EmbeddingCommitment()
    e = np.ones(384, dtype=np.float32) / 20.0
    c.add_embedding(e)
    c.commit()
    s = c.summary()
    assert s["num_documents"] == 1
    assert "root" in s


def test_leaf_count_bound_into_root():
    """A 3-doc corpus and a 4-doc corpus whose 4th doc duplicates the 3rd must NOT
    share a root. Before domain-separation + count-binding they collided (odd-leaf
    duplication, line 55). Confirmed-critical in docs/AUDIT_COMPLEX_2026-06-07.md."""
    e0 = np.zeros(384, dtype=np.float32); e0[0] = 1.0
    e1 = np.zeros(384, dtype=np.float32); e1[1] = 1.0
    e2 = np.zeros(384, dtype=np.float32); e2[2] = 1.0

    c3 = EmbeddingCommitment()
    for e in (e0, e1, e2):
        c3.add_embedding(e)
    c4 = EmbeddingCommitment()
    for e in (e0, e1, e2, e2):  # 4th duplicates the 3rd
        c4.add_embedding(e)

    assert c3.commit() != c4.commit(), "different corpus sizes must not share a root"


def test_single_leaf_root_differs_from_leaf():
    """A 1-leaf root must differ from the leaf hash, so an empty-path 'proof' of the
    root value is not accepted as inclusion."""
    e = np.zeros(384, dtype=np.float32); e[0] = 1.0
    c = EmbeddingCommitment()
    c.add_embedding(e)
    root = c.commit()
    assert root != c.leaves[0]
    # empty-path proof of the root value must fail
    assert not EmbeddingCommitment.verify_inclusion_proof(root, [], root, 0, 1)
