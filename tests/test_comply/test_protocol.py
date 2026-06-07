"""End-to-end protocol tests (deterministic encoder)."""

from __future__ import annotations

import pytest

from substrate_guard.comply.fingerprinter import DeterministicFingerprinter
from substrate_guard.comply.protocol import ZKSNMProtocol


def test_full_protocol_member_detected():
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=False, fingerprinter=fp)
    secret = "unique-protected-line-aaa"
    p.commit_training_data([secret, "other-bbb"])
    cert = p.verify_non_membership(secret)
    assert cert["result"]["verified"] is False
    assert cert["certificate_hash"]
    assert cert["commitment_root"]


def test_full_protocol_non_member():
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=False, fingerprinter=fp)
    p.commit_training_data(["corpus-one-xyz", "corpus-two-abc"])
    cert = p.verify_non_membership("query-not-in-corpus-789012345")
    assert cert["result"]["verified"] is True


def test_batch_verification():
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=False, fingerprinter=fp)
    p.commit_training_data(["only-one-doc"])
    out = p.verify_batch(["only-one-doc", "unrelated-query-zz"])
    assert out["summary"]["total_queries"] == 2
    assert out["summary"]["violations_found"] >= 1


def test_uncommitted_raises():
    p = ZKSNMProtocol(use_z3=False)
    with pytest.raises(RuntimeError, match="commit"):
        p.verify_non_membership("x")


def test_certificate_has_timestamp():
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(use_z3=False, fingerprinter=fp)
    p.commit_training_data(["a"])
    cert = p.verify_non_membership("b")
    assert "T" in cert["timestamp"] or "-" in cert["timestamp"]


def test_protocol_with_z3():
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=True, fingerprinter=fp)
    p.commit_training_data(["x1", "x2"])
    cert = p.verify_non_membership("y-unrelated")
    assert "result" in cert
    res = cert["result"]
    assert "z3_confirmed" in res or res.get("z3_skipped") is True


def test_commitment_binding_detects_corpus_swap():
    """verify_non_membership must reject when the embeddings being checked no longer
    match the committed root (a prover advertising corpus A's root but verifying a
    different set). Confirmed-critical in docs/AUDIT_COMPLEX_2026-06-07.md Part 3."""
    import numpy as np

    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(threshold=0.85, use_z3=False, fingerprinter=fp)
    p.commit_training_data(["corpus-A-doc1", "corpus-A-doc2"])
    # Tamper: change the committed embedding set after commit (resets the cached root).
    p.commitment.add_embedding(np.zeros(384, dtype=np.float32))
    with pytest.raises(RuntimeError, match="binding"):
        p.verify_non_membership("any-query")


def test_certificate_keyed_mac():
    """With an hmac_key the certificate hash is a tamper-evident keyed MAC."""
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(use_z3=False, fingerprinter=fp, hmac_key="secret-key")
    p.commit_training_data(["doc-a"])
    cert = p.verify_non_membership("query-b")
    assert cert["certificate_hash_alg"] == "HMAC-SHA256"
    assert len(cert["certificate_hash"]) == 64


def test_certificate_unkeyed_checksum_labeled():
    """Without a key the hash is honestly labeled an unkeyed checksum."""
    fp = DeterministicFingerprinter()
    p = ZKSNMProtocol(use_z3=False, fingerprinter=fp)
    p.commit_training_data(["doc-a"])
    cert = p.verify_non_membership("query-b")
    assert "unkeyed" in cert["certificate_hash_alg"].lower()
