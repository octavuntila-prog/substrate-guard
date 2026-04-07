"""Tests for deterministic and optional SBERT fingerprinters."""

from __future__ import annotations

import numpy as np
import pytest

from substrate_guard.comply.fingerprinter import DeterministicFingerprinter, SemanticFingerprinter


def test_fingerprint_returns_384_dim():
    fp = DeterministicFingerprinter()
    e = fp.fingerprint("hello world")
    assert e.shape == (384,)


def test_fingerprint_is_normalized():
    fp = DeterministicFingerprinter()
    e = fp.fingerprint("norm check")
    n = float(np.linalg.norm(e))
    assert abs(n - 1.0) < 1e-4


def test_same_doc_identical():
    fp = DeterministicFingerprinter()
    a = fp.fingerprint("stable text")
    b = fp.fingerprint("stable text")
    assert np.allclose(a, b)


def test_different_docs_not_identical():
    fp = DeterministicFingerprinter()
    a = fp.fingerprint("aaaa")
    b = fp.fingerprint("bbbb")
    assert not np.allclose(a, b)


def test_similarity_self_one():
    fp = DeterministicFingerprinter()
    e = fp.fingerprint("x")
    assert abs(fp.similarity(e, e) - 1.0) < 1e-5


def test_batch_fingerprint():
    fp = DeterministicFingerprinter()
    b = fp.fingerprint_batch(["a", "b", "c"])
    assert b.shape == (3, 384)


def test_document_hash_deterministic():
    fp = DeterministicFingerprinter()
    assert fp.document_hash("x") == fp.document_hash("x")
    assert fp.document_hash("x") != fp.document_hash("y")


def test_protocol_id_format():
    fp = DeterministicFingerprinter()
    assert "dim384" in fp.protocol_id
    assert "det:" in fp.protocol_id


def test_sbert_optional_smoke():
    pytest.importorskip("sentence_transformers")
    fp = SemanticFingerprinter()
    e = fp.fingerprint("hello")
    assert e.shape == (384,)
