"""Tests for Layer 4: ZK-SNM Copyright Compliance.

Tests cover:
- SemanticFingerprinter: embedding generation, similarity
- TrainingDataCommitment: Merkle tree, proofs
- NonMembershipVerifier: similarity check, Z3 confirmation
- ZKSNMProtocol: full 4-phase protocol
- ComplyGuard: Guard integration with compliance checking
"""

import json
import os
import tempfile
import time
import numpy as np
import pytest

from substrate_guard.comply.fingerprinter import SemanticFingerprinter
from substrate_guard.comply.commitment import TrainingDataCommitment
from substrate_guard.comply.verifier import NonMembershipVerifier
from substrate_guard.comply.protocol import ZKSNMProtocol
from substrate_guard.comply.comply_guard import ComplyGuard


# ============================================
# Fixtures
# ============================================

@pytest.fixture(scope="module")
def fingerprinter():
    """Shared fingerprinter (model loading is expensive)."""
    return SemanticFingerprinter()


@pytest.fixture(scope="module")
def sample_embeddings(fingerprinter):
    """Pre-computed embeddings for test documents."""
    docs = [
        "The European Union has enacted new regulations on artificial intelligence.",
        "Machine learning models must comply with data protection laws.",
        "Climate change affects global food production and supply chains.",
        "Quantum computing promises exponential speedups for specific algorithms.",
        "The stock market experienced significant volatility during the quarter.",
    ]
    return fingerprinter.fingerprint_batch(docs), docs


# ============================================
# SemanticFingerprinter tests
# ============================================

class TestSemanticFingerprinter:
    def test_fingerprint_shape(self, fingerprinter):
        emb = fingerprinter.fingerprint("Hello world")
        assert emb.shape == (384,)
        assert emb.dtype == np.float32

    def test_fingerprint_normalized(self, fingerprinter):
        emb = fingerprinter.fingerprint("Test document")
        norm = np.linalg.norm(emb)
        assert abs(norm - 1.0) < 0.01  # L2-normalized

    def test_similar_docs_high_similarity(self, fingerprinter):
        e1 = fingerprinter.fingerprint("The cat sat on the mat")
        e2 = fingerprinter.fingerprint("A feline was sitting on the rug")
        sim = fingerprinter.similarity(e1, e2)
        assert sim > 0.5  # Semantically related

    def test_different_docs_low_similarity(self, fingerprinter):
        e1 = fingerprinter.fingerprint("Quantum computing uses qubits for parallel processing")
        e2 = fingerprinter.fingerprint("Italian cuisine features pasta and olive oil")
        sim = fingerprinter.similarity(e1, e2)
        assert sim < 0.3  # Unrelated topics

    def test_identical_docs_perfect_similarity(self, fingerprinter):
        text = "This is the exact same document."
        e1 = fingerprinter.fingerprint(text)
        e2 = fingerprinter.fingerprint(text)
        sim = fingerprinter.similarity(e1, e2)
        assert sim > 0.99

    def test_batch_fingerprint(self, fingerprinter):
        docs = ["First document", "Second document", "Third document"]
        embs = fingerprinter.fingerprint_batch(docs)
        assert embs.shape == (3, 384)

    def test_embedding_hash(self, fingerprinter):
        emb = fingerprinter.fingerprint("Test")
        h = fingerprinter.embedding_hash(emb)
        assert len(h) == 64  # SHA-256 hex

    def test_info(self, fingerprinter):
        info = fingerprinter.info()
        assert info["model"] == "all-MiniLM-L6-v2"
        assert info["dimension"] == 384


# ============================================
# TrainingDataCommitment tests
# ============================================

class TestTrainingDataCommitment:
    def test_commit(self, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        root = c.commit()
        assert len(root) == 64
        assert c.committed is True
        assert c.size == 5

    def test_cannot_add_after_commit(self, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        with pytest.raises(RuntimeError):
            c.add_embedding(embs[0])

    def test_merkle_proof(self, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        proof = c.get_proof(0)
        assert TrainingDataCommitment.verify_proof(proof) is True

    def test_merkle_proof_all_leaves(self, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        for i in range(c.size):
            proof = c.get_proof(i)
            assert TrainingDataCommitment.verify_proof(proof) is True

    def test_deterministic_root(self, sample_embeddings):
        embs, _ = sample_embeddings
        c1 = TrainingDataCommitment()
        c1.add_embeddings_batch(embs)
        r1 = c1.commit()
        
        c2 = TrainingDataCommitment()
        c2.add_embeddings_batch(embs)
        r2 = c2.commit()
        
        assert r1 == r2

    def test_summary(self, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        s = c.summary()
        assert s["documents"] == 5
        assert s["committed"] is True


# ============================================
# NonMembershipVerifier tests
# ============================================

class TestNonMembershipVerifier:
    def test_clear_on_unrelated(self, fingerprinter, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        verifier = NonMembershipVerifier(c, threshold=0.85)
        query = fingerprinter.fingerprint("Italian pizza recipes from Naples")
        result = verifier.verify(query)
        
        assert result.is_member is False
        assert result.max_similarity < 0.85

    def test_violation_on_similar(self, fingerprinter, sample_embeddings):
        embs, docs = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        verifier = NonMembershipVerifier(c, threshold=0.50)  # Low threshold
        # Query very similar to doc 0
        query = fingerprinter.fingerprint(
            "The EU has passed new AI regulations for compliance."
        )
        result = verifier.verify(query)
        
        # Should find similarity with the AI regulation doc
        assert result.max_similarity > 0.50

    def test_exact_match_detected(self, fingerprinter, sample_embeddings):
        embs, docs = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        verifier = NonMembershipVerifier(c, threshold=0.95)
        # Query with exact training doc
        query = fingerprinter.fingerprint(docs[0])
        result = verifier.verify(query)
        
        assert result.is_member is True
        assert result.max_similarity > 0.99
        assert result.closest_index == 0

    def test_result_to_dict(self, fingerprinter, sample_embeddings):
        embs, _ = sample_embeddings
        c = TrainingDataCommitment()
        c.add_embeddings_batch(embs)
        c.commit()
        
        verifier = NonMembershipVerifier(c, threshold=0.85)
        query = fingerprinter.fingerprint("Random unrelated text")
        result = verifier.verify(query)
        d = result.to_dict()
        
        assert "verdict" in d
        assert "note" in d  # Honesty note about prototype


# ============================================
# ZKSNMProtocol tests
# ============================================

class TestZKSNMProtocol:
    def test_full_protocol_clear(self):
        protocol = ZKSNMProtocol(threshold=0.85)
        
        # Phase 2: Commit
        training_docs = [
            "The European Union has enacted new regulations on AI.",
            "Climate change affects food production globally.",
            "Quantum computing uses qubits for computation.",
        ]
        root = protocol.commit_training_data(training_docs)
        assert len(root) == 64
        
        # Phase 3: Verify (unrelated doc)
        result = protocol.verify_document("Italian pizza recipes from Naples")
        assert result.is_member is False
        
        # Phase 4: Certify
        cert = protocol.generate_certificate(result, "Italian pizza recipes from Naples")
        assert cert.verdict == "CLEAR"
        assert cert.protocol_version == "ZK-SNM-1.0-prototype"
        assert len(cert.certificate_hash) == 64

    def test_full_protocol_violation(self):
        protocol = ZKSNMProtocol(threshold=0.90)
        
        training_docs = [
            "The New York Times reported on climate change today.",
        ]
        protocol.commit_training_data(training_docs)
        
        # Query with the exact training doc
        result = protocol.verify_document(
            "The New York Times reported on climate change today."
        )
        assert result.is_member is True
        
        cert = protocol.generate_certificate(result)
        assert cert.verdict == "VIOLATION"

    def test_certificate_save_load(self, tmp_path):
        protocol = ZKSNMProtocol()
        protocol.commit_training_data(["Test document"])
        result = protocol.verify_document("Unrelated query")
        cert = protocol.generate_certificate(result)
        
        path = str(tmp_path / "cert.json")
        cert.save(path)
        
        loaded = json.loads(open(path).read())
        assert loaded["verdict"] in ("CLEAR", "VIOLATION")
        assert "certificate_hash" in loaded

    def test_status(self):
        protocol = ZKSNMProtocol()
        protocol.commit_training_data(["Doc 1", "Doc 2"])
        s = protocol.status()
        assert s["training_docs_committed"] == 2
        assert s["ready"] is True


# ============================================
# ComplyGuard tests
# ============================================

class TestComplyGuard:
    def test_check_output_clear(self):
        guard = ComplyGuard(
            protected_documents=[
                "The New York Times article about AI regulation.",
                "Getty Images photograph of the Eiffel Tower.",
            ],
            threshold=0.85,
            observe=True, policy="nonexistent/", verify=True, use_mock=True,
        )
        
        result = guard.check_output("Italian cooking recipes for beginners")
        assert result.is_compliant is True
        assert result.verification.max_similarity < 0.85

    def test_check_output_violation(self):
        protected = "The New York Times published an article about AI safety regulations."
        guard = ComplyGuard(
            protected_documents=[protected],
            threshold=0.90,
            observe=True, policy="nonexistent/", verify=True, use_mock=True,
        )
        
        # Query with the exact protected doc
        result = guard.check_output(protected)
        assert result.is_compliant is False

    def test_compliance_status(self):
        guard = ComplyGuard(
            protected_documents=["Doc 1", "Doc 2"],
            observe=True, policy="nonexistent/", verify=True, use_mock=True,
        )
        guard.check_output("Test query")
        
        status = guard.compliance_status()
        assert status["checks_performed"] == 1
        assert status["corpus_size"] == 2

    def test_no_corpus_always_compliant(self):
        guard = ComplyGuard(
            observe=True, policy="nonexistent/", verify=True, use_mock=True,
        )
        result = guard.check_output("Anything")
        assert result.is_compliant is True

    def test_guard_still_works(self):
        guard = ComplyGuard(
            protected_documents=["Protected content"],
            observe=True, policy="nonexistent/", verify=True, use_mock=True,
        )
        from substrate_guard.observe.events import EventType, FileEvent
        event = FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="evil")
        ge = guard.evaluate_event(event)
        assert ge.policy_decision.allowed is False
