"""Tests for non-membership verifier."""

from __future__ import annotations

import numpy as np

from substrate_guard.comply.verifier import NonMembershipVerifier


def _unit(n: int, axis: int) -> np.ndarray:
    e = np.zeros(n, dtype=np.float32)
    e[axis] = 1.0
    return e


def test_verify_no_similar():
    v = NonMembershipVerifier(threshold=0.9)
    q = _unit(384, 0)
    corpus = [_unit(384, i) for i in range(1, 5)]
    r = v.verify(q, corpus)
    assert r["verified"]
    assert r["max_similarity"] < 0.9


def test_verify_similar_found():
    v = NonMembershipVerifier(threshold=0.5)
    q = _unit(384, 0)
    corpus = [_unit(384, 0), _unit(384, 1)]
    r = v.verify(q, corpus)
    assert not r["verified"]
    assert r["violations"][0]["index"] == 0


def test_verify_exact_match():
    v = NonMembershipVerifier(threshold=0.99)
    e = _unit(384, 3)
    r = v.verify(e, [e.copy()])
    assert not r["verified"]
    assert r["max_similarity"] >= 0.99


def test_verify_empty_set():
    v = NonMembershipVerifier()
    q = _unit(384, 0)
    r = v.verify(q, [])
    assert r["verified"]
    assert r["max_similarity"] == -1.0


def test_verify_returns_max_similarity():
    v = NonMembershipVerifier(threshold=0.99)
    q = np.ones(384, dtype=np.float32) / np.sqrt(384.0)
    corpus = [q.copy(), _unit(384, 1)]
    r = v.verify(q, corpus)
    assert not r["verified"]
    assert r["max_similarity"] >= 0.99


def test_multiple_violations():
    v = NonMembershipVerifier(threshold=0.1)
    q = np.ones(384, dtype=np.float32) / np.sqrt(384.0)
    corpus = [q.copy(), q.copy(), _unit(384, 2)]
    r = v.verify(q, corpus)
    assert not r["verified"]
    assert len(r["violations"]) >= 2


def test_decorative_z3_path_removed():
    """The decorative verify_with_z3 (audit 2.A step 2) is gone; only the honest
    single NumPy cosine pass remains, and its backend never claims a Z3 step."""
    v = NonMembershipVerifier(threshold=0.85)
    assert not hasattr(v, "verify_with_z3")
    r = v.verify(_unit(384, 0), [_unit(384, 3)])
    assert r["backend"] == "numpy_cosine"
    assert "z3_confirmed" not in r and "z3_note" not in r
