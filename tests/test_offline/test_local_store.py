"""LocalStore SQLite + HMAC chain tests."""

from __future__ import annotations

import json

import pytest

from substrate_guard.chain import ChainConfigError
from substrate_guard.offline.local_store import (
    GENESIS_PREV,
    INSECURE_DEFAULT_HMAC_KEY,
    LocalStore,
)


def test_no_key_no_env_raises(tmp_path, monkeypatch):
    """No hmac_key, no env var, no opt-in → ChainConfigError (fail-loud).

    Aligns LocalStore with the L4 AuditChain discipline (v13.4.0 Decision 1):
    no silent fallback to a hardcoded, publicly-known default key.
    """
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    with pytest.raises(ChainConfigError):
        LocalStore(tmp_path / "x.db")


def test_empty_key_raises(tmp_path, monkeypatch):
    """hmac_key="" must not sneak past the truthy check → ChainConfigError."""
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    with pytest.raises(ChainConfigError):
        LocalStore(tmp_path / "x.db", hmac_key="")


def test_env_var_used_when_no_param(tmp_path, monkeypatch):
    """GUARD_HMAC_SECRET env (unified with L4) is used when no param given.

    Also verifies the stable env key still verifies the SAME DB after reopen —
    the reason LocalStore's opt-in uses a stable key, not a random one.
    """
    monkeypatch.setenv("GUARD_HMAC_SECRET", "env-secret-key")
    s = LocalStore(tmp_path / "x.db")
    s.store_event("t", "L", {"a": 1})
    assert s.verify_chain()["valid"]
    s.close()
    s2 = LocalStore(tmp_path / "x.db")
    assert s2.verify_chain()["valid"]
    s2.close()


def test_allow_insecure_default_opt_in(tmp_path, monkeypatch):
    """Explicit opt-in → constructs and produces a valid chain (demo path)."""
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    s = LocalStore(tmp_path / "x.db", allow_insecure_default=True)
    s.store_event("t", "L", {"a": 1})
    assert s.verify_chain()["valid"]
    s.close()


def test_insecure_default_is_the_known_dev_key(tmp_path, monkeypatch):
    """Opt-in fallback uses the publicly-known dev key, not a random one.

    Compares the RESOLVED key directly: the HMAC now binds the per-event id +
    timestamp, so two identical events legitimately get different hashes."""
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    a = LocalStore(tmp_path / "a.db", allow_insecure_default=True)
    b = LocalStore(tmp_path / "b.db", hmac_key=INSECURE_DEFAULT_HMAC_KEY)
    assert a.hmac_key == b.hmac_key == INSECURE_DEFAULT_HMAC_KEY.encode()
    a.close()
    b.close()


def test_store_and_verify_empty_ok(tmp_path):
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    assert s.verify_chain() == {"valid": True, "events": 0}
    s.close()


def test_chain_two_events_valid(tmp_path):
    s = LocalStore(tmp_path / "x.db", hmac_key="same-key")
    s.store_event("t", "L", {"a": 1})
    s.store_event("t", "L", {"b": 2})
    r = s.verify_chain()
    assert r["valid"] and r["events"] == 2
    assert s.count() == 2
    s.close()


def test_tamper_breaks_chain(tmp_path):
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    s.store_event("t", "L", {"x": 1})
    s.conn.execute("UPDATE events SET data = ? WHERE rowid = 1", (json.dumps({"x": 2}),))
    s.conn.commit()
    r = s.verify_chain()
    assert r["valid"] is False
    s.close()


def test_unsynced_and_mark(tmp_path):
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    s.store_event("t", "L", {})
    assert s.count(synced=False) == 1
    u = s.get_unsynced()
    assert len(u) == 1
    s.mark_synced([u[0]["id"]])
    assert s.count(synced=False) == 0
    assert s.count(synced=True) == 1
    s.close()


def test_first_event_prev_is_genesis(tmp_path):
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    s.store_event("t", "L", {})
    row = s.conn.execute(
        "SELECT prev_hash FROM events ORDER BY rowid ASC LIMIT 1"
    ).fetchone()
    assert row[0] == GENESIS_PREV
    s.close()


def test_hmac_binds_event_type(tmp_path):
    """Tampering a denormalized column (event_type) must break verify_chain -- the
    HMAC binds every authenticated column, not just data + prev_hash."""
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    ev = s.store_event("audit", "L", {"n": 1})
    assert s.verify_chain()["valid"]
    s.conn.execute("UPDATE events SET event_type = 'forged' WHERE id = ?", (ev["id"],))
    assert s.verify_chain()["valid"] is False
    s.close()


def test_concurrent_store_event_no_fork(tmp_path):
    """Concurrent store_event from many threads must not fork the HMAC chain (atomic
    read-tail-then-append under BEGIN IMMEDIATE + lock; a thread-bound connection
    previously lost writes / forked the chain)."""
    import threading

    s = LocalStore(tmp_path / "x.db", hmac_key="k")

    def worker():
        for i in range(25):
            s.store_event("audit", "L", {"i": i})

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert s.count() == 150
    assert s.verify_chain()["valid"], "chain forked under concurrency"
    s.close()


def test_hmac_distinguishes_none_and_empty_agent_id(tmp_path):
    """agent_id=None and agent_id="" must produce DIFFERENT HMACs -- None must not
    collapse to "" (a DB-write attacker could otherwise flip between them undetected)."""
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    h_none = s._compute_hmac("id", "t", "audit", None, "L", "{}", "p")
    h_empty = s._compute_hmac("id", "t", "audit", "", "L", "{}", "p")
    h_nul = s._compute_hmac("id", "t", "audit", "\x00", "L", "{}", "p")
    assert h_none != h_empty
    assert h_none != h_nul  # None must not collide with a real agent_id == "\x00"
    s.close()


def test_verify_chain_detects_truncation_with_expected_count(tmp_path):
    """H1: a tail-truncated store verifies as a valid prefix; expected_count catches it."""
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    for i in range(5):
        s.store_event("audit", "L", {"i": i})
    assert s.verify_chain(expected_count=5)["valid"]
    s.conn.execute(
        "DELETE FROM events WHERE rowid IN "
        "(SELECT rowid FROM events ORDER BY rowid DESC LIMIT 2)"
    )
    assert s.verify_chain()["valid"]                          # prefix still verifies
    assert s.verify_chain(expected_count=5)["valid"] is False  # caught by expected_count
    s.close()


def test_hmac_no_delimiter_injection(tmp_path):
    """Distinct (layer, data) tuples that the old "\\x1f".join collided (content
    rebalanced across the field boundary) must now hash differently -- json field
    boundaries are unambiguous."""
    s = LocalStore(tmp_path / "x.db", hmac_key="k")
    h1 = s._compute_hmac("id", "t", "audit", "a", "L", "A\x1fB", "p")
    h2 = s._compute_hmac("id", "t", "audit", "a", "L\x1fA", "B", "p")
    assert h1 != h2  # the old join produced byte-identical payloads here
    s.close()


def test_different_hmac_key_different_chain(tmp_path):
    a = LocalStore(tmp_path / "a.db", hmac_key="aaa")
    b = LocalStore(tmp_path / "b.db", hmac_key="bbb")
    ea = a.store_event("t", "L", {"z": 1})
    eb = b.store_event("t", "L", {"z": 1})
    assert ea["hmac_hash"] != eb["hmac_hash"]
    a.close()
    b.close()
