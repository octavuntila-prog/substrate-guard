"""LocalStore SQLite + HMAC chain tests."""

from __future__ import annotations

import json

from substrate_guard.offline.local_store import GENESIS_PREV, LocalStore


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


def test_different_hmac_key_different_chain(tmp_path):
    a = LocalStore(tmp_path / "a.db", hmac_key="aaa")
    b = LocalStore(tmp_path / "b.db", hmac_key="bbb")
    ea = a.store_event("t", "L", {"z": 1})
    eb = b.store_event("t", "L", {"z": 1})
    assert ea["hmac_hash"] != eb["hmac_hash"]
    a.close()
    b.close()
