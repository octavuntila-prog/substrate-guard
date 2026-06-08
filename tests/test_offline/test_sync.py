"""SyncEngine tests using SQLite as remote sink."""

from __future__ import annotations

import sqlite3

from substrate_guard.offline.local_store import LocalStore
from substrate_guard.offline.sync import SyncEngine


def _remote_schema(path):
    c = sqlite3.connect(str(path))
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS guard_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            agent_id TEXT,
            layer TEXT NOT NULL,
            data TEXT NOT NULL,
            hmac_hash TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            source TEXT
        )
        """
    )
    c.commit()
    return c


def test_sync_to_sqlite_remote(tmp_path):
    local_db = tmp_path / "local.db"
    remote_db = tmp_path / "remote.db"
    store = LocalStore(local_db, hmac_key="sync-test")
    store.store_event("audit", "guard", {"n": 1})
    store.store_event("audit", "guard", {"n": 2})

    def factory():
        return _remote_schema(remote_db)

    eng = SyncEngine(store, factory)
    out = eng.sync()
    assert out["status"] == "complete"
    assert out["synced"] == 2
    assert store.count(synced=False) == 0

    rc = sqlite3.connect(str(remote_db))
    n = rc.execute("SELECT COUNT(*) FROM guard_events").fetchone()[0]
    assert n == 2
    rc.close()
    store.close()


def test_sync_nothing_pending(tmp_path):
    store = LocalStore(tmp_path / "l.db", hmac_key="k")

    def factory():
        return _remote_schema(tmp_path / "r.db")

    out = SyncEngine(store, factory).sync()
    assert out["status"] == "nothing_to_sync"
    store.close()


def test_sync_no_factory(tmp_path):
    store = LocalStore(tmp_path / "l.db", hmac_key="k")
    out = SyncEngine(store, None).sync()
    assert out["status"] == "no_connection_factory"
    store.close()


def test_sync_all_failed_reports_failed_not_complete(tmp_path):
    """When every row fails (here the remote table is missing), the status must be
    'failed' -- not 'complete'. The audited bug reported "complete" with synced=0 on a
    Postgres remote where the SQLite-only SQL no-op'd every row."""
    store = LocalStore(tmp_path / "local.db", hmac_key="k")
    store.store_event("audit", "guard", {"n": 1})

    def factory():
        return sqlite3.connect(str(tmp_path / "empty_remote.db"))  # no guard_events table

    out = SyncEngine(store, factory).sync()
    assert out["status"] == "failed", out
    assert out["synced"] == 0
    assert store.count(synced=False) == 1  # local event stays unsynced
    store.close()


def test_sync_already_present_row_is_marked_not_re_pushed(tmp_path):
    """An event already on the remote (e.g. a prior sync that did not mark locally)
    must be marked synced on the next pass -- not reported failed and re-pushed
    forever (the regression in the cur.rowcount 'honest status' change)."""
    store = LocalStore(tmp_path / "local.db", hmac_key="k")
    store.store_event("audit", "guard", {"n": 1})
    ev = store.get_unsynced(limit=1)[0]
    remote_path = tmp_path / "remote.db"
    rc = _remote_schema(remote_path)
    rc.execute(  # pre-insert the row remotely (id is the PRIMARY KEY)
        "INSERT INTO guard_events (id,timestamp,event_type,agent_id,layer,data,"
        "hmac_hash,prev_hash,source) VALUES (?,?,?,?,?,?,?,?,?)",
        (ev["id"], "t", "audit", "a", "guard", "{}", "h", "p", "pre"),
    )
    rc.commit()
    rc.close()

    out = SyncEngine(store, lambda: sqlite3.connect(str(remote_path))).sync()
    assert out["status"] == "complete", out   # already-present counts as synced
    assert store.count(synced=False) == 0      # marked, not re-pushed
    store.close()
