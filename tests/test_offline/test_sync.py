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
