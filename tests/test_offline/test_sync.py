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


def test_sync_postgres_dialect_sql(tmp_path):
    """Postgres branch (audit 2.C): the SQLite-remote tests never exercise the
    non-sqlite dialect. Capture the generated SQL via a fake non-sqlite3 connection
    and assert it uses %s placeholders + INSERT ... ON CONFLICT (id) DO NOTHING --
    verifiable without a real Postgres. (The real-Postgres end-to-end run lives in
    tests/test_postgres_ci.py::test_sync_engine_to_real_postgres.)"""
    store = LocalStore(tmp_path / "l.db", hmac_key="k")
    store.store_event("audit", "guard", {"n": 1})

    executed: list[str] = []

    class _FakeCursor:
        rowcount = 1

        def execute(self, sql, params=None):
            executed.append(sql)

        def close(self):
            pass

    class _FakePgConn:  # __module__ is the test module, not 'sqlite3' -> is_sqlite False
        def cursor(self):
            return _FakeCursor()

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    out = SyncEngine(store, lambda: _FakePgConn()).sync()
    assert out["synced"] == 1, out
    assert executed, "no SQL executed"
    sql = executed[0]
    assert "%s" in sql and "?" not in sql
    assert "ON CONFLICT (id) DO NOTHING" in sql
    assert "INSERT INTO guard_events" in sql
    store.close()


def test_sync_sqlite_constraint_drop_not_falsely_complete(tmp_path):
    """A row silently dropped by a remote SQLite constraint (INSERT OR IGNORE no-op,
    rowcount 0, no exception -- same signature as already-present) must NOT be marked
    synced or reported 'complete'; the existence check keeps it unsynced, not lost."""
    store = LocalStore(tmp_path / "local.db", hmac_key="k")
    store.store_event("audit", "guard", {"n": 1}, agent_id=None)  # agent_id NULL
    remote_path = tmp_path / "remote.db"
    rc = sqlite3.connect(str(remote_path))
    rc.execute(  # remote schema with agent_id NOT NULL -> the NULL event is dropped
        "CREATE TABLE guard_events (id TEXT PRIMARY KEY, timestamp TEXT, event_type TEXT,"
        " agent_id TEXT NOT NULL, layer TEXT, data TEXT, hmac_hash TEXT, prev_hash TEXT, source TEXT)"
    )
    rc.commit()
    rc.close()

    out = SyncEngine(store, lambda: sqlite3.connect(str(remote_path))).sync()
    assert out["status"] != "complete", out    # not falsely complete
    assert out["synced"] == 0
    assert store.count(synced=False) == 1       # row stays unsynced, not lost
    store.close()
