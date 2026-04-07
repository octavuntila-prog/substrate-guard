"""CLI hooks for Layer 6."""

from __future__ import annotations

import argparse
import sqlite3
import tempfile
from pathlib import Path


def register_offline_parser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "offline",
        help="Layer 6: SQLite offline store + optional sync (no Postgres required for demo)",
    )
    sp = p.add_subparsers(dest="offline_action", required=True)
    sp.add_parser(
        "demo",
        help="Store events in temp SQLite, verify HMAC chain, sync copy to second SQLite DB",
    )


def cmd_offline(args: argparse.Namespace) -> int:
    if args.offline_action == "demo":
        return run_offline_demo()
    return 1


def _ensure_guard_events_table(conn: sqlite3.Connection) -> None:
    conn.execute(
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
            source TEXT DEFAULT 'offline_sync'
        )
        """
    )
    conn.commit()


def run_offline_demo() -> int:
    from .local_store import LocalStore
    from .sync import SyncEngine

    base = Path(tempfile.mkdtemp(prefix="substrate-offline-"))
    local_path = base / "offline.db"
    remote_path = base / "remote.db"

    store = LocalStore(db_path=local_path, hmac_key="demo-hmac-key")
    a = store.store_event("audit", "guard", {"msg": "first"}, agent_id="a1")
    b = store.store_event("audit", "guard", {"msg": "second"}, agent_id="a1")
    rep = store.verify_chain()
    if not rep.get("valid"):
        print("chain invalid", rep)
        return 1

    def factory() -> sqlite3.Connection:
        c = sqlite3.connect(str(remote_path))
        _ensure_guard_events_table(c)
        return c

    engine = SyncEngine(store, factory)
    out = engine.sync()
    unsynced_after = store.count(synced=False)

    print("Layer 6 offline demo (SQLite + append-only sync)")
    print(f"  local events:     {rep['events']} chain_ok={rep['valid']}")
    print(f"  event ids:        {a['id'][:8]}... {b['id'][:8]}...")
    print(f"  sync result:      {out}")
    print(f"  unsynced local:   {unsynced_after}")
    rc = sqlite3.connect(str(remote_path))
    _ensure_guard_events_table(rc)
    n = rc.execute("SELECT COUNT(*) FROM guard_events").fetchone()[0]
    rc.close()
    print(f"  rows in remote:   {n}")
    store.close()
    return 0 if out.get("synced", 0) >= 1 and n >= 1 else 1
