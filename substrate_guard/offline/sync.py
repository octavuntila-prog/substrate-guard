"""Push unsynced SQLite events to a remote DB (PostgreSQL or SQLite with same schema)."""

from __future__ import annotations

import json
import logging
from contextlib import suppress
from typing import Any, Callable

logger = logging.getLogger("substrate_guard.offline.sync")


class SyncEngine:
    """Append-only merge via INSERT OR IGNORE: a union by primary-key id.

    Assumes event ids are unique per event (UUIDs over an append-only log), so
    id-existence == event-identity. NOT a general CRDT: on a same-id conflict with
    DIFFERENT data, OR IGNORE keeps the existing remote row (no value-level merge or
    conflict detection). Each row is committed INDIVIDUALLY, so a later row's failure
    cannot roll back an already-synced row (PostgreSQL aborts the whole transaction on
    a failed statement), and an idempotent no-op for an already-present row still
    commits -- so it is marked synced rather than re-pushed forever.
    """

    def __init__(
        self,
        local_store: Any,
        pg_connection_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.local = local_store
        self.pg_factory = pg_connection_factory

    def sync(self, batch_size: int = 500) -> dict[str, Any]:
        if self.pg_factory is None:
            return {
                "synced": 0,
                "status": "no_connection_factory",
                "message": "Set pg_factory to a callable returning a DB-API connection",
            }

        unsynced = self.local.get_unsynced(limit=batch_size)
        if not unsynced:
            return {"synced": 0, "status": "nothing_to_sync"}

        try:
            conn = self.pg_factory()
            # Dialect-aware: SQLite uses ? + INSERT OR IGNORE; PostgreSQL/others use
            # %s + INSERT ... ON CONFLICT DO NOTHING. cur.rowcount is portable (was
            # conn.total_changes, which is SQLite-only and silently no-op'd Postgres).
            is_sqlite = type(conn).__module__.split(".")[0] == "sqlite3"
            ph = "?" if is_sqlite else "%s"
            head = "INSERT OR IGNORE INTO" if is_sqlite else "INSERT INTO"
            tail = "" if is_sqlite else " ON CONFLICT (id) DO NOTHING"
            sql = (
                f"{head} guard_events "
                "(id, timestamp, event_type, agent_id, layer, data, hmac_hash, "
                "prev_hash, source) "
                f"VALUES ({', '.join([ph] * 9)}){tail}"
            )
            cur = conn.cursor()
            synced_ids: list[str] = []
            for event in unsynced:
                try:
                    cur.execute(sql, (
                        event["id"], event["timestamp"], event["event_type"],
                        event["agent_id"], event["layer"], json.dumps(event["data"]),
                        event["hmac_hash"], event["prev_hash"], "offline_sync",
                    ))
                    # SQLite INSERT OR IGNORE swallows NOT NULL / CHECK violations as a
                    # silent no-op (rowcount 0, no exception) -- the SAME signature as an
                    # already-present row. Mark synced only if the row is ACTUALLY on the
                    # remote, else a constraint-dropped row would be lost as a false
                    # "complete". (Postgres raises such violations, so it is unaffected.)
                    if is_sqlite and cur.rowcount == 0:
                        present = conn.execute(
                            "SELECT 1 FROM guard_events WHERE id = ?", (event["id"],)
                        ).fetchone()
                        if present is None:
                            raise RuntimeError("row silently dropped by a remote constraint")
                    # Commit PER ROW: a later row's failure cannot roll back an
                    # already-synced row (Postgres aborts the whole txn on a failed
                    # statement), and an idempotent no-op (row already present) still
                    # commits -- so it is marked synced, not re-pushed forever. A row
                    # is marked ONLY after its remote commit succeeds (no data loss).
                    conn.commit()
                    synced_ids.append(event["id"])
                except Exception as e:
                    with suppress(Exception):
                        conn.rollback()  # clear Postgres aborted-transaction state
                    logger.warning("Failed to sync event %s: %s", event["id"], e)
            with suppress(Exception):
                cur.close()
            with suppress(Exception):
                conn.close()

            if synced_ids:
                self.local.mark_synced(synced_ids)
                self.local.log_sync(len(synced_ids), "remote")

            failed = len(unsynced) - len(synced_ids)
            # Honest status: never "complete" when nothing actually synced.
            status = "complete" if failed == 0 else ("partial" if synced_ids else "failed")
            return {"synced": len(synced_ids), "failed": failed, "status": status}
        except Exception as e:
            logger.error("Sync failed: %s", e)
            return {"synced": 0, "status": "error", "error": str(e)}
