"""Push unsynced SQLite events to a remote DB (PostgreSQL or SQLite with same schema)."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

logger = logging.getLogger("substrate_guard.offline.sync")


class SyncEngine:
    """Append-only merge: INSERT with conflict ignore / OR IGNORE — CRDT-style union by id."""

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
            cur = conn.cursor()
            synced_ids: list[str] = []
            for event in unsynced:
                try:
                    before = conn.total_changes
                    cur.execute(
                        """
                        INSERT OR IGNORE INTO guard_events
                        (id, timestamp, event_type, agent_id, layer, data,
                         hmac_hash, prev_hash, source)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event["id"],
                            event["timestamp"],
                            event["event_type"],
                            event["agent_id"],
                            event["layer"],
                            json.dumps(event["data"]),
                            event["hmac_hash"],
                            event["prev_hash"],
                            "offline_sync",
                        ),
                    )
                    if conn.total_changes > before:
                        synced_ids.append(event["id"])
                except Exception as e:
                    logger.warning("Failed to sync event %s: %s", event["id"], e)
            conn.commit()
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

            if synced_ids:
                self.local.mark_synced(synced_ids)
                self.local.log_sync(len(synced_ids), "remote")

            return {
                "synced": len(synced_ids),
                "failed": len(unsynced) - len(synced_ids),
                "status": "complete",
            }
        except Exception as e:
            logger.error("Sync failed: %s", e)
            return {"synced": 0, "status": "error", "error": str(e)}
