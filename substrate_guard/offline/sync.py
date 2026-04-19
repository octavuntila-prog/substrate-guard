"""Sync Engine — Merges local SQLite events to PostgreSQL on reconnection.

Audit events are append-only, making them a trivial CRDT:
- Commutative: order of merge doesn't matter
- Associative: grouping of merges doesn't matter
- Idempotent: merging the same event twice is safe

INSERT ... ON CONFLICT DO NOTHING handles all of this.

Usage:
    syncer = SyncEngine(local_store, db_url)
    result = syncer.sync()
    print(f"Synced {result['synced_count']} events")
"""

from __future__ import annotations

import json
import time
import logging
from typing import Optional

logger = logging.getLogger("substrate_guard.offline.sync")


class SyncEngine:
    """Syncs local SQLite events to PostgreSQL.
    
    Uses INSERT ON CONFLICT DO NOTHING for idempotent merge.
    The event_id (UUID) is the natural dedup key.
    
    Args:
        local_store: LocalStore instance with unsynced events.
        db_url: PostgreSQL connection URL.
        batch_size: Number of events to sync per batch.
    """

    def __init__(self, local_store, db_url: Optional[str] = None, batch_size: int = 100):
        self._store = local_store
        self._db_url = db_url
        self._batch_size = batch_size

    def _get_pg_connection(self):
        """Get a psycopg2 connection to PostgreSQL."""
        try:
            import psycopg2
        except ImportError:
            raise ImportError("psycopg2 required for sync. Install: pip install psycopg2-binary")
        
        url = self._db_url
        if not url:
            raise ValueError("No db_url configured for sync")
        
        # Strip +asyncpg if present
        url = url.replace("+asyncpg", "")
        
        return psycopg2.connect(url)

    def sync(self) -> dict:
        """Sync all unsynced events to PostgreSQL.
        
        Returns dict with sync results.
        """
        unsynced = self._store.get_unsynced()
        if not unsynced:
            return {
                "synced_count": 0,
                "already_synced": self._store.count(synced_only=True),
                "total_local": self._store.count(),
                "status": "NOTHING_TO_SYNC",
            }

        start = time.time()
        synced_ids = []
        errors = []

        try:
            conn = self._get_pg_connection()
            cur = conn.cursor()

            # Create the offline_events table if it doesn't exist
            cur.execute("""
                CREATE TABLE IF NOT EXISTS offline_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp DOUBLE PRECISION NOT NULL,
                    agent_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_data JSONB NOT NULL,
                    policy_allowed BOOLEAN NOT NULL,
                    policy_reasons JSONB NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    source TEXT DEFAULT 'offline',
                    synced_at TIMESTAMP DEFAULT NOW()
                )
            """)

            # Batch insert with ON CONFLICT DO NOTHING (CRDT merge)
            for i in range(0, len(unsynced), self._batch_size):
                batch = unsynced[i:i + self._batch_size]
                
                for event in batch:
                    try:
                        cur.execute(
                            """INSERT INTO offline_events 
                               (event_id, timestamp, agent_id, event_type, event_data,
                                policy_allowed, policy_reasons, prev_hash, hash, source)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'offline')
                               ON CONFLICT (event_id) DO NOTHING""",
                            (
                                event.event_id, event.timestamp, event.agent_id,
                                event.event_type, json.dumps(event.event_data),
                                event.policy_allowed, json.dumps(event.policy_reasons),
                                event.prev_hash, event.hash,
                            ),
                        )
                        synced_ids.append(event.event_id)
                    except Exception as e:
                        errors.append({"event_id": event.event_id, "error": str(e)})

                conn.commit()

            cur.close()
            conn.close()

        except Exception as e:
            logger.error(f"Sync failed: {e}")
            return {
                "synced_count": 0,
                "error": str(e),
                "status": "SYNC_FAILED",
            }

        # Mark successfully synced events in local store
        if synced_ids:
            self._store.mark_synced(synced_ids)

        elapsed = time.time() - start
        
        result = {
            "synced_count": len(synced_ids),
            "errors": len(errors),
            "error_details": errors[:5] if errors else [],
            "elapsed_ms": round(elapsed * 1000, 1),
            "remaining_unsynced": self._store.count_unsynced(),
            "total_local": self._store.count(),
            "status": "SYNCED" if not errors else "PARTIAL_SYNC",
        }
        
        logger.info(
            f"Sync complete: {result['synced_count']} events in {result['elapsed_ms']}ms"
            f" ({result['errors']} errors, {result['remaining_unsynced']} remaining)"
        )
        
        return result

    def sync_status(self) -> dict:
        """Current sync status without performing sync."""
        return {
            "total_local": self._store.count(),
            "synced": self._store.count(synced_only=True),
            "unsynced": self._store.count_unsynced(),
            "chain_integrity": self._store.verify_chain()[0],
        }
