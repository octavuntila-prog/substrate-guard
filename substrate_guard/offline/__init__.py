"""Local Store — SQLite-backed event storage for offline operation.

When PostgreSQL is unavailable, events are stored locally in SQLite
with full HMAC-SHA256 chain integrity. When connectivity returns,
events are synced to PostgreSQL via INSERT ON CONFLICT DO NOTHING.

The append-only nature of audit events makes them a trivial CRDT:
union of sets, commutative, associative, idempotent. No merge
conflicts are possible.

Usage:
    store = LocalStore("/var/lib/substrate-guard/offline.db")
    store.append(event_data, policy_decision)
    
    # Later, when PG is back:
    unsynced = store.get_unsynced()
    store.mark_synced(event_ids)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("substrate_guard.offline.local_store")

GENESIS_HASH = "0" * 64
DEFAULT_DB_PATH = "/var/lib/substrate-guard/offline.db"


@dataclass
class LocalEvent:
    """A single event stored in the local SQLite database."""
    event_id: str
    timestamp: float
    agent_id: str
    event_type: str
    event_data: dict
    policy_allowed: bool
    policy_reasons: list
    prev_hash: str
    hash: str
    synced: bool = False


class LocalStore:
    """SQLite-backed local event store with HMAC chain.
    
    Every event is chained to the previous one via HMAC-SHA256,
    creating a tamper-evident append-only log identical in structure
    to the main AuditChain but persisted to disk.
    
    Args:
        db_path: Path to SQLite database file.
        hmac_secret: HMAC secret key. Reads from GUARD_HMAC_SECRET env if not provided.
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, hmac_secret: Optional[str] = None):
        self._db_path = db_path
        self._secret = (hmac_secret or os.environ.get("GUARD_HMAC_SECRET", "offline-default")).encode()
        
        # Ensure directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent reads
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()
        
        # Load head hash from last entry
        self._head_hash = self._load_head_hash()
        
        logger.info(f"LocalStore opened: {db_path} ({self.count()} events, head={self._head_hash[:16]}...)")

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                policy_allowed INTEGER NOT NULL,
                policy_reasons TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL,
                synced INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_synced ON events(synced);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);
        """)
        self._conn.commit()

    def _load_head_hash(self) -> str:
        """Load the hash of the last entry in the chain."""
        row = self._conn.execute(
            "SELECT hash FROM events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    def _compute_hash(self, event_id: str, timestamp: float,
                      event_data_json: str, prev_hash: str) -> str:
        payload = f"{event_id}:{timestamp}:{event_data_json}:{prev_hash}"
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()

    def append(self, event_data: dict, policy_allowed: bool = True,
               policy_reasons: Optional[list] = None) -> LocalEvent:
        """Append an event to the local store with HMAC chain.
        
        Returns the LocalEvent with computed hash.
        """
        event_id = str(uuid.uuid4())
        timestamp = time.time()
        agent_id = event_data.get("agent_id", "unknown")
        event_type = event_data.get("type", "unknown")
        reasons = policy_reasons or []
        
        canonical = json.dumps(event_data, sort_keys=True, default=str)
        entry_hash = self._compute_hash(event_id, timestamp, canonical, self._head_hash)
        
        self._conn.execute(
            """INSERT INTO events 
               (event_id, timestamp, agent_id, event_type, event_data,
                policy_allowed, policy_reasons, prev_hash, hash, synced)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (event_id, timestamp, agent_id, event_type, canonical,
             1 if policy_allowed else 0, json.dumps(reasons),
             self._head_hash, entry_hash),
        )
        self._conn.commit()
        
        prev = self._head_hash
        self._head_hash = entry_hash
        
        return LocalEvent(
            event_id=event_id, timestamp=timestamp, agent_id=agent_id,
            event_type=event_type, event_data=event_data,
            policy_allowed=policy_allowed, policy_reasons=reasons,
            prev_hash=prev, hash=entry_hash, synced=False,
        )

    def get_unsynced(self) -> list[LocalEvent]:
        """Get all events not yet synced to PostgreSQL."""
        rows = self._conn.execute(
            """SELECT event_id, timestamp, agent_id, event_type, event_data,
                      policy_allowed, policy_reasons, prev_hash, hash, synced
               FROM events WHERE synced = 0 ORDER BY rowid"""
        ).fetchall()
        
        return [
            LocalEvent(
                event_id=r[0], timestamp=r[1], agent_id=r[2],
                event_type=r[3], event_data=json.loads(r[4]),
                policy_allowed=bool(r[5]), policy_reasons=json.loads(r[6]),
                prev_hash=r[7], hash=r[8], synced=bool(r[9]),
            )
            for r in rows
        ]

    def mark_synced(self, event_ids: list[str]):
        """Mark events as synced after successful PostgreSQL insert."""
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        self._conn.execute(
            f"UPDATE events SET synced = 1 WHERE event_id IN ({placeholders})",
            event_ids,
        )
        self._conn.commit()
        logger.info(f"Marked {len(event_ids)} events as synced")

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Verify the entire local chain integrity.
        
        Returns:
            (True, None) if chain is intact
            (False, event_id) if chain is broken
        """
        rows = self._conn.execute(
            """SELECT event_id, timestamp, event_data, prev_hash, hash
               FROM events ORDER BY rowid"""
        ).fetchall()
        
        prev_hash = GENESIS_HASH
        for event_id, timestamp, event_data_json, stored_prev, stored_hash in rows:
            if stored_prev != prev_hash:
                return False, event_id
            
            expected = self._compute_hash(event_id, timestamp, event_data_json, prev_hash)
            if stored_hash != expected:
                return False, event_id
            
            prev_hash = stored_hash
        
        return True, None

    def count(self, synced_only: bool = False) -> int:
        """Count events in local store."""
        if synced_only:
            row = self._conn.execute("SELECT COUNT(*) FROM events WHERE synced = 1").fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0]

    def count_unsynced(self) -> int:
        """Count events not yet synced."""
        return self._conn.execute("SELECT COUNT(*) FROM events WHERE synced = 0").fetchone()[0]

    def summary(self) -> dict:
        """Summary for reporting."""
        chain_ok, broken_at = self.verify_chain()
        return {
            "db_path": self._db_path,
            "total_events": self.count(),
            "synced": self.count(synced_only=True),
            "unsynced": self.count_unsynced(),
            "head_hash": self._head_hash,
            "chain_integrity": "VERIFIED" if chain_ok else f"BROKEN at {broken_at}",
        }

    @property
    def head_hash(self) -> str:
        return self._head_hash

    def close(self):
        self._conn.close()
