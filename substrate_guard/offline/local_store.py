"""Append-only SQLite store with HMAC chain (offline audit fallback)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_PREV = "0" * 64


class LocalStore:
    """WAL-mode SQLite for events when PostgreSQL / network is unavailable."""

    def __init__(self, db_path: str | Path, hmac_key: str | bytes | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        raw = hmac_key or os.environ.get("GUARD_HMAC_KEY", "substrate-guard-default-dev-key")
        self.hmac_key = raw.encode() if isinstance(raw, str) else raw
        self.conn = __import__("sqlite3").connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                agent_id TEXT,
                layer TEXT NOT NULL,
                data TEXT NOT NULL,
                hmac_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                synced INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                synced_at TEXT NOT NULL,
                events_synced INTEGER NOT NULL,
                target TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_synced ON events(synced);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            """
        )
        self.conn.commit()

    def _compute_hmac(self, data: str, prev_hash: str) -> str:
        payload = f"{prev_hash}:{data}".encode()
        return hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()

    def _get_last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT hmac_hash FROM events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_PREV

    def store_event(
        self,
        event_type: str,
        layer: str,
        data: dict[str, Any],
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        data_json = json.dumps(data, sort_keys=True)
        prev_hash = self._get_last_hash()
        hmac_hash = self._compute_hmac(data_json, prev_hash)
        self.conn.execute(
            """INSERT INTO events
               (id, timestamp, event_type, agent_id, layer, data,
                hmac_hash, prev_hash, synced)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (
                event_id,
                timestamp,
                event_type,
                agent_id,
                layer,
                data_json,
                hmac_hash,
                prev_hash,
            ),
        )
        self.conn.commit()
        return {
            "id": event_id,
            "timestamp": timestamp,
            "hmac_hash": hmac_hash,
            "stored": "local",
        }

    def get_unsynced(self, limit: int = 1000) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT id, timestamp, event_type, agent_id, layer,
                      data, hmac_hash, prev_hash
               FROM events WHERE synced = 0
               ORDER BY rowid ASC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "event_type": r[2],
                "agent_id": r[3],
                "layer": r[4],
                "data": json.loads(r[5]),
                "hmac_hash": r[6],
                "prev_hash": r[7],
            }
            for r in rows
        ]

    def mark_synced(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" * len(event_ids))
        self.conn.execute(
            f"UPDATE events SET synced = 1 WHERE id IN ({placeholders})",
            event_ids,
        )
        self.conn.commit()

    def verify_chain(self) -> dict[str, Any]:
        rows = self.conn.execute(
            "SELECT data, hmac_hash, prev_hash FROM events ORDER BY rowid ASC"
        ).fetchall()
        if not rows:
            return {"valid": True, "events": 0}
        expected_prev = GENESIS_PREV
        for i, (data, stored_hash, prev_hash) in enumerate(rows):
            if prev_hash != expected_prev:
                return {
                    "valid": False,
                    "broken_at": i,
                    "reason": "prev_hash mismatch",
                }
            computed = self._compute_hmac(data, prev_hash)
            if computed != stored_hash:
                return {"valid": False, "broken_at": i, "reason": "hmac mismatch"}
            expected_prev = stored_hash
        return {"valid": True, "events": len(rows)}

    def count(self, synced: bool | None = None) -> int:
        if synced is None:
            return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE synced = ?",
            (1 if synced else 0,),
        ).fetchone()[0]

    def log_sync(self, events_synced: int, target: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO sync_log (synced_at, events_synced, target) VALUES (?, ?, ?)",
            (ts, events_synced, target),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
