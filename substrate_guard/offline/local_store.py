"""Append-only SQLite store with HMAC chain (offline audit fallback)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..chain import ChainConfigError

GENESIS_PREV = "0" * 64

# Publicly-known key used ONLY when the caller explicitly opts in via
# ``allow_insecure_default=True`` (demo / testing). It is committed to source,
# so anyone can forge the chain with it — it provides no tamper resistance and
# must never be selected silently.
INSECURE_DEFAULT_HMAC_KEY = "substrate-guard-default-dev-key"

logger = logging.getLogger("substrate_guard.offline")


class LocalStore:
    """WAL-mode SQLite for events when PostgreSQL / network is unavailable."""

    def __init__(
        self,
        db_path: str | Path,
        hmac_key: str | bytes | None = None,
        allow_insecure_default: bool = False,
    ) -> None:
        self.db_path = Path(db_path)
        self.hmac_key = self._resolve_hmac_key(hmac_key, allow_insecure_default)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a re-entrant lock: usable from worker threads (a
        # thread-bound connection silently lost writes). isolation_level=None
        # (autocommit) so store_event can hold an explicit BEGIN IMMEDIATE write lock
        # for an ATOMIC read-tail-then-append -- otherwise concurrent writers (even
        # across processes) both chain from the same tail and FORK the chain.
        self._lock = threading.RLock()
        self.conn = __import__("sqlite3").connect(
            str(self.db_path), check_same_thread=False, isolation_level=None
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    @staticmethod
    def _resolve_hmac_key(
        hmac_key: str | bytes | None,
        allow_insecure_default: bool,
    ) -> bytes:
        """Resolve the HMAC key, failing loud when none is configured.

        Mirrors the L4 ``AuditChain`` discipline (v13.4.0 Decision 1): an
        explicit key — ``hmac_key=`` parameter or the ``GUARD_HMAC_SECRET``
        environment variable (unified with L4; was ``GUARD_HMAC_KEY``) — is
        required, and the insecure fallback must be opted into rather than
        applied silently behind a hardcoded default.

        Unlike ``AuditChain`` — whose opt-in generates a *random* per-process
        key — ``LocalStore`` persists events to SQLite and must verify the
        same DB across process restarts, so a random key would render a
        reopened store unverifiable. The opt-in here therefore selects a
        *stable* but publicly-known dev key, clearly labelled insecure.

        Raises:
            ChainConfigError: If no key is available (neither parameter nor
                ``SUBSTRATE_GUARD_HMAC_SECRET`` / ``GUARD_HMAC_SECRET`` env) and ``allow_insecure_default`` is
                False (the default).
        """
        # Accept SUBSTRATE_GUARD_HMAC_SECRET (the operational/cron name) first, then the
        # legacy GUARD_HMAC_SECRET -- same resolution order as AuditChain, so an operator
        # who sets only the documented name gets a working offline store too.
        raw = (hmac_key or os.environ.get("SUBSTRATE_GUARD_HMAC_SECRET")
               or os.environ.get("GUARD_HMAC_SECRET", ""))
        if not raw:
            if not allow_insecure_default:
                raise ChainConfigError(
                    "LocalStore requires an HMAC key. Pass hmac_key=, set the "
                    "SUBSTRATE_GUARD_HMAC_SECRET (or GUARD_HMAC_SECRET) environment variable, or pass "
                    "allow_insecure_default=True (demo/testing only — uses a "
                    "publicly-known key that provides no tamper resistance)."
                )
            logger.warning(
                "LocalStore using the publicly-known insecure default HMAC "
                "key — the offline audit chain is NOT tamper-evident. Set "
                "GUARD_HMAC_SECRET or pass hmac_key= for any real use."
            )
            raw = INSECURE_DEFAULT_HMAC_KEY
        return raw.encode() if isinstance(raw, str) else raw

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

    def _compute_hmac(
        self, event_id: str, timestamp: str, event_type: str,
        agent_id: str | None, layer: str, data: str, prev_hash: str,
    ) -> str:
        # Bind EVERY authenticated column (not just data+prev_hash) with an
        # unambiguous unit separator, so a tampered event_type/agent_id/timestamp/
        # layer/id is detected by verify_chain (the chain.py denormalized-field fix,
        # propagated to L6).
        # Canonical JSON list -> UNAMBIGUOUS field boundaries (no \x1f delimiter
        # injection, where an embedded separator rebalances content across fields to
        # forge a collision) AND native None-vs-"" distinction (null vs ""), so any
        # tampered field is detected by verify_chain. Replaces a "\x1f".join that emitted
        # the fields raw.
        payload = json.dumps(
            [prev_hash, event_id, timestamp, event_type, agent_id, layer, data]
        ).encode()
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
        with self._lock:
            # BEGIN IMMEDIATE takes the write lock BEFORE reading the tail, so the
            # read-tail + append is atomic across processes (no chain fork).
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                prev_hash = self._get_last_hash()
                hmac_hash = self._compute_hmac(
                    event_id, timestamp, event_type, agent_id, layer, data_json, prev_hash
                )
                self.conn.execute(
                    """INSERT INTO events
                       (id, timestamp, event_type, agent_id, layer, data,
                        hmac_hash, prev_hash, synced)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                    (event_id, timestamp, event_type, agent_id, layer,
                     data_json, hmac_hash, prev_hash),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {
            "id": event_id,
            "timestamp": timestamp,
            "hmac_hash": hmac_hash,
            "stored": "local",
        }

    def get_unsynced(self, limit: int = 1000) -> list[dict[str, Any]]:
        with self._lock:
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
        # One bound parameter per row (no dynamic IN (...) SQL); sqlite3.executemany batches safely.
        with self._lock:
            self.conn.executemany(
                "UPDATE events SET synced = 1 WHERE id = ?",
                [(eid,) for eid in event_ids],
            )
            self.conn.commit()

    def verify_chain(self, expected_count: int | None = None) -> dict[str, Any]:
        """Walk the HMAC chain. Like AuditChain.verify, a valid PREFIX verifies, so a
        TAIL-TRUNCATED store still reports valid; pass expected_count (held out-of-band)
        to detect it."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT id, timestamp, event_type, agent_id, layer, data, "
                "hmac_hash, prev_hash FROM events ORDER BY rowid ASC"
            ).fetchall()
        if expected_count is not None and len(rows) != expected_count:
            return {"valid": False, "events": len(rows),
                    "reason": f"row count {len(rows)} != expected {expected_count} (possible truncation)"}
        if not rows:
            return {"valid": True, "events": 0}
        expected_prev = GENESIS_PREV
        for i, (eid, ts, etype, aid, layer, data, stored_hash, prev_hash) in enumerate(rows):
            if prev_hash != expected_prev:
                return {
                    "valid": False,
                    "broken_at": i,
                    "reason": "prev_hash mismatch",
                }
            computed = self._compute_hmac(eid, ts, etype, aid, layer, data, prev_hash)
            if computed != stored_hash:
                return {"valid": False, "broken_at": i, "reason": "hmac mismatch"}
            expected_prev = stored_hash
        return {"valid": True, "events": len(rows)}

    def count(self, synced: bool | None = None) -> int:
        with self._lock:
            if synced is None:
                return self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            return self.conn.execute(
                "SELECT COUNT(*) FROM events WHERE synced = ?",
                (1 if synced else 0,),
            ).fetchone()[0]

    def log_sync(self, events_synced: int, target: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.conn.execute(
                "INSERT INTO sync_log (synced_at, events_synced, target) VALUES (?, ?, ?)",
                (ts, events_synced, target),
            )
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()
