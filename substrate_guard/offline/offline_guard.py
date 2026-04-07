"""Route audit rows to remote callback when PostgreSQL is reachable, else SQLite."""

from __future__ import annotations

import logging
from typing import Any, Callable

from .health import ConnectivityChecker
from .local_store import LocalStore
from .sync import SyncEngine

logger = logging.getLogger("substrate_guard.offline")


class OfflineGuard:
    """``remote_store`` optional; without it, ``record`` always uses :class:`LocalStore` when not using remote."""

    def __init__(self, config: dict | None = None) -> None:
        config = config or {}
        db = config.get("offline_db")
        if not db:
            raise ValueError("offline_db path is required in config")
        self.local = LocalStore(db_path=db, hmac_key=config.get("hmac_key"))
        self.health = ConnectivityChecker(
            pg_host=config.get("pg_host", "127.0.0.1"),
            pg_port=int(config.get("pg_port", 1)),
        )
        self._remote_store: Callable[..., None] | None = config.get("remote_store")
        self.sync_engine: SyncEngine | None = None
        if config.get("pg_factory"):
            self.sync_engine = SyncEngine(self.local, config["pg_factory"])

    def record(
        self,
        event_type: str,
        layer: str,
        data: dict[str, Any],
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        if self.health.status()["postgres"] and self._remote_store is not None:
            try:
                self._remote_store(event_type, layer, data, agent_id)
                return {"mode": "online", "stored": "remote"}
            except Exception as e:
                logger.warning("Remote store failed, using SQLite: %s", e)
        stored = self.local.store_event(event_type, layer, data, agent_id)
        return {**stored, "mode": "offline"}

    def try_sync(self) -> dict[str, Any]:
        if self.sync_engine is None:
            return {"synced": 0, "status": "no_sync_engine"}
        return self.sync_engine.sync()

    def chain_report(self) -> dict[str, Any]:
        return self.local.verify_chain()
