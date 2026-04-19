"""OfflineGuard — Wraps Guard with automatic online/offline failover.

Online mode:  events → Guard → PostgreSQL (normal)
PG goes down: events → Guard → SQLite (automatic switch)
PG comes back: events → Guard → PostgreSQL + sync SQLite backlog

Z3, OPA, and eBPF all work offline by design. The only component
that needs network is PostgreSQL storage. OfflineGuard handles
the storage failover transparently.

Usage:
    guard = OfflineGuard(
        db_url="postgresql://...",
        local_db="/var/lib/substrate-guard/offline.db",
        observe=True, policy="policies/", verify=True,
    )
    
    # Works identically to Guard — but survives PG outages
    with guard.monitor("agent-7") as session:
        result = agent.run(task="something")
        session.process_events()
    
    # Check status
    print(guard.offline_status())
"""

from __future__ import annotations

import logging
import time
from typing import Optional
from pathlib import Path

from ..guard import Guard, GuardEvent, SessionReport
from ..observe.events import Event
from .health import HealthCheck
from .sync import SyncEngine

logger = logging.getLogger("substrate_guard.offline.guard")

# Import LocalStore from the __init__ module
from . import LocalStore


class OfflineGuard:
    """Guard with automatic online/offline failover.
    
    Wraps the standard Guard pipeline (eBPF → OPA → Z3 → HMAC chain)
    and adds transparent storage failover:
    
    - When PostgreSQL is reachable: normal operation
    - When PostgreSQL is down: events stored in local SQLite
    - When PostgreSQL returns: automatic sync of backlog
    
    All verification layers (eBPF, OPA, Z3) work identically in both
    modes — they are local by design.
    
    Args:
        db_url: PostgreSQL URL for online storage and sync target.
        local_db: Path to SQLite database for offline storage.
        hmac_secret: HMAC secret for both online chain and local chain.
        check_interval: Seconds between PostgreSQL health checks.
        auto_sync: Automatically sync when PostgreSQL comes back.
        **guard_kwargs: Passed to Guard constructor (observe, policy, verify, etc.)
    """

    def __init__(
        self,
        db_url: Optional[str] = None,
        local_db: str = "/var/lib/substrate-guard/offline.db",
        hmac_secret: Optional[str] = None,
        check_interval: float = 30.0,
        auto_sync: bool = True,
        **guard_kwargs,
    ):
        # Core Guard (eBPF → OPA → Z3 → chain)
        self._guard = Guard(
            chain=True,
            hmac_secret=hmac_secret,
            **guard_kwargs,
        )
        
        # Offline components
        self._local_store = LocalStore(db_path=local_db, hmac_secret=hmac_secret)
        self._health = HealthCheck(db_url=db_url, check_interval=check_interval)
        self._sync_engine = SyncEngine(self._local_store, db_url=db_url)
        
        self._auto_sync = auto_sync
        self._mode = "INITIALIZING"
        self._offline_events = 0
        self._online_events = 0
        self._sync_count = 0
        self._last_mode_change = time.time()
        
        # Initial check
        if self._health.is_online():
            self._mode = "ONLINE"
            logger.info("OfflineGuard started in ONLINE mode")
        else:
            self._mode = "OFFLINE"
            logger.warning("OfflineGuard started in OFFLINE mode — events will be stored locally")

    def evaluate_event(self, event: Event) -> GuardEvent:
        """Evaluate event through full pipeline, storing appropriately.
        
        The verification pipeline (eBPF → OPA → Z3) runs identically
        regardless of online/offline mode. Only storage differs.
        """
        # Full pipeline evaluation (works offline — all local)
        guard_event = self._guard.evaluate_event(event)
        
        # Check if mode should change
        was_online = (self._mode == "ONLINE")
        is_online = self._health.is_online()
        
        if was_online and not is_online:
            self._mode = "OFFLINE"
            self._last_mode_change = time.time()
            logger.warning("Switching to OFFLINE mode — PostgreSQL unreachable")
        
        elif not was_online and is_online:
            self._mode = "ONLINE"
            self._last_mode_change = time.time()
            logger.info("Switching to ONLINE mode — PostgreSQL is back")
            
            # Auto-sync backlog
            if self._auto_sync and self._local_store.count_unsynced() > 0:
                self._do_sync()
        
        # Store in local SQLite if offline
        if not is_online:
            event_data = event.to_dict() if hasattr(event, 'to_dict') else {"raw": str(event)}
            self._local_store.append(
                event_data=event_data,
                policy_allowed=guard_event.policy_decision.allowed,
                policy_reasons=guard_event.policy_decision.reasons,
            )
            self._offline_events += 1
        else:
            self._online_events += 1
        
        return guard_event

    def _do_sync(self):
        """Sync local events to PostgreSQL."""
        unsynced = self._local_store.count_unsynced()
        if unsynced == 0:
            return
        
        logger.info(f"Auto-syncing {unsynced} offline events to PostgreSQL...")
        result = self._sync_engine.sync()
        self._sync_count += result.get("synced_count", 0)
        
        if result["status"] == "SYNCED":
            logger.info(f"Sync complete: {result['synced_count']} events")
        else:
            logger.warning(f"Sync partial: {result}")

    def force_sync(self) -> dict:
        """Force sync regardless of auto_sync setting."""
        return self._sync_engine.sync()

    def monitor(self, agent_id: str):
        """Delegate to Guard's monitor context manager."""
        return self._guard.monitor(agent_id)

    def verify_artifact(self, artifact, artifact_type: str = "code"):
        """Delegate to Guard's verify_artifact."""
        return self._guard.verify_artifact(artifact, artifact_type)

    def offline_status(self) -> dict:
        """Complete offline/online status report."""
        health = self._health.status()
        local = self._local_store.summary()
        
        return {
            "mode": self._mode,
            "health": health,
            "local_store": local,
            "counters": {
                "online_events": self._online_events,
                "offline_events": self._offline_events,
                "total_synced": self._sync_count,
            },
            "last_mode_change": self._last_mode_change,
            "layers_offline_capable": {
                "L1_eBPF": True,  # kernel-level, no network needed
                "L2_OPA": True,   # policy file is local
                "L3_Z3": True,    # solver runs on-device
                "L4_chain": True, # HMAC is local crypto
                "L6_storage": True,  # SQLite fallback
            },
        }

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def guard(self) -> Guard:
        """Access the underlying Guard for direct use."""
        return self._guard

    @property
    def local_store(self) -> LocalStore:
        return self._local_store
