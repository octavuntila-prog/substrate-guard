"""Tests for Layer 6: Offline Verification.

Tests cover:
- LocalStore: SQLite storage with HMAC chain
- HealthCheck: PostgreSQL availability detection
- SyncEngine: CRDT merge to PostgreSQL
- OfflineGuard: Automatic online/offline failover
"""

import json
import os
import sqlite3
import tempfile
import time
import pytest

from substrate_guard.offline import LocalStore, GENESIS_HASH
from substrate_guard.offline.health import HealthCheck
from substrate_guard.offline.sync import SyncEngine
from substrate_guard.offline.offline_guard import OfflineGuard
from substrate_guard.observe.events import EventType, FileEvent, NetworkEvent


SECRET = "test-offline-secret"


# ============================================
# LocalStore tests
# ============================================

class TestLocalStore:
    @pytest.fixture
    def store(self, tmp_path):
        db = str(tmp_path / "test_offline.db")
        return LocalStore(db_path=db, hmac_secret=SECRET)

    def test_empty_store(self, store):
        assert store.count() == 0
        assert store.head_hash == GENESIS_HASH

    def test_append_event(self, store):
        ev = store.append({"type": "test", "agent_id": "a1", "data": "hello"})
        assert store.count() == 1
        assert ev.event_type == "test"
        assert ev.agent_id == "a1"
        assert ev.synced is False
        assert len(ev.hash) == 64

    def test_chain_links(self, store):
        e1 = store.append({"type": "t1", "agent_id": "a1"})
        e2 = store.append({"type": "t2", "agent_id": "a1"})
        assert e2.prev_hash == e1.hash
        assert e2.hash != e1.hash

    def test_persist_across_reopen(self, tmp_path):
        db = str(tmp_path / "persist.db")
        s1 = LocalStore(db_path=db, hmac_secret=SECRET)
        s1.append({"type": "test", "agent_id": "a1"})
        head1 = s1.head_hash
        s1.close()
        
        s2 = LocalStore(db_path=db, hmac_secret=SECRET)
        assert s2.count() == 1
        assert s2.head_hash == head1
        s2.close()

    def test_verify_chain_intact(self, store):
        for i in range(10):
            store.append({"type": "test", "agent_id": f"a{i}", "idx": i})
        ok, broken = store.verify_chain()
        assert ok is True
        assert broken is None

    def test_verify_detects_tampering(self, store):
        for i in range(5):
            store.append({"type": "test", "agent_id": "a1", "idx": i})
        
        # Tamper with event 3
        store._conn.execute(
            "UPDATE events SET event_data = '{\"tampered\": true}' WHERE rowid = 3"
        )
        store._conn.commit()
        
        ok, broken = store.verify_chain()
        assert ok is False
        assert broken is not None

    def test_unsynced_tracking(self, store):
        store.append({"type": "t1", "agent_id": "a1"})
        store.append({"type": "t2", "agent_id": "a2"})
        
        assert store.count_unsynced() == 2
        
        unsynced = store.get_unsynced()
        assert len(unsynced) == 2
        
        store.mark_synced([unsynced[0].event_id])
        assert store.count_unsynced() == 1
        assert store.count(synced_only=True) == 1

    def test_append_with_policy_deny(self, store):
        ev = store.append(
            {"type": "file_write", "agent_id": "evil", "path": "/etc/passwd"},
            policy_allowed=False,
            policy_reasons=["dangerous_path: /etc/passwd"],
        )
        assert ev.policy_allowed is False
        assert "dangerous_path" in ev.policy_reasons[0]

    def test_summary(self, store):
        store.append({"type": "t1", "agent_id": "a1"})
        store.append({"type": "t2", "agent_id": "a2"})
        s = store.summary()
        assert s["total_events"] == 2
        assert s["unsynced"] == 2
        assert s["chain_integrity"] == "VERIFIED"

    def test_append_event_object(self, store):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        ev = store.append(
            event.to_dict(),
            policy_allowed=True,
        )
        assert ev.event_type == "file_write"
        assert ev.agent_id == "a1"

    def test_bulk_append(self, store):
        for i in range(100):
            store.append({"type": "bulk", "agent_id": f"agent-{i % 10}", "idx": i})
        assert store.count() == 100
        ok, _ = store.verify_chain()
        assert ok is True


# ============================================
# HealthCheck tests
# ============================================

class TestHealthCheck:
    def test_default_offline(self):
        # Connect to a port that's definitely not listening
        h = HealthCheck(db_url="postgresql://user:pass@127.0.0.1:59999/test",
                       check_interval=0, connect_timeout=0.5)
        assert h.is_pg_up() is False
        assert h.is_online() is False

    def test_status_format(self):
        h = HealthCheck(db_url="postgresql://user:pass@127.0.0.1:59999/test",
                       check_interval=0, connect_timeout=0.5)
        status = h.status()
        assert "postgresql" in status
        assert "network" in status
        assert "mode" in status
        assert status["mode"] == "OFFLINE"

    def test_parse_url(self):
        h = HealthCheck(db_url="postgresql+asyncpg://user:pass@myhost:5433/mydb")
        assert h._db_host == "myhost"
        assert h._db_port == 5433

    def test_cached_check(self):
        h = HealthCheck(db_url="postgresql://user:pass@127.0.0.1:59999/test",
                       check_interval=60, connect_timeout=0.5)
        # First check actually runs
        h.force_check()
        first_time = h._last_check
        
        # Second call uses cache (within 60s interval)
        h.is_online()
        assert h._last_check == first_time

    def test_force_check(self):
        h = HealthCheck(db_url="postgresql://user:pass@127.0.0.1:59999/test",
                       check_interval=60, connect_timeout=0.5)
        result = h.force_check()
        assert result["postgresql"] == "DOWN"


# ============================================
# SyncEngine tests (without real PG)
# ============================================

class TestSyncEngine:
    @pytest.fixture
    def store_with_events(self, tmp_path):
        db = str(tmp_path / "sync_test.db")
        store = LocalStore(db_path=db, hmac_secret=SECRET)
        for i in range(5):
            store.append({"type": "test", "agent_id": "a1", "idx": i})
        return store

    def test_sync_status(self, store_with_events):
        syncer = SyncEngine(store_with_events, db_url=None)
        status = syncer.sync_status()
        assert status["total_local"] == 5
        assert status["unsynced"] == 5
        assert status["chain_integrity"] is True

    def test_sync_no_url_fails(self, store_with_events):
        syncer = SyncEngine(store_with_events, db_url=None)
        result = syncer.sync()
        # No URL configured — should fail gracefully
        assert result["status"] in ("SYNC_FAILED", "NOTHING_TO_SYNC") or result["synced_count"] == 0

    def test_sync_nothing_to_sync(self, tmp_path):
        db = str(tmp_path / "empty.db")
        store = LocalStore(db_path=db, hmac_secret=SECRET)
        syncer = SyncEngine(store, db_url="postgresql://fake:fake@localhost/fake")
        result = syncer.sync()
        assert result["status"] == "NOTHING_TO_SYNC"
        assert result["synced_count"] == 0


# ============================================
# OfflineGuard tests
# ============================================

class TestOfflineGuard:
    @pytest.fixture
    def offline_guard(self, tmp_path):
        return OfflineGuard(
            db_url="postgresql://user:pass@127.0.0.1:59999/test",  # Non-existent PG
            local_db=str(tmp_path / "offline.db"),
            hmac_secret=SECRET,
            check_interval=0,
            auto_sync=False,
            observe=True,
            policy="nonexistent/",
            verify=True,
            use_mock=True,
        )

    def test_starts_offline(self, offline_guard):
        assert offline_guard.mode == "OFFLINE"

    def test_events_stored_locally_when_offline(self, offline_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        offline_guard.evaluate_event(event)
        
        assert offline_guard.local_store.count() == 1
        assert offline_guard._offline_events == 1

    def test_multiple_events_offline(self, offline_guard):
        for i in range(10):
            event = FileEvent(type=EventType.FILE_WRITE, path=f"/workspace/file{i}.py", agent_id="a1")
            offline_guard.evaluate_event(event)
        
        assert offline_guard.local_store.count() == 10
        ok, _ = offline_guard.local_store.verify_chain()
        assert ok is True

    def test_policy_still_works_offline(self, offline_guard):
        # Malicious event — should be denied by OPA even offline
        event = FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="evil")
        ge = offline_guard.evaluate_event(event)
        
        assert ge.policy_decision.allowed is False
        
        # Event still stored locally with policy decision
        unsynced = offline_guard.local_store.get_unsynced()
        assert len(unsynced) == 1
        assert unsynced[0].policy_allowed is False

    def test_offline_status_report(self, offline_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        offline_guard.evaluate_event(event)
        
        status = offline_guard.offline_status()
        assert status["mode"] == "OFFLINE"
        assert status["local_store"]["total_events"] == 1
        assert status["counters"]["offline_events"] == 1
        assert status["layers_offline_capable"]["L1_eBPF"] is True
        assert status["layers_offline_capable"]["L2_OPA"] is True
        assert status["layers_offline_capable"]["L3_Z3"] is True

    def test_chain_integrity_maintained(self, offline_guard):
        for i in range(20):
            event = FileEvent(type=EventType.FILE_WRITE, path=f"/workspace/f{i}.py", agent_id=f"a{i%3}")
            offline_guard.evaluate_event(event)
        
        ok, _ = offline_guard.local_store.verify_chain()
        assert ok is True
        assert offline_guard.local_store.count() == 20

    def test_guard_pipeline_works(self, offline_guard):
        """Verify the full Guard pipeline (eBPF→OPA→Z3) works through OfflineGuard."""
        from substrate_guard.observe.tracer import MockScenario
        
        with offline_guard.monitor("test-agent") as session:
            MockScenario.safe_web_agent(offline_guard.guard._tracer, "test-agent")
            session.process_events()
        
        report = session.report()
        assert report.events_observed == 4
        assert report.policy_violations == 0
