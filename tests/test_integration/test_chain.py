"""Tests for HMAC-SHA256 tamper-evident chain and compliance export."""

import json
import os
import pytest
import tempfile

from substrate_guard.chain import AuditChain, ChainEntry, GENESIS_HASH
from substrate_guard.compliance import ComplianceExporter
from substrate_guard.guard import Guard, SessionReport
from substrate_guard.observe.events import (
    EventType, FileEvent, NetworkEvent, ProcessEvent,
)
from substrate_guard.observe.tracer import MockScenario


SECRET = "test-secret-key-for-chain"


# ============================================
# AuditChain core tests
# ============================================

class TestAuditChain:
    def test_empty_chain(self):
        chain = AuditChain(secret=SECRET)
        assert chain.length == 0
        assert chain.head_hash == GENESIS_HASH

    def test_append_event(self):
        chain = AuditChain(secret=SECRET)
        entry = chain.append({"type": "test", "agent_id": "a1", "data": "hello"})
        assert chain.length == 1
        assert entry.index == 0
        assert entry.prev_hash == GENESIS_HASH
        assert len(entry.hash) == 64  # SHA-256 hex

    def test_chain_links(self):
        chain = AuditChain(secret=SECRET)
        e1 = chain.append({"type": "t1", "agent_id": "a1"})
        e2 = chain.append({"type": "t2", "agent_id": "a1"})
        assert e2.prev_hash == e1.hash
        assert e2.hash != e1.hash

    def test_verify_intact(self):
        chain = AuditChain(secret=SECRET)
        for i in range(10):
            chain.append({"type": "test", "agent_id": f"a{i}", "index": i})
        ok, idx = chain.verify()
        assert ok is True
        assert idx is None

    def test_verify_detects_tampering(self):
        chain = AuditChain(secret=SECRET)
        for i in range(5):
            chain.append({"type": "test", "index": i})
        # Tamper with entry 2
        chain._entries[2].event_data["index"] = 999
        ok, idx = chain.verify()
        assert ok is False
        assert idx == 2

    def test_verify_detects_deletion(self):
        chain = AuditChain(secret=SECRET)
        for i in range(5):
            chain.append({"type": "test", "index": i})
        # Delete entry 2
        del chain._entries[2]
        # Fix indices to hide deletion
        for i, e in enumerate(chain._entries):
            e.index = i
        ok, idx = chain.verify()
        assert ok is False

    def test_verify_detects_insertion(self):
        chain = AuditChain(secret=SECRET)
        for i in range(3):
            chain.append({"type": "test", "index": i})
        # Insert fake entry
        fake = ChainEntry(
            index=1, timestamp=0, event_type="fake",
            agent_id="evil", event_data={"type": "fake"},
            prev_hash=chain._entries[0].hash, hash="fake_hash",
        )
        chain._entries.insert(1, fake)
        ok, idx = chain.verify()
        assert ok is False

    def test_different_secrets_different_hashes(self):
        c1 = AuditChain(secret="secret-A")
        c2 = AuditChain(secret="secret-B")
        data = {"type": "test", "value": 42}
        e1 = c1.append(data)
        e2 = c2.append(data)
        assert e1.hash != e2.hash

    def test_append_event_object(self):
        chain = AuditChain(secret=SECRET)
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py",
                         agent_id="a1")
        entry = chain.append(event)
        assert entry.event_type == "file_write"
        assert entry.agent_id == "a1"

    def test_summary(self):
        chain = AuditChain(secret=SECRET)
        chain.append({"type": "file_write", "agent_id": "a1"})
        chain.append({"type": "network_connect", "agent_id": "a2"})
        chain.append({"type": "file_write", "agent_id": "a1"})
        s = chain.summary()
        assert s["chain_length"] == 3
        assert s["unique_agents"] == 2
        assert s["event_types"]["file_write"] == 2
        assert s["integrity"] == "verified"


# ============================================
# Chain export/import tests
# ============================================

class TestChainExport:
    def test_export_and_verify(self):
        chain = AuditChain(secret=SECRET)
        for i in range(5):
            chain.append({"type": "test", "index": i, "agent_id": "a1"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            chain.export(path)
            ok, reason = AuditChain.verify_export(path, secret=SECRET)
            assert ok is True
            assert reason is None
        finally:
            os.unlink(path)

    def test_export_tampered_fails(self):
        chain = AuditChain(secret=SECRET)
        for i in range(3):
            chain.append({"type": "test", "index": i, "agent_id": "a1"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            chain.export(path)
            # Tamper with the file
            data = json.loads(open(path).read())
            data["entries"][1]["event_data"]["index"] = 999
            open(path, "w").write(json.dumps(data))
            ok, reason = AuditChain.verify_export(path, secret=SECRET)
            assert ok is False
            assert "mismatch" in reason.lower()
        finally:
            os.unlink(path)

    def test_wrong_secret_fails(self):
        chain = AuditChain(secret=SECRET)
        chain.append({"type": "test", "agent_id": "a1"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            chain.export(path)
            ok, reason = AuditChain.verify_export(path, secret="wrong-secret")
            assert ok is False
        finally:
            os.unlink(path)

    def test_export_format(self):
        chain = AuditChain(secret=SECRET)
        chain.append({"type": "test", "agent_id": "a1"})

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            chain.export(path)
            data = json.loads(open(path).read())
            assert data["format"] == "substrate-guard-audit-chain"
            assert data["version"] == "1.0"
            assert data["entries_count"] == 1
            assert "chain_signature" in data
        finally:
            os.unlink(path)


# ============================================
# Guard + Chain integration tests
# ============================================

class TestGuardChainIntegration:
    def test_guard_with_chain(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=True, hmac_secret=SECRET, use_mock=True,
        )
        assert guard._chain is not None
        assert guard._chain.length == 0

    def test_events_added_to_chain(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=True, hmac_secret=SECRET, use_mock=True,
        )
        guard.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py", agent_id="a1")
        )
        guard.evaluate_event(
            NetworkEvent(type=EventType.NETWORK_CONNECT, remote_port=443, agent_id="a1")
        )
        assert guard._chain.length == 2
        ok, _ = guard._chain.verify()
        assert ok is True

    def test_chain_includes_policy_decision(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=True, hmac_secret=SECRET, use_mock=True,
        )
        guard.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="a1")
        )
        entry = guard._chain.entries[0]
        assert entry.event_data["_policy_allowed"] is False
        assert len(entry.event_data["_policy_reasons"]) > 0

    def test_scenario_through_chain(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=True, hmac_secret=SECRET, use_mock=True,
        )
        with guard.monitor("chain-test") as session:
            MockScenario.malicious_agent(guard._tracer, "chain-test")
            session.process_events()

        assert guard._chain.length == 4
        ok, _ = guard._chain.verify()
        assert ok is True

    def test_guard_without_chain(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=False, use_mock=True,
        )
        assert guard._chain is None
        # Should work fine without chain
        guard.evaluate_event(
            FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py", agent_id="a1")
        )


# ============================================
# Compliance export tests
# ============================================

class TestComplianceExport:
    @pytest.fixture
    def chain_and_report(self):
        guard = Guard(
            observe=True, policy="nonexistent/", verify=True,
            chain=True, hmac_secret=SECRET, use_mock=True,
        )
        with guard.monitor("compliance-test") as session:
            MockScenario.safe_web_agent(guard._tracer, "compliance-test")
            session.process_events()
        return guard._chain, session.report()

    def test_soc2_export(self, chain_and_report):
        chain, report = chain_and_report
        exporter = ComplianceExporter(chain, report)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            exporter.export_soc2(path)
            data = json.loads(open(path).read())
            assert data["framework"] == "SOC 2 Type II"
            assert "CC6.1_logical_access" in data["trust_service_criteria"]
            assert "CC7.2_system_monitoring" in data["trust_service_criteria"]
            assert "CC8.1_change_management" in data["trust_service_criteria"]
            assert "CC4.1_monitoring_controls" in data["trust_service_criteria"]
            assert data["chain_integrity"]["status"] == "VERIFIED"
        finally:
            os.unlink(path)

    def test_iso27001_export(self, chain_and_report):
        chain, report = chain_and_report
        exporter = ComplianceExporter(chain, report)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            exporter.export_iso27001(path)
            data = json.loads(open(path).read())
            assert data["framework"] == "ISO 27001:2022"
            assert "A.8.15_logging" in data["annex_a_controls"]
        finally:
            os.unlink(path)

    def test_iso42001_export(self, chain_and_report):
        chain, report = chain_and_report
        exporter = ComplianceExporter(chain, report)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            exporter.export_iso42001(path)
            data = json.loads(open(path).read())
            assert data["framework"] == "ISO/IEC 42001:2023"
            assert "audit_trail" in data["controls"]
        finally:
            os.unlink(path)

    def test_summary_export(self, chain_and_report):
        chain, report = chain_and_report
        exporter = ComplianceExporter(chain, report)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            exporter.export_summary(path)
            data = json.loads(open(path).read())
            assert data["compliance_status"]["SOC_2_Type_II"] == "EVIDENCE_AVAILABLE"
            assert "differentiator" in data
        finally:
            os.unlink(path)
