"""Tests for Layer 5: Device Attestation.

Tests cover:
- DeviceFingerprint: hardware identifier collection, hashing, persistence
- DeviceKey: Ed25519/HMAC signing and verification
- LocalCA: certificate issuance, verification, renewal
- AttestedGuard: full pipeline with attestation
"""

import json
import os
import time
import tempfile
import pytest

from substrate_guard.attest.fingerprint import DeviceFingerprint
from substrate_guard.attest.device_key import DeviceKey
from substrate_guard.attest.local_ca import LocalCA, DeviceCert
from substrate_guard.attest.attested_guard import AttestedGuard
from substrate_guard.observe.events import EventType, FileEvent, NetworkEvent


# ============================================
# DeviceFingerprint tests
# ============================================

class TestDeviceFingerprint:
    def test_fingerprint_created(self, tmp_path):
        fp = DeviceFingerprint(cache_path=str(tmp_path / "fp.json"))
        assert len(fp.fingerprint) == 64  # SHA-256 hex
        assert fp.fingerprint != "0" * 64

    def test_fingerprint_deterministic(self, tmp_path):
        fp1 = DeviceFingerprint(cache_path=str(tmp_path / "fp1.json"))
        fp2 = DeviceFingerprint(cache_path=str(tmp_path / "fp2.json"))
        assert fp1.fingerprint == fp2.fingerprint

    def test_components_collected(self, tmp_path):
        fp = DeviceFingerprint(cache_path=str(tmp_path / "fp.json"))
        c = fp.components
        assert "machine_id" in c
        assert "hostname" in c
        assert "platform" in c
        assert "mac_addresses" in c

    def test_save_and_verify(self, tmp_path):
        cache = str(tmp_path / "fp.json")
        fp1 = DeviceFingerprint(cache_path=cache)
        fp1.save()
        
        fp2 = DeviceFingerprint(cache_path=cache)
        assert fp2.verify() is True

    def test_to_dict(self, tmp_path):
        fp = DeviceFingerprint(cache_path=str(tmp_path / "fp.json"))
        d = fp.to_dict()
        assert "device_id" in d
        assert "fingerprint" in d
        assert len(d["device_id"]) == 16
        assert len(d["fingerprint"]) == 64


# ============================================
# DeviceKey tests
# ============================================

class TestDeviceKey:
    def test_key_generated(self, tmp_path):
        dk = DeviceKey(key_dir=str(tmp_path / "keys"))
        assert dk.backend in ("ed25519", "hmac-fallback")

    def test_sign_and_verify(self, tmp_path):
        dk = DeviceKey(key_dir=str(tmp_path / "keys"))
        data = b"test event data"
        sig = dk.sign(data)
        assert dk.verify(data, sig) is True

    def test_sign_wrong_data_fails(self, tmp_path):
        dk = DeviceKey(key_dir=str(tmp_path / "keys"))
        sig = dk.sign(b"original data")
        assert dk.verify(b"tampered data", sig) is False

    def test_sign_hex(self, tmp_path):
        dk = DeviceKey(key_dir=str(tmp_path / "keys"))
        sig_hex = dk.sign_hex("test string")
        assert dk.verify_hex("test string", sig_hex) is True
        assert dk.verify_hex("wrong string", sig_hex) is False

    def test_key_persists(self, tmp_path):
        key_dir = str(tmp_path / "keys")
        dk1 = DeviceKey(key_dir=key_dir)
        sig1 = dk1.sign(b"test")
        
        dk2 = DeviceKey(key_dir=key_dir)
        # Same key should verify same signature
        assert dk2.verify(b"test", sig1) is True

    def test_info(self, tmp_path):
        dk = DeviceKey(key_dir=str(tmp_path / "keys"))
        info = dk.info()
        assert "backend" in info
        assert info["tpm_available"] is False
        assert info["attestation_backend"] == "software-key"


# ============================================
# LocalCA tests
# ============================================

class TestLocalCA:
    def test_issue_certificate(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"))
        cert = ca.issue_certificate("abcd1234" * 8)
        assert cert.is_valid()
        assert len(cert.serial) > 0
        assert cert.issuer == "substrate-guard-ca"

    def test_certificate_expiry(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"), ttl=1)  # 1 second TTL
        cert = ca.issue_certificate("abcd1234" * 8)
        assert cert.is_valid()
        
        # Simulate expiry
        assert cert.is_valid(now=cert.expires_at + 1) is False

    def test_verify_valid_cert(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"))
        cert = ca.issue_certificate("abcd1234" * 8)
        ok, reason = ca.verify_certificate(cert)
        assert ok is True
        assert reason is None

    def test_verify_tampered_cert(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"))
        cert = ca.issue_certificate("abcd1234" * 8)
        cert.device_fingerprint = "tampered" * 8
        ok, reason = ca.verify_certificate(cert)
        assert ok is False
        assert "mismatch" in reason.lower() or "tampered" in reason.lower()

    def test_renew_if_needed(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"), ttl=86400)  # 24h
        cert = ca.issue_certificate("abcd1234" * 8)
        
        # Not near expiry — should return same cert
        same = ca.renew_if_needed(cert)
        assert same.serial == cert.serial
        
        # Simulate near-expiry (within RENEW_BEFORE=3600 window)
        cert.expires_at = time.time() + 30  # 30s left
        new = ca.renew_if_needed(cert)
        assert new.serial != cert.serial

    def test_cert_to_dict(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"))
        cert = ca.issue_certificate("test_fp")
        d = cert.to_dict()
        assert "serial" in d
        assert "signature" in d
        
        # Roundtrip
        cert2 = DeviceCert.from_dict(d)
        assert cert2.serial == cert.serial

    def test_ca_info(self, tmp_path):
        ca = LocalCA(ca_dir=str(tmp_path / "ca"))
        ca.issue_certificate("test")
        info = ca.info()
        assert info["certs_issued"] == 1
        assert info["signing_algorithm"] == "HMAC-SHA256"


# ============================================
# AttestedGuard tests
# ============================================

class TestAttestedGuard:
    @pytest.fixture
    def attested_guard(self, tmp_path):
        return AttestedGuard(
            key_dir=str(tmp_path / "attest"),
            observe=True,
            policy="nonexistent/",
            verify=True,
            use_mock=True,
        )

    def test_initialization(self, attested_guard):
        assert len(attested_guard.device_fingerprint) == 64
        assert attested_guard.cert.is_valid()

    def test_event_gets_attestation(self, attested_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        result = attested_guard.evaluate_event(event)
        
        att = result.attestation
        assert len(att.device_id) == 16
        assert len(att.device_fingerprint) == 64
        assert att.cert_valid is True
        assert att.tpm_available is False
        assert att.key_backend in ("ed25519", "hmac-fallback")
        assert len(att.signature) > 0

    def test_attestation_verifiable(self, attested_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        result = attested_guard.evaluate_event(event)
        
        assert attested_guard.verify_attestation(result) is True

    def test_policy_still_works(self, attested_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/etc/passwd", agent_id="evil")
        result = attested_guard.evaluate_event(event)
        
        assert result.guard_event.policy_decision.allowed is False
        assert result.attestation.cert_valid is True  # Attestation still valid

    def test_multiple_events(self, attested_guard):
        for i in range(10):
            event = FileEvent(type=EventType.FILE_WRITE, path=f"/workspace/f{i}.py", agent_id="a1")
            result = attested_guard.evaluate_event(event)
            assert attested_guard.verify_attestation(result) is True

    def test_attestation_status(self, attested_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        attested_guard.evaluate_event(event)
        
        status = attested_guard.attestation_status()
        assert status["attested_events"] == 1
        assert status["tpm_available"] is False
        assert status["attestation_backend"] == "software-key"
        assert "device" in status
        assert "certificate" in status
        assert status["certificate"]["valid"] is True

    def test_to_dict_complete(self, attested_guard):
        event = FileEvent(type=EventType.FILE_WRITE, path="/workspace/test.py", agent_id="a1")
        result = attested_guard.evaluate_event(event)
        d = result.to_dict()
        assert "guard" in d
        assert "attestation" in d
        assert d["attestation"]["tpm_available"] is False

    def test_different_events_different_signatures(self, attested_guard):
        e1 = FileEvent(type=EventType.FILE_WRITE, path="/workspace/a.py", agent_id="a1")
        e2 = FileEvent(type=EventType.FILE_WRITE, path="/workspace/b.py", agent_id="a1")
        r1 = attested_guard.evaluate_event(e1)
        r2 = attested_guard.evaluate_event(e2)
        assert r1.attestation.signature != r2.attestation.signature
