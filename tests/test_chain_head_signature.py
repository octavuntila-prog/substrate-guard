"""L5 finish: Ed25519 signature over the chain head (non-repudiation / public
verifiability). See AuditChain.export(device_key=) / verify_export / verify_head_signature."""

from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")

from substrate_guard.attest.device_key import DeviceKey
from substrate_guard.chain import AuditChain

_SECRET = "s3cret-hmac"


def _chain(n=3):
    ch = AuditChain(secret=_SECRET)
    for i in range(n):
        ch.append({"type": "test", "agent_id": "a", "i": i})
    return ch


def _export_signed(tmp_path, dk, n=3):
    path = str(tmp_path / "chain.json")
    _chain(n).export(path, device_key=dk)
    return path, json.loads(open(path).read())


def test_export_attaches_ed25519_head_signature(tmp_path):
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    _, data = _export_signed(tmp_path, dk)
    assert data["head_signature_alg"] == "Ed25519"
    assert data["signer_public_key"] == dk.public_key_hex
    assert data["signer_device_id"] == dk.device_id
    assert len(bytes.fromhex(data["head_signature"])) == 64


def test_verify_export_checks_embedded_signature(tmp_path):
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    path, _ = _export_signed(tmp_path, dk)
    assert AuditChain.verify_export(path, _SECRET) == (True, None)


def test_verify_export_trusted_key_match_and_mismatch(tmp_path):
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    dk_other = DeviceKey(key_dir=tmp_path / "k2", passphrase="pw")
    path, _ = _export_signed(tmp_path, dk)
    assert AuditChain.verify_export(path, _SECRET, trusted_public_key=dk.public_key_hex) == (True, None)
    ok, reason = AuditChain.verify_export(path, _SECRET, trusted_public_key=dk_other.public_key_hex)
    assert ok is False and "trusted key" in reason


def test_require_signature(tmp_path):
    # export WITHOUT a device key -> no head_signature
    path = str(tmp_path / "nosig.json")
    _chain().export(path)
    assert AuditChain.verify_export(path, _SECRET) == (True, None)          # not required -> ok
    ok, reason = AuditChain.verify_export(path, _SECRET, require_signature=True)
    assert ok is False and "Missing Ed25519" in reason


def test_public_verify_needs_no_secret(tmp_path):
    """A third party with only the public key verifies the head — no HMAC secret."""
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    _, data = _export_signed(tmp_path, dk)
    assert AuditChain.verify_head_signature(
        data["head_hash"], data["entries_count"], data["head_signature"], data["signer_public_key"]
    ) is True


def test_public_verify_detects_head_and_count_tamper(tmp_path):
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    _, data = _export_signed(tmp_path, dk)
    sig, pub = data["head_signature"], data["signer_public_key"]
    assert AuditChain.verify_head_signature("00" * 32, data["entries_count"], sig, pub) is False
    assert AuditChain.verify_head_signature(data["head_hash"], 999, sig, pub) is False
    assert AuditChain.verify_head_signature(data["head_hash"], data["entries_count"], "ab" * 64, pub) is False


def test_head_commitment_identical_for_hmac_and_ed25519(tmp_path):
    """The HMAC chain_signature and the Ed25519 head_signature MUST bind the same
    (head, count) bytes -- guards against the two commitments drifting apart."""
    dk = DeviceKey(key_dir=tmp_path / "k", passphrase="pw")
    _, data = _export_signed(tmp_path, dk)
    commitment = AuditChain._head_commitment(data["head_hash"], data["entries_count"])
    assert commitment == f"chain:{data['head_hash']}:{data['entries_count']}".encode()
    # Ed25519 verifies against exactly this commitment
    assert DeviceKey.verify_with_public_key(
        data["signer_public_key"], commitment, bytes.fromhex(data["head_signature"])
    ) is True


def test_backward_compat_export_without_device_key(tmp_path):
    """Old call site (no device_key) still exports + verifies with only the HMAC."""
    path = str(tmp_path / "legacy.json")
    _chain().export(path)
    data = json.loads(open(path).read())
    assert "head_signature" not in data
    assert AuditChain.verify_export(path, _SECRET) == (True, None)
