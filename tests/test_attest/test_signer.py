"""Event signer tests."""

from __future__ import annotations

from substrate_guard.attest.device_key import DeviceKey
from substrate_guard.attest.fingerprint import DeviceFingerprint
from substrate_guard.attest.local_ca import LocalCA
from substrate_guard.attest.signer import EventSigner


def test_sign_and_verify_roundtrip(tmp_path):
    keys = tmp_path / "k"
    ca = tmp_path / "c"
    dk = DeviceKey(key_dir=keys)
    fp = DeviceFingerprint()
    lca = LocalCA(dk, ca_dir=ca)
    signer = EventSigner(dk, fp, lca)
    ev = {"action": "file_write", "path": "/tmp/x"}
    signed = signer.sign_event(ev)
    assert "device_attestation" in signed
    assert signed["action"] == "file_write"
    assert signer.verify_signed_event(signed)


def test_tamper_breaks_verification(tmp_path):
    keys = tmp_path / "k"
    ca = tmp_path / "c"
    dk = DeviceKey(key_dir=keys)
    fp = DeviceFingerprint()
    lca = LocalCA(dk, ca_dir=ca)
    signer = EventSigner(dk, fp, lca)
    signed = signer.sign_event({"a": 1})
    signed["a"] = 2
    assert not signer.verify_signed_event(signed)
