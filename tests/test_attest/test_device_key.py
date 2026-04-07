"""Device Ed25519 key tests."""

from __future__ import annotations

from substrate_guard.attest.device_key import DeviceKey


def test_generate_and_sign_verify(tmp_path):
    dk = DeviceKey(key_dir=tmp_path)
    msg = b"hello attest"
    sig = dk.sign(msg)
    assert len(sig) == 64
    assert dk.verify(msg, sig)
    assert len(dk.public_key_hex) == 64
    assert len(dk.device_id) == 16


def test_reload_same_key(tmp_path):
    dk1 = DeviceKey(key_dir=tmp_path)
    pk = dk1.public_key_hex
    dk2 = DeviceKey(key_dir=tmp_path)
    assert dk2.public_key_hex == pk


def test_verify_tampered_fails(tmp_path):
    dk = DeviceKey(key_dir=tmp_path)
    sig = dk.sign(b"x")
    assert not dk.verify(b"y", sig)
