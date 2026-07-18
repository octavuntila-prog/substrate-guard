"""Device Ed25519 key tests."""

from __future__ import annotations

import os

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


def test_private_key_is_owner_restricted(tmp_path):
    """The at-rest private key must not be readable by broad principals (the audited
    gap: chmod was applied only on POSIX, leaving Windows keys world-readable).
    POSIX: mode 0o600. Windows: no Everyone / BUILTIN\\Users in the ACL after the
    icacls restriction."""
    DeviceKey(key_dir=tmp_path)
    p = tmp_path / "device.key"
    assert p.exists()
    if os.name != "nt":
        import stat
        assert stat.S_IMODE(p.stat().st_mode) == 0o600
    else:
        import subprocess
        out = subprocess.run(["icacls", str(p)], capture_output=True, text=True).stdout
        assert "Everyone" not in out, out
        assert "BUILTIN\\Users" not in out, out


# ── At-rest passphrase encryption (audit 2026-07-17 item #14) ────────────────

def test_passphrase_key_is_encrypted_pem(tmp_path):
    """With a passphrase the at-rest key is PKCS#8 PEM under encryption -- the
    raw Ed25519 seed must NOT appear anywhere in the file."""
    dk = DeviceKey(key_dir=tmp_path, passphrase="s3cret-pass")
    blob = (tmp_path / "device.key").read_bytes()
    assert blob.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    sig = dk.sign(b"msg")
    assert dk.verify(b"msg", sig)


def test_passphrase_roundtrip_same_identity(tmp_path):
    dk1 = DeviceKey(key_dir=tmp_path, passphrase="s3cret-pass")
    pk = dk1.public_key_hex
    dk2 = DeviceKey(key_dir=tmp_path, passphrase="s3cret-pass")
    assert dk2.public_key_hex == pk


def test_wrong_passphrase_fails_loud(tmp_path):
    import pytest

    DeviceKey(key_dir=tmp_path, passphrase="right-pass")
    with pytest.raises(RuntimeError, match="wrong passphrase or corrupted"):
        DeviceKey(key_dir=tmp_path, passphrase="wrong-pass")


def test_missing_passphrase_on_encrypted_key_fails_loud(tmp_path, monkeypatch):
    """An encrypted key without a passphrase must ERROR -- never silently
    regenerate a new device identity over the old one."""
    import pytest

    monkeypatch.delenv("SUBSTRATE_ATTEST_KEY_PASSPHRASE", raising=False)
    dk = DeviceKey(key_dir=tmp_path, passphrase="s3cret-pass")
    pk = dk.public_key_hex
    with pytest.raises(RuntimeError, match="passphrase-encrypted"):
        DeviceKey(key_dir=tmp_path)
    # identity untouched by the failed load
    assert DeviceKey(key_dir=tmp_path, passphrase="s3cret-pass").public_key_hex == pk


def test_raw_key_upgrades_to_encrypted_with_same_identity(tmp_path):
    """Legacy raw key + newly configured passphrase -> at-rest format upgrades
    to encrypted PEM, key material (identity) unchanged."""
    dk_raw = DeviceKey(key_dir=tmp_path)          # raw, unencrypted
    pk = dk_raw.public_key_hex
    assert not (tmp_path / "device.key").read_bytes().startswith(b"-----BEGIN")
    dk_up = DeviceKey(key_dir=tmp_path, passphrase="new-pass")
    assert dk_up.public_key_hex == pk
    assert (tmp_path / "device.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED")
    # and the encrypted file now REQUIRES the passphrase
    dk_again = DeviceKey(key_dir=tmp_path, passphrase="new-pass")
    assert dk_again.public_key_hex == pk


def test_env_var_passphrase_is_honored(tmp_path, monkeypatch):
    monkeypatch.setenv("SUBSTRATE_ATTEST_KEY_PASSPHRASE", "env-pass")
    DeviceKey(key_dir=tmp_path)
    assert (tmp_path / "device.key").read_bytes().startswith(b"-----BEGIN ENCRYPTED")
    monkeypatch.delenv("SUBSTRATE_ATTEST_KEY_PASSPHRASE")
    import pytest
    with pytest.raises(RuntimeError, match="passphrase-encrypted"):
        DeviceKey(key_dir=tmp_path)
