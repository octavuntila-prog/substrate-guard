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
