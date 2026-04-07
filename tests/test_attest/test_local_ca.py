"""Local CA certificate tests."""

from __future__ import annotations

from substrate_guard.attest.device_key import DeviceKey
from substrate_guard.attest.local_ca import LocalCA


def test_issue_and_verify_cert(tmp_path):
    keys = tmp_path / "k"
    ca = tmp_path / "c"
    dk = DeviceKey(key_dir=keys)
    lca = LocalCA(dk, ca_dir=ca)
    cur = lca.current
    assert "serial" in cur
    assert "signature" in cur
    assert lca.verify_cert(dict(cur))


def test_attestation_bundle(tmp_path):
    keys = tmp_path / "k"
    ca = tmp_path / "c"
    dk = DeviceKey(key_dir=keys)
    lca = LocalCA(dk, ca_dir=ca)
    a = lca.attestation()
    assert a["device_id"] == dk.device_id
    assert "cert_serial" in a
