"""Local CA certificate tests."""

from __future__ import annotations

import json

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


def test_verify_cert_rejects_foreign_key_signed_by_local(tmp_path):
    """A cert claiming a DIFFERENT public_key but signed by the local CA key must
    be rejected. The previous verify_cert checked the signature against
    self.device_key, so ANY locally-signed cert passed regardless of the
    public_key it claimed -- an identity spoof."""
    dk = DeviceKey(key_dir=tmp_path / "k")
    lca = LocalCA(dk, ca_dir=tmp_path / "c")
    other = DeviceKey(key_dir=tmp_path / "k2")

    # Build a cert that CLAIMS `other`'s identity but is SIGNED by the local key.
    cert_data = {
        "version": 1,
        "device_id": other.device_id,
        "public_key": other.public_key_hex,
        "issued_at": "2026-06-07T00:00:00+00:00",
        "expires_at": "2099-01-01T00:00:00+00:00",
        "issuer": "substrate-guard-local-ca",
        "serial": "deadbeefdeadbeef",
    }
    payload = json.dumps(cert_data, sort_keys=True).encode()
    spoof = {**cert_data, "signature": dk.sign(payload).hex()}

    # Locally signed, but it claims `other`'s key -> must be rejected.
    assert lca.verify_cert(spoof) is False
    # Sanity: a genuine cert (claims + signed by dk) still verifies.
    assert lca.verify_cert(dict(lca.current)) is True
