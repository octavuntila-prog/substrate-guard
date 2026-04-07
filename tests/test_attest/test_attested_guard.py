"""AttestedGuard integration tests."""

from __future__ import annotations

from substrate_guard.attest.attested_guard import AttestedGuard


def test_process_event_signed(tmp_path):
    key_dir = tmp_path / "keys"
    ca_dir = tmp_path / "ca"
    ag = AttestedGuard(None, {"key_dir": str(key_dir), "ca_dir": str(ca_dir)})
    out = ag.process_event({"type": "ping"})
    assert ag.signer.verify_signed_event(out)


def test_status_fields(tmp_path):
    key_dir = tmp_path / "keys"
    ca_dir = tmp_path / "ca"
    ag = AttestedGuard(None, {"key_dir": str(key_dir), "ca_dir": str(ca_dir)})
    s = ag.status()
    assert s["device_id"]
    assert s["cert_valid"] is True
    assert s["tpm_available"] is False
