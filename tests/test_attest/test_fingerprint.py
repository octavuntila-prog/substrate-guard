"""Device fingerprint tests."""

from __future__ import annotations

from substrate_guard.attest.fingerprint import DeviceFingerprint


def test_fingerprint_stable_64_hex():
    fp = DeviceFingerprint()
    h = fp.fingerprint()
    assert len(h) == 64
    assert fp.fingerprint() == h


def test_collect_has_hostname():
    fp = DeviceFingerprint()
    c = fp.collect()
    assert "hostname" in c
    assert "machine" in c


def test_verify_matches_self():
    fp = DeviceFingerprint()
    h = fp.fingerprint()
    assert fp.verify(h)


def test_clear_cache_changes_not_same_instance():
    fp = DeviceFingerprint()
    a = fp.fingerprint()
    fp.clear_cache()
    b = fp.fingerprint()
    assert a == b
