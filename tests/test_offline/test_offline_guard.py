"""OfflineGuard tests."""

from __future__ import annotations

import pytest

from substrate_guard.chain import ChainConfigError
from substrate_guard.offline.offline_guard import OfflineGuard


def test_no_hmac_key_raises(tmp_path, monkeypatch):
    """No hmac_key in config and no env var, no opt-in → ChainConfigError.

    OfflineGuard threads its LocalStore through the same L4 fail-loud
    discipline (v13.4.0 Decision 1) — it must not silently fall back to a
    publicly-known default key.
    """
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    with pytest.raises(ChainConfigError):
        OfflineGuard({"offline_db": str(tmp_path / "o.db")})


def test_allow_insecure_default_opt_in(tmp_path, monkeypatch):
    """Explicit allow_insecure_default in config → constructs (demo/testing)."""
    monkeypatch.delenv("GUARD_HMAC_SECRET", raising=False)
    g = OfflineGuard(
        {
            "offline_db": str(tmp_path / "o.db"),
            "allow_insecure_default": True,
        }
    )
    r = g.record("e", "L", {"x": 1})
    assert r["mode"] == "offline"
    assert g.chain_report()["events"] == 1
    g.local.close()


def test_record_goes_local_when_pg_down(tmp_path):
    g = OfflineGuard(
        {
            "offline_db": str(tmp_path / "o.db"),
            "pg_host": "127.0.0.1",
            "pg_port": 1,
            "hmac_key": "hk",
        }
    )
    r = g.record("e", "layer", {"x": 1}, agent_id="a1")
    assert r["mode"] == "offline"
    assert r["stored"] == "local"
    assert g.chain_report()["events"] == 1
    g.local.close()


def test_record_remote_when_configured_and_pg_up(monkeypatch, tmp_path):
    calls = []

    def remote(et, layer, data, agent_id):
        calls.append((et, layer, data, agent_id))

    monkeypatch.setattr(
        "substrate_guard.offline.offline_guard.ConnectivityChecker.status",
        lambda self: {
            "postgres": True,
            "internet": False,
            "mode": "online",
            "alerts": False,
        },
    )
    g = OfflineGuard(
        {
            "offline_db": str(tmp_path / "o.db"),
            "remote_store": remote,
            "hmac_key": "hk",
        }
    )
    r = g.record("e", "L", {"z": 3})
    assert r["mode"] == "online"
    assert r["stored"] == "remote"
    assert len(calls) == 1
    g.local.close()
