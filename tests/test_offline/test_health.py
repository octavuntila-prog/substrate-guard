"""Connectivity checker tests."""

from __future__ import annotations

from substrate_guard.offline.health import ConnectivityChecker


def test_postgres_unreachable_local_port():
    c = ConnectivityChecker(pg_host="127.0.0.1", pg_port=1, timeout=0.1)
    assert c.check_postgres() is False
    assert c.status()["mode"] == "offline"


def test_internet_monkeypatched_offline(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("no net")

    monkeypatch.setattr(
        "substrate_guard.offline.health.socket.create_connection",
        boom,
    )
    assert ConnectivityChecker().check_internet() is False
