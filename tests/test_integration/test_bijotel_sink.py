"""Tests for the optional bijotel durable sink on AuditChain (F1 step 2).

The sink is additive dual-write: append() seals in-memory (unchanged) AND into
a bijotel chain.db when configured. Three contracts pinned here:
  1. dual-write — the event lands in the bijotel chain and verify_chain VALID,
     while the in-memory chain is byte-identical to sink-off behaviour;
  2. FAIL-OPEN (tested, not designed) — a bijotel write failure NEVER breaks the
     guard's audit path: append() still returns, in-memory chain intact;
  3. secret bridge confirmed PRE-WRITE — bad/missing/short hex bijotel secret
     (separate from substrate-guard's raw secret) fails loud at CONSTRUCTION,
     not silently at the first seal.

Skips entirely if bijotel is not installed (it is an optional extra).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

# bijotel is an optional dependency; skip the whole module if absent.
bijotel = pytest.importorskip("bijotel")
from bijotel import verify_chain  # noqa: E402

from substrate_guard.chain import AuditChain, ChainConfigError  # noqa: E402

SG_SECRET = "substrate-guard-raw-secret-string"   # raw (substrate-guard scheme)
BJ_SECRET_HEX = "ab" * 32                          # hex (bijotel scheme), 32 bytes
BJ_SECRET_BYTES = bytes.fromhex(BJ_SECRET_HEX)


def _bijotel_rows(db: Path) -> int:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT COUNT(*) FROM chain").fetchone()[0]


def test_dual_write_seals_into_bijotel_and_verifies(tmp_path: Path) -> None:
    bj_db = tmp_path / "bijotel_chain.db"
    chain = AuditChain(
        secret=SG_SECRET, bijotel_db=str(bj_db), bijotel_secret_hex=BJ_SECRET_HEX
    )

    chain.append({"type": "policy_decision", "agent_id": "a1", "allow": True})
    chain.append({"type": "verification", "agent_id": "a1", "counterexample": None})

    # in-memory chain unchanged
    assert chain.length == 2
    assert chain.verify()[0] is True

    # bijotel durable chain got both events AND verifies cryptographically
    assert _bijotel_rows(bj_db) == 2
    valid, last_seq, reason = verify_chain(bj_db, BJ_SECRET_BYTES)
    assert valid is True, reason
    assert last_seq == 2


def test_sink_off_by_default_writes_no_bijotel_db(tmp_path: Path) -> None:
    bj_db = tmp_path / "should_not_exist.db"
    chain = AuditChain(secret=SG_SECRET)  # no bijotel_db
    chain.append({"type": "x", "agent_id": "a"})
    assert chain.length == 1
    assert chain.verify()[0] is True
    assert not bj_db.exists()  # sink off => no bijotel artifact


def test_sink_is_fail_open_on_write_error(tmp_path: Path) -> None:
    """A bijotel write failure must NOT break the guard's audit path."""
    bj_db = tmp_path / "bijotel_chain.db"
    chain = AuditChain(
        secret=SG_SECRET, bijotel_db=str(bj_db), bijotel_secret_hex=BJ_SECRET_HEX
    )
    # one good event first
    chain.append({"type": "before", "agent_id": "a"})
    assert _bijotel_rows(bj_db) == 1

    # Force the sink to blow up on the next append.
    def _boom(*_a, **_k):
        raise RuntimeError("simulated bijotel outage")

    chain._bijotel_append = _boom

    # append() must NOT raise; in-memory entry is committed and returned.
    entry = chain.append({"type": "during_outage", "agent_id": "a"})
    assert entry is not None
    assert entry.event_type == "during_outage"
    assert chain.length == 2                 # in-memory advanced
    assert chain.verify()[0] is True         # in-memory chain intact
    # bijotel chain did NOT get the failed row (still 1), proving independence
    assert _bijotel_rows(bj_db) == 1


def test_bijotel_secret_invalid_hex_fails_at_construction(tmp_path: Path) -> None:
    with pytest.raises(ChainConfigError, match="valid hex"):
        AuditChain(
            secret=SG_SECRET,
            bijotel_db=str(tmp_path / "c.db"),
            bijotel_secret_hex="not-hex-zz",
        )


def test_bijotel_secret_missing_fails_at_construction(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("BIJOTEL_HMAC_SECRET", raising=False)
    with pytest.raises(ChainConfigError, match="no bijotel secret"):
        AuditChain(secret=SG_SECRET, bijotel_db=str(tmp_path / "c.db"))


def test_bijotel_secret_too_short_fails_at_construction(tmp_path: Path) -> None:
    with pytest.raises(ChainConfigError, match="16 bytes"):
        AuditChain(
            secret=SG_SECRET,
            bijotel_db=str(tmp_path / "c.db"),
            bijotel_secret_hex="abcd",  # 2 bytes
        )


def test_bijotel_secret_from_env(tmp_path: Path, monkeypatch) -> None:
    """Sink resolves the bijotel secret from BIJOTEL_HMAC_SECRET when no param."""
    bj_db = tmp_path / "bijotel_chain.db"
    monkeypatch.setenv("BIJOTEL_HMAC_SECRET", BJ_SECRET_HEX)
    chain = AuditChain(secret=SG_SECRET, bijotel_db=str(bj_db))
    chain.append({"type": "via_env", "agent_id": "a"})
    valid, _last, reason = verify_chain(bj_db, BJ_SECRET_BYTES)
    assert valid is True, reason
    assert _bijotel_rows(bj_db) == 1


def test_secrets_are_independent_schemes(tmp_path: Path) -> None:
    """The bijotel chain verifies with the BIJOTEL secret, not the SG secret."""
    bj_db = tmp_path / "bijotel_chain.db"
    chain = AuditChain(
        secret=SG_SECRET, bijotel_db=str(bj_db), bijotel_secret_hex=BJ_SECRET_HEX
    )
    chain.append({"type": "x", "agent_id": "a"})
    # Correct (bijotel) secret verifies.
    assert verify_chain(bj_db, BJ_SECRET_BYTES)[0] is True
    # The substrate-guard raw secret must NOT verify the bijotel chain.
    assert verify_chain(bj_db, SG_SECRET.encode())[0] is False
