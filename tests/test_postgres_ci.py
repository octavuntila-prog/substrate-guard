"""Postgres integration — run only when ``POSTGRES_CI=1`` (GitHub Actions ``postgres-ci`` job)."""

from __future__ import annotations

import os

import pytest

pytestmark = [
    pytest.mark.postgres_ci,
    pytest.mark.skipif(
        os.environ.get("POSTGRES_CI") != "1",
        reason="set POSTGRES_CI=1 with a reachable Postgres (see CI workflow postgres-ci)",
    ),
]


_MOCK_HMAC_SECRET = "test-mock-hmac-key-deterministic-not-for-production"


@pytest.fixture(autouse=True)
def _mock_hmac_secret_env(monkeypatch):
    """Auto-applied: HMAC env vars for run_audit() tests in this module.

    Mirrors tests/test_integration/test_audit.py fixture (v13.4.0 Step 5.pre).
    test_run_audit_* here run ONLY when POSTGRES_CI=1 (CI postgres-ci job) —
    invisible to local pytest (always skipped), live in CI. Without this,
    run_audit() -> Guard(chain=True, hmac_secret=None) -> ChainConfigError
    fail-loud (Decision 1). The Step 5.pre fixture was scoped to test_audit.py
    only; this closes the test_postgres_ci.py gap (CI-surfaced, N=14 pattern).
    """
    monkeypatch.setenv("SUBSTRATE_GUARD_HMAC_SECRET", _MOCK_HMAC_SECRET)
    monkeypatch.setenv("GUARD_HMAC_SECRET", _MOCK_HMAC_SECRET)


def _db_url():
    from substrate_guard.audit import resolve_db_url

    url = resolve_db_url(None, None)
    assert url, "resolve_db_url returned None — set POSTGRES_* or DATABASE_URL"
    return url


def test_resolve_url_from_ci_env():
    url = _db_url()
    assert url.startswith("postgresql://")


def test_query_db_roundtrip():
    from substrate_guard.audit import query_db

    rows = query_db(_db_url(), "SELECT 1 AS one")
    assert rows and rows[0].get("one") == 1


def test_fetch_table_counts_pipeline_tables():
    from substrate_guard.audit import fetch_table_counts

    counts = fetch_table_counts(_db_url())
    assert counts.get("pipeline_traces", -1) >= 0
    assert counts.get("agent_runs", -1) >= 0


def test_fetch_pipeline_and_runs_empty_ok():
    from substrate_guard.audit import fetch_agent_runs, fetch_pipeline_traces

    db_url = _db_url()
    assert fetch_pipeline_traces(db_url, hours=None) == []
    assert fetch_agent_runs(db_url, hours=None) == []


def test_run_audit_zero_rows(tmp_path):
    from substrate_guard.audit import run_audit
    from substrate_guard.constants import BUILTIN_POLICY_PATH

    code = run_audit(
        _db_url(),
        hours=None,
        output_dir=str(tmp_path),
        policy_path=BUILTIN_POLICY_PATH,
        policy_mode='builtin',
        policy_source='default',
    )
    assert code == 0
    assert list(tmp_path.glob("audit_*.json"))


def test_run_audit_with_one_trace(tmp_path):
    from substrate_guard.audit import run_audit

    try:
        import psycopg2
    except ImportError:
        pytest.skip("psycopg2-binary not installed")

    db_url = _db_url()
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pipeline_traces (
                    trace_id, pipeline_run_id, step_index, agent_name, status,
                    model_used, input_summary, output_summary, duration_ms,
                    started_at, completed_at
                ) VALUES (
                    'ci-row-1', '1', 1, 'CI Agent', 'completed',
                    'gpt', 'hello', 'world result', 10,
                    NOW(), NOW()
                )
                """
            )
    finally:
        conn.close()

    try:
        from substrate_guard.constants import BUILTIN_POLICY_PATH

        code = run_audit(
            db_url,
            hours=None,
            output_dir=str(tmp_path),
            policy_path=BUILTIN_POLICY_PATH,
            policy_mode='builtin',
            policy_source='default',
        )
        assert code == 0
    finally:
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM pipeline_traces WHERE trace_id = 'ci-row-1'")
        finally:
            conn.close()


def test_run_audit_violation_row_exits_1(tmp_path):
    """Execute-test for the violation(1) branch (audit 2026-07-17 item #13).

    The clean(0) branch above is execute-tested; this closes the other half of
    the exit-code contract on real Postgres. Deterministic route through the
    vendor bridge: a critical system path in output_summary becomes
    FileEvent(FILE_WRITE, path=/etc/passwd) -> _check_dangerous_paths denies ->
    >=1 violation -> run_audit returns 1. model_used stays NULL so the only
    other synthesized event is a harmless PROCESS_EXEC.
    """
    from substrate_guard.audit import run_audit
    from substrate_guard.constants import BUILTIN_POLICY_PATH

    try:
        import psycopg2
    except ImportError:
        pytest.skip("psycopg2-binary not installed")

    db_url = _db_url()
    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO pipeline_traces (
                    trace_id, pipeline_run_id, step_index, agent_name, status,
                    model_used, input_summary, output_summary, duration_ms,
                    started_at, completed_at
                ) VALUES (
                    'ci-violation-1', '1', 1, 'CI Violation Agent', 'completed',
                    NULL, 'n/a', 'wrote config to /etc/passwd then continued', 10,
                    NOW(), NOW()
                )
                """
            )
        conn.commit()   # psycopg2 is NOT autocommit -- run_audit's separate
        #                 connection must actually SEE the row (the benign clean(0)
        #                 test above passes even uncommitted; a violation row does not).
    finally:
        conn.close()

    try:
        code = run_audit(
            db_url,
            hours=None,
            output_dir=str(tmp_path),
            policy_path=BUILTIN_POLICY_PATH,
            policy_mode='builtin',
            policy_source='default',
        )
        assert code == 1, f"violation row must exit 1, got {code}"
        # the report must actually record the violation
        import json
        reports = sorted(tmp_path.glob("audit_*.json"))
        assert reports, "no audit report written"
        data = json.loads(reports[-1].read_text())
        assert data["evaluation"]["violations"] >= 1
    finally:
        conn = psycopg2.connect(db_url)
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM pipeline_traces WHERE trace_id = 'ci-violation-1'")
            conn.commit()
        finally:
            conn.close()


_GUARD_EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS guard_events (
    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
    agent_id TEXT, layer TEXT NOT NULL, data TEXT NOT NULL,
    hmac_hash TEXT NOT NULL, prev_hash TEXT NOT NULL, source TEXT
)
"""


def test_sync_engine_to_real_postgres(tmp_path):
    """L6 SyncEngine local(SQLite events) -> REAL Postgres guard_events (audit 2.C step 2).

    Exercises the Postgres-only branches the SQLite-as-remote tests cannot:
    %s placeholders + INSERT ... ON CONFLICT (id) DO NOTHING. Asserts the
    HMAC-chain columns cross the boundary byte-exact (integrity preserved) and that
    a re-sync is idempotent -- append-only union-by-id, no duplicates.
    """
    from substrate_guard.offline.local_store import LocalStore
    from substrate_guard.offline.sync import SyncEngine

    try:
        import psycopg2
    except ImportError:
        pytest.skip("psycopg2-binary not installed")

    db_url = _db_url()

    def _pg():
        return psycopg2.connect(db_url)

    # Ensure the remote table exists (CI schema-apply also creates it via 002_*.sql).
    admin = _pg()
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(_GUARD_EVENTS_DDL)
    finally:
        admin.close()

    store = LocalStore(tmp_path / "local.db", hmac_key="pg-sync-test")
    store.store_event("audit", "guard", {"n": 1}, agent_id="agentA")
    store.store_event("audit", "guard", {"n": 2}, agent_id="agentB")
    local = {e["id"]: e for e in store.get_unsynced(limit=100)}
    ids = list(local)

    try:
        out = SyncEngine(store, _pg).sync()
        assert out["status"] == "complete", out
        assert out["synced"] == 2
        assert store.count(synced=False) == 0

        # rows landed byte-exact (HMAC chain still verifiable across the sink) + source tag
        conn = _pg()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, hmac_hash, prev_hash, source FROM guard_events "
                    "WHERE id = ANY(%s)", (ids,)
                )
                remote = {r[0]: r for r in cur.fetchall()}
        finally:
            conn.close()
        assert set(remote) == set(ids)
        for eid, e in local.items():
            assert remote[eid][1] == e["hmac_hash"], "hmac drifted across sync"
            assert remote[eid][2] == e["prev_hash"], "prev_hash drifted across sync"
            assert remote[eid][3] == "offline_sync"

        # append-only idempotence: force a re-sync; ON CONFLICT (id) DO NOTHING must
        # keep exactly 2 rows (no dupes) and still report complete. (No public API
        # un-marks a synced row, so reset the local flag directly for the test.)
        store.conn.execute("UPDATE events SET synced = 0")
        store.conn.commit()
        out2 = SyncEngine(store, _pg).sync()
        assert out2["status"] == "complete", out2
        conn = _pg()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM guard_events WHERE id = ANY(%s)", (ids,))
                assert cur.fetchone()[0] == 2, "ON CONFLICT failed -- duplicate rows"
        finally:
            conn.close()
    finally:
        store.close()
        cleanup = _pg()
        cleanup.autocommit = True
        try:
            with cleanup.cursor() as cur:
                cur.execute("DELETE FROM guard_events WHERE id = ANY(%s)", (ids,))
        finally:
            cleanup.close()
