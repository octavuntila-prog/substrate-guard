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
