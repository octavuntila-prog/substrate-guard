#!/usr/bin/env python3
"""Apply every ``scripts/sql/*.sql`` file (in name order) using ``POSTGRES_*`` /
``DATABASE_URL`` from the environment.

Used by CI and optionally locally before ``substrate-guard audit``. Applies
001_audit_tables.sql (pipeline_traces/agent_runs) and 002_offline_guard_events.sql
(the L6 SyncEngine sink) -- so the Postgres SyncEngine integration test has its
remote table."""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SQL_DIR = REPO / "scripts" / "sql"


def _split_statements(sql: str) -> list[str]:
    """Split DDL file on ';' — safe for our init scripts (no semicolons in strings)."""
    out: list[str] = []
    for raw in sql.split(";"):
        block = raw.strip()
        if not block:
            continue
        lines = [
            ln
            for ln in block.splitlines()
            if ln.strip() and not ln.strip().startswith("--")
        ]
        if not lines:
            continue
        stmt = "\n".join(lines).strip()
        if stmt:
            out.append(stmt + ";")
    return out


def main() -> int:
    os.chdir(REPO)
    sys.path.insert(0, str(REPO))

    from substrate_guard.audit import resolve_db_url

    url = resolve_db_url(None, None)
    if not url:
        print("Error: could not resolve DB URL (set POSTGRES_* or DATABASE_URL).", file=sys.stderr)
        return 1

    try:
        import psycopg2
    except ImportError:
        print("Error: psycopg2 required (pip install -e '.[postgres]').", file=sys.stderr)
        return 1

    sql_files = sorted(SQL_DIR.glob("*.sql"))
    if not sql_files:
        print(f"Error: no .sql files under {SQL_DIR}", file=sys.stderr)
        return 1

    conn = psycopg2.connect(url)
    conn.autocommit = True
    total = 0
    try:
        with conn.cursor() as cur:
            for sql_file in sql_files:
                stmts = _split_statements(sql_file.read_text(encoding="utf-8"))
                for stmt in stmts:
                    cur.execute(stmt)
                total += len(stmts)
                print(f"Applied {len(stmts)} statement(s) from {sql_file.relative_to(REPO)}")
    finally:
        conn.close()

    print(f"Applied {total} statement(s) from {len(sql_files)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
