#!/usr/bin/env python3
"""Apply ``scripts/sql/001_audit_tables.sql`` using ``POSTGRES_*`` / ``DATABASE_URL`` from the environment.

Used by CI and optionally locally before ``substrate-guard audit``."""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SQL_FILE = REPO / "scripts" / "sql" / "001_audit_tables.sql"


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

    sql_text = SQL_FILE.read_text(encoding="utf-8")
    stmts = _split_statements(sql_text)
    if not stmts:
        print(f"Error: no statements parsed from {SQL_FILE}", file=sys.stderr)
        return 1

    conn = psycopg2.connect(url)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            for stmt in stmts:
                cur.execute(stmt)
    finally:
        conn.close()

    print(f"Applied {len(stmts)} statement(s) from {SQL_FILE.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
