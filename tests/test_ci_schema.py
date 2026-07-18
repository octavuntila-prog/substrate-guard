"""Guard the CI DDL splitter (audit 2026-07-17 item 2.C follow-up).

A semicolon inside a comment in 002_offline_guard_events.sql once split a comment
into an orphan fragment that reached Postgres ('syntax error at or near
SyncEngine'). These tests parse every scripts/sql/*.sql the way CI does and assert
each resulting statement is a real DDL statement -- catching that class locally,
without a Postgres.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SQL_DIR = _REPO / "scripts" / "sql"
sys.path.insert(0, str(_REPO / "scripts"))

from ci_apply_audit_schema import _split_statements  # noqa: E402

_SQL_FILES = sorted(_SQL_DIR.glob("*.sql"))
_DDL_KEYWORDS = ("CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE", "GRANT", "COMMENT")


def test_sql_dir_has_files():
    assert _SQL_FILES, f"no .sql files under {_SQL_DIR}"


@pytest.mark.parametrize("sql_file", _SQL_FILES, ids=lambda p: p.name)
def test_every_statement_is_real_ddl(sql_file):
    stmts = _split_statements(sql_file.read_text(encoding="utf-8"))
    assert stmts, f"{sql_file.name}: no statements parsed"
    for stmt in stmts:
        first = stmt.lstrip().split(None, 1)[0].upper()
        assert first in _DDL_KEYWORDS, (
            f"{sql_file.name}: statement does not start with a DDL keyword "
            f"(orphan comment fragment?): {stmt[:60]!r}"
        )


def test_comment_semicolon_does_not_orphan_a_fragment():
    """Regression: a ';' inside a full-line comment must not survive as a statement."""
    sql = (
        "-- keeps an events log; SyncEngine pushes rows\n"
        "CREATE TABLE t (id TEXT PRIMARY KEY);\n"
    )
    stmts = _split_statements(sql)
    assert stmts == ["CREATE TABLE t (id TEXT PRIMARY KEY);"], stmts
