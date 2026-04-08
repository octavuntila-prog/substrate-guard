"""Structural SQL checks via ``sqlparse`` (statement type), not substring heuristics."""

from __future__ import annotations

import sqlparse

from substrate_guard.ast_parse.patterns import StructuralViolation


def sql_destructive_statements(sql: str) -> list[StructuralViolation]:
    """Flag high-risk DDL / destructive DML using parsed statement type."""
    out: list[StructuralViolation] = []
    text = sql.strip()
    if not text:
        return out
    try:
        statements = sqlparse.parse(text)
    except Exception:
        return out
    for statement in statements:
        if not statement.tokens:
            continue
        stype = (statement.get_type() or "").upper()
        snippet = str(statement).strip()[:500]
        if stype == "DROP":
            out.append(
                StructuralViolation(
                    rule="ast_sql_drop",
                    description="DROP statement (structural sqlparse)",
                    matched_text=snippet,
                )
            )
        elif stype == "TRUNCATE":
            out.append(
                StructuralViolation(
                    rule="ast_sql_truncate",
                    description="TRUNCATE statement (structural sqlparse)",
                    matched_text=snippet,
                )
            )
        elif stype == "ALTER":
            u = str(statement).upper()
            if "DROP COLUMN" in u or "DROP CONSTRAINT" in u:
                out.append(
                    StructuralViolation(
                        rule="ast_sql_alter_drop",
                        description="ALTER … DROP COLUMN / CONSTRAINT (structural)",
                        matched_text=snippet,
                    )
                )
    return out
