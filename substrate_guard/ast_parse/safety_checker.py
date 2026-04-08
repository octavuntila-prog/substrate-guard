"""Orchestrate structural checks for a single CLI / snippet string (unified entry)."""

from __future__ import annotations

from substrate_guard.ast_parse.json_yaml_patterns import json_structural_issues, yaml_structural_issues
from substrate_guard.ast_parse.parser import detect_shell_language, parse_bash, tree_sitter_bash_available
from substrate_guard.ast_parse.patterns import StructuralViolation, python_dangerous_calls, run_bash_checks
from substrate_guard.ast_parse.sql_patterns import sql_destructive_statements

# Avoid huge tree-sitter parses on pathological inputs (align with CLI truncation elsewhere).
_MAX_AST_BYTES = 256 * 1024


def structural_scan(code: str) -> list[StructuralViolation]:
    """Single entry: bash, Python ``ast``, SQL (sqlparse), JSON, YAML (PyYAML)."""
    if not code or len(code) > _MAX_AST_BYTES:
        return []
    lang = detect_shell_language(code)
    out: list[StructuralViolation] = []
    if lang == "bash" and tree_sitter_bash_available():
        root = parse_bash(code)
        if root is not None:
            out.extend(run_bash_checks(root))
    elif lang == "python":
        out.extend(python_dangerous_calls(code))
    elif lang == "sql":
        out.extend(sql_destructive_statements(code))
    elif lang == "json":
        out.extend(json_structural_issues(code))
    elif lang == "yaml":
        out.extend(yaml_structural_issues(code))
    return out


def check_shell_command_ast(command: str) -> list[StructuralViolation]:
    """Backward-compatible alias for :func:`structural_scan`."""
    return structural_scan(command)
