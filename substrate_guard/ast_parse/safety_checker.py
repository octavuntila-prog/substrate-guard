"""Orchestrate AST structural checks for a single CLI / snippet string."""

from __future__ import annotations

from substrate_guard.ast_parse.parser import detect_shell_language, parse_bash, tree_sitter_bash_available
from substrate_guard.ast_parse.patterns import StructuralViolation, python_dangerous_calls, run_bash_checks

# Avoid huge tree-sitter parses on pathological inputs (align with CLI truncation elsewhere).
_MAX_AST_BYTES = 256 * 1024


def check_shell_command_ast(command: str) -> list[StructuralViolation]:
    """Return structural violations; empty if skipped, unparseable, or clean."""
    if not command or len(command) > _MAX_AST_BYTES:
        return []
    lang = detect_shell_language(command)
    out: list[StructuralViolation] = []
    if lang == "bash" and tree_sitter_bash_available():
        root = parse_bash(command)
        if root is not None:
            out.extend(run_bash_checks(root))
    elif lang == "python":
        out.extend(python_dangerous_calls(command))
    return out
