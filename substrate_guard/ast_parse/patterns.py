"""Structural safety patterns on parsed AST (bash + Python), not regex on raw text."""

from __future__ import annotations

import ast as py_ast
from dataclasses import dataclass

from substrate_guard.ast_parse.parser import ASTNode


@dataclass
class StructuralViolation:
    rule: str
    description: str
    matched_text: str


def _collect_rm_flags(args: list[str]) -> set[str]:
    flags: set[str] = set()
    for arg in args:
        if arg.startswith("-") and not arg.startswith("--"):
            flags.update(c for c in arg.lstrip("-") if c.isalpha())
        if arg == "--recursive":
            flags.add("r")
        if arg == "--force":
            flags.add("f")
    return flags


def bash_destructive(ast: ASTNode) -> list[StructuralViolation]:
    """Flag destructive shell structure: ``rm`` with r+f, ``chmod 777``, ``dd`` to block dev, ``mkfs``."""
    out: list[StructuralViolation] = []
    for cmd in ast.find_commands():
        name = cmd["name"]
        args = cmd["args"]
        text = cmd["text"]
        if name == "rm":
            flags = _collect_rm_flags(args)
            if "r" in flags and "f" in flags:
                out.append(
                    StructuralViolation(
                        rule="ast_bash_rm_recursive_force",
                        description="Recursive forced deletion (AST flag analysis)",
                        matched_text=text[:500],
                    )
                )
        if name == "chmod" and "777" in args:
            out.append(
                StructuralViolation(
                    rule="ast_bash_chmod_777",
                    description="World-writable chmod 777 (AST)",
                    matched_text=text[:500],
                )
            )
        if name == "dd":
            for a in args:
                if a.startswith("of=/dev/") and not a.startswith("of=/dev/null"):
                    out.append(
                        StructuralViolation(
                            rule="ast_bash_dd_block_device",
                            description="dd output to block device (AST)",
                            matched_text=text[:500],
                        )
                    )
        if name.startswith("mkfs"):
            out.append(
                StructuralViolation(
                    rule="ast_bash_mkfs",
                    description="Filesystem format command (AST)",
                    matched_text=text[:500],
                )
            )
    return out


def bash_pipe_to_shell(ast: ASTNode) -> list[StructuralViolation]:
    """``curl``/``wget`` piped to ``sh``/``bash``."""
    out: list[StructuralViolation] = []
    for pipeline in ast.find_all("pipeline"):
        cmds = [c for c in pipeline.named_children if c.type == "command"]
        if len(cmds) < 2:
            continue
        first = cmds[0].find_commands()
        last = cmds[-1].find_commands()
        if not first or not last:
            continue
        a, b = first[0]["name"], last[0]["name"]
        if a in ("curl", "wget") and b in ("sh", "bash", "zsh"):
            out.append(
                StructuralViolation(
                    rule="ast_bash_pipe_to_shell",
                    description="Download piped to shell (AST pipeline)",
                    matched_text=pipeline.text[:500],
                )
            )
    return out


def python_dangerous_calls(source: str) -> list[StructuralViolation]:
    """stdlib ``ast`` — ``eval``/``exec``/``compile`` calls (not ``evaluate``)."""
    out: list[StructuralViolation] = []
    try:
        tree = py_ast.parse(source)
    except SyntaxError:
        return out
    bad_names = frozenset({"eval", "exec", "compile", "__import__"})
    for node in py_ast.walk(tree):
        if isinstance(node, py_ast.Call):
            func = node.func
            if isinstance(func, py_ast.Name) and func.id in bad_names:
                snippet = py_ast.get_source_segment(source, node) or func.id
                out.append(
                    StructuralViolation(
                        rule=f"ast_python_{func.id}",
                        description=f"Dangerous builtin {func.id} (AST)",
                        matched_text=snippet[:500],
                    )
                )
    return out


def run_bash_checks(root: ASTNode) -> list[StructuralViolation]:
    v: list[StructuralViolation] = []
    v.extend(bash_destructive(root))
    v.extend(bash_pipe_to_shell(root))
    return v
