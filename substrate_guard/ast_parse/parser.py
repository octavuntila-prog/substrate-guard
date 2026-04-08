"""Tree-sitter bash parsing — structural representation before regex-only checks."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from typing import Any

# Lazy parser cache: language id -> Parser
_parsers: dict[str, Any] = {}


def tree_sitter_bash_available() -> bool:
    try:
        importlib.import_module("tree_sitter_bash")
        importlib.import_module("tree_sitter")
    except ImportError:
        return False
    return True


def _bash_parser():
    if "bash" in _parsers:
        return _parsers["bash"]
    from tree_sitter import Language, Parser
    import tree_sitter_bash as bash_mod

    lang = Language(bash_mod.language())
    p = Parser(lang)
    _parsers["bash"] = p
    return p


@dataclass
class ASTNode:
    """Thin wrapper over tree-sitter ``Node`` with query helpers."""

    _node: Any
    _source: str

    @property
    def type(self) -> str:
        return self._node.type

    @property
    def text(self) -> str:
        return self._source[self._node.start_byte : self._node.end_byte]

    @property
    def children(self) -> list[ASTNode]:
        return [ASTNode(c, self._source) for c in self._node.children]

    @property
    def named_children(self) -> list[ASTNode]:
        return [ASTNode(c, self._source) for c in self._node.named_children]

    def find_all(self, node_type: str) -> list[ASTNode]:
        out: list[ASTNode] = []
        if self._node.type == node_type:
            out.append(self)
        for c in self._node.children:
            out.extend(ASTNode(c, self._source).find_all(node_type))
        return out

    def find_commands(self) -> list[dict[str, Any]]:
        """Extract simple commands; unwrap ``sudo`` so ``rm`` is visible."""
        commands: list[dict[str, Any]] = []
        for node in self.find_all("command"):
            name = ""
            args: list[str] = []
            for ch in node.named_children:
                if ch.type == "command_name":
                    for w in ch.named_children:
                        if w.type == "word":
                            name = w.text
                elif ch.type == "word":
                    args.append(ch.text)
            stripped = name.lstrip("\\")
            if stripped == "sudo" and args:
                inner, rest = _sudo_unwrap(args)
                cmd = {"name": inner.lstrip("\\"), "args": rest, "text": node.text}
            else:
                cmd = {"name": stripped, "args": args, "text": node.text}
            commands.append(cmd)
        return commands


def _sudo_unwrap(args: list[str]) -> tuple[str, list[str]]:
    """Skip ``sudo`` flags (``-u user``, ``-E``, …) and return real subcommand + args."""
    i = 0
    n = len(args)
    while i < n:
        a = args[i]
        if a in ("-u", "-g", "-U", "-p", "-D", "-R", "-r", "-C", "-T", "-h", "-K", "-S", "-b", "-a", "-i", "-s"):
            if a in ("-u", "-g", "-U", "-p", "-D", "-R", "-r", "-C", "-T", "-h", "-K", "-S", "-b", "-a") and i + 1 < n:
                i += 2
            else:
                i += 1
            continue
        if a == "--":
            i += 1
            break
        if a.startswith("-") and len(a) > 1:
            i += 1
            continue
        break
    if i >= n:
        return "", []
    return args[i], args[i + 1 :]


def _looks_like_yaml(s: str) -> bool:
    """Heuristic: stream / mapping document (not JSON, not shell)."""
    t = s.lstrip()
    if t.startswith("---") or t.startswith("%YAML"):
        return True
    if t.startswith("{") or t.startswith("["):
        return False
    for line in s.splitlines()[:24]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("- "):
            line = line[2:].lstrip()
        if ":" not in line:
            break
        head, _, _rest = line.partition(":")
        head = head.strip()
        if not head or not re.match(r"^[\w.-]+$", head):
            break
        colon = line.find(":")
        if "://" in line[: colon + 8]:
            continue
        return True
    return False


def detect_shell_language(code: str) -> str:
    """Heuristic: is this likely a shell one-liner vs Python / unknown."""
    s = code.strip()
    if not s:
        return "unknown"
    if s.startswith(("#!/bin/", "#!/usr/bin/env bash", "#!/usr/bin/env sh")):
        return "bash"
    # Python surface syntax (not a shell line starting with ``eval ``).
    if re.match(r"eval\s*\(", s) or re.match(r"exec\s*\(", s):
        return "python"
    # Shell invokes `python -m ...` — still a bash parse, but not Python source.
    if re.match(r"python3?\s+", s):
        return "bash"
    bash_starts = (
        "sudo ",
        "apt ",
        "cd ",
        "ls ",
        "rm ",
        "mv ",
        "cp ",
        "chmod ",
        "chown ",
        "grep ",
        "find ",
        "cat ",
        "echo ",
        "export ",
        "pip ",
        "docker ",
        "git ",
        "curl ",
        "wget ",
        "kubectl ",
        "systemctl ",
        "iptables ",
        "strace ",
        "tcpdump ",
        "openssl ",
        "ssh ",
        "socat ",
        "nsenter ",
        "dd ",
        "mount ",
        "sed ",
        "awk ",
        "perl ",
        "bash ",
        "sh ",
        "eval ",
        "source ",
    )
    if any(s.startswith(p) for p in bash_starts):
        return "bash"
    py_starts = (
        "import ",
        "from ",
        "def ",
        "class ",
        "if __name__",
        "print(",
        "for ",
        "while ",
        "with ",
    )
    if any(s.startswith(k) for k in py_starts):
        return "python"
    if s.startswith(("{", "[")):
        return "json"
    if _looks_like_yaml(s):
        return "yaml"
    u = s.upper()
    if any(
        u.startswith(k)
        for k in (
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "DROP ",
            "CREATE ",
            "ALTER ",
            "WITH ",
            "TRUNCATE ",
        )
    ):
        return "sql"
    return "unknown"


def parse_bash(code: str) -> ASTNode | None:
    """Parse bash source; returns ``None`` if tree-sitter bash is not installed."""
    if not tree_sitter_bash_available():
        return None
    p = _bash_parser()
    data = code if code.endswith("\n") else code + "\n"
    tree = p.parse(data.encode("utf-8"))
    return ASTNode(tree.root_node, data)
