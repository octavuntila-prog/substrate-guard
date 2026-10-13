"""`substrate-guard verify` dispatch. Until 2026-10-13 the subparser dest ('command') and
the `--command` option shared a name, so `args.command` was None / the CLI string and no
`verify --type ...` branch ever ran; the tool branch also rebuilt the ToolDefinition
without its operation_template (always UNKNOWN). Exit codes: 0 SAFE / 1 UNSAFE / 2 UNKNOWN."""
from __future__ import annotations

import json
import sys

from substrate_guard import cli


def _run(monkeypatch, argv):
    """Exit code, or None when the branch returns without calling sys.exit."""
    monkeypatch.setattr(sys, "argv", ["substrate-guard", *argv])
    try:
        cli.main()
    except SystemExit as e:
        return e.code
    return None


def _tool_file(tmp_path, template, params):
    p = tmp_path / "tool.json"
    p.write_text(json.dumps({"name": "t", "description": "", "params": params, "operation_template": template}))
    return str(p)


def test_verify_tool_dispatches_and_keeps_operation_template(tmp_path, monkeypatch, capsys):
    dangerous = _tool_file(tmp_path, "rm -rf /{mode}", [{"name": "mode", "type": "enum", "enum": ["read", "list"]}])
    assert _run(monkeypatch, ["verify", "--type", "tool", dangerous]) == 1
    out = capsys.readouterr().out
    assert "UNSAFE" in out and "Operation: rm -rf /read" in out
    safe = _tool_file(tmp_path, "ls -l /workspace/{d}", [{"name": "d", "type": "enum", "enum": ["docs", "src"]}])
    assert _run(monkeypatch, ["verify", "--type", "tool", safe]) == 0
    assert "SAFE" in capsys.readouterr().out


def test_verify_tool_unknown_exits_2(tmp_path, monkeypatch, capsys):
    no_template = tmp_path / "t.json"
    no_template.write_text(json.dumps({"name": "t", "params": [{"name": "q", "type": "string"}]}))
    assert _run(monkeypatch, ["verify", "--type", "tool", str(no_template)]) == 2
    assert "no_template" in capsys.readouterr().out


def test_verify_tool_categories_select_lists(tmp_path, monkeypatch, capsys):
    f = _tool_file(tmp_path, "kubectl delete {r} --all", [{"name": "r", "type": "enum", "enum": ["pods", "svc"]}])
    assert _run(monkeypatch, ["verify", "--type", "tool", f, "--categories", "database"]) == 0
    assert _run(monkeypatch, ["verify", "--type", "tool", f, "--categories", "cloud"]) == 1
    assert "cloud_destructive" in capsys.readouterr().out


def test_verify_cli_command_dispatches(monkeypatch, capsys):
    assert _run(monkeypatch, ["verify", "--type", "cli", "--command", "rm -rf /"]) == 1
    assert "UNSAFE" in capsys.readouterr().out
    assert _run(monkeypatch, ["verify", "--type", "cli", "--command", "ls -la /home/user"]) == 0
    assert "SAFE" in capsys.readouterr().out
    assert _run(monkeypatch, ["verify", "--type", "cli"]) == 1
    assert "--command required" in capsys.readouterr().out


def test_verify_code_dispatches(tmp_path, monkeypatch, capsys):
    src = tmp_path / "f.py"
    src.write_text("def my_abs(x: int) -> int:\n    if x >= 0:\n        return x\n    return -x\n")
    code = _run(monkeypatch, ["verify", "--type", "code", str(src), "--postcondition", "__return__ >= 0"])
    out = capsys.readouterr().out
    assert code in (0, 1) and out.strip()   # the branch runs and prints a verdict (never the silent fall-through)
