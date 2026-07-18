"""Layer-wiring invariant (audit 2026-07-17 item #15).

DECISION: layers L4 (comply), L5 (attest), L6 (offline) are PROTOTYPE / demo-only
-- reachable through the `cli.py` demo subcommands, NOT wired into the production
cron audit path (guard.py / audit.py). The README states this ("Prototyped ...
not yet in production pipeline"); these tests turn that prose into a pinned
invariant so an accidental future import cannot make the claim silently false --
in either direction:
  * production modules must NOT import L4/L5/L6 (else "not in production" is false);
  * cli.py MUST reach all three (else "code exists, validated" via demo is false).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_PKG = Path(__file__).resolve().parents[1] / "substrate_guard"
_LAYER_MODULES = {"comply", "attest", "offline"}


def _imported_submodules(py_path: Path) -> set[str]:
    """First-component set of every substrate_guard.* submodule imported by a file
    (handles `from .comply import X`, `from substrate_guard.attest import Y`,
    `import substrate_guard.offline`)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            mod = node.module
            if mod.startswith("substrate_guard."):
                found.add(mod.split(".")[1])
            elif node.level >= 1:  # relative: from .comply / from ..attest
                found.add(mod.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("substrate_guard."):
                    found.add(alias.name.split(".")[1])
    return found


@pytest.mark.parametrize("prod_module", ["guard.py", "audit.py"])
def test_production_path_does_not_import_prototype_layers(prod_module):
    imported = _imported_submodules(_PKG / prod_module)
    leaked = imported & _LAYER_MODULES
    assert not leaked, (
        f"{prod_module} imports prototype layer(s) {leaked} -- the README claims "
        f"L4/L5/L6 are NOT in the production pipeline. Wire them properly (with "
        f"production tests) or keep them out of the cron path."
    )


def test_cli_reaches_all_three_prototype_layers():
    """The demo path must actually exercise L4/L5/L6, so 'code exists, validated'
    is real. cli.py may delegate to per-layer cli_commands; accept either a direct
    import or a registered subparser module."""
    imported = _imported_submodules(_PKG / "cli.py")
    # cli.py registers each layer's parser; the layer package (or its cli_commands)
    # must be reachable from cli.py's import graph.
    reachable = set()
    for mod in _LAYER_MODULES:
        if mod in imported:
            reachable.add(mod)
    # Fallback: cli.py imports combo_cli / per-layer cli_commands that import them.
    if reachable != _LAYER_MODULES:
        cli_src = (_PKG / "cli.py").read_text(encoding="utf-8")
        for mod in _LAYER_MODULES - reachable:
            if mod in cli_src:
                reachable.add(mod)
    assert reachable == _LAYER_MODULES, (
        f"cli.py does not reach prototype layers {_LAYER_MODULES - reachable}; "
        f"the 'validated demo' claim would be unbacked for those."
    )


def test_readme_marks_layers_prototyped_not_production():
    readme = (_PKG.parent / "README.md").read_text(encoding="utf-8")
    assert "not yet in production pipeline" in readme, (
        "README lost the explicit 'not yet in production pipeline' L4-L6 caveat "
        "that this wiring invariant pins."
    )
