"""The tool benchmark's golden verdicts, run under pytest so the push/PR matrix sees them
(the `benchmarks` CI job is workflow_dispatch-only)."""
from __future__ import annotations

import pytest

from benchmarks.run_tool_benchmark import CASES, drift, run_case
from substrate_guard.ast_parse.parser import tree_sitter_bash_available


def test_tree_sitter_bash_available_for_denylist_cases():
    assert tree_sitter_bash_available(), "cli_denylist cases would silently degrade"


@pytest.mark.parametrize("case", CASES, ids=[c.name for c in CASES])
def test_golden_verdict(case):
    res = run_case(case)
    assert drift(case, res) is None, str(res)
