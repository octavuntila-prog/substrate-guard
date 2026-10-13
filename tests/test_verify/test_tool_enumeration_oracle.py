"""Differential oracle: exhaustive enumeration vs Z3 string theory on generated finite-domain
tools. Z3 is forced (max_enumeration=0) on the same tool + literal patterns; wherever Z3
decides (sat/unsat on every pattern) its verdict must equal the enumeration verdict, and
the per-pattern outcomes must agree. Z3 abstentions are counted, not failed (string theory
is incomplete). Bounded: ~60 tools, 500 ms per Z3 run, hard wall-clock cap.

This is what keeps "Z3 as test oracle" an actual test and not a slogan (Step 0, 2026-10-13).
"""
from __future__ import annotations

import random
import time

import pytest

from substrate_guard.tool_verifier import (
    ForbiddenPattern,
    ToolDefinition,
    ToolParam,
    ToolSafetyStatus,
    verify_tool,
)

ALPHABET = ["rm", " -rf", " /", "ls", "x", "-", " ", "a", "b", "f", "/tmp"]
KEYWORDS = [" rm -rf", "ls /", "x-f", "a b", "/tmp/", " -rf /", "bx", "f f"]
PATTERNS = [ForbiddenPattern(f"k{i}", f"kw {kw!r}", keywords=[kw], case_sensitive=(i % 3 != 0))
            for i, kw in enumerate(KEYWORDS)]
N_TOOLS = 60
Z3_BUDGET_MS = 500
WALL_CAP_S = 45.0
MIN_DECIDED = 15


def _gen(rng: random.Random, i: int) -> ToolDefinition:
    n_params = rng.randint(1, 3)
    params, parts = [], []
    for j in range(n_params):
        name = f"p{j}"
        if rng.random() < 0.25:
            params.append(ToolParam(name, "bool"))
        else:
            params.append(ToolParam(name, "enum", enum_values=rng.sample(ALPHABET, rng.randint(2, 4))))
        parts.append(rng.choice(ALPHABET) if rng.random() < 0.7 else "")
        parts.append("{%s}" % name)
    parts.append(rng.choice(ALPHABET) if rng.random() < 0.7 else "")
    return ToolDefinition(f"g{i}", "", params, "".join(parts))


def test_enumeration_equals_z3_wherever_z3_decides():
    rng = random.Random(20261013)
    tools = [_gen(rng, i) for i in range(N_TOOLS)]
    t0 = time.perf_counter()
    compared = decided = abstained = 0
    mismatches = []
    for t in tools:
        if time.perf_counter() - t0 > WALL_CAP_S:
            break
        enum_res = verify_tool(t, PATTERNS, timeout_ms=5000)
        assert enum_res.engine == "enumeration", t.operation_template
        z3_res = verify_tool(t, PATTERNS, timeout_ms=Z3_BUDGET_MS, max_enumeration=0)
        assert z3_res.engine == "z3", t.operation_template
        compared += 1
        if z3_res.status is ToolSafetyStatus.UNKNOWN:
            abstained += 1
            continue
        decided += 1
        if z3_res.status is not enum_res.status:
            mismatches.append((t.operation_template, enum_res.status.value, z3_res.status.value))
            continue
        e_out = {c["pattern"]: c["outcome"] for c in enum_res.checks}
        z_out = {c["pattern"]: c["outcome"] for c in z3_res.checks}
        if e_out != z_out:
            mismatches.append((t.operation_template, e_out, z_out))
    print(f"\noracle: compared={compared} decided_by_z3={decided} z3_abstained={abstained} "
          f"wall={time.perf_counter() - t0:.1f}s")
    assert not mismatches, mismatches
    assert decided >= MIN_DECIDED, f"too few z3-decided comparisons ({decided}); oracle not exercised"


@pytest.mark.parametrize("template,params,expect", [
    ("rm{a} -rf /", [ToolParam("a", "enum", enum_values=["", "x"])], ToolSafetyStatus.UNSAFE),
    ("ls {a}{b}", [ToolParam("a", "enum", enum_values=["/", "x"]), ToolParam("b", "bool")], ToolSafetyStatus.SAFE),
])
def test_hand_cases_agree_on_both_engines(template, params, expect):
    pats = [ForbiddenPattern("k", "k", keywords=[" rm -rf", "ls /1"])]  # '1' is not a bool rendering
    t = ToolDefinition("h", "", params, template)
    e = verify_tool(t, pats)
    z = verify_tool(t, pats, timeout_ms=5000, max_enumeration=0)
    assert e.status is expect
    assert z.status in (expect, ToolSafetyStatus.UNKNOWN)
