"""Benchmark: Distillation verification.

Simulates reasoning traces from large (correct) and distilled (sometimes buggy)
models solving math problems. Z3 + SymPy verify each step.

Categories:
  - Arithmetic evaluation (pure computation)
  - Algebra (solving equations)
  - Multi-step reasoning (chains of deductions)
  - Distilled model errors (realistic mistakes small models make)
"""

import sys
sys.path.insert(0, "/home/claude/substrate-guard")

from substrate_guard.distill_verifier import DistillationVerifier

verifier = DistillationVerifier()
passed = 0
failed = 0


def check(name, result, expected_all_valid):
    global passed, failed
    ok = result.all_valid == expected_all_valid
    icon = "+" if ok else "X"
    status = "PASS" if ok else "FAIL"
    counts = (f"{result.valid_count}v {result.invalid_count}i "
              f"{result.unparseable_count}u")
    print(f"  {icon} {status}: {name} — {result.status.value} "
          f"[{counts}] ({result.time_ms:.1f}ms)")
    if not ok:
        for s in result.steps:
            if s.status.value != "valid":
                print(f"    Step {s.step_number}: {s.status.value} — {s.error or s.raw_text}")
    if ok:
        passed += 1
    else:
        failed += 1


def check_compare(name, comparison, expected_error_by_distillation):
    global passed, failed
    ok = comparison["error_introduced_by_distillation"] == expected_error_by_distillation
    icon = "+" if ok else "X"
    status = "PASS" if ok else "FAIL"
    ref = "valid" if comparison["reference_valid"] else "errors"
    dist = "valid" if comparison["distilled_valid"] else "errors"
    diverge = len(comparison["divergences"])
    print(f"  {icon} {status}: {name} — ref:{ref} dist:{dist} "
          f"divergences:{diverge}")
    if not ok:
        for d in comparison["divergences"]:
            print(f"    Step {d['step']}: {d['distilled_error']}")
    if ok:
        passed += 1
    else:
        failed += 1


print("=" * 70)
print("SUBSTRATE-GUARD — Distillation Verifier Benchmark")
print("=" * 70)

# ══════════════════════════════════════════════════════════════════════
# ARITHMETIC EVALUATION — pure computation, no variables
# ══════════════════════════════════════════════════════════════════════

print("\n-- Arithmetic (correct traces) --")

check("simple addition", verifier.verify_trace(
    "What is 17 + 28?",
    [{"expression": "17 + 28", "value": "45"}]
), True)

check("multiplication chain", verifier.verify_trace(
    "What is 12 * 15?",
    [
        {"expression": "12 * 15", "value": "180"},
    ]
), True)

check("multi-step arithmetic", verifier.verify_trace(
    "Calculate (3 + 4) * (5 + 6)",
    [
        {"expression": "3 + 4", "value": "7"},
        {"expression": "5 + 6", "value": "11"},
        {"expression": "7 * 11", "value": "77"},
    ]
), True)

check("order of operations", verifier.verify_trace(
    "What is 2 + 3 * 4?",
    [{"expression": "2 + 3 * 4", "value": "14"}]
), True)

check("nested parentheses", verifier.verify_trace(
    "Calculate ((2 + 3) * 4 - 6) / 2",
    [
        {"expression": "2 + 3", "value": "5"},
        {"expression": "5 * 4", "value": "20"},
        {"expression": "20 - 6", "value": "14"},
        {"expression": "14 / 2", "value": "7"},
    ]
), True)

print("\n-- Arithmetic (buggy traces) --")

check("wrong addition", verifier.verify_trace(
    "What is 17 + 28?",
    [{"expression": "17 + 28", "value": "43"}]  # BUG: should be 45
), False)

check("wrong multiplication", verifier.verify_trace(
    "What is 12 * 15?",
    [{"expression": "12 * 15", "value": "170"}]  # BUG: should be 180
), False)

check("carry error in multi-step", verifier.verify_trace(
    "Calculate (3 + 4) * (5 + 6)",
    [
        {"expression": "3 + 4", "value": "7"},
        {"expression": "5 + 6", "value": "11"},
        {"expression": "7 * 11", "value": "78"},  # BUG: should be 77
    ]
), False)

check("order of operations error", verifier.verify_trace(
    "What is 2 + 3 * 4?",
    [{"expression": "2 + 3 * 4", "value": "20"}]  # BUG: (2+3)*4 not 2+(3*4)
), False)

# ══════════════════════════════════════════════════════════════════════
# ALGEBRA — solving equations
# ══════════════════════════════════════════════════════════════════════

print("\n-- Algebra (correct traces) --")

check("solve linear equation", verifier.verify_trace(
    "Solve 3x + 6 = 15",
    [
        {"claim": "3*x + 6 = 15 → 3*x = 9", "operation": "subtract 6"},
        {"claim": "3*x = 9 → x = 3", "operation": "divide by 3"},
    ]
), True)

check("solve with negative", verifier.verify_trace(
    "Solve 2x - 8 = 0",
    [
        {"claim": "2*x - 8 = 0 → 2*x = 8", "operation": "add 8"},
        {"claim": "2*x = 8 → x = 4", "operation": "divide by 2"},
    ]
), True)

check("substitution check", verifier.verify_trace(
    "Verify x=3 in 3x + 6 = 15",
    [
        {"expression": "3 * 3 + 6", "value": "15"},
    ]
), True)

check("two-step equation", verifier.verify_trace(
    "Solve 5x + 3 = 2x + 12",
    [
        {"claim": "5*x + 3 = 2*x + 12 → 3*x + 3 = 12", "operation": "subtract 2x"},
        {"claim": "3*x + 3 = 12 → 3*x = 9", "operation": "subtract 3"},
        {"claim": "3*x = 9 → x = 3", "operation": "divide by 3"},
    ]
), True)

print("\n-- Algebra (buggy traces) --")

check("wrong subtraction in solving", verifier.verify_trace(
    "Solve 3x + 6 = 15",
    [
        {"claim": "3*x + 6 = 15 → 3*x = 11", "operation": "subtract 6"},  # BUG: 15-6=9
        {"claim": "3*x = 11 → x = 11/3", "operation": "divide by 3"},
    ]
), False)

check("wrong division", verifier.verify_trace(
    "Solve 4x = 20",
    [
        {"claim": "4*x = 20 → x = 4", "operation": "divide by 4"},  # BUG: 20/4=5
    ]
), False)

check("sign error", verifier.verify_trace(
    "Solve 2x - 8 = 0",
    [
        {"claim": "2*x - 8 = 0 → 2*x = -8", "operation": "add 8"},  # BUG: sign
        {"claim": "2*x = -8 → x = -4", "operation": "divide by 2"},
    ]
), False)

# ══════════════════════════════════════════════════════════════════════
# MULTI-STEP REASONING
# ══════════════════════════════════════════════════════════════════════

print("\n-- Multi-step reasoning (correct) --")

check("quadratic factoring check", verifier.verify_trace(
    "Verify that (x+2)(x+3) = x^2 + 5x + 6",
    [
        {"expression": "(x+2)*(x+3) - (x**2 + 5*x + 6)", "value": "0"},
    ]
), True)

check("distance formula values", verifier.verify_trace(
    "Distance between (0,0) and (3,4)",
    [
        {"expression": "3**2", "value": "9"},
        {"expression": "4**2", "value": "16"},
        {"expression": "9 + 16", "value": "25"},
    ]
), True)

check("percentage calculation", verifier.verify_trace(
    "What is 15% of 240?",
    [
        {"expression": "240 * 15 / 100", "value": "36"},
    ]
), True)

print("\n-- Multi-step reasoning (buggy) --")

check("wrong expansion", verifier.verify_trace(
    "Verify that (x+2)(x+3) = x^2 + 5x + 5",
    [
        {"expression": "(x+2)*(x+3) - (x**2 + 5*x + 5)", "value": "0"},  # BUG: should be 1
    ]
), False)

check("wrong square", verifier.verify_trace(
    "Distance between (0,0) and (3,4)",
    [
        {"expression": "3**2", "value": "9"},
        {"expression": "4**2", "value": "14"},  # BUG: 16
        {"expression": "9 + 14", "value": "23"},
    ]
), False)

# ══════════════════════════════════════════════════════════════════════
# DISTILLED vs REFERENCE — side-by-side comparison
# ══════════════════════════════════════════════════════════════════════

print("\n-- Distilled vs reference model comparison --")

# Problem 1: Reference correct, distilled correct
check_compare("both correct: solve 2x + 4 = 10",
    verifier.compare_traces(
        "Solve 2x + 4 = 10",
        reference_trace=[
            {"claim": "2*x + 4 = 10 → 2*x = 6", "operation": "subtract 4"},
            {"claim": "2*x = 6 → x = 3", "operation": "divide by 2"},
        ],
        distilled_trace=[
            {"claim": "2*x + 4 = 10 → 2*x = 6", "operation": "subtract 4"},
            {"claim": "2*x = 6 → x = 3", "operation": "divide by 2"},
        ],
    ),
    expected_error_by_distillation=False,
)

# Problem 2: Reference correct, distilled makes arithmetic error
check_compare("distilled error: solve 5x - 10 = 25",
    verifier.compare_traces(
        "Solve 5x - 10 = 25",
        reference_trace=[
            {"claim": "5*x - 10 = 25 → 5*x = 35", "operation": "add 10"},
            {"claim": "5*x = 35 → x = 7", "operation": "divide by 5"},
        ],
        distilled_trace=[
            {"claim": "5*x - 10 = 25 → 5*x = 35", "operation": "add 10"},
            {"claim": "5*x = 35 → x = 8", "operation": "divide by 5"},  # BUG
        ],
    ),
    expected_error_by_distillation=True,
)

# Problem 3: Reference correct, distilled sign error
check_compare("distilled sign error: solve 3x + 9 = 0",
    verifier.compare_traces(
        "Solve 3x + 9 = 0",
        reference_trace=[
            {"claim": "3*x + 9 = 0 → 3*x = -9", "operation": "subtract 9"},
            {"claim": "3*x = -9 → x = -3", "operation": "divide by 3"},
        ],
        distilled_trace=[
            {"claim": "3*x + 9 = 0 → 3*x = 9", "operation": "subtract 9"},  # BUG: sign
            {"claim": "3*x = 9 → x = 3", "operation": "divide by 3"},
        ],
    ),
    expected_error_by_distillation=True,
)

# Problem 4: Both solve correctly but distilled uses different valid path
check_compare("different valid paths: solve 4x + 8 = 20",
    verifier.compare_traces(
        "Solve 4x + 8 = 20",
        reference_trace=[
            {"claim": "4*x + 8 = 20 → 4*x = 12", "operation": "subtract 8"},
            {"claim": "4*x = 12 → x = 3", "operation": "divide by 4"},
        ],
        distilled_trace=[
            # Different path: divide everything by 4 first
            {"claim": "4*x + 8 = 20 → x + 2 = 5", "operation": "divide by 4"},
            {"claim": "x + 2 = 5 → x = 3", "operation": "subtract 2"},
        ],
    ),
    expected_error_by_distillation=False,
)

# Problem 5: Distilled skips step and gets wrong answer
check_compare("distilled wrong final: 7x + 14 = 49",
    verifier.compare_traces(
        "Solve 7x + 14 = 49",
        reference_trace=[
            {"claim": "7*x + 14 = 49 → 7*x = 35", "operation": "subtract 14"},
            {"claim": "7*x = 35 → x = 5", "operation": "divide by 7"},
        ],
        distilled_trace=[
            {"claim": "7*x + 14 = 49 → 7*x = 35", "operation": "subtract 14"},
            {"claim": "7*x = 35 → x = 7", "operation": "divide by 7"},  # BUG: 35/7=5
        ],
    ),
    expected_error_by_distillation=True,
)

# ── Summary ─────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed, {total} total")
print(f"{'=' * 70}")
