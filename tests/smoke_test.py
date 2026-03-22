"""Smoke tests — verify the engine handles all patterns correctly."""

import sys
sys.path.insert(0, "/home/claude/substrate-guard")

from substrate_guard.code_verifier import verify_code, Spec

passed = 0
failed = 0


def check(name, result, expected_verified):
    global passed, failed
    ok = result.verified == expected_verified
    status = "PASS" if ok else "FAIL"
    icon = "+" if ok else "X"
    print(f"  {icon} {status}: {name} — got {result.status.value}, "
          f"expected {'verified' if expected_verified else 'unsafe'} "
          f"({result.time_ms:.1f}ms)")
    if not ok:
        print(f"    {result}")
        failed += 1
    else:
        passed += 1


print("=" * 60)
print("SUBSTRATE-GUARD CODE VERIFIER — Smoke Tests")
print("=" * 60)

# ── Functions that SHOULD verify ────────────────────────────────────

print("\n-- Should be VERIFIED --")

check("clamp(x, lo, hi)", verify_code("""
def clamp(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x
""", Spec(
    preconditions=["lo <= hi"],
    postconditions=["__return__ >= lo", "__return__ <= hi"],
    description="clamp within bounds"
)), True)

check("abs(x)", verify_code("""
def my_abs(x: int) -> int:
    if x >= 0:
        return x
    return -x
""", Spec(
    postconditions=["__return__ >= 0"],
    description="abs is non-negative"
)), True)

check("max(a, b)", verify_code("""
def my_max(a: int, b: int) -> int:
    if a >= b:
        return a
    return b
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b"],
    description="max >= both inputs"
)), True)

check("safe_div(a, b)", verify_code("""
def safe_div(a: int, b: int) -> int:
    if b == 0:
        return 0
    return a // b
""", Spec(
    preconditions=["a >= 0", "b > 0"],
    postconditions=["__return__ >= 0"],
    description="safe_div non-negative"
)), True)

check("sign(x)", verify_code("""
def sign(x: int) -> int:
    if x > 0:
        return 1
    if x < 0:
        return -1
    return 0
""", Spec(
    postconditions=["__return__ * __return__ <= 1"],
    description="sign^2 <= 1"
)), True)

check("relu(x)", verify_code("""
def relu(x: int) -> int:
    if x > 0:
        return x
    return 0
""", Spec(
    postconditions=["__return__ >= 0"],
    description="relu is non-negative"
)), True)

check("min(a, b)", verify_code("""
def my_min(a: int, b: int) -> int:
    if a <= b:
        return a
    return b
""", Spec(
    postconditions=["__return__ <= a", "__return__ <= b"],
    description="min <= both inputs"
)), True)

check("ternary abs", verify_code("""
def ternary_abs(x: int) -> int:
    return x if x >= 0 else -x
""", Spec(
    postconditions=["__return__ >= 0"],
    description="ternary abs non-negative"
)), True)

check("double(x)", verify_code("""
def double(x: int) -> int:
    return x + x
""", Spec(
    preconditions=["x >= 0"],
    postconditions=["__return__ >= x"],
    description="double >= input for non-negative"
)), True)

check("midpoint(a, b)", verify_code("""
def midpoint(a: int, b: int) -> int:
    return (a + b) // 2
""", Spec(
    preconditions=["a >= 0", "b >= 0", "a <= 1000", "b <= 1000"],
    postconditions=["__return__ >= 0"],
    description="midpoint of non-negatives is non-negative"
)), True)

# ── Functions that SHOULD be UNSAFE ─────────────────────────────────

print("\n-- Should be UNSAFE --")

check("broken_abs (returns x instead of -x)", verify_code("""
def broken_abs(x: int) -> int:
    if x > 0:
        return x
    return x
""", Spec(
    postconditions=["__return__ >= 0"],
    description="abs should be non-negative"
)), False)

check("off_by_one clamp", verify_code("""
def bad_clamp(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo + 1
    if x > hi:
        return hi
    return x
""", Spec(
    preconditions=["lo <= hi"],
    postconditions=["__return__ >= lo", "__return__ <= hi"],
    description="clamp within bounds"
)), False)

check("subtract_one claims non-negative", verify_code("""
def subtract_one(x: int) -> int:
    return x - 1
""", Spec(
    preconditions=["x >= 0"],
    postconditions=["__return__ >= 0"],
    description="result should be non-negative"
)), False)

check("leaky relu wrong threshold", verify_code("""
def leaky_relu(x: int) -> int:
    if x > 0:
        return x
    return x // 10
""", Spec(
    postconditions=["__return__ >= 0"],
    description="should be non-negative"
)), False)

check("max returns wrong branch", verify_code("""
def bad_max(a: int, b: int) -> int:
    if a >= b:
        return b
    return a
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b"],
    description="max >= both"
)), False)

check("divide without guard", verify_code("""
def unsafe_div(a: int, b: int) -> int:
    return a // b
""", Spec(
    preconditions=["a >= 0"],
    postconditions=["__return__ >= 0"],
    description="should be non-negative (but b could be negative!)"
)), False)

# ── Summary ─────────────────────────────────────────────────────────

print(f"\n{'=' * 60}")
print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
print(f"{'=' * 60}")
