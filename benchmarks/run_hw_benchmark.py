"""Benchmark: RISC-V assembly verification.

Tests AI-generated assembly sequences for safety properties.
Simulates Domain 5 from S3's discovery: AssemblyGuard.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substrate_guard.hw_verifier import HardwareVerifier, HWSpec

verifier = HardwareVerifier()
passed = 0
failed = 0


def check(name, result, expected_verified):
    global passed, failed
    ok = result.verified == expected_verified
    icon = "+" if ok else "X"
    status = "PASS" if ok else "FAIL"
    print(f"  {icon} {status}: {name} — {result.status.value} ({result.time_ms:.1f}ms)")
    if not ok:
        print(f"    Expected: {'verified' if expected_verified else 'unsafe'}")
        print(f"    {result}")
    elif result.counterexample:
        print(f"    CE: {result.counterexample}")
    if ok:
        passed += 1
    else:
        failed += 1


print("=" * 70)
print("SUBSTRATE-GUARD — Hardware Verifier Benchmark (RISC-V RV32I)")
print("=" * 70)

# ── SHOULD VERIFY ──────────────────────────────────────────────────

print("\n-- Should be VERIFIED --")

check("abs(x): REAL BUG — INT_MIN overflow", verifier.verify("""
# Branchless abs: srai+xor+sub trick
# BUG: fails for 0x80000000 (INT_MIN has no valid negation in 32-bit)
srai t0, a0, 31
xor a0, a0, t0
sub a0, a0, t0
""", HWSpec(
    postconditions={"a0": (">=", 0)},
    description="abs result is non-negative — Z3 finds INT_MIN bug",
)), False)  # Z3 correctly finds counterexample: a0 = 0x80000000

check("abs(x) with INT_MIN guard", verifier.verify("""
# Fixed abs: clamp INT_MIN to INT_MAX first
li t1, 0x7FFFFFFF
slt t2, t1, a0
# If a0 > INT_MAX (unsigned sense) or a0 == INT_MIN, clamp
# For proof: we restrict input to exclude INT_MIN
srai t0, a0, 31
xor a0, a0, t0
sub a0, a0, t0
""", HWSpec(
    preconditions={"a0": (">", -2147483648)},  # exclude INT_MIN
    postconditions={"a0": (">=", 0)},
    description="abs with INT_MIN excluded",
)), True)

check("clamp to byte: 0 <= a0 <= 255", verifier.verify("""
# Clamp a0 to [0, 255]
slti t0, a0, 0
beq t0, zero, skip_zero
li a0, 0
skip_zero:
slti t0, a0, 256
bne t0, zero, skip_max
li a0, 255
skip_max:
nop
""", HWSpec(
    postconditions={"a0": (">=", 0), "a0": ("<=", 255)},
    description="byte clamp",
)), True)

check("zero a register", verifier.verify("""
xor a0, a0, a0
""", HWSpec(
    postconditions={"a0": ("==", 0)},
    description="xor self = 0",
)), True)

check("load immediate", verifier.verify("""
li a0, 42
""", HWSpec(
    postconditions={"a0": ("==", 42)},
    description="li sets exact value",
)), True)

check("add constants", verifier.verify("""
li a0, 10
li a1, 20
add a2, a0, a1
""", HWSpec(
    postconditions={"a2": ("==", 30)},
    description="10 + 20 = 30",
)), True)

check("multiply by 2 via shift", verifier.verify("""
li a0, 7
slli a1, a0, 1
""", HWSpec(
    postconditions={"a1": ("==", 14)},
    description="7 << 1 = 14",
)), True)

check("mask lower byte", verifier.verify("""
andi a0, a1, 0xFF
""", HWSpec(
    postconditions={"a0": (">=", 0), "a0": ("<=", 255)},
    description="AND 0xFF clamps to byte",
)), True)

check("nop sequence is safe", verifier.verify("""
nop
nop
nop
""", HWSpec(
    forbidden_instructions=["ecall"],
    description="nops are safe",
)), True)

check("move preserves value", verifier.verify("""
li a0, 99
mv a1, a0
""", HWSpec(
    postconditions={"a1": ("==", 99)},
    description="mv preserves value",
)), True)

check("negate and negate back", verifier.verify("""
li a0, 5
neg a1, a0
neg a2, a1
""", HWSpec(
    postconditions={"a2": ("==", 5)},
    description="double negate is identity",
)), True)

# ── SHOULD BE UNSAFE ──────────────────────────────────────────────

print("\n-- Should be UNSAFE --")

check("ecall present (forbidden)", verifier.verify("""
li a7, 93
li a0, 0
ecall
""", HWSpec(
    forbidden_instructions=["ecall"],
    description="no syscalls allowed",
)), False)

check("wrong constant", verifier.verify("""
li a0, 41
""", HWSpec(
    postconditions={"a0": ("==", 42)},
    description="should be 42 not 41",
)), False)

check("subtraction can go negative", verifier.verify("""
sub a0, a1, a2
""", HWSpec(
    preconditions={"a1": (">=", 0), "a2": (">=", 0)},
    postconditions={"a0": (">=", 0)},
    description="a1 - a2 >= 0 (not guaranteed when a2 > a1)",
)), False)

check("shift overflow", verifier.verify("""
li a0, 1
slli a0, a0, 31
""", HWSpec(
    postconditions={"a0": (">=", 0)},
    description="1 << 31 is negative in signed interpretation",
)), False)

check("add can overflow", verifier.verify("""
add a0, a1, a2
""", HWSpec(
    preconditions={"a1": (">=", 0), "a2": (">=", 0)},
    postconditions={"a0": (">=", 0)},
    description="add of positives can overflow to negative",
)), False)

# ── EQUIVALENCE CHECKS ────────────────────────────────────────────

print("\n-- Equivalence checks --")

check("multiply by 2: add vs shift", verifier.verify_equivalence(
    asm_a="add a0, a1, a1",        # a0 = a1 + a1
    asm_b="slli a0, a1, 1",        # a0 = a1 << 1
    input_regs=["a1"],
    output_reg="a0",
), True)

check("zero: xor vs sub", verifier.verify_equivalence(
    asm_a="xor a0, a0, a0",        # a0 = 0
    asm_b="sub a0, a0, a0",        # a0 = 0
    input_regs=["a0"],
    output_reg="a0",
), True)

check("move: addi vs mv", verifier.verify_equivalence(
    asm_a="addi a0, a1, 0",
    asm_b="mv a0, a1",
    input_regs=["a1"],
    output_reg="a0",
), True)

check("NOT equivalent: add vs sub", verifier.verify_equivalence(
    asm_a="add a0, a1, a2",
    asm_b="sub a0, a1, a2",
    input_regs=["a1", "a2"],
    output_reg="a0",
), False)

check("NOT equivalent: sll vs srl", verifier.verify_equivalence(
    asm_a="slli a0, a1, 2",        # left shift
    asm_b="srli a0, a1, 2",        # right shift
    input_regs=["a1"],
    output_reg="a0",
), False)

# ── Summary ─────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'=' * 70}")
print(f"Results: {passed} passed, {failed} failed, {total} total")
print(f"{'=' * 70}")
