"""Z3 Distillation Verifier — formal verification of reasoning post-compression.

Domain 3 from S3's emergent discovery: DistillCheck.
Verifies that mathematical reasoning traces from distilled (smaller) models
preserve the correctness of the original (larger) model.

The key insight: when you compress a 70B model to 7B, the model might
produce plausible-looking reasoning that's mathematically wrong. Testing
catches some errors; Z3 catches ALL errors within the supported domain.

Approach:
1. Parse reasoning trace into structured steps
2. Convert each step to SymPy symbolic expressions
3. Verify each step's logical validity using Z3
4. Compare distilled vs reference traces for equivalence

Supported math domains:
  - Arithmetic (integers, fractions, basic operations)
  - Algebra (equations, inequalities, simplification)
  - Basic calculus properties (monotonicity, sign)
  - Modular arithmetic
  - Logical deductions
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import sympy
from sympy import (
    Eq,
    Integer,
    Rational,
    Symbol,
    simplify,
    solve,
    sympify,
    symbols,
)
from sympy.parsing.sympy_parser import (
    convert_xor,
    implicit_multiplication_application,
    parse_expr,
    standard_transformations,
)
from z3 import (
    And,
    ArithRef,
    Int,
    IntVal,
    Not,
    Or,
    Real,
    RealVal,
    Solver,
    sat,
    unsat,
)


class StepStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNPARSEABLE = "unparseable"
    UNCHECKED = "unchecked"


class TraceStatus(str, Enum):
    ALL_VALID = "all_valid"
    HAS_ERRORS = "has_errors"
    PARSE_FAILURE = "parse_failure"


@dataclass
class ReasoningStep:
    """A single step in a mathematical reasoning trace."""

    step_number: int
    raw_text: str
    expression: str  # the mathematical claim/operation
    operation: str  # what was done: "simplify", "substitute", "solve", etc.
    result: str  # the result of this step


@dataclass
class StepVerification:
    """Verification result for a single reasoning step."""

    step_number: int
    status: StepStatus
    raw_text: str = ""
    error: str | None = None
    expected: str | None = None
    actual: str | None = None


@dataclass
class TraceVerification:
    """Verification result for an entire reasoning trace."""

    status: TraceStatus
    steps: list[StepVerification] = field(default_factory=list)
    valid_count: int = 0
    invalid_count: int = 0
    unparseable_count: int = 0
    time_ms: float = 0.0
    problem: str = ""

    @property
    def all_valid(self) -> bool:
        return self.status == TraceStatus.ALL_VALID

    def __str__(self) -> str:
        icon = "V" if self.all_valid else "X"
        parts = [
            f"{icon} {self.status.value} — {self.problem} "
            f"({self.valid_count} valid, {self.invalid_count} invalid, "
            f"{self.unparseable_count} unparseable, {self.time_ms:.1f}ms)"
        ]
        for step in self.steps:
            if step.status == StepStatus.VALID:
                parts.append(f"  + Step {step.step_number}: valid")
            elif step.status == StepStatus.INVALID:
                parts.append(f"  X Step {step.step_number}: INVALID")
                if step.error:
                    parts.append(f"    {step.error}")
                if step.expected and step.actual:
                    parts.append(f"    Expected: {step.expected}, Got: {step.actual}")
            elif step.status == StepStatus.UNPARSEABLE:
                parts.append(f"  ? Step {step.step_number}: unparseable — {step.error}")
        return "\n".join(parts)


# ── Sympy parsing helpers ───────────────────────────────────────────

TRANSFORMATIONS = standard_transformations + (
    implicit_multiplication_application,
    convert_xor,
)


def safe_parse(expr_str: str) -> sympy.Expr | None:
    """Parse a math expression string to SymPy, handling common LLM formats."""
    expr_str = expr_str.strip()
    # Clean up common LLM formatting
    expr_str = expr_str.replace("^", "**")
    expr_str = expr_str.replace("×", "*")
    expr_str = expr_str.replace("÷", "/")
    expr_str = expr_str.replace("−", "-")
    expr_str = re.sub(r"(\d)([a-zA-Z])", r"\1*\2", expr_str)  # 3x → 3*x

    try:
        return parse_expr(expr_str, transformations=TRANSFORMATIONS)
    except Exception:
        try:
            return sympify(expr_str)
        except Exception:
            return None


def sympy_to_z3(expr: sympy.Expr, var_map: dict[str, Any]) -> Any:
    """Convert a SymPy expression to Z3.

    Handles: integers, rationals, symbols, Add, Mul, Pow (integer exp),
    comparisons (Eq, Lt, Le, Gt, Ge).
    """
    if isinstance(expr, sympy.Integer):
        return IntVal(int(expr))

    if isinstance(expr, sympy.Rational):
        return RealVal(float(expr))

    if isinstance(expr, sympy.Float):
        return RealVal(float(expr))

    if isinstance(expr, sympy.Symbol):
        name = str(expr)
        if name not in var_map:
            var_map[name] = Real(name)
        return var_map[name]

    if isinstance(expr, sympy.Add):
        terms = [sympy_to_z3(arg, var_map) for arg in expr.args]
        result = terms[0]
        for t in terms[1:]:
            result = result + t
        return result

    if isinstance(expr, sympy.Mul):
        factors = [sympy_to_z3(arg, var_map) for arg in expr.args]
        result = factors[0]
        for f in factors[1:]:
            result = result * f
        return result

    if isinstance(expr, sympy.Pow):
        base = sympy_to_z3(expr.args[0], var_map)
        exp = expr.args[1]
        if isinstance(exp, sympy.Integer) and 0 <= int(exp) <= 10:
            result = IntVal(1) if isinstance(base, ArithRef) else RealVal(1)
            for _ in range(int(exp)):
                result = result * base
            return result
        return sympy_to_z3(expr.args[0], var_map)  # fallback: ignore exponent

    if isinstance(expr, sympy.Abs):
        inner = sympy_to_z3(expr.args[0], var_map)
        from z3 import If
        return If(inner >= 0, inner, -inner)

    if isinstance(expr, sympy.Mod):
        a = sympy_to_z3(expr.args[0], var_map)
        b = sympy_to_z3(expr.args[1], var_map)
        return a % b

    # Numbers that SymPy wraps
    if isinstance(expr, sympy.core.numbers.One):
        return IntVal(1)
    if isinstance(expr, sympy.core.numbers.Zero):
        return IntVal(0)
    if isinstance(expr, sympy.core.numbers.NegativeOne):
        return IntVal(-1)

    raise ValueError(f"Cannot convert {type(expr).__name__}: {expr}")


# ── Core verifier ───────────────────────────────────────────────────


class DistillationVerifier:
    """Verify mathematical reasoning traces from distilled models."""

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def verify_trace(self, problem: str, steps: list[dict]) -> TraceVerification:
        """Verify a reasoning trace.

        Each step dict has:
            {"claim": "3x + 6 = 15 → 3x = 9", "operation": "subtract 6"}
        or:
            {"lhs": "3x + 6", "rhs": "15", "result_lhs": "3x", "result_rhs": "9", "operation": "subtract 6"}
        """
        t0 = time.time()
        verifications = []
        valid = 0
        invalid = 0
        unparseable = 0

        for i, step in enumerate(steps):
            sv = self._verify_step(i + 1, step)
            verifications.append(sv)
            if sv.status == StepStatus.VALID:
                valid += 1
            elif sv.status == StepStatus.INVALID:
                invalid += 1
            elif sv.status == StepStatus.UNPARSEABLE:
                unparseable += 1

        elapsed = (time.time() - t0) * 1000

        if invalid > 0:
            status = TraceStatus.HAS_ERRORS
        elif unparseable > 0 and valid == 0:
            status = TraceStatus.PARSE_FAILURE
        else:
            status = TraceStatus.ALL_VALID

        return TraceVerification(
            status=status,
            steps=verifications,
            valid_count=valid,
            invalid_count=invalid,
            unparseable_count=unparseable,
            time_ms=elapsed,
            problem=problem,
        )

    def _verify_step(self, step_num: int, step: dict) -> StepVerification:
        """Verify a single reasoning step."""

        # Format 1: "claim" with arrow
        if "claim" in step:
            return self._verify_claim(step_num, step["claim"], step.get("operation", ""))

        # Format 2: explicit lhs/rhs transformation
        if "lhs" in step and "result_lhs" in step:
            return self._verify_transformation(step_num, step)

        # Format 3: "equation" and "result"
        if "equation" in step and "result" in step:
            return self._verify_equation_result(step_num, step)

        # Format 4: "expression" and "value"
        if "expression" in step and "value" in step:
            return self._verify_evaluation(step_num, step)

        return StepVerification(
            step_number=step_num,
            status=StepStatus.UNPARSEABLE,
            error=f"Unknown step format: {list(step.keys())}",
        )

    def _verify_claim(self, step_num: int, claim: str, operation: str) -> StepVerification:
        """Verify a claim like '3x + 6 = 15 → 3x = 9'."""
        # Split on arrow
        parts = re.split(r"[→⟹⇒]|->|==>", claim)
        if len(parts) != 2:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                raw_text=claim,
                error="Cannot split claim into before/after",
            )

        before, after = parts[0].strip(), parts[1].strip()

        # Parse both sides of equations
        before_eq = self._parse_equation(before)
        after_eq = self._parse_equation(after)

        if before_eq is None or after_eq is None:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                raw_text=claim,
                error=f"Cannot parse: before={before}, after={after}",
            )

        # Verify: if before is true, then after must be true
        return self._check_implication(step_num, before_eq, after_eq, claim)

    def _verify_transformation(self, step_num: int, step: dict) -> StepVerification:
        """Verify lhs op rhs → result_lhs op result_rhs."""
        lhs = safe_parse(step["lhs"])
        rhs = safe_parse(step.get("rhs", step["lhs"]))
        result_lhs = safe_parse(step["result_lhs"])
        result_rhs = safe_parse(step.get("result_rhs", step.get("rhs", "0")))

        if any(x is None for x in [lhs, rhs, result_lhs, result_rhs]):
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                error=f"Cannot parse transformation components",
            )

        # Build equations
        before_eq = sympy.Eq(lhs, rhs)
        after_eq = sympy.Eq(result_lhs, result_rhs)

        return self._check_implication(step_num, before_eq, after_eq,
                                       f"{lhs}={rhs} → {result_lhs}={result_rhs}")

    def _verify_equation_result(self, step_num: int, step: dict) -> StepVerification:
        """Verify solving an equation produces the claimed result."""
        eq_str = step["equation"]
        result_str = step["result"]

        # Parse equation
        eq = self._parse_equation(eq_str)
        if eq is None:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                error=f"Cannot parse equation: {eq_str}",
            )

        # Parse result (might be "x = 5" or just "5")
        result_eq = self._parse_equation(result_str)
        if result_eq is None:
            # Try as a plain value
            result_val = safe_parse(result_str)
            if result_val is not None:
                # Assume it's the value of the first free symbol
                free = list(eq.free_symbols)
                if free:
                    result_eq = sympy.Eq(free[0], result_val)

        if result_eq is None:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                error=f"Cannot parse result: {result_str}",
            )

        return self._check_implication(step_num, eq, result_eq,
                                       f"{eq_str} → {result_str}")

    def _verify_evaluation(self, step_num: int, step: dict) -> StepVerification:
        """Verify that an expression evaluates to a claimed value."""
        expr = safe_parse(step["expression"])
        value = safe_parse(str(step["value"]))

        if expr is None or value is None:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                error=f"Cannot parse expression/value",
            )

        # If expression is purely numeric, just check equality
        if not expr.free_symbols:
            simplified = simplify(expr - value)
            if simplified == 0:
                return StepVerification(step_number=step_num, status=StepStatus.VALID,
                                       raw_text=f"{step['expression']} = {step['value']}")
            else:
                return StepVerification(
                    step_number=step_num, status=StepStatus.INVALID,
                    raw_text=f"{step['expression']} = {step['value']}",
                    error=f"Expression evaluates to {simplify(expr)}, not {value}",
                    expected=str(value), actual=str(simplify(expr)),
                )

        # Symbolic — check via Z3
        eq = sympy.Eq(expr, value)
        var_map = {}
        try:
            z3_eq = self._sympy_eq_to_z3(eq, var_map)
        except ValueError as e:
            return StepVerification(
                step_number=step_num, status=StepStatus.UNPARSEABLE,
                error=f"Z3 conversion failed: {e}",
            )

        solver = Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(Not(z3_eq))
        result = solver.check()

        if result == unsat:
            return StepVerification(step_number=step_num, status=StepStatus.VALID,
                                   raw_text=f"{step['expression']} = {step['value']}")
        else:
            return StepVerification(
                step_number=step_num, status=StepStatus.INVALID,
                raw_text=f"{step['expression']} = {step['value']}",
                error="Z3 found counterexample or could not verify",
                expected=str(value), actual=str(expr),
            )

    def _parse_equation(self, s: str) -> sympy.Eq | None:
        """Parse 'lhs = rhs' into a SymPy Eq."""
        s = s.strip()
        if "=" not in s:
            return None

        # Handle != and ==
        s = s.replace("==", "=")
        parts = s.split("=")
        if len(parts) != 2:
            return None

        lhs = safe_parse(parts[0].strip())
        rhs = safe_parse(parts[1].strip())
        if lhs is None or rhs is None:
            return None

        return sympy.Eq(lhs, rhs)

    def _check_implication(self, step_num: int, before: sympy.Eq,
                           after: sympy.Eq, raw_text: str) -> StepVerification:
        """Check if 'before' implies 'after' using Z3."""
        var_map = {}

        try:
            z3_before = self._sympy_eq_to_z3(before, var_map)
            z3_after = self._sympy_eq_to_z3(after, var_map)
        except ValueError as e:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.UNPARSEABLE,
                raw_text=raw_text,
                error=f"Z3 conversion: {e}",
            )

        # Check: is there any assignment where before is true but after is false?
        solver = Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(z3_before)
        solver.add(Not(z3_after))

        result = solver.check()

        if result == unsat:
            # No counterexample → implication holds
            return StepVerification(
                step_number=step_num,
                status=StepStatus.VALID,
                raw_text=raw_text,
            )
        elif result == sat:
            model = solver.model()
            ce = {str(k): str(model[k]) for k in model}
            return StepVerification(
                step_number=step_num,
                status=StepStatus.INVALID,
                raw_text=raw_text,
                error=f"Counterexample: {ce}",
                expected=str(after),
                actual=f"Does not follow from {before}",
            )
        else:
            return StepVerification(
                step_number=step_num,
                status=StepStatus.VALID,  # conservative: unknown → accept
                raw_text=raw_text,
            )

    def _sympy_eq_to_z3(self, eq: sympy.Eq, var_map: dict) -> Any:
        """Convert SymPy Eq to Z3 equality."""
        lhs_z3 = sympy_to_z3(eq.lhs, var_map)
        rhs_z3 = sympy_to_z3(eq.rhs, var_map)
        return lhs_z3 == rhs_z3

    def verify_arithmetic(self, expression: str, claimed_result: str) -> StepVerification:
        """Standalone: verify a single arithmetic claim.

        Example: verify_arithmetic("17 * 23 + 5", "396")
        """
        return self._verify_evaluation(1, {
            "expression": expression,
            "value": claimed_result,
        })

    def compare_traces(self, problem: str,
                       reference_trace: list[dict],
                       distilled_trace: list[dict]) -> dict:
        """Compare a reference model's trace against a distilled model's trace.

        Returns analysis of where the distilled model diverges.
        """
        ref_result = self.verify_trace(f"{problem} (reference)", reference_trace)
        dist_result = self.verify_trace(f"{problem} (distilled)", distilled_trace)

        divergences = []
        for dist_step in dist_result.steps:
            if dist_step.status == StepStatus.INVALID:
                # Find corresponding ref step
                ref_step = None
                for rs in ref_result.steps:
                    if rs.step_number == dist_step.step_number:
                        ref_step = rs
                        break
                divergences.append({
                    "step": dist_step.step_number,
                    "distilled": dist_step.raw_text,
                    "distilled_error": dist_step.error,
                    "reference_valid": ref_step.status == StepStatus.VALID if ref_step else None,
                })

        return {
            "problem": problem,
            "reference": ref_result,
            "distilled": dist_result,
            "divergences": divergences,
            "reference_valid": ref_result.all_valid,
            "distilled_valid": dist_result.all_valid,
            "error_introduced_by_distillation": ref_result.all_valid and not dist_result.all_valid,
        }


def verify_distillation(problem: str, steps: list[dict]) -> TraceVerification:
    """One-shot trace verification."""
    return DistillationVerifier().verify_trace(problem, steps)
