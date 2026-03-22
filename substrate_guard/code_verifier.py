"""Z3 Code Verifier — formal verification of LLM-generated functions.

Takes a Python function + specification (pre/post conditions)
and returns a mathematical proof of correctness or a counterexample.

This is NOT testing. Testing checks specific inputs.
This proves correctness for ALL possible inputs satisfying preconditions.
"""

import ast
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from z3 import And, Not, Solver, sat, unsat

from .ast_translator import ASTTranslator, TranslationError, TranslationResult


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"
    TRANSLATION_ERROR = "translation_error"


@dataclass
class Counterexample:
    """A concrete input that violates the specification."""

    inputs: dict[str, Any]
    description: str = ""


@dataclass
class VerificationResult:
    """Result of formal verification."""

    status: VerificationStatus
    function_name: str = ""
    spec_description: str = ""
    counterexample: Counterexample | None = None
    time_ms: float = 0.0
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def verified(self) -> bool:
        return self.status == VerificationStatus.VERIFIED

    def __str__(self) -> str:
        if self.status == VerificationStatus.VERIFIED:
            sym = "✅ VERIFIED"
        elif self.status == VerificationStatus.UNSAFE:
            sym = "❌ UNSAFE"
        elif self.status == VerificationStatus.UNKNOWN:
            sym = "⚠️  UNKNOWN"
        else:
            sym = "🔴 TRANSLATION ERROR"

        parts = [f"{sym} — {self.function_name}"]
        if self.spec_description:
            parts.append(f"  Spec: {self.spec_description}")
        if self.counterexample:
            parts.append(f"  Counterexample: {self.counterexample.inputs}")
            if self.counterexample.description:
                parts.append(f"  {self.counterexample.description}")
        if self.warnings:
            for w in self.warnings:
                parts.append(f"  ⚠ {w}")
        if self.error:
            parts.append(f"  Error: {self.error}")
        parts.append(f"  Time: {self.time_ms:.1f}ms")
        return "\n".join(parts)


@dataclass
class Spec:
    """Specification for a function — preconditions and postconditions.

    Preconditions:  constraints on inputs (assumed true)
    Postconditions: constraints on output (must be proven)

    Both are written as Python expressions using parameter names and
    a special variable `__return__` for the function's return value.

    Example:
        Spec(
            preconditions=["x >= 0", "y > 0"],
            postconditions=["__return__ >= 0"],
            description="non-negative inputs produce non-negative output"
        )
    """

    preconditions: list[str] = field(default_factory=list)
    postconditions: list[str] = field(default_factory=list)
    description: str = ""


class CodeVerifier:
    """Verify that a Python function satisfies a formal specification.

    Approach:
    1. Parse function to AST
    2. Translate AST → Z3 constraints (via ASTTranslator)
    3. Encode spec as Z3 formulas
    4. Check: ∃ input satisfying preconditions ∧ ¬postconditions?
       - SAT   → counterexample exists → function is UNSAFE
       - UNSAT → no violation possible → function is VERIFIED
       - UNKNOWN → Z3 can't decide (timeout, etc.)
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def verify(self, source: str, spec: Spec) -> VerificationResult:
        """Verify a Python function against a specification."""
        t0 = time.time()

        # Extract function name
        func_name = self._extract_func_name(source)

        try:
            # Step 1-2: Translate function to Z3
            translator = ASTTranslator()
            translation = translator.translate_function(source)

            if translation.return_expr is None:
                return VerificationResult(
                    status=VerificationStatus.TRANSLATION_ERROR,
                    function_name=func_name,
                    spec_description=spec.description,
                    error="Function has no return statement reachable by translator",
                    time_ms=(time.time() - t0) * 1000,
                )

            # Step 3: Build Z3 formulas from spec strings
            precond = self._build_conditions(
                spec.preconditions, translation, "__return__"
            )
            postcond = self._build_conditions(
                spec.postconditions, translation, "__return__"
            )

            # Step 4: Check ∃ inputs: preconditions ∧ ¬postconditions
            solver = Solver()
            solver.set("timeout", self.timeout_ms)

            # Add any constraints from the function body (assertions, etc.)
            for c in translation.constraints:
                solver.add(c)

            # Preconditions hold
            if precond:
                solver.add(And(*precond))

            # At least one postcondition is violated
            if postcond:
                solver.add(Not(And(*postcond)))
            else:
                return VerificationResult(
                    status=VerificationStatus.TRANSLATION_ERROR,
                    function_name=func_name,
                    spec_description=spec.description,
                    error="No postconditions specified",
                    time_ms=(time.time() - t0) * 1000,
                )

            result = solver.check()

            elapsed = (time.time() - t0) * 1000

            if result == unsat:
                # No violation exists → VERIFIED
                return VerificationResult(
                    status=VerificationStatus.VERIFIED,
                    function_name=func_name,
                    spec_description=spec.description,
                    time_ms=elapsed,
                    warnings=translation.unsupported,
                )

            elif result == sat:
                # Found a counterexample → UNSAFE
                model = solver.model()
                ce_inputs = {}
                for name, z3_var in translation.params.items():
                    val = model.eval(z3_var, model_completion=True)
                    ce_inputs[name] = str(val)

                # Also show what the return value would be
                ret_val = model.eval(
                    translation.return_expr, model_completion=True
                )

                return VerificationResult(
                    status=VerificationStatus.UNSAFE,
                    function_name=func_name,
                    spec_description=spec.description,
                    counterexample=Counterexample(
                        inputs=ce_inputs,
                        description=f"Return value: {ret_val}",
                    ),
                    time_ms=elapsed,
                    warnings=translation.unsupported,
                )

            else:
                return VerificationResult(
                    status=VerificationStatus.UNKNOWN,
                    function_name=func_name,
                    spec_description=spec.description,
                    time_ms=elapsed,
                    warnings=translation.unsupported + [
                        "Z3 returned unknown (timeout or undecidable)"
                    ],
                )

        except TranslationError as e:
            return VerificationResult(
                status=VerificationStatus.TRANSLATION_ERROR,
                function_name=func_name,
                spec_description=spec.description,
                error=str(e),
                time_ms=(time.time() - t0) * 1000,
            )

    def _build_conditions(
        self, expressions: list[str], translation: TranslationResult, return_name: str
    ) -> list:
        """Parse condition strings into Z3 expressions.

        Uses the same ASTTranslator but with pre-populated variables
        from the function's parameters + a __return__ variable.
        """
        conditions = []
        for expr_str in expressions:
            translator = ASTTranslator()
            # Populate with function's parameter variables
            translator.variables = dict(translation.params)
            # Add __return__ as the function's return expression
            translator.variables[return_name] = translation.return_expr

            tree = ast.parse(expr_str, mode="eval")
            z3_expr = translator._translate_expr(tree.body)
            conditions.append(z3_expr)

        return conditions

    def _extract_func_name(self, source: str) -> str:
        """Extract function name from source code."""
        try:
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    return node.name
        except SyntaxError:
            pass
        return "<unknown>"


# ── Convenience function ──────────────────────────────────────────────


def verify_code(source: str, spec: Spec, timeout_ms: int = 5000) -> VerificationResult:
    """One-shot verification of a Python function.

    Args:
        source: Python source code containing a function definition.
        spec: Specification with preconditions and postconditions.
        timeout_ms: Z3 solver timeout in milliseconds.

    Returns:
        VerificationResult with status, optional counterexample, timing.

    Example:
        >>> result = verify_code(
        ...     '''
        ...     def clamp(x: int, lo: int, hi: int) -> int:
        ...         if x < lo:
        ...             return lo
        ...         if x > hi:
        ...             return hi
        ...         return x
        ...     ''',
        ...     Spec(
        ...         preconditions=["lo <= hi"],
        ...         postconditions=["__return__ >= lo", "__return__ <= hi"],
        ...         description="clamp returns value within [lo, hi]"
        ...     )
        ... )
        >>> result.verified
        True
    """
    verifier = CodeVerifier(timeout_ms=timeout_ms)
    return verifier.verify(source, spec)
