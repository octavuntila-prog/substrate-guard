"""Translate Python AST → Z3 constraints.

Supported subset (honest scope for paper):
  - Integer/float arithmetic (+, -, *, //, %, abs)
  - Comparisons (<, <=, >, >=, ==, !=)
  - Boolean operations (and, or, not)
  - If/else expressions and statements
  - Variable assignments (SSA-style)
  - Return statements
  - Function parameters with type hints

Explicitly unsupported (flagged, not silently wrong):
  - Loops, recursion, strings, lists, dicts, external calls
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from z3 import (
    And,
    ArithRef,
    BitVec,
    Bool,
    BoolRef,
    If,
    Int,
    IntVal,
    Not,
    Or,
    Real,
    RealVal,
)


def _is_int(x: Any) -> bool:
    """True iff x is a Z3 integer-sorted expression (not Real or bool)."""
    return isinstance(x, ArithRef) and x.is_int()


class TranslationError(Exception):
    """Raised when AST contains unsupported constructs."""

    def __init__(self, node: ast.AST, reason: str):
        self.node = node
        self.reason = reason
        line = getattr(node, "lineno", "?")
        super().__init__(f"Line {line}: {reason}")


@dataclass
class TranslationResult:
    """Result of translating a Python function to Z3."""

    params: dict[str, ArithRef | BoolRef]  # Z3 variables for parameters
    return_expr: Any  # Z3 expression for return value
    path_conditions: list  # conditions under which each return is reached
    constraints: list  # additional constraints from assignments
    unsupported: list[str]  # warnings about unsupported constructs
    nonzero_divisors: list = field(default_factory=list)  # divisors that must be != 0


class ASTTranslator:
    """Translate Python function AST to Z3 expressions.

    Uses SSA (Static Single Assignment) style: each assignment creates
    a new Z3 variable. Branches become Z3 If() expressions.
    """

    def __init__(self):
        self.variables: dict[str, Any] = {}  # current scope variables
        self.constraints: list = []
        self.unsupported: list[str] = []
        self.nonzero_divisors: list = []  # divisors that must be proven != 0
        self._var_counter = 0

    def _fresh_var(self, base_name: str, sort: str = "int") -> Any:
        """Create a fresh Z3 variable (SSA style)."""
        self._var_counter += 1
        name = f"{base_name}_{self._var_counter}"
        if sort == "int":
            return Int(name)
        elif sort == "real":
            return Real(name)
        elif sort == "bool":
            return Bool(name)
        raise TranslationError(None, f"Unknown sort: {sort}")

    def translate_function(self, source: str) -> TranslationResult:
        """Translate a Python function source to Z3 constraints."""
        tree = ast.parse(source)
        func_def = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_def = node
                break
        if func_def is None:
            raise TranslationError(tree, "No function definition found")

        # Extract parameters and create Z3 variables
        params = self._translate_params(func_def)

        # Translate function body
        return_expr = self._translate_body(func_def.body)

        return TranslationResult(
            params=params,
            return_expr=return_expr,
            path_conditions=[],
            constraints=list(self.constraints),
            unsupported=list(self.unsupported),
            nonzero_divisors=list(self.nonzero_divisors),
        )

    def _translate_params(self, func_def: ast.FunctionDef) -> dict:
        """Create Z3 variables for function parameters based on type hints."""
        params = {}
        for arg in func_def.args.args:
            name = arg.arg
            annotation = arg.annotation

            # Determine Z3 sort from type hint
            sort = "int"  # default
            if annotation:
                if isinstance(annotation, ast.Name):
                    if annotation.id == "float":
                        sort = "real"
                    elif annotation.id == "bool":
                        sort = "bool"
                    elif annotation.id == "int":
                        sort = "int"
                elif isinstance(annotation, ast.Constant):
                    if annotation.value == float:
                        sort = "real"

            if sort == "int":
                z3_var = Int(name)
            elif sort == "real":
                z3_var = Real(name)
            elif sort == "bool":
                z3_var = Bool(name)
            else:
                z3_var = Int(name)

            params[name] = z3_var
            self.variables[name] = z3_var

        return params

    def _translate_body(self, stmts: list[ast.stmt]) -> Any:
        """Translate a sequence of statements. Returns the Z3 return expression.

        Key pattern: early returns in if-without-else become Z3 If() chains.
            if cond: return a   →   If(cond, a, <rest of body>)
            return b
        """
        return self._translate_body_from(stmts, 0)

    def _translate_body_from(self, stmts: list[ast.stmt], idx: int) -> Any:
        """Translate statements starting at index idx."""
        if idx >= len(stmts):
            return None

        stmt = stmts[idx]

        # If statement with early return but no else: merge with continuation
        if isinstance(stmt, ast.If) and not stmt.orelse and self._branch_returns(stmt.body):
            condition = self._translate_expr(stmt.test)

            # Save state, translate the 'then' branch
            saved_vars = dict(self.variables)
            then_result = self._translate_body(stmt.body)

            # Restore state, translate the continuation (remaining statements)
            self.variables = dict(saved_vars)
            else_result = self._translate_body_from(stmts, idx + 1)
            cont_vars = dict(self.variables)

            # Merge variables
            self._merge_vars(condition, saved_vars, saved_vars, cont_vars)

            if then_result is not None and else_result is not None:
                return If(condition, then_result, else_result)
            elif then_result is not None:
                return then_result
            return else_result

        # No-else `if` whose body returns only on SOME paths. The early-return
        # merge above handles only bodies that DEFINITELY return; a partial return
        # cannot be faithfully joined with the fall-through continuation, so record
        # it and abstain (via the non-empty `unsupported` gate) instead of silently
        # dropping a branch and proving a property about a strictly weaker model.
        if (
            isinstance(stmt, ast.If)
            and not stmt.orelse
            and self._contains_return(stmt.body)
            and not self._branch_returns(stmt.body)
        ):
            self.unsupported.append(
                f"Line {stmt.lineno}: conditional return inside if-without-else "
                "(partial control flow not modeled)"
            )
            return self._translate_body_from(stmts, idx + 1)

        # Normal statement processing
        result = self._translate_stmt(stmt)
        if result is not None:
            return result

        # Continue to next statement
        return self._translate_body_from(stmts, idx + 1)

    def _branch_returns(self, stmts: list[ast.stmt]) -> bool:
        """Check if a branch definitely returns."""
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                return True
            if isinstance(stmt, ast.If):
                then_returns = self._branch_returns(stmt.body)
                else_returns = bool(stmt.orelse) and self._branch_returns(stmt.orelse)
                if then_returns and else_returns:
                    return True
        return False

    def _contains_return(self, stmts: list[ast.stmt]) -> bool:
        """True if any statement in the subtree contains a Return (possibly on
        only some paths)."""
        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                return True
            if isinstance(stmt, ast.If):
                if self._contains_return(stmt.body) or self._contains_return(stmt.orelse):
                    return True
        return False

    def _translate_stmt(self, stmt: ast.stmt) -> Any:
        """Translate a single statement. Returns Z3 expr if it's a return."""
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                return IntVal(0)
            return self._translate_expr(stmt.value)

        elif isinstance(stmt, ast.Assign):
            # SSA: create new Z3 variable for the assigned value
            if len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name = stmt.targets[0].id
                value = self._translate_expr(stmt.value)
                self.variables[name] = value
                return None
            self.unsupported.append(
                f"Line {stmt.lineno}: complex assignment target"
            )
            return None

        elif isinstance(stmt, ast.AugAssign):
            # Handle +=, -=, etc.
            if isinstance(stmt.target, ast.Name):
                name = stmt.target.id
                current = self.variables.get(name)
                if current is None:
                    raise TranslationError(stmt, f"Undefined variable: {name}")
                rhs = self._translate_expr(stmt.value)
                new_val = self._translate_binop(stmt.op, current, rhs)
                self.variables[name] = new_val
                return None
            self.unsupported.append(
                f"Line {stmt.lineno}: complex augmented assignment"
            )
            return None

        elif isinstance(stmt, ast.If):
            return self._translate_if(stmt)

        elif isinstance(stmt, (ast.For, ast.While)):
            self.unsupported.append(
                f"Line {stmt.lineno}: loops not supported (would need bounded unrolling)"
            )
            return None

        elif isinstance(stmt, ast.Expr):
            # A bare expression statement. A string constant is a docstring and is
            # safely ignored; anything else (e.g. a side-effecting call) is NOT
            # modeled, so record it as unsupported — otherwise the verdict could
            # silently prove a property about a function whose effects were dropped.
            if not (isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)):
                self.unsupported.append(
                    f"Line {stmt.lineno}: unmodeled expression statement "
                    f"({type(stmt.value).__name__}) — effects dropped"
                )
            return None

        elif isinstance(stmt, ast.Assert):
            # Assertions become additional Z3 constraints
            cond = self._translate_expr(stmt.test)
            self.constraints.append(cond)
            return None

        else:
            self.unsupported.append(
                f"Line {getattr(stmt, 'lineno', '?')}: {type(stmt).__name__} not supported"
            )
            return None

    def _translate_if(self, if_stmt: ast.If) -> Any:
        """Translate if/elif/else to Z3 If() expressions."""
        condition = self._translate_expr(if_stmt.test)

        # Save state before branches
        saved_vars = dict(self.variables)

        # Translate 'then' branch
        then_result = self._translate_body(if_stmt.body)
        then_vars = dict(self.variables)

        # Restore and translate 'else' branch
        self.variables = dict(saved_vars)
        else_result = self._translate_body(if_stmt.orelse) if if_stmt.orelse else None
        else_vars = dict(self.variables)

        # Merge variables modified in either branch using Z3 If()
        self._merge_vars(condition, saved_vars, then_vars, else_vars)

        # If EITHER branch only PARTIALLY returns (e.g. an inner if-without-else that
        # returns on some sub-paths), _translate_body still yields a non-None value but
        # the fall-through continuation INSIDE that branch is dropped -- the both-return
        # merge below would then be a false VERIFIED. Abstain. (Sibling of the no-else
        # partial-return case in _translate_body_from.)
        for _body in (if_stmt.body, if_stmt.orelse):
            if _body and self._contains_return(_body) and not self._branch_returns(_body):
                self.unsupported.append(
                    f"Line {if_stmt.lineno}: branch with a partial/conditional return "
                    "(continuation not modeled)"
                )
                return then_result if then_result is not None else else_result

        # Merge return values
        if then_result is not None and else_result is not None:
            # Both branches return — a faithful Z3 If() over the two values.
            return If(condition, then_result, else_result)

        if then_result is not None or else_result is not None:
            # Exactly ONE branch returns; the other falls through to the
            # statements AFTER this if (its continuation), which is not visible
            # from inside _translate_if. The returning branch therefore cannot
            # be faithfully joined with that continuation: returning its value
            # unconditionally (the old behaviour) silently drops BOTH the branch
            # condition and the fall-through path, proving a property about a
            # strictly weaker model than the real function (a false VERIFIED).
            # Record it and abstain via the non-empty `unsupported` gate in
            # code_verifier. This is the if/else sibling of the no-else
            # partial-return case handled in _translate_body_from.
            self.unsupported.append(
                f"Line {if_stmt.lineno}: asymmetric if/else — only one branch "
                "returns while the other falls through (partial control flow "
                "not modeled)"
            )
            return then_result if then_result is not None else else_result

        return None

    def _merge_vars(self, condition, saved_vars, then_vars, else_vars):
        """Merge variable state from two branches using Z3 If()."""
        all_names = set(then_vars.keys()) | set(else_vars.keys())
        for name in all_names:
            then_val = then_vars.get(name, saved_vars.get(name))
            else_val = else_vars.get(name, saved_vars.get(name))
            if then_val is not None and else_val is not None:
                if str(then_val) != str(else_val):
                    self.variables[name] = If(condition, then_val, else_val)
                else:
                    self.variables[name] = then_val

    def _translate_expr(self, expr: ast.expr) -> Any:
        """Translate a Python expression to a Z3 expression."""
        if isinstance(expr, ast.Constant):
            return self._translate_constant(expr)

        elif isinstance(expr, ast.Name):
            if expr.id in self.variables:
                return self.variables[expr.id]
            elif expr.id == "True":
                return True
            elif expr.id == "False":
                return False
            raise TranslationError(expr, f"Undefined variable: {expr.id}")

        elif isinstance(expr, ast.BinOp):
            left = self._translate_expr(expr.left)
            right = self._translate_expr(expr.right)
            return self._translate_binop(expr.op, left, right)

        elif isinstance(expr, ast.UnaryOp):
            operand = self._translate_expr(expr.operand)
            return self._translate_unaryop(expr.op, operand)

        elif isinstance(expr, ast.BoolOp):
            values = [self._translate_expr(v) for v in expr.values]
            if isinstance(expr.op, ast.And):
                return And(*values)
            elif isinstance(expr.op, ast.Or):
                return Or(*values)

        elif isinstance(expr, ast.Compare):
            return self._translate_compare(expr)

        elif isinstance(expr, ast.IfExp):
            # Ternary: a if cond else b
            cond = self._translate_expr(expr.test)
            then_val = self._translate_expr(expr.body)
            else_val = self._translate_expr(expr.orelse)
            return If(cond, then_val, else_val)

        elif isinstance(expr, ast.Call):
            return self._translate_call(expr)

        raise TranslationError(
            expr, f"Unsupported expression: {type(expr).__name__}"
        )

    def _translate_constant(self, node: ast.Constant) -> Any:
        """Translate a constant value."""
        val = node.value
        if isinstance(val, bool):
            return val
        if isinstance(val, int):
            return IntVal(val)
        if isinstance(val, float):
            return RealVal(val)
        raise TranslationError(node, f"Unsupported constant type: {type(val)}")

    def _translate_binop(self, op: ast.operator, left: Any, right: Any) -> Any:
        """Translate a binary operation."""
        if isinstance(op, ast.Add):
            return left + right
        elif isinstance(op, ast.Sub):
            return left - right
        elif isinstance(op, ast.Mult):
            return left * right
        elif isinstance(op, ast.FloorDiv):
            # Python floor division differs from Z3 integer (Euclidean) division on
            # negative operands: Python 7 // -2 == -4 but Z3 7/-2 == -3. Adjust the
            # Euclidean quotient down by one when the divisor is negative and the
            # remainder is non-zero, so the verdict is correct for every sign.
            if _is_int(left) and _is_int(right):
                self.nonzero_divisors.append(right)
                q = left / right
                r = left % right
                return If(And(right < 0, r != 0), q - 1, q)
            raise TranslationError(None, "floor division modeled only for integer operands")
        elif isinstance(op, ast.Mod):
            # Python modulo takes the sign of the divisor; Z3's Euclidean mod is
            # always non-negative. Convert Euclidean r to Python's: r + divisor when
            # the divisor is negative and r is non-zero.
            if _is_int(left) and _is_int(right):
                self.nonzero_divisors.append(right)
                r = left % right
                return If(And(right < 0, r != 0), r + right, r)
            raise TranslationError(None, "modulo modeled only for integer operands")
        elif isinstance(op, ast.Pow):
            # Limited: only integer exponents
            if isinstance(right, int) or (hasattr(right, "as_long") and right.is_int()):
                return left ** right
            raise TranslationError(None, "Only integer exponents supported for **")
        elif isinstance(op, ast.BitAnd):
            return left & right
        elif isinstance(op, ast.BitOr):
            return left | right
        elif isinstance(op, ast.BitXor):
            return left ^ right
        raise TranslationError(None, f"Unsupported binary op: {type(op).__name__}")

    def _translate_unaryop(self, op: ast.unaryop, operand: Any) -> Any:
        """Translate a unary operation."""
        if isinstance(op, ast.USub):
            return -operand
        elif isinstance(op, ast.Not):
            return Not(operand)
        elif isinstance(op, ast.UAdd):
            return operand
        raise TranslationError(None, f"Unsupported unary op: {type(op).__name__}")

    def _translate_compare(self, expr: ast.Compare) -> Any:
        """Translate a comparison chain (e.g., a < b <= c)."""
        result = None
        left = self._translate_expr(expr.left)
        for op, comparator in zip(expr.ops, expr.comparators):
            right = self._translate_expr(comparator)
            cmp = self._compare_op(op, left, right)
            result = And(result, cmp) if result is not None else cmp
            left = right
        return result

    def _compare_op(self, op: ast.cmpop, left: Any, right: Any) -> BoolRef:
        """Single comparison operation."""
        if isinstance(op, ast.Lt):
            return left < right
        elif isinstance(op, ast.LtE):
            return left <= right
        elif isinstance(op, ast.Gt):
            return left > right
        elif isinstance(op, ast.GtE):
            return left >= right
        elif isinstance(op, ast.Eq):
            return left == right
        elif isinstance(op, ast.NotEq):
            return left != right
        raise TranslationError(None, f"Unsupported comparison: {type(op).__name__}")

    def _translate_call(self, expr: ast.Call) -> Any:
        """Translate function calls — only builtins we can model in Z3."""
        if isinstance(expr.func, ast.Name):
            name = expr.func.id

            if name == "abs" and len(expr.args) == 1:
                arg = self._translate_expr(expr.args[0])
                return If(arg >= 0, arg, -arg)

            if name == "max" and len(expr.args) == 2:
                a = self._translate_expr(expr.args[0])
                b = self._translate_expr(expr.args[1])
                return If(a >= b, a, b)

            if name == "min" and len(expr.args) == 2:
                a = self._translate_expr(expr.args[0])
                b = self._translate_expr(expr.args[1])
                return If(a <= b, a, b)

        raise TranslationError(
            expr,
            f"Unsupported function call: {ast.dump(expr.func)}. "
            "Only abs(), min(), max() are supported.",
        )
