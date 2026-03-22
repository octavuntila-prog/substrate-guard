"""Benchmark: 50 functions simulating LLM-generated code.

Categories:
  - Arithmetic (10): basic math, overflow-adjacent
  - Comparison/sorting (10): min, max, median, clamp patterns
  - Control flow (10): multi-branch, nested if, early return
  - Index/boundary (10): off-by-one, range checks
  - Financial/business (10): pricing, tax, discount calculations

Each has:
  - source: Python function (some correct, some with realistic LLM bugs)
  - spec: formal preconditions + postconditions
  - expected: True (should verify) or False (should find bug)
  - bug_type: description of the bug for analysis (or "none")
"""

BENCHMARKS = []


def bench(name, source, spec, expected, bug_type="none", category="misc"):
    BENCHMARKS.append({
        "name": name,
        "source": source,
        "spec": spec,
        "expected": expected,
        "bug_type": bug_type,
        "category": category,
    })


# ═══════════════════════════════════════════════════════════════════════
# ARITHMETIC (10)
# ═══════════════════════════════════════════════════════════════════════

from substrate_guard.code_verifier import Spec

bench("arith_01_add_positive", """
def add_positive(a: int, b: int) -> int:
    return a + b
""", Spec(
    preconditions=["a > 0", "b > 0"],
    postconditions=["__return__ > a", "__return__ > b"],
    description="sum of positives > each"
), expected=True, category="arithmetic")

bench("arith_02_multiply_sign", """
def multiply_sign(a: int, b: int) -> int:
    return a * b
""", Spec(
    preconditions=["a >= 0", "b >= 0"],
    postconditions=["__return__ >= 0"],
    description="product of non-negatives is non-negative"
), expected=True, category="arithmetic")

bench("arith_03_square_positive", """
def square(x: int) -> int:
    return x * x
""", Spec(
    postconditions=["__return__ >= 0"],
    description="square is always non-negative"
), expected=True, category="arithmetic")

bench("arith_04_buggy_average", """
def average(a: int, b: int) -> int:
    return (a + b) // 2
""", Spec(
    preconditions=["a >= 0", "b >= 0"],
    postconditions=["__return__ >= a", "__return__ >= b"],
    description="average >= both (WRONG spec — average is between)"
), expected=False, bug_type="wrong_postcondition_for_average", category="arithmetic")

bench("arith_05_safe_subtract", """
def safe_subtract(a: int, b: int) -> int:
    if a >= b:
        return a - b
    return 0
""", Spec(
    preconditions=["a >= 0", "b >= 0"],
    postconditions=["__return__ >= 0"],
    description="safe subtract is non-negative"
), expected=True, category="arithmetic")

bench("arith_06_buggy_percentage", """
def percentage(value: int, total: int) -> int:
    return (value * 100) // total
""", Spec(
    preconditions=["value >= 0", "total > 0", "value <= total"],
    postconditions=["__return__ >= 0", "__return__ <= 100"],
    description="percentage in [0, 100]"
), expected=True, category="arithmetic")

bench("arith_07_increment_wraps", """
def increment(x: int) -> int:
    return x + 1
""", Spec(
    postconditions=["__return__ > x"],
    description="increment always greater"
), expected=True, category="arithmetic")

bench("arith_08_buggy_negate", """
def negate(x: int) -> int:
    return -x
""", Spec(
    preconditions=["x > 0"],
    postconditions=["__return__ >= 0"],
    description="negate of positive should be non-negative (BUG)"
), expected=False, bug_type="negate_positive_not_nonneg", category="arithmetic")

bench("arith_09_double_minus", """
def double_negate(x: int) -> int:
    return -(-x)
""", Spec(
    postconditions=["__return__ == x"],
    description="double negate is identity"
), expected=True, category="arithmetic")

bench("arith_10_power_of_two", """
def power_of_two(x: int) -> int:
    return x * x * x * x
""", Spec(
    postconditions=["__return__ >= 0"],
    description="x^4 is always non-negative"
), expected=True, category="arithmetic")

# ═══════════════════════════════════════════════════════════════════════
# COMPARISON / SORTING (10)
# ═══════════════════════════════════════════════════════════════════════

bench("comp_01_max_correct", """
def my_max(a: int, b: int) -> int:
    if a >= b:
        return a
    return b
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b"],
    description="max >= both"
), expected=True, category="comparison")

bench("comp_02_min_correct", """
def my_min(a: int, b: int) -> int:
    if a <= b:
        return a
    return b
""", Spec(
    postconditions=["__return__ <= a", "__return__ <= b"],
    description="min <= both"
), expected=True, category="comparison")

bench("comp_03_max_swapped", """
def bad_max(a: int, b: int) -> int:
    if a >= b:
        return b
    return a
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b"],
    description="max >= both (branches swapped)"
), expected=False, bug_type="swapped_branches", category="comparison")

bench("comp_04_clamp_correct", """
def clamp(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x
""", Spec(
    preconditions=["lo <= hi"],
    postconditions=["__return__ >= lo", "__return__ <= hi"],
    description="clamp in bounds"
), expected=True, category="comparison")

bench("comp_05_clamp_off_by_one", """
def clamp(x: int, lo: int, hi: int) -> int:
    if x < lo:
        return lo
    if x >= hi:
        return hi
    return x
""", Spec(
    preconditions=["lo <= hi"],
    postconditions=["__return__ >= lo", "__return__ <= hi"],
    description="clamp in bounds (>= instead of >)"
), expected=True, category="comparison")  # Actually still correct!

bench("comp_06_median_of_three", """
def median3(a: int, b: int, c: int) -> int:
    if a <= b:
        if b <= c:
            return b
        if a <= c:
            return c
        return a
    if a <= c:
        return a
    if b <= c:
        return c
    return b
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b", "__return__ >= c"],
    description="median >= all three (WRONG — median is middle value)"
), expected=False, bug_type="wrong_spec_median", category="comparison")

bench("comp_07_max3", """
def max3(a: int, b: int, c: int) -> int:
    if a >= b:
        if a >= c:
            return a
        return c
    if b >= c:
        return b
    return c
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b", "__return__ >= c"],
    description="max3 >= all three"
), expected=True, category="comparison")

bench("comp_08_buggy_max3", """
def max3(a: int, b: int, c: int) -> int:
    if a >= b:
        if a >= c:
            return a
        return c
    return b
""", Spec(
    postconditions=["__return__ >= a", "__return__ >= b", "__return__ >= c"],
    description="max3 missing b vs c comparison"
), expected=False, bug_type="missing_comparison", category="comparison")

bench("comp_09_abs_diff", """
def abs_diff(a: int, b: int) -> int:
    if a >= b:
        return a - b
    return b - a
""", Spec(
    postconditions=["__return__ >= 0"],
    description="abs_diff is non-negative"
), expected=True, category="comparison")

bench("comp_10_buggy_abs_diff", """
def abs_diff(a: int, b: int) -> int:
    return a - b
""", Spec(
    postconditions=["__return__ >= 0"],
    description="abs_diff non-negative (missing abs)"
), expected=False, bug_type="missing_abs", category="comparison")

# ═══════════════════════════════════════════════════════════════════════
# CONTROL FLOW (10)
# ═══════════════════════════════════════════════════════════════════════

bench("ctrl_01_sign", """
def sign(x: int) -> int:
    if x > 0:
        return 1
    if x < 0:
        return -1
    return 0
""", Spec(
    postconditions=["__return__ >= -1", "__return__ <= 1"],
    description="sign in [-1, 1]"
), expected=True, category="control_flow")

bench("ctrl_02_fizzbuzz_value", """
def fizzbuzz_val(x: int) -> int:
    if x % 15 == 0:
        return 15
    if x % 3 == 0:
        return 3
    if x % 5 == 0:
        return 5
    return x
""", Spec(
    preconditions=["x > 0", "x <= 100"],
    postconditions=["__return__ > 0"],
    description="fizzbuzz value always positive"
), expected=True, category="control_flow")

bench("ctrl_03_relu", """
def relu(x: int) -> int:
    if x > 0:
        return x
    return 0
""", Spec(
    postconditions=["__return__ >= 0"],
    description="relu non-negative"
), expected=True, category="control_flow")

bench("ctrl_04_leaky_relu_bug", """
def leaky_relu(x: int) -> int:
    if x > 0:
        return x
    return x // 10
""", Spec(
    postconditions=["__return__ >= 0"],
    description="leaky relu non-negative (BUG: negative leak)"
), expected=False, bug_type="negative_leak", category="control_flow")

bench("ctrl_05_nested_positive", """
def categorize(x: int) -> int:
    if x > 0:
        if x > 100:
            return 3
        if x > 10:
            return 2
        return 1
    return 0
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 3"],
    description="categorize returns 0-3"
), expected=True, category="control_flow")

bench("ctrl_06_step_function", """
def step(x: int) -> int:
    if x < 0:
        return 0
    if x < 10:
        return 1
    if x < 100:
        return 2
    return 3
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 3"],
    description="step in [0, 3]"
), expected=True, category="control_flow")

bench("ctrl_07_buggy_step", """
def step(x: int) -> int:
    if x < 0:
        return -1
    if x < 10:
        return 1
    if x < 100:
        return 2
    return 3
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 3"],
    description="step in [0, 3] (BUG: returns -1)"
), expected=False, bug_type="negative_return", category="control_flow")

bench("ctrl_08_bool_to_int", """
def bool_to_int(x: int) -> int:
    if x == 0:
        return 0
    return 1
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 1"],
    description="bool_to_int returns 0 or 1"
), expected=True, category="control_flow")

bench("ctrl_09_ternary_chain", """
def grade(score: int) -> int:
    return 4 if score >= 90 else (3 if score >= 80 else (2 if score >= 70 else (1 if score >= 60 else 0)))
""", Spec(
    preconditions=["score >= 0", "score <= 100"],
    postconditions=["__return__ >= 0", "__return__ <= 4"],
    description="grade 0-4"
), expected=True, category="control_flow")

bench("ctrl_10_abs_via_assignment", """
def my_abs(x: int) -> int:
    result = x
    if x < 0:
        result = -x
    return result
""", Spec(
    postconditions=["__return__ >= 0"],
    description="abs via variable assignment"
), expected=True, category="control_flow")

# ═══════════════════════════════════════════════════════════════════════
# INDEX / BOUNDARY (10)
# ═══════════════════════════════════════════════════════════════════════

bench("idx_01_bound_check", """
def bound(idx: int, size: int) -> int:
    if idx < 0:
        return 0
    if idx >= size:
        return size - 1
    return idx
""", Spec(
    preconditions=["size > 0"],
    postconditions=["__return__ >= 0", "__return__ < size"],
    description="bound index in [0, size)"
), expected=True, category="boundary")

bench("idx_02_buggy_bound", """
def bound(idx: int, size: int) -> int:
    if idx < 0:
        return 0
    if idx > size:
        return size
    return idx
""", Spec(
    preconditions=["size > 0"],
    postconditions=["__return__ >= 0", "__return__ < size"],
    description="bound in [0, size) — BUG: > instead of >="
), expected=False, bug_type="off_by_one_boundary", category="boundary")

bench("idx_03_wrap_around", """
def wrap(idx: int, size: int) -> int:
    return idx % size
""", Spec(
    preconditions=["size > 0", "idx >= 0"],
    postconditions=["__return__ >= 0", "__return__ < size"],
    description="modulo wraps to [0, size)"
), expected=True, category="boundary")

bench("idx_04_midpoint", """
def midpoint(lo: int, hi: int) -> int:
    return lo + (hi - lo) // 2
""", Spec(
    preconditions=["lo >= 0", "hi >= lo"],
    postconditions=["__return__ >= lo", "__return__ <= hi"],
    description="midpoint between lo and hi"
), expected=True, category="boundary")

bench("idx_05_buggy_midpoint", """
def midpoint(lo: int, hi: int) -> int:
    return (lo + hi) // 2
""", Spec(
    preconditions=["lo >= 0", "hi >= lo"],
    postconditions=["__return__ >= lo"],
    description="midpoint >= lo"
), expected=True, category="boundary")

bench("idx_06_clamp_to_byte", """
def to_byte(x: int) -> int:
    if x < 0:
        return 0
    if x > 255:
        return 255
    return x
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 255"],
    description="clamp to byte [0, 255]"
), expected=True, category="boundary")

bench("idx_07_buggy_byte", """
def to_byte(x: int) -> int:
    if x < 0:
        return 0
    if x > 256:
        return 255
    return x
""", Spec(
    postconditions=["__return__ >= 0", "__return__ <= 255"],
    description="byte clamp BUG: 256 passes through"
), expected=False, bug_type="off_by_one_256", category="boundary")

bench("idx_08_page_number", """
def page(offset: int, page_size: int) -> int:
    return offset // page_size
""", Spec(
    preconditions=["offset >= 0", "page_size > 0"],
    postconditions=["__return__ >= 0"],
    description="page number non-negative"
), expected=True, category="boundary")

bench("idx_09_safe_array_len", """
def items_left(total: int, taken: int) -> int:
    if taken > total:
        return 0
    return total - taken
""", Spec(
    preconditions=["total >= 0", "taken >= 0"],
    postconditions=["__return__ >= 0"],
    description="items left non-negative"
), expected=True, category="boundary")

bench("idx_10_buggy_items_left", """
def items_left(total: int, taken: int) -> int:
    return total - taken
""", Spec(
    preconditions=["total >= 0", "taken >= 0"],
    postconditions=["__return__ >= 0"],
    description="items left (BUG: no guard for taken > total)"
), expected=False, bug_type="missing_guard", category="boundary")

# ═══════════════════════════════════════════════════════════════════════
# FINANCIAL / BUSINESS LOGIC (10)
# ═══════════════════════════════════════════════════════════════════════

bench("fin_01_tax", """
def tax(price: int, rate: int) -> int:
    return (price * rate) // 100
""", Spec(
    preconditions=["price >= 0", "rate >= 0", "rate <= 100"],
    postconditions=["__return__ >= 0", "__return__ <= price"],
    description="tax <= price"
), expected=True, category="financial")

bench("fin_02_discount", """
def apply_discount(price: int, discount: int) -> int:
    return price - (price * discount) // 100
""", Spec(
    preconditions=["price >= 0", "discount >= 0", "discount <= 100"],
    postconditions=["__return__ >= 0", "__return__ <= price"],
    description="discounted price in [0, price]"
), expected=True, category="financial")

bench("fin_03_buggy_discount", """
def apply_discount(price: int, discount: int) -> int:
    return price - discount
""", Spec(
    preconditions=["price >= 0", "discount >= 0"],
    postconditions=["__return__ >= 0"],
    description="discount subtracts directly (BUG: discount > price)"
), expected=False, bug_type="discount_exceeds_price", category="financial")

bench("fin_04_tip", """
def calculate_tip(bill: int, percent: int) -> int:
    return (bill * percent) // 100
""", Spec(
    preconditions=["bill >= 0", "percent >= 0", "percent <= 50"],
    postconditions=["__return__ >= 0"],
    description="tip is non-negative"
), expected=True, category="financial")

bench("fin_05_total_with_tax", """
def total_with_tax(price: int, tax_rate: int) -> int:
    return price + (price * tax_rate) // 100
""", Spec(
    preconditions=["price >= 0", "tax_rate >= 0"],
    postconditions=["__return__ >= price"],
    description="total with tax >= original price"
), expected=True, category="financial")

bench("fin_06_split_bill", """
def split_bill(total: int, people: int) -> int:
    return total // people
""", Spec(
    preconditions=["total >= 0", "people > 0"],
    postconditions=["__return__ >= 0"],
    description="split is non-negative"
), expected=True, category="financial")

bench("fin_07_margin", """
def margin(revenue: int, cost: int) -> int:
    if revenue <= 0:
        return 0
    return ((revenue - cost) * 100) // revenue
""", Spec(
    preconditions=["revenue > 0", "cost >= 0", "cost <= revenue"],
    postconditions=["__return__ >= 0", "__return__ <= 100"],
    description="margin in [0%, 100%]"
), expected=True, category="financial")

bench("fin_08_buggy_margin", """
def margin(revenue: int, cost: int) -> int:
    return ((revenue - cost) * 100) // revenue
""", Spec(
    preconditions=["revenue > 0", "cost >= 0"],
    postconditions=["__return__ >= 0"],
    description="margin non-negative (BUG: cost > revenue)"
), expected=False, bug_type="cost_exceeds_revenue", category="financial")

bench("fin_09_compound", """
def compound_simple(principal: int, rate: int, years: int) -> int:
    return principal + (principal * rate * years) // 100
""", Spec(
    preconditions=["principal > 0", "rate >= 0", "years >= 0"],
    postconditions=["__return__ >= principal"],
    description="compound >= principal"
), expected=True, category="financial")

bench("fin_10_commission", """
def commission(sales: int, tier: int) -> int:
    if tier == 1:
        return sales // 10
    if tier == 2:
        return sales // 5
    return sales // 20
""", Spec(
    preconditions=["sales >= 0", "tier >= 1", "tier <= 3"],
    postconditions=["__return__ >= 0"],
    description="commission non-negative"
), expected=True, category="financial")
