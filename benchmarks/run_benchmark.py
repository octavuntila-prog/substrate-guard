"""Run the full benchmark and produce paper-ready results."""

import json
import sys
import time

sys.path.insert(0, "/home/claude/substrate-guard")

from benchmarks.llm_functions import BENCHMARKS
from substrate_guard.code_verifier import verify_code


def run_benchmarks():
    results = []
    categories = {}

    print("=" * 70)
    print("SUBSTRATE-GUARD — Code Verifier Benchmark (50 functions)")
    print("=" * 70)

    total_time = 0
    correct = 0
    wrong = 0
    errors = 0

    for i, b in enumerate(BENCHMARKS, 1):
        result = verify_code(b["source"], b["spec"])
        actual_verified = result.verified
        expected_verified = b["expected"]
        match = actual_verified == expected_verified
        total_time += result.time_ms

        if result.status.value == "translation_error":
            icon = "E"
            errors += 1
        elif match:
            icon = "+"
            correct += 1
        else:
            icon = "X"
            wrong += 1

        cat = b["category"]
        if cat not in categories:
            categories[cat] = {"correct": 0, "wrong": 0, "errors": 0, "time_ms": 0}
        if match:
            categories[cat]["correct"] += 1
        elif result.status.value == "translation_error":
            categories[cat]["errors"] += 1
        else:
            categories[cat]["wrong"] += 1
        categories[cat]["time_ms"] += result.time_ms

        status_str = "OK" if match else "MISMATCH"
        print(f"  {icon} [{i:02d}] {b['name']:<35} {result.status.value:<10} "
              f"{'(expected)' if match else '*** UNEXPECTED ***'} "
              f"{result.time_ms:6.1f}ms")

        if not match:
            print(f"       Expected: {'verified' if expected_verified else 'unsafe'}, "
                  f"Got: {result.status.value}")
            if result.counterexample:
                print(f"       Counterexample: {result.counterexample.inputs}")
            if result.error:
                print(f"       Error: {result.error}")

        results.append({
            "name": b["name"],
            "category": b["category"],
            "expected": "verified" if expected_verified else "unsafe",
            "actual": result.status.value,
            "correct": match,
            "time_ms": round(result.time_ms, 2),
            "bug_type": b["bug_type"],
            "counterexample": (
                result.counterexample.inputs if result.counterexample else None
            ),
            "warnings": result.warnings,
        })

    # ── Summary ─────────────────────────────────────────────────────

    total = len(BENCHMARKS)
    print(f"\n{'=' * 70}")
    print(f"RESULTS SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total functions:     {total}")
    print(f"  Correctly classified: {correct}/{total} ({100*correct/total:.1f}%)")
    print(f"  Misclassified:       {wrong}/{total}")
    print(f"  Translation errors:  {errors}/{total}")
    print(f"  Total time:          {total_time:.1f}ms")
    print(f"  Avg per function:    {total_time/total:.1f}ms")
    print()

    # ── Per-category breakdown ──────────────────────────────────────

    print(f"  {'Category':<20} {'Correct':>8} {'Wrong':>8} {'Errors':>8} {'Avg ms':>8}")
    print(f"  {'-'*56}")
    for cat, stats in sorted(categories.items()):
        n = stats["correct"] + stats["wrong"] + stats["errors"]
        avg = stats["time_ms"] / n if n > 0 else 0
        print(f"  {cat:<20} {stats['correct']:>8} {stats['wrong']:>8} "
              f"{stats['errors']:>8} {avg:>7.1f}")

    # ── Bug detection analysis ──────────────────────────────────────

    print(f"\n  Bug Detection Analysis:")
    bugs_expected = [r for r in results if r["expected"] == "unsafe"]
    bugs_caught = [r for r in bugs_expected if r["actual"] == "unsafe"]
    clean_expected = [r for r in results if r["expected"] == "verified"]
    clean_confirmed = [r for r in clean_expected if r["actual"] == "verified"]
    false_positives = [r for r in clean_expected if r["actual"] == "unsafe"]
    false_negatives = [r for r in bugs_expected if r["actual"] == "verified"]

    print(f"  True positives (bugs caught):    {len(bugs_caught)}/{len(bugs_expected)}")
    print(f"  True negatives (clean confirmed): {len(clean_confirmed)}/{len(clean_expected)}")
    print(f"  False positives (clean flagged):  {len(false_positives)}")
    print(f"  False negatives (bugs missed):    {len(false_negatives)}")

    if false_negatives:
        print(f"\n  *** Bugs missed:")
        for r in false_negatives:
            print(f"      {r['name']} (bug: {r['bug_type']})")

    if false_positives:
        print(f"\n  *** False alarms:")
        for r in false_positives:
            print(f"      {r['name']} — CE: {r['counterexample']}")

    # ── Save results ────────────────────────────────────────────────

    output = {
        "meta": {
            "tool": "substrate-guard",
            "version": "0.1.0",
            "verifier": "code",
            "total_functions": total,
            "accuracy": round(100 * correct / total, 2),
            "total_time_ms": round(total_time, 2),
            "avg_time_ms": round(total_time / total, 2),
            "true_positive_rate": round(
                len(bugs_caught) / len(bugs_expected) * 100, 2
            ) if bugs_expected else 0,
            "false_positive_rate": round(
                len(false_positives) / len(clean_expected) * 100, 2
            ) if clean_expected else 0,
        },
        "results": results,
    }

    with open("/home/claude/substrate-guard/results/code_verifier_benchmark.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Results saved to results/code_verifier_benchmark.json")
    return output


if __name__ == "__main__":
    run_benchmarks()
