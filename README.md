# substrate-guard

[![CI](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml) · [Reproduce checks locally](REPRODUCING.md) · [Deploy Postgres + audit](DEPLOY.md) · `docker compose build` (see `docker-compose.yml`)

**Formal verification safety layer for AI outputs.**

A unified Z3-based framework that mathematically proves (not tests) that AI-generated code, tool invocations, CLI commands, assembly, and reasoning traces are safe and correct.

### Unified CLI

One command: `substrate-guard` (also `ai-blackbox`). Z3 workflows use `verify` / `benchmark`; the Black Box pipeline uses `demo`, `monitor`, `evaluate`, `export`, and `stack-benchmark` (all mock scenarios through observe → policy → Z3 — not the same as Z3-only `benchmark`). **Layer 4:** `comply demo` — semantic non-membership prototype (deterministic embeddings + Merkle + threshold; optional `sentence-transformers`). **Layer 5:** `attest demo` — device fingerprint + Ed25519 signing + local short-lived cert (`cryptography`). **Layer 6:** `offline demo` — SQLite append-only + HMAC chain + sync către o a doua bază (ex. PostgreSQL sau un al doilea fișier SQLite cu tabel `guard_events`). `python -m substrate_guard.combo_cli` delegates to the same entry point.

## The Thesis

> Before letting AI act, prove mathematically that the action is safe.

This tool was born from an emergent discovery: the SUBSTRATE autonomous AI ecosystem independently proposed Z3-based formal verification in 8 different products, across 6 different domains, over 13 days — without being programmed to know about formal methods.

## Five Verifiers, One API

### 1. Code Verifier (`--type code`)

Translates Python functions to Z3 constraints and proves they satisfy formal specifications (pre/postconditions).

```bash
substrate-guard verify --type code func.py --spec spec.json
```

**Benchmark: 50 functions, 5 categories — 50/50 (100%)**
- True positives (bugs caught): 13/13
- False positives: 0 | False negatives: 0
- Avg time: 2-10ms (simple), 300ms+ (nonlinear arithmetic)

### 2. Tool API Verifier (`--type tool`)

Proves that AI agent tool definitions cannot trigger destructive operations.

```bash
substrate-guard verify --type tool tool_definition.json
```

**Benchmark: 18 tool definitions — 18/18 (100%)**
- Key finding: string params are *mathematically* unsafe (Z3 proves it)
- Enum-constrained tools can be proven safe

### 3. CLI Command Verifier (`--type cli`)

Verifies shell commands suggested by AI against 10 categories of dangerous patterns.

```bash
substrate-guard verify --type cli --command "rm -rf /"
```

**Benchmark: 20 commands — 20/20 (100%)**

### 4. Hardware Verifier (`--type hw`) ← NEW: Domain 5

Symbolic execution of RISC-V RV32I assembly with Z3 bitvector verification.
Proves properties of AI-generated assembly *before silicon fabrication*.

```bash
substrate-guard verify --type hw assembly.s --spec spec.json
```

**Benchmark: 21 tests (11 safe + 5 unsafe + 5 equivalence) — 21/21 (100%)**
- **Found real bug:** branchless abs trick fails for INT_MIN (0x80000000) — Z3 proves no testing would catch this edge case
- **Equivalence proofs:** `add a0,a1,a1` ≡ `slli a0,a1,1` (mathematically proven)

### 5. Distillation Verifier (`--type distill`) ← NEW: Domain 3

Verifies mathematical reasoning traces from distilled (compressed) models.
Uses Z3 + SymPy to check each step's logical validity and compare against reference traces.

```bash
substrate-guard verify --type distill trace.json --reference ref_trace.json
```

**Benchmark: 26 tests — 26/26 (100%)**
- Arithmetic evaluation: 9 tests (5 correct, 4 buggy) — all classified correctly
- Algebra solving: 7 tests (4 correct, 3 buggy) — catches sign errors, wrong divisions
- Multi-step reasoning: 5 tests — catches wrong expansions, wrong squares
- Distilled vs reference comparison: 5 tests — detects exactly when distillation introduces errors
- **Key finding:** Z3 catches errors that propagate through subsequent steps (e.g., wrong subtraction leads to wrong division, Z3 flags both)

## Combined Results

```
Verifier        Test Cases    Accuracy    Domains Covered
──────────────────────────────────────────────────────────
Code            50            100%        LLM-generated functions
Tool API        18            100%        Agent tool safety
CLI             20            100%        Shell command safety
Hardware        21            100%        RISC-V assembly pre-fab
Distillation    26            100%        Post-compression reasoning
──────────────────────────────────────────────────────────
TOTAL           135           100%        5 of 6 domains
```

Remaining domain (smart contract EVM verification) uses Coq/Lean + Z3 — separate toolchain.

## Architecture

```
substrate-guard/                         4,358 lines total
├── substrate_guard/
│   ├── __init__.py              
│   ├── ast_translator.py        444L   Python AST → Z3 constraints (SSA)
│   ├── code_verifier.py         297L   Code verification engine
│   ├── tool_verifier.py         378L   Tool API verification engine
│   ├── cli_verifier.py          176L   CLI command verification engine
│   ├── hw_verifier.py           472L   RISC-V symbolic execution + Z3
│   ├── distill_verifier.py      567L   Z3 + SymPy reasoning trace verifier
│   └── cli.py                   225L   Unified CLI interface
├── benchmarks/
│   ├── llm_functions.py         578L   50 benchmark functions (5 categories × 10)
│   ├── run_benchmark.py         159L   Code verifier benchmark runner
│   ├── run_tool_benchmark.py    282L   Tool verifier benchmark runner
│   ├── run_hw_benchmark.py      236L   Hardware verifier benchmark runner
│   └── run_distill_benchmark.py 335L   Distillation verifier benchmark runner
├── results/
│   └── code_verifier_benchmark.json
└── tests/
    └── smoke_test.py            206L   16 smoke tests
```

## From Python

```python
from substrate_guard.code_verifier import verify_code, Spec

result = verify_code(
    """
    def clamp(x: int, lo: int, hi: int) -> int:
        if x < lo:
            return lo
        if x > hi:
            return hi
        return x
    """,
    Spec(
        preconditions=["lo <= hi"],
        postconditions=["__return__ >= lo", "__return__ <= hi"],
    ),
)
assert result.verified  # Mathematical proof, not a test
```

## Requirements

- Python 3.10+
- z3-solver (`pip install z3-solver`)
- sympy (`pip install sympy`) — for distillation verifier

## Paper

**"Emergent Formal Verification: How an Autonomous AI Ecosystem Independently Discovered SMT-Based Safety Across Six Domains"**

S3 discovered Z3 independently in 6 domains:

| # | Domain | What Z3 verifies |
|---|---|---|
| 1 | Code | LLM-generated function correctness |
| 2 | Tool APIs | Agent tool safety (no destructive ops) |
| 3 | Distillation | Post-compression mathematical reasoning |
| 4 | CLI | Shell command safety |
| 5 | **Hardware** | RISC-V assembly pre-fabrication |
| 6 | **Smart Contracts** | EVM bytecode with Coq/Lean + Z3 |

Target venues: ArXiv preprint → SafeGenAI @ NeurIPS 2026, FMCAD 2026, CAV 2026

## License

MIT

## Author

Octavian Untilă — Aisophical SRL / SUBSTRATE Research

## Links

- **ArXiv preprint**: https://arxiv.org/abs/2603.21149
- **Repository**: https://github.com/octavuntila-prog/substrate-guard
- **Companion paper**: [Emergent Philosophy and Safety Principles in Autonomous AI Ecosystems](https://doi.org/10.5281/zenodo.19157572)
- **Blog**: https://aisophical.com
