# L3 — per-event formal verification (selective / sampled / budget-bounded; async opt-in)

Three verifiers (`code` / `hw` / `distill`) are Z3/SMT; `tool` is a typed-schema checker
(exhaustive instantiation of enum / bool / bounded-int parameters + literal forbidden lists
+ the L2 CLI denylist; Z3 only for unbounded integer parameters or finite domains above the enumeration cap). All four are **sound on a bounded
fragment** (integer/linear arithmetic, straight-line RISC-V, literal containment over typed
schemas, step-arithmetic — no loops/recursion; a free-string parameter is UNSAFE by
construction against every literal pattern, with a witness — matcher-only pattern sets
abstain (`unchecked`); a regex-constrained string is UNSAFE when a keyword satisfies its
regex and abstains (`pattern_unsupported`) otherwise). Their soundness is pinned by
`tests/test_verify/`. Until now they only ran **on-demand per artifact** (`Guard.verify_artifact`),
never on live events. This is the design for running them per-event **honestly** — the
opposite of "Z3 on every event", which is neither feasible (Z3 is slow) nor sound
(most events carry nothing a bounded SMT fragment can prove).

## Verdict taxonomy (4-way, not a bool)

The guard layer used to collapse every verifier to `verified: bool`, hiding *why*. The
per-event path preserves a 4-way verdict:

| Verdict    | Meaning                                                        | `verified` |
|------------|---------------------------------------------------------------|-----------|
| `VERIFIED` | proof holds **on the bounded fragment** (nothing dropped)     | true      |
| `REFUTED`  | a concrete counterexample was found (the artifact is unsafe)  | false     |
| `ABSTAIN`  | out-of-domain / unsupported construct — **not proven, not refuted** | false |
| `TIMEOUT`  | the verifier hit the per-artifact budget (tool: reason `timeout`; Z3 verifiers: ≥85 % of the budget consumed) | false |

`ABSTAIN` is the honest default for anything the fragment can't model — the verifiers
already return `UNKNOWN`/`UNCHECKED`/`PARSE_ERROR` there and **never** a false
`VERIFIED`. `TIMEOUT` is `ABSTAIN` that specifically hit the time budget (distinguished
so operators can see budget pressure vs genuine out-of-domain). Both are fail-safe:
`verified = false`, so an unverifiable artifact is **not trusted**.

## Selection — verify only what carries a provable artifact

An event is a verification candidate **only** if it carries a structured artifact:
`event.metadata["formal_artifact"] = {"type": "code|tool|hw|distill", "artifact": <str>,
"spec": <optional>}`. Everything else (a bare file write, a network connect) has nothing
a bounded SMT fragment proves — it is handled by L2 policy, not L3. So the selection
rate is naturally tiny: only artifact-bearing events, and only the enabled types.

**Depends on L1-real.** The cron `replay` path (batch DB-replay of recorded traces)
carries no structured artifacts; the orchestrator **inject** path (L1 `source="inject"`) is where an agent's generated
code / tool-spec actually arrives. So per-event verify is exercised on the inject path.

## Sampling — deterministic, budget-bounded

Under high artifact volume, verify a fraction. Sampling is **deterministic** on the
artifact hash (`sha256(artifact) % 1000 < rate*1000`), so it is reproducible and
auditable — the same artifact is always sampled the same way, no RNG. `sample_rate=1.0`
verifies every candidate (the default; sampling is for scale).

## Latency budget — a small per-artifact budget

Each verifier accepts `timeout_ms`. For `code` / `hw` / `distill` it is the Z3 solver
timeout (`solver.set("timeout", ...)`); for `tool` it is a wall-clock deadline over the
exhaustive instantiation and the CLI matcher (a solver runs only for unbounded ints or
over-cap domains, each query capped at a fair slice of the remaining budget). The
per-event path passes a **small** budget (default 300 ms); exceeding it yields `TIMEOUT`.
Measured (2026-10-14): a 2,000-operation tool decides in ~255–290 ms, i.e. at the edge of
the default; the matcher costs 0.09–0.23 ms per bash-/unknown-routed operation and
0.55–0.76 ms per bare SQL statement (sqlparse); the one-time imports (z3 ~85 ms, L2
denylist ~90 ms) are paid in `PerEventVerifier.__init__`, before any clock starts. This is the whole point: verification
never runs unbounded on the ingestion path.

## Execution — synchronous by default; async only via a process pool

The default (and the only currently-wired) mode is **synchronous**: `submit` runs the
verifier inline, bounded by the small per-artifact budget, so it returns in
~`timeout_ms` (plus a 15–35 ms solver overshoot on the Z3 paths). Because selection +
sampling make candidates rare, that inline cost is
small. A `ThreadPoolExecutor` is **NOT** usable — Z3 is not thread-safe and corrupts its
solver context across threads (verified by a crash during development). True async (off
the ingestion path) is opt-in via an injected `ProcessPoolExecutor` (process isolation);
`verify_one` is module-level and returns picklable primitives for exactly that.

Verdicts are collected (`drain`) and recorded into the HMAC chain as
`formal_verification` entries carrying the 4-way `verdict` (additive to the existing
`verified` bool — the chain `event_data` is free-form). In async mode a verdict that is
not ready by drain time is reported as still-pending, never silently dropped.

## What this is NOT

- NOT "Z3 proves every event" — only artifact-bearing, selected, sampled events.
- NOT a universal correctness proof — `VERIFIED` is sound **on the bounded fragment**;
  anything outside it is `ABSTAIN`, never a false `VERIFIED`.
- NOT a replacement for L2 policy — verify complements the denylist/allow decision.

See `substrate_guard/perevent_verify.py` and `tests/test_perevent_verify.py`.
