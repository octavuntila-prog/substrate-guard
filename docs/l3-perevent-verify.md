# L3 — per-event formal verification (selective / sampled / async)

The four verifiers (`code` / `tool` / `hw` / `distill`) are real Z3/SMT and **sound on
a bounded fragment** (integer/linear arithmetic, straight-line RISC-V, string-contains,
step-arithmetic — no loops/recursion/unbounded strings). Their soundness is pinned by
41 tests. Until now they only ran **on-demand per artifact** (`Guard.verify_artifact`),
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
| `TIMEOUT`  | the solver hit the per-artifact latency budget                | false     |

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

**Depends on L1-real.** The cron mock/DB-replay path carries no structured artifacts;
the orchestrator **inject** path (L1 `source="inject"`) is where an agent's generated
code / tool-spec actually arrives. So per-event verify is exercised on the inject path.

## Sampling — deterministic, budget-bounded

Under high artifact volume, verify a fraction. Sampling is **deterministic** on the
artifact hash (`sha256(artifact) % 1000 < rate*1000`), so it is reproducible and
auditable — the same artifact is always sampled the same way, no RNG. `sample_rate=1.0`
verifies every candidate (the default; sampling is for scale).

## Latency budget — a small per-artifact Z3 timeout

Each verifier already accepts `timeout_ms` and calls `solver.set("timeout", ...)`. The
per-event path passes a **small** budget (default 300 ms) so Z3 itself bounds the work
and returns fast; exceeding it yields `TIMEOUT` → `ABSTAIN`. This is the whole point:
verification never runs unbounded on the ingestion path.

## Async — never block ingestion

Candidates are submitted to a bounded `ThreadPoolExecutor`; ingestion continues while
proofs run. Verdicts are collected (`drain`) and recorded into the HMAC chain as
`formal_verification` entries carrying the 4-way `verdict` (additive to the existing
`verified` bool — the chain `event_data` is free-form). A verdict that is not ready by
drain time is reported as still-pending, never silently dropped.

## What this is NOT

- NOT "Z3 proves every event" — only artifact-bearing, selected, sampled events.
- NOT a universal correctness proof — `VERIFIED` is sound **on the bounded fragment**;
  anything outside it is `ABSTAIN`, never a false `VERIFIED`.
- NOT a replacement for L2 policy — verify complements the denylist/allow decision.

See `substrate_guard/perevent_verify.py` and `tests/test_perevent_verify.py`.
