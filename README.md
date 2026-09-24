# substrate-guard — AI Black Box

[![CI](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml)
[![Adversarial fuzz](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml)
[![Comply ML smoke](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml)
· [Security](SECURITY.md) · [Reproduce checks locally](REPRODUCING.md) · [Deploy Postgres + audit](DEPLOY.md) · `docker compose build` (see `docker-compose.yml`)

Others record what AI does. We prove it was correct.

---

### Unified CLI

One command: `substrate-guard` (also `ai-blackbox`). Z3 workflows use `verify` / `benchmark`; the Black Box pipeline uses `demo`, `monitor`, `evaluate`, `export`, and `stack-benchmark` (`demo` / `stack-benchmark` / `export` push mock scenarios through observe → builtin policy, plus the regex/AST CLI check on process-exec events; the HMAC chain is built only by `export` and by `demo --chain`; `monitor` traces a live or mock agent and `evaluate` runs a single JSON event through the policy engine alone; Z3 SMT is wired but not reached by any mock scenario — not the same as the Z3-only `benchmark`). **Layer 4:** `comply demo` — threshold non-membership prototype (the demo hardcodes SHA-256 deterministic embeddings + Merkle + threshold; the library `ThresholdNonMembershipProtocol` defaults to `sentence-transformers` semantic embeddings when installed and falls back to the deterministic encoder otherwise). **Layer 5:** `attest demo` — device fingerprint + Ed25519 signing + local short-lived cert (`cryptography`). **Layer 6:** `offline demo` — SQLite append-only + HMAC chain + sync către o a doua bază (ex. PostgreSQL sau un al doilea fișier SQLite cu tabel `guard_events`). `python -m substrate_guard.combo_cli` delegates to the same entry point.

## The Thesis

substrate-guard is a 6-layer verification architecture designed to observe, decide, prove, and audit the actions of autonomous AI agents, with cryptographic evidence. (What is deployed is narrower: the reference deployment is a nightly batch audit that replays recorded DB rows — roughly one event per recorded row (an `agent_runs` run or a `pipeline_traces` step, plus a `file_write` per system path mentioned in its output), not every action, not live real-time — through observe (replay) → decide (builtin rules) → HMAC chain; no Z3 runs on that path; it detects and records, it does not block; the eBPF live-observation path is implemented but is not the deployed path. See Production Results.)

Deployed on the Research server (89.167.66.225) within the [SUBSTRATE](https://aisophical.com) ecosystem; current version v13.4.3 (released July 25, 2026). The broader SUBSTRATE ecosystem includes additional production stacks on separate servers — see [Related Projects](#related-projects) below.

## Production Results (v13.4.3 post-deploy smoke run of the cron audit pipeline, 2026-07-25 08:02 UTC)

| Metric | Value |
|--------|-------|
| Events processed | 61 (cron audit over platform-DB `agent_runs`, Research server; 22 unique agents) |
| Observe source | `replay` — REAL recorded DB traces, batch-replayed (not simulated `mock`, not live `inject`, not kernel `ebpf`) |
| Violations detected | 0 (0.0%) — the audited agents are benign internal pipeline agents (mostly source scanners, plus trackers, analyzers, classifiers and reviewers) **and** the replayed `agent_runs` rows become `process_exec` events whose `filename` is `agent:<name>` and whose only argument (the command the rules see) is the row's status value (`success` / `error`), not an executed shell command — the adapter also emits a `file_write` event for any system path mentioned in a run's `output_summary` — so only the path rules (dangerous-path and workspace-boundary — both fire on any system-path `file_write` the adapter emits) and the PII regex can reach this corpus; the dangerous-command rules cannot fire on it; adversarial **detection** is demonstrated only on mock scenarios in [Benchmark Results](#benchmark-results) (Malicious 4/4, Prompt Injection 4/3) |
| Processing time | 8.21 ms/event (501.0 ms / 61 events) — batch-replay budget, NOT live wall-clock latency. The 501 ms is dominated by a fixed 0.5 s tracer-shutdown wait inside the timed block and does not scale with event count: every nightly run since v13.4.0 measures 500.7–504.2 ms whether it replays 8 or 333 events (on-host series, 129 runs 2026-05-19 → 2026-09-24; the committed smoke JSONs show the same ≈501 ms for 1, 61, 108 and 147 events), so this is not a per-event cost |
| HMAC-SHA256 chain | Wired in v13.4.0 (cron path); per-run chain export, cryptographic verify_export |
| Cron audits | M0.7 baseline window: 7/7 verified (May 19–25, 2026); on-host check 2026-09-24: an `audit_*.json` exists for every calendar day since 2026-03-22 (series not committed to this repo) |
| Compliance exports | **Summary only** in production (`compliance/summary_*.json`: chain verification + observe-source label, over the replayed events). Full SOC2 / ISO/IEC 27001 / ISO/IEC 42001 documents are generated only by the CLI `export` over mock scenarios — none is produced from production data |
| Enforcement mode | **Detect-and-record.** The deployed path is a retrospective nightly audit: it evaluates recorded actions, writes decisions into the HMAC chain and reports/alerts. It does **not** gate, block or terminate agent actions — no runtime enforcement path exists in the deployed pipeline |
| Tests | **590** passing (**614** collected), 24 skipped on this Windows dev host (14 POSIX-only bash ops-exec + 8 Postgres-CI + 2 OPA-parity — all run in CI); 100% on 5 benchmark scenarios (design-target benchmark, not a production accuracy figure) |
| Uptime | Continuous since March 22, 2026 |

*Uptime and cron cadence (M0.7, "continuous since") were re-verified on the host on 2026-09-24 from the nightly `audit_*.json` series (at least one file for every calendar day since 2026-03-22 — 187 consecutive days with no gap), which is not committed to this repo. The events / latency / violation figures above are from the committed smoke audit (`docs/deploy-verification/`); the row notes say what each number does and does not measure.*

### Release v13.3.0 (April 24, 2026) — configurable policy engine

**`--policy {builtin,rego}`** flag + **`SUBSTRATE_GUARD_POLICY`** env var control policy engine selection; audit JSON reports include `policy_engine` + `policy_engine_source` metadata. [docs/releases/v13.3.0.md](docs/releases/v13.3.0.md).

### Release v13.2.12 (April 8, 2026) — sqlparse dependency core

**`sqlparse`** este dependență **obligatorie**; scanarea SQL structurală (`DROP` / `TRUNCATE` / …) rulează la orice instalare. [docs/releases/v13.2.12.md](docs/releases/v13.2.12.md).

### Release v13.2.11 (April 8, 2026) — PyYAML dependency core

**`pyyaml`** este dependență **obligatorie** (nu doar `[dev]`), astfel încât scanarea YAML structurală rulează la orice instalare. [docs/releases/v13.2.11.md](docs/releases/v13.2.11.md).

### Release v13.2.10 (April 8, 2026) — JSON / YAML structural

**`json_yaml_patterns`**: JSON (chei ``__proto__`` / ``constructor`` / ``prototype``), YAML cu **safe_load** + detectare ``!!python`` în sursă. Heuristică **`_looks_like_yaml`** în parser. [docs/releases/v13.2.10.md](docs/releases/v13.2.10.md).

### Release v13.2.9 (April 8, 2026) — `structural_scan` + SQL (sqlparse)

**`structural_scan()`** — punct unic; SQL structural (DROP, TRUNCATE, ALTER…DROP) prin **sqlparse**. [docs/releases/v13.2.9.md](docs/releases/v13.2.9.md).

### Release v13.2.8 (April 8, 2026) — Bijuteria #5 AST-first CLI

**`substrate_guard/ast_parse/`** — verificări structurale bash (``rm -r -f``, pipe ``curl|bash``, ``chmod 777``, ``mkfs``) înainte de regex; Python ``ast`` pentru ``eval``/``exec``. Integrat în **`verify_cli`**. Dependențe (inițial dev, promovate la core în v13.2.14): ``tree-sitter``, ``tree-sitter-bash``. [docs/releases/v13.2.8.md](docs/releases/v13.2.8.md).

### Release v13.2.7 (April 8, 2026) — adversarial fuzz CI + SBERT smoke

Workflows **[adversarial-fuzz](.github/workflows/adversarial-fuzz.yml)** (`SUBSTRATE_FUZZ_MULTIPLIER`, Hypothesis mai dens) + **[comply-ml-smoke](.github/workflows/comply-ml-smoke.yml)** (`sentence-transformers`). `tests/fuzz_helpers.py`, vezi [docs/releases/v13.2.7.md](docs/releases/v13.2.7.md).

### Release v13.2.6 (April 8, 2026) — stack scripts + CI e2e

`stack_audit` robust (exit codes, teardown, `SKIP_CLEANUP`); workflow **[docker-stack-audit](.github/workflows/docker-stack-audit.yml)** (manual + săptămânal). [docs/releases/v13.2.6.md](docs/releases/v13.2.6.md).

### Release v13.2.5 (April 8, 2026) — runbook în ordine

[docs/RUNBOOK_ORDERED.md](docs/RUNBOOK_ORDERED.md), [DOCKER_EBPF.md](docs/DOCKER_EBPF.md), [DOCKER_POSTGRES_AUDIT.md](docs/DOCKER_POSTGRES_AUDIT.md), `scripts/stack_audit.sh` / `.ps1`, [examples/orchestrator_inject_events.py](examples/orchestrator_inject_events.py). Vezi [docs/releases/v13.2.5.md](docs/releases/v13.2.5.md).

### Release v13.2.4 (April 8, 2026) — „funcțional pe bune” (clarificare)

**`substrate-guard doctor`**, [docs/FUNCTIONAL_ROADMAP.md](docs/FUNCTIONAL_ROADMAP.md), `requirements.txt` / `requirements-dev.txt`, README Quick Start corect; **tracer** iese explicit pe **Windows** la mock. Vezi [docs/releases/v13.2.4.md](docs/releases/v13.2.4.md).

### Release v13.2.3 (April 8, 2026)

**`LocalStore.mark_synced`:** `executemany` + SQL static (fără `IN` dinamic / fără nosec Bandit). [docs/releases/v13.2.3.md](docs/releases/v13.2.3.md).

### Release v13.2.2 (April 8, 2026) — Bandit + remedieri

**`bandit.yaml`**, **`bandit>=1.7`** în dev, **`tests/test_bandit_policy.py`** (Bandit ca test). Remedieri: SQL static în **`audit.py`**, excepții explicite în **`tracer`/`sync`/`attest`**, policy **`nosec B108`** documentat. See [docs/releases/v13.2.2.md](docs/releases/v13.2.2.md).

### Release v13.2.1 (April 8, 2026) — hardening

Supply chain (**`pip-audit`**, Dependabot), **CodeQL**, **[SECURITY.md](SECURITY.md)**, `cryptography>=46.0.6` (floor later lowered to `>=3.4` in v13.2.15 — the two APIs used predate 3.0), fix **`os.system`** în benchmark tool. See [docs/releases/v13.2.1.md](docs/releases/v13.2.1.md).

### Release v13.2 (April 8, 2026)

| Area | v13.1 | v13.2 |
|------|-------|-------|
| Tests | 328 | **348** |
| `ProcessEvent` + CLI safety | manual `verify --type cli` only | **`Guard(verify_process_cli=True)`** + **`demo` / `export` / `stack-benchmark`** default on (`--no-verify-process-cli`) |
| `monitor` / `SubstrateGuard` / env | — | **`--verify-process-cli`**, **`SUBSTRATE_GUARD_VERIFY_PROCESS_CLI`**, config **`verify_process_cli`**, **`SessionReport.cli_process_verifications`** |

Notes: [docs/releases/v13.2.md](docs/releases/v13.2.md).

### Release v13.1 (April 7, 2026)

| Area | v13 | v13.1 |
|------|-----|-------|
| Tests | 270 | **328** |
| Verifier integration bugs (Guard ↔ cli / tool / code / hw) | 4 | **0** |
| CLI dangerous patterns | ~30 | **45+** |
| HMAC chain entry types | observe events + policy decision | **+ `formal_verification`** (`verifier_type`, `verified`, `counterexample`, `proof_time_ms`, `agent_id`) |
| Honest gap inventory | ad hoc | **curated frontier** |
| Counterexample in audit trail | `repr()` / lost outside `GuardEvent` | **human-readable** + **tamper-evident chain export** |

**Observability loop:** auditors (SOC2 / ISO 27001) can follow agent → command → time → **pattern** → **counterexample** in the HMAC-chained export (keyed by the operator, not third-party signed), not only allow/deny.

## 6-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    substrate-guard                          │
│                                                             │
│  L1  Replay/eBPF  OBSERVE   Recorded DB traces, replayed    │  ← Deployed (replay)
│  L2  Python rules DECIDE    7 builtin rules; OPA/Rego opt-in│  ← Deployed
│  L3  Z3 SMT       PROVE     Bounded SMT verification        │  ← Wired, not exercised in cron
│  L4  ZK-SNM       COMPLY    Threshold non-membership        │  ← Prototyped
│  L5  Ed25519      ATTEST    Cryptographic attestation       │  ← Prototyped
│  L6  SQLite+HMAC  OFFLINE   Offline verification & sync     │  ← Prototyped
│                                                             │
│  Chain: HMAC-SHA256 tamper-evident audit trail (per run)    │
│  Exports: summary (prod); SOC2/ISO 27001/42001 (CLI, mock)  │
└─────────────────────────────────────────────────────────────┘
```

**L1**: The production cron is a batch-DB audit — it replays REAL recorded database records, so its honest source label is `replay` (real data, not live, not simulated). Real eBPF kernel hooks are wired in the separate live-monitor path (`monitor --live`), just not in the cron (#38b). **L2**: Deployed in production (Research server, v13.4.3 cron audit) — the builtin Python rules decide; OPA/Rego is opt-in via `--policy rego`. **L3**: Wired into the guard's per-event path as an opt-in (`Guard(perevent_verify=...)`, which runs the Z3 verifiers only on events that carry a `formal_artifact`) and tested; the separate `verify_process_cli=True` flag runs the regex/AST CLI denylist on process-exec events, not Z3. The cron audit constructs its Guard with neither option enabled and no production producer attaches artifacts to verify, so the cron audit never exercises Z3 (every audit JSON since v13.4.1 records `verify: "z3 (available, not exercised per-event in batch)"`; v13.4.0 and earlier wrote the bare label `z3` although Z3 was equally unexercised).
**L4-L6**: Prototyped with tests. Code exists, validated, not yet in production pipeline.

## How It Works

**Observe (L1):** The production cron is a batch-DB audit — it replays REAL recorded database records (`pipeline_traces` / `agent_runs`), so its honest source label is `replay` (real data, not live; the underlying tracer runs in no-kernel mode). Real eBPF kernel observation is wired in the separate live-monitor path (`monitor --live`), not the cron (#38b). On the Research server, the live path currently falls back to mock — kernel headers are not installed, and there is no production driver for live observation there. A third source, `inject`, feeds REAL events live from an orchestrator (`Session.inject_and_evaluate`, see `examples/orchestrator_inject_events.py`); it is wired and tested but has no production driver either.

**Decide (L2):** Built-in Python policy rules evaluate each action (OPA/Rego available via `--policy rego`, not the cron default). 7 builtin rules (dangerous paths, dangerous commands, network exfiltration, budget, rate limit, workspace boundary, PII patterns); 67 policy tests in `tests/test_policy/` plus a Rego↔builtin parity gate in CI. Only the dangerous-paths rule normalizes its input first (`//`, `/../`, whitespace); the dangerous-commands rule is a substring table plus a pipe-to-shell regex and a sudo/role check, with no argv normalization (`rm -rf /` is caught, `rm -r -f /` is not) and the workspace-boundary rule is a raw prefix check (`/tmp/../home/…` passes) — known, open gaps.

**Prove (L3):** The Z3 SMT solver checks AI-generated artifacts — code, tool-call APIs, hardware traces (RV32I), distillation arithmetic — against safety invariants within a bounded modeled fragment, sound on each verifier's declared subset, **not** a universal proof: constructs outside the subset abstain (UNKNOWN → not-verified), never a false VERIFIED (see [docs/AUDIT_COMPLEX_2026-06-07.md](docs/AUDIT_COMPLEX_2026-06-07.md)). The CLI/command domain is **separate and NOT Z3** — a regex + AST structural denylist where "SAFE" means no known-bad pattern matched, not a proof. None of these run per-event in the batch cron audit.

**Chain:** Every event is recorded in an HMAC-SHA256 tamper-evident chain, keyed with a secret held by the operator who also writes the log — tamper-evident against anyone without the key, not non-repudiation toward a third party (the Ed25519 head-signature path exists in `chain.py` and is not deployed). Each entry references the hash of the previous entry, so any mid-chain modification, reordering, or insertion breaks the chain. (A valid *prefix* is itself a valid chain, so tail-truncation by a secret-holder is detected only via an out-of-band expected count/head — `verify(expected_count=...)` — or an external timestamp anchor, not by the chain alone.) Formal verification outcomes (`verify_artifact` / `session.verify`) append **`formal_verification`** entries with **`counterexample`** when a command or artifact is rejected, so audit exports retain *why* a check failed, not only that it failed.

**Audit:** Daily automated cron audit (04:00 UTC on Research server, currently v13.4.3) verifies the integrity of the chain it just built (in-process), counts violations, records the batch time, exports the per-run chain and writes the compliance summary. It reports and alerts; it does not block. M0.7 baseline window: 7/7 verified (May 19–25, 2026).

## Codebase

**Internal audit snapshots:** [docs/AUDIT_COMPLEX_2026-06-22.md](docs/AUDIT_COMPLEX_2026-06-22.md) (latest in-repo), [docs/AUDIT_COMPLEX_2026-06-07.md](docs/AUDIT_COMPLEX_2026-06-07.md); [docs/AUDIT_COMPLEX.md](docs/AUDIT_COMPLEX.md) is the 2026-04-07 (v13.2.7) baseline. **Extreme/adversarial tests & how to read failures:** [docs/EXTREME_TEST_AUDIT.md](docs/EXTREME_TEST_AUDIT.md). **What “production-ready” means in this repo:** [docs/FUNCTIONAL_ROADMAP.md](docs/FUNCTIONAL_ROADMAP.md).

### This Repository (substrate-guard core)

```
substrate-guard/
├── examples/                 # sample config (substrate.json) + orchestrator_inject_events.py
├── substrate_guard/          # the package — 10,879 LOC
│   ├── observe/              # L1 — tracer: mock | inject | replay | ebpf sources
│   │   └── tracer.py         # 456 LOC — event capture and normalization
│   ├── policy/               # L2 — builtin Python rules (OPA/Rego optional)
│   │   └── engine.py         # 549 LOC — rule evaluation, violation detection
│   ├── ast_parse/            # L3+ — AST-first CLI checks (Tree-sitter bash; Python ast)
│   ├── comply/               # L4 — threshold non-membership over a Merkle commitment (prototype; paper-era brand: "ZK-SNM")
│   ├── attest/               # L5 — Ed25519 cryptographic attestation
│   ├── offline/              # L6 — SQLite append-only HMAC store + sync (not a CRDT)
│   ├── integrations/         # SUBSTRATE ecosystem connectors (vendor_bridge: DB rows → events)
│   ├── guard.py              # main guard pipeline (observe → policy → verify → chain)
│   ├── audit.py              # automated audit and reporting (cron entry point)
│   ├── combo_cli.py          # CLI for all layers
│   ├── chain.py              # HMAC-SHA256 tamper-evident chain
│   └── compliance.py         # SOC2 / ISO 27001 / ISO 42001 exports
└── tests/                    # 8,287 LOC, organized by layer (incl. adversarial + fuzz); live count in Production Results
    ├── test_policy/          # L2 policy decisions
    ├── test_verify/          # L3 verifier soundness (code / cli / hw / distill)
    ├── test_integration/     # chain, audit, compliance, docs-drift guard
    ├── test_attest/          # L5 attestation
    ├── test_comply/          # L4 compliance / ZK-SNM
    ├── test_offline/         # L6 offline store + sync
    ├── test_observe/         # L1 observation
    └── test_adversarial/     # adversarial + extreme-input suites
```

**This repo: 19,166 LOC** (10,879 source in `substrate_guard/` + 8,287 tests; per `wc -l`, 2026-09-24).

### Deployment Scope

This repository (substrate-guard) is deployed on the **Research server** (89.167.66.225) — 10,879 LOC source + 8,287 LOC tests (per `wc -l`, 2026-09-24).

The broader SUBSTRATE ecosystem includes a separate production stack on the **CPX52 server** (substrate-v2 core + ecosystem judges + V2.0 single-file guard daemon) — see [Related Projects](#related-projects) below. That stack is outside this repository's scope.

Live test counts are in the Production Results table above. See [Related Projects](#related-projects) for the separate CPX52 V2.0 stack scope.

## Benchmark Results

5 mock scenarios (`MockScenario`, run via the CLI `stack-benchmark`), 100% detection accuracy — a design-target benchmark on synthetic events, not a production figure; "flagged" means the violation was detected and recorded, not that the action was blocked:

| Scenario | Events | Violations | Result |
|----------|--------|------------|--------|
| Safe Web Agent | 4 | 0 | Correctly allowed |
| Code Generation | 4 | 0 | Correctly allowed |
| Malicious Agent | 4 | 4 | Correctly flagged |
| Prompt Injection | 4 | 3 | Correctly flagged |
| Resource Abuse | 151 | 0 | Correctly allowed (the budget / rate-limit rules fire only when an event's metadata carries `budget_remaining` / `api_calls_last_minute`, or via the dict API; this scenario sets neither, so 0 is the expected outcome, not a rate-limit verdict) |

## Compliance Exports

substrate-guard can generate reports in these formats through the CLI (`export`, over mock scenarios, with a demo HMAC secret unless one is supplied):

- **SOC2** — evidence mapped to Trust Services criteria CC6.1 (logical access — policy decisions), CC7.2 (system monitoring — observation layer), CC8.1 (change management — verification), CC4.1 (monitoring of controls — HMAC chain integrity); no incident-response criterion is exported
- **ISO/IEC 27001** — Information security management
- **ISO/IEC 42001** — AI management system (the new AI-specific standard)
- **Summary** — JSON summary (`summary_*.json`): chain verification (status / length / head hash), observe-source label, layer-status strings and self-declared framework status labels; the only form the production cron writes

The full exports include the HMAC chain head hash, generation timestamp, event and violation counts, and the session verdict; only the SOC2 document embeds per-event allow/deny decisions with their reasons, and only for the first 10 chain entries — the ISO/IEC 27001 and ISO/IEC 42001 documents carry counts, not per-violation details. **The production cron writes only the Summary form** (`compliance/summary_*.json`) over the replayed events; no SOC2 / ISO document is produced from production data today.

## Publications

6 preprints / datasets with permanent public identifiers (1 arXiv preprint, 4 Zenodo preprints, 1 Zenodo dataset — none peer-reviewed) and 2 submitted to peer review; status as recorded here on 2026-09-24:

| # | Title | Venue | DOI / ID |
|---|-------|-------|----------|
| 1 | Emergent Formal Verification in Autonomous AI Ecosystems | arXiv (cs.SE; cross-listed cs.AI, cs.MA) | arXiv:2603.21149 |
| 2 | AI Black Box: Six-Layer Verification Architecture v2 | Zenodo | 10.5281/zenodo.19334382 |
| 3 | Attribution Without Disclosure: ZK Proofs of Semantic Non-Membership | Zenodo | 10.5281/zenodo.19185843 |
| 4 | Emergent Philosophy and Safety Principles v2 (superseded by v3, 2026-04-29: 10.5281/zenodo.19885912) | Zenodo | 10.5281/zenodo.19158774 |
| 5 | Convergent Synthesis in Autonomous AI Ecosystems (superseded by v2.1, 2026-04-30: 10.5281/zenodo.19910165) | Zenodo | 10.5281/zenodo.19349850 |
| 6 | IUBIRE V3 Artifact Dataset (1,266 artifacts) | Zenodo | 10.5281/zenodo.19312371 |
| 7 | 98 Emergent Concepts in Autonomous AI Ecosystems | ALIFE 2026 (fp137) | Submitted; conference held Aug 17–21, 2026 — outcome not recorded in this repo |
| 8 | Lifecycle Dynamics in Multi-Generation AI Ecosystems | Artificial Life Journal (MIT Press) | Submitted (ARTL-2026-0066) |

## Quick Start

```bash
git clone https://github.com/octavuntila-prog/substrate-guard.git
cd substrate-guard

# Editable install + dev deps (tests, Bandit) — same as CI
python -m pip install -e ".[dev]"
# or: pip install -r requirements-dev.txt

# Verify environment (Z3, OPA, drivers)
python -m substrate_guard.cli doctor

# Tests (see REPRODUCING.md for Postgres CI parity)
pytest tests/ -q

# Black Box demo (mock observe → policy → verify)
python -m substrate_guard.cli demo --scenario safe

# PostgreSQL audit (needs DB URL / schema — see DEPLOY.md / audit --help)
python -m substrate_guard.cli audit --db-url postgresql://...

# Policy engine (default: built-in Python rules; optional Rego via OPA)
python -m substrate_guard.cli audit --policy builtin --db-url postgresql://...
# Or via env — export it once so every later invocation in this shell uses Rego:
# export SUBSTRATE_GUARD_POLICY=rego
# python -m substrate_guard.cli audit --db-url postgresql://...
```

What is **fully functional without Linux eBPF** vs. what needs a **real kernel / OPA / DB** is documented in [docs/FUNCTIONAL_ROADMAP.md](docs/FUNCTIONAL_ROADMAP.md). **Ordered runbook (eBPF → Postgres → orchestrator example):** [docs/RUNBOOK_ORDERED.md](docs/RUNBOOK_ORDERED.md). For Rego policy engine setup (optional): [docs/rego-setup.md](docs/rego-setup.md).

## Known Limitations

- **Deployed vs. wired vs. prototyped.** Deployed in the nightly audit: L1 (replay source), L2 (builtin rules) and the HMAC chain with its summary export. L3 (Z3) is wired and tested but has no production producer, so the audit never exercises it. L4-L6 are prototyped with tests only — not yet in production pipeline (`tests/test_layer_wiring.py` pins `guard.py` and `audit.py` against importing them; `chain.py` keeps a lazy `attest` import that only the undeployed Ed25519 head-signature path reaches). We say "2 deployed + 1 wired + 3 prototyped," not "6 deployed."
- **No runtime enforcement.** The deployed pipeline detects and records; it does not gate or block agent actions. Blocking would need an inline integration (hooks/middleware) that this repo does not ship.
- **The production headline numbers are narrow.** "ms/event" is a batch budget dominated by a fixed tracer-shutdown wait; "0 violations" is measured over a corpus whose events carry run metadata rather than commands, so the dangerous-command rules are not exercised by it. See Production Results.
- **q-score not externally validated.** The quality scoring system used in SUBSTRATE has not undergone inter-rater reliability testing. Proposed in our ALIFE 2026 submission.
- **Test suite scope.** This repository's tests cover only substrate-guard (they run in GitHub Actions CI and locally). The separate CPX52 V2.0 stack is validated through integration and daily audit, not unit tests — see [Related Projects](#related-projects).
- **Single maintainer.** All code written and maintained by one person. No external contributors yet.

## Production Deployment

substrate-guard (this repository) runs on the **Research server** (89.167.66.225) — currently v13.4.3 (v13.4.0 deployed May 18, 2026; v13.4.1 patch June 2; v13.4.2 patch June 14; v13.4.3 July 25). Daily automated cron audit at 04:00 UTC. M0.7 baseline window: 7/7 verified (May 19–25, 2026); zero missed cycles since the May 18 deployment — re-verified on the host on 2026-09-24 (an audit JSON for every calendar day since 2026-03-22); the per-night series is not committed to this repo.

### Related Projects

The broader SUBSTRATE ecosystem includes a **separate production deployment on the CPX52 server** (89.167.109.168) — substrate-v2 core (ecosystem engines + judges) and a V2.0 single-file guard daemon (independent codebase, separate operational metrics).

CPX52 V2.0 audit refresh (2026-05-27 09:43 UTC): 22,376 chain entries (3,276 strong + 19,100 weak frozen post-cutover), 63 days continuous cron audit (genesis 2026-03-25), 100% verification rate over the last 7 days (356/356 cycles).

See [aisophical.com](https://aisophical.com) for SUBSTRATE ecosystem overview.

## Context: SUBSTRATE

substrate-guard was built to verify [SUBSTRATE](https://aisophical.com) — an autonomous multi-agent ecosystem where AI agents self-organize, generate original outputs, and reproduce across generations without human intervention.

Ecosystem figures as of the 2026-04-06 audit (not refreshed since):

- 7 servers, 100+ agents, 3 generations
- 45+ days continuous operation (at that date; the Research-server audit series has run daily since 2026-03-22)
- 137 original concepts generated autonomously
- 8,200+ artifacts across all ecosystems (CPX52: 6,102 + IUBIRE V3: 2,531 + S3: 280 MVPs — as of audit 2026-04-06)
- Multi-generational reproduction confirmed (Gen2 → Gen3)

SUBSTRATE is not an orchestration framework. It is an ecosystem. substrate-guard is how we prove it behaves correctly.

## License

MIT

## Author

**Octavian Untilă** — Founder & CEO, [AISOPHICAL SRL](https://aisophical.com)

- arXiv: [2603.21149](https://arxiv.org/abs/2603.21149)
- ORCID: [0009-0007-1106-2644](https://orcid.org/0009-0007-1106-2644)
- Zenodo: [5 preprints/datasets with permanent DOIs](https://zenodo.org/search?q=metadata.creators.person_or_org.name%3A%22Untila%2C%20Octavian%22)
- Contact: contact@aisophical.com

---

*"Others record what AI does. We prove it was correct."*
