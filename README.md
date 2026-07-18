# substrate-guard — AI Black Box

[![CI](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml)
[![Adversarial fuzz](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml)
[![Comply ML smoke](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml)
· [Security](SECURITY.md) · [Reproduce checks locally](REPRODUCING.md) · [Deploy Postgres + audit](DEPLOY.md) · `docker compose build` (see `docker-compose.yml`)

Others record what AI does. We prove it was correct.

---

### Unified CLI

One command: `substrate-guard` (also `ai-blackbox`). Z3 workflows use `verify` / `benchmark`; the Black Box pipeline uses `demo`, `monitor`, `evaluate`, `export`, and `stack-benchmark` (all mock scenarios through observe → policy → Z3 — not the same as Z3-only `benchmark`). **Layer 4:** `comply demo` — threshold non-membership prototype (deterministic embeddings + Merkle + threshold; optional `sentence-transformers` for actually-semantic embeddings). **Layer 5:** `attest demo` — device fingerprint + Ed25519 signing + local short-lived cert (`cryptography`). **Layer 6:** `offline demo` — SQLite append-only + HMAC chain + sync către o a doua bază (ex. PostgreSQL sau un al doilea fișier SQLite cu tabel `guard_events`). `python -m substrate_guard.combo_cli` delegates to the same entry point.

## The Thesis

substrate-guard is a 6-layer verification architecture that observes, decides, proves, and audits every action taken by autonomous AI agents, with cryptographic evidence. (The reference deployment runs as a nightly batch audit over recorded actions — not live real-time; the eBPF live-observation path is implemented but is not the deployed path. See Production Results.)

Deployed on the Research server (89.167.66.225) within the [SUBSTRATE](https://aisophical.com) ecosystem; current version v13.4.2 (released June 14, 2026). The broader SUBSTRATE ecosystem includes additional production stacks on separate servers — see [Related Projects](#related-projects) below.

## Production Results (v13.4.2 cron audit, 2026-06-14)

| Metric | Value |
|--------|-------|
| Events processed | 108 (cron audit over platform-DB `agent_runs`, Research server) |
| Violations detected | 0 (0.0%) — the audited agents are benign internal scanners; adversarial **detection** is demonstrated in [Benchmark Results](#benchmark-results) (Malicious 4/4, Prompt Injection 4/3) |
| Processing time | 4.64 ms/event (500.8 ms / 108 events) — batch-mock replay budget, NOT live wall-clock latency |
| HMAC-SHA256 chain | Wired in v13.4.0 (cron path); per-run chain export, cryptographic verify_export |
| Cron audits | M0.7 baseline window: 7/7 verified (May 19–25, 2026) |
| Compliance exports | SOC2, ISO/IEC 27001, ISO/IEC 42001 |
| Tests | **503** passing (**512** collected), 9 skipped (1 SBERT + 6 Postgres CI + 2 POSIX-only ops-exec); 100% on 5 benchmark scenarios (design-target benchmark, not a production accuracy figure) |
| Uptime | Continuous since March 22, 2026 |

*Uptime and cron cadence (M0.7, "continuous since") are from operator monitoring — the per-night `audit_*.json` series is not committed to this repo. The events / latency / violation figures above are from the committed smoke audit (`docs/deploy-verification/`).*

### Release v13.3.0 (April 24, 2026) — configurable policy engine

**`--policy {builtin,rego}`** flag + **`SUBSTRATE_GUARD_POLICY`** env var control policy engine selection; audit JSON reports include `policy_engine` + `policy_engine_source` metadata. [docs/releases/v13.3.0.md](docs/releases/v13.3.0.md).

### Release v13.2.12 (April 7, 2026) — sqlparse dependency core

**`sqlparse`** este dependență **obligatorie**; scanarea SQL structurală (`DROP` / `TRUNCATE` / …) rulează la orice instalare. [docs/releases/v13.2.12.md](docs/releases/v13.2.12.md).

### Release v13.2.11 (April 7, 2026) — PyYAML dependency core

**`pyyaml`** este dependență **obligatorie** (nu doar `[dev]`), astfel încât scanarea YAML structurală rulează la orice instalare. [docs/releases/v13.2.11.md](docs/releases/v13.2.11.md).

### Release v13.2.10 (April 7, 2026) — JSON / YAML structural

**`json_yaml_patterns`**: JSON (chei ``__proto__`` / ``constructor`` / ``prototype``), YAML cu **safe_load** + detectare ``!!python`` în sursă. Heuristică **`_looks_like_yaml`** în parser. [docs/releases/v13.2.10.md](docs/releases/v13.2.10.md).

### Release v13.2.9 (April 7, 2026) — `structural_scan` + SQL (sqlparse)

**`structural_scan()`** — punct unic; SQL structural (DROP, TRUNCATE, ALTER…DROP) prin **sqlparse**. [docs/releases/v13.2.9.md](docs/releases/v13.2.9.md).

### Release v13.2.8 (April 7, 2026) — Bijuteria #5 AST-first CLI

**`substrate_guard/ast_parse/`** — verificări structurale bash (``rm -r -f``, pipe ``curl|bash``, ``chmod 777``, ``mkfs``) înainte de regex; Python ``ast`` pentru ``eval``/``exec``. Integrat în **`verify_cli`**. Dependențe dev: ``tree-sitter``, ``tree-sitter-bash``. [docs/releases/v13.2.8.md](docs/releases/v13.2.8.md).

### Release v13.2.7 (April 7, 2026) — adversarial fuzz CI + SBERT smoke

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

Supply chain (**`pip-audit`**, Dependabot), **CodeQL**, **[SECURITY.md](SECURITY.md)**, `cryptography>=46.0.6`, fix **`os.system`** în benchmark tool. See [docs/releases/v13.2.1.md](docs/releases/v13.2.1.md).

### Release v13.2 (April 7, 2026)

| Area | v13.1 | v13.2 |
|------|-------|-------|
| Tests | 328 | **354** |
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

**Observability loop:** auditors (SOC2 / ISO 27001) can follow agent → command → time → **pattern** → **counterexample** in the signed chain, not only allow/deny.

## 6-Layer Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    substrate-guard                           │
│                                                             │
│  L1  eBPF         OBSERVE   Mock tracer (kernel hooks: #38b)│  ← Mock
│  L2  OPA/Rego     DECIDE    Declarative policy enforcement  │  ← Deployed
│  L3  Z3 SMT       PROVE     Bounded SMT verification        │  ← Deployed
│  L4  ZK-SNM       COMPLY    Threshold non-membership        │  ← Prototyped
│  L5  Ed25519      ATTEST    Cryptographic attestation        │  ← Prototyped
│  L6  SQLite+HMAC  OFFLINE   Offline verification & sync     │  ← Prototyped
│                                                             │
│  Chain: HMAC-SHA256 tamper-evident audit trail               │
│  Exports: SOC2 / ISO 27001 / ISO 42001                      │
└─────────────────────────────────────────────────────────────┘
```

**L1**: The production cron is a batch-DB audit — correctly mock (it replays database records; no live process to observe). Real eBPF kernel hooks are wired in the separate live-monitor path (`monitor --live`), just not in the cron (#38b). **L2-L3**: Deployed in production (Research server, v13.4.2 cron audit pipeline).
**L4-L6**: Prototyped with tests. Code exists, validated, not yet in production pipeline.

## How It Works

**Observe (L1):** The production cron is a batch-DB audit — it replays database records, so it correctly uses a mock tracer (no live process to observe). Real eBPF kernel observation is wired in the separate live-monitor path (`monitor --live`), not the cron (#38b). On the Research server, the live path currently falls back to mock — kernel headers are not installed, and there is no production driver for live observation there.

**Decide (L2):** Built-in Python policy rules evaluate each action (OPA/Rego available via `--policy rego`, not the cron default). 80 policy tests cover authorization, rate limiting, data access, and behavioral constraints.

**Prove (L3):** The Z3 SMT solver checks AI-generated artifacts — code, tool-call APIs, hardware traces (RV32I), distillation arithmetic — against safety invariants within a bounded modeled fragment, sound on each verifier's declared subset, **not** a universal proof: constructs outside the subset abstain (UNKNOWN → not-verified), never a false VERIFIED (see [docs/AUDIT_COMPLEX_2026-06-07.md](docs/AUDIT_COMPLEX_2026-06-07.md)). The CLI/command domain is **separate and NOT Z3** — a regex + AST structural denylist where "SAFE" means no known-bad pattern matched, not a proof. None of these run per-event in the batch cron audit.

**Chain:** Every event is recorded in an HMAC-SHA256 tamper-evident chain. Each entry references the hash of the previous entry, so any mid-chain modification, reordering, or insertion breaks the chain. (A valid *prefix* is itself a valid chain, so tail-truncation by a secret-holder is detected only via an out-of-band expected count/head — `verify(expected_count=...)` — or an external timestamp anchor, not by the chain alone.) Formal verification outcomes (`verify_artifact` / `session.verify`) append **`formal_verification`** entries with **`counterexample`** when a command or artifact is rejected, so audit exports retain *why* a check failed, not only that it failed.

**Audit:** Daily automated cron audit (04:00 UTC on Research server, currently v13.4.2) verifies chain integrity, counts violations, measures latency, and exports compliance reports. M0.7 baseline window: 7/7 verified (May 19–25, 2026).

## Codebase

**Internal audit snapshot:** [docs/AUDIT_COMPLEX.md](docs/AUDIT_COMPLEX.md) (inventory tests, layers, gaps). **Extreme/adversarial tests & how to read failures:** [docs/EXTREME_TEST_AUDIT.md](docs/EXTREME_TEST_AUDIT.md). **What “production-ready” means in this repo:** [docs/FUNCTIONAL_ROADMAP.md](docs/FUNCTIONAL_ROADMAP.md).

### This Repository (substrate-guard core)

```
substrate-guard/
├── examples/         # sample configs + orchestrator_inject_events.py
├── observe/          # L1 — eBPF tracer, pipeline integration
│   └── tracer.py     # 417 LOC — event capture and normalization
├── policy/           # L2 — OPA/Rego policy engine
│   └── engine.py     # 411 LOC — rule evaluation, violation detection
├── ast_parse/        # L3+ — AST-first CLI checks (Tree-sitter bash; Python ast)
├── comply/           # L4 — threshold non-membership over a Merkle commitment (prototype; paper-era brand: "ZK-SNM")
├── attest/           # L5 — Ed25519 cryptographic attestation
├── offline/          # L6 — SQLite append-only HMAC store + sync (not a CRDT)
├── guard.py          # main guard pipeline (observe → policy → verify → chain)
├── audit.py          # automated audit and reporting (cron entry point)
├── combo_cli.py      # CLI for all layers
├── integrations/     # SUBSTRATE ecosystem connectors
├── chain.py          # HMAC-SHA256 tamper-evident chain
├── compliance.py     # SOC2 / ISO 27001 / ISO 42001 exports
└── tests/            # 512 tests collected, organized by layer (incl. adversarial + fuzz)
    ├── test_policy/       # L2 policy decisions
    ├── test_verify/       # L3 verifier soundness (code / cli / hw / distill)
    ├── test_integration/  # chain, audit, compliance, docs-drift guard
    ├── test_attest/       # L5 attestation
    ├── test_comply/       # L4 compliance / ZK-SNM
    ├── test_offline/      # L6 offline store + sync
    ├── test_observe/      # L1 observation
    └── test_adversarial/  # adversarial + extreme-input suites
```

**This repo: 16,509 LOC** (10,135 source in `substrate_guard/` + 6,374 tests; per `wc -l`, 2026-06-10).

### Deployment Scope

This repository (substrate-guard) is deployed on the **Research server** (89.167.66.225) — 10,135 LOC source + 6,374 LOC tests (per `wc -l`, 2026-06-10).

The broader SUBSTRATE ecosystem includes a separate production stack on the **CPX52 server** (substrate-v2 core + ecosystem judges + V2.0 single-file guard daemon) — see [Related Projects](#related-projects) below. That stack is outside this repository's scope.

**Tests: 512** collected (**503** passed in a local run on 2026-06-22; 9 skipped: 1 SBERT, 6 Postgres CI, 2 POSIX-only ops-exec). See [Related Projects](#related-projects) for the separate CPX52 V2.0 stack scope.

## Benchmark Results

5 adversarial scenarios, 100% accuracy:

| Scenario | Events | Violations | Result |
|----------|--------|------------|--------|
| Safe Web Agent | 4 | 0 | Correctly allowed |
| Code Generation | 4 | 0 | Correctly allowed |
| Malicious Agent | 4 | 4 | Correctly blocked |
| Prompt Injection | 4 | 3 | Correctly blocked |
| Resource Abuse | 151 | 0 | Correctly allowed (rate/budget enforcement is dict-API only, not exercised on the observe path) |

## Compliance Exports

substrate-guard generates audit-ready reports in standard formats:

- **SOC2** — Security controls, access logging, incident response
- **ISO/IEC 27001** — Information security management
- **ISO/IEC 42001** — AI management system (the new AI-specific standard)
- **Summary** — Human-readable executive summary with chain verification

All exports include HMAC chain hash, timestamp, event counts, and violation details.

## Publications

6 published, 2 under review (as of audit 2026-04-06):

| # | Title | Venue | DOI / ID |
|---|-------|-------|----------|
| 1 | Emergent Formal Verification in Autonomous AI Ecosystems | arXiv (cs.AI + cs.MA) | arXiv:2603.21149 |
| 2 | AI Black Box: Six-Layer Verification Architecture v2 | Zenodo | 10.5281/zenodo.19334382 |
| 3 | Attribution Without Disclosure: ZK Proofs of Semantic Non-Membership | Zenodo | 10.5281/zenodo.19185843 |
| 4 | Emergent Philosophy and Safety Principles v2 | Zenodo | 10.5281/zenodo.19158774 |
| 5 | Convergent Synthesis in Autonomous AI Ecosystems | Zenodo | 10.5281/zenodo.19349850 |
| 6 | IUBIRE V3 Artifact Dataset (1,266 artifacts) | Zenodo | 10.5281/zenodo.19312371 |
| 7 | 98 Emergent Concepts in Autonomous AI Ecosystems | ALIFE 2026 (fp137) | Under review |
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
# Or enable via env (persists across invocations):
# SUBSTRATE_GUARD_POLICY=rego python -m substrate_guard.cli audit --db-url postgresql://...
```

What is **fully functional without Linux eBPF** vs. what needs a **real kernel / OPA / DB** is documented in [docs/FUNCTIONAL_ROADMAP.md](docs/FUNCTIONAL_ROADMAP.md). **Ordered runbook (eBPF → Postgres → orchestrator example):** [docs/RUNBOOK_ORDERED.md](docs/RUNBOOK_ORDERED.md). For Rego policy engine setup (optional): [docs/rego-setup.md](docs/rego-setup.md).

## Known Limitations

- **L4-L6 are prototyped, not production-deployed.** Tests pass, code exists, but these layers are not yet in the live pipeline. We say "3 deployed + 3 prototyped," not "6 deployed."
- **q-score not externally validated.** The quality scoring system used in SUBSTRATE has not undergone inter-rater reliability testing. Proposed in our ALIFE 2026 submission.
- **Test suite scope.** This repository's tests run on the Research server only. The separate CPX52 V2.0 stack is validated through integration and daily audit, not unit tests — see [Related Projects](#related-projects).
- **Single maintainer.** All code written and maintained by one person. No external contributors yet.

## Production Deployment

substrate-guard (this repository) runs on the **Research server** (89.167.66.225) — currently v13.4.2 (v13.4.0 deployed May 18, 2026; v13.4.1 patch June 2; v13.4.2 patch June 14). Daily automated cron audit at 04:00 UTC. M0.7 baseline window: 7/7 verified (May 19–25, 2026); zero missed cycles since the May 18 deployment — per operator monitoring; per-night audit JSONs are not committed to this repo.

### Related Projects

The broader SUBSTRATE ecosystem includes a **separate production deployment on the CPX52 server** (89.167.109.168) — substrate-v2 core (ecosystem engines + judges) and a V2.0 single-file guard daemon (independent codebase, separate operational metrics).

CPX52 V2.0 audit refresh (2026-05-27 09:43 UTC): 22,376 chain entries (3,276 strong + 19,100 weak frozen post-cutover), 63 days continuous cron audit (genesis 2026-03-25), 100% verification rate over the last 7 days (356/356 cycles).

See [aisophical.com](https://aisophical.com) for SUBSTRATE ecosystem overview.

## Context: SUBSTRATE

substrate-guard was built to verify [SUBSTRATE](https://aisophical.com) — an autonomous multi-agent ecosystem where AI agents self-organize, generate original outputs, and reproduce across generations without human intervention.

- 7 servers, 100+ agents, 3 generations
- 45+ days continuous operation
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
- Zenodo: [6 datasets/preprints with permanent DOIs](https://zenodo.org/search?q=metadata.creators.person_or_org.name%3A%22Untila%2C%20Octavian%22)
- Contact: contact@aisophical.com

---

*"Others record what AI does. We prove it was correct."*
