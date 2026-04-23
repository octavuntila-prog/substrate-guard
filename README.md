# substrate-guard — AI Black Box

[![CI](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/ci.yml)
[![Adversarial fuzz](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/adversarial-fuzz.yml)
[![Comply ML smoke](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml/badge.svg)](https://github.com/octavuntila-prog/substrate-guard/actions/workflows/comply-ml-smoke.yml)
· [Security](SECURITY.md) · [Reproduce checks locally](REPRODUCING.md) · [Deploy Postgres + audit](DEPLOY.md) · `docker compose build` (see `docker-compose.yml`)

Others record what AI does. We prove it was correct.

---

### Unified CLI

One command: `substrate-guard` (also `ai-blackbox`). Z3 workflows use `verify` / `benchmark`; the Black Box pipeline uses `demo`, `monitor`, `evaluate`, `export`, and `stack-benchmark` (all mock scenarios through observe → policy → Z3 — not the same as Z3-only `benchmark`). **Layer 4:** `comply demo` — semantic non-membership prototype (deterministic embeddings + Merkle + threshold; optional `sentence-transformers`). **Layer 5:** `attest demo` — device fingerprint + Ed25519 signing + local short-lived cert (`cryptography`). **Layer 6:** `offline demo` — SQLite append-only + HMAC chain + sync către o a doua bază (ex. PostgreSQL sau un al doilea fișier SQLite cu tabel `guard_events`). `python -m substrate_guard.combo_cli` delegates to the same entry point.

## The Thesis

substrate-guard is a 6-layer verification architecture that observes, decides, proves, and audits every action taken by autonomous AI agents — in real time, with cryptographic evidence.

Deployed in production on [SUBSTRATE](https://aisophical.com), an autonomous multi-agent ecosystem running continuously on 7 servers across 3 generations since February 19, 2026.

## Production Results (verified April 6, 2026)

| Metric | Value |
|--------|-------|
| Events monitored | 18,353 (3,704 Research + 14,649 CPX52) |
| Violations detected | 79 (0.54%) |
| Latency | 0.14ms/event |
| HMAC-SHA256 chain | VERIFIED (14,649 entries, intact) |
| Cron audits | 45 reports, 16 consecutive days, zero missed |
| Compliance exports | SOC2, ISO/IEC 27001, ISO/IEC 42001 |
| Tests | **358** passing (365 collected), 7 skipped optional (SBERT + Postgres CI); 100% accuracy on 5 benchmark scenarios |
| Uptime | Continuous since March 22, 2026 |

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
│  L1  eBPF         OBSERVE   Kernel-level, zero overhead     │  ← Deployed
│  L2  OPA/Rego     DECIDE    Declarative policy enforcement  │  ← Deployed
│  L3  Z3 SMT       PROVE     Formal mathematical proofs      │  ← Deployed
│  L4  ZK-SNM       COMPLY    Zero-knowledge compliance       │  ← Prototyped
│  L5  Ed25519      ATTEST    Cryptographic attestation        │  ← Prototyped
│  L6  SQLite+CRDT  OFFLINE   Offline verification & sync     │  ← Prototyped
│                                                             │
│  Chain: HMAC-SHA256 tamper-evident audit trail               │
│  Exports: SOC2 / ISO 27001 / ISO 42001                      │
└─────────────────────────────────────────────────────────────┘
```

**L1-L3**: Deployed in production, processing live events from autonomous AI ecosystems.
**L4-L6**: Prototyped with tests. Code exists, validated, not yet in production pipeline.

## How It Works

**Observe (L1):** eBPF hooks capture every agent action at the kernel level — syscalls, network, file access — with zero runtime overhead.

**Decide (L2):** OPA/Rego policies evaluate each action against declarative rules. 80 policy tests cover authorization, rate limiting, data access, and behavioral constraints.

**Prove (L3):** Z3 SMT solver generates formal mathematical proofs that agent behavior satisfies safety invariants. Not statistical confidence — mathematical certainty.

**Chain:** Every event is recorded in an HMAC-SHA256 tamper-evident chain. Each entry references the hash of the previous entry. Any modification breaks the chain — detectable instantly. Formal verification outcomes (`verify_artifact` / `session.verify`) append **`formal_verification`** entries with **`counterexample`** when a command or artifact is rejected, so audit exports retain *why* a check failed, not only that it failed.

**Audit:** Daily automated audits (cron 04:00 UTC) verify chain integrity, count violations, measure latency, and export compliance reports.

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
├── comply/           # L4 — ZK semantic non-membership proofs
├── attest/           # L5 — Ed25519 cryptographic attestation
├── offline/          # L6 — SQLite + CRDT offline verification
├── guard.py          # main guard pipeline (observe → policy → verify → chain)
├── audit.py          # 440 LOC — automated audit and reporting
├── combo_cli.py      # 478 LOC — CLI for all layers
├── integrations/     # 404 LOC — SUBSTRATE ecosystem connectors
├── chain.py          # HMAC-SHA256 tamper-evident chain
├── compliance.py     # SOC2 / ISO 27001 / ISO 42001 exports
└── tests/            # 365 tests collected, ~3,410 LOC (incl. adversarial + fuzz + agent CLI suite)
    ├── test_policy.py     # 541 LOC — L2 policy decisions
    ├── test_substrate.py  # 438 LOC — integration tests
    ├── test_comply.py     # 347 LOC — L4 ZK compliance
    ├── test_chain.py      # 325 LOC — HMAC chain integrity
    ├── test_vendor.py     # 309 LOC — vendor integrations
    ├── test_offline.py    # 295 LOC — L6 offline sync
    ├── test_attest.py     # 248 LOC — L5 attestation
    ├── test_audit.py      # 234 LOC — audit pipeline
    ├── test_guard.py      # 227 LOC — guard pipeline
    └── test_observe.py    # 195 LOC — L1 observation
```

**This repo: ~9,456 LOC** (6,046 production + ~3,410 tests; rounded).

### Full Production Stack

The complete system deployed on SUBSTRATE includes additional components not in this repository:

| Component | LOC | Location | Function |
|-----------|-----|----------|----------|
| substrate-v2 core | 4,690 | CPX52 server | 9 ecosystem engines (base.py 541, persistence 213, runner 70, 9 ecosystems 1,815) |
| Guard daemon | 583 | CPX52 (in v9-oracle) | Production guard chain, hourly audits |
| Mirror | 322 | CPX52 (in v9-oracle) | Anomaly detection, 30-min reflection cycles |
| Synthesizer | 290 | CPX52 (in v9-oracle) | Cross-ecosystem synthesis |
| Kalshi Collector | 271 | CPX52 (in v9-oracle) | Prediction market signal collection |
| Market Judge | 235 | CPX52 (in v9-oracle) | Diversity monitoring, monoculture alerts |
| Blog Judge Gate | 213 | CPX52 (in v9-oracle) | Content filtering, duplicate detection |
| Blog Judge | 210 | CPX52 (in v9-oracle) | Pattern matching, quality assessment |

**Total production stack: 16,019 LOC** across 2 servers (9,205 Research + 6,814 CPX52). Zero tests on production.

**Tests: 365** collected (**358** passed in a typical local run; 7 skipped) — all on Research server. Zero tests on CPX52 production (daemon services tested through integration, not unit tests).

## Benchmark Results

5 adversarial scenarios, 100% accuracy:

| Scenario | Events | Violations | Result |
|----------|--------|------------|--------|
| Safe Web Agent | 4 | 0 | Correctly allowed |
| Code Generation | 4 | 0 | Correctly allowed |
| Malicious Agent | 4 | 4 | Correctly blocked |
| Prompt Injection | 4 | 3 | Correctly blocked |
| Resource Abuse | 15 | 10 | Correctly allowed (within limits) |

## Compliance Exports

substrate-guard generates audit-ready reports in standard formats:

- **SOC2** — Security controls, access logging, incident response
- **ISO/IEC 27001** — Information security management
- **ISO/IEC 42001** — AI management system (the new AI-specific standard)
- **Summary** — Human-readable executive summary with chain verification

All exports include HMAC chain hash, timestamp, event counts, and violation details.

## Publications

7 published, 2 under peer review (as of April 6, 2026):

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
- **Tests only on Research server.** CPX52 production daemons (Mirror, Blog Judge, Market Judge, Guard) have zero unit tests — they are validated through integration and daily audit, not test suites.
- **Single maintainer.** All code written and maintained by one person. No external contributors yet.

## Production Deployment

substrate-guard runs in production on two servers:

- **Research** (89.167.66.225) — Full test suite, benchmark, development
- **CPX52** (89.167.109.168) — Production guard chain, 14,649 entries, 16 days continuous cron audit

Daily automated audit at 04:00 UTC. Results sent via Telegram alerts. Zero missed days since March 22, 2026.

## Context: SUBSTRATE

substrate-guard was built to verify [SUBSTRATE](https://aisophical.com) — an autonomous multi-agent ecosystem where AI agents self-organize, generate original outputs, and reproduce across generations without human intervention.

- 7 servers, 100+ agents, 3 generations
- 45+ days continuous operation
- 137 original concepts generated autonomously
- 8,200+ artifacts across all ecosystems (CPX52: 6,102 + IUBIRE V3: 2,531 + S3: 280 MVPs — audited April 6, 2026)
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
