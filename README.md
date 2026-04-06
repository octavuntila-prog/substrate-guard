# substrate-guard — AI Black Box

**The first known formal verification system for autonomous multi-agent emergent behavior.**

Others record what AI does. We prove it was correct.

---

## What It Does

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
| Tests | 270, all passing, 100% accuracy on 5 benchmark scenarios |
| Uptime | Continuous since March 22, 2026 |

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

**Chain:** Every event is recorded in an HMAC-SHA256 tamper-evident chain. Each entry references the hash of the previous entry. Any modification breaks the chain — detectable instantly.

**Audit:** Daily automated audits (cron 04:00 UTC) verify chain integrity, count violations, measure latency, and export compliance reports.

## Codebase

### This Repository (substrate-guard core)

```
substrate-guard/
├── observe/          # L1 — eBPF tracer, pipeline integration
│   └── tracer.py     # 417 LOC — event capture and normalization
├── policy/           # L2 — OPA/Rego policy engine
│   └── engine.py     # 411 LOC — rule evaluation, violation detection
├── verify/           # L3 — Z3 SMT formal verification
├── comply/           # L4 — ZK semantic non-membership proofs
├── attest/           # L5 — Ed25519 cryptographic attestation
├── offline/          # L6 — SQLite + CRDT offline verification
├── guard.py          # 378 LOC — main guard pipeline
├── audit.py          # 440 LOC — automated audit and reporting
├── combo_cli.py      # 478 LOC — CLI for all layers
├── integrations/     # 404 LOC — SUBSTRATE ecosystem connectors
├── chain.py          # HMAC-SHA256 tamper-evident chain
├── compliance.py     # SOC2 / ISO 27001 / ISO 42001 exports
└── tests/            # 270 tests, 3,159 LOC
    ├── test_observe.py    # 20 tests — L1 observation
    ├── test_policy.py     # 80 tests — L2 policy decisions
    ├── test_guard.py      # 59 tests — guard pipeline + substrate + vendor + audit
    ├── test_chain.py      # 23 tests — HMAC chain integrity
    ├── test_attest.py     # 26 tests — L5 attestation
    ├── test_offline.py    # 26 tests — L6 offline sync
    ├── test_comply.py     # 27 tests — L4 ZK compliance
    └── test_substrate.py  # 438 LOC — integration tests
```

**This repo: 9,205 LOC** (6,046 production + 3,159 tests).

### Full Production Stack

The complete system deployed on SUBSTRATE includes additional components not in this repository:

| Component | LOC | Location | Function |
|-----------|-----|----------|----------|
| substrate-v2 core | 4,690 | CPX52 server | 9 ecosystem engines, peer-to-peer mesh |
| Guard daemon | 583 | CPX52 (in v9-oracle) | Production guard chain, hourly audits |
| Mirror | 322 | CPX52 | Anomaly detection, 30-min reflection cycles |
| Kalshi Collector | 271 | CPX52 | Prediction market signal collection |
| Market Judge | 235 | CPX52 | Diversity monitoring, monoculture alerts |
| Blog Judge Gate | 213 | CPX52 | Content filtering, duplicate detection |
| Blog Judge | 210 | CPX52 | Pattern matching, quality assessment |
| Synthesizer | 290 | CPX52 | Cross-ecosystem synthesis |
| Host scripts | 448 | CPX52 | Deployment, monitoring |

**Total production stack: 16,467 LOC** across 2 servers (9,205 Research + 7,262 CPX52).

**Tests: 270** — all on Research server. Zero tests on CPX52 production (daemon services tested through integration, not unit tests).

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
# Clone
git clone https://github.com/octavuntila-prog/substrate-guard.git
cd substrate-guard

# Install
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run audit on existing database
python audit.py --db /path/to/traces.db --export json

# Run benchmark
python combo_cli.py benchmark

# Generate compliance report
python combo_cli.py compliance --format soc2
```

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
