# substrate-guard: Combo A — The Complete Verification Stack

**eBPF observes → OPA decides → Z3 proves**

Three levels of AI safety verification, from kernel to mathematical proof, in a single framework.

## The Thesis

AI safety has three fundamental questions, each at a different level:

| Level | Question | Answer |
|---|---|---|
| **Kernel** | What is the AI agent actually doing? (syscalls, files, network) | **eBPF** |
| **Policy** | Does it have permission to do this? (rules, budgets, limits) | **OPA/Rego** |
| **Formal** | Is what it did mathematically correct? (proof or counterexample) | **Z3 SMT** |

Nobody has unified all three into a working stack with experimental results. Until now.

## Architecture

```
AI Agent action
       │
       ▼
┌─────────────────────────────────────────┐
│  Layer 1: eBPF OBSERVE                  │
│  Intercepts syscalls, file I/O, network │
│  Overhead: <3%                          │
└──────────────┬──────────────────────────┘
               │ events (JSON)
               ▼
┌─────────────────────────────────────────┐
│  Layer 2: OPA/Rego DECIDE               │
│  Evaluates against safety policies      │
│  Latency: <5ms per decision             │
└──────────────┬──────────────────────────┘
               │ allowed events only
               ▼
┌─────────────────────────────────────────┐
│  Layer 3: Z3 PROVE                      │
│  Formal verification of AI outputs      │
│  Code, tools, CLI, hardware, distill    │
└──────────────┬──────────────────────────┘
               ▼
         ✅ verified  or  ❌ violation + counterexample
```

## Target Server: AI Research Agency

Tested and adapted for the live SUBSTRATE server:

| Spec | Value |
|---|---|
| Host | ai-research-agency (89.167.66.225) |
| Arch | **ARM64** (aarch64) — deploy.sh auto-detects |
| OS | Ubuntu 24.04.3 LTS, Kernel 6.8.0 |
| CPU | 2 vCPU |
| RAM | 3.7 GB total, ~2.1 GB free |
| Stack | Docker (11 containers), FastAPI, PostgreSQL 16, Redis, Nginx |
| Agents | 125 (19 categories + 4 meta-agents) |
| DB | 43 tables, 1,483 pipeline_traces, 1,132 agent_runs, 1,444 ideas |

Resource limits enforced: 400 MB RAM max, 25% CPU max, 5s Z3 timeout.

## Quick Start

```bash
# Run a demo scenario
python -m substrate_guard.combo_cli demo --scenario malicious

# Benchmark all scenarios
python -m substrate_guard.combo_cli benchmark

# Evaluate a single event
python -m substrate_guard.combo_cli evaluate --event '{
  "agent": {"id": "agent-7", "role": "code-gen"},
  "action": {"type": "file_write", "path": "/etc/passwd"},
  "context": {}
}'
```

## Python API

```python
from substrate_guard.guard import Guard

guard = Guard(
    observe=True,       # eBPF kernel tracing (mock if no root)
    policy="policies/", # OPA/Rego rules
    verify=True,        # Z3 formal verification
)

with guard.monitor("agent-7") as session:
    result = agent.run(task="generate sorting function")
    report = session.report()
    print(report.summary_line())
    # ✅ SAFE | agent=agent-7 | observed=47 | policy_violations=0 | formal_failures=0
```

## SUBSTRATE Integration

Connects directly to the live backend vendor packages and PostgreSQL database.

### VendorBridge — Audit DB Records

```python
from substrate_guard.integrations.vendor_bridge import VendorBridge

bridge = VendorBridge(db_url="postgresql://user:pass@localhost/airesearch")

# Audit pipeline_traces (1,483 records in DB)
report = bridge.audit_traces(traces_from_db)
print(report.summary_line())

# Audit agent_runs (1,132 records across 19 categories)
report = bridge.audit_runs(runs_from_db)
```

`PipelineTraceAdapter` converts DB rows to Guard events — extracts model, cost_usd, tokens, file_path, tool_calls. Detects Anthropic vs OpenAI endpoints automatically.

`AgentRunAdapter` supports all 19 agent categories (acquisition, action, advisor, analysis, automation, bridge, content, filters, growth, knowledge, learning, legal, monetization, ops, qa_checks, quality, reporting, scanners, strategy) plus 4 meta-agents (evolver, guardian, memorykeeper, taskmaster).

### SessionTrace Adapter — Span-Level

```python
from substrate_guard.integrations import SubstrateGuard

sg = SubstrateGuard(config_path="/opt/substrate-guard/config/substrate.json")

# Feed SessionTrace spans through the pipeline
report = sg.process_spans(spans)

# Health check — verifies all 3 layers
print(sg.health_check())
```

### Service Mapping

| Guard Adapter | Server Service | Path on Server |
|---|---|---|
| `PipelineTraceAdapter` | pipeline_traces table | PostgreSQL |
| `AgentRunAdapter` | agent_runs table | PostgreSQL |
| `SessionTraceAdapter` | SessionTrace vendor | `backend/vendor/sessiontrace/` |
| `MarketJudgeAdapter` | MarketJudge vendor | `backend/vendor/marketjudge/` |
| `MirrorReporter` | Guardian meta-agent | `backend/meta_agents/guardian/` |

Guard complements the existing Guardian meta-agent — Guardian handles runtime decisions, Guard adds kernel observation (eBPF), policy-as-code (OPA), and formal verification (Z3).

## Deploy Options

### Option C: Hybrid Mock (Recommended First Step)

Zero risk, guaranteed to work. Mock eBPF, built-in Python policy evaluator, Z3 if available.

```bash
scp substrate-guard-comboA-v2.tar.gz root@89.167.66.225:/opt/
ssh root@89.167.66.225
cd /opt && tar xzf substrate-guard-comboA-v2.tar.gz && cd substrate-guard
./scripts/deploy.sh install
substrate-guard demo --scenario malicious
substrate-guard benchmark
```

### Option A: Docker Container

Add to existing docker-compose stack. Isolated, consistent with current architecture.

```bash
./scripts/deploy.sh docker
# Then add substrate-guard service from docker-compose.guard.yml
docker compose -f docker-compose.guard.yml up -d
```

Container limits: 512 MB RAM, 0.5 CPU. Includes healthcheck.

### Option B: Full Install (Real eBPF + OPA)

Real kernel tracing. Downloads ARM64 binaries for OPA. Installs bcc-tools.

```bash
./scripts/deploy.sh full
systemctl start substrate-guard
systemctl enable substrate-guard
```

Requires root. eBPF from container needs `privileged: true` or `CAP_BPF`.

## Test Results

```
Layer              Test Cases   Accuracy
──────────────────────────────────────────
Observe (L1)            30       100%
Policy  (L2)            58       100%
Pipeline                18       100%
SUBSTRATE adapters      22       100%
VendorBridge (DB)       19       100%
──────────────────────────────────────────
Combo A TOTAL          147       100%
```

Combined with existing substrate-guard Z3 verifiers (Layer 3):

```
Layer 3 (Z3)       Test Cases   Accuracy
──────────────────────────────────────────
Code                    50       100%
Tool API                18       100%
CLI                     20       100%
Hardware (RISC-V)       21       100%
Distillation            26       100%
──────────────────────────────────────────
Z3 TOTAL               135       100%
```

**Grand total: 282 test cases, 100% accuracy, zero false positives.**

## Scenarios

| Scenario | Events | Violations | What happens |
|---|---|---|---|
| Safe Web Agent | 4 | 0 | Google, Wikipedia, writes to /workspace |
| Code Generation | 4 | 0 | Writes code, runs Python, calls API |
| Malicious Agent | 4 | 4 | Reads /etc/passwd, exfiltrates port 4444, curl\|sh |
| Prompt Injection | 4 | 3 | sudo escalation, /etc/crontab, suspicious port |
| Resource Abuse | 151 | 0 | 150 API calls (rate limit at policy level) |
| DB Audit (100 traces) | 200 | 0 | Realistic pipeline_traces simulation |
| Attack in Traffic | 12 | 2+ | 1 rogue agent among 10 normal |

## Policy Rules (Built-in)

7 rules evaluate every agent action:

1. **Dangerous Paths** — Block writes to /etc/, /root/, /boot/, /dev/, /proc/, /sys/ and reads of critical files (/etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab)
2. **Dangerous Commands** — Block rm -rf, DROP TABLE, chmod 777, fork bombs, pipe-to-shell (curl|sh regex)
3. **Network Exfiltration** — Block connections to suspicious ports (4444, 31337, 12345, etc.)
4. **Budget Enforcement** — Block actions when agent budget ≤ $0
5. **Rate Limiting** — Block when API calls > 100/minute
6. **Workspace Boundary** — File writes must be within /workspace/ or /tmp/
7. **PII Detection** — Block actions containing SSN or credit card patterns

## Files

```
substrate_guard/
├── guard.py                         # Unified pipeline (359 LOC)
├── combo_cli.py                     # CLI interface (374 LOC)
├── observe/
│   ├── events.py                    # Event types (240 LOC)
│   ├── tracer.py                    # eBPF tracer + mock (417 LOC)
│   └── bpf_programs/
│       └── agent_trace.c            # Kernel BPF programs (183 LOC)
├── policy/
│   ├── engine.py                    # OPA/Rego engine (411 LOC)
│   └── policies/
│       └── agent_safety.rego        # Safety policy (158 LOC)
├── integrations/
│   ├── __init__.py                  # SessionTrace/Mirror adapters (290 LOC)
│   └── vendor_bridge.py            # DB adapters for server (315 LOC)
└── (existing Z3 verifiers)          # 4,358 LOC

scripts/
├── deploy.sh                        # ARM64-aware deploy (362 LOC)
└── config_docker.json               # Resource-limited config

Dockerfile                           # ARM64 compatible
docker-compose.guard.yml             # Add to existing stack

tests/                               # 147 tests (1,662 LOC)
├── test_observe/                    # 30 tests
├── test_policy/                     # 58 tests
└── test_integration/                # 59 tests (guard + substrate + vendor)
```

**Combo A code: 2,431 LOC implementation + 1,188 LOC infra = 3,619 LOC**
**Tests: 147 tests in 1,662 LOC**
**Combined with Z3 (Layer 3): ~8,700 LOC total, 282 tests**

## Requirements

- Python 3.10+ (server has 3.12.3 ✅)
- Kernel 5.4+ for eBPF (server has 6.8.0 ✅)
- Layer 1 (eBPF): bcc-tools ARM64 (falls back to mock)
- Layer 2 (OPA): OPA binary ARM64 (falls back to built-in Python evaluator)
- Layer 3 (Z3): `pip install z3-solver` (has aarch64 wheels ✅)

## Related Work

| Framework | eBPF | OPA | Z3 | Implementation | Results |
|---|---|---|---|---|---|
| AgentSight | ✅ | ❌ | ❌ | 6000 LOC Rust | 3153 events |
| AAGATE (CSA) | ✅ | ✅ | ❌ | Whitepaper only | None |
| Sakura Sky | ❌ | ✅ | ✅ | Blog snippets | None |
| **substrate-guard** | **✅** | **✅** | **✅** | **~8700 LOC** | **282 tests, 100%** |

## Links

- **Code**: [github.com/octavuntila-prog/substrate-guard](https://github.com/octavuntila-prog/substrate-guard)
- **Paper (observational)**: [DOI: 10.5281/zenodo.19157572](https://doi.org/10.5281/zenodo.19157572)
- **Paper (Z3 experimental)**: [DOI: 10.5281/zenodo.19158774](https://doi.org/10.5281/zenodo.19158774)
- **SUBSTRATE ecosystem**: [aisophical.com](https://aisophical.com)
- **AI Research Agency**: [untilaoctavian.com](https://untilaoctavian.com)

---

*Part of the SUBSTRATE autonomous AI ecosystem research. Aisophical SRL, Bucharest.*
