# Runbook — pași în ordine (produs + integrare)

Urmați ordinea de mai jos; fiecare pas se bazează pe cel anterior unde e cazul.

| Pas | Scop | Document / artefact |
|-----|------|---------------------|
| **1** | Înțelegi ce merge fără kernel special (mock, Z3, policy built-in) | [FUNCTIONAL_ROADMAP.md](FUNCTIONAL_ROADMAP.md) |
| **2** | Verifici mediul după instalare | `substrate-guard doctor` |
| **3** | L1 eBPF real (`monitor --live`) — Linux, privilegii, bcc | [DOCKER_EBPF.md](DOCKER_EBPF.md) |
| **4** | Postgres + audit în Docker (date reale sau tabele goale) | [DOCKER_POSTGRES_AUDIT.md](DOCKER_POSTGRES_AUDIT.md), `scripts/stack_audit.sh` / `.ps1` |
| **4b** | Același flux în CI (săptămânal / manual) | [`.github/workflows/docker-stack-audit.yml`](../.github/workflows/docker-stack-audit.yml) |
| **5** | Evenimente din orchestrator fără eBPF (API → Guard) | [examples/orchestrator_inject_events.py](../examples/orchestrator_inject_events.py) |

**Reproducere CI locală:** [REPRODUCING.md](../REPRODUCING.md).  
**Deploy agregat:** [DEPLOY.md](../DEPLOY.md).
