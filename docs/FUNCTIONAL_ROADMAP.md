# Roadmap: substrate-guard „funcțional pe bune”

Acest document separă ce **funcționează astăzi** din repo de ce necesită **mediu suplimentar** (kernel, privilegii, servicii externe). Scopul este să știi exact ce poți promite utilizatorilor open-source vs. ce este integrare SUBSTRATE / producție.

---

## Nivel A — Funcțional fără presupuneri speciale (recomandat pentru orice mașină)

| Capabilitate | Cum se validează |
|--------------|-------------------|
| Instalare din sursă | `pip install -e ".[dev]"` sau `pip install -r requirements-dev.txt` |
| Verificatori Z3 (cod / tool / CLI) | `substrate-guard verify --type cli -c "echo test"` |
| Pipeline Black Box (mock observe) | `substrate-guard demo --scenario safe` |
| Teste + Bandit + politică documentată | `pytest tests/`; vezi `bandit.yaml`, `SECURITY.md` |
| **Diagnostic mediu** | `substrate-guard doctor` |

**Concluzie:** Nivelul A este „produs software” în sensul: instalabil, testat, repetabil. Nu observă kernelul real — folosește **mock tracer** și reguli **policy** built-in sau OPA dacă îl instalați.

---

## Nivel B — Observare reală (L1 eBPF)

| Cerință | Motiv |
|---------|--------|
| OS Linux, kernel **≥ 5.4** | eBPF API stabil pentru programele din `observe/bpf_programs/` |
| **root** sau **CAP_BPF** / CAP_PERFMON | încărcare programe BPF |
| **bcc** (Python `bcc`, pachete `bpfcc-tools` / echivalent) | încărcare și attach |

Fără acestea, codul cade automat pe **MockTracer** (comportament intenționat, nu crash).

**Windows / macOS:** nu există același stack eBPF ca pe Linux; rămâneți la Nivel A sau la injectare evenimente (`inject_event`) pentru integrare.

---

## Nivel C — Policy OPA/Rego ca sursă unică

| Cerință | Motiv |
|---------|--------|
| Binariul **`opa`** în `PATH` | `PolicyEngine` folosește `opa eval` când există `.rego` încărcat |
| Fișiere `.rego` sub `policy_path` | altfel se folosesc regulile **built-in** Python (suficiente pentru demo) |

---

## Nivel D — Audit PostgreSQL / producție agency

| Cerință | Motiv |
|---------|--------|
| URL Postgres + schemă compatibilă | `substrate-guard audit`, teste `POSTGRES_CI` |
| Opțional: variabile din `.env` | vezi `audit.py` și `REPRODUCING.md` |

---

## Straturi L4–L6 (Comply / Attest / Offline)

Codul există și este acoperit de teste; „funcțional pe bune” în sens **research** = da. Integrare în același pipeline ca L1–L3 pe CPX52 = domeniu **SUBSTRATE**, nu doar acest repo.

---

## Pași concreți de „perfecționare” (prioritate)

1. **Menține README / REPRODUCING aliniate cu `pyproject.toml`** (fără comenzi moarte).
2. **Rulați `doctor` după instalare** pe orice mediu nou.
3. Pentru demo „ca în producție”: Linux VM + Docker cu capabilități BPF sau integrare prin **evenimente injectate** din orchestratorul vostru.
4. Urmăriți **Dependabot / pip-audit / CodeQL** și actualizați `cryptography` etc. ca în workflow-uri.

---

*Ultima actualizare: aliniată versiunii din `pyproject.toml`.*
