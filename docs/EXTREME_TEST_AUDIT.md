# Audit — teste extreme & adversariale (substrate-guard)

Acest document descrie **ce rulăm** pentru a scoate la iveală regresii, excepții neprinse sau slăbiciuni de model (regex / policy), și **cum interpretăm** rezultatele.

---

## 1. Comenzi recomandate (local)

| Scop | Comandă |
|------|---------|
| Toate testele adversariale + fuzz | `pytest tests/test_adversarial/ -q --tb=short` |
| Doar marker fuzz (Hypothesis) | `pytest tests/ -m fuzz -q` |
| Verificare statică Bandit | `bandit -c bandit.yaml -r substrate_guard -q` |
| Suite completă CI-parity | `pytest tests/ -q` |
| Smoke cod Z3 | `python tests/smoke_test.py` |
| Fuzz „greu” (mai multe exemple Hypothesis, local) | `set SUBSTRATE_FUZZ_MULTIPLIER=5` apoi `pytest tests/test_adversarial/ -q` (Windows PowerShell: `$env:SUBSTRATE_FUZZ_MULTIPLIER=5`) |

**Bandit** este rulat implicit odată cu suite completă prin **`tests/test_bandit_policy.py`** (apel la `bandit` cu `bandit.yaml`). Comanda manuală din tabel rămâne utilă pentru depanare rapidă.

Înainte de release tag: **toate rândurile** din tabel (sau echivalent CI).

---

## 2. Ce acoperă directoarele

| Loc | Rol |
|-----|-----|
| `tests/test_adversarial/test_extreme_adversarial.py` | CLI benchmark unsafe, „extra extreme”, honest-gap inventory, cod/tool adversarial, VendorBridge masă, sesiune Guard „storm” |
| `tests/test_adversarial/test_fuzz_short_inputs.py` | Hypothesis pe CLI, `parse_json_field`, `build_db_url`, adapter pipeline, `FileEvent` |
| `tests/test_adversarial/test_extreme_guard_fuzz.py` | **ProcessEvent + `verify_process_cli`**, argv/filename fuzz, lungime extremă CLI, volum raport |

---

## 3. Ce „iese la iveală” (interpretare)

- **Eșec la `test_cli_honest_gap_inventory`** — un șir din lista *documentată ca SAFE pe frontieră* a devenit UNSAFE: actualizați lista sau documentația honest-gap, nu „reparați” testul fără analiză.
- **Eșec la `test_cli_patterns_closed_former_documented_gaps`** — regresie: un pattern cunoscut nu mai e prins; extindeți `DANGEROUS_PATTERNS` sau remediați fals negativul.
- **Crash în teste fuzz** — bug real (excepție neprinsă): prioritate înaltă.
- **Bandit non-zero** — încălciți politica din `bandit.yaml`; fie remediere, fie justificare documentată (`# nosec` punctual).

---

## 4. Integrare CI

- Job-ul principal rulează **`pytest tests/`** (fără excludere adversarial; include Bandit prin `test_bandit_policy`).
- **`postgres-ci`** — integrare Postgres (`POSTGRES_CI=1`), vezi [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
- **Adversarial + fuzz greu** — [`.github/workflows/adversarial-fuzz.yml`](../.github/workflows/adversarial-fuzz.yml): `workflow_dispatch` + cron săptămânal; setează **`SUBSTRATE_FUZZ_MULTIPLIER=5`** și rulează `tests/test_adversarial/`.
- **Comply ML (SBERT)** — [`.github/workflows/comply-ml-smoke.yml`](../.github/workflows/comply-ml-smoke.yml): `pip install -e ".[dev,comply-ml]"` + smoke `test_sbert_optional_smoke` (acoperă skip-ul local fără `sentence_transformers`).
- **Docker stack audit** (alt flux): vezi [RUNBOOK_ORDERED.md](RUNBOOK_ORDERED.md).

---

## 5. Istoric (completare manuală la release)

| Data | Versiune | Rezumat rulare adversarial/fuzz |
|------|-----------|-----------------------------------|
| 2026-04-08 | 13.2.x | Introducere `test_extreme_guard_fuzz` + acest document |
| 2026-04-07 | — | Local: `pytest tests/test_adversarial/` 71 passed; `pytest tests/` 358 passed, 7 skipped |
| 2026-04-07 | 13.2.7 | `fuzz_helpers` + `SUBSTRATE_FUZZ_MULTIPLIER`; workflows adversarial-fuzz + comply-ml-smoke |

---

*Nu înlocuiește un pen-test extern sau audit de securitate organizațional.*
