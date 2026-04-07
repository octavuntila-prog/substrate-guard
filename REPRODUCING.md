# Cum reproduci dovada (același flux ca în CI)

Acest document descrie pașii pentru a rula **aceleași verificări** ca workflow-ul GitHub Actions (`.github/workflows/ci.yml`).

## Cerințe

- Python **3.10+**
- Git

## Instalare (mediu curat)

```bash
cd Z3-PAPER
python -m venv .venv
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"
```

## Dovada automată (principală)

```bash
python -m pytest tests/ -q --tb=short
```

Așteptare: toate testele trec; pot fi **skip** pentru: `sentence-transformers` (Comply ML opțional) și `tests/test_postgres_ci.py` dacă nu setezi `POSTGRES_CI=1` (aceste teste rulează în job-ul separat **`postgres-ci`** din CI, cu serviciu PostgreSQL 16).

## Integrare Postgres (job `postgres-ci` + local)

În GitHub Actions, după job-ul principal `test`, workflow-ul rulează **`postgres-ci`**: pornește Postgres, aplică `python scripts/ci_apply_audit_schema.py`, apoi `pytest tests/test_postgres_ci.py -m postgres_ci`.

Local, cu Postgres ascultând și aceleași variabile `POSTGRES_*`:

```bash
pip install -e ".[dev,postgres]"
export POSTGRES_CI=1   # PowerShell: $env:POSTGRES_CI="1"
python scripts/ci_apply_audit_schema.py
python -m pytest tests/test_postgres_ci.py -v -m postgres_ci
```

## Smoke verificator cod (Z3 pe funcții)

```bash
python tests/smoke_test.py
```

Cod de ieșire: **0** dacă toate cazurile trec, **1** dacă există eșecuri.

## Demouri CLI (straturi 1–6, fără Postgres)

```bash
python -m substrate_guard.cli --help
python -m substrate_guard.cli demo --scenario safe --chain
python -m substrate_guard.cli comply demo
python -m substrate_guard.cli attest demo
python -m substrate_guard.cli offline demo
```

## Opțional: encoder semantic (Comply ML)

```bash
pip install -e ".[comply-ml]"
python -m pytest tests/test_comply/test_fingerprinter.py::test_sbert_optional_smoke -q
```

## Benchmark-uri lungi (nu rulează implicit în CI)

Rulează manual sau prin **Actions → CI → Run workflow → benchmarks** (`workflow_dispatch`):

```bash
python -m benchmarks.run_benchmark
python -m benchmarks.run_tool_benchmark
python -m substrate_guard.cli benchmark --type cli
python -m benchmarks.run_hw_benchmark
python -m benchmarks.run_distill_benchmark
```

## Docker (imagine care rulează pytest la build)

```bash
docker build -t substrate-guard:local .
```

Build-ul eșuează dacă `pytest` eșuează (vezi `Dockerfile`).

### Compose local (fără rețea externă)

```bash
docker compose build
docker compose run --rm substrate-guard python -m substrate_guard.cli demo --scenario safe --chain
```

Fișier: `docker-compose.yml` (context `.` = rădăcina repo-ului unde e `Dockerfile`).

### Compose cu stack-ul „agency” (Postgres + rețea existentă)

```bash
# creează rețeaua din stack-ul principal, apoi:
docker compose -f docker-compose.guard.yml build
docker compose -f docker-compose.guard.yml run --rm substrate-guard \
  python -m substrate_guard.cli stack-benchmark
```

Config montat: `scripts/config_docker.json` → `/app/config/substrate.json`. Pentru audit DB, decomentează `env_file` în compose și folosește `.env` (vezi `.env.example`).

## Scripturi locale (CI + demos CLI)

`scripts/run-ci-local.sh` și `scripts/run-ci-local.ps1` rulează: `pip install -e ".[dev]"`, `pytest`, `tests/smoke_test.py`, apoi `demo` / `comply demo` / `attest demo` / `offline demo` (verificare funcțională straturi 1–6 fără Postgres).

---

**Regulă:** dacă `pip install -e ".[dev]"` + `pytest tests/` trec pe mașina ta, ai aceeași poartă minimă ca pipeline-ul `test` din CI. Pentru parity completă cu `postgres-ci`, rulează și pașii din secțiunea *Integrare Postgres* de mai sus.
