# Deploy „pe bine” — PostgreSQL + audit real

Acest ghid presupune că vrei **conexiune la Postgres** și rularea **`substrate_guard.audit`** (citește `pipeline_traces` și `agent_runs`, evaluează prin Guard).

## 1. Dependențe Python (pe host sau în venv)

```bash
pip install -e ".[dev,postgres]"
```

`postgres` instalează `psycopg2-binary` (necesar pentru audit).

## 2. Variabile de conexiune

Audit-ul acceptă:

- **`--db-url postgresql://USER:PASS@HOST:5432/DB`**, sau
- fișier **`.env`** cu una din variante:
  - `DATABASE_URL=postgresql://...`
  - sau `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`

Vezi și `build_db_url()` în `substrate_guard/audit.py`.

## 3. Stack Docker all-in-one (recomandat pentru primul deploy)

Fișier: **`docker-compose.stack.yml`** — pornește **Postgres 16** + container **substrate-guard** pe aceeași rețea, cu tabele minime din **`scripts/sql/001_audit_tables.sql`**.

```bash
cd Z3-PAPER
copy .env.example .env
# Editează POSTGRES_PASSWORD=... (Windows) sau export în Linux/macOS

docker compose -f docker-compose.stack.yml up -d --build
```

Audit (folosește variabilele `POSTGRES_*` din container; `resolve_db_url` cade pe `os.environ` dacă `.env` lipsește):

```bash
docker compose -f docker-compose.stack.yml exec substrate-guard \
  substrate-guard audit
```

Dacă ai nevoie de URL explicit (alt host sau parolă cu caractere speciale):

```bash
docker compose -f docker-compose.stack.yml exec substrate-guard \
  substrate-guard audit --db-url "postgresql://guard:changeme@db:5432/substrate"
```

(înlocuiește `changeme` cu parola din `.env`.)

Rapoarte JSON: implicit sub `/var/log/substrate-guard` în container (volumul `guard-logs`).

## 4. Integrare în stack-ul existent (agency)

Dacă ai deja **rețeaua** `ai-research-agency_internal` și **Postgres** pornit:

1. Copiază `.env` cu aceleași credențiale ca backend-ul.
2. Pornește serviciul guard:

```bash
docker compose -f docker-compose.guard.yml up -d --build
```

3. Rulează audit din container (montează `.env` sau setează `DATABASE_URL`):

```bash
docker compose -f docker-compose.guard.yml exec substrate-guard \
  substrate-guard audit --db-url "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}"
```

Decomentează `env_file: - .env` în `docker-compose.guard.yml` dacă vrei încărcare automată.

## 5. Schema bazei

Audit-ul așteaptă tabelele **`pipeline_traces`** și **`agent_runs`** cu coloanele din `audit.py` / `VendorBridge`.  
Stack-ul minimal din `scripts/sql/001_audit_tables.sql` creează structura goală; datele reale vin din aplicația ta.

## 6. Comenzi CLI unificate

```bash
substrate-guard audit --help
substrate-guard audit --db-url "postgresql://..."
substrate-guard audit --env /path/to/.env --hours 24
```

## 7. Imagine Docker

`Dockerfile` include **`psycopg2-binary`** ca să poți rula audit în container fără pas suplimentar.

---

**Dacă ceva nu se conectează:** verifică firewall-ul, numele serviciului (`db` vs `postgres`), și că parola din URL este URL-encoded dacă conține caractere speciale.
