# Deploy „pe bine” — PostgreSQL + audit real

**Index pas-cu-pas (ordine recomandată):** [docs/RUNBOOK_ORDERED.md](docs/RUNBOOK_ORDERED.md) · Postgres+Docker: [docs/DOCKER_POSTGRES_AUDIT.md](docs/DOCKER_POSTGRES_AUDIT.md) · eBPF: [docs/DOCKER_EBPF.md](docs/DOCKER_EBPF.md).

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
cd substrate-guard
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

## 8. Audit zilnic programat (host cron)

Pe un host (nu în container), auditul rulează zilnic la 04:00 printr-un cron. **Prerechizit obligatoriu** — cheia HMAC pentru lanțul tamper-evident; fără ea auditul iese cu **cod 2** (eroare de config) și paginează, în loc să verifice tăcut nimic:

```bash
# 1. Generează cheia HMAC stabilă (o singură dată; pierderea ei rupe verificarea cross-run)
sudo mkdir -p /etc/substrate-guard
openssl rand -hex 32 | sudo tee /etc/substrate-guard/hmac.key > /dev/null
sudo chmod 600 /etc/substrate-guard/hmac.key    # 600 sau 400; alte permisiuni => audit iese 2

# 2. Copiază proiectul in /opt si instaleaza cron-ul canonic (din radacina repo-ului)
sudo ./scripts/deploy.sh install     # copiaza substrate_guard/ + scripts/ in /opt/substrate-guard
sudo ./scripts/setup-cron.sh         # instaleaza cron-audit.sh canonic + adauga cron 0 4 * * *
```

`cron-audit.sh` exportă `SUBSTRATE_GUARD_HMAC_SECRET` din `/etc/substrate-guard/hmac.key`, rulează auditul pe ultimele 24h, și **paginează prin Telegram** dacă: cheia lipsește/are permisiuni greșite (cod 2), apar violări (cod 1), sau orice eroare neașteptată (cod 2 — niciodată un fals „VIOLATIONS DETECTED"). Loguri: `/var/log/substrate-guard/`.

---

**Dacă ceva nu se conectează:** verifică firewall-ul, numele serviciului (`db` vs `postgres`), și că parola din URL este URL-encoded dacă conține caractere speciale.
