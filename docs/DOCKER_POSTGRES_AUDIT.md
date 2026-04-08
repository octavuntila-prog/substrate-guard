# În ordine: Postgres + `substrate-guard audit` (Docker)

Pașii de mai jos pornesc un **Postgres 16** local, aplică schema minimă din `scripts/sql/`, și rulează **audit** din containerul `substrate-guard` pe aceeași rețea.

## 0. Prerequisite

- Docker + Docker Compose v2  
- Repo clonat, terminal în rădăcina proiectului (`Z3-PAPER` / `substrate-guard`)

## 1. Variabile de mediu

```bash
cp .env.example .env
# Setați POSTGRES_PASSWORD=... (obligatoriu pentru producție; pentru local merge și defaultul din compose)
```

Pe Windows PowerShell: copiați manual sau `Copy-Item .env.example .env`.

## 2. Pornește stack-ul

```bash
docker compose -f docker-compose.stack.yml up -d --build
```

Așteptați ca serviciul `db` să fie **healthy** (healthcheck `pg_isready`). Init SQL (`scripts/sql/*.sql`) rulează la prima pornire a volumului Postgres.

## 3. Verifică mediul în container

```bash
docker compose -f docker-compose.stack.yml exec substrate-guard \
  python -m substrate_guard.cli doctor
```

Ar trebui să vedeți **z3-solver: OK**, **psycopg2** disponibil (imaginea instalează `[dev,postgres]`).

## 4. Rulează auditul

Tabelele pot fi goale — audit-ul trebuie să se încheie fără excepție (0 rânduri sau date reale dacă le populați din aplicație):

```bash
docker compose -f docker-compose.stack.yml exec substrate-guard \
  substrate-guard audit
```

URL explicit (dacă nu vă bazați pe `POSTGRES_*` din mediu):

```bash
docker compose -f docker-compose.stack.yml exec substrate-guard \
  substrate-guard audit --db-url "postgresql://guard:CHANGEME@db:5432/substrate"
```

Înlocuiți `CHANGEME` cu parola din `.env` / `POSTGRES_PASSWORD`.

## 5. Oprire

```bash
docker compose -f docker-compose.stack.yml down
# date persistente: volumul `pgdata` (vezi `docker-compose.stack.yml`)
```

## Scripturi rapide

- **Linux/macOS:** `scripts/stack_audit.sh` — pornește stack-ul și rulează `doctor` + `audit`.
- **Windows:** `scripts/stack_audit.ps1`

## Detalii suplimentare

- [DEPLOY.md](../DEPLOY.md) — variante cu `docker-compose.guard.yml` (rețea externă agency).
- [FUNCTIONAL_ROADMAP.md](FUNCTIONAL_ROADMAP.md) — tier D (audit DB).
