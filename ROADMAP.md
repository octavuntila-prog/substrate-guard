# Roadmap — pachet complet (pași mici, cu porți de verificare)

Fiecare fază se închide doar când **toate testele** trec și criteriul de dovadă e îndeplinit.

## Faza 0 — Baseline (în lucru continuu)

- **Cod:** `Z3-PAPER/substrate_guard/` (L1–L3 + chain + compliance + audit).
- **Dovadă:** `pip install -e ".[dev]"` apoi `pytest` (doar `test_*.py`).
- **Manual:** `python tests/smoke_test.py` — verificator cod Z3 (benchmark funcții).

## Faza 1 — CLI și integrare (făcut)

- **Obiectiv:** un singur punct de intrare: `substrate-guard` = `substrate_guard.cli`.
- **Comenzi:** `verify`, `benchmark` (Z3), `demo`, `evaluate`, `monitor`, `export`, `stack-benchmark` (pipeline complet; vechiul `combo_cli benchmark`).
- **Dovadă:** `tests/test_combo_cli_smoke.py` (inclusiv `--help` și delegare `python -m substrate_guard.combo_cli`).

## Faza 2 — Layer 4 (comply / semantic non-membership) (făcut)

- **Cod:** `substrate_guard/comply/` — `DeterministicFingerprinter` (SHA256, fără ML), `SemanticFingerprinter` opțional (`sentence-transformers`), `EmbeddingCommitment`, `NonMembershipVerifier` (numpy + verificare Z3 pe scalare întreagă), `ZKSNMProtocol`, `ComplyGuard`.
- **CLI:** `substrate-guard comply demo`
- **Dovadă:** `pytest tests/test_comply/` (1 test skip fără `sentence-transformers`).
- **Opțional ML:** `pip install sentence-transformers` pentru encoder real.

## Faza 3 — Layer 5 (attestare dispozitiv) (făcut)

- **Cod:** `substrate_guard/attest/` — `DeviceFingerprint`, `DeviceKey` (Ed25519 via `cryptography`), `LocalCA` (cert JSON 24h, semnat cu cheia dispozitiv), `EventSigner`, `AttestedGuard`.
- **CLI:** `substrate-guard attest demo`
- **Dovadă:** `pytest tests/test_attest/` + smoke CLI.
- **Notă:** identitate software (fără TPM); chei în `key_dir` configurat.

## Faza 4 — Layer 6 (offline) (făcut)

- **Cod:** `substrate_guard/offline/` — `LocalStore` (SQLite WAL, lanț HMAC pe `rowid`), `ConnectivityChecker` (TCP Postgres + internet best-effort), `SyncEngine` (INSERT OR IGNORE în `guard_events`, marcare `synced`), `OfflineGuard` (`remote_store` opțional când „online”).
- **CLI:** `substrate-guard offline demo`
- **Dovadă:** `pytest tests/test_offline/` + smoke CLI.
- **Notă:** sync-ul folosește SQL cu `?` (compatibil sqlite3); pentru PostgreSQL real, folosește un adaptor sau un factory care returnează conexiune cu același schema.

## Faza 5 — Închidere (făcut)

- **CI:** `.github/workflows/ci.yml` — pe push/PR: `pip install -e ".[dev]"`, `pytest tests/`, `python tests/smoke_test.py` (matrice Python 3.10–3.12). Job separat `benchmarks` doar la `workflow_dispatch`.
- **Docker:** `Dockerfile` instalează din `pyproject.toml`, rulează `pytest` la build; `HEALTHCHECK` simplu pe `__version__`.
- **Compose:** `docker-compose.yml` (local), `docker-compose.guard.yml` (rețea externă agency), `scripts/config_docker.json`, `.env.example`.
- **Reproducere:** `REPRODUCING.md` + `scripts/run-ci-local.sh` / `run-ci-local.ps1`.

## Faza 6 — AST-first CLI (Bijuteria #5) (făcut)

- **Cod:** `substrate_guard/ast_parse/` — `tree-sitter` + `tree-sitter-bash` (în `dev`), verificări pe structură pentru bash; `ast` stdlib pentru snippet-uri Python (`eval`/`exec`/…).
- **Integrare:** `cli_verifier.py` rulează `_structural_cli_violations` înainte de regex+Z3.
- **Dovadă:** `pytest tests/test_ast_parse.py`.

---

Regulă: **nu trecem la faza N+1** până Faza N nu are teste verzi și un exemplu rulabil.
