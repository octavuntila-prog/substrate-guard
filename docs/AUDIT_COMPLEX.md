# Audit complex — substrate-guard (stare actuală)

**Data referință:** 7 aprilie 2026  
**Versiune pachet:** `13.2.1` (`pyproject.toml`)  
**Scop:** inventar tehnic, capabilități, teste, lanț de audit, gap-uri și limitări — fără a înlocui un audit SOC2/ISO extern.

---

## 1. Rezumat executiv

| Dimensiune | Valoare |
|------------|---------|
| **Teste colectate (pytest)** | **355** |
| **Rulare tipică locală** | **348 passed**, **7 skipped** |
| **Skip:** | 1× `sentence_transformers` (comply-ml); 6× Postgres CI fără `POSTGRES_CI` |
| **Grupuri regex CLI** (`DANGEROUS_PATTERNS`) | **40** |
| **Fișiere Python `substrate_guard/`** | 40 |
| **Linii cod aprox. în `substrate_guard/`** | ~7 030 |
| **Linii aprox. în `tests/`** | ~3 410 |

**Nucleu:** pipeline **Observe → Policy → Verify (Z3)** cu opțional **HMAC chain** și export **compliance**; integrare **Guard.verify_artifact** pentru **cli / tool / code / hw / distill** cu **counterexample** lizibil și persistare **`formal_verification`** în lanț.

**Opțional:** `Guard(..., verify_process_cli=True)` rulează verificarea CLI pe **`ProcessEvent`** (comandă reconstruită din `args`), după intrarea din chain pentru observare — aliniază eBPF/exec cu același motor regex ca `verify_artifact` manual.

---

## 2. Arhitectură pe straturi

| Strat | Modul principal | Rol |
|-------|-----------------|-----|
| **L1 Observe** | `observe/tracer.py`, `observe/events.py` | Evenimente (fișier, rețea, proces); scenarii mock pentru teste |
| **L2 Policy** | `policy/engine.py` | Reguli OPA-style / built-in; `PolicyDecision` |
| **L3 Verify** | `code_verifier`, `tool_verifier`, `cli_verifier`, `hw_verifier`, `distill_verifier`, `ast_translator` | Domenii Z3 / simbolic; CLI = regex + schemă Z3 booleană |
| **Chain** | `chain.py` | `AuditChain` HMAC-SHA256, export JSON semnat |
| **Guard** | `guard.py` | Orchestrare sesiuni, `verify_artifact`, append **`formal_verification`** în chain |
| **L4 Comply** | `comply/*` | Fingerprinter, commitment, protocol, `ComplyGuard` (embeddings opționale) |
| **L5 Attest** | `attest/*` | Device key, fingerprint, signer, CA local, `AttestedGuard` |
| **L6 Offline** | `offline/*` | SQLite append-only, sync, `OfflineGuard` |
| **Audit DB** | `audit.py` | PostgreSQL: `pipeline_traces`, `agent_runs`, rapoarte |
| **Compliance** | `compliance.py` | Export SOC2 / ISO 27001 / ISO 42001 / summary |
| **Integrări** | `integrations/vendor_bridge.py` | Poduri către date vendor |

---

## 3. `Guard.verify_artifact` — integrare verificatori

| Tip artefact | Verificator | Mapare spec / payload | Rezultat către `VerificationResult` |
|--------------|-------------|------------------------|-------------------------------------|
| `cli` | `CLIVerifier` | — | `safe` → `verified`; violări → string `counterexample` |
| `tool` | `verify_tool(tool_definition_from_payload(...))` | JSON/dict → `ToolDefinition` | `ToolSafetyResult.safe` |
| `code` | `CodeVerifier` | `spec_from_mapping` / `Spec` | `VerificationResult.verified` + counterexample formatat |
| `hw` | `HardwareVerifier` | `hw_spec_from_mapping` / `HWSpec` | `HWVerifyResult.verified` |
| `distill` | `DistillationVerifier.verify` | JSON `problem` + `steps` | `TraceVerification.all_valid` |
| Eșec parse tool / excepții | — | — | `verified=False`, mesaj în `counterexample` |

**Lanț:** orice return trece prin `_append_verification_to_chain` când `chain=True`, cu câmpuri: `type=formal_verification`, `agent_id`, `verifier_type`, `verified`, `artifact_preview`, `counterexample`, `proof_time_ms`.

---

## 4. CLI — `DANGEROUS_PATTERNS` (40 grupuri)

Ordine logică (nume interne):

1. recursive_delete, root_filesystem, privilege_escalation, disk_wipe, fork_bomb  
2. network_exfil, cron_manipulation, history_tampering, env_manipulation, shutdown  
3. pipe_to_shell, chmod_recursive_root, kubectl_destructive, cloud_exfil_or_wide_sync, raw_disk_redirect  
4. netcat_exec, user_account_create, iptables_destructive, pip_insecure_install, systemd_disable_or_mask  
5. package_manager_remove, mount_block_device, sed_system_paths, docker_compose_remote_spec, git_clone_sensitive_target  
6. eval_or_shell_c_remote_fetch, strace_attach_init, tcpdump_any_interface, openssl_server_or_pkcs12_export  
7. curl_or_wget_insecure_tls, ssh_host_key_bypass, socat_exec_or_system, socat_listen_fork, chmod_loose_ssh_material  
8. docker_run_privileged, docker_run_host_namespaces, nsenter_init, iptables_nat_redirect  

**Limită:** matching pe **string** — nu AST shell; false positive / negative posibile; test **`test_cli_honest_gap_inventory`** menține explicit comenzi încă **SAFE** (frontieră documentată).

---

## 5. Inventar teste (orientativ)

| Zonă | Fișiere reprezentative | Conținut |
|------|-------------------------|----------|
| **Integrare** | `test_guard.py`, `test_chain.py`, `test_substrate.py`, `test_audit.py`, `test_vendor.py` | Pipeline Guard, chain, vendor, audit |
| **Policy** | `test_policy.py` | Reguli și evenimente |
| **Comply** | `test_*` în `test_comply/` | Protocol, commitment, verifier, fingerprinter |
| **Attest** | `test_attest/*` | CA, device key, fingerprint, signer |
| **Offline** | `test_offline/*` | Store, sync, health |
| **Adversarial** | `test_extreme_adversarial.py`, `test_agent_cli_proposals.py`, `test_fuzz_short_inputs.py` | CLI gap, agenți, Hypothesis |
| **Combo / smoke** | `test_combo_cli_smoke.py`, `smoke_test.py` (manual) | CLI unificat |
| **Postgres CI** | `test_postgres_ci.py` | Marcat pentru mediu cu DB real |

**Markeri pytest:** `postgres_ci`, `fuzz` (în `pyproject.toml`).

---

## 6. CI (GitHub Actions)

- **Job `test`:** Python 3.10 / 3.11 / 3.12, `pip install -e ".[dev]"`, `pytest tests/ -q`, apoi `python tests/smoke_test.py`.  
- **Job `postgres-ci`:** Postgres 16 service, `POSTGRES_CI=1`, schemă audit, teste Postgres dedicate.
- **Workflow `supply-chain`:** `pip>=25.3`, `pip install -e ".[dev]"`, **`pip-audit`** pe mediul curat (CVE-uri în dependențe declarate).  
- **Workflow `CodeQL`:** analiză statică Python pe push/PR + săptămânal.  
- **Dependabot:** actualizări săptămânale `pip` + GitHub Actions. Politică raportare: [SECURITY.md](../SECURITY.md).

---

## 7. Dependențe runtime vs opționale

| Tip | Pachete |
|-----|---------|
| **Core** | `z3-solver`, `sympy`, `numpy`, `cryptography` |
| **Dev** | `pytest`, `pytest-asyncio`, `hypothesis` |
| **Postgres** | `psycopg2-binary` |
| **Comply ML** | `sentence-transformers` (lipsă → skip test fingerprinter) |

---

## 8. Gap-uri și riscuri (transparență)

1. **CLI regex:** comenzi legitime pot coincide cu pattern-uri; comenzi malicioase pot ocoli regex — inventar honest-gap actual include (exemplu): `git clone … /tmp`, `pip install -e .`, `openssl req -x509 …`, `curl` fără `-k`, `http.server`, `rsync`, `chmod 600` chei, `docker compose up`, `docker run -p`, `sysctl`, `kubectl exec`.  
2. **Policy vs formal:** evenimentele din tracer nu declanșează automat `verify_artifact`; verificarea formală e apel explicit sau integrare viitoare.  
3. **Distill / HW:** domenii parțiale — erori de parsare → status dedicate în verificatori.  
4. **Secret HMAC:** chain folosește secret; exportul trebuie protejat la rest.

---

## 9. Concluzie audit

**Puncte forte:** acoperire teste largă (348), integrare Guard ↔ verificatori corectată, lanț de audit cu **motiv formal** (`counterexample`) pentru conformitate și investigații interne, CLI extins cu grupuri clare, CI multi-Python + Postgres.

**Următori pași posibili (nu sunt defecte):** extindere structurală dincolo de regex pentru shell; integrare automată verify la anumite tipuri de eveniment; mediu CI cu SBERT pentru zero skip.

---

*Document generat pentru trasabilitate internă; nu constituie certificare legală sau de conformitate fără revizuire umană și scope definit.*
