# AUDIT COMPLEX — substrate-guard

*Analiză per-strat: stadiu, ce funcționează cu adevărat, ce rămâne de făcut.*
*Data: 2026-06-22 · HEAD `4145136` (main, 1 commit înaintea tag-ului v13.4.2 / a507d30: `feat(chain): optional bijotel durable sink`).*

**Metodă:** audit multi-agent — 9 dimensiuni citite **din sursă** (nu din memorie), fiecare verificată **adversarial** pe overclaim-uri, sinteza tratând corecțiile adversariale ca autoritative. 19 agenți, 398 tool-uses.

---

## Reconciliere post-audit (verificare-din-sursă a recomandărilor)

Auditul e o hartă, nu autoritate — fiecare item `[BLOCK]` a fost re-verificat din sursă înainte de a fi aplicat:

- **Test-count:** auditul a zis 512/503/9 vs README 504/495. **Confirmat 512 collected / 503 passed / 9 skipped** (rulare completă pe HEAD `4145136`). Divergența: commit-ul bijotel nereleasat a adăugat 8 teste pe main, deasupra tag-ului v13.4.2. README actualizat la 512/503 (3 locații). ✅
- **`cron-with-alert` (v13.4.0.md):** auditul l-a marcat „inexistent în scripts/" → **RESPINS**. Wrapper-ul EXISTĂ pe server (`/usr/local/bin/cron-with-alert`, un tool de sistem, nu un fișier de repo); iar „exits 1" e un snapshot istoric corect pentru v13.4.0 (scriptul a trecut la exit 2 ulterior) — a-l schimba ar rescrie istoria. Doc-ul rămâne neatins.
- **Longevity claims** (uptime since Mar 22, M0.7 7/7, 20+ nights): operator-adevărate dar evidența (serie `audit_*.json`) nu e comisă în repo. Decizie de scope deschisă (commit evidență vs reformulare vs lasă).
- **Rename `ZKSNMProtocol`:** opțional, refactor de cod (teste + importuri) — codul e DEJA onest pe interior (docstring protocol.py, cli help). Aplicat doar eticheta README; clasa rămâne.

**Corecții README aplicate (2026-06-22):** test-count 504/495→512/503 (×3) · L3 „Prove" carve-out CLI din lista Z3 · L4 codebase label → „threshold non-membership over Merkle commitment (ZK-SNM prototype)" · L6 „SQLite+CRDT" → „SQLite append-only HMAC (not a CRDT)" (diagramă + codebase).

---

## 1. Snapshot de maturitate

Imaginea „3 deployed + 3 prototyped" e corectă, dar precizarea reală e între **ce rulează în cron-ul de producție** (Research, 89.167.66.225, `0 4 * * *`) și **ce e bibliotecă testată dar neconectată**.

**Ce rulează cu adevărat în cron-ul nocturn:**
- **L1 observe — MOCK** (`use_mock=True`, audit.py:397): „evenimentele" sunt *sintetizate din rânduri PostgreSQL* (vendor_bridge.py:88-161), nu syscall-uri.
- **L2 policy — builtin Python, 7 reguli** (default `builtin`, audit.py:162), NU OPA/Rego.
- **chain+compliance — real:** lanț HMAC-SHA256 semnat per-run, status `EVIDENCE_AVAILABLE` (niciodată certified).
- **ops/deploy — real:** cron autonom, contract exit-code 0/1/2, fail-loud pe cheia HMAC, release.sh disciplinat.

**Ce e prototip-cu-teste, neconectat:**
- **L3 verify** — invocat doar per-artefact explicit, niciodată per-event în cron.
- **L4 comply / L5 attest / L6 offline** — accesibile în binarul de producție doar prin subcomenzi `… demo`.

**O propoziție onestă:** substrate-guard e *un audit nocturn real, single-host/single-operator, care reia înregistrări DB prin politică builtin și le sigilează într-un lanț HMAC tamper-evident* — cripto-lanțul, verificatoarele Z3 sound-pe-fragment și disciplina ops sunt genuine și bine testate; straturile care dau numele produsului (eBPF, ZK-SNM, atestare hardware, verificare formală per-event) sunt fie mock, fie prototipuri pe raft, fie etichetate dincolo de ce livrează codul.

---

## 2. Per strat

### L1 — observe · *partial · 35%*
**Stadiu:** cod eBPF real există, nu e exercitat în producție; cron-ul reia DB prin mock; calea live (`monitor --live`) cade pe mock pe singurul host de deploy.

**Ce merge:** încărcare bcc reală (tracer.py:78-104); probe C eBPF genuine pentru execve/openat/connect cu `perf_submit` + `BPF_HASH` PID-filter (agent_trace.c:82-148); fallback onest la mock cu gărzi (Windows/kernel<5.4/non-root/ImportError); Guard raportează modul *real* nu eticheta (`observe=eBPF` doar când `not is_mock`, audit.py:503); 11 teste unitare trec.

**Gap-uri:** eBPF nu rulează niciodată în producție (`use_mock=True`); `bcc` nedeclarat în dependențe → import eșuază + cade silent pe mock; evenimentele auditate sunt fabricate din coloane DB; zero teste pe calea eBPF reală; uprobe TLS e stub; fără IPv6 în connect probe; `ProcessEvent.args[]` mereu gol din eBPF.

**Onestitate:** NU „eBPF în producție"; NU „observăm syscall-uri" (sunt sintetizate din PostgreSQL); NU calea eBPF „testată". Codul eBPF e REAL și non-trivial — gap-ul e capabilitate neexersată, nu denaturare în docs.

### L2 — policy · *partial · 72%*
**Stadiu:** builtin Python e default-ul de producție și funcționează; OPA/Rego e EXPERIMENTAL, neexecutat de teste/CI, nu la paritate.

**Ce merge:** engine builtin de 7 reguli e deciderul real (audit.py:161-162, sentinela engine.py:215-220); cele 7 reguli exact (engine.py:536-544); 67 teste trec; hardening genuin testat (canonizare cale, normalizare IP IPv4/IPv6, fail-safe type-confusion, malformed→deny); OPA fail-safe `default allow := false`; status experimental impus în cod cu WARNING.

**Gap-uri:** logica Rego NU rulează niciodată pe binar OPA real (cele 2 teste „OPA" mock-uiesc `subprocess.run`); Rego nu la paritate, documentat mai puțin sigur (fără PII/canonizare/IPv6/type-confusion); „PII" = denylist regex fără Luhn; pe calea cron doar 5/7 reguli efective (budget/rate_limit inerte); model rețea divergent (builtin denylist vs Rego allowlist → schimbarea engine-ului inversează silent allow/deny).

**Onestitate:** default-ul de producție e BUILTIN nu OPA; NU prezenta engine-urile ca echivalente; NU „Rego testată"; e 7 predicate Python NU formal/Z3-dovedit; riscul de supra-afirmare e integral pe partea Rego/OPA.

### L3 — verify · *prototyped-tested (research-grade) · 62%*
**Stadiu:** sound-pe-subset-declarat; nedeployat la scară.

**Ce merge:** patru verificatoare (code, tool, hw, distill) sunt Z3/SMT real peste un fragment deliberat mărginit, **sound pe acel fragment** (orice construct extern → abstain, niciodată fals VERIFIED); code_verifier AST→Z3 (VERIFIED doar cu `unsupported` gol); hw_verifier execuție simbolică BitVec RV32I; distill SymPy→Z3 raționale exacte + gărzi DoS; mapare fail-closed (abstain⇒verified=False, guard.py:69-112); **41/41 teste soundness adversarial trec**, zero corecții.

**Gap-uri:** SUBSET nu universal (aritmetică întreagă/liniară, fără bucle/string/recursie); domeniul CLI are ZERO Z3 — denylist regex+AST („SAFE"=„nu a fost prins"); empiric trec `shred -u`, `wipefs`, setuid cp; fals-pozitiv `truncate -s 0 /etc/passwd`→SQL TRUNCATE; tool_verifier supra-flaghează free-string; cele 4 Z3 nu rulează niciodată per-event.

**Onestitate:** „Z3-verified" se aplică EXACT celor 4; CLI = denylist regex, niciodată „formal verificat"; VERIFIED e sound-pe-subset-mărginit nu universal; soundness (niciodată fals VERIFIED) e REALĂ și test-backed — cea mai puternică afirmație onestă a stratului.

### L4 — comply · *prototyped-tested (doar CLI demo) · 30%*
**Stadiu:** prototip de non-membership pe prag; NU în pipeline, NU zero-knowledge, NU semantic sub encoder default.

**Ce merge:** commitment Merkle binar cu domain-separation (commitment.py:14-39, închide echivocare de mărime + forjare); verificare legată de corpus comis (re-comite + excepție pe rădăcină schimbată); proof-uri incluziune testate; MAC HMAC opțional; 40 passed/1 skipped.

**Gap-uri:** NU conectat la runtime (`ComplyGuard` doar în teste); NU zero-knowledge (iterează embeddings cleartext); encoder default NON-semantic (SHA-256 al string-ului exact → matching byte-exact, „garanția semantică e vacuă"); pasul Z3 nu adaugă soundness (scalare NumPy ca `IntVal` constante, fără variabile libere — „z3_confirmed e teatru"); fără calibrare prag 0.85.

**Onestitate:** „ZK semantic non-membership" e MISNOMER (nici ZK, nici semantic sub default); NU „ZK proof"/„garanție semantică" fără calificative; `certificate_hash` e checksum unkeyed by default; binding-ul Merkle E genuin sound — singura parte unde implementarea = afirmația.

### L5 — attest · *prototyped-tested · 45%*
**Stadiu:** auto-atestare software Ed25519; NU în pipeline (CLI doar `attest demo`).

**Ce merge:** Ed25519 real via `cryptography` (device_key.py:121-148); semnătura acoperă întreg `{event, attestation}` ⇒ tamper-evident (signer.py:30-34); `device_id=sha256(pubkey)[:16]` legat criptografic, `verify_cert` re-derivă + respinge mismatch; respingere cert expirat; ACL Windows icacls; 18 teste (spoof/tamper/expiry).

**Gap-uri:** NU în pipeline (singur caller `run_attest_demo`); doar auto-atestare (fără PKI cross-device, fără root extern); fără TPM (`tpm_available=False` hardcodat); cheia privată NECRIPTAT pe disc (`NoEncryption()`); fără revocare/CRL/rotație; `verify_cert` cod mort în producție.

**Onestitate:** „Cryptographic attestation" = auto-atestare *software* NU hardware/TPM; „LocalCA" NU e CA trust-anchor; cripto Ed25519 e REAL (nu subestima); validează doar evenimente semnate de cheia LOCALĂ; L5 NU e în pipeline; cheia e NECRIPTATĂ (NU „keys protected at rest").

### L6 — offline · *prototyped-tested · 60%*
**Stadiu:** store SQLite append-only HMAC + rutare pe conectivitate + sync append-only; NU în pipeline (doar `offline demo`).

**Ce merge:** store append-only cu lanț HMAC-SHA256, `verify_chain` detectează orice rupere (local_store.py:144-248); rezoluție fail-loud a cheii (ChainConfigError); HMAC leagă fiecare coloană via JSON canonic; append concurrent-safe (RLock+BEGIN IMMEDIATE, 6 thread×25→lanț 150); sync append-only `INSERT OR IGNORE` cu status onest complete/partial/failed; router conectivitate; 29/29 teste trec.

**Gap-uri:** README mislabel „SQLite+CRDT" — codul spune „NOT a general CRDT" (sync.py:14-23); NU conectat (audit.py vorbește direct cu Postgres); ramura Postgres NU testată pe Postgres real (sync folosește SQLite ca „remote"); mismatch schemă `events` vs `guard_events`; `pg_port` default 1; fără retenție/compactare.

**Onestitate:** „CRDT" e FALS (union-by-PK cu OR IGNORE); lanțul HMAC e tamper-evident *în limita cheii* NU Merkle/semnătură (deținătorul cheii poate rescrie tot; tail-truncation indetectabil fără `expected_count`); Postgres CLAIMED dar NEVERIFICAT; L6 NU în pipeline.

### chain + compliance · *prototyped-tested · 71%*
**Stadiu:** cripto-lanțul real și bine testat; complianța = export evidență JSON NU atestare certificată; rulează peste date mock-tracer batch.

**Ce merge:** lanț HMAC-SHA256 corect tamper-evident (chain.py:190-310); modificare mid-chain/reordonare/inserție/delete-clone toate detectate; onest despre singura limită (tail-truncation cere `expected_count`/`expected_head` out-of-band); config fail-loud; append thread-safe (8×400→indici secvențiali); sink bijotel opțional aditiv fail-open (8 teste); compliance onest post-fix (CLI=regex/AST fără Z3, Rego=available-not-default, eBPF=implemented-not-wired, status=EVIDENCE_AVAILABLE); onestitate regression-guarded (test_chain.py:476-558); **agregat: 78 passed**.

**Gap-uri:** tail-truncation indetectabilă de lanț singur (niciun anchor extern conectat în repo); lanțul simetric (deținătorul secretului poate forja tot; non-repudiere doar via bijotel, off by default); strat AST CLI fail-OPEN (`except` gol→`[]` dacă Tree-sitter/sqlparse lipsesc, degradează silent regex/AST la regex-only); status EVIDENCE_AVAILABLE auto-asertat NU terț; rulează peste mock.

**Onestitate:** lanțul e HMAC (simetric) NU semnătură — tamper-EVIDENT contra celor fără secret NU non-repudiabil contra writer-ului; „detects deletion" cu calificativul mid-chain-da/tail-doar-contra-count; Z3 real pentru code/tool/hw/distill sound-pe-subset NU per-event în cron; benchmark „100%" pe 5 scenarii etichetat *design target*; status = EVIDENCE_AVAILABLE/PARTIAL NU „SOC2 certified".

### teste + CI · *prototyped-tested · 72%*
**Stadiu:** suită unit/soundness puternică + CI multi-job; core de verificare bine testat, observe eBPF mock-only, fără coverage tooling.

**Ce merge:** **512 collected / 503 passed / 9 skipped** (verificat prin rulare, 2026-06-22); counts per-strat confirmate (integration 152, adversarial 71, policy 67, verify 41, comply 41, offline 29, observe 28, attest 18); soundness L3 profund Z3/SymPy-backed; tamper-evidence riguros acoperit; 3 gate-uri CI curate la HEAD (ruff/smoke/bandit); matrice CI py3.10/3.11/3.12 + postgres-ci + codeql + supply-chain + adversarial-fuzz + comply-ml-smoke; skip-uri legitime CI-acoperite.

**Gap-uri:** L1 eBPF MOCK-ONLY în teste (zero teste încarcă BPF C real); fără pytest-cov (coverage linie/branch NEMĂSURAT); CLI „verifier" denylist regex (testele înseși inventariază fals-negativele); bandit/fuzz/comply-ml NU gate-uri blocante de PR; fără mutation testing.

**Onestitate:** NU cita 504/495/9 (stale) — real 512/503/9; L3 are genuin Z3/SymPy-proven dar pe SUBSET; CLI „verify" denylist regex NU Z3; L1 eBPF MOCK-ONLY în teste; bandit gated doar via test pytest skip-abil; fără coverage tooling — orice „coverage %" = *număr de teste* + adâncime, niciodată coverage măsurat.

### ops + deploy · *in-pipeline · 68%*
**Stadiu:** cron autonom zilnic pe server Research real, single-host/single-operator; fără HA/IaC/rollout orchestrat.

**Ce merge:** cron autonom conectat (setup-cron.sh:42, cron-audit.sh:83-86); artefact real v13.4.2 (108 evenimente, 0 violări, 4.64ms/event); contract exit-code 0/1/2 defense-in-depth (orice eroare→2, niciodată traceback necapturat); HMAC fail-loud (abort+Telegram pe cheie lipsă/perms≠600/400); logica exit-code EXECUTATĂ în teste (subprocess real); release.sh gate mecanic (semver/clean-tree/main/version-sync/release-notes/pytest); **6 tag-uri anotate reale v13.3.0..v13.4.2**; docs-drift CI guard.

**Gap-uri:** single-host/single-operator, fără IaC/HA; fără rollback automation (doar `git checkout` manual); afirmații README neverificabile din repo (uptime since Mar 22, M0.7 7/7, 20+ nights — zero loguri/serie comisă); inconsistență doc/script (v13.4.0.md exit 1 vs script exit 2 — *dar e snapshot istoric corect*); ramurile clean(0)/violation(1) end-to-end nerulate; fără retenție log enforced (retain_days declarat, nimic nu prunează); release.sh interactiv (`read -p`) nerulabil în CI.

**Onestitate:** L1 al cron-ului e MOCK; „0 violări în 108 evenimente" = rulare curată peste agenți benigni NU dovadă că detecția merge în producție; L3 NU per-event în cron; politica = builtin NU OPA; afirmațiile de longevitate = *testimonial de operator* NU evidență comisă; „producție" = un server real rulează nocturn + pinguie Telegram, NU HA/IaC/rotație/retenție.

---

## 3. Ce mai avem de lucru — listă prioritizată

Tag: **`[BLOCK]`** production-blocking (onestitate-etichetă) · **`[HARD]`** hardening · **`[POLISH]`** research-polish.

| # | Item | Efort | Tag | Status |
|---|------|-------|-----|--------|
| 1 | README test-count → 512/503/9 (3 locații) | XS | `[BLOCK]` | ✅ FĂCUT 06-22 |
| 4 | L3: carve-out CLI din lista Z3 (regex/AST ≠ Z3) | S | `[BLOCK]` | ✅ FĂCUT 06-22 |
| 5 | L4 label README → „threshold non-membership over Merkle (ZK-SNM prototype)" | S | `[BLOCK]` | ✅ FĂCUT (README); rename clasă = opțional |
| 6 | README L6 „SQLite+CRDT" → „append-only HMAC (not a CRDT)" | XS | `[BLOCK]` | ✅ FĂCUT 06-22 |
| 2 | v13.4.0.md cron-with-alert / exit 1 | S | `[BLOCK]` | ❌ RESPINS (wrapper real + doc istoric) |
| 3 | Longevity claims: commit evidență SAU scope README | M | `[BLOCK]` | ⚖️ decizie deschisă |
| 7 | `bcc` ca extra opțional `[ebpf]` + doc `bpfcc-tools` | S | `[HARD]` | |
| 8 | Host Linux cu kernel headers + bcc; validează `monitor --live` end-to-end | L | `[HARD]` | |
| 9 | Retenție/compactare log în calea cron (prune peste retain_days) | S | `[HARD]` | |
| 10 | Test e2e cron-audit.sh ramurile clean(0)/violation(1) | M | `[HARD]` | |
| 11 | pytest-cov + emisie coverage în CI + floor non-blocant | S | `[HARD]` | |
| 12 | Test integrare PostgreSQL real pentru SyncEngine | M | `[HARD]` | |
| 13 | Strat AST CLI fail-closed (sau semnal degraded) când lipsesc Tree-sitter/sqlparse | S | `[HARD]` | |
| 14 | Anchor extern de head (OpenTimestamps/Rekor) în export/cron default | M | `[HARD]` | |
| 15 | Decide & documentează dacă L4/L5/L6 sunt production-wired; conectează cu teste sau marchează explicit demo/experimental | M | `[HARD]` | |
| 16 | Criptare at-rest pentru cheia privată L5 (passphrase/keyring) | M | `[HARD]` | |
| 17 | Semnătură Ed25519 peste head-ul lanțului în calea core (non-repudiere) | M | `[HARD]` | |
| 18 | Bandit job CI blocant; subset fuzz/comply-ml pe PR | S | `[HARD]` | |
| 19 | release.sh non-interactive-safe; pytest lipsă = hard failure | S | `[HARD]` | |
| 20 | Rollback automation: health-gate post-deploy + revert automat | M | `[HARD]` | |
| 21 | CI cu OPA real + harness paritate Rego-vs-builtin | M | `[POLISH]` | |
| 22 | Rego la paritate documentată SAU fence-uit experimental | H | `[POLISH]` | |
| 23 | Înlocuiește pasul Z3 decorativ din L4 sau elimină-l | S | `[POLISH]` | |
| 24 | Encoder semantic L4 default (sentence-transformers) cu teste prag reale | M | `[POLISH]` | |
| 25 | Completează uprobe TLS L1 sau elimină afirmațiile TLS | M | `[POLISH]` | |
| 26 | Mutation testing (mutmut) pe code/hw/distill_verifier | M | `[POLISH]` | |
| 27 | Rotație cheie HMAC + continuitate cross-run (master chain) | L | `[POLISH]` | |

---

## 4. Verdict

substrate-guard este, onest, **un singur strat de producție genuin — un audit nocturn tamper-evident — înconjurat de cinci straturi de bibliotecă de calitate de cercetare, bine testate, dar neconectate.** Ce rulează cu adevărat pe serverul Research în fiecare noapte e modest și solid inginerit: reia înregistrări PostgreSQL prin observe-ul *mock* (nu eBPF), le trece printr-un engine de politică builtin de 7 reguli Python (nu OPA), și le sigilează într-un lanț HMAC-SHA256 a cărui rezistență la tamper mid-chain e reală și test-backed, cu o singură limită cinstit declarată (tail-truncation cere un anchor out-of-band). Disciplina de ops — contract exit-code defense-in-depth, fail-loud pe cheie, release.sh mecanic, docs-drift guard — e partea cea mai matură și se susține la verificarea sursei. Cele patru verificatoare Z3 (code/tool/hw/distill) sunt cea mai impresionantă realizare tehnică și singura unde „verificare formală" nu e o supra-afirmare — dar sunt *sound-pe-fragment-mărginit-sau-abstain*, exersate doar de teste, niciodată per-event în producție. Restul numelor de produs (observabilitate eBPF, ZK semantic non-membership, atestare hardware, sync CRDT) descriu intenții, nu capabilități livrate: codul de dedesubt e fie mock, fie un prototip onest-documentat accesibil doar prin `… demo`, fie etichetat dincolo de ce face. Semnalul real de maturitate al proiectului nu sunt procentele, ci faptul că **docstring-urile, notele de certificat și testele de regresie de onestitate își dezmint propriile etichete de marketing** — disciplina de onestitate e încorporată în cod. Următorul lucru de construit nu e o capabilitate nouă; sunt corecțiile `[BLOCK]` care aliniază eticheta exterioară (README, numele claselor, notele de release) la ce demonstrează deja repo-ul — pentru că singurul loc unde acest proiect supra-afirmă este în cuvinte, nu în cod.
