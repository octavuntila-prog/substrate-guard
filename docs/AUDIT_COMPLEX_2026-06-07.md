# Complex Audit — substrate-guard — 2026-06-07

**Method:** multi-agent verify-from-source audit across 9 dimensions (honesty, core
correctness, verifiers, security, crypto soundness, architecture, tests, cross-artifact,
ops). Every finding was independently adversarially verified (a skeptic tried to refute it
against the source) before it was allowed to count. 64 agents, ~3.2M tokens.

**Result:** 52 findings raised, **51 confirmed**, 1 refuted (re-confirmed under another lens).
Severity: 2 critical, ~8 high, ~15 medium, ~20 low. The #1 critical (`verify_export`) was
additionally confirmed by hand-reading `chain.py`.

> Net verdict: the honest-claims discipline is **real but unevenly applied** — the fixes the
> team already made (mock-tracer disclosure, "Z3 not exercised per-event" in summary/ISO
> exports, fail-loud HMAC chain, by-design batch `use_mock`) hold up under adversarial
> verification. But several flagship public artifacts still overclaim, two formal verifiers
> are unsound, the export-verification path is forgeable, and two cron-path data-integrity
> bugs corrupt the headline audit artifact. The architecture and most layers are sound; the
> L3 verifier soundness gaps + the compliance/benchmark overclaims are material and must be
> fixed for the "honest claims" positioning to survive reproduction.

---

## CRITICAL

### C1 — `verify_export` is forgeable WITHOUT the HMAC key (export tamper-evidence broken)
`substrate_guard/chain.py:234-261`
The in-memory `verify()` (L186) walks the chain: `if entry.prev_hash != prev_hash: return False`
and checks index sequencing. **`verify_export()` does neither** — it recomputes each entry's
hash from that entry's *own stored* `prev_hash`, never checking it links to the previous
entry, and never checking index order. The `chain_signature` only binds `head_hash + count`.
So an adversary holding only the exported JSON (no secret), keeping the last entry and the
count, can **reorder middle entries or delete-and-clone an entry** and the file still verifies
as intact. `verify_export` is the documented third-party verification path behind the SOC2/ISO
evidence — this breaks the central "tamper-evident black box" claim on the export artifact.
Tests (`tests/test_integration/test_chain.py:138-156`) only cover single-field mutation + wrong
secret, which is why it regressed undetected.
**Fix:** make `verify_export` track running `prev_hash` from `GENESIS_HASH` and reject on
`entry.prev_hash != prev_hash` and non-sequential `index`, exactly like `verify()`. Add
regression tests for reorder, internal-delete-and-clone, and index renumbering.

### C2 — ToolVerifier is unsound: ignores `operation_template`, inverts SAFE/UNSAFE
`substrate_guard/tool_verifier.py:283-328` (`_build_trigger_check`)
`_build_trigger_check` only asks "can the attacker type a dangerous keyword as a parameter
value?" — it **never references `tool.operation_template`** (the field modelling how params
become an operation). Int `min/max_value` and `pattern` never constrain anything. Result: any
tool with one free `string` param (e.g. a search `query`) is reported UNSAFE on all 10
standard patterns with nonsense counterexamples (`{'query':'rmdir'}`) — 100% false positive on
realistic tools; conversely a tool whose template is `rm -rf /{mode}` with enum `['read','list']`
is reported SAFE. The module claims it "proves mathematically that no parameter combination can
trigger a forbidden operation" — that guarantee carries no formal meaning.
`test_extreme_adversarial.py:177-188` encodes the false positive as *expected*, hiding it.
**Fix:** substitute symbolic params into `operation_template` and use Z3 string theory
(Concat/Contains) to prove the constructed string can never contain a forbidden substring,
honoring int ranges and enum/regex; OR stop returning SAFE/UNSAFE, relabel as a parameter-value
keyword denylist, and stop flagging tools UNSAFE solely for having a free string param.

---

## HIGH

- **FloorDiv/Mod → raw Z3 `/`,`%`** `ast_translator.py:366-369` — Z3 Euclidean ≠ Python floor for
  negative operands. Verified end-to-end: `def fdiv(x): return x // -2` reports the *correct*
  spec UNSAFE and the *wrong* spec VERIFIED. These verdicts flow into the HMAC chain as
  `formal_verification` entries — a wrong attestation at the highest-trust place. *Fix:* encode
  floored div/mod to match CPython, or raise `TranslationError` on negative divisors (honest scope).
- **Cron audit overwrites `event.agent_id`** `guard.py:519` (consumed `audit.py:408,450-452`) —
  `inject_and_evaluate` mutates each event to the session label `audit-full`; `unique_agents`
  always reports 1, per-agent grouping collapses, and the HMAC chain records `agent_id="audit-full"`
  for every event, erasing attribution from the tamper-evident trail. The paper's evaluation
  consumes this. *Fix:* default `agent_id` only when empty/unknown (or copy); compute
  `unique_agents` before the mutating loop; add a multi-agent `run_audit` regression test.
- **README benchmark fabricates the Resource Abuse row** `README.md:189-199` — claims 15 events /
  10 violations; the scenario (`observe/tracer.py:367-381`) injects 151 events, all ALLOWED
  (`151 / 0`). The other 4 rows match the code, so the defect is isolated. The "10 violations"
  implies rate-limit firing that the pipeline never does. *Fix:* correct to `151 / 0` with honest
  wording; re-check the "100% accuracy" headline.
- **SOC2 export hardcodes accuracy 100% / FP 0 / FN 0** `compliance.py:115-125` — static literals,
  emitted even when Z3 never ran. `cli` `false_negatives:0` is contradicted by
  `test_cli_honest_gap_inventory` (11 known-risky commands classified SAFE). The summary/ISO27001
  exports in the *same file* got the honest caveat; SOC2 CC8.1 was left bare. *Fix:* apply the
  existing "benchmark-only, NOT exercised per-event" caveat or derive from `SessionReport`; drop
  the unfounded `cli` FN:0.
- **distill drops exponents > 10** `distill_verifier.py:198-206` — `x**12 → x`, so the Z3 check runs
  on a different claim → false VALID in the exact failure mode the verifier exists to catch. *Fix:*
  mark UNCHECKED rather than VALID when the exponent can't be encoded.
- **Offline LocalStore HMAC uses a hardcoded public default key** `offline/local_store.py:23-24` —
  the offline append-only fallback's tamper-evidence is forgeable by anyone who can read the SQLite
  file; `verify_chain()` still returns valid. Violates the fail-loud discipline `AuditChain` enforces.
  *Fix:* fail loud (or explicit opt-in) when no key; remove the default; align env-var names.
- **README headline production metrics contradict every committed artifact** `README.md:22-33` —
  "79 violations / 0.54% / 0.14 ms-per-event" vs committed evidence `0 violations / 3.41 ms` (~24×
  latency discrepancy). Not derivable from anything in the tree. *Fix:* commit the backing
  `audit_*.json` and cite it, or replace with the real numbers + provenance links.
- **Audit report attributes decisions to OPA/rego when builtin ran** `audit.py:472-492` — with
  `--policy rego` on a host lacking the OPA binary (the default), the 7 builtin Python rules decide
  every event but the JSON reports `policy_engine='rego'` — misrepresenting methodology in the
  artifact meant for publication. The observe layer got a real `is_mock` check; the policy layer
  did not. *Fix:* derive the reported engine from runtime (`policy_engine_active` vs `_requested`).

---

## MEDIUM (selected)

- **budget + rate_limit (2 of 7 advertised rules) unreachable on every real event path**
  `policy/engine.py:151-186` — `evaluate_event` never sets `budget_remaining` /
  `api_calls_last_minute`; the rules fire only via the raw `evaluate(dict)` API (tests/cmd_evaluate).
  README/SOC2 present them as active controls. *Fix:* populate the context, or document dict-API-only
  and correct the "7 rules" framing.
- **Guard logs `policy(OPA)` when only builtin runs** `guard.py:292-296` — keys on whether `.rego`
  files were *discovered*, not whether OPA *ran*. *Fix:* `engine = 'OPA' if (self._policy._opa_bin and self._policy._policies) else 'builtin'`.
- **`inject_event` overwrites historical DB timestamp with wall-clock** `observe/tracer.py:200` —
  every cron event's exported chain timestamp becomes the run time, collapsing temporal provenance
  in a "flight recorder" product. *Fix:* set timestamp only when unset.
- **distill Rational/Float → `RealVal(float(...))`** `distill_verifier.py:172-176` — loses exactness on
  the symbolic path. *Fix:* `RealVal(Fraction(p,q))`, avoid `float()`.
- **SyncEngine claims PostgreSQL but SQL is SQLite-only** `offline/sync.py` — `INSERT OR IGNORE` + `?`
  + `conn.total_changes` are SQLite-only; against Postgres every row errors → silent no-op reported as
  status "complete". *Fix:* dialect-aware SQL or narrow the claim; don't report "complete" when all rows failed.
- **hw_verifier + distill_verifier (~1100 LOC) have zero enforced test coverage**; benchmark scripts
  never `sys.exit(1)` on failure, so the "100% accuracy" CI job is green even on misclassification.
- **policy_engine label, eBPF/live path, and OPA/Rego path are all untested.**
- **cron-audit.sh treats audit DB-failure exit code as policy violations** `scripts/cron-audit.sh:69-92`
  — a Postgres outage fires a false "VIOLATIONS DETECTED" Telegram alert. *Fix:* distinct exit codes
  (0 clean / 1 violations / 2 error) and branch accordingly.
- **deploy.sh host install never installs psycopg2** → first cron run can't reach Postgres → false
  violation alert. **install_full reports "eBPF enabled" editing an inert config field nothing reads.**

## LOW (selected)
- `_check_dangerous_commands` folds the agent label into the match string (latent false positives),
  `engine.py:330-345`.
- CLI verifier's Z3 layer is decorative (verdict is 100% regex), `cli_verifier.py:361-399`.
- Bash AST matches command name by exact string, so `/bin/rm` evades the structural layer,
  `ast_parse/patterns.py:37`.
- Chain/audit JSON written world-readable (sensitive DB content), `chain.py:214`.
- Merkle commitment malleable (odd-leaf duplication, no domain separation), `comply/commitment.py:51-59`.
- comply "Z3 confirmation" is a tautology over numpy-computed constants, `comply/verifier.py:76-99`.
- HMAC env-var name divergence (`GUARD_HMAC_SECRET` vs `SUBSTRATE_GUARD_HMAC_SECRET` vs `GUARD_HMAC_KEY`).
- README codebase tree lists test files that don't exist + stale LOC; changelog omits v13.3.1–v13.4.1.
- Dockerfile runs as root, unpinned base + floating deps (contradicts "reproducible").
- `DEPLOY.md`/`REPRODUCING.md` say `cd Z3-PAPER` (a directory that doesn't exist after clone).
- cron-audit.sh `.env` parsing via `export $(grep | xargs)` is fragile against spaces/special chars.
- **POSITIVE:** `comply/protocol.py:62-76` ZK-SNM is an *honest, well-labeled placeholder* — the
  certificate note admits no zero-knowledge property; claims match implementation. Recorded as
  honest-disclosure, not an overclaim (optional: rename the `protocol: ZK-SNM` field to `-prototype`).

---

## What's solid (audit-confirmed)
- **Bimodal mock/live design is sound and honestly framed** — `use_mock=True` in the cron audit is
  correct by design (batch DB replay, no live process), and the README states the live path falls
  back to mock for lack of kernel headers. Not conflated or oversold.
- **The honesty re-wording HOLDS where applied** — `export_summary` and `export_iso27001` carry the
  accurate "Z3 available but NOT exercised per-event" caveat; the mock-tracer/#38b disclosure is
  present; v13.4.1 dropped a prior unfounded "135 test cases" claim. The discipline is real; the gaps
  are parity oversights, not the norm.
- **The HMAC chain's in-memory `verify()` mechanism is robust** (index:ts:json:prev_hash linkage,
  fail-loud when no secret). NOTE: the *export* verifier is broken (C1) — distinct from the mechanism.
- **5 of 7 policy rules fire correctly** on the real event path; Malicious (4/4) and Prompt Injection
  (4/3) benchmark rows independently reproduced and match the code.
- **CodeVerifier is genuinely sound for its non-negative-arithmetic subset.**
- **vendor_bridge adapters do the right thing** (per-agent labels, preserved DB timestamps,
  `agent_ids` computed before the loop) — the bugs are in the shared inject path, not the adapters.
- **Failure modes are fail-safe, not fail-open** — no security control was found silently passing a
  dangerous action.

---

## Systemic areas flagged for deeper audit (completeness critic)
The single-verifier critical (C2) is part of a **systemic L3 soundness pattern**, and two whole
subsystems (comply, attest) plus the OPA path were under-examined:

- **Verifier suite UNKNOWN→accept antipattern:** `distill_verifier.py:543` (UNKNOWN→VALID),
  `tool_verifier.py:281` (unknown→assume safe) — at least two verifiers with the same inversion.
- **code_verifier returns VERIFIED while silently dropping unsupported constructs** (loops, bare
  Expr/calls, complex targets) — a function whose behavior depends on a dropped statement can be
  "VERIFIED."
- **hw_verifier:** branches (beq/bne/blt/bge) advertised but never implemented; unknown instructions
  silently skipped; memory unmodeled → multi-path assembly "VERIFIED" unsoundly.
- **cli_verifier:** advertised as Z3 "mathematical certainty" but implementation is pure regex.
- **comply:** Merkle without leaf/node domain separation; fake-Z3 constant check; the default
  `DeterministicFingerprinter` is SHA-256 expansion with no semantic content → non-membership/privacy
  guarantee **vacuous** under the default CI encoder.
- **attest:** self-signed "CA" (signs + verifies with the device's own key — no independent root);
  Ed25519 private key stored with `NoEncryption()` and chmod only on non-Windows → **unprotected on
  Windows** (the project's stated platform).
- **OPA path likely broken + never CI-tested:** `engine.py:219` runs `opa eval --format raw ...` then
  `.get('allow')/.get('deny')` on output that shape doesn't return; the OPA branch is exercised by nothing.
- **Role hardcoded `'unknown'`** in `evaluate_event` → admin-exemption branches dead for real events.

---

## Recommendations (priority order)
1. **CRITICAL:** fix `verify_export` (add the linkage walk) and fix-or-downgrade `ToolVerifier`.
   Add reorder/delete-clone and free-string-param regression tests.
2. **HIGH (verifier correctness):** fix FloorDiv/Mod (wrong attestation in the chain).
3. **HIGH (headline artifact):** stop overwriting `agent_id` (guard.py:519) and historical timestamp
   (tracer.py:200) in the shared inject path; compute `unique_agents` before the loop; add multi-agent
   regression tests. Restores the production audit + forensic chain the paper depends on.
4. **HIGH (honesty parity — quick string edits, zero runtime risk):** correct the README Resource
   Abuse row + headline metrics, add the existing caveat to SOC2 CC8.1 and ISO42001, fix the OPA/rego
   label.
5. **MEDIUM:** resolve budget/rate-limit reachability (or de-advertise); fix the Guard `policy(OPA)` label.
6. **SYSTEMIC:** a dedicated verifier-suite soundness pass (soundness-direction tests for all 5
   verifiers) + comply/attest crypto review + an OPA-path test.
7. **PROCESS:** a CI step that diffs `stack-benchmark`/`demo` output against the README table and the
   compliance literals, so claim-vs-code drift fails the build automatically.

---

# Part 2 — Empirical verifier-soundness probe (2026-06-07)

**Method:** a second multi-agent pass that did NOT just read the code — it CONSTRUCTED adversarial
inputs and **RAN the verifiers** (Python 3.12.10, z3 4.16.0), then a skeptic **re-ran every repro**.
36 agents. **26 holes probed, 22 confirmed, all 22 reproduced live (byte-for-byte).**

## Verdict: the L3 "mathematical certainty" claim is empirically FALSE — 5/5 Z3 verifiers unsound

One root pathology recurs across the entire suite (the single most important finding):

> **UNMODELED CONSTRUCT → SILENT DROP/DEMOTE → PROVE-ON-A-WEAKER-MODEL → REPORT VERIFIED.**

The gate (`guard.py fully_safe` L163-169, `cli.py:56`) consults only the boolean `verified` status,
which ignores the dropped-construct set — so every silently-dropped construct becomes a usable false
VERIFIED at the integration boundary. A second pathology: **fake/decorative Z3** — solver calls that
constant-fold a value Python already computed and cannot disagree with it.

### Confirmed live (representative repros)
- **code_verifier (5 holes):**
  - `verify_code('def f(x): return x // -2', spec __return__==-3)` → **VERIFIED** (wrong: Python `7//-2==-4`); the *true* spec `==-4` → UNSAFE. Z3 `/`,`%` ≠ Python floor on negatives (`ast_translator.py:366-370`). **CRITICAL.**
  - A `for` loop is silently dropped (`ast_translator.py:238-242` `return None`): `sum_to_n` with body discarded → `__return__==0` reports **VERIFIED** (true answer 10 → UNSAFE). **CRITICAL.**
  - A bare call `do_something_dangerous(x); return x` → **VERIFIED with EMPTY warnings** (not even the decorative flag fires).
- **cli_verifier (3 holes):** the Z3 step is a tautology over `BoolVal(matched)` flags (zero discriminating power); with regex+structural neutralized it certifies `rm -rf / ; dd if=/dev/zero of=/dev/sda` as **SAFE**; the AST layer is bypassed for any non-bare invocation (`/bin/rm`, `\rm`, `env rm`).
- **tool_verifier (2 holes):** ignores `operation_template` — a tool whose template is hardcoded `rm -rf /` is certified **SAFE**, while every read-only string-param tool is flagged **UNSAFE** on all 10 patterns. The SAFE verdict is meaningless in both directions.
- **distill_verifier (3 holes):** `x**12 → x` (exponent dropped) → false VALID; Z3 `unknown` → VALID; Rational → `float()` exactness collapse.
- **hw_verifier (4 holes):** advertised branches (beq/j) and div/rem never implemented; unknown opcodes silently no-op'd (`else: pass`); memory contents unmodeled → multi-path assembly VERIFIED unsoundly.
- **comply/attest (5 holes):** Merkle commitment non-binding (odd-leaf duplication collision, no leaf/node domain separation → forgeable inclusion proofs); non-membership guarantee vacuous (a paraphrase of a committed secret scores ~−0.03 → declared non-member while marketing semantic-leakage protection); comply `verify_with_z3` is a constant-fold with zero free variables; **`LocalCA.verify_cert` authenticates the WRONG key → accepts an identity-spoofing cert (CRITICAL, new vs Part 1's self-signed-CA finding).**

## Fix priorities (from the empirical pass)
- **P0 — close the universal drop-to-VERIFIED channel (one meta-fix neutralizes ~10 holes):** make any
  unmodeled construct a hard, sound abstain. `code_verifier`: if `translation.unsupported` is non-empty
  (also record bare Expr / complex targets there) → return TRANSLATION_ERROR/UNKNOWN, never VERIFIED;
  `.verified` must require empty `unsupported`. `hw_verifier`: replace `else: pass` with PARSE_ERROR or
  destination-register havoc; reject opcodes outside the documented subset. `distill_verifier`: map
  dropped exponents and Z3-unknown to UNCHECKED, treat UNCHECKED as non-ALL_VALID.
- **P1 — false-SAFE accepts (highest blast radius):** tool_verifier must substitute params into
  `operation_template` and scan the constructed operation; cli_verifier must run structural scan on
  path/wrapper-prefixed commands and tokenize split flags.
- **P2 — arithmetic semantics:** sign-correct Python floor-div/mod, div-by-zero obligations, exact
  rationals (`RatVal`, not `float()`).
- **P3 — crypto/attest binding & identity:** Merkle leaf/node domain separation (0x00/0x01) + bind leaf
  count; `LocalCA.verify_cert` must verify against the cert's embedded public key (or assert it equals
  the device key).
- **P4 — stop overclaiming:** redescribe cli/comply "Z3 proofs" as what they are; scope README/
  compliance "mathematical certainty / proves correctness" to the actually-verified subset.

## Fair credit (honest vs unsound)
The fair characterization: **substrate-guard is a competent BOUNDED checker whose modeled subset is
real, wrapped in unsound failure-handling and overstated "mathematical certainty" marketing.**
- **Credit where due:** within each verifier's modeled subset (integer linear arithmetic, no loops/
  negatives; bare known-dangerous commands; modeled RV32I straight-line opcodes; exact low-degree
  algebra) the solvers do real, correct UNSAT-based reasoning — the core SMT plumbing is legitimate.
  The HMAC chain and the concrete counterexample reporting are honest and useful. And the
  `ast_translator` docstring states the *right intent* ("supported subset … unsupported flagged, not
  silently wrong") — the failure is that the implementation contradicts it.
- **The P0 abstain-on-drop fix would make that stated intent real**, turning the code verifier honestly
  sound on its declared subset. Crediting "mathematical certainty" requires (i) sound abstain on every
  unmodeled construct, (ii) modeling the templates/memory/control-flow it claims to cover, (iii)
  correct Python/rational semantics, and (iv) scoping the public claims to the verified subset.

---

## Refuted (1)
- *[security] L6 offline HMAC silently falls back to a hardcoded default key* — the **code facts are
  accurate** but the security-dimension framing was refuted by its verifier; the SAME issue was
  **confirmed** under the crypto dimension (HIGH, see local_store.py:23-24 above). Net: it is a real
  finding; only one of two duplicate framings was rejected.

---

# Part 3 — Remediation status (2026-06-07)

All findings below were fixed verify-from-source and regression-tested (full suite **426 passed,
7 skipped**). The remediation was then **adversarially re-verified** by a 13-agent pass that re-read
each diff and attempted bypasses — which found 4 of the 10 first-round fixes were only *partial*; 3
had real residuals (verify_cert `device_id`, code nested-if, hw `verify_equivalence`) and were
subsequently **completed**. That honest second pass is why the table distinguishes "closed" from
"closed after residual-fix".

## Closed (verified)
| Finding | Fix commit(s) | Status |
|---------|---------------|--------|
| **C1** `verify_export` forgeable without the key | `a8c877d` | CLOSED — per-entry linkage + index walk; reorder/delete-clone rejected |
| **C2** ToolVerifier ignores `operation_template` | `1ca9751` | CLOSED — substitutes params into the template, checks the constructed operation |
| **LocalCA identity spoof** | `6d02143` + `3a25bf7` | CLOSED — verifies the embedded key AND binds `device_id` to its fingerprint |
| **code_verifier** drop→VERIFIED | `3b0d009` + `0a7fe02` | CLOSED — abstains on dropped constructs AND on conditional-return in if-without-else |
| **distill_verifier** unknown→VALID + dropped exponent | `7e7e9de` | CLOSED — abstain → UNCHECKED/UNPARSEABLE; INCONCLUSIVE trace status |
| **hw_verifier** silent-skip | `10ff211` + `3366b9d` | CLOSED — `verify()` AND `verify_equivalence()` abstain on unmodeled instructions |
| **FloorDiv/Mod** negative-operand semantics | `8bd22c4` | CLOSED — Python floored semantics; exhaustively checked -12..12 |
| **offline** hardcoded HMAC key | `3a864e7` | CLOSED — fail-loud; insecure default must be opted into |
| **agent_id / timestamp overwrite** | `844fa8d` | CLOSED — defaults only when unset; provenance preserved |
| **L3 "mathematical certainty" overclaims** | `6005c79` + drift-guard | scoped to bounded checking; `tests/test_integration/test_docs_drift_guard.py` fails the build on metric drift |
| **tool_verifier stale module docstring** | (docs) | CLOSED — docstring now describes the implemented operation_template modeling |

## Documented residuals (NOT closed — honest accounting)
- **chain (low):** the denormalized `ChainEntry.event_type`/`agent_id` fields are not in the hash
  payload (the `event_data` dict IS), so those two copies are mutable on an export without detection;
  shared with in-memory `verify()`. Also: rollback/replay of an older fully-valid signed export is not
  detectable (no freshness binding). Closing either needs a breaking hash/signature-format change.
- **code_verifier (low):** division by zero is left uninterpreted by Z3 (pre-existing); a spurious
  verdict is possible at `divisor == 0`.
- **tool_verifier (disclosed):** a Z3 `unknown` result falls back to *safe*; a free-string parameter is
  conservatively flagged UNSAFE on every pattern.
- **distill_verifier (cosmetic/robustness):** `_verify_evaluation` maps Z3 `unknown` → INVALID (sound
  over-reject, inconsistent with `_check_implication`); a pre-existing `AttributeError` on
  `BooleanTrue/False` simplification is a robustness bug, not a false-ALL_VALID.
- **L4 comply (ZK-SNM):** audited + partially remediated — see the dedicated section below.

## Process closure
`tests/test_integration/test_docs_drift_guard.py` asserts the README production metrics, the package
version, and the policy-rule count against their committed source-of-truth JSON (the smoke-audit /
smoke-compliance artifacts) — closing the silent-regression channel (Recommendation #7) that allowed
the original 79 / 0.54% / 0.14 ms headline drift.

## L4 comply (ZK-SNM) — audit + remediation
A 26-agent adversarial pass (empirically RUN, like Part 2) found the L4 layer's branding
far exceeds its implementation. **Confirmed-critical:** the Merkle commitment was malleable
(no leaf/node domain separation → forged inclusion; odd-leaf duplication → size-equivocation);
verification was not bound to the committed root (commit corpus A, verify a different set); a
perturbed member is certified non-member (threshold false-negative). **Confirmed-high:** the Z3
step is decorative (a constant comparison with no free variables; the verdict is independent of
it); there is no zero-knowledge (cleartext embeddings); the default encoder only catches
byte-exact duplicates.

**Fixed:** `be3d95b` domain-separates + count-binds the Merkle commitment (binding now sound);
`469a887` binds verification to the committed root and honestly relabels the claims (Z3 →
"redundant integer re-check"; README/note "Zero-knowledge compliance" → "semantic
non-membership"; threshold/encoder caveats).

**Residual (NOT closed — user's call, paper-tied):** the `ZK-SNM` class/CLI naming + the cited
paper title "ZK Proofs of Semantic Non-Membership"; `certificate_hash` → a keyed MAC; a
soundness bound for the threshold; a semantic default encoder. The deep redesign (separate
prover/verifier, a real ZK circuit) is out of scope for the prototype.
