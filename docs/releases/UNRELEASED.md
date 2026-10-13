# Unreleased — tool checker rebuilt (R3 pattern hygiene → R1 verdict fidelity → R2 exhaustive instantiation)

Draft release notes for the commits of 2026-10-13/14 on `main`. Rename to `vX.Y.Z.md` when
the version is chosen (`scripts/release.sh` requires `docs/releases/vX.Y.Z.md`).

## Why

A 77-tool labelled corpus (Step 0, 2026-10-13) showed that the Z3 string-theory tool verifier
decided nothing that exhaustive instantiation of the typed parameters did not decide in
microseconds, cost 243 s (p90 15 s), reported Z3 `unknown` as UNSAFE, and flipped five
verdicts between a 300 ms and a 5000 ms budget. Its keyword list (`/` for "root access",
`WHERE`, `10.`) produced almost all false positives.

## What changed

- **`substrate_guard/tool_verifier.py` rewritten.** Three engines chosen from the template's
  placeholders: `enumeration` (every placeholder bound to an enum / bool / bounded int,
  product ≤ 20,000 — exact), `witness` (a free string or orphan `{name}` placeholder: UNSAFE
  by construction against every literal pattern, with a replayable, admissible witness, no
  solver; matcher patterns `unchecked`), `z3` (unbounded ints or
  over-cap finite domains; digit-free keywords decided exactly without the solver, the rest
  through Z3 with a fair budget slice per pattern and a leftover pass).
- **Verdict contract.** UNSAFE only with a concrete witness (instantiated operation + pattern
  + literal + parameter assignment, replayable, within the declared domains); SAFE only with
  complete coverage; otherwise UNKNOWN with a machine-readable `reason` (`timeout`,
  `z3_unknown`, `no_keyword`, `unchecked`, `domain_too_large`, `no_template`,
  `template_unparsed`, `unmodeled_param`, `pattern_unsupported`, `no_patterns`). Lowering
  `timeout_ms` never flips SAFE↔UNSAFE; `timeout_ms` is a wall-clock budget for the whole
  call; `remaining ≤ 0` never reaches the solver (Z3 `timeout=0` means *no* limit).
  `forbidden=[]` is UNKNOWN(`no_patterns`), not a vacuous SAFE.
- **Template parsing fails closed**: `{n:03d}`, `{p!r}`, `{a.b}`, `{{`, unbalanced braces →
  `template_unparsed`. `${VAR}` / `$VAR` with no declared parameter stay literal (shell
  expansion); a bare `{name}` with no parameter is attacker-controlled.
- **Default lists (`STANDARD_FORBIDDEN`).** Removed: `root_access` (`/`), `rmdir`,
  `internal_network` and `credential_exfil` (the last two exported as opt-in lists —
  `INTERNAL_NETWORK_FORBIDDEN`, `CREDENTIAL_FORBIDDEN` — because they flag every local
  service / authenticated API call). Added: `db_privilege`, `store_flush`, `cloud_metadata`,
  `cloud_destructive`, `cloud_privilege`, `container_destructive`, `vcs_destructive`,
  `process_kill`; `rm -R`, `no-preserve-root`, `-delete`, `--delete`, `-exec rm`, `shred`,
  `chmod 0777 / u+s / +s`. SQL patterns are case-insensitive. Command literals are anchored
  at a separator (space, quote, `;`, `&`, `|`, `(`, backtick) so `gosu`/`pseudo` do not match
  while `"su root` / `;rm -rf` do. The L2 regex + structural CLI denylist is bridged as the
  `cli_denylist` matcher pattern (concrete operations only). Deliberate over-approximations
  are stated in each pattern's description (`DELETE FROM` with or without WHERE, `TRUNCATE `
  incl. coreutils, `rm -r` on any path, ` --delete ` incl. `git branch --delete`).
- **Known gaps of a literal checker** (pinned in the benchmark's known-FN table): a pid
  range (`kill -{sig} {pid}`), SQL column assignment (`SET role='admin'`), `rmdir`. Tools with
  unbounded ints or > 20,000 operations can no longer be SAFE under the default set (the
  matcher is `unchecked` / `domain_too_large`); Z3 on `IntToStr` is slow and often `unknown`
  for digit-bearing keywords — declare bounds to get exact enumeration.
- **Per-event (`perevent_verify.py`).** TIMEOUT vs ABSTAIN decided by the verifier's `reason`
  (elapsed-time heuristic kept only for verifiers without one); `REFUTED` detail carries
  `pattern: literal in operation`; UNKNOWN detail names the undecided pattern; chain events
  gain `engine` (and `z3_version` when the z3 engine was selected). `PerEventVerifier`
  pays the one-time z3 / L2 imports at construction, not inside the first verdict.
- **CLI.** `substrate-guard verify` was unreachable for every type (`--command` shared the
  subparser dest); the tool branch dropped `operation_template` (always UNKNOWN). Now:
  `--categories {filesystem,database,network,cloud,cli}` (default = library default), exit
  codes 0 SAFE / 1 UNSAFE / 2 UNKNOWN / 3 invalid input for `--type tool` (code/cli stay 0/1;
  argparse usage errors keep argparse's exit 2),
  JSON-schema spellings accepted (`integer`, `boolean`, `minimum`, `maximum`, `type: string`
  + `enum`), stdout tolerant of a cp1252 console.
- **Distill (`distill_verifier.py`, separate commit).** A Z3 `unknown` on an expression step
  is now `UNCHECKED` (→ `INCONCLUSIVE`), no longer `INVALID` — that was a REFUTED without a
  counterexample that depended on the solver budget.
- **L2 (`cli_verifier.py`, separate commit).** `recursive_delete` matches `rm -Rf`/`-fR`/`-R`;
  `pipe_to_shell` matches `… | sh` at the end of a command and `zsh`/`dash`;
  `privilege_escalation` matches `su root` (needed `su -` or two spaces before).
- **Benchmark** (`benchmarks/run_tool_benchmark.py`) rewritten: golden engine verdicts +
  arbitrated human labels + explicit known-FN/FP table; exits 1 only on golden drift; also
  runs under pytest (`tests/test_verify/test_tool_benchmark_golden.py`).
- **Brand.** README, `docs/l3-perevent-verify.md`, `docs/AUDIT_COMPLEX.md` (dated pointer),
  `compliance.py` exports: "three Z3 verifiers (code / hw / distill) + one typed-schema tool
  checker", not "four Z3 verifiers".

## Measured

Bases differ and are stated: the "before" column is the Step-0 measurement (72 enumerable
tools, blind-consensus labels, 5000 ms); the "after" columns are all 77 tools against the
arbitrated `label_final` (the 5 free-string tools are UNSAFE on both engines).

| | Z3-only (before, Step 0) | new engine, 300 ms | new engine, 5000 ms |
|---|---|---|---|
| precision / recall / accuracy | 0.55 / 0.68 / 0.54 | 0.98 / 0.93 / 0.95 | 0.98 / 0.93 / 0.95 |
| UNKNOWN | 11 `unknown` reported UNSAFE | 0–1 (a 2,000-op tool at the edge of 300 ms) | 0 |
| SAFE↔UNSAFE flips across budgets | 5 | 0 (1 / 5 / 50 / 300 / 5000 ms) | |
| total time | 243 s | 0.9 s | 0.9 s |

Differential oracle: 60 generated tools, Z3 forced vs enumeration — 60/60 identical;
adversarial fuzz (1,400 + 950 tools over three verification rounds) and a held-out set of
113 MCP-style templates (recall 1.00, precision 0.96 — the 3 benign tools flagged are the
documented over-approximations: `git branch --delete`, `aws s3 cp`, coreutils `truncate`)
found no false SAFE and no non-replayable witness after the fixes.

## Descoped (stated, not done)

Shared wall-clock budget across `distill` steps (each step still gets the full `timeout_ms`);
`monitor()` draining per-event verdicts into
the chain; `PerEventVerifier` refusing non-`ProcessPoolExecutor` executors; a regular (NFA×KMP)
decider for digit-bearing keywords on unbounded ints; Z3 `InRe` for regex-constrained strings;
the arXiv/ARTIFACT text and the Combo A paper still describe a "Z3 Tool API verifier".
