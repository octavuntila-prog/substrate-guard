# OPA/Rego parity gate (L2 activation)

The built-in Python policy engine (`substrate_guard/policy/engine.py`) is the
production reference. The Rego bundle (`substrate_guard/policy/policies/`) is a
port. Before production can be flipped to Rego (`SUBSTRATE_GUARD_POLICY=rego`), the
two engines must agree on real traffic — otherwise the flip could **silently invert**
an allow/deny decision. `tests/test_policy_parity.py` is the gate that enforces this.

## OPA version

The rego uses `import rego.v1`, so it runs natively on **opa v1.x** (verified on
v1.18.2). The earlier plan pinned v0.71.0 — that is **stale**; target v1.x. CI pins
`v1.18.2` and installs `opa_linux_amd64_static` from the GitHub release.

## Run the parity harness locally

```bash
# get opa v1.x (example: Linux)
curl -fsSL -o ./opa \
  https://github.com/open-policy-agent/opa/releases/download/v1.18.2/opa_linux_amd64_static
chmod +x ./opa

SUBSTRATE_GUARD_OPA_BIN=$PWD/opa REQUIRE_PARITY_OPA=1 \
  python -m pytest tests/test_policy_parity.py -v
```

Without an `opa` binary the harness **skips** (base CI); the dedicated `policy-parity`
CI job installs opa and sets `REQUIRE_PARITY_OPA=1` so a missing binary is a failure.

## How the gate works

A fixed corpus of events runs through both engines. The build is red on any
divergence **except** a small checked-in baseline (`KNOWN_DIVERGENCES`) of
deliberately-pending reconciliations. New divergence → red (a regression or an
un-ported rule). A known divergence that stops diverging → red too, prompting you
to shrink the baseline (parity progress). The Tier-2 end state is an empty baseline.

## Divergence status (2026-07-18)

Measured on the corpus, opa v1.18.2:

- **Closed:** dangerous commands where the executable token is in the process
  `filename` (e.g. exec `rm` + args `-rf /`, also `chmod 777` / `dd if=` / `mkfs`).
  The rego previously matched `input.action.command` only; it now matches the
  lowercased `filename + " " + command`, exactly like the builtin. 4 real
  under-blocks (rego was LESS safe) closed.
- **Pending baseline (deliberate reconciliation):** network **denylist vs
  allowlist**. The rego is `default allow := false` (deny network unless known-safe);
  the builtin is a denylist (allow unless suspicious IP/port/metadata). The rego
  OVER-blocks non-safe network — safe direction, but divergent. Reconciling the
  network model is a policy decision, not a silent code change; tracked as the
  remaining `KNOWN_DIVERGENCES`.

Do NOT flip production to Rego until `KNOWN_DIVERGENCES` is empty and the
`policy-parity` job is green (plan 1.B Tier-2 acceptance).
