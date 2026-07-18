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

Measured on the corpus with opa v1.18.2. **`KNOWN_DIVERGENCES` is now empty** — zero
divergences on the parity corpus (plan 1.B Tier-2, corpus-scoped). Reconciled:

- **Dangerous commands via the exec filename:** the rego matched
  `input.action.command` only, so `rm`/`chmod`/`dd`/`mkfs` slipped when the tool was
  the process `filename`. Now matches the lowercased `filename + " " + command`, like
  the builtin (4 real under-blocks — rego was LESS safe — closed).
- **Network model:** the rego was an ALLOWLIST (deny egress unless :443-known-domain
  or :53); reconciled to the builtin's DENYLIST — allow egress unless suspicious port /
  metadata-or-link-local / low port without a domain. This was an explicit **policy
  decision** (chosen: match the production reference), not a silent change.
- **IPv6 link-local (`fe80::/10`):** a gap the builtin ALSO had (it checked only IPv4
  link-local). Now denied on BOTH engines — symmetric, both safer, parity held.
- **PII:** the builtin's SSN / credit-card detection was ported to the rego.

**Honesty caveat:** this is parity **on the harness corpus**, not a formal proof of
engine equality. Expand the corpus when adding rules. A production flip to Rego is
now *unblocked by the gate* but remains an operator decision; keep `policy-parity`
green (Tier-2) as the precondition.
