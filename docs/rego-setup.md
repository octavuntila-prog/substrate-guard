# Policy Engine Setup

substrate-guard ships with two policy engines: a built-in Python rule
set (default, zero configuration) and an optional OPA/Rego engine for
deployments that require policy-as-code enforcement.

## Default — built-in Python rules

The built-in engine evaluates events against seven hardcoded rules
(file access patterns, dangerous commands, network exfiltration,
budget, rate limit, workspace boundary, PII patterns). No setup is
required — this is what runs if no configuration is provided.

Verify the active engine from an audit report:

```json
{
  "policy_engine": "builtin",
  "policy_engine_source": "default"
}
```

## Optional — OPA/Rego engine

The Rego engine requires the `opa` binary to be installed and on PATH.
Policies are loaded from `substrate_guard/policy/policies/` shipped
with the package.

### 1. Install OPA

Download the static binary from https://openpolicyagent.org/downloads
and place it on PATH. For Linux production hosts (Research Agency is
ARM64):

```bash
# ARM64 (Hetzner, Raspberry Pi, AWS Graviton)
curl -L -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/v0.71.0/opa_linux_arm64_static
chmod +x /usr/local/bin/opa

# AMD64
curl -L -o /usr/local/bin/opa \
  https://openpolicyagent.org/downloads/v0.71.0/opa_linux_amd64_static
chmod +x /usr/local/bin/opa
```

Verify:

```bash
opa version
which opa
```

> **Version pin:** `v0.71.0` matches `scripts/deploy.sh:206` (single
> source of truth for OPA version). If you update OPA, update both.

### 2. Activate Rego enforcement

Three ways to activate, in order of precedence (first match wins):

**Per-run (CLI flag):**
```bash
python -m substrate_guard.audit --policy rego [...]
```

**Global (environment variable):**
```bash
export SUBSTRATE_GUARD_POLICY=rego
python -m substrate_guard.audit [...]
```

**In cron (edit `scripts/cron-audit.sh`):**
```bash
export SUBSTRATE_GUARD_POLICY=rego
# ... rest of script unchanged
```

Default (no flag, no env var): built-in Python rules.

### 3. Verify activation

Check the audit report JSON for confirmation:

```json
{
  "policy_engine": "rego",
  "policy_engine_source": "cli"
}
```

`policy_engine_source` values: `cli` (flag passed), `env` (env var
set), `default` (neither).

## Rollback

To return to the built-in engine:

1. **If using CLI flag:** stop passing `--policy rego` (or pass
   `--policy builtin` explicitly).
2. **If using env var:** `unset SUBSTRATE_GUARD_POLICY` (or set to
   `builtin`).
3. **If OPA was installed for other reasons** but you want only
   built-in evaluation: leave OPA in place; the built-in engine is
   independent of OPA presence.

Verify via `policy_engine: "builtin"` in the next audit report.

## Background

The built-in Python engine and the Rego policy file cover overlapping
but not identical rule sets. The semantic gap between the two engines
is documented in the substrate-guard paper, Section 5.3.1 (Zenodo DOI:
10.5281/zenodo.19334382). In production through 13.2.x, the built-in
engine was active by default due to a hardcoded policy path that did
not resolve to any filesystem location; M1.2 (v13.3.0) makes this
choice explicit and user-configurable while preserving the same
default behavior.
