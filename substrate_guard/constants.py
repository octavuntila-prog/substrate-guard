"""Constants for substrate-guard package."""

# Sentinel path that does not resolve to any filesystem location.
# Used by audit.py to trigger Python built-in fallback in PolicyEngine.
# See M1.2 Design Document, Decision D3.
BUILTIN_POLICY_PATH = "__builtin_fallback__"

# Rego policies directory (shipped with package)
# Resolved at runtime via Path(__file__).parent / "policy" / "policies"
DEFAULT_REGO_POLICIES_SUBDIR = "policy/policies"

# Valid policy modes
VALID_POLICY_MODES = frozenset({'rego', 'builtin'})

# Env var name
POLICY_ENV_VAR = "SUBSTRATE_GUARD_POLICY"
