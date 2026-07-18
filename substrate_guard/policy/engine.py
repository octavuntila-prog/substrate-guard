"""PolicyEngine — Evaluates AI agent actions against policy.

The built-in Python evaluator is the PRODUCTION reference (it decides the deployed
cron audit). The OPA/Rego path is OPT-IN and gated by a CI builtin<->rego parity
harness (opa v1.x); it is not the default and the flip to rego is a pending operator
decision. Set SUBSTRATE_GUARD_POLICY=rego to select it where the OPA binary exists.

Usage:
    engine = PolicyEngine("policies/")
    decision = engine.evaluate({
        "agent": {"id": "agent-7", "role": "code-generator"},
        "action": {"type": "file_write", "path": "/etc/passwd"},
        "context": {"budget_remaining": 0.50}
    })
    # decision.allowed = False
    # decision.reasons = ["write to /etc/* denied for code-generator role"]
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from substrate_guard.constants import BUILTIN_POLICY_PATH

logger = logging.getLogger("substrate_guard.policy")


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    policy_file: str = ""
    input_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "latency_ms": round(self.latency_ms, 2),
            "policy_file": self.policy_file,
        }

    @property
    def denied(self) -> bool:
        return not self.allowed


class PolicyEngine:
    """Evaluates actions against OPA/Rego policies.
    
    Args:
        policy_path: Path to .rego file or directory of .rego files
        use_opa_binary: Try to use OPA binary (faster). Falls back to
                       built-in evaluator if OPA is not installed.
        opa_binary: Path to OPA binary (default: find in PATH)
    """

    def __init__(
        self,
        policy_path: str | Path = "policies/",
        use_opa_binary: bool = True,
        opa_binary: Optional[str] = None,
    ):
        self._policy_path = Path(policy_path)
        self._opa_bin = None
        self._policies: list[Path] = []
        self._builtin_rules: list[dict] = []
        self._decision_count = 0
        self._total_latency = 0.0

        # Discover policies
        self._load_policies()

        # Try OPA binary
        if use_opa_binary:
            self._opa_bin = opa_binary or shutil.which("opa")
            if self._opa_bin:
                logger.info(f"Using OPA binary: {self._opa_bin}")
            else:
                logger.info("OPA binary not found — using built-in evaluator")

        # EXPERIMENTAL GATE (decision 2026-06-14): the OPA/Rego path is opt-in and NOT at
        # parity with the built-in engine (the production reference). Its decisions DIVERGE
        # -- see the agent_safety.rego header caveat (PII under-block; command-deny is a
        # best-effort subset; network allowlist). It also has no production consumer (the
        # cron decides with the builtin). Warn whenever it would actually decide events, so
        # it is never relied on silently. The Rego path is for operator-authored /
        # experimental policy only.
        if self._opa_bin and self._policies:
            logger.warning(
                "Policy: the OPA/Rego path (--policy rego) is EXPERIMENTAL (not the "
                "production default). It is kept at PARITY with the built-in engine on the "
                "parity-harness corpus (tests/test_policy_parity.py / the policy-parity CI "
                "job), but that is corpus-verified, NOT a formal proof of equality -- keep "
                "the parity job green before relying on --policy rego. The built-in remains "
                "the production reference."
            )

    def _load_policies(self):
        """Discover and load .rego files."""
        if self._policy_path.is_file():
            self._policies = [self._policy_path]
        elif self._policy_path.is_dir():
            self._policies = sorted(self._policy_path.glob("**/*.rego"))
            if not self._policies:
                logger.warning(
                    f"Policy directory {self._policy_path} contains no .rego files. "
                    "Falling back to built-in Python rules."
                )
        else:
            # Two cases distinguished:
            #   1. Sentinel BUILTIN_POLICY_PATH — by-design fallback to Python rules (INFO)
            #   2. Real path provided but missing — genuine misconfiguration (WARNING)
            if str(self._policy_path) == BUILTIN_POLICY_PATH:
                logger.info(
                    "No Rego policy configured. Using built-in Python rules."
                )
            else:
                logger.warning(
                    f"Policy path {self._policy_path} not found. "
                    "Falling back to built-in Python rules."
                )
        
        logger.info(f"Loaded {len(self._policies)} policy file(s)")

        # Always load built-in rules as baseline
        self._builtin_rules = _BUILTIN_RULES.copy()

    def evaluate(self, input_data: dict) -> PolicyDecision:
        """Evaluate an action against all loaded policies.
        
        Args:
            input_data: Dict with agent/action/context structure:
                {
                    "agent": {"id": "...", "role": "..."},
                    "action": {"type": "...", ...},
                    "context": {"budget_remaining": ..., ...}
                }
        
        Returns:
            PolicyDecision with allowed/denied and reasons
        """
        start = time.perf_counter()
        
        if self._opa_bin and self._policies:
            decision = self._evaluate_opa(input_data)
        else:
            decision = self._evaluate_builtin(input_data)

        elapsed = (time.perf_counter() - start) * 1000
        decision.latency_ms = elapsed
        decision.input_data = input_data
        
        self._decision_count += 1
        self._total_latency += elapsed

        return decision

    def evaluate_event(self, event) -> PolicyDecision:
        """Evaluate an Event object (from observe layer) against policies.
        
        Converts Event to OPA input format automatically.
        """
        from ..observe.events import FileEvent, NetworkEvent, ProcessEvent

        meta = getattr(event, "metadata", None) or {}
        input_data = {
            "agent": {
                "id": event.agent_id,
                "role": meta.get("role", "unknown"),
            },
            "action": {
                "type": event.type.value,
            },
            "context": {
                "timestamp": event.timestamp,
                "pid": event.pid,
                "uid": event.uid,
                "comm": event.comm,
            }
        }
        # Live-state rules (budget_enforcement, rate_limiting) fire ONLY when the
        # event carries the state in its metadata. The retrospective DB-batch cron
        # path does not populate it, so those 2 of 7 rules stay inert there BY DESIGN
        # (not silently disabled) -- they are reachable on a live path that sets
        # event.metadata["budget_remaining"] / ["api_calls_last_minute"].
        for _k in ("budget_remaining", "api_calls_last_minute"):
            if _k in meta:
                input_data["context"][_k] = meta[_k]

        if isinstance(event, FileEvent):
            input_data["action"]["path"] = event.path
            input_data["action"]["flags"] = event.flags
            input_data["action"]["bytes_count"] = event.bytes_count
        elif isinstance(event, NetworkEvent):
            input_data["action"]["remote_ip"] = event.remote_ip
            input_data["action"]["remote_port"] = event.remote_port
            input_data["action"]["domain"] = event.domain
        elif isinstance(event, ProcessEvent):
            input_data["action"]["filename"] = event.filename
            input_data["action"]["command"] = " ".join(str(a) for a in event.args)

        return self.evaluate(input_data)

    def batch_evaluate(self, events: list) -> list[PolicyDecision]:
        """Evaluate a batch of events."""
        return [self.evaluate_event(e) for e in events]

    @property
    def active_engine(self) -> str:
        """The engine that ACTUALLY decides events at runtime: 'opa' only when the
        OPA binary is present AND .rego policies were loaded; otherwise 'builtin'.
        Distinct from the *requested* mode -- a `--policy rego` run on a host without
        the OPA binary still decides with the builtin Python rules."""
        return "opa" if (self._opa_bin and self._policies) else "builtin"

    @property
    def stats(self) -> dict:
        avg = (self._total_latency / self._decision_count
               if self._decision_count > 0 else 0)
        return {
            "decisions": self._decision_count,
            "avg_latency_ms": round(avg, 2),
            "total_latency_ms": round(self._total_latency, 2),
            "policy_files": len(self._policies),
            "builtin_rules": len(self._builtin_rules),
            "using_opa_binary": self._opa_bin is not None,
        }

    # --- OPA binary evaluation ---

    def _evaluate_opa(self, input_data: dict) -> PolicyDecision:
        """Evaluate using the OPA binary subprocess.

        FAIL-SAFE CAVEAT: the deny-by-default guarantee lives in the loaded policy
        BUNDLE, not in this code. The shipped ``policies/agent_safety.rego`` declares
        ``default allow := false`` -- a malformed / type-confused input matches no allow
        rule and is denied. A CUSTOM bundle loaded via ``--policy`` that omits its own
        ``default allow := false`` would fail OPEN on such input. (This engine still
        defaults ``allow`` to False if OPA returns no ``allow`` key, and falls back to
        the hardened built-in evaluator on any OPA error/timeout -- itself
        deny-by-default -- but the Rego default is the operator's responsibility.)
        """
        try:
            # `opa eval -I` ALREADY wraps stdin as the `input` document, so passing
            # {"input": input_data} double-wrapped it -> every rule saw `input.input.*`,
            # matched nothing -> allow=false / deny=[] for EVERY action (the whole
            # --policy rego path silently over-blocked, denying even legitimate
            # /workspace writes). Pass input_data raw. (Pre-existing; surfaced by the M-a
            # re-verification with a real OPA binary.)
            input_json = json.dumps(input_data)
            
            # Combine all policy files
            policy_args = []
            for p in self._policies:
                policy_args.extend(["-d", str(p)])

            result = subprocess.run(
                [self._opa_bin, "eval", "-I", "--format", "raw",
                 *policy_args,
                 "data.substrate_guard.agent_policy"],
                input=input_json,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                logger.warning(f"OPA eval failed: {result.stderr}")
                return self._evaluate_builtin(input_data)

            opa_result = json.loads(result.stdout) if result.stdout.strip() else {}
            
            allow = opa_result.get("allow", False)
            deny_msgs = opa_result.get("deny", [])
            
            if isinstance(deny_msgs, set):
                deny_msgs = list(deny_msgs)

            return PolicyDecision(
                allowed=allow and len(deny_msgs) == 0,
                reasons=deny_msgs if deny_msgs else ([] if allow else ["denied by default"]),
                policy_file=str(self._policies[0]) if self._policies else "",
            )

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            logger.warning(f"OPA evaluation failed: {e}. Falling back to built-in.")
            return self._evaluate_builtin(input_data)

    # --- Built-in Python evaluator ---

    def _evaluate_builtin(self, input_data: dict) -> PolicyDecision:
        """Evaluate using built-in Python rules (no OPA dependency)."""
        deny_reasons = []

        # Fail-safe on a non-dict container (evaluate("x") / a JSON string or array);
        # input_data.get() would otherwise raise AttributeError.
        if not isinstance(input_data, dict):
            return PolicyDecision(
                allowed=False,
                reasons=["malformed policy input (expected a JSON object)"],
                policy_file="builtin",
            )

        # Defensive: malformed-but-valid JSON can make these non-dicts (e.g. a string
        # `action`); coerce so the rules' .get() / string ops do not crash.
        action = input_data.get("action", {})
        agent = input_data.get("agent", {})
        context = input_data.get("context", {})
        if not isinstance(action, dict):
            action = {}
        if not isinstance(agent, dict):
            agent = {}
        if not isinstance(context, dict):
            context = {}

        # Fail-safe on TYPE CONFUSION: the rules gate on action.type and substring-match
        # string fields, so an evasive value slips past every `x in (...)` check and is
        # silently ALLOWED. NON-ENUMERATED (an earlier per-field list missed `filename`):
        # the gating type must be a clean non-empty string, and NO action field may be a
        # structured (list/dict) value -- str(["rm","-rf","/"]) lacks the literal
        # substring. Scalar-but-wrong types (path=12345) are caught by the per-rule
        # try/except below.
        atype = action.get("type")
        if "type" in action and not (isinstance(atype, str) and atype):
            deny_reasons.append("malformed or missing action.type (cannot classify)")
        for _k, _v in action.items():
            if isinstance(_v, (list, dict)):
                deny_reasons.append(f"malformed action.{_k} (structured value not allowed)")

        for rule in self._builtin_rules:
            try:
                reason = rule["check"](action, agent, context)
            except Exception as e:
                # A rule must not crash the evaluator on a malformed field. Fail SAFE:
                # treat an unevaluable rule as a denial, not a silent pass.
                logger.warning("Policy rule %s errored on input: %s", rule.get("name", "?"), e)
                reason = f"policy rule {rule.get('name', '?')} could not evaluate input (malformed)"
            if reason:
                deny_reasons.append(reason)

        return PolicyDecision(
            allowed=len(deny_reasons) == 0,
            reasons=deny_reasons,
            policy_file="builtin",
        )


# =============================================
# Built-in rules (Python equivalent of Rego)
# =============================================

def _check_dangerous_paths(action, agent, context) -> Optional[str]:
    """Deny writes to system directories and reads of critical files."""
    action_type = action.get("type", "")
    raw_path = action.get("path", "")
    # Canonicalize so `//etc/passwd`, `/etc/../etc/passwd`, or a trailing space cannot
    # bypass the exact-string / prefix matches below. POSIX-deterministic, no FS access.
    import posixpath
    import re as _re
    path = posixpath.normpath(_re.sub(r"/{2,}", "/", (raw_path or "").strip()))

    # Specific critical files — deny ALL access (read, write, open)
    critical = {"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"}
    if path in critical and action_type in ("file_write", "file_read", "file_open"):
        return f"Access to critical file {raw_path} denied"
    
    # System directories — deny writes
    if action_type not in ("file_write", "file_open"):
        return None
    
    forbidden = [
        "/etc/", "/root/", "/boot/", "/dev/", "/proc/", "/sys/",
        "/var/log/", "/usr/bin/", "/usr/sbin/", "/sbin/",
    ]
    for prefix in forbidden:
        if path.startswith(prefix):
            return f"File access to {prefix}* denied for agent {agent.get('id', '?')}"
    
    return None


def _check_dangerous_commands(action, agent, context) -> Optional[str]:
    """Deny dangerous command patterns."""
    if action.get("type") != "process_exec":
        cmd = action.get("command", "")
        if not cmd:
            return None
    else:
        cmd = action.get("command", "")
    
    filename = action.get("filename", "")
    
    patterns = {
        "rm -rf": "Recursive force delete",
        "rm -fr": "Recursive force delete",
        "DROP TABLE": "Database table drop",
        "DROP DATABASE": "Database drop",
        "chmod 777": "World-writable permission",
        "chmod -R 777": "Recursive world-writable permission",
        "> /dev/sda": "Disk wipe",
        "dd if=": "Raw disk write",
        "mkfs": "Filesystem format",
        ":(){ :|:& };:": "Fork bomb",
        "curl|sh": "Remote code execution",
        "curl | sh": "Remote code execution",
        "wget|sh": "Remote code execution",
        "wget | sh": "Remote code execution",
    }
    
    check_str = f"{filename} {cmd}".lower()
    for pattern, description in patterns.items():
        if pattern.lower() in check_str:
            return f"Dangerous command blocked ({description}): {cmd[:80]}"
    
    # Pipe-to-shell detection: any download tool piped to any shell
    import re
    if re.search(r'(curl|wget|fetch)\b.*\|\s*(sh|bash|zsh|dash|python|perl|ruby)', 
                 check_str):
        return f"Dangerous command blocked (Remote code execution via pipe): {cmd[:80]}"
    
    # Sudo escalation
    if "sudo" in check_str and agent.get("role") != "admin":
        return f"Privilege escalation (sudo) denied for role {agent.get('role', '?')}"
    
    return None


def _check_network_exfiltration(action, agent, context) -> Optional[str]:
    """Deny connections to suspicious ports/IPs."""
    if action.get("type") not in ("network_connect", "network_send"):
        return None
    
    port = action.get("remote_port", 0)
    ip = action.get("remote_ip", "")

    # Cloud metadata endpoint — a classic SSRF / credential-exfil target. NORMALIZE via
    # ipaddress so textually-different forms of the SAME address (IPv6 expanded /
    # uppercase / zero-padded, leading/trailing whitespace) cannot bypass a string match.
    if isinstance(ip, str) and ip.strip():
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip.strip().strip("[]"))
            # Fold an IPv6 transition encoding of an IPv4 host to its IPv4 -- the SAME
            # host must not bypass the metadata deny: IPv4-mapped (::ffff:a.b.c.d, what a
            # dual-stack getpeername() returns) and IPv4-compatible (::a.b.c.d, high 96
            # bits zero).
            if addr.version == 6:
                if addr.ipv4_mapped is not None:
                    addr = addr.ipv4_mapped
                elif 0 < int(addr) <= 0xFFFFFFFF:
                    addr = ipaddress.ip_address(int(addr))
            _meta = {
                ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure IMDS
                ipaddress.ip_address("169.254.170.2"),     # AWS ECS task-credentials
                ipaddress.ip_address("100.100.100.200"),   # Alibaba Cloud
                ipaddress.ip_address("192.0.0.192"),       # Oracle OCI
                ipaddress.ip_address("fd00:ec2::254"),     # AWS IPv6 IMDS
            }
            # Explicit metadata endpoints OR any link-local address -- IPv4 169.254.0.0/16
            # (the AWS/GCP/Azure/ECS metadata family) AND IPv6 fe80::/10. Link-local egress
            # is almost never legitimate for an agent (classic SSRF/exfil vector). The v6
            # case was previously missed here; closed 2026-07-18 symmetrically with the Rego.
            if addr in _meta or addr.is_link_local:
                return f"Connection to cloud metadata / link-local IP {ip.strip()} denied"
        except ValueError:
            pass  # not a parseable IP literal -> the port checks below still apply

    suspicious_ports = {4444, 5555, 6666, 8888, 31337, 12345, 9001}
    if port in suspicious_ports:
        return f"Connection to suspicious port {port} denied"
    
    # Block reverse shell ports
    if port < 1024 and port not in {80, 443, 53, 22}:
        domain = action.get("domain", "")
        if not domain:  # No known domain = suspicious low port
            return f"Connection to low port {port} without known domain denied"
    
    return None


def _check_budget(action, agent, context) -> Optional[str]:
    """Deny actions when budget is exhausted."""
    budget = context.get("budget_remaining")
    if budget is not None and budget <= 0:
        return f"Agent {agent.get('id', '?')} budget exhausted (${budget:.2f} remaining)"
    return None


def _check_rate_limit(action, agent, context) -> Optional[str]:
    """Deny when API call rate exceeds limit."""
    calls = context.get("api_calls_last_minute", 0)
    limit = context.get("rate_limit", 100)
    if calls > limit:
        return f"Rate limit exceeded: {calls}/{limit} calls/minute for agent {agent.get('id', '?')}"
    return None


def _check_workspace_boundary(action, agent, context) -> Optional[str]:
    """File writes must be within /workspace/ (or configured boundary)."""
    if action.get("type") != "file_write":
        return None
    path = action.get("path", "")
    workspace = context.get("workspace", "/workspace/")
    
    # Allow workspace and /tmp (path prefix check, not mkstemp — policy sandbox)
    if path.startswith(workspace) or path.startswith("/tmp/"):  # nosec B108
        return None
    
    # Everything else is denied for non-admin agents
    if agent.get("role") != "admin":
        return f"File write outside workspace denied: {path}"
    return None


def _check_pii_patterns(action, agent, context) -> Optional[str]:
    """Basic PII detection in action content."""
    import re
    content = json.dumps(action)
    
    # SSN pattern
    if re.search(r'\b\d{3}-\d{2}-\d{4}\b', content):
        return "Potential SSN detected in action"
    
    # Credit card pattern (basic Luhn-eligible)
    if re.search(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', content):
        return "Potential credit card number detected in action"
    
    return None


_BUILTIN_RULES = [
    {"name": "dangerous_paths", "check": _check_dangerous_paths},
    {"name": "dangerous_commands", "check": _check_dangerous_commands},
    {"name": "network_exfiltration", "check": _check_network_exfiltration},
    {"name": "budget", "check": _check_budget},
    {"name": "rate_limit", "check": _check_rate_limit},
    {"name": "workspace_boundary", "check": _check_workspace_boundary},
    {"name": "pii_patterns", "check": _check_pii_patterns},
]
