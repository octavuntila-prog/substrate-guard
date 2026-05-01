"""PolicyEngine — Evaluates AI agent actions against OPA/Rego policies.

Uses OPA binary (preferred, <5ms per decision) or built-in Python
evaluator as fallback for environments without OPA installed.

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
import os
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from fnmatch import fnmatch

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

    def _load_policies(self):
        """Discover and load .rego files."""
        if self._policy_path.is_file():
            self._policies = [self._policy_path]
        elif self._policy_path.is_dir():
            self._policies = sorted(self._policy_path.glob("**/*.rego"))
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
        from ..observe.events import Event, FileEvent, NetworkEvent, ProcessEvent

        input_data = {
            "agent": {
                "id": event.agent_id,
                "role": "unknown",
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
        """Evaluate using OPA binary subprocess."""
        try:
            # Write input to temp file
            input_json = json.dumps({"input": input_data})
            
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
        
        action = input_data.get("action", {})
        agent = input_data.get("agent", {})
        context = input_data.get("context", {})
        action_type = action.get("type", "")

        for rule in self._builtin_rules:
            reason = rule["check"](action, agent, context)
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
    path = action.get("path", "")
    
    # Specific critical files — deny ALL access (read, write, open)
    critical = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab"]
    if path in critical and action_type in ("file_write", "file_read", "file_open"):
        return f"Access to critical file {path} denied"
    
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
