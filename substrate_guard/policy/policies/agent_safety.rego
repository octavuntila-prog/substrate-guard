# substrate-guard Agent Safety Policy
# Package: substrate_guard.agent_policy
# 
# Evaluates AI agent actions against safety rules.
# Input: {"agent": {...}, "action": {...}, "context": {...}}
# Output: {"allow": bool, "deny": set[str]}
#
# PARITY CAVEAT (REGULA 0): the production-hardened reference is the BUILT-IN Python
# engine (substrate_guard/policy/engine.py). This Rego bundle is a best-effort port and
# does NOT carry all of the builtin's hardening. Known gaps in this revision:
#   - No path CANONICALIZATION: critical_file is exact-match, so `//etc/passwd`,
#     `/etc/../etc/passwd`, or a trailing-space variant can bypass it (the builtin
#     normalizes via posixpath before matching).
#   - IP matching is exact-string: it does NOT normalize IPv6 alternate forms of the
#     metadata address (the builtin folds ::ffff: / :: forms via the ipaddress module).
#   - No type-confusion fail-safe or pipe-to-shell regex detection.
# These rules were hand-reviewed against rego.v1 but are NOT exercised by the test suite
# (which runs the builtin via use_opa_binary=False) nor by CI (no OPA). An OPA deployment
# MUST `opa test` + validate parity before relying on `--policy rego`.

package substrate_guard.agent_policy

import rego.v1

# Deny-by-default -- the fail-safe foundation. An action matching NO allow rule
# (including malformed / type-confused input) is denied. A custom bundle that REPLACES
# this file MUST keep its own `default allow := false`, or it fails OPEN.
default allow := false

# ============================================
# ALLOW rules — explicitly permitted actions
# ============================================

# Allow file operations within workspace
allow if {
    input.action.type in {"file_write", "file_read", "file_open"}
    startswith(input.action.path, "/workspace/")
}

# Allow file operations in /tmp
allow if {
    input.action.type in {"file_write", "file_read", "file_open"}
    startswith(input.action.path, "/tmp/")
}

# Allow HTTPS connections to known-good domains
allow if {
    input.action.type == "network_connect"
    input.action.remote_port == 443
    known_safe_domain(input.action.domain)
}

# Allow DNS lookups
allow if {
    input.action.type == "network_connect"
    input.action.remote_port == 53
}

# Admin role can do anything (except what deny catches)
allow if {
    input.agent.role == "admin"
}

# ============================================
# DENY rules — hard blocks (override allow)
# ============================================

# Deny writes to system directories
deny contains msg if {
    input.action.type in {"file_write", "file_open"}
    system_path(input.action.path)
    msg := sprintf("Write to system path denied: %s", [input.action.path])
}

# Deny access to critical files
deny contains msg if {
    input.action.type in {"file_write", "file_read", "file_open"}
    critical_file(input.action.path)
    msg := sprintf("Access to critical file denied: %s", [input.action.path])
}

# Deny dangerous command patterns
deny contains msg if {
    some pattern in dangerous_patterns
    contains(input.action.command, pattern.text)
    msg := sprintf("Dangerous command blocked (%s): %s", [pattern.reason, input.action.command])
}

# Deny dangerous executables
deny contains msg if {
    input.action.type == "process_exec"
    dangerous_executable(input.action.filename)
    input.agent.role != "admin"
    msg := sprintf("Executable %s denied for role %s", [input.action.filename, input.agent.role])
}

# Deny connections to suspicious ports
deny contains msg if {
    input.action.type == "network_connect"
    suspicious_port(input.action.remote_port)
    msg := sprintf("Connection to suspicious port %d denied", [input.action.remote_port])
}

# Deny connections to cloud-metadata endpoints (SSRF / credential exfil).
# NOTE: exact-string match only -- see the IP-normalization gap in the header caveat;
# the builtin Python engine additionally normalizes IPv6 alternate forms.
deny contains msg if {
    input.action.type in {"network_connect", "network_send"}
    metadata_ip(input.action.remote_ip)
    msg := sprintf("Connection to cloud metadata IP denied: %s", [input.action.remote_ip])
}

# Deny when budget is exhausted
deny contains msg if {
    input.context.budget_remaining <= 0
    msg := sprintf("Agent %s budget exhausted", [input.agent.id])
}

# Deny when rate limit exceeded
deny contains msg if {
    input.context.api_calls_last_minute > 100
    msg := sprintf("Rate limit exceeded: %d calls/min for agent %s", 
        [input.context.api_calls_last_minute, input.agent.id])
}

# Deny privilege escalation
deny contains msg if {
    input.action.type == "process_exec"
    contains(input.action.filename, "sudo")
    input.agent.role != "admin"
    msg := sprintf("Privilege escalation denied for role %s", [input.agent.role])
}

# ============================================
# Helper functions
# ============================================

system_path(path) if startswith(path, "/etc/")
system_path(path) if startswith(path, "/root/")
system_path(path) if startswith(path, "/boot/")
system_path(path) if startswith(path, "/dev/")
system_path(path) if startswith(path, "/proc/")
system_path(path) if startswith(path, "/sys/")
system_path(path) if startswith(path, "/usr/bin/")
system_path(path) if startswith(path, "/usr/sbin/")
system_path(path) if startswith(path, "/sbin/")
system_path(path) if startswith(path, "/var/log/")

critical_file("/etc/passwd")
critical_file("/etc/shadow")
critical_file("/etc/sudoers")
critical_file("/etc/crontab")
critical_file("/etc/hosts")

known_safe_domain("api.openai.com")
known_safe_domain("api.anthropic.com")
known_safe_domain("api.cohere.ai")
known_safe_domain("www.google.com")
known_safe_domain("en.wikipedia.org")
known_safe_domain("github.com")
known_safe_domain("pypi.org")

suspicious_port(4444)
suspicious_port(5555)
suspicious_port(6666)
suspicious_port(8888)
suspicious_port(31337)
suspicious_port(12345)
suspicious_port(9001)

metadata_ip("169.254.169.254")   # AWS/GCP/Azure IMDS
metadata_ip("169.254.170.2")     # AWS ECS task-credentials
metadata_ip("100.100.100.200")   # Alibaba Cloud
metadata_ip("192.0.0.192")       # Oracle OCI
metadata_ip("fd00:ec2::254")     # AWS IPv6 IMDS

dangerous_executable(path) if contains(path, "sudo")
dangerous_executable(path) if contains(path, "su")
dangerous_executable(path) if path == "/bin/bash"
dangerous_executable(path) if path == "/bin/sh"

dangerous_patterns contains {"text": "rm -rf", "reason": "recursive force delete"} 
dangerous_patterns contains {"text": "rm -fr", "reason": "recursive force delete"}
dangerous_patterns contains {"text": "DROP TABLE", "reason": "database table drop"}
dangerous_patterns contains {"text": "DROP DATABASE", "reason": "database drop"}
dangerous_patterns contains {"text": "chmod 777", "reason": "world-writable permission"}
dangerous_patterns contains {"text": "> /dev/sda", "reason": "disk wipe"}
dangerous_patterns contains {"text": "mkfs", "reason": "filesystem format"}
dangerous_patterns contains {"text": ":(){ :|:& };:", "reason": "fork bomb"}
