"""CLI Command Safety Checker — regex/pattern denylist for shell commands.

Flags AI-suggested shell commands that match known-dangerous patterns. This is a
DENYLIST, not a proof: it imports no Z3 and makes no formal guarantee. A command it
passes is "not matched by any known-bad pattern", NOT "proven safe" -- an unlisted
dangerous construct passes. (The decorative Z3 wrapper was removed; this module header
previously still claimed "Z3 ... proves shell commands are safe".)
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum


class CLISafetyStatus(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"


@dataclass
class CLIViolation:
    pattern_name: str
    description: str
    matched_text: str


@dataclass
class CLISafetyResult:
    status: CLISafetyStatus
    command: str
    violations: list[CLIViolation] = field(default_factory=list)
    time_ms: float = 0.0

    @property
    def safe(self) -> bool:
        return self.status == CLISafetyStatus.SAFE

    def __str__(self) -> str:
        icon = "V SAFE" if self.safe else "X UNSAFE"
        parts = [f"{icon} — {self.command!r} ({self.time_ms:.1f}ms)"]
        for v in self.violations:
            parts.append(f"  ! {v.pattern_name}: {v.description} [{v.matched_text}]")
        return "\n".join(parts)


# ── Forbidden patterns ──────────────────────────────────────────────

DANGEROUS_PATTERNS = [
    {
        "name": "recursive_delete",
        "description": "Recursive file deletion",
        "patterns": [r"\brm\s+(-\w*r\w*|-\w*f\w*r|--recursive)", r"\brm\b.*\s+/\s*$"],
    },
    {
        "name": "root_filesystem",
        "description": "Operations targeting root filesystem",
        "patterns": [r"\brm\b.*\s+/$", r"\brm\b.*\s+/\s", r"\bdd\b.*\bof=/dev/[sh]d"],
    },
    {
        "name": "privilege_escalation",
        "description": "Privilege escalation",
        "patterns": [r"\bsudo\b", r"\bsu\s+-?\s", r"\bchmod\s+[0-7]*7[0-7]*\s"],
    },
    {
        "name": "disk_wipe",
        "description": "Disk wiping operations",
        "patterns": [r"\bdd\b.*\bif=/dev/zero", r"\bdd\b.*\bif=/dev/urandom", r"\bmkfs\b"],
    },
    {
        "name": "fork_bomb",
        "description": "Fork bomb or resource exhaustion",
        "patterns": [r":\(\)\{.*\|.*\}", r"\bfork\b.*\bwhile\b"],
    },
    {
        "name": "network_exfil",
        "description": "Data exfiltration via network",
        "patterns": [r"\bcurl\b.*-d\s*@?.*(/etc/|/home/|\.ssh)", r"\bwget\b.*--post-file"],
    },
    {
        "name": "cron_manipulation",
        "description": "Cron job manipulation",
        "patterns": [r"\bcrontab\s+-r\b", r"\bcrontab\s+-e\b"],
    },
    {
        "name": "history_tampering",
        "description": "Shell history manipulation",
        "patterns": [r"\bhistory\s+-c\b", r"\bunset\s+HISTFILE"],
    },
    {
        "name": "env_manipulation",
        "description": "Critical environment variable manipulation",
        "patterns": [r"\bexport\s+PATH=", r"\bexport\s+LD_PRELOAD="],
    },
    {
        "name": "shutdown",
        "description": "System shutdown or reboot",
        "patterns": [r"\bshutdown\b", r"\breboot\b", r"\binit\s+0\b", r"\binit\s+6\b"],
    },
    {
        "name": "pipe_to_shell",
        "description": "Piping downloads or data into bash/sh",
        "patterns": [
            r"\bcurl\b[^\n]*\|\s*(bash|sh)\b",
            r"\bwget\b[^\n]*\|\s*(bash|sh)\b",
            r"\|\s*(bash|sh)\s*(-c|\s|<)",
        ],
    },
    {
        "name": "chmod_recursive_root",
        "description": "Recursive chmod targeting filesystem root",
        "patterns": [
            r"\bchmod\s+(-R|--recursive)\s+\S+\s+/\s*$",
            r"\bchmod\s+(-R|--recursive)\s+/\s",
        ],
    },
    {
        "name": "kubectl_destructive",
        "description": "Kubernetes destructive operations",
        "patterns": [r"\bkubectl\s+delete\b", r"\bkubectl\s+drain\b"],
    },
    {
        "name": "cloud_exfil_or_wide_sync",
        "description": "Cloud CLI bulk copy/sync (exfil risk)",
        "patterns": [r"\baws\s+s3\s+(sync|cp)\b", r"\bgcloud\s+.*\brsync\b"],
    },
    {
        "name": "raw_disk_redirect",
        "description": "Redirect to block device",
        "patterns": [r">\s*/dev/sd[a-z]", r">>\s*/dev/sd[a-z]"],
    },
    {
        "name": "netcat_exec",
        "description": "Netcat / ncat with -e (bind or reverse shell)",
        "patterns": [
            r"\bnc\s+[^\n]*-e\s+",
            r"\bnetcat\s+[^\n]*-e\s+",
            r"\bncat\s+[^\n]*-e\s+",
        ],
    },
    {
        "name": "user_account_create",
        "description": "POSIX useradd with flags (new login-capable account)",
        "patterns": [
            r"\buseradd\s+-",
            r"\badduser\s+--",
        ],
    },
    {
        "name": "iptables_destructive",
        "description": "Firewall flush or permissive default policy",
        "patterns": [
            r"\biptables\s+(-F|--flush)\b",
            r"\biptables\s+-P\s+INPUT\s+ACCEPT\b",
        ],
    },
    {
        "name": "pip_insecure_install",
        "description": "pip install from plain http:// or git+http (MITM / malicious package)",
        "patterns": [
            r"\bpip3?\s+install\s+http://",
            r"\bpip3?\s+install\s+git\+http://",
        ],
    },
    {
        "name": "systemd_disable_or_mask",
        "description": "Disable or mask systemd units (SSH, audit, etc.)",
        "patterns": [
            r"\bsystemctl\s+disable\b",
            r"\bsystemctl\s+mask\b",
        ],
    },
    {
        "name": "package_manager_remove",
        "description": "Remove packages via distro package manager",
        "patterns": [
            r"\bapt-get\s+(-y\s+)?(remove|purge)\b",
            r"\bapt\s+(-y\s+)?(remove|purge)\b",
            r"\byum\s+remove\b",
            r"\bdnf\s+remove\b",
            r"\brpm\s+-e\b",
        ],
    },
    {
        "name": "mount_block_device",
        "description": "Mount raw block devices (data theft / persistence)",
        "patterns": [
            r"\bmount\s+/dev/sd[a-z0-9]+\s+",
            r"\bmount\s+/dev/nvme\d+n\d+p\d+\s+",
            r"\bmount\s+/dev/vd[a-z]\d*\s+",
        ],
    },
    {
        "name": "sed_system_paths",
        "description": "sed edits targeting /etc or /boot (config tampering)",
        "patterns": [
            r"\bsed\s+[^\n]*/etc/\S+",
            r"\bsed\s+[^\n]*/boot/\S+",
        ],
    },
    {
        "name": "docker_compose_remote_spec",
        "description": "docker compose using compose file from http(s) URL",
        "patterns": [r"\bdocker\s+compose\b.*\s-f\s+https?://"],
    },
    {
        "name": "git_clone_sensitive_target",
        "description": "git clone into /etc, /root, or bootloader paths",
        "patterns": [
            r"\bgit\s+clone\s+\S+\s+/etc\b",
            r"\bgit\s+clone\s+\S+\s+/root\b",
            r"\bgit\s+clone\s+\S+\s+/boot\b",
        ],
    },
    {
        "name": "eval_or_shell_c_remote_fetch",
        "description": "eval / shell -c / source with command substitution fetching curl or wget output",
        "patterns": [
            r"\beval\s+[\"']?\$\(curl\b",
            r"\beval\s+[\"']?\$\(wget\b",
            r"\b(?:bash|sh|dash|zsh)\s+-c\s+[\"']\$\(curl\b",
            r"\b(?:bash|sh|dash|zsh)\s+-c\s+[\"']\$\(wget\b",
            r"\bsource\s+<\s*\(\s*curl\b",
            r"\bsource\s+<\s*\(\s*wget\b",
            r"\.\s+<\s*\(\s*curl\b",
            r"\.\s+<\s*\(\s*wget\b",
        ],
    },
    {
        "name": "strace_attach_init",
        "description": "strace attached to PID 1 (init / invasive system tracing)",
        "patterns": [r"\bstrace\s+[^\n]*-p\s+1\b"],
    },
    {
        "name": "tcpdump_any_interface",
        "description": "tcpdump capture on all interfaces (wide sniffing)",
        "patterns": [r"\btcpdump\s+[^\n]*-i\s+any\b"],
    },
    {
        "name": "openssl_server_or_pkcs12_export",
        "description": "openssl TLS test server or PKCS#12 export (credential handling)",
        "patterns": [
            r"\bopenssl\s+s_server\b",
            r"\bopenssl\s+pkcs12\b[^\n]*\s-export\b",
        ],
    },
    {
        "name": "curl_or_wget_insecure_tls",
        "description": "curl/wget TLS verification disabled (MITM risk)",
        "patterns": [
            r"\bcurl\s+-k(\s|$)",
            r"\bcurl\s+--insecure(\s|$)",
            r"\bcurl\s+[^\n]*\s--insecure(\s|$)",
            r"\bcurl\s+[^\n]*\s-k(\s|$)",
            r"\bwget\s+[^\n]*--no-check-certificate\b",
        ],
    },
    {
        "name": "ssh_host_key_bypass",
        "description": "ssh with host key / known_hosts verification disabled",
        "patterns": [
            r"\bssh\s+[^\n]*StrictHostKeyChecking=no\b",
            r"\bssh\s+[^\n]*UserKnownHostsFile=/dev/null\b",
        ],
    },
    {
        "name": "socat_exec_or_system",
        "description": "socat EXEC or SYSTEM address (arbitrary command / shell)",
        "patterns": [
            r"\bsocat\s+[^\n]*\bEXEC:",
            r"\bsocat\s+[^\n]*\bSYSTEM:",
        ],
    },
    {
        "name": "socat_listen_fork",
        "description": "socat TCP listener with fork (concurrent binds / bind-shell style)",
        "patterns": [r"\bsocat\s+[^\n]*-LISTEN[^\n]*\bfork\b"],
    },
    {
        "name": "chmod_loose_ssh_material",
        "description": "Overly permissive chmod on .ssh paths or SSH key files",
        "patterns": [
            r"\bchmod\s+[^\n]*(?:777|666)\s+[^\n]*\.ssh",
            r"\bchmod\s+[^\n]*(?:777|666)\s+[^\n]*authorized_keys\b",
            r"\bchmod\s+[^\n]*(?:777|666)\s+[^\n]*id_rsa\b",
            r"\bchmod\s+[^\n]*(?:777|666)\s+[^\n]*id_ed25519\b",
        ],
    },
    {
        "name": "docker_run_privileged",
        "description": "docker run with full host privileges",
        "patterns": [r"\bdocker\s+run\b[^\n]*\s--privileged\b"],
    },
    {
        "name": "docker_run_host_namespaces",
        "description": "docker run sharing host PID or network namespace",
        "patterns": [
            r"\bdocker\s+run\b[^\n]*--pid=host\b",
            r"\bdocker\s+run\b[^\n]*\s--network\s+host\b",
            r"\bdocker\s+run\b[^\n]*--network=host\b",
        ],
    },
    {
        "name": "nsenter_init",
        "description": "nsenter targeting PID 1 (host namespaces / breakout)",
        "patterns": [
            r"\bnsenter\s+[^\n]*-t\s+1\b",
            r"\bnsenter\s+[^\n]*--target\s+1\b",
        ],
    },
    {
        "name": "iptables_nat_redirect",
        "description": "iptables NAT REDIRECT/DNAT (traffic interception / forwarding)",
        "patterns": [
            r"\biptables\s+-t\s+nat\s+[^\n]*-j\s+REDIRECT\b",
            r"\biptables\s+-t\s+nat\s+[^\n]*-j\s+DNAT\b",
        ],
    },
    # ── D3 expansion (audit 2026-07-17 item #16): secure-erase + setuid class ──
    {
        "name": "secure_erase",
        "description": "Irreversible secure-wipe / filesystem-signature destruction",
        "patterns": [
            r"\bshred\b",
            r"\bwipefs\b",
            r"\bblkdiscard\b",
            r"\bmkswap\s+/dev/",
            r"\bscrub\b\s+[^\n]*/dev/",
        ],
    },
    {
        "name": "file_truncate",
        "description": "Zero-length file truncation (log/evidence wiping via coreutils truncate)",
        "patterns": [
            r"\btruncate\s+(-s|--size)\s*=?\s*0\b",
            r"\btruncate\s+[^\n]*(-s|--size)\s*=?\s*0\b",
        ],
    },
    {
        "name": "setuid_setgid_bit",
        "description": "Grant setuid/setgid bit (privilege-escalation persistence)",
        "patterns": [
            r"\bchmod\s+[^\n]*[ugao]*\+s\b",              # chmod u+s / g+s / +s
            r"\bchmod\s+(?:-\w+\s+)*[24678]\d{3}\b",      # chmod 4755 / 2755 / 6755 (leading setid digit)
            r"\bchmod\s+(?:-\w+\s+)*[24678]\d{3}\s",
        ],
    },
    {
        "name": "capabilities_grant_escalation",
        "description": "Grant escalation-capable Linux file capabilities",
        "patterns": [
            r"\bsetcap\s+[^\n]*cap_setuid\b",
            r"\bsetcap\s+[^\n]*cap_sys_admin\b",
            r"\bsetcap\s+[^\n]*cap_dac_override\b",
            r"\bsetcap\s+[^\n]*=ep\b",
        ],
    },
]


def _structural_cli_violations(command: str) -> list[CLIViolation]:
    """AST-first checks (bash Tree-sitter, Python ``ast``) when dependencies allow.

    FAIL-CLOSED (audit 2026-07-17 item #17): when the AST layer is AVAILABLE but
    throws while scanning a specific command, that command is treated as UNSAFE --
    an input that crashes the parser is exactly where a denylist must not fall open
    (a crafted string could evade the regex list AND crash the AST scan). A missing
    tree-sitter dependency is a deployment-config state, not a per-command signal,
    so it degrades to regex-only rather than flagging every command.
    """
    try:
        from substrate_guard.ast_parse.safety_checker import structural_scan

        return [
            CLIViolation(
                pattern_name=sv.rule,
                description=sv.description,
                matched_text=sv.matched_text[:400],
            )
            for sv in structural_scan(command)
        ]
    except Exception as e:
        try:
            from substrate_guard.ast_parse.parser import tree_sitter_bash_available

            ast_available = tree_sitter_bash_available()
        except Exception:
            ast_available = False
        if ast_available:
            return [CLIViolation(
                pattern_name="unparseable_shell",
                description=(
                    f"AST structural scan failed ({type(e).__name__}); command "
                    "treated as unsafe (fail-closed)"
                ),
                matched_text=command[:400],
            )]
        return []


class CLIVerifier:
    """Verify CLI commands against dangerous patterns.

    **AST-first (Bijuteria #5):** :func:`structural_scan` runs first — bash
    (Tree-sitter), Python ``ast``, SQL ``sqlparse``, JSON ``json``, YAML (``pyyaml`` / ``safe_load``).
    Then a regex denylist runs: the command is SAFE iff there is no structural hit
    and no regex pattern matches.

    This is structural-AST + regex denylist matching, NOT an SMT proof. (A prior
    version wrapped the concrete regex outcomes in a Z3 ``BoolVal`` SAT check with no
    free variables; it could not change the regex+AST verdict, so the decorative
    solver was removed.) See docs/AUDIT_COMPLEX_2026-06-07.md (P0/P4).
    """

    def __init__(self, patterns: list[dict] | None = None):
        self.patterns = patterns or DANGEROUS_PATTERNS

    def verify(self, command: str) -> CLISafetyResult:
        """Verify a single CLI command."""
        t0 = time.time()
        structural = _structural_cli_violations(command)
        violations = list(structural)

        # Regex denylist: a command is unsafe iff it matches any dangerous pattern.
        for pat_def in self.patterns:
            for regex in pat_def["patterns"]:
                m = re.search(regex, command)
                if m:
                    violations.append(CLIViolation(
                        pattern_name=pat_def["name"],
                        description=pat_def["description"],
                        matched_text=m.group(),
                    ))
                    break

        elapsed = (time.time() - t0) * 1000
        status = CLISafetyStatus.UNSAFE if violations else CLISafetyStatus.SAFE
        return CLISafetyResult(
            status=status,
            command=command,
            violations=violations,
            time_ms=elapsed,
        )

    def verify_batch(self, commands: list[str]) -> list[CLISafetyResult]:
        """Verify multiple commands."""
        return [self.verify(cmd) for cmd in commands]


def verify_cli(command: str) -> CLISafetyResult:
    """One-shot CLI command verification."""
    return CLIVerifier().verify(command)
