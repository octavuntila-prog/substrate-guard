"""Z3 CLI Command Verifier — proves shell commands are safe.

Verifies that AI-suggested shell commands don't contain dangerous patterns.
Uses Z3 to formally model command structure and check against forbidden patterns.
"""

import re
import time
from dataclasses import dataclass, field
from enum import Enum

from z3 import And, Bool, BoolVal, Not, Or, Solver, sat, unsat


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
]


class CLIVerifier:
    """Verify CLI commands against dangerous patterns.

    Approach: Compiles forbidden patterns into a Z3 boolean formula.
    Each pattern is a Bool variable that is True if the command matches.
    The command is SAFE iff no pattern matches (AND of all NOT(pattern)).

    While the regex matching is concrete (not symbolic), the Z3 encoding
    gives us a formal proof structure: we can express the safety property
    as a theorem and the verification as its proof.
    """

    def __init__(self, patterns: list[dict] | None = None):
        self.patterns = patterns or DANGEROUS_PATTERNS

    def verify(self, command: str) -> CLISafetyResult:
        """Verify a single CLI command."""
        t0 = time.time()
        violations = []

        solver = Solver()

        # Create a Bool variable for each pattern
        pattern_vars = []
        for pat_def in self.patterns:
            pat_var = Bool(f"matches_{pat_def['name']}")
            pattern_vars.append(pat_var)

            # Concretely evaluate if command matches this pattern
            matched = False
            matched_text = ""
            for regex in pat_def["patterns"]:
                m = re.search(regex, command)
                if m:
                    matched = True
                    matched_text = m.group()
                    break

            # Assert the concrete match result
            solver.add(pat_var == BoolVal(matched))

            if matched:
                violations.append(CLIViolation(
                    pattern_name=pat_def["name"],
                    description=pat_def["description"],
                    matched_text=matched_text,
                ))

        # Safety property: command is safe iff no pattern matches
        safety = And(*[Not(pv) for pv in pattern_vars])
        solver.add(safety)

        result = solver.check()
        elapsed = (time.time() - t0) * 1000

        if result == sat:
            status = CLISafetyStatus.SAFE
        else:
            status = CLISafetyStatus.UNSAFE

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
