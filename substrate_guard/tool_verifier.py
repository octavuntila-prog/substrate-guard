"""Tool-definition safety checker — exhaustive typed-schema instantiation against literal
forbidden lists, with Z3 only where enumeration is impossible.

Given a tool definition (name, typed parameters, operation_template) and a list of
forbidden patterns, decides whether ANY admissible parameter assignment makes the
CONSTRUCTED operation (the template with the parameters substituted) contain a forbidden
literal — or, for concrete-only patterns, trip a matcher such as the L2 CLI denylist.

Three engines, chosen from the template's placeholders (not from the parameter list):

* ``enumeration`` — every placeholder is bound to a finite parameter (enum, bool, or an
  int with both bounds) and the Cartesian product is at most ``max_enumeration``: all
  operations are instantiated and checked exactly. Literal patterns run first over the
  whole product; matcher patterns run afterwards over the distinct operations until the
  deadline. This is the path for typed MCP-style schemas and is exact (no abstraction).
  A parameter with a non-empty ``enum`` list is an enum whatever its declared ``type``
  (JSON Schema writes ``"type": "string", "enum": [...]``).
* ``witness`` — some placeholder is bound to a free ``string`` parameter (or to no
  parameter at all — an orphan ``{name}`` placeholder is attacker-controlled by the same
  logic): for each literal pattern the witness is built directly (the keyword is the
  parameter value), so the verdict is UNSAFE by construction, in microseconds, with a
  replayable witness. No solver is involved. Every parameter in the witness is
  admissible: a ``pattern``-constrained string gets a value matching its regex or the
  pattern is reported ``pattern_unsupported`` (UNKNOWN), never UNSAFE on an inadmissible
  witness.
* ``z3`` — every placeholder is finite-or-int but at least one int has no bounds, or the
  finite product exceeds ``max_enumeration``. A keyword that contains no digit and does
  not end in ``-`` cannot overlap an integer rendering (``-?[0-9]+``), so it is decided
  exactly by enumerating the enum/bool parameters with the ints as separators; only the
  remaining keywords go to Z3 string theory (``IntToStr`` with an explicit sign, enum/bool
  as index-selected literals, one keyword per query, a fair budget slice per pattern and a
  second pass over the leftovers). Matcher patterns cannot be evaluated symbolically and
  are reported ``unchecked`` / ``domain_too_large``.

Verdict contract (every engine):
  UNSAFE  only with a concrete witness: the instantiated operation, the pattern, the
          matched keyword/text and the parameter assignment; substituting the assignment
          into the template reproduces the operation and the match re-checks true.
  SAFE    only when every pattern was checked over the whole admissible domain.
  UNKNOWN otherwise, with a machine-readable ``reason`` (``timeout``, ``z3_unknown``,
          ``no_keyword``, ``unchecked``, ``domain_too_large``, ``no_template``,
          ``template_unparsed``, ``unmodeled_param``, ``pattern_unsupported``,
          ``no_patterns``). Lowering ``timeout_ms`` can turn SAFE or UNSAFE into
          UNKNOWN(timeout), never SAFE into UNSAFE or back. ``timeout_ms`` is a wall-clock
          budget for the whole ``verify()`` call (the one-time import of the L2 denylist,
          ~100 ms, is taken before the clock starts).

Matching is substring containment on the operation padded with one space on each side.
Command-name literals in the default lists are anchored at a separator (space, quote,
``;``, ``&``, ``|``, ``(``, backtick): ``gosu app`` does not match ``su``, while
``sh -c "su root"`` and ``ls;su root`` do. Case-insensitive patterns fold both sides per
code point (``_fold``), identically in every engine. Literal matching is not a
command-grammar parse: flags, ranges (``kill -9 {pid}`` with a pid range) and column
assignments (``SET role='admin'``) are known gaps. Deliberate over-approximations are
stated in each pattern's description; the bridged L2 denylist (``cli_denylist``) brings
its own (e.g. ``sed -i`` on ``/etc/*``, ``aws s3 cp``/``sync`` flagged as wide copies).

Template placeholders: ``{name}``, ``${name}`` and ``$name``. ``${VAR}`` / ``$VAR`` with
no declared parameter are shell expansions and stay literal; a bare ``{name}`` with no
parameter is a format-string hole and is treated as attacker-controlled. Any other brace
group (``{n:03d}``, ``{p!r}``, ``{a.b}``, ``{{``) is ``template_unparsed``.

Measured (2026-10-14, 16-core desktop): literal phase ~180 operations/ms end-to-end
with the default lists (one C-level find per keyword over the joined padded corpus:
20,000 operations x 260 keywords in ~110 ms, ~36 ms of it materialising the product);
L2 matcher 0.09–0.23 ms/operation for bash-/unknown-routed operations and 0.55–0.76 ms
for bare SQL statements (sqlparse) — 20,000 bash operations ≈ 2.6–3.7 s (fits the
5,000 ms default), 20,000 bare-SQL operations ≈ 11–15 s (UNKNOWN(timeout) at the
default; ~8,000 fit); a 2,000-operation tool decides in ~255–290 ms, at the edge of the
300 ms per-event default. The Z3-only predecessor was measured against exhaustive
enumeration on a 77-tool labelled corpus: identical verdicts wherever Z3 decided, 243 s
vs <1 s, and five verdicts that depended on the solver budget; this module is the result
of that experiment. Z3 is kept as a differential test oracle and for unbounded integers.
"""

from __future__ import annotations

import itertools
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

import z3
from z3 import (
    Concat,
    Contains,
    If,
    Int,
    IntToStr,
    Solver,
    StringVal,
    sat,
    unsat,
)

Z3_VERSION = z3.get_version_string()


class ToolSafetyStatus(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


@dataclass
class ForbiddenPattern:
    """A pattern that should never be reachable through tool invocation.

    ``keywords`` is the explicit literal list checked by substring containment. When it
    is ``None`` the quoted literals of ``condition`` are used (legacy form:
    ``"operation contains 'rm -rf' or 'rmdir'"``). ``matcher`` is a concrete-only check
    (``str -> matched text | None``) such as the L2 CLI denylist; it can only run on the
    enumeration engine and is reported ``unchecked`` elsewhere. A pattern is either a
    literal pattern (keywords) or a matcher pattern, not both.
    """

    name: str
    description: str
    condition: str = ""
    keywords: Optional[list[str]] = None
    case_sensitive: bool = True
    matcher: Optional[Callable[[str], Optional[str]]] = None

    def literal_keywords(self) -> list[str]:
        if self.keywords is not None:
            return list(self.keywords)
        return re.findall(r"'([^']+)'", self.condition)


@dataclass
class ToolParam:
    """A parameter in a tool definition."""

    name: str
    type: str  # "string" | "int" | "bool" | "enum" (+ JSON-schema aliases integer/boolean/str/text)
    enum_values: list[str] | None = None
    min_value: int | None = None
    max_value: int | None = None
    pattern: str | None = None  # regex constraint on a string param (fullmatch)


@dataclass
class ToolDefinition:
    """An AI agent tool definition to verify."""

    name: str
    description: str
    params: list[ToolParam]
    # What the tool constructs from params (e.g., a shell command, SQL query, API call)
    operation_template: str | None = None


@dataclass
class ToolSafetyResult:
    """Result of tool safety verification.

    ``violations`` holds only real witnesses (see module docstring); ``checks`` holds one
    entry per pattern with its ``outcome`` (``passed`` / ``violated`` / a reason code).
    """

    status: ToolSafetyStatus
    tool_name: str
    checks_passed: int
    checks_total: int
    violations: list[dict] = field(default_factory=list)
    time_ms: float = 0.0
    checks: list[dict] = field(default_factory=list)
    engine: str = "none"
    reason: Optional[str] = None
    budget_exhausted: bool = False
    z3_version: str = Z3_VERSION
    rlimit: int = 0

    @property
    def safe(self) -> bool:
        return self.status == ToolSafetyStatus.SAFE

    def __str__(self) -> str:
        if self.status == ToolSafetyStatus.SAFE:
            mark, icon = "V", "SAFE"
        elif self.status == ToolSafetyStatus.UNSAFE:
            mark, icon = "X", "UNSAFE"
        else:
            mark, icon = "?", "UNKNOWN"
        head = (f"{mark} {icon} — {self.tool_name} ({self.checks_passed}/{self.checks_total} "
                f"checks passed, {self.time_ms:.1f}ms, engine={self.engine}")
        if self.reason:
            head += f", reason={self.reason}"
        parts = [head + ")"]
        for v in self.violations:
            parts.append(f"  ! {v['pattern']}: {v['description']}")
            if v.get("operation") is not None:
                parts.append(f"    Operation: {v['operation']}")
            if v.get("keyword") is not None:
                parts.append(f"    Keyword: {v['keyword']!r}")
            if v.get("matched") is not None:
                parts.append(f"    Matched: {v['matched']}")
            if v.get("counterexample"):
                parts.append(f"    Counterexample: {v['counterexample']}")
        for c in self.checks:
            if c["outcome"] not in ("passed", "violated"):
                detail = f" ({c['detail']})" if c.get("detail") else ""
                parts.append(f"  ? {c['pattern']}: {c['outcome']}{detail}")
        return "\n".join(parts)


# ── Standard forbidden patterns ─────────────────────────────────────
#
# Literals are substring-matched on ' ' + operation + ' '. _cmd() anchors a command name
# at a separator so that 'gosu'/'pseudo'/'platformdirs' do not match while quoted and
# chained forms ('"su ', ';rm -rf', '&&sudo ') do. Lists are ordered most-specific first so
# the witness names the sharpest keyword. Deliberate over-approximations are stated in
# the description.

_SEPARATORS = (" ", '"', "'", ";", "&", "|", "(", "`")


def _cmd(*tails: str) -> list[str]:
    """Separator-anchored variants of command literals ('su ' -> ' su ', '\"su ', ';su ', ...)."""
    return [sep + tail for tail in tails for sep in _SEPARATORS]


FILESYSTEM_FORBIDDEN = [
    ForbiddenPattern(
        "destructive_delete",
        "Tool can trigger recursive or forced deletion (any path, including /tmp; "
        "'--delete' also matches 'git branch --delete'; quoted or chained mentions such as "
        "grep \"rm -rf\" also match — deliberate)",
        keywords=_cmd("rm -rf", "rm -fr", "rm -Rf", "rm -fR", "rm -r ", "rm -R ", "rm -r/", "rm -R/", "shred ")
        + ["no-preserve-root", " -delete", " --delete ", "-exec rm"],
    ),
    ForbiddenPattern(
        "privilege_escalation",
        "Tool can run with elevated privileges or set setuid bits (quoted or chained mentions such as "
        "grep \"sudo \" or echo 'su root' also match — deliberate)",
        keywords=_cmd("sudo ", "su ", "doas ", "chmod -R 777", "chmod -R 0777", "chmod 777", "chmod 0777",
                      "chmod u+s", "chmod g+s", "chmod +s"),
    ),
    ForbiddenPattern(
        "sensitive_files",
        "Tool can access credential or system-authentication files (*.pub reads also match — deliberate)",
        keywords=[
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", ".ssh/", "id_rsa", "id_ed25519",
            "authorized_keys", ".aws/credentials", ".pgpass", ".git-credentials",
        ],
    ),
]

DATABASE_FORBIDDEN = [
    ForbiddenPattern(
        "drop_table",
        "Tool can drop database objects",
        keywords=["DROP TABLE", "DROP DATABASE", "DROP SCHEMA"],
        case_sensitive=False,
    ),
    ForbiddenPattern(
        "truncate",
        "Tool can truncate tables (also matches coreutils 'truncate ' — deliberate)",
        keywords=["TRUNCATE "],
        case_sensitive=False,
    ),
    ForbiddenPattern(
        "delete_all",
        "Tool can delete rows (any DELETE FROM is flagged, with or without WHERE — "
        "a literal checker cannot bind 'without WHERE'; deliberate over-approximation)",
        keywords=["DELETE FROM"],
        case_sensitive=False,
    ),
    ForbiddenPattern(
        "alter_schema",
        "Tool can modify database schema",
        keywords=["ALTER TABLE", "ALTER DATABASE", "ALTER SCHEMA"],
        case_sensitive=False,
    ),
    ForbiddenPattern(
        "db_privilege",
        "Tool can change database roles, grants or server configuration",
        keywords=["GRANT ALL", "SET ROLE ", "SET SESSION AUTHORIZATION", "ALTER ROLE", "ALTER USER",
                  "CREATE USER", "CREATE ROLE", "ALTER SYSTEM", " SUPERUSER"],
        case_sensitive=False,
    ),
    ForbiddenPattern(
        "store_flush",
        "Tool can wipe a key-value store",
        keywords=["FLUSHALL", "FLUSHDB"],
        case_sensitive=False,
    ),
]

NETWORK_FORBIDDEN = [
    ForbiddenPattern(
        "cloud_metadata",
        "Tool can reach a cloud instance-metadata / credential endpoint",
        keywords=["169.254.169.254", "169.254.170.2", "metadata.google.internal", "metadata/computeMetadata",
                  "100.100.100.200"],
    ),
]

# Opt-in (NOT in STANDARD_FORBIDDEN): flags every tool that talks to a local or
# private-range service. Measured on the labelled corpus it produced only false positives
# (health checks, internal package indexes); use it for tools specified as external-only.
INTERNAL_NETWORK_FORBIDDEN = [
    ForbiddenPattern(
        "internal_network",
        "Tool can address a loopback / link-local / private-range host",
        keywords=["//127.", "//localhost", "//0.0.0.0", "//[::1]", "//10.", "//192.168.", "//169.254."]
        + [f"//172.{i}." for i in range(16, 32)],
    ),
]

# Opt-in (NOT in STANDARD_FORBIDDEN): a literal cannot see the destination, so these
# match credential USE (bearer headers, api_key query params, PGPASSWORD=) as readily as
# exfiltration. Kept for deployments that forbid any credential in a constructed operation.
CREDENTIAL_FORBIDDEN = [
    ForbiddenPattern(
        "credential_exfil",
        "Tool can place a credential in the constructed operation",
        keywords=["password=", "passwd=", "token=", "secret=", "api_key=", "apikey=",
                  "aws_secret_access_key", "private key", "authorization: bearer"],
        case_sensitive=False,
    ),
]

CLOUD_FORBIDDEN = [
    ForbiddenPattern(
        "cloud_destructive",
        "Tool can delete cloud resources or workloads",
        keywords=[
            "aws s3 rb", "aws s3 rm", "terminate-instances", "delete-db-instance",
            "gcloud compute instances delete", "gcloud sql instances delete",
            "az group delete", "az vm delete",
            "kubectl delete",  # duplicated by the L2 regex on purpose: keeps the verdict on the z3 engine too
            "terraform destroy",
        ],
    ),
    ForbiddenPattern(
        "cloud_privilege",
        "Tool can grant cloud IAM privileges or mint access keys",
        keywords=["attach-user-policy", "attach-role-policy", "AdministratorAccess",
                  "iam create-access-key", "add-iam-policy-binding", "roles/owner"],
    ),
    ForbiddenPattern(
        "container_destructive",
        "Tool can force-remove or kill containers, images or volumes",
        keywords=["docker rm -f", "docker kill", "docker system prune", "docker volume rm",
                  "docker rmi", "compose down -v"],
    ),
    ForbiddenPattern(
        "vcs_destructive",
        "Tool can rewrite shared history or discard the working tree",
        keywords=["push --force", "push -f ", "git clean -f", "clean -fd", "clean -xd", "clean -fx",
                  "reset --hard", "branch -D "],
    ),
    ForbiddenPattern(
        "process_kill",
        "Tool can kill init / all processes",
        keywords=_cmd("kill -9 1 ", "kill -KILL 1 ", "kill -SIGKILL 1 ", "kill -9 -1 ", "killall5 "),
    ),
]


class CLIDenylistMatcher:
    """Concrete-only matcher bridging the L2 ``CLIVerifier`` (regex + tree-sitter / sqlparse
    structural denylist). One verifier instance is cached for the process lifetime; it
    snapshots ``cli_verifier.DANGEROUS_PATTERNS`` at first use (tests that patch that list
    must reset ``CLIDenylistMatcher._cli = None``). ``warm()`` pays the one-time import
    (~100 ms) outside the verify() budget."""

    _cli = None

    def warm(self) -> None:
        if CLIDenylistMatcher._cli is None:
            from .cli_verifier import CLIVerifier

            CLIDenylistMatcher._cli = CLIVerifier()
            for op in ("ls -l /tmp", "SELECT 1", "echo {}"):  # one op per route: tree-sitter, sqlparse, json
                CLIDenylistMatcher._cli.verify(op)

    def __call__(self, op: str) -> Optional[str]:
        if CLIDenylistMatcher._cli is None:
            self.warm()
        r = CLIDenylistMatcher._cli.verify(op)
        if r.safe:
            return None
        v = r.violations[0]
        return f"{v.pattern_name} [{v.matched_text[:80]}]"


CLI_DENYLIST_FORBIDDEN = [
    ForbiddenPattern(
        "cli_denylist",
        "Instantiated operation trips the L2 regex + structural (tree-sitter / sqlparse) CLI denylist "
        "(brings its own over-approximations: sed -i on /etc/*, aws s3 cp/sync, ...)",
        matcher=CLIDenylistMatcher(),
    ),
]

STANDARD_LITERAL_FORBIDDEN = FILESYSTEM_FORBIDDEN + DATABASE_FORBIDDEN + NETWORK_FORBIDDEN + CLOUD_FORBIDDEN
STANDARD_FORBIDDEN = STANDARD_LITERAL_FORBIDDEN + CLI_DENYLIST_FORBIDDEN

BOOL_RENDERINGS = ("True", "False", "true", "false")
_INT_SENTINEL = "\x00"  # stands for an integer rendering in the digit-free pre-pass

# ── Template parsing ────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r"\$\{(\w+)\}|\{(\w+)\}|\$(\w+)")
_BRACE_GROUP = re.compile(r"\{[^{}]*\}")
_STRICT_BRACE = re.compile(r"\{\w+\}")


def _parse_template(template: str, param_names: set[str]) -> tuple[list[tuple[str, str]], Optional[str]]:
    """Split the template into ('lit', text) / ('ph', name) segments.

    ``{name}`` is always a placeholder (orphan if undeclared). ``${name}`` and ``$name``
    are placeholders only for a declared parameter; otherwise they are shell expansions
    and stay literal. Any other brace group (``{n:03d}``, ``{p!r}``, ``{a.b}``, ``{{``
    escapes, unbalanced braces) means the producer renders something this parser does
    not model -> ``template_unparsed`` (fail closed).
    """
    if "{{" in template or "}}" in template:
        return [], "template_unparsed"
    groups = _BRACE_GROUP.findall(template)
    if any(_STRICT_BRACE.fullmatch(g) is None for g in groups):
        return [], "template_unparsed"
    if template.count("{") != len(groups) or template.count("}") != len(groups):
        return [], "template_unparsed"
    segs: list[tuple[str, str]] = []
    pos = 0
    for m in _PLACEHOLDER.finditer(template):
        name = m.group(1) or m.group(2) or m.group(3)
        if m.group(2) is None and name not in param_names:
            continue  # $WORD / ${WORD} that is not a parameter: shell expansion, literal text
        if m.start() > pos:
            segs.append(("lit", template[pos:m.start()]))
        segs.append(("ph", name))
        pos = m.end()
    if pos < len(template):
        segs.append(("lit", template[pos:]))
    return segs, None


def _render(segs: list[tuple[str, str]], values: dict[str, str]) -> str:
    return "".join(values[name] if kind == "ph" else name for kind, name in segs)


def _kind(p: Optional[ToolParam]) -> str:
    if p is None:
        return "orphan"
    if p.enum_values:  # JSON Schema: "type": "string", "enum": [...] is an enum
        return "enum"
    t = (p.type or "").lower()
    if t in ("int", "integer"):
        return "int"
    if t in ("bool", "boolean"):
        return "bool"
    if t in ("string", "str", "text"):
        return "string"
    return "unmodeled"  # enum without values, 'number', unknown types


def _fold(s: str) -> str:
    """Case folding used by every engine: per code point, no context (Python's str.lower
    applies Final_Sigma context on whole strings, which would make a per-segment fold in
    the Z3 encoding disagree with the concrete check)."""
    if s.isascii():
        return s.lower()
    return "".join(ch.lower() for ch in s)


def _contains(op: str, keyword: str, case_sensitive: bool) -> bool:
    hay = " " + op + " "
    if case_sensitive:
        return keyword in hay
    return _fold(keyword) in _fold(hay)


def _int_free(keyword: str) -> bool:
    """A keyword with no digit that does not end in '-' cannot overlap an integer rendering
    (-?[0-9]+): the only overlaps are a keyword prefix matching trailing digits or a keyword
    suffix matching the leading '-'."""
    return not any(c.isdigit() for c in keyword) and not keyword.endswith("-")


class _Haystack:
    """All padded operations joined with a separator no keyword can contain, so each keyword
    is ONE C-level `find` over the corpus instead of a Python loop per operation; the hit
    offset maps back to the operation index with a bisect."""

    _SEP = "\x01"

    def __init__(self, padded: list[str]):
        self.n = len(padded)
        self._raw = self._SEP.join(padded)
        self._raw_off = self._offsets(padded)
        self._fold_text: Optional[str] = None
        self._fold_off: Optional[list[int]] = None
        self._padded = padded

    @classmethod
    def _offsets(cls, parts: list[str]) -> list[int]:
        out, pos = [], 0
        for part in parts:
            out.append(pos)
            pos += len(part) + 1
        return out

    def first_hit(self, keywords: list[str], case_sensitive: bool) -> Optional[tuple[int, str]]:
        """(operation index, keyword) of the earliest-listed keyword that occurs anywhere."""
        import bisect

        if case_sensitive:
            text, off = self._raw, self._raw_off
        else:
            if self._fold_text is None:
                folded = [_fold(h) for h in self._padded]
                self._fold_text, self._fold_off = self._SEP.join(folded), self._offsets(folded)
            text, off = self._fold_text, self._fold_off
        for kw in keywords:
            needle = kw if case_sensitive else _fold(kw)
            pos = text.find(needle)
            if pos >= 0:
                return bisect.bisect_right(off, pos) - 1, kw
        return None


def _bad_keywords(kws: list[str]) -> list[str]:
    """Literals the matching machinery cannot represent (empty, or containing the internal
    operation separator / int sentinel). Reported ``pattern_unsupported`` on every engine."""
    return [kw for kw in kws if kw == "" or _Haystack._SEP in kw or _INT_SENTINEL in kw]


def _glue_note(segs, values, unmodeled, op: str, kw: str, case_sensitive: bool) -> str:
    """Assumption text for a witness that involves unmodeled placeholders rendered as '':
    says whether the matched keyword is formed ONLY because such a hole rendered empty
    (the match spans the hole) or lies outside every hole."""
    fold = (lambda s: s) if case_sensitive else _fold
    padded = " " + fold(op) + " "
    start = padded.find(fold(kw))
    end = start + len(fold(kw))
    holes, pos = [], 1  # positions in the padded string
    for kind, text in segs:
        if kind == "lit":
            pos += len(fold(text))
        else:
            if text in unmodeled:
                holes.append(pos)
            pos += len(fold(values[text]))
    glued = start >= 0 and any(start < h < end for h in holes)
    return ("unmodeled parameter rendered as ''; the keyword is formed only if it renders empty" if glued
            else "unmodeled parameter rendered as ''; the keyword lies outside it")


# ── Verifier ────────────────────────────────────────────────────────


class ToolVerifier:
    """Decide whether any admissible parameter assignment makes the constructed operation
    contain a forbidden literal (or trip a concrete matcher). See the module docstring for
    the three engines and the verdict contract. Not thread-safe (neither is Z3)."""

    def __init__(self, timeout_ms: int = 5000, max_enumeration: int = 20_000,
                 bool_renderings: tuple[str, ...] = BOOL_RENDERINGS, max_memory_mb: int = 1024,
                 rlimit: int = 0, clock: Callable[[], float] = time.perf_counter):
        self.timeout_ms = timeout_ms
        self.max_enumeration = max_enumeration
        self.bool_renderings = tuple(bool_renderings)
        self.max_memory_mb = max_memory_mb
        self.rlimit = rlimit
        self._clock = clock  # injectable for deterministic deadline tests
        self._deadline = 0.0
        self._budget_exhausted = False

    # --- public ---------------------------------------------------------------

    def verify(self, tool: ToolDefinition, forbidden: list[ForbiddenPattern]) -> ToolSafetyResult:
        for p in forbidden:  # one-time imports of bridged matchers stay outside the budget
            if isinstance(p.matcher, CLIDenylistMatcher):
                p.matcher.warm()
        t0 = self._clock()
        self._deadline = t0 + self.timeout_ms / 1000.0
        self._budget_exhausted = False

        def finish(checks: list[dict], violations: list[dict], engine: str) -> ToolSafetyResult:
            return ToolSafetyResult(
                status=self._status(checks, violations), tool_name=tool.name,
                checks_passed=sum(1 for c in checks if c["outcome"] == "passed"),
                checks_total=len(checks), violations=violations,
                time_ms=(self._clock() - t0) * 1000, checks=checks, engine=engine,
                reason=self._reason(checks, violations), budget_exhausted=self._budget_exhausted,
                rlimit=self.rlimit,
            )

        def abstain(reason: str, detail: Optional[str] = None) -> ToolSafetyResult:
            checks = [{"pattern": p.name, "outcome": reason, **({"detail": detail} if detail else {})}
                      for p in forbidden]
            if not checks:  # forbidden == [] -> a vacuous SAFE must not be reachable
                checks = [{"pattern": "*", "outcome": reason}]
            return finish(checks, [], "none")

        if not forbidden:
            return abstain("no_patterns")
        if not tool.operation_template:
            return abstain("no_template")

        by_name = {p.name: p for p in tool.params}
        segs, err = _parse_template(tool.operation_template, set(by_name))
        if err:
            return abstain(err)
        kinds = {n: _kind(by_name.get(n)) for n in dict.fromkeys(n for k, n in segs if k == "ph")}
        empty = [n for n, k in kinds.items() if k == "int" and by_name[n].min_value is not None
                 and by_name[n].max_value is not None and by_name[n].max_value < by_name[n].min_value]
        if empty:
            return abstain("unmodeled_param", detail="empty int domain (min > max): " + ", ".join(empty))

        free = [n for n, k in kinds.items() if k in ("string", "orphan")]
        unmodeled = [n for n, k in kinds.items() if k == "unmodeled"]
        if free:
            return finish(*self._engine_witness(segs, kinds, by_name, free, unmodeled, forbidden), "witness")

        domains = {n: ([""] if kinds[n] == "unmodeled" else self._domain(by_name[n], kinds[n])) for n in kinds}
        if all(d is not None for d in domains.values()):
            size = 1
            for d in domains.values():
                size *= len(d)
            if size <= self.max_enumeration:
                checks, violations = self._engine_enumeration(segs, kinds, domains, forbidden, unmodeled)
                return finish(checks, violations, "enumeration")
            matcher_outcome = "domain_too_large"
        else:
            matcher_outcome = "unchecked"
        if unmodeled:  # cannot certify SAFE and the int part is undecidable here: abstain honestly
            return abstain("unmodeled_param", detail="params: " + ", ".join(unmodeled))
        return finish(*self._engine_z3(segs, kinds, by_name, forbidden, matcher_outcome), "z3")

    # --- shared ---------------------------------------------------------------

    def _domain(self, p: ToolParam, kind: str):
        """Finite domain as a sequence (list of str, or a range of ints), or None."""
        if kind == "enum":
            return [str(v) for v in p.enum_values]
        if kind == "bool":
            return list(self.bool_renderings)
        if kind == "int":
            if p.min_value is None or p.max_value is None or p.max_value < p.min_value:
                return None
            return range(p.min_value, p.max_value + 1)
        return None

    def _over(self) -> bool:
        if self._clock() > self._deadline:
            self._budget_exhausted = True
            return True
        return False

    @staticmethod
    def _status(checks: list[dict], violations: list[dict]) -> ToolSafetyStatus:
        if violations:
            return ToolSafetyStatus.UNSAFE
        if checks and all(c["outcome"] == "passed" for c in checks):
            return ToolSafetyStatus.SAFE
        return ToolSafetyStatus.UNKNOWN

    @staticmethod
    def _reason(checks: list[dict], violations: list[dict]) -> Optional[str]:
        if violations:
            return None
        if any(c["outcome"] == "timeout" for c in checks):
            return "timeout"
        for c in checks:
            if c["outcome"] != "passed":
                return c["outcome"]
        return None

    @staticmethod
    def _witness(pattern: ForbiddenPattern, op: str, values: dict[str, str], engine: str, *,
                 keyword: Optional[str] = None, matched: Optional[str] = None,
                 assumptions: Optional[dict] = None) -> dict:
        w = {"pattern": pattern.name, "description": pattern.description, "keyword": keyword,
             "matched": matched, "operation": op, "counterexample": dict(values), "engine": engine}
        if assumptions:
            w["assumptions"] = assumptions
        return w

    def _neutral(self, p: Optional[ToolParam], kind: str) -> str:
        if kind == "enum":
            return str(p.enum_values[0])
        if kind == "bool":
            return self.bool_renderings[0]
        if kind == "int":
            return str(p.min_value if p.min_value is not None else (p.max_value if p.max_value is not None else 0))
        return ""

    # --- engine: witness by construction (free string / orphan placeholder) ------------

    def _engine_witness(self, segs, kinds, by_name, free, unmodeled, forbidden):
        checks: list[dict] = []
        violations: list[dict] = []
        assumptions = {n: "unmodeled placeholder rendered as ''" for n in unmodeled}
        assumptions.update({n: "orphan placeholder (no declared parameter) treated as attacker-controlled"
                            for n in free if n not in by_name})

        def unsupported(detail: str):
            return ([{"pattern": p.name, "outcome": "pattern_unsupported", "detail": detail} for p in forbidden], [])

        # compile the regex constraints once; pick an admissible neutral for every constrained free string
        regexes: dict[str, re.Pattern] = {}
        for n in free:
            pat = by_name[n].pattern if n in by_name else None
            if pat is None:
                continue
            try:
                regexes[n] = re.compile(pat)
            except re.error as e:
                return unsupported(f"string param {n!r} declares an invalid regex {pat!r}: {e}")
        neutral = {n: self._neutral(by_name.get(n), k) for n, k in kinds.items()}
        no_neutral: list[str] = []
        for n, rx in regexes.items():
            for cand in ("", "a", "0", "a0", "x1", "aa", "test", "A", "AA", "TEST", "X1"):
                if rx.fullmatch(cand):
                    neutral[n] = cand
                    break
            else:
                no_neutral.append(n)
        if len(no_neutral) > 1:
            return unsupported(f"no admissible neutral value found for string params {no_neutral!r}; "
                               "regex-constrained strings are not decided by this checker")
        if no_neutral:  # that parameter can only ever carry the keyword itself
            targets = no_neutral
        else:
            targets = [n for n in free if n not in regexes] + [n for n in free if n in regexes]

        for p in forbidden:
            kws = p.literal_keywords()
            if not kws:
                if p.matcher is not None:
                    checks.append({"pattern": p.name, "outcome": "unchecked",
                                   "detail": "matcher needs a finite domain; parameter is a free string"})
                else:
                    checks.append({"pattern": p.name, "outcome": "no_keyword"})
                continue
            bad = _bad_keywords(kws)
            if bad:
                checks.append({"pattern": p.name, "outcome": "pattern_unsupported", "detail": f"keywords not representable: {bad!r}"})
                continue
            hit = None
            inadmissible = False
            for kw in kws:
                candidates = [kw, kw.strip()] if p.case_sensitive else [kw, kw.strip(), _fold(kw), kw.upper()]
                for target in targets:
                    rx = regexes.get(target)
                    for candidate in dict.fromkeys(candidates):
                        if rx is not None and rx.fullmatch(candidate) is None:
                            inadmissible = True
                            continue
                        values = dict(neutral)
                        values[target] = candidate
                        op = _render(segs, values)
                        if _contains(op, kw, p.case_sensitive):
                            hit = self._witness(p, op, values, "witness", keyword=kw, assumptions=assumptions or None)
                            break
                    if hit:
                        break
                if hit:
                    break
            if hit:
                violations.append(hit)
                checks.append({"pattern": p.name, "outcome": "violated"})
            elif inadmissible:
                checks.append({"pattern": p.name, "outcome": "pattern_unsupported",
                               "detail": "every free string is regex-constrained and no keyword witness matches "
                                         "its pattern; regex-constrained strings are not decided by this checker"})
            else:
                checks.append({"pattern": p.name, "outcome": "unchecked", "detail": "no keyword witness"})
        return checks, violations

    # --- engine: exhaustive enumeration ------------------------------------------------

    def _engine_enumeration(self, segs, kinds, domains, forbidden, unmodeled=()):
        names = list(domains)
        ops: list[str] = []
        assignments: list[dict[str, str]] = []
        padded: list[str] = []
        timed_out = False
        for j, combo in enumerate(itertools.product(*[domains[n] for n in names])):
            if j % 512 == 0 and self._over():
                timed_out = True
                break
            values = {n: str(v) for n, v in zip(names, combo)}
            op = _render(segs, values)
            ops.append(op)
            assignments.append(values)
            padded.append(" " + op + " ")
        bools = [n for n, k in kinds.items() if k == "bool"]
        base_assumptions = {n: f"bool rendered as one of {list(self.bool_renderings)}" for n in bools}

        def assumptions_for(j: int, kw: Optional[str], case_sensitive: bool) -> Optional[dict]:
            a = dict(base_assumptions)
            for n in unmodeled:
                a[n] = (_glue_note(segs, assignments[j], unmodeled, ops[j], kw, case_sensitive) if kw is not None
                        else "unmodeled parameter rendered as ''")
            return a or None

        checks: list[Optional[dict]] = [None] * len(forbidden)
        violations: list[dict] = []
        hay = _Haystack(padded)
        # phase 1: literal patterns over the whole product (one C-level find per keyword)
        for i, p in enumerate(forbidden):
            kws = p.literal_keywords()
            if not kws:
                continue
            bad = _bad_keywords(kws)
            if bad:
                checks[i] = {"pattern": p.name, "outcome": "pattern_unsupported", "detail": f"keywords not representable: {bad!r}"}
                continue
            if timed_out or self._over():
                timed_out = True
                checks[i] = {"pattern": p.name, "outcome": "timeout",
                             "detail": f"budget exhausted before this pattern ({len(ops)} operations materialised)"}
                continue
            found = hay.first_hit(kws, p.case_sensitive)
            if found:
                j, kw = found
                if not _contains(ops[j], kw, p.case_sensitive):  # never an UNSAFE the operation itself does not replay
                    checks[i] = {"pattern": p.name, "outcome": "pattern_unsupported",
                                 "detail": f"keyword {kw!r} matched only across operation boundaries"}
                    continue
                violations.append(self._witness(p, ops[j], assignments[j], "enumeration", keyword=kw,
                                                assumptions=assumptions_for(j, kw, p.case_sensitive)))
                checks[i] = {"pattern": p.name, "outcome": "violated"}
            else:
                checks[i] = {"pattern": p.name, "outcome": "passed"}
        # phase 2: matcher patterns over the distinct operations until the deadline
        first_index: dict[str, int] = {}
        for j, op in enumerate(ops):
            first_index.setdefault(op, j)
        for i, p in enumerate(forbidden):
            if checks[i] is not None:
                continue
            if p.matcher is None:
                checks[i] = {"pattern": p.name, "outcome": "no_keyword"}
                continue
            if timed_out:
                checks[i] = {"pattern": p.name, "outcome": "timeout", "detail": "budget exhausted before this pattern"}
                continue
            hit = None
            covered = 0
            for op, j in first_index.items():
                if self._over():
                    timed_out = True
                    break
                m = p.matcher(op)
                covered += 1
                if m:
                    hit = self._witness(p, op, assignments[j], "enumeration", matched=m,
                                        assumptions=assumptions_for(j, None, True))
                    break
            if hit:
                violations.append(hit)
                checks[i] = {"pattern": p.name, "outcome": "violated"}
            elif timed_out:
                checks[i] = {"pattern": p.name, "outcome": "timeout",
                             "detail": f"covered {covered}/{len(first_index)} operations"}
            else:
                checks[i] = {"pattern": p.name, "outcome": "passed"}
        if unmodeled:  # an unmodeled parameter never certifies a pattern as passed over the whole domain
            for c in checks:
                if c["outcome"] == "passed":
                    c["outcome"] = "unmodeled_param"
                    c["detail"] = "params: " + ", ".join(unmodeled)
        return checks, violations

    # --- engine: Z3 (unbounded int / over-cap finite domains) -----------------------------

    def _int_witness_value(self, p: ToolParam) -> str:
        if p.min_value is not None:
            return str(p.min_value)
        if p.max_value is not None:
            return str(p.max_value)
        return "0"

    def _prepass_int_free(self, segs, kinds, by_name, forbidden):
        """Decide digit-free keywords exactly with the ints as separators (see _int_free).
        Returns {pattern index: (witness | None, decided keywords set)} or None if the
        enum/bool product is itself too large."""
        finite = [n for n, k in kinds.items() if k in ("enum", "bool")]
        ints = [n for n, k in kinds.items() if k == "int"]
        domains = {n: self._domain(by_name[n], kinds[n]) for n in finite}
        size = 1
        for d in domains.values():
            size *= len(d)
        if size > self.max_enumeration:
            return None
        rendered: list[str] = []
        assignments: list[dict] = []
        for combo in itertools.product(*[domains[n] for n in finite]):
            values = {n: str(v) for n, v in zip(finite, combo)}
            values.update({n: _INT_SENTINEL for n in ints})
            rendered.append(" " + _render(segs, values) + " ")
            assignments.append(values)
        hay = _Haystack(rendered)
        out = {}
        for i, p in enumerate(forbidden):
            kws = [kw for kw in p.literal_keywords() if _int_free(kw)]
            if not kws:
                continue
            hit = None
            found = hay.first_hit(kws, p.case_sensitive)
            if found:
                j, kw = found
                concrete = dict(assignments[j])
                concrete.update({n: self._int_witness_value(by_name[n]) for n in ints})
                cop = _render(segs, concrete)
                if not _contains(cop, kw, p.case_sensitive):
                    out[i] = (None, set())  # should not happen; leave every keyword to Z3 rather than guess
                    continue
                hit = self._witness(p, cop, concrete, "z3", keyword=kw)
            out[i] = (hit, set(kws))
        return out

    def _engine_z3(self, segs, kinds, by_name, forbidden, matcher_outcome):
        checks: list[Optional[dict]] = [None] * len(forbidden)
        violations: list[dict] = []
        pre = self._prepass_int_free(segs, kinds, by_name, forbidden) or {}
        z3_vars: dict[str, dict] = {}
        constraints = []
        for n, k in kinds.items():
            p = by_name[n]
            v = Int(f"param_{n}")
            if k == "int":
                if p.min_value is not None:
                    constraints.append(v >= p.min_value)
                if p.max_value is not None:
                    constraints.append(v <= p.max_value)
                z3_vars[n] = {"var": v, "type": "int"}
            else:  # enum / bool: index-selected literal
                values = [str(x) for x in p.enum_values] if k == "enum" else list(self.bool_renderings)
                constraints += [v >= 0, v < len(values)]
                z3_vars[n] = {"var": v, "type": k, "values": values}
        bools = [n for n, k in kinds.items() if k == "bool"]
        assumptions = {n: f"bool rendered as one of {list(self.bool_renderings)}" for n in bools} or None

        pending: list[tuple[int, list[str]]] = []  # (pattern index, keywords still needing Z3)
        for i, p in enumerate(forbidden):
            kws = p.literal_keywords()
            if not kws:
                checks[i] = ({"pattern": p.name, "outcome": matcher_outcome, "detail": "matcher patterns need the enumeration engine"}
                             if p.matcher is not None else {"pattern": p.name, "outcome": "no_keyword"})
                continue
            bad = _bad_keywords(kws)
            if bad:
                checks[i] = {"pattern": p.name, "outcome": "pattern_unsupported", "detail": f"keywords not representable: {bad!r}"}
                continue
            hit, decided = pre.get(i, (None, set()))
            if hit:
                violations.append(hit)
                checks[i] = {"pattern": p.name, "outcome": "violated"}
                continue
            rest = [kw for kw in kws if kw not in decided]
            if not rest:
                checks[i] = {"pattern": p.name, "outcome": "passed"}
            else:
                pending.append((i, rest))

        # Z3 passes: a fair slice per pending pattern; patterns whose slice ran out are retried
        # with a re-sliced share of what is left, until the budget is spent or nothing is pending
        passes = 0
        while pending and passes < 8 and not self._budget_exhausted:
            passes += 1
            retry: list[tuple[int, list[str]]] = []
            for k, (i, rest) in enumerate(pending):
                p = forbidden[i]
                remaining_ms = int((self._deadline - self._clock()) * 1000)
                if remaining_ms <= 0:
                    self._budget_exhausted = True
                    checks[i] = {"pattern": p.name, "outcome": "timeout", "detail": "budget exhausted before this pattern"}
                    continue
                slice_ms = max(1, remaining_ms // (len(pending) - k))
                outcome, detail, hit, undecided = self._z3_pattern(segs, z3_vars, constraints, p, rest, slice_ms, assumptions)
                if hit:
                    violations.append(hit)
                    checks[i] = {"pattern": p.name, "outcome": "violated"}
                elif outcome == "timeout" and not self._budget_exhausted:
                    checks[i] = {"pattern": p.name, "outcome": "timeout", "detail": detail}
                    retry.append((i, undecided))
                else:
                    checks[i] = {"pattern": p.name, "outcome": outcome, **({"detail": detail} if detail else {})}
            pending = retry
        return checks, violations

    def _z3_pattern(self, segs, z3_vars, constraints, p, kws, slice_ms, assumptions):
        """Run one pattern's keywords through Z3 within slice_ms. Returns
        (outcome, detail, witness, keywords still undecided)."""
        fold = not p.case_sensitive
        op_expr = self._z3_operation(segs, z3_vars, fold)
        unsat_cores: set[str] = set()  # Contains(op, sep+tail) implies Contains(op, tail): one unsat per tail

        def query(text: str):
            remaining_ms = int((self._deadline - self._clock()) * 1000)
            if remaining_ms <= 0:
                self._budget_exhausted = True
                return "timeout", None
            solver = Solver()
            solver.set("timeout", max(1, min(remaining_ms, slice_ms)))
            solver.set("max_memory", self.max_memory_mb)
            if self.rlimit:
                solver.set("rlimit", self.rlimit)
            for c in constraints:
                solver.add(c)
            needle = _fold(text) if fold else text
            solver.add(Contains(Concat(StringVal(" "), op_expr, StringVal(" ")), StringVal(needle)))
            res = solver.check()
            if res == sat:
                return "sat", solver.model()
            if res == unsat:
                return "unsat", None
            why = solver.reason_unknown()
            return ("timeout" if "timeout" in why or "canceled" in why else "unknown"), why

        for k, kw in enumerate(kws):
            core = kw[1:] if len(kw) > 1 and kw[0] in _SEPARATORS else kw
            if core in unsat_cores:
                continue
            if core != kw and sum(1 for x in kws if x.endswith(core)) > 1:
                # several separator variants share this tail: settle the tail first
                res, _ = query(core)
                if res == "unsat":
                    unsat_cores.add(core)
                    continue
                if res == "timeout":
                    if self._budget_exhausted:
                        return "timeout", f"budget exhausted before keyword {kw!r}", None, kws[k:]
                    self._over()
                    return "timeout", f"solver: timeout (slice {slice_ms}ms, keyword tail {core!r})", None, kws[k:]
                # sat on the tail does not settle the anchored variant: fall through to the exact query
            res, payload = query(kw)
            if res == "sat":
                values = self._z3_values(payload, z3_vars)
                op = _render(segs, values)
                if _contains(op, kw, p.case_sensitive):
                    return "violated", None, self._witness(p, op, values, "z3", keyword=kw, assumptions=assumptions), []
                return "z3_unknown", f"witness did not replay for keyword {kw!r}", None, kws[k:]
            if res == "unsat":
                continue
            if res == "timeout":
                if self._budget_exhausted:
                    return "timeout", f"budget exhausted before keyword {kw!r}", None, kws[k:]
                self._over()
                return "timeout", f"solver: timeout (slice {slice_ms}ms, keyword {kw!r})", None, kws[k:]
            return "z3_unknown", f"solver: {payload} (keyword {kw!r})", None, kws[k:]
        return "passed", None, None, []

    @staticmethod
    def _z3_operation(segs, z3_vars, fold: bool):
        parts = []
        for kind, text in segs:
            if kind == "lit":
                parts.append(StringVal(_fold(text) if fold else text))
                continue
            info = z3_vars[text]
            if info["type"] == "int":
                v = info["var"]
                parts.append(If(v < 0, Concat(StringVal("-"), IntToStr(-v)), IntToStr(v)))
            else:
                vals = [_fold(x) if fold else x for x in info["values"]]
                expr = StringVal(vals[-1])
                for i in range(len(vals) - 1):
                    expr = If(info["var"] == i, StringVal(vals[i]), expr)
                parts.append(expr)
        if not parts:
            return StringVal("")
        op = parts[0]
        for q in parts[1:]:
            op = Concat(op, q)
        return op

    @staticmethod
    def _z3_values(model, z3_vars) -> dict[str, str]:
        values = {}
        for n, info in z3_vars.items():
            raw = model.eval(info["var"], model_completion=True)
            idx = raw.as_long() if hasattr(raw, "as_long") else int(str(raw))
            if info["type"] == "int":
                values[n] = str(idx)
            else:
                values[n] = info["values"][idx] if 0 <= idx < len(info["values"]) else info["values"][0]
        return values


# ── Convenience ─────────────────────────────────────────────────────


def tool_definition_from_payload(payload: str | dict) -> ToolDefinition:
    """Build a :class:`ToolDefinition` from JSON text or a dict (Guard / CLI).

    Shape matches ``substrate_guard.cli`` tool file loading: ``name``, ``params`` /
    ``parameters``, optional ``operation_template``. JSON-schema spellings are accepted:
    ``integer`` / ``boolean`` / ``str`` types, ``minimum`` / ``maximum`` bounds, and
    ``"type": "string", "enum": [...]`` (any param with an ``enum`` list is an enum).
    Non-integer bounds raise ``ValueError``.
    """
    import json

    if isinstance(payload, str):
        if not payload.strip():
            return ToolDefinition(name="unknown", description="", params=[])
        data = json.loads(payload)
    else:
        data = payload
    if not isinstance(data, dict):
        raise TypeError("tool payload must be a dict or JSON object")

    def bound(p, *keys):
        for k in keys:
            if p.get(k) is not None:
                try:
                    return int(p[k])
                except (TypeError, ValueError) as e:
                    raise ValueError(f"param {p.get('name')!r}: {k} must be an integer, got {p[k]!r}") from e
        return None

    params: list[ToolParam] = []
    for p in data.get("params", data.get("parameters", [])):
        params.append(
            ToolParam(
                name=p["name"],
                type=p.get("type", "string"),
                enum_values=p.get("enum", p.get("enum_values")),
                min_value=bound(p, "min", "minimum"),
                max_value=bound(p, "max", "maximum"),
                pattern=p.get("pattern"),
            )
        )
    return ToolDefinition(
        name=data.get("name", "unknown"),
        description=data.get("description", ""),
        params=params,
        operation_template=data.get("operation_template"),
    )


def verify_tool(
    tool: ToolDefinition,
    forbidden: list[ForbiddenPattern] | None = None,
    timeout_ms: int = 5000,
    **verifier_kwargs: Any,
) -> ToolSafetyResult:
    """One-shot tool verification. ``forbidden=None`` uses :data:`STANDARD_FORBIDDEN`
    (literal lists + the L2 CLI denylist); ``timeout_ms`` bounds the whole call."""
    if forbidden is None:
        forbidden = STANDARD_FORBIDDEN
    verifier = ToolVerifier(timeout_ms=timeout_ms, **verifier_kwargs)
    return verifier.verify(tool, forbidden)
