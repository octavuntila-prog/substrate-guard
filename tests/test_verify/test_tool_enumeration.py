"""Verdict contract of the tool checker (exhaustive instantiation + literal lists; Z3 only
for unbounded ints). Pins the findings of the 2026-10-13 design review:

  UNSAFE only with a replayable witness; SAFE only with complete coverage; otherwise
  UNKNOWN with a reason; lowering the budget never flips SAFE<->UNSAFE; orphan / unparsed
  placeholders and empty pattern lists are never SAFE; the leading-space anchor keeps
  'gosu' from matching ' su '.
"""
from __future__ import annotations

import re
import time

import pytest

from substrate_guard.tool_verifier import (
    CLI_DENYLIST_FORBIDDEN,
    STANDARD_FORBIDDEN,
    STANDARD_LITERAL_FORBIDDEN,
    ForbiddenPattern,
    ToolDefinition,
    ToolParam,
    ToolSafetyStatus,
    ToolVerifier,
    _contains,
    verify_tool,
)

SAFE, UNSAFE, UNKNOWN = ToolSafetyStatus.SAFE, ToolSafetyStatus.UNSAFE, ToolSafetyStatus.UNKNOWN
DELETE = [ForbiddenPattern("destructive_delete", "recursive deletion", keywords=[" rm -rf", " rmdir "])]


def tool(template, *params, name="t"):
    return ToolDefinition(name, "", list(params), template)


def enum(name, *values):
    return ToolParam(name, "enum", enum_values=list(values))


def replay(template: str, witness: dict) -> str:
    op = template
    for k, v in witness["counterexample"].items():
        op = op.replace("${%s}" % k, v).replace("{%s}" % k, v)
        op = re.sub(r"\$%s\b" % re.escape(k), lambda m: v, op)
    return op


def assert_witness_replays(res, template):
    assert res.status is UNSAFE and res.violations
    for v in res.violations:
        assert replay(template, v) == v["operation"], (template, v)
        if v.get("keyword") is not None:
            assert _contains(v["operation"], v["keyword"], True) or _contains(v["operation"], v["keyword"], False)


# --- enumeration engine is exact ----------------------------------------------------------

def test_keyword_only_reachable_through_one_combination():
    t = tool("cmd {a}{n}{f}", enum("a", "x", "y"), ToolParam("n", "int", min_value=5, max_value=9), ToolParam("f", "bool"))
    hit = verify_tool(t, [ForbiddenPattern("p", "p", keywords=["x7true"])])
    assert hit.engine == "enumeration"
    assert_witness_replays(hit, "cmd {a}{n}{f}")
    assert hit.violations[0]["counterexample"] == {"a": "x", "n": "7", "f": "true"}
    miss = verify_tool(t, [ForbiddenPattern("p", "p", keywords=["x3true", "y10false"])])
    assert miss.status is SAFE and miss.checks_passed == 1


def test_keyword_glued_across_placeholder_boundary():
    t = tool("r{a} -rf /", enum("a", "m", "x"))
    res = verify_tool(t, DELETE)
    assert_witness_replays(res, "r{a} -rf /")
    assert res.violations[0]["counterexample"] == {"a": "m"}


def test_negative_int_renders_with_sign_on_both_engines():
    pat = [ForbiddenPattern("neg", "neg", keywords=["o-5"])]
    bounded = verify_tool(tool("echo{n}", ToolParam("n", "int", min_value=-9, max_value=9)), pat)
    assert bounded.engine == "enumeration" and bounded.violations[0]["counterexample"] == {"n": "-5"}
    unbounded = verify_tool(tool("echo{n}", ToolParam("n", "int", min_value=-9)), pat, timeout_ms=5000)
    assert unbounded.engine == "z3"
    if unbounded.status is UNSAFE:  # z3 may also abstain on string theory; it must never say SAFE
        assert unbounded.violations[0]["counterexample"] == {"n": "-5"}
    else:
        assert unbounded.status is UNKNOWN


def test_bool_renderings_are_explicit_and_flagged_as_assumption():
    t = tool("run --flag={f}", ToolParam("f", "bool"))
    hit = verify_tool(t, [ForbiddenPattern("b", "b", keywords=["=true"])])
    assert hit.status is UNSAFE and hit.violations[0]["counterexample"] == {"f": "true"}
    assert "f" in hit.violations[0]["assumptions"]
    assert verify_tool(t, [ForbiddenPattern("b", "b", keywords=["=1"])]).status is SAFE


def test_case_insensitive_sql_on_both_engines():
    ci = [ForbiddenPattern("drop", "drop", keywords=["DROP TABLE"], case_sensitive=False)]
    assert verify_tool(tool('psql -c "drop table {t}"', enum("t", "a")), ci).status is UNSAFE
    res = verify_tool(tool('psql -c "DROP TABLE t{n}"', ToolParam("n", "int")),
                      [ForbiddenPattern("drop", "drop", keywords=["drop table"], case_sensitive=False)], timeout_ms=5000)
    assert res.engine == "z3" and res.status is UNSAFE
    assert_witness_replays(res, 'psql -c "DROP TABLE t{n}"')
    cs = [ForbiddenPattern("drop", "drop", keywords=["DROP TABLE"], case_sensitive=True)]
    assert verify_tool(tool('psql -c "drop table {t}"', enum("t", "a")), cs).status is SAFE


# --- never a false SAFE ----------------------------------------------------------------------

@pytest.mark.parametrize("params", [[], [enum("mode", "a", "b")]])
def test_orphan_placeholder_is_attacker_controlled_not_safe(params):
    res = verify_tool(tool("exec {cmd}", *params), DELETE)
    assert res.status is UNSAFE and res.engine == "witness"
    assert_witness_replays(res, "exec {cmd}")
    assert "cmd" in res.violations[0]["assumptions"]


@pytest.mark.parametrize("template", ["exec {cmd:s}", "exec {cmd!r}", "exec {a.b}", "exec {{a}}", "exec {a", "exec a}"])
def test_unparsed_template_abstains(template):
    res = verify_tool(tool(template, enum("a", "x"), ToolParam("cmd", "string")), DELETE)
    assert res.status is UNKNOWN and res.reason == "template_unparsed"


def test_bare_dollar_is_a_placeholder_only_for_declared_params():
    assert verify_tool(tool("exec $cmd", ToolParam("cmd", "string")), DELETE).status is UNSAFE
    assert verify_tool(tool("ls $HOME/{d}", enum("d", "docs", "src")), DELETE).status is SAFE


def test_empty_pattern_list_is_not_vacuously_safe():
    res = verify_tool(tool("ls {d}", enum("d", "docs")), [])
    assert res.status is UNKNOWN and res.reason == "no_patterns"


def test_unmodeled_type_abstains_and_json_schema_aliases_enumerate():
    assert verify_tool(tool("sleep {n}", ToolParam("n", "number"))).reason == "unmodeled_param"
    assert verify_tool(tool("sleep {n}", ToolParam("n", "enum", enum_values=None)), DELETE).status is UNKNOWN
    r = verify_tool(tool("tail -n {n} {q}", ToolParam("n", "integer", min_value=1, max_value=3), ToolParam("q", "boolean")))
    assert r.engine == "enumeration" and r.status is SAFE


def test_pattern_constrained_string_never_yields_inadmissible_witness():
    res = verify_tool(tool("exec {cmd}", ToolParam("cmd", "string", pattern=r"^[0-9]+$")), DELETE)
    assert res.status is UNKNOWN and res.reason == "pattern_unsupported"
    ok = verify_tool(tool("exec {cmd}", ToolParam("cmd", "string", pattern=r"^[a-z -]+$")), DELETE)
    assert ok.status is UNSAFE and re.fullmatch(r"^[a-z -]+$", ok.violations[0]["counterexample"]["cmd"])


def test_matcher_pattern_is_unchecked_off_the_enumeration_engine():
    free = verify_tool(tool("exec {cmd}", ToolParam("cmd", "string")), CLI_DENYLIST_FORBIDDEN)
    assert free.status is UNKNOWN and free.reason == "unchecked"
    big = verify_tool(tool("add {a} {b}", ToolParam("a", "int", min_value=0, max_value=99),
                           ToolParam("b", "int", min_value=0, max_value=99)),
                      CLI_DENYLIST_FORBIDDEN + [ForbiddenPattern("k", "k", keywords=["zzz"])],
                      timeout_ms=5000, max_enumeration=100)
    assert big.engine == "z3" and big.status is UNKNOWN
    assert {c["outcome"] for c in big.checks if c["pattern"] == "cli_denylist"} == {"domain_too_large"}


# --- budget semantics --------------------------------------------------------------------------

def test_lower_budget_never_flips_safe_and_unsafe():
    tools = [
        tool("ls -l /workspace/{d}", enum("d", "docs", "src")),
        tool("rm -rf /{m}", enum("m", "read", "list")),
        tool("tail -n {n} /var/log/{f}", ToolParam("n", "int", min_value=1, max_value=500), enum("f", "syslog", "auth.log")),
        tool("exec {cmd}", ToolParam("cmd", "string")),
        tool("sleep {n}", ToolParam("n", "int")),
    ]
    for t in tools:
        verdicts = {verify_tool(t, STANDARD_FORBIDDEN, timeout_ms=b).status for b in (1, 5, 50, 5000)}
        assert not ({SAFE, UNSAFE} <= verdicts), (t.operation_template, verdicts)


def test_deadline_is_deterministic_with_injected_clock():
    state = {"t": 0.0}
    calls = {"n": 0}

    def clock():
        return state["t"]

    def slow_matcher(op):
        calls["n"] += 1
        state["t"] += 1.0   # every matcher call burns a second
        return None

    t = tool("tail -n {n}", ToolParam("n", "int", min_value=1, max_value=50))
    pats = STANDARD_LITERAL_FORBIDDEN + [ForbiddenPattern("slow", "slow", matcher=slow_matcher)]
    res = ToolVerifier(timeout_ms=500, clock=clock).verify(t, pats)
    assert res.status is UNKNOWN and res.reason == "timeout" and res.budget_exhausted
    # literal patterns were fully decided before the matcher phase started
    assert all(c["outcome"] == "passed" for c in res.checks if c["pattern"] != "slow")
    assert [c for c in res.checks if c["pattern"] == "slow"][0]["outcome"] == "timeout"
    assert calls["n"] == 1


def test_z3_path_returns_promptly_when_budget_is_gone():
    t0 = time.perf_counter()
    res = verify_tool(tool("run {n}", ToolParam("n", "int")), STANDARD_FORBIDDEN * 3, timeout_ms=1)
    assert (time.perf_counter() - t0) < 2.0
    assert res.status is UNKNOWN and res.reason == "timeout"


def test_z3_slice_timeout_on_one_pattern_does_not_starve_the_rest():
    """A pattern whose z3 queries do not finish must not mark every later pattern
    'budget exhausted before this pattern' while budget remains."""
    pats = [ForbiddenPattern("slow", "slow", keywords=[" rm -r ", " -delete"]),
            ForbiddenPattern("fast", "fast", keywords=["zzz"])]
    res = verify_tool(tool("sleep {n}", ToolParam("n", "int")), pats, timeout_ms=1500)
    outcomes = {c["pattern"]: c["outcome"] for c in res.checks}
    assert outcomes["fast"] in ("passed", "timeout", "z3_unknown")
    if outcomes["fast"] == "timeout":
        assert "before this pattern" not in [c for c in res.checks if c["pattern"] == "fast"][0].get("detail", "") or res.budget_exhausted


# --- standard set behaviour -------------------------------------------------------------------

@pytest.mark.parametrize("template,params", [
    ("ls -l /workspace/{dir}", [enum("dir", "docs", "src")]),
    ("SELECT * FROM {table} WHERE id = {id}", [enum("table", "users", "orders"), ToolParam("id", "int", min_value=1, max_value=50)]),
    ("curl -s https://api.example.com/{path}", [enum("path", "weather", "news")]),
    ("calc {a} {op} {b}", [ToolParam("a", "int", min_value=-9, max_value=9), enum("op", "+", "-", "*", "/"), ToolParam("b", "int", min_value=-9, max_value=9)]),
    ("gosu {u} python app.py", [enum("u", "app", "web")]),
    ("pip install platformdirs=={v}", [enum("v", "4.2.0", "4.3.0")]),
])
def test_standard_set_benign_templates_are_safe(template, params):
    res = verify_tool(tool(template, *params))
    assert res.status is SAFE and res.engine == "enumeration", str(res)


@pytest.mark.parametrize("template,params,pattern", [
    ("rm -rf /{mode}", [enum("mode", "read", "list")], "destructive_delete"),
    ("su {u}", [enum("u", "root", "app")], "privilege_escalation"),
    ('psql -c "drop table {t}"', [enum("t", "a")], "drop_table"),
    ("curl http://169.254.169.254/latest/meta-data/{p}", [enum("p", "iam", "hostname")], "cloud_metadata"),
    ("find /var/log -name {g} -delete", [enum("g", "*.log", "*.gz")], "destructive_delete"),
    ("aws s3 rb s3://{b} --force", [enum("b", "logs", "tmp")], "cloud_destructive"),
    ("git push --force origin {br}", [enum("br", "main", "dev")], "vcs_destructive"),
    ("kill -9 {pid}", [ToolParam("pid", "int", min_value=1, max_value=3)], "process_kill"),
    ("base64 -d /tmp/{f} | sh", [enum("f", "a.b64")], "cli_denylist"),
])
def test_standard_set_dangerous_templates_are_unsafe_with_witness(template, params, pattern):
    res = verify_tool(tool(template, *params))
    assert_witness_replays(res, template)
    assert pattern in {v["pattern"] for v in res.violations}, str(res)


def test_legacy_condition_only_patterns_still_extract_keywords():
    legacy = ForbiddenPattern("x", "x", "operation contains 'rm -rf' or 'rmdir'")
    assert legacy.literal_keywords() == ["rm -rf", "rmdir"]
    assert verify_tool(tool("rm -rf /{m}", enum("m", "a")), [legacy]).status is UNSAFE


def test_str_carries_reason_and_witness():
    unk = str(verify_tool(tool("exec {cmd:s}", ToolParam("cmd", "string")), DELETE))
    assert "UNKNOWN" in unk and "template_unparsed" in unk
    bad = str(verify_tool(tool("rm -rf /{m}", enum("m", "a"))))
    assert "Operation: rm -rf /a" in bad and "Keyword:" in bad


# --- round 2: findings of the post-implementation verification panel (2026-10-14) --------------

def test_json_schema_enum_is_an_enum_whatever_the_declared_type():
    """{"type": "string", "enum": [...]} (JSON Schema) must enumerate, not be a free string."""
    safe = verify_tool(tool("ls {mode}", ToolParam("mode", "string", enum_values=["-l", "-a"])))
    assert safe.status is SAFE and safe.engine == "enumeration"
    bad = verify_tool(tool("ls; {mode}", ToolParam("mode", "integer", enum_values=["-l", "rm -rf x"])))
    assert bad.status is UNSAFE and bad.violations[0]["counterexample"]["mode"] in ("-l", "rm -rf x")
    from substrate_guard.tool_verifier import tool_definition_from_payload
    t = tool_definition_from_payload({"name": "t", "params": [{"name": "d", "type": "string", "enum": ["docs", "src"]}],
                                      "operation_template": "ls -l /workspace/{d}"})
    assert verify_tool(t).status is SAFE


@pytest.mark.parametrize("template", ["{a} {b}", "{b} {a}"])
def test_witness_is_admissible_for_every_free_string_and_order_independent(template):
    params = [ToolParam("a", "string", pattern=r"[a-z]+"), ToolParam("b", "string")]
    res = verify_tool(tool(template, *params), DELETE)
    assert res.status is UNSAFE
    for v in res.violations:
        assert re.fullmatch(r"[a-z]+", v["counterexample"]["a"]), v
        assert_witness_replays(res, template)


def test_braced_env_var_stays_literal_but_bare_brace_is_an_orphan():
    assert verify_tool(tool("echo ${HOME} && ls {dir}", enum("dir", "./a"))).status is SAFE
    assert verify_tool(tool("echo $HOME && ls {dir}", enum("dir", "./a"))).status is SAFE
    orphan = verify_tool(tool("echo {HOME} && ls {dir}", enum("dir", "./a")))
    assert orphan.status is UNSAFE and orphan.engine == "witness"


def test_case_folding_agrees_between_engines_for_non_ascii():
    """Final-sigma context made whole-string lower() differ from per-segment lower(); every
    engine now folds per code point, so enumeration and z3 agree (both SAFE here)."""
    t = tool("A{x}", enum("x", "Σ", "B"))
    p = [ForbiddenPattern("sig", "", keywords=["ς"], case_sensitive=False)]
    assert verify_tool(t, p).status is verify_tool(t, p, max_enumeration=0).status
    q = [ForbiddenPattern("sig", "", keywords=["aσ"], case_sensitive=False)]
    assert verify_tool(t, q).status is UNSAFE and verify_tool(t, q, max_enumeration=0).status is UNSAFE


def test_unmodeled_param_with_dangerous_literal_template_is_unsafe():
    res = verify_tool(tool("rm -rf /{cmd}", ToolParam("cmd", "enum", enum_values=None)))
    assert res.status is UNSAFE and "cmd" in res.violations[0]["assumptions"]
    benign = verify_tool(tool("sleep {n}", ToolParam("n", "number")))
    assert benign.status is UNKNOWN and benign.reason == "unmodeled_param"


def test_empty_int_domain_abstains():
    res = verify_tool(tool("rm -rf /{n}", ToolParam("n", "int", min_value=5, max_value=1)), DELETE)
    assert res.status is UNKNOWN and res.reason == "unmodeled_param" and "min > max" in res.checks[0]["detail"]


def test_invalid_regex_constraint_is_pattern_unsupported_not_an_exception():
    res = verify_tool(tool("{q}", ToolParam("q", "string", pattern="[")), DELETE)
    assert res.status is UNKNOWN and res.reason == "pattern_unsupported"


@pytest.mark.parametrize("template", ['sh -c "su root {d}"', "ls;su root {d}", "ls && su root {d}", "x|rm -rf /{d}", "$(rm -rf /{d})"])
def test_quoted_and_chained_command_literals_are_unsafe_under_the_default_set(template):
    res = verify_tool(tool(template, enum("d", "a", "b")))
    assert_witness_replays(res, template)


def test_digit_free_keywords_are_decided_exactly_without_a_solver_for_unbounded_ints():
    """' rm -rf' cannot overlap an integer rendering, so an unbounded int never blocks it."""
    pats = [ForbiddenPattern("rd", "", keywords=[" rm -rf", " sudo "]),
            ForbiddenPattern("sql", "", keywords=["drop table"], case_sensitive=False)]
    safe = verify_tool(tool("SELECT * FROM t WHERE id={n}", ToolParam("n", "int", min_value=0)), pats, timeout_ms=5000)
    assert safe.status is SAFE and safe.engine == "z3" and safe.time_ms < 1000
    hit = verify_tool(tool("sudo rm -rf /tmp/{n}", ToolParam("n", "int")), pats)
    assert hit.status is UNSAFE and hit.violations[0]["counterexample"] == {"n": "0"}
    assert_witness_replays(hit, "sudo rm -rf /tmp/{n}")
    big = verify_tool(tool("echo {a} {b}", ToolParam("a", "int", min_value=0, max_value=300),
                           ToolParam("b", "int", min_value=0, max_value=300)), pats)
    assert big.status is SAFE and big.engine == "z3"


# --- round 3: findings of the re-verification panel (2026-10-14) ----------------------------------

def test_unmodeled_glue_assumption_says_when_the_keyword_depends_on_the_empty_rendering():
    glued = verify_tool(tool("rm -{flags}rf {p}", ToolParam("flags", "number"), enum("p", "a", "b")),
                        [ForbiddenPattern("rd", "", keywords=[" rm -rf"])])
    assert glued.status is UNSAFE and "formed only if it renders empty" in glued.violations[0]["assumptions"]["flags"]
    outside = verify_tool(tool("rm -rf {p} {x}", ToolParam("x", "number"), enum("p", "a")),
                          [ForbiddenPattern("rd", "", keywords=[" rm -rf"]), ForbiddenPattern("su", "", keywords=[" sudo "])])
    assert outside.status is UNSAFE and "lies outside it" in outside.violations[0]["assumptions"]["x"]
    # a pattern that found nothing is not 'passed' over a domain that was never covered
    assert {c["outcome"] for c in outside.checks} == {"violated", "unmodeled_param"}


def test_keywords_the_machinery_cannot_represent_are_pattern_unsupported_on_every_engine():
    for template, params in (("{a}", [enum("a", "x", "y")]), ("{a}{n}", [enum("a", "x", "y"), ToolParam("n", "int")]),
                             ("{s}", [ToolParam("s", "string")])):
        res = verify_tool(tool(template, *params), [ForbiddenPattern("bad", "", keywords=["x \x01 y"]),
                                                    ForbiddenPattern("empty", "", keywords=[""])])
        assert res.status is UNKNOWN and res.reason == "pattern_unsupported", (template, str(res))


def test_constrained_free_string_whose_regex_admits_the_keyword_is_decided():
    res = verify_tool(tool("{c}", ToolParam("c", "string", pattern=r"^rm -rf$")), [ForbiddenPattern("rd", "", keywords=[" rm -rf"])])
    assert res.status is UNSAFE and res.violations[0]["counterexample"] == {"c": "rm -rf"}
    ci = verify_tool(tool("{c}", ToolParam("c", "string", pattern=r"[A-Z ]+")),
                     [ForbiddenPattern("dt", "", keywords=["drop table"], case_sensitive=False)])
    assert ci.status is UNSAFE and ci.violations[0]["counterexample"] == {"c": "DROP TABLE"}


def test_digit_bearing_keyword_still_goes_to_the_solver():
    pats = [ForbiddenPattern("k9", "", keywords=[" kill -9 1 "])]
    res = verify_tool(tool("kill -9 {pid}", ToolParam("pid", "int", min_value=1)), pats, timeout_ms=5000)
    assert res.engine == "z3"
    assert res.status in (UNSAFE, UNKNOWN)
    if res.status is UNSAFE:
        assert res.violations[0]["counterexample"] == {"pid": "1"}
