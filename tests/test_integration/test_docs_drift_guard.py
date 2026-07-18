"""Documentation drift-guard.

Fails the build when a machine-checkable doc claim drifts from its committed
source of truth. This closes the silent-regression channel that the audit
(docs/AUDIT_COMPLEX_2026-06-07.md, Recommendation #7) blamed for the original
headline-metric drift: the README once stated 79 violations / 0.54% / 0.14 ms/event
while the real measured values were 0 / 0.0% / 3.41 ms/event.

Scope (deliberately conservative — only robustly-sourced claims):
  - the smoke-audit JSON is internally consistent (the arithmetic holds);
  - the package version agrees across pyproject, the latest smoke-audit JSON, and README;
  - the README "Production Results" metrics match the latest smoke-audit JSON;
  - the smoke-compliance chain length matches the smoke-audit event count;
  - the advertised policy-rule count is consistent across compliance.py and the JSON.

Version-pinned historical numbers (per-release test/LOC counts) are intentionally
NOT guarded here — they are snapshot-dated prose, not a live source of truth.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "docs" / "deploy-verification"


def _latest(glob_pat: str) -> dict:
    files = list(DEPLOY.glob(glob_pat))
    assert files, f"no file matching {glob_pat} in {DEPLOY}"
    parsed = [json.loads(f.read_text(encoding="utf-8")) for f in files]
    return max(parsed, key=lambda d: d.get("timestamp") or d.get("generated_at") or "")


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "version not found in pyproject.toml"
    return m.group(1)


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def _readme_production_section() -> str:
    readme = _readme()
    # Anchor on the section HEADING, not the first prose occurrence: the thesis
    # legitimately cross-references "See Production Results." (2026-07-18), and
    # slicing at that mention returned the thesis tail instead of the metrics
    # table (CI red on 78fa058 — this guard caught its own fragile anchor).
    m = re.search(r"\n#{2,3} Production Results", readme)
    assert m, "README has no Production Results section heading"
    after = readme[m.end():]
    return re.split(r"\n#{2,3} ", after)[0]


def test_smoke_audit_internally_consistent():
    a = _latest("*_smoke_audit_*.json")
    ev = a["evaluation"]
    assert ev["allowed"] + ev["violations"] == a["events_generated"], \
        "allowed + violations must equal events_generated"
    if a["events_generated"]:
        assert ev["violation_rate"] == pytest.approx(
            100.0 * ev["violations"] / a["events_generated"], abs=0.01
        ), "violation_rate inconsistent with violations/events"
        assert ev["per_event_ms"] == pytest.approx(
            ev["total_ms"] / a["events_generated"], abs=0.02
        ), "per_event_ms inconsistent with total_ms/events"


def test_version_consistent_across_artifacts():
    v = _pyproject_version()
    assert _latest("*_smoke_audit_*.json")["substrate_guard_version"] == v, \
        "latest smoke-audit JSON version disagrees with pyproject"
    assert v in _readme(), f"README does not mention the current version {v}"


def test_readme_production_metrics_match_smoke_audit():
    a = _latest("*_smoke_audit_*.json")
    section = _readme_production_section()
    ev = a["evaluation"]
    assert str(a["events_generated"]) in section, \
        "README events count drifted from smoke-audit JSON"
    assert str(ev["per_event_ms"]) in section, \
        "README latency drifted from smoke-audit JSON (per_event_ms)"
    assert f'{ev["violation_rate"]}' in section, \
        "README violation rate drifted from smoke-audit JSON"


def test_compliance_chain_length_matches_audit_events():
    audit = _latest("*_smoke_audit_*.json")
    comp = _latest("*_smoke_compliance_*.json")
    assert comp["chain_integrity"]["chain_length"] == audit["events_generated"], \
        "smoke-compliance chain_length disagrees with smoke-audit events_generated"


def test_policy_rule_count_consistent():
    comp = _latest("*_smoke_compliance_*.json")
    compliance_src = (ROOT / "substrate_guard" / "compliance.py").read_text(encoding="utf-8")
    # The advertised "7 rules" must appear in both the source claim and the
    # exported compliance artifact (cross-artifact agreement).
    assert "7 rules" in compliance_src, "compliance.py no longer states '7 rules'"
    assert "7 rules" in json.dumps(comp), "smoke-compliance JSON no longer states '7 rules'"
