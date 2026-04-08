# Security policy

## Supported versions

| Version | Supported          |
|---------|-------------------|
| 13.x    | Yes               |
| pre-13  | Best effort only  |

Use the latest patch release of **13.x** for dependency fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

**Preferred:** email **octav@aisophical.com** with:

- A short description of the issue and impact
- Steps to reproduce (or a proof-of-concept) if possible
- Affected version(s) and component (e.g. `substrate_guard.cli`, `guard.py`, verifiers)

You should receive an acknowledgment within a few business days. We will coordinate a fix, release, and public advisory timeline with you before full disclosure.

## Scope

**In scope**

- This repository (`substrate-guard`): Python package code under `substrate_guard/`, CLI entrypoints, and documented install paths (`pip install -e .`, Dockerfiles in this repo).

**Out of scope (by default)**

- Deployments and daemons that are not part of this repository (e.g. production-only services, forks with custom patches).
- Theoretical issues in upstream dependencies without a practical exploit path in our usage.
- Regex / policy **bypasses** that are already acknowledged as limitations (see README *Known Limitations* and `docs/AUDIT_COMPLEX.md` honest-gap inventory) — still welcome as regular issues if you have a concrete improvement.

## Supply chain

- CI runs **`pip-audit`** on the installed package environment to surface known CVEs in declared dependencies.
- **Dependabot** is enabled for `pip` and GitHub Actions.
- **CodeQL** runs on the default branch and pull requests for Python analysis.
- **Bandit** is run against `substrate_guard/` using **`bandit.yaml`** (policy) and **`tests/test_bandit_policy.py`** so regressions fail CI the same way as unit tests.

Hardening is iterative; patches that tighten boundaries without breaking public APIs are especially welcome.
