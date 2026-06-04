"""Runtime capability checks (``substrate-guard doctor``)."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Callable


def _line(name: str, ok: bool, detail: str = "") -> None:
    status = "OK" if ok else "MISSING"
    extra = f" — {detail}" if detail else ""
    print(f"  {name:24s} {status:8s}{extra}")


def _try(msg: str, fn: Callable[[], object]) -> tuple[bool, str]:
    try:
        fn()
        return True, ""
    except Exception as e:
        return False, str(e)


def run_doctor(json_output: bool = False) -> int:
    """Print a concise report. Exit 0 always unless --strict (future)."""
    if json_output:
        print('{"error": "use plain text for now"}', file=sys.stderr)
        return 2

    print("substrate-guard — environment diagnostics")
    print("=" * 52)

    import substrate_guard

    print(f"  {'package':24s} {substrate_guard.__version__}")
    print(f"  {'Python':24s} {sys.version.split()[0]} ({sys.platform})")

    z3_ok, z3_err = _try("import z3", lambda: __import__("z3"))
    _line("z3-solver (Layer 3)", z3_ok, "" if z3_ok else z3_err[:60])

    opa = shutil.which("opa")
    _line("OPA binary", opa is not None, opa or "not in PATH — built-in policy only")

    try:
        from bcc import BPF  # noqa: F401
        bcc_import_ok, bcc_err = True, ""
    except Exception as e:
        bcc_import_ok, bcc_err = False, str(e)[:70]

    # Import alone over-claims: bcc compiles agent_trace.c at runtime (LLVM),
    # which needs kernel headers. Missing headers => eBPF cannot compile and
    # the live path falls back to mock (validated 3 Jun on Research server).
    if not bcc_import_ok:
        _line("bcc (eBPF)", False, bcc_err)
    elif not sys.platform.startswith("linux"):
        _line("bcc (eBPF)", True, "import ok; eBPF needs Linux (mock on this platform)")
    elif Path(f"/lib/modules/{os.uname().release}/build").exists():
        _line("bcc (eBPF)", True, "import + kernel headers ok (real eBPF can compile)")
    else:
        _line("bcc (eBPF)", False, "import ok BUT kernel headers MISSING -> eBPF cannot compile; live path falls back to mock")

    for name, mod in (
        ("psycopg2 (Postgres CI)", "psycopg2"),
        ("cryptography", "cryptography"),
    ):
        ok, err = _try(f"import {mod}", lambda m=mod: __import__(m))
        _line(name, ok, err[:50] if err else "")

    policy_dir = Path(__file__).resolve().parent / "policy" / "policies"
    rego_ok = policy_dir.is_dir() and any(policy_dir.glob("*.rego"))
    _line("policy/*.rego on disk", rego_ok, str(policy_dir) if rego_ok else "none")

    print()
    print("Reference: docs/FUNCTIONAL_ROADMAP.md")
    print("Quick check: substrate-guard demo --scenario safe")
    return 0
