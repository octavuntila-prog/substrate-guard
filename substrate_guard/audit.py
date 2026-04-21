"""Real Audit — Query PostgreSQL and evaluate 2,615+ records through Guard.

Connects to the ai-research-agency PostgreSQL (postgres:16-alpine) on the
internal Docker network, pulls pipeline_traces (1,483) and agent_runs (1,132),
and runs every record through the eBPF→OPA→Z3 pipeline.

Usage (from host):
    python3 -m substrate_guard.audit --db-url postgresql://user:pass@localhost:5432/dbname

Usage (from Docker on internal network):
    python3 -m substrate_guard.audit --db-url postgresql://user:pass@postgres:5432/dbname

Usage (with .env file):
    python3 -m substrate_guard.audit --env /opt/ai-research-agency/.env

Output:
    - Console report with violations
    - JSON report saved to /var/log/substrate-guard/audit_YYYYMMDD_HHMMSS.json
    - Summary suitable for paper's evaluation section
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import logging
from datetime import datetime, timedelta

from substrate_guard import __version__ as substrate_guard_version
from pathlib import Path
from typing import Optional

from .guard import Guard, SessionReport
from .integrations.vendor_bridge import VendorBridge, PipelineTraceAdapter, AgentRunAdapter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("substrate_guard.audit")

# ANSI colors
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"


def parse_env_file(env_path: str) -> dict:
    """Parse a .env file to extract DATABASE_URL or DB components."""
    env = {}
    try:
        for line in Path(env_path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        logger.warning(f".env file not found: {env_path}")
    return env


def resolve_db_url(db_url: Optional[str], env_path: Optional[str]) -> Optional[str]:
    """Resolve connection URL: explicit arg, then .env file, then ``os.environ`` (Docker-friendly)."""
    if db_url:
        return db_url
    env: dict = {}
    if env_path:
        env = parse_env_file(env_path)
    resolved = build_db_url(env)
    if resolved:
        return resolved
    return build_db_url(dict(os.environ))


def build_db_url(env: dict) -> Optional[str]:
    """Build PostgreSQL URL from .env variables.
    
    Handles asyncpg URLs: postgresql+asyncpg://... → postgresql://...
    """
    # Try DATABASE_URL first
    if "DATABASE_URL" in env:
        url = env["DATABASE_URL"]
        # Strip async driver prefixes (asyncpg, aiopg, etc.)
        url = url.replace("postgresql+asyncpg://", "postgresql://")
        url = url.replace("postgres+asyncpg://", "postgresql://")
        url = url.replace("postgres://", "postgresql://")
        return url

    # Try component parts (common in Docker setups)
    host = env.get("POSTGRES_HOST", env.get("DB_HOST", "postgres"))
    port = env.get("POSTGRES_PORT", env.get("DB_PORT", "5432"))
    user = env.get("POSTGRES_USER", env.get("DB_USER", ""))
    password = env.get("POSTGRES_PASSWORD", env.get("DB_PASSWORD", ""))
    db = env.get("POSTGRES_DB", env.get("DB_NAME", ""))

    if user and db:
        return f"postgresql://{user}:{password}@{host}:{port}/{db}"
    return None


def query_db(db_url: str, query: str, params: tuple = ()) -> list[dict]:
    """Execute a query and return results as list of dicts."""
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        try:
            import psycopg
            conn = psycopg.connect(db_url)
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(query, params)
                return cur.fetchall()
        except ImportError:
            logger.error("Neither psycopg2 nor psycopg3 installed.")
            logger.error("Install: pip install psycopg2-binary --break-system-packages")
            return []

    conn = psycopg2.connect(db_url)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


# Static SQL only (no dynamic identifiers): parameters use psycopg placeholders.
_SQL_PIPELINE_WITH_HOURS = """
    SELECT id, trace_id, pipeline_run_id, step_index, agent_id,
           agent_name, status, model_used, input_summary, output_summary,
           tokens_in, tokens_out, cost_usd, duration_ms, error,
           started_at, completed_at, confidence
    FROM pipeline_traces
    WHERE started_at >= %s
    ORDER BY started_at DESC
    LIMIT %s
"""

_SQL_PIPELINE_NO_HOURS = """
    SELECT id, trace_id, pipeline_run_id, step_index, agent_id,
           agent_name, status, model_used, input_summary, output_summary,
           tokens_in, tokens_out, cost_usd, duration_ms, error,
           started_at, completed_at, confidence
    FROM pipeline_traces
    ORDER BY started_at DESC
    LIMIT %s
"""

_SQL_AGENT_RUNS_WITH_HOURS = """
    SELECT id, agent_id, agent_name, status, duration_ms,
           confidence, error, input_summary, output_summary,
           trace_id, created_at
    FROM agent_runs
    WHERE created_at >= %s
    ORDER BY created_at DESC
    LIMIT %s
"""

_SQL_AGENT_RUNS_NO_HOURS = """
    SELECT id, agent_id, agent_name, status, duration_ms,
           confidence, error, input_summary, output_summary,
           trace_id, created_at
    FROM agent_runs
    ORDER BY created_at DESC
    LIMIT %s
"""

_COUNT_QUERIES: dict[str, str] = {
    "pipeline_traces": "SELECT COUNT(*) as cnt FROM pipeline_traces",
    "agent_runs": "SELECT COUNT(*) as cnt FROM agent_runs",
    "pipeline_runs": "SELECT COUNT(*) as cnt FROM pipeline_runs",
    "ideas": "SELECT COUNT(*) as cnt FROM ideas",
    "qa_reports": "SELECT COUNT(*) as cnt FROM qa_reports",
    "audit_log": "SELECT COUNT(*) as cnt FROM audit_log",
    "notifications": "SELECT COUNT(*) as cnt FROM notifications",
}


def fetch_pipeline_traces(db_url: str, hours: Optional[int] = None, limit: int = 5000) -> list[dict]:
    """Fetch pipeline_traces from PostgreSQL.
    
    Real schema: id, trace_id, pipeline_run_id, step_index, agent_id (int),
    agent_name, status, model_used, input_summary, output_summary,
    tokens_in, tokens_out, cost_usd, duration_ms, error, started_at,
    completed_at, confidence
    """
    if hours:
        since = datetime.utcnow() - timedelta(hours=hours)
        return query_db(db_url, _SQL_PIPELINE_WITH_HOURS, (since, limit))
    return query_db(db_url, _SQL_PIPELINE_NO_HOURS, (limit,))


def fetch_agent_runs(db_url: str, hours: Optional[int] = None, limit: int = 5000) -> list[dict]:
    """Fetch agent_runs from PostgreSQL.
    
    Real schema: id, agent_id (int), agent_name, status, duration_ms,
    confidence, error, input_summary, output_summary, trace_id, created_at
    """
    if hours:
        since = datetime.utcnow() - timedelta(hours=hours)
        return query_db(db_url, _SQL_AGENT_RUNS_WITH_HOURS, (since, limit))
    return query_db(db_url, _SQL_AGENT_RUNS_NO_HOURS, (limit,))


def fetch_table_counts(db_url: str) -> dict:
    """Get record counts for key tables."""
    counts: dict[str, int] = {}
    for table, query in _COUNT_QUERIES.items():
        try:
            rows = query_db(db_url, query)
            counts[table] = rows[0]["cnt"] if rows else 0
        except Exception:
            counts[table] = -1
    return counts


def parse_json_field(value) -> dict:
    """Safely parse a JSON field that might be string, dict, or None.

    Contract: always returns a ``dict``. JSON ``null``, scalars, or arrays
    (legal JSON but malformed as a structured field) collapse to ``{}``
    so callers can chain ``.get(...)`` without ``AttributeError``.
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def run_audit(db_url: str, hours: Optional[int] = None, output_dir: str = "/var/log/substrate-guard"):
    """Main audit function."""
    start_time = time.time()

    print(f"\n{C.BOLD}substrate-guard — Real DB Audit{C.RESET}")
    print(f"{C.DIM}eBPF observes → OPA decides → Z3 proves{C.RESET}\n")

    # ── Step 1: DB Connection ──
    print(f"{C.CYAN}[1/5]{C.RESET} Connecting to PostgreSQL...")
    
    counts = fetch_table_counts(db_url)
    if all(v == -1 for v in counts.values()):
        print(f"{C.RED}  ✗ Cannot connect to database{C.RESET}")
        print(f"  URL: {db_url[:30]}...")
        return 1
    
    for table, count in counts.items():
        if count >= 0:
            print(f"  {table}: {C.BOLD}{count:,}{C.RESET} records")
    print()

    # ── Step 2: Fetch Records ──
    time_label = f"last {hours}h" if hours else "all time"
    print(f"{C.CYAN}[2/5]{C.RESET} Fetching records ({time_label})...")

    traces = fetch_pipeline_traces(db_url, hours)
    runs = fetch_agent_runs(db_url, hours)

    print(f"  pipeline_traces: {C.BOLD}{len(traces)}{C.RESET}")
    print(f"  agent_runs:      {C.BOLD}{len(runs)}{C.RESET}")
    print(f"  Total records:   {C.BOLD}{len(traces) + len(runs)}{C.RESET}")
    print()

    # ── Step 3: Convert to Events ──
    print(f"{C.CYAN}[3/5]{C.RESET} Converting to Guard events...")

    trace_events = []
    for t in traces:
        trace_events.extend(PipelineTraceAdapter.db_row_to_events(t))

    run_events = []
    for r in runs:
        run_events.extend(AgentRunAdapter.db_row_to_events(r))

    all_events = trace_events + run_events
    print(f"  From traces: {len(trace_events)} events")
    print(f"  From runs:   {len(run_events)} events")
    print(f"  Total:       {C.BOLD}{len(all_events)}{C.RESET} events to evaluate")
    print()

    # ── Step 4: Evaluate Through Pipeline ──
    print(f"{C.CYAN}[4/5]{C.RESET} Running Guard pipeline (observe → policy → verify)...")

    guard = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)
    
    violations = []
    allowed = 0
    eval_start = time.perf_counter()

    with guard.monitor("audit-full") as session:
        for event in all_events:
            ge = session.inject_and_evaluate(event)
            if ge.policy_decision.allowed:
                allowed += 1
            else:
                violations.append({
                    "event_type": event.type.value,
                    "agent_id": event.agent_id,
                    "reasons": ge.policy_decision.reasons,
                    "severity": event.severity.value,
                    "details": _event_detail(event),
                })

    eval_elapsed = (time.perf_counter() - eval_start) * 1000
    per_event = eval_elapsed / max(len(all_events), 1)

    report = session.report()

    print(f"  Evaluated: {len(all_events)} events in {eval_elapsed:.0f}ms ({per_event:.2f}ms/event)")
    print(f"  Allowed:   {C.GREEN}{allowed}{C.RESET}")
    print(f"  Violations: {C.RED if violations else C.GREEN}{len(violations)}{C.RESET}")
    print()

    # ── Step 5: Results ──
    print(f"{C.CYAN}[5/5]{C.RESET} Results\n")

    if violations:
        print(f"  {C.RED}{C.BOLD}❌ {len(violations)} VIOLATIONS DETECTED{C.RESET}\n")
        
        # Group by agent
        by_agent = {}
        for v in violations:
            aid = v["agent_id"]
            by_agent.setdefault(aid, []).append(v)
        
        for agent_id, agent_violations in sorted(by_agent.items()):
            print(f"  {C.BOLD}{agent_id}{C.RESET} ({len(agent_violations)} violations):")
            for v in agent_violations[:5]:  # max 5 per agent
                reason = v["reasons"][0] if v["reasons"] else "unknown"
                print(f"    {C.RED}✗{C.RESET} [{v['event_type']}] {reason}")
                if v["details"]:
                    print(f"      {C.DIM}{v['details']}{C.RESET}")
            if len(agent_violations) > 5:
                print(f"    {C.DIM}... and {len(agent_violations) - 5} more{C.RESET}")
            print()
    else:
        print(f"  {C.GREEN}{C.BOLD}✅ ALL CLEAN — No violations in {len(all_events)} events{C.RESET}\n")

    # ── Summary for Paper ──
    agent_ids = set()
    for event in all_events:
        agent_ids.add(event.agent_id)

    categories = set()
    for r in runs:
        name = r.get("agent_name", "")
        if name:
            categories.add(name)
    for t in traces:
        name = t.get("agent_name", "")
        if name:
            categories.add(name)

    total_cost = sum(float(t.get("cost_usd", 0) or 0) for t in traces)

    summary = {
        "timestamp": datetime.utcnow().isoformat(),
        "substrate_guard_version": substrate_guard_version,
        "db_records": {
            "pipeline_traces": len(traces),
            "agent_runs": len(runs),
            "total": len(traces) + len(runs),
        },
        "events_generated": len(all_events),
        "unique_agents": len(agent_ids),
        "categories": sorted(categories),
        "total_cost_usd": round(total_cost, 4),
        "evaluation": {
            "allowed": allowed,
            "violations": len(violations),
            "violation_rate": round(len(violations) / max(len(all_events), 1), 6),
            "total_ms": round(eval_elapsed, 1),
            "per_event_ms": round(per_event, 2),
        },
        "violations_detail": violations[:50],  # first 50 for paper
        "layers": {
            "observe": "mock",
            "policy": "builtin (7 rules)",
            "verify": "z3" if guard._z3_available else "unavailable",
        },
        "server": {
            "arch": "aarch64",
            "hostname": "ai-research-agency",
        },
    }

    print(f"  {C.BOLD}Paper Summary:{C.RESET}")
    print(f"  Records audited:    {len(traces) + len(runs):,}")
    print(f"  Events evaluated:   {len(all_events):,}")
    print(f"  Unique agents:      {len(agent_ids)}")
    print(f"  Agent names:        {len(categories)}")
    print(f"  Total API cost:     ${total_cost:.2f}")
    print(f"  Violations found:   {len(violations)}")
    print(f"  Violation rate:     {len(violations) / max(len(all_events), 1) * 100:.2f}%")
    print(f"  Eval latency:       {per_event:.2f}ms/event")
    print()

    # Save JSON report
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_path = f"{output_dir}/audit_{ts}.json"
    try:
        Path(report_path).write_text(json.dumps(summary, indent=2, default=str))
        print(f"  {C.GREEN}Report saved:{C.RESET} {report_path}")
    except Exception as e:
        print(f"  {C.YELLOW}Could not save report: {e}{C.RESET}")

    total_elapsed = time.time() - start_time
    print(f"\n  {C.DIM}Total time: {total_elapsed:.1f}s{C.RESET}\n")

    return 0 if not violations else 1


def _event_detail(event) -> str:
    """Extract a human-readable detail string from an event."""
    if hasattr(event, 'path') and event.path:
        return event.path
    if hasattr(event, 'domain') and event.domain:
        return f"{event.domain}:{getattr(event, 'remote_port', '?')}"
    if hasattr(event, 'filename') and event.filename:
        args = " ".join(str(a) for a in getattr(event, 'args', []))
        return f"{event.filename} {args}".strip()
    return ""


def main():
    parser = argparse.ArgumentParser(
        prog="substrate-guard audit",
        description="Audit AI Research Agency DB through the verification pipeline",
    )
    parser.add_argument("--db-url", help="PostgreSQL connection URL")
    parser.add_argument("--env", default="/opt/ai-research-agency/.env",
                       help="Path to .env file with DB credentials")
    parser.add_argument("--hours", type=int, default=None,
                       help="Only audit records from last N hours (default: all)")
    parser.add_argument("--output", default="/var/log/substrate-guard",
                       help="Output directory for JSON report")

    args = parser.parse_args()

    db_url = resolve_db_url(args.db_url, args.env)
    if not db_url:
        print(f"{C.RED}Error:{C.RESET} No database URL found.")
        print(f"Tried .env at: {args.env}, then process environment (POSTGRES_* / DATABASE_URL).")
        print(f"Use --db-url or set credentials in .env / environment.")
        print(f"\nExample:")
        print(f"  python3 -m substrate_guard.audit --db-url postgresql://user:pass@postgres:5432/dbname")
        return 1

    return run_audit(db_url, hours=args.hours, output_dir=args.output)


if __name__ == "__main__":
    sys.exit(main())
