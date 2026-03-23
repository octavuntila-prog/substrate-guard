"""substrate-guard CLI — Unified AI safety verification from kernel to proof.

Commands:
    substrate-guard monitor --agent <id> [--pid <pid>]
        Monitor an AI agent through all 3 layers (eBPF → OPA → Z3)
    
    substrate-guard evaluate --event <json>
        Evaluate a single event against policies
    
    substrate-guard verify --type <code|tool|cli|hw|distill> <artifact>
        Run Z3 formal verification on an artifact
    
    substrate-guard demo --scenario <safe|malicious|injection|abuse>
        Run a demo scenario through the full pipeline
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import logging

from .guard import Guard, SessionReport
from .observe.events import (
    Event, EventType, FileEvent, NetworkEvent, ProcessEvent,
)
from .observe.tracer import AgentTracer, MockScenario
from .policy.engine import PolicyEngine


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("substrate_guard.cli")


# ============================================
# ANSI colors for terminal output
# ============================================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    DIM = "\033[2m"

    @staticmethod
    def ok(s): return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def fail(s): return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def warn(s): return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def info(s): return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def bold(s): return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def dim(s): return f"{C.DIM}{s}{C.RESET}"


def print_banner():
    print(f"""
{C.bold("substrate-guard")} — The Complete Verification Stack
{C.dim("eBPF observes → OPA decides → Z3 proves")}
""")


def print_report(report: SessionReport):
    """Pretty-print a session report."""
    d = report.to_dict()
    verdict = d["verdict"]
    
    if verdict == "SAFE":
        verdict_str = C.ok("✅ SAFE")
    else:
        verdict_str = C.fail("❌ VIOLATIONS DETECTED")

    print(f"\n{'='*60}")
    print(f"  {C.bold('Session Report')} — agent: {C.info(report.agent_id)}")
    print(f"{'='*60}")
    print(f"  Verdict:    {verdict_str}")
    print(f"  Duration:   {report.duration_s:.2f}s")
    print()
    
    # Layer 1: Observe
    print(f"  {C.bold('Layer 1: eBPF Observe')}")
    print(f"    Events captured:    {d['layers']['observe']['events']}")
    print()
    
    # Layer 2: Policy
    print(f"  {C.bold('Layer 2: OPA Policy')}")
    violations = d['layers']['policy']['violations']
    allowed = d['layers']['policy']['allowed']
    v_color = C.ok if violations == 0 else C.fail
    print(f"    Allowed:            {C.ok(allowed)}")
    print(f"    Violations:         {v_color(violations)}")
    print()
    
    # Layer 3: Verify
    print(f"  {C.bold('Layer 3: Z3 Verify')}")
    checked = d['layers']['verify']['checked']
    failures = d['layers']['verify']['failures']
    f_color = C.ok if failures == 0 else C.fail
    print(f"    Verified:           {checked}")
    print(f"    Failures:           {f_color(failures)}")
    print()

    # Detail: violations
    if report.policy_violations > 0:
        print(f"  {C.bold('Violations:')}")
        for ge in report.events:
            if not ge.policy_decision.allowed:
                evt = ge.event
                for reason in ge.policy_decision.reasons:
                    print(f"    {C.fail('✗')} [{evt.type.value}] {reason}")
        print()

    print(f"{'='*60}\n")


def cmd_demo(args):
    """Run a demo scenario through the full pipeline."""
    print_banner()
    
    scenario_name = args.scenario
    scenarios = {
        "safe": ("Safe Web Agent", MockScenario.safe_web_agent),
        "code": ("Code Generation Agent", MockScenario.code_generation),
        "malicious": ("Malicious Agent", MockScenario.malicious_agent),
        "injection": ("Prompt Injection", MockScenario.prompt_injection),
        "abuse": ("Resource Abuse", MockScenario.resource_abuse),
    }

    if scenario_name not in scenarios:
        print(f"Unknown scenario: {scenario_name}")
        print(f"Available: {', '.join(scenarios.keys())}")
        return 1

    label, scenario_fn = scenarios[scenario_name]
    agent_id = f"demo-{scenario_name}"

    print(f"  Scenario: {C.bold(label)}")
    print(f"  Agent:    {C.info(agent_id)}")
    print(f"  Pipeline: eBPF(mock) → OPA(builtin) → Z3")
    print()

    guard = Guard(
        observe=True,
        policy="nonexistent/",
        verify=True,
        use_mock=True,
    )

    with guard.monitor(agent_id) as session:
        # Inject scenario events
        scenario_fn(guard._tracer, agent_id)
        session.process_events()

        # Print each event as it flows through
        for ge in session._events:
            evt = ge.event
            status = C.ok("ALLOW") if ge.policy_decision.allowed else C.fail("DENY")
            severity = {
                "info": C.dim("INFO"),
                "warn": C.warn("WARN"),
                "critical": C.fail("CRIT"),
            }.get(evt.severity.value, evt.severity.value)
            
            # Event detail
            detail = ""
            if hasattr(evt, 'path'):
                detail = evt.path
            elif hasattr(evt, 'remote_port'):
                detail = f"{getattr(evt, 'remote_ip', '?')}:{evt.remote_port}"
                if hasattr(evt, 'domain') and evt.domain:
                    detail += f" ({evt.domain})"
            elif hasattr(evt, 'filename'):
                detail = f"{evt.filename} {' '.join(str(a) for a in getattr(evt, 'args', []))}"
            
            print(f"  [{severity}] {evt.type.value:20s} → {status}  {C.dim(detail)}")
            
            if not ge.policy_decision.allowed:
                for reason in ge.policy_decision.reasons:
                    print(f"         {C.fail('└─')} {reason}")

    report = session.report()
    print_report(report)
    
    return 0 if report.policy_violations == 0 else 1


def cmd_evaluate(args):
    """Evaluate a single event against policies."""
    print_banner()
    
    try:
        event_data = json.loads(args.event)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}")
        return 1

    engine = PolicyEngine(
        policy_path=args.policy or "nonexistent/",
        use_opa_binary=not args.no_opa,
    )
    
    decision = engine.evaluate(event_data)
    
    if decision.allowed:
        print(f"  {C.ok('✅ ALLOWED')}")
    else:
        print(f"  {C.fail('❌ DENIED')}")
        for reason in decision.reasons:
            print(f"    {C.fail('•')} {reason}")
    
    print(f"  {C.dim(f'Latency: {decision.latency_ms:.2f}ms')}")
    return 0 if decision.allowed else 1


def cmd_monitor(args):
    """Monitor an agent (interactive mode)."""
    print_banner()
    
    agent_id = args.agent
    print(f"  Monitoring agent: {C.info(agent_id)}")
    
    if args.pid:
        print(f"  Tracing PID: {args.pid}")
    
    print(f"  Policy: {args.policy or 'builtin'}")
    print(f"  Press Ctrl+C to stop\n")

    guard = Guard(
        observe=True,
        policy=args.policy or "nonexistent/",
        verify=True,
        use_mock=not args.live,
    )

    try:
        with guard.monitor(agent_id, pid=args.pid) as session:
            if guard._tracer and not guard._tracer.is_mock:
                # Real eBPF mode — stream events
                for event in guard._tracer.events():
                    ge = guard.evaluate_event(event)
                    session._events.append(ge)
                    
                    status = C.ok("�allow") if ge.policy_decision.allowed else C.fail("DENY")
                    print(f"  [{event.type.value:20s}] {status}  agent={event.agent_id}")
            else:
                # Mock mode — wait for Ctrl+C
                print(f"  {C.warn('Mock mode')} — no real eBPF. Use --live for real tracing.")
                print(f"  Use 'substrate-guard demo' to see the pipeline in action.\n")
                while True:
                    time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n  Stopped.")
        report = session.report()
        print_report(report)
    
    return 0


def cmd_benchmark(args):
    """Run benchmark across all scenarios and print results."""
    print_banner()
    print(f"  {C.bold('Benchmark: Full Pipeline')}")
    print(f"  Running all scenarios through eBPF(mock) → OPA(builtin) → Z3\n")

    scenarios = {
        "safe_web": ("Safe Web Agent", MockScenario.safe_web_agent),
        "code_gen": ("Code Generation", MockScenario.code_generation),
        "malicious": ("Malicious Agent", MockScenario.malicious_agent),
        "injection": ("Prompt Injection", MockScenario.prompt_injection),
        "abuse": ("Resource Abuse (150 calls)", MockScenario.resource_abuse),
    }

    results = []

    for key, (label, scenario_fn) in scenarios.items():
        guard = Guard(observe=True, policy="nonexistent/", verify=True, use_mock=True)
        
        start = time.perf_counter()
        with guard.monitor(f"bench-{key}") as session:
            scenario_fn(guard._tracer, f"bench-{key}")
            session.process_events()
        elapsed = (time.perf_counter() - start) * 1000
        
        report = session.report()
        results.append({
            "scenario": label,
            "events": report.events_observed,
            "violations": report.policy_violations,
            "latency_ms": elapsed,
            "per_event_ms": elapsed / max(report.events_observed, 1),
        })

    # Print table
    print(f"  {'Scenario':<30s} {'Events':>7s} {'Violations':>11s} {'Total ms':>9s} {'Per-event':>10s}")
    print(f"  {'-'*30} {'-'*7} {'-'*11} {'-'*9} {'-'*10}")
    
    total_events = 0
    total_violations = 0
    
    for r in results:
        v_str = C.ok(str(r['violations'])) if r['violations'] == 0 else C.fail(str(r['violations']))
        print(f"  {r['scenario']:<30s} {r['events']:>7d} {v_str:>20s} {r['latency_ms']:>8.1f}ms {r['per_event_ms']:>8.2f}ms")
        total_events += r['events']
        total_violations += r['violations']

    print(f"  {'-'*30} {'-'*7} {'-'*11} {'-'*9} {'-'*10}")
    tv_str = C.ok(str(total_violations)) if total_violations == 0 else C.fail(str(total_violations))
    print(f"  {'TOTAL':<30s} {total_events:>7d} {tv_str:>20s}")
    print()
    
    return 0


def cmd_export(args):
    """Run a demo scenario with chain enabled, then export compliance report."""
    print_banner()

    framework = args.framework.upper()
    output = args.output or f"compliance_{framework.lower()}.json"
    scenario = args.scenario

    print(f"  Framework: {C.bold(framework)}")
    print(f"  Scenario:  {scenario}")
    print(f"  Output:    {output}")
    print()

    # Run scenario with chain enabled
    from .chain import AuditChain
    from .compliance import ComplianceExporter

    guard = Guard(
        observe=True,
        policy="nonexistent/",
        verify=True,
        chain=True,
        hmac_secret=args.secret or "substrate-guard-demo",
        use_mock=True,
    )

    scenarios = {
        "safe": ("Safe Web Agent", MockScenario.safe_web_agent),
        "code": ("Code Generation", MockScenario.code_generation),
        "malicious": ("Malicious Agent", MockScenario.malicious_agent),
        "injection": ("Prompt Injection", MockScenario.prompt_injection),
        "all": None,  # run all scenarios
    }

    agent_id = f"export-{scenario}"

    with guard.monitor(agent_id) as session:
        if scenario == "all":
            for key, val in scenarios.items():
                if val is not None:
                    label, fn = val
                    fn(guard._tracer, agent_id)
                    session.process_events()
        else:
            label, fn = scenarios[scenario]
            fn(guard._tracer, agent_id)
            session.process_events()

    report = session.report()

    # Export
    exporter = ComplianceExporter(
        chain=guard._chain,
        report=report,
        org_name=args.org or "Aisophical SRL",
    )

    if framework == "SOC2":
        exporter.export_soc2(output)
    elif framework == "ISO27001":
        exporter.export_iso27001(output)
    elif framework == "ISO42001":
        exporter.export_iso42001(output)
    elif framework == "SUMMARY":
        exporter.export_summary(output)
    elif framework == "CHAIN":
        guard._chain.export(output)
    else:
        print(f"  {C.fail('Unknown framework')}: {framework}")
        return 1

    # Also export the raw chain
    if framework != "CHAIN":
        chain_path = output.replace(".json", "_chain.json")
        guard._chain.export(chain_path)
        print(f"  {C.ok('Chain exported:')} {chain_path} ({guard._chain.length} entries)")

    print(f"  {C.ok('Report exported:')} {output}")
    print()

    # Print chain summary
    chain_ok, _ = guard._chain.verify()
    print(f"  Chain integrity: {C.ok('VERIFIED') if chain_ok else C.fail('BROKEN')}")
    print(f"  Chain length:    {guard._chain.length}")
    print(f"  Head hash:       {guard._chain.head_hash[:16]}...")
    print()

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="substrate-guard",
        description="AI Black Box — eBPF → OPA → Z3 → HMAC Chain",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Demo
    demo_parser = subparsers.add_parser("demo", help="Run a demo scenario")
    demo_parser.add_argument("--scenario", "-s", default="safe",
                            choices=["safe", "code", "malicious", "injection", "abuse"],
                            help="Scenario to run")

    # Evaluate
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate a single event")
    eval_parser.add_argument("--event", "-e", required=True, help="JSON event data")
    eval_parser.add_argument("--policy", "-p", help="Path to .rego policy file/dir")
    eval_parser.add_argument("--no-opa", action="store_true",
                            help="Use built-in evaluator instead of OPA binary")

    # Monitor
    mon_parser = subparsers.add_parser("monitor", help="Monitor an agent")
    mon_parser.add_argument("--agent", "-a", required=True, help="Agent ID")
    mon_parser.add_argument("--pid", type=int, help="PID to trace")
    mon_parser.add_argument("--policy", "-p", help="Path to .rego policy file/dir")
    mon_parser.add_argument("--live", action="store_true",
                           help="Use real eBPF (requires root + kernel 5.4+)")

    # Benchmark
    subparsers.add_parser("benchmark", help="Run benchmark across all scenarios")

    # Export compliance reports
    export_parser = subparsers.add_parser("export", help="Export compliance evidence")
    export_parser.add_argument("--framework", "-f", required=True,
                              choices=["SOC2", "ISO27001", "ISO42001", "SUMMARY", "CHAIN"],
                              help="Compliance framework to export")
    export_parser.add_argument("--scenario", "-s", default="all",
                              choices=["safe", "code", "malicious", "injection", "all"],
                              help="Scenario to run before export")
    export_parser.add_argument("--output", "-o", help="Output file path")
    export_parser.add_argument("--secret", help="HMAC secret for chain (default: demo key)")
    export_parser.add_argument("--org", help="Organization name for report")

    args = parser.parse_args()

    if args.command == "demo":
        sys.exit(cmd_demo(args))
    elif args.command == "evaluate":
        sys.exit(cmd_evaluate(args))
    elif args.command == "monitor":
        sys.exit(cmd_monitor(args))
    elif args.command == "benchmark":
        sys.exit(cmd_benchmark(args))
    elif args.command == "export":
        sys.exit(cmd_export(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
