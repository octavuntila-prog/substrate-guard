#!/usr/bin/env python3
"""Simulate an external orchestrator feeding events into Guard without eBPF.

Uses :meth:`GuardSession.inject_and_evaluate` — same path as SubstrateGuard-style
integrations when traces are already normalized to :class:`~substrate_guard.observe.events.Event`.

Run from repo root::

    python examples/orchestrator_inject_events.py
"""

from __future__ import annotations

from substrate_guard.guard import Guard
from substrate_guard.observe.events import EventType, FileEvent, NetworkEvent


def main() -> None:
    guard = Guard(
        observe=True,
        policy="nonexistent/",
        verify=True,
        use_mock=True,
    )
    agent_id = "orchestrator-demo"

    with guard.monitor(agent_id) as session:
        session.inject_and_evaluate(
            FileEvent(
                type=EventType.FILE_WRITE,
                agent_id=agent_id,
                path="/workspace/out.py",
            )
        )
        session.inject_and_evaluate(
            NetworkEvent(
                type=EventType.NETWORK_CONNECT,
                agent_id=agent_id,
                remote_ip="1.1.1.1",
                remote_port=443,
                domain="api.example.com",
            )
        )

    report = session.report()
    d = report.to_dict()
    # Avoid emoji in summary_line() on Windows consoles (cp1252).
    print("verdict:", d.get("verdict"), "| duration_s:", d.get("duration_s"))
    print("events_observed:", report.events_observed)
    print("policy_violations:", report.policy_violations)


if __name__ == "__main__":
    main()
