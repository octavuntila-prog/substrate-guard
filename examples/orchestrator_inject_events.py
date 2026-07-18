#!/usr/bin/env python3
"""External orchestrator feeding REAL events into Guard without eBPF (L1-real, inject).

Uses :meth:`GuardSession.inject_and_evaluate` — the same path as SubstrateGuard-style
integrations when traces are already normalized to
:class:`~substrate_guard.observe.events.Event`. Constructing the Guard with
``source="inject"`` labels this honestly: the report's ``observe.source`` is
``"inject"`` (real events via API, cross-platform, NO kernel) — NOT ``"mock"``
(which would hide that the events are real) and NOT ``"eBPF"`` (no kernel here).

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
        source="inject",   # real events via API, honestly labeled (not mock, not eBPF)
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
    print("observe.source:", d["layers"]["observe"]["source"])  # -> "inject" (real, no kernel)
    print("events_observed:", report.events_observed)
    print("policy_violations:", report.policy_violations)


if __name__ == "__main__":
    main()
