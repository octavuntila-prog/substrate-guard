# L1 Observe — event sources (mock / inject / eBPF)

The observe layer (`AgentTracer`) reports an honest `source` for where events come
from. Reports (`SessionReport.to_dict()["layers"]["observe"]["source"]` and the cron
audit JSON `layers.observe`) carry it verbatim, so a reader can always tell whether the
decisions were made on real or simulated events.

| `source`   | Events are…                          | Kernel? | How to select |
|------------|--------------------------------------|---------|---------------|
| `mock`     | **simulated** (`MockScenario`)       | no      | `use_mock=True` / `source="mock"` |
| `inject`   | **real**, fed via `inject_event()`   | no      | `source="inject"` |
| `ebpf`     | **real**, kernel-observed            | yes     | `source="auto"` (default) on Linux with bcc + root/CAP_BPF |

`is_mock` is a coarse **"not kernel"** flag — it is `True` for BOTH `mock` and
`inject`. Always use `source` for reporting so injected REAL events are never shown as
simulated `mock`, and non-kernel paths are never shown as `eBPF`.

## The inject path (cross-platform L1-real, plan 1.A step 2)

An orchestrator that already has normalized events (SubstrateGuard-style integrations,
a runtime hook, a replay of recorded traces) feeds them straight into the pipeline —
no kernel required, works on any OS:

```python
guard = Guard(observe=True, policy=..., source="inject")
with guard.monitor("agent-7") as session:
    session.inject_and_evaluate(event)   # REAL event, evaluated through policy/verify
report = session.report()
report.to_dict()["layers"]["observe"]["source"]   # -> "inject"
```

See `examples/orchestrator_inject_events.py`.

## The eBPF path (kernel, Linux only)

`source="auto"` (the default) tries eBPF and falls back to `mock` if unavailable.
eBPF needs: Linux kernel ≥ 5.4, `bcc` / `bpfcc-tools` (an OS package — see the `[ebpf]`
extra, but prefer `apt install bpfcc-tools python3-bpfcc`), and root / CAP_BPF. Check
readiness with `substrate-guard doctor` (it reports whether bcc is importable).

The production cron audit runs `use_mock=True` → `source="mock"` (a batch replay of DB
records, honestly labeled). Flipping it to real observation is a separate step: point it
at the inject path (an orchestrator source) or provision an eBPF host, keeping the
`source` label truthful either way.
