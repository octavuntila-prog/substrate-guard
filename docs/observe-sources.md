# L1 Observe — event sources (mock / inject / replay / eBPF)

The observe layer (`AgentTracer`) reports an honest `source` for where events come
from. Reports (`SessionReport.to_dict()["layers"]["observe"]["source"]` and the cron
audit JSON `layers.observe`) carry it verbatim, so a reader can always tell whether the
decisions were made on real or simulated events.

| `source`   | Events are…                                        | Kernel? | Live? | How to select |
|------------|----------------------------------------------------|---------|-------|---------------|
| `mock`     | **simulated** (`MockScenario`)                     | no      | —     | `use_mock=True` / `source="mock"` |
| `inject`   | **real**, fed LIVE via `inject_event()` by an orchestrator | no | yes | `source="inject"` |
| `replay`   | **real recorded** events, re-fed as a BATCH REPLAY of historical DB traces | no | no | `source="replay"` |
| `ebpf`     | **real**, kernel-observed                          | yes     | yes   | `source="auto"` (default) on Linux with bcc + root/CAP_BPF |

`is_mock` is a coarse **"not kernel"** flag — it is `True` for `mock`, `inject`, AND
`replay`. Always use `source` for reporting so real events are never shown as simulated
`mock`, non-kernel paths are never shown as `eBPF`, and **live `inject` is never
conflated with historical `replay`** (the distinction a compliance reader needs).

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

## The replay path (the nightly cron audit)

The production cron audit re-feeds REAL recorded DB traces (`pipeline_traces` /
`agent_runs`) through the pipeline as a **batch replay** — real data, not live, and NOT
simulated. It runs `Guard(source="replay")` (was `use_mock=True` → `source="mock"`, which
mislabelled real recorded events as simulated — audit HARD #10). The audit JSON carries
`layers.observe = "replay"` plus an `observe_note` disclosing that liveness is conveyed by
the preserved per-event timestamps, not wall-clock. Compliance evidence threads this same
real source (never a hardcoded label). Moving to LIVE observation is a further step: point
the pipeline at a live `inject` orchestrator source or provision an `eBPF` host — keeping
the `source` label truthful either way.
