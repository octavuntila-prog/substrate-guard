# eBPF / `monitor --live` în Docker și pe host

## Fapte scurte

- Programele eBPF rulează în **kernelul mașinii gazdă**, nu „în interiorul” unui container ca un proces oarecare.
- Imaginea **`Dockerfile`** din acest repo este **slim**, **fără bcc**, și rulează testele la build — este potrivită pentru **CI**, **demo**, **audit DB**, nu pentru L1 real.
- Pe **Windows** și **macOS**, tracerul folosește **mock**; pentru L1 real folosiți **Linux**.

## Opțiunea recomandată: rulează `monitor --live` pe host (Linux)

1. Instalați kernel **≥ 5.4**, **bcc** / **python3-bpfcc** (denumirea pachetului variază pe distro).
2. Rulați ca **root** (sau cu capabilități echivalente pentru BPF).
3. Din repo, cu venv activ:

   ```bash
   pip install -e ".[dev]"
   substrate-guard doctor    # trebuie să vadă bcc (import ok)
   substrate-guard monitor -a my-agent --live --pid <PID>
   ```

`--pid` urmărește un proces deja pornit; fără mock, evenimentele vin din eBPF.

## Opțiunea container: privilegii și kernel host

Rularea BPF **în** container necesită de obicei:

- `--privileged` **sau** capabilități fine (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN` — depinde de versiune kernel/Docker),
- montarea `/sys/fs/bpf`, uneori `/lib/modules` de pe host,
- aceeași arhitectură și kernel ca hostul.

Nu există în repo un `Dockerfile.ebpf` „oficial”, pentru că matricea (distro × kernel × Docker) este mare și greu de susținut în open source fără echipă dedicată.

**Șablon minimal (experimentat pe propria răspundere):**

```bash
docker run --rm -it --privileged --pid=host --network=host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v "$PWD":/work -w /work \
  python:3.12-bookworm bash
# în container: apt update && apt install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
# pip install -e ".[dev]"
# substrate-guard monitor -a agent --live --pid ...
```

Dacă `uname -r` în container nu se potrivește cu modulele host, încărcarea BPF poate eșua — de aceea **host Linux** rămâne varianta stabilă.

## Legături

- Niveluri capabilitate: [FUNCTIONAL_ROADMAP.md](FUNCTIONAL_ROADMAP.md) (tier B).
- Diagnostic: `substrate-guard doctor`.
