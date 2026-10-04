# cachetop

Use hardware PMU counters to inspect LLC reads and misses, MPKI, IPC, and CPU migrations when checking thread placement.

## Installation

Example for x86_64. Static ARMv7 and ARM64 binaries are also available from [cachetop-release](https://github.com/calcky/tools/releases/tag/cachetop-release).

```sh
curl -fLO https://github.com/calcky/tools/releases/download/cachetop-release/cachetop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 cachetop-linux-x86_64 "$HOME/.local/bin/cachetop"
```

## Common commands

```sh
cachetop                   # per-host-CPU view
cachetop -p 1234           # per-thread view for one process
cachetop -p 1234 -d 0.5    # refresh every 0.5 seconds
cachetop -p 1234 -c 10     # ten plain-text snapshots
```

In the live window, use `j/k` or arrows to select a row. Press `m`, `p`, `i`, or `c` to sort by LLC misses/s, MPKI, IPC, or CPU/TID ID; `q` quits.

## Key options

| Option | Meaning |
| --- | --- |
| `-p PID` | Show threads of a process; otherwise show host CPUs |
| `-d SEC` | Sample interval, 0.1–60 seconds; default one second |
| `-c N` | Print N plain-text snapshots without opening the window |

## Metrics and limits

- `LLC rd/s` and `LLC miss/s` count last-level cache **read** accesses and misses. `rd hit% = 1 - misses / accesses`; it is not an all-cache hit rate. MPKI is LLC read misses per thousand retired instructions; IPC is retired instructions per cycle.
- `migrate/s` counts CPU migration events. The process view's `CPU` is only the thread's last observed CPU, **not** its residency over the interval or allowed affinity mask.
- `PMU run%` is the hardware counter's running coverage. Counts are scaled when the counter runs for less than 100% of the interval; low coverage makes estimates less stable. Unavailable events and zero denominators show `-`, not zero.
- Requires hardware PMU events and `perf_event_open` access. Depending on `perf_event_paranoid`, root or `CAP_PERFMON` may be needed; host-wide sampling often needs more privileges. Generic LLC event availability and meaning vary by CPU.
- Fewer LLC misses do not guarantee higher throughput or lower tail latency. Keep traffic fixed and compare PPS, drops, CPU usage, and latency as well. Use `perf list` and `perf stat -t TID -e cycles,instructions,LLC-loads,LLC-load-misses` to cross-check event semantics.

[Full manual](https://github.com/calcky/tools/blob/master/cachetop/README.md)
