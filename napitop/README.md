# napitop

`napitop` shows how much work Linux NAPI polls do per network interface and NAPI ID. It combines `napi:napi_poll` work and budget values with the elapsed time from `__napi_poll` entry to that tracepoint. The default view is an interactive table with a selected NAPI's busiest CPUs; `-c` emits plain-text samples.

## Requirements

Linux 6.6 or newer with BTF, the `napi_poll` tracepoint, `__napi_poll` fentry support, and BPF/tracing privileges. The tool filters to the current network namespace. It never changes the interface or its XDP programs. If the kernel omits `__napi_poll` from BTF or restricts tracing, attachment fails with an explicit error.

## Usage

```sh
napitop                 # interactive NAPI overview
napitop -i eth0         # only eth0
napitop -d 0.5          # sample twice per second
napitop -i eth0 -c 10   # ten text snapshots
napitop -h              # options
```

The text view is also used when stdout is redirected; without `-c` it continues until Ctrl+C. In the TUI, use `j/k` or arrow keys to select, `[`/`]` to page through the selected NAPI's CPUs, `s` to cycle sorting (work rate, budget-hit percentage, average poll duration), and `q` or Ctrl+C to quit. `NO_COLOR` disables highlight colors.

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Restrict to one interface in the current network namespace |
| `-d SEC` | Sampling interval, 0.1 to 60 seconds; default 1 |
| `-c N` | Emit N plain-text samples and exit |
| `-h` | Show help |
| `-V` | Show version |

## Interpreting the counters

- `poll/s` counts completed NAPI poll calls. `work/s` sums their returned `work` values; this usually approximates processed packets but is not a wire packet counter for every driver. `work/poll` is their ratio.
- `budget%` is the share of poll calls whose returned `work` reached or exceeded the supplied budget. A hit indicates poll pressure, **not** a packet drop or proof that the interface is overloaded. Cross-check throughput, CPU, driver counters, and `softnet_stat` budget pressure.
- `avg us` measures from `__napi_poll` entry to its `napi_poll` tracepoint. `p50 us*` and `p99 us*` are bounds of power-of-two-microsecond histogram buckets (`>16384` for the open last bucket), not exact percentiles. `-` means no matched timing samples in that interval.
- The CPU shown on a row is its highest-work CPU. The detail lists three CPUs per page, sorted by work. One NAPI may move between CPUs across samples.
- `map miss` counts failed BPF stats-map insertions; `timing miss` counts poll events without a matching entry timestamp. Nonzero values mean coverage is incomplete. Map reads are not an atomic global snapshot, so short intervals can show small inconsistencies.
- IDs identify NAPI contexts, not hardware RX queues. A one-to-one queue mapping must not be inferred without driver-specific evidence. The kernel's NAPI tracepoint does not carry queue ID.

## Development

From the repository root, `make napitop` builds `bin/napitop`, and `make check-napitop` runs format, unit tests, and Clippy. The embedded CO-RE object is built with Clang.
