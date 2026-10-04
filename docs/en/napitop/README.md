# napitop

Inspect NAPI poll work, budget-hit pressure, latency and busiest CPUs by interface and NAPI instance.

## Installation

Install the x86_64 static binary from [napitop-release](https://github.com/calcky/tools/releases/tag/napitop-release):

```sh
curl -fL https://github.com/calcky/tools/releases/download/napitop-release/napitop-linux-x86_64 -o napitop
chmod +x napitop
install -m 755 napitop "$HOME/.local/bin/napitop"
```

Ensure `$HOME/.local/bin` is on `PATH`. The Release also contains ARMv7 and ARM64 binaries. Running the tool requires BPF/tracing privileges.

## Common usage

```sh
napitop                 # interactive overview
napitop -i eth0         # one interface
napitop -d 0.5          # sample twice per second
napitop -i eth0 -c 10   # ten text snapshots
```

Use `j/k` or arrow keys to move, `[`/`]` to page through a NAPI's CPUs, `s` to sort by work, budget-hit percentage or average duration, and `q` or Ctrl+C to quit. Redirected output is plain text and runs until Ctrl+C unless `-c` is supplied. `NO_COLOR` disables colors.

## Options

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Limit to one interface in the current network namespace |
| `-d SEC` | Sample interval, 0.1–60 seconds; default 1 |
| `-c N` | Output N text samples, then exit |
| `-h` / `-V` | Help / version |

## Metrics and limits

- `poll/s` counts NAPI poll calls. `work/s` sums driver-returned work; it is not a universal wire-packet counter. `work/poll` is their ratio.
- `budget%` is the fraction of polls that reached the supplied budget. It is **not a drop rate**. Correlate with throughput, CPU, driver counters and softnet pressure.
- `avg us` spans from `__napi_poll` entry to the `napi_poll` tracepoint. `p50 us*` and `p99 us*` are power-of-two-microsecond histogram bucket bounds, not exact percentiles; `>16384` is the open tail bucket. `-` means no matched duration sample.
- Rows aggregate per NAPI instance, with the highest-work CPU and three CPUs per detail page. NAPI IDs are not hardware queue IDs.
- Nonzero `map miss` or `timing miss` means incomplete coverage. Reading BPF map entries is not a global atomic snapshot.
- Requires Linux 6.6+, BTF, the `napi_poll` tracepoint, `__napi_poll` fentry, and BPF/tracing permissions. Only the current network namespace is observed; no device settings are changed.
- Isolated veth traffic showed rates tracking load from about 90 to 123k work/s. Budget saturation was not reproduced, and kernel BPF probe overhead has not been reliably quantified.

[Full manual](https://github.com/calcky/tools/blob/master/napitop/README.md)
