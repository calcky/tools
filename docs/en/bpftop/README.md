# bpftop

Monitor eBPF program event rates, average runtime and estimated CPU use in real time, with per-program trend graphs. These are static Linux builds of upstream bpftop v0.9.0 for ARMv7, ARM64 and x86_64.

## Installation

x86_64 example; other architectures and checksums are in [bpftop-release](https://github.com/calcky/tools/releases/tag/bpftop-release).

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpftop-release/bpftop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpftop-linux-x86_64 "$HOME/.local/bin/bpftop"
```

## Common Usage

```sh
bpftop          # Show loaded eBPF programs live
bpftop -d 2     # Refresh every 2 seconds
bpftop -h       # Show full help
```

In the TUI, use `j/k` or arrow keys to select a program, Enter for trend graphs, `f` to filter, `s` to sort and `q` to quit.

## Options

| Option | Meaning |
| --- | --- |
| `-d, --delay SEC` | Refresh interval, 1-3599 seconds; default 1 second |
| `-h, --help` | Show help |
| `-V, --version` | Show the upstream program version |

## Limitations

- The program explicitly requires root. Static linking does not remove kernel requirements. Upstream calls for Linux 5.8 or newer; functionality on older kernels may be limited.
- Rates and CPU estimates come from kernel BPF runtime statistics, enabled while bpftop runs and disabled when it exits. These are not host-wide CPU figures.
- An empty list can mean no eBPF programs are loaded or that inspection is not permitted.

[Upstream documentation](https://github.com/jfernandez/bpftop) · [Packaging notes](https://github.com/calcky/tools/blob/master/bpftop/README.md)
