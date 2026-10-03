# Linux tools

[中文](README.md) | **English**

Small, standalone Linux debugging, monitoring and testing tools.

## Tools

| Tool | Purpose |
| --- | --- |
| [irqtop / irqstat](irqtop/README.md) | Hardware IRQ, softirq and softnet monitoring in a live window or text reports |
| [netping](netping/README.md) | ICMP, UDP and TCP latency/failure checks, plus MTU/MSS inspection |
| [flowgen](flowgen/README.md) | Multi-session TCP/UDP load, RTT statistics and offline HTML reports |
| [cttop](cttop/README.md) | Live conntrack monitoring, grouped drilldown and offline analysis |
| [netlens](netlens/README.md) | Interfaces, sockets, qdisc, routes and layered network counters |
| [bpftrace](bpftrace/README.md) | Static Linux tracing executables for three architectures |
| [nettrace](nettrace/README.md) | Kernel skb path tracing, packet-drop diagnosis and processing latency |
| [netcap](netcap/README.md) | Capture skb packets at selected kernel functions and write pcap files |
| [xpcap](xpcap/README.md) | Capture AF_XDP and conventional traffic together, with optional XDP stages and PCAPNG output |
| [xsktop](xsktop/README.md) | Live AF_XDP socket rates, errors and process ownership |
| [droptop](droptop/README.md) | Aggregate kernel skb drop rates by reason, interface and site, with call stacks |
| [bpfmap](bpfmap/README.md) | Read-only BPF map inventory, BTF-decoded entry preview and interval deltas |
| [gomemtop](gomemtop/README.md) | Live Go pprof heap growth and local process RSS analysis |
| [systop](systop/README.md) | eBPF syscall, process and thread call-rate top |

The repository also includes `irq-affinity.sh` for configuring IRQ/RPS.
The affinity script changes IRQ/RPS configuration.

## Documentation

[Overview](docs/en/index.md) · [Quick start](docs/en/getting-started.md)

The documentation site defaults to Chinese; use the header to switch to English.
The table above links to each tool's full manual.

## Installation

Choose a tool and architecture from [GitHub Releases](https://github.com/calcky/tools/releases):
`linux-x86_64`, `linux-arm64`, or `linux-arm` (`linux-armv7` for netlens).

For netping on x86_64:

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
netping -h
```

Add `$HOME/.local/bin` to `PATH`. These are static Linux executables; no Rust runtime is needed.

To install one tool from source, with Rust and a C toolchain:

```sh
git clone https://github.com/calcky/tools.git
cd tools
make netping
make install-netping PREFIX="$HOME/.local"
```
