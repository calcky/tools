# Linux tools

[中文](README.md) | **English**

Small, standalone Linux debugging, monitoring and testing tools.

## Tools

| Tool | Purpose | Release |
| --- | --- | --- |
| [bpfmap](bpfmap/README.md) | Read-only BPF map inventory, BTF-decoded entry preview and interval deltas | [Release](https://github.com/calcky/tools/releases/tag/bpfmap-release) |
| [bpftop](bpftop/README.md) | Live eBPF program runtime, event rate and CPU estimates | [Release](https://github.com/calcky/tools/releases/tag/bpftop-release) |
| [bpftrace](bpftrace/README.md) | Static Linux tracing executables for three architectures | [Release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| [cachetop](cachetop/README.md) | Hardware PMU view of LLC read misses, MPKI, IPC and thread placement | [Release](https://github.com/calcky/tools/releases/tag/cachetop-release) |
| [cttop](cttop/README.md) | Live conntrack monitoring, grouped drilldown and offline analysis | [Release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| [droptop](droptop/README.md) | Aggregate kernel skb drop rates by reason, interface and site, with call stacks | [Release](https://github.com/calcky/tools/releases/tag/droptop-release) |
| [fdtop](fdtop/README.md) | eBPF process/FD I/O monitoring with lightweight counters and opt-in latency for files, sockets, pipes, devices and POSIX MQ | [Release](https://github.com/calcky/tools/releases/tag/fdtop-release) |
| [flowgen](flowgen/README.md) | Multi-session TCP/UDP load, RTT statistics and offline HTML reports | [Release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| [gomemtop](gomemtop/README.md) | Live Go pprof heap growth and local process RSS analysis | [Release](https://github.com/calcky/tools/releases/tag/gomemtop-release) |
| [irqtop / irqstat](irqtop/README.md) | Hardware IRQ, softirq and softnet monitoring in a live window or text reports | [Release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| [napitop](napitop/README.md) | NAPI poll work, budget pressure, latency and CPU hotspots | [Release](https://github.com/calcky/tools/releases/tag/napitop-release) |
| [netcap](netcap/README.md) | Capture skb packets at selected kernel functions and write pcap files | [Release](https://github.com/calcky/tools/releases/tag/netcap-release) |
| [netlens](netlens/README.md) | Interfaces, sockets, qdisc, routes and layered network counters | [Release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| [netping](netping/README.md) | ICMP, UDP and TCP latency/failure checks, plus MTU/MSS inspection | [Release](https://github.com/calcky/tools/releases/tag/netping-release) |
| [nettrace](nettrace/README.md) | Kernel skb path tracing, packet-drop diagnosis and processing latency | [Release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| [skbtop](skbtop/README.md) | IPv4/IPv6 INPUT, OUTPUT and routed/NAT or bridged forwarding skb stack, egress queue and total latency by interface and directed pair | No prebuilt release yet |
| [systop](systop/README.md) | eBPF syscall, process and thread call-rate top | [Release](https://github.com/calcky/tools/releases/tag/systop-release) |
| [xpcap](xpcap/README.md) | Capture AF_XDP and conventional traffic together, with optional XDP stages and PCAPNG output | [Release](https://github.com/calcky/tools/releases/tag/xpcap-release) |
| [xsktop](xsktop/README.md) | Live AF_XDP socket rates, errors and process ownership | [Release](https://github.com/calcky/tools/releases/tag/xsktop-release) |

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
