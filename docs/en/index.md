# Linux tools

Small, standalone Linux debugging, monitoring and testing tools.

## Choose A Tool

[fdtop](fdtop/README.md): application I/O by process and FD, with optional lifecycle events.

| Tool | Purpose |
| --- | --- |
| [irqtop / irqstat](irqtop/README.md) | Interrupt rates, CPU distribution and softnet |
| [netping](netping/README.md) | ICMP, UDP and TCP latency, plus MTU/MSS inspection |
| [flowgen](flowgen/README.md) | Multi-session load, RTT analysis and HTML time-series reports |
| [cttop](cttop/README.md) | Live conntrack monitoring, grouped drilldown and offline analysis |
| [netlens](netlens/README.md) | Interfaces, sockets, qdisc, routes and layered network health |
| [bpftrace](bpftrace/README.md) | Kernel tracing with static executables for three architectures |
| [bpftop](bpftop/README.md) | Live eBPF program runtime, event rate and CPU estimates |
| [nettrace](nettrace/README.md) | Kernel skb paths, packet-drop diagnosis and processing latency |
| [netcap](netcap/README.md) | Capture skb packets at selected kernel functions and write pcap files |
| [xpcap](xpcap/README.md) | Capture AF_XDP and conventional traffic together, with optional XDP stages |
| [xsktop](xsktop/README.md) | AF_XDP socket rates, errors and process ownership |
| [droptop](droptop/README.md) | Aggregate skb drops by reason, interface and call site; inspect samples and kernel stacks |
| [gomemtop](gomemtop/README.md) | Analyze Go pprof heap growth and local process RSS |
| [cachetop](cachetop/README.md) | Inspect LLC read misses, MPKI, IPC, and thread placement |
| [napitop](napitop/README.md) | Inspect NAPI poll work, budget pressure, latency and CPU hotspots |

Start with [Installation](getting-started.md).

## Installation

| Tool | Release |
| --- | --- |
| irqtop / irqstat | [irqtop-release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| netping | [netping-release](https://github.com/calcky/tools/releases/tag/netping-release) |
| flowgen | [flowgen-release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| cttop | [cttop-release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| netlens | [netlens-release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| bpftrace | [bpftrace-release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| bpftop | [bpftop-release](https://github.com/calcky/tools/releases/tag/bpftop-release) |
| nettrace | [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| netcap | [netcap-release](https://github.com/calcky/tools/releases/tag/netcap-release) |
| xpcap | [xpcap-release](https://github.com/calcky/tools/releases/tag/xpcap-release) |
| xsktop | [xsktop-release](https://github.com/calcky/tools/releases/tag/xsktop-release) |
| droptop | [droptop-release](https://github.com/calcky/tools/releases/tag/droptop-release) |
| gomemtop | [gomemtop-release](https://github.com/calcky/tools/releases/tag/gomemtop-release) |
| cachetop | [cachetop-release](https://github.com/calcky/tools/releases/tag/cachetop-release) |
| napitop | [napitop-release](https://github.com/calcky/tools/releases/tag/napitop-release) |

## Other Scripts

- `irq-affinity.sh`: sets IRQ affinity and RPS; changes system configuration.
