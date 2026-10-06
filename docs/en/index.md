# Linux tools

Small, standalone Linux debugging, monitoring and testing tools.

## Choose A Tool

| Tool | Purpose | Release |
| --- | --- | --- |
| [bpfmap](bpfmap/README.md) | Read-only BPF map metadata, entry previews and sample deltas | [Release](https://github.com/calcky/tools/releases/tag/bpfmap-release) |
| [bpftop](bpftop/README.md) | Live eBPF program runtime, event rate and CPU estimates | [Release](https://github.com/calcky/tools/releases/tag/bpftop-release) |
| [bpftrace](bpftrace/README.md) | Kernel tracing with static executables for three architectures | [Release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| [cachetop](cachetop/README.md) | Inspect LLC read misses, MPKI, IPC, and thread placement | [Release](https://github.com/calcky/tools/releases/tag/cachetop-release) |
| [cttop](cttop/README.md) | Live conntrack monitoring, grouped drilldown and offline analysis | [Release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| [droptop](droptop/README.md) | Aggregate skb drops by reason, interface and call site; inspect samples and kernel stacks | [Release](https://github.com/calcky/tools/releases/tag/droptop-release) |
| [fdtop](fdtop/README.md) | Application I/O by process and FD, complete FD inventories and lifecycle events | [Release](https://github.com/calcky/tools/releases/tag/fdtop-release) |
| [flowgen](flowgen/README.md) | Multi-session load, RTT analysis and HTML time-series reports | [Release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| [gomemtop](gomemtop/README.md) | Analyze Go pprof heap growth and local process RSS | [Release](https://github.com/calcky/tools/releases/tag/gomemtop-release) |
| [irqtop / irqstat](irqtop/README.md) | Interrupt rates, CPU distribution and softnet | [Release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| [napitop](napitop/README.md) | Inspect NAPI poll work, budget pressure, latency and CPU hotspots | [Release](https://github.com/calcky/tools/releases/tag/napitop-release) |
| [netcap](netcap/README.md) | Capture skb packets at selected kernel functions and write pcap files | [Release](https://github.com/calcky/tools/releases/tag/netcap-release) |
| [netlens](netlens/README.md) | Interfaces, sockets, qdisc, routes and layered network health | [Release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| [netping](netping/README.md) | ICMP, UDP and TCP latency, plus MTU/MSS inspection | [Release](https://github.com/calcky/tools/releases/tag/netping-release) |
| [nettrace](nettrace/README.md) | Kernel skb paths, packet-drop diagnosis and processing latency | [Release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| [skbtop](skbtop/README.md) | IPv4/IPv6 INPUT, OUTPUT and routed/NAT or bridged forwarding skb stack, egress queue and total latency by interface and directed pair | [Release](https://github.com/calcky/tools/releases/tag/skbtop-release) |
| [xpcap](xpcap/README.md) | Capture AF_XDP and conventional traffic together, with optional XDP stages | [Release](https://github.com/calcky/tools/releases/tag/xpcap-release) |
| [xsktop](xsktop/README.md) | AF_XDP socket rates, errors and process ownership | [Release](https://github.com/calcky/tools/releases/tag/xsktop-release) |

Start with [Installation](getting-started.md).

## Other Scripts

- `irq-affinity.sh`: sets IRQ affinity and RPS; changes system configuration.
