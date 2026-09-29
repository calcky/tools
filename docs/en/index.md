# Linux tools

Small, standalone Linux debugging, monitoring and testing tools.

## Choose A Tool

| Tool | Purpose |
| --- | --- |
| [irqtop / irqstat](irqtop/README.md) | Interrupt rates, CPU distribution and softnet |
| [netping](netping/README.md) | ICMP, UDP and TCP latency, plus MTU/MSS inspection |
| [flowgen](flowgen/README.md) | Multi-session load, RTT analysis and HTML time-series reports |
| [cttop](cttop/README.md) | Live conntrack monitoring, grouped drilldown and offline analysis |
| [netlens](netlens/README.md) | Interfaces, sockets, qdisc, routes and layered network health |
| [bpftrace](bpftrace/README.md) | Kernel tracing with static executables for three architectures |
| [nettrace](nettrace/README.md) | Kernel skb paths, packet-drop diagnosis and processing latency |
| [netcap](netcap/README.md) | Capture skb packets at selected kernel functions and write pcap files |

Start with [Installation](getting-started.md).

## Downloads

| Tool | Static Executables |
| --- | --- |
| irqtop / irqstat | [irqtop-release](https://github.com/calcky/tools/releases/tag/irqtop-release) |
| netping | [netping-release](https://github.com/calcky/tools/releases/tag/netping-release) |
| flowgen | [flowgen-release](https://github.com/calcky/tools/releases/tag/flowgen-release) |
| cttop | [cttop-release](https://github.com/calcky/tools/releases/tag/cttop-release) |
| netlens | [netlens-release](https://github.com/calcky/tools/releases/tag/netlens-release) |
| bpftrace | [bpftrace-release](https://github.com/calcky/tools/releases/tag/bpftrace-release) |
| nettrace | [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release) |
| netcap | [netcap-release](https://github.com/calcky/tools/releases/tag/netcap-release) |

## Other Scripts

- `irq-affinity.sh`: sets IRQ affinity and RPS; changes system configuration.
