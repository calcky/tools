skbtop measures traffic and elapsed latency along observed Linux skb paths.

- INPUT, OUTPUT and route/NAT or bridge FORWARD views, grouped by interface
  and directed interface pair; dynamically track interface lifecycles.
- IN/OUT skb rates and byte rates; Stack, Queue and Total min, avg, max and
  newest latency, with approximate percentiles in the detailed view.
- Interactive terminal with clickable sorting, search and path details;
  plain-text snapshots and JSONL recordings with a standalone HTML report.
- Static musl executables for ARMv7 hard-float, ARM64 and x86_64, supplied
  directly without archives. SHA256SUMS covers all three executables.

Requires Linux 6.6+, root/BPF tracing permissions, kernel BTF and all required
receive, IP/bridge, queue and driver observation hooks. Kernel version alone
does not guarantee compatibility. Required bridge hooks need built-in bridge
support or a loaded bridge module.

Latency is elapsed time between the documented hooks, not CPU time or network
RTT. skb rates are not on-wire packet rates. XDP/AF_XDP and hardware-offloaded
paths are outside coverage; fragmentation/reassembly tracking is incomplete.
Inspect health and capacity counters before interpreting measurements.
Full tracing adds workload-dependent overhead; no fixed overhead budget is
guaranteed.

Usage and observation hooks: [中文](https://github.com/calcky/tools/blob/master/docs/zh/skbtop/README.md)
| [English](https://github.com/calcky/tools/blob/master/docs/en/skbtop/README.md).
