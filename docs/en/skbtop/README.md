# skbtop

`skbtop` v0.1.0 measures observed Linux skb path latency for IPv4/IPv6 local INPUT, local OUTPUT and routed/NAT or bridged forwarding. It separates stack processing, egress queue and total latency between the stated observation points, by interface and directed interface pair.

## Installation

No public Release or prebuilt skbtop assets have been published yet. The static build workflow targets ARMv7 hard-float, ARM64 and x86_64; this is not a list of available downloads. See the [repository manual](https://github.com/calcky/tools/blob/master/skbtop/README.md) for development installation. An installed executable uses the name `skbtop` on `PATH`.

Tracing requires root and a kernel with the required BPF permissions, BTF and tracing hooks. Run in the network namespace you want to observe. Static userspace linkage does not provide missing kernel support.

## Common commands

```sh
skbtop
skbtop -i eth0,eth1
skbtop -i eth0 -i eth1 -d 0.5
skbtop -c 5
skbtop -c 60 -T 60 -o capture
skbtop -i eth0,eth1 -m 262144 -g 4096 -c 10 -o capture
skbtop -h
skbtop -v
```

Without `-i`, all non-loopback interfaces in the current network namespace are observed. Interface discovery continues during capture, including creation, removal, renaming and ifindex reuse; separate interface lifetimes retain their own identity. Device removal disables its tracking immediately, and a new device reusing the index does not inherit that lifetime's statistics. Other network namespaces are outside the view.

Without `-c`, the live UI requires a terminal. `-T` limits duration without changing the output mode; use `-c N` for scripts or redirected recordings.

## Options

```text
skbtop [-i IFACE] [-d SEC] [-c N] [-T SEC] [-m N] [-g N] [-o DIR] [-h/-v]
```

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Select interfaces; accept comma-separated names or repeated `-i`. Default: all non-loopback interfaces in the current network namespace. |
| `-d SEC` | Refresh/sample interval in seconds; default `1`. |
| `-c N` | Print N plain-text interval snapshots instead of opening the live UI. |
| `-T SEC` | Stop after this capture duration in seconds. |
| `-m N` | Combined capacity for inflight origin and transmit associations; default `262144`. This is an association budget, not a packet count. |
| `-g N` | Maximum number of directed paths; default `4096`. This is a capacity, not a grouping mode. |
| `-o DIR` | Record interval JSONL, `summary.json` and a standalone `report.html` in DIR. |
| `-h` | Show help. |
| `-v` | Show version (`skbtop 0.1.0`). |

## Read the live view

The screen has three sections: INPUT, OUTPUT and FORWARD. INPUT and OUTPUT rows identify the local interface. FORWARD groups the two interfaces together and keeps each direction on its own row, such as `eth0 -> eth1` and `eth1 -> eth0`. A same-interface hairpin, such as `eth0 -> eth0`, has its own row. Route/NAT and bridge forwarding are distinguished within the forwarding statistics.

Use `Tab`/`Shift-Tab` to change sections, arrow keys or `j/k` to select rows, and PageUp/PageDown or Home/End to navigate. Click a column header to sort all three sections by that metric and focus the clicked section. A new numeric column starts descending; PATH starts alphabetical. Click again to reverse; the active header shows an up/down arrow. Sorting returns to the top. Mouse sorting requires a terminal supporting mouse events; `s` cycles OUT bandwidth, OUT PPS and total average, and `S` reverses the order.

`/` searches interface/path names, `Enter` opens interval and cumulative details, `Esc` closes details or clears the filter, and `q` quits. These display controls do not reduce recorded path coverage.

IN and OUT describe the start and end of the **same directed path**. Both rates on `eth0 -> eth1` belong to that direction; reverse traffic has its own `eth1 -> eth0` row.

| Column | Meaning |
| --- | --- |
| `IN bit/s` / `IN PPS` | Start-hook skb bytes times 8 / skb observations, divided by the actual interval. |
| `OUT bit/s` / `OUT PPS` | End-hook skb bytes times 8 / completed skb observations, divided by the actual interval. |
| `Avg` | Mean elapsed time for each stage in the current interval. |
| `Min` / `Max` | Minimum / maximum elapsed time for each stage in the current interval. |
| `Newest` | Each stage's latency for the most recently completed sample, selected by its monotonic completion observation timestamp. It is not an average or refresh time. Missing or mismatched stage completion timestamps display `-` rather than mixing samples; older recordings without these fields also display `-`. |
| `PEND` | Queued transmit associations not yet completed or retired. |

Latency headers have two levels, with all values in microseconds (`us`):

```text
       Avg       |       Min       |       Max       |      Newest
  S    Q    T    |  S    Q    T    |  S    Q    T    |  S    Q    T
```

`S = Stack`, `Q = Queue`, `T = Total`. INPUT has no Queue, so Q displays `-`; its Stack and Total measure the same span. Total is measured independently; stage minima or maxima must not be added to infer Total minima or maxima. Click a lower S/Q/T header to sort by that stage and statistic. The footer spells out the metric, such as `Queue max`.

From 120 columns, all four latency groups show S/Q/T. Below 120 columns, they show only T while retaining OUT rates and wider path labels; other stages remain in details. From 160 columns, IN rates and PEND also appear, with bandwidth and PPS columns adjacent to their counterparts. Vertical lines separate columns; group titles span their three stage columns. Large latency values use scientific notation when needed, still in us. Text snapshots always show every stage and both IN/OUT rates.

Each rate and latency column highlights its maximum, while Min highlights the smallest minimum. Default sorting uses OUT bandwidth descending. FORWARD directions remain adjacent for every sort: IN/OUT rates and PEND use the pair sum, Min uses the smaller minimum, other latency columns use the larger value of the two directions, and groups with no latency samples stay last in either order.

Path IN counters are booked at local delivery or the first egress queue, once the path is known, using the length saved at the start. OUT is booked at local delivery or a successful driver result. Bookings can fall in different intervals; bridge branches, GSO and header changes also affect counts and bytes. Their difference is not a loss measurement. See [observation hooks](hooks.md) for the hooks and accounting times.

Rates describe the measured interval. Latency statistics use completed skb samples, not a single CPU's events or a sampled function duration. Each latency distribution shows its sample count, min, average, approximate histogram percentiles and max, in microseconds (`us`). Min, average and max come from the exact observed timestamp differences; histogram-derived percentiles are estimates. A missing completed sample is not zero latency.

Normal traffic uses compact 64-byte per-CPU interval records; each completion updates S/Q/T together in one latency record. Userspace merges CPU shards, closed intervals and the open interval for cumulative counters and distributions without averaging percentiles or writing normal traffic twice. Active writers prevent premature retirement. Traffic and latency maps each allow four entries per configured path, keyed by path and epoch; memory also scales with the kernel's possible CPU count. Slow readers or delayed intervals can trigger `interval_capacity`: shared path fallback retains affected cumulative counters or latency samples, while affected interval statistics remain incomplete. Global traffic counters are per-CPU; Pending and the association budget remain global.

Userspace reuses batch buffers and merges CPU shards as each batch is read, without copying the whole interval map. Empty latency shards do not allocate histograms. Retired intervals are deleted after the complete traversal. The scratch target is 4 MiB; one per-CPU entry or a crowded hash bucket can require more. This is not a limit on BPF maps, cumulative statistics or total process memory, and does not reduce timing coverage.

Kernel helpers reuse live configuration within an event and the reserved counter on insertion rollback. Fields are read live, including the capacity check after atomic admission and the stop/parent checks between GSO children. Pointers remain local to the current invocation. Global budget, retirement accounting and timing coverage retain their existing semantics.

The histogram uses four bins per power-of-two latency range, with roughly 14-25% relative bin width; percentile estimates use bin upper bounds constrained by observed min/max.

Byte counts use `skb->len` at each observation point: RX core commonly excludes the L2 header, driver TX commonly includes it, and INPUT protocol dispatch may exclude the IP header, so differing ingress/egress byte counts do not establish loss.

## Measurement boundaries

Queue and driver-attempt hooks check the namespace and interface lifetime before skb association lookups, reducing unrelated hash lookups. Hooks still run system-wide and have a cost. Retirement remains keyed by skb identity because its device can change before release. These checks do not reduce latency sampling coverage.

| Path | Start | End |
| --- | --- | --- |
| INPUT | `tp_btf/netif_receive_skb` inside RX core | IPv4 `fentry/ip_protocol_deliver_rcu`, IPv6 `fentry/ip6_protocol_deliver_rcu` |
| OUTPUT | IPv4 `fentry/__ip_local_out`, IPv6 `fentry/__ip6_local_out` | `tp_btf/net_dev_start_xmit` for an attempt later confirmed successful |
| FORWARD | `tp_btf/netif_receive_skb` inside RX core, through IP route/NAT or bridge forwarding | `tp_btf/net_dev_start_xmit` for an attempt later confirmed successful |

For OUTPUT and FORWARD, `stack` ends at `tp_btf/net_dev_queue`, `queue` runs from there to the successful driver attempt's entry, and `total` independently spans the start to that entry. `tp_btf/net_dev_xmit` confirms success with `NETDEV_TX_OK`; the latency endpoint remains the attempt's entry. Queue latency includes egress scheduling and transmit retry delays, so it is not pure qdisc residence time. The end timestamp is neither the driver's return nor hardware completion or a wire timestamp. INPUT ends before the socket and application and has no egress queue stage.

INPUT timing excludes NIC reception, NAPI/GRO and RPS work before RX core entry, socket waiting and application processing. Stack latency is elapsed time between hooks, not CPU utilization. NAT can change headers without making the traversal a new flow; these are skb path statistics, not per-connection RTTs.

The BTF-typed receive tracepoint uses `tp_btf/netif_receive_skb`, emitted directly inside `__netif_receive_skb_core`, including list receive paths. It does not require that function to expose an fentry BTF target, but the tracepoint must expose its BTF type.

The IPv6 endpoint is protocol dispatcher entry at `ip6_protocol_deliver_rcu`, which can precede extension header processing. This boundary excludes subsequent protocol handlers, socket waiting and application work.

## Recording

`-o DIR` preserves interval snapshots in `snapshots.jsonl`. `summary.json` holds cumulative statistics and interface identities. `report.html` is a standalone offline report with no external runtime assets; it includes all captured directed paths, including paths that did not fit on the live screen. The chart timeline may be thinned to bound report size, while full interval snapshots remain in JSONL and all path summaries are retained. Live row visibility does not limit recording. Existing recording files are not overwritten; choose a new directory for another capture.

## Requirements and limitations

Requires Linux with BPF syscall/tracing support, kernel BTF at `/sys/kernel/btf/vmlinux` and attachable receive, IP/bridge, queue and driver observation probes. A Linux 6.6 version number or a compiled kernel symbol alone does not establish probe availability: the running kernel must expose the required BTF tracepoint types and function targets and support the collector's attachment mechanisms. Missing required probes or attachment failures are reported; they must not be read as a quiet interface.

Required bridge probes, including `br_dev_queue_push_xmit`, need Linux bridge support built into the kernel or the bridge module loaded and an attachable function target.

The inflight associations and path maps are bounded by `-m` and `-g`. `-m` budgets combined origin and transmit association entries, not a number of packets. Capacity, tracking and accounting errors are reported in the health counters. Inspect them before interpreting latency or rates: unfinished, freed or untrackable skbs do not become successful latency samples, and missing coverage is not evidence of no traffic. Clones and GSO segmentation support identity propagation within this bounded tracking; an skb count need not equal the number of wire packets.

Health counters describe observation coverage and diagnostics; they are not network-loss measurements.

| Counter | Interpretation |
| --- | --- |
| `association_capacity` | The combined origin/transmit budget is exhausted; some associations cannot be tracked. |
| `unrecorded_path_events` | A directional event could not be recorded because the path map is full. Existing paths remain recorded and global traffic counters are retained. |
| `interval_capacity` | Interval statistics could not be stored; affected interval counts/latency are incomplete. Recorded paths retain cumulative counters and fallback latency samples. |
| `late_interval_records` | An active writer deferred a completed interval until a later snapshot. Samples remain in cumulative distributions; affected time-series intervals are delayed. |
| `map_update_failure` | A tracking-map update failed; no timers are used. |
| `unsupported_conversion` | A transformation or tracking-depth limit prevented complete correlation. |
| `unclassified_forward` | A successful FORWARD completion had neither route nor bridge classification; traffic totals and valid endpoint latency remain available, but its forwarding classification is unknown. |
| `expired_associations` / `unknown_exit` | An association aged out, or an origin was freed without an observed completion/known queued exit. Neither establishes packet loss on the network. |
| `driver_busy` | A driver attempt requested retry; this is a retry diagnostic, not a loss counter. |
| `freed_before_completion` | A tracked queued skb was observed being freed before its measured endpoint, not evidence of loss on the wire. |
| `unmatched_queue` / `unmatched_result` | A queue or driver-result event lacked its matching tracked association. |
| `integrity` | A tracking/accounting consistency check failed; inspect the capture before interpreting its statistics. |
| `newest_contention` | A bounded latest-sample update could not complete under concurrent/nested tracing in the path-local fallback. Normal interval samples use per-CPU shards. Other latency statistics continue; Newest stays unavailable until a newer valid sample is recorded. |

IPv4/IPv6 fragmentation and reassembly are currently not fully correlated. Separate `fragmentation` and `reassembly` counters flag these transformations, and latency samples for tracked affected skbs are excluded. Newly allocated fragments can be unmatched. Treat these counters as missing correlation coverage, not measured fragment/reassembly latency.

Stale inflight associations expire after 30 seconds, with cleanup once per second independently of `-d`; retention is therefore approximately 31 seconds at most. With no inflight reservations, cleanup skips hash-map traversal; newly admitted records are checked on a later sweep. Expiry is reported and does not turn an unfinished skb into a completed latency sample. Cleanup does not inject network packets or change network configuration.

XDP, AF_XDP, hardware-offloaded bypass traffic and non-IP local INPUT/OUTPUT are outside the measurement scope. The tool does not measure socket/application latency, NIC or hardware transmit completion, or end-to-end network latency.
