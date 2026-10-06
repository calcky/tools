# Observation Hooks

These are the eBPF observation points actually attached by `skbtop`. `fentry/function` observes function entry, `fexit/function` obtains its return result, and `tp_btf/event` listens to a tracepoint with its kernel BTF signature. They are not XDP/TC programs installed on interfaces or a set of netfilter rules. See the [usage page](README.md) for metrics and controls.

## Timing Function Map

The kernel function triggers the observation; a separate BPF handler records timestamps or confirms the result. These mappings follow the [collector source](https://github.com/calcky/tools/blob/master/skbtop/bpf/observe.bpf.c).

| Observation | Kernel function / trigger | Attached probe | BPF handler |
| --- | --- | --- | --- |
| INPUT / FORWARD start | `trace_netif_receive_skb(skb)` inside `__netif_receive_skb_core()` | `tp_btf/netif_receive_skb` | `on_receive()` → `receive_event()` → `begin()` |
| IPv4 OUTPUT start | Entry to `__ip_local_out()` | `fentry/__ip_local_out` | `on_output4()` → `begin()` |
| IPv6 OUTPUT start | Entry to `__ip6_local_out()` | `fentry/__ip6_local_out` | `on_output6()` → `begin()` |
| IPv4 INPUT end | Entry to `ip_protocol_deliver_rcu()` | `fentry/ip_protocol_deliver_rcu` | `on_input4()` → `deliver()` |
| IPv6 INPUT end | Entry to `ip6_protocol_deliver_rcu()` | `fentry/ip6_protocol_deliver_rcu` | `on_input6()` → `deliver()` |
| **Stack end / Queue start** | **`trace_net_dev_queue(skb)` inside `__dev_queue_xmit()`** | **`tp_btf/net_dev_queue`** | **`on_queue()` → `enqueue()`** |
| Queue / Total endpoint candidate | `trace_net_dev_start_xmit(skb, dev)` in `xmit_one()`, before invoking the driver | `tp_btf/net_dev_start_xmit` | `on_attempt()` → `attempt_event()` |
| Confirm transmit result | `trace_net_dev_xmit(skb, rc, dev, len)` in `xmit_one()`, after the driver returns | `tp_btf/net_dev_xmit` | `on_result()` → `result_event()` |

In Linux 6.6, `net_dev_queue` occurs inside `__dev_queue_xmit()` after egress netfilter/TC processing and TX queue selection, before `__dev_xmit_skb()` and qdisc enqueue/bypass. It is not an entry probe on `qdisc_enqueue()`, and no-qdisc paths also trigger it. Queue can therefore include lock waits, scheduling and BUSY retries, rather than pure qdisc residence time.

## INPUT: Interface To Host

```text
tp_btf/netif_receive_skb                    t0: save start time and skb->len
  inside __netif_receive_skb_core
        |
        | IP receive, routed to the host
        v
IPv4: fentry/ip_protocol_deliver_rcu        t1: local protocol dispatcher entry
IPv6: fentry/ip6_protocol_deliver_rcu

Stack = t1 - t0; only S is recorded, no Queue / Total
```

The endpoint precedes subsequent TCP/UDP/ICMP processing, sockets and applications; IPv6 extension-header processing may also follow it. NIC reception, NAPI/GRO and RPS work before RX core entry are excluded. Non-IP local delivery has no measured INPUT latency.

## OUTPUT: Host To Interface

```text
IPv4: fentry/__ip_local_out                 t0: local IP output start
IPv6: fentry/__ip6_local_out
        |
        | IP output, netfilter, neighbor and egress work
        v
__dev_queue_xmit(): trace_net_dev_queue(skb)
  tp_btf/net_dev_queue -> on_queue()       tq: Stack end / Queue start
        |
        | Egress scheduling, qdisc, possible driver BUSY retries
        v
xmit_one(): trace_net_dev_start_xmit(skb, dev)
  tp_btf/net_dev_start_xmit -> on_attempt() tx: driver transmit attempt entry
        |
xmit_one(): trace_net_dev_xmit(skb, rc, dev, len)
  tp_btf/net_dev_xmit -> on_result()       result: NETDEV_TX_OK confirms completion

Stack = tq - t0; Queue = tx - tq; Total = tx - t0
```

The actual probe names are `__ip_local_out` / `__ip6_local_out`, including both leading underscores. Application write/send and earlier transport-layer work, such as TCP processing before this entry, are outside the timing boundary.

## FORWARD: Ingress To Egress Interface

```text
tp_btf/netif_receive_skb                    t0: ingress RX core
        |
        +-- IP route / NAT -- ip_forward / ip6_forward
        |
        +-- Linux bridge -- br_* classification and branches
        |
        v
__dev_queue_xmit(): trace_net_dev_queue(skb)
  tp_btf/net_dev_queue -> on_queue()       tq: actual egress interface known
        |
tp_btf/net_dev_start_xmit                  tx: driver transmit attempt entry
        |
tp_btf/net_dev_xmit                        result: NETDEV_TX_OK confirms completion

Stack = tq - t0; Queue = tx - tq; Total = tx - t0
```

Actual ingress and egress interfaces form a directed path. Each bridge flood branch is counted independently, including same-interface hairpins. NAT has no additional timing probe and no separately measured NAT duration.

| Function-entry probe | BPF handler | Purpose |
| --- | --- | --- |
| `fentry/ip_forward` | `on_route4()` → `mark()` | IPv4 route forwarding. |
| `fentry/ip6_forward` | `on_route6()` → `mark()` | IPv6 route forwarding. |
| `fentry/br_handle_frame_finish` | `on_bridge_receive()` → `mark()` | Bridge receive. |
| `fentry/br_forward` | `on_bridge_branch()` → `mark()` | Bridge egress branch. |
| `fentry/br_flood` | `on_bridge_flood()` → `mark()` | Bridge flooding. |
| `fentry/br_forward_finish` | `on_bridge()` → `mark()` | Bridge forwarding egress. |
| `fentry/br_dev_queue_push_xmit` | `on_bridge_transmit()` → `mark()` | Bridge transmit egress. |
| `fentry/br_dev_xmit` | `on_bridge_output()` → `mark()` | Local output through a bridge. |

These classification probes do not produce separate latency stages. The queue observer also validates the bridge device identity in the skb control buffer to supplement classification affected by inlining and similar optimizations. Path counters `route` / `bridge` / `combo` count successful completions with only route, only bridge, or both markers; the last often appears where bridge and IP paths combine.

## When IN / OUT Counters Are Booked

| Path | IN counter | OUT counter |
| --- | --- | --- |
| INPUT | Booked at protocol dispatcher entry, using the saved RX core start length. | Booked at the same entry, using the current skb length. |
| OUTPUT | Booked on the first `net_dev_queue` for the identified egress, using the saved local IP output start length. | Booked when `net_dev_xmit` confirms success, using the length saved at that `net_dev_start_xmit`. |
| FORWARD | Booked per egress branch on the first `net_dev_queue` for the identified egress, using the saved receive start length. | As for OUTPUT, counted per successful transmit branch. |

IN describes start observations for identified paths, not every interface receive. An skb not yet delivered or queued may have only a global start count and no path row. OUT counters and latency samples belong to the completion interval; initial queuing may belong to an earlier interval. Total retains the original start timestamp. Intervals use the monotonic clock when statistics are recorded, while latency uses hook-entry timestamps; a sample crossing a refresh boundary may belong to the following interval.

RX core usually excludes the Ethernet header, driver transmit usually includes it, and INPUT dispatch may have removed the IP header. Cloning, flooding and GSO segmentation can change completion counts or lengths, particularly when one queued parent becomes multiple completion samples after segmentation. Unequal IN/OUT bytes or PPS do not establish packet loss.

BUSY attempts add neither OUT counts nor successful latency samples. A later successful attempt supplies the endpoint; Queue/Total include the intervening wait. The `net_dev_xmit` return time confirms and books completion but is not part of the measured latency. Success means driver acceptance, not NIC transmit completion or peer receipt.

## Correlation And Lifecycle Hooks

| Attached probe | BPF handler | Purpose |
| --- | --- | --- |
| `fexit/skb_clone` | `on_clone()` → `inherit()` | Clone identity inheritance. |
| `fexit/skb_copy` | `on_copy()` → `inherit()` | Copy identity inheritance. |
| `fexit/skb_copy_expand` | `on_expand()` → `inherit()` | Expanded copy inheritance. |
| `fexit/__pskb_copy_fclone` | `on_pskb()` → `inherit()` | Partial copy inheritance. |
| `fexit/skb_morph` | `on_morph()` → `inherit()` | Identity inheritance after replacing skb contents. |
| `fexit/skb_segment` | `on_segment()` → `segments()` | GSO child inheritance. |
| `fexit/skb_segment_list` | `on_segment_list()` → `segments()` | GSO list inheritance. |
| `fentry/skb_release_head_state` | `on_release()` → `forget()` | Head-state association cleanup. |
| `tp_btf/consume_skb` | `on_consume()` → `consume_event()` → `forget()` | Consumption cleanup. |
| `tp_btf/kfree_skb` | `on_drop()` → `drop_event()` → `forget()` | Free-path cleanup. |
| `fentry/unregister_netdevice_queue` | `on_unregister()` | Disable the interface identity. |
| `fentry/ip_do_fragment` | `on_fragment4()` → `conversion()` | IPv4 fragmentation coverage gap. |
| `fentry/ip6_fragment` | `on_fragment6()` → `conversion()` | IPv6 fragmentation coverage gap. |
| `fentry/ip_defrag` | `on_reassembly4()` → `conversion()` | IPv4 reassembly coverage gap. |
| `fentry/ipv6_frag_rcv` | `on_reassembly6()` → `conversion()` | IPv6 reassembly coverage gap. |

Userspace calls the `SEC("socket")` program `cleanup()` through BPF test-run once per second to execute `origin_expire()` / `tx_expire()`; it is not attached to a business socket. Test-only `raw_tp/*` wrappers and `on_free()` support the native state-machine harness and are not additional production attachments.

`__kfree_skb` reaches `skb_release_head_state`, so it has no separate attachment.
Consume/drop tracepoints remain for alternate free paths, including stateless
consumption; head-state release also retires the old identity before `skb_morph`.
GSO traversal reuses the parent's association in a bounded 128-segment callback;
each child still has its own identity and capacity charge.

Fragmentation and reassembly are not fully correlated. Tracked affected skbs do not produce normal latency samples, so traffic counts and latency sample counts may differ. Separate health counters expose coverage gaps. Userspace invokes a BPF cleanup program once per second to expire stale associations, without injecting packets. Interface discovery, renames and deletion use rtnetlink.

The current collector requires all attached probes; a missing required probe produces an error even if that traffic class is absent. `tp_btf` needs the tracepoint's BTF type, `fentry/fexit` need the relevant BTF function targets, and bridge support must be available. All times are elapsed time between observation points. Total percentiles are calculated independently; do not add Stack/Queue percentiles. XDP, AF_XDP and hardware-offloaded traffic bypassing these hooks are outside the scope.
