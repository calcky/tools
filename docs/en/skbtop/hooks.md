# Observation Hooks

These are the eBPF observation points actually attached by `skbtop`. `fentry/function` observes function entry, `fexit/function` obtains its return result, and `tp_btf/event` listens to a tracepoint with its kernel BTF signature. They are not XDP/TC programs installed on interfaces or a set of netfilter rules. See the [usage page](README.md) for metrics and controls.

## INPUT: Interface To Host

```text
tp_btf/netif_receive_skb                    t0: save start time and skb->len
  inside __netif_receive_skb_core
        |
        | IP receive, routed to the host
        v
IPv4: fentry/ip_protocol_deliver_rcu        t1: local protocol dispatcher entry
IPv6: fentry/ip6_protocol_deliver_rcu

Stack = Total = t1 - t0; no Queue
```

The endpoint precedes subsequent TCP/UDP/ICMP processing, sockets and applications; IPv6 extension-header processing may also follow it. NIC reception, NAPI/GRO and RPS work before RX core entry are excluded. Non-IP local delivery has no measured INPUT latency.

## OUTPUT: Host To Interface

```text
IPv4: fentry/__ip_local_out                 t0: local IP output start
IPv6: fentry/__ip6_local_out
        |
        | IP output, netfilter, neighbor and egress work
        v
tp_btf/net_dev_queue                       tq: egress queue observation
        |
        | Egress scheduling, qdisc, possible driver BUSY retries
        v
tp_btf/net_dev_start_xmit                  tx: driver transmit attempt entry
        |
tp_btf/net_dev_xmit                        result: NETDEV_TX_OK confirms completion

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
tp_btf/net_dev_queue                       tq: actual egress interface known
        |
tp_btf/net_dev_start_xmit                  tx: driver transmit attempt entry
        |
tp_btf/net_dev_xmit                        result: NETDEV_TX_OK confirms completion

Stack = tq - t0; Queue = tx - tq; Total = tx - t0
```

Actual ingress and egress interfaces form a directed path. Each bridge flood branch is counted independently, including same-interface hairpins. NAT has no additional timing probe and no separately measured NAT duration.

| Classification | Actual function-entry probes | Purpose |
| --- | --- | --- |
| Route | `fentry/ip_forward`, `fentry/ip6_forward` | Mark IPv4/IPv6 route forwarding. |
| Bridge receive and branches | `fentry/br_handle_frame_finish`, `fentry/br_forward`, `fentry/br_flood` | Mark bridge receive, unicast branches and flooding. |
| Bridge egress | `fentry/br_forward_finish`, `fentry/br_dev_queue_push_xmit`, `fentry/br_dev_xmit` | Retain bridge classification at egress or for local output through a bridge. |

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

| Purpose | Actual probes |
| --- | --- |
| Clone/copy identity inheritance | `fexit/skb_clone`, `fexit/skb_copy`, `fexit/skb_copy_expand`, `fexit/__pskb_copy_fclone`, `fexit/skb_morph` |
| Software segmentation child inheritance | `fexit/skb_segment`, `fexit/skb_segment_list` |
| Free and retire associations | `fentry/skb_release_head_state`, `tp_btf/consume_skb`, `tp_btf/kfree_skb` |
| Device unregister | `fentry/unregister_netdevice_queue` |
| Fragmentation/reassembly coverage diagnostics | `fentry/ip_do_fragment`, `fentry/ip6_fragment`, `fentry/ip_defrag`, `fentry/ipv6_frag_rcv` |

`__kfree_skb` reaches `skb_release_head_state`, so it has no separate attachment.
Consume/drop tracepoints remain for alternate free paths, including stateless
consumption; head-state release also retires the old identity before `skb_morph`.
GSO traversal reuses the parent's association in a bounded 128-segment callback;
each child still has its own identity and capacity charge.

Fragmentation and reassembly are not fully correlated. Tracked affected skbs do not produce normal latency samples, so traffic counts and latency sample counts may differ. Separate health counters expose coverage gaps. Userspace invokes a BPF cleanup program once per second to expire stale associations, without injecting packets. Interface discovery, renames and deletion use rtnetlink.

The current collector requires all attached probes; a missing required probe produces an error even if that traffic class is absent. `tp_btf` needs the tracepoint's BTF type, `fentry/fexit` need the relevant BTF function targets, and bridge support must be available. All times are elapsed time between observation points. Total percentiles are calculated independently; do not add Stack/Queue percentiles. XDP, AF_XDP and hardware-offloaded traffic bypassing these hooks are outside the scope.
