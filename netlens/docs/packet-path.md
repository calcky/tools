# Linux Packet Paths and Observation Boundaries

Status: draft; operator scope confirmation is pending.

netlens models packet processing as a directed graph of branches, clones, transforms, and re-entry points. There is no universal linear "socket -> Netfilter -> TC -> NIC" path: local input, local output, L3 forwarding, L2 forwarding, XDP redirects, virtual devices, tunnels, and XFRM traverse different nodes.

The diagrams use these implementation labels:

- `[I]`: `implemented` evidence or reported path metadata exists now.
- `[P]`: `planned`; a task owner exists, but no registered provider/evidence exists.
- `[U]`: `explicitly unsupported`; the current release must expose a gap and stop inference.

An unlabeled arrow is a processing relationship, not proof that a captured packet traversed it.

## Current evidence overlay

The current build has four evidence providers and one core path resolver:

| Label | Current observation | Scope boundary |
|---|---|---|
| `[I-PROC]` | `linux.proc.protocol_counters`: Socket, Transport, Network, and Route counter deltas | Current-netns aggregate; no interface, flow, or per-packet path identity |
| `[I-SOFTNET]` | `linux.proc.softnet_counters`: RX backlog drops, softirq pressure, and RPS flow-limit drops | Host-wide/per-CPU and `broader_only` |
| `[I-LINK]` | `linux.link.counters`: generic Netdevice, Driver, and NIC counter deltas | Current namespace; interface identity where exposed, but current anchored paths remain broader because closure is incomplete |
| `[I-KFREE]` | `linux.tracepoint.kfree_skb`: neutral skb-free events and validated symbolic reason attribution | Host-wide and `broader_only`; begins only after an skb exists and does not cover every skb path |
| `[I-PATH]` | Core resolver: visible sysfs `upper_*`, `lower_*`, and local `iflink` closure | Current namespace; always records `dynamic_redirect` today, and records cross-namespace/unresolved-lower gaps when found |

`[I-KFREE]` never treats a free as an unconditional drop. A validated symbolic reason may identify a dropped or rejected disposition and a coarse stage; an unknown reason remains neutral, and `SKB_CONSUMED` is normal consumption/completion. Raw skb and location pointers are not public identities.

## Report v3 path vocabulary

[ADR-0006](decisions/0006-report-v3-path-graph.md) separates report-v3 `network`, `route`, and `xfrm`. Network contains IP validation, fragmentation/reassembly, and MTU processing; Route contains lookup and neighbor decisions; XFRM contains policy and transform processing. These Layers classify evidence but do not define one processing order. `l2_local_input` and `l2_local_output` PathRoles distinguish bridge-local delivery and locally generated L2 traffic from `local_input` and `local_output` IP paths.

Every Evidence row and Finding carries a required nullable execution domain. Current kernel-path evidence uses `linux.kernel`, while NIC/PHY evidence uses `linux.hardware`; this is independent of measurement domain and network namespace. Capability `stageCoverage` states which provider, Stage, and execution-domain combinations are active or degraded and which Evidence forms they can produce. Layer-wide coverage alone does not authorize evidence at an uncovered Stage.

Observed graph order uses the existing `hop` and `flow_domain` Subjects. Every Hop has a positive `nwdiag.path.hop_ordinal`. A non-null transition is valid only with explicit, disjoint `before` and `after` Hop or FlowDomain references and a known execution domain. The ordinal orders hops within that reported path context; it does not order Stages globally or connect branches by itself. Without such transition metadata, netlens reports evidence by Layer and must not describe the Layer display order as a traversed path. The diagrams below describe possible Linux processing relationships; their arrows are not report-v3 transition evidence.

## Receive front end and XDP branches

```text
[I-LINK] NIC/PHY and aggregate RX counters
    |
    +-> [U] hardware/offloaded XDP or SmartNIC action
    |       `-> host path may terminate with no host verdict evidence
    |
    `-> RX ring/DMA -> driver NAPI poll
            |
            +-> [P] native XDP
            |       |-> DROP/ABORTED: terminate
            |       |-> XDP_TX/devmap: driver XDP TX branch
            |       |-> XSKMAP: [U] AF_XDP RX/userspace/UMEM
            |       `-> cpumap PASS: target CPU, then possible skb re-entry
            |
            `-> skb build/GRO -> [I-SOFTNET] RPS/per-CPU backlog
                    -> [P] generic XDP
                         -> [P] software VLAN header untag, when present
                         |-> tap copy -> [U] AF_PACKET consumer boundary
                         `-> main skb -> [P] TC ingress
                              -> [P] NF_NETDEV_INGRESS
                              -> [P] metadata VLAN receive / rx_handler
                                   |-> device switch and RX re-entry
                                   `-> virtual-device/L2 branch or L3 receive
```

Native XDP executes before the normal skb ingress path, so `[I-KFREE]` cannot account for native XDP drops. Generic XDP has an skb; a validated reason can sometimes attribute a generic-XDP free, but this does not implement XDP program/verdict inventory. XDP_TX, devmap, cpumap, and XSKMAP lead to different destinations and must not be collapsed into one redirect.

Software VLAN headers are removed after generic XDP and before packet taps/TC. A hardware-accelerated metadata VLAN is resolved after TC and `NF_NETDEV_INGRESS`; it can change `skb->dev` and re-enter the RX round. The two paths are distinct observation stages.

AF_XDP is a bidirectional bypass boundary. XSKMAP RX transfers an XDP frame to userspace/UMEM, while an AF_XDP TX ring can enter driver XDP TX without Socket, TC, Netfilter, qdisc, or the normal skb path. Fill/RX/TX/completion rings, starvation, invalid descriptors, and copy/zero-copy modes are explicitly unsupported until Tasks 13b and 16c provide dedicated evidence.

AF_PACKET observes a tap copy, not ownership of the original main-path packet. A tap ring overflow or filter loss must be scoped to that consumer and cannot be inferred from main-path counters; the current release explicitly stops at this boundary.

## Local input

```text
RX common front
  -> [P] IPv4/IPv6 receive validation
  -> [P] NF_PRE_ROUTING (conntrack defrag may be one hook participant)
  -> [P] route decision
       |-> [P] local-delivery reassembly
       -> [P] NF_LOCAL_IN
       -> [P] inbound XFRM policy / optional decrypt re-entry
       -> [P] transport validation and demux
       -> [U] sk_lookup/reuseport, cgroup skb ingress, LSM, socket filter
       -> [I-PROC] socket receive/listen/backlog aggregate deltas
       -> application
```

`[I-PROC]` can show namespace-wide Network validation/discard evidence, Route no-route evidence, UDP receive-buffer errors, listen overflow/drop, TCP backlog drops, and retransmission symptoms. It cannot prove that a packet observed elsewhere reached a particular socket. `[I-KFREE]` may independently provide a validated Socket, Transport, Network, Route, or XFRM reason, but its host-wide scope prevents attaching the requested interface, namespace, or flow identity.

Inbound tunnel-mode XFRM is a cycle, not an inline label: an outer packet can reach LOCAL_IN, decrypt, produce an inner packet/domain, and re-enter PRE_ROUTING. The inner and outer quantities cannot be subtracted or treated as one unchanged packet identity.

## Local output

```text
application
  -> [P] socket send queue / transport construction
  -> [P] route
  -> [P] NF_LOCAL_OUT
  -> [P] output policy and possible reroute
  -> [P] NF_POST_ROUTING / SNAT flow-domain transition
  -> [P] XFRM transform and possible outer route/output re-entry
  -> [U] cgroup inet/skb egress policy
  -> [P] local MTU and fragmentation/GSO
  -> [P] neighbor
  -> DEVICE HOP
```

The proc provider may report current-netns Socket, Transport, Network, or Route aggregates around this path, but it does not establish traversal between nodes. A synchronous application send failure is not a wire drop. NAT and XFRM create new flow or measurement domains; without an explicit transition mapping, correlation stops.

## L3 forwarding

```text
[P] NF_PRE_ROUTING -> route
  -> [P] XFRM_POLICY_FWD
  -> [P] TTL/hop-limit/MTU checks
  -> [P] NF_FORWARD
  -> [P] output policy/route
  -> [P] NF_POST_ROUTING
  -> [P] optional XFRM transform and outer re-entry
  -> [P] fragmentation / packet-too-big
  -> [P] neighbor
  -> DEVICE HOP
```

An L3-forwarded packet does not traverse `NF_LOCAL_IN` or `NF_LOCAL_OUT`, and it does not acquire a local socket path. Current namespace-wide IP counters can indicate aggregate Network or Route evidence, but skipped Netfilter, Route, and XFRM nodes remain planned, not observed.

`NF_NETDEV_EGRESS` is unavailable before Linux 5.16. On 5.16+ it remains `[P]` until a family/hook-specific runtime probe and attach succeeds; a version comparison alone cannot claim the node.

## L2 forwarding and bridge-family paths

```text
RX common front -> [P] native bridge ingress / bridge-family PRE_ROUTING
  -> [P] bridge core (STP, VLAN, FDB/MDB, isolation, hairpin, multicast)
       |
       +-> local delivery (`l2_local_input`)
       |     -> [P] bridge-family LOCAL_IN
       |     -> bridge-master RX re-entry
       |     -> TC/netdev/L3 receive stages may repeat
       |
       `-> forward or flood clone(s)
             -> [P] bridge-family FORWARD
             -> [P] bridge-family POST_ROUTING
             -> one DEVICE HOP per egress clone

L2 local output (`l2_local_output`)
  -> [P] bridge-family LOCAL_OUT
  -> [P] bridge-family POST_ROUTING
  -> DEVICE HOP
```

Native bridge decisions and bridge-family Netfilter hooks are different nodes. When `br_netfilter` is disabled, no IPv4/IPv6 hook may be synthesized for L2 forwarding. When it is enabled, only actually observed IP-hook evidence may be added, and the path role remains L2.

A bridge local-delivery branch uses `l2_local_input` and re-enters receive processing through the bridge master. A flood creates multiple egress clones; fanout itself is not a drop, and clone quantities cannot be added to the original as if all rows measured one packet domain. Bridge semantics are planned under Tasks 14a and 15b.

## Device hops, qdisc, and lower devices

```text
DEVICE HOP
  -> [P] NF_NETDEV_EGRESS (5.16+ candidate only)
  -> [P] TC egress
  -> [P] TX queue selection
  -> [P] qdisc enqueue/dequeue, or noqueue
  -> [P] xmit validation / GSO
       |-> tap copy -> [U] AF_PACKET TX consumer boundary
       `-> main skb -> [P] driver ndo_start_xmit
            |
            +-> virtual/lower device: start a new DEVICE HOP
            `-> TX ring/DMA -> [I-LINK] aggregate Driver/NIC counters
                         `-> [P] asynchronous completion/BQL/queue-wake feedback
```

A lower-device transition repeats the device-hop stages; it does not merely rename the same interface. In report v3 an observed handoff needs separate Hop Subjects with their own ordinals plus explicit `before` and `after` transition endpoints. Normal completion is not a drop, and driver acceptance or DMA completion does not prove physical wire delivery. GSO skbs, segments, interface packets, and wire frames belong to different measurement domains.

`[I-PATH]` currently walks visible sysfs upper/lower links and local `iflink`, but it does not know the semantics of VLAN, bond/team, veth, tun/tap, macvlan/ipvlan, or tunnels. Semantic topology and per-hop stitching are planned in Tasks 15a and 15e. Because TC/XDP redirect inventory is absent, every resolved anchor contains `dynamic_redirect`; therefore closure filtering is not applied and link evidence remains `all_visible`/`broader_only`.

A peer outside the current namespace adds `cross_namespace` and terminates correlation. An unresolved lower link does the same at that boundary. Visible tunnel netdevices may appear in the static closure, but encapsulation, decapsulation, and inner/outer flow transitions remain unobserved. OVS datapath decisions are explicitly unsupported and terminate path inference.

## XFRM outer/inner cycles

```text
inbound:
  outer PRE_ROUTING -> route -> LOCAL_IN -> [P] decrypt
      -> new inner domain -> PRE_ROUTING re-entry -> route -> local input or forward

outbound/forward:
  policy lookup -> POST_ROUTING -> [P] transform
      -> new outer domain -> route/output re-entry
      -> policy/hook cycle as actually observed -> DEVICE HOP
```

Policy lookup, transform, reroute, post-SNAT policy relookup, and re-entry are separate XFRM nodes, not Route stages. Transport and tunnel modes can produce different cycles. Hardware-offloaded transforms use a distinct execution domain and may leave only inventory or counters; until Task 15d implements and validates explicit FlowDomain/Hop transitions, netlens must not connect inner and outer evidence by timing or a presumed unchanged five-tuple.

## Gap and termination rules

- `dynamic_redirect` broadens an interface-anchored request because an unobserved TC/XDP redirect may leave the visible static closure.
- `cross_namespace` or an unresolved lower device terminates stitching at the last visible hop; evidence from another namespace is not assigned to the anchor.
- Hardware/offloaded XDP, flowtable, XFRM, switchdev, SmartNIC/DPU, SR-IOV, VFIO/UIO, and DPDK paths terminate or broaden host correlation unless a dedicated runtime source proves the next transition.
- AF_XDP, AF_PACKET, OVS, cgroup/socket policy, and other explicitly unsupported boundaries never inherit evidence from a neighboring stage.
- A topology gap is a coverage limitation, not a drop. Likewise, lack of evidence is never reported as zero loss.
- A Hop ordinal without a validated transition does not prove adjacency; matching time, tuple, or Layer rank does not fill in a missing edge.
- Planned TC, Netfilter, qdisc, XDP, bridge, XFRM, or lower-hop nodes are not marked observed merely because an aggregate link/proc counter or a broad skb-free event exists nearby.
