# Provider and Stage Support Matrix

Status: draft; operator scope confirmation is pending.

This document states what the current netlens build can observe and where it must stop. The product baseline is Linux 4.14, but a kernel version is only a candidate capability: readable sources, compatible runtime layouts, permissions, map creation, and successful attachment still decide whether a provider is active.

The default v1 TUI uses a separate counter-monitor contract from the frozen
Report evidence providers described below. Its live adapters currently cover
proc protocol/socket/conntrack data, qdisc statistics through bounded `tc` JSON,
rtnetlink/sysfs/proc link statistics, sysfs link/configuration, opaque ethtool
link/ring/pause/feature/coalescing settings and `ethtool -S` statistics,
`/proc/softirqs`, softnet counters and `net.core` budget/backlog configuration,
sysfs-verified NIC HardIRQs, and bounded read-only iptables/nftables policy
inventory and rule counters. TC filter/action
data, pause/FEC counters, verified ring-drop semantics, and every BPF/event
overlay remain unsupported in the default TUI. An unavailable command,
permission, or kernel source degrades only its monitor provider and never
becomes a synthetic zero.

NIC settings include current and maximum ring lengths, flow control,
TSO/LRO/GRO/GSO, and common coalescing values (adaptive RX/TX and RX/TX
usecs/frames). Ordinary ethtool plus `-g`, `-a`, `-k`, and `-c` run at startup
and refresh approximately every 30 seconds; cached configuration remains
visible between refreshes while retaining the completion time and collection
duration of the NIC collection cycle that performed the actual static refresh.
Dynamic `ethtool -S` statistics run every main sampling interval. Configuration
values are context only and do not become WARN or CRIT solely because of their
value. Newly observed hardware interfaces are refreshed immediately rather than
waiting for cache expiry. Interface HardIRQ detail reuses the available RX/TX
coalescing settings; SoftIRQ detail shows the current packet/time budgets,
backlog weight, and maximum per-CPU backlog without treating missing values as
zero.

## Status and claim rules

This matrix uses exactly three implementation statuses:

- `implemented`: current code can probe, collect, and report the capability.
- `planned`: a task owner exists, but no live evidence adapter exists yet; a contract-only provider may already be registered as unavailable.
- `explicitly unsupported`: the current release must expose a gap and must not infer the path.

An `implemented` provider can still be unavailable or degraded on a particular host. Runtime coverage is reported separately through availability, visibility, forms, filter support, integrity, and provider-stage execution-domain coverage. Conversely, finding `tc`, `nft`, `ethtool`, or `devlink` during capability discovery does not activate a Report evidence collector for that subsystem. The separate default-TUI command providers below run their own probes and health reporting.

Only these public evidence provider IDs are currently registered:

- `linux.proc.protocol_counters`
- `linux.proc.softnet_counters`
- `linux.link.counters`
- `linux.sock_diag.skmeminfo`
- `linux.tracepoint.kfree_skb`
- `linux.tracepoint.udp_fail_queue_rcv_skb`
- `linux.tracepoint.sock_rcvqueue_full`

`nwdiag.core` is a Schema-recognized tool-owned identity, but it is not an active packet-path collector and is not counted as one here. No other provider ID is reserved by this document. A broad observation, including a reason-attributed skb free, does not make a dedicated stage collector implemented.

`linux.sock_diag.skmeminfo` executes its private collector and reports query telemetry. Live report v5 publishes a positive delta only as generic per-socket context with a fresh opaque Subject, `source_units`, null Layer/Stage, and no Finding. The frozen v4 descriptor incorrectly treated generic `sk_drops` as receive-queue evidence; [ADR-0009](decisions/0009-generic-socket-drop-accounting.md) defines the corrected contract. The two causal tracepoint provider IDs are registered but remain unavailable until their independent adapters are implemented.

## Default TUI Netfilter monitor

This capability belongs to the continuous monitor contract, not the public
Report evidence-provider list above. The Netfilter page exposes
`Menu -> Conntrack / iptables IPv4 / iptables IPv6 / nftables`. A rules entry
opens a chain list, and a selected chain opens its one-row-per-rule inventory.

| Menu entry | Monitor provider/source | Implemented visibility | Runtime degradation |
|---|---|---|---|
| Conntrack | `linux.proc.netfilter.conntrack`; procfs/sysfs | Table use, capacity, utilization, and per-CPU lookup/insert/invalid/drop/pressure counters; transient flow table on demand | Missing or denied proc/sys sources remain unavailable; flow tuples stay outside general monitor history |
| iptables IPv4 | `linux.iptables.ipv4`; bounded `iptables-save -c` | Chain/table membership, policy, rule expression/verdict, and available packet/byte hit counters | Missing command is Unsupported; permission is PermissionDenied; other bounded command/schema failures retain typed health |
| iptables IPv6 | `linux.iptables.ipv6`; bounded `ip6tables-save -c` | Same policy inventory for IPv6, kept independent from IPv4 | Same independent degradation rules as IPv4 |
| nftables | `linux.nft.ruleset`; bounded `nft -j -a list ruleset` JSON | Family/table/chain identity, hook/priority/type/policy, named or inline counters, rule expression/verdict, and available packet/byte hits | Missing command and permission remain explicit; an observed flowtable makes visibility Partial |

The backend identity remains `nftables`, `iptables_nft`, `iptables_legacy`, or
`iptables_unknown`; counters are never combined across those identities.
Native nftables and iptables-nft can observe the same underlying rules and must
not be added. Counterless rules remain visible as `NO COUNTER`, not zero. A rule
hit is not a drop unless its verdict is explicitly DROP or REJECT; QUEUE only
proves userspace delivery. NAT rule counters commonly cover connection setup
rather than whole-connection traffic. Detected nft flowtables provide only
partial classic-rule visibility, including when traffic is hardware offloaded.

## Implemented provider profiles

| Provider | Baseline | Runtime probe and source | Forms | Reported layers and stages | Effective scope and filters | Blind spots | Fallback |
|---|---|---|---|---|---|---|---|
| `linux.proc.protocol_counters` | Linux 4.14 | Read `/proc/net/snmp` and `/proc/net/netstat`; parse paired header/value tables | `counter_delta` | Socket: `socket.receive_queue`, `socket.listen_queue`, `socket.backlog`; Transport: `transport.retransmission`; Network: `network.unspecified`, `network.receive_validation`; Route: `route.lookup` | Current network namespace aggregate. Layer selection is userspace exact and the current namespace is kernel exact; interface, direction, protocol, and flow attribution are `broader_only`. | No socket, interface, queue, rule, or flow identity. Retransmission is a symptom, not a local drop location. Counters with different measurement identities are not added. | A failed table is reported; independently valid evidence may remain, but coverage is not promoted and no source is treated as an equivalent replacement. |
| `linux.proc.softnet_counters` | Linux 4.14 | Read `/proc/net/softnet_stat`; use `/sys/devices/system/cpu/online` when available to map rows to online CPUs | `counter_delta` | `netdevice.rx_backlog`, `netdevice.softirq`, `netdevice.rps_backlog` | Host-wide, with per-CPU rows when mapping is available. All namespace, interface, direction, protocol, and flow filters are `broader_only`. | Cannot attribute pressure or drops to an interface or flow. `time_squeeze` is pressure; `dropped` and `flow_limit_count` are distinct drop counters; `received_rps` counts RPS softirq/IPI trigger occurrences, not packets. | Preserve row identity if CPU mapping is unavailable; provider is unavailable if softnet data cannot be read. |
| `linux.link.counters` | Linux 4.14 | Native rtnetlink link-statistics dump; fall back to `/sys/class/net/*/statistics`, then `/proc/net/dev` | `counter_delta` | `netdevice.unspecified`, `driver.rx_queue`, `driver.unspecified`, `nic.phy` | Current network namespace. RX/TX direction selection is userspace exact. Interface-path filtering is userspace exact only for a complete topology closure; every current resolved path has `dynamic_redirect`, so anchored captures currently remain `all_visible` and `broader_only`. | Aggregate interface counters do not identify a packet, queue in most cases, or an exact driver/NIC execution point. Offload, detailed ethtool/devlink semantics, resets, and cross-namespace hops can prevent attribution. | Rtnetlink -> sysfs -> procfs. Each fallback retains only the fields and labels it exposes; failure is reported rather than converted to zero. Folded `/proc/net/dev` RX `drop`, RX `frame`, and TX `carrier` are not mapped to any one exact canonical field. |
| `linux.sock_diag.skmeminfo` | Linux 4.14 | Native `NETLINK_SOCK_DIAG` start/end dumps for IPv4/IPv6 TCP/UDP; strictly parse `INET_DIAG_SKMEMINFO/SK_MEMINFO_DROPS` and privately match identity | Generic context `counter_delta` | Evidence has null Layer/Stage and contributes only aggregate Socket context coverage; it owns no StageCoverage | Collection is current-network-namespace-wide. Layer selection is userspace exact; namespace is kernel exact; interface, direction, protocol, and flow filters are `broader_only`. A positive delta references one fresh opaque Socket Subject. | `sk_drops` mixes queue, checksum/filter, copy, TCP processing/listen, and other sources, with source-dependent units including GSO segments. Churn, reuse, missing SKMEMINFO, and full 32-bit wraps add further uncertainty. | Keep collection errors and netlink telemetry; retain proc Socket aggregates independently. Only audited causal events may provide exact queue attribution. |
| `linux.tracepoint.kfree_skb` | Linux 4.14 legacy path | Read the runtime `skb:kfree_skb` format, select a validated legacy/reason/rx-sk object, create its transport, and load/attach it. Resolve symbolic reasons and `SKB_CONSUMED` from running-kernel BTF when available. | `event` | Neutral `linux.skb.free` observations. A validated symbolic reason may add a reason-derived Socket, Transport, Network, Netfilter, Route, XFRM, Virtual device, TC, Netdevice, or generic-XDP stage. | Host-wide, `all_visible`, and `broader_only` for namespace, interface, direction, protocol, and flow requests. | An skb free is not inherently a drop. Legacy events have no standardized reason; unknown raw reasons remain neutral. It does not cover hardware, offloaded/native XDP, pre-skb loss, AF_XDP/DPDK paths, or every policy verdict. Raw skb/location pointers are never public. | Unknown layout or failed map/load/attach selects counter-only operation: this provider is unavailable while the other counter providers continue. |

## Report v5 and the inherited v3 layer/graph contract

[ADR-0006](decisions/0006-report-v3-path-graph.md) made `network`, `route`, and `xfrm` separate report-v3 Layers; report v5 inherits that contract unchanged. This is an ownership split, not a claim that every Stage now has a dedicated collector:

| Layer | Current evidence owner | Current Stage boundary | Planned dedicated owner |
|---|---|---|---|
| Network | `linux.proc.protocol_counters` maps IP discards to `network.unspecified` and header/address errors to `network.receive_validation`; validated `linux.tracepoint.kfree_skb` reasons can add Network stages | IP receive validation, fragmentation/reassembly, and MTU processing belong here; they are not route decisions | Network/L3 owner (Task 15c) |
| Route | `linux.proc.protocol_counters` maps `OutNoRoutes` to `route.lookup`; validated `linux.tracepoint.kfree_skb` no-route and neighbor reasons can add Route stages | Lookup, FIB/policy-routing, and neighbor decisions belong here; MTU and fragmentation do not | Route/neighbor owner (Task 15c) |
| XFRM | Validated `linux.tracepoint.kfree_skb` XFRM reasons can add `xfrm.policy` or `xfrm.unspecified` coverage dynamically | Policy, transform, and inner/outer re-entry are distinct XFRM nodes; an XFRM reason alone does not prove a transition | XFRM owner (Task 15d) |

Every current report-v5 Evidence row and Finding carries the required nullable `executionDomain` introduced in v3. Current kernel stages use `linux.kernel`; NIC/PHY evidence uses `linux.hardware`. Capability `stageCoverage` is keyed by provider, Stage, and execution domain and publishes that Stage's availability, visibility, forms, filter support, integrity, and limitations. Staged Evidence is valid only when an active or degraded row covers the same Layer, Stage, domain, and form. Generic sock-diag context is deliberately unstaged and therefore requires no StageCoverage row.

The graph contract reuses `hop` and `flow_domain` Subjects. Every Hop has a positive `nwdiag.path.hop_ordinal`; an explicit transition has a namespaced transition value plus disjoint `before` and `after` Hop or FlowDomain references. The inherited contract also distinguishes `l2_local_input` and `l2_local_output` from IP-local roles. The current collectors emit no transition edges, and the static core path resolver does not yet provide semantic per-hop stitching, so current output must not turn Layer order into an observed path.

## Stage matrix

`Minimum kernel` is the lowest upstream/product reference for a candidate path. It never activates a capability by itself; every implemented and future owner must probe the running host. `Feature-dependent` means a composite planned row has no single version: the product fallback remains Linux 4.14, and its eventual provider must record and probe each concrete source separately.

| Status | Stage/path | Owner | Minimum kernel | Probe | Forms | Filter support | Blind spots | Fallback |
|---|---|---|---|---|---|---|---|---|
| `implemented` | Socket receive queue, listen queue, and backlog aggregates | `linux.proc.protocol_counters` (Task 10a) | 4.14 | Procfs table/field presence and strict parsing | `counter_delta` | Current-netns aggregate; other filters `broader_only` | No per-socket identity or causal event | Report the provider gap; never turn absence into zero |
| `implemented` | Generic per-socket `sk_drops` context; no causal Stage | `linux.sock_diag.skmeminfo` (Tasks 10b-10d2) | 4.14 | Native current-netns collection, private identity matching, and strict v5 normalization | `counter_delta` | Current-netns query; interface, direction, protocol, and flow filters `broader_only` | Mixed causes, directions, domains, and source-defined units cannot prove receive-queue overflow | Emit null Layer/Stage context with an opaque Socket Subject and no Finding; retain proc evidence independently |
| `planned` | UDP receive-buffer and protocol-memory rejection | `linux.tracepoint.udp_fail_queue_rcv_skb` (Task 10d3) | IPv4 call site in 4.14; IPv6 in 6.5; runtime-probed | Provider-specific format/ABI/load/attach/transport state; adapter not implemented | Future `event`; current Stage rows have no forms | Host-wide; all namespace, interface, direction, protocol, address, and port filters `broader_only` | Legacy and tuple layouts differ; old kernels lack IPv6 coverage; batching leaves a mainline gap | Provider remains independently unavailable; retain MIB, sock-diag context, and kfree evidence without inferring this event |
| `planned` | Generic-helper receive-buffer occupancy rejection | `linux.tracepoint.sock_rcvqueue_full` (Task 10d4) | 4.14; runtime-probed | Provider-specific format/load/attach/transport state; adapter not implemented | Future `event` with bounded numeric attributes; current Stage row has no forms | Host-wide; all namespace, interface, direction, protocol, address, and port filters `broader_only` | Covers only `__sock_queue_rcv_skb()` occupancy rejection, not UDP, protocol memory, locked-socket backlog, or listen queues | Provider remains independently unavailable; retain other sources without widening this event's claim |
| `explicitly unsupported` | Stable causal TCP listen/accept overflow event | None; aggregate fallback only | No stable upstream source found | Capability matrix retains the gap | None | No causal event scope can be claimed | `SOCKET_BACKLOG` is input skb backlog, and `sock_rcvqueue_full` is not listen evidence | Keep `ListenDrops`/`ListenOverflows` and generic sock-diag context separate; never add their quantities |
| `implemented` | TCP retransmission aggregate | `linux.proc.protocol_counters` (Task 10a) | 4.14 | Procfs table/field presence | `counter_delta` | Current-netns aggregate; flow and interface `broader_only` | Symptom only; cannot locate a local drop | Report only the aggregate symptom |
| `planned` | TCP reset/timeout/state and TCP/UDP validation/error detail | Transport event and validation owner (Tasks 10e, 10g) | Feature-dependent; runtime-probed | Runtime tracepoint/ABI/attach probe and validated counters | `event`, `counter_delta`, `gauge` | Source-dependent; effective scope must be explicit | Offload domains and differing segment/datagram/skb units | Retain validated proc counters without inferring a stage |
| `implemented` | IP discard and receive-validation aggregates at `network.unspecified` and `network.receive_validation` | `linux.proc.protocol_counters` | 4.14 | Procfs table/field presence | `counter_delta` | Current-netns aggregate; interface and flow `broader_only` | A namespace aggregate cannot identify an IP version, packet, interface, hook, or exact validation branch | Preserve each raw metric and Network Stage; do not claim traversal or a route decision |
| `implemented` | IP no-route aggregate at `route.lookup` | `linux.proc.protocol_counters` | 4.14 | Procfs `OutNoRoutes` field presence | `counter_delta` | Current-netns aggregate; interface and flow `broader_only` | No route-table, FIB-rule, destination, packet, or causal lookup identity | Report only the aggregate Route signal; do not infer neighbor or XFRM processing |
| `planned` | Per-packet IPv4/IPv6 receive validation, fragmentation/reassembly, and MTU detail | Network/L3 owner (Task 15c) | Feature-dependent; runtime-probed | Validated protocol counters plus event-format/attach probes | `event`, `counter_delta`, `gauge` | Intended namespace/interface/path scope; source-dependent | IPv4 checksum and IPv6 version/length/address semantics differ; fragment and MTU units/domains differ | Retain implemented aggregate Network evidence without claiming a graph edge |
| `planned` | Route lookup, FIB rules/ECMP, and neighbor detail | Route/neighbor owner (Task 15c) | Feature-dependent; runtime-probed | Rtnetlink/neighbor inventory plus validated event-format/attach probes | `event`, `counter_delta`, `gauge`, `inventory` | Intended namespace/interface/path scope; source-dependent | Policy routing, VRF, multipath and transformed domains break linear inference | Stop at the unresolved decision/hop and report the coverage gap |
| `implemented` | RX backlog drop, softirq budget pressure, and RPS flow-limit drop | `linux.proc.softnet_counters` | 4.14 | Softnet file and CPU-row mapping probe | `counter_delta` | Host/per-CPU; `broader_only` | No interface, namespace, or flow attribution | Preserve row identity or report provider unavailable |
| `planned` | NAPI, net receive/transmit, and per-packet netdevice detail | Netdevice/NAPI owner (Task 11) | Feature-dependent; runtime-probed | Runtime tracepoint format and attach plus link-source probes | `event`, `counter_delta`, `gauge` | Source-dependent | GRO/RPS and host-wide sources prevent packet-count equivalence | Retain softnet and link aggregates |
| `implemented` | Generic link drops at `netdevice.unspecified` | `linux.link.counters` | 4.14 | Rtnetlink with sysfs/procfs fallback probes | `counter_delta` | Current namespace; direction userspace exact; anchored path currently `broader_only` | Driver semantics vary; no exact queue or packet identity | Rtnetlink -> sysfs -> procfs |
| `implemented` | RX missed/FIFO/interface errors at driver stages | `linux.link.counters` | 4.14 | Rtnetlink with sysfs/procfs fallback probes | `counter_delta` | Current namespace/interface population; direction userspace exact | Aggregate link fields cannot prove driver handoff or completion | Retain only fields exposed by the selected fallback |
| `planned` | TX queue selection, BQL, qdisc-to-driver handoff, completion, and timeout | TX queue/driver owner (Task 12b) | Feature-dependent; runtime-probed | Queue inventory plus validated runtime event probes | `event`, `counter_delta`, `gauge`, `inventory` | Intended interface/queue scope; source-dependent | GSO, asynchronous completion, lower hops, and hardware execution | Retain aggregate link counters |
| `implemented` | CRC/carrier physical-link signals at `nic.phy` | `linux.link.counters` | 4.14 | Rtnetlink with sysfs/procfs fallback probes | `counter_delta` | Current namespace/interface population; direction userspace exact where meaningful | No vendor ring, pause, FEC, firmware, or wire-delivery proof | Retain available generic link fields |
| `planned` | Standard ethtool and verified vendor NIC counters | NIC statistics owners (Tasks 16a, 16b) | Feature-dependent; runtime-probed | Native ethtool UAPI first; validated structured fallback where required | `counter_delta`, `gauge`, `inventory` | Intended interface/queue scope; source-dependent | Vendor meanings and firmware/offload domains require verified mappings | Retain generic link counters and raw unknown metrics |
| `implemented` | Neutral skb free and validated reason-derived stage attribution | `linux.tracepoint.kfree_skb` | 4.14 legacy; reason support runtime-probed | Runtime tracepoint layout, map/load/attach, transport, and BTF reason-catalog probes | `event` | Host-wide and `broader_only` | No end-to-end skb identity; no hardware/native-XDP/pre-skb coverage; not every free is a drop | Counter-only report; do not infer a reason or stage |
| `planned` | TC ingress/egress policy, action counters, and redirects | TC policy owner (Task 12) | Feature-dependent; runtime-probed | Structured TC inventory/schema plus event-source probes | `event`, `counter_delta`, `inventory` | Intended interface/hook/rule scope; source-dependent | Arbitrary TC-BPF verdicts and hardware-only actions may remain partial | Reason-attributed skb events, if independently available, stay broad and do not prove rule identity |
| `planned` | qdisc enqueue/dequeue/drop/overlimit/requeue | qdisc owner (Task 12a) | Feature-dependent; runtime-probed | Qdisc inventory/counters and validated event-format/attach probes | `event`, `counter_delta`, `gauge`, `inventory` | Intended interface/queue scope; source-dependent | GSO units, noqueue, multiqueue, and pressure/drop distinctions | Retain link counters and any independent broad skb reason |
| `planned` | XDP mode/program inventory, verdicts, exceptions, and redirect destinations | XDP owners (Tasks 13a, 13b) | 4.14 product baseline; feature-dependent | Link/program/mode inventory plus runtime tracepoint/probe attachment | `event`, `counter_delta`, `inventory` | Intended program/interface/destination scope; offload may be inventory-only | Ordinary or offloaded XDP_DROP may lack a stable host verdict source | Expose partial/unsupported visibility; never invent skipped skb stages |
| `planned` | Netfilter netdev/IP/bridge hooks and verdict events | Netfilter hook owner (Task 14a) | 4.14 baseline; netdev egress requires 5.16 | Family/hook-specific runtime format and successful attach | `event` | Intended hook/family/path-role scope; source-dependent | A hook/reason does not imply table, chain, or rule identity | Retain broad skb reason only when independently validated |
| `planned` | Report-v5 nftables/iptables policy evidence and rule attribution; the separate default-TUI inventory is implemented above | Netfilter policy owner (Task 14b) | Feature-dependent; runtime-probed | Promotion requires structured ruleset/backend/schema probes plus an evidence adapter | `counter_delta`, `inventory` | Intended namespace/family/table/chain/rule scope | Stateful NAT counters, flowtable, duplicate nft/iptables-nft views, and hardware offload change visibility | Retain the TUI monitor inventory without promoting it to Report evidence or inferring rule identity across gaps |
| `planned` | NFQUEUE delivery/failure, conntrack pressure, NAT transitions, and normalized path fragments | Netfilter state/path owners (Tasks 14c-14f) | Feature-dependent; runtime-probed | Queue/conntrack UAPI and structured policy probes | `event`, `counter_delta`, `gauge`, `inventory` | Intended queue/netns/flow-domain scope; source-dependent | Userspace verdicts, tuple reuse, NAT, and offload can terminate correlation | Preserve separate gaps and pre/post-NAT flow domains |
| `implemented` | Visible static interface closure through sysfs `upper_*`, `lower_*`, and local `iflink` | Core path resolver (Task 2b; not an evidence provider) | 4.14 | Enumerate visible sysfs relations and ifindices | Reported path metadata; no Evidence form | Current namespace only; exact only for a complete closure | Does not understand link semantics, TC/XDP redirects, offload, or hidden peers | Add `dynamic_redirect`; add `cross_namespace` or unresolved-lower gaps when found |
| `planned` | Typed topology, virtual/lower hops, tunnels, redirects, and semantic path stitching | Topology/path owners (Tasks 15a, 15e) | Feature-dependent; runtime-probed | Rtnetlink topology plus redirect/tunnel inventories | `inventory` plus linked stage evidence | Intended visible path closure; gaps broaden or terminate scope | Clone, encapsulation, namespace, OVS, redirect, and offload boundaries | Keep static closure and its gaps; never imply an unobserved hop |
| `planned` | Native bridge decisions, L2 fanout/local delivery, and bridge-family hooks | Bridge owner (Task 15b), with hook evidence from Task 14a | Feature-dependent; runtime-probed | Bridge port/VLAN/FDB/MDB/STP inventory and family-specific hook probes | `event`, `counter_delta`, `gauge`, `inventory` | Intended bridge/port/VLAN/hook scope | Flood clones, local re-entry, and `br_netfilter` cannot be inferred from IP counters | Stop at the topology gap; do not synthesize IP hooks |
| `planned` | XFRM policy, transform, outer/inner domains, and hook re-entry | XFRM owner (Task 15d) | Feature-dependent; runtime-probed | XFRM UAPI plus validated event/attach probes | `event`, `counter_delta`, `inventory` | Intended policy/state/domain scope; source-dependent | Encryption and offload obscure packet identity and invalidate count subtraction | Terminate cross-domain correlation when mapping is absent |

## Special and bypass ownership

These rows define who must make a special path observable. `explicitly unsupported` means the current release must not substitute skb, link, or protocol aggregates for evidence inside that path.

| Status | Special path | Owner | Required evidence or fixture before promotion | Current boundary |
|---|---|---|---|---|
| `explicitly unsupported` | AF_PACKET RX/TX rings, copy/filter, and consumer loss | Socket/bypass inventory owners (Tasks 10f, 16c) | RX/TX ring pressure and copy/filter-loss fixtures with tap-consumer scope | Tap loss is not main-path loss; no ring provider exists |
| `explicitly unsupported` | AF_XDP RX/TX/fill/completion rings, UMEM, copy/zero-copy | XDP redirect owner (Task 13b) and bypass inventory owner (Task 16c) | Linux 4.18+ XSKMAP RX, TX re-entry, starvation, invalid-descriptor, and mode fixtures | Stop at the XSKMAP/userspace or TX-ring boundary; do not infer socket, TC, Netfilter, qdisc, or skb stages |
| `explicitly unsupported` | cgroup skb ingress/egress | Socket/policy inventory owner (Task 10f) | Attached-program inventory plus verdict/gap fixtures | Program presence or runtime statistics are not verdict evidence |
| `explicitly unsupported` | `sk_lookup`, reuseport, LSM receive, and socket filters | Socket/policy inventory owner (Task 10f) | Per-attach-point inventory and deny/verdict-or-gap fixtures | Do not infer lookup, selection, security, or filter outcomes |
| `explicitly unsupported` | AF_INET raw, AF_PACKET TX injection, and sockmap/sockhash `sk_msg`/`sk_skb` redirect | Socket/policy and virtual-path owners (Tasks 10f, 15e) | Entry/redirect-specific inventory, queue and path-transition fixtures | Do not synthesize skipped transport, Netfilter or device-hop stages |
| `planned` | tun/tap userspace ingress/egress | Topology/path and bypass owners (Tasks 15a, 15e, 16c) | Queue, userspace handoff and kernel re-entry fixtures | Terminate at an unobserved userspace queue; a visible netdevice does not prove the userspace path |
| `planned` | TC/qdisc redirect, mirror, clone, and driver handoff | TC/qdisc/TX owners (Tasks 12, 12a, 12b) | Action, qdisc, lower-hop, and hardware/software execution fixtures | `dynamic_redirect` prevents current path closure |
| `planned` | XDP_TX, devmap, cpumap PASS/re-entry, and redirect failures | XDP redirect owner (Task 13b) | Destination-specific redirect/error and re-entry fixtures | Do not synthesize skipped or repeated skb stages |
| `planned` | NFQUEUE kernel queue and userspace delivery | NFQUEUE owner (Task 14c) | No-listener, queue-full, slow-consumer, bypass, and verdict-visibility fixtures | A QUEUE rule hit means queued, not dropped; userspace verdict is not currently visible |
| `planned` | Conntrack, DNAT/SNAT, hairpin NAT, and flow domains | Netfilter state/path owners (Tasks 14d-14f) | Stateful/stateless NAT, tuple reuse, flowtable, and offload fixtures | Do not correlate pre/post-NAT tuples without an explicit mapping |
| `planned` | Native bridge and bridge-family hooks | Bridge owner (Task 15b), hook owner (Task 14a) | STP/VLAN deny, flood clone, local re-entry, and `br_netfilter` on/off fixtures | Do not infer IP hooks from L2 forwarding |
| `planned` | VLAN, bond/team, veth, macvlan/ipvlan, VRF/l3mdev | Topology/path owners (Tasks 15a, 15e) | Ifindex-based topology, policy-routing context and per-hop graph fixtures | Static visible links are partially resolved; semantics, routing tables and cross-namespace peers are not stitched |
| `planned` | VXLAN, Geneve, GRE, WireGuard, and other tunnel hops | Virtual/tunnel path owner (Task 15e) | Encapsulation/decapsulation, inner/outer domain, and lower-hop fixtures | Visible static links may be in closure, but tunnel transitions are not evidence |
| `planned` | IPsec/XFRM | XFRM owner (Task 15d) | IN/FWD/OUT policy, transport/tunnel mode, transform, offload, and re-entry fixtures | Inner and outer traffic cannot currently be correlated |
| `explicitly unsupported` | IPVS, LWT, SRv6, MPLS, multicast fanout and loopback re-entry | Netfilter/route/virtual-path owners (Tasks 14f, 15c, 15e) | Decision, clone, encapsulation and re-entry graph fixtures | Stop before the special decision or re-entry; timing proximity is not a transition |
| `explicitly unsupported` | Open vSwitch datapaths and verdicts | Virtual-path owner (Task 15e), bypass inventory owner (Task 16c) | Dedicated OVS inventory/verdict and userspace/kernel datapath fixtures | Terminate correlation at the OVS boundary; visible netdevices do not reveal OVS decisions |
| `planned` | virtio/vhost device hops | Driver/virtual-path owners (Tasks 12b, 15e, 16a) | Frontend/backend queue, handoff, completion, and lower-hop fixtures | Generic link counters may exist but do not identify the virtio/vhost drop point |
| `planned` | mac80211/wireless queues and link behavior | NIC statistics/mapping owners (Tasks 16a, 16b) | Subsystem-specific queue/retry/drop and hardware-domain fixtures | Generic link fields remain aggregate; no wireless-specific attribution exists |
| `explicitly unsupported` | DSA CPU ports/hardware switching, MACsec, PPP and PPPoE | Topology, virtual-path and NIC owners (Tasks 15a, 15e, 16a-16c) | CPU/user port, encapsulation, offload and physical-link fixtures | CPE-visible interfaces do not reveal hidden switch or encapsulation decisions |
| `explicitly unsupported` | devlink traps, policers, health, and hardware drop reasons | Devlink/bypass inventory owner (Task 16c) | Trap/group/policer plus health-vs-drop fixtures | The current command probe is not a collector; no trap evidence is reported |
| `explicitly unsupported` | SR-IOV PF/VF/representor, switchdev, SmartNIC/DPU, and hardware offload | Devlink/bypass inventory owner (Task 16c) | Port relationship, execution-domain, offload, and visibility-gap fixtures | Host evidence cannot be projected into hardware-only execution |
| `explicitly unsupported` | VFIO/UIO-bound devices and DPDK or other userspace bypass | Devlink/bypass inventory owner (Task 16c) | Driver-binding/topology inventory and controlled bypass fixture | The kernel path terminates at the binding boundary; userspace verdicts are invisible |

## Version and activation boundaries

- Linux 4.14 remains the product baseline. Baseline compatibility does not mean every stage is observable.
- AF_XDP requires at least Linux 4.18 upstream and remains explicitly unsupported until its dedicated runtime sources and fixtures exist.
- `NF_NETDEV_EGRESS` does not exist before Linux 5.16. On 5.16 or newer it is still inactive until its runtime hook/layout and attach probe succeeds.
- Tracepoint fields, BTF, BPF transports, netlink attributes, and distribution backports vary independently of `uname`. Version checks may choose probes, but only successful probes may activate coverage.
