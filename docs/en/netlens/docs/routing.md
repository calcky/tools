# Routing And Conntrack

## Inspect Connections And Directional Traffic

```sh
netlens conntrack
```

Each row shows protocol, state, original endpoints, mark, and directional bytes, packets, PPS and bandwidth.
Enter opens original/reply tuples, NAT relationships and available counters. Use `s/r` to sort or reverse.

Press `/` to filter and Ctrl+U to clear:

```text
tcp and dst port 443
src net 192.168.0.0/24
udp and portrange 10000-20000
```

Expressions match the original tuple; `src/dst` does not use translated NAT addresses.
Filtering changes display only, without resetting totals or changing collection scope.

## Separate Direction From Totals

| Field | Meaning |
| --- | --- |
| TX | Original initiator direction, not necessarily local-interface transmit |
| RX | Reply direction, not necessarily local-interface receive |
| PACKETS / traffic byte | Connection-lifetime packets / bytes |
| PPS / BANDWIDTH | Consecutive valid sample deltas; bandwidth is bit/s |
| avg pkt byte | Lifetime bytes divided by packets in that direction |
| CT mark | Conntrack mark, not another socket or packet mark |

With zero packets or missing accounting, average packet size is `n/a`, not a zero-byte packet.
Hardware forwarding and flow offload can bypass conntrack accounting; incomplete statistics do not prove traffic stopped.

Capacity, utilization, insert failures, drops and early drops describe tracking pressure, not application success rates.
Rule counters are available through Netfilter; enter `:netfilter` in command mode for the related views.
Rules without counters show `NO COUNTER`. Do not sum native nftables and iptables-nft views.

## Inspect Routes And Neighbours

```sh
netlens route
```

Routes, Policy Rules and Neighbours belong to the current namespace.
Select a row and press Enter for matches, nexthops, MTU, policy selectors or ARP/NDISC state.
A neighbour marked `FAILED` is a current NUD state, not a failure rate.

Route and neighbour changes are net differences between complete snapshots, not an event log.
Entries that appear and disappear between samples can be missed. Failed or incomplete samples do not advance the complete baseline.

## Query The Kernel-Selected Route

Open Route Lookup and enter literal IP addresses:

```text
192.168.0.1 from 192.168.0.2 oif eth0 mark 0x1
```

The grammar is:

```text
DEST [from SOURCE] [iif IFACE] [oif IFACE] [mark N] [uid N] [tos N]
```

Source and destination must use the same address family. Numbers accept decimal or a `0x` prefix. No DNS lookup is performed.
The result is the final route, table and nexthop returned by the kernel, not a trace of every policy-rule traversal.

## Forwarding Boundaries

Forwarded traffic usually has no local application socket. Check Network, Conntrack, Qdisc and Interface together.
Network separates IPv4/IPv6, ICMP, fragmentation and reassembly; error fields cannot simply be summed into total loss.
XDP redirects, bridges, tunnels and hardware offload may bypass ordinary IP forwarding; see [Packet Paths](packet-path.md).
