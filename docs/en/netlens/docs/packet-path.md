# Packet Paths

A packet may use the ordinary stack or be handled early by XDP, TC, bridging or hardware offload.
This guide explains **where processing happens, which layers observe it and why counters differ**. These are not netlens per-packet traces.
Sketches reference common Linux 6.6 paths; hooks, drivers and devices vary by environment.

## Ordinary Receive Path

```text
wire -> NIC RX queue / DMA
                  |
             IRQ -> NAPI poll
                  |
            native XDP (if attached)
                  | PASS
                  v
             skb / GRO
                  |
            receive processing
                  |
            generic XDP (if attached)
                  | PASS
                  v
             TC ingress
                  |
        IP / routing / netfilter
                  |
            local delivery
                  |
             TCP / UDP
                  |
           socket -> application
```

Native and generic show alternative execution positions, not a requirement to execute XDP twice for an ordinary received packet.
VLAN, packet taps, netfilter ingress and bridge branches are omitted; this is not an exact ordering of every hook.

The NIC delivers frames into receive buffers and NAPI processes batches; one interrupt may initiate work for multiple packets.
Continued polling or busy polling need not receive a new IRQ for each batch.
GRO can merge packets, and not every packet traverses backlog/RPS.

| Observation Point | Start In netlens |
| --- | --- |
| NIC, driver and receive resources | Interface standard/driver counters |
| Interrupts and receive-processing pressure | HardIRQ, SoftIRQ and softnet |
| IP errors, fragmentation and reassembly | Network |
| TCP/UDP protocol errors | Transport |
| Unread application data, TCP windows and RTT | Socket details |

## XDP {#xdp}

XDP runs a BPF program on the receive path to make an early packet decision. It is not another TCP service and need not enter the IP stack.
Programs on ordinary interfaces typically see link-layer packets; parsing bounds, header modifications and redirect targets are the program's responsibility.

### Three Execution Modes

| Mode | Approximate Location | Important Difference |
| --- | --- | --- |
| native / driver | Driver receive processing, usually before skb creation | Requires driver support; can bypass later stack work |
| generic / skb | Software receive path with an existing skb | Broader compatibility; some skb/receive costs are already paid |
| hardware offload | A supporting NIC | Hardware limits apply; some traffic may never enter host receive processing |

**Native does not mean AF_XDP zero-copy.** XDP execution mode and AF_XDP copy/zero-copy buffer delivery are separate choices.
A mode name alone does not establish speed, CPU cost or complete feature support.

### After The Program Returns

```text
                     XDP program
                          |
    +---------+-----------+-----------+-------------+
    |         |           |           |             |
   PASS      DROP        TX       REDIRECT        ABORTED
    |         |           |           |             |
 normal    discard    same-device    target      exception
 receive              transmit       |
                              +------+------+
                              |      |      |
                           DEVMAP CPUMAP XSKMAP
                              |      |      |
                           netdev   CPU   AF_XDP
```

| Action | Next Step | Accounting Implications |
| --- | --- | --- |
| XDP_PASS | Continue the receive path | Later points may observe it; it can still be dropped later |
| XDP_DROP | Discard at XDP | No later IP/TCP/application counters; not guaranteed in standard RX dropped |
| XDP_TX | Transmit on the receiving device | Not ordinary application TX; generally bypasses the normal egress qdisc |
| XDP_REDIRECT | Hand off to a device, CPU or AF_XDP socket | Does not imply routing/NAT; the returned action does not guarantee delivery |
| XDP_ABORTED | Exceptional action; discard and emit an exception trace signal | Not an ordinary DROP; netlens does not collect this trace signal |

DEVMAP often forwards between devices. It does not automatically perform ordinary IP routing, TTL handling, neighbour resolution or NAT for the program.
CPUMAP moves processing to another CPU, where another program or stack processing may follow; moving CPU alone does not transmit a packet.
Redirects can still fail due to targets, queues, buffers or drivers. Action counts are not successful transmit counts.
Ordinary application TX does not automatically run receive-side XDP. Entering a peer veth's receive path, for example, may encounter XDP there.

### What netlens Can Observe

netlens **does not collect a general XDP attachment inventory, BPF maps or PASS/DROP/REDIRECT action statistics**.
Drivers may expose private `xdp_*` counters. Available source values are retained, but names, units and overlaps are driver-specific.

Native XDP_DROP packets usually never reach the downstream ordinary tcpdump/AF_PACKET capture point on the same device.
Hardware counters may increase while IP, TCP or corresponding softnet counters do not; generic and native visibility also differs.
These differences do not prove driver loss. Zero IP traffic does not prove the absence of received traffic.
Inspect the program's maps, driver documentation or separate tracing tools to verify action distributions.

## AF_XDP: Another Path To Userspace {#af-xdp}

AF_XDP is a socket family, not another name for XDP. Receive typically uses XDP_REDIRECT through XSKMAP to a socket matching the device and queue.

```text
NIC RX -> XDP -> XSKMAP -> AF_XDP RX ring
                                     |
                              user application
                                     |
                              AF_XDP TX ring
                                     |
                              driver -> wire

FILL: application supplies receive buffers
COMPLETION: transmitted buffers can be reused
UMEM: shared packet-buffer memory
```

RX/TX rings hold descriptors; packet data resides in UMEM. FILL supplies receive buffers; COMPLETION returns buffers after transmit completion.
Missing FILL buffers or a full RX ring can prevent reception. COMPLETION is not acknowledgement from the peer.
AF_XDP supplies no TCP reliability, retransmission or RTT. Applications must parse and handle their protocols.

Copy mode copies into UMEM; zero-copy uses UMEM buffers directly with driver support. Native mode alone does not establish zero-copy.
Receive/transmit bypass ordinary TCP/UDP socket delivery and the normal egress qdisc, but still have queues and backpressure.

In netlens Socket, filter with `xdp` to inspect visible sockets' queue IDs, UMEM, ring settings and available error counters.
Configured ring capacity is not occupancy; socket errors are not global XDP_DROP counts.

## TC Compared With XDP

TC ingress/egress usually handles skbs and can classify, drop, modify or redirect.
Native XDP executes earlier in driver receive processing; packets dropped there do not reach that device's later TC ingress.
Both can run BPF, but program types, contexts, helpers and processing costs differ; they are not interchangeable.

TC ingress is not ordinary egress queueing. An egress qdisc can schedule and buffer packets waiting to transmit.
Native XDP_TX, common DEVMAP redirects and AF_XDP TX usually bypass the normal egress qdisc; its traffic cannot account for all TX.
netlens shows qdisc object counters, not class/filter/action inventories or individual TC-BPF action counts.

## Ordinary Transmit Path

```text
application -> socket / TCP / UDP
                         |
                  IP / route lookup
                         |
                  netfilter output
                         |
                  netfilter postrouting
                         |
                  TC egress / qdisc
                         |
                  driver / TX ring
                         |
                        wire
```

TCP retransmission belongs to transport; qdisc requeue is re-enqueueing, not a TCP retransmission.
`acked-app` means the peer TCP acknowledged application bytes, not that its application read or processed them.
Increased TX counters report a local observation point, not proof of delivery.

## Ordinary IP Forwarding And Bypass Paths

```text
ingress -> receive -> IP routing
                          |
                  netfilter forward
                          |
                  netfilter postrouting
                          |
                  qdisc -> egress
```

Conntrack tracks at applicable netfilter hooks; NAT translates at configured hooks. Each packet need not create a connection or decide its NAT mapping anew.
Ordinary forwarding usually has no local application socket. An empty Socket table does not mean no forwarding.
XDP redirect is a different path; bridges, tunnels, veth and hardware offload also alter paths and visibility.
Conntrack TX/RX means original/reply, not ingress/egress interfaces.

## Why Packet Totals Differ

| Cause | Typical Effect |
| --- | --- |
| GRO / LRO | Receive aggregation makes later software counts differ from wire frames |
| GSO / TSO | Large software packets are segmented; wire packet counts may be higher |
| IRQ coalescing / NAPI | One interrupt or poll handles multiple packets |
| XDP / TC | Drops, redirects and bypass paths hide packets from later accounting |
| veth / bridge / tunnel | Multiple netdevices may count the same application traffic |
| Flow / hardware offload | Traffic bypasses software tracking and rule counters |
| Retransmissions and byte definitions | TCP segments, application bytes and link bytes have different scopes |

Check time windows, scope, units and Providers status before comparing counters.
Increasing drops can narrow an investigation, but differences between adjacent totals do not locate an individual packet loss.

## Further Reading

- [Linux AF_XDP](https://docs.kernel.org/6.6/networking/af_xdp.html): UMEM, rings and copy/zero-copy.
- [Linux XDP redirect](https://docs.kernel.org/6.6/bpf/redirect.html): redirect processing, failures and tracing.
- [DEVMAP](https://docs.kernel.org/6.6/bpf/map_devmap.html) / [CPUMAP](https://docs.kernel.org/6.6/bpf/map_cpumap.html): device/CPU redirects.
