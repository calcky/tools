# Interfaces, Queues And IRQs

## Drill Down From An Interface

```sh
netlens -i eth0,eth1 interface
netlens qdisc
netlens hardirq
netlens softirq
```

Interface combines traffic and settings. Select a device and press Enter for its layer details.
Use `s/r` or traffic headings to sort and reverse; settings are not sortable.
`-i` filters interface-labelled rows. Host-wide softirq statistics do not become per-interface measurements.

## Traffic And Driver Counters

Start with RX/TX bandwidth and PPS, then drops, errors and driver-provided categories.

| Metric | Scope |
| --- | --- |
| PACKETS / TRAFFIC | Cumulative device packets / bytes |
| PPS / BANDWIDTH | Changes over actual elapsed time; bandwidth is bit/s |
| DROPS / ERRORS | Netdevice drops / errors, not end-to-end loss |
| CRC / frame / missed | Driver/hardware categories, not automatically additive |
| Driver-private counters | Source values; names alone do not establish units or XDP action semantics |

PFs and VFs appear as actual netdevices, including DOWN devices. A VF without a netdevice in the current namespace is not fabricated.
Software-interface RX/TX is not physical wire traffic; one application packet can traverse multiple virtual devices.

## Read Settings

Settings include speed, duplex, driver, MTU, RX/TX queues and rings, pause, offload and the root qdisc.
They are read-only facts; one setting alone does not establish a fault.

- MTU bounds IP packet size on the link; it is not TCP MSS.
- RX/TX rings, `tx_queue_len` and BQL are distinct buffers or limits, not substitutes.
- Queue counts include driver-reported combined channels; sysfs fallbacks retain their source labels.
- `fixed` requires explicit source evidence, not a current value equal to its maximum.
- GRO/GSO/TSO change packet counts at different points; see [Packet Paths](packet-path.md).

Missing settings remain `n/a`. Check Providers for driver support and permission failures.

## Inspect qdisc Queues And Drops

```sh
netlens qdisc
```

| Metric | Meaning |
| --- | --- |
| backlog | Current queued data, not historical drops |
| drop/s | Queue drop rate |
| requeue/s | Re-enqueueing, not loss or TCP retransmission |
| overlimit | A scheduling limit was exceeded, not necessarily a drop |
| packets / bytes | Lifetime traffic at this qdisc accounting point |

Roots and children remain separate and must not be summed. Overview highlights root egress qdiscs with new drops or requeues.
Class/filter/action collection is not included. TC ingress and XDP redirects do not follow ordinary egress-qdisc accounting.

## Compare Hardware IRQs And softnet

HardIRQ lists verified network IRQs, not all system interrupts.
Each row totals all CPUs for one IRQ. CPU lists currently active processors; `+N` means more do not fit, but the totals still include them.

| Page / Metric | Observation |
| --- | --- |
| HardIRQ `COUNT` / `intr/s` | Cumulative interrupts / interrupt-handler rate |
| SoftIRQ NET_RX / NET_TX | Softirq invocations, not packets |
| softnet processed | Receive-processing count, not wire PPS |
| softnet dropped | Receive-backlog enqueue drops |
| time squeeze | Exhausted receive budget, not drop count |
| flow limit | RPS flow-limit drops; do not add them again to total dropped |

Interrupt coalescing and NAPI batching allow multiple packets per IRQ. Continued polling needs no new IRQ for each batch.
Softnet and softirq are per CPU and cannot be attributed directly to one interface.
XDP_DROP/TX/REDIRECT can bypass later accounting; differences between IRQ, softnet and interface counts do not prove loss.
