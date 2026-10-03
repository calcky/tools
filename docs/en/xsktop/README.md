# xsktop

Monitor AF_XDP sockets in the current network namespace, grouped by interface and queue, with RX/TX rates, errors and process ownership.

## Installation

Get the static ARMv7, ARM64 or x86_64 executable from [xsktop-release](https://github.com/calcky/tools/releases/tag/xsktop-release). For example:

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xsktop-release/xsktop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 xsktop-linux-x86_64 "$HOME/.local/bin/xsktop"
```

## Common Commands

```sh
xsktop                   # live window
xsktop -i eth0           # one interface
xsktop -d 0.5            # refresh every 0.5 seconds
xsktop -c 5 -d 1 > log   # five plain-text samples
```

Use arrow keys or `j/k` to select a socket, click a Q/rate/error column header to sort (click again to reverse), `s` to cycle sort columns, and `q` to quit. Metric sorts rank interfaces by their aggregate rate, then queues within each interface.

`XDP` is the interface's XDP program attachment mode: `skb` (generic), `drv` (native), `hw` (offload), `multi` (multiple modes), or `none`; `?` means the query failed or returned an unknown mode. This is separate from the socket's `XSK` mode (`copy/zc`, indicating zero-copy). The XDP mode always appears in details, appears in the table at terminal widths of at least 100 columns, and is included in text samples.

## Key Options

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Restrict to an interface |
| `-d SEC` | Sampling interval, at least 0.1 seconds |
| `-c N` | Print N samples without requiring a terminal |

## Errors and Events

The detail counters come from the kernel AF_XDP socket diagnostic interface, not NIC hardware statistics:

| Metric | Meaning |
| --- | --- |
| `RX dropped` | Packet could not enter XSK for another RX reason, such as no available UMEM frame or a packet larger than the configured frame; RX-ring-full drops are separate. |
| `RX invalid` | Kernel-reported invalid RX-ring descriptors; not the count of invalid fill-ring entries. |
| `RX ring full` | The XSK RX ring had no free slot. Check whether the application drains it promptly. |
| `TX invalid` | Invalid TX descriptor, such as an invalid UMEM address or length. |
| `UMEM fill empty` | No usable fill-ring entry when the kernel requested an RX buffer. This counts checks, not necessarily one lost packet per increment; sockets sharing a UMEM pool share this counter. |
| `TX empty` | No usable descriptor when the kernel checked the TX ring. This is not a transmit error or packet-loss count. |

`rate/s` is the increase since the previous sample divided by elapsed time; `total` is the cumulative kernel count for that socket (or shared UMEM pool). `-` in `rate/s` means no valid previous sample, not zero. The table's `RX err/s` sums the first three RX errors; `TX err/s` counts only `TX invalid`. Empty-ring events are excluded. These are XSK-side counters, not NIC errors or on-wire loss.

## Notes

- Requires Linux 6.6+, `CONFIG_XDP_SOCKETS_DIAG`, kernel BTF and fentry/fexit BPF support; root or equivalent capabilities are normally needed.
- RX is delivery into an XSK, while TX is dequeue by the kernel. Neither means application consumption or on-wire transmission. Ring figures are capacities, not occupancy.
- Native XDP RX counts every successful redirect into an XSK. Generic XDP RX, TX, and socket error/event counters are also unsampled. At low rates, short intervals can show zero or fluctuate; increase `-d`.
- `UMEM fill empty` and `TX empty` are events, not RX/TX errors. Fill-ring events may be shared by sockets using the same UMEM. Traffic attribution is hidden when multiple XSKs share an interface and queue; after one closes, the first interval may still include its traffic.
- Generic/copy and native/copy were tested on veth, and native zero-copy RX was tested on i40e with Linux 6.6.141. Other drivers and multi-buffer packets remain unvalidated.

## Observation Cost Reference: X710

This measures the throughput effect of exact per-packet observation with `xsktop 0.1.4` on X710. It is not a production forwarding guarantee.

| Item | Hardware and topology |
| --- | --- |
| Host A | Intel i5-8500, X710/i40e `eth10`; OpenWrt 24.10.7, Linux 6.6.141. |
| Host B | Intel i5-13400, X710/i40e `ns1/enp1s0f0np0`; Ubuntu 24.04.1, Linux 6.8.0-41. |
| Link | Host B `ns1/enp1s0f0np0` ↔ 10 Gb/s full duplex ↔ Host A `eth10`. |

Tests used AF_XDP queue 0 and batch 64, with the dataplane on host A CPU4, `xsktop` on CPU3, and the host B generator on CPU4. `xsktop` sampled once per second without packet sampling; each group ran OFF -> ON -> ON -> OFF. RX throughput is the actual XSK receive count from `xdp-bench` divided by 8 seconds (10 seconds for the earlier 64 B run). TX uses the median of generator samples 4-10 from a 12-second run. Six 512/1400 B groups use reruns with simultaneous per-process CPU sampling; other data came from earlier batches and should be compared only within a group.

Every group has measured throughput and an equivalent packet interval. The five groups with clear throughput changes show the interval difference; other rows state why that difference is not useful rather than leaving a missing value. An interval difference is not probe execution time.

| RX mode · size | Throughput OFF -> ON (Mpps) | Equivalent interval OFF -> ON (ns/packet)* | Equivalent interval difference (ns/packet; increase) or limit | Throughput change |
| --- | ---: | ---: | --- | ---: |
| `skb / copy` · 64 B | 0.5524 -> 0.5515 | 1810.3 -> 1813.2 | Not estimable: receiver saturation | -0.16% |
| `skb / copy` · 512 B | 0.5506 -> 0.5513 | 1816.1 -> 1814.0 | Not estimable: receiver saturation | +0.11% |
| `skb / copy` · 1400 B | 0.8803 -> 0.8774 | 1135.9 -> 1139.8 | Not estimable: line rate and drops | -0.34% |
| `drv / copy` · 64 B | 0.5557 -> 0.5545 | 1799.5 -> 1803.4 | Not estimable: receiver saturation | -0.22% |
| `drv / copy` · 512 B | 2.3497 -> 2.3423 | 425.6 -> 426.9 | Not estimable: near line rate | -0.31% |
| `drv / copy` · 1400 B | 0.8803 -> 0.8792 | 1136.0 -> 1137.5 | Not estimable: line rate and drops | -0.13% |
| `drv / zc` · 64 B | 14.7646 -> 5.2181 | 67.7 -> 191.6 | +123.9; +182.95% | -64.66% |
| `drv / zc` · 512 B | 2.3497 -> 2.3477 | 425.6 -> 426.0 | Not estimable: near line rate | -0.09% |
| `drv / zc` · 1400 B | 0.8803 -> 0.8803 | 1135.9 -> 1135.9 | Not estimable: line rate | ~0% |

| TX mode · size | Throughput OFF -> ON (Mpps) | Equivalent interval OFF -> ON (ns/packet)* | Equivalent interval difference (ns/packet; increase) or limit | Throughput change |
| --- | ---: | ---: | --- | ---: |
| `skb / copy` · 64 B | 2.3870 -> 1.4095 | 418.9 -> 709.5 | +290.5; +69.35% | -40.95% |
| `skb / copy` · 512 B | 1.8288 -> 1.2143 | 546.8 -> 823.5 | +276.7; +50.61% | -33.60% |
| `skb / copy` · 1400 B | 0.8796 -> 0.8797 | 1136.9 -> 1136.7 | Not estimable: line rate | +0.01% |
| `drv / copy` · 64 B | 2.3820 -> 1.4042 | 419.8 -> 712.2 | +292.4; +69.64% | -41.05% |
| `drv / copy` · 512 B | 1.8342 -> 1.2252 | 545.2 -> 816.2 | +271.0; +49.70% | -33.20% |
| `drv / copy` · 1400 B | 0.8806 -> 0.8799 | 1135.6 -> 1136.5 | Not estimable: line rate | -0.08% |
| `drv / zc` · 64 B | 14.8754 -> 14.8736 | 67.2 -> 67.2 | Not estimable: line rate | -0.01% |
| `drv / zc` · 512 B | 2.3496 -> 2.3496 | 425.6 -> 425.6 | Not estimable: line rate | ~0% |
| `drv / zc` · 1400 B | 0.8803 -> 0.8803 | 1136.0 -> 1136.0 | Not estimable: line rate | ~0% |

* `ns/packet = 1000 / Mpps` is an equivalent interval per successfully handled packet, not measured eBPF instruction time. The four TX copy differences reflect processing-budget changes under CPU-limited throughput. RX `drv/zc` at 64 B had many NIC drops during ON; its `+123.9 ns/packet` reflects the lower successful RX rate only. Line rate hides spare CPU cost; receiver saturation, full XSK rings, and NIC drops mix processing capacity with packet loss, so an interval difference cannot be attributed to the probe. Throughput change is ON relative to OFF; a small positive value is not evidence that observation helps.

[Full manual](https://github.com/calcky/tools/blob/master/xsktop/README.md)
