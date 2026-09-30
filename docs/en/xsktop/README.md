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
- `UMEM fill empty` and `TX empty` are events, not RX/TX errors. Fill-ring events may be shared by sockets using the same UMEM. Traffic attribution is hidden when multiple XSKs share an interface and queue; after one closes, the first interval may still include its traffic.
- Generic/copy and native/copy were tested on veth; hardware zero-copy and multi-buffer packets remain unvalidated.

[Full manual](https://github.com/calcky/tools/blob/master/xsktop/README.md)
