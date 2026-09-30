# xpcap

Observe AF_XDP (XSK) and conventional interface (PCAP) traffic together. Optionally capture XDP program entry, exit and redirect stages. The default captures XSK and PCAP; it does not replace an attached XDP program.

## Build And Run

```sh
make xpcap
sudo bin/xpcap -i eth0
sudo bin/xpcap -i any -c 20 tcp and port 443
sudo bin/xpcap -i eth0 -S xdp-in,xdp-out,redirect -q 3 -T 10
sudo bin/xpcap -i eth0 -S pcap -ev -c 10 tcp
sudo bin/xpcap -i eth0 -w trace.pcapng udp and port 9000
```

`-i` is required and repeatable. `-i any` covers all interfaces and cannot be combined with another `-i`. `-w` writes PCAPNG alongside terminal output. Simple filter expressions can be passed without quotes; quote expressions containing shell metacharacters such as parentheses.

## Common Options

| Option | Purpose |
| --- | --- |
| `-S LIST` | Comma-separated stages: `xsk`, `pcap`, `xdp-in`, `xdp-out`, `redirect`, or `xsk-in/out` and `pcap-in/out` |
| `-Q in\|out\|inout` | Capture direction; default is both. `xdp-out` means program exit, not interface transmit |
| `-q QUEUE` | XDP/XSK queue filter; PCAP cannot report a queue |
| `-c EVENTS` / `-T SECONDS` | Global event count / duration limit |
| `-s BYTES` | Captured bytes per packet; default 2048, maximum 9216 |
| `-m N` | Retain about one in N matching packets per stage |
| `-B PAGES` | Perf buffer pages per CPU; default 256 |
| `-v` | Show IP header details such as TTL, ID, fragmentation flags and checksum field |
| `-e` | Show link header; MAC/VLAN on Ethernet, available SLL fields for PCAP on `any` |

Terminal output separates source (`PCAP`/`XSK`), direction (`IN`/`OUT`) and queue; the protocol summary includes TCP flags, seq/ack, window and options. `-v/-e` affect terminal text only, not saved packet bytes. SLL cannot reconstruct a full source/destination MAC pair for `-i any`.

## Limits

- XDP/XSK stages require Linux 6.6+, BTF and BPF tracing privileges. `-S pcap` only requires `AF_PACKET` and `CAP_NET_RAW`.
- XSK RX means RX-ring acceptance; XSK TX means descriptor dequeue or a generic transmit attempt, not application consumption or physical transmission. The same packet can appear at multiple stages without deduplication.
- PCAP on `-i any` uses Linux cooked (SLL), while XSK/XDP retain Ethernet. Use Wireshark/tshark for mixed-link-type PCAPNG; some tcpdump versions cannot read it.
- PCAP content filtering on `-i any` runs in userspace. Prefer a named interface for high-rate capture; XDP/XSK filters still run in the kernel probe.

[Full manual and build prerequisites](https://github.com/calcky/tools/blob/master/xpcap/README.md)
