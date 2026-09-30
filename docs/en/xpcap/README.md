# xpcap

Observe AF_XDP (XSK) and conventional interface (PCAP) traffic together. Optionally capture XDP program entry, exit and redirect stages. The default captures XSK and PCAP; it does not replace an attached XDP program.

## Installation

Example for x86_64; see [xpcap-release](https://github.com/calcky/tools/releases/tag/xpcap-release) for other architectures.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xpcap-release/xpcap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 xpcap-linux-x86_64 "$HOME/.local/bin/xpcap"
```

## Common Usage

```sh
xpcap -i eth0
xpcap -i any -c 20 tcp and port 443
xpcap -i eth0 -S xdp-in,xdp-out,redirect -q 3 -T 10
xpcap -i eth0 -S pcap -ev -c 10 tcp
xpcap -i eth0 -w trace.pcapng udp and port 9000
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

## Filter Expressions

Arguments after the options form one tcpdump-style filter expression. xpcap
uses the `pktbaffle` classic-BPF subset. The available categories are:

```text
# Hosts and networks
host 192.0.2.1
src host 192.0.2.1
net 192.0.2.0/24
dst net 2001:db8::/32

# Ports and ranges
port 443
tcp dst port 22
udp src port 53
portrange 1024-65535
tcp src portrange 32768-60999

# Protocols
tcp  udp  icmp  icmp6  arp  rarp  igmp  sctp
ah  esp  pim  vrrp  ip  ip6  proto 47

# Link layer, VLAN, MPLS, PPPoE
ether host aa:bb:cc:dd:ee:ff
ether src aa:bb:cc:dd:ee:ff
ether proto 0x0806
vlan 100
mpls 1000
pppoed
pppoes

# Broadcast, multicast, and length
ip broadcast
ip multicast
ip6 multicast
ether broadcast
len > 1400
less 64
greater 1400

# Raw fields and TCP/ICMP constants
ip[9] = 6
tcp[tcpflags] & tcp-syn != 0
tcp[13] & tcp-syn != 0
icmp[icmptype] = icmp-echo
icmp6[icmp6type] = 128
```

Boolean operators are `and`/`&&`, `or`/`||`, and `not`/`!`, with precedence
`not`, then `and`, then `or`. Use parentheses for explicit grouping. `src` and
`dst` qualify `host`, `net`, `port`, and `portrange`:

```sh
xpcap -i eth0 'tcp and (dst port 80 or dst port 443)'
xpcap -i eth0 'src net 192.0.2.0/24 and dst portrange 8000-9000'
xpcap -i eth0 'vlan 100 and tcp[tcpflags] & tcp-syn != 0'
```

TCP flag constants include `tcp-fin`, `tcp-syn`, `tcp-rst`, `tcp-push`,
`tcp-ack`, `tcp-urg`, `tcp-ece`, and `tcp-cwr`; `tcpflags` is the flags
offset. ICMP offsets include `icmptype`, `icmpcode`, `icmp6type`, and
`icmp6code`.

This is not the complete libpcap grammar: `inbound`, `outbound`, and complex
IPv6 extension-header traversal are unavailable. `ether multicast` is not
reliable; use `ip multicast` or `ip6 multicast`. Named-interface PCAP filters
run in the kernel; PCAP filtering for `-i any` runs in userspace. XDP/XSK
filters must fit 128 classic-BPF instructions or startup reports an error.

## Limits

- XDP/XSK stages require Linux 6.6+, BTF and BPF tracing privileges. `-S pcap` only requires `AF_PACKET` and `CAP_NET_RAW`.
- XSK RX means RX-ring acceptance; XSK TX means descriptor dequeue or a generic transmit attempt, not application consumption or physical transmission. The same packet can appear at multiple stages without deduplication.
- PCAP on `-i any` uses Linux cooked (SLL), while XSK/XDP retain Ethernet. Use Wireshark/tshark for mixed-link-type PCAPNG; some tcpdump versions cannot read it.
- PCAP content filtering on `-i any` runs in userspace. Prefer a named interface for high-rate capture; XDP/XSK filters still run in the kernel probe.

[Full manual](https://github.com/calcky/tools/blob/master/xpcap/README.md)
