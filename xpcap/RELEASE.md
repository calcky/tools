# xpcap v0.1.2

Linux release with ARMv7, ARM64 and x86_64 static executables.

- Capture AF_XDP RX/TX and conventional packet-socket traffic by default; opt in to XDP entry/exit and redirect stages.
- Capture one or multiple interfaces, or use `-i any` for all interfaces. Terminal output separates interface, queue, stage and direction.
- Print tcpdump-style TCP/UDP/ICMP summaries. `-v` adds IP header fields; `-e` adds Ethernet/VLAN or cooked SLL details.
- Use short capture options, tcpdump-style packet filters, and optional PCAPNG output with per-packet stage context.
- Name XDP program hooks `xdp-entry` and `xdp-exit`; show the XDP action at exit without implying interface egress.

XDP/XSK tracing requires Linux 6.6+, BTF and supported BPF tracing hooks. ARMv7 binaries are provided, but their XDP/XSK hooks depend on kernel trampoline support; the `pcap` stage does not require those hooks. With `-i any`, conventional packets use Linux cooked (SLL) format and the content filter runs in userspace; some tcpdump versions cannot read PCAPNG files mixing SLL and Ethernet interfaces. See the README for per-stage observation limits.
