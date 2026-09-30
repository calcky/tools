# xpcap

Capture packets at XDP and AF_XDP kernel stages, alongside conventional interface traffic, without replacing the attached XDP program. XDP/XSK stages require Linux 6.6+, kernel BTF, and privileges to load and attach BPF tracing programs. The `pcap` stage only requires Linux packet-socket privileges (`CAP_NET_RAW`).

```sh
make xpcap
sudo bin/xpcap -i eth0
sudo bin/xpcap -i any -c 20
sudo bin/xpcap -i eth0 -i eth1 -w trace.pcapng
sudo bin/xpcap -i eth0 -S xdp-out,redirect,xsk-rx -q 3 -c 100
sudo bin/xpcap -i eth0 udp and src net 192.0.2.0/24 and dst port 9000
sudo bin/xpcap -i eth0 -S pcap -w conventional.pcapng
sudo bin/xpcap -i eth0 -S xsk -Q in -w xsk-rx.pcapng
sudo bin/xpcap -i eth0 -S xsk,pcap -Q out tcp and port 443
sudo bin/xpcap -i eth0 -S pcap -v -e -c 10 tcp
sudo bin/xpcap -i eth0 -S xsk-in,pcap-out host 192.0.2.1 and udp
sudo bin/xpcap -i eth0 -S xsk,pcap -w combined.pcapng udp port 9000
```

`-i` is required and repeatable. `-i any` captures all interfaces and cannot be combined with another `-i`; newly attached interfaces are included by the packet socket, while XDP programs are discovered only at startup. The default stages are XSK receive/transmit and conventional PCAP receive/transmit. Select XDP or redirect explicitly with `-S/--stage`. `-S xsk` selects both AF_XDP directions; `-S pcap` selects conventional receive/transmit packets; combine them as `-S xsk,pcap`. For a specific direction per source use `xsk-in`, `xsk-out`, `pcap-in`, or `pcap-out`. The original `xsk-rx` and `xsk-tx` names remain accepted, as do `xdp-in`, `xdp-out`, and `redirect`.

`-Q in|out|inout` applies a tcpdump-style direction filter (default `inout`). XDP entry, exit and redirect are ingress observations; `xdp-out` is **not** a transmit direction. `-q/--queue` selects an XDP/XSK queue only; packet sockets cannot report a queue. `-c` limits the combined event count, `-T` limits seconds, `-s` sets output snaplen (default 2048, maximum 9216), and `-B/--perf-pages` sets perf-buffer pages per CPU (power of two, default 256). `-m/--sample N` retains about one in N matching observations (default 1): XDP/XSK sample in the probe before copying, while `pcap` samples after the packet socket has received the packet. Sampling is independent at each stage, so a packet need not appear at every stage. `sampled` in the summary counts intentional skips separately from perf lost and output errors. Ctrl+C prints the summary.

`-v` adds IPv4 TOS, TTL, ID, fragment offset/flags, protocol, IP length and header checksum; for IPv6 it adds traffic class, flow label, hop limit, next header and payload length. The checksum is the captured field value, not a validation result; transmit offload can leave it unset. `-e` adds source/destination MAC, EtherType, VLAN ID and priority where an Ethernet header is present. With `-i any`, PCAP uses Linux cooked SLL: `-e` shows packet type and the available link address, not a fabricated source/destination MAC pair. Both flags affect terminal output only; `-w` keeps the original captured bytes.

A trailing tcpdump-style filter expression supports common protocol, host, network, port, range and boolean terms, for example `tcp and port 443`. Simple expressions do not need quotes; use shell quotes around parentheses, as in `'tcp and (port 80 or port 443)'`. The expression is the only packet-content filter. It is compiled to classic BPF: named-interface `pcap` sockets attach it in the kernel, while XDP/XSK probes evaluate it in the kernel before copying packet data into a perf event. For `-i any`, the cooked PCAP filter is evaluated in userspace after receive; this can be costly at high traffic rates, and length-sensitive filters see at most the first 9216 payload bytes. XDP/XSK expressions are limited to 128 classic BPF instructions; an unsupported or oversized expression fails at startup rather than falling back to userspace filtering. This is not a full libpcap grammar. The filter can inspect the readable first segment regardless of `-s`; on multi-buffer XDP packets, `len` tests use the full packet length but byte-offset tests cannot inspect later fragments.

`-w` additionally writes PCAPNG. Named-interface records use Ethernet; with `-i any`, conventional PCAP records use Linux cooked (SLL), while XSK/XDP records retain Ethernet. PCAP-only `any` files are readable by tcpdump; some tcpdump versions reject files containing both cooked and Ethernet records, so use Wireshark/tshark or capture the stages separately for those files. Terminal rows use a tcpdump-like packet summary with separate uppercase source and direction columns, and a queue column (`q-` for PCAP). TCP rows show flags, absolute seq/ack numbers (like `tcpdump -S`), window, common options and TCP payload length. UDP `length` is the UDP payload length; ICMP `length` is the ICMP message length. Non-IP rows use frame length. Truncated packets show the captured frame length and omit unavailable header fields. Terminal rows omit the interface name for one named interface, and show it for multiple interfaces or `any`:

```text
13:21:17.150802342 oam          q-   PCAP     OUT IP 10.0.7.41.22 > 10.0.7.1.59986: Flags [P.], seq 825408377:825408461, ack 3055846085, win 122, options [nop,nop,TS val 2654234192 ecr 1783253350], length 84
13:21:17.150925742 oam          q-   PCAP     IN  IP 10.0.7.1.59986 > 10.0.7.41.22: Flags [.], ack 825408461, win 63, options [nop,nop,TS val 1783253420 ecr 2654234192], length 0
```

PCAPNG comments retain the existing stage labels (`xsk-in`, `pcap-out`, etc.), direction, XSK TX path, queue, action/result, and any known map information. `xdp-in/out` copy across XDP fragments up to `-s` and label such packets `multi-buffer`; `partial` means fewer bytes were captured than the known packet length, or an XSK TX descriptor indicates a continuing chain. Redirect and XSK RX still copy only the first readable segment; XSK TX captures one descriptor, not an entire multi-descriptor chain. No packet identity is inferred across stages.

| Stage | What is observed | What is **not** implied |
| --- | --- | --- |
| `xdp-in` / `xdp-out` | Entry/exit of an attached XDP BPF program and its return action | That a `TX` or `REDIRECT` packet physically left the NIC |
| `redirect` | Entry and result of `xdp_do_redirect` or `xdp_do_redirect_frame`, plus map ID/index and destination from tracepoints | Successful transmission at the target device |
| `xsk-rx` | Successful native or generic AF_XDP RX-ring acceptance | That userspace consumed the descriptor |
| `xsk-tx` | Generic skb build (or direct-xmit attempt when that hook is inlined), or zero-copy driver descriptor dequeue | Physical transmit completion |
| `pcap` | Conventional receive/transmit packets from an `AF_PACKET` socket, marked `direction=rx/tx` | Visibility into XDP drops or AF_XDP-exclusive paths |

The conventional stage uses Linux `AF_PACKET`, the same kernel capture path commonly used by libpcap/tcpdump; it does not link libpcap. Capturing it together with XDP/XSK stages may produce multiple records of the same packet; stage comments distinguish them and xpcap does not deduplicate. The generic TX hook and individual zero-copy driver paths depend on kernel symbols and driver implementation. When `xsk_build_skb` is absent from kernel BTF, the generic fallback observes calls into `__dev_direct_xmit` from an AF_XDP sender; this is an attempt, and the driver may still reject the packet. Missing hooks are reported independently; zero records do not prove zero traffic. `xdp-in/out` require an attached XDP program with function BTF; xpcap resolves its full function name from BTF, including names longer than the kernel's 15-character program name. A missing XDP program is reported; xpcap does not load a replacement PASS program. Only named interfaces (or all interfaces with `any`) and their bound XSKs are captured. The destination of a redirect is not followed automatically.

The startup coverage table reports each requested stage as `ready`, `degraded`, or `unavailable` and lists attached paths. `Ready` means the requested hooks attached, not that traffic will traverse them; `degraded` means some interfaces or hook paths are missing. The summary includes records per stage, filtered and sampled observations, read/output failures, partial captures, and omitted descriptors from batches larger than 64. Perf-buffer lost events cannot be attributed to a stage and are reported globally. Packet-socket kernel drops are reported separately. Filters on non-IP packets exclude those packets; IPv6 extension parsing is bounded. Timestamp conversion uses the monotonic-to-wall-clock offset measured at startup.

## Kernel configuration

For the XDP, redirect and XSK eBPF stages on Linux 6.6+, check these kernel options:

```text
CONFIG_NET=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_PERF_EVENTS=y
CONFIG_BPF_EVENTS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
```

`CONFIG_BPF_EVENTS` enables the tracing helpers and tracepoint attachment; in Linux 6.6 its Kconfig dependencies require `CONFIG_KPROBE_EVENTS=y` or `CONFIG_UPROBE_EVENTS=y`, although xpcap does not attach kprobes or uprobes. `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` is architecture-provided and is needed for fentry/fexit attachment to ftrace-managed kernel functions. In particular, a compiled ARMv7 binary does not imply that the target kernel supports these hooks. The runtime must also expose `/sys/kernel/btf/vmlinux`, support BPF trampolines for the selected targets, and grant privileges to load tracing programs and open perf events.

The XSK stages additionally need `CONFIG_XDP_SOCKETS=y` and an AF_XDP socket bound to the selected interface. The conventional `--stage pcap` path instead needs `CONFIG_PACKET=y` (or `m` with `af_packet` loaded) and `CAP_NET_RAW`; it does not need BTF or the tracing options above. `xdp-in`/`xdp-out` require an XDP program already attached to the interface. A driver or kernel function may still be unavailable even with these options enabled; xpcap reports each unavailable hook at startup.

Check the running kernel with `zcat /proc/config.gz | grep -E '^CONFIG_(NET|BPF_SYSCALL|BPF_JIT|PERF_EVENTS|BPF_EVENTS|DEBUG_INFO_BTF|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|DYNAMIC_FTRACE_WITH_DIRECT_CALLS|XDP_SOCKETS|PACKET)='` and `test -r /sys/kernel/btf/vmlinux`. If `/proc/config.gz` is absent, inspect `/boot/config-$(uname -r)` instead.

Build prerequisites: Rust/Cargo, Clang with BPF target, C headers for libbpf, libelf, zlib and zstd, and pkg-config. `make xpcap` and `make check-xpcap` locate native static libraries through `pkg-config libelf`; override `XPCAP_LIB_DIR` if needed. `make install-xpcap` installs `bin/xpcap`. The CI workflow builds static musl binaries for ARMv7, ARM64 and x86_64; each embeds the same CO-RE BPF object.
