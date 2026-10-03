AF_XDP socket monitoring with live per-queue RX/TX packet and byte rates,
separate RX/TX error rates, UMEM/ring configuration, and best-effort process
ownership. Native RX counts every successful redirect with one fexit probe
and direct CO-RE field reads. Per-CPU hash counters reduce receive-path
overhead while preserving exact queue counts. Generic RX, TX, and socket
error/event counters remain unsampled.

Exact observation has a measurable throughput cost under saturation. On an
isolated X710 10 Gb/s link, 64 B native zero-copy RX fell from 14.76 to
5.22 Mpps with xsktop enabled; 512 B copy TX fell by about 33%. These are
workload-specific results, not per-probe CPU timings. The bilingual xsktop
documentation includes the 18-case X710 cost matrix.

The interface's XDP attachment mode (`skb`, `drv`, `hw`, `multi`, or `none`)
appears alongside the socket's `copy`/`zc` mode.
XDP appears after the interface in the wide live table and text samples,
and remains visible in the details pane on narrow terminals.

The live details view separates errors, events, and configuration.
Click a Q, rate, or error column header to sort; click again to reverse.
Metric sorts rank interfaces by their aggregate available rate, then queues
within each interface. Use `s` to change sort columns without a mouse, or
`-c N` for N text samples without a TTY.

Shared interface/queue traffic cannot be attributed to individual sockets.
The first sample after one shared socket closes may still contain its traffic;
see the README for other counter and attribution limits.

Requires Linux 6.6 or newer, `CONFIG_XDP_SOCKETS_DIAG`, kernel BTF, and
fentry/fexit BPF support. Root or suitable BPF/tracing capabilities are needed.
Generic/copy and native/copy were tested on an isolated veth, and native
zero-copy RX was tested on i40e with Linux 6.6.141. Other drivers and
multi-buffer packets have not been validated.
