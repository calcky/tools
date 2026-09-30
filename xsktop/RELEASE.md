AF_XDP socket monitoring with live per-queue RX/TX packet and byte rates,
separate RX/TX error rates, UMEM/ring configuration, and best-effort process
ownership. Sockets are grouped by interface and queue; packet and bandwidth
rates stay visible together at supported terminal widths. Use `-c N` for N
text samples without a TTY.

Shared interface/queue traffic cannot be attributed to individual sockets.
The first sample after one shared socket closes may still contain its traffic;
see the README for other counter and attribution limits.

Requires Linux 6.6 or newer, `CONFIG_XDP_SOCKETS_DIAG`, kernel BTF, and
fentry/fexit BPF support. Root or suitable BPF/tracing capabilities are needed.
Generic/copy and native/copy were tested on an isolated veth; hardware
zero-copy and multi-buffer paths have not been validated.
