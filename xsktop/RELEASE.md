AF_XDP socket monitoring with live per-queue RX/TX packet and byte rates,
socket error and empty-ring event rates, UMEM/ring configuration, and
best-effort process ownership. Use `-c N` for N text samples without a TTY.

Requires Linux 6.6 or newer, `CONFIG_XDP_SOCKETS_DIAG`, kernel BTF, and
fentry/fexit BPF support. Root or suitable BPF/tracing capabilities are needed.
Generic/copy and native/copy were tested on an isolated veth; hardware
zero-copy and multi-buffer paths have not been validated.
