# xpcap v0.1.0

Initial Linux release with ARMv7, ARM64 and x86_64 static executables.

- Capture XDP entry/exit, redirect, AF_XDP RX/TX and conventional packet-socket traffic, individually or together.
- Apply tcpdump-style filters inside the kernel probes, select directions and queues, and optionally sample observations.
- Print stage-labelled packets and write PCAPNG with per-packet context; report hook coverage and capture losses.

XDP/XSK tracing requires Linux 6.6+, BTF and supported BPF tracing hooks. ARMv7 binaries are provided, but their XDP/XSK hooks depend on kernel trampoline support; the `pcap` stage does not require those hooks. Native/zero-copy AF_XDP traffic and every driver-specific TX path have not been validated on all targets. See the README for per-stage observation limits.
