Initial release of flowgen, a Linux TCP/UDP session-load generator with a paired server.

The v0.1.0 build stopped before publication because the ARM integration-test
environment could not launch emulated child processes. This release registers
QEMU interpreters so the complete test suite can run on all three targets.

- Fixed session count with paced warmup, or continuous session replacement at a configured rate.
- Per-session request pacing and equal-length responses, with multi-worker and multi-source-IP support.
- RTT, jitter, timeout, duplicate, late and reordered response accounting.
- Binary event recordings and offline analysis via `flowgen -R DIR`, including latency percentiles, per-session statistics and CSV reports.
- Bordered terminal reports with adaptive side-by-side tables, highlighted latency and anomaly counters, and plain output for redirection or `NO_COLOR`.
- Efficient session scheduling, bounded pending state, reusable buffers and batched UDP I/O.

Download the executable for your Linux architecture: `arm` (ARMv7 hard-float), `arm64`, or `x86_64`. All three are statically linked with musl and are distributed without an archive.

Make the downloaded file executable with `chmod +x flowgen-linux-<arch>`, then run it with `-h` for help. Both client and server use the same executable.

Session capacity depends on available file descriptors, source tuples, kernel limits and memory; flowgen does not change system settings automatically.
