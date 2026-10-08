## netping v0.1.1

- Add `-j N` for 1-256 independent sessions to one target: persistent TCP
  connections, distinct UDP source ports, ICMP Echo IDs, or TCP connect schedules.
- Apply rate, interval and count per session; keep a common sending duration.
- Include session IDs in text replies, aggregate performance reports and RTT
  distributions, and print a final table of each session's results.
- Add window session details: press `s` to switch the selected protocol between
  totals and sessions; pause and reset still apply to all sessions.
- Isolate failures, timeouts, reordered, duplicate and late replies per session;
  allocate distinct raw ICMP Echo IDs and preserve single-session behavior.
- Update Chinese and English documentation and add multi-session regression tests.

Static Linux executables are provided for ARMv7 (`arm`), ARM64 (`arm64`), and
x86_64. Download the matching executable and install it as `netping`; no archive
extraction is needed. `SHA256SUMS` contains the asset checksums.

TCP and UDP echo require a target running `netping -s`. ICMP uses Linux ping
sockets or requires CAP_NET_RAW/root for the raw socket fallback.
