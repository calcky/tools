# cttop v0.2.0

Analyze a single conntrack snapshot with `cttop summary` and exit. The live
monitor and interactive static-file view remain unchanged.

- One-shot overview, protocol and TCP-state distributions, top sources,
  destinations, services and marks, plus NAT and unreplied signals.
- Saved packet/byte totals report counter coverage; unavailable data stays `N/A`.
- Live snapshots include kernel occupancy and cumulative failure/drop counters.
  Static files and pipes work without root: `cttop summary -f connections.txt`.
- The report uses two columns on wide terminals and stacks sections on narrow
  terminals. `--summary` remains accepted for compatibility.
- As with any single snapshot, bandwidth, lifecycle rates and observed state age
  cannot be inferred from this report.

## Downloads

Three standalone Linux executables, statically linked with musl:

| Asset | Architecture |
| --- | --- |
| `cttop-linux-arm` | ARMv7, little-endian, hard-float ABI |
| `cttop-linux-arm64` | AArch64 / ARM64 |
| `cttop-linux-x86_64` | x86-64 / AMD64 |

Download the appropriate executable, run `chmod +x` on it, then use `-h` for help.
Live mode requires CAP_NET_ADMIN in the target network namespace. No sysctls or
firewall rules are changed by cttop. Static files cannot provide bandwidth,
lifecycle rates or observed age; these metrics are shown as N/A.
