# cttop v0.1.0

Initial release of the Linux conntrack session monitor.

- Live connection tracking with snapshots and lifecycle events, original/NAT views,
  and grouping by IP, port, protocol, zone or conntrack mark.
- Nested group drilldown, one-connection-per-row view, search, filters and terminal help.
- Directional bandwidth, cumulative packet/byte counters, state distributions and
  diagnostic hints, with explicit unavailable/partial data indicators.
- Static conntrack text snapshots: `cttop -f connections.txt` or `conntrack -L | cttop -f`.
  Offline viewing needs no root and preserves grouping, search and NAT inspection.
- Adaptive terminal layout, monochrome support and plain reports.

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
