# ADR-0017: Keep Bounded Interface Operational Summaries

## Status

Accepted

## Date

2026-08-06

## Context

The four-row interface summary established by ADR-0012 kept hosts with many
interfaces easy to scan, but it exposed only identity, RX, TX, and one health
cause. Operators still had to open a layer detail to answer basic operational
questions such as which driver is bound, whether RX/TX queue and ring sizing is
asymmetric, or whether flow control and segmentation offloads are enabled.

Those values are useful orientation, not packet-loss proof. Linux exposes them
through independent sysfs files and ethtool commands, and any individual value
may be missing, malformed, unsupported, or temporarily unreadable.

## Decision

1. Each Overview interface uses exactly six rows: identity/link/health,
   driver/duplex/queue/ring configuration, flow-control/offload state, RX, TX,
   and the primary `WHY` cause. The row count remains fixed and interface order
   remains physical first, virtual second, then ifindex.
2. The interface-layer menu from ADR-0016 remains the investigation path.
   Overview configuration rows are orientation only; `Enter` still opens the
   TC/Qdisc, Netdevice Core, Driver/NAPI, NIC/PHY, and HardIRQ summaries and a
   second `Enter` opens one layer's complete collected series.
3. Driver identity comes only from the basename of the
   `/sys/class/net/<interface>/device/driver` symlink. Queue counts include only
   exact `queues/rx-N` and `queues/tx-N` entries. TX queue length is a bounded
   unsigned sysfs value. Missing or malformed optional values remain missing
   and do not create a collection error.
4. Ordinary `ethtool <interface>` remains the required base settings query.
   After it yields usable settings, bounded `-g`, `-a`, `-k`, and `-c` queries
   may add current and maximum ring lengths, RX/TX flow control,
   TSO/LRO/GRO/GSO state, and common adaptive/usecs/frames coalescing values.
   Each optional query fails independently and cannot erase or downgrade the
   base settings result.
5. Static ethtool settings are queried at startup and refresh approximately
   every 30 seconds. Their cached values remain visible between refreshes;
   cache hits retain the completion time and collection duration of the NIC
   collection cycle that performed the actual static refresh. They do not
   advance the settings attempt time or replace its reported cost. Dynamic
   private `ethtool -S` statistics continue on every main sampling interval.
   Newly observed hardware interfaces are refreshed immediately under their
   complete interface and ifindex identity. The defensive `refresh_pending`
   status yields Partial coverage and is not an interface-unavailable result.
6. These configuration values remain opaque current state. Their values do not
   by themselves produce WARN or CRIT, and their names do not grant packet,
   drop, error, or causal semantics. Private `ethtool -S` values remain
   separate.

This ADR supersedes the four-row Overview density in ADR-0012. It does not
change ADR-0016's layer navigation, history semantics, health evaluation, or
the stable interface ordering contract.

## Alternatives Considered

### Keep Four Rows And Put Everything In Layer Details

This preserves maximum density, but hides basic interface configuration needed
to choose which interface and layer to inspect. The additional two fixed rows
keep the cost bounded while avoiding a blind first drilldown.

### Expand Configuration Inline On Demand

Inline expansion would reduce the default row count, but it would make row
positions and interface visibility depend on another UI state. A fixed summary
keeps scrolling and selection deterministic.

### Treat Optional Query Failure As A Partial Base Result

This would make coverage look worse on devices that support ordinary ethtool
settings but not one optional operation. Independent optional absence is more
accurate and retains the usable base evidence.

## Consequences

- Overview shows more operational context while retaining a fixed per-interface
  bound.
- Hosts with many interfaces require more vertical scrolling than the four-row
  design.
- Unsupported optional ethtool operations appear as missing fields rather than
  masking supported settings.
- Firmware, channel, and FEC configuration remain future R7 work.
