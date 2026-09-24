# ADR-0013: Hide Zero-Only Numeric Metrics in Details

## Status

Accepted

## Date

2026-08-03

## Context

ADR-0012 made every Fresh or Stale value visible in the default detail view,
including numeric zero. A single interface can have many qdisc, CPU, queue, and
driver-private series. Rows such as per-qdisc drops and overlimits commonly stay
at zero, so showing every one obscures active traffic and anomalies.

Zero remains a valid observation. It must continue to participate in health,
coverage, interface inventory, history, and the complete detail view. The TUI
only needs a quieter default projection; collection must not discard the value.
A history-capable metric that was nonzero earlier in this process should also
remain visible after returning to zero so an observed anomaly does not
disappear.

## Decision

1. Enter-opened layer and interface details default to meaningful data. A
   numeric Counter or Gauge is meaningful when its Fresh or Stale current value,
   interval projection, since-baseline projection, or any all-session history
   bucket is nonzero.
2. `linux.nic.raw_private` is an information-only Gauge whose interval and
   history are intentionally unavailable because its vendor-defined semantics
   are opaque. Its visibility therefore uses only its Fresh or Stale current
   value; zero is hidden and a nonzero value is shown.
3. A numeric series that has remained zero across its available projections is
   hidden from the default dynamic rows and fixed summaries. The visibility
   decision always uses all-session history and does not change with the
   recent/all-session trend display control.
4. Fresh and Stale State series remain visible regardless of their text. An
   opaque state value such as `"0"` is not interpreted as a numeric measurement.
5. Unavailable series and empty fixed slots remain hidden by default. Pressing
   `a` continues to expose every series instantiated in the current snapshot,
   including zero and Unavailable rows, plus fixed summary placeholders.
6. Detail visibility is independent from interface observation and inventory.
   A successfully observed zero does not make an interface disappear.

## Alternatives Considered

### Treat Every Observed Zero as Display Data

This preserves a literal Fresh/Stale interpretation, but repeats large groups
of inactive qdisc, CPU, and driver counters and hides useful rows in noise.

### Drop Zero Values During Collection

This reduces snapshot size, but loses evidence, breaks complete `a` mode, and
conflates collection semantics with one presentation choice.

### Use Only the Current Value

This is simpler, but a reset or a Gauge returning to zero would erase an anomaly
that the process already observed. Session history must keep such a row visible.

### Add a General Per-Metric Zero-Visibility Policy

This could support more presentation variants, but the only current exception is
already defined by the raw-private metric's no-projection contract. A broader
catalog policy would add configuration without another required behavior.

## Consequences

- Default details emphasize active or previously active numeric metrics.
- Operators can still inspect every zero and unavailable value with `a`.
- Visibility remains stable when switching the trend window because it considers
  the complete process history.
- Opaque private NIC statistics are current-only and may disappear when their
  current value returns to zero; `a` still exposes them.
- State, health, coverage, and interface inventory semantics are unchanged.

This ADR supersedes only ADR-0012 Decision 3's statement that numeric zero is
visible by default. All other ADR-0012 decisions remain accepted.
