# ADR-0016: Drill Into Interface Layers

## Status

Accepted

## Date

2026-08-06

## Context

ADR-0012 made an interface open one scrollable page containing TC/Qdisc,
Netdevice Core, Driver/NAPI, NIC/PHY, and HardIRQ summaries followed by every
collected series for every stage. This preserved a vertical navigation model,
but the stage boundaries became difficult to scan. Interfaces with many qdisc,
queue, CPU, or private ethtool series turned the page into a long mixed list,
so an operator could not first compare the state of all five layers and then
focus on one layer.

The existing dashboard already assigns each interface series to one of those
five stages. The TUI can therefore provide a second drilldown without changing
collection, metric ownership, health rules, or history semantics.

## Decision

1. `Enter` on an Overview interface opens an interface-layer menu. It keeps the
   interface header and shows the five stage summaries in the existing stable
   order: TC/Qdisc, Netdevice Core, Driver/NAPI, NIC/PHY, and HardIRQ.
2. `Up`/`Down` and `k`/`j` select a stage in that menu. `Enter` opens a
   scrollable detail containing only the selected interface and stage. The
   detail reuses ADR-0013's meaningful-data default and `a` all-series toggle.
3. `Esc` from a stage detail restores the same interface-layer selection and
   menu scroll position. A second `Esc` restores the same interface selection
   and scroll position in Overview.
4. Layer selection is explicit application state, independent of row offsets.
   This keeps the selection stable when terminal width, metric visibility, or
   refreshed evidence changes the number of rendered rows.
5. Collection, dashboard placement, health assessment, history, and report
   models are unchanged.

This ADR supersedes the interface-detail portions of ADR-0012 Decisions 2, 3,
and 4. Global-layer details and the rest of ADR-0012 remain accepted.

## Alternatives Considered

### Keep One Flat Interface Detail

This avoids another Enter/Esc level, but large per-interface metric sets obscure
the five layer states that guide the investigation.

### Expand and Collapse Stages Inline

This keeps one page, but requires multiple expansion states and makes row
positions unstable as live evidence appears or disappears. A separate detail
has a simpler selection and return contract.

### Use Horizontal Tabs

Tabs make stages directly reachable, but reintroduce the horizontal navigation
model removed by ADR-0012. The visible vertical layer list should remain the
source of navigation truth.

## Consequences

- Operators compare all interface-layer summaries before opening raw metrics.
- Large dynamic qdisc and ethtool sets are isolated to their owning layer.
- Interface investigation gains one explicit Enter/Esc level.
- Returning from detail preserves both Overview and interface-layer context.
