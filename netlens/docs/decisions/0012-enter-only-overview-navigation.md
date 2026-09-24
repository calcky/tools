# ADR-0012: Use Enter-Only Detail Navigation From Overview

## Status

Accepted; numeric-zero visibility is superseded by ADR-0013, interface-layer
detail navigation is superseded by ADR-0016, and four-row interface density is
superseded by ADR-0017

## Date

2026-07-31

## Context

ADR-0011 established the counter-only TUI and a fixed horizontal order across
Overview, Socket, Netfilter, TC, Netdevice, NIC, SoftIRQ, HardIRQ, and
Providers. Number keys, horizontal arrows, Tab, and next/previous commands made
each section directly reachable, but they split normal navigation between a
section carousel and the vertically scrollable Overview.

The interface-centric Overview now carries the operator's primary path through
the network stack. It already keeps the global protocol-stack state above
compact, stable interface summaries, with physical interfaces before virtual
interfaces. A separate horizontal section model makes it harder to understand
which item is selected, scales poorly when many interfaces are present, and
requires controls that do not match the visible vertical structure.

Global blocks and interfaces need different detail contents without different
navigation rules. A global block must expose all of that block's RX, TX, and key
series. An interface must expose its TC/Qdisc, Netdevice Core, Driver/NAPI,
NIC/PHY, and HardIRQ stages without expanding every interface in Overview.

## Decision

1. Overview is the normal interactive navigation root. Its selection order is
   Socket/Application, Transport, Network/Route, Netfilter/Conntrack, SoftIRQ,
   physical interfaces, and virtual interfaces. Interface groups retain their
   stable ifindex order.
2. `Up`/`Down` and `k`/`j` move the Overview selection vertically. In a detail
   view, the same keys scroll its rows.
3. `Enter` opens the selected item. A global layer opens a scrollable rendering
   of that exact Overview block's RX, TX, and key series. An interface opens the
   existing scrollable TC/Qdisc, Netdevice Core, Driver/NAPI, NIC/PHY, and
   HardIRQ detail. Both default to Fresh and Stale metric values, including
   numeric zero, while hiding Unavailable rows and empty fixed-slot
   placeholders. `a` exposes all series instantiated in the current snapshot
   plus fixed summary placeholders; it does not synthesize uninstantiated
   catalog metrics. The selected mode persists across opened Overview items.
4. `Esc` returns from either detail kind to Overview and restores the same
   selection and scroll position. Interface identity reconciliation continues
   to use the complete name-plus-ifindex identity and the previous stable
   position when an interface disappears.
5. Left/Right, Tab/Shift+Tab, and number keys do not navigate. `:next`, `:prev`,
   and `:previous` are removed because there is no normal section carousel to
   advance.
6. Named direct entry remains available for operators and startup automation.
   Commands such as `:softirq` and `:section softirq`, as well as CLI
   `--section`, open the requested section without reintroducing horizontal
   navigation. Other command-mode, pause, history, time-view, scrolling, and
   quit controls are unchanged.

This ADR supersedes only the fixed horizontal section-navigation portion of
ADR-0011 Decision 5. ADR-0011's counter-only boundary, default TUI entry point,
sampling and history model, terminal lifecycle, and all other decisions remain
accepted. Its support for named `:` section selection is also preserved.

## Alternatives Considered

### Keep Horizontal Section Switching Alongside Overview Selection

This retains fast cycling between legacy views, but leaves two competing
navigation axes and an overloaded set of arrow and Tab controls. The visible
Overview hierarchy should define the normal interaction instead.

### Open Details Only for Interfaces

This keeps global blocks permanently compact, but prevents an operator from
inspecting their complete series through the primary Overview workflow. Global
and interface items should obey the same Enter/Esc contract.

### Expand Every Interface Stage Inline

This avoids a detail page, but repeats five stage groups for every interface
and makes the Overview unusable on hosts with many interfaces. Four-row
interface summaries keep scanning bounded while Enter provides the full data.

### Remove Named Direct Section Entry

This would make Overview the only possible route, but would also remove useful
startup targeting and command-mode access to views such as Providers. Direct
names can coexist with one normal interactive navigation model.

## Consequences

- Operators can scan one stable vertical Overview and use the same Enter/Esc
  interaction for global layers and interfaces.
- Detail pages can show complete data without increasing the number of rows per
  interface in Overview.
- Existing muscle memory for horizontal arrows, Tab, number keys, and
  next/previous commands no longer changes views; named section commands are
  the explicit direct-entry replacement.
- Returning from detail preserves investigation context, including Overview
  selection and scroll position.
- Providers and legacy section-oriented views remain directly accessible by
  `--section` or named command even though they are not part of the Overview
  selection sequence.
