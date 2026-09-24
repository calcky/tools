# Numerical Monitor Without Trends

Status: Accepted, 2026-09-21.

The user requested removal of trends from every monitor view while work on
one-second CPU overhead continues. Current values, interval rates/deltas,
since-baseline statistics, source health and reset/gap semantics remain useful.

## Decision

- Remove trend graphs, trend columns and history-window labels from Overview,
  direct metric sections, global/interface layer details, Network/Route metrics
  and selected-socket details. Reclaim the space for numerical values and state.
- Remove the `h` shortcut and `:history` command. Keep `t`/`:time` for numerical
  interval and since-baseline projections where supported.
- Keep RX/TX queue sizes and all existing socket traffic, RTT, congestion,
  window and retransmission values as ordinary numerical diagnostics.
- Stop collecting the private selected-socket graph history. Retain selected
  identity, latest observed values, missing/reappearing status, observation time
  and immutable paused display state. Socket rates remain the existing
  consecutive-observation projections from the socket table collector.
- Keep general monitor bounded history and sampling contracts. The numerical
  detail filter still uses past nonzero observations to keep relevant reset
  rows visible. No configuration or counter polling interval changes here.

This supersedes the trend display and selected-socket graph storage portions of
decisions 0013 and 0015. Their identity, visibility, privacy and numerical
diagnostic rules remain applicable.

## Verification

Render tests cover compact and wide terminals, interval/baseline values, source
state, missing sockets, recovery and absence of sparkline glyphs or trend
controls. Full test suites and a real-terminal speed run validate integration.
CPU measurements must use one-second release runs including child processes;
removing graphs alone is not evidence that the at-most-2% target is met.
