# ADR-0015: Keep Per-Socket TCP Detail Transient and Identity-Bound

## Status

Accepted

## Date

2026-08-06

## Context

The on-demand INET socket table from ADR-0014 identifies which TCP connection
owns traffic and queue activity, but it does not expose the congestion,
latency, recovery, window, and memory state needed to explain a specific
connection. The table is sorted by recent activity on every sample, so a row
number or tuple is not a stable connection identity. Socket tuples, inode
values, cookies, PIDs, and process names also remain private TUI data.

Linux exposes the required diagnostics through the append-only `tcp_info`
UAPI returned by `INET_DIAG_INFO`. The Linux 4.14 192-byte prefix includes
congestion window, RTT, retransmission, pacing, delivery, receive autotuning,
and buffer-limited timing fields. It does not include the peer-advertised
receive window that limits local sending (`snd_wnd`) or the local advertised
receive window (`rcv_wnd`), which are newer suffix fields. `rcv_space` and
`rcv_ssthresh` are related receive
autotuning values, not substitutes for the current advertised receive window.

## Decision

1. `Enter` on the selected socket-table row opens a third-level socket detail
   page. Selection follows the private family/protocol/cookie/inode identity,
   never the activity-sorted row number or tuple. `Esc` restores the table
   selection and scroll position.
2. The existing on-demand socket-table worker remains alive while either the
   table or detail page is open. No second netlink session or external `ss`
   process is introduced.
3. Parse the stable Linux 4.14 `tcp_info` prefix and only parse newer append-only
   fields when the attribute contains each complete field. Unsupported fields
   render as `n/a`; socket buffers and `rcv_space` must not be labelled as TCP
   advertised windows. A zero delivery-rate field is no sample, not an observed
   zero rate. LISTEN and TIME_WAIT do not receive connection-only TCP
   diagnostics; LISTEN instead exposes accept-queue pending/limit connection
   counts.
4. Keep one bounded history for the currently opened socket detail. It begins
   when that detail page is opened, records only observations with the same
   private identity, and inserts a gap when the socket is absent or its query is
   unavailable. Each trend series has 120 private buckets, independent of the
   general monitor's 16-bucket series; compaction starts only after those 120
   slots fill. A compacted trend point retains observed extrema and a graph peak
   while preserving gaps. Closing the detail discards the history; leaving the
   Socket layer also cancels and joins the worker.
5. Lead the page with a connection summary for RX application rate, TX
   acknowledged-application rate, latency/retransmission, and send ceilings.
   Detailed traffic labels distinguish all TCP segments (`all-seg`), received
   application bytes (`app`), and acknowledged sent application bytes
   (`acked-app`); none is presented as a wire-byte count. Send ceilings are
   compared only when both `snd_cwnd` and `snd_wnd` are available.
6. Key trends include RTT, congestion window, RX/TX application bit rate,
   RX/TX queue, retransmission rate, delivery rate, and advertised windows when
   available. RTT and window gauges scale across the selected visible bucket
   range, while rates and queue occupancy retain a zero baseline. The default
   view suppresses unavailable and zero-only diagnostic noise; `a` exposes all
   zero, `n/a`, and raw-detail fields. A paused UI freezes the displayed detail
   but collection and its bounded history continue; resume advances to the
   latest sample.
7. Endpoints, owner identity, and socket identity stay out of general monitor
   metrics/history, report DTOs, logs, and ordinary `Debug` output. All detail
   collections and diagnostic text retain hard cardinality and length limits.
8. If the latest query does not contain the selected identity, retain only
   explicitly last-observed identity context and gap-aware history. Do not
   present the previous sample's rates, RTT, windows, or queue state as current.

## Alternatives Considered

### Track the Selected Row Number

Activity sorting can move a different connection into the same row on every
sample. This would silently show diagnostics for the wrong socket.

### Execute `ss -tiem`

This would duplicate the existing netlink collection, add an OpenWrt runtime
dependency and text-format compatibility surface, and weaken cancellation and
privacy bounds.

### Store History for Every Socket

Retaining time series for thousands of transient connections has poor and
unpredictable memory behavior on embedded systems. Most of that sensitive data
would never be viewed.

### Treat `rcv_space` as the Receive Window

The fields have different kernel meanings. Relabelling the autotuning estimate
as the current advertised window would make old kernels appear to provide data
that they do not expose.

## Consequences

- An operator can follow one connection through table reordering and inspect
  congestion, latency, recovery, window, queue, and memory state.
- Linux 4.14 remains supported with explicit unavailable modern window fields.
- Trend coverage is honest and bounded to 120 buckets per private series, but
  starts when the detail is opened rather than at process start because
  per-socket collection is intentionally on demand.
- The feature does not expand the public report or general monitor identity
  contracts.
