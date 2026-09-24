# ADR-0014: Use an On-Demand Transient INET Socket Table

## Status

Accepted

## Date

2026-08-05

## Context

The Socket / Application Overview block reports namespace-wide protocol and
memory state. Those aggregates cannot show which socket owns a queue, which
process holds it, or which active TCP socket is carrying traffic. The TUI needs
a second-level operational view without enabling BPF or expanding the public
report identity model to include reusable tuples, inode values, or process
identity.

Linux 4.14 provides `NETLINK_SOCK_DIAG` for IPv4/IPv6 TCP and UDP inventory.
The base diagnostic message exposes tuple, state, queues, UID, inode, and a
private socket cookie. `INET_DIAG_INFO` adds versioned TCP information, while
`INET_DIAG_SKMEMINFO` adds memory state and the broad `sk_drops` source counter.
UDP has no equivalent per-socket cumulative packet and byte accounting.

## Decision

1. `Enter` from Socket / Application detail opens a current-network-namespace
   INET socket table. Its collector exists only while that page is open; leaving
   the page cancels netlink and process scans and joins the worker.
2. Use native `NETLINK_SOCK_DIAG` rather than executing `ss` or parsing
   `/proc/net/tcp*`. Request the Linux 4.14-compatible stable prefixes of
   `INET_DIAG_INFO` and `INET_DIAG_SKMEMINFO`. Collect IPv4/IPv6 TCP and UDP as
   four independently reported queries.
3. Retain at most 4096 rows per query while draining the complete netlink dump
   and recording the actual observed count. Retain at most 4096 rows in the
   rendered table. Any query, parser, permission, loss, or capacity failure is
   visible as partial or failed coverage rather than a complete empty table.
4. Match adjacent TCP samples only by the private family/protocol/cookie/inode
   identity. A first sample, socket churn, missing identity, counter decrease,
   or collection gap produces no rate. Each protocol/family query records its
   own completion time before process-owner scanning, so scan cost does not
   distort the rate interval.
5. TCP RX uses received application bytes and all inbound TCP segments. TCP TX
   uses acknowledged application bytes and all outbound TCP segments. Segment
   counts are transport-level rather than L2 packet counts, and byte rates are
   not wire throughput. UDP and TCP listeners expose no per-socket traffic
   totals or rates. Queues remain gauges; listener RX/TX queues mean pending/max
   backlog. `SK_MEMINFO_DROPS` remains a source-defined mixed-cause counter.
6. Map inode to PID and command by a bounded, cancellable scan of visible
   `/proc/<pid>/fd` entries. Permission failures and owner/process/FD limits make
   the process mapping partial without discarding socket data.
7. Tuple, UID, inode/cookie, PID, and process name are transient TUI data. They
   must not enter general monitor history, report DTOs, logs, or ordinary
   `Debug` output. Debug implementations redact endpoint and owner identity.

## Alternatives Considered

### Execute `ss`

This reduces parser code, but adds an external runtime dependency, unstable
text/JSON compatibility across embedded distributions, process overhead, and
weaker cancellation and size control.

### Parse `/proc/net/tcp*` and `/proc/net/udp*`

These files provide inventory on many kernels but do not provide the required
stable TCP byte/data-segment counters. Combining them with other files would
still require private identity matching and would create more race windows.

### Derive Traffic from Queue Changes

Queue occupancy can rise or fall because applications and the network operate
concurrently. Its delta is neither packet rate nor bandwidth, so unavailable
traffic remains `n/a`.

### Collect the Table Continuously

Always-on tuple and process scans add recurring overhead and retain sensitive
operational data even when no operator is viewing it. The detail page owns the
collector lifetime instead.

## Consequences

- Operators can move from aggregate Socket health to one-row-per-socket state
  and see RX/TX TCP activity, totals, queues, drops, and process ownership.
- UDP traffic accounting and unsupported TCP states remain explicitly
  unavailable instead of appearing as zero.
- Large hosts and permission-restricted systems remain usable with visible
  partial coverage and bounded memory, process, FD, and render work.
- The table is an operational TUI surface, not a new report or history contract.
