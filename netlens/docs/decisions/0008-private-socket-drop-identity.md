# ADR-0008: Keep Socket-Diagnostic Identity Private and Report Only Conservative Deltas

## Status

Superseded by ADR-0009

## Date

2026-07-29

## Context

`NETLINK_SOCK_DIAG` can expose `SK_MEMINFO_DROPS` for IPv4 and IPv6 TCP/UDP sockets. Unlike the existing `/proc` protocol counters, these values can distinguish sockets, but a counter is useful over a capture window only when the start and end samples refer to the same kernel socket.

The available diagnostic identity is kernel-facing data. Publishing a socket cookie, inode, UID, address/port tuple, queue value, or pointer would create a stable correlation handle and would violate ADR-0004's opaque report-local identity contract. Matching by tuple alone would also confuse socket churn with a counter increment.

`SK_MEMINFO_DROPS` is a 32-bit cumulative counter. With only two dumps, neither endpoint order proves that the counter did not wrap: a decrease may be a wrap, reset, or exact identity reuse, while an apparent increase may follow one or more complete wraps. Query failure, interrupted or lossy netlink dumps, malformed data, and sockets that omit `INET_DIAG_SKMEMINFO` also make the per-socket view incomplete. The existing namespace-wide `/proc` counters may observe related drops, but their measurement identity and scope differ from a per-socket diagnostic counter.

Report v3 was already frozen before this provider existed. Its provider, Metric, and Subject ownership vocabularies are strict enums, so adding sock_diag in place would make a nominal v3 report fail an older v3 validator.

## Decision

1. The collector retains only family, protocol, the two-word socket cookie, inode, and optional `SK_MEMINFO_DROPS` value between the start and end snapshots. It does not retain tuple, ifindex, UID, queue state, or another public socket label.
2. A sample is matchable only when its cookie is not `INET_DIAG_NOCOOKIE` and its inode is non-zero. A delta requires exact equality of family, protocol, cookie, and inode at both snapshots. Created, closed, partially reused, and unmatched sockets produce no evidence. This relies on Linux `sock_diag_save_cookie` exposing the socket's 64-bit generated cookie as the two UAPI words; it is a strong in-window identity component, not a cryptographic or eternal non-reuse guarantee.
3. An increasing counter produces the visible positive 32-bit difference with `lower_bound` measurement semantics because complete wraps cannot be excluded. An unchanged counter produces no row, even though a complete wrap is theoretically possible. A decreasing counter produces a reset row with no delta; nwdiag does not assume wrap. Exact simultaneous reuse of every private identity component is not distinguishable from persistence, so this remains an explicit residual limitation rather than a basis for synthetic wrap arithmetic.
4. Missing `INET_DIAG_SKMEMINFO` produces no socket evidence. Query errors, loss signals, dump interruptions, parse errors, and missing extensions are recorded in provider telemetry and runtime capability state. They degrade or disable only `linux.sock_diag.skmeminfo` and Socket coverage; other provider stages continue independently.
5. After delta calculation, private identity is discarded. Each reportable delta receives a fresh random report-local Socket Subject and Metric ID. The Subject and Metric attributes are empty, and the Metric has exactly one `primary` Socket Subject reference. IDs neither encode nor remain stable for a socket across reports.
6. `linux.sock_diag.skmeminfo_drops` is causal ingress/local-input evidence at `socket.receive_queue`, in the `linux.kernel` execution domain, with `skb` measurement domain and Socket scope. Values are limited to the source counter's 32-bit width. A present delta must use `lower_bound`; a reset has no measurement bound.
7. Per-socket diagnostic rows remain separate from one another and from `/proc` UDP receive-buffer or listen-queue aggregates. Findings reference the source Metric IDs. Counts with different Subjects, scopes, domains, providers, or measurement identities are never added into a synthetic total.
8. The provider is current-network-namespace only and read-only. Interface, direction, protocol, address, and port requests that cannot be enforced are reported through effective scope and filter support rather than copied into evidence context.
9. Task 10c introduces report v4 rather than extending report v3 in place. The v3 Schema and fixture remain frozen and reject the new provider. Report v4 inherits the v3 graph contract and adds the sock_diag provider, Metric, and empty opaque Socket Subject profile.

## Consequences

- A report can show that a particular opaque socket Subject accumulated drops during the window without exposing a reusable socket identifier.
- Socket churn and partial cookie/inode reuse fail closed. Exact reuse of all private identity components is not observable from two dumps and remains a documented limitation.
- A visible positive difference is a lower bound, while a decrease is a reset without an invented delta. This may undercount wraps, which is preferable to claiming an unprovable exact count.
- Partial sock_diag failure does not erase valid rows from successful query pairs, but coverage and telemetry show that the view is incomplete.
- Namespace aggregate and per-socket evidence can corroborate the same incident while remaining numerically independent.

## Alternatives Considered

### Publish Cookie, Inode, or Tuple Attributes

This would make reports easier to correlate externally, but it would expose stable kernel or flow identity and expand the privacy surface. Opaque report-local Subjects provide separation without disclosure.

### Match by Five-Tuple

Tuples are reusable and can change meaning across socket churn, NAT, and namespace boundaries. They are neither a sufficient lifetime identity nor necessary for the current diagnostic claim.

### Treat a 32-Bit Difference as Exact Wrap Arithmetic

Two snapshots cannot prove the number of wraps, or distinguish a decrease from identity reuse or reset. Computing wrapping subtraction or marking an apparent increase exact would turn uncertainty into a false precision claim.

### Add Per-Socket and Namespace Counters

The counters have different providers, scopes, domains, and overlap. Addition would double-count related loss and violate the analyzer's measurement-identity rules.
