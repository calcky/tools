# ADR-0009: Keep Generic Socket Drop Accounting Separate From Causal Events

## Status

Accepted

Supersedes ADR-0008's public evidence semantics. ADR-0008's private identity,
delta, reset, and privacy decisions remain in force.

## Date

2026-07-29

## Context

ADR-0008 treated `SK_MEMINFO_DROPS` as causal `socket.receive_queue` evidence
with ingress/local-input direction and an `skb` measurement domain. The field
is actually the current value of the socket's broad `sk_drops` accumulator.

Linux v4.14, v5.4, and v6.8 all export `sk_drops` through this UAPI slot. Its
contributors include receive-queue and protocol-memory rejection, UDP
checksum/filter/copy failures, UDP multicast clone failure, TCP validation and
out-of-order processing, socket input backlog, and TCP listen processing. TCP
may add `max(1, skb->gso_segs)` while other branches add one. A positive delta
therefore proves that a socket-associated source counter increased, but does
not prove one causal Stage, direction/path role, or packet measurement domain.

Report v4 has already frozen the incorrect profile into a strict Schema,
fixture, hash, Rust validator, Finding, and capability Stage. Rewriting that
profile in place would make old and new reports with the same schema version
mean different things.

The source audit and event compatibility matrix are recorded in
`docs/research/socket-drop-kernel-sources.md`.

## Decision

1. Keep report-v1 through report-v4 Schema, fixtures, and hashes unchanged.
   The transitional live v4 producer suppressed non-empty sock-diag Metric,
   Socket Subject, and Finding rows. Its sock-diag `socket.receive_queue` Stage
   coverage was unsupported with no evidence forms; absence was never displayed
   as zero. Report v5 is now the active live contract.
2. Report v5 restores the delta as a context Metric attached to a fresh opaque
   Socket Subject. Cause, Layer, Stage, direction, path role, and measurement
   domain are null. Scope remains Socket, positive deltas remain lower bounds,
   and a source-defined counter unit makes clear that the value is not a packet
   or skb count. The Metric alone does not create a causal Finding.
3. Exact queue attribution comes only from source-specific causal events.
   `udp:udp_fail_queue_rcv_skb` and `sock:sock_rcvqueue_full` are independent
   providers with independent capability, integrity, and failure state.
   `-ENOMEM` and `-ENOBUFS` UDP outcomes remain distinct receive-buffer and
   protocol-memory causes.
4. Socket tracepoint records are host-wide and `broader_only` until a verified
   in-kernel scope filter exists. Ports, addresses, pointers, cookies, inodes,
   UIDs, and other private identity are discarded before the BPF transport;
   event evidence is not joined to a sock-diag Socket Subject. Active report v5
   capability output also omits the process effective UID; v1-v4 files remain
   frozen historical contracts.
5. No stable TCP listen/accept overflow tracepoint is claimed. Existing
   `ListenDrops`/`ListenOverflows` and generic sock-diag context remain
   fallbacks, and their quantities are never added. `SOCKET_BACKLOG` means the
   input skb backlog, not the listen/accept backlog.

## Alternatives Considered

### Rewrite Report v4 In Place

This would preserve the current version number but violate the frozen contract
and make schema-version equality insufficient for semantic compatibility.

### Keep `socket.receive_queue` With a Limitation String

A limitation cannot undo a machine-readable causal Stage, direction, role, and
measurement domain. Consumers would still receive a false precise claim.

### Use `socket.unspecified` but Keep Causal Packet Semantics

This is less specific than receive queue, but the accumulator still mixes
contributors across Socket, Transport, policy, and listen processing and can
count GSO segments. Null causal location and source-defined units are the
conservative contract.

### Remove Sock-Diag Permanently

That would discard useful per-socket change and privacy-preserving identity.
Keeping it as context preserves diagnostic value without inventing a cause.

## Consequences

- Frozen v4 remains structurally compatible and records the historical
  descriptor, while the transitional live v4 producer preferred omission over
  publishing a false Stage.
- Current report v5 returns sock-diag deltas only through the generic context
  profile described above.
- Analyzer and UI wording must say that a source counter increased, not that a
  receive buffer overflow occurred or that a specific number of packets fell.
- Causal event coverage is narrower and version-dependent, but every precise
  claim is tied to an audited call site and runtime-validated format.
- ADR-0008 continues to govern private matching, churn/reuse handling,
  lower-bound/reset behavior, and identity disposal.
