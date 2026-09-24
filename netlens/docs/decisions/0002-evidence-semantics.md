# ADR-0002: Keep Evidence Semantics Orthogonal

## Status

Accepted

Decision 5 is superseded by [ADR-0004](0004-report-evidence-and-subject-identity.md); the remaining evidence semantics stay accepted.

## Date

2026-07-28

## Context

Linux exposes network evidence in incompatible forms and counting domains. A wire frame, XDP frame, skb, GRO aggregate, GSO super-packet, transport segment, and socket delivery are not interchangeable quantities. Event versus aggregate is also independent from observation coverage and from the confidence of a diagnostic conclusion.

The original draft used `exact | partial | aggregate | unsupported` as one coverage enum and treated every unknown `kfree_skb` reason as a direct drop. Linux 6.2+ can report normal TX completion through `kfree_skb` with `SKB_CONSUMED`, which is intentionally absent from the tracepoint's drop-reason symbolic table. That made an unknown raw code capable of producing a false drop Finding.

## Decision

1. Treat `kfree_skb` as neutral skb-free Evidence. A symbolic drop reason may establish a dropped disposition; `SKB_CONSUMED`, resolved from the running kernel BTF, establishes consumed; an unresolved raw code keeps an unknown disposition and cannot create a drop Finding.
2. Describe Evidence with independent stage, hook, direction, path role, context, disposition, signal, form, role, measurement domain, unit, scope, and bound fields. Layer remains a coarse classification; Stage is an extensible namespaced identifier.
3. Split Layer coverage into availability, visibility, evidence forms, filter support, and integrity. `event`, `counter_delta`, `gauge`, and `inventory` are Evidence-form values; `counter_delta` and `gauge` can carry aggregate quantities. “Aggregate” is neither a coverage level nor a Finding confidence value. This supersedes the single coverage-enum paragraph in ADR-0001.
4. Combine quantities only when their diagnostic ID and complete Evidence descriptor are compatible. Different stages, directions, contexts, dispositions, forms, domains, units, scopes, or bounds remain separate. Pressure and symptom signals never become drop dispositions.
5. Superseded by ADR-0004 after the Socket/Transport and per-socket designs demonstrated the second concrete adapter and subject-identity requirements.

## Alternatives Considered

### One unified Evidence envelope now

This gives the cleanest long-term interface and report-local evidence IDs, but would also require migrating every counter, replay format, analyzer reference, and collector before another provider can ship. The current shared descriptor captures the required invariants with a smaller migration.

### Keep aggregate in Coverage

This is smaller, but allows a report to confuse “only aggregate evidence exists” with “only part of the path is visible.” Those facts must be independently expressible.

### Hard-code the numeric value of SKB_CONSUMED

The project already treats running-kernel symbolic data as authoritative because enum values can move or be backported. BTF is used when available; without it the outcome remains unknown and fails closed.

## Consequences

- Unknown raw reasons remain inspectable observations but do not create false drop conclusions.
- Event loss changes measurement bounds and coverage integrity without changing the confidence of events that were actually captured.
- Host-wide softnet and tracepoint evidence cannot be silently attributed to a requested interface or network namespace.
- JSON v1 becomes more verbose for observations and findings, but future providers reuse one vocabulary instead of inventing incompatible fields.
