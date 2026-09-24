# ADR-0003: Separate Observer Loss by Pipeline Boundary

## Status

Accepted

The contract described by this ADR is frozen for `schemaVersion: 1`.

## Date

2026-07-28

## Context

The first report model used `bpfEventsReceived`, `bpfEventsLost`, and `userEventsLost`. Those names collapsed distinct boundaries in the event pipeline:

```text
probe hit -> BPF output -> perf/ring transport -> decode -> bounded userspace store
```

In particular, the BPF-side hit counter was named "received," and a single loss field could not distinguish an output reservation failure from a perf-buffer overwrite or a userspace capacity drop. That prevents the report from stating which part of its own observation path was incomplete.

Task 2a migrated this accounting into the strict report-v1 DTO and Schema. The shapes and semantics below are now part of `schemaVersion: 1`, rather than reserved future work.

## Decision

1. Report the event pipeline with independent counters:
   - `bpfEventsSeen`: probe executions counted before attempting output.
   - `bpfOutputLost`: records the BPF program could not submit, such as a failed ring reservation or perf output helper call.
   - `transportEventsReceived`: callbacks delivered to userspace, counted before decode.
   - `transportEventsLost`: loss explicitly reported by the transport, such as a perf-buffer lost callback.
   - `userEventsDropped`: valid decoded records not retained because a bounded userspace store was full.
   - `parseErrors`: records or collector inputs that reached a parser but failed validation.
2. Keep netlink signals separate. `netlinkLossEvents` counts detected loss notifications, not an inferred number of missing messages; `netlinkDumpInterruptions` counts dumps whose snapshot may be inconsistent.
3. Treat all counters as saturating diagnostic telemetry, not as a conservation equation. Providers can filter, aggregate, or lack a loss signal, and `parseErrors` can include non-BPF collectors.
4. Publish every boundary counter per provider. Every one of the eight fields is required and has exactly one tagged shape: `{"status":"measured","value":0}`, `{"status":"not_applicable"}`, or `{"status":"unknown"}`.

   `measured` contains a `u64`; measured zero is evidence that the boundary was counted and observed zero. `not_applicable` means that boundary was not part of that provider's effective collection path. `unknown` means it was applicable but no trustworthy value survived. Unknown values must never be serialized as zero.
5. Represent each session total with required `value: u64` and `bound: "exact"|"lower_bound"` fields, for example `{"value":0,"bound":"exact"}`. Sum measured provider values with saturation, ignore `not_applicable`, and make the result `lower_bound` if any provider is `unknown` or if summation overflows. Overflow clamps the value to `u64::MAX`. With no unknowns, including when every provider is `not_applicable`, the total is exact.
6. Always publish provider and session sampling with one strict shape: `{"mode":"none"}`, `{"mode":"sampled","method":"vendor.method","scope":"vendor.scope","effectiveNumerator":1,"effectiveDenominator":100}`, or `{"mode":"mixed","components":[...]}`.

   `method` and `scope` are namespaced names. Effective numerator and denominator are non-zero `u32` values and the numerator cannot exceed the denominator. `mixed.components` contains 2 through 64 unique, non-nested components. A component is either `{"mode":"none","scope":"provider.or.scope"}` or the full `sampled` shape. Session sampling is derived from provider sampling: identical provider values remain that value; differing values are flattened into `mixed`, with an unsampled provider represented by a `none` component scoped to its provider ID.
7. Any unknown provider counter, or any non-zero measured output, transport-loss, userspace, netlink, or parse-loss counter, lowers affected evidence measurement bounds. Non-zero `bpfEventsSeen` and `transportEventsReceived` are activity, not loss. BPF loss also changes active reason-derived coverage integrity to `loss_detected`; a failed BPF join publishes unknown applicable counters and a collection error rather than zero. Zero in one counter does not prove end-to-end completeness; capability and coverage still govern that claim.
8. The ambiguous pre-release scalar fields have been removed. Because v1 validators reject unknown properties and enum values, any newly emitted field or variant, removal, rename, or semantic change now requires a new `schemaVersion`.

## Frozen v1 Contract

`Telemetry` has four required properties:

```text
Telemetry {
  totals: BoundaryCounters<BoundedTotal>,
  providers: ProviderTelemetry[],
  collectionErrors: CollectionError[],
  sampling: SamplingTelemetry
}

ProviderTelemetry {
  provider: ProviderName,
  counters: BoundaryCounters<CounterStatus>,
  sampling: SamplingTelemetry
}

CollectionError { provider: ProviderName, message: string }
```

Both `totals` and each provider's `counters` require all eight fields: `bpfEventsSeen`, `bpfOutputLost`, `transportEventsReceived`, `transportEventsLost`, `userEventsDropped`, `netlinkLossEvents`, `netlinkDumpInterruptions`, and `parseErrors`. A report cannot omit an inapplicable or unknown field.

Provider IDs are a closed v1 registry:

- `linux.proc.protocol_counters`
- `linux.proc.softnet_counters`
- `linux.link.counters`
- `linux.tracepoint.kfree_skb`
- `nwdiag.core`

Provider telemetry IDs must be unique. `collectionErrors` use the same provider registry, contain a message of 1 through 1024 UTF-8 bytes, and require a telemetry row for the named provider. The byte limit is normative and is enforced by Rust validation; JSON Schema `maxLength` counts Unicode code points and is not sufficient by itself for this limit. Every Metric and Observation likewise requires a telemetry row for its provider with at least one applicable boundary. Session totals and sampling are derived data: `Report::validate` rejects values that do not exactly match the provider rows.

`Report::validate` freezes and enforces this provider applicability matrix. Here, applicable means `measured` or `unknown`; it never means `not_applicable`.

| Provider | Applicability rule | Always not applicable |
| --- | --- | --- |
| `linux.proc.protocol_counters` | `parseErrors` must be applicable | The other seven fields |
| `linux.proc.softnet_counters` | `parseErrors` must be applicable | The other seven fields |
| `linux.link.counters` | `netlinkLossEvents`, `netlinkDumpInterruptions`, and `parseErrors` must be applicable | The five BPF/transport/userspace fields |
| `linux.tracepoint.kfree_skb` | The five BPF/transport/userspace fields plus `parseErrors` must be either all applicable or all not applicable | Both netlink fields |
| `nwdiag.core` | No additional restriction beyond requiring all eight status fields | None imposed by provider registration |

The current CLI realizes that matrix as follows:

- Protocol and softnet `parseErrors` are measured zero when collection completes; a canonical collection error makes the corresponding value unknown.
- Link netlink and parse fields use the collector's measured counters. The rtnetlink, sysfs, and `/proc/net/dev` decoders distinguish parser rejection from I/O or target errors; every rejected fallback input increments `parseErrors` before the next fallback is attempted.
- After a successful BPF attempt, all six kfree event-path fields are measured. After a failed join, all six are unknown and a canonical collection error is emitted. When no BPF collection is attempted, all six are not applicable.
- The current CLI does not emit an `nwdiag.core` telemetry row.

A collection error and a measured counter may coexist: the error describes collection failure context, while the status says whether that specific boundary count remains trustworthy.

## Alternatives Considered

### Keep the original names and document them

This avoids a pre-release schema change but preserves the misleading implication that the BPF hit counter measures userspace receipt.

### Publish one total-loss counter

This is simpler, but overlapping provider capabilities make a trustworthy total impossible and hide whether loss occurred before or after kernel-to-userspace transport.

### Infer missing records from counter subtraction

This assumes every provider emits one carrier per probe hit and that every transport exposes equivalent loss signals. Those assumptions do not hold across perf buffers, ring buffers, filtering, and future aggregate providers.

## Consequences

- Operators can identify whether incompleteness occurred at BPF output, transport, parsing, or userspace retention.
- Collectors must increment `transportEventsReceived` before decoding, drain a detached buffer before reading final counters, and retain provider-scoped accounting through normalization.
- Table and JSON output must use the same field meanings, and contract fixtures must reject the removed ambiguous names.
- The provider dimension is required for every boundary; applicability is carried by its tagged status rather than by omission.
- This ADR is the normative frozen contract for Rust DTOs, JSON Schema, fixtures, JSON output, and table output. A new provider ID, counter, status, sampling variant, or changed meaning requires a report schema-version change.
