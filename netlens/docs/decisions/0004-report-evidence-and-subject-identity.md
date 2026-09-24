# ADR-0004: Separate Evidence Identity From Diagnostic Subject Identity

## Status

Accepted

The contract described by this ADR is frozen for `schemaVersion: 1`.

This supersedes Decision 5 in ADR-0002. That decision deferred a common event carrier until a second adapter demonstrated concrete requirements; the Socket/Transport and per-socket `sock_diag` designs now do so.

## Date

2026-07-28

## Context

The pre-Task-2a report duplicated counter and skb-free payload inside each Finding, and `Observation` was specific to skb-free events. Adding socket, policy, queue, hop, and hardware evidence would have created one Finding reference variant per provider and repeated provider payload throughout the report.

There are also two distinct identity problems:

- A Finding needs to reference the exact Metric or Observation that supports it.
- The analyzer needs to know whether evidence concerns the same socket, rule, program, queue, or topology hop.

The first is evidence identity. The second is diagnostic subject identity. A socket cookie, skb address, or kernel pointer cannot safely serve either public role.

The strict report schema rejects unknown fields and enum variants. Provider-specific tagged payload variants would therefore force a schema change whenever a provider is added.

## Decision

1. Keep `MetricDelta` and `Observation` as separate report collections, but give every entry a unique report-local evidence ID.
2. Define a shared strict `EvidenceMeta` containing evidence ID, provider, required-nullable Layer, EvidenceDescriptor, and typed subject references. A Metric row adds a namespaced metric type and measured values; an Observation row adds a namespaced event type and monotonic timestamp. Both carry bounded namespaced typed attributes.
3. Make Finding evidence a reference containing the evidence kind and ID. It does not duplicate Metric, Observation, descriptor, reason, or provider payload.
4. Add a report-local Subject table. Each row has an ID, a closed/versioned kind, a provider, and bounded typed attributes. Each Subject reference has a closed/versioned role; subject identity participates in aggregation compatibility, while evidence identity does not.
5. Generate both ID classes inside one report. They are opaque, non-reusable across reports, and never expose or reversibly encode skb addresses, socket cookies, kernel pointers, complete default flow tuples, or other sensitive identifiers.
6. Use one closed provider registry for Metric, Observation, Subject, telemetry, and collection errors. Each provider has explicit evidence-type and attribute allowlists. If both descriptor context and a Subject state an interface, queue, or network namespace, they must agree; a queue Subject with an ifindex must have a matching owner interface/hop reference.
7. Keep attribute value shapes, Subject kinds, and Subject roles closed and versioned while allowing namespaced attribute names. If a provider cannot normalize evidence into the frozen envelopes/value types, the report schema version changes rather than silently emitting a new shape.
8. Run `validate_evidence` after normalization and before analysis, then run full `Report::validate` after Findings are built and before output. A deserialized report must pass `Report::validate` before use. JSON Schema validates structure, while the Rust validators reject the cross-row and provider-specific errors listed below.
9. Aggregate only when Finding ID, full EvidenceDescriptor, measurement identity, and relevant Subject IDs are compatible. NAT, encapsulation, redirect, clone, and re-entry require explicit transition evidence; report-local IDs alone never prove packet identity.

## Frozen v1 Contract

All report-v1 DTOs reject unknown properties. Required-nullable fields, including `EvidenceMeta.layer` and the nullable `MetricValues` fields, must be present with either a value or JSON `null`; omission is invalid.

All `u64` and UTF-8 byte limits in this ADR are normative semantic limits. Rust deserialization and `Report::validate` enforce them; JSON Schema remains a structural pre-check where its vocabulary cannot express the same rule. The Schema applies the shared `u64::MAX` bound to nullable `MetricValues.start`, `end`, and `delta`. JSON Schema `maxLength`, however, counts Unicode code points rather than UTF-8 bytes, so Schema-only acceptance of an overlong multibyte string does not make a report conforming.

### Names and IDs

Namespaced names are ASCII strings of at most 128 bytes, contain at least one dot, and match `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`.

Evidence and Subject IDs have distinct report-local shapes:

- Evidence: `e_<32 lowercase hex nonce>_<non-zero decimal counter>`
- Subject: `s_<32 lowercase hex nonce>_<non-zero decimal counter>`

The nonce is randomly generated for each report. IDs are opaque and cannot encode raw skb/socket addresses, socket cookies, kernel pointers, full default flow tuples, or another reusable kernel identity.

The canonical provider IDs are:

- `linux.proc.protocol_counters`
- `linux.proc.softnet_counters`
- `linux.link.counters`
- `linux.tracepoint.kfree_skb`
- `nwdiag.core`

Their frozen evidence ownership is:

| Provider | Metric | Observation | Subject attributes |
| --- | --- | --- | --- |
| `linux.proc.protocol_counters` | `metricType` starts with `linux.mib.` | Not allowed | Subjects not allowed |
| `linux.proc.softnet_counters` | `metricType` starts with `linux.softnet.` | Not allowed | Subjects not allowed |
| `linux.link.counters` | `metricType` starts with `linux.link.` | Not allowed | Only `queue`, `interface`, and `hop` Subjects, with link allowlists below |
| `linux.tracepoint.kfree_skb` | Not allowed | `eventType` is exactly `linux.skb.free` | Subjects not allowed |
| `nwdiag.core` | Not allowed in v1 | Not allowed in v1 | All seven Subject kinds, with core allowlists below |

### Evidence Envelopes

Every Metric and Observation contains the same required metadata:

```json
{
  "id": "e_00000000000000000000000000000000_1",
  "provider": "linux.link.counters",
  "layer": "netdevice",
  "descriptor": {
    "stage": "netdevice.unspecified",
    "hook": null,
    "direction": "ingress",
    "pathRole": null,
    "context": {
      "networkNamespace": null,
      "ingressIfindex": 2,
      "egressIfindex": null,
      "queueId": null,
      "cpu": null,
      "protocol": null
    },
    "outcome": {"disposition":"dropped","signal":null},
    "form": "counter_delta",
    "role": "causal",
    "measurement": {
      "unit": "occurrences",
      "domain": "interface_packet",
      "scope": "interface",
      "bound": "exact"
    }
  },
  "subjects": [
    {"role":"ingress","id":"s_00000000000000000000000000000000_1"}
  ]
}
```

Metric descriptors have `form: "counter_delta"`; Observation descriptors have `form: "event"`. A non-null stage must use a registered Layer namespace and `meta.layer` must equal the mapped Layer. A non-null Layer without a stage is invalid. Every registered Metric requires both Layer and stage; an unclassified Observation may set both to null.

A Metric row is exactly `{"meta": EvidenceMeta, "metricType": NamespacedName, "values": MetricValues, "attributes": Attributes}`. `MetricValues` requires `start`, `end`, and `delta` as nullable `u64` values plus boolean `reset`. Its combinations are semantic contract:

- With both endpoints and `end >= start`, `reset` is false and `delta` equals `end - start`.
- With both endpoints and `end < start`, `reset` is true and `delta` is null.
- With exactly one endpoint, `reset` is false and `delta` is null.
- Both endpoints null is invalid.
- `descriptor.measurement.bound` is present exactly when `delta` is present.

An Observation row is exactly `{"meta": EvidenceMeta, "eventType": NamespacedName, "monotonicNs": u64, "attributes": Attributes}`. The only v1 Observation registration is `linux.tracepoint.kfree_skb` plus `linux.skb.free`.

Metric Finding aggregation uses provider plus a normalized measurement identity. The identity is the exact `metricType` except for two registered overlapping pairs: `linux.mib.tcp_ext.listen_drops` with `linux.mib.tcp_ext.listen_overflows`, and `linux.mib.tcp.retrans_segs` with `linux.mib.tcp_ext.tcp_syn_retrans`. The analyzer takes the maximum only within one such identity; disjoint identities such as UDP and UDP-Lite receive-buffer errors remain separate Findings. Observation identity is provider plus `eventType`, and occurrence events are counted by addition.

A Finding evidence reference contains no copied payload and is exactly `{"kind":"metric","id":"e_00000000000000000000000000000000_1"}` or `{"kind":"observation","id":"e_00000000000000000000000000000000_2"}`.

### Subjects and Roles

A Subject row is `{"id": SubjectId, "provider": ProviderName, "kind": SubjectKind, "attributes": Attributes}`. The closed Subject kinds are exactly:

- `socket`
- `rule`
- `program`
- `queue`
- `interface`
- `hop`
- `flow_domain`

A Subject reference is `{"role": SubjectRole, "id": SubjectId}`. The closed roles and valid target kinds are:

| Role | Valid Subject kinds |
| --- | --- |
| `primary` | All seven kinds |
| `ingress`, `egress` | `interface`, `hop` |
| `owner` | `interface`, `hop`, `program` |
| `peer` | `socket`, `interface`, `hop` |
| `before`, `after` | `rule`, `program`, `hop`, `flow_domain` |

Subject role/ID pairs within one evidence row must be unique; the same Subject may appear under distinct valid roles. If a Subject declares `linux.network_namespace.id`, it cannot conflict with descriptor context. An ingress/egress Subject ifindex must match the corresponding context ifindex when present. A directed `primary` Subject must match the context selected by descriptor direction; an undirected `primary`, `owner`, `peer`, `before`, or `after` Subject must match either ingress or egress context if either is present. A queue's `linux.queue.id` cannot conflict with context queue ID. A queue carrying an ifindex must also be accompanied by an `owner` reference to an interface or hop with the same ifindex.

### Attributes

An Attributes object contains at most 16 entries. Every key is a namespaced name and every value has exactly one tagged shape: `{"type":"string","value":"text"}`, `{"type":"unsigned","value":42}`, or `{"type":"boolean","value":true}`.

Strings contain at most 128 bytes, unsigned values are `u64`, and booleans are JSON booleans. These three value shapes are frozen, but a value is legal only when its provider, owner type, attribute name, and range appear in the following allowlists. No current provider allowlist accepts a boolean attribute.

Except for `linux.skb_free.source_mode`, allowed attributes are optional; no Subject attribute is required merely by its kind.

| Owner | Provider | Allowed attributes |
| --- | --- | --- |
| Metric | `linux.proc.protocol_counters` | None |
| Metric | `linux.proc.softnet_counters` | Optional `linux.cpu.row`: unsigned `0..=u32::MAX` |
| Metric | `linux.link.counters` | Optional `linux.interface.name`: valid Linux interface name; optional `linux.counter.bits`: unsigned `32` or `64` |
| Observation | `linux.tracepoint.kfree_skb` | Required `linux.skb_free.source_mode`: string `counter_only|legacy_perf|reason_ring`; optional `linux.skb_free.reason_code`: unsigned `0..=u32::MAX`; optional `linux.skb_free.reason_name`: 1..=64 ASCII uppercase/digit/underscore characters and requires reason code |
| Subject `interface` or `hop` | `linux.link.counters`, `nwdiag.core` | `linux.interface.name`, `linux.interface.ifindex`, `linux.network_namespace.id` |
| Subject `queue` | `linux.link.counters` | `linux.interface.ifindex`, `linux.network_namespace.id` |
| Subject `queue` | `nwdiag.core` | `linux.interface.ifindex`, `linux.queue.id`, `linux.network_namespace.id` |
| Subject `socket` or `flow_domain` | `nwdiag.core` | `linux.network_namespace.id` |
| Subject `rule` or `program` | `nwdiag.core` | None |

`linux.proc.protocol_counters`, `linux.proc.softnet_counters`, and `linux.tracepoint.kfree_skb` cannot own a Subject. `linux.link.counters` cannot own `socket`, `rule`, `program`, or `flow_domain`, even with empty attributes.

Interface names contain 1 through 15 bytes, cannot be `.` or `..`, and cannot contain slash, NUL, or ASCII whitespace. `linux.interface.ifindex` is unsigned `1..=2_147_483_647`. `linux.queue.id` is unsigned `0..=u32::MAX`. `linux.network_namespace.id` is a non-empty printable ASCII string of at most 128 bytes.

### Semantic Validation

In addition to structural Schema validation, `Report::validate` rejects:

- a report or embedded capability `schemaVersion` other than `1`;
- duplicate evidence IDs across Metric and Observation collections;
- duplicate Subject IDs, dangling Subject references, duplicate references within an evidence row, or an invalid role/kind pair;
- unknown providers, invalid provider/Subject-kind ownership, unregistered Metric prefixes, unregistered Observation provider/event combinations, or attributes outside the allowlists;
- Metric or Observation descriptor forms that do not match their carrier; a missing, unregistered, or Layer-conflicting stage; or an inconsistent Metric start/end/delta/reset/bound combination;
- missing required skb-free source mode, or a reason name without a reason code;
- a Finding whose ID is not namespaced, has no evidence, has duplicate/dangling references, uses the wrong evidence kind, or combines evidence whose provider-normalized measurement identity, Layer, full descriptor, and ordered Subject references are incompatible;
- a collection error without a telemetry row for the same provider, or Metric/Observation evidence without a provider telemetry row containing an applicable boundary;
- an exact evidence measurement when any counter for its provider is unknown, or when a measured output/transport-loss/userspace/netlink/parse-loss counter is non-zero;
- provider telemetry totals or session sampling that do not derive exactly from provider rows, as specified by ADR-0003.

## Alternatives Considered

### Keep provider payload inside Finding references

This is the smallest migration, but every new provider duplicates data and expands the public `EvidenceRef` union.

### Use one unified Evidence collection for counters and events

This removes one collection boundary but forces a larger migration without simplifying the current collector inputs. Separate Metric and Observation collections with common IDs provide the needed reference semantics.

### Add one tagged Observation detail variant per provider

This is strongly typed, but strict older validators reject each new variant. It would make provider delivery and schema versioning unnecessarily coupled.

### Publish socket cookies or kernel addresses as identity

These values are sensitive, unstable, and can be reused. They violate the privacy boundary and still do not establish end-to-end packet identity.

## Consequences

- This ADR is the normative frozen report-v1 contract for Rust DTOs, JSON Schema, fixtures, analyzer grouping, and output. JSON Schema's code-point-based string length limitation does not relax the Rust-enforced UTF-8 byte limits.
- Per-socket, per-rule, per-program, per-queue, and per-hop findings can remain distinct without exposing kernel identities.
- Consumers resolve Finding references through report collections; `Report::validate` makes dangling, duplicate, wrong-kind, and context-conflicting IDs contract errors that JSON Schema alone cannot express.
- Provider attribute registries and privacy tests are part of each provider's acceptance criteria. Adding a provider, kind, role, attribute, tagged value shape, evidence carrier, measurement-identity alias, or changed semantic requires a new `schemaVersion`.
