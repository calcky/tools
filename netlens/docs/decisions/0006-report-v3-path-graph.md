# ADR-0006: Represent Report v3 Packet Paths as an Explicit Graph

## Status

Accepted

## Date

2026-07-29

## Context

Report v1 and v2 classify IP receive validation, route and neighbor decisions, and XFRM policy or transform failures under one coarse `route` Layer. That compatibility shape cannot say whether an error happened while validating an IP packet, selecting a route, resolving a neighbor, or applying an XFRM policy. It also encourages renderers to arrange Layers in one fixed order even though local input, local output, L2 forwarding, L3 forwarding, redirects, lower devices, clones, transforms, and re-entry form different graphs.

Layer and Stage alone do not identify where code executed. The same logical action may run in the host kernel, in an offload domain, or in hardware, and evidence from those domains cannot be treated as interchangeable. Layer-wide coverage also cannot show that one provider observes one Stage/domain pair while another Stage in the same Layer is unavailable.

ADR-0004 already defines report-local `hop` and `flow_domain` Subjects plus `before` and `after` Subject roles. Adding a second path-node identity system would create two ways to describe the same interface hop and would make reference validation ambiguous. The report also needs to preserve its independent, frozen event-stream v1 contract, which has no report-local Subject references and cannot encode graph edges.

## Decision

1. Report v3 separates the coarse L3 categories into `network`, `route`, and `xfrm` Layers. `network.*` Stages cover IP validation, fragmentation/reassembly, and MTU processing; `route.*` Stages cover lookup and neighbor decisions; `xfrm.*` Stages cover policy and transform processing. A Stage namespace must map to its corresponding Layer. Report v3 also adds `l2_local_input` and `l2_local_output` PathRoles so bridge-local delivery and locally generated L2 traffic are not mislabeled as IP-local paths.
2. Every report Evidence row and Finding has a required, nullable `executionDomain` namespaced value. It identifies where the reported operation or signal executed, such as `linux.kernel` or `linux.hardware`. It is distinct from network namespace, PathRole, measurement domain, and measurement scope. Unknown is represented by explicit `null`, never by assuming host-kernel execution. Execution domain is part of Finding/evidence compatibility, so evidence from different execution domains is not aggregated into one Finding.
3. `CapabilityReport.stageCoverage` records provider-stage-domain coverage. Each row identifies provider, Layer, Stage, nullable execution domain, availability, visibility, forms, filter support, integrity, and limitations. The `(provider, stage, executionDomain)` key is unique, the Stage must belong to the declared Layer, active or degraded rows must declare at least one form, and unavailable rows must not advertise forms. Every staged Evidence row must match an active or degraded coverage row with the same provider, Layer, Stage, execution domain, and Evidence form. Layer coverage remains a coarse summary; it does not replace stage coverage.
4. Report v3 reuses `SubjectKind: hop` for path nodes. Every Hop Subject carries the typed unsigned attribute `nwdiag.path.hop_ordinal` with a value from 1 through `u32::MAX`. The ordinal identifies a hop's position within the reported path context; it is not a global Layer rank and does not order unrelated branches or Stages within a hop. Interface name, ifindex, and observed network namespace remain typed Hop attributes where available.
5. A graph edge is present only when Evidence has a non-null namespaced `transition` and explicit Subject references with `before` and `after` roles. Each side must contain at least one endpoint, endpoints must be Hop or FlowDomain Subjects, and the same Subject cannot be both before and after on one edge. Multiple endpoints allow an observed clone or fanout to remain a branch; separate edges and endpoints allow redirects, lower-device hops, transforms, and re-entry without flattening cycles. A transition also requires a non-null execution domain.
6. A report-local Subject ID, matching timestamp, adjacent Layer, or matching tuple does not prove a transition. When explicit transition evidence is absent, output may group rows as evidence by Layer but must not present the Layer order as an observed packet path. Rendering an observed order is reserved for graph metadata using PathRole, Hop ordinals, and transitions.
7. Report v1 and v2 DTOs, Schemas, and fixtures remain byte-for-byte frozen. Report v3 is a new Schema version rather than an in-place extension. Evidence graph fields live in report `EvidenceMeta` and Finding rather than `EvidenceDescriptor`, because the descriptor is shared with event-stream v1.
8. Event-stream v1 remains `schemaVersion: 1` and retains its original Layer and PathRole vocabulary. Conversion may discard only the implied `linux.kernel` execution domain. It rejects report-v3-only `network.*` Stages, L2-local PathRoles, transition metadata, and any non-kernel execution domain. A future event-stream v2 is required before JSONL can carry the complete report-v3 graph contract.

## Alternatives Considered

### Keep Network and XFRM under Route

This avoids a report version increase, but preserves the ambiguity that prompted the change. It also makes provider ownership and stage coverage misleading: an IP header counter, a neighbor failure, and an XFRM policy rejection do not observe the same subsystem.

### Define a second PathNode and Edge registry

A dedicated graph table appears explicit, but duplicates the existing Hop and FlowDomain Subject identities and their provider-owned typed attributes. Reusing Subjects with `before` and `after` references keeps one identity and validation model.

### Treat Layer order as the packet path

A fixed rank is convenient for tables, but it is false for bridge-local paths, forwarding, redirects, lower-device repetition, clones, and XFRM re-entry. Layer remains classification, not chronology.

### Add graph fields to EvidenceDescriptor and event-stream v1

This would make descriptor semantics uniform, but it would silently change the strict event-stream v1 envelope and its compatibility behavior. Keeping graph metadata at the report layer preserves the frozen stream contract until a separately versioned stream migration exists.

## Consequences

- Providers must declare the exact Stage and execution-domain coverage that backs staged Evidence; broad Layer availability cannot authorize an unsupported Stage.
- Current normalized kernel evidence uses `linux.kernel`, while NIC/PHY evidence uses `linux.hardware`. Future offload providers must use their own namespaced execution domains and cannot project hardware-only evidence into the kernel path.
- Transition-producing providers must create or reference valid Hop or FlowDomain Subjects and supply both endpoints. This is more verbose, but makes every claimed edge auditable and rejects inferred continuity.
- Existing collectors may continue to emit `transition: null`. Their evidence remains useful, but it is grouped by Layer rather than described as an observed end-to-end path.
- Report v1/v2 consumers and event-stream v1 consumers see no contract change. Full graph-capable JSONL requires event-stream v2.
