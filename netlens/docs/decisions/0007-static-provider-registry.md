# ADR-0007: Register Report Providers in One Static Descriptor Table

## Status

Accepted

## Date

2026-07-29

## Context

The first four evidence providers were added before the report-v3 path contract stabilized. Their names, owned Layers, metric sources, telemetry boundaries, effective scopes, and capability stages accumulated in separate matches across `model`, normalization, provider selection, scope construction, and capability reporting. Adding the planned `sock_diag` provider in that shape would require updating several parallel tables, and one missed branch could produce a provider with no telemetry row, an invalid effective scope, or contradictory coverage.

Provider execution is not uniform. Procfs snapshots, rtnetlink dumps, and BPF event streams have different runtime state and error handling. Turning those collectors into dynamic plugins or a trait hierarchy would couple static report metadata to I/O orchestration without removing that provider-specific behavior.

Report event-stream v1 is already frozen. It accepts only `linux.tracepoint.kfree_skb` observations and cannot expand automatically when report providers are registered.

## Decision

1. `src/provider.rs` is the single static registry for report-provider identity and declarative contract metadata. A descriptor owns its canonical name, Layers, metric sources and type prefixes, capability-source aliases, observation types, Subject kinds, telemetry applicability, scope policy, and baseline capability Layer/Stage metadata.
2. The registry is a compile-time slice with typed enums and structs. It has no trait hierarchy, dynamic loading, collector function pointers, or arbitrary callbacks.
3. Provider selection, effective scope construction, metric-source normalization, report-v3 provider/metric/observation/Subject validation, telemetry applicability, and baseline capability coverage derive from the registry. Capability source aliases remain explicit because frozen fixtures and kernel-facing collectors may use source names that differ from canonical provider IDs.
4. Telemetry applicability is declared per boundary counter as required, not applicable, optional, or part of a named all-or-none group. A row with every counter `not_applicable` remains the valid inactive representation. Any active row must satisfy its descriptor, and unknown providers remain invalid.
5. Scope descriptors declare activation, namespace extent, interface-path handling, direction handling, and filter support. Runtime values such as the requested namespace identity, path completeness, selected BPF mode, provider availability, loss, and sampled evidence remain runtime inputs interpreted by the owning module.
6. Baseline capability Layer and Stage descriptors carry evidence forms, visibility, filter support, integrity, execution domain, and limitations. Runtime discovery still creates provider status rows, and reason-derived `kfree_skb` stages remain dynamic, but both paths use descriptor ownership when publishing coverage.
7. Collector dispatch and provider-specific parsing stay explicit in their owning adapters. Registering a provider creates its report identity, inactive telemetry row, selection/scope behavior, and validation/capability vocabulary; implementing its runtime collector still requires the corresponding adapter.
8. Event-stream v1 keeps its explicit `kfree_skb` and `linux.skb.free` check. The extensible report registry must not widen that frozen stream contract; a future event-stream v2 requires a separate decision and Schema.
9. Registry tests enforce unique and complete provider names, metric/capability sources, Layers, Stages/domains, observation types, and current v3 parity. Report validation rejects capability and effective-scope Layers outside descriptor ownership.

## Alternatives Considered

### Keep Provider Matches in Each Owning Module

Local matches are initially direct, but every new provider must update identity, scope, telemetry, normalization, and capability logic in lockstep. The compiler cannot detect a missing parallel branch, which is the failure mode Task 2e is intended to remove.

### Define a Provider Trait and Dynamic Plugin Registry

A trait could combine collection and metadata behind one interface, but procfs, netlink, and BPF have materially different lifecycles. Dynamic dispatch would add object-safety, registration, and initialization concerns while the product ships as one binary with a fixed provider set.

### Store Collector Callbacks in Static Descriptors

Function pointers avoid trait objects but still mix declarative report facts with runtime orchestration and error-state ownership. Explicit adapters keep I/O control flow visible and let the registry remain data-only.

### Derive Event-Stream Validation from the Report Registry

This would make observation registration appear uniform, but silently broadens event-stream v1 whenever a report provider is added. Keeping the v1 check explicit preserves its frozen compatibility boundary.

## Consequences

- Adding a report provider no longer requires parallel name, Layer, source, telemetry, scope, Subject, observation, and baseline capability matches.
- Runtime collectors remain intentionally provider-specific; the registry does not pretend unlike transports share one lifecycle.
- The descriptor table is more verbose than individual matches, but its invariants and parity tests make omissions visible in one place.
- Capability sources are closed over canonical provider IDs, registered metric sources, and explicit aliases. Unknown source ownership fails closed.
- Report-v3 registration and event-stream-v1 compatibility remain separate. New report observations do not become valid JSONL records automatically.
