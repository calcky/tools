# ADR-0005: Version Capture Scope and Exit Status

## Status

Accepted

## Date

2026-07-29

## Context

Report v1 froze the evidence, identity, and telemetry contract. It exposed only an interface name and network-namespace identity for capture scope. That shape could not distinguish what an operator requested from what each provider actually observed. It also could not represent an interface as a path anchor, show a provider that collected a broader population, or make strict automation decisions from structured data.

Adding those fields to v1 would violate its strict Schema and the versioning rules in ADR-0003 and ADR-0004. Task 2b also requires stable process exit behavior for argument rejection, fatal report failure, coverage enforcement, and findings.

## Decision

1. `CapturePlan` is the single typed request used by CLI validation and report execution. It owns duration, selected and required layers, optional direction, optional interface path, the current network namespace, protocol and source/destination address/port filters, process filters, sampling, detail level, strict coverage, and the optional finding threshold.
2. PID and cgroup filters remain modeled but unsupported. A request containing either fails as an argument error before collection. It is never projected into a scope with the field silently removed.
3. An interface request is a path anchor. Before collection, nwdiag resolves the anchor to an ifindex and walks current-namespace sysfs `upper_*`, `lower_*`, and locally resolvable `iflink` relationships. The report records the visible closure and explicit topology gaps. An unresolved anchor prevents a valid report.
4. `Report.scope.requested` records the validated request. Every telemetry provider has exactly one `Report.scope.providers` row containing the same requested scope, a nullable effective scope, and filter support for layers, namespace, interface path, direction, protocol, addresses, and ports.
5. `kernel_exact` and `userspace_exact` effective values may retain the requested value. `broader_only` must publish the broader population, such as `host_wide`, `all_visible`, or a null flow dimension; it must not copy a requested anchor or five-tuple value. `unsupported` cannot produce an active effective scope for a requested dimension.
6. Requested scope is not observed evidence context. Evidence context continues to come only from decoded events, counter labels, or inventory values. Interface filtering retains closure link metrics only when the resolved path is complete. If topology gaps remain, link metrics stay all-visible and the provider reports `broader_only`; evidence never synthesizes an ifindex from the requested anchor.
7. The current shape is `schemaVersion: 2` and is defined by `docs/schema/report-v2.schema.json`. The frozen v1 Schema and fixture remain checked in as the compatibility baseline. Rust semantic validation additionally requires provider-scope uniqueness, equality with telemetry provider IDs, identical requested scopes, active effective scope for every evidence provider, and evidence layers within provider effective layers.
8. Exit statuses are fixed as follows:

   | Code | Meaning |
   | --- | --- |
   | `0` | A valid report was produced and no requested policy matched. |
   | `1` | A valid report was produced and an explicit `--fail-on` threshold matched. |
   | `2` | CLI syntax, typed request validation, or an explicitly unsupported filter failed. |
   | `3` | A valid report could not be produced, including an unresolved runtime anchor or output failure. |
   | `4` | A valid report was produced but required or strict coverage was not complete. |

9. Precedence is argument error, fatal report failure, strict coverage, `--fail-on`, then success. Strict coverage therefore returns `4` even when the same valid report also contains a threshold-matching Finding.
10. Strict coverage requires every selected or required layer to be active, full for its declared scope, exact-filtered, complete, and backed by at least one evidence form. Normal mode still emits broader or degraded evidence with its scope and coverage instead of failing.

## Consequences

- Automation can tell zero from unavailable coverage and requested scope from broader evidence without parsing human text.
- Report v2 is intentionally more verbose because each provider carries its own effective scope.
- Current-namespace interface topology is a visible static closure, not a guarantee about dynamic TC/XDP redirects, offload, or a peer hidden in another namespace. Until TC/XDP redirect inventory exists, every resolved path records `dynamic_redirect`; the link provider therefore remains `all_visible`/`broader_only` and does not closure-filter metrics. Future providers must retain any remaining limitations and degrade when discovered.
- Sampling defaults to none and detail defaults to summary. CLI exposure of non-default values waits until collectors implement the corresponding behavior and telemetry.
- Table output is not a public API, but it renders the same scope object used by JSON and is covered by consistency tests.
