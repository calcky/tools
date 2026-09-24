# ADR-0001: Support Linux 4.14 With Capability-Selected Collectors

## Status

Accepted

The old coverage enum and unconditional drop-event interpretation are superseded by [ADR-0002](0002-evidence-semantics.md); the kernel compatibility decision remains accepted.

## Date

2026-07-28

## Context

nwdiag must diagnose packet drops from socket to NIC on Linux 4.14 and newer. The relevant kernel observability interfaces do not have one common feature baseline:

- Linux 4.14 has BPF tracepoint programs and perf-event arrays, but normally has no kernel BTF, BPF ring buffer, fentry/fexit, or skb drop reason.
- `skb:kfree_skb` gained an initial reason field in Linux 5.17 and broader reasons in 5.18.
- Linux 6.2 added `SKB_CONSUMED`; successful TX completion can therefore appear on `kfree_skb` without being a drop, and later raw reason values may shift.
- Linux 6.11 inserted `rx_sk` into `skb:kfree_skb`, moving `protocol` and `reason` to new offsets without creating a new tracepoint name.
- BPF ring buffer appeared after the minimum target, in Linux 5.8.
- Enterprise kernels backport features, so the release string is not a reliable capability contract.
- BPF helpers and instructions have a stable ABI, but tracepoint field layout and symbolic enum values do not.

Requiring a modern kernel would violate the product requirement. Pretending the old kernel has modern attribution would create false diagnoses.

## Decision

Use one Rust userspace program with multiple independently loadable collectors:

1. Stable counter/config collectors are always attempted first and work without BPF.
2. A legacy BPF object is selected only for the exact `skbaddr@8`, `location@16`, `protocol@24` layout and uses a perf-event array. It does not require target-kernel BTF and never reads a reason field.
3. One reason/ring-buffer object supports the pre-6.11 layout (`protocol@24`, `reason@28`). A separate object supports the layout with `rx_sk@24` (`protocol@32`, `reason@36`).
4. Userspace reads field names, offsets, and sizes from the running tracefs `format` file before choosing an object. An unknown layout is not probed and falls back to counter-only mode, because attach success cannot prove that a tracepoint program read the correct offsets.
5. Drop reason code-to-name mappings come from the running tracepoint's `__print_symbolic(REC->reason, ...)` table. Special non-drop values such as `SKB_CONSUMED` come from the running kernel BTF. Numeric values are never compiled into userspace; the `MAX` sentinel is ignored and unknown codes remain raw, unclassified evidence.
6. Optional future CO-RE fentry/fexit or kprobe objects can improve a layer but can never be required for the baseline report. Kernel BTF is reported as a capability but is not required by the current fixed tracepoint-layout objects.

Selection is based on actual format/map/load/attach probes. `uname` is reported as context, not used as the sole switch.

Every report records the selected source and independent coverage availability, visibility, evidence forms, filter support, and integrity for each layer. A missing collector is never represented as a zero counter. The full evidence semantics are defined by ADR-0002.

## Alternatives Considered

### Require Linux 5.18+

This would simplify the BPF implementation and provide useful skb drop reasons, but fails the explicit Linux 4.14 requirement.

### Use Aya for all BPF code

This would make the source almost entirely Rust. libbpf has a more mature compatibility path for CO-RE, perf buffers, and old enterprise kernels, while the user allowed a small C probe layer.

### Maintain one universal BPF object

A single object cannot safely assume both old tracepoint layouts and modern reason/ring-buffer support. A failed relocation or unsupported map would disable otherwise usable diagnostics.

### Infer features from the kernel version

Distribution backports make version-only checks both falsely positive and falsely negative.

## Consequences

- Userspace models and JSON stay common across all kernels.
- The build produces one small BPF object per accepted tracepoint layout/transport combination and tests each compatibility tier.
- Linux 4.14 reports host-wide skb-free/protocol observations and counter deltas, not modern reason attribution; unknown frees cannot create drop Findings.
- New tracepoint layouts deliberately lose BPF coverage until their fields are reviewed and a matching object/test is added.
- The compatibility matrix must include 4.14, 5.4, 5.15, 5.16, 5.17, 5.18, 6.1, 6.2, 6.6, 6.11, and a current kernel.
- Collector and transport loss telemetry is part of the public report contract.
