# ADR-0011: Make the Counter-Only TUI the Default Interface

## Status

Accepted

## Date

2026-07-29

## Context

The original binary exposed one-shot `doctor`, `report`, and `replay`
subcommands. The first interactive release instead needs an `htop`-style view
that stays open, samples the host continuously, and lets an operator move among
Socket, Netfilter, TC, Netdevice, NIC, SoftIRQ, and HardIRQ without resetting
the observation baseline.

The repository's report v1-v5 and event-stream v1 models are frozen contracts.
They describe evidence reports, not a long-running monitor: SoftIRQ and HardIRQ
are execution contexts rather than report Layers, and an aggregate kernel
counter must not be presented as per-packet causal evidence. Reusing those
models for the TUI would couple a terminal view to compatibility contracts that
do not express its sampling and history semantics.

The first TUI must also work for an unprivileged user. Loading BPF programs by
default would change privileges, compatibility, resource lifetime, and meaning
of the displayed data based on host capabilities.

## Decision

1. Running `nwdiag` without a subcommand is the only v1 user entry point and
   starts the TUI. The binary does not expose `doctor`, `report`, or `replay`;
   their library models, schemas, fixtures, and regression tests remain in the
   repository as compatibility baselines.
2. The default monitor is counter-only. It does not call the BPF loader,
   capability probe, or event runtime, even when the process has sufficient
   privileges. Any future event overlay requires an explicit user option and a
   separate contract.
3. The monitor owns a terminal-independent model and closed metric catalog.
   Metrics declare their section, kind, unit, source priority, labels, and
   display meaning. Missing, unsupported, stale, reset, wrapped, and recovered
   values remain distinct from zero.
4. A sampling worker owns the process-lifetime baseline and bounded history.
   The TUI consumes immutable snapshots through a latest-value handoff. Pausing
   freezes only the rendered snapshot; collection and history continue.
5. The fixed navigation order is Overview, Socket, Netfilter, TC, Netdevice,
   NIC, SoftIRQ, HardIRQ, and Providers. Number keys, arrows or Tab, and `:`
   commands select views without restarting the session.
6. History starts with this process, never with kernel boot. Counter views show
   interval delta/rate and since-baseline delta/rate. The history store uses a
   fixed number of compacting buckets per admitted series and records gaps and
   resets explicitly.
7. Crossterm terminal state is acquired in stages and released by an RAII
   guard. Non-TTY stdin or stdout fails before raw mode or alternate-screen
   control sequences are written. Session shutdown cancels and joins the
   worker before terminal state is released.
8. `SIGINT` and `SIGTERM` set an atomic termination flag consumed by the TUI
   loop. Signal shutdown stops and joins the worker before restoring the
   terminal, then follows the runtime-error exit path (`3`). A collector panic
   closes the latest-snapshot handoff and becomes a bounded session error whose
   message does not contain the panic payload. The process-wide panic hook
   suppresses output only for the named monitor worker and delegates every
   other panic to the previously installed hook.

## Alternatives Considered

### Keep the Batch Subcommands Alongside the TUI

This preserves more executable surface but makes the first interactive product
carry two different operating models and their option sets. The existing
contracts remain available to library tests without keeping those commands in
the v1 binary.

### Reuse the Report Model for TUI Snapshots

This avoids a second model but forces continuous counter state into a one-shot
evidence contract and would incorrectly turn SoftIRQ and HardIRQ into report
Layers. A separate monitor contract keeps both meanings closed and testable.

### Enable BPF Automatically When Available

Automatic activation makes identical invocations change semantics and resource
requirements across hosts. Keeping v1 counter-only provides predictable,
unprivileged behavior; causal event evidence can be added later as an explicit
overlay.

### Store Every Sample Since Startup

An unbounded vector gives exact recent history but eventually consumes all
memory in a long-running process. Fixed per-series compaction preserves startup
coverage, recent detail, gaps, and resets with a stable memory ceiling.

## Consequences

- The normal workflow is `nwdiag [OPTIONS]`, followed by keyboard navigation;
  scripts that used the removed subcommands must use an older binary or the
  retained library contracts.
- Every section remains visible even when its provider is not implemented or
  unavailable; the UI reports that state instead of manufacturing zeroes.
- The TUI can skip rendered snapshots without losing the worker's baseline or
  history. Provider missed samples and UI skips remain separate telemetry.
- Full history browsing, more kernel counter providers, unified
  input/snapshot/resize wakeup, terminal write-failure gates, long-duration
  soak tests, and optional BPF overlays remain additive work on top of this
  boundary.
