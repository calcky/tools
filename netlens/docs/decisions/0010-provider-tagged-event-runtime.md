# ADR-0010: Coordinate Event Providers Through One Tagged Runtime

## Status

Accepted

## Date

2026-07-29

## Context

The first BPF collector owned its thread, ready channel, duration, fallback, and
join operation in `bpf.rs`. The report command knew that lifecycle directly and
used the global `selectedBpfMode` field to decide whether the `kfree_skb`
provider had an effective scope. That shape cannot isolate the planned UDP and
generic socket queue event providers: one global BPF result could activate an
unrelated provider, and every new adapter would add another start/wait/join
branch to the CLI.

The event paths also need stronger exit semantics. A poll, detach, drain, or
first map-read error previously returned early and skipped later cleanup work.
An event provider must retain validated observations and every counter that is
still readable while allowing other event providers and counter snapshots to
complete.

Linux BPF resources and perf/ring callbacks are local, in-process dependencies.
They have lifetimes that are easiest to keep inside one adapter stack frame;
exposing link, map, or buffer objects across the runtime seam would make the
interface both unsafe and provider-specific.

## Decision

1. `event_runtime` is the single lifecycle module between CLI commands and
   event adapters. Its external interface is the typestate sequence `start`,
   `StartingRuntime::wait_ready`, `PreparedRuntime::begin`, and
   `RunningRuntime::finish`. Dropping any live typestate sends stop to every
   worker before joining them as a best-effort fallback.
2. The runtime starts one worker per selected, implemented adapter and waits on
   one shared ready deadline. Each provider independently becomes ready, fails
   before ready, or times out. Readiness and cancellation are arbitrated by one
   mutex/condition-variable state machine: `Starting -> Attaching -> Ready`,
   `Failed`, or `Cancelled`. The transition into attach, occurrence timestamp,
   deadline decision, and late-result rejection are therefore linearizable.
   Cancellation queries also consult this locked state, so fallback cannot
   start in the interval before the worker's cooperative atomic stop flag is
   published. A provider failure is outcome data and never aborts another
   provider or the counter window.
3. The runtime owns the canonical provider key. Adapters return untagged
   captures; the runtime places each capture under the registration key in a
   stable `BTreeMap`. Adapters cannot attach observations to another
   provider's outcome.
4. The internal adapter seam has one `run` method. Link/map/buffer ownership,
   layout choice, and pre-ready fallback remain in the concrete adapter.
   Loaded adapters delegate attach and execution to the runtime driver. Once a
   buffer exists, the driver always attempts capture disable, detach, drain,
   both independent final counter reads, and then lets lexical ownership
   release buffers and BPF objects. Attach failure and failure or panic in a
   later driver phase do not skip the remaining finalizer phases.
5. Fallback is allowed only before ready. The reason-aware `kfree_skb` adapter
   may fall back to legacy/perf after completely releasing a failed setup. Once
   ready, any poll or cleanup failure produces a partial outcome from that same
   implementation. Cancellation is persistent and checked between expensive
   startup phases and before fallback, so a timed-out provider cannot start a
   second candidate.
6. A ready provider retains validated observations, measured local counters,
   and successful map reads after a later failure. A provider that never became
   ready publishes no capture. Readiness means attach and the pre-window
   Prepare phase succeeded; a later Prime, Start, poll, or cleanup failure keeps
   that identity and produces a partial outcome. Internal unit acknowledgements
   mean that a barrier phase resolved, not that it succeeded. Task 8b2 owns the
   mapping of these values to report `measured`, `unknown`, and
   `not_applicable` statuses.
7. Every BPF object has a default-disabled `capture_control` array map. After
   attach, `wait_ready` sends a common Prepare command that keeps the gate
   disabled and discards pre-window transport contents. `begin` then sends
   Prime to every ready worker; each worker disables and flushes again and
   records local and BPF counter baselines while event production is disabled.
   Only after every Prime phase resolves does the runtime publish one Start
   window and enable successful providers. This prevents a fast provider from
   polling while a slow provider is still establishing its baseline.
8. Provider scope activation uses the ready provider-key set from this runtime.
   `selectedBpfMode` remains in the frozen report contract as kfree-specific
   compatibility information, but it is not an activation input for any
   provider.
9. The Start window has one monotonic deadline and one wall-clock report
   timestamp. Workers stop autonomously at that deadline instead of depending
   on delayed CLI post-processing. The gate is disabled before detach and
   drain. Zero duration, or a Start that has already expired while enabling,
   publishes no observations and reports every readable boundary delta as
   zero. Counter underflow remains an error rather than being coerced to zero.
10. Worker panics are contained per provider. Runtime issues contain only a
    typed phase and kind; report text and worker stderr are fixed, bounded text.
    Raw adapter errors and panic payloads never cross the runtime boundary. The
    panic hook also ignores stderr write failure instead of panicking again.
    The process permanently disables libbpf's default print callback before
    any capability or BPF operation, preventing raw libbpf diagnostics from
    bypassing this boundary.
11. Stop is cooperative. Each BPF poll is bounded to 100 ms, but Rust threads
    cannot safely interrupt an arbitrary stuck libbpf/kernel call. A ready
    timeout classifies and requests cancellation; `finish` still waits for the
    worker to release its resources.
12. Outcomes make no cross-provider or cross-CPU ordering claim. Each adapter
    preserves only the ordering its transport can support.

## Alternatives Considered

### Keep One Worker Type Per BPF Provider

This is direct for one tracepoint but repeats readiness, timeout, panic, stop,
and join behavior in every caller. It also leaves no provider-keyed outcome
contract for failure isolation.

### Wrap the Counter Window in `run_window`

A closure-based single entry point makes the current report path concise and
guarantees cleanup around that closure. It also couples counter collection to
the event runtime and is a poor fit for a later interactive trace session. The
typestate interface preserves the same ordering while keeping the modules
independent.

### Expose `begin`, `poll`, `detach`, `drain`, and `read_counters` on Adapters

This would let the supervisor call every phase directly, but it makes the
internal seam mirror the implementation and forces libbpf lifetime details
into stored trait objects. A one-method adapter plus the shared attached driver
keeps the seam small while still centralizing phase order and panic handling.

### Use Tokio or One Global Poll Thread

The first release has a small static provider set and no async caller. Standard
threads and channels work on Rust 1.82, avoid a runtime dependency, and keep a
blocked or failed provider isolated. A more complex scheduler is not justified
until measured scale requires it.

## Consequences

- CLI commands no longer contain provider-specific worker lifecycle branches.
- New event providers register one adapter and reuse the same readiness,
  prepare/prime/start, deadline, cancellation, cleanup, panic, and outcome
  behavior.
- Provider scope cannot be activated by another provider's BPF mode.
- Partial cleanup results are representable without publishing pre-ready data.
- Event transport, userspace, and BPF map counters share a gate-disabled
  baseline and one declared capture window.
- The runtime permanently installs a redacting panic hook for its named worker
  threads; non-runtime threads retain the previously installed hook.
- Hard cancellation of a stuck kernel operation remains out of scope. Process
  isolation would be required to provide that guarantee.
