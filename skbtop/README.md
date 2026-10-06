# skbtop

`skbtop` v0.1.1 measures observed Linux skb path latency for IPv4/IPv6 local
INPUT, local OUTPUT and route/NAT or bridge forwarding. It splits elapsed
latency into stack processing, egress queue and total, with rates and latency
distributions for each interface or directed interface pair.
Measurements span the stated observation points, not the skb's entire lifetime.

User documentation: [中文](../docs/zh/skbtop/README.md) |
[English](../docs/en/skbtop/README.md).

## Installation

The canonical [skbtop-release](https://github.com/calcky/tools/releases/tag/skbtop-release)
contains static musl executables for ARMv7 hard-float, ARM64 and x86_64,
along with `SHA256SUMS`. Install the x86_64 executable as `skbtop`:

```sh
mkdir -p "$HOME/.local/bin"
curl -fL https://github.com/calcky/tools/releases/download/skbtop-release/skbtop-linux-x86_64 -o skbtop
install -m 755 skbtop "$HOME/.local/bin/skbtop"
```

Add `$HOME/.local/bin` to `PATH`.

For a local source build, use Rust 1.96 (the release workflow version), a C toolchain, clang
with the BPF target, libbpf headers, libelf, zlib, zstd and pkg-config
development packages. The native build follows the other libbpf-based tools;
it is separate from the workflow's fully static musl build.

From the repository root:

```sh
make skbtop
make install-skbtop PREFIX="$HOME/.local"
skbtop -h
```

`make skbtop` copies the executable into `bin/skbtop`.
Add `$HOME/.local/bin` to `PATH`. Runtime tracing requires root, BPF/tracing
permissions, kernel BTF at `/sys/kernel/btf/vmlinux` and the receive,
IP/bridge, queue and driver hooks used by the observer. Run inside the desired
network namespace. Static userspace binaries still depend on these kernel
facilities; missing required hooks and attachment failures are reported.
Linux 6.6 alone is not a compatibility guarantee. The running kernel must
expose the required BTF tracepoints, BTF types and function targets and support
the collector's attachment mechanisms; a compiled symbol alone is insufficient.

## Usage

```text
skbtop [-i IFACE] [-d SEC] [-c N] [-T SEC] [-m N] [-g N] [-o DIR] [-h/-v]
```

```sh
skbtop
skbtop -i eth0,eth1
skbtop -i eth0 -i eth1 -d 0.5
skbtop -c 5
skbtop -c 60 -T 60 -o capture
skbtop -i eth0,eth1 -m 262144 -g 4096 -c 10 -o capture
skbtop -h
skbtop -v
```

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Comma-separated or repeated interface selection. Default: all non-loopback interfaces in the current network namespace. |
| `-d SEC` | Refresh/sample interval in seconds; default `1`. |
| `-c N` | Print N plain-text interval snapshots instead of opening the UI. |
| `-T SEC` | Capture duration in seconds. |
| `-m N` | Combined capacity for inflight origin and transmit associations; default `262144`. This is an association budget, not a packet count. |
| `-g N` | Directed path map capacity; default `4096`, not a grouping mode. |
| `-o DIR` | Record interval JSONL, `summary.json` and standalone `report.html`. |
| `-h` | Help. |
| `-v` | Version: `skbtop 0.1.1`. |

Interface discovery remains active throughout capture. New, removed and
renamed devices and reused ifindices are tracked as interface lifecycles;
statistics retain the identity of the interface lifetime they describe.
The `unregister_netdevice_queue` probe disables tracking immediately on device
removal. Device identity cookies and a new generation prevent a reused ifindex
from inheriting the old device's observations.
The default scope is the current network namespace, not the whole host.

Without `-c`, the live UI requires a terminal. `-T` bounds duration without
selecting text mode; scripts and redirected captures should use `-c N`.
Required bridge probes, including `br_dev_queue_push_xmit`, need built-in
Linux bridge support or a loaded bridge module and an attachable function target.

The live view has INPUT, OUTPUT and FORWARD sections. Local traffic is grouped
by interface. Forwarding is grouped by interface pair, with separate rows for
each direction and a row for same-interface hairpin forwarding. It
distinguishes route/NAT and bridge forwarding within the path statistics.
Rates use the actual interval; latency distributions use complete skb samples
and timestamps across CPUs, not sampled function durations.

Use `Tab`/`Shift-Tab` to focus sections, arrow keys or `j/k` to select rows,
and PageUp/PageDown or Home/End to navigate. Click a column header to sort
all three sections by that metric and focus the clicked section. A new numeric
column starts descending; PATH starts alphabetical. Click again to reverse;
the active header shows an up/down arrow. Sorting returns to the top.
`s` cycles OUT bandwidth, OUT PPS and total average; `S` reverses the order.
Mouse sorting requires a terminal supporting mouse events.
`/` searches interface/path names. `Enter` opens interval
and cumulative details, `Esc` returns or clears the filter, and `q` quits.
Display navigation and filtering do not limit recording.

## Traffic columns

IN and OUT describe the start and end of the **same directed path**.
For `eth0 -> eth1`, both describe that direction; `eth1 -> eth0` is a separate row.

| Column | Meaning |
| --- | --- |
| `IN bit/s` / `IN PPS` | Start-hook skb bytes (times 8) / skb observations, divided by the actual interval. |
| `OUT bit/s` / `OUT PPS` | End-hook skb bytes (times 8) / completed skb observations, divided by the actual interval. |
| `Avg` | Mean elapsed time for each stage in the current interval. |
| `Min` / `Max` | Minimum / maximum elapsed time for each stage in the current interval. |
| `Newest` | Each stage's latency for the most recently completed sample, selected by its monotonic completion observation timestamp. Stages with missing or mismatched completion timestamps display `-`, rather than mixing different samples. Older recordings without these fields also show `-`. |
| `PEND` | Queued transmit associations without a completion or retirement yet. |

Latency headers have two levels, with all values in microseconds (`us`):

```text
INPUT
   Avg  |   Min  |   Max  | Newest
    S   |    S   |    S   |    S

OUTPUT / FORWARD
       Avg       |       Min       |       Max       |      Newest
  S    Q    T    |  S    Q    T    |  S    Q    T    |  S    Q    T
```

`S = Stack`, `Q = Queue`, `T = Total`. INPUT records and displays only S;
OUTPUT and FORWARD retain S/Q/T. Total is measured independently;
stage minima or maxima must not be added to infer Total minima or maxima.
Click the lower S/Q/T header to sort by that specific stage and statistic.
The footer spells out the selected metric, such as `Queue max`.
When another section selects Queue or Total sorting, INPUT uses the
corresponding Stack metric and its S header shows the sort arrow.

INPUT always has one S column under each Avg/Min/Max/Newest group.
OUTPUT and FORWARD show S/Q/T from 120 columns; below that width,
they show only T. Details and text snapshots retain each path's applicable
stages. From 160 columns, IN rates and PEND also
appear, with bandwidth and PPS columns adjacent to their counterparts.
Vertical lines separate columns; each group title spans its three stage columns.
Large latency values use scientific notation when needed, still in us.
Maxima are highlighted separately for each rate and latency column;
Min highlights the smallest measured minimum. FORWARD directions
remain adjacent for every sort: IN/OUT rates and PEND use the pair sum;
Min uses the smaller minimum, and other latency columns use the larger value
of the two directions. Missing latency
samples stay last in either order. Default sorting uses OUT bandwidth descending.

Path IN counters are booked when delivery or the first egress queue identifies
the path, using the length saved at its start. OUT counters are booked at local
delivery or a successful driver result. The two bookings can land in different
intervals. Header changes, bridge branches and GSO can also change counts or
sizes. Neither IN minus OUT nor a smaller OUT rate is a packet-loss measurement.

## Latency semantics

All latency values use microseconds (`us`). Each distribution reports its
sample count, min, average, approximate histogram percentiles and max.
Min, average and max use the exact observed timestamp differences;
percentiles are histogram estimates. No completed samples means no measured
latency, not a zero-latency path.

The histogram has four bins per power-of-two latency range, with roughly
14-25% relative bin width. Percentiles use bin upper bounds constrained by
the observed min/max.

Byte counts use `skb->len` at each hook: RX core commonly excludes L2,
driver TX commonly includes L2, and INPUT protocol dispatch may exclude IP
headers, so differing ingress/egress byte counts do not establish loss.

| Path | Start | End |
| --- | --- | --- |
| INPUT | `tp_btf/netif_receive_skb` inside RX core | `fentry/ip_protocol_deliver_rcu` (IPv4) or `fentry/ip6_protocol_deliver_rcu` (IPv6) |
| OUTPUT | `fentry/__ip_local_out` (IPv4) or `fentry/__ip6_local_out` (IPv6) | `tp_btf/net_dev_start_xmit` for an attempt later confirmed successful |
| FORWARD | `tp_btf/netif_receive_skb` inside RX core through route/NAT or bridge forwarding | `tp_btf/net_dev_start_xmit` for an attempt later confirmed successful |

`tp_btf/net_dev_queue` divides STACK and QUEUE: `__dev_queue_xmit()` triggers
`trace_net_dev_queue(skb)` after egress netfilter/TC, before qdisc processing;
the BPF handler is `on_queue()` -> `enqueue()`. `xmit_one()` triggers the
driver start/result tracepoints. `tp_btf/net_dev_xmit`
confirms the attempt with `NETDEV_TX_OK`; its return timestamp is not the
latency endpoint. Route classifiers are `fentry/ip_forward` and
`fentry/ip6_forward`; bridge classifiers use the `br_*` hooks.
See [observation hooks](../docs/en/skbtop/hooks.md) or
[观测钩子](../docs/zh/skbtop/hooks.md) for all path diagrams, accounting points,
bridge probes, clone/GSO tracking and cleanup hooks.

The BTF-typed receive tracepoint is emitted directly inside
`__netif_receive_skb_core`, including list receive paths. The collector does
not require that function to have an fentry BTF target, but the tracepoint
must expose its BTF type.
The IPv6 endpoint is protocol dispatcher entry at `ip6_protocol_deliver_rcu`,
which can precede extension header processing. Subsequent protocol handlers,
socket waiting and application work are outside this boundary.

For OUTPUT and FORWARD, stack time ends at egress queue entry, queue time
continues to the successful driver attempt's entry, and total time spans both.
Queue time includes egress scheduling and transmit retry delays; it is not
pure qdisc residence time. The endpoint is neither the driver's return nor
hardware completion or an on-wire timestamp. INPUT has no egress queue stage.

INPUT excludes NIC reception, NAPI/GRO and RPS work before RX core entry,
socket waiting and application processing. Stack time is elapsed time,
not CPU utilization. NAT may rewrite headers during one traversal; the
statistics describe skb paths, not connection RTTs.

## Recording and coverage

INPUT tables, details and HTML charts use only Stack. JSON latency arrays
retain the Stack/Queue/Total order; INPUT's Queue/Total slots have zero samples
and empty distributions.

The recorder retains interval snapshots in `snapshots.jsonl` and cumulative
path and interface statistics in `summary.json`. `report.html` is a standalone offline
report without external runtime assets and includes every captured directed
path, including rows outside the live terminal's visible area.
Chart history may be thinned to bound report size; full snapshots remain in
JSONL and all path summaries are retained. Existing recording files are not
overwritten, so choose a new output directory for another capture.

The inflight origin/transmit associations and directed path maps have finite
capacities set by `-m` and `-g`. `-m` budgets the combined origin and transmit
association entries, not a number of packets. Health counters disclose
capacity, tracking and accounting errors; inspect them before treating rates
and latency distributions as complete.
Unfinished, freed or untrackable skbs do not become successful latency samples.
Clones and GSO segmentation support identity propagation within the bounded
tracking capacity. skb counts need not equal wire-packet counts.

Normal traffic counters use compact 64-byte per-CPU interval records. Each
completion updates the applicable stages (INPUT: S; others: S/Q/T) in one
per-CPU latency record. Userspace
merges CPU shards, safely retired intervals and the current open interval for
lifetime counters and distributions, without averaging percentiles. This
avoids duplicate lifetime traffic writes and reduces shared-counter contention.
Active writers protect intervals from premature removal. Traffic and latency
maps each allow four entries per configured path, keyed by path and epoch;
their per-CPU memory scales with the kernel's possible CPU count. Slow readers
or delayed intervals can exhaust either map and trigger `interval_capacity`.
Shared path fallback retains affected cumulative counters or latency samples,
but affected interval statistics remain incomplete. Global traffic counters
are also per-CPU; Pending and the association budget remain shared.

Userspace reuses batch buffers and merges borrowed CPU slices as each batch is
read, rather than copying the whole interval map. Empty latency shards do not
allocate histograms. Retired keys are deleted only after the complete traversal.
The batch scratch target is 4 MiB; a single per-CPU entry or a crowded hash
bucket can require more. This is not a limit on BPF maps, cumulative statistics
or total process memory, and does not reduce timing coverage.

Kernel helpers reuse the live configuration within an event and reuse the
reserved counter for insertion rollback. Configuration fields are read live,
including the capacity check after atomic admission and the stop/parent checks
between GSO children. Pointers are reused only within the current invocation;
global budget and retirement accounting retain their existing semantics.
Timing coverage is unchanged.

Queue and driver-attempt hooks reject unselected namespaces and interface
lifetimes before looking up skb associations. The hooks still run system-wide;
this avoids unrelated hash lookups without reducing timing coverage. Retirement
continues to use skb identity, since its device can change before it is freed.

Health counters describe observation coverage, not network loss:

| Counter | Interpretation |
| --- | --- |
| `association_capacity` | Combined origin/transmit budget exhausted; associations cannot be tracked. |
| `unrecorded_path_events` | Directional event omitted because the path map is full; existing paths and global traffic counters remain recorded. |
| `interval_capacity` | Interval statistics storage failed; affected interval counts/latency are incomplete. Recorded paths retain cumulative counters and fallback latency samples. |
| `late_interval_records` | A completed interval was deferred by an active writer and collected in a later snapshot. Its samples remain in cumulative distributions; the affected time-series intervals are delayed. |
| `map_update_failure` | Tracking-map update failed; no timers are used. |
| `unsupported_conversion` | Transformation or tracking-depth limit prevented complete correlation. |
| `unclassified_forward` | Successful FORWARD completion lacked route/bridge classification; totals and valid endpoint latency remain available with unknown forwarding classification. |
| `expired_associations` / `unknown_exit` | Association aged out, or an origin was freed without an observed completion/known queued exit; neither measures network loss. |
| `driver_busy` | Driver retry diagnostic, not loss. |
| `freed_before_completion` | Observed free of a tracked queued skb before its endpoint, not wire loss. |
| `unmatched_queue` / `unmatched_result` | Queue or driver-result event lacked a matching association. |
| `integrity` | Tracking/accounting consistency check failed. |
| `newest_contention` | A bounded latest-sample update could not complete under concurrent/nested tracing. Other latency statistics continue; Newest stays unavailable until a newer valid sample is recorded. |

IPv4/IPv6 fragmentation and reassembly are currently not fully correlated.
Independent `fragmentation` and `reassembly` counters flag these transformations;
tracked affected skbs are excluded from latency samples. Newly allocated
fragments can be unmatched. These counters disclose correlation gaps, not
measured fragmentation/reassembly latency.

Stale inflight associations expire after 30 seconds, with cleanup once per
second independently of `-d`, for approximately 31 seconds maximum retention.
Expiry is reported and does not produce a successful latency sample. The
collector runs an unattached socket-filter cleanup program through
`BPF_PROG_TEST_RUN` to iterate and expire associations. This maintenance
requires kernel support for that operation, injects no network packets and
changes no network configuration. With no inflight reservations, cleanup
skips hash-map traversal; newly admitted records are checked on a later sweep.

XDP, AF_XDP, hardware-offloaded bypass traffic and non-IP local INPUT/OUTPUT
are outside scope. Socket/application latency, NIC or hardware transmit
completion and end-to-end network latency are not measured.

## Development and static builds

From the repository root, run the formatting, test and lint checks:

```sh
make check-skbtop
```

The Makefile uses `pkg-config --variable=libdir libelf` to locate native
libraries and passes `LIBBPF_SYS_LIBRARY_PATH` for static libelf linkage. Override
`SKBTOP_LIB_DIR` if the development libraries live elsewhere.

Dual-stack routed and bridged network namespace fixtures and capture commands
are in [tests/README.md](tests/README.md).

The workflow runs `cargo fmt -- --check`, `cargo test --locked` and
`cargo clippy --locked --all-targets -- -D warnings`. Build artifacts are
checked for the target ELF machine, absence of an interpreter and dynamic
dependencies, and executable help/version startup before upload.

`libbpf-rs` uses its `static` feature. The Cross Dockerfiles follow droptop's
musl pattern with static libelf, zlib, argp and zstd under
`/opt/skbtop/lib`. libelf's bundled `crc32.o` is removed to avoid the
duplicate definition with zlib. zstd is built for each target compiler from a
checksum-verified archive.

The ARM64 build runs the Cross musl toolchain in an Ubuntu 24.04 host image.
This keeps Rust build scripts compatible with the host libc while the final
executable remains statically linked against musl.

The BPF object is portable across the three target CPU architectures. Compile
it on the build host with `clang -target bpf -mcpu=v3` for BPF atomics, without
a target architecture macro, then pass its path through
`SKBTOP_BPF_OBJECT`. `v3` selects the BPF instruction set, not the host or
target CPU architecture. This environment variable supplies a build-time
object to embed; it is not a runtime CLI option.
For example, from `skbtop/` with Cross 0.2.5 and Docker available:

```sh
mkdir -p target
clang -target bpf -mcpu=v3 -O2 -g -Wall -Werror \
  -I/usr/include/$(cc -dumpmachine) \
  -c bpf/observe.bpf.c -o target/observe.bpf.o
SKBTOP_BPF_OBJECT=target/observe.bpf.o \
  LIBBPF_SYS_LIBRARY_PATH=/opt/skbtop/lib \
  LIBBPF_SYS_EXTRA_CFLAGS=-I/opt/skbtop/include \
  RUSTFLAGS="-C target-feature=+crt-static" \
  cross build --release --locked --target x86_64-unknown-linux-musl
```

The other Cross targets are `armv7-unknown-linux-musleabihf` and
`aarch64-unknown-linux-musl`. ARM binaries require ARMv7 with the hard-float
ABI. The workflow uses QEMU for ARM/ARM64 help and version checks; those checks
do not validate kernel probe attachment or packet latency on target hardware.
