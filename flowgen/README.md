# flowgen

Linux TCP/UDP session-load generator with a paired equal-length echo server,
per-session request pacing, binary recording and offline RTT analysis.
Requires Rust 1.88 or newer to build. Ordinary loopback tests need no sudo.

```sh
cargo build --release
cargo test
```

## Run

Start the server, then run either client example in another terminal. Each
`-o` directory must be fresh; choose a new name when repeating a run.

```sh
./target/release/flowgen -s -p 11112 -w 1 -o results/server-1

# Fixed: ramp to 100 ready sessions over 2 seconds, then send for 10 seconds.
./target/release/flowgen -u -c 100 -a 2 -r 20 -T 10 -w 1 \
  -P 20000-29999 -o results/fixed-1 127.0.0.1

# Churn: same ramp, then replace 20 sessions/s while targeting 100 ready.
./target/release/flowgen -t -c 100 -a 2 -U 20 -r 20 -T 10 -w 1 \
  -P 20000-29999 -o results/churn-1 127.0.0.1

./target/release/flowgen -R results/churn-1
```

Use `-6` on both endpoints for IPv6 (for example, target `::1`). Both data
protocols require a TCP control connection to the same server port. No load
requests are sent until all initial sessions are ready. Missing warmup slots
receive paced admission attempts within a bounded `a + W` grace window;
missed slots never trigger catch-up bursts or unbounded retries. Warmup fails
if the readiness target cannot be reached within that window. Churn drains an old
session before admitting its replacement, so setup/drain delays can create a
temporary ready-session deficit. Ctrl+C stops scheduling and drains outstanding
work before recording and reporting finish.

## Options

| Option | Meaning (default) |
| --- | --- |
| `-s` | Server: TCP control/data and UDP on one port |
| `-t` / `-u` | Client data protocol; select exactly one |
| `-c N` | Client target sessions (1000); client-only |
| `-a SEC` | Positive warmup duration (10) |
| `-U RATE` | Replacements/s after warmup (0: fixed mode) |
| `-r RATE` | Requests/s **per ready session** (10) |
| `-l BYTES` | Application message length including header, 48..65507 (128) |
| `-T SEC` | Load duration excluding warmup (60) |
| `-W SEC` | Setup, request and drain timeout (1) |
| `-w N` | Workers (default up to 4, depending on available CPUs) |
| `-L MODE` | Recording: `events`, `summary`, or `off` (`events`) |
| `-A CPUS` | Pin workers to CPUs, for example `0-3,8` |
| `-S BYTES` | Requested TCP/UDP send buffer size |
| `-D BYTES` | Requested TCP/UDP receive buffer size |
| `-b COUNT` | TCP listen backlog on the server (4096) |
| `-B IP` | Source IP; repeatable, already configured on this host |
| `-P LOW-HIGH` | Source ports (Linux ephemeral range); reserved ports excluded |
| `-Q SEC` | Permit reuse after a positive cooldown; fresh tuples first |
| `-p PORT` | Listen/destination port (11112) |
| `-4` / `-6` | Address family (IPv4) |
| `-o DIR` | Raw recording directory (unique path under `results/`) |
| `-R DIR` | Offline analysis only; no other runtime arguments |
| `-h` / `-v` | Help / version |

Times accept fractional seconds. Server mode accepts `-s`, `-w`, `-L`, `-A`,
`-S`, `-D`, `-b`, `-p`, `-4`/`-6` and `-o`. The server does not impose a session count limit,
either globally or per run. Client `-c` controls the target; replacement
registrations can overlap old sessions still being closed by the server.
Actual capacity depends on available memory and `RLIMIT_NOFILE`; provision the
file limit for the expected TCP connections before starting. Client preflight
checks arithmetic overflow and resource capacities without imposing a fixed
application-memory ceiling. Server startup checks only
worker/control descriptor overhead. Protocol validation, pending-registration,
control-run and buffer/queue protections remain in place. flowgen does not change
sysctls, addresses or file-descriptor limits automatically.
Clients use `min(requested workers, target sessions)` effective workers.

## Capacity And Measurements

Source tuples are not reused within a run by default, including failed
attempts. For one destination, provision at least `N + ceil(U*T)` usable
source-IP/port combinations, plus repair/failure headroom. For example,
50,000 sessions and 10,000 replacements/s over 60 seconds need 650,000 tuples
before headroom. One source IP is insufficient. `-B` and `-P` expand the pool;
occupied/reserved ports reduce usable capacity. Known insufficient capacity is
rejected before warmup. In default no-reuse mode, runtime exhaustion stops
admissions/healthy rotations while existing traffic continues. With `-Q`, a
fully occupied pool can retire a healthy session to start its cooldown, then
refill on a later repair slot. Small pools can therefore create ready deficits
and reduce achieved turnover below `-U`. `-Q` does not bypass TCP TIME_WAIT or
prove that a DUT has expired its connection state.

All valid data requests receive an unchanged, equal-length application echo.
At steady readiness the target rate is `N*r` messages/s, **not wire PPS**:
TCP can segment/coalesce messages and UDP can fragment. Echo traffic adds a
response stream of the same application size; framing is included in `-l`.

Periodic output shows phase, ready/target/deficit, connecting/draining sessions,
open/ready/close rates, request/response msg/s and Mbit/s, pending/timeouts,
failures, local limits/skips, tuple use/reuse and rotations/repairs. Server
observations are labeled separately. Final client counters include sent,
received, timeout, canceled, duplicate, late and reordered responses.

`skipped send/session` separates missed request slots from missed session
creation/replacement slots; neither is network loss. Offline `skipped` counts
request slots and `session_skipped` counts session slots, including warmup.
Overdue requests are not sent in a catch-up burst; subsequent deadlines retain
each session's original phase instead of synchronizing after a stall. Send-buffer or pending-request
limits are reported as `limited`.

Workers maintain local traffic counters and publish cumulative snapshots about
every 100 ms; session readiness remains live for warmup coordination. Final
counters are published when workers exit. Request and receive buffers are reused,
and TCP decoding borrows complete frames from the receive buffer. Each session
has at most one request deadline, tracking its oldest outstanding request or
partial send. Completed requests cancel or advance that deadline.
Outgoing requests reserve capacity before writing, including writes blocked
before their first byte. Such writes expire after `-W`; RTT still starts at the
first successful write. Buffer reuse retains a small amount of per-session
memory to avoid allocating a fresh message for every request.

Client sessions use indexed slots with generation-checked event tokens. Reusing
a slot cannot deliver an old socket event or timer to its replacement. The
oldest pending request is stored inline, without a per-session hash allocation;
overlapping requests use reusable overflow storage. Out-of-order completions
still advance to the oldest live request, and completed sequence metadata stays
bounded even while an earlier response is missing.

Server traffic counters accumulate locally and publish to independent
cache-aligned worker slots about every 100 ms. Counters are also published
before releasing a flow or acknowledging retirement, so final reports include
all completed traffic. TCP/UDP queued reply storage is reused from a
worker-local cache, capped at 1 MiB, 512 buffers and 32 message lengths in
addition to the existing live queue limits. UDP uses nonblocking
`recvmmsg`/`sendmmsg` batches of up to 32 packets, with about 2 MiB of receive
storage per worker. Valid DATA with no queued reply is echoed directly from
the receive batch, without copying payloads or allocating queue entries.
Only unsent replies enter the bounded queues, preserving per-flow order.
It never waits to fill a batch; only the successful send
prefix is counted and released, and the unsent suffix keeps its original
deadline. Truncated input counts as invalid.

Client shutdown retires sessions in batches while continuing to receive and
expire outstanding requests. UDP turnover uses a bounded reliable control queue;
backpressure pauses admissions while workers retain unsent retirement IDs and
continue processing traffic. Final shutdown uses one reliable END barrier instead
of a CLOSE datagram and control entry for every remaining session.
The server acknowledges each retirement batch after its data workers have
processed it, so a slow owner applies backpressure instead of filling another
queue. Reliable retirement also rejects a delayed OPEN for that session.
END stops new admissions and wakes data workers for teardown before returning
final request/response counts. Errors after the run has ended and all its data
owners have closed remain visible in global server counters, outside that run's
final report. Final teardown uses a separate timeout of `max(30s, -W)`; ordinary
request timeouts retain the configured `-W` value.

Both protocols measure complete request/response RTT using the client's
monotonic clock. TCP RTT includes stream delivery and retransmission delays;
TCP failures/timeouts are not a UDP packet-loss percentage. UDP response
reordering is measured per session and cannot identify the impaired direction.
Jitter is the absolute RTT difference between adjacent request sequence
numbers within one session, only when both complete on time. It is not
one-way jitter, and missing requests break the pair.

The offline terminal report separates summary, latency and diagnostic tables
with blank lines. Metrics are never hidden to force a one-screen layout.
A compact table shows each group's
sessions, request/response record counts, unique timeouts, timeout percentage
and logging status. Client latency rows show RTT, per-session mean RTT (`Mean`),
setup time and adjacent-sequence RTT jitter; `N` is the sample or pair count.
Each group's details show event counters, session/scheduling counters, timeout
accounting and recording quality in two pairs of columns, including zero counts.
Labels and values are aligned separately. Tables have closed ASCII borders,
with a divider between columns and a rule below the header.
The two detail tables sit side by side when the terminal is wide enough
(162 columns for typical counts), and stack vertically otherwise. For redirected
output, `COLUMNS` selects the layout width; the fallback is 120 columns.
On a color terminal, headings are bold cyan and Avg/Max/P99 are bold.
Nonzero failure and recording-error counters are red; late, reordered, canceled,
limited and skipped counters are yellow. Zero detail counters are dimmed.
Set `NO_COLOR` to disable styling. Redirected output and `TERM=dumb` remain plain.
All three slowest sessions retain their run/flow identifiers, sample counts and
logging status. `INCOMPLETE` and unavailable timeout reasons remain visible.
Latency values are rounded to fit, with scientific notation for extreme values;
counts and output paths are displayed in full. Redirected output uses the same
format without terminal control codes. CSV and raw event files retain
nanosecond precision. Timeout percentage is a request/response failure metric,
not a directional packet-loss claim. When both endpoint recordings and their
matching end manifests are available, `-R` also produces UDP forward delivery
and missing-rate reconciliation.

## Recordings

Per-worker `*.fgr` files contain versioned binary lifecycle/measurement events,
not payload captures. Clients also write `run.txt`, `tuples-*.csv` and, when
available, `server-final.txt`. Analysis runs after a client finishes; `-R DIR`
repeats it without generating traffic and writes `sessions.csv`, `summary.csv`
and `recordings.csv`, plus `errors.csv` (and `forward.csv` and `forward-summary.csv` when
reconciliation is available). Times in these reports are nanoseconds; `NA` means
unavailable. Server recordings can be analyzed separately after shutdown.

Use `-L summary` when only bounded HDR latency summaries are needed; it writes
per-worker summary CSV files and prints the client aggregate at shutdown. Use
`-L off` to disable recording files and the offline event analysis path while
keeping normal runtime counters and final server accounting.

Client failure diagnostics retain the operation (`socket`, `bind`, `connect`,
`register`, `send`, `receive`, `decode`, `setup_timeout`, `send_timeout`, or
`interest`) and OS errno in raw records. `errors.csv` aggregates these by
run/protocol/role/stage/errno. Errno 0 means no OS errno was available; diagnostic
events do not increment the separate failed-session count. Existing v1 recordings
remain readable; older records have no inferred error details or session skips.

RTT distributions include only first on-time completions. Late/duplicate
responses and timeouts remain separate counters. Message-weighted quantiles
and the distribution of per-session mean RTT are different statistics. HDR
quantiles use three significant digits (approximately 0.1% precision), not
exact sorted percentiles. All retained eligible samples are used; sparse
samples and omitted/failed responses limit tail interpretation.

Record to a sufficiently fast local disk with space for both endpoint event
streams. Bounded asynchronous buffers can drop events under disk pressure;
logging gaps, truncation and corruption mark analysis incomplete. Missing
records are not network loss. Offline sorting also needs temporary disk space.
The network thread encodes directly into reusable batches; the writer computes
checksums in batches before writing. The v1 file bytes, checksum validation and
drop/footer accounting are unchanged.

`cargo test --test loopback -- --nocapture` exercises IPv4/IPv6 TCP/UDP fixed
and churn runs, refusal/capacity failures, Ctrl+C with offline replay, TCP frame
faults and a local UDP duplicate/reorder proxy. It allocates ports and temporary
recording directories, reaps child processes on failure, and retains failed
run artifacts under the printed temporary path. IPv6 loopback must be enabled.
