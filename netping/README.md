# netping

Linux ICMP, UDP/TCP echo and TCP connection latency in one Rust executable.
UDP and TCP echo use a paired netping server. ICMP uses the operating system's
echo responder; TCP connect can target an ordinary listening TCP port.

## Common commands

```sh
netping 192.168.0.1                         # ICMP, one probe per second
netping -s                                 # Serve UDP + TCP on port 11111
netping -u 192.168.0.1                      # UDP echo
netping -t 192.168.0.1                      # TCP echo on one established connection
netping -C -p 443 192.168.0.1               # TCP connection time
netping -u -c 20 -i .1 192.168.0.1          # 20 probes, 100ms apart
netping -u -b 192.168.0.1                   # 1000 PPS, 10 seconds, per-second reports
netping -t -b -r 100 -T 30 192.168.0.1      # 100 PPS for 30 seconds
netping -t -b -f -T 5 192.168.0.1          # Continuous one-at-a-time ping-pong
netping -s -6 -p 2222                       # IPv6 server
netping -u -6 -p 2222 ::1                   # IPv6 UDP client
netping -w 192.168.0.1                      # Live ICMP + UDP + TCP echo window
netping -w -C -P 443 192.168.0.1            # TCP connect 443; UDP echo 11111
netping -M 192.168.0.1                     # Path MTU discovery using ICMP
netping -M -u 192.168.0.1                  # UDP forward probes, small server ACKs
netping -M -6 2001:db8::1                  # IPv6 Packet Too Big detection
netping -S -p 443 192.168.0.1              # Inspect MSS on an ordinary TCP service
netping -S -t 192.168.0.1                  # Also query a netping server's send MSS
```

The server listens on all local addresses in the selected family; run separate
`-4` and `-6` servers if both families are needed. No configuration files or
runtime are required. UDP/TCP do not need root when using unprivileged ports.
ICMP first tries a Linux ping socket, then a raw socket. If both are denied,
run with `sudo`, grant `CAP_NET_RAW`, or allow the user's group through the
system's `net.ipv4.ping_group_range` policy.

## Options

Only short options are supported. Values are separate arguments; do not combine
switches such as `-ub`. HOST can be an IP address or DNS name; one resolved
address in the selected family is tested for the entire run.

| Option | Meaning |
| --- | --- |
| `-S` | One-shot TCP MSS inspection; `-t` opts into paired-server MSS telemetry |
| `-w` | Live three-protocol window; default TCP echo, replace with TCP connect using `-C` |
| `-M` | Path MTU discovery using ICMP or `-u`; see limits and confidence below |
| `-P PORT` | TCP port override in window mode; otherwise TCP uses `-p`; UDP always uses `-p` |
| `-u / -t / -C` | UDP echo / TCP echo / TCP connect; mutually exclusive; default ICMP |
| `-s` | UDP + TCP server; accepts only `-p`, `-4` and `-6` |
| `-b` | Performance mode: one report per second; default 1000 PPS and 10s |
| `-f` | Continuous ping-pong, at most one request pending; requires `-b` |
| `-p PORT` | Destination or listening port; default 11111; not used with ICMP |
| `-c COUNT` | Maximum send attempts; positive integer |
| `-i SECONDS` | Send interval; default 1s in ping mode, .001s in performance mode |
| `-r PPS` | Send rate; mutually exclusive with `-i` and `-f` |
| `-W SECONDS` | Per-request timeout, and initial TCP echo connection timeout; default 1s |
| `-T SECONDS` | Sending duration; `-c` and `-T` stop at whichever comes first |
| `-l BYTES` | Test payload length including its 32-byte header; default 64; 32..65507, ICMP maximum 65499 |
| `-4 / -6` | IPv4 (default) / IPv6 |
| `-h / -v` | Help / version |

Times are decimal seconds, without suffixes. Intervals have a minimum of 1us;
durations and timeouts have a maximum of 86400s. The maximum configured PPS is
1000000; actual achievable rate depends on the host and network. After the
count or sending duration ends, outstanding requests drain until their
individual deadlines. Ctrl+C/SIGTERM stop immediately and retain pending
requests in the summary.

## TCP MSS inspection

`netping -S -p 443 HOST` opens one ordinary TCP connection and prints:

```text
Local SYN MSS        1300
Peer SYN-ACK MSS     1200
Local send MSS       1188
Peer send MSS        - (requires -S -t and a netping server)
```

All values are TCP payload bytes. SYN and SYN-ACK MSS options advertise each
endpoint's **receive limit**, as observed at the client. Local send MSS is the
connection's current `TCP_INFO.tcpi_snd_mss`, not the peer's raw advertisement.
TCP options and the kernel's path information can reduce it. The example
includes a 12-byte timestamp option. An advertised MSS is not proof that a
data segment of that size can pass; this mode does not confirm path MTU.

Use `netping -S -t HOST` with an updated `netping -s` to additionally obtain
the server's actual send MSS on the same connection. The server reads its
own `TCP_INFO` when processing the query. For the example above it could
report `Peer send MSS 1288`, distinct from its advertised receive limit of
1200. These are snapshots at slightly different times, not maximum observed
packet sizes or a measurement of the reverse path MTU.

`-S` accepts only HOST, `-t`, `-p`, `-W` and `-4/-6`. The default port remains
11111. `-W` defaults to 1 second and bounds connection setup and the optional
server query separately. Without `-t`, no application data is sent, so an
ordinary HTTPS/SSH listener can be inspected. With `-t`, a 64-byte netping
query is sent; use it only with a paired server. The request uses opt-in
payload markers and preserves existing TCP frame sizes and old echo behavior.

Capturing handshake values requires root or `CAP_NET_RAW`. A kernel packet
filter limits ordinary capture to SYN traffic on the chosen client port;
the parser validates addresses, ports, options and the SYN/SYN-ACK sequence
relationship, including IPv6 extension headers. No capture is saved to disk.
Without capture permission, local and paired-server send MSS still work.
Missing captures, an absent MSS option, unsupported old servers and failed
queries show explicit unavailable reasons, never an inferred peer send MSS.
Client-side captures cannot show changes to the outgoing SYN after it leaves
the client; observing both endpoints is needed to locate MSS rewriting.

Exit status is 0 for a successful connection (and available peer send MSS
when `-t` is requested), 1 for connection/query failures or interruption,
and 2 for setup/configuration errors. Missing handshake capture alone does
not fail the command. Ctrl+C retains any results collected so far.

## Path MTU discovery

`netping -M HOST` searches for the largest IP packet that reaches the target
without local fragmentation. IPv4 probes set DF; IPv6 probes disable source
fragmentation. Linux probe mode ignores cached path MTU restrictions so that
each candidate is actually tested up to the local interface limit.

The default search ceiling is **9000 IP bytes**, with 100ms pacing, a 1s
per-probe timeout and a 60s overall limit. `-l` sets the maximum **payload**,
including the test header, as in ordinary ping mode. Add 28 bytes for IPv4 or
48 for IPv6 (no IP options/extension headers). For example, `-M -l 1472 HOST`
searches up to 1500 IPv4 bytes. `-i/-r`, `-W`, `-T` and `-c` remain available;
`-c` limits all probe attempts, including small controls. `-M` cannot be
combined with `-t/-C/-s/-w/-b/-f`; TCP segments application writes itself.

ICMP requires only the target's normal Echo responder. `-M -u` requires an
updated `netping -s`: it confirms each large request with a **32-byte payload
ACK**, carrying the original request size, session and sequence. This reduces
interference from the return path. An older server does not support these
requests; no baseline reply produces an inconclusive result. Ordinary UDP
echo and TCP messages remain compatible with older peers.

Results distinguish evidence:

- `Path MTU = ...`: a matching Too Big error provided the upper bound, and
  the reported size was verified by a successful probe.
- `Path MTU >= ...`: the search ceiling succeeded; no exact limit was found.
- `suspected size limit / MTU black hole`: three attempts failed at a size,
  with successful small control probes between them. A binary search locates
  a candidate boundary, but this is **not a confirmed PMTU**. Size-dependent
  filtering, congestion, or a remote reply policy can produce similar results.
- `inconclusive`: baseline/control probes failed, a network error occurred,
  evidence conflicted, or count/duration/signal limits interrupted discovery.

Matched IPv4 Fragmentation Needed and IPv6 Packet Too Big errors are read
from the socket error queue. Old sequence/session errors are ignored;
unidentifiable truncated errors may therefore fall back to timeout probing.
ICMP Echo also depends on the return path, so a timeout-derived limit cannot
be attributed to the forward path alone. Routes may change during a test.
The final report retains the largest size observed to succeed. Exit status is
0 for a confirmed limit or a verified search ceiling, 1 for suspected or
inconclusive results, and 2 for configuration/runtime errors.

## Live window

`netping -w HOST` tests one resolved IP with ICMP, UDP echo and TCP echo at the
same time. It compares end-to-end measurements, not intermediate router hops.
UDP and TCP echo require `netping -s` on the target. `-w -C` measures TCP
connection time instead; `-P` permits a separate TCP service port such as 443.

The table shows sent/received counts, Loss-Fail%, Last, Avg, Min, Max and Mdev.
ICMP/UDP percentages describe probe loss; TCP percentages describe request
failure, not network packet loss. All latency values are milliseconds. Smaller
windows move Min/Max/Mdev into the protocol details. Three bordered panels
show ICMP, UDP and TCP details simultaneously, including P50/P95/P99, pending
requests, exceptional replies, connection state and the last error. Panels
stack vertically on ordinary terminals and sit side by side at 120 columns
or wider. The focused panel has a highlighted border; errors highlight only
the affected protocol. Focusing a panel never hides the other two. Protocol
titles stay bright and show the connection state on the right. Wide panels
align latency, percentiles and counters in fixed columns. Zero counters are
muted; nonzero failures are red, exceptional replies and local send limits
are yellow, and pending requests are cyan. The last-error line appears only
when an error has been recorded and dims after recovery.
Missing latency is `-`; failed recent probes show `timeout` or `failed`.

The TCP panel also shows **TCP RETRANS**, with cumulative segment counts and
observed counts per second for each direction. `Tx` is the client's send
direction, read from the connection's Linux `TCP_INFO`; `Rx` is the server's
send direction, reported in echo replies. Nonzero values are red. These count
TCP segment retransmissions, not failed probes or application-level duplicate
replies. A request can succeed after retransmission with zero request failure.
The text summary includes `TCP retrans Tx/Rx = .../... segments`.

New TCP retransmissions highlight the table row and panel border in yellow,
with a bold `RETRANS` status even when every request succeeds. The warning
uses newly observed segments and the latest sampling interval, not the
cumulative total; it clears after an interval with no new retransmissions.
Request timeouts show red `TIMEOUT`; a broken or failed echo connection shows
red `DISCONNECTED` throughout reconnection. These errors take priority over
`RETRANS`. A successful request clears the timeout/failure status; historical
counters and the last error remain available. Status labels also work with
`NO_COLOR`.

Echo retransmission counters exclude connection setup and accumulate across
reconnections. Rates use actual monotonic sampling intervals of at least one
second; a fresh interval has rate `-` until sampled. Reset clears both
directions. Connect mode (`-C`) reports client SYN retransmissions from sockets
as they finish, fail or time out; pending sockets are also sampled on exit.
It has no server telemetry, so its `Rx` is `-`.
While reconnecting, the live panel shows `-` until a new connection sample is
available. Previously observed counts remain in the exit summary even when
the final connection attempt fails.

Server telemetry needs an updated `netping -s` and a payload of at least
**40 bytes**; the default 64 bytes already fits. The optional report uses eight
existing payload bytes and does not change frame length or protocol version.
Older servers still echo successfully; older clients receive their original
payload back. An older server, a smaller payload or unavailable kernel data
shows `-`, never a fabricated zero. Server counts are the last reported sample,
so they can lag; retransmissions after the final report or before a broken
connection can go unreported. `Duplicate` and `Reordered` remain application
message statistics and do not measure TCP packet duplication or reordering.

| Key | Action |
| --- | --- |
| Up/Down or `k/j` | Highlight a protocol row and its details panel |
| Space | Pause/resume new sends; continue receiving and timing out pending requests |
| `r` | Restart all three sessions, counters and the duration clock; discard old in-flight requests |
| `q` or Ctrl+C | Exit immediately, restore the terminal and print three summaries |

The default is one probe per second **per protocol**, until exit. `-i/-r`,
`-W`, `-l`, `-4/-6`, `-c` and `-T` apply to all three. Counts are independent
send-attempt limits; the duration uses a shared wall clock and includes pauses.
After count/duration limits, replies drain until their deadlines, then the
window closes and summaries print. Resume never sends a catch-up burst.
`-w` rejects `-u/-t/-s/-b/-f`; `-P` requires `-w`. Window payloads have the
ICMP maximum of 65499 bytes. Existing text and performance modes are unchanged.

Each protocol has independent pending requests and deadlines. ICMP permission
errors leave that row unavailable; `r` retries initialization. TCP echo
reconnects after disconnects, retrying no faster than once per second (or the
configured interval when longer). Outstanding requests on a broken connection
fail once. Connection setup is excluded from echo RTT; setup failures appear
separately as ConnFail. Scheduled attempts during connection setup/retry count
as Skipped and consume `-c`, without increasing Sent or network loss.

The screen refreshes at most four times per second and requires TTY input and
output with `TERM` other than `dumb`. All three detail panels fit at 80x24;
narrower terminals need more height (60x33 also works). Smaller windows show
a resize prompt while probes continue. `NO_COLOR=1`
disables colors while preserving bold and textual error indicators. Redirected
output is supported by text modes; `-w` rejects it before changing the terminal.
Window exit status is 0 if every protocol has at least one successful result
and none is unavailable, otherwise 1. Configuration/runtime errors return 2.

## Reading results

Ping mode prints `seq=... rtt=... ms`, `timeout`, `late` or `duplicate`.
An out-of-order successful reply appends `reordered` to its RTT line.
TCP connect prints `connect=... ms`. All latency values are milliseconds;
RTT is the complete round trip, not RTT/2. TCP echo excludes connection setup.
Measurements use the client's monotonic clock; no clock synchronization is needed.

Performance mode reports actual TX/s and RX/s plus application payload
TX-kB/s and RX-kB/s over the reporting interval. Bandwidth uses decimal kB
and excludes IP/transport headers, ICMP headers and TCP framing; TCP kernel
retransmissions are reported separately. It also reports pending requests,
interval TIMEOUT/FAILED counts, cumulative LOSS% or FAIL%, and interval
minimum, average, P99 and maximum latency. The final summary adds total
payload bytes and average kB/s plus Mbit/s. The final partial interval is also
printed. Text/performance output is plain text suitable for redirection.

- `sent`: requests sent, or TCP connection attempts. Local send errors also
  count as attempts and are included in `failed`.
- `received`: the first valid reply before its deadline, or a successful connection.
- `timeout`: no valid reply/connection before the deadline.
- `failed`: immediate send/connect errors, or outstanding requests lost on TCP disconnect.
- `pending`: still outstanding; excluded from loss/failure percentages.
- UDP/ICMP `loss`: `(timeout + failed) / (received + timeout + failed)`.
- TCP `failure`: the same request-level calculation. TCP retransmission means
  this is not a network packet loss measurement.
- `reordered`: a first valid reply before its deadline with a sequence lower
  than the highest sequence already received successfully. It still counts
  as received and contributes to RTT statistics. Late, duplicate and invalid
  replies neither increase this counter nor advance the highest sequence.
  For TCP, this describes application reply order (or connection completion
  order in connect mode), not TCP packet reordering on the network.
- `late` and `duplicate`: recognized replies excluded from normal RTT statistics.
  A late reply remains a timeout; another copy of that late reply is a duplicate.
- `invalid`: unrelated sessions, malformed replies or unrecognized sequences;
  packets from unrelated peers are normally filtered by the connected socket.
- `limited`: a send slot could not be used due to socket pressure or the in-flight cap.
- `skipped`: pacing slots missed due to scheduling/processing delays. They are
  not sent in a catch-up burst and are not counted as network loss.

The final summary adds population standard deviation (`mdev`) and P50/P95/P99. Quantiles use a
three-significant-digit histogram with microsecond resolution; min/avg/max and
standard deviation retain the clock's finer resolution. No per-packet history
grows with test duration. There are at most 8192 in-flight requests and a
65536-entry recent-result ring; older unmatched replies count as invalid.

Example summary (all latency values, including percentiles, are in ms):

```text
--- UDP statistics | 0.261 s ---

  Sent             14   Received         12   Loss         14.29%
  Timeout           2   Failed            0   Pending           0
  Reordered         1   Duplicate         1   Late              1
  Invalid           1   Limited           0   Skipped           0

  rtt min/avg/max/mdev = 0.096470/3.435260/39.264757/10.803078 ms
  Percentiles P50/P95/P99 = 0.163/39.265/39.265 ms
```

No successful samples produce `-` latency cells. TCP uses `Failure` instead
of `Loss`; connect mode labels its latency as `connect` instead of `rtt`.

Fixed-rate probes continue while earlier probes are pending. Continuous
ping-pong waits for the current reply or timeout before sending the next.
With `-c`, locally limited send slots still consume attempts, so the printed
`sent` count can be lower than `-c`. A TCP partial write cannot be discarded
without corrupting the stream; if that request expires, the connection closes.

Exit status: 0 when at least one request succeeds and the transport remains
usable, 1 for no successful requests or an interrupted TCP transport, and 2
for configuration, setup or runtime errors. Some packet loss can still return 0.
The server exits 0 on Ctrl+C/SIGTERM.

## Protocol and limits

The new binary protocol is independent of the existing Python tools, sockperf
and IRTT. It validates a version, session ID, sequence and payload length.
UDP has one message per datagram; TCP adds a four-byte network-order frame length.
The server returns an equal-sized response for ordinary echo requests and a
32-byte ACK for UDP MTU probes. It processes multiple clients, ignores invalid
UDP requests and closes invalid TCP streams.

The server caps TCP peers at 256, per-peer queued replies at 1 MiB and idle
TCP connections at 60s. It closes peers that exceed these limits. These are
diagnostic limits, not throughput targets. There is no authentication or encryption;
run the server on a test network or restrict access with the host firewall.

## Build and verify

Source layout:

- `src/probe.rs`, `client.rs`, `server.rs`: shared probe sessions, text client and paired server.
- `src/net.rs`, `icmp.rs`, `wire.rs`, `tcp.rs`: sockets, ICMP, framing and TCP telemetry.
- `src/stats.rs`, `output.rs`: bounded statistics and text reports.
- `src/window.rs`, `ui.rs`, `terminal.rs`: simultaneous protocol sessions and terminal display.
- `src/mtu*.rs`, `mss*.rs`: MTU search, MSS inspection and handshake capture.
- `tests/`, `bench/`: live protocol/terminal checks and CPU/memory measurements.

From the tools repository root:

```sh
make netping
make check-netping
python3 netping/tests/verify.py bin/netping
python3 netping/tests/window.py bin/netping
python3 netping/tests/retrans.py bin/netping
python3 netping/tests/mtu.py bin/netping
python3 netping/tests/mss.py bin/netping
sudo python3 netping/tests/mss.py bin/netping --capture
sudo unshare -n python3 netping/tests/retrans.py bin/netping --loss
sudo unshare -n python3 netping/tests/mtu.py bin/netping --network
sudo unshare -n python3 netping/tests/mss.py bin/netping --network
python3 netping/bench/measure.py bin/netping
python3 netping/bench/window.py bin/netping --seconds 60
sudo make install-netping
```

The live tests create temporary loopback listeners, use IPv4/IPv6, inject
packet faults and stop all test processes on completion. Hosts without ICMP
socket permission can use `--skip-icmp`; run the complete checks on a host
with permission as well.
Window tests use temporary pseudo-terminals and check key handling, terminal
restoration, simultaneous protocols, independent ports and fault recovery.
Retransmission tests cover legacy peers, small payloads and both address
families. The optional loss test requires `ip` and `tc`; it refuses to alter
the host network and uses only an isolated namespace's loopback device.
MTU tests cover search ceilings, small ACKs, legacy servers and stop limits.
The optional routed test needs root, `ip`, `nsenter`, `iptables` and `ip6tables`;
inside isolated namespaces it checks remote/local MTU limits, ping/raw sockets
and filtered Too Big errors for IPv4 and IPv6.
MSS tests check both families, passive ordinary-service connections, paired
and legacy telemetry, framing, timeouts and signals. The isolated network
test also needs `setpriv`; it applies different SYN/SYN-ACK MSS clamps and
verifies both endpoints' actual send MSS, including without capture permission.

Static builds use Rust 1.96.0 and cross 0.2.5, with separate target directories:

```sh
RUSTUP_TOOLCHAIN=1.96.0 RUSTFLAGS='-C target-feature=+crt-static' \
  cross build --manifest-path netping/Cargo.toml --locked --release \
  --target x86_64-unknown-linux-musl --target-dir /tmp/netping-x86_64
```

Other targets: `aarch64-unknown-linux-musl` and
`armv7-unknown-linux-musleabihf` (ARMv7 with hardware floating point).
Run `cross test` and `cross run --release ... -- -v` for each target too.
