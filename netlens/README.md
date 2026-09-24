# netlens

Previously named `nwdiag`. The executable and shell completions now use `netlens`.
Historical report identifiers keep their `nwdiag.*` namespace for compatibility;
dated design notes and benchmark records retain the name used at the time.

`netlens` is an `htop`-style terminal monitor for Linux network counters. It
continuously shows activity, errors, drops, pressure signals,
and provider health across Sockets, Transport, Network, Conntrack, Qdisc,
Netdev, SoftIRQ, and HardIRQ. All views are numerical, without trend graphs.

The current v1 monitor is counter-only. It does not load or attach BPF programs,
capture packets, or modify nftables, TC, XDP, sysctls, or other network state.
Missing or unusable coverage is shown explicitly as `UNSUPPORTED`,
`UNAVAILABLE`, or `NO PROVIDER`; absence of data is not presented as zero
traffic or a healthy network.

## Run

Static ARMv7, ARM64 and x86_64 executables are available from
[GitHub Releases](https://github.com/calcky/tools/releases/tag/netlens-v0.1.0).
See [the release notes](RELEASE.md) for architecture requirements and checksums.

Run `netlens` directly from an interactive terminal:

```text
netlens [--interval 1s]
       [--interface eth0]
       [COMMAND]
```

The sampling interval defaults to one second and accepts whole-millisecond
durations from `250ms` through `60s`. Module commands select the initial page:
`overview`, `interface`, `qdisc`, `softirq`, `hardirq`, `socket`, `transport`,
`network`, `conntrack`, `route`, or `providers`.

Collection follows the visible page. Overview and Providers collect all summary
layers; other pages stop unrelated collectors before any probe or cache refresh.
Socket keeps protocol/socket summaries and its connection table. Transport and
Network keep protocol counters; Conntrack keeps conntrack health and its flow
table. Interface keeps link/NIC data, Qdisc keeps qdisc data, SoftIRQ keeps
softirq/softnet data, and HardIRQ keeps hardware interrupt data. Interface
drilldowns retain the collectors needed by their displayed layers, including
link/NIC data for the interface header and hardware coalescing settings. A layer
detail's header health reflects that layer; the whole-interface view assesses
all its layers.

Active counters follow `--interval`. In Overview and Providers, NIC statistics
and hardirq data refresh every 5 seconds, firewall rules every 10 seconds (or
the requested interval if longer), and qdisc counters every sample. Opening a
corresponding detail triggers a refresh and follows `--interval`. Ettool
configuration refreshes on a separate worker while its page needs it. Its first
batch starts immediately; recurring batches spread probes across five seconds
and aim for a completed refresh roughly every 30 seconds (rounded to the NIC
poll cadence). Dynamic counters never wait for a configuration batch. Only
complete batches replace cached settings, retaining their observation timestamp
between refreshes; configuration collection cost excludes deliberate stagger
waits. Initial settings may briefly show `refresh_pending`.
Queue directory counts are checked at most every 5 seconds while their directory
identity is checked each inventory pass; a replacement queue directory forces
an immediate recount. This keeps queue topology visible without making a
directory scan part of every one-second traffic sample.
TCP memory limits and `net.core` SoftIRQ budget settings use the same 30-second
configuration cadence and retain their real observation timestamp.
Socket/conntrack flow tables and route inventories start on entry to their
respective pages and stop on exit. A stopped counter establishes a new baseline
on return: its first sample has no rate, and the next sample has a measured rate.
Raw cumulative values remain available; since-baseline values restart when a
counter resumes. Intentional suspension does not publish stale provider errors.

Between polls, cached values retain their actual observation time and the rate
from the last measured interval. A slow-provider rate is therefore an average
over its collection interval; shorter bursts may be smoothed. Cache reuse does
not add history observations, zero rates, or collection gaps. Terminal updates
are coalesced when collectors finish close together, while keyboard input
continues to redraw promptly.

NIC statistics use read-only `SIOCETHTOOL` queries where supported, falling back
to the bounded `ethtool -S` command on failure. PF and VF interfaces follow the
same path. Driver-private fields retain their existing current-only semantics.
Configuration still uses the 30-second ethtool cache. Monitor snapshots share
immutable data, and interface tables format only the visible rows.

Explicit unsupported NIC operations are retried after five minutes or after a
device/driver identity change. Permission errors, timeouts, parse failures and
ambiguous command failures are not cached as unsupported. Ring ioctl fallback
remains independent of the command capability cache. Configuration workers stop
when leaving NIC-dependent pages; cancellation interrupts stagger waits, while
an in-flight bounded probe finishes before the worker joins.

Socket collection reuses its SOCK_DIAG connection and receive buffer. Every
query has a new sequence; incomplete, cancelled or invalid dumps discard the
connection before retry. IPv4/IPv6 TCP/UDP discovery and counters retain the
selected sampling interval.

From the tools repository root, build, check and install this tool with
`make netlens`, `make check-netlens` and `make install-netlens`. The executable
is `bin/netlens`; this directory remains an independent Cargo crate.

The bounded terminal benchmark lives in `bench/measure.py`, following the other
tools. For a 1s sampling measurement, run from the tools repository root:

```sh
python3 netlens/bench/measure.py ./bin/netlens --section interface --interval 1s --seconds 16 --warmup 5
```

It reports CPU use and memory along with the terminal session. Measurements
depend on the selected page, interface/socket count and available providers.

`--interface` filters interface-labelled rows in Overview and
layer details while retaining host/current-namespace aggregate rows. Collection
still attempts every interface in the current network namespace within the
documented provider and session bounds, so the anchor does not reset or narrow
the process history.
Both the default Overview's Interface area and the separate Interface page
include every observed netdevice, including DOWN SR-IOV VFs, and keep the real
link state visible. Explicit interface-name anchors still restrict the displayed
interfaces. Other interface-grouped layer tables retain their existing
hide-DOWN behavior unless anchored.
VFs assigned elsewhere without a netdevice in the current namespace are not
invented as interfaces or given synthetic traffic counters.

There are no user-facing `report`, `doctor`, or `replay` subcommands in v1.
Those words are rejected as unexpected arguments.

### Build For OpenWrt

OpenWrt uses musl rather than glibc. A normal `cargo build --release` on a
glibc host produces a binary that requires `/lib64/ld-linux-x86-64.so.2` and
cannot run on stock OpenWrt. For an x86_64 OpenWrt target, install Rust's musl
standard library once and use the checked build target:

```text
rustup target add x86_64-unknown-linux-musl
make openwrt
```

The result is `target/x86_64-unknown-linux-musl/release/netlens`. The Makefile
rejects an artifact that still has a dynamic program interpreter, shared-library
dependencies, or `GLIBC_*` symbol references. All builds use the same counter-only
TUI. The BPF runtime, BPF C programs and libbpf build dependencies have been
removed; no feature flag or Clang/libelf toolchain is needed.
Historical report schemas and their validation/normalization code still retain
BPF-named fields for compatibility with saved reports. They do not collect or
replay BPF events. Earlier design and research notes describe the removed runtime.

For another OpenWrt CPU architecture, set `OPENWRT_TARGET` to the matching Rust
musl target and configure the corresponding OpenWrt SDK linker. The target must
match both `uname -m` and the firmware ABI.

To build static ARMv7 hard-float, ARM64 and x86_64 binaries together, install
Docker, rustup with Rust 1.96.0, and host `readelf`/`file`, then run:

```sh
bash tools/build-static.sh
```

This uses the cross-rs 0.2.5 musl toolchain images and the default build of the
counter-only TUI. Results are
`dist/netlens-linux-armv7`, `dist/netlens-linux-arm64`, and
`dist/netlens-linux-x86_64`, with `SHA256SUMS` and `BUILDINFO.txt` recording the
source commit and build toolchain. ARMv7 requires little-endian ARMv7 with
hardware floating point; it is not an ARMv5/ARMv6 or soft-float binary.

Each TUI module can also be selected as a subcommand. Common options may
follow the subcommand:

```sh
netlens                         # Overview
netlens interface               # Interface
netlens qdisc                   # Qdisc
netlens softirq                 # SoftIRQ
netlens hardirq --interval 1s   # HardIRQ
netlens socket                  # Socket
netlens transport               # Transport
netlens network                 # Network
netlens conntrack               # Conntrack
netlens route                   # Route
netlens providers               # Providers
```

`interface`/`netdev`,
`qdisc`/`tc`, `conntrack`/`netfilter`, and `route`/`routes` provide aliases
where the terminal page uses a different internal collection name.

Generate Tab completion scripts with:

```sh
netlens completions bash > ~/.local/share/bash-completion/completions/netlens
netlens completions zsh > ~/.zfunc/_netlens
netlens completions fish > ~/.config/fish/completions/netlens.fish
```

The command also accepts `powershell` and `elvish`.

Overview places Sockets, TCP/UDP Transport, IP/ICMP Network, Conntrack,
Qdisc and SoftIRQ above the Interface tables. Socket resources combine address
families; TCP memory is allocated MiB / the `tcp_mem` upper threshold in MiB.
Host-scoped memory and softirq counters are labelled separately from namespace
protocol counters. `Tab` / `Shift+Tab` or a mouse click selects a page.

Each Overview module has a thin outline and a bold colored heading in the top
border; the selected module's border is cyan. The Interface module combines
traffic and configuration in one outline. Side and bottom borders do not open
details or sort tables. In Overview, the first click selects a module or interface
row; another click on the same selection opens it. Switching targets or using a
keyboard action resets this click sequence. `Enter` opens the selection directly,
and sortable column headings still sort on a single click.
The Interface module title follows the same two-click rule and opens the
standalone Interface table; interface rows open the selected device's details.
`Qdisc` and `Interface` are the tab titles; the existing
`:tc`, `:netdev`, and `:nic` commands remain available alongside `:qdisc` and
`:interface`.

Each summary layer uses up to two rows of core metrics, with stable slots at a
given terminal width. Values follow their labels closely, and dim vertical
guides separate the cells. The grid fits five columns in a 160-column terminal
and six at 200 columns, growing up to eight. Wider layouts show more core
metrics. Interface tables use the available width with vertical column guides.
One additional row highlights nonzero diagnostic signals.
`signals` counts valid nonzero diagnostic metrics, such as retransmissions or
drops, across the layer. `unavailable` counts summary metrics without a valid
current reading, including missing/unsupported data, permission failures,
warmup, reset, gaps, stale data and incomplete sources. These counts include
metrics that do not fit in the current width. Missing readings stay distinct
from zero. Enter the layer for all metrics, cumulative counters, configuration
and English meanings. Overview keeps interface traffic visible on a normal
160x40 terminal without scrolling when
there are few TC exceptions. Smaller terminals and longer exception lists scroll.

The session header describes collection status: `LIVE`, `DATA GAPS`, `NO DATA`,
or a session `ERROR`. It does not classify the network as healthy or faulty.
An unsupported backup provider is ignored only when an equivalent fresh source
covers it. Other unsupported coverage, partial results, denied access, errors
and stale observations remain visible; the Providers page explains them.
Providers uses aligned vertical separators in its header and every data row.

Interface has a sortable traffic table and a configuration table for the same
visible interfaces in the same order. The default order is ifindex. `s` cycles
the sort metric and `r` reverses its direction; traffic headings are clickable,
configuration headings are static. The Interface heading shows the visible
range and total interface count. The number of visible interfaces follows
terminal height, not a fixed batch of three. Configuration includes driver,
link speed/duplex/autoneg, RX/TX queues and rings, MTU, TX queue length, pause,
TSO/LRO/GRO/GSO and the observed root qdisc. Unsupported values remain `n/a`.
`Enter` or a row click opens the interface layer menu and its diagnostic details.
In Overview, interface rows use the select-then-open click sequence described above.
Interface details group identity, configuration and layer statistics in bordered
sections. The identity table shows NETDEV, IFINDEX, TYPE and DRIVER. Each layer
summary uses metrics as column headings and RX/TX or the interface as rows.
Netdevice shows PACKETS, TRAFFIC, PPS, BANDWIDTH, DROPS and ERRORS, with cumulative
counts and separately labelled rate columns. Qdisc adds REQUEUES, OVERLIMITS and
BACKLOG; HardIRQ shows INTERRUPTS, INTR/S, IMBALANCE and CPU AFFINITY.
Narrow terminals split columns into groups and repeat DIR or NETDEV in each group.
Missing values remain explicit. Baseline mode labels average rates with AVG and
gauge ranges with RANGE; counter totals remain cumulative.
HardIRQ coalescing uses a separate DIR / ADAPTIVE / USECS / FRAMES table.
The redundant link-status banner and RX/TX path descriptions are omitted.
Detailed statistics use side-by-side groups on wide terminals and stack them
on narrow terminals. Layer selection, paging and return retain the selected interface,
including a DOWN VF opened from Interface.

Queue configuration is queried with read-only `ETHTOOL_GCHANNELS`, also for
virtual interfaces, at the existing 30-second configuration cadence. RX and TX
each include the current combined channels; maximum counts and other channels
are excluded. If the driver reports `EOPNOTSUPP`, the observed
`/sys/class/net/<interface>/queues/rx-*` and `tx-*` counts are shown with `fixed`.
Here `fixed` means no ethtool channel configuration is exposed. Other query
failures use the observed sysfs counts with `sysfs`, without claiming fixed
configuration. Missing sysfs counts remain unavailable. Cached settings keep
their real observation timestamp, and interface identity changes refresh them.

At the same 30-second configuration cadence, sysfs `speed`, `duplex` and
`carrier` supply independently observed fallback fields; driver identity uses
`device/driver` or the `DRIVER` entry in `device/uevent`. Interface prefers usable
ethtool values, then these fallbacks. A failed base ethtool query also permits
an independent read-only ring ioctl. Query errors remain visible in provider
status. Autonegotiation and hardware ring length have no universal sysfs file;
missing values remain `n/a`. Neither `tx_queue_len` nor BQL is a descriptor ring
length. Offload flags retain `fixed` only when ethtool text or kernel feature
capabilities explicitly establish it. Reading from sysfs, a permission error,
or a ring value equal to its maximum does not imply a fixed configuration.

TC in Overview contains only root egress qdiscs with fresh `drop/s > 0` or
`requeue/s > 0`. Historical cumulative counts and backlog alone do not qualify;
reset, warming, missing and stale rates are not treated as zero. Requeues are
retries, not drops or TCP retransmissions. TC actions are not shown in Overview.
The TC page retains root and child objects separately, with sortable queue and
traffic metrics and a selected-object detail. Roots and children are never
summed together. Class/filter/action collection remains unsupported.

Network opens IP/ICMP metrics with current rates, cumulative counters and
English meanings. The separate Route page retains the structured route menu.
`IP / ICMP / MTU` separates IPv4 and IPv6 traffic, forwarding, no-route,
validation, ICMP, Packet Too Big, fragmentation, and reassembly counters with
the normal interval/session projections. `Routes`, `Policy Rules`,
and `Neighbours` show bounded, stable-order inventories for the current network
namespace. Select a row and press `Enter` for its complete kernel detail,
including TOS-specific matches, nexthops, route MTU/TCP metrics, policy
selectors, or ARP/NDISC cache state. Addresses and gateways are shown only
after this explicit drilldown.
Absent optional fields are hidden by default; `a` reveals them and zero/raw
fields. A neighbour marked `FAILED` is a current NUD state, not a failure rate.
Route menu entries have selection-highlighted frames. Route lists, details and
lookup views keep an outer border while their contents scroll; keyboard paging
and selection account for the space used by the border.

Route, rule, and neighbour inventories run only while the Route page or one of
its drilldowns is open, following `--interval`. Leaving stops its worker;
reopening starts a new inventory baseline and change totals. For each inventory
and IP family, the first complete dump establishes a baseline. The menu keeps saturating
cumulative counts of net changes observed between later complete samples:
additions, removals, neighbour
updates, NUD state changes, and transitions into `FAILED`. This is sampled
inventory change, not an event log; an add and remove entirely between polls is
not observable.

A failed family dump degrades only that family and reuses its last complete
table as stale when available; before the first success it remains empty with an
error. A retention-limited dump shows its bounded partial rows but does not
replace the saved complete table. Neither failure nor truncation advances that
family's change baseline. Recovery compares the new complete table with the
preceding complete one, so collection gaps do not fabricate changes.

`Route Lookup` asks the kernel for its effective route. It accepts literal IP
addresses with this grammar:

```text
DEST [from SOURCE] [iif IFACE] [oif IFACE] [mark N] [uid N] [tos N]
```

Numeric selectors accept decimal values, while `mark` and the other numeric
fields also accept a `0x` prefix. Source and destination families must match.
The result is the final route/table/nexthop returned by the kernel; it does not
claim to expose every policy-rule traversal step. No DNS lookup is performed.

The Conntrack tab opens the current namespace's on-demand flow table with one
connection per row. It shows separate PROTO and STATE columns, the original
endpoints and CT mark, then two-level `traffic byte`, PACKETS (cumulative), PPS,
BANDWIDTH (bit/s) and `avg pkt byte` headings, each with independent TX/RX columns. TX is the original
initiator direction and RX is its reply, not host-interface traffic. Average
packet length uses each direction's lifetime bytes / packets; absent counters
or zero packets show `n/a`. Full original/reply and NAT tuples remain in detail.
`s` cycles sorting, including directional packet totals and average lengths;
PPS has only directional sorts. `r` reverses it. Click a TX/RX heading to sort,
and click it again to reverse. PROTO, STATE, original endpoints and CT mark also
support sorting. `Enter` or a second click on the selected row opens tuples, NAT, CT mark, counters
and status. A missing mark is shown as `n/a`.
Selection follows the connection identity across refreshes. Offloaded flows
may bypass conntrack accounting, so their rates and totals can be incomplete.
Press `/` for a tcpdump-style expression such as
`tcp and src net 192.168.0.0/24 and dst port 443`.
New expressions match the original tuple. They support `host`, `net`, `port`,
`portrange`, protocol/family, `src/dst`, `and/or/not` and parentheses.
Empty input or `Ctrl+u` clears the filter. This is a connection-metadata subset,
not a packet-capture BPF engine: DNS names, payload offsets and link-layer
predicates are unsupported.

The legacy `:netfilter` section retains Conntrack health and firewall views.

The iptables and nftables entries open a chain list, then a one-row-per-rule
view with verdict, PPS, bit/s, cumulative packets, and cumulative bytes.
iptables chains aggregate their contributing tables in the chain list and keep
the table column on each rule. nftables keeps family, table, and chain as its
chain identity. Rules without a counter remain visible as `NO COUNTER` rather
than zero. Native nftables and nft-backed iptables remain separate views and
must not be added together.

The Socket tab opens the current namespace's live IPv4/IPv6 TCP/UDP socket
table. Each socket stays on one row with PROTO, STATE, LOCAL, REMOTE, PROCESS,
RECV-Q, SEND-Q, RTT, MSS and CC. TCP-only RTT, send MSS and congestion control
remain `n/a` for UDP and listeners. Queues show bytes, except a listening TCP
socket's pending/max accept-backlog counts. Window, traffic and limit evidence
stay in the selected connection's detail. Compact identity and three independent
module stacks keep the regular wide-terminal detail on one screen where it fits.
Labels and values are separated and aligned; narrower terminals and all-fields
mode remain scrollable. Process ownership can be partial when
`/proc/<pid>/fd` is not readable.

Socket counters, TCP_INFO and connection membership retain the selected sampling
interval. Process attribution runs independently: full scans every 10 seconds,
with new or invalidated connections requesting a scan at most every 2 seconds.
Until resolved, these connections show an unknown owner. The process-map status
reports its observation age and whether a refresh is in flight, in both the list
and connection detail. Cached attribution is matched by socket cookie/inode and
validated against PID start time and a matching FD; closed or reused identities
are discarded. Process names can lag by one attribution refresh. Cache entries
expire after 20 seconds if scanning stalls. No process scans run after leaving
the socket session.

In the socket table, use `j`/`k` or the arrow keys to select one socket and
press `Enter` to open its diagnostic detail. In both Socket and Conntrack,
the first click selects a row and a second click on that selected connection
opens its detail. Socket `s` cycles the ten displayed fields, defaulting to
Recv-Q descending; `r` reverses the order. Clicking a heading selects that field;
clicking it again reverses direction. Sortable headers use a bidirectional
arrow; the active field has an up/down arrow and a highlighted column.
Interface and Qdisc use the same header feedback; configuration is not sortable.
Socket and Conntrack keep both grouped header rows fixed while connection entries
scroll. PageUp/PageDown move by the number of visible entries. On short terminals,
summary metadata is shortened to preserve the column labels and a connection row.
Press `/` in either table to enter expressions such as
`tcp and (port 443 or port 8443)`, `src net 192.0.2.0/24`, or
`udp and portrange 53-5353`. `ip` / `ip6` select address families.
As in libpcap, `and` and `or` have equal precedence and associate left to right;
use parentheses to group conditions. In Socket, source means local and
destination means remote, including accepted sockets. Conntrack directions
refer to its original tuple. `Ctrl+u` clears the current page's filter, including
while editing. Each page remembers its filter, sort field and direction until exit.
Legacy `host=`, `src=`, `dst=`, `port=`, `sport=`, `dport=` and `proto=` filters
remain supported, with implicit AND and their previous NAT-aware unqualified
host/port matching. Do not mix key=value tokens with the new expression syntax.
Filters are compiled once per edit; evaluating rows performs no DNS or collection.
Filters search only the retained snapshot; collection continues at the same cadence
while that page is active, without resetting counters when filtering changes.
`TRUNCATED` means matching connections may have been omitted by collection limits.
Shown, retained and observed/kernel counts have different scopes. Zero matches
in a truncated or incomplete snapshot do not prove that no matching connection exists.
Unknown values stay last in either direction; equal values use stable socket
identity. Sort changes and refreshes preserve the selected connection, including
while paused and after returning from detail. Queue sorting uses the displayed
kernel value, so a listener's pending/maximum connection counts retain their
distinct meaning. Sorting reuses row indexes until data or ordering changes.
The detail remains vertically
scrollable with `j`/`k`. `Esc` returns first to the socket table and then to the
Socket / Application layer. A `CONNECTION SUMMARY` leads with RX application
rate, TX acknowledged-application rate, RTT/retransmission, and the known
congestion/peer-window send ceilings. It compares the two ceilings only when
the peer window is available; Linux 4.14 therefore reports that comparison as
unavailable rather than assuming congestion control is smaller. Detailed
traffic labels keep all TCP segments (`all-seg`), received application bytes
(`app`), and acknowledged sent application bytes (`acked-app`) distinct;
application-bearing TCP data-segment totals are separate again. TCP detail also
separates congestion, flow-control, and buffer measurements: `snd_cwnd` is the
congestion window, `snd_wnd` is the peer-advertised receive window that limits
local sending, `rcv_wnd` is the local advertised receive window, and
`rcv_space` is a receive-autotuning space estimate rather than the current
receive window. `rcv_ssthresh` is shown as a separate receive-autotuning
threshold. The default view suppresses unavailable fields and zero-only
diagnostic noise; press `a` to show all zero, `n/a`, and raw-detail rows and
fields. A TCP listener instead shows its accept queue as pending/limit
connection counts and does not reuse connection-only traffic, RTT, window, or
recovery labels. If the selected identity is absent from the latest query,
current diagnostics are suppressed; only explicitly last-observed identity
context remains.

TCP detail includes `LIMIT BASIS`: the decision, rule, query-to-query sample
interval, busy-time delta, rwnd/sndbuf-limited deltas and their percentages of
busy time. A 50% busy-time threshold identifies a dominant observed timed
constraint; it is a display heuristic, not a kernel-provided verdict. The
busy-time denominator is distinct from wall-clock sample duration. First
observations, missing/reset counters and gaps remain unknown. No additional
queries or graph history are collected. Current flight is estimated as
unacked - sacked - lost + retransmitted segments. `CWND?` requires unsent data,
estimated flight >=90% of cwnd, CA Open and an available peer window at least as
large as cwnd in bytes. `APP?` combines no unsent data with the latest delivery
sample's app-limited flag; neither estimate proves the current bottleneck.
`ACTIVE` means no dominant timed limit was observed, not that no other limit
exists. UDP and listeners do not display LIMIT or LIMIT BASIS.

RTT, congestion-window, traffic, queue, window, and retransmission values are
shown numerically. Pages have no trend graphs or trend columns. The bounded
sock_diag and process scans
continue without restarting while either the socket table or a selected socket
detail is open, and stop after leaving both pages.
Private socket identity and current detail state are not added to the general
monitor history or report model. Socket details do not collect graph history.

## Controls

| Key | Action |
| --- | --- |
| `Up` / `k`, `Down` / `j` | Select the previous or next global layer/interface in Overview, select an interface layer or table row, or scroll one row in a detail view. |
| `Enter` | Open the selected Overview item, interface layer, or Network/Route item; open a Netfilter menu item, chain, Socket or Conntrack table; open a selected socket, route, rule, or neighbour detail; submit route lookup input. |
| `Esc` | Cancel active input or return one level at a time through object, table, layer, and Overview pages while restoring stable selections. |
| `Tab` / `Shift+Tab` | Next / previous page; page labels also accept mouse clicks. |
| `s` / `r` | Cycle sort metric / reverse sort in Interface, Socket, Conntrack, Qdisc, SoftIRQ and HardIRQ tables. |
| `v` | Toggle queue and traffic metrics on the TC page. |
| `/` | In Socket/Conntrack, filter IP/CIDR, host/port, protocol and source/destination. |
| `Ctrl+u` | Clear the current connection filter, including while editing; sorting is preserved. |
| `a` | In metric or object details, toggle between fields with data and all current rows, including zero, absent, and raw fields. |
| `PageUp` / `PageDown` | Move one visible page in Socket and Network/Route tables; scroll details by a page or bounded row group. |
| `Home` | Return to the first row. |
| `:` | Enter command mode. |
| `p` or `Space` | Pause or resume display updates; collection and history continue. |
| `t` | Toggle interval and since-baseline values on pages that expose those projections; selected-socket detail uses its live values. |
| `q` or `Ctrl+C` | Quit. |

Command mode accepts a section name directly, for example `:softirq`, or
`:section softirq`. It also accepts `:pause`, `:time`, `:q`, and
`:quit`. `:time` has no effect in selected-socket detail. Press `Enter` to
submit or `Esc` to cancel. Page aliases include `:netdev`, `:transport`,
`:network`, `:conntrack`, and `:route`. Left/Right and number keys are not
navigation shortcuts.

SoftIRQ CPU tables support clickable sort headings in both the SoftIRQ page and
the Overview detail. The active heading shows its direction; a first click sorts
CPU ascending or a statistic descending, and another click reverses it. Sorting
uses the underlying values for the selected time view, with missing, stale or
unready samples last. Column headings remain visible when scrolling CPU rows.
Configuration and sampling meanings are grouped in bordered sections. Both
entry paths use the same display mode and sort state: all columns by default,
including zero-valued statistics. `a` toggles fields with data on either page.
Switching entry paths preserves that mode, independently of other detail pages.

HardIRQ shows verified network IRQs from `/proc/interrupts` in a bordered table:
`IRQ | NETDEV | CPU | COUNT | intr/s`. COUNT is the cumulative counter since boot;
intr/s uses the actual elapsed time between successful samples. Each IRQ occupies
one bold row, with the total rate right-aligned. CPU lists processors active in
that interval; `-` means no activity, `n/a` means no valid interval, and `+N`
indicates additional active CPUs that do not fit in the column. COUNT and intr/s
always include every CPU, including those omitted from the displayed list.
IRQ, NETDEV, COUNT and intr/s headings support click sorting, plus `s` and `r`;
column headings stay visible while scrolling. First samples, resets, changed IRQ
ownership and collection gaps show `n/a` until a new rate baseline is available.

## Current Coverage

The current implementation reads:

- Socket and protocol counters from `/proc/net/snmp`, `/proc/net/netstat`,
  `/proc/net/snmp6`, `/proc/net/sockstat`, and `/proc/net/sockstat6`, plus an
  on-demand bounded `NETLINK_SOCK_DIAG` TCP/UDP table and `/proc/<pid>/fd`
  process-owner mapping.
- IPv4/IPv6 and ICMP counters from procfs plus native `NETLINK_ROUTE`
  route, policy-rule, and ARP/NDISC neighbour dumps and explicit route lookup.
  Netlink framing, sequence, sender, interruption, overrun, truncation, and
  cardinality failures remain local to the affected inventory.
- Conntrack count, capacity, utilization, and per-CPU counters from procfs and
  sysfs, plus an on-demand bounded `/proc/net/nf_conntrack` flow table with
  directional PPS and bandwidth. Bounded read-only `iptables-save -c`,
  `ip6tables-save -c`, and `nft -j -a list ruleset` collection adds chain/rule
  inventory and available rule packet/byte counters without merging native nft
  and iptables-nft views.
- Per-interface qdisc packet, byte, drop, overlimit, requeue, and backlog data
  from native `RTM_GETQDISC` with bounded `tc -s -j qdisc show` fallback.
  Class/filter/action inventory is not yet collected.
- All 25 `rtnl_link_stats64` fields are mapped exactly once across Netdevice and
  NIC, with sysfs and `/proc/net/dev` fallbacks where those sources expose the
  field. `carrier_changes` is collected as a separate counter rather than
  conflated with `tx_carrier_errors`. The folded `/proc/net/dev` RX `drop`, RX
  `frame`, and TX `carrier` columns are not used as exact single-field
  fallbacks.
- NIC link state, driver, RX/TX queue counts, and TX queue length from sysfs,
  plus ordinary `ethtool <interface>` settings and `ethtool -S <interface>`
  statistics for hardware-backed interfaces. Optional `ethtool -g`, `-a`,
  `-k`, and `-c` probes add current/maximum ring lengths, RX/TX flow control,
  TSO/LRO/GRO/GSO, and common adaptive/usecs/frames coalescing state when
  supported. Static settings run when NIC collection starts and refresh
  approximately every 30 seconds while needed; dynamic `ethtool -S` statistics
  follow the page-dependent cadence described above.
  These configuration fields remain opaque information and do not warn solely
  because of their values. Scalar and multiline settings are retained. There
  is no 256-statistic truncation;
  bounded command output and the 4096-reading provider limit fail visibly as a
  partial/error result. `linux.nic.ethtool_settings_status` and
  `linux.nic.ethtool_statistics_status` expose each admitted interface attempt;
  `complete` means fresh collection coverage, not a healthy network. Every
  ethtool text field is an opaque current value, and familiar or driver-private
  names are never guessed to mean packet, error, drop, or counter semantics.
- Per-CPU `NET_RX`/`NET_TX` from `/proc/softirqs`, plus softnet activity, drops,
  budget pressure, RPS softirq/IPI trigger occurrences, and flow-limit counters
  from `/proc/net/softnet_stat`. The RPS field is not a packet count.
- Per-interface, per-CPU hard interrupt counters, imbalance, and aggregate
  affinity from `/proc/interrupts` only when the NIC relationship is verified
  through sysfs. MSI/MSI-X mappings take precedence over the inactive legacy IRQ;
  devices without a current procfs IRQ row do not suppress other devices' data.
  Host VFs are included, and PF `virtfnN` relationships identify VFIO IRQs as
  `pf/vfN` when no host netdevice owns the IRQ. Interrupt descriptions are never
  used to guess a NIC. Shared IRQs appear once with multiple owners in the raw
  table; ambiguous IRQs are excluded from per-interface summary metrics.
  Topology and affinity refresh every 30 seconds, while IRQ counters follow the
  current page's sampling interval. Large interface/CPU matrices use compact
  interface summary counters to stay within the 4096-reading provider budget;
  the raw IRQ table retains per-CPU data separately, bounded to 1,048,576 cells
  and two snapshots. It adds no collector thread or duplicate procfs polling.

The Overview and Providers views expose partial attempts, unsupported commands,
permissions, schema mismatches, and missing kernel sources while other sections
keep updating. A partial provider keeps successful current rows and marks
omitted historical rows stale with the collection warning.
Overview shows actual current gauges and interval rates with explicit
`n/a`, `warmup`, `reset`, `gap` and `stale` values where appropriate. Provider
health and diagnostics remain available on Providers. A source being fresh
without a matching metric is not treated as observed data.

Each selectable global block opens a scrollable detail for its RX, TX, and key
series. An interface first opens a layer menu ordered as TC/Qdisc, Netdevice
Core, Driver/NAPI, NIC/PHY, and HardIRQ. `Up`/`Down` or `k`/`j` selects a layer;
`Enter` opens one scrollable detail containing only that interface and layer.
Detail pages default to rows with meaningful Fresh or Stale data. Numeric rows
that are zero in their current value and every retained projection/history
bucket are hidden, while state rows and numeric rows with retained nonzero data
remain visible. Opaque private NIC statistics are current-only, so their zero
values are hidden. Rows that have only an Unavailable value and empty fixed-slot
placeholders are hidden.
Press `a` to show every series instantiated in the current snapshot, including
unavailable rows, plus the fixed summary placeholders. It does not synthesize
rows for catalog metrics that no provider has instantiated. Press it again to
return to metrics with data. Dynamic opaque ethtool fields remain reachable.
`Esc` returns from a layer detail to the same interface-layer selection, then to
the same Overview interface. If the selected interface disappears, either
interface page says `NO LONGER OBSERVED`; returning to Overview selects the
nearest remaining interface by the previous stable position.

## History

Baselines and history begin when the process starts; pre-existing kernel
counter values are not treated as activity observed by `netlens`. The UI labels
the cumulative projection `SINCE BASELINE`: a series starts at `SessionStart`
or `FirstObserved`, and a reset or recovery after a gap establishes a new
`Reset` or `RecoveredAfterGap` baseline. Current, interval, and since-baseline
values remain distinct. General monitor history keeps at most 16 buckets per
metric series for numerical visibility and session coverage. Older buckets are
compacted to a coarser resolution while retaining the observed session span and
highest observed interval rate in each merged bucket. Selected-socket detail
keeps its latest observation and identity without collecting graph history.
The TUI converts byte-counter rates to bit/s; `t` switches interval and
since-baseline values outside selected-socket detail. Trends and history-window
controls are not displayed. History is not persisted after exit.

## Architecture

The terminal renderer consumes immutable `MonitorSnapshot` values produced by a
background `MonitorSession`. Collection continues while the display is paused;
switching pages changes the active provider groups. The closed metric catalog keeps counter units,
scope, source, and display meaning separate so unrelated quantities are not
summed together.

Frozen report schemas and report fixtures remain in the repository as internal
regression baselines. The old BPF byte fixtures and event replay implementation
have been removed. Reports are not v1 CLI entry points. See
[docs/cli.md](docs/cli.md) for the complete interactive contract,
[docs/monitor-metrics.md](docs/monitor-metrics.md) for metric semantics, and
[ADR-0011](docs/decisions/0011-counter-only-tui.md) for the counter-only TUI
boundary. [ADR-0012](docs/decisions/0012-enter-only-overview-navigation.md)
records the Enter-only Overview navigation model.
