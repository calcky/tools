# netlens CLI

## Interface

`netlens` has one user-facing mode in v1: running the binary directly starts an
`htop`-style continuous terminal monitor.

```text
netlens [--interval DURATION]
       [--interface NAME]
       [COMMAND]
```

The binary requires interactive stdin and stdout before it initializes the
alternate screen. A non-terminal invocation fails without writing ANSI escape
sequences. `--help` and `--version` remain available without starting the TUI.

Module commands select the initial page: `overview`, `interface`, `qdisc`,
`softirq`, `hardirq`, `socket`, `transport`, `network`, `conntrack`, `route`,
and `providers`. Global options work before or after the command, for example
`netlens socket --interval 2s`. With no command, the initial page is Overview.

`netlens completions <shell>` generates completion scripts without a terminal
for Bash, Zsh, Fish, PowerShell, or Elvish. See the README for installation paths.

`netlens report`, `netlens doctor`, and `netlens replay` are not compatibility
aliases or hidden commands; clap rejects them as unrecognized subcommands.
Frozen report and event-stream schemas remain internal regression material.
Their historical `nwdiag.*` identifiers are unchanged by the project rename.

## Options

| Option | Meaning |
| --- | --- |
| `--interval DURATION` | Sampling interval. Defaults to `1s`; accepts whole-millisecond durations from `250ms` through `60s`. |
| `--interface NAME` | Validate and retain a Linux interface-name view anchor. |

The current collector samples all visible interfaces. Interface anchors filter
interface-labelled rows in Overview and layer details; rows without an
interface identity, such as host/current-namespace aggregates and per-CPU
softnet counters, remain visible. The filter does not change collection scope,
restart collection, or reset the process baseline.

Overview and Providers sample every summary layer. Other pages stop unrelated
provider groups before I/O, while keeping their own counters at `--interval`.
Interface drilldowns also keep the link/NIC dependencies used in their headers
and coalescing settings. Socket/Conntrack tables and Route inventories start
on entry and stop on exit. Resumed counters rebaseline on their first sample;
the next sample supplies a rate. Raw cumulative values are retained, but
since-baseline values restart after suspension. Active-source failures still
produce normal stale or unavailable coverage.

The following section names remain valid in the TUI for `:<section>` and
`:section <section>`. They are not assigned to number keys:

| Section | Current implementation |
| --- | --- |
| `overview` | Sockets, Transport, Network, Conntrack, TC exceptions and SoftIRQ, then aligned Netdev traffic/configuration tables. |
| `socket` | Protocol, IPv6, socket-count, and memory data from procfs. |
| `netfilter` | Conntrack count/capacity/per-CPU data plus read-only iptables IPv4, iptables IPv6, and nftables chain/rule inventory and available counters. |
| `tc` | Sortable root/child qdisc traffic and queue counters with per-object detail; class/filter/action data is unsupported. |
| `netdevice` | Netdev traffic/configuration tables, backed by rtnetlink with sysfs and `/proc/net/dev` fallbacks. |
| `nic` | Netdev tables; Enter opens per-interface TC, netdevice, driver, NIC and IRQ details. |
| `softirq` | Per-CPU `/proc/softirqs` and `/proc/net/softnet_stat`, with current `net.core` packet/time budget, backlog weight, and maximum backlog configuration. |
| `hardirq` | Per-NIC/per-CPU `/proc/interrupts` data with unique sysfs-verified device mapping; shared IRQs are skipped, and interface HardIRQ detail includes available RX/TX `ethtool -c` coalescing settings. |
| `providers` | Per-provider health, last attempt, collection cost, missing-reading count, and bounded diagnostic. |

Sysfs supplies driver, RX/TX queue counts, and TX queue length. MTU reuses the
existing link metadata dump with an optional sysfs fallback. Successful
optional `ethtool -g`, `-a`, `-k`, and `-c` probes add current/maximum RX/TX
ring lengths, flow-control state, TSO/LRO/GRO/GSO state, and adaptive RX/TX plus
RX/TX usecs/frames coalescing values. These values and ordinary
`ethtool <interface>` settings, including scalar and multiline fields, remain
opaque information even when a field name looks familiar. They are collected
when needed and refreshed approximately every 30 seconds, with cached settings
shown between refreshes. A separate worker staggers recurring configuration
batches across five seconds; dynamic counters continue on their own cadence.
Only complete batches replace settings, and topology changes discard obsolete
results. Reusing cached settings preserves the completion time
and collection duration of the NIC collection cycle that performed the most
recent actual static refresh; it does not advance the reported settings
last-attempt time or replace its reported collection cost. Pause-frame and FEC
counters plus verified ring-drop semantics are not yet collected. The monitor
does not infer packet, error, drop, or counter meaning from text or warn solely
because of a configuration value. Dynamic `ethtool -S` statistics follow the
main interval in NIC/whole-interface views and a five-second cadence in
Overview, Providers and other interface-layer details (or the selected interval
if longer). Unrelated pages stop NIC collection. There is no 256-statistic
truncation; each independent
settings/statistics provider remains bounded to 4096 readings. Per-interface
outcomes are retained before payload fields, then remaining capacity is shared
fairly across interfaces. Exceeding a command output or reading bound produces
an explicit partial/error result. Unsupported providers remain visible instead
of producing synthetic zero rows. Provider health `partial` retains successful
current rows while omitted rows from earlier samples become stale; the Providers
page shows the bounded warning.

The NIC/PHY `linux.nic.ethtool_settings_status` and Driver/NAPI
`linux.nic.ethtool_statistics_status` rows require both interface name and
ifindex. Their closed values are `complete`, `refresh_pending`,
`partial_schema_mismatch`, `partial_cardinality_limit`, `unsupported`,
`command_not_found`, `permission_denied`, `interface_unavailable`, `timed_out`,
`output_limit`, `invalid_output`, `command_failed`, and `io_error`. `complete`
supplies Fresh coverage only; it is not evidence that the network is healthy.
Unsupported outcomes produce Unsupported coverage, and all other incomplete
outcomes produce Partial coverage with a `collection_status` WHY cause whose
target is `complete`. A failure on one interface does not downgrade another
interface whose matching ethtool outcome is complete.

Newly observed hardware interfaces are refreshed immediately. The settings-only
`refresh_pending` value is reserved for a defensive cache-miss fallback;
it yields Partial coverage and does not mean the interface is unavailable.

Overview summaries require matching fresh readings for each displayed rate or
gauge. Missing, stale, warmup, reset and gap states remain explicit; a successful
provider with no matching metric never implies zero traffic. Interface detail
coverage retains the existing ACTIVE/PARTIAL/DEGRADED classifications.

## Overview And Detail

Overview contains Sockets, TCP/UDP Transport, IP/ICMP Network, Conntrack,
TC/Qdisc and host SoftIRQ. TCP socket counts combine IPv4/IPv6; memory is
allocated / maximum in MiB. Protocol details include rates, cumulative counters
and English meanings. Netdev follows with a sortable traffic table and static
configuration tables showing the same visible identities in the same order.
Configuration includes driver, link speed/duplex/autoneg, queues, current rings,
MTU, TX queue length, pause and TSO/LRO/GRO/GSO. Width selects a combined
configuration table or separate link/queue and offload tables; height controls
the number of visible interfaces. There is no three-interface cap.

Default Netdev order is ifindex with name as a deterministic tie-breaker.
`s` cycles sorting and `r` reverses direction. Traffic headings are clickable;
configuration headings cannot reorder the table. Unknown values sort last.
Selection follows the same interface identity across sorting and updates.

TC Overview shows root egress qdiscs only when a fresh interval has positive
drop/s OR requeue/s. Root/child counters are never summed. Cumulative drops,
backlog alone, resets, gaps and stale data do not trigger an exception row.
Requeues indicate retry pressure, not loss. No TC actions appear in Overview.
The TC page includes other observed qdiscs and selected-object details; `v`
switches between queue and traffic columns. Unavailable collection coverage is
reported separately from an empty exception list.

`Tab` / `Shift+Tab` or a mouse click changes pages. Page command aliases include
`:netdev`, `:transport`, `:network`, `:conntrack` and `:route`. Route preserves
the existing inventory/lookup menu, while Network opens IP/ICMP counters.
Overview selection moves through the six global blocks, then interfaces.
`Enter` or a click on an interface opens a selectable menu of its
TC/Qdisc, Netdevice Core, Driver/NAPI, NIC/PHY, and HardIRQ summaries. Select a
layer with `Up`/`Down` or `k`/`j` and press `Enter` again to open one scrollable
page containing only that interface and layer, including dynamic opaque ethtool
fields. Detail pages default to meaningful Fresh and Stale data while hiding
Unavailable rows, empty fixed slots, and numeric rows that have remained zero
in the current value, projections, and all-session history. State rows and
numeric rows with any retained nonzero data remain visible. Opaque private NIC
statistics are current-only, so their zero values are hidden. `a` exposes every
series instantiated in the current snapshot, including zero and Unavailable
rows, plus fixed summary placeholders; it does not synthesize uninstantiated
catalog metrics. `Esc` returns to the same interface-layer selection before
returning to Overview. The selected visibility mode persists when another
Overview item is opened.

The Socket tab directly opens an on-demand table for the current network
namespace's IPv4/IPv6 TCP and UDP sockets. The legacy Socket summary also
retains its Enter shortcut. Every socket remains
on one row with PROTO, STATE, LOCAL, REMOTE, PROCESS, RECV-Q, SEND-Q, RTT, MSS and CC.
All ten columns support header-click sorting; `s` cycles fields and `r`
reverses direction. RTT, send MSS and CC are unavailable for UDP and listeners.
Queue values are bytes except TCP listener pending/max backlog counts.
Traffic counters and window diagnostics remain in connection detail.
LOCAL and REMOTE are capped at 22 terminal cells; middle truncation preserves
the endpoint tail, while detail retains the full address. The Socket detail
uses compact connection identity above bordered modules with aligned labels
and values. Wide terminals use three independent stacks: traffic/windows,
LIMIT/path, and congestion/latency. Narrow terminals use two or one column.
The regular view aims to fit one screen without dropping metrics; smaller
windows, long values and `a` (all fields) can still require scrolling.

In the socket table, `Up`/`Down` or `k`/`j` selects a specific socket without
depending on its sorted row number. The first mouse click selects; clicking
the same selected connection again opens it, as does `Enter`. Socket and
Conntrack use this same interaction. `Enter` opens that socket's
vertically scrollable detail, where `Up`/`Down` or `k`/`j` scrolls the diagnostic
rows. `Esc` returns from the socket detail to the same table selection, then
from the table to Socket / Application detail. If the selected kernel identity
is no longer observed, the detail is not silently switched to another socket.
Press `/` for tcpdump-style metadata expressions. For example:
`tcp and src net 192.168.0.0/24 and dst port 443`,
`ip6 and tcp`, `udp and portrange 53-5353`, or
`tcp and (port 443 or port 8443)`.
`host` accepts numeric IPs; `net` accepts IPv4/IPv6 networks.
`src/dst` mean local/remote, even for accepted sockets. `src or dst` and
`src and dst` are supported. `not`, parentheses and qualifier inheritance
(`port 80 or 443`) work. Like libpcap, `and` and `or` associate left to right
with equal precedence. These filters inspect connection metadata, not captured
packets; packet offsets, DNS names and link-layer predicates are unsupported.
Legacy key=value filters remain accepted separately; mixing syntaxes is an error.
Empty input or `Ctrl+u` clears the current filter, including while editing.
Filters and sorting survive page changes until the program exits.
Filtering searches retained sockets without restarting collection or resetting
counters. The header distinguishes shown, retained and observed counts.
`TRUNCATED` warns that matching sockets may be omitted; zero matches in an
incomplete snapshot do not imply that no matching socket exists.

TCP detail keeps related but non-equivalent measurements separate. `snd_cwnd`
is the congestion window in segments, with a byte value derived from the send
MSS. `snd_wnd` is the peer's advertised receive window after scaling and is the
flow-control window for local sends. `rcv_wnd` is the local advertised receive
window after scaling. `rcv_space` is the kernel's receive-autotuning space
estimate; it is neither the current `rcv_wnd` nor the socket receive-buffer
limit. `rcv_ssthresh` is a separate receive-autotuning threshold. TCP data
segments are also shown separately from the all-segment PPS and totals. A
`CONNECTION SUMMARY` puts RX application rate, TX acknowledged-application
rate, RTT/retransmission, congestion window, peer window, and the smaller send
ceiling first. The smaller-ceiling comparison is made only when both windows
are available; on Linux 4.14, where `snd_wnd` is absent, it remains explicitly
unavailable. The traffic rows label all TCP segments as `all-seg`, received
application bytes as `app`, and acknowledged sent application bytes as
`acked-app`; none of these is a wire-byte estimate. A field absent from the
running kernel's complete `tcp_info` prefix is `n/a`, not zero. The default view
hides unavailable fields and zero-only diagnostics that carry no
signal; `a` toggles all zero, `n/a`, and raw-detail rows and fields into view.
UDP sockets can enter the same detail, but TCP-only diagnostics remain
unavailable rather than being synthesized. LISTEN sockets use a dedicated
accept-backlog row whose pending/limit values are connection counts, not bytes,
and suppress connection-only traffic, RTT, window, and recovery diagnostics.
TCP LIMIT BASIS shows adjacent-sample timing deltas, busy-time percentages,
the sample interval, current notsent and estimated flight/cwnd, and the exact
decision rule. RWND/SNDBUF use >=50% of busy time. CWND? and APP? are explicitly
marked estimates; missing evidence is UNKNOWN. UDP and listeners omit LIMIT.
When the selected identity is missing from the latest query, stale current
diagnostics are suppressed; the page retains explicitly last-observed identity
context.

The socket table collector and `/proc/<pid>/fd` owner scan stay active without
restarting while either the table or one selected-socket detail is open. They
stop only after both pages are left. Collection is bounded and reports partial
coverage when a query, permission boundary, or capacity limit prevents a
complete view. Endpoints, kernel socket identity, UID, PID, process name, and
selected-socket sampling state remain transient TUI state; they are excluded
from general monitor history, reports, logs, and ordinary `Debug` output.

Conntrack opens the live flow table directly. TX is original-direction traffic
from the initiator; RX is reply-direction traffic. These are not host-interface
TX/RX. Both directions show PPS, bandwidth and cumulative bytes. `s` cycles
total/directional bandwidth, PPS and byte sorting; `r` reverses the order.
PROTO and STATE are separate sortable columns. The traffic groups use
`traffic byte` and `avg pkt byte`; there is no lifetime column.
`Enter` or a second click on the selected row opens per-flow identity, original/reply tuples, NAT, counters
and diagnostics. An absent selected identity remains absent rather than changing
to a different connection. Detail groups connection properties, tuples/NAT,
TX/RX traffic, totals and sample coverage into bordered modules with colored
headings and aligned fields. Wide terminals use two columns; narrower windows
stack the modules and retain full address wrapping and scrolling. Sample
coverage describes the whole conntrack query, not just the selected flow.
`/` uses the same expression grammar as Socket,
for example `tcp and src net 192.168.0.0/24 and dst port 443`.
New expressions match only the original tuple, including unqualified host/port
predicates. Legacy key=value and bare-token filters keep their previous implicit
AND and NAT-aware unqualified host/port behavior. Empty input or `Ctrl+u`
clears the filter. Each connection
page independently remembers filtering and sorting across page changes until exit.
Filters search retained flows only; `TRUNCATED` means some matches may be omitted.
Offload or disabled accounting may make counters unavailable or incomplete.

The legacy `:netfilter` section retains the four-item menu: Conntrack,
iptables IPv4, iptables IPv6 and nftables. Its Conntrack health detail can also
open the same flow table.

`Enter` on a rules backend opens its chain list, and `Enter` on a chain opens
the rules in that chain. The chain view shows family/table membership,
hook/priority, policy/type, rule and counter coverage, rule hits, and explicit
DROP/REJECT rates. iptables presents a chain-first view and lists every table
represented by a chain; nftables retains table in the chain identity because
different nft tables may use the same chain name. The rule view keeps one rule
per row with its table, position, bounded match/action summary, verdict, PPS,
bit rate, packet total, and byte total.

Rule counters are match counters, not proof that packets were dropped. Only an
explicit DROP or REJECT verdict is presented as a discard; QUEUE means delivery
to userspace and does not reveal the later userspace verdict. A NAT rule counter
often measures only rule evaluation for a connection's first packet, so it is
not a whole-connection traffic counter. A rule with no counter remains in the
inventory and displays `NO COUNTER`, never a synthetic zero.

Native nftables, nft-backed iptables, legacy iptables, and an unidentifiable
iptables backend retain distinct backend identities. Native nftables and
iptables-nft can expose the same underlying rules on some hosts, so their
counters must not be added. A detected nft flowtable makes the nft provider
Partial because classic rule counters cannot provide complete visibility into
flowtable or hardware-offloaded traffic. If `nft`, `iptables-save`, or
`ip6tables-save` is absent, that menu item reports Unsupported; insufficient
privilege reports Permission. Neither condition is rendered as zero traffic.

`Esc` returns from a selected-socket detail to its socket table before following
the usual table-to-layer-to-Overview path. Other details return to the same
Overview selection and scroll position. Refresh preserves an interface's
complete name-plus-ifindex identity. If that identity disappears while its
detail is open, the page reports `NO LONGER OBSERVED`; returning selects the
nearest remaining interface at the previous stable position. Display pause
freezes this reconciliation until display updates resume.

## Keyboard Input

| Input | Action |
| --- | --- |
| `Up` or `k` | Select the previous global layer/interface in Overview, interface layer, or table row; otherwise scroll up one row. |
| `Down` or `j` | Select the next global layer/interface in Overview, interface layer, or table row; otherwise scroll down one row. |
| `Enter` | Open the selected Overview item or interface layer; in Netfilter, open the selected menu item, chain, or Conntrack flow table; open a Socket table or selected socket detail; submit command input. |
| `Esc` | Return one level through rule, chain, menu, object detail, table, interface layer, and Overview pages while restoring the previous selection; cancel command input. |
| `Tab` / `Shift+Tab` | Select the next / previous page. |
| `s` / `r` | Cycle sorting / reverse sorting in Netdev, TC and Conntrack. |
| `v` | Switch the TC table between queue and traffic metrics. |
| `/` | In Socket/Conntrack, filter IP/CIDR, host/port, protocol and source/destination. |
| `Ctrl+u` | Clear the current connection filter, including while editing; sorting is preserved. |
| `a` | Toggle metrics with signal/all current rows in an Enter-opened layer/interface or socket detail, including zero and `n/a` socket diagnostics; insert `a` in command mode. |
| `PageUp` or `PageDown` | Move one visible page in the socket table; scroll ten rows in other tables and details. |
| `Home` | Return to the first table row. |
| `:` | Enter command mode. |
| `p` or `Space` | Toggle display pause. The monitor worker and history continue sampling. |
| `t` | Toggle the metric column between interval rate/delta and since-baseline values; selected-socket detail has no such projection. |
| `q` or `Ctrl+C` | Stop the monitor, join its worker, restore the terminal, and exit. |

Outside an Enter-opened detail, `a` has no navigation action. Left/Right and
`0` through `9` also have no navigation action. Page labels and supported table
rows accept left clicks; the mouse wheel scrolls the active view.

While command mode is active, printable characters are inserted into the
command buffer, `Backspace` deletes one character, `Enter` submits, and `Esc`
cancels. A `q` typed in command mode is text until the command is submitted.

## Colon Commands

A section can be selected either directly or with the `section` prefix:

```text
:softirq
:section softirq
:providers
```

A named non-Overview section is a direct detail entry. `Esc` returns from it
through the same Overview restoration path used by Enter-opened details.

The other accepted commands are:

| Command | Action |
| --- | --- |
| `:pause` | Toggle display pause. |
| `:time` | Toggle interval and since-baseline values; it has no effect in selected-socket detail. |
| `:q` or `:quit` | Quit. |

`:next`, `:prev`, and `:previous` are not commands. As with any unknown command,
entering one leaves the monitor running and displays an error in the footer.

## Data And Time Semantics

The v1 process reads bounded kernel/exported counters, gauges, and states; it
does not enable event instrumentation:

- `/proc/net/snmp` and `/proc/net/netstat` for current-network-namespace TCP,
  UDP, IPv4, and extended TCP counters represented in the monitor catalog.
- `/proc/net/snmp6`, `/proc/net/sockstat`, and `/proc/net/sockstat6` for IPv6,
  socket inventory, and protocol-memory gauges.
- Native, bounded `NETLINK_SOCK_DIAG` dumps for the on-demand INET TCP/UDP
  socket table, with bounded `/proc/<pid>/fd` process-owner mapping.
- Procfs/sysfs conntrack sources for table use and per-CPU counters.
- Bounded, read-only `iptables-save -c`, `ip6tables-save -c`, and
  `nft -j -a list ruleset` commands for current-network-namespace policy,
  chain, rule, verdict, and available packet/byte counter data.
- Native bounded `RTM_GETQDISC` dumps on a persistent Netlink socket, with a
  bounded `tc -s -j qdisc show` fallback when native decoding or collection is
  unavailable. Statistics include backlog, requeues, maximum packet size,
  queue-limit drops, ECN marks and exported flow-list counters. Root, parent
  and handle metadata remain explicit; parent/child objects are never summed.
- Native rtnetlink link statistics for visible interfaces, falling back first
  to `/sys/class/net/*/statistics` and then `/proc/net/dev` when needed. The
  folded proc RX `drop`, RX `frame`, and TX `carrier` columns are not used as
  exact canonical field fallbacks.
- Sysfs link state, driver, queue counts, and TX queue length plus bounded
  ordinary-ethtool, ring, pause, feature, coalescing, and `ethtool -S` probes
  for hardware-backed interfaces. Settings refresh approximately every 30
  seconds while needed; `-S` follows the page-dependent cadence above.
- `/proc/softirqs` for per-CPU `NET_RX` and `NET_TX` activity.
- `/proc/net/softnet_stat` plus the online CPU list for per-CPU softnet
  processed, dropped, time-squeeze, RPS softirq/IPI-trigger, and flow-limit
  counters. The RPS field counts trigger occurrences, not packets.
- `/proc/interrupts` for hard interrupt activity only after a NIC-to-IRQ
  relationship is verified through sysfs; description strings are ignored.

The monitor does not load or attach BPF, inspect packet payloads, install rules,
or modify nftables, TC, XDP, sysctls, or interface configuration. Provider
permission, parse, I/O, and unsupported states are reported independently; a
missing source is never interpreted as a zero counter.

Link-stat fallbacks are normalized only after the interface name and ifindex
have been validated. Switching among rtnetlink, sysfs, and `/proc/net/dev`
therefore updates one canonical interface series rather than creating a row per
source.

A counter's raw current value is distinct from its interval delta/rate and the
column labelled `SINCE BASELINE`. A series observed on the initial collection
cycle has origin `SessionStart`; one first observed later has `FirstObserved`
and an earlier coverage gap. An unverified decrease uses `Reset`, while the
first fresh value after missing data uses `RecoveredAfterGap`; both start a new
baseline and suppress a cross-boundary delta. A verified wrap remains
continuous.

History is in-memory and process-local. Each admitted general-monitor metric
series retains at most 16 buckets. When
capacity fills, the two oldest buckets are merged repeatedly, so resolution
becomes coarser while session-span coverage is retained. A merged counter
bucket keeps the highest observed interval rate it contains rather than
replacing a spike with an average. Pausing the display does not pause history,
and exiting does not persist it.

Selected-socket rates use consecutive observations of the same private kernel
identity while the socket collector is active. Missing observations or counter
discontinuities make the affected rate unavailable rather than inserting zero.
Leaving the selected detail discards its selection state; the collector stays
active while the socket table remains open.

All pages show numerical values without trend graphs or trend columns. The
`t`/`:time` control switches Overview and general detail tables between interval
and since-baseline values. Selected-socket detail shows live socket values, so
the time projection control is disabled there. The old `h` shortcut has no
action and `:history` is no longer a command.

## Exit Status

| Code | Meaning |
| --- | --- |
| `0` | The user quit the monitor normally. |
| `2` | clap rejected an argument, or the monitor plan was invalid. |
| `3` | An interactive terminal was unavailable, or monitor/TUI startup or runtime failed. |

An external `SIGINT` or `SIGTERM` follows the runtime-failure path and exits
with `3` after the monitor worker has stopped and the terminal has been
restored. The in-terminal `Ctrl+C` key is a normal interactive quit and exits
with `0`.

The v1 CLI is read-only. Availability of a provider may depend on the running
kernel, namespace, permissions, and exposed files, but one unavailable provider
does not stop the remaining sections from updating.
