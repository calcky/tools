# ctop

Read-only Linux conntrack monitoring for gateways and application servers.
Combines an initial Netlink snapshot, NEW/UPDATE/DESTROY events and periodic
full calibration. Uses the current network namespace; no packet capture,
firewall changes or automatic sysctl changes.

```sh
make ctop                       # from the repository root
sudo ./bin/ctop                 # live window, group by original source IP
sudo ./bin/ctop -g none         # one conntrack entry per row
sudo ./bin/ctop -g none -p tcp -D 443
sudo ./bin/ctop -g dst,dport,proto
sudo ./bin/ctop -g src,dst -p tcp
sudo ./bin/ctop -g mark
sudo ./bin/ctop -g mark,src
sudo ./bin/ctop -g dport -r 1    # sample bandwidth roughly every second
sudo ./bin/ctop -N -g src,sport
sudo ./bin/ctop -s 192.168.1.10 -D 443 -p tcp
sudo ./bin/ctop -b -c 3         # plain reports
./bin/ctop -f conntrack.txt     # static snapshot, no root required
sudo conntrack -L | ./bin/ctop -f
sudo ip netns exec router ./bin/ctop
```

Build requires Rust 1.88+. Running requires CAP_NET_ADMIN in the target network
namespace, an active conntrack subsystem and ctnetlink support. `sudo` is the usual
way to obtain permission. Containers need access to the namespace being diagnosed;
running inside an ordinary container shows that container's connections only.
The name overlaps some unrelated container-monitoring tools, so use `./bin/ctop`
or the full installed path when both are present.

Prebuilt musl static executables are available from the
[ctop releases](https://github.com/calcky/tools/releases/tag/ctop-v0.1.0):
`ctop-linux-arm` (ARMv7 hard-float), `ctop-linux-arm64`, and `ctop-linux-x86_64`.
They are direct binary downloads; apply `chmod +x` before running.
The `Build ctop` workflow tests all three targets, checks static linkage and
publishes version-tagged releases.

## Options

| Option | Meaning |
| --- | --- |
| `-f [FILE]` | Load a static `conntrack -L` text snapshot; no filename or `-` reads stdin until EOF |
| `-g FIELDS` | Comma-separated `src,sport,dst,dport,proto,zone,mark`; default `src`; `none` lists individual CT entries |
| `-N` | Group by translated forward endpoints, obtained by reversing the reply tuple |
| `-s IP`, `-d IP` | Exact original source/destination IP, IPv4 or IPv6 |
| `-S PORT`, `-D PORT` | Original source/destination port |
| `-p PROTO` | `tcp`, `udp`, `icmp`, `icmp6`, `sctp`, or protocol number |
| `-z ZONE` | Original zone filter |
| `-i SEC` | Report interval; default 1, minimum 0.2 |
| `-r SEC` | Full calibration interval; default 5, minimum 1 |
| `-W SEC` | Observed-state age threshold; default 10, minimum 1 |
| `-m N` | Minimum live sessions per group; default 0 (includes recently deleted groups) |
| `-b` | Plain periodic reports; automatic for redirected output or `TERM=dumb` |
| `-c N` | Stop after N reports; implies `-b` |
| `-h`, `-v` | Help and version |

Filters always use original tuples, even in the NAT view. Groups with different
original/reply zones remain separate. ICMP has an ID/type/code identity, not port 0;
port aggregation displays `-` for protocols without ports.

## Static Files

```sh
sudo conntrack -L -o extended > conntrack.txt
./bin/ctop -f conntrack.txt -g dst,dport,proto
./bin/ctop -f conntrack.txt -g mark,src
sudo conntrack -L | ./bin/ctop -f
./bin/ctop -f conntrack.txt -g none -b
```

Static mode needs no CAP_NET_ADMIN and does not open a netlink socket or read
local kernel statistics. The window is labeled `STATIC`; grouping, drilldown,
search, NAT view and filters work as in live mode. Piped input is consumed to EOF,
then keyboard input comes from `/dev/tty`. Redirected output, `TERM=dumb`, `-b`,
or no available input terminal produces one report and exits, regardless of `-c`.

Both normal and extended text layouts are accepted, including IPv4/IPv6 TCP,
UDP, ICMP/ICMPv6, SCTP, DCCP and UDP-Lite. Original/reply counters, marks and zones
are retained when present. NAT is inferred from the two tuples. Missing counters
and marks stay `N/A`. Only counters already present in the dump can be displayed;
`-o extended` does not enable kernel accounting.

A single snapshot has no bandwidth, lifecycle rates or observed state duration;
these show `N/A` and do not increase while browsing. Saved TTL is not connection
age. Empty files are valid empty snapshots. Blank lines, `#` comments and the
conntrack summary are ignored; malformed/unsupported records and duplicate
connections stop loading with a source and line number. Supply one snapshot,
not concatenated dumps, XML or `conntrack -E` event output.

`mark` is the conntrack mark (`CTA_MARK`), not the per-packet skb mark. It is
displayed in hexadecimal: `0x0` is zero, while `N/A` means the attribute was not
available. Live mark updates move entries between groups and drilldown scopes.
NEW/DESTROY rates use the mark observed at event time; a mark UPDATE does not
count as a new or destroyed connection.

## Window

The header shows namespace, global allocated entries/maximum, occupancy, cached
entries, collection status and capture gaps. Kernel deltas `+fail`, `+drop` and
`+early` are the sums of per-CPU `insert_failed`, `drop` and `early_drop`. They
describe the namespace, not the selected group. Allocated and cached counts can
differ during churn, snapshots or while unconfirmed/dying entries exist.

The group table always shows live session count, original/reply bandwidth and
total packets, including at 70- or 80-column widths. At 120+ columns it also shows
observed NEW/DESTROY rates, UNREPLIED and TCP SYN-state count; these remain available
in details on narrower screens. Flags appear at 160+ columns and in details.
Grouping fields have their own aligned headings: service shows Destination,
Dst port and Proto; pair shows Source and Destination. Ports, protocols and
marks have distinct colors (disabled by `NO_COLOR`). When space is insufficient,
group fields stack into labeled lines, keeping bandwidth and packets visible.
The individual connection table always shows Mark, bandwidth and packets;
state is added at 100+ columns and remains available in details.
These are conntrack entries, not
necessarily application sessions. `New/s` and `End/s` are event counts divided by
the measured report interval. `End/s` is not successful TCP closure. The initial
window, disabled events and known collection gaps show `N/A` rates. Event mode
`auto` may omit notifications for older entries that lack event extensions;
periodic snapshots correct membership but cannot recover lost lifecycle history.

| Key | Action |
| --- | --- |
| `0` | Toggle individual CT / grouped view, keeping CLI filters and the current drilldown scope |
| `1`..`6` | Regroup the current scope by source IP, target service, source/destination pair, protocol, source port, destination port |
| `7` | Regroup the current scope by conntrack mark |
| `g` | Edit the grouping field list; Ctrl+U clears it, Enter applies |
| `n` | Toggle original / translated forward view |
| `/` | Search group labels, or displayed tuple/protocol/state/hexadecimal mark in individual CT view |
| `s` | Sort by sessions, new events, unreplied or observed-aged counts |
| Enter | Enter the selected group and inspect its connections; use `1`..`7` or `g` to regroup within it |
| Esc | Return one level, restoring the parent grouping, direction, search and selection; clear search at the root |
| Arrows / `j/k`, PgUp/PgDn | Select and page |
| `[` / `]` | Scroll details, particularly on a small terminal |
| `q` / Ctrl+C | Exit |
| `h` | Open help with all keys and metric definitions; `h` or Esc closes, arrows / `j/k` / PgUp / PgDn scroll |

`-g none` works in both the live window and plain reports. Each row is a separate
conntrack entry, even when endpoints match in different zones. Individual rows
show the tuple, Mark and directional bandwidth/packet counters; wide terminals add
state. ID, zone, TTL and state duration stay in Details, not the connection list
or plain report columns. Ordering is by original
tuple, zone and ID; live refresh preserves the selected entry when possible.
`0` does not add a drilldown level. `1`..`7` or `g` selects a grouping; `g` accepts
`none` too. Switching views clears the display search, not CLI or ancestor filters.
The `-m` minimum applies only to grouped views.

For example, press `6`, select port `443`, press Enter, then `1` to group only
that port's connections by source IP. Select an IP and press Enter again;
`2` now groups that IP's port-443 connections by target service. Each Enter
adds a filter, shown in the header path; Esc removes one level (up to 16 levels).
Regrouping includes all matching cached entries, not just the 5,000 displayed
connections, and applies the same scope to NEW/DESTROY rates. New matching
connections appear automatically. Changing original/NAT view affects the current
display and grouping; ancestor filters retain the direction used when entered.

Details include state and protocol distributions, distinct destination IPs and
protocol/port pairs, NAT count, cumulative original/reply bytes and accounting
coverage. Session detail retains original, translated and reply tuples, zone,
ID, mark, sampled timeout, packet/byte counters and observed state duration.
The window follows layout A: capacity, kernel/capture health and accounting at
the top; the connection table remains central. At 120+ columns, group Details
separates **TRAFFIC**, **STATES** and **SIGNALS**; individual connections use
**TRAFFIC**, **ENDPOINTS** and **STATE**. Traffic aligns original/reply bandwidth,
packets and bytes in one table. State bars show connection proportions; TIME_WAIT
remains neutral. Sustained SYN/unreplied counts are highlighted as investigation
hints. Narrow screens stack these sections. Details scroll with `[` / `]`,
including long endpoint tuples and coverage counts. Shortcut keys are bold yellow;
`NO_COLOR` keeps the bold emphasis. Help does not pause collection or change the
current selection or drilldown scope. The latest collector message is in help.
Prefer an 120x32 or wider terminal; 70x20 is the minimum. Small screens keep flags
and extended information in the scrollable detail pane. `NO_COLOR` disables color;
text labels remain. Errors, signals and panic restore the terminal.

## Interpreting Flags

- `SYN-aged`: TCP SYN_SENT/SYN_RECV/SYN_SENT2 observed for at least `-W` seconds.
- `unreplied-aged`: entry observed for at least `-W` seconds with no reply seen.
- `closing-aged`: a TCP closing state observed for at least `-W` seconds.
- `fanout`: a source-IP group has at least 128 distinct current destination IPs
  or protocol/port pairs; the flag reports both counts. This is a current-table
  observation, not a historical scan detector.
- Occupancy at or above 80% is highlighted. Nonzero kernel error deltas are red.

These are investigation hints, not automatic failure diagnoses. One-way UDP is
legitimate; TIME_WAIT is normal. Conntrack TCP states reflect observed packets,
not a process's socket state. Asymmetric routing and offload can limit visibility.
No RTT, TCP retransmission rate or directional packet-loss rate is inferred.

Packet/byte counters require per-entry accounting. Missing counters show `N/A`;
`*` marks partial totals, with directional coverage counts in group details.
`Packets` in the main table sums both directions; details and plain reports show
original/reply separately. These are cumulative counters of **currently cached live
connections**, not totals since ctop started; deleting a connection removes its
counters from the group. NAT view does not swap the counter directions.

Bandwidth uses per-connection byte deltas between two successful full snapshots,
divided by actual elapsed monotonic time, displayed in decimal bit/s, kb/s, Mb/s
or Gb/s. It updates on `-r` (default 5s), independently of screen/report refresh `-i`;
it is a sampled average of surviving connections, not total interface throughput.
Traffic from connections that disappear between snapshots is not included.
New entries, missing accounting/identity, counter resets and capture gaps show
`N/A` until two comparable samples exist. Partial groups show `*`. UPDATE events
never advance the bandwidth baseline because they are not per-packet notifications.
No extra polling is performed for bandwidth.

`nf_conntrack_acct` only provides counters for entries created with accounting
enabled; ctop does not change it. Connection age uses kernel
timestamps when available, otherwise it is labeled observed duration. Remaining
timeout is the value at sampling time and is never used as connection age.

## Collection And Limits

The event socket is subscribed before the initial dump. Events received during a
dump are replayed over the completed snapshot. Interrupted/truncated snapshots
never replace the previous cache; it remains marked STALE until resynchronization.
Kernel ENOBUFS, malformed messages and replay overflow invalidate rates and trigger
a new snapshot. Old dump sequences and late deletes for replaced IDs are ignored.
Netlink dumps are not atomic, so membership is eventually consistent during churn.

The cache/snapshot limit is two million entries; exceeding it stops with an error.
Replay and report windows hold at most 100,000 events each; overflow is visible.
Individual CT views and drilldown keep a 5,000-entry display window; navigation
loads adjacent windows, so all matching cached entries remain accessible. The
title shows the window range and total, and plain reports emit every matching
entry. Sorting uses a temporary index of references to the cache; individual
views skip group aggregation. Apply narrower filters for very large groups. Aggregation
and full snapshots are O(table size); this release has not been benchmarked on
million-entry production tables. Increase `-i`/`-r` to reduce refresh work.

## Verification

```sh
make check-ctop
```

Unit tests cover Netlink framing, IPv4/IPv6 and ICMP parsing, NAT/zone grouping,
filters, snapshot/event reconciliation, stale generations, counter availability,
state age and narrow/wide monochrome terminal layouts.

`CTOP_BIN=./bin/ctop python3 ctop/tests/offline.py` checks static files, piped
input, counters, NAT, filters, malformed input and terminal interactions without
root. It requires Python 3 with `pyte`. Parser tests also cover ICMP identifiers,
directional zones and unavailable values; static views never accrue observed age.

`tests/live.py` exercises real IPv4/IPv6 TCP/UDP, DNAT/SNAT, lifecycle events and
PTY interactions. It requires Python 3 with `pyte`, iptables, conntrack, CAP_NET_ADMIN and
`CTOP_LIVE_ISOLATED=1`. Run **only in a disposable isolated network namespace**:
the harness installs test firewall rules. Set `CTOP_BIN` to the built executable
and provide a writable `/checks` directory for the PTY transcript. Optional Docker
`--sysctl net.netfilter.nf_conntrack_acct=1` and
`--sysctl net.netfilter.nf_conntrack_timestamp=1` exercise accounting and timestamps.
