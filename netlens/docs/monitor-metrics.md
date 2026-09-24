# Continuous monitor contract

The v1 monitor is an internal, counter-only contract for the default `netlens`
TUI. It is independent of the frozen Report DTO and never adds SoftIRQ or
HardIRQ to `model::Layer`.

The executable catalog in `src/monitor/catalog.rs` is authoritative. This
document records the rules collectors, the session engine, and the renderer
must share.

## Sections and ownership

| Collection section | Canonical owner | Primary sources | Minimum display groups |
|---|---|---|---|
| Socket | `linux.monitor.socket` | `/proc/net/snmp`, `netstat`, `snmp6`, `sockstat`, `sockstat6` | TCP state/activity/retransmit/reset/listen, UDP activity/errors, IP activity/errors, socket and memory gauges |
| Netfilter | `linux.monitor.netfilter` | conntrack proc/sysfs; bounded `iptables-save`, `ip6tables-save`, and structured `nft` rulesets | table capacity/utilization, lookup/insert pressure, explicit conntrack drop, chain inventory, rule verdicts, and available rule hit counters |
| TC | `linux.monitor.tc` | bounded native rtnetlink TC with validated `tc` JSON fallback | qdisc packet/byte activity, explicit and queue-limit drops, overlimit/requeue, backlog, ECN, maximum-packet, and flow-list statistics; class/filter/action data remains unsupported |
| Netdevice | `linux.monitor.netdevice` | rtnetlink link stats, sysfs, `/proc/net/dev` | per-interface RX/TX packets, bytes, generic errors/drops, multicast/no-handler |
| NIC | `linux.monitor.nic` | generic link stats, sysfs link/configuration, bounded ordinary/ring/pause/feature/coalescing ethtool and `ethtool -S` text | CRC/frame/FIFO/missed/carrier, link state, driver/queue/ring/flow-control/offload/coalescing settings, opaque private statistics; pause/FEC counters and verified ring-drop semantics remain unsupported |
| SoftIRQ | `linux.monitor.softirq` | `/proc/softirqs`, `/proc/net/softnet_stat`, `/proc/sys/net/core` | NET_RX/NET_TX, processed/dropped, time squeeze, RPS softirq/IPI triggers, flow limit and queue state per CPU, plus packet/time budget, backlog weight, and maximum backlog configuration |
| HardIRQ | `linux.monitor.hardirq` | `/proc/interrupts` plus verified sysfs mapping and interface `ethtool -c` context | network interrupt activity, CPU imbalance, aggregate affinity, and RX/TX interrupt-coalescing configuration |

Every descriptor has exactly one primary section and canonical owner. Its
ordered source list is a fallback priority list. Source provenance is part of
provider health, but it is not part of canonical series identity. Link adapters
must validate and attach the canonical interface name plus ifindex before a row
is admitted. A switch among rtnetlink, sysfs, and `/proc/net/dev` therefore
starts a recovered epoch on the existing interface series instead of creating
a duplicate row.

IPv4 and IPv6 protocol rows have distinct canonical IDs. They remain separate
even when their unit and aggregation domain match.

The numerical layout groups those canonical rows into Sockets, Transport,
Network, Conntrack, TC, SoftIRQ and Netdev presentation layers without changing
ownership. Combined-family and per-CPU summaries require fresh compatible
readings; partial providers cannot produce complete-looking aggregate totals.
`linux.socket.tcp.memory_max_pages` reads the third `/proc/sys/net/ipv4/tcp_mem`
threshold. TCP memory and that maximum are host-scoped kernel pages, converted
using the actual system page size. `linux.nic.mtu` is a current byte gauge and
reuses link metadata, with optional sysfs fallback.

TC keeps opaque row identity plus validated root/handle/parent attachment
metadata. Its Overview predicate is fresh positive drops/s OR requeues/s on
root egress qdiscs. A reset, gap, first observation, stale value or historical
cumulative total does not qualify. Roots, children and actions are different
accounting points and are never added together. Native counters retain their
known 32/64-bit widths so a validated wrap does not become a false reset;
JSON counters retain unknown widths. Native/JSON source changes establish a
new sampling epoch rather than differencing incompatible observations.

### Netfilter policy visibility

The Netfilter menu has four independent entries: Conntrack,
iptables IPv4, iptables IPv6, and nftables. Conntrack continues to use
`linux.proc.netfilter.conntrack`. The policy collectors execute bounded,
read-only `iptables-save -c`, `ip6tables-save -c`, and
`nft -j -a list ruleset` commands in the process's current network namespace.
Their provider IDs are `linux.iptables.ipv4`, `linux.iptables.ipv6`, and
`linux.nft.ruleset`.

Policy inventory uses these canonical metrics:

| Metric | Kind | Meaning |
|---|---|---|
| `linux.netfilter.chain.rules` | Gauge | Current rule count for one backend/family/table/chain identity |
| `linux.netfilter.chain.policy` | State | Base-chain policy when the source exports one; inventory, not a drop counter |
| `linux.netfilter.chain.type` | State | nftables base-chain type when exported |
| `linux.netfilter.rule.position` | Gauge | Current one-based position in the source chain |
| `linux.netfilter.rule.expression` | State | Bounded printable match/action summary |
| `linux.netfilter.rule.packets` | Counter | Packets that matched the rule's counter |
| `linux.netfilter.rule.bytes` | Counter | Bytes measured by the rule's counter |

Chain identity requires `backend + family + table + chain`. Rule identity adds
a nonzero session-local `row_id`, verdict, and optional source handle. The
backend label is one of `nftables`, `iptables_nft`, `iptables_legacy`, or
`iptables_unknown`. Backend, family, table, chain, rule, and source dimensions
are not reducible. In particular, native nftables and iptables-nft observations
must not be added: on an nft-backed host they can describe the same underlying
rules. IPv4 and IPv6 iptables providers also remain independent.

The renderer is chain-first. Within one iptables backend and family, chains
with the same name are shown once with their contributing tables listed; the
rule page retains each rule's table. nftables keeps
`family + table + chain` as the selectable identity because arbitrary nft
tables can reuse a chain name. The chain row reports the number of rules with
usable counters as `COUNTED`, so a partial sum is visible as partial coverage
rather than being mistaken for a complete chain total.

A rule hit is a policy match, not inherently a drop. Only an explicit `drop` or
`reject` verdict contributes to the displayed discard rates. `queue` means the
rule sent traffic to userspace; the userspace verdict remains unobserved. NAT
counters commonly reflect only rule evaluation for a connection's first
packet and must not be treated as whole-connection packet or byte totals.

Rules without an inline or resolved named counter still emit position,
expression, and verdict. Their packet and byte readings use
`UnavailableReason::Missing`; the rule page displays `NO COUNTER`, never zero.
A missing command maps that provider to Unsupported, while an execution or
kernel permission failure maps it to PermissionDenied. Other command, timeout,
output-bound, cardinality, and schema failures retain their typed provider
health and do not affect the independently collected Netfilter sources.

An nft ruleset containing one or more flowtables makes the nft provider
Partial. The classic chain/rule inventory remains available, but it cannot
claim complete packet visibility once software or hardware flowtable paths can
bypass those counters. The monitor does not infer the omitted traffic.

### Interface organization and link/NIC coverage

Overview first follows the global receive/transmit path through
Socket/Application, Transport, Network/Route, Netfilter/Conntrack, and SoftIRQ.
It then shows each visible, currently inventoried interface in a fixed six-row
block: identity/link/health, driver/duplex/queue configuration, flow-control and
segmentation features, RX summary, TX summary, and the primary `WHY` cause across
TC, Netdevice Core, Driver/NAPI, NIC/PHY, and HardIRQ. Without an explicit
interface anchor, a Fresh `linux.nic.link_state` value of exactly `down` removes
that interface from Overview and interface-grouped layer tables. Stale,
Unavailable, and every other link state remain visible; a matching
`--interface` or `--ifindex` anchor overrides the default hiding rule. RX and TX
summarize packets, bit/s, errors, and drops from the Netdevice counters. A rate
is present only for a fresh contiguous interval; first samples, stale rows,
resets, and gap recovery display `-` rather than a synthetic zero.

`linux.nic.interface_kind` is the authoritative inventory row once present.
Its Fresh or Stale projection keeps an interface in the inventory before the
link-state visibility rule is applied; an Unavailable projection removes the
historical identity from Overview even though the session retains its series
and history. This distinction lets an open detail page report `NO LONGER
OBSERVED` after hot unplug without discarding collected history. Snapshots
predating that inventory row fall back to any Fresh/Stale interface series.

Physical classification comes only from the existence of
`/sys/class/net/<interface>/device`; neither interface names nor ethtool success
are classification evidence. Physical interfaces precede virtual interfaces,
and each group is ordered by ifindex with name as a deterministic tie-breaker.
Health never changes ordering. Selection uses the complete interface name and
ifindex identity; deletion moves it to the same ordinal in the new stable list,
or the preceding final item when that ordinal no longer exists.

The dedicated interface page presents a selectable menu ordered TC/Qdisc,
Netdevice Core, Driver/NAPI, NIC/PHY, then HardIRQ. Each stage retains its status
heading and fixed summaries. The HardIRQ summary also shows that interface's
adaptive RX/TX, usecs, and frame coalescing settings when `ethtool -c` exposes
them. Opening a stage shows the collected series for only that interface and
stage. The default layer-detail projection includes
state values and numeric Fresh or Stale series whose current value, interval,
since-baseline projection, or all-session history is nonzero.
Numeric series that have remained zero, Unavailable series, and empty fixed-slot
placeholders are omitted. The `a` control exposes every series instantiated in
the current snapshot plus fixed summary placeholders, including zero and
Unavailable rows, but does not synthesize uninstantiated catalog metrics.
Opaque private NIC statistics intentionally have no interval or history
projection, so this filter uses only their current/last numeric value. Dynamic
opaque ethtool fields and collection gaps therefore remain reachable through
`a`. SoftIRQ remains host/per-CPU data and is never attributed to an interface
without evidence.

The 25 `rtnl_link_stats64` fields have one canonical catalog owner each:

- Netdevice owns `rx_packets`, `tx_packets`, `rx_bytes`, `tx_bytes`,
  `rx_errors`, `tx_errors`, `rx_dropped`, `tx_dropped`, `multicast`,
  `rx_compressed`, `tx_compressed`, `rx_nohandler`, and
  `rx_otherhost_dropped`.
- NIC owns `collisions`, `rx_length_errors`, `rx_over_errors`, `rx_crc_errors`,
  `rx_frame_errors`, `rx_fifo_errors`, `rx_missed_errors`,
  `tx_aborted_errors`, `tx_carrier_errors`, `tx_fifo_errors`,
  `tx_heartbeat_errors`, and `tx_window_errors`.

`carrier_changes` is an additional independent counter sourced from the
rtnetlink carrier-change attribute or the interface-root sysfs file. It is not
an alias for `tx_carrier_errors`. Sysfs and `/proc/net/dev` are field-by-field
fallbacks; a field absent from a fallback stays unavailable and is never filled
with zero. In particular, `/proc/net/dev` RX `drop`, RX `frame`, and TX
`carrier` each fold several `rtnl_link_stats64` fields together. They are not
used as fallbacks for any one exact canonical field.

Sysfs driver/queue settings and ordinary `ethtool <interface>` settings become
opaque current-only states. Successful bounded `ethtool -g`, `-a`, `-k`, and
`-c` probes add current and maximum ring lengths, flow-control state,
TSO/LRO/GRO/GSO state, and common coalescing state: adaptive RX/TX plus RX/TX
usecs and frames. The ordinary, ring, pause, feature, and coalescing probes run
at startup and refresh approximately every 30 seconds; cached settings remain
visible between refreshes. Cache reuse preserves the completion time and
collection duration of the NIC collection cycle that performed the actual
static refresh; it does not advance the reported settings attempt time or
replace its reported collection cost. `ethtool -S <interface>` remains a
separate dynamic provider and runs on every main sampling interval with
current-cycle timing. All valid `-S` fields become opaque current-only gauges,
including names matching generic link fields; text names never grant counter,
packet, error, or drop semantics. There is no 256-statistic parser cutoff. Each
provider attempt is limited to 4096 readings. Interface identity or outcome
rows are retained first, then payload is fairly interleaved before truncation;
rejected input, omitted readings, timeouts, and output limits are reported as
partial/error health.

Ring, flow-control, offload, and coalescing values are configuration context.
Their numeric or enabled/disabled values do not by themselves produce WARN or
CRIT health causes. The SoftIRQ detail similarly shows `netdev_budget`,
`netdev_budget_usecs`, `dev_weight`, and `netdev_max_backlog` as current-only
configuration above its per-CPU matrix. A configured zero remains visible;
missing settings remain distinct from zero.

Two interface-scoped state metrics make ethtool coverage independently
auditable:

| Metric | Provider | Dashboard block |
|---|---|---|
| `linux.nic.ethtool_settings_status` | `linux.ethtool.link_text` | NIC/PHY |
| `linux.nic.ethtool_statistics_status` | `linux.ethtool.text` | Driver/NAPI |

Both require the complete `interface + ifindex` identity and have opaque
packet-path attribution. Their closed values are `complete`, `refresh_pending`,
`partial_schema_mismatch`, `partial_cardinality_limit`, `unsupported`,
`command_not_found`, `permission_denied`, `interface_unavailable`, `timed_out`,
`output_limit`, `invalid_output`, `command_failed`, and `io_error`.

Newly observed hardware interfaces are refreshed immediately and enter the
cache under their complete interface and ifindex identity. The settings-only
`refresh_pending` value is reserved as a defensive fallback if an unrefreshed
cache miss reaches the translation boundary; it produces Partial coverage and
is not evidence that the interface is unavailable.

`complete` means Fresh collection coverage and contributes no network-health
evidence. `unsupported` and `command_not_found` mean Unsupported coverage. Every
other incomplete value means Partial coverage and emits an UNKNOWN
`collection_status` cause with threshold `complete`. For the two ethtool
providers only, a payload row inherits the matching interface outcome instead
of provider-wide health; this prevents one failed NIC from degrading a complete
NIC while retaining the failure on the affected NIC. Other providers continue
to propagate provider-wide Partial coverage to their interface rows.

Within a provider attempt, interface primary rows are admitted before payload:
sysfs interface kind before link state, and ethtool outcome before settings or
statistics. If even primary rows exceed the 4096 limit, the provider reports the
number of omitted interface outcomes separately. The 16384 admitted-session
series limit remains authoritative; rejected new identities are exposed through
engine telemetry rather than silently evicted.

## Input and projection

`ProviderSample` is one collection attempt. `Fresh` and `Partial` samples may
contain readings. `Partial` means that the included rows are current but some
rows or interfaces failed in the same attempt; its warning is visible in the
Providers view. A previously observed row omitted by a partial attempt becomes
stale with that warning, while successful rows remain fresh. A reading is
either an observed counter/gauge/state or a typed unavailable reason. Zero is
an observed value and is never used for missing, unsupported, denied, stale,
parse failure, negative sentinel, or overflow.

`MonitorSnapshot` is the immutable TUI projection. It owns session generation
and sequence, elapsed time, provider health, admitted series, history coverage,
and engine telemetry. Stale values exist only in this projection; a failed
provider sample never repeats its previous values.

Counter width is optional source metadata. A decreasing counter is a wrap only
when the source supplied a stable 32-bit or 64-bit width and the session can
prove the transition. Otherwise it is a reset.

| Counter transition | Projection rule |
|---|---|
| First fresh sample at session start | `SessionStart`; no interval delta/rate |
| First fresh sample after start | `FirstObserved`; earlier time remains a gap |
| Two contiguous fresh samples | exact delta and rate from their monotonic elapsed time |
| Verified width wrap | wrapped delta, width, and elapsed time |
| Unverified decrease | `Reset`; start a new baseline and suppress a cross-reset delta |
| Failed, stale, or omitted part of a partial attempt | retain last value with age; add no interval/history sample |
| First fresh sample after a gap | `RecoveredAfterGap`; do not calculate across the gap |

Gauge min/max/sum/count include fresh observations only. State continuity also
ends at a gap, even when the value before and after the gap is equal.

The renderer names the cumulative column `SINCE BASELINE` and maps each origin
to a visible label: `SessionStart` as `start`, `FirstObserved` as `first-seen`,
`Reset` as `reset-base`, and `RecoveredAfterGap` as `gap-base`.
Overview coverage is based on matching fresh series rows, not provider health
alone. Its closed states are `ACTIVE` when all minimum rows are fresh,
`PARTIAL` when some are fresh, `DEGRADED` when none are fresh and a provider
failed, `UNAVAILABLE` when a fresh provider produced no matching row,
`UNSUPPORTED` when only unsupported providers exist, and `NO PROVIDER` when no
catalogued provider snapshot exists.

## Aggregation

Aggregation is denied by default. A catalog descriptor may allow summing only
when all of the following match:

- canonical metric ID and actual source provenance;
- kind, unit, measurement domain, and source semantics;
- all non-reducible labels and entity scope;
- the declared target scope.

The only initial cross-row reduction is a per-CPU counter whose descriptor
declares `cpu` reducible to host scope. Interface, IP family, Netfilter backend,
table, chain, rule, TC row, and source labels are not implicitly reducible.
Existing host totals from
`softnet_stat` must not be admitted alongside catalog-reduced per-CPU rows.

TC row identity is a nonzero, session-local ID. Raw qdisc handles and hardware
queue indexes stay inside adapters. TC packet-like values use source units and
the source-statistic domain unless a future descriptor verifies a narrower
packet/GSO/skb measurement domain.

Every qdisc row also carries validated interface, ifindex, and qdisc-kind
labels. Direction is emitted only when the adapter can classify it without
duplicating one object; `clsact` therefore does not become two synthetic
counter rows. When exported by the qdisc, the adapter also retains `maxpacket`,
`drop_overlimit`, `new_flow_count`, `ecn_mark`, `new_flows_len`, and
`old_flows_len`; missing fields remain unavailable rather than becoming zero.

Unknown NIC private statistics are always `Gauge + SourceUnits + Source scope +
InformationOnly + no aggregation`. The renderer may show their current value
and source, but it must not produce interval change, rate, or since-baseline
projections, or infer counter, packet, drop, or ratio semantics from the
statistic name.

The TUI shows numerical current values, interval rates/deltas and since-baseline
statistics without trend graphs or trend columns. Byte-counter rates are
converted to bit/s; gaps and resets retain their existing rate-validity rules.
The internal bounded history remains available for metric visibility and
sampling contracts. Section changes, scrolling and display pause do not stop
collection or reset history.

## Bounds and privacy

- Sampling interval: `250ms..=60s`, default `1s`, whole milliseconds.
- Identifier and label value: at most 128 printable ASCII bytes.
- Labels per series: 8.
- Provider diagnostic: 256 printable ASCII bytes; no raw panic payload.
- Providers: 64; readings per provider attempt: 4096. Each ethtool command is
  also bounded to two seconds, 1 MiB stdout, and 64 KiB stderr. Each Netfilter
  policy command is bounded to two seconds, 4 MiB stdout, and 64 KiB stderr.
- Admitted session series: 16384.
- History: 262144 buckets and 64 MiB globally.

When the admitted-series limit is full, a new identity is rejected and counted
in `EngineTelemetry::rejected_series`; existing identities continue to update
and snapshot publication continues. The current engine does not evict series,
so `evicted_series` remains zero.

Raw IRQ numbers, interrupt vectors, RX/TX queue indexes, socket identity,
addresses, ports, tuples, kernel pointers, cookies, inodes, and UIDs are not in
the monitor label vocabulary. IRQ and TC adapters must replace required dynamic
identity with session-local numeric row IDs or aggregate it away before making
it a generic metric in a `ProviderSample`.

Conntrack tuples are the one display-only exception: they may exist in the
bounded snapshot owned by the Conntrack Flow TUI while that page is open. They
must be discarded when the page closes and must never enter generic metric
labels, session history, reports, logs, diagnostics, or non-redacted `Debug`
output.
