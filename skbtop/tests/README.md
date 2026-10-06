# Network namespace fixtures

These nslab manifests exercise dual-stack routing and Linux bridge forwarding
with skbtop observing the forwarding node's network namespace. The routed
fixture also provides local INPUT/OUTPUT traffic. They use namespace-local
veth interfaces and the same manifest patterns as nslab's `ipv4-forward`,
`ipv6-forward` and `bridge-fdb` examples.

Run the commands from the tools repository root in a root shell. Install
`nslab` 0.6.0 or newer, `skbtop`, `iproute2` and an IPv4/IPv6-capable `ping` on `PATH`.
The running kernel must provide the collector's BTF types, fentry targets and
BTF-typed tracepoints, including `tp_btf/netif_receive_skb`; a Linux version alone
does not establish probe availability. These are functional observation
fixtures, without throughput or latency performance thresholds.

## Isolated Validation

From a root shell, the runner creates uniquely named deployments for routed
IPv4/IPv6 INPUT/OUTPUT/FORWARD, IPv4/IPv6 masquerade, 20ms egress netem, bridge
unicast and bridge unknown-unicast flooding:

```sh
python3 skbtop/tests/nslab-smoke.py
```

Use `--nslab /path/to/nslab` for a source-checkout CLI, `--binary` for a
different built executable, or repeat `--case route|nat|netem|bridge|flood`
to run selected scenarios.

It copies the current `bin/skbtop` release executable, waits for a recorded interval before
sending traffic, checks completed path and latency coverage and verifies
interval/cumulative reconciliation. NAT rules must match both address
families; the netem case checks that the configured delay appears in queue
latency. The three-port flood fixture disables FDB learning so traffic to
one host also traverses the other egress port.

Neighbors are pinned before capture to distinguish the three requested flood
packets from ARP refresh traffic. Checks require matching directional
entry/completion counts, complete route/bridge classification, no unexpected
hairpins and no pending transmit associations after idle. Addressless bridge
ports must not acquire local INPUT rows from peer namespaces. Interface
indices, selected names and the observer namespace are saved with each case.

Each deployment is destroyed after its case. The copied executable, its hash,
ping and collector logs, rule/qdisc evidence, `validation.json` and recording
directories remain under the printed `/tmp/skbtop-validation-...` path.
The runner requires nftables and netem support as well as the tracing
prerequisites above. Read health counters and any failed checks before
interpreting these functional checks as complete coverage.

## UDP Load and Capacity

With `iperf3` and `bpftool` installed, run bounded paired loads in the routed
fixture from a root shell:

```sh
python3 skbtop/tests/nslab-benchmark.py --pairs 3 --seconds 8
```

The runner alternates baseline/collector order for 10 and 50 Mbit/s UDP using
512-byte payloads, with concurrent ICMP probes. It records received throughput,
UDP loss, endpoint CPU reports, external RTT p99, collector CPU/RSS/high-water
memory, kernel map memlock reports and collector health. RTT p99 and collector
stack p99 have different endpoints. Collector process CPU excludes BPF work
charged to packet-processing contexts; aggregate host CPU includes other work
on a shared machine. Reported map memlock is separate from process RSS and is
not a complete measurement of dynamically allocated kernel memory.

Separate 20ms netem runs exercise `-g 1`, `-m 2` and combined `-g 1 -m 2`.
Capacity checks retain existing paths, verify reported omissions and global
successful traffic beyond the recorded path cap, and check association/path
bounds independently of interval-statistics capacity and integrity errors.
Baseline runs reject another active skbtop process. Run these measurements
after other tracing fixtures have exited. Results and recordings remain under
`/tmp/skbtop-benchmark-...`; the owned topology is destroyed on exit.
Keep measured results with the local run artifacts, separately from these
reusable fixtures. The generated reports identify their executable hash.

## Interface Lifecycles, Hairpin and GSO

The default suite also requires `iperf3` and `ethtool` for its software GSO
case, plus nftables and bridge netfilter support for the dual-stack case.

```sh
python3 skbtop/tests/nslab-lifecycle.py
```

The runner covers five cases:

- `dynamic`: default discovery finds a newly added dummy interface, follows
  its rename, then distinguishes a replacement created with the same ifindex.
  The old lifetime retains six OUTPUT completions and the new lifetime three,
  with separate generations and a retained deleted-interface label.
- `selection`: explicitly selected routed interfaces remain selected after
  `eth0` becomes `uplink0`; the existing directed path identity keeps its
  counters across the rename.
- `hairpin`: the existing three-port flood fixture enables hairpin on `swp1`.
  Three non-IP broadcast frames produce three completions on each distinct
  branch: `swp1 -> swp1`, `swp1 -> swp2` and `swp1 -> swp3`.
- `bridge-netfilter`: IPv4 and IPv6 bridge netfilter are enabled, and both
  nftables family counters must record traffic. Every completed forwarding
  branch must have bridge classification without duplicated branch counts.
- `gso`: disables TSO/GSO on routed egress `eth1`, sends a three-second TCP
  load with iperf3, and requires more forward completions than ingress skbs
  to demonstrate software segmentation children. It retains feature settings
  and client/server JSON alongside the recording.

Each case checks complete recording, interval/cumulative reconciliation and
no pending transmit associations after idle. The runner sends SIGINT directly
to the isolated collector so it can finalize its recording; interrupting the
nslab wrapper can terminate the child before finalization. Cases retain their
recordings, destroy their own labs and support `--binary`, `--nslab` and
repeatable `--case dynamic|selection|hairpin|bridge-netfilter|gso`.

## Routed INPUT, OUTPUT and FORWARD

The topology is `h1:eth0 -- r1:eth0` and `r1:eth1 -- h2:eth0`, with separate
IPv4 and IPv6 subnets and explicit routes on both hosts.

In the first terminal, deploy and start the finite recording:

```sh
nslab graph -t skbtop/tests/nslab-route.yaml --format mermaid
nslab deploy -t skbtop/tests/nslab-route.yaml
nslab inspect -n skbtop-route
SKBTOP_ROUTE_OUTPUT=$(mktemp -d /tmp/skbtop-route.XXXXXX)
nslab exec -n skbtop-route -N r1 -- \
  skbtop -i eth0,eth1 -d 1 -c 60 -T 60 -o "$SKBTOP_ROUTE_OUTPUT"
```

After the collector prints its first interval, generate traffic in a second
root terminal. Successful replies check connectivity separately from probe
coverage. `-w` bounds each command if the topology is not reachable.

```sh
nslab exec -n skbtop-route -N h1 -- ping -4 -c 5 -w 10 198.51.100.2
nslab exec -n skbtop-route -N h2 -- ping -4 -c 5 -w 10 192.0.2.2
nslab exec -n skbtop-route -N h1 -- ping -6 -c 5 -w 10 2001:db8:2::2
nslab exec -n skbtop-route -N h2 -- ping -6 -c 5 -w 10 2001:db8:1::2
nslab exec -n skbtop-route -N r1 -- ping -4 -c 5 -w 10 192.0.2.2
nslab exec -n skbtop-route -N r1 -- ping -6 -c 5 -w 10 2001:db8:1::2
```

Check that the recording contains FORWARD rows for `eth0 -> eth1` and
`eth1 -> eth0`, with routed completions and nonempty STACK, QUEUE and TOTAL
latency distributions. The last two commands should also yield local OUTPUT
and INPUT rows on `eth0`. Address families share an interface-path identity,
so use the ping results to establish that each family traversed the fixture.

After the finite collector exits, keep the output directory and remove the
topology:

```sh
nslab destroy -n skbtop-route
```

## Bridged FORWARD

The topology is `h1:eth0 -- sw1:swp1` and `sw1:swp2 -- h2:eth0`. Both hosts
share an IPv4 subnet and an IPv6 subnet. `sw1` uses `br0` without STP or VLAN
filtering, and no IP router is required.

In the first terminal:

```sh
nslab graph -t skbtop/tests/nslab-bridge.yaml --format mermaid
nslab deploy -t skbtop/tests/nslab-bridge.yaml
nslab inspect -n skbtop-bridge
SKBTOP_BRIDGE_OUTPUT=$(mktemp -d /tmp/skbtop-bridge.XXXXXX)
nslab exec -n skbtop-bridge -N sw1 -- \
  skbtop -i swp1,swp2 -d 1 -c 60 -T 60 -o "$SKBTOP_BRIDGE_OUTPUT"
```

After the first collector interval, in the second root terminal:

```sh
nslab exec -n skbtop-bridge -N h1 -- ping -4 -c 5 -w 10 192.0.2.3
nslab exec -n skbtop-bridge -N h2 -- ping -4 -c 5 -w 10 192.0.2.2
nslab exec -n skbtop-bridge -N h1 -- ping -6 -c 5 -w 10 2001:db8:3::3
nslab exec -n skbtop-bridge -N h2 -- ping -6 -c 5 -w 10 2001:db8:3::2
```

Check for completed bridged FORWARD rows for `swp1 -> swp2` and
`swp2 -> swp1`. Keep both directions separate; do not merge their percentile
values. Neighbor discovery and ARP may add traffic, so do not require an exact
skb count equal to the number of ping requests.

After the finite recording exits:

```sh
nslab destroy -n skbtop-bridge
```

## Interpret a capture

Each output directory should contain `snapshots.jsonl`, `summary.json` and
`report.html`. Check recording completeness and reported health/accounting
errors before interpreting the path distributions. A successful ping with no
completed samples requires investigation of probe attachment and tracking;
it is not a zero-latency result. Startup failures and missing probes fail the
observation check even when traffic itself works.

Latency values are in `us`; min, average and max come from observed timestamp
differences, while percentiles are histogram estimates. STACK ends at egress
queue entry and QUEUE ends at the entry of the driver attempt that succeeds.
The interval is broader than pure qdisc residence time. Do not add stage
percentiles to predict a total percentile or compare these values to ping RTT
as though they had the same endpoints.

The manual examples exercise ordinary forwarding and local IP paths. The
runner adds NAT, netem and flood-clone scenarios; the benchmark adds bounded
capacity stress and the lifecycle runner adds interface identity changes,
selected-interface rename, hairpin branches and dual-stack bridge netfilter.
Its `gso` case exercises software segmentation with a bounded TCP load.
