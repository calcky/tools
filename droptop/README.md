# droptop

`droptop` continuously aggregates Linux `skb:kfree_skb` events in eBPF. The
live view ranks drop rates by reason and network device. For the selected group,
it captures kernel call stacks and bounded skb metadata samples. It complements `netlens` counters,
`nettrace` packet-path traces, and `xsktop` AF_XDP socket statistics.

## Installation

Example for x86_64; the same [droptop-release](https://github.com/calcky/tools/releases/tag/droptop-release)
also provides arm and arm64 binaries.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/droptop-release/droptop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 droptop-linux-x86_64 "$HOME/.local/bin/droptop"
```

## Usage

The live view needs a terminal. Root or equivalent BPF/tracing capabilities
are required. `-c` prints a fixed number of samples to stdout without terminal
control sequences.

```sh
droptop                 # reason + device, live window
droptop -i eth0         # one interface in the current network namespace
droptop -g reason       # group all interfaces by drop reason
droptop -g site -c 5   # five text samples grouped by call site
droptop -d 0.5 -c 10   # half-second samples, suitable for redirection
```

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Filter by `skb->dev` at the drop point in the current network namespace; events without an associated device are excluded. This is not a filter on the original ingress interface. |
| `-d SECONDS` | Interval, 0.1 to 60 seconds; default 1. |
| `-c N` | Print N interval samples instead of opening the window. |
| `-g pair\|reason\|device\|site` | Initial aggregation; default `pair` (reason + device). |
| `-h`, `-V` | Help and version. |

In the live view, the top table ranks drop groups, the middle timeline lists
recent skb samples from the selected group, and the bottom shows the selected
sample plus a **group-level** hot-path stack. The stack is not attributed to
the selected skb. Tracepoint wrappers and the leading `kfree_skb_reason`
frame are hidden so the first frame shows the drop caller. At narrower terminal
widths the two bottom panels are
stacked; at 105 columns or wider they sit side by side. `j/k` or arrow keys
select a group, `[`/`]` browse older/newer skb samples, Left/Right select a
hot path, PageUp/PageDown scroll its frames, `g` cycles aggregation, and `q`
quits. A new group selection clears its stack and skb sample windows; wait for
new drops to see that group's call paths and packet metadata. `drop/s` is the
count increase over the measured interval, not a cumulative average. Rows with
zero recent rate stay below active rows so their stacks remain accessible.
`TOTAL` is the event count since attachment. Text mode prints the top 30 groups
per sample and does not collect stacks or skb samples. `map` reports drops
that could not be recorded after the bounded aggregation map filled; `stack`
reports failed stack capture or stack aggregation. A missing stack is not proof
that the selected reason has no call path.

Press **Space** to pause/resume. `PAUSED` freezes the displayed rates, totals,
samples and stacks; sample and stack navigation remain available. You can
change groups or aggregation to inspect the frozen counters, but details
are retained only for the group selected when pausing. Other groups show
"no captured details"; returning to the captured group restores its details.
Global kernel drop counting continues while paused; stack and skb sampling
stop. Resume starts fresh detail collection and a new rate baseline, so
paused events remain in `TOTAL` without appearing as a rate spike.

The skb timeline shows when each sample was observed since attachment, its
protocol, length, CPU, TID, `PROCESS [FD]` as `name(PID)`, and flow. At 105
columns it adds the call site, and at 120 columns it also shows the reason.
Column widths adapt to the samples; values that cannot fit end in `...`.
The selected skb panel starts with CPU/TID/thread information and shows its
reason, length, source and
destination addresses and TCP/UDP ports, drop call site, `skb_iif` (RX
ifindex), and
`skb->dev` (device associated at the drop point). `skb_iif` can be zero or
refer to a logical interface; it does not reliably identify the original
physical ingress port. Address/port values reflect the packet at the drop
point and may be post-NAT. Non-IP payloads, unreadable headers, non-initial
IPv4 fragments and IPv6 extension headers are explicitly marked incomplete;
ports are not guessed. The kernel allows at most four sample events per CPU
per second for the selected group, and the window keeps the latest 16. The
`limit`, `ring`, and `user` counters in the header disclose sample loss;
they do not affect the separate full-rate drop counters. `limit` and `ring`
are interval deltas; `user` is cumulative since startup.

The sample's `CPU` is the CPU that observed the drop. `PROC [FD snapshot]`
lists `name(PID)` for processes whose open descriptors match the inode of
`skb->sk->sk_socket` when available; it is a later `/proc` lookup, not proof
of the sender or the process responsible for dropping the packet. Shared
sockets can show several holders; up to two are shown with `+N` for others.
Lookups run in the background at most once per second, with a 50 ms / 25,000
descriptor budget and at most eight holders per socket; missing permissions
or limits produce `partial`. No associated inode or no verified FD holder
leaves `PROC` as `-`; there is no five-tuple inference. `TID` and `THREAD`
remain `-`: neither the current task in IRQ/softirq nor the process holding
a shared socket proves a packet's thread. Owner snapshots freeze on pause.
Linux TID identifies a thread; its process PID is the `Tgid` field in
`/proc/<tid>/status`, which may differ from the TID. An FD holder's PID is
not sufficient to infer the packet's TID.

Reason names come from the running kernel's BTF `skb_drop_reason` enum; unknown
values remain numeric. Device names resolve only in the current network
namespace; other namespaces are labeled with ifindex and namespace inode.
`unknown` means no device was available on the skb at this tracepoint. A call
site and stack are kernel locations, not packet ownership or the application
responsible for the condition. If `/proc/kallsyms` hides addresses, locations
remain hexadecimal.

## Scope and requirements

This counts events at `skb:kfree_skb`, not every possible packet loss. NIC
hardware drops, early XDP drops, AF_XDP ring failures and application-level
loss can occur without an skb reaching this tracepoint. Some reasons, especially
`NOT_SPECIFIED`, do not by themselves establish a network fault. Do not add
these counts to unrelated NIC or queue counters as if their scopes were
disjoint. Sampling call stacks and skb metadata adds per-event work only for
the selected group.

Requires Linux 6.6 or newer with `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`,
`CONFIG_DEBUG_INFO_BTF`, kernel BTF at `/sys/kernel/btf/vmlinux`, and the
`skb:kfree_skb` tracepoint. Loading the probe also requires BPF and tracing
permissions. Unavailable BTF or tracepoint support is reported at startup.

Build from the repository root with `make droptop`; verify with
`make check-droptop`. The executable is installed to `bin/droptop`.
