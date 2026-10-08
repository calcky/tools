# droptop

Continuously aggregate Linux `skb:kfree_skb` drop events by reason, interface or call site. Select a hot group to inspect recent skb samples and kernel call stacks.

## Installation

Install the x86_64 binary from [droptop-release](https://github.com/calcky/tools/releases/tag/droptop-release). The same Release provides ARMv7 and ARM64 binaries.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/droptop-release/droptop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 droptop-linux-x86_64 "$HOME/.local/bin/droptop"
```

Running the tool requires root or equivalent BPF and tracing capabilities. The examples assume those permissions are available.

## Common Commands

```sh
droptop                 # reason + interface, live window
droptop -i eth0         # drops associated with eth0 at the drop point
droptop -g reason       # group across interfaces by reason
droptop -g site -c 5   # five plain-text samples by call site
droptop -d 0.5 -c 10   # half-second samples, suitable for redirection
```

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Filter by `skb->dev` at the drop point in the current network namespace; not the original ingress interface. Events with no associated device are excluded. |
| `-d SEC` | Sampling interval, 0.1-60 seconds; default 1. |
| `-c N` | Print N text samples without opening the live window. |
| `-g pair\|reason\|device\|site` | Initial grouping; default `pair` (reason + interface). |
| `-h` / `-V` | Help / version. |

## Window And Metrics

The top table ranks groups by `drop/s`; the middle timeline shows recent skb samples from the selected group; the bottom shows the selected packet metadata and a hot call stack for the **group**. The stack is not attributed to the selected skb. At widths of at least 105 columns, the bottom panels sit side by side; otherwise they stack vertically.

Tracepoint wrappers and the leading `kfree_skb_reason` frame are hidden so the first frame shows the drop caller.

Use `j/k` or arrow keys to select a group, `[` / `]` to browse samples, Left/Right to choose a hot path, PageUp/PageDown to scroll stack frames, `g` to cycle grouping and `q` to quit. After changing groups, wait for new drops to populate its samples and stacks. `-c` text mode prints only the top 30 groups per sample; it does not collect skb samples or stacks.

**Space pauses/resumes**. `PAUSED` freezes rates, totals, samples and stacks while allowing detail navigation and regrouping of frozen counters. Details are retained only for the group selected when pausing; other groups show no captured details, and returning to the captured group restores them. Global kernel drop counting continues, but stack and skb sampling stop. Resume collects fresh details and starts a new rate baseline: paused events remain in `TOTAL` without causing a rate spike.

- `drop/s` is the count increase divided by the measured interval; `TOTAL` counts events since probe attachment.
- The sample timeline shows observation time, protocol, length, CPU, TID, `PROCESS [FD]` as `name(PID)`, and flow. The call site appears at 105 columns and the reason at 120 columns. Column widths adapt to the contents; values that cannot fit end in `...`.
- Sample details include `skb_iif` (receive ifindex) and `skb->dev` (device at the drop point). Neither reliably identifies the original physical ingress interface; addresses and ports may be post-NAT.
- `CPU` is where the drop was observed. `PROC [FD snapshot]` lists local holders of descriptors matching the associated socket inode as `name(PID)`. This is a later lookup snapshot, not proof of the sender or the process responsible for the drop. Shared sockets may have several holders; up to two are shown with `+N` for others. Incomplete lookups say `partial`; unverified associations stay `-`, without five-tuple inference.
- Thread information appears in the timeline and at the top of `Selected skb`. `TID` and `THREAD` remain `-` unless thread attribution can be proven. The current softirq/interrupted task or a socket's holding process cannot establish which thread owns a packet, so this version does not infer a thread from them. A thread's process PID is the `Tgid` field in `/proc/<tid>/status`; it may differ from its TID. FD lookup results also freeze on pause.
- `map` and `stack` report aggregation-map misses and stack capture or aggregation failures. The sample header's `limit`, `ring` and `user` counters expose sample loss without changing the separate full-rate drop counts. `limit` and `ring` are interval deltas; `user` is cumulative since startup.

## Scope And Requirements

This counts only events reaching `skb:kfree_skb`. NIC hardware drops, early XDP DROP, AF_XDP ring failures and application-level loss may not appear. Do not add these counters directly to drop counters from other layers. Reasons such as `NOT_SPECIFIED` alone do not establish a network fault.

Reason names come from the running kernel's BTF `skb_drop_reason` enum. Unreadable headers, non-initial IPv4 fragments and IPv6 extension headers are marked incomplete; ports are not guessed. A call site is a kernel location, not the responsible process. If `/proc/kallsyms` hides symbols, locations remain hexadecimal.

Requires Linux 6.6+, `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_DEBUG_INFO_BTF`, `/sys/kernel/btf/vmlinux` and the `skb:kfree_skb` tracepoint. See the [project manual](https://github.com/calcky/tools/blob/master/droptop/README.md) for full semantics.
