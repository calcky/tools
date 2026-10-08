# bpfmap

A read-only terminal viewer for full BPF map names, types, current counts, capacities, and entry changes. Watch map occupancy and a small set of keys live; use `bpftool` for one-off exports or modifications.

## Installation

For x86_64, install the static binary below. ARMv7 and ARM64 binaries and checksums are available in [bpfmap-release](https://github.com/calcky/tools/releases/tag/bpfmap-release).

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpfmap-release/bpfmap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpfmap-linux-x86_64 "$HOME/.local/bin/bpfmap"
```

On Linux 6.6, listing map IDs and opening a map by ID both require `CAP_SYS_ADMIN`; entry access also depends on map permissions. Automatic counts require Linux 6.6+, kernel BTF, map iterator/kfunc support, and BPF loading privileges, typically `CAP_BPF`/`CAP_PERFMON` or `CAP_SYS_ADMIN`. Metadata and previews remain available if counting cannot load. The commands below assume sufficient privileges.

## Common Commands

```sh
bpfmap                # List accessible maps
bpfmap -m 42          # Open map ID 42 directly
bpfmap -n 32 -d 2     # Preview up to 32 entries every 2 seconds
```

| Option | Meaning |
| --- | --- |
| `-m ID` | Open the specified map directly. |
| `-n N` | Show at most N matching entries per data page; default 64, range 1-256. |
| `-d SEC` | Entry and count refresh interval; default 1 second, range 0.2-60. Metadata refreshes every 5 seconds. |
| `-h` / `-V` | Help / version. |

Press `Enter` to open a map or expand an entry, `Tab` to switch Entries/Info, and `Esc` to go back. Use `j/k` or arrows to move/scroll, PgUp/PgDn to page, `r` to refresh and retry collection, `c` for a background key count scan, `h` for help, and `q` or Ctrl+C to quit. An interactive terminal is required. `NO_COLOR=1` disables colors.

In ordinary key/value tables, `/` searches displayed KEY/VALUE text case-insensitively, `f` performs an exact raw-key lookup (not available for longest-prefix-matching LPM Trie maps), and `x` clears the query. `[`/`]` read previous/next data pages; PgUp/PgDn only move within the current page. Enter full hex bytes in kernel memory order: little-endian u32 key 1 is `01 00 00 00`. Scanned counts and partial status describe coverage; an incomplete search does not prove absence.

## Details

KEY/VALUE use compact values or `field=value`, with recognized IPs shown directly. Verified flow keys use `sourceIP:port -> destinationIP:port TCP/UDP`; ICMP shows addresses and the Echo id. Columns adapt to content and have vertical separators. Long entries wrap to at most three lines; `...` indicates more content available with `Enter`. Zero reserved fields are omitted only in the list; details retain complete BTF and hex with space indentation. `Display`/`IP address` provide readable interpretations; BTF MEMORY VALUES retain memory values, which may differ for network-order ports.

IP examples: `192.168.200.1` and `fe80::62be:b4ff:fe2d:41bb`. Use `/` to search addresses, ports, or protocols. Supported schemas are `in_addr`/`in6_addr`, source/destination IP fields explicitly typed as `__be32`, and the verified `aiwan_xdp_local_ips`, IPv6 key, and flow key (address_family 4/6). Plain integers, standalone `__be32`, and ambiguous byte arrays are not guessed as IPs; without BTF, hex is kept. Exact lookup with `f` still takes raw key bytes, such as `c0 a8 c8 01`.

- **Entries**: bounded key/value preview. Press `Enter` again for expanded BTF fields, raw hex bytes, and individual per-CPU values, including zero values. Expansion follows the raw key; a key missing from the current preview is reported instead of showing stale data. CPU IDs unavailable from sysfs are labeled `CopyN`.
- **Per-CPU distribution**: BTF-verified unsigned integers show VALUE/DELTA/SHARE, with the greatest positive delta highlighted in bold. SHARE is a proportion of positive observed deltas. First samples show `-`; decreases show reset. Press `v` to explicitly interpret values as counters and add RATE/s using actual elapsed time. Packet/byte semantics are never inferred. Raw and BTF values remain available.
- **Reference entries**: ProgArray, ArrayOfMaps, and HashOfMaps show keys, target IDs, names, and type/capacity metadata. `Enter` opens an inner map or program type, UID, JIT size, and up to 64 referenced map IDs; `Esc` returns, with a maximum depth of 16. Lookups return object IDs, not FDs. Unreadable targets retain their IDs and show unavailable.
- **Info**: sections for configuration, counts, BTF/pins, and referencing programs show flags, frozen, memlock, map_extra, CPU copies, type IDs/declarations, and all visible pin paths. Memlock is kernel-reported allocation, not bytes used by occupied entries or process RSS. Frozen restricts userspace writes; program access is determined by flags.
- **Referencing programs**: ID, kernel name, type, and loader UID, taken from loaded programs' map references. These are not attachment locations or process owners. Background queries allow up to one second, 4096 programs, and 4096 map IDs per program; failures or limits are marked partial. Queries run on opening a map, every five seconds in Info, or on `r`.
- **XSKMAP**: opens a socket table showing KEY, IFACE, QUEUE, MODE (Copy/Zero-copy), and STATE (Ready: not bound yet; Bound; Unbound: binding removed). KEY is a map slot and **need not equal the queue ID**. Wide screens add IFINDEX/NETNS; narrow screens show them below the table. Interface names and namespace IDs come from the socket's device. `Enter` expands a binding and `Tab` opens Info; see [xsktop](../xsktop/README.md) for rings and activity. Other types without entry previews open Info by default.

## Reading The View

`NAME` recovers a unique full `.maps` BTF declaration matching the kernel prefix, map type, capacity, and key/value types. Without BTF or with ambiguous matches, the kernel name is kept instead of guessing. The selected-map area and details show names clipped in the list.

`COUNT` is type-specific, with its source shown below the list; `-` means unknown, not empty. `CAPACITY` is the maximum entry count, or buffer bytes for ring buffers. `KEY`/`VALUE` are individual key/value sizes, moved to the selected-map area on narrow terminals. `PIN PATH` covers visible bpffs paths only.

| Map Type | COUNT Meaning |
| --- | --- |
| Hash, per-CPU Hash, LRU, HashOfMaps | Kernel-maintained key count. |
| LPM Trie, DevMapHash, SockHash | Corresponding kernel count. |
| Array, per-CPU Array, StructOps | Fixed `N slots`, not nonzero/valid values; CPU copies are not multiplied. |
| XSKMAP, program/event/cgroup/map arrays, DevMap, CPUMap, SockMap, ReuseportSockarray, StackTrace | Non-null reference slots. |
| Queue, Stack | Current depth from read-only head/tail observations; no pop. |
| Ringbuf, UserRingbuf | Used/reserved `N B`, including headers and padding, not record count. |
| Bloom Filter, storage types without a supported read-only count | `-`; no inferred count. |

Required kernel BTF fields must exist; missing fields or failed reads produce unknown counts. Dynamic counts are not atomic snapshots under concurrent updates. Negative or over-capacity values are marked unknown rather than clamped.

In the entry table, each `KEY` identifies an entry and `VALUE` is its current content. Its meaning depends on the program that created the map. BTF is used for decoding when available; otherwise values are shown as bounded hex. Per-CPU unsigned integers are summed in the table; other values preview the first possible CPU. Expand an entry to see each CPU's value. Reads across CPUs are not an atomic snapshot.

`DELTA` is the **raw change from the previous observation, not a per-second rate**. BTF-verified unsigned integers use `+N`; top-level integer fields of structures may show field deltas. `new` means the key was not observed previously, `=` means unchanged bytes, `changed` means a non-quantifiable change, and `reset/-` means a numeric decrease.

## Reading Limits

- Ordinary key/value previews support hash, array, per-CPU hash/array, LRU hash, and LPM trie maps. XSKMAP shows bindings; ProgArray/ArrayOfMaps/HashOfMaps show references. Remaining types only show supported counts without reading or consuming their contents.
- Ordinary userspace XSKMAP lookup does not expose socket values. Details use an independent CO-RE iterator and require matching kernel BTF fields and BPF loading privileges. Each query scans at most the first 16384 slots and returns at most `-n` sockets; more exist means additional references, and partial means a scan limit or read error. `!` marks unread fields; `-` means unknown/unbound. Unavailable collection shows an error; `r` retries. Binding fields are not an atomic snapshot.
- Reference scans inspect at most 16384 slots per map and 65536 per interval. `N part` is incomplete, not a whole-map count. `c` deduplicates keys of iterable types without reading values, with budgets of 2 seconds, approximately 16 MiB, and one million successful key reads; reaching a budget also marks the result incomplete.
- Each page has at most `-n` matching entries. A background chunk examines at most 4096 keys, 2 MiB, or 50 ms. Keys/values above 4096 bytes and per-CPU entries above 64 KiB are not previewed. Empty partial search chunks continue automatically up to 65536 examined keys or 2 seconds; use `]` to continue afterward. Search matches displayed values, not unshown nested fields. More exist is independent of COUNT.
- Reference details inspect at most 16384 slots, 2 MiB, or 50 ms, with a separate 50 ms metadata budget, and return at most `-n` entries. Use `[`/`]` for data pages. Linux 6.6 map-in-map lookups may wait for RCU; even small maps can be partial. Limits or unreadable metadata show partial. Deadlines are checked between calls; individual kernel calls cannot be preempted. These values do not identify attachment locations or process owners, nor reveal lookup misses, update failures, or LRU evictions.
- Traversal of a hash map under concurrent updates is not an atomic snapshot: keys may be missed, duplicated, or changed during the read. Preview counts and deltas are not whole-map totals or rates.
- Pin scanning visits at most 2048 nodes; metadata lists at most 8192 maps. Counts run in the background. The temporary count iterator and its internal budget map are released on exit, are never pinned or attached to business networking, and never modify existing maps.
