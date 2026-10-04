# bpfmap

A read-only terminal viewer for BPF map types, capacities, key/value sizes, pin paths, bounded entry previews, and changes between adjacent samples. Use it to watch a small set of entries live; `bpftool` remains useful for one-off queries, exports, and modifications.

## Installation

For x86_64, install the static binary below. ARMv7 and ARM64 binaries and checksums are available in [bpfmap-release](https://github.com/calcky/tools/releases/tag/bpfmap-release).

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpfmap-release/bpfmap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpfmap-linux-x86_64 "$HOME/.local/bin/bpfmap"
```

Reading map metadata typically requires `CAP_BPF` or `CAP_SYS_ADMIN`; reading entries also depends on the map's permissions and type. The commands below assume sufficient privileges.

## Common Commands

```sh
bpfmap                # List accessible maps
bpfmap -m 42          # Open map ID 42 directly
bpfmap -n 32 -d 2     # Preview up to 32 entries every 2 seconds
```

| Option | Meaning |
| --- | --- |
| `-m ID` | Open the specified map directly. |
| `-n N` | Read at most N entries per interval; default 64, range 1-256. |
| `-d SEC` | Entry refresh interval; default 1 second, range 0.2-60. The map list refreshes every 5 seconds. |
| `-h` / `-V` | Help / version. |

Press `Enter` to open a map and `Esc` to return to the list. Use `j/k` or arrow keys to move, `r` to refresh, `h` for help, and `q` or Ctrl+C to quit. An interactive terminal is required. Set `NO_COLOR=1` to disable colors.

## Reading The View

In the list, `CAPACITY` is usually the configured maximum entry count; ring buffers instead show their size in bytes with a `B` suffix. `KEY` and `VALUE` are the sizes of one key and one value in bytes, not total memory use. `PIN PATH` covers only visible bpffs paths; an absent path does not prove that the map is unpinned in another mount namespace.

In the detail view, each `KEY` identifies an entry and `VALUE` is its current content. Its meaning depends on the program that created the map. BTF is used for decoding when available; otherwise values are shown as bounded hex. Per-CPU unsigned integer values are summed across CPUs; other per-CPU values show a CPU0 preview and CPU count.

`DELTA` is the **raw change from the previous observation, not a per-second rate**. BTF-verified unsigned integers use `+N`; top-level integer fields of structures may show field deltas. `new` means the key was not observed previously, `=` means unchanged bytes, `changed` means a non-quantifiable change, and `reset/-` means a numeric decrease.

## Reading Limits

- Only ordinary hash, array, per-CPU hash/array, LRU hash, and LPM trie maps support entry previews. Ring buffers, queues/stacks, program arrays, and socket/device reference maps show metadata only; consuming operations are not called.
- Previews start at the first key. Each interval reads at most `-n` entries and 2 MiB total. Keys or values above 4096 bytes, and per-CPU entries above 64 KiB, are not previewed. The `+` in `Entries 64/64+` means additional keys exist.
- Traversal of a hash map under concurrent updates is not an atomic snapshot: keys may be missed, duplicated, or changed during the read. Preview counts and deltas are not whole-map totals or rates.
- Pin scanning visits at most 2048 nodes. Incomplete list or pin coverage is marked in the UI. The tool never creates, updates, or deletes maps.
