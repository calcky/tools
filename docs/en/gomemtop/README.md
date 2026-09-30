# gomemtop

Sample a Go application's heap pprof in a live terminal window to inspect current heap usage and growing call stacks. With a local PID, compare process RSS with Go runtime memory. Growth is an investigation lead, not a leak verdict.

The target must expose `net/http/pprof` on a trusted network. pprof can reveal function names and application internals; do not expose it publicly.

## Installation

Example for x86_64; see [gomemtop-release](https://github.com/calcky/tools/releases/tag/gomemtop-release) for other architectures.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/gomemtop-release/gomemtop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 gomemtop-linux-x86_64 "$HOME/.local/bin/gomemtop"
```

Make sure `$HOME/.local/bin` is on `PATH`.

## Common Commands

```sh
# Sample every 30 seconds; use the server root or a complete heap URL
gomemtop http://127.0.0.1:6060

# Also inspect local PID RSS and Go runtime memory; press d for details
gomemtop -p 8110 http://127.0.0.1:6060

# Sample every 10 seconds with a 5-second request timeout
gomemtop -i 10 -T 5 http://127.0.0.1:6060/debug/pprof/heap
```

## Options

| Option | Meaning |
| --- | --- |
| `-p PID` | Read local process RSS and Go runtime data; PID must be visible in the current `/proc` |
| `-i SEC` | Sample interval; default 30 seconds, range 0.2–3600 seconds |
| `-T SEC` | HTTP request timeout; default 10 seconds, range 0.2–3600 seconds |
| `-h` / `-V` | Help / version |

## Window Keys

| Key | Action |
| --- | --- |
| `j/k`, arrow keys | Select a call stack; scroll detailed analysis |
| PageUp / PageDown | Page through frames or analysis |
| `m` | Toggle `inuse_space` / `alloc_space` |
| `b` | Reset the baseline to the current sample |
| `g` | Toggle forced GC and reset the comparison baseline |
| `d` | Toggle detailed RSS analysis; requires `-p` |
| Space / `r` | Pause or resume automatic sampling / sample now |
| `q`, Ctrl+C | Quit and restore the terminal |

## Reading Results

The main list ranks call stacks by `inuse_space` growth from the baseline. Select a stack to inspect its current size, previous-sample and baseline changes, and full frames. `alloc_space` shows cumulative allocation pressure, not retained memory.

With `-p`, the window shows RSS, anonymous/file/shared resident pages and Go `MemStats`. Diagnostic hints require at least three successful paired samples and show the evidence and investigation direction; press `d` for retained heap, span slack and RSS comparison. These counters are not mutually exclusive RSS partitions, and HTTP and `/proc` observations are not atomic. They cannot establish a leak or attribute all RSS beyond heap to native memory.

Sampling does not force GC by default. Enabling it can affect target latency; growth between GCs may be normal. To inspect RSS for a remote pprof target, run `gomemtop -p` on that host. Unreadable metrics are marked unavailable. The tool retains aggregated results in memory only and does not save raw profiles.

[Full manual](https://github.com/calcky/tools/blob/master/gomemtop/README.md)
