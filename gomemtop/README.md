# gomemtop

Inspect growth in a Go program's heap profile through a live terminal window.
The target must expose `net/http/pprof` on an HTTP(S) server. Profile access can
reveal function names and application internals; bind pprof to a trusted address.

For an application that does not already serve pprof, register it on a trusted
listener (importing `net/http/pprof` registers the handlers on the default mux):

```go
import (
    "log"
    "net/http"
    _ "net/http/pprof"
)

go func() { log.Println(http.ListenAndServe("127.0.0.1:6060", nil)) }()
```

Download `gomemtop-linux-x86_64`, `gomemtop-linux-arm64`, or
`gomemtop-linux-arm` from the
[gomemtop release](https://github.com/calcky/tools/releases/tag/gomemtop-release),
make it executable, and run it in an interactive terminal.

```sh
make gomemtop
bin/gomemtop http://127.0.0.1:6060
bin/gomemtop -i 10 -T 5 http://127.0.0.1:6060/debug/pprof/heap
```

The first successful profile becomes the baseline. The main table ranks full
call stacks by change in `inuse_space` since that baseline. The selected stack
shows its frames, current size and object count, change since the previous
sample, and change since baseline. Press `m` to switch to `alloc_space`. The
top trend retains the most recent 60 successful values of the selected metric.

| Key | Action |
| --- | --- |
| `j/k`, Up/Down | Select a stack |
| PageUp/PageDown | Scroll selected stack frames |
| `m` | Toggle in-use / cumulative allocation metric |
| `b` | Set the current sample as baseline |
| `g` | Toggle `?gc=1`; discard prior samples and establish a new baseline |
| Space | Pause/resume automatic sampling |
| `r` | Request the next sample immediately |
| `q`, Ctrl+C | Quit and restore the terminal |

The default interval is 30 seconds and the request timeout is 10 seconds.
`-i` changes the interval in seconds; `-T` changes the HTTP timeout in seconds.
Both the server root and a complete `/debug/pprof/heap` URL are accepted.
Sampling does not trigger GC unless `g` enables it. Forcing GC affects the
target's latency; comparisons across GC modes are deliberately discarded.
Requests and protobuf parsing run off the UI thread. Failed requests leave the
last successful data on screen and are retried at the next interval.

Heap profile values are **sampled estimates**, not process RSS. `inuse_space`
can increase between GCs without a leak. `alloc_space` counts cumulative
allocation pressure, not retained memory. The tool does not claim that a
growing stack is a leak. It keeps aggregated samples in memory only and does
not save raw profiles. Response and decompressed profile sizes are limited to
32 MiB; profiles with more than 300,000 samples are rejected.
