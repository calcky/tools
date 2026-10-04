# fdtop

Monitor application I/O by process and file descriptor with eBPF. Inspect idle
descriptors as well as read/write rates, operation rates and FD lifecycle events.

## Installation

Linux 6.6+, BTF, raw syscall tracepoints, fentry and BPF/tracing privileges are
required. Run in the host PID namespace. Native x86_64 and ARM64 are supported;
ARM64 probing still needs hardware validation. ARMv7 is not supported.
The canonical release is `fdtop-release`; publication accompanies this change.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/fdtop-release/fdtop-linux-x86_64
install -m 755 fdtop-linux-x86_64 ~/.local/bin/fdtop
```

Use the `fdtop-linux-arm64` asset for ARM64. Ensure `~/.local/bin` is on PATH.

## Common Usage

```sh
fdtop
fdtop -p 1234
fdtop -p 1234 -t xsk
fdtop -l -p 1234
fdtop -n nginx -t socket
fdtop -p 1234 -j -c 5
fdtop -e
fdtop -e -p 1234
fdtop -e -p 1234 -j > fd-events.jsonl
```

Without `-e`, the default view ranks active processes. Enter opens a complete FD
inventory, including idle descriptors. `e` enables event capture on demand and
switches between I/O and events; capture continues after switching back.
The initial event scope stays fixed until exit. A PID filter does not follow children.

## Options

| Option | Meaning |
| --- | --- |
| `-p PID` | Kernel process filter and complete process FD inventory |
| `-f FD` | Filter one FD; requires `-p` |
| `-n COMM` | Process-name substring; kernel comm is at most 15 bytes |
| `-t TYPE` | file/socket/tcp/udp/unix/xsk/netlink/pipe/char/block/mq/eventfd/timerfd/signalfd/epoll/bpfmap/bpfprog/btf/other |
| `-d SECONDS` | Refresh interval, 0.1–60 seconds; default 1 |
| `-l` | Enable syscall latency and approximate percentiles |
| `-e` | Enable FD lifecycle capture and start in the event view |
| `-c COUNT` | Exit after COUNT output batches |
| `-b` / `-j` | Text / JSON Lines output |
| `-h` / `-v` | Help / version |

Use j/k or arrows to select, Enter to inspect FDs, Esc to return, s to cycle I/O
sorting, h for help, and q or Ctrl+C to quit. The terminal needs 80×18 cells.
`NO_COLOR` disables colors; redirected output automatically uses text.

## Interpretation And Limits

Read/write B/s measures application operations, not disk requests or wire traffic.
ROPS/s and WOPS/s count completed endpoint attempts, including errors and EAGAIN.
Pending is an unfinished operation, not necessarily an error. Latency in `-l`
mode is syscall elapsed time, not device service time. Default light mode displays
unavailable latency as null or `-`. FD mode r/w/rw/path describes permissions.

The inventory distinguishes open, closed, reused, unconfirmed and invalid objects.
XSK metadata shows interface and queue; mmap ring bytes are not measured and show
`-`. Metadata reports live/cached/observed/proc provenance and query errors.
Paths or socket addresses may be unavailable due to permissions or races.
An FD inventory excludes lsof cwd/txt/mem records. It is capped at 65536 slots.

Events include EXISTING (selected-process baseline), OPEN, DUP, CLOSE, INHERIT
and UPDATE (bind/connect). They do not require I/O. dup replacement emits old CLOSE
then new DUP. close_range, CLOEXEC and final file-table release are observed.
CLOSE means descriptor removal, not final object destruction. Global mode has no
system-wide baseline. Capture does not reconstruct history before attachment.

The event ring is 4 MiB. History and queued output each hold 8192 records.
Loss counters report ring overflow, metadata read failures, map capacity and bulk
scan truncation. JSON also reports history_evicted, output_dropped and decode_errors.
Nonzero loss means incomplete capture. Multiple CPUs can produce interleaved
timestamps. Shutdown drains remaining events and may append a final batch.

Event object cookies are independent of I/O cookies. Transient names are limited
to 63 bytes and do not guarantee full paths. Generic socket events retain type and
inode; current addresses are in the I/O view. XSK bind updates retain interface/queue.
The startup baseline is not atomic with probe attachment.

Required event hooks include fd_install, file_close_fd_locked (pick_file on older
kernels), do_dup2, do_close_on_exec and exit_files/put_files_struct. Missing hooks
fail explicitly. fork/exec/table-release scans are capped at 65536 slots.
Shared-table changes are attributed to the actor, not duplicated for every owner.
io-wq actions are not automatically attributed to the submitting process.

I/O excludes io_uring, Linux AIO, mmap, System V MQ, ioctl and fsync. Event tracking
covers ordinary numeric FDs, not io_uring fixed-file slots. Compat/x32 syscalls are
skipped for I/O; generic install/close hooks still apply, but compat DUP sources and
UPDATE are not guaranteed. High syscall rates can noticeably affect workloads;
prefer PID-scoped, on-demand capture. No HTML preview layout is included in this release.
