# xsktop

`xsktop` is a live AF_XDP socket monitor for Linux 6.6 with kernel BTF. It
discovers sockets through `NETLINK_SOCK_DIAG` and measures traffic at the XSK
kernel paths with CO-RE eBPF probes. It does not modify the XDP program.

## Kernel requirements

The running kernel needs these options (the build-time kernel headers alone
are not sufficient):

| Option | Why xsktop needs it |
| --- | --- |
| `CONFIG_XDP_SOCKETS=y` | AF_XDP socket support |
| `CONFIG_XDP_SOCKETS_DIAG=y` or `m` | Enumerate XSKs and read ring, UMEM, and error statistics through `NETLINK_SOCK_DIAG`; if `m`, the module must be available |
| `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y` | Load BPF maps/programs and attach fentry/fexit trampolines |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE type information and fentry/fexit function signatures; `/sys/kernel/btf/vmlinux` must be readable |
| `CONFIG_FTRACE=y`, `CONFIG_FUNCTION_TRACER=y`, `CONFIG_DYNAMIC_FTRACE=y` | Function-tracing support for the fentry/fexit attachment path |
| `CONFIG_BPF_EVENTS=y` | BPF tracing support |

Check the active configuration and BTF file, for example:

```sh
grep -E '^(# )?CONFIG_(XDP_SOCKETS|XDP_SOCKETS_DIAG|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|FTRACE|FUNCTION_TRACER|DYNAMIC_FTRACE|BPF_EVENTS)(=| )' /boot/config-"$(uname -r)"
ls -l /sys/kernel/btf/vmlinux
```

Some distributions expose the configuration at `/proc/config.gz` instead.
`CONFIG_XDP_SOCKETS_DIAG=m` can auto-load; if its module is absent, xsktop
cannot enumerate sockets and exits even though AF_XDP traffic still works.
The BPF probes also require the named XSK kernel functions to exist and be
attachable on the running kernel; config options alone cannot guarantee that.

```sh
sudo xsktop                 # all XSKs in the current network namespace
sudo xsktop -i eth0         # one interface
sudo xsktop -d 0.5          # refresh every 500 ms
sudo xsktop -c 5 -d 1 > xsktop.txt  # five measured text samples, no TTY needed
```

`j/k` or arrow keys select a socket, `s` cycles the sort key, and `q` quits.
Sockets are grouped by interface and sorted by queue by default. Other sort
keys reorder queues within each interface. The table always shows adjacent
RX/TX packet rates, adjacent RX/TX megabits per second, separate RX/TX error
rates, and the process holding the socket. RX errors sum dropped packets,
invalid descriptors, and RX-ring-full counts; TX errors count invalid TX
descriptors. The details pane breaks down these error classes and shows UMEM,
ring **capacity**
(not occupancy), error and empty-ring event rates, and their cumulative totals.
`UMEM fill empty` and `TX empty` are events, not errors, so they are excluded
from the RX/TX error columns. The fill-ring counter belongs to the UMEM pool;
if sockets share that pool, it is not attributable to one socket. Process
ownership is best-effort when
`/proc` is restricted or file descriptors are shared.

With `-c N`, xsktop takes one baseline snapshot and then prints N interval
samples to standard output. Each sample lists sockets in the selected network
namespace, their traffic/error/event rates, and the actual elapsed interval.
Press Ctrl+C to stop early. Without `-c`, xsktop opens the live terminal window
(minimum 74 x 20 columns).

RX means successful delivery **into** XSK; TX means dequeued by the kernel or
accepted by the generic transmit path. Neither is application consumption or
on-wire delivery. The bandwidth is packet bytes at that point, not Ethernet
wire rate. `>=` marks a lower bound when a fragmented RX packet or an oversized
TX batch prevents a complete byte count or packet count. If multiple XSKs share
one interface and queue, traffic is hidden because it cannot be attributed to
either socket. In that case the header RX/TX rates are lower bounds, while
per-socket error rates remain visible. If one of those sockets closes between
samples, the first subsequent interval may still include its traffic and be
attributed to the remaining socket.
Copy and zero-copy paths are observed separately; the UMEM `zc/copy` flag is
reported from the kernel.

The socket list is a periodic snapshot: sockets created and closed between
refreshes may not appear. A failed snapshot is shown in the header and retried
at the next refresh; displayed rates remain from the last successful sample.
Startup errors identify a missing XDP socket diagnostic handler or kernel BTF;
probe attachment errors include the failing program and target function.

The program needs root (or the required BPF/tracing capabilities), kernel BTF,
and access to `/proc` for process names. Probe attachment fails explicitly if
the running kernel lacks a required function. Without AF_XDP sockets, the table
is empty. Generic/copy and native/copy were smoke-tested on an isolated veth
pair on `speed` (Linux 7.0.14) and in a privileged container on a Linux
6.6.87 WSL2 kernel. Rates matched the `xdp-bench` workload; a 1400-byte ICMP
payload showed about 42 PPS and 0.484 Mb/s in each direction. The zero-copy
driver paths and multi-buffer packets still need runtime validation on
supported hardware. Empty TX ring checks are events, not errors, and are
excluded from the `ERR/s` column.

## Build

Requires Rust, Clang with BPF target, libbpf headers, and static libelf/zlib/zstd.
On distributions where Rust does not find the multiarch static libraries, set
`RUSTFLAGS='-L native=/usr/lib/x86_64-linux-gnu'` when building.

```sh
make xsktop
make check-xsktop
sudo bin/xsktop
```

`make` resolves the static library directory with `pkg-config`. To run the
isolated root-only smoke test, provide paths to `xsktop` and `xdp-bench`:

```sh
bash xsktop/tests/smoke.sh /absolute/path/xsktop /absolute/path/xdp-bench skb
bash xsktop/tests/smoke.sh /absolute/path/xsktop /absolute/path/xdp-bench native
bash xsktop/tests/smoke.sh /absolute/path/xsktop /absolute/path/xdp-bench native text
```

Set `PING_SIZE=1400` to check the bandwidth display with larger packets.
