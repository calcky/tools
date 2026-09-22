# Linux tools

Small Linux debugging and testing tools. Each tool keeps its own source and
documentation; generated executables and command links live in `bin/`.

| Path | Purpose |
| --- | --- |
| [irqtop/](irqtop/README.md) | Hardware IRQ, softirq and softnet monitoring; provides irqtop and irqstat |
| [netping/](netping/README.md) | ICMP, UDP/TCP latency, live window, bandwidth/retransmission statistics and MTU/MSS inspection |
| irq-affinity.sh | IRQ affinity and RPS configuration |
| uping/ | Standalone UDP ping |
| udp-ping-pong/ | UDP client/server test scripts |

## Build

```sh
make
./bin/irqtop -n
./bin/irqstat -n 1 5
./bin/netping -h
make check
sudo make install
```

`make` builds both Rust tools and creates:

```text
bin/
  irqtop
  irqstat -> irqtop
  netping
```

`make install` installs the built executables and relative link to
`/usr/local/bin`. Build before installing. Use `PREFIX="$HOME/.local"` for a
per-user install or `DESTDIR` for a staging directory. Use `make irqtop` or
`make netping` to build one tool, and `make install-irqtop` or
`make install-netping` to install it individually. `make check` checks both;
`make check-netping` checks only netping.

Both Rust tools keep implementation in `src/`, live checks in `tests/`, and
CPU/memory measurements in `bench/`. Each tool's README documents its options,
validation commands and build requirements. `netping -s` provides the paired
UDP/TCP server; ICMP and ordinary TCP connection/MSS checks can use existing
services.
