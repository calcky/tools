# Linux tools

Small Linux debugging and testing tools. Each tool keeps its own source and
documentation; generated executables and command links live in `bin/`.

## Documentation

The MkDocs documentation site is configured for Read the Docs. Start with the
[documentation overview](docs/index.md), [installation guide](docs/getting-started.md)
or [common tasks](docs/tasks.md). Tool manuals are generated directly from each
tool's README to keep one source of truth.

```sh
python3 -m venv .venv-docs
.venv-docs/bin/pip install -r docs/requirements.txt
.venv-docs/bin/mkdocs serve
```

See [documentation maintenance and hosting](docs/documentation.md) for strict
build checks and the initial Read the Docs project import.

## Tools

| Path | Purpose |
| --- | --- |
| [irqtop/](irqtop/README.md) | Hardware IRQ, softirq and softnet monitoring; provides irqtop and irqstat |
| [netping/](netping/README.md) | ICMP, UDP/TCP latency, live window, bandwidth/retransmission statistics and MTU/MSS inspection |
| [flowgen/](flowgen/README.md) | TCP/UDP session load, equal-length request/response traffic and offline latency analysis |
| [cttop/](cttop/README.md) | Live/offline conntrack aggregation, original/NAT views, traffic counters and session-state diagnostics |
| [netlens/](netlens/README.md) | Layered network stack monitoring with interfaces, qdisc, IRQs, sockets, conntrack and routes |
| irq-affinity.sh | IRQ affinity and RPS configuration |
| uping/ | Standalone UDP ping |
| udp-ping-pong/ | UDP client/server test scripts |

## Build

```sh
make
./bin/irqtop -n
./bin/irqstat -n 1 5
./bin/netping -h
./bin/flowgen -h
./bin/netlens --help
make check
sudo make install
```

`make` builds the Rust tools and creates:

```text
bin/
  irqtop
  irqstat -> irqtop
  netping
  flowgen
  cttop
  netlens
```

`make install` installs the built executables and relative link to
`/usr/local/bin`. Build before installing. Use `PREFIX="$HOME/.local"` for a
per-user install or `DESTDIR` for a staging directory. Use `make irqtop` or
`make netping`, `make flowgen`, `make cttop` or `make netlens` to build one tool,
and the corresponding `make install-<tool>` to install it individually.
`make check` checks all tools;
`make check-<tool>` checks one tool individually.

The Rust tools keep implementation in `src/`, live checks in `tests/`, and
CPU/memory measurements in `bench/`. Each tool's README documents its options,
validation commands and build requirements. `netping -s` provides the paired
UDP/TCP server; ICMP and ordinary TCP connection/MSS checks can use existing
services.
