# Linux tools

Small Linux debugging and testing tools. Each tool keeps its own source and
documentation; generated executables and command links live in `bin/`.

| Path | Purpose |
| --- | --- |
| [irqtop/](irqtop/README.md) | Hardware IRQ, softirq and softnet monitoring; provides irqtop and irqstat |
| irq-affinity.sh | IRQ affinity and RPS configuration |
| uping/ | Standalone UDP ping |
| udp-ping-pong/ | UDP client/server test scripts |

## Build

```sh
make
./bin/irqtop -n
./bin/irqstat -n 1 5
make check
sudo make install
```

`make` compiles `irqtop/target/release/irqtop` and creates:

```text
bin/
  irqtop
  irqstat -> irqtop
```

`make install` installs the built executable and relative link to
`/usr/local/bin`. Build before installing. Use `PREFIX="$HOME/.local"` for a
per-user install or `DESTDIR` for a staging directory. Only irqtop is currently
managed by these build targets.

The irqtop source directory contains `src/`, `tests/` for live CLI/terminal
checks and `bench/` for CPU measurements. See its
README for options and validation commands.
