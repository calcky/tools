# Getting Started

## Installation

Choose a tool from the [overview](index.md#installation), open its Release, and select your CPU architecture. The example uses x86_64.

| CPU Architecture | Asset Suffix |
| --- | --- |
| x86-64 / AMD64 | `linux-x86_64` |
| AArch64 / ARM64 | `linux-arm64` |
| ARMv7, hard-float ABI | `linux-arm`, or `linux-armv7` for netlens |

For netping on x86_64:

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netping-release/netping-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netping-linux-x86_64 "$HOME/.local/bin/netping"
netping -h
```

Add `$HOME/.local/bin` to `PATH`. These are static Linux executables: no Rust runtime or dynamic musl/glibc is needed.
ARMv7 assets do not support ARMv5/ARMv6 or soft-float systems.

## Use irqstat

irqstat and irqtop share one executable; the command name selects the display mode.
After installing irqtop, create the link:

```sh
install -m 755 irqtop-linux-x86_64 "$HOME/.local/bin/irqtop"
ln -sfn irqtop "$HOME/.local/bin/irqstat"
irqstat -n 1 5
```

## Permissions

Ordinary UDP/TCP tests need no root. ICMP and kernel tracing may need additional privileges;
live conntrack monitoring needs `CAP_NET_ADMIN` in the target network namespace.
A container normally sees only its own network namespace. See each tool's page for requirements.
