# netlens

Inspect Linux network traffic, errors, drops and resource pressure by layer, then drill down into connections, interfaces or protocols.

## Start

```sh
sudo netlens
sudo netlens -i eth0,eth1 -d 0.5
```

The default sample interval is one second. `-d` accepts 0.25–60 seconds; `-i` filters interface-labelled rows without changing host or namespace totals.
Run `netlens --help` for options.

Select a layer or interface in Overview and press Enter for details; Esc returns. Commands such as `netlens socket` open a page directly.

[![netlens layered overview and loopback interface statistics](../../assets/screenshots/netlens-overview.png)](../../assets/screenshots/netlens-overview.png)

Loopback traffic in an isolated network namespace. Missing sources retain their actual status instead of appearing as zero.

## Choose By Task

| Investigate | Read | Open Directly |
| --- | --- | --- |
| Application connections, TCP RTT and retransmissions | [Connections And Processes](docs/cli.md) | `netlens socket` |
| Interface traffic, queues, drops and CPU interrupts | [Interfaces, Queues And IRQs](docs/interfaces.md) | `netlens interface` |
| NAT, connection tracking, routes and neighbours | [Routing And Conntrack](docs/routing.md) | `netlens conntrack` / `route` |
| Units, totals, permissions or missing data | [Metrics And Data Status](docs/monitor-metrics.md) | `netlens providers` |
| How XDP, TC and the stack fit together | [Packet Paths](docs/packet-path.md) | Reference guide |

## Basic Controls

| Key | Action |
| --- | --- |
| Tab / Shift+Tab | Change pages |
| Arrows, `j/k` | Select or scroll |
| Enter / Esc | Open details / return |
| `s` / `r` | Change sort field / reverse sorting |
| `/` / Ctrl+U | Filter connections / clear the filter |
| PgUp/PgDn / Home | Page / return to the first row |
| `a` | Show zero/unavailable fields in supported details |
| `t` | Switch interval values and since-baseline totals |
| Space / `p` | Pause display; collection continues |
| `q` / Ctrl+C | Quit |

Press `:` and enter a page name, such as `:softirq` or `:providers`, to switch directly.
The first connection-row click selects it; the second opens details. Clicking a sortable heading again reverses sorting.

## Before You Start

The tool is read-only: no capture, BPF loading or network configuration changes. It observes the current network namespace; host-wide metrics are labelled separately.
`sudo` improves process/device visibility but cannot supply unsupported kernel or driver fields.
`n/a` is not zero. Check Providers when data is missing or stale.

[Static downloads](https://github.com/calcky/tools/releases/tag/netlens-release) · [Full manual](https://github.com/calcky/tools/blob/master/netlens/README.md)
