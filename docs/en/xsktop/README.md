# xsktop

Monitor AF_XDP sockets in the current network namespace, grouped by interface and queue, with RX/TX rates, errors and process ownership.

## Download

Get the static ARMv7, ARM64 or x86_64 executable from [xsktop-release](https://github.com/calcky/tools/releases/tag/xsktop-release). For example:

```sh
curl -fLO https://github.com/calcky/tools/releases/download/xsktop-release/xsktop-linux-x86_64
chmod +x xsktop-linux-x86_64
sudo ./xsktop-linux-x86_64
```

## Common Commands

```sh
sudo xsktop                   # live window
sudo xsktop -i eth0           # one interface
sudo xsktop -d 0.5            # refresh every 0.5 seconds
sudo xsktop -c 5 -d 1 > log   # five plain-text samples
```

Use arrow keys or `j/k` to select a socket, `s` to sort and `q` to quit.

## Key Options

| Option | Meaning |
| --- | --- |
| `-i IFACE` | Restrict to an interface |
| `-d SEC` | Sampling interval, at least 0.1 seconds |
| `-c N` | Print N samples without requiring a terminal |

## Notes

- Requires Linux 6.6+, `CONFIG_XDP_SOCKETS_DIAG`, kernel BTF and fentry/fexit BPF support; root or equivalent capabilities are normally needed.
- RX is delivery into an XSK, while TX is dequeue by the kernel. Neither means application consumption or on-wire transmission. Ring figures are capacities, not occupancy.
- `UMEM fill empty` and `TX empty` are events, not RX/TX errors. Fill-ring events may be shared by sockets using the same UMEM. Traffic attribution is hidden when multiple XSKs share an interface and queue; after one closes, the first interval may still include its traffic.
- Generic/copy and native/copy were tested on veth; hardware zero-copy and multi-buffer packets remain unvalidated.

[Full manual](https://github.com/calcky/tools/blob/master/xsktop/README.md)
