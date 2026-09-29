# cttop

Inspect Linux conntrack connections, traffic and anomaly signals, with grouped drilldown, NAT views and offline file analysis.

[![cttop source-IP groups and details from a static snapshot](../../assets/screenshots/cttop-static.png)](../../assets/screenshots/cttop-static.png)

Static sample using documentation addresses. Saved packets/bytes are available; bandwidth and change rates remain `N/A`.

## Common Commands

```sh
# Group by original source IP
sudo cttop

# One connection per row
sudo cttop -g none

# Group by mark/source or destination service
sudo cttop -g mark,src
sudo cttop -g dst,dport,proto

# Filter TCP 443, or inspect translated endpoints
sudo cttop -p tcp -D 443
sudo cttop -N -g src,sport

# Three periodic text reports
sudo cttop -b -c 3

# Export and load a snapshot, or read from a pipe
sudo conntrack -L -o extended > conntrack.txt
cttop -f conntrack.txt
sudo conntrack -L | cttop -f
```

## Key Options

| Option | Meaning |
| --- | --- |
| `-g FIELDS` | Group by `src,sport,dst,dport,proto,zone,mark`; `none` lists individual connections |
| `-N` | Show translated forward endpoints |
| `-s IP` / `-d IP` | Original source / destination IP filter |
| `-S PORT` / `-D PORT` | Original source / destination port filter |
| `-p PROTO` | Protocol filter, such as `tcp` or `udp` |
| `-f [FILE]` | Load a conntrack text snapshot; omitted filename or `-` reads stdin |
| `-i SEC` | Display interval; default 1 second |
| `-r SEC` | Full calibration and bandwidth sampling interval; default 5 seconds |
| `-m N` | Minimum live sessions per group; default 0 |
| `-b` / `-c N` | Text reports / report count |
| `-h` / `-v` | Help / version |

## Reading Results

Live views show connection counts, states, original/reply bandwidth, packet/byte counters,
and lifecycle or kernel-drop signals. Drill into a port group with Enter, then regroup by another field.

Packet and byte counters require kernel conntrack accounting; missing counters show `N/A`.
Bandwidth uses byte differences between samples. Partial coverage is explicit;
missing data is not treated as zero traffic.

## Window Keys

| Key | Action |
| --- | --- |
| `0` | One connection per row |
| `1`..`7` / `g` | Select grouping / edit the field list |
| Enter / Esc | Drill down / return one level |
| `n` | Toggle original and NAT views |
| `/` / `s` | Search / change sorting |
| Arrows, `j/k` | Select a row |
| `h` / `q` | Help / quit |

## Notes

Live monitoring needs `CAP_NET_ADMIN` in the target network namespace; `sudo` is the usual choice.
Offline analysis needs no root. A static snapshot can show recorded counters and states,
but cannot calculate bandwidth, creation rates or connection age.
Command-line IP/port filters always match original tuples, including in the NAT view.
The tool is read-only; it does not change firewall rules or enable accounting automatically.

[Static downloads](https://github.com/calcky/tools/releases/tag/cttop-release) · [Full manual](https://github.com/calcky/tools/blob/master/cttop/README.md)
