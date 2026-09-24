Initial release of netlens, a Linux network stack monitor, in the tools repository.
Previously named nwdiag.

- Numerical overview and dedicated Interface, Qdisc, SoftIRQ, HardIRQ, Socket,
  Transport, Network, Conntrack, Route and Providers pages.
- PF/VF interface inventory, driver/link/queue/ring/offload configuration, and
  framed interface details with metric column headings and RX/TX rows.
- Sortable socket and conntrack tables, tcpdump-style connection filters, and
  per-connection details. TCP details include RTT, MSS, congestion control and
  the evidence behind send-limit estimates.
- Hardware IRQ, softirq and softnet rates, protocol counters, qdisc drops and
  requeues, and route/neighbour inspection.
- Collection follows the selected page; configuration uses slower cached
  sampling. Missing or unsupported data is reported explicitly.
- Module subcommands and Bash, Zsh and Fish shell completions.

Download the executable matching your Linux architecture:

| Asset | Architecture |
| --- | --- |
| `netlens-linux-armv7` | ARMv7 little-endian, hard-float EABI5 |
| `netlens-linux-arm64` | AArch64 |
| `netlens-linux-x86_64` | x86-64 |

All three executables are statically linked with musl and distributed without
an archive. ARMv7 is not compatible with ARMv5/ARMv6 or soft-float systems.
`SHA256SUMS` contains executable checksums; `BUILDINFO.txt` records the source
commit, compiler and build images.

Make the download executable, then run it in an interactive terminal:

```sh
chmod +x netlens-linux-x86_64
./netlens-linux-x86_64 --help
sudo ./netlens-linux-x86_64
sudo ./netlens-linux-x86_64 socket --interval 1s
```

Some collectors require root privileges and kernel/driver support. The monitor
does not modify network configuration, capture packets or attach BPF programs.
