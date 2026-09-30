# netcap

Capture skb packets at a selected kernel function or tracepoint to inspect traffic at a specific point in the network stack.

## Installation

Example for x86_64; see [netcap-release](https://github.com/calcky/tools/releases/tag/netcap-release) for other architectures.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/netcap-release/netcap-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 netcap-linux-x86_64 "$HOME/.local/bin/netcap"
```

The static executable includes BCC/LLVM, so the target needs no external Clang or shared libraries. BPF probes are still compiled at runtime.

## Common Commands

```sh
# Capture 10 packets at the ICMP receive function into pcap
netcap skb -f icmp_rcv@1 -e 'icmp' -i eth0 -w icmp.pcap -c 10

# Apply one packet filter at multiple kernel locations
netcap skb -f 'ip_local_deliver@1,icmp_rcv@1' \
  -e 'host 192.0.2.10' -i eth0 -w path.pcap -c 20

# Show the generated BPF C code without loading a probe
netcap skb -f icmp_rcv@1 -e 'icmp' -i eth0 --dry-run
```

## Key Options

| Option | Meaning |
| --- | --- |
| `skb` | Trace Linux skb packets; `raw` and `mbuf` target AF_XDP/DPDK processes |
| `-f FUNCTION@N` | Function and skb argument number; separate multiple locations with commas |
| `-e EXPR` | tcpdump-style packet filter |
| `-i IFACE` | Restrict capture to an interface |
| `-w FILE` | Write a pcap file |
| `-c COUNT` | Stop after this many packets |
| `--dry-run` | Print generated BPF C code only |

## Notes

- `skb` capture requires root or equivalent tracing privileges, debugfs, and prepared headers matching the running kernel. Set `BCC_KERNEL_SOURCE` for a custom kernel.
- Without `-w`, text output invokes external `bash` and `tcpdump`; static linking does not include those programs.
- Loopback capture was tested on x86_64. ARM64 and ARMv7 builds passed CLI startup checks, but capture has not been tested on matching hardware.
- `raw` and `mbuf` require a compatible AF_XDP/DPDK target process and have not been validated here.

[Full manual](https://github.com/calcky/tools/blob/master/netcap/README.md) · [Upstream usage](https://github.com/bytedance/netcap)
