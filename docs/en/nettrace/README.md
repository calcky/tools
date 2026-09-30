# nettrace

Trace skb paths through the Linux kernel with eBPF to investigate packet drops and network-stack processing latency.

## Installation

Example for x86_64; see [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release) for other architectures.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/nettrace-release/nettrace-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 nettrace-linux-x86_64 "$HOME/.local/bin/nettrace"
```

The BPF object is embedded; the target needs no clang, bpftool or shared libraries.
Tracing still requires root or equivalent capabilities, kernel BTF and BPF trampoline/fentry/fexit support.

## Common Commands

```sh
# Trace ICMP to a target, including interface, CPU and process context
nettrace -p icmp --daddr 192.0.2.10 --detail

# Diagnose a TCP service, printing only detected abnormalities
nettrace -p tcp --dport 443 --diag --diag-quiet

# Inspect skb release/drop events for a target
nettrace --drop --daddr 192.0.2.10

# Show ICMP paths taking over 1ms, including per-stage latency
nettrace -p icmp --daddr 192.0.2.10 \
  --min-latency 1000 --latency-show
```

Replace the example address with the actual target; press Ctrl+C to stop tracing. Add `--netns-current` to restrict tracing to the current network namespace when investigating containers.

## Key Options

| Option | Meaning |
| --- | --- |
| `-p PROTO` | Filter protocols such as `tcp`, `udp` or `icmp` |
| `--saddr` / `--daddr` / `--addr` | Filter source, destination or either address |
| `--sport` / `--dport` / `-P PORT` | Filter source, destination or either TCP/UDP port |
| `--detail` | Show CPU, interface, PID/process name and other context |
| `--basic` | Print individual events without assembling skb lifetimes |
| `--diag` / `--diag-quiet` | Diagnose abnormalities / print only abnormalities |
| `--drop` / `--drop-stack` | Release/drop events / also show call stacks |
| `--min-latency US` / `--latency-show` | Minimum processing time in microseconds / per-stage latency |
| `-t LIST` | Select trace functions or groups, separated by commas |
| `--netns-current` | Restrict tracing to the current network namespace |
| `-h` / `-V` | Help / version; `-v` enables logging, not version output |

## Notes

- This static build uses the upstream `btf` branch. `/sys/kernel/btf/vmlinux` must exist, but BTF alone does not guarantee tracing support.
- If debugfs is not mounted, it must be mounted at `/sys/kernel/debug` on the host. Containers may also impose capability or mount restrictions.
- **ARMv7 is experimental**: ordinary upstream 32-bit ARM kernels lack the required trampoline implementation. CLI startup does not establish usable packet tracing. Actual tracing on ARM64 has not been verified.
- `--drop` observes skb release/drop events; not every release represents network packet loss.
- Process names describe the execution context of the event, not necessarily the application owning the socket.
- native XDP runs before skb creation and may not appear in these paths. Missing events do not prove a logical layer was skipped.
- Narrow the protocol, address or port filter before enabling detail or call stacks to avoid affecting the observed system with excessive events.

[Full notes](https://github.com/calcky/tools/blob/master/nettrace/README.md) · [Upstream usage](https://github.com/OpenCloudOS/nettrace/blob/d455f001315322db4d606a8bdf8c659ba36b269c/README.md)
