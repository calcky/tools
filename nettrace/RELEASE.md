# nettrace v1.2.11

Fully static Linux builds of OpenCloudOS/nettrace, pinned to the `btf` branch
commit `d455f001315322db4d606a8bdf8c659ba36b269c`.

- x86_64 and ARM64 executables, plus an experimental ARMv7 hard-float executable.
- musl libc, libbpf 1.6.3, libelf, zlib and zstd are statically linked.
- No ELF interpreter or shared library dependencies; BPF programs are embedded.
- Each executable has a separate SHA-256 checksum. Download the executable
  matching your architecture and make it executable with `chmod +x`.
- Upstream and dependency licenses are provided in `nettrace-LICENSES.txt`.

## Runtime Requirements

Root or equivalent capabilities, kernel BTF, debugfs and the required eBPF
tracing features are still necessary. Static linking does not remove kernel
requirements. No clang or bpftool installation is required on the target.

**ARMv7 is experimental, not a verified packet-tracing target.** This branch
uses BPF trampoline/fentry/fexit, which ordinary upstream 32-bit ARM kernels
do not implement. CLI startup on QEMU does not demonstrate usable tracing.
Such systems may require the upstream `master` branch's older kprobe backend.

## Verification

All three architectures pass static linkage, ELF architecture, checksum and
`-h`/`-V` startup checks. ARMv7 startup is checked through QEMU.
The x86_64 build also captured an actual ICMP `icmp_rcv` event on WSL2 Linux
6.6.87.2. Actual packet tracing on ARM64 and ARMv7 has not been verified.

## Sources And Rebuilding

The [build recipe](https://github.com/calcky/tools/tree/nettrace-release/nettrace)
contains the pinned upstream commit, dependency build and musl compatibility
header. The upstream nettrace source is unmodified. Source links and licenses
for the statically linked components are included with the license notices.

```sh
./nettrace/build-static.sh all
```
