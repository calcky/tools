Static Linux builds of [bpftop](https://github.com/jfernandez/bpftop) v0.9.0,
from upstream commit `35de7182f1603c9e45d4b7d21bd79fc0da89a195`.

Assets: `bpftop-linux-arm` (ARMv7), `bpftop-linux-arm64` (ARM64),
`bpftop-linux-x86_64`, `SHA256SUMS`, and upstream `LICENSE` (Apache-2.0).
The executables have no ELF interpreter or shared-library dependencies.

bpftop still requires a compatible Linux kernel and root privileges for
eBPF program inspection and runtime statistics. See the
[tool guide](https://github.com/calcky/tools/blob/master/bpftop/README.md).
