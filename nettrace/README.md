# nettrace

Build fully static executables of [OpenCloudOS/nettrace](https://github.com/OpenCloudOS/nettrace),
an eBPF tool for tracing packets through the Linux network stack.

The source is pinned to the `btf` branch commit
`d455f001315322db4d606a8bdf8c659ba36b269c` (version 1.2.11).
The build uses Alpine 3.22/musl and libbpf 1.6.3 at commit
`3b4f0ef5a6fa247ce1958d909c0e85e760249840`.
The pinned source uses libbpf APIs introduced in 1.6, despite the upstream
README listing 1.4 as its minimum.

## Installation

Example for x86_64; see [nettrace-release](https://github.com/calcky/tools/releases/tag/nettrace-release) for other architectures.
The release includes checksums and upstream/dependency licenses.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/nettrace-release/nettrace-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 nettrace-linux-x86_64 "$HOME/.local/bin/nettrace"
```

## Build

Docker Buildx and binfmt/QEMU are required for non-native architectures.

```sh
./nettrace/build-static.sh x86_64
./nettrace/build-static.sh arm64
./nettrace/build-static.sh arm
# Or build all three:
./nettrace/build-static.sh all
```

Set `NETTRACE_JOBS` to change the default four build jobs.
Each architecture has its own source checkout in `.build/`.
The user-space compatibility header fixes Linux UAPI/musl header conflicts;
it does not modify the embedded BPF programs or upstream source.

Executables and SHA-256 checksums are written to `nettrace/dist/`:

```text
nettrace-linux-x86_64
nettrace-linux-arm64
nettrace-linux-arm
```

Each build checks that the ELF has no interpreter or shared library dependencies
and runs `-V` and `-h` (through QEMU for ARM targets).
The BPF object is embedded; clang and bpftool are build dependencies only.

## Run

```sh
nettrace -V
nettrace -p icmp --detail
```

Runtime still requires kernel BTF, the relevant eBPF tracing features, debugfs
and root or equivalent capabilities. Static linking removes shared library
dependencies, not kernel requirements.

**ARMv7 is experimental.** The `btf` branch relies on BPF trampoline/fentry/fexit.
The usual upstream 32-bit ARM kernel does not provide the required trampoline
implementation. Successful compilation and QEMU CLI startup therefore do not
establish usable packet tracing on ARMv7. Such targets may need the upstream
`master` branch's older kprobe implementation instead.

The x86_64 executable was tested against the WSL2 Linux 6.6.87.2 kernel:
an ICMP loopback probe produced an `icmp_rcv` event. ARM tracing requires a
real compatible ARM kernel and is not verified by the build's CLI checks.
