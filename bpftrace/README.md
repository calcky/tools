# bpftrace

This directory builds a pinned-source, fully static `bpftrace` executable for
Linux ARMv7, ARM64 and x86_64. The source is fetched from the upstream
bpftrace repository at the commit recorded in `build-static.sh`; bpftrace's
LLVM, BCC, libbpf, musl libc and other dependencies are linked from static
archives.

The executable has no dynamic loader or shared-library dependency. It still
requires a suitable kernel, BTF where the selected script needs it, and root
or equivalent capabilities for tracing. The `skb_output` feature is disabled
because Alpine's static `libpcap.a` cannot link into the ARM64 executable.

## Build locally

Docker Buildx and binfmt/QEMU support are required for ARM builds:

```sh
./bpftrace/build-static.sh x86_64
./bpftrace/build-static.sh arm64
./bpftrace/build-static.sh arm
```

The executables and SHA-256 files are written to `bpftrace/dist/`. Run all
three builds with `./bpftrace/build-static.sh all`. The first build for each
architecture downloads the pinned upstream source and creates an Alpine build
image; subsequent builds reuse both. Builds use four parallel jobs by default;
set `BPFTRACE_JOBS` to tune this for the host.

The GitHub Actions workflow performs the same build and uploads one executable
per architecture. A tag such as `bpftrace-v0.27.0` publishes a GitHub release.

## Runtime check

```sh
sudo ./bpftrace-linux-x86_64 -e 'tracepoint:syscalls:sys_enter_execve { printf("%s\n", comm); }'
```

The release artifact is the executable itself, without an additional archive.
