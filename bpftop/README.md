# bpftop (static builds)

This directory packages [jfernandez/bpftop](https://github.com/jfernandez/bpftop)
v0.9.0 for Linux ARMv7, ARM64 and x86_64. The upstream source is pinned to
commit `35de7182f1603c9e45d4b7d21bd79fc0da89a195`. This is a build and
distribution wrapper, not a fork of bpftop's application code. See
[LICENSE](LICENSE) for the upstream Apache-2.0 license.

## Installation

Example for x86_64; the [bpftop-release](https://github.com/calcky/tools/releases/tag/bpftop-release)
also contains ARMv7 and ARM64 executables and checksums.

```sh
curl -fLO https://github.com/calcky/tools/releases/download/bpftop-release/bpftop-linux-x86_64
mkdir -p "$HOME/.local/bin"
install -m 755 bpftop-linux-x86_64 "$HOME/.local/bin/bpftop"
```

`bpftop` explicitly requires root and a kernel with the required
eBPF facilities; static linking removes shared-library dependencies, not kernel
requirements. Run `bpftop -h` for options. `bpftop -d 2` refreshes every two
seconds. In the TUI, use `j/k` to select, Enter for graphs, `f` to filter, `s`
to sort and `q` to quit.

## Building

Docker, cross 0.2.5 and QEMU/binfmt support for the ARM targets are required.
Run `bash bpftop/build-static.sh all` from the repository root. The source and
build intermediates live in `bpftop/.build/`; the three executables and their
SHA-256 files are written to `bpftop/dist/`. The script rejects an unexpected
upstream commit and executables with an ELF interpreter or `NEEDED` dependency.
The GitHub workflow also checks architecture and `--version` under emulation
before uploading the three binaries to one canonical Release.
