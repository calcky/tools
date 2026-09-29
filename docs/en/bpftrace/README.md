# bpftrace

Trace Linux kernels and processes with short scripts. Static executables are available for ARMv7, ARM64 and x86_64.

## Installation

Choose the matching architecture from the [download page](https://github.com/calcky/tools/releases/tag/bpftrace-release).
For x86_64:

```sh
chmod +x bpftrace-linux-x86_64
sudo ./bpftrace-linux-x86_64 --info
```

The executable needs no dynamic musl/glibc, but tracing still depends on kernel features and permissions.

## Common Commands

```sh
# List syscall tracepoints
sudo ./bpftrace-linux-x86_64 -l 'tracepoint:syscalls:sys_enter_*'

# Print the names of processes executing programs
sudo ./bpftrace-linux-x86_64 -e \
  'tracepoint:syscalls:sys_enter_execve { printf("%s\n", comm); }'

# Count read calls per process name every second
sudo ./bpftrace-linux-x86_64 -e \
  'tracepoint:syscalls:sys_enter_read { @[comm] = count(); } interval:s:1 { print(@); clear(@); }'

# Run an existing script
sudo ./bpftrace-linux-x86_64 trace.bt
```

Press Ctrl+C to stop tracing.

## Key Options

| Option | Meaning |
| --- | --- |
| `-e SCRIPT` | Run an inline script |
| `-l [PATTERN]` | List matching probes |
| `-p PID` | Attach to an existing process; scope depends on probe type |
| `-c COMMAND` | Run a command and trace while it runs |
| `--info` | Inspect kernel and tracing capabilities |
| `--help` / `--version` | Help / version |

## Notes

- Root or appropriate tracing capabilities are normally required; containers may further restrict BPF.
- Some scripts need kernel BTF. A static executable does not supply missing kernel features.
- High-frequency probes and excessive printing can affect the system; start with a narrow scope.
- This static build does not provide `skb_output`.

[Static downloads](https://github.com/calcky/tools/releases/tag/bpftrace-release) · [Full notes](https://github.com/calcky/tools/blob/master/bpftrace/README.md) · [Upstream manual](https://bpftrace.org/docs)
