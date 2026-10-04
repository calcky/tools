# cachetop v0.1.0

Initial release of a Linux PMU viewer for LLC reads and misses, MPKI, IPC,
and CPU migrations, with host-CPU and per-process thread views. Includes
static ARMv7, ARM64, and x86_64 executables.

PMU access depends on the host's hardware and perf permissions. LLC counters
describe read events, not a global cache hit rate. See the
[usage and limitations](https://github.com/calcky/tools/blob/master/cachetop/README.md).
