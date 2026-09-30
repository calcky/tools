# gomemtop v0.2.0

Adds `--pid` to compare a Go heap profile with actual Linux process RSS,
anonymous/file/shared resident pages, and Go runtime memory counters. A
diagnostic panel compares multiple paired samples and shows its evidence
without claiming a leak from a single snapshot. Includes ARMv7, ARM64, and
x86_64 static Linux binaries.

See [usage and limitations](https://github.com/calcky/tools/blob/master/gomemtop/README.md).
