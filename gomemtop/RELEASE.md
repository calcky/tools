# gomemtop v0.1.0

Initial release of a live Go heap pprof analyzer. Samples a trusted pprof
endpoint, ranks allocation stacks by growth since a baseline, and shows
current in-use or cumulative allocation estimates in an interactive terminal.
Includes optional GC sampling and ARMv7, ARM64, and x86_64 static Linux binaries.

See [usage and limitations](https://github.com/calcky/tools/blob/master/gomemtop/README.md).
