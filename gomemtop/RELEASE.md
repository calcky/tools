# gomemtop v0.2.1

Fixes RSS collection on systems without `/proc/PID/smaps_rollup` by falling
back to `/proc/PID/status`. Go runtime MemStats now read beyond the first 2 MiB
of pprof text, tolerate a missing stack field, and show an explicit error when
unavailable. Includes ARMv7, ARM64, and x86_64 static Linux binaries.

See [usage and limitations](https://github.com/calcky/tools/blob/master/gomemtop/README.md).
