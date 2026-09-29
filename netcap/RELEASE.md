Static Linux builds of ByteDance netcap 1.0.1 from upstream commit
`027dd2a763ebc893474f398b1eb28aab156e51c7`.

- Choose `netcap-linux-x86_64`, `netcap-linux-arm64`, or `netcap-linux-arm` (ARMv7).
- Each executable is statically linked; the matching `.sha256` file verifies its download.
- x86_64 `skb` capture was tested against loopback ICMP. ARM64 and ARMv7 were build- and startup-tested, but not capture-tested on matching hardware.
- Runtime BCC compilation needs matching, prepared kernel headers, debugfs, and tracing privileges. Set `BCC_KERNEL_SOURCE` for custom kernels.
- Text output still invokes external `bash` and `tcpdump`; use `-w capture.pcap` without them. `raw`/`mbuf` modes have not been validated.

Build details: https://github.com/calcky/tools/tree/netcap-release/netcap
