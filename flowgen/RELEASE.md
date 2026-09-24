flowgen v0.1.3 improves unattended TCP/UDP load generation and startup defaults.

The v0.1.2 build stopped before publication because the file-limit test assumed
the container's hard limit matched the kernel ceiling. The test now respects
the inherited hard limit, including restricted CI containers.

- `-T 0` and `-T0` run continuously after warmup until Ctrl+C or SIGTERM. Request timeouts, graceful draining, final statistics and recordings still apply. Upgrade both client and server to use unlimited runs.
- The server no longer prints periodic statistics by default. Use `flowgen -s --stats` to enable one-second aggregate reports.
- `-h` and `-v` work anywhere in the command line, including `flowgen -u HOST -T0 -h`.
- Both client and server try to maximize their process file-descriptor limits up to Linux's `fs.nr_open` ceiling. Without permission to raise the hard limit, they fall back to the existing hard limit. Startup fails only when the resulting limit is insufficient, with an actionable error. No persistent system settings are changed.

Unlimited runs with connection turnover still honor source-tuple policy: without `-Q`, a depleted pool stops replacements while existing sessions continue sending. `-Q` explicitly enables cooldown reuse.

Download the executable for your Linux architecture: `arm` (ARMv7 hard-float), `arm64`, or `x86_64`. All three are statically linked with musl and distributed without an archive. Both client and server use the same executable.

Make the downloaded file executable with `chmod +x flowgen-linux-<arch>`, then run it with `-h` for help.

The release workflow runs unit and integration tests on all three targets, smoke-tests each executable and checks that no dynamic interpreter or shared-library dependencies remain before publication.
