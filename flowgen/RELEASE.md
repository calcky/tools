flowgen v0.1.4 adds standalone offline HTML reports and LOAD-phase target attainment.

- Client event recordings now generate `report.html` and `timeseries.csv`. Rebuild reports from existing recordings with `flowgen -R DIR`; the embedded chart library and data work offline without a web server.
- Four linked charts show RTT (Avg/P90/P99), sample coverage and request timeouts, traffic (PPS and application bandwidth), and sessions/failures. Detail tabs retain full latency, request, session, recording and diagnostic statistics.
- Full-run summaries and anomalies remain independent of chart zoom. Chart PNG exports preserve the selected range and visible series; CSV exports preserve full-run values and recording/accounting status.
- Target attainment compares configured targets with LOAD-phase Ready sessions, request PPS and initiated rotations/s, excluding warmup and drain. Ready and deficit sampling supplements Live; Live still includes opening and draining sessions.
- Readiness sampling reports temporal coverage. Missing samples and unavailable counters are not treated as zero, and incomplete runs do not certify attainment. Older recordings without Ready samples or rotation counters keep those fields unavailable.
- Summary recording produces aggregate-only HTML with sampled Ready/rotation attainment; exact LOAD request PPS requires event recordings. Off recording generates no HTML or readiness samples.

The existing client/server protocol and binary event-recording format are unchanged. Percentiles are calculated from eligible samples, not averaged across sessions or timeline buckets. TCP request timeouts remain distinct from network packet loss.

Download the executable for your Linux architecture: `arm` (ARMv7 hard-float), `arm64`, or `x86_64`. All three are statically linked with musl and distributed without an archive. Both client and server use the same executable.

Make the downloaded file executable with `chmod +x flowgen-linux-<arch>`, then run it with `-h` for help.

The release workflow runs unit and integration tests on all three targets, smoke-tests each executable and checks that no dynamic interpreter or shared-library dependencies remain before publication.
