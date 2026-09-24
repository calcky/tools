use std::time::Duration;

use super::{PreviousCounters, SocketTcpDiagnostics};

/// Adjacent observations of the same kernel socket, timed at query completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketLimitInterval {
    pub(crate) elapsed: Duration,
    pub(crate) busy_micros: u64,
    pub(crate) rwnd_micros: Option<u64>,
    pub(crate) sndbuf_micros: Option<u64>,
}

impl SocketLimitInterval {
    pub(super) fn between(
        current: &PreviousCounters,
        previous: Option<&PreviousCounters>,
        elapsed: Option<Duration>,
    ) -> Option<Self> {
        let previous = previous?;
        let elapsed = elapsed.filter(|value| !value.is_zero())?;
        let busy_micros = current.busy_micros?.checked_sub(previous.busy_micros?)?;
        let delta = |current: Option<u64>, previous: Option<u64>| {
            current?
                .checked_sub(previous?)
                .filter(|value| *value <= busy_micros)
        };
        Some(Self {
            elapsed,
            busy_micros,
            rwnd_micros: delta(current.rwnd_micros, previous.rwnd_micros),
            sndbuf_micros: delta(current.sndbuf_micros, previous.sndbuf_micros),
        })
    }

    pub(crate) fn share(self, micros: Option<u64>) -> Option<f64> {
        (self.busy_micros > 0)
            .then(|| micros.map(|value| value as f64 / self.busy_micros as f64))
            .flatten()
    }
}

impl SocketTcpDiagnostics {
    pub(crate) fn estimated_flight_segments(self) -> Option<u32> {
        self.unacked_segments
            .checked_sub(self.sacked_segments)?
            .checked_sub(self.lost_segments)?
            .checked_add(self.retransmitted_segments)
    }

    /// Time counters describe the interval; gauges can only suggest a current constraint.
    pub(crate) fn limit_reason(self) -> (&'static str, &'static str) {
        let Some(interval) = self.limit_interval else {
            return ("UNKNOWN", "No valid adjacent TCP_INFO timing baseline");
        };
        let rwnd = interval.share(interval.rwnd_micros);
        let sndbuf = interval.share(interval.sndbuf_micros);
        let rwnd_high = rwnd.is_some_and(|share| share >= 0.5);
        let sndbuf_high = sndbuf.is_some_and(|share| share >= 0.5);
        if rwnd_high && sndbuf_high {
            return (
                "RWND + SNDBUF",
                "Both counters reached 50% of busy time in this interval",
            );
        }
        if rwnd_high {
            return (
                "RWND",
                "rwnd_limited delta / busy delta >= 50% in this interval",
            );
        }
        if sndbuf_high {
            return (
                "SNDBUF",
                "sndbuf_limited delta / busy delta >= 50% in this interval",
            );
        }
        if interval.rwnd_micros.is_none() || interval.sndbuf_micros.is_none() {
            return (
                "UNKNOWN",
                "Limited-time counter missing, reset, or inconsistent with busy time",
            );
        }
        if interval.busy_micros == 0 {
            return if self.notsent_bytes == Some(0) && self.unacked_segments == 0 {
                (
                    "IDLE",
                    "No busy-time increase, no unsent data, and no unacked segments",
                )
            } else {
                (
                    "UNKNOWN",
                    "No busy-time increase; pending data or flight still present",
                )
            };
        }
        if self.notsent_bytes.is_some_and(|bytes| bytes > 0)
            && self.send_cwnd_segments > 0
            && self.estimated_flight_segments().is_some_and(|flight| {
                u64::from(flight) * 10 >= u64::from(self.send_cwnd_segments) * 9
            })
            && self.congestion_state == 0
            && self
                .send_window_bytes
                .is_some_and(|window| u64::from(window) >= self.congestion_window_bytes())
        {
            return ("CWND?", "Snapshot estimate: unsent > 0, flight/cwnd >= 90%, CA Open, peer window >= cwnd bytes");
        }
        if self.notsent_bytes == Some(0) && self.delivery_rate_app_limited {
            return (
                "APP?",
                "No unsent data now; latest delivery-rate sample was app-limited",
            );
        }
        (
            "ACTIVE",
            "No dominant timed limit observed; other constraints remain possible",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counters(busy: u64, rwnd: u64, sndbuf: u64) -> PreviousCounters {
        PreviousCounters {
            receive_segments: None,
            receive_bytes: None,
            send_segments: None,
            send_bytes: None,
            total_retransmitted_segments: None,
            drops: None,
            busy_micros: Some(busy),
            rwnd_micros: Some(rwnd),
            sndbuf_micros: Some(sndbuf),
        }
    }

    #[test]
    fn timing_requires_adjacent_monotonic_counters_and_preserves_zero() {
        let old = counters(10_000, 8_000, 500);
        let current = counters(11_000, 8_720, 620);
        let elapsed = Some(Duration::from_secs(2));
        assert_eq!(SocketLimitInterval::between(&current, None, elapsed), None);
        assert_eq!(
            SocketLimitInterval::between(&current, Some(&old), Some(Duration::ZERO)),
            None
        );
        let delta = SocketLimitInterval::between(&current, Some(&old), elapsed).unwrap();
        assert_eq!(delta.busy_micros, 1_000);
        assert_eq!(delta.elapsed, Duration::from_secs(2));
        assert_eq!(delta.share(delta.rwnd_micros), Some(0.72));
        assert_eq!(delta.share(delta.sndbuf_micros), Some(0.12));
        assert_eq!(
            SocketLimitInterval::between(&old, Some(&current), elapsed),
            None
        );
        let idle = SocketLimitInterval::between(&old, Some(&old), elapsed).unwrap();
        assert_eq!(idle.rwnd_micros, Some(0));
        assert_eq!(idle.share(idle.rwnd_micros), None);
        let invalid = counters(11_000, 10_000, 400);
        let delta = SocketLimitInterval::between(&invalid, Some(&old), elapsed).unwrap();
        assert_eq!(delta.rwnd_micros, None);
        assert_eq!(delta.sndbuf_micros, None);
    }

    #[test]
    fn diagnosis_distinguishes_interval_evidence_from_snapshot_estimates() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let mut tcp = snapshot.sockets()[0].tcp().unwrap();
        assert_eq!(tcp.limit_reason().0, "UNKNOWN");
        tcp.limit_interval = Some(SocketLimitInterval {
            elapsed: Duration::from_secs(1),
            busy_micros: 1_000_000,
            rwnd_micros: Some(720_000),
            sndbuf_micros: Some(120_000),
        });
        tcp.notsent_bytes = Some(0);
        assert_eq!(
            tcp.limit_reason().0,
            "RWND",
            "Interval evidence survives an empty current queue"
        );
        tcp.limit_interval.as_mut().unwrap().rwnd_micros = Some(0);
        tcp.limit_interval.as_mut().unwrap().sndbuf_micros = Some(600_000);
        assert_eq!(tcp.limit_reason().0, "SNDBUF");
        tcp.limit_interval.as_mut().unwrap().sndbuf_micros = Some(0);
        tcp.notsent_bytes = Some(8192);
        tcp.unacked_segments = 20;
        assert_eq!(tcp.limit_reason().0, "CWND?");
        tcp.sacked_segments = 5;
        assert_eq!(tcp.estimated_flight_segments(), Some(15));
        assert_eq!(tcp.limit_reason().0, "ACTIVE");
        tcp.sacked_segments = 0;
        tcp.send_window_bytes = None;
        assert_eq!(
            tcp.limit_reason().0,
            "ACTIVE",
            "Missing peer window cannot confirm cwnd constraint"
        );
        tcp.notsent_bytes = Some(0);
        tcp.delivery_rate_app_limited = true;
        assert_eq!(tcp.limit_reason().0, "APP?");
        tcp.limit_interval.as_mut().unwrap().busy_micros = 0;
        tcp.unacked_segments = 0;
        assert_eq!(tcp.limit_reason().0, "IDLE");
    }
}
