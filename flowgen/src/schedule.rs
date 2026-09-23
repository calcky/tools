use std::time::{Duration, Instant};

/// A globally spaced schedule, partitioned by index across workers.
pub struct Pacer {
    epoch: Instant,
    step: f64,
    index: u64,
    stride: u64,
}
impl Pacer {
    pub fn new(epoch: Instant, rate: f64, worker: usize, workers: usize) -> Self {
        Self {
            epoch,
            step: 1.0 / rate,
            index: worker as u64 + 1,
            stride: workers as u64,
        }
    }
    pub fn deadline(&self) -> Instant {
        self.epoch + Duration::from_secs_f64(self.index as f64 * self.step)
    }
    /// Consume this slot and skip missed slots, never burst to catch up.
    pub fn advance(&mut self, now: Instant) -> u64 {
        self.index += self.stride;
        let elapsed = now.saturating_duration_since(self.epoch).as_secs_f64();
        let passed = (elapsed / self.step).floor() as u64;
        if self.index <= passed {
            let missed = (passed - self.index) / self.stride + 1;
            self.index += missed * self.stride;
            missed
        } else {
            0
        }
    }
}

pub fn next_send(previous: Instant, now: Instant, interval: Duration) -> (Instant, u64) {
    let next = previous + interval;
    if next > now {
        return (next, 0);
    }
    let elapsed = now.duration_since(next).as_nanos();
    let skipped = (elapsed / interval.as_nanos() + 1) as u64;
    let remainder = elapsed % interval.as_nanos();
    let remainder = Duration::new(
        (remainder / 1_000_000_000) as u64,
        (remainder % 1_000_000_000) as u32,
    );
    // Preserve each flow's phase after a stall, without replaying missed slots.
    (now + (interval - remainder), skipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn workers_partition_without_bursts() {
        let now = Instant::now();
        let a = Pacer::new(now, 10.0, 0, 2);
        let mut b = Pacer::new(now, 10.0, 1, 2);
        assert_eq!(a.deadline() - now, Duration::from_millis(100));
        assert_eq!(b.deadline() - now, Duration::from_millis(200));
        assert_eq!(b.advance(now + Duration::from_millis(850)), 3);
        assert_eq!(b.deadline() - now, Duration::from_secs(1));
    }
    #[test]
    fn no_send_catchup() {
        let start = Instant::now();
        let (next, skipped) = next_send(
            start,
            start + Duration::from_millis(550),
            Duration::from_millis(100),
        );
        assert_eq!(skipped, 5);
        assert_eq!(next, start + Duration::from_millis(600));
    }

    #[test]
    fn stalled_flows_keep_distinct_phases_and_future_deadlines() {
        let start = Instant::now();
        let now = start + Duration::from_millis(550);
        for phase in [0, 10, 30, 50, 90] {
            let (next, _) = next_send(
                start + Duration::from_millis(phase),
                now,
                Duration::from_millis(100),
            );
            assert!(next > now);
            assert!(next <= now + Duration::from_millis(100));
            assert_eq!(next.duration_since(start).as_millis() % 100, phase as u128);
        }
    }
}
