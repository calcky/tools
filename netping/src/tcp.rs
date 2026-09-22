use std::time::{Duration, Instant};

pub const SAMPLE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Default)]
pub struct CounterView {
    pub total: Option<u64>,
    pub rate: Option<f64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct View {
    pub tx: CounterView,
    pub rx: CounterView,
}

pub struct Counter {
    total: u64,
    raw: Option<u32>,
    available: bool,
    recorded: bool,
    rate: Option<f64>,
    anchor: Instant,
    anchor_total: u64,
}

impl Counter {
    fn new(now: Instant) -> Self {
        Self {
            total: 0,
            raw: None,
            available: false,
            recorded: false,
            rate: None,
            anchor: now,
            anchor_total: 0,
        }
    }

    pub fn connection(&mut self, baseline: Option<u32>, now: Instant) {
        self.raw = baseline;
        self.available = baseline.is_some();
        self.recorded |= baseline.is_some();
        self.rate = None;
        self.anchor = now;
        self.anchor_total = self.total;
    }

    pub fn observe(&mut self, raw: Option<u32>) {
        let Some(raw) = raw else {
            self.available = false;
            self.rate = None;
            return;
        };
        let delta = self.raw.map_or(raw, |old| raw.wrapping_sub(old));
        // Allow a 32-bit counter wrap, but ignore replayed older reports.
        if self.raw.is_some() && delta > i32::MAX as u32 {
            return;
        }
        self.total = self.total.saturating_add(u64::from(delta));
        self.raw = Some(raw);
        self.available = true;
        self.recorded = true;
    }

    pub fn completed(&mut self, raw: Option<u32>) {
        self.raw = None;
        self.observe(raw);
    }

    fn sample(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.anchor);
        if elapsed >= SAMPLE {
            self.rate = self.available.then(|| {
                self.total.saturating_sub(self.anchor_total) as f64 / elapsed.as_secs_f64()
            });
            self.anchor = now;
            self.anchor_total = self.total;
        }
    }

    fn view(&self) -> CounterView {
        CounterView {
            total: self.available.then_some(self.total),
            rate: self.available.then_some(self.rate).flatten(),
        }
    }

    fn active(&self) -> bool {
        self.available
            && (self.total > self.anchor_total || self.rate.is_some_and(|rate| rate > 0.0))
    }

    fn summary(&self) -> CounterView {
        CounterView {
            total: self.recorded.then_some(self.total),
            rate: None,
        }
    }
}

pub struct Retrans {
    pub tx: Counter,
    pub rx: Counter,
}

impl Retrans {
    pub fn new(now: Instant) -> Self {
        Self {
            tx: Counter::new(now),
            rx: Counter::new(now),
        }
    }

    pub fn sample(&mut self, now: Instant) {
        self.tx.sample(now);
        self.rx.sample(now);
    }

    pub fn view(&self) -> View {
        View {
            tx: self.tx.view(),
            rx: self.rx.view(),
        }
    }

    pub fn active(&self) -> bool {
        self.tx.active() || self.rx.active()
    }

    pub fn summary(&self) -> View {
        View {
            tx: self.tx.summary(),
            rx: self.rx.summary(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_tracks_new_retransmissions_not_historical_totals() {
        let now = Instant::now();
        let mut s = Retrans::new(now);
        s.tx.connection(Some(4), now);
        assert!(!s.active());
        s.tx.observe(Some(5));
        assert!(s.active());
        s.sample(now + SAMPLE);
        assert!(s.active());
        s.sample(now + SAMPLE * 2);
        assert!(!s.active());
        assert_eq!(s.view().tx.total, Some(1));
        s.rx.observe(Some(2));
        assert!(s.active());
        s.rx.observe(Some(1));
        s.sample(now + SAMPLE * 3);
        s.rx.observe(Some(2));
        s.sample(now + SAMPLE * 4);
        assert!(!s.active());
        s.tx.completed(Some(1));
        assert!(s.active());
        s.tx.connection(None, now + SAMPLE * 4);
        assert!(!s.active());
    }

    #[test]
    fn counters_survive_reconnect_and_ignore_replays() {
        let start = Instant::now();
        let mut s = Retrans::new(start);
        s.tx.connection(Some(2), start);
        s.tx.observe(Some(5));
        s.tx.observe(Some(5));
        s.tx.observe(Some(3));
        s.sample(start + SAMPLE);
        assert_eq!(s.view().tx.total, Some(3));
        assert_eq!(s.view().tx.rate, Some(3.0));
        assert_eq!(s.view().rx.total, None);
        s.tx.connection(Some(0), start + SAMPLE);
        s.tx.observe(Some(2));
        s.sample(start + SAMPLE * 2);
        assert_eq!(s.view().tx.total, Some(5));
        assert_eq!(s.view().tx.rate, Some(2.0));
        s.sample(start + SAMPLE * 3);
        assert_eq!(s.view().tx.rate, Some(0.0));
    }

    #[test]
    fn unavailable_is_not_zero_and_recovery_keeps_the_previous_baseline() {
        let now = Instant::now();
        let mut c = Counter::new(now);
        assert_eq!(c.view().total, None);
        c.observe(Some(7));
        c.observe(None);
        assert_eq!(c.view().total, None);
        c.observe(Some(9));
        assert_eq!(c.view().total, Some(9));
        c.connection(None, now);
        assert_eq!(c.view().total, None);
        assert_eq!(c.summary().total, Some(9));
        c.observe(Some(1));
        assert_eq!(c.view().total, Some(10));
    }

    #[test]
    fn wraps_and_short_lived_connect_sockets_are_counted_once() {
        let now = Instant::now();
        let mut c = Counter::new(now);
        c.connection(Some(u32::MAX - 1), now);
        c.observe(Some(1));
        assert_eq!(c.view().total, Some(3));
        c.completed(Some(2));
        c.completed(Some(4));
        c.sample(now + Duration::from_secs(2));
        assert_eq!(c.view().total, Some(9));
        assert_eq!(c.view().rate, Some(4.5));
    }
}
