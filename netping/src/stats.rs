use hdrhistogram::Histogram;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
pub const CAPACITY: usize = 8192;
const HISTORY: usize = 65536;

pub enum Event {
    Sent,
    Received(Duration),
    Timeout,
    Failed,
    Late,
    Duplicate,
    Reordered,
    Invalid,
    Limited,
    Skipped(u64),
}
pub struct Window {
    pub sent: u64,
    pub recv: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub timeout: u64,
    pub failed: u64,
    pub late: u64,
    pub duplicate: u64,
    pub reordered: u64,
    pub invalid: u64,
    pub limited: u64,
    pub skipped: u64,
    pub hist: Histogram<u64>,
    pub mean: f64,
    pub m2: f64,
    pub min: f64,
    pub max: f64,
}
impl Default for Window {
    fn default() -> Self {
        Self {
            sent: 0,
            recv: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            timeout: 0,
            failed: 0,
            late: 0,
            duplicate: 0,
            reordered: 0,
            invalid: 0,
            limited: 0,
            skipped: 0,
            hist: Histogram::new_with_bounds(1, 86_400_000_000, 3).unwrap(),
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: 0.0,
        }
    }
}
impl Window {
    fn record(&mut self, e: &Event) {
        match e {
            Event::Sent => self.sent += 1,
            Event::Timeout => self.timeout += 1,
            Event::Failed => self.failed += 1,
            Event::Late => self.late += 1,
            Event::Duplicate => self.duplicate += 1,
            Event::Reordered => self.reordered += 1,
            Event::Invalid => self.invalid += 1,
            Event::Limited => self.limited += 1,
            Event::Skipped(n) => self.skipped += n,
            Event::Received(d) => {
                self.recv += 1;
                let ms = d.as_secs_f64() * 1000.0;
                self.min = self.min.min(ms);
                self.max = self.max.max(ms);
                let delta = ms - self.mean;
                self.mean += delta / self.recv as f64;
                self.m2 += delta * (ms - self.mean);
                self.hist
                    .record((d.as_micros() as u64).min(86_400_000_000))
                    .unwrap();
            }
        }
    }
    pub fn quantile(&self, q: f64) -> f64 {
        if self.recv == 0 {
            return 0.0;
        }
        (self.hist.value_at_quantile(q) as f64 / 1000.0).clamp(self.min, self.max)
    }
    pub fn deviation(&self) -> f64 {
        if self.recv == 0 {
            0.0
        } else {
            (self.m2 / self.recv as f64).sqrt()
        }
    }
    pub fn loss(&self) -> f64 {
        let n = self.recv + self.timeout + self.failed;
        if n == 0 {
            0.0
        } else {
            (self.timeout + self.failed) as f64 * 100.0 / n as f64
        }
    }
}
#[derive(Clone, Copy, PartialEq)]
enum State {
    Empty,
    Received,
    Timeout,
    Late,
    Failed,
}
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Received(Duration),
    Reordered(Duration),
    Late,
    Duplicate,
    Invalid,
}
pub struct Tracker {
    pub pending: BTreeMap<u64, Instant>,
    history: Vec<(u64, State)>,
    pub total: Window,
    pub current: Window,
    timeout: Duration,
    highest_received: u64,
}
impl Tracker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: BTreeMap::new(),
            history: vec![(0, State::Empty); HISTORY],
            total: Window::default(),
            current: Window::default(),
            timeout,
            highest_received: 0,
        }
    }
    pub fn record(&mut self, e: Event) {
        self.total.record(&e);
        self.current.record(&e);
    }
    pub fn sent(&mut self, seq: u64, at: Instant) {
        self.sent_with_bytes(seq, at, 0);
    }
    pub fn sent_with_bytes(&mut self, seq: u64, at: Instant, bytes: u64) {
        self.pending.insert(seq, at);
        self.record(Event::Sent);
        self.total.tx_bytes = self.total.tx_bytes.saturating_add(bytes);
        self.current.tx_bytes = self.current.tx_bytes.saturating_add(bytes);
    }
    pub fn known(&self, seq: u64) -> bool {
        let (old, state) = self.history[seq as usize % HISTORY];
        self.pending.contains_key(&seq) || (old == seq && state != State::Empty)
    }
    fn remember(&mut self, seq: u64, s: State) {
        self.history[seq as usize % HISTORY] = (seq, s);
    }
    pub fn fail(&mut self, seq: u64) {
        if self.pending.remove(&seq).is_some() {
            self.remember(seq, State::Failed);
            self.record(Event::Failed);
        }
    }
    #[allow(dead_code)]
    pub fn receive(&mut self, seq: u64, now: Instant) -> Outcome {
        self.receive_with_bytes(seq, now, 0)
    }
    pub fn receive_with_bytes(&mut self, seq: u64, now: Instant, bytes: u64) -> Outcome {
        if let Some(sent) = self.pending.remove(&seq) {
            let duration = now.duration_since(sent);
            if duration < self.timeout {
                self.remember(seq, State::Received);
                self.record(Event::Received(duration));
                self.record_rx_bytes(bytes);
                let reordered = seq < self.highest_received;
                self.highest_received = self.highest_received.max(seq);
                return if reordered {
                    self.record(Event::Reordered);
                    Outcome::Reordered(duration)
                } else {
                    Outcome::Received(duration)
                };
            }
            self.record(Event::Timeout);
            self.remember(seq, State::Late);
            self.record(Event::Late);
            self.record_rx_bytes(bytes);
            return Outcome::Late;
        }
        let (old, state) = self.history[seq as usize % HISTORY];
        if old != seq || state == State::Empty {
            self.record(Event::Invalid);
            Outcome::Invalid
        } else if state == State::Timeout {
            self.remember(seq, State::Late);
            self.record(Event::Late);
            self.record_rx_bytes(bytes);
            Outcome::Late
        } else {
            self.record(Event::Duplicate);
            self.record_rx_bytes(bytes);
            Outcome::Duplicate
        }
    }
    fn record_rx_bytes(&mut self, bytes: u64) {
        self.total.rx_bytes = self.total.rx_bytes.saturating_add(bytes);
        self.current.rx_bytes = self.current.rx_bytes.saturating_add(bytes);
    }
    pub fn expire(&mut self, now: Instant) -> Vec<u64> {
        let mut expired = Vec::new();
        while let Some((&seq, &at)) = self.pending.first_key_value() {
            if now.duration_since(at) < self.timeout {
                break;
            }
            self.pending.pop_first();
            self.remember(seq, State::Timeout);
            self.record(Event::Timeout);
            expired.push(seq);
        }
        expired
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.pending
            .first_key_value()
            .map(|(_, at)| *at + self.timeout)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reordering_counts_first_valid_replies_without_losing_rtt_samples() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_millis(10));
        for seq in 1..=4 {
            s.sent(seq, t);
        }
        assert_eq!(
            s.receive(3, t + Duration::from_millis(1)),
            Outcome::Received(Duration::from_millis(1))
        );
        assert_eq!(
            s.receive(1, t + Duration::from_millis(2)),
            Outcome::Reordered(Duration::from_millis(2))
        );
        assert_eq!(
            s.receive(1, t + Duration::from_millis(3)),
            Outcome::Duplicate
        );
        assert_eq!(
            s.receive(99, t + Duration::from_millis(3)),
            Outcome::Invalid
        );
        assert_eq!(
            s.receive(2, t + Duration::from_millis(4)),
            Outcome::Reordered(Duration::from_millis(4))
        );
        assert_eq!(
            s.receive(4, t + Duration::from_millis(5)),
            Outcome::Received(Duration::from_millis(5))
        );
        assert_eq!(
            (s.total.recv, s.total.reordered, s.current.reordered),
            (4, 2, 2)
        );
        assert_eq!(s.total.mean, 3.0);
        assert_eq!(s.total.hist.len(), 4);
        assert_eq!(s.total.loss(), 0.0);
    }
    #[test]
    fn late_replies_do_not_count_as_reordered_or_advance_receive_sequence() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_millis(10));
        s.sent(9, t);
        s.sent(1, t + Duration::from_millis(5));
        assert_eq!(s.receive(9, t + Duration::from_millis(10)), Outcome::Late);
        assert_eq!(
            s.receive(1, t + Duration::from_millis(11)),
            Outcome::Received(Duration::from_millis(6))
        );
        s.sent(2, t + Duration::from_millis(12));
        s.sent(3, t + Duration::from_millis(12));
        s.receive(3, t + Duration::from_millis(13));
        assert_eq!(s.expire(t + Duration::from_millis(22)), vec![2]);
        assert_eq!(s.receive(2, t + Duration::from_millis(23)), Outcome::Late);
        assert_eq!(s.total.reordered, 0);
        assert_eq!(s.total.late, 2);
    }
    #[test]
    fn reorder_detection_survives_interval_reset_and_history_wrap() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_secs(1));
        s.sent(1, t);
        s.sent(HISTORY as u64 + 2, t);
        s.receive(HISTORY as u64 + 2, t);
        s.current = Window::default();
        assert_eq!(s.receive(1, t), Outcome::Reordered(Duration::ZERO));
        assert_eq!((s.total.reordered, s.current.reordered), (1, 1));
    }
    #[test]
    fn approximate_quantiles_stay_within_observed_bounds() {
        let mut w = Window::default();
        assert_eq!(w.quantile(0.99), 0.0);
        for us in [51, 3615, 43319] {
            w.record(&Event::Received(Duration::from_micros(us)));
        }
        for q in [0.0, 0.5, 0.95, 0.99, 1.0] {
            assert!((w.min..=w.max).contains(&w.quantile(q)));
        }
    }
    #[test]
    fn replies_timeouts_late_duplicates_and_unknown() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_millis(10));
        s.sent(1, t);
        s.sent(2, t);
        s.sent(3, t);
        assert!(matches!(
            s.receive(2, t + Duration::from_millis(2)),
            Outcome::Received(_)
        ));
        assert_eq!(
            s.receive(2, t + Duration::from_millis(3)),
            Outcome::Duplicate
        );
        assert_eq!(s.expire(t + Duration::from_millis(10)), vec![1, 3]);
        assert_eq!(s.receive(1, t + Duration::from_millis(11)), Outcome::Late);
        assert_eq!(
            s.receive(1, t + Duration::from_millis(12)),
            Outcome::Duplicate
        );
        assert_eq!(s.receive(99, t), Outcome::Invalid);
        assert_eq!(
            (
                s.total.sent,
                s.total.recv,
                s.total.timeout,
                s.total.late,
                s.total.duplicate,
                s.total.invalid
            ),
            (3, 1, 2, 1, 2, 1)
        );
        assert_eq!(s.total.mean, 2.0);
    }
    #[test]
    fn receipt_at_deadline_is_late_even_before_expiry_scan() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_secs(1));
        s.sent(1, t);
        assert_eq!(s.receive(1, t + Duration::from_secs(1)), Outcome::Late);
        assert_eq!(s.total.timeout, 1);
        assert_eq!(s.total.recv, 0);
    }
    #[test]
    fn pending_not_counted_as_loss_and_histogram_is_bounded() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_secs(1));
        s.sent(1, t);
        s.sent(2, t);
        s.receive(1, t + Duration::from_millis(1));
        assert_eq!(s.total.loss(), 0.0);
        s.fail(2);
        assert_eq!(s.total.loss(), 50.0);
        let mut w = Window::default();
        for n in [1, 2, 3] {
            w.record(&Event::Received(Duration::from_millis(n)));
        }
        assert_eq!(w.mean, 2.0);
        assert!((w.deviation() - (2.0f64 / 3.0).sqrt()).abs() < 1e-9);
        assert!((w.quantile(0.99) - 3.0).abs() < 0.01);
    }

    #[test]
    fn payload_bandwidth_counts_valid_late_and_duplicate_replies_once_each() {
        let t = Instant::now();
        let mut s = Tracker::new(Duration::from_millis(10));
        s.sent_with_bytes(1, t, 100);
        assert_eq!(
            s.receive_with_bytes(1, t + Duration::from_millis(1), 200),
            Outcome::Received(Duration::from_millis(1))
        );
        assert_eq!(
            s.receive_with_bytes(1, t + Duration::from_millis(2), 200),
            Outcome::Duplicate
        );
        s.sent_with_bytes(2, t, 100);
        s.expire(t + Duration::from_millis(10));
        assert_eq!(
            s.receive_with_bytes(2, t + Duration::from_millis(11), 200),
            Outcome::Late
        );
        assert_eq!((s.total.tx_bytes, s.total.rx_bytes), (200, 600));
    }
}
