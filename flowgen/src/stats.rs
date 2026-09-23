use std::{
    cell::Cell,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
};

#[derive(Default)]
pub struct Stats {
    pub ready: AtomicU64,
    pub connecting: AtomicU64,
    pub draining: AtomicU64,
    pub attempts: AtomicU64,
    pub established: AtomicU64,
    pub closed: AtomicU64,
    pub rotations: AtomicU64,
    pub repairs: AtomicU64,
    pub failed: AtomicU64,
    pub session_skipped: AtomicU64,
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub pending: AtomicU64,
    pub timeout: AtomicU64,
    pub canceled: AtomicU64,
    pub duplicate: AtomicU64,
    pub late: AtomicU64,
    pub reordered: AtomicU64,
    pub invalid: AtomicU64,
    pub limited: AtomicU64,
    pub skipped: AtomicU64,
    pub log_dropped: AtomicU64,
}

/// One worker's published traffic counters, isolated from neighboring workers.
#[repr(align(128))]
#[derive(Default)]
pub struct TrafficSnapshot {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub pending: AtomicU64,
    pub timeout: AtomicU64,
    pub canceled: AtomicU64,
    pub duplicate: AtomicU64,
    pub late: AtomicU64,
    pub reordered: AtomicU64,
    pub invalid: AtomicU64,
    pub limited: AtomicU64,
    pub skipped: AtomicU64,
    pub log_dropped: AtomicU64,
}

/// Worker-owned counters. The caller publishes every 100 ms; drop publishes last.
pub struct LocalTraffic {
    snapshot: Arc<TrafficSnapshot>,
    pub sent: Cell<u64>,
    pub received: Cell<u64>,
    pub tx_bytes: Cell<u64>,
    pub rx_bytes: Cell<u64>,
    pub pending: Cell<u64>,
    pub timeout: Cell<u64>,
    pub canceled: Cell<u64>,
    pub duplicate: Cell<u64>,
    pub late: Cell<u64>,
    pub reordered: Cell<u64>,
    pub invalid: Cell<u64>,
    pub limited: Cell<u64>,
    pub skipped: Cell<u64>,
    pub log_dropped: Cell<u64>,
}

impl LocalTraffic {
    /// Each worker must own a distinct snapshot, initially zeroed.
    pub fn new(snapshot: Arc<TrafficSnapshot>) -> Self {
        Self {
            snapshot,
            sent: Cell::new(0),
            received: Cell::new(0),
            tx_bytes: Cell::new(0),
            rx_bytes: Cell::new(0),
            pending: Cell::new(0),
            timeout: Cell::new(0),
            canceled: Cell::new(0),
            duplicate: Cell::new(0),
            late: Cell::new(0),
            reordered: Cell::new(0),
            invalid: Cell::new(0),
            limited: Cell::new(0),
            skipped: Cell::new(0),
            log_dropped: Cell::new(0),
        }
    }

    /// Store cumulative counters and the current pending gauge without resetting.
    /// Readers may observe fields from different publications.
    pub fn publish(&self) {
        self.snapshot.sent.store(self.sent.get(), Relaxed);
        self.snapshot.received.store(self.received.get(), Relaxed);
        self.snapshot.tx_bytes.store(self.tx_bytes.get(), Relaxed);
        self.snapshot.rx_bytes.store(self.rx_bytes.get(), Relaxed);
        self.snapshot.pending.store(self.pending.get(), Relaxed);
        self.snapshot.timeout.store(self.timeout.get(), Relaxed);
        self.snapshot.canceled.store(self.canceled.get(), Relaxed);
        self.snapshot.duplicate.store(self.duplicate.get(), Relaxed);
        self.snapshot.late.store(self.late.get(), Relaxed);
        self.snapshot.reordered.store(self.reordered.get(), Relaxed);
        self.snapshot.invalid.store(self.invalid.get(), Relaxed);
        self.snapshot.limited.store(self.limited.get(), Relaxed);
        self.snapshot.skipped.store(self.skipped.get(), Relaxed);
        self.snapshot
            .log_dropped
            .store(self.log_dropped.get(), Relaxed);
    }
}

impl Drop for LocalTraffic {
    fn drop(&mut self) {
        self.publish();
    }
}

impl Stats {
    /// Copy authoritative shared stats and add each worker's published traffic.
    /// Like individual relaxed loads, this is not a coherent point-in-time view.
    pub fn snapshot(&self, shards: &[Arc<TrafficSnapshot>]) -> Stats {
        let result = Self {
            ready: AtomicU64::new(get(&self.ready)),
            connecting: AtomicU64::new(get(&self.connecting)),
            draining: AtomicU64::new(get(&self.draining)),
            attempts: AtomicU64::new(get(&self.attempts)),
            established: AtomicU64::new(get(&self.established)),
            closed: AtomicU64::new(get(&self.closed)),
            rotations: AtomicU64::new(get(&self.rotations)),
            repairs: AtomicU64::new(get(&self.repairs)),
            failed: AtomicU64::new(get(&self.failed)),
            session_skipped: AtomicU64::new(get(&self.session_skipped)),
            sent: AtomicU64::new(get(&self.sent)),
            received: AtomicU64::new(get(&self.received)),
            tx_bytes: AtomicU64::new(get(&self.tx_bytes)),
            rx_bytes: AtomicU64::new(get(&self.rx_bytes)),
            pending: AtomicU64::new(get(&self.pending)),
            timeout: AtomicU64::new(get(&self.timeout)),
            canceled: AtomicU64::new(get(&self.canceled)),
            duplicate: AtomicU64::new(get(&self.duplicate)),
            late: AtomicU64::new(get(&self.late)),
            reordered: AtomicU64::new(get(&self.reordered)),
            invalid: AtomicU64::new(get(&self.invalid)),
            limited: AtomicU64::new(get(&self.limited)),
            skipped: AtomicU64::new(get(&self.skipped)),
            log_dropped: AtomicU64::new(get(&self.log_dropped)),
        };
        for shard in shards {
            add(&result.sent, get(&shard.sent));
            add(&result.received, get(&shard.received));
            add(&result.tx_bytes, get(&shard.tx_bytes));
            add(&result.rx_bytes, get(&shard.rx_bytes));
            add(&result.pending, get(&shard.pending));
            add(&result.timeout, get(&shard.timeout));
            add(&result.canceled, get(&shard.canceled));
            add(&result.duplicate, get(&shard.duplicate));
            add(&result.late, get(&shard.late));
            add(&result.reordered, get(&shard.reordered));
            add(&result.invalid, get(&shard.invalid));
            add(&result.limited, get(&shard.limited));
            add(&result.skipped, get(&shard.skipped));
            add(&result.log_dropped, get(&shard.log_dropped));
        }
        result
    }
}

/// Counters use wrapping arithmetic, matching the existing atomic operations.
pub trait Counter {
    fn add(&self, n: u64);
    fn sub(&self, n: u64);
    fn get(&self) -> u64;
}

impl Counter for AtomicU64 {
    #[inline]
    fn add(&self, n: u64) {
        self.fetch_add(n, Relaxed);
    }

    #[inline]
    fn sub(&self, n: u64) {
        self.fetch_sub(n, Relaxed);
    }

    #[inline]
    fn get(&self) -> u64 {
        self.load(Relaxed)
    }
}

impl Counter for Cell<u64> {
    #[inline]
    fn add(&self, n: u64) {
        self.set(self.get().wrapping_add(n));
    }

    #[inline]
    fn sub(&self, n: u64) {
        self.set(self.get().wrapping_sub(n));
    }

    #[inline]
    fn get(&self) -> u64 {
        Cell::get(self)
    }
}

#[inline]
pub fn inc(value: &(impl Counter + ?Sized)) {
    value.add(1);
}

#[inline]
pub fn add(value: &(impl Counter + ?Sized), n: u64) {
    value.add(n);
}

#[inline]
pub fn dec(value: &(impl Counter + ?Sized)) {
    value.sub(1);
}

#[inline]
pub fn get(value: &(impl Counter + ?Sized)) -> u64 {
    value.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_share_wrapping_arithmetic() {
        let atomic = AtomicU64::new(0);
        let local = Cell::new(0_u64);
        for counter in [&atomic as &dyn Counter, &local as &dyn Counter] {
            inc(counter);
            add(counter, 7);
            dec(counter);
            assert_eq!(get(counter), 7);
            add(counter, u64::MAX);
            assert_eq!(get(counter), 6);
            counter.sub(6);
            dec(counter);
            assert_eq!(get(counter), u64::MAX);
            inc(counter);
            assert_eq!(get(counter), 0);
        }
    }

    #[test]
    fn publication_and_aggregation_cover_all_traffic_fields() {
        let shared = Stats::default();
        let shards = [
            Arc::new(TrafficSnapshot::default()),
            Arc::new(TrafficSnapshot::default()),
        ];
        let workers = shards
            .each_ref()
            .map(|shard| LocalTraffic::new(shard.clone()));
        macro_rules! check_traffic {
            ($($field:ident),+ $(,)?) => {$(
                add(&shared.$field, 3);
                add(&workers[0].$field, 5);
                add(&workers[1].$field, 7);
                assert_eq!(get(&shards[0].$field), 0);
                assert_eq!(get(&shared.snapshot(&shards).$field), 3);
                workers[0].publish();
                workers[1].publish();
                assert_eq!(get(&shared.snapshot(&shards).$field), 15);
                workers[0].publish();
                assert_eq!(get(&shared.snapshot(&shards).$field), 15);
                inc(&workers[0].$field);
                assert_eq!(get(&shared.snapshot(&shards).$field), 15);
                workers[0].publish();
                assert_eq!(get(&shared.snapshot(&shards).$field), 16);
                assert_eq!(get(&workers[0].$field), 6);
                assert_eq!(get(&shared.$field), 3);
            )+};
        }
        check_traffic!(
            sent,
            received,
            tx_bytes,
            rx_bytes,
            pending,
            timeout,
            canceled,
            duplicate,
            late,
            reordered,
            invalid,
            limited,
            skipped,
            log_dropped,
        );
    }

    #[test]
    fn shared_lifecycle_remains_authoritative() {
        let shared = Stats::default();
        let shards = [Arc::new(TrafficSnapshot::default())];
        macro_rules! check_shared {
            ($($field:ident),+ $(,)?) => {$(
                add(&shared.$field, 9);
                let snapshot = shared.snapshot(&shards);
                assert_eq!(get(&snapshot.$field), 9);
                assert_eq!(get(&shared.snapshot(&[]).$field), 9);
                inc(&shared.$field);
                assert_eq!(get(&snapshot.$field), 9);
                assert_eq!(get(&shared.snapshot(&shards).$field), 10);
            )+};
        }
        check_shared!(
            ready,
            connecting,
            draining,
            attempts,
            established,
            closed,
            rotations,
            repairs,
            failed,
            session_skipped,
        );
    }

    #[test]
    fn pending_decrements_replace_the_published_gauge() {
        let shared = Stats::default();
        let shards = [Arc::new(TrafficSnapshot::default())];
        let worker = LocalTraffic::new(shards[0].clone());
        add(&worker.pending, 3);
        worker.publish();
        assert_eq!(get(&shared.snapshot(&shards).pending), 3);
        dec(&worker.pending);
        worker.publish();
        assert_eq!(get(&shared.snapshot(&shards).pending), 2);
        dec(&worker.pending);
        dec(&worker.pending);
        drop(worker);
        assert_eq!(get(&shared.snapshot(&shards).pending), 0);
    }

    #[test]
    fn drop_publishes_on_error_return() {
        fn worker_run(snapshot: Arc<TrafficSnapshot>) -> Result<(), &'static str> {
            let worker = LocalTraffic::new(snapshot);
            inc(&worker.sent);
            worker.publish();
            add(&worker.sent, 4);
            inc(&worker.log_dropped);
            Err("worker error")?;
            Ok(())
        }
        let snapshot = Arc::new(TrafficSnapshot::default());
        assert!(worker_run(snapshot.clone()).is_err());
        assert_eq!(get(&snapshot.sent), 5);
        assert_eq!(get(&snapshot.log_dropped), 1);
    }

    #[test]
    fn drop_publishes_during_unwinding() {
        let snapshot = Arc::new(TrafficSnapshot::default());
        let published = snapshot.clone();
        let result = std::panic::catch_unwind(move || {
            let worker = LocalTraffic::new(published);
            inc(&worker.received);
            panic!("worker panic");
        });
        assert!(result.is_err());
        assert_eq!(get(&snapshot.received), 1);
    }

    #[test]
    fn snapshot_is_cache_line_aligned() {
        assert_eq!(std::mem::align_of::<TrafficSnapshot>(), 128);
        let snapshot = Arc::new(TrafficSnapshot::default());
        assert_eq!(Arc::as_ptr(&snapshot) as usize % 128, 0);
    }
}
