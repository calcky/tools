use crate::{
    model::{Entry, Key},
    netlink::{Message, Socket},
};
use std::{
    collections::HashMap,
    fs, io,
    time::{Duration, Instant},
};

pub(crate) const MAX_ENTRIES: usize = 2_000_000;
const MAX_EVENTS: usize = 100_000;
struct Dump {
    seq: u32,
    started: Instant,
    entries: HashMap<Key, Entry>,
    replay: Vec<(bool, bool, Entry)>,
}

#[derive(Default)]
pub struct Health {
    pub count: Option<u64>,
    pub max: Option<u64>,
    pub acct: Option<u64>,
    pub events: Option<u64>,
    pub errors: [Option<u64>; 3],
    pub delta: [Option<u64>; 3],
    pub namespace: String,
}
impl Health {
    pub fn sample(&mut self) {
        let read = |name: &str| {
            fs::read_to_string(format!("/proc/sys/net/netfilter/{name}"))
                .ok()
                .and_then(|s| s.trim().parse().ok())
        };
        self.count = read("nf_conntrack_count");
        self.max = read("nf_conntrack_max");
        self.acct = read("nf_conntrack_acct");
        self.events = read("nf_conntrack_events");
        self.namespace = fs::read_link("/proc/self/ns/net")
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".into());
        let next = fs::read_to_string("/proc/net/stat/nf_conntrack")
            .ok()
            .map(|text| parse_stats(&text))
            .unwrap_or([None; 3]);
        for (i, new) in next.iter().enumerate() {
            self.delta[i] = self.errors[i]
                .zip(*new)
                .and_then(|(old, new)| new.checked_sub(old));
        }
        self.errors = next;
    }
}
fn parse_stats(text: &str) -> [Option<u64>; 3] {
    let mut lines = text.lines();
    let headers: Vec<_> = lines.next().unwrap_or("").split_whitespace().collect();
    let indexes =
        ["insert_failed", "drop", "early_drop"].map(|key| headers.iter().position(|h| *h == key));
    let mut result = indexes.map(|i| i.map(|_| 0u64));
    for line in lines {
        let values: Vec<_> = line.split_whitespace().collect();
        for (i, index) in indexes.iter().enumerate() {
            result[i] = result[i]
                .zip(
                    index
                        .and_then(|j| values.get(j))
                        .and_then(|v| u64::from_str_radix(v, 16).ok()),
                )
                .and_then(|(a, b)| a.checked_add(b));
        }
    }
    result
}

pub struct Engine {
    socket: Option<Socket>,
    pub offline_at: Option<Instant>,
    pub entries: HashMap<Key, Entry>,
    dump: Option<Dump>,
    pub health: Health,
    pub ready: bool,
    pub stale: bool,
    pub message: String,
    pub resyncs: u64,
    pub lost: u64,
    pub events: Vec<(bool, Entry)>,
    pub interval_valid: bool,
    pub last_sync: Option<Instant>,
    next_dump: Instant,
    refresh: Duration,
}
impl Engine {
    pub fn open(refresh: Duration) -> io::Result<Self> {
        let now = Instant::now();
        let mut socket = Socket::open()?;
        let seq = socket.dump()?;
        let mut health = Health::default();
        health.sample();
        Ok(Self {
            socket: Some(socket),
            offline_at: None,
            entries: HashMap::new(),
            dump: Some(Dump {
                seq,
                started: now,
                entries: HashMap::new(),
                replay: Vec::new(),
            }),
            health,
            ready: false,
            stale: true,
            message: "Initial snapshot...".into(),
            resyncs: 0,
            lost: 0,
            events: Vec::new(),
            interval_valid: false,
            last_sync: None,
            next_dump: now + refresh,
            refresh,
        })
    }
    pub fn fd(&self) -> i32 {
        self.socket.as_ref().map_or(-1, Socket::fd)
    }
    pub fn offline(entries: HashMap<Key, Entry>, source: String, at: Instant) -> Self {
        Self {
            socket: None,
            offline_at: Some(at),
            health: Health {
                count: Some(entries.len() as u64),
                namespace: source,
                ..Health::default()
            },
            entries,
            dump: None,
            ready: true,
            stale: false,
            message: "Static snapshot; bandwidth, lifecycle rates and observed age unavailable"
                .into(),
            resyncs: 0,
            lost: 0,
            events: Vec::new(),
            interval_valid: false,
            last_sync: None,
            next_dump: at,
            refresh: Duration::ZERO,
        }
    }
    pub fn collecting(&self) -> bool {
        self.dump.is_some()
    }
    fn invalidate(&mut self, why: String, now: Instant) {
        self.lost += 1;
        self.interval_valid = false;
        self.stale = true;
        self.message = why;
        self.dump = None;
        self.next_dump = now + Duration::from_secs(1);
        self.events.clear();
    }
    fn remember(&mut self, new: bool, e: Entry) {
        if self.events.len() < MAX_EVENTS {
            self.events.push((new, e));
        } else {
            self.interval_valid = false;
            self.message = "Lifecycle window overflow; rates N/A".into();
        }
    }
    fn event(&mut self, new: bool, delete: bool, e: Entry, now: Instant) {
        let key = e.key.clone();
        if delete {
            if self
                .entries
                .get(&key)
                .is_some_and(|old| !old.same_generation(&e))
            {
                return;
            }
            let mut removed = self.entries.remove(&key).unwrap_or_else(|| e.clone());
            removed.merge(e, now);
            if self.ready {
                self.remember(false, removed);
            }
        } else {
            let exists = self
                .entries
                .get(&key)
                .is_some_and(|old| old.same_generation(&e));
            if new && !exists && self.ready {
                self.remember(true, e.clone());
            }
            if exists {
                self.entries.get_mut(&key).unwrap().merge(e, now);
            } else {
                self.entries.insert(key, e);
            }
        }
    }
    fn handle(&mut self, message: Message, now: Instant) -> io::Result<()> {
        match message {
            Message::Entry {
                seq,
                new,
                delete,
                entry,
            } => {
                let e = *entry;
                if seq != 0 && self.dump.as_ref().is_none_or(|dump| dump.seq != seq) {
                    return Ok(());
                }
                if let Some(dump) = &mut self.dump {
                    if seq == dump.seq {
                        if dump.entries.len() >= MAX_ENTRIES {
                            return Err(io::Error::other("snapshot exceeds two million entries; narrow the network namespace"));
                        }
                        dump.entries.insert(e.key.clone(), e);
                        return Ok(());
                    }
                    if dump.replay.len() >= MAX_EVENTS {
                        self.invalidate(
                            "Event buffer overflow during snapshot; resync pending".into(),
                            now,
                        );
                        return Ok(());
                    }
                    dump.replay.push((new, delete, e.clone()));
                }
                // Delayed replies from an abandoned dump are not lifecycle events.
                if seq == 0 {
                    self.event(new, delete, e, now);
                }
                if self.entries.len() > MAX_ENTRIES {
                    return Err(io::Error::other("cache exceeds two million entries"));
                }
            }
            Message::Done { seq, interrupted } => {
                if self.dump.as_ref().is_none_or(|d| d.seq != seq) {
                    return Ok(());
                }
                if interrupted {
                    self.invalidate("Interrupted snapshot; resync pending".into(), now);
                    return Ok(());
                }
                let dump = self.dump.take().unwrap();
                let mut next = dump.entries;
                for (key, e) in &mut next {
                    // Events may contain counters, but only complete dumps advance the baseline.
                    e.sample_traffic(self.entries.get(key).filter(|_| !self.stale), dump.started);
                    if let Some(old) = self.entries.get(key).filter(|old| old.same_generation(e)) {
                        e.seen = old.seen;
                        if e.state == old.state {
                            e.state_since = old.state_since;
                        }
                    }
                }
                self.entries = next;
                let ready = self.ready;
                self.ready = false;
                for (new, delete, e) in dump.replay {
                    self.event(new, delete, e, now);
                }
                self.ready = true;
                self.stale = false;
                self.message = if self.health.events == Some(0) {
                    "Events disabled; lifecycle rates N/A".into()
                } else {
                    "Snapshot + events; existing event coverage may be partial".into()
                };
                self.last_sync = Some(now);
                self.next_dump = now + self.refresh;
                if ready {
                    self.resyncs += 1;
                }
            }
            Message::Error { seq, errno } => {
                if matches!(errno, libc::EPERM | libc::EACCES) {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                if self.dump.as_ref().is_some_and(|d| d.seq == seq) {
                    self.invalidate(
                        format!("Snapshot error: {}", io::Error::from_raw_os_error(errno)),
                        now,
                    );
                }
            }
            Message::Lost => {
                self.invalidate("Netlink overrun; rates N/A, resync pending".into(), now)
            }
        }
        Ok(())
    }
    pub fn pump(&mut self) -> io::Result<()> {
        if self.offline_at.is_some() {
            return Ok(());
        }
        let start = Instant::now();
        // A bounded receive quantum keeps keyboard handling responsive under churn.
        while start.elapsed() < Duration::from_millis(20) {
            match self.socket.as_mut().unwrap().receive() {
                Ok(Some(messages)) => {
                    for m in messages {
                        self.handle(m, Instant::now())?;
                    }
                }
                Ok(None) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.raw_os_error() == Some(libc::ENOBUFS)
                        || e.kind() == io::ErrorKind::InvalidData =>
                {
                    self.invalidate(format!("Capture gap: {e}; resync pending"), Instant::now());
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        let now = Instant::now();
        if self
            .dump
            .as_ref()
            .is_some_and(|d| now.duration_since(d.started) > Duration::from_secs(30))
        {
            self.invalidate("Snapshot timed out; resync pending".into(), now);
        }
        if self.dump.is_none() && now >= self.next_dump {
            let seq = self.socket.as_mut().unwrap().dump()?;
            self.dump = Some(Dump {
                seq,
                started: now,
                entries: HashMap::new(),
                replay: Vec::new(),
            });
        }
        Ok(())
    }
    pub fn take_window(&mut self) -> (Vec<(bool, Entry)>, bool) {
        if self.offline_at.is_some() {
            return (Vec::new(), false);
        }
        self.health.sample();
        let valid = self.interval_valid && !self.stale && self.health.events != Some(0);
        self.interval_valid = self.ready && !self.stale;
        (std::mem::take(&mut self.events), valid)
    }
}

#[cfg(test)]
pub fn fixture() -> Engine {
    let now = Instant::now();
    Engine {
        socket: Some(Socket::stub()),
        offline_at: None,
        entries: HashMap::new(),
        dump: None,
        health: Health {
            events: Some(1),
            ..Health::default()
        },
        ready: true,
        stale: false,
        message: "LIVE".into(),
        resyncs: 0,
        lost: 0,
        events: Vec::new(),
        interval_valid: true,
        last_sync: Some(now),
        next_dump: now + Duration::from_secs(5),
        refresh: Duration::from_secs(5),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bandwidth_uses_snapshot_baseline_despite_events_and_resets_after_gaps() {
        let mut engine = fixture();
        let at = Instant::now();
        let mut a = crate::model::fixture();
        a.sample_traffic(None, at);
        engine.entries.insert(a.key.clone(), a.clone());
        let mut patch = a.clone();
        patch.bytes = [Some(900); 2];
        engine.handle(update(patch, 0, false, false), at).unwrap();
        let mut next = a.clone();
        next.bytes = [Some(1100); 2];
        dump(&mut engine, 1);
        engine.dump.as_mut().unwrap().started = at + Duration::from_secs(2);
        engine
            .handle(update(next.clone(), 1, false, false), at)
            .unwrap();
        engine
            .handle(
                Message::Done {
                    seq: 1,
                    interrupted: false,
                },
                at,
            )
            .unwrap();
        assert_eq!(
            engine.entries[&a.key]
                .traffic
                .as_ref()
                .unwrap()
                .bytes_per_second,
            [Some(500.0); 2]
        );
        engine.handle(Message::Lost, at).unwrap();
        dump(&mut engine, 2);
        engine.handle(update(next, 2, false, false), at).unwrap();
        engine
            .handle(
                Message::Done {
                    seq: 2,
                    interrupted: false,
                },
                at,
            )
            .unwrap();
        assert_eq!(
            engine.entries[&a.key]
                .traffic
                .as_ref()
                .unwrap()
                .bytes_per_second,
            [None; 2]
        );
    }
    fn update(e: Entry, seq: u32, new: bool, delete: bool) -> Message {
        Message::Entry {
            seq,
            new,
            delete,
            entry: Box::new(e),
        }
    }
    fn dump(e: &mut Engine, seq: u32) {
        e.dump = Some(Dump {
            seq,
            started: Instant::now(),
            entries: HashMap::new(),
            replay: Vec::new(),
        });
    }
    #[test]
    fn events_reconcile_with_snapshot_without_double_counting() {
        let mut e = fixture();
        let a = crate::model::fixture();
        let now = Instant::now();
        e.entries.insert(a.key.clone(), a.clone());
        dump(&mut e, 5);
        e.handle(update(a.clone(), 5, false, false), now).unwrap();
        e.handle(update(a.clone(), 0, false, true), now).unwrap();
        let mut b = a.clone();
        b.id = Some(2);
        e.handle(update(b.clone(), 0, true, false), now).unwrap();
        e.handle(
            Message::Done {
                seq: 5,
                interrupted: false,
            },
            now,
        )
        .unwrap();
        assert_eq!(e.entries.len(), 1);
        assert_eq!(e.entries[&b.key].id, Some(2));
        assert_eq!(e.events.len(), 2);
        assert!(!e.events[0].0);
        assert!(e.events[1].0);
        e.handle(update(a, 0, false, true), now).unwrap();
        assert_eq!(e.entries.len(), 1);
        assert_eq!(e.events.len(), 2);
    }
    #[test]
    fn interrupted_or_lost_snapshot_never_replaces_cache() {
        let mut e = fixture();
        let a = crate::model::fixture();
        let now = Instant::now();
        e.entries.insert(a.key.clone(), a.clone());
        dump(&mut e, 5);
        e.handle(
            Message::Done {
                seq: 5,
                interrupted: true,
            },
            now,
        )
        .unwrap();
        assert!(e.stale);
        assert!(!e.interval_valid);
        assert_eq!(e.entries.len(), 1);
        let mut b = a;
        b.id = Some(2);
        e.handle(update(b, 5, false, false), now).unwrap();
        assert_eq!(e.entries.values().next().unwrap().id, Some(1));
        e.handle(Message::Lost, now).unwrap();
        assert_eq!(e.lost, 2);
        dump(&mut e, 6);
        e.handle(
            Message::Done {
                seq: 6,
                interrupted: false,
            },
            now,
        )
        .unwrap();
        assert!(!e.stale);
        assert!(e.entries.is_empty());
        assert!(!e.interval_valid);
    }
    #[test]
    fn initial_snapshot_does_not_count_existing_sessions_as_new() {
        let mut e = fixture();
        e.ready = false;
        let a = crate::model::fixture();
        let now = Instant::now();
        dump(&mut e, 1);
        e.handle(update(a, 1, true, false), now).unwrap();
        e.handle(
            Message::Done {
                seq: 1,
                interrupted: false,
            },
            now,
        )
        .unwrap();
        assert_eq!(e.entries.len(), 1);
        assert!(e.events.is_empty());
        assert!(e.ready);
    }
    #[test]
    fn unchanged_snapshot_preserves_observation_age() {
        let mut e = fixture();
        let a = crate::model::fixture();
        let original = a.seen;
        e.entries.insert(a.key.clone(), a.clone());
        dump(&mut e, 2);
        let mut b = a;
        b.seen += Duration::from_secs(20);
        b.state_since = b.seen;
        e.handle(update(b, 2, false, false), Instant::now())
            .unwrap();
        e.handle(
            Message::Done {
                seq: 2,
                interrupted: false,
            },
            Instant::now(),
        )
        .unwrap();
        let result = e.entries.values().next().unwrap();
        assert_eq!(result.seen, original);
        assert_eq!(result.state_since, original);
    }
    #[test]
    fn kernel_stats_sum_cpu_rows_and_unknown_is_not_zero() {
        let text = "entries drop early_drop insert_failed\n01 02 03 04\n01 05 06 07\n";
        assert_eq!(parse_stats(text), [Some(11), Some(7), Some(9)]);
        assert_eq!(parse_stats("entries drop\n1 2\n"), [None, Some(2), None]);
        assert_eq!(parse_stats("entries drop\n1 x\n"), [None, None, None]);
    }
}
