use crate::collect::{Identity, Key, Metrics, Record, Snapshot};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub fn clean(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes.split(|v| *v == 0).next().unwrap_or_default())
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

impl Metrics {
    pub fn delta(&self, prev: &Self) -> Self {
        Self {
            bytes: self.bytes.saturating_sub(prev.bytes),
            ops: self.ops.saturating_sub(prev.ops),
            errors: self.errors.saturating_sub(prev.errors),
            again: self.again.saturating_sub(prev.again),
            restarts: self.restarts.saturating_sub(prev.restarts),
            ns: self.ns.saturating_sub(prev.ns),
            max_ns: self.max_ns,
            hist: std::array::from_fn(|i| self.hist[i].saturating_sub(prev.hist[i])),
        }
    }
    pub fn add(&mut self, other: &Self) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.ops = self.ops.saturating_add(other.ops);
        self.errors = self.errors.saturating_add(other.errors);
        self.again = self.again.saturating_add(other.again);
        self.restarts = self.restarts.saturating_add(other.restarts);
        self.ns = self.ns.saturating_add(other.ns);
        self.max_ns = self.max_ns.max(other.max_ns);
        for (a, b) in self.hist.iter_mut().zip(other.hist) {
            *a = a.saturating_add(b);
        }
    }
    pub fn avg_ms(&self) -> Option<f64> {
        (self.ops > 0).then(|| self.ns as f64 / self.ops as f64 / 1e6)
    }
    // Log2 microsecond buckets; percentile is the bucket's upper bound.
    pub fn percentile_ms(&self, percentile: u64) -> Option<f64> {
        let count: u64 = self.hist.iter().sum();
        if count == 0 {
            return None;
        }
        let rank = (count * percentile).div_ceil(100).max(1);
        let mut total = 0;
        for (i, n) in self.hist.iter().enumerate() {
            total += n;
            if total >= rank {
                return Some((1_u64 << (i + 1)) as f64 / 1000.0);
            }
        }
        None
    }
}

impl Identity {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            1 => "FILE",
            2 => match (self.family, self.protocol) {
                (1, _) => "UNIX",
                (2 | 10, 6) => "TCP",
                (2 | 10, 17) => "UDP",
                (44, _) => "XSK",
                (16, _) => "NETLINK",
                _ => "SOCKET",
            },
            3 => "PIPE",
            4 => "CHAR",
            5 => "BLOCK",
            6 => "MQ",
            7 => match self.name.split(|b| *b == 0).next().unwrap_or_default() {
                b"[eventfd]" => "EVENTFD",
                b"[timerfd]" => "TIMERFD",
                b"[signalfd]" => "SIGNALFD",
                b"[eventpoll]" => "EPOLL",
                b"bpf-map" => "BPFMAP",
                b"bpf-prog" => "BPFPROG",
                b"btf" => "BTF",
                _ => "OTHER",
            },
            _ => "OTHER",
        }
    }
    pub fn object_name(&self) -> String {
        if self.kind == 7 {
            return format!("anon_inode:{}", clean(&self.name));
        }
        if self.kind == 2 && matches!(self.family, 2 | 10) {
            let addr = |b: [u8; 16]| {
                if self.family == 2 {
                    IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
                } else {
                    IpAddr::V6(Ipv6Addr::from(b))
                }
            };
            return format!(
                "{} -> {}",
                std::net::SocketAddr::new(addr(self.src), self.sport),
                std::net::SocketAddr::new(addr(self.dst), u16::from_be(self.dport))
            );
        }
        if self.kind == 3 {
            return format!("pipe:[{}]", self.ino);
        }
        if self.kind == 2 {
            let family = match self.family {
                1 => "UNIX",
                16 => "NETLINK",
                44 => "XSK",
                _ => "socket",
            };
            return format!("{family}:[{}]", self.ino);
        }
        if self.key.object == 0 {
            return "unresolved/invalid FD".into();
        }
        format!("{} [ino:{}]", clean(&self.name), self.ino)
    }
}

#[derive(Clone)]
pub struct Row {
    pub access: &'static str,
    pub state: &'static str,
    pub total: Record,
    pub rd: Metrics,
    pub wr: Metrics,
    pub calls: u64,
    pub pending: u64,
    pub wait_ms: f64,
    pub object: String,
    pub metadata_source: &'static str,
    pub metadata_age_ms: Option<u64>,
    pub metadata_error: Option<String>,
}
impl Row {
    pub fn ops(&self) -> u64 {
        self.rd.ops + self.wr.ops
    }
}

#[derive(Default, Clone)]
pub struct Process {
    pub pid: u32,
    pub start: u64,
    pub comm: String,
    pub rd: Metrics,
    pub wr: Metrics,
    pub calls: u64,
    pub pending: u64,
    pub wait_ms: f64,
    pub fds: usize,
}

pub struct Frame {
    pub inventory_error: Option<String>,
    pub latency: bool,
    pub seconds: f64,
    pub rows: Vec<Row>,
    pub processes: Vec<Process>,
    pub gaps: [u64; 5],
    pub tracked: usize,
}

#[derive(Default, Clone)]
pub struct Filter {
    pub name: Option<String>,
    pub kind: Option<String>,
    pub fd: Option<i32>,
}

pub fn frame(previous: &Snapshot, current: &Snapshot, filter: &Filter) -> Frame {
    let seconds = (current.at.saturating_sub(previous.at) as f64 / 1e9).max(1e-9);
    let mut pending: HashMap<Key, (u64, f64)> = HashMap::new();
    for p in &current.pending {
        for key in [Some(p.first), (p.two != 0).then_some(p.second)]
            .into_iter()
            .flatten()
        {
            let e = pending.entry(key).or_default();
            e.0 += 1;
            if current.latency {
                e.1 = e.1.max(current.at.saturating_sub(p.since) as f64 / 1e6);
            }
        }
    }
    let mut rows = Vec::new();
    let mut processes: BTreeMap<(u32, u64), Process> = BTreeMap::new();
    for (key, total) in &current.records {
        let comm = clean(&total.id.comm);
        if filter.fd.is_some_and(|fd| fd != key.fd)
            || filter
                .name
                .as_ref()
                .is_some_and(|name| !comm.contains(name))
            || filter.kind.as_ref().is_some_and(|kind| {
                kind != total.id.kind_name() && !(kind == "SOCKET" && total.id.kind == 2)
            })
        {
            continue;
        }
        let old = previous.records.get(key).copied().unwrap_or_default();
        let rd = total.rd.delta(&old.rd);
        let wr = total.wr.delta(&old.wr);
        let calls = total.calls.saturating_sub(old.calls);
        let (waiting, wait_ms) = pending.get(key).copied().unwrap_or_default();
        if rd.ops + wr.ops == 0 && waiting == 0 {
            continue;
        }
        let process = processes
            .entry((key.pid, key.start))
            .or_insert_with(|| Process {
                pid: key.pid,
                start: key.start,
                comm,
                ..Default::default()
            });
        process.rd.add(&rd);
        process.wr.add(&wr);
        process.calls += calls;
        process.pending += waiting;
        process.wait_ms = process.wait_ms.max(wait_ms);
        process.fds += 1;
        rows.push(Row {
            access: "-",
            state: if key.object == 0 {
                "invalid"
            } else if current.retired.contains(&key.object) {
                "closed"
            } else {
                "observed"
            },
            total: *total,
            rd,
            wr,
            calls,
            pending: waiting,
            wait_ms,
            object: total.id.object_name(),
            metadata_source: "observed",
            metadata_age_ms: None,
            metadata_error: None,
        });
    }
    rows.sort_by_key(|r| r.total.id.key);
    Frame {
        inventory_error: None,
        latency: current.latency,
        seconds,
        rows,
        processes: processes.into_values().collect(),
        gaps: current.gaps,
        tracked: current.records.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::Pending;
    fn record(object: u64, bytes: u64) -> Record {
        Record {
            id: Identity {
                key: Key {
                    pid: 42,
                    fd: 3,
                    start: 10,
                    object,
                },
                ..Default::default()
            },
            rd: Metrics {
                bytes,
                ops: 1,
                ..Default::default()
            },
            calls: 1,
            ..Default::default()
        }
    }
    #[test]
    fn fd_reuse_never_subtracts_old_object_counters() {
        let a = record(1, 1000);
        let b = record(2, 7);
        let prev = Snapshot {
            at: 1_000_000_000,
            records: HashMap::from([(a.id.key, a)]),
            ..Default::default()
        };
        let cur = Snapshot {
            at: 2_000_000_000,
            records: HashMap::from([(a.id.key, a), (b.id.key, b)]),
            ..Default::default()
        };
        let result = frame(&prev, &cur, &Filter::default());
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].rd.bytes, 7);
    }
    #[test]
    fn outstanding_call_is_visible_without_completed_samples() {
        let mut r = record(1, 0);
        r.rd = Metrics::default();
        r.calls = 0;
        let cur = Snapshot {
            at: 3_000_000_000,
            latency: true,
            records: HashMap::from([(r.id.key, r)]),
            pending: vec![Pending {
                first: r.id.key,
                since: 1_000_000_000,
                ..Default::default()
            }],
            ..Default::default()
        };
        let result = frame(&Snapshot::default(), &cur, &Filter::default());
        assert_eq!(result.rows[0].pending, 1);
        assert_eq!(result.rows[0].wait_ms, 2000.0);
        assert_eq!(result.rows[0].rd.avg_ms(), None);
        let light = Snapshot {
            latency: false,
            ..cur
        };
        let result = frame(&Snapshot::default(), &light, &Filter::default());
        assert_eq!(result.rows[0].pending, 1);
        assert_eq!(result.rows[0].wait_ms, 0.0);
    }
    #[test]
    fn pid_reuse_creates_separate_process_and_shared_object_keeps_fd_rows() {
        let a = record(1, 5);
        let mut b = a;
        b.id.key.fd = 4;
        let mut c = a;
        c.id.key.start = 20;
        let cur = Snapshot {
            at: 1_000_000_000,
            records: HashMap::from([(a.id.key, a), (b.id.key, b), (c.id.key, c)]),
            ..Default::default()
        };
        let result = frame(&Snapshot::default(), &cur, &Filter::default());
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.processes.len(), 2);
        assert_eq!(result.processes[0].fds, 2);
    }
    #[test]
    fn percentiles_ignore_unfinished_calls_and_use_interval_histogram() {
        let mut a = Metrics::default();
        a.hist[3] = 100;
        a.ops = 100;
        let mut b = a;
        b.hist[10] = 1;
        b.ops += 1;
        let d = b.delta(&a);
        assert_eq!(d.percentile_ms(99), Some(2.048));
        assert_eq!(Metrics::default().percentile_ms(95), None);
    }
    #[test]
    fn anonymous_fd_types_are_distinct_and_filterable() {
        for (name, kind) in [
            ("[eventfd]", "EVENTFD"),
            ("[timerfd]", "TIMERFD"),
            ("[signalfd]", "SIGNALFD"),
            ("[eventpoll]", "EPOLL"),
            ("bpf-map", "BPFMAP"),
            ("bpf-prog", "BPFPROG"),
            ("btf", "BTF"),
        ] {
            let mut r = record(1, 8);
            r.id.kind = 7;
            r.id.name[..name.len()].copy_from_slice(name.as_bytes());
            assert_eq!(r.id.kind_name(), kind);
            assert_eq!(r.id.object_name(), format!("anon_inode:{name}"));
            let cur = Snapshot {
                at: 1,
                records: HashMap::from([(r.id.key, r)]),
                ..Default::default()
            };
            for filter in ["EVENTFD", "TIMERFD", "SIGNALFD", "OTHER", "FILE", "SOCKET"] {
                let data = frame(
                    &Snapshot::default(),
                    &cur,
                    &Filter {
                        kind: Some(filter.into()),
                        ..Default::default()
                    },
                );
                assert_eq!(data.rows.len(), usize::from(filter == kind));
            }
            r.id.kind = 1;
            assert_eq!(r.id.kind_name(), "FILE");
        }
    }
    #[test]
    fn socket_filter_includes_unix_and_control_text_is_safe() {
        let mut r = record(1, 1);
        r.id.kind = 2;
        r.id.family = 1;
        let cur = Snapshot {
            at: 1,
            records: HashMap::from([(r.id.key, r)]),
            ..Default::default()
        };
        assert_eq!(
            frame(
                &Snapshot::default(),
                &cur,
                &Filter {
                    kind: Some("SOCKET".into()),
                    ..Default::default()
                }
            )
            .rows
            .len(),
            1
        );
        assert_eq!(clean(b"abc\x1b\n\0"), "abc??");
    }
}
