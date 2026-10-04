use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Key {
    pub ifindex: u32,
    pub netns: u32,
    pub napi_id: u32,
    pub cpu: u32,
}

impl Key {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        (raw.len() == 16).then(|| Self {
            ifindex: u32::from_ne_bytes(raw[0..4].try_into().unwrap()),
            netns: u32::from_ne_bytes(raw[4..8].try_into().unwrap()),
            napi_id: u32::from_ne_bytes(raw[8..12].try_into().unwrap()),
            cpu: u32::from_ne_bytes(raw[12..16].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub polls: u64,
    pub work: u64,
    pub budget_hits: u64,
    pub duration_ns: u64,
    pub timed_polls: u64,
    pub latency_us: [u64; 16],
}

impl Counters {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() != 168 {
            return None;
        }
        let read = |index: usize| u64::from_ne_bytes(raw[index..index + 8].try_into().unwrap());
        let mut result = Self {
            polls: read(0),
            work: read(8),
            budget_hits: read(16),
            duration_ns: read(24),
            timed_polls: read(32),
            ..Self::default()
        };
        for (i, value) in result.latency_us.iter_mut().enumerate() {
            *value = read(40 + i * 8);
        }
        Some(result)
    }

    pub fn delta(&self, old: &Self) -> Self {
        let mut result = Self {
            polls: self.polls.saturating_sub(old.polls),
            work: self.work.saturating_sub(old.work),
            budget_hits: self.budget_hits.saturating_sub(old.budget_hits),
            duration_ns: self.duration_ns.saturating_sub(old.duration_ns),
            timed_polls: self.timed_polls.saturating_sub(old.timed_polls),
            ..Self::default()
        };
        for (i, value) in result.latency_us.iter_mut().enumerate() {
            *value = self.latency_us[i].saturating_sub(old.latency_us[i]);
        }
        result
    }

    pub fn add(&mut self, other: &Self) {
        self.polls = self.polls.saturating_add(other.polls);
        self.work = self.work.saturating_add(other.work);
        self.budget_hits = self.budget_hits.saturating_add(other.budget_hits);
        self.duration_ns = self.duration_ns.saturating_add(other.duration_ns);
        self.timed_polls = self.timed_polls.saturating_add(other.timed_polls);
        for (left, right) in self.latency_us.iter_mut().zip(other.latency_us) {
            *left = left.saturating_add(right);
        }
    }

    pub fn hit_percent(&self) -> f64 {
        percent(self.budget_hits, self.polls)
    }

    pub fn work_per_poll(&self) -> f64 {
        ratio(self.work, self.polls)
    }

    pub fn avg_us(&self) -> Option<f64> {
        (self.timed_polls > 0).then(|| ratio(self.duration_ns, self.timed_polls) / 1000.0)
    }

    pub fn percentile_us(&self, percentile: u64) -> Option<(u64, bool)> {
        let count: u64 = self.latency_us.iter().sum();
        if count == 0 || !(1..=100).contains(&percentile) {
            return None;
        }
        let target = ((count as u128 * percentile as u128).div_ceil(100)) as u64;
        let mut seen = 0;
        for (i, value) in self.latency_us.iter().enumerate() {
            seen += value;
            if seen >= target {
                return Some((1_u64 << i.min(14), i == 15));
            }
        }
        None
    }
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn percent(numerator: u64, denominator: u64) -> f64 {
    ratio(numerator, denominator) * 100.0
}

#[derive(Clone, Debug)]
pub struct CpuRow {
    pub cpu: u32,
    pub stats: Counters,
}

#[derive(Clone, Debug)]
pub struct NapiRow {
    pub ifindex: u32,
    pub napi_id: u32,
    pub stats: Counters,
    pub cpus: Vec<CpuRow>,
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub rows: Vec<NapiRow>,
    pub total: Counters,
    pub errors: [u64; 2],
    pub elapsed: f64,
}

pub fn sample(
    old: &HashMap<Key, Counters>,
    now: &HashMap<Key, Counters>,
    old_errors: [u64; 2],
    now_errors: [u64; 2],
    elapsed: f64,
) -> Sample {
    let mut grouped: HashMap<(u32, u32), NapiRow> = HashMap::new();
    let mut total = Counters::default();
    for (key, value) in now {
        let delta = value.delta(old.get(key).unwrap_or(&Counters::default()));
        if delta.polls == 0 {
            continue;
        }
        total.add(&delta);
        let row = grouped
            .entry((key.ifindex, key.napi_id))
            .or_insert_with(|| NapiRow {
                ifindex: key.ifindex,
                napi_id: key.napi_id,
                stats: Counters::default(),
                cpus: Vec::new(),
            });
        row.stats.add(&delta);
        row.cpus.push(CpuRow {
            cpu: key.cpu,
            stats: delta,
        });
    }
    let mut rows: Vec<_> = grouped.into_values().collect();
    rows.sort_by(|a, b| {
        b.stats
            .work
            .cmp(&a.stats.work)
            .then_with(|| a.ifindex.cmp(&b.ifindex))
            .then_with(|| a.napi_id.cmp(&b.napi_id))
    });
    for row in &mut rows {
        row.cpus
            .sort_by_key(|cpu| std::cmp::Reverse(cpu.stats.work));
    }
    Sample {
        rows,
        total,
        errors: [
            now_errors[0].saturating_sub(old_errors[0]),
            now_errors[1].saturating_sub(old_errors[1]),
        ],
        elapsed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_and_counters() {
        let key = [1_u32, 2, 3, 4].map(u32::to_ne_bytes).concat();
        assert_eq!(Key::parse(&key).unwrap().cpu, 4);
        assert!(Key::parse(&key[..15]).is_none());
        let mut raw = [0_u8; 168];
        raw[..8].copy_from_slice(&7_u64.to_ne_bytes());
        raw[40..48].copy_from_slice(&3_u64.to_ne_bytes());
        let parsed = Counters::parse(&raw).unwrap();
        assert_eq!(parsed.polls, 7);
        assert_eq!(parsed.latency_us[0], 3);
        assert!(Counters::parse(&raw[..167]).is_none());
    }

    #[test]
    fn aggregates_cpus_and_interval_histogram() {
        let first = Key {
            ifindex: 2,
            netns: 1,
            napi_id: 9,
            cpu: 0,
        };
        let second = Key { cpu: 1, ..first };
        let old = HashMap::from([(
            first,
            Counters {
                polls: 10,
                work: 100,
                ..Default::default()
            },
        )]);
        let now = HashMap::from([
            (
                first,
                Counters {
                    polls: 12,
                    work: 120,
                    budget_hits: 1,
                    timed_polls: 2,
                    duration_ns: 4000,
                    latency_us: [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                },
            ),
            (
                second,
                Counters {
                    polls: 1,
                    work: 5,
                    ..Default::default()
                },
            ),
        ]);
        let sample = sample(&old, &now, [0; 2], [1, 2], 1.0);
        assert_eq!(sample.rows.len(), 1);
        assert_eq!(sample.total.work, 25);
        assert_eq!(sample.rows[0].cpus.len(), 2);
        assert_eq!(sample.rows[0].stats.percentile_us(99), Some((1, false)));
        assert_eq!(sample.errors, [1, 2]);
    }

    #[test]
    fn no_timed_polls_is_unavailable() {
        let stats = Counters {
            polls: 2,
            work: 10,
            ..Default::default()
        };
        assert_eq!(stats.avg_us(), None);
        assert_eq!(stats.percentile_us(99), None);
    }

    #[test]
    fn percentile_uses_bucket_boundaries() {
        let mut stats = Counters::default();
        stats.latency_us[0] = 50;
        stats.latency_us[4] = 49;
        stats.latency_us[15] = 1;
        assert_eq!(stats.percentile_us(50), Some((1, false)));
        assert_eq!(stats.percentile_us(99), Some((16, false)));
        assert_eq!(stats.percentile_us(100), Some((16384, true)));
        assert_eq!(stats.hit_percent(), 0.0);
    }
}
