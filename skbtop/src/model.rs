use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const BUCKETS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(u32)]
pub enum Kind {
    Input = 1,
    Output = 2,
    Forward = 3,
}

impl Kind {
    pub fn latency_stages(self) -> &'static [usize] {
        match self {
            Self::Input => &[0],
            Self::Output | Self::Forward => &[0, 1, 2],
        }
    }

    pub fn primary_stage(self) -> usize {
        match self {
            Self::Input => 0,
            Self::Output | Self::Forward => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Input => "INPUT",
            Self::Output => "OUTPUT",
            Self::Forward => "FORWARD",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PathKey {
    pub kind: Kind,
    pub ingress: u32,
    pub egress: u32,
    pub netns: u32,
    pub ingress_generation: u64,
    pub egress_generation: u64,
}

impl PathKey {
    pub fn group(self) -> Self {
        let mut key = self;
        if key.kind == Kind::Forward
            && (key.ingress, key.ingress_generation) > (key.egress, key.egress_generation)
        {
            std::mem::swap(&mut key.ingress, &mut key.egress);
            std::mem::swap(&mut key.ingress_generation, &mut key.egress_generation);
        }
        key
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Interface {
    pub ifindex: u32,
    pub generation: u64,
    pub name: String,
    pub alive: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub in_packets: u64,
    pub in_bytes: u64,
    pub out_packets: u64,
    pub out_bytes: u64,
    pub route: u64,
    pub bridge: u64,
    pub combo: u64,
    pub freed: u64,
}

impl Counters {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn delta(&self, previous: &Self) -> Self {
        Self {
            in_packets: self.in_packets.saturating_sub(previous.in_packets),
            in_bytes: self.in_bytes.saturating_sub(previous.in_bytes),
            out_packets: self.out_packets.saturating_sub(previous.out_packets),
            out_bytes: self.out_bytes.saturating_sub(previous.out_bytes),
            route: self.route.saturating_sub(previous.route),
            bridge: self.bridge.saturating_sub(previous.bridge),
            combo: self.combo.saturating_sub(previous.combo),
            freed: self.freed.saturating_sub(previous.freed),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn bucket_index(ns: u64) -> usize {
    if ns < 4 {
        return ns as usize;
    }
    let exponent = 63 - ns.leading_zeros() as usize;
    (exponent * 4 + ((ns >> (exponent - 2)) & 3) as usize).min(BUCKETS - 1)
}

/// Inclusive bounds; buckets 4..7 are unused by the collector's mapping.
pub fn bucket_upper_ns(index: usize) -> u64 {
    match index {
        0..=3 => index as u64,
        4..=7 => 3,
        255.. => u64::MAX,
        _ => {
            let exponent = index / 4;
            ((((5 + index % 4) as u128) << (exponent - 2)) - 1) as u64
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Latency {
    pub samples: u64,
    pub min_us: Option<f64>,
    pub avg_us: Option<f64>,
    pub p50_us: Option<f64>,
    pub p90_us: Option<f64>,
    pub p95_us: Option<f64>,
    pub p99_us: Option<f64>,
    pub max_us: Option<f64>,
    #[serde(default)]
    pub newest_us: Option<f64>,
    #[serde(default)]
    pub newest_at_ns: Option<u64>,
    pub histogram: Vec<u64>,
    pub sum_ns: u64,
}

impl Latency {
    pub fn from_raw(
        samples: u64,
        sum_ns: u64,
        min_ns: u64,
        max_ns: u64,
        mut histogram: Vec<u64>,
    ) -> Self {
        histogram.resize(BUCKETS, 0);
        let percentile = |percent: u128| {
            if samples == 0 {
                return None;
            }
            let rank = (u128::from(samples) * percent).div_ceil(100);
            let mut count = 0u128;
            for (index, bucket) in histogram.iter().enumerate() {
                count += u128::from(*bucket);
                if count >= rank {
                    return Some(bucket_upper_ns(index).max(min_ns).min(max_ns) as f64 / 1_000.0);
                }
            }
            None
        };
        Self {
            samples,
            min_us: (samples > 0).then_some(min_ns as f64 / 1_000.0),
            avg_us: (samples > 0).then(|| sum_ns as f64 / samples as f64 / 1_000.0),
            p50_us: percentile(50),
            p90_us: percentile(90),
            p95_us: percentile(95),
            p99_us: percentile(99),
            max_us: (samples > 0).then_some(max_ns as f64 / 1_000.0),
            newest_us: None,
            newest_at_ns: None,
            histogram,
            sum_ns,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Row {
    pub key: PathKey,
    pub ingress_name: String,
    pub egress_name: String,
    pub interval: Counters,
    pub total: Counters,
    pub latency: [Latency; 3],
    pub total_latency: [Latency; 3],
    pub pending: u64,
    pub pps: f64,
    pub bps: f64,
    pub in_pps: f64,
    pub in_bps: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Health {
    pub inflight: u64,
    pub inflight_capacity: u64,
    pub path_capacity: u64,
    pub global: Counters,
    pub errors: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub sequence: u64,
    pub elapsed_secs: f64,
    pub interval_secs: f64,
    pub unix_ms: u64,
    pub rows: Vec<Row>,
    pub interfaces: Vec<Interface>,
    pub health: Health,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(ingress: u32, egress: u32) -> PathKey {
        PathKey {
            kind: Kind::Forward,
            ingress,
            egress,
            netns: 7,
            ingress_generation: 11,
            egress_generation: 22,
        }
    }

    #[test]
    fn forward_identity_is_unordered_but_keeps_generations_namespace_and_kind() {
        let a = key(2, 3);
        let b = PathKey {
            ingress: a.egress,
            egress: a.ingress,
            ingress_generation: a.egress_generation,
            egress_generation: a.ingress_generation,
            ..a
        };
        assert_eq!(a.group(), b.group());
        assert_eq!(key(2, 2).group().group(), key(2, 2).group());
        for different in [
            PathKey { netns: 8, ..a },
            PathKey {
                ingress_generation: 12,
                ..a
            },
            PathKey {
                kind: Kind::Input,
                ..a
            },
            PathKey {
                kind: Kind::Output,
                ..a
            },
        ] {
            assert_ne!(a.group(), different.group());
        }
        let input = PathKey {
            kind: Kind::Input,
            ..b
        };
        assert_eq!(input.group(), input);
        assert_eq!(Kind::Input.label(), "INPUT");
        assert_eq!(Kind::Output.label(), "OUTPUT");
        assert_eq!(Kind::Forward.label(), "FORWARD");
    }

    #[test]
    fn counter_delta_handles_resets_without_wrapping() {
        let previous = Counters {
            in_packets: 10,
            in_bytes: 1_000,
            out_packets: 9,
            out_bytes: 900,
            route: 8,
            bridge: 7,
            combo: 6,
            freed: 5,
        };
        let current = Counters {
            in_packets: 12,
            in_bytes: 1_200,
            out_packets: 4,
            out_bytes: 400,
            route: 9,
            bridge: 9,
            combo: 9,
            freed: 9,
        };
        let delta = current.delta(&previous);
        assert_eq!(delta.in_packets, 2);
        assert_eq!(delta.in_bytes, 200);
        assert_eq!(delta.out_packets, 0);
        assert_eq!(delta.out_bytes, 0);
        assert_eq!(
            (delta.route, delta.bridge, delta.combo, delta.freed),
            (1, 2, 3, 4)
        );
    }

    #[test]
    fn histogram_bounds_cover_every_exponent_and_sub_bucket() {
        assert_eq!(
            (0..8).map(bucket_index).collect::<Vec<_>>(),
            [0, 1, 2, 3, 8, 9, 10, 11]
        );
        for exponent in 2..64 {
            for fraction in 0..4 {
                let lower = (4 + fraction) << (exponent - 2);
                let index = exponent as usize * 4 + fraction as usize;
                assert_eq!(bucket_index(lower), index);
                let upper = bucket_upper_ns(index);
                assert!(lower <= upper);
                assert_eq!(bucket_index(upper), index);
                if index < 255 {
                    assert_eq!(bucket_index(upper + 1), index + 1);
                }
            }
        }
        assert_eq!(bucket_index(u64::MAX), 255);
        assert_eq!(bucket_upper_ns(usize::MAX), u64::MAX);
        assert!((1..BUCKETS).all(|i| bucket_upper_ns(i - 1) <= bucket_upper_ns(i)));
    }

    #[test]
    fn raw_latency_uses_nearest_rank_and_observed_extrema() {
        let values = [
            (1_000u64, 50u64),
            (2_000, 40),
            (3_000, 5),
            (4_000, 4),
            (5_000, 1),
        ];
        let mut histogram = vec![0; BUCKETS];
        for (ns, count) in values {
            histogram[bucket_index(ns)] += count;
        }
        let latency = Latency::from_raw(100, 166_000, 1_000, 5_000, histogram);
        assert_eq!(latency.min_us, Some(1.0));
        assert_eq!(latency.avg_us, Some(1.66));
        assert_eq!(latency.p50_us, Some(1.023));
        assert_eq!(latency.p90_us, Some(2.047));
        assert_eq!(latency.p95_us, Some(3.071));
        assert_eq!(latency.p99_us, Some(4.095));
        assert_eq!(latency.max_us, Some(5.0));
        let mut histogram = vec![0; BUCKETS];
        histogram[bucket_index(5_000)] = 1;
        let single = Latency::from_raw(1, 5_000, 5_000, 5_000, histogram);
        assert_eq!(single.p99_us, Some(5.0));
    }

    #[test]
    fn empty_incomplete_and_large_histograms_are_safe() {
        let empty = Latency::from_raw(0, 0, u64::MAX, 0, Vec::new());
        assert_eq!(empty.histogram.len(), BUCKETS);
        assert_eq!(empty.min_us, None);
        assert_eq!(empty.avg_us, None);
        assert_eq!(empty.p99_us, None);
        let missing = Latency::from_raw(10, 100, 10, 10, Vec::new());
        assert_eq!(missing.p99_us, None);
        let mut histogram = vec![0; BUCKETS + 1];
        histogram[255] = u64::MAX;
        let large = Latency::from_raw(u64::MAX, u64::MAX, u64::MAX, u64::MAX, histogram);
        assert_eq!(large.histogram.len(), BUCKETS);
        assert_eq!(large.p99_us, Some(u64::MAX as f64 / 1_000.0));
    }
}
