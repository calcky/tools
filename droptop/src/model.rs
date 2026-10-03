use crate::collect::{Focus, Key, Snapshot};
use clap::ValueEnum;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum GroupBy {
    #[default]
    Pair,
    Reason,
    Device,
    Site,
}

impl GroupBy {
    pub fn next(self) -> Self {
        match self {
            Self::Pair => Self::Reason,
            Self::Reason => Self::Device,
            Self::Device => Self::Site,
            Self::Site => Self::Pair,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pair => "reason + device",
            Self::Reason => "reason",
            Self::Device => "device",
            Self::Site => "call site",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GroupKey {
    Pair(u32, u32, u32),
    Reason(u32),
    Device(u32, u32),
    Site(u64),
}

impl GroupKey {
    pub fn from_drop(key: Key, group: GroupBy) -> Self {
        match group {
            GroupBy::Pair => Self::Pair(key.reason, key.ifindex, key.netns),
            GroupBy::Reason => Self::Reason(key.reason),
            GroupBy::Device => Self::Device(key.ifindex, key.netns),
            GroupBy::Site => Self::Site(key.location),
        }
    }

    pub fn focus(self) -> Focus {
        match self {
            Self::Pair(reason, ifindex, netns) => Focus {
                reason,
                ifindex,
                netns,
                mask: 3,
                ..Focus::default()
            },
            Self::Reason(reason) => Focus {
                reason,
                mask: 1,
                ..Focus::default()
            },
            Self::Device(ifindex, netns) => Focus {
                ifindex,
                netns,
                mask: 2,
                ..Focus::default()
            },
            Self::Site(location) => Focus {
                location,
                mask: 4,
                ..Focus::default()
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub key: GroupKey,
    pub count: u64,
    pub rate: f64,
}

pub fn rows(current: &Snapshot, previous: &Snapshot, elapsed: f64, group: GroupBy) -> Vec<Row> {
    let mut groups: HashMap<GroupKey, (u64, u64)> = HashMap::new();
    for (&key, &count) in &current.drops {
        let prior = previous.drops.get(&key).copied().unwrap_or_default();
        let delta = count.saturating_sub(prior);
        let entry = groups.entry(GroupKey::from_drop(key, group)).or_default();
        entry.0 = entry.0.saturating_add(count);
        entry.1 = entry.1.saturating_add(delta);
    }
    let mut rows: Vec<_> = groups
        .into_iter()
        .map(|(key, (count, delta))| Row {
            key,
            count,
            rate: delta as f64 / elapsed.max(0.001),
        })
        .collect();
    rows.sort_by(|a, b| {
        b.rate
            .total_cmp(&a.rate)
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.key.cmp(&b.key))
    });
    rows
}

pub fn total_rate(current: &Snapshot, previous: &Snapshot, elapsed: f64) -> f64 {
    current
        .drops
        .iter()
        .map(|(key, value)| value.saturating_sub(*previous.drops.get(key).unwrap_or(&0)))
        .sum::<u64>() as f64
        / elapsed.max(0.001)
}

pub fn stack_rates(current: &Snapshot, previous: &Snapshot, elapsed: f64) -> Vec<(u32, f64, u64)> {
    let mut stacks: Vec<_> = current
        .stacks
        .iter()
        .map(|(&id, &count)| {
            let delta = count.saturating_sub(*previous.stacks.get(&id).unwrap_or(&0));
            (id, delta as f64 / elapsed.max(0.001), count)
        })
        .collect();
    stacks.sort_by(|a, b| {
        b.1.total_cmp(&a.1)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.0.cmp(&b.0))
    });
    stacks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drop(reason: u32, iface: u32, site: u64) -> Key {
        Key {
            reason,
            ifindex: iface,
            netns: 10,
            location: site,
            protocol: 0x800,
        }
    }

    #[test]
    fn combines_sites_for_same_reason_and_device() {
        let mut old = Snapshot::default();
        let mut now = Snapshot::default();
        old.drops.insert(drop(1, 2, 8), 4);
        now.drops.insert(drop(1, 2, 8), 6);
        now.drops.insert(drop(1, 2, 9), 4);
        now.drops.insert(drop(2, 2, 9), 2);
        let result = rows(&now, &old, 2.0, GroupBy::Pair);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].key, GroupKey::Pair(1, 2, 10));
        assert_eq!(result[0].rate, 3.0);
        assert_eq!(total_rate(&now, &old, 2.0), 4.0);
    }

    #[test]
    fn never_replays_counter_reset() {
        let mut old = Snapshot::default();
        let mut now = Snapshot::default();
        old.drops.insert(drop(1, 2, 8), 8);
        now.drops.insert(drop(1, 2, 8), 2);
        let result = rows(&now, &old, 1.0, GroupBy::Reason);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rate, 0.0);
    }

    #[test]
    fn scopes_stack_collection_to_group() {
        assert_eq!(GroupKey::Pair(1, 2, 10).focus().mask, 3);
        assert_eq!(GroupKey::Reason(1).focus().mask, 1);
        assert_eq!(GroupKey::Device(2, 10).focus().mask, 2);
        assert_eq!(GroupKey::Site(8).focus().mask, 4);
    }

    #[test]
    fn stack_rates_are_deltas() {
        let mut old = Snapshot::default();
        let mut now = Snapshot::default();
        old.stacks.insert(7, 5);
        now.stacks.insert(7, 9);
        now.stacks.insert(8, 6);
        assert_eq!(stack_rates(&now, &old, 2.0), vec![(8, 3.0, 6), (7, 2.0, 9)]);
    }
}
