use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

pub struct Pending {
    pub start: Instant,
    pub stamp: u64,
}

#[derive(Default)]
struct Overflow {
    entries: HashMap<u64, Pending>,
    order: VecDeque<u64>,
}

/// Keep the oldest request inline. Allocate only when requests overlap, and
/// retain overflow storage for reuse without retaining completed sequence IDs.
#[derive(Default)]
pub struct PendingRequests {
    first: Option<(u64, Pending)>,
    overflow: Option<Box<Overflow>>,
}

impl PendingRequests {
    pub fn len(&self) -> usize {
        usize::from(self.first.is_some())
            + self
                .overflow
                .as_ref()
                .map_or(0, |extra| extra.entries.len())
    }

    pub fn is_empty(&self) -> bool {
        self.first.is_none()
    }

    pub fn oldest(&self) -> Option<(u64, Instant)> {
        self.first
            .as_ref()
            .map(|(seq, pending)| (*seq, pending.start))
    }

    pub fn get(&self, seq: &u64) -> Option<&Pending> {
        if let Some((first, pending)) = &self.first {
            if first == seq {
                return Some(pending);
            }
        }
        self.overflow
            .as_ref()
            .and_then(|extra| extra.entries.get(seq))
    }

    pub fn insert(&mut self, seq: u64, pending: Pending) {
        if self.first.is_none() {
            self.first = Some((seq, pending));
            return;
        }
        assert!(self.get(&seq).is_none(), "request sequence already pending");
        let extra = self.overflow.get_or_insert_with(Default::default);
        extra.entries.insert(seq, pending);
        extra.order.push_back(seq);
        if extra.order.len() > 2 * (extra.entries.len() + 16) {
            extra.order.retain(|seq| extra.entries.contains_key(seq));
        }
    }

    pub fn remove(&mut self, seq: &u64) -> Option<Pending> {
        if self.first.as_ref().is_some_and(|(first, _)| first == seq) {
            let (_, pending) = self.first.take().unwrap();
            if let Some(extra) = &mut self.overflow {
                while let Some(next) = extra.order.pop_front() {
                    if let Some(pending) = extra.entries.remove(&next) {
                        self.first = Some((next, pending));
                        break;
                    }
                }
            }
            Some(pending)
        } else {
            self.overflow
                .as_mut()
                .and_then(|extra| extra.entries.remove(seq))
        }
    }

    pub fn drain(&mut self) -> impl Iterator<Item = (u64, Pending)> + '_ {
        std::iter::from_fn(|| {
            let seq = self.first.as_ref()?.0;
            self.remove(&seq).map(|pending| (seq, pending))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, time::Duration};

    #[test]
    fn isolated_requests_never_allocate_overflow() {
        let mut requests = PendingRequests::default();
        let start = Instant::now();
        for seq in 1..=10000 {
            requests.insert(seq, Pending { start, stamp: seq });
            assert_eq!(requests.oldest(), Some((seq, start)));
            assert_eq!(requests.len(), 1);
            assert_eq!(requests.remove(&seq).unwrap().stamp, seq);
            assert!(requests.is_empty());
            assert!(requests.overflow.is_none());
        }
    }

    #[test]
    fn reorder_promotes_the_oldest_live_request_and_drains_exactly_once() {
        let start = Instant::now();
        let mut requests = PendingRequests::default();
        for seq in 1..=5 {
            requests.insert(
                seq,
                Pending {
                    start: start + Duration::from_millis(seq),
                    stamp: seq,
                },
            );
        }
        assert_eq!(requests.remove(&3).unwrap().stamp, 3);
        assert!(requests.remove(&3).is_none());
        assert_eq!(requests.remove(&1).unwrap().stamp, 1);
        assert_eq!(
            requests.oldest(),
            Some((2, start + Duration::from_millis(2)))
        );
        assert_eq!(
            requests
                .drain()
                .map(|(seq, p)| (seq, p.stamp))
                .collect::<Vec<_>>(),
            [(2, 2), (4, 4), (5, 5)]
        );
        assert!(requests.is_empty());
        assert!(requests.overflow.as_ref().unwrap().order.is_empty());
        requests.insert(6, Pending { start, stamp: 6 });
        assert_eq!(requests.oldest(), Some((6, start)));
    }

    #[test]
    fn a_missing_oldest_response_does_not_retain_unbounded_order_metadata() {
        let start = Instant::now();
        let mut requests = PendingRequests::default();
        requests.insert(1, Pending { start, stamp: 1 });
        for seq in 2..10000 {
            requests.insert(seq, Pending { start, stamp: seq });
            assert_eq!(requests.remove(&seq).unwrap().stamp, seq);
            assert_eq!(requests.len(), 1);
            assert!(requests.overflow.as_ref().unwrap().order.len() <= 34);
        }
        requests.remove(&1).unwrap();
        assert!(requests.is_empty());
        assert!(requests.overflow.as_ref().unwrap().order.is_empty());
    }

    #[test]
    fn random_insert_remove_and_drain_match_ordered_reference() {
        let start = Instant::now();
        let mut requests = PendingRequests::default();
        let mut reference = BTreeMap::new();
        let mut state = 0x4d59_5df4_d0f3_3173u64;
        for seq in 1..20000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if state.is_multiple_of(3) {
                requests.insert(seq, Pending { start, stamp: seq });
                reference.insert(seq, seq);
            } else {
                let remove = state % seq;
                assert_eq!(
                    requests.get(&remove).map(|p| p.stamp),
                    reference.get(&remove).copied()
                );
                assert_eq!(
                    requests.remove(&remove).map(|p| p.stamp),
                    reference.remove(&remove)
                );
            }
            assert_eq!(requests.len(), reference.len());
            assert_eq!(
                requests.oldest().map(|(seq, _)| seq),
                reference.first_key_value().map(|(&seq, _)| seq)
            );
            if seq % 500 == 0 {
                assert_eq!(
                    requests
                        .drain()
                        .map(|(seq, p)| (seq, p.stamp))
                        .collect::<Vec<_>>(),
                    reference.iter().map(|(&k, &v)| (k, v)).collect::<Vec<_>>()
                );
                reference.clear();
            }
        }
    }
}
