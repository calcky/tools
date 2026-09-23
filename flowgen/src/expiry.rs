use std::collections::HashMap;
use std::time::Instant;

/// One pending deadline per flow token, ordered by deadline then token.
/// Storage is retained across removals for reuse by subsequent requests.
#[derive(Default)]
pub struct Expirations {
    heap: Vec<(Instant, usize, u64)>,
    indexes: HashMap<usize, usize>,
}

impl Expirations {
    /// Insert a deadline or replace the token's existing deadline in place.
    pub fn set(&mut self, token: usize, seq: u64, deadline: Instant) {
        if let Some(&index) = self.indexes.get(&token) {
            self.heap[index] = (deadline, token, seq);
            self.repair(index);
        } else {
            let index = self.heap.len();
            self.heap.push((deadline, token, seq));
            self.indexes.insert(token, index);
            self.sift_up(index);
        }
    }

    /// Cancel a token's deadline; absent tokens are harmless.
    pub fn remove(&mut self, token: usize) {
        if let Some(&index) = self.indexes.get(&token) {
            self.remove_at(index);
        }
    }

    pub fn peek(&self) -> Option<(Instant, usize, u64)> {
        self.heap.first().copied()
    }

    pub fn pop(&mut self) -> Option<(Instant, usize, u64)> {
        if self.heap.is_empty() {
            None
        } else {
            Some(self.remove_at(0))
        }
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    fn remove_at(&mut self, index: usize) -> (Instant, usize, u64) {
        let removed = self.heap.swap_remove(index);
        self.indexes.remove(&removed.1);
        if index < self.heap.len() {
            *self.indexes.get_mut(&self.heap[index].1).unwrap() = index;
            self.repair(index);
        }
        removed
    }

    fn repair(&mut self, index: usize) {
        if index > 0 && self.heap[index] < self.heap[(index - 1) / 2] {
            self.sift_up(index);
        } else {
            self.sift_down(index);
        }
    }

    fn sift_up(&mut self, mut index: usize) {
        while index > 0 {
            let parent = (index - 1) / 2;
            if self.heap[parent] <= self.heap[index] {
                break;
            }
            self.swap(index, parent);
            index = parent;
        }
    }

    fn sift_down(&mut self, mut index: usize) {
        // Only internal nodes have children, so child arithmetic cannot overflow.
        while index < self.heap.len() / 2 {
            let left = index * 2 + 1;
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[index] <= self.heap[child] {
                break;
            }
            self.swap(index, child);
            index = child;
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        *self.indexes.get_mut(&self.heap[a].1).unwrap() = a;
        *self.indexes.get_mut(&self.heap[b].1).unwrap() = b;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn check_invariants(expirations: &Expirations) {
        assert_eq!(expirations.heap.len(), expirations.indexes.len());
        for (index, entry) in expirations.heap.iter().enumerate() {
            assert_eq!(expirations.indexes.get(&entry.1), Some(&index));
            if index > 0 {
                assert!(expirations.heap[(index - 1) / 2] <= *entry);
            }
        }
    }

    #[test]
    fn update_reorders_both_directions_and_replaces_sequence() {
        let now = Instant::now();
        let mut expirations = Expirations::default();
        for token in 0..7 {
            expirations.set(token, 1, now + Duration::from_secs(token as u64 + 1));
        }
        let heap_capacity = expirations.heap.capacity();
        let heap_pointer = expirations.heap.as_ptr();
        let map_capacity = expirations.indexes.capacity();

        expirations.set(6, 2, now);
        assert_eq!(expirations.peek(), Some((now, 6, 2)));
        check_invariants(&expirations);
        expirations.set(6, 3, now + Duration::from_secs(20));
        assert_eq!(
            expirations.peek(),
            Some((now + Duration::from_secs(1), 0, 1))
        );
        check_invariants(&expirations);
        expirations.set(0, u64::MAX, now + Duration::from_secs(1));
        assert_eq!(
            expirations.peek(),
            Some((now + Duration::from_secs(1), 0, u64::MAX))
        );
        assert_eq!(expirations.len(), 7);
        assert_eq!(expirations.heap.capacity(), heap_capacity);
        assert_eq!(expirations.heap.as_ptr(), heap_pointer);
        assert_eq!(expirations.indexes.capacity(), map_capacity);

        for token in 0..6 {
            let seq = if token == 0 { u64::MAX } else { 1 };
            assert_eq!(
                expirations.pop(),
                Some((now + Duration::from_secs(token as u64 + 1), token, seq))
            );
            check_invariants(&expirations);
        }
        assert_eq!(
            expirations.pop(),
            Some((now + Duration::from_secs(20), 6, 3))
        );
        assert_eq!(expirations.pop(), None);
        assert_eq!(expirations.peek(), None);
        check_invariants(&expirations);
    }

    #[test]
    fn cancellation_repairs_in_both_directions() {
        let now = Instant::now();
        // Removing 12 moves 3 above its new parent, 10. Removing 1 then
        // moves 10 below its new child, 2.
        let mut expirations = Expirations::default();
        for token in [1, 10, 2, 11, 12, 3] {
            expirations.set(token, token as u64, now + Duration::from_secs(token as u64));
        }
        expirations.remove(12);
        check_invariants(&expirations);
        expirations.remove(1);
        check_invariants(&expirations);
        expirations.remove(usize::MAX);
        assert_eq!(expirations.len(), 4);
        expirations.remove(11); // Last element.
        check_invariants(&expirations);
        expirations.remove(2); // Root.
        check_invariants(&expirations);
        for token in [3, 10] {
            assert_eq!(
                expirations.pop(),
                Some((now + Duration::from_secs(token as u64), token, token as u64))
            );
        }
        expirations.remove(10);
        assert_eq!(expirations.peek(), None);
        expirations.set(usize::MAX, u64::MAX, now);
        expirations.remove(usize::MAX); // Singleton.
        assert_eq!(expirations.pop(), None);
        check_invariants(&expirations);
    }

    #[test]
    fn equal_deadlines_use_token_order() {
        let now = Instant::now();
        let mut expirations = Expirations::default();
        for token in [usize::MAX, 5, 0, 2] {
            expirations.set(token, 9, now);
        }
        expirations.set(2, 0, now);
        for token in [0, 2, 5, usize::MAX] {
            assert_eq!(
                expirations.pop(),
                Some((now, token, if token == 2 { 0 } else { 9 }))
            );
            check_invariants(&expirations);
        }
    }

    #[test]
    fn many_cycles_reuse_bounded_storage_without_stale_entries() {
        const FLOWS: usize = 64;
        let now = Instant::now();
        let mut expirations = Expirations::default();
        for token in 0..FLOWS {
            expirations.set(token, 0, now);
        }
        let heap_capacity = expirations.heap.capacity();
        let heap_pointer = expirations.heap.as_ptr();
        let map_capacity = expirations.indexes.capacity();

        for cycle in 1..=2_000 {
            for token in 0..FLOWS {
                expirations.set(
                    token,
                    cycle,
                    now + Duration::from_secs((FLOWS - token) as u64),
                );
                expirations.set(token, cycle, now);
            }
            assert_eq!(expirations.len(), FLOWS);
            check_invariants(&expirations);
            for token in (0..FLOWS).step_by(2) {
                expirations.remove(token);
                expirations.set(token, cycle + 1, now);
            }
            for token in 0..FLOWS {
                let seq = if token % 2 == 0 { cycle + 1 } else { cycle };
                assert_eq!(expirations.pop(), Some((now, token, seq)));
            }
            assert_eq!(expirations.len(), 0);
            assert_eq!(expirations.peek(), None);
            assert_eq!(expirations.pop(), None);
            check_invariants(&expirations);
            assert_eq!(expirations.heap.capacity(), heap_capacity);
            assert_eq!(expirations.heap.as_ptr(), heap_pointer);
            // HashMap's reported capacity may vary with deleted buckets, but
            // reinsertion must not grow storage with the number of requests.
            assert!(expirations.indexes.capacity() <= map_capacity);
        }
    }

    #[test]
    fn deterministic_random_operations_match_btree_reference() {
        let now = Instant::now();
        let mut expirations = Expirations::default();
        let mut reference = BTreeMap::new();
        let mut by_token = BTreeMap::new();
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        let mut random = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for seq in 0..30_000 {
            let token = (random() % 128) as usize;
            match random() % 10 {
                0..=5 => {
                    let deadline = now + Duration::from_millis(random() % 256);
                    if let Some(old) = by_token.insert(token, deadline) {
                        reference.remove(&(old, token));
                    }
                    reference.insert((deadline, token), seq);
                    expirations.set(token, seq, deadline);
                }
                6..=7 => {
                    if let Some(old) = by_token.remove(&token) {
                        reference.remove(&(old, token));
                    }
                    expirations.remove(token);
                }
                _ => {
                    let expected = reference.pop_first().map(|((deadline, token), seq)| {
                        by_token.remove(&token);
                        (deadline, token, seq)
                    });
                    assert_eq!(expirations.pop(), expected);
                }
            }
            assert_eq!(expirations.len(), reference.len());
            assert_eq!(
                expirations.peek(),
                reference
                    .first_key_value()
                    .map(|(&(deadline, token), &seq)| (deadline, token, seq))
            );
            for &(deadline, token, seq) in &expirations.heap {
                assert_eq!(reference.get(&(deadline, token)), Some(&seq));
            }
            check_invariants(&expirations);
        }
        for ((deadline, token), seq) in reference {
            assert_eq!(expirations.pop(), Some((deadline, token, seq)));
            check_invariants(&expirations);
        }
        assert_eq!(expirations.len(), 0);
        assert_eq!(expirations.pop(), None);
        assert_eq!(expirations.peek(), None);
    }
}
