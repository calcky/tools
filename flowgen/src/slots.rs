use mio::Token;

const INDEX_BITS: usize = 20;
const INDEX_MASK: usize = (1 << INDEX_BITS) - 1;
// Reserve generation zero for special event tokens, and the top generation
// so no slot can produce the wake token (usize::MAX).
const MAX_GENERATION: usize = (usize::MAX >> INDEX_BITS) - 1;

struct Slot<T> {
    generation: usize,
    occupied: bool,
    value: Option<T>,
}

/// A stable slot table with indexed, generation-checked tokens.
/// Capacity is a reservation, not an admission limit. There are at most 2^20
/// slots, including retired slots, matching the server's ready queue bound.
/// Exhausted generations retire their slot permanently instead of aliasing
/// stale tokens. Taken values remain live until put back or released.
pub struct SlotTable<T> {
    slots: Vec<Slot<T>>,
    free: Vec<usize>,
    live: usize,
    highwater: usize,
}

impl<T> SlotTable<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= INDEX_MASK + 1);
        Self {
            slots: Vec::with_capacity(capacity.min(1024)),
            free: Vec::with_capacity(capacity.min(1024)),
            live: 0,
            highwater: 0,
        }
    }

    pub fn insert(&mut self, value: T) -> Option<Token> {
        let index = if let Some(index) = self.free.pop() {
            index
        } else if self.slots.len() <= INDEX_MASK {
            let index = self.slots.len();
            self.slots.push(Slot {
                generation: 1,
                occupied: false,
                value: None,
            });
            index
        } else {
            return None;
        };
        let slot = &mut self.slots[index];
        debug_assert!(slot.value.is_none());
        debug_assert!(!slot.occupied);
        slot.occupied = true;
        slot.value = Some(value);
        self.live += 1;
        self.highwater = self.highwater.max(self.live);
        Some(Self::token(index, slot.generation))
    }

    pub fn get(&self, token: Token) -> Option<&T> {
        let (index, generation) = Self::decode(token)?;
        self.slots.get(index).and_then(|slot| {
            (slot.generation == generation)
                .then_some(slot.value.as_ref())
                .flatten()
        })
    }

    pub fn get_mut(&mut self, token: Token) -> Option<&mut T> {
        let (index, generation) = Self::decode(token)?;
        self.slots.get_mut(index).and_then(|slot| {
            (slot.generation == generation)
                .then_some(slot.value.as_mut())
                .flatten()
        })
    }

    pub fn remove(&mut self, token: Token) -> Option<T> {
        let value = self.take(token)?;
        let released = self.release_taken(token);
        debug_assert!(released);
        Some(value)
    }

    /// Release a token whose value was extracted with `take` and then closed.
    /// Returns false for stale, already released, or still populated slots.
    pub fn release_taken(&mut self, token: Token) -> bool {
        let Some((index, generation)) = Self::decode(token) else {
            return false;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if slot.generation != generation || !slot.occupied || slot.value.is_some() {
            return false;
        }
        slot.occupied = false;
        if slot.generation < MAX_GENERATION {
            slot.generation += 1;
            self.free.push(index);
        }
        self.live -= 1;
        true
    }

    /// Temporarily extracts a live value without changing its token generation.
    /// This permits service code to borrow the worker and peer independently.
    pub fn take(&mut self, token: Token) -> Option<T> {
        let (index, generation) = Self::decode(token)?;
        let slot = self.slots.get_mut(index)?;
        (slot.generation == generation)
            .then(|| slot.value.take())
            .flatten()
    }

    pub fn put(&mut self, token: Token, value: T) -> bool {
        let Some((index, generation)) = Self::decode(token) else {
            return false;
        };
        let Some(slot) = self.slots.get_mut(index) else {
            return false;
        };
        if slot.generation != generation || !slot.occupied || slot.value.is_some() {
            return false;
        }
        slot.value = Some(value);
        true
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.live
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = (Token, &T)> {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            slot.value
                .as_ref()
                .map(|value| (Self::token(index, slot.generation), value))
        })
    }

    #[allow(dead_code)]
    pub fn highwater(&self) -> usize {
        self.highwater
    }

    pub fn tokens(&self) -> Vec<Token> {
        self.iter().map(|(token, _)| token).collect()
    }

    fn token(index: usize, generation: usize) -> Token {
        Token((generation << INDEX_BITS) | index)
    }

    fn decode(token: Token) -> Option<(usize, usize)> {
        let generation = token.0 >> INDEX_BITS;
        (generation != 0 && generation <= MAX_GENERATION)
            .then_some((token.0 & INDEX_MASK, generation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_tokens_cannot_access_reused_slots() {
        let mut slots = SlotTable::with_capacity(1);
        let old = slots.insert("old").unwrap();
        assert_eq!(slots.remove(old), Some("old"));
        let current = slots.insert("new").unwrap();
        assert_ne!(old, current);
        assert!(slots.get(old).is_none());
        assert_eq!(slots.get(current), Some(&"new"));
        assert_eq!(slots.highwater(), 1);
    }

    #[test]
    fn take_put_preserves_token_generation_and_highwater() {
        let mut slots = SlotTable::with_capacity(2);
        let token = slots.insert(1).unwrap();
        let value = slots.take(token).unwrap();
        assert_eq!(slots.len(), 1);
        assert!(slots.put(token, value + 1));
        assert_eq!(slots.get(token), Some(&2));
        assert_eq!(slots.highwater(), 1);
    }

    #[test]
    fn release_taken_is_exactly_once_and_never_releases_a_present_value() {
        let mut slots = SlotTable::with_capacity(1);
        let old = slots.insert(1).unwrap();
        assert!(!slots.release_taken(old));
        assert_eq!(slots.take(old), Some(1));
        assert_eq!(slots.take(old), None);
        assert_eq!(slots.remove(old), None);
        assert_eq!(slots.len(), 1);
        assert!(slots.release_taken(old));
        assert!(!slots.release_taken(old));
        assert!(!slots.put(old, 2));
        assert_eq!(slots.len(), 0);
        let current = slots.insert(3).unwrap();
        assert!(!slots.release_taken(old));
        assert_eq!(slots.remove(current), Some(3));
        assert!(!slots.release_taken(current));
        assert_eq!(slots.len(), 0);
        assert_eq!(slots.highwater(), 1);
    }

    #[test]
    fn exhausted_slot_is_retired_and_cannot_be_restored() {
        let mut slots = SlotTable::with_capacity(1);
        let original = slots.insert(1).unwrap();
        slots.slots[0].generation = MAX_GENERATION;
        let last = SlotTable::<i32>::token(0, MAX_GENERATION);
        assert!(slots.get(original).is_none());
        assert_eq!(slots.take(last), Some(1));
        assert!(slots.release_taken(last));
        assert!(slots.free.is_empty());
        assert!(!slots.put(last, 2));
        assert!(!slots.release_taken(last));
        let current = slots.insert(3).unwrap();
        assert_eq!(SlotTable::<i32>::decode(current).unwrap().0, 1);
        assert_eq!(slots.get(current), Some(&3));
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn churn_beyond_65536_never_reuses_a_token_or_leaks_live_slots() {
        let mut slots = SlotTable::with_capacity(1);
        let mut seen = std::collections::HashSet::new();
        for value in 0..131_073 {
            let token = slots.insert(value).unwrap();
            assert!(seen.insert(token.0));
            assert!(token.0 > 1 && token.0 != usize::MAX);
            assert_eq!(slots.get(token), Some(&value));
            if value % 2 == 0 {
                assert_eq!(slots.remove(token), Some(value));
            } else {
                assert_eq!(slots.take(token), Some(value));
                assert!(slots.release_taken(token));
            }
            assert!(slots.get(token).is_none());
            assert!(!slots.release_taken(token));
            assert_eq!(slots.len(), 0);
        }
        assert_eq!(slots.highwater(), 1);
        assert_eq!(slots.slots.len(), 131_072 / MAX_GENERATION + 1);
    }

    #[test]
    fn live_slots_can_grow_beyond_65536() {
        let mut slots = SlotTable::with_capacity(1);
        for value in 0..70_000 {
            let token = slots.insert(value).unwrap();
            assert_eq!(slots.get(token), Some(&value));
        }
        assert_eq!(slots.len(), 70_000);
        assert_eq!(slots.highwater(), 70_000);
    }

    #[test]
    fn full_table_rejects_without_changing_live_count_and_can_reuse() {
        let mut slots = SlotTable::with_capacity(1);
        let first = slots.insert(()).unwrap();
        for _ in 1..=INDEX_MASK {
            assert!(slots.insert(()).is_some());
        }
        assert!(slots.insert(()).is_none());
        assert_eq!(slots.len(), INDEX_MASK + 1);
        assert_eq!(slots.remove(first), Some(()));
        let replacement = slots.insert(()).unwrap();
        assert_ne!(first, replacement);
        assert_eq!(slots.len(), INDEX_MASK + 1);
    }

    #[test]
    fn reserved_and_out_of_range_tokens_are_rejected() {
        let mut slots = SlotTable::with_capacity(1);
        for token in [Token(0), Token(1), Token(usize::MAX), Token(INDEX_MASK)] {
            assert!(slots.get(token).is_none());
            assert!(slots.take(token).is_none());
            assert!(!slots.release_taken(token));
            assert!(!slots.put(token, 1));
        }
        let last = SlotTable::<i32>::token(INDEX_MASK, MAX_GENERATION);
        assert_eq!(
            SlotTable::<i32>::decode(last),
            Some((INDEX_MASK, MAX_GENERATION))
        );
    }
}
