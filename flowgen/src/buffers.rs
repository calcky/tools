use crate::wire::MAX;
use std::collections::HashMap;

const MAX_CACHED_BYTES: usize = 1024 * 1024;
const MAX_CACHED_BUFFERS: usize = 512;
const MAX_LENGTHS: usize = 32;

/// Worker-local, exact-length buffer cache with no locks.
///
/// At most 1 MiB of vector capacity and 512 buffers are cached across 32 length
/// classes. Checked-out buffers are not included in these idle-cache limits.
/// Empty classes retain their metadata for allocation-free steady-state reuse.
pub struct BufferPool {
    classes: HashMap<usize, Vec<Vec<u8>>>,
    cached_bytes: usize,
    cached_buffers: usize,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            classes: HashMap::with_capacity(MAX_LENGTHS),
            cached_bytes: 0,
            cached_buffers: 0,
        }
    }
}

impl BufferPool {
    /// Return an initialized vector with exactly `len` bytes.
    ///
    /// Cache hits retain previous contents; misses return zero-filled bytes.
    /// Callers must overwrite every byte they expose, including headers and
    /// payloads, and must not treat unread bytes after a partial read as input.
    /// Any length is accepted, but only lengths in `1..=wire::MAX` are cached.
    pub fn take(&mut self, len: usize) -> Vec<u8> {
        if let Some(buffer) = self.classes.get_mut(&len).and_then(Vec::pop) {
            self.cached_bytes -= buffer.capacity();
            self.cached_buffers -= 1;
            buffer
        } else {
            vec![0; len]
        }
    }

    /// Return a buffer without clearing its length or contents.
    ///
    /// Buffers are dropped if empty, oversized, over a cache limit, or if their
    /// capacity differs from their length. At the class limit, a new length can
    /// replace an empty class; populated classes are never evicted.
    pub fn give(&mut self, buffer: Vec<u8>) {
        let len = buffer.len();
        let capacity = buffer.capacity();
        if !(1..=MAX).contains(&len)
            || capacity != len
            || self.cached_buffers == MAX_CACHED_BUFFERS
            || capacity > MAX_CACHED_BYTES - self.cached_bytes
        {
            return;
        }

        if !self.classes.contains_key(&len) {
            let bucket = if self.classes.len() == MAX_LENGTHS {
                let Some(empty) = self
                    .classes
                    .iter()
                    .find_map(|(&length, buffers)| buffers.is_empty().then_some(length))
                else {
                    return;
                };
                // Reuse the empty bucket's storage when changing length classes.
                self.classes.remove(&empty).unwrap()
            } else {
                Vec::new()
            };
            self.classes.insert(len, bucket);
        }
        self.classes.get_mut(&len).unwrap().push(buffer);
        self.cached_bytes += capacity;
        self.cached_buffers += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_bounds(pool: &BufferPool) {
        let mut bytes = 0;
        let mut count = 0;
        for (&len, buffers) in &pool.classes {
            assert!((1..=MAX).contains(&len));
            // Each bucket can retain metadata from at most the global buffer cap.
            assert!(buffers.capacity() <= MAX_CACHED_BUFFERS);
            for buffer in buffers {
                assert_eq!(buffer.len(), len);
                assert_eq!(buffer.capacity(), len);
                bytes += buffer.capacity();
                count += 1;
            }
        }
        assert_eq!(pool.cached_bytes, bytes);
        assert_eq!(pool.cached_buffers, count);
        assert!(bytes <= MAX_CACHED_BYTES);
        assert!(count <= MAX_CACHED_BUFFERS);
        assert!(pool.classes.len() <= MAX_LENGTHS);
    }

    #[test]
    fn misses_return_initialized_exact_lengths_without_creating_classes() {
        let mut pool = BufferPool::default();
        for len in [0, 1, 48, 128, MAX, MAX + 1] {
            let buffer = pool.take(len);
            assert_eq!(buffer.len(), len);
            assert!(buffer.iter().all(|&byte| byte == 0));
        }
        assert!(pool.classes.is_empty());
        check_bounds(&pool);
    }

    #[test]
    fn reuse_preserves_pointer_length_contents_and_class_storage() {
        let mut pool = BufferPool::default();
        let buffer = vec![0xa5; 128];
        let pointer = buffer.as_ptr();
        pool.give(buffer);
        let bucket_pointer = pool.classes[&128].as_ptr();
        let map_capacity = pool.classes.capacity();
        for _ in 0..10_000 {
            let buffer = pool.take(128);
            assert_eq!(buffer.as_ptr(), pointer);
            assert_eq!(buffer.len(), 128);
            assert!(buffer.iter().all(|&byte| byte == 0xa5));
            assert!(pool.classes[&128].is_empty());
            assert_eq!(pool.cached_bytes, 0);
            assert_eq!(pool.cached_buffers, 0);
            pool.give(buffer);
            assert_eq!(pool.classes[&128].as_ptr(), bucket_pointer);
            assert_eq!(pool.classes.capacity(), map_capacity);
        }
        check_bounds(&pool);
    }

    #[test]
    fn heterogeneous_buffers_are_reused_only_for_their_exact_length() {
        let mut pool = BufferPool::default();
        let mut expected = Vec::new();
        for (len, byte) in [(48, 1), (49, 2), (128, 3), (MAX, 4)] {
            let buffer = vec![byte; len];
            expected.push((len, byte, buffer.as_ptr()));
            pool.give(buffer);
        }
        let missed = pool.take(50);
        assert_eq!(missed, vec![0; 50]);
        for (len, byte, pointer) in expected.into_iter().rev() {
            let buffer = pool.take(len);
            assert_eq!(buffer.as_ptr(), pointer);
            assert_eq!(buffer, vec![byte; len]);
        }
        assert_eq!(pool.cached_bytes, 0);
        assert_eq!(pool.cached_buffers, 0);
        check_bounds(&pool);
    }

    #[test]
    fn rejects_empty_oversized_and_excess_capacity_buffers() {
        let mut pool = BufferPool::default();
        let mut spare_capacity = Vec::with_capacity(256);
        spare_capacity.resize(128, 1);
        pool.give(spare_capacity);
        pool.give(Vec::with_capacity(128));
        pool.give(Vec::new());
        pool.give(vec![0; MAX + 1]);
        assert!(pool.classes.is_empty());
        check_bounds(&pool);
    }

    #[test]
    fn byte_limit_is_exact_and_take_releases_capacity_budget() {
        let mut pool = BufferPool::default();
        for _ in 0..MAX_CACHED_BYTES / MAX {
            pool.give(vec![0; MAX]);
        }
        let remainder = MAX_CACHED_BYTES % MAX;
        assert_ne!(remainder, 0);
        pool.give(vec![0; remainder]);
        assert_eq!(pool.cached_bytes, MAX_CACHED_BYTES);
        let count = pool.cached_buffers;
        pool.give(vec![0; 1]);
        assert_eq!(pool.cached_buffers, count);
        assert!(!pool.classes.contains_key(&1));
        let buffer = pool.take(MAX);
        assert_eq!(pool.cached_bytes, MAX_CACHED_BYTES - MAX);
        pool.give(buffer);
        assert_eq!(pool.cached_bytes, MAX_CACHED_BYTES);
        check_bounds(&pool);
    }

    #[test]
    fn count_limit_is_independent_of_bytes_and_take_releases_a_slot() {
        let mut pool = BufferPool::default();
        for _ in 0..MAX_CACHED_BUFFERS + 10 {
            pool.give(vec![0; 1]);
        }
        assert_eq!(pool.cached_buffers, MAX_CACHED_BUFFERS);
        assert_eq!(pool.cached_bytes, MAX_CACHED_BUFFERS);
        let buffer = pool.take(1);
        assert_eq!(pool.cached_buffers, MAX_CACHED_BUFFERS - 1);
        pool.give(vec![0; 2]);
        pool.give(buffer);
        assert_eq!(pool.cached_bytes, MAX_CACHED_BUFFERS + 1);
        check_bounds(&pool);
    }

    #[test]
    fn new_lengths_replace_only_empty_classes_at_the_type_limit() {
        let mut pool = BufferPool::default();
        for len in 1..=MAX_LENGTHS {
            pool.give(vec![len as u8; len]);
        }
        pool.give(vec![0; MAX_LENGTHS + 1]);
        assert!(!pool.classes.contains_key(&(MAX_LENGTHS + 1)));
        assert_eq!(pool.cached_buffers, MAX_LENGTHS);

        let bucket_pointer = pool.classes[&7].as_ptr();
        let old = pool.take(7);
        assert!(pool.classes.contains_key(&7));
        pool.give(vec![0; MAX_LENGTHS + 1]);
        assert!(!pool.classes.contains_key(&7));
        assert_eq!(pool.classes[&(MAX_LENGTHS + 1)].as_ptr(), bucket_pointer);
        pool.give(old);
        assert!(!pool.classes.contains_key(&7));
        for len in (1..=MAX_LENGTHS).filter(|&len| len != 7) {
            assert_eq!(pool.take(len), vec![len as u8; len]);
        }
        check_bounds(&pool);
    }

    #[test]
    fn length_churn_bounds_metadata_and_preserves_immediate_reuse() {
        let mut pool = BufferPool::default();
        for len in 1..=4096 {
            let buffer = pool.take(len);
            let pointer = buffer.as_ptr();
            pool.give(buffer);
            let buffer = pool.take(len);
            assert_eq!(buffer.as_ptr(), pointer);
            assert_eq!(buffer.len(), len);
            assert_eq!(pool.cached_buffers, 0);
            assert_eq!(pool.classes.len(), len.min(MAX_LENGTHS));
            check_bounds(&pool);
        }
    }
}
