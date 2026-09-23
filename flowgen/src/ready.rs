use std::{collections::HashMap, hash::Hash};

struct Node<T> {
    value: Option<T>,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Bounded FIFO with O(1) deduplication and cancellation.
pub struct ReadyQueue<T: Copy + Eq + Hash> {
    nodes: Vec<Node<T>>,
    free: Vec<usize>,
    index: HashMap<T, usize>,
    head: Option<usize>,
    tail: Option<usize>,
    len: usize,
    highwater: usize,
    capacity: usize,
}

impl<T: Copy + Eq + Hash> ReadyQueue<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(capacity.min(1024)),
            free: Vec::with_capacity(capacity.min(1024)),
            index: HashMap::with_capacity(capacity.min(1024)),
            head: None,
            tail: None,
            len: 0,
            highwater: 0,
            capacity,
        }
    }

    pub fn push_back(&mut self, value: T) -> bool {
        if self.index.contains_key(&value) || self.len == self.capacity {
            return false;
        }
        let node = if let Some(index) = self.free.pop() {
            index
        } else {
            self.nodes.push(Node {
                value: None,
                prev: None,
                next: None,
            });
            self.nodes.len() - 1
        };
        self.nodes[node].value = Some(value);
        self.nodes[node].prev = self.tail;
        self.nodes[node].next = None;
        if let Some(tail) = self.tail {
            self.nodes[tail].next = Some(node);
        } else {
            self.head = Some(node);
        }
        self.tail = Some(node);
        self.index.insert(value, node);
        self.len += 1;
        self.highwater = self.highwater.max(self.len);
        true
    }

    pub fn push_front(&mut self, value: T) -> bool {
        if self.index.contains_key(&value) || self.len == self.capacity {
            return false;
        }
        let node = if let Some(index) = self.free.pop() {
            index
        } else {
            self.nodes.push(Node {
                value: None,
                prev: None,
                next: None,
            });
            self.nodes.len() - 1
        };
        self.nodes[node].value = Some(value);
        self.nodes[node].prev = None;
        self.nodes[node].next = self.head;
        if let Some(head) = self.head {
            self.nodes[head].prev = Some(node);
        } else {
            self.tail = Some(node);
        }
        self.head = Some(node);
        self.index.insert(value, node);
        self.len += 1;
        self.highwater = self.highwater.max(self.len);
        true
    }

    pub fn pop_front(&mut self) -> Option<T> {
        let node = self.head?;
        self.unlink(node)
    }

    pub fn remove(&mut self, value: &T) -> Option<T> {
        let node = *self.index.get(value)?;
        self.unlink(node)
    }

    #[allow(dead_code)]
    pub fn contains(&self, value: &T) -> bool {
        self.index.contains_key(value)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[allow(dead_code)]
    pub fn highwater(&self) -> usize {
        self.highwater
    }

    fn unlink(&mut self, node: usize) -> Option<T> {
        let value = self.nodes[node].value.take()?;
        let prev = self.nodes[node].prev;
        let next = self.nodes[node].next;
        if let Some(prev) = prev {
            self.nodes[prev].next = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.nodes[next].prev = prev;
        } else {
            self.tail = prev;
        }
        self.index.remove(&value);
        self.nodes[node].prev = None;
        self.nodes[node].next = None;
        self.free.push(node);
        self.len -= 1;
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_cancellation_and_reuse_are_bounded() {
        let mut queue = ReadyQueue::with_capacity(2);
        assert!(queue.push_back(1));
        assert!(queue.push_back(2));
        assert!(!queue.push_back(1));
        assert!(!queue.push_back(3));
        assert_eq!(queue.remove(&1), Some(1));
        assert!(queue.push_front(3));
        assert_eq!(queue.pop_front(), Some(3));
        assert_eq!(queue.pop_front(), Some(2));
        assert_eq!(queue.highwater(), 2);
    }
}
