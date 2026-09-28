use std::cmp::Ordering;
use std::sync::Arc;

use crate::monitor::socket_table::{
    InetSocketSnapshot, SocketFilter, SocketRowKey, SocketTableSnapshot,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::tui) enum SocketSort {
    Protocol,
    State,
    Local,
    Remote,
    Process,
    #[default]
    RxQueue,
    TxQueue,
    Rtt,
    Mss,
    CongestionControl,
}

impl SocketSort {
    pub(in crate::tui) const ALL: [Self; 10] = [
        Self::Protocol,
        Self::State,
        Self::Local,
        Self::Remote,
        Self::Process,
        Self::RxQueue,
        Self::TxQueue,
        Self::Rtt,
        Self::Mss,
        Self::CongestionControl,
    ];

    pub(in crate::tui) fn label(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::State => "state",
            Self::Local => "local endpoint",
            Self::Remote => "remote endpoint",
            Self::Process => "process",
            Self::RxQueue => "RX queue",
            Self::TxQueue => "TX queue",
            Self::Rtt => "RTT",
            Self::Mss => "MSS",
            Self::CongestionControl => "congestion control",
        }
    }

    fn compare(
        self,
        left: &InetSocketSnapshot,
        right: &InetSocketSnapshot,
        descending: bool,
    ) -> Ordering {
        let order = match self {
            Self::Protocol => compare_available(
                Some(left.protocol()),
                Some(right.protocol()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::RxQueue | Self::TxQueue | Self::Rtt | Self::Mss => {
                let value = |socket: &InetSocketSnapshot| match self {
                    Self::RxQueue => (socket.queue_kind()
                        != crate::monitor::socket_table::QueueKind::Unavailable)
                        .then_some(u128::from(socket.receive_queue())),
                    Self::TxQueue => (socket.queue_kind()
                        != crate::monitor::socket_table::QueueKind::Unavailable)
                        .then_some(u128::from(socket.send_queue())),
                    Self::Rtt => socket.tcp().map(|tcp| u128::from(tcp.rtt_micros)),
                    Self::Mss => socket.tcp().map(|tcp| u128::from(tcp.send_mss_bytes)),
                    _ => unreachable!(),
                };
                compare_available(value(left), value(right), descending, u128::cmp)
            }
            Self::State => compare_available(
                Some(left.state()),
                Some(right.state()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::Local => compare_available(
                Some(left.local()),
                Some(right.local()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::Remote => compare_available(
                Some(left.remote()),
                Some(right.remote()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::Process => {
                fn value(socket: &InetSocketSnapshot) -> Option<(&str, u32)> {
                    socket
                        .owners()
                        .first()
                        .map(|owner| (owner.command().unwrap_or(""), owner.pid()))
                }
                compare_available(value(left), value(right), descending, |a, b| a.cmp(b))
            }
            Self::CongestionControl => compare_available(
                left.congestion_algorithm(),
                right.congestion_algorithm(),
                descending,
                |a, b| a.cmp(b),
            ),
        };
        order.then_with(|| left.row_key().cmp(right.row_key()))
    }
}
fn compare_available<T>(
    left: Option<T>,
    right: Option<T>,
    descending: bool,
    compare: impl FnOnce(&T, &T) -> Ordering,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            let order = compare(&left, &right);
            if descending {
                order.reverse()
            } else {
                order
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[derive(Debug)]
pub(in crate::tui) struct SocketOrder {
    snapshot: Option<Arc<SocketTableSnapshot>>,
    filter: Option<SocketFilter>,
    indices: Vec<usize>,
    peers: Vec<Option<usize>>,
    sort: SocketSort,
    descending: bool,
}

impl Default for SocketOrder {
    fn default() -> Self {
        Self {
            snapshot: None,
            filter: None,
            indices: Vec::new(),
            peers: Vec::new(),
            sort: SocketSort::default(),
            descending: true,
        }
    }
}

impl SocketOrder {
    pub(in crate::tui) fn select_sort(&mut self, sort: SocketSort) {
        self.descending = if self.sort == sort {
            !self.descending
        } else {
            true
        };
        self.sort = sort;
        self.sort_rows();
    }
    pub(in crate::tui) fn update(
        &mut self,
        snapshot: Arc<SocketTableSnapshot>,
        filter: Option<&SocketFilter>,
    ) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, &snapshot))
            && self.filter.as_ref() == filter
        {
            return;
        }
        self.indices.clear();
        self.peers = snapshot.local_peer_indices();
        self.indices.extend(
            snapshot
                .sockets()
                .iter()
                .enumerate()
                .filter(|(index, socket)| {
                    let peer = self.peers[*index].map(|index| &snapshot.sockets()[index]);
                    // Stable endpoint ordering also survives reconnects with new kernel cookies.
                    // This is presentation order, not an inference about client/server roles.
                    peer.is_none_or(|peer| {
                        socket
                            .local()
                            .canonical()
                            .cmp(&peer.local().canonical())
                            .then_with(|| socket.row_key().cmp(peer.row_key()))
                            .is_lt()
                    }) && filter.is_none_or(|filter| {
                        filter.matches(socket) || peer.is_some_and(|peer| filter.matches(peer))
                    })
                })
                .map(|(index, _)| index),
        );
        self.snapshot = Some(snapshot);
        self.filter = filter.cloned();
        self.sort_rows();
    }

    fn sort_rows(&mut self) {
        if let Some(snapshot) = &self.snapshot {
            self.indices.sort_unstable_by(|&left, &right| {
                self.sort.compare(
                    &snapshot.sockets()[left],
                    &snapshot.sockets()[right],
                    self.descending,
                )
            });
        }
    }

    pub(in crate::tui) fn cycle(&mut self) {
        let index = SocketSort::ALL
            .iter()
            .position(|sort| *sort == self.sort)
            .unwrap();
        self.sort = SocketSort::ALL[(index + 1) % SocketSort::ALL.len()];
        self.sort_rows();
    }

    pub(in crate::tui) fn reverse(&mut self) {
        self.descending = !self.descending;
        self.sort_rows();
    }

    pub(in crate::tui) fn clear(&mut self) {
        self.snapshot = None;
        self.filter = None;
        self.indices.clear();
        self.peers.clear();
    }

    pub(in crate::tui) fn shown_count(&self) -> usize {
        self.indices.len()
    }

    pub(in crate::tui) fn filter(&self) -> Option<&SocketFilter> {
        self.filter.as_ref()
    }

    pub(in crate::tui) fn position(&self, key: &SocketRowKey) -> Option<usize> {
        self.indices.iter().position(|&index| {
            self.snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.sockets()[index].row_key() == key
                    || self.peer(index).is_some_and(|peer| peer.row_key() == key)
            })
        })
    }

    pub(in crate::tui) fn socket(&self, position: usize) -> Option<&InetSocketSnapshot> {
        self.snapshot
            .as_ref()?
            .sockets()
            .get(*self.indices.get(position)?)
    }

    pub(in crate::tui) fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub(in crate::tui) fn peer(&self, index: usize) -> Option<&InetSocketSnapshot> {
        self.snapshot
            .as_ref()?
            .sockets()
            .get(self.peers.get(index).copied().flatten()?)
    }

    pub(in crate::tui) const fn sort(&self) -> SocketSort {
        self.sort
    }

    pub(in crate::tui) const fn descending(&self) -> bool {
        self.descending
    }

    pub(in crate::tui) fn status(&self) -> String {
        format!(
            "sort {} {}",
            self.sort.label(),
            if self.descending { "desc" } else { "asc" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_connection_keeps_direction_across_sort_filter_and_dump_order() {
        let mut order = SocketOrder::default();
        let initial = Arc::new(crate::monitor::socket_table::synthetic_local_socket_pair());
        let primary = initial.sockets()[0].row_key().clone();
        let peer = initial.sockets()[1].row_key().clone();
        for reverse in [false, true] {
            let snapshot = Arc::new(
                crate::monitor::socket_table::synthetic_local_socket_pair_at(2, reverse, false),
            );
            for query in ["", "src port 42000", "src port 443", "dst port 42000"] {
                let filter = SocketFilter::parse(query).unwrap();
                order.update(Arc::clone(&snapshot), filter.as_ref());
                for sort in SocketSort::ALL {
                    order.select_sort(sort);
                    order.reverse();
                    assert_eq!(order.shown_count(), 1);
                    assert_eq!(order.socket(0).unwrap().row_key(), &primary);
                    assert_eq!(order.position(&primary), Some(0));
                    assert_eq!(order.position(&peer), Some(0));
                    assert_eq!(order.peer(order.indices()[0]).unwrap().row_key(), &peer);
                }
            }
        }
        let reconnected =
            Arc::new(crate::monitor::socket_table::synthetic_local_socket_pair_at(3, true, true));
        order.update(reconnected, None);
        assert_eq!(order.shown_count(), 1);
        assert_eq!(
            order.socket(0).unwrap().local().port(),
            Some(42000),
            "reconnection must not reverse endpoints when cookie allocation order changes"
        );
    }

    #[test]
    fn sorting_matches_socket_fields_and_keeps_missing_last() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_sort_snapshot(2);
        let mut order = SocketOrder::default();
        order.update(Arc::clone(&snapshot), None);
        for (sort, descending, ascending) in [
            (SocketSort::Protocol, [1, 0, 2], [0, 2, 1]),
            (SocketSort::RxQueue, [0, 2, 1], [2, 1, 0]),
            (SocketSort::TxQueue, [2, 0, 1], [1, 0, 2]),
            (SocketSort::Rtt, [0, 2, 1], [0, 2, 1]),
            (SocketSort::Mss, [0, 2, 1], [0, 2, 1]),
            (SocketSort::CongestionControl, [0, 2, 1], [0, 2, 1]),
            (SocketSort::Process, [0, 2, 1], [0, 2, 1]),
            (SocketSort::Local, [1, 2, 0], [0, 2, 1]),
            (SocketSort::Remote, [1, 0, 2], [0, 2, 1]),
            (SocketSort::State, [1, 0, 2], [0, 2, 1]),
        ] {
            order.sort = sort;
            order.descending = true;
            order.sort_rows();
            assert_eq!(order.indices(), &descending, "{sort:?} descending");
            order.reverse();
            assert_eq!(order.indices(), &ascending, "{sort:?} ascending");
        }
        let index = order.indices.as_ptr();
        order.update(snapshot, None);
        assert_eq!(
            index,
            order.indices.as_ptr(),
            "unchanged data reuses its order"
        );
    }
}
#[test]
fn process_filter_matches_either_local_peer_without_reversing_the_row() {
    let snapshot = Arc::new(crate::monitor::socket_table::synthetic_local_socket_pair());
    let mut order = SocketOrder::default();
    order.update(Arc::clone(&snapshot), None);
    let primary = order.socket(0).unwrap().row_key().clone();
    for query in ["proc client", "proc SERVER", "proc worker"] {
        let filter = SocketFilter::parse(query).unwrap();
        order.update(Arc::clone(&snapshot), filter.as_ref());
        assert_eq!(order.shown_count(), 1);
        assert_eq!(order.socket(0).unwrap().row_key(), &primary);
        assert!(order.peer(order.indices()[0]).is_some());
    }
    order.update(
        snapshot,
        SocketFilter::parse("proc absent").unwrap().as_ref(),
    );
    assert_eq!(order.shown_count(), 0);
}
