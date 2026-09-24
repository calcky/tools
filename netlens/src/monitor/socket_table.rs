use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::collect::sock_diag::{
    self, CollectErrorKind, RawSocket, SocketFamily as RawFamily, SocketIdentity,
    SocketProtocol as RawProtocol, SocketTableCollection,
};
use crate::collect::socket_process::{self, ProcessScanStatus, ProcessScanUnavailable};
use crate::collect::SystemPaths;

use super::{CounterSpan, MonitorError, MonitorErrorCode, ProviderHealth};

const QUERY_COUNT: usize = 4;
const MAX_RETAINED_PER_QUERY: usize = 4_096;
const MAX_DISPLAYED_SOCKETS: usize = 4_096;

mod owners;
use owners::{OwnerService, OwnerSnapshot};
mod limits;
pub(crate) use limits::SocketLimitInterval;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

impl SocketFamily {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "4",
            Self::Ipv6 => "6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SocketFilter(super::connection_filter::ConnectionFilter);

impl SocketFilter {
    pub(crate) fn parse(query: &str) -> Result<Option<Self>, &'static str> {
        super::connection_filter::ConnectionFilter::parse_socket(query)
            .map(|filter| filter.map(Self))
    }

    pub(crate) fn query(&self) -> &str {
        self.0.query()
    }

    pub(crate) fn matches(&self, socket: &InetSocketSnapshot) -> bool {
        let local = (socket.local().address(), Some(socket.local().port()));
        let remote = (socket.remote().address(), Some(socket.remote().port()));
        self.0.matches(
            match socket.protocol() {
                SocketProtocol::Tcp => 6,
                SocketProtocol::Udp => 17,
            },
            local,
            remote,
            &[local, remote],
        )
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
enum SocketRowIdentity {
    Stable(SocketIdentity),
    Ephemeral { sequence: u64, ordinal: usize },
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SocketRowKey(SocketRowIdentity);

impl SocketRowKey {
    fn new(identity: &SocketIdentity, sequence: u64, ordinal: usize) -> Self {
        if identity.is_matchable() {
            Self(SocketRowIdentity::Stable(identity.clone()))
        } else {
            Self(SocketRowIdentity::Ephemeral { sequence, ordinal })
        }
    }

    pub(crate) const fn is_stable(&self) -> bool {
        matches!(self.0, SocketRowIdentity::Stable(_))
    }
}

impl fmt::Debug for SocketRowKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketRowKey(<redacted>)")
    }
}

impl SocketProtocol {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SocketEndpoint {
    address: IpAddr,
    port: u16,
}

impl SocketEndpoint {
    pub(crate) const fn address(&self) -> IpAddr {
        self.address
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Debug for SocketEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketEndpoint(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SocketOwner {
    pid: u32,
    command: Option<String>,
}

impl SocketOwner {
    pub(crate) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }
}

impl fmt::Debug for SocketOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketOwner(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketProcessCoverage {
    Complete,
    Pending,
    Partial {
        permission_denied_processes: usize,
        io_errors: usize,
        truncated: bool,
    },
    PermissionDenied,
    Unavailable,
}

impl SocketProcessCoverage {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Pending => "pending",
            Self::Partial { .. } => "partial",
            Self::PermissionDenied => "permission-denied",
            Self::Unavailable => "unavailable",
        }
    }

    pub(crate) const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub(crate) fn summary(self) -> String {
        match self {
            Self::Partial {
                permission_denied_processes,
                io_errors,
                truncated,
            } => format!(
                "partial denied={permission_denied_processes} io={io_errors} truncated={}",
                if truncated { "yes" } else { "no" }
            ),
            _ => self.label().to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketTraffic {
    segments: Option<u64>,
    bytes: Option<u64>,
    segment_interval: Option<CounterSpan>,
    byte_interval: Option<CounterSpan>,
}

impl SocketTraffic {
    pub(crate) const fn segments(self) -> Option<u64> {
        self.segments
    }

    pub(crate) const fn bytes(self) -> Option<u64> {
        self.bytes
    }

    pub(crate) fn segments_per_second(self) -> Option<f64> {
        self.segment_interval.map(CounterSpan::rate_per_second)
    }

    pub(crate) fn bits_per_second(self) -> Option<f64> {
        self.byte_interval
            .map(|interval| interval.rate_per_second() * 8.0)
    }

    fn interval_segments(self) -> u64 {
        self.segment_interval.map_or(0, CounterSpan::delta)
    }

    fn interval_bytes(self) -> u64 {
        self.byte_interval.map_or(0, CounterSpan::delta)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketMemoryDiagnostics {
    pub(crate) receive_allocated: u32,
    pub(crate) receive_limit: u32,
    pub(crate) send_allocated: u32,
    pub(crate) send_limit: u32,
    pub(crate) forward_allocated: u32,
    pub(crate) send_queued: u32,
    pub(crate) option_memory: u32,
    pub(crate) backlog: u32,
    pub(crate) drops: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketTcpDiagnostics {
    pub(crate) state: u8,
    pub(crate) congestion_state: u8,
    pub(crate) retransmit_timeouts: u8,
    pub(crate) probes: u8,
    pub(crate) backoff: u8,
    pub(crate) options: u8,
    pub(crate) send_window_scale: Option<u8>,
    pub(crate) receive_window_scale: Option<u8>,
    pub(crate) delivery_rate_app_limited: bool,
    pub(crate) retransmission_timeout_micros: u32,
    pub(crate) ack_timeout_micros: u32,
    pub(crate) send_mss_bytes: u32,
    pub(crate) receive_mss_bytes: u32,
    pub(crate) unacked_segments: u32,
    pub(crate) sacked_segments: u32,
    pub(crate) lost_segments: u32,
    pub(crate) retransmitted_segments: u32,
    pub(crate) fackets: u32,
    pub(crate) last_data_sent_millis: u32,
    pub(crate) last_ack_sent_millis: u32,
    pub(crate) last_data_received_millis: u32,
    pub(crate) last_ack_received_millis: u32,
    pub(crate) path_mtu_bytes: u32,
    pub(crate) receive_ssthresh_bytes: u32,
    pub(crate) rtt_micros: u32,
    pub(crate) rtt_variance_micros: u32,
    pub(crate) send_ssthresh_segments: u32,
    pub(crate) send_cwnd_segments: u32,
    pub(crate) advertised_mss_bytes: u32,
    pub(crate) reordering_segments: u32,
    pub(crate) receive_rtt_micros: u32,
    pub(crate) receive_space_bytes: u32,
    pub(crate) total_retransmitted_segments: u32,
    pub(crate) total_retransmit_interval: Option<CounterSpan>,
    pub(crate) pacing_rate_bytes_per_second: Option<u64>,
    pub(crate) max_pacing_rate_bytes_per_second: Option<u64>,
    pub(crate) notsent_bytes: Option<u32>,
    pub(crate) min_rtt_micros: Option<u32>,
    pub(crate) data_segments_in: Option<u32>,
    pub(crate) data_segments_out: Option<u32>,
    pub(crate) delivery_rate_bytes_per_second: Option<u64>,
    pub(crate) busy_time_micros: Option<u64>,
    pub(crate) receive_window_limited_micros: Option<u64>,
    pub(crate) send_buffer_limited_micros: Option<u64>,
    pub(crate) limit_interval: Option<SocketLimitInterval>,
    pub(crate) send_window_bytes: Option<u32>,
    pub(crate) receive_window_bytes: Option<u32>,
}

impl SocketTcpDiagnostics {
    pub(crate) fn congestion_window_bytes(self) -> u64 {
        u64::from(self.send_cwnd_segments).saturating_mul(u64::from(self.send_mss_bytes))
    }

    pub(crate) fn total_retransmits_per_second(self) -> Option<f64> {
        self.total_retransmit_interval
            .map(CounterSpan::rate_per_second)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct InetSocketSnapshot {
    row_key: SocketRowKey,
    family: SocketFamily,
    protocol: SocketProtocol,
    state: String,
    local: SocketEndpoint,
    remote: SocketEndpoint,
    bound_ifindex: u32,
    expires_millis: u32,
    receive_queue: u32,
    send_queue: u32,
    uid: u32,
    owners: Arc<[SocketOwner]>,
    congestion_algorithm: Option<String>,
    memory: Option<SocketMemoryDiagnostics>,
    tcp: Option<SocketTcpDiagnostics>,
    receive: SocketTraffic,
    send: SocketTraffic,
    drops: Option<u64>,
    drop_interval: Option<CounterSpan>,
    retransmits: u8,
    sort_inode: u32,
}

impl InetSocketSnapshot {
    pub(crate) const fn row_key(&self) -> &SocketRowKey {
        &self.row_key
    }

    pub(crate) const fn family(&self) -> SocketFamily {
        self.family
    }

    pub(crate) const fn protocol(&self) -> SocketProtocol {
        self.protocol
    }

    pub(crate) fn is_tcp_listener(&self) -> bool {
        self.protocol == SocketProtocol::Tcp && self.state == "LISTEN"
    }

    pub(crate) fn state(&self) -> &str {
        &self.state
    }

    pub(crate) const fn local(&self) -> &SocketEndpoint {
        &self.local
    }

    pub(crate) const fn remote(&self) -> &SocketEndpoint {
        &self.remote
    }

    pub(crate) const fn bound_ifindex(&self) -> u32 {
        self.bound_ifindex
    }

    pub(crate) const fn expires_millis(&self) -> u32 {
        self.expires_millis
    }

    pub(crate) const fn receive_queue(&self) -> u32 {
        self.receive_queue
    }

    pub(crate) const fn send_queue(&self) -> u32 {
        self.send_queue
    }

    pub(crate) const fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn owners(&self) -> &[SocketOwner] {
        &self.owners
    }

    pub(crate) const fn memory(&self) -> Option<SocketMemoryDiagnostics> {
        self.memory
    }

    pub(crate) fn congestion_algorithm(&self) -> Option<&str> {
        self.congestion_algorithm.as_deref()
    }

    pub(crate) const fn tcp(&self) -> Option<SocketTcpDiagnostics> {
        self.tcp
    }

    pub(crate) const fn owner_lookup_applicable(&self) -> bool {
        self.sort_inode != 0
    }

    pub(crate) const fn receive_traffic(&self) -> SocketTraffic {
        self.receive
    }

    pub(crate) const fn send_traffic(&self) -> SocketTraffic {
        self.send
    }

    pub(crate) const fn drops(&self) -> Option<u64> {
        self.drops
    }

    pub(crate) fn drops_per_second(&self) -> Option<f64> {
        self.drop_interval.map(CounterSpan::rate_per_second)
    }

    fn interval_bytes(&self) -> u64 {
        self.receive
            .interval_bytes()
            .saturating_add(self.send.interval_bytes())
    }

    fn interval_segments(&self) -> u64 {
        self.receive
            .interval_segments()
            .saturating_add(self.send.interval_segments())
    }
}

impl fmt::Debug for InetSocketSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InetSocketSnapshot")
            .field("family", &self.family)
            .field("protocol", &self.protocol)
            .field("state", &self.state)
            .field("owner_count", &self.owners.len())
            .field("receive", &self.receive)
            .field("send", &self.send)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SocketTableSnapshot {
    sequence: u64,
    attempted_at: Duration,
    collection_duration: Duration,
    health: ProviderHealth,
    completed_queries: usize,
    failed_queries: usize,
    observed_sockets: usize,
    truncated: bool,
    process_coverage: SocketProcessCoverage,
    process_map_age: Option<Duration>,
    process_map_refreshing: bool,
    scanned_processes: usize,
    scanned_fds: usize,
    sockets: Arc<[InetSocketSnapshot]>,
}

impl SocketTableSnapshot {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn attempted_at(&self) -> Duration {
        self.attempted_at
    }

    #[cfg(test)]
    pub(crate) const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub(crate) fn health(&self) -> &ProviderHealth {
        &self.health
    }

    pub(crate) const fn completed_queries(&self) -> usize {
        self.completed_queries
    }

    pub(crate) const fn failed_queries(&self) -> usize {
        self.failed_queries
    }

    pub(crate) const fn observed_sockets(&self) -> usize {
        self.observed_sockets
    }

    pub(crate) const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) const fn process_coverage(&self) -> SocketProcessCoverage {
        self.process_coverage
    }

    pub(crate) fn process_map_summary(&self) -> String {
        process_map_summary(
            self.process_coverage,
            self.process_map_age,
            self.process_map_refreshing,
        )
    }

    #[cfg(test)]
    pub(crate) const fn scanned_processes(&self) -> usize {
        self.scanned_processes
    }

    #[cfg(test)]
    pub(crate) const fn scanned_fds(&self) -> usize {
        self.scanned_fds
    }

    pub(crate) fn sockets(&self) -> &[InetSocketSnapshot] {
        &self.sockets
    }

    pub(crate) fn socket(&self, key: &SocketRowKey) -> Option<&InetSocketSnapshot> {
        self.sockets.iter().find(|socket| socket.row_key() == key)
    }
}

impl fmt::Debug for SocketTableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketTableSnapshot")
            .field("sequence", &self.sequence)
            .field("health", &self.health)
            .field("completed_queries", &self.completed_queries)
            .field("failed_queries", &self.failed_queries)
            .field("observed_sockets", &self.observed_sockets)
            .field("retained_sockets", &self.sockets.len())
            .field("truncated", &self.truncated)
            .field("process_coverage", &self.process_coverage)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct SocketDetailState {
    key: SocketRowKey,
    opened_at: Duration,
    last_at: Duration,
    last_sequence: u64,
    observed_latest: bool,
    last_observed: InetSocketSnapshot,
    process_map: String,
}

impl SocketDetailState {
    #[cfg(test)]
    pub(crate) fn start(snapshot: &SocketTableSnapshot, key: SocketRowKey) -> Option<Self> {
        Self::start_at(snapshot, snapshot, key, snapshot.attempted_at())
    }

    pub(crate) fn start_at(
        selected_snapshot: &SocketTableSnapshot,
        initial_snapshot: &SocketTableSnapshot,
        key: SocketRowKey,
        opened_at: Duration,
    ) -> Option<Self> {
        let selected_socket = selected_snapshot.socket(&key)?.clone();
        let socket = initial_snapshot.socket(&key);
        let opened_at = opened_at.max(initial_snapshot.attempted_at());
        Some(Self {
            key,
            opened_at,
            last_at: opened_at,
            last_sequence: initial_snapshot.sequence(),
            observed_latest: socket.is_some(),
            last_observed: socket.cloned().unwrap_or(selected_socket),
            process_map: if socket.is_some() {
                initial_snapshot.process_map_summary()
            } else {
                selected_snapshot.process_map_summary()
            },
        })
    }

    pub(crate) fn record(&mut self, snapshot: &SocketTableSnapshot) {
        if snapshot.sequence() <= self.last_sequence {
            return;
        }
        let at = snapshot.attempted_at().max(self.last_at);
        let socket = snapshot.socket(&self.key);
        self.observed_latest = socket.is_some();
        if let Some(socket) = socket {
            self.last_observed = socket.clone();
            self.process_map = snapshot.process_map_summary();
        }
        self.last_at = at;
        self.last_sequence = snapshot.sequence();
    }

    pub(crate) const fn key(&self) -> &SocketRowKey {
        &self.key
    }

    pub(crate) const fn socket(&self) -> &InetSocketSnapshot {
        &self.last_observed
    }

    pub(crate) fn process_map_summary(&self) -> &str {
        &self.process_map
    }

    pub(crate) const fn observed_latest(&self) -> bool {
        self.observed_latest
    }

    #[cfg(test)]
    pub(crate) const fn opened_at(&self) -> Duration {
        self.opened_at
    }

    #[cfg(test)]
    pub(crate) const fn last_at(&self) -> Duration {
        self.last_at
    }
}

impl fmt::Debug for SocketDetailState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketDetailState")
            .field("opened_at", &self.opened_at)
            .field("last_at", &self.last_at)
            .field("last_sequence", &self.last_sequence)
            .field("observed_latest", &self.observed_latest)
            .finish()
    }
}

#[derive(Default)]
struct SocketProjector {
    previous: BTreeMap<SocketIdentity, PreviousObservation>,
}

#[derive(Clone, Copy)]
struct PreviousObservation {
    completed_at: Instant,
    counters: PreviousCounters,
}

#[derive(Clone, Copy)]
struct PreviousCounters {
    receive_segments: Option<u64>,
    receive_bytes: Option<u64>,
    send_segments: Option<u64>,
    send_bytes: Option<u64>,
    total_retransmitted_segments: Option<u64>,
    drops: Option<u64>,
    busy_micros: Option<u64>,
    rwnd_micros: Option<u64>,
    sndbuf_micros: Option<u64>,
}

struct BoundedCollection {
    collection: SocketTableCollection,
    observed_sockets: usize,
    truncated: bool,
}

impl BoundedCollection {
    fn new(mut collection: SocketTableCollection) -> Self {
        let mut observed_sockets = 0_usize;
        let mut truncated = false;
        for query in &mut collection.queries {
            observed_sockets = observed_sockets.saturating_add(query.observed_sockets);
            truncated |= query.truncated;
            if let Ok(sockets) = &mut query.outcome {
                if sockets.len() > MAX_RETAINED_PER_QUERY {
                    sockets.truncate(MAX_RETAINED_PER_QUERY);
                    truncated = true;
                }
            }
        }
        Self {
            collection,
            observed_sockets,
            truncated,
        }
    }

    fn owner_targets(&self) -> BTreeSet<SocketIdentity> {
        self.collection
            .queries
            .iter()
            .filter_map(|query| query.outcome.as_ref().ok())
            .flat_map(|sockets| sockets.iter())
            .map(|socket| &socket.identity)
            .filter(|identity| identity.is_matchable())
            .cloned()
            .collect()
    }
}

impl SocketProjector {
    fn project(
        &mut self,
        sequence: u64,
        attempted_at: Duration,
        collection_duration: Duration,
        bounded: BoundedCollection,
        process_scan: OwnerSnapshot,
    ) -> Arc<SocketTableSnapshot> {
        let process_coverage = process_scan.coverage;
        let mut next = BTreeMap::new();
        let mut completed_queries = 0_usize;
        let mut errors = Vec::new();
        let mut sockets = Vec::new();

        for query in bounded.collection.queries {
            let completed_at = query.completed_at;
            match query.outcome {
                Ok(rows) => {
                    completed_queries = completed_queries.saturating_add(1);
                    for row in rows {
                        let before = row
                            .identity
                            .is_matchable()
                            .then(|| self.previous.get(&row.identity))
                            .flatten();
                        let elapsed = before
                            .and_then(|before| {
                                completed_at.checked_duration_since(before.completed_at)
                            })
                            .filter(|elapsed| *elapsed > Duration::ZERO);
                        let counters = raw_counters(&row);
                        let projected = project_socket(
                            &row,
                            before.map(|before| &before.counters),
                            elapsed,
                            process_scan.owners(&row.identity),
                            sequence,
                            sockets.len(),
                        );
                        if row.identity.is_matchable() {
                            next.insert(
                                row.identity.clone(),
                                PreviousObservation {
                                    completed_at,
                                    counters,
                                },
                            );
                        }
                        sockets.push(projected);
                    }
                }
                Err(error) => errors.push(error),
            }
        }

        sockets.sort_by(compare_socket_activity);
        let truncated = bounded.truncated || sockets.len() > MAX_DISPLAYED_SOCKETS;
        sockets.truncate(MAX_DISPLAYED_SOCKETS);
        let health = collection_health(completed_queries, &errors, truncated, process_coverage);
        if completed_queries == 0 {
            self.previous.clear();
        } else {
            self.previous = next;
        }

        Arc::new(SocketTableSnapshot {
            sequence,
            attempted_at,
            collection_duration,
            health,
            completed_queries,
            failed_queries: errors.len(),
            observed_sockets: bounded.observed_sockets,
            truncated,
            process_coverage,
            process_map_age: process_scan.age,
            process_map_refreshing: process_scan.refreshing,
            scanned_processes: process_scan.scanned_processes,
            scanned_fds: process_scan.scanned_fds,
            sockets: sockets.into(),
        })
    }
}

fn connection_tcp_info(socket: &RawSocket) -> Option<sock_diag::SocketTcpInfo> {
    if socket.protocol == RawProtocol::Tcp && !matches!(socket.state, 6 | 10) {
        socket.tcp_info
    } else {
        None
    }
}

fn raw_counters(socket: &RawSocket) -> PreviousCounters {
    let tcp = connection_tcp_info(socket);
    PreviousCounters {
        receive_segments: tcp.and_then(|info| info.segments_in.map(u64::from)),
        receive_bytes: tcp.and_then(|info| info.bytes_received),
        send_segments: tcp.and_then(|info| info.segments_out.map(u64::from)),
        send_bytes: tcp.and_then(|info| info.bytes_acked),
        total_retransmitted_segments: tcp.map(|info| u64::from(info.total_retransmitted_segments)),
        drops: socket.memory.map(|memory| u64::from(memory.drops)),
        busy_micros: tcp.and_then(|info| info.busy_time_micros),
        rwnd_micros: tcp.and_then(|info| info.receive_window_limited_micros),
        sndbuf_micros: tcp.and_then(|info| info.send_buffer_limited_micros),
    }
}

fn project_socket(
    socket: &RawSocket,
    previous: Option<&PreviousCounters>,
    elapsed: Option<Duration>,
    owners: &[socket_process::SocketProcess],
    sequence: u64,
    ordinal: usize,
) -> InetSocketSnapshot {
    let counters = raw_counters(socket);
    let tcp_info = connection_tcp_info(socket);
    InetSocketSnapshot {
        row_key: SocketRowKey::new(&socket.identity, sequence, ordinal),
        family: match socket.family {
            RawFamily::Ipv4 => SocketFamily::Ipv4,
            RawFamily::Ipv6 => SocketFamily::Ipv6,
        },
        protocol: match socket.protocol {
            RawProtocol::Tcp => SocketProtocol::Tcp,
            RawProtocol::Udp => SocketProtocol::Udp,
        },
        state: socket_state(socket.protocol, socket.state),
        local: SocketEndpoint {
            address: socket.local.address,
            port: socket.local.port,
        },
        remote: SocketEndpoint {
            address: socket.remote.address,
            port: socket.remote.port,
        },
        bound_ifindex: socket.bound_ifindex,
        expires_millis: socket.expires_millis,
        receive_queue: socket.receive_queue,
        send_queue: socket.send_queue,
        uid: socket.uid,
        owners: owners
            .iter()
            .map(|owner| SocketOwner {
                pid: owner.pid,
                command: owner.command.clone(),
            })
            .collect::<Vec<_>>()
            .into(),
        congestion_algorithm: tcp_info.and(socket.congestion_algorithm.clone()),
        memory: socket.memory.map(project_socket_memory),
        tcp: tcp_info.map(|info| {
            let mut diagnostics = project_tcp_diagnostics(
                info,
                project_counter(
                    counters.total_retransmitted_segments,
                    previous.and_then(|value| value.total_retransmitted_segments),
                    elapsed,
                ),
            );
            diagnostics.limit_interval = SocketLimitInterval::between(&counters, previous, elapsed);
            diagnostics
        }),
        receive: SocketTraffic {
            segments: counters.receive_segments,
            bytes: counters.receive_bytes,
            segment_interval: project_counter(
                counters.receive_segments,
                previous.and_then(|value| value.receive_segments),
                elapsed,
            ),
            byte_interval: project_counter(
                counters.receive_bytes,
                previous.and_then(|value| value.receive_bytes),
                elapsed,
            ),
        },
        send: SocketTraffic {
            segments: counters.send_segments,
            bytes: counters.send_bytes,
            segment_interval: project_counter(
                counters.send_segments,
                previous.and_then(|value| value.send_segments),
                elapsed,
            ),
            byte_interval: project_counter(
                counters.send_bytes,
                previous.and_then(|value| value.send_bytes),
                elapsed,
            ),
        },
        drops: counters.drops,
        drop_interval: project_counter(
            counters.drops,
            previous.and_then(|value| value.drops),
            elapsed,
        ),
        retransmits: socket.retransmits,
        sort_inode: socket.identity.inode(),
    }
}

fn project_socket_memory(memory: sock_diag::SocketMemory) -> SocketMemoryDiagnostics {
    SocketMemoryDiagnostics {
        receive_allocated: memory.receive_allocated,
        receive_limit: memory.receive_limit,
        send_allocated: memory.send_allocated,
        send_limit: memory.send_limit,
        forward_allocated: memory.forward_allocated,
        send_queued: memory.send_queued,
        option_memory: memory.option_memory,
        backlog: memory.backlog,
        drops: memory.drops,
    }
}

fn project_tcp_diagnostics(
    info: sock_diag::SocketTcpInfo,
    total_retransmit_interval: Option<CounterSpan>,
) -> SocketTcpDiagnostics {
    SocketTcpDiagnostics {
        state: info.state,
        congestion_state: info.congestion_state,
        retransmit_timeouts: info.retransmit_timeouts,
        probes: info.probes,
        backoff: info.backoff,
        options: info.options,
        send_window_scale: info.send_window_scale,
        receive_window_scale: info.receive_window_scale,
        delivery_rate_app_limited: info.delivery_rate_app_limited,
        retransmission_timeout_micros: info.retransmission_timeout_micros,
        ack_timeout_micros: info.ack_timeout_micros,
        send_mss_bytes: info.send_mss_bytes,
        receive_mss_bytes: info.receive_mss_bytes,
        unacked_segments: info.unacked_segments,
        sacked_segments: info.sacked_segments,
        lost_segments: info.lost_segments,
        retransmitted_segments: info.retransmitted_segments,
        fackets: info.fackets,
        last_data_sent_millis: info.last_data_sent_millis,
        last_ack_sent_millis: info.last_ack_sent_millis,
        last_data_received_millis: info.last_data_received_millis,
        last_ack_received_millis: info.last_ack_received_millis,
        path_mtu_bytes: info.path_mtu_bytes,
        receive_ssthresh_bytes: info.receive_ssthresh_bytes,
        rtt_micros: info.rtt_micros,
        rtt_variance_micros: info.rtt_variance_micros,
        send_ssthresh_segments: info.send_ssthresh_segments,
        send_cwnd_segments: info.send_cwnd_segments,
        advertised_mss_bytes: info.advertised_mss_bytes,
        reordering_segments: info.reordering_segments,
        receive_rtt_micros: info.receive_rtt_micros,
        receive_space_bytes: info.receive_space_bytes,
        total_retransmitted_segments: info.total_retransmitted_segments,
        total_retransmit_interval,
        pacing_rate_bytes_per_second: info
            .pacing_rate_bytes_per_second
            .filter(|value| *value != u64::MAX),
        max_pacing_rate_bytes_per_second: info
            .max_pacing_rate_bytes_per_second
            .filter(|value| *value != u64::MAX),
        notsent_bytes: info.notsent_bytes,
        min_rtt_micros: info.min_rtt_micros.filter(|value| *value != u32::MAX),
        data_segments_in: info.data_segments_in,
        data_segments_out: info.data_segments_out,
        delivery_rate_bytes_per_second: info
            .delivery_rate_bytes_per_second
            .filter(|value| *value > 0),
        busy_time_micros: info.busy_time_micros,
        receive_window_limited_micros: info.receive_window_limited_micros,
        send_buffer_limited_micros: info.send_buffer_limited_micros,
        limit_interval: None,
        send_window_bytes: info.send_window_bytes,
        receive_window_bytes: info.receive_window_bytes,
    }
}

fn project_counter(
    current: Option<u64>,
    previous: Option<u64>,
    elapsed: Option<Duration>,
) -> Option<CounterSpan> {
    let delta = current?.checked_sub(previous?)?;
    CounterSpan::new(delta, elapsed?).ok()
}

fn compare_socket_activity(left: &InetSocketSnapshot, right: &InetSocketSnapshot) -> Ordering {
    right
        .interval_bytes()
        .cmp(&left.interval_bytes())
        .then_with(|| right.interval_segments().cmp(&left.interval_segments()))
        .then_with(|| left.protocol.cmp(&right.protocol))
        .then_with(|| left.family.cmp(&right.family))
        .then_with(|| left.local.cmp(&right.local))
        .then_with(|| left.remote.cmp(&right.remote))
        .then_with(|| left.sort_inode.cmp(&right.sort_inode))
}

fn socket_state(protocol: RawProtocol, state: u8) -> String {
    let state = match (protocol, state) {
        (RawProtocol::Udp, 1) => "CONNECTED",
        (RawProtocol::Udp, 7) => "UNCONN",
        (RawProtocol::Tcp, 1) => "ESTABLISHED",
        (RawProtocol::Tcp, 2) => "SYN_SENT",
        (RawProtocol::Tcp, 3) => "SYN_RECV",
        (RawProtocol::Tcp, 4) => "FIN_WAIT1",
        (RawProtocol::Tcp, 5) => "FIN_WAIT2",
        (RawProtocol::Tcp, 6) => "TIME_WAIT",
        (RawProtocol::Tcp, 7) => "CLOSE",
        (RawProtocol::Tcp, 8) => "CLOSE_WAIT",
        (RawProtocol::Tcp, 9) => "LAST_ACK",
        (RawProtocol::Tcp, 10) => "LISTEN",
        (RawProtocol::Tcp, 11) => "CLOSING",
        (RawProtocol::Tcp, 12) => "NEW_SYN_RECV",
        _ => return format!("STATE#{state}"),
    };
    state.to_owned()
}

fn project_process_coverage(status: ProcessScanStatus) -> SocketProcessCoverage {
    match status {
        ProcessScanStatus::Complete => SocketProcessCoverage::Complete,
        ProcessScanStatus::Partial {
            permission_denied_processes,
            io_errors,
            truncated,
        } => SocketProcessCoverage::Partial {
            permission_denied_processes,
            io_errors,
            truncated,
        },
        ProcessScanStatus::Unavailable(ProcessScanUnavailable::PermissionDenied) => {
            SocketProcessCoverage::PermissionDenied
        }
        ProcessScanStatus::Unavailable(ProcessScanUnavailable::Io) => {
            SocketProcessCoverage::Unavailable
        }
    }
}

fn process_map_summary(
    coverage: SocketProcessCoverage,
    age: Option<Duration>,
    refreshing: bool,
) -> String {
    format!(
        "{}{}{}",
        coverage.summary(),
        age.map_or_else(String::new, |age| format!(" age {:.1}s", age.as_secs_f64())),
        if refreshing { " refreshing" } else { "" }
    )
}

fn collection_health(
    completed_queries: usize,
    errors: &[sock_diag::CollectError],
    truncated: bool,
    process_coverage: SocketProcessCoverage,
) -> ProviderHealth {
    if completed_queries == QUERY_COUNT
        && errors.is_empty()
        && !truncated
        && matches!(
            process_coverage,
            SocketProcessCoverage::Complete | SocketProcessCoverage::Pending
        )
    {
        return ProviderHealth::Fresh;
    }

    let primary_error = errors
        .iter()
        .max_by_key(|error| collect_error_priority(error.kind()));
    let warning_code = collection_warning_code(
        primary_error.map(sock_diag::CollectError::kind),
        truncated,
        process_coverage,
    );
    let primary_diagnostic = primary_error
        .map(|error| format!("; primary failure: {error}"))
        .unwrap_or_default();

    if completed_queries > 0 {
        let diagnostic = format!(
            "socket queries {completed_queries}/{QUERY_COUNT}; failed {}; truncated {}; process map {}{primary_diagnostic}",
            errors.len(),
            if truncated { "yes" } else { "no" },
            process_coverage.summary(),
        );
        return ProviderHealth::Partial {
            warning: monitor_error(warning_code, diagnostic),
        };
    }

    let code = if !errors.is_empty()
        && errors
            .iter()
            .all(|error| error.kind() == CollectErrorKind::PermissionDenied)
    {
        MonitorErrorCode::PermissionDenied
    } else if !errors.is_empty()
        && errors
            .iter()
            .all(|error| error.kind() == CollectErrorKind::Unsupported)
    {
        MonitorErrorCode::Unsupported
    } else {
        warning_code
    };
    let error = monitor_error(
        code,
        format!(
            "all socket diagnostic queries failed ({}){primary_diagnostic}",
            errors.len()
        ),
    );
    match code {
        MonitorErrorCode::PermissionDenied => ProviderHealth::PermissionDenied { reason: error },
        MonitorErrorCode::Unsupported => ProviderHealth::Unsupported { reason: error },
        _ => ProviderHealth::Error { error },
    }
}

const fn collection_warning_code(
    primary_error: Option<CollectErrorKind>,
    truncated: bool,
    process_coverage: SocketProcessCoverage,
) -> MonitorErrorCode {
    if let Some(kind) = primary_error {
        collect_error_code(kind)
    } else if truncated {
        MonitorErrorCode::CardinalityLimit
    } else {
        match process_coverage_error_code(process_coverage) {
            Some(code) => code,
            None => MonitorErrorCode::Internal,
        }
    }
}

const fn collect_error_code(kind: CollectErrorKind) -> MonitorErrorCode {
    match kind {
        CollectErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
        CollectErrorKind::Unsupported => MonitorErrorCode::Unsupported,
        CollectErrorKind::Io => MonitorErrorCode::Io,
        CollectErrorKind::Loss => MonitorErrorCode::OutputLimit,
        CollectErrorKind::Interrupted => MonitorErrorCode::Timeout,
        CollectErrorKind::Malformed => MonitorErrorCode::SchemaMismatch,
    }
}

const fn collect_error_priority(kind: CollectErrorKind) -> u8 {
    match kind {
        CollectErrorKind::Malformed => 6,
        CollectErrorKind::Loss => 5,
        CollectErrorKind::Interrupted => 4,
        CollectErrorKind::PermissionDenied => 3,
        CollectErrorKind::Io => 2,
        CollectErrorKind::Unsupported => 1,
    }
}

const fn process_coverage_error_code(coverage: SocketProcessCoverage) -> Option<MonitorErrorCode> {
    match coverage {
        SocketProcessCoverage::Complete | SocketProcessCoverage::Pending => None,
        SocketProcessCoverage::Partial {
            truncated: true, ..
        } => Some(MonitorErrorCode::CardinalityLimit),
        SocketProcessCoverage::Partial {
            permission_denied_processes,
            ..
        } if permission_denied_processes > 0 => Some(MonitorErrorCode::PermissionDenied),
        SocketProcessCoverage::Partial { .. } | SocketProcessCoverage::Unavailable => {
            Some(MonitorErrorCode::Io)
        }
        SocketProcessCoverage::PermissionDenied => Some(MonitorErrorCode::PermissionDenied),
    }
}

fn monitor_error(code: MonitorErrorCode, diagnostic: impl fmt::Display) -> MonitorError {
    let mut diagnostic = diagnostic.to_string();
    diagnostic.retain(|character| character.is_ascii_graphic() || character == ' ');
    diagnostic.truncate(256);
    MonitorError::new(code, diagnostic)
        .expect("socket table diagnostics are bounded printable ASCII")
}

struct LatestState {
    snapshot: Option<Arc<SocketTableSnapshot>>,
    closed: bool,
    error: Option<String>,
}

struct LatestSlot {
    state: Mutex<LatestState>,
    changed: Condvar,
}

impl LatestSlot {
    fn new() -> Self {
        Self {
            state: Mutex::new(LatestState {
                snapshot: None,
                closed: false,
                error: None,
            }),
            changed: Condvar::new(),
        }
    }

    fn publish(&self, snapshot: Arc<SocketTableSnapshot>) {
        let mut state = self
            .state
            .lock()
            .expect("socket table latest mutex poisoned");
        state.snapshot = Some(snapshot);
        self.changed.notify_all();
    }

    fn close(&self, error: Option<String>) {
        let mut state = self
            .state
            .lock()
            .expect("socket table latest mutex poisoned");
        state.closed = true;
        state.error = error;
        self.changed.notify_all();
    }
}

pub(crate) struct SocketTableSession {
    latest: Arc<LatestSlot>,
    cancelled: Arc<AtomicBool>,
    wake: mpsc::SyncSender<()>,
    worker: Option<JoinHandle<()>>,
}

impl SocketTableSession {
    pub(crate) fn start(interval: Duration, paths: SystemPaths) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !interval.is_zero(),
            "socket table interval must be positive"
        );
        let (wake, wake_receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let latest = Arc::new(LatestSlot::new());
        let worker_latest = Arc::clone(&latest);
        let worker_cancelled = Arc::clone(&cancelled);
        let owners =
            OwnerService::start(paths.proc_root.clone()).context("spawn socket owner worker")?;
        let worker = thread::Builder::new()
            .name("netlens-socket-table".to_owned())
            .spawn(move || {
                run_worker(
                    interval,
                    paths,
                    &worker_cancelled,
                    wake_receiver,
                    &worker_latest,
                    owners,
                );
            })
            .context("spawn socket table worker")?;
        Ok(Self {
            latest,
            cancelled,
            wake,
            worker: Some(worker),
        })
    }

    pub(crate) fn wait_after(
        &self,
        sequence: u64,
        timeout: Duration,
    ) -> anyhow::Result<Option<Arc<SocketTableSnapshot>>> {
        let state = self
            .latest
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("socket table latest mutex poisoned"))?;
        let (state, _) = self
            .latest
            .changed
            .wait_timeout_while(state, timeout, |state| {
                !state.closed
                    && state
                        .snapshot
                        .as_ref()
                        .is_none_or(|snapshot| snapshot.sequence <= sequence)
            })
            .map_err(|_| anyhow::anyhow!("socket table latest mutex poisoned"))?;
        if let Some(snapshot) = state
            .snapshot
            .as_ref()
            .filter(|snapshot| snapshot.sequence > sequence)
            .cloned()
        {
            return Ok(Some(snapshot));
        }
        if state.closed {
            if let Some(error) = &state.error {
                anyhow::bail!("socket table worker stopped: {error}");
            }
        }
        Ok(None)
    }

    pub(crate) fn shutdown(mut self) -> anyhow::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> anyhow::Result<()> {
        self.cancelled.store(true, AtomicOrdering::Release);
        let _ = self.wake.try_send(());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("socket table worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for SocketTableSession {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run_worker(
    interval: Duration,
    paths: SystemPaths,
    cancelled: &AtomicBool,
    wake: mpsc::Receiver<()>,
    latest: &LatestSlot,
    mut owners: OwnerService,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session_start = Instant::now();
        let mut deadline = session_start;
        let mut sequence = 0_u64;
        let mut projector = SocketProjector::default();
        let mut diagnostic = sock_diag::Context::default();
        loop {
            if cancelled.load(AtomicOrdering::Acquire) {
                break;
            }
            let started = Instant::now();
            let Some(collection) = diagnostic.collect_table(Some(cancelled)) else {
                break;
            };
            let counters_finished = Instant::now();
            let bounded = BoundedCollection::new(collection);
            let process_scan =
                owners.snapshot(bounded.owner_targets(), &paths.proc_root, counters_finished);
            let finished = Instant::now();
            let attempted_at = counters_finished.saturating_duration_since(session_start);
            let collection_duration = finished
                .saturating_duration_since(started)
                .min(finished.saturating_duration_since(session_start));
            if cancelled.load(AtomicOrdering::Acquire) {
                break;
            }
            sequence = sequence.saturating_add(1);
            latest.publish(projector.project(
                sequence,
                attempted_at,
                collection_duration,
                bounded,
                process_scan,
            ));

            deadline += interval;
            while deadline <= Instant::now() {
                deadline += interval;
            }
            match wake.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }));
    latest.close(result.err().map(|_| "worker panicked".to_owned()));
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_snapshot() -> Arc<SocketTableSnapshot> {
    synthetic_socket_table_snapshot_at(2)
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_snapshot_at(sequence: u64) -> Arc<SocketTableSnapshot> {
    let traffic = |segments, bytes, segment_delta, byte_delta| SocketTraffic {
        segments: Some(segments),
        bytes: Some(bytes),
        segment_interval: CounterSpan::new(segment_delta, Duration::from_secs(1)).ok(),
        byte_interval: CounterSpan::new(byte_delta, Duration::from_secs(1)).ok(),
    };
    Arc::new(SocketTableSnapshot {
        sequence,
        attempted_at: Duration::from_secs(sequence),
        collection_duration: Duration::from_millis(3),
        health: ProviderHealth::Fresh,
        completed_queries: QUERY_COUNT,
        failed_queries: 0,
        observed_sockets: 2,
        truncated: false,
        process_coverage: SocketProcessCoverage::Complete,
        process_map_age: Some(Duration::ZERO),
        process_map_refreshing: false,
        scanned_processes: 2,
        scanned_fds: 8,
        sockets: vec![
            InetSocketSnapshot {
                row_key: SocketRowKey::new(
                    &SocketIdentity::synthetic(RawFamily::Ipv4, RawProtocol::Tcp, 7),
                    sequence,
                    0,
                ),
                family: SocketFamily::Ipv4,
                protocol: SocketProtocol::Tcp,
                state: "ESTABLISHED".to_owned(),
                local: SocketEndpoint {
                    address: "192.0.2.10".parse().unwrap(),
                    port: 42_000,
                },
                remote: SocketEndpoint {
                    address: "198.51.100.20".parse().unwrap(),
                    port: 443,
                },
                bound_ifindex: 2,
                expires_millis: 0,
                receive_queue: 128,
                send_queue: 256,
                uid: 1_000,
                owners: vec![SocketOwner {
                    pid: 1234,
                    command: Some("client-worker".to_owned()),
                }]
                .into(),
                congestion_algorithm: Some("cubic".to_owned()),
                memory: Some(SocketMemoryDiagnostics {
                    receive_allocated: 4_096,
                    receive_limit: 131_072,
                    send_allocated: 8_192,
                    send_limit: 262_144,
                    forward_allocated: 0,
                    send_queued: 256,
                    option_memory: 2_048,
                    backlog: 0,
                    drops: 1,
                }),
                tcp: Some(project_tcp_diagnostics(
                    sock_diag::SocketTcpInfo {
                        state: 1,
                        send_window_scale: Some(7),
                        receive_window_scale: Some(7),
                        retransmission_timeout_micros: 204_000,
                        ack_timeout_micros: 40_000,
                        send_mss_bytes: 1_448,
                        receive_mss_bytes: 1_448,
                        unacked_segments: 2,
                        send_ssthresh_segments: 32,
                        send_cwnd_segments: 20,
                        advertised_mss_bytes: 1_448,
                        path_mtu_bytes: 1_500,
                        rtt_micros: 12_500,
                        rtt_variance_micros: 1_200,
                        receive_rtt_micros: 13_000,
                        receive_space_bytes: 65_535,
                        receive_ssthresh_bytes: 524_288,
                        total_retransmitted_segments: 3,
                        options: 0x07,
                        reordering_segments: 3,
                        pacing_rate_bytes_per_second: Some(2_000_000),
                        max_pacing_rate_bytes_per_second: Some(4_000_000),
                        min_rtt_micros: Some(10_500),
                        data_segments_in: Some(80),
                        data_segments_out: Some(160),
                        delivery_rate_bytes_per_second: Some(1_500_000),
                        busy_time_micros: Some(900_000),
                        receive_window_limited_micros: Some(100_000),
                        send_buffer_limited_micros: Some(50_000),
                        send_window_bytes: Some(262_140),
                        receive_window_bytes: Some(131_070),
                        ..sock_diag::SocketTcpInfo::default()
                    },
                    CounterSpan::new(1, Duration::from_secs(1)).ok(),
                )),
                receive: traffic(100, 10_000, 10, 1_000),
                send: traffic(200, 20_000, 20, 2_000),
                drops: Some(1),
                drop_interval: CounterSpan::new(1, Duration::from_secs(1)).ok(),
                retransmits: 0,
                sort_inode: 7,
            },
            InetSocketSnapshot {
                row_key: SocketRowKey::new(
                    &SocketIdentity::synthetic(RawFamily::Ipv6, RawProtocol::Udp, 8),
                    sequence,
                    1,
                ),
                family: SocketFamily::Ipv6,
                protocol: SocketProtocol::Udp,
                state: "UNCONN".to_owned(),
                local: SocketEndpoint {
                    address: "2001:db8::1".parse().unwrap(),
                    port: 53,
                },
                remote: SocketEndpoint {
                    address: "::".parse().unwrap(),
                    port: 0,
                },
                bound_ifindex: 0,
                expires_millis: 0,
                receive_queue: 64,
                send_queue: 0,
                uid: 53,
                owners: Arc::from([]),
                congestion_algorithm: None,
                memory: Some(SocketMemoryDiagnostics {
                    receive_allocated: 64,
                    receive_limit: 212_992,
                    send_allocated: 0,
                    send_limit: 212_992,
                    forward_allocated: 0,
                    send_queued: 0,
                    option_memory: 0,
                    backlog: 0,
                    drops: 0,
                }),
                tcp: None,
                receive: SocketTraffic {
                    segments: None,
                    bytes: None,
                    segment_interval: None,
                    byte_interval: None,
                },
                send: SocketTraffic {
                    segments: None,
                    bytes: None,
                    segment_interval: None,
                    byte_interval: None,
                },
                drops: Some(0),
                drop_interval: CounterSpan::new(0, Duration::from_secs(1)).ok(),
                retransmits: 0,
                sort_inode: 8,
            },
        ]
        .into(),
    })
}

#[cfg(test)]
pub(crate) fn synthetic_socket_sort_snapshot(sequence: u64) -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(sequence)).clone();
    let mut sockets = snapshot.sockets.to_vec();
    let mut second = sockets[0].clone();
    second.row_key = SocketRowKey::new(
        &SocketIdentity::synthetic(RawFamily::Ipv4, RawProtocol::Tcp, 9),
        sequence,
        2,
    );
    second.local.port = 43_000;
    second.receive_queue = 64;
    second.send_queue = 512;
    sockets[0].receive.bytes = Some(u64::MAX - 1);
    sockets[0].send.bytes = Some(100);
    second.receive.bytes = Some(u64::MAX);
    second.send.bytes = Some(99);
    second.receive.byte_interval = CounterSpan::new(4_000, Duration::from_secs(1)).ok();
    second.send.byte_interval = CounterSpan::new(500, Duration::from_secs(1)).ok();
    second.receive.segment_interval = CounterSpan::new(100, Duration::from_secs(1)).ok();
    second.send.segment_interval = CounterSpan::new(1, Duration::from_secs(1)).ok();
    sockets.push(second);
    snapshot.observed_sockets = sockets.len();
    snapshot.sockets = sockets.into();
    Arc::new(snapshot)
}

#[cfg(test)]
pub(crate) fn synthetic_truncated_socket_snapshot() -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(2)).clone();
    snapshot.truncated = true;
    snapshot.observed_sockets = 10_000;
    Arc::new(snapshot)
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_snapshot_reordered_at(
    sequence: u64,
) -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(sequence)).clone();
    let mut sockets = snapshot.sockets.to_vec();
    sockets.reverse();
    snapshot.sockets = sockets.into();
    Arc::new(snapshot)
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_snapshot_with_rtt_at(
    sequence: u64,
    rtt_micros: u32,
) -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(sequence)).clone();
    let mut sockets = snapshot.sockets.to_vec();
    if let Some(mut tcp) = sockets[0].tcp {
        tcp.rtt_micros = rtt_micros;
        sockets[0].tcp = Some(tcp);
    }
    snapshot.sockets = sockets.into();
    Arc::new(snapshot)
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_listener_snapshot_at(
    sequence: u64,
) -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(sequence)).clone();
    let mut sockets = snapshot.sockets.to_vec();
    let listener = &mut sockets[0];
    listener.state = "LISTEN".to_owned();
    listener.receive_queue = 11;
    listener.send_queue = 128;
    listener.congestion_algorithm = None;
    listener.tcp = None;
    if let Some(mut memory) = listener.memory {
        memory.forward_allocated = 0;
        memory.option_memory = 0;
        memory.backlog = 0;
        listener.memory = Some(memory);
    }
    listener.receive = SocketTraffic {
        segments: None,
        bytes: None,
        segment_interval: None,
        byte_interval: None,
    };
    listener.send = SocketTraffic {
        segments: None,
        bytes: None,
        segment_interval: None,
        byte_interval: None,
    };
    snapshot.sockets = sockets.into();
    Arc::new(snapshot)
}

#[cfg(test)]
pub(crate) fn synthetic_socket_table_snapshot_without_tcp_at(
    sequence: u64,
) -> Arc<SocketTableSnapshot> {
    let mut snapshot = (*synthetic_socket_table_snapshot_at(sequence)).clone();
    snapshot.sockets = snapshot
        .sockets
        .iter()
        .filter(|socket| socket.protocol() != SocketProtocol::Tcp)
        .cloned()
        .collect::<Vec<_>>()
        .into();
    snapshot.observed_sockets = snapshot.sockets.len();
    Arc::new(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_filter_accepts_conntrack_style_terms() {
        let filter = SocketFilter::parse("host=192.0.2.1 port=443 proto=tcp").unwrap();
        assert_eq!(
            filter.as_ref().map(SocketFilter::query),
            Some("host=192.0.2.1 port=443 proto=tcp")
        );
        assert!(SocketFilter::parse("").unwrap().is_none());
        assert!(SocketFilter::parse("proto=icmp").is_err());
        assert!(SocketFilter::parse("port=70000").is_err());
    }

    fn raw_socket(
        seed: u32,
        protocol: RawProtocol,
        state: u8,
        receive_segments: u32,
        receive_bytes: u64,
        send_segments: u32,
        send_bytes: u64,
    ) -> RawSocket {
        let family = RawFamily::Ipv4;
        RawSocket {
            identity: SocketIdentity::synthetic(family, protocol, seed),
            family,
            protocol,
            state,
            timer: 0,
            retransmits: 0,
            local: sock_diag::SocketEndpoint {
                address: "192.0.2.10".parse().unwrap(),
                port: 42_000,
            },
            remote: sock_diag::SocketEndpoint {
                address: "198.51.100.20".parse().unwrap(),
                port: 443,
            },
            bound_ifindex: 2,
            expires_millis: 0,
            receive_queue: 11,
            send_queue: 12,
            uid: 1_000,
            memory: Some(sock_diag::SocketMemory {
                receive_allocated: 0,
                receive_limit: 0,
                send_allocated: 0,
                send_limit: 0,
                forward_allocated: 0,
                send_queued: 0,
                option_memory: 0,
                backlog: 0,
                drops: receive_segments,
            }),
            tcp_info: Some(sock_diag::SocketTcpInfo {
                bytes_acked: Some(send_bytes),
                bytes_received: Some(receive_bytes),
                segments_out: Some(send_segments),
                segments_in: Some(receive_segments),
                total_retransmitted_segments: receive_segments,
                ..sock_diag::SocketTcpInfo::default()
            }),
            congestion_algorithm: None,
        }
    }

    fn bounded_at(completed_at: Instant, sockets: Vec<RawSocket>) -> BoundedCollection {
        let observed_sockets = sockets.len();
        BoundedCollection::new(SocketTableCollection {
            queries: vec![sock_diag::SocketTableQueryResult {
                family: RawFamily::Ipv4,
                protocol: RawProtocol::Tcp,
                completed_at,
                observed_sockets,
                truncated: false,
                outcome: Ok(sockets),
            }],
        })
    }

    #[test]
    fn bounded_collection_preserves_collector_observation_and_truncation_metadata() {
        let bounded = BoundedCollection::new(SocketTableCollection {
            queries: vec![sock_diag::SocketTableQueryResult {
                family: RawFamily::Ipv4,
                protocol: RawProtocol::Tcp,
                completed_at: Instant::now(),
                observed_sockets: 8_000,
                truncated: true,
                outcome: Ok(Vec::new()),
            }],
        });

        assert_eq!(bounded.observed_sockets, 8_000);
        assert!(bounded.truncated);
    }

    #[test]
    fn health_codes_preserve_capacity_and_process_mapping_causes() {
        let ProviderHealth::Partial { warning } =
            collection_health(QUERY_COUNT, &[], true, SocketProcessCoverage::Complete)
        else {
            panic!("truncated collection should be partial");
        };
        assert_eq!(warning.code(), MonitorErrorCode::CardinalityLimit);

        assert_eq!(
            collection_warning_code(
                Some(CollectErrorKind::Interrupted),
                true,
                SocketProcessCoverage::Complete,
            ),
            MonitorErrorCode::Timeout,
            "a real query failure must not be hidden by simultaneous truncation"
        );

        let ProviderHealth::Partial { warning } = collection_health(
            QUERY_COUNT,
            &[],
            false,
            SocketProcessCoverage::PermissionDenied,
        ) else {
            panic!("incomplete process mapping should be partial");
        };
        assert_eq!(warning.code(), MonitorErrorCode::PermissionDenied);

        assert_eq!(
            SocketProcessCoverage::Partial {
                permission_denied_processes: 2,
                io_errors: 3,
                truncated: true,
            }
            .summary(),
            "partial denied=2 io=3 truncated=yes"
        );
    }

    #[test]
    fn sock_diag_error_kinds_keep_distinct_monitor_codes() {
        for (kind, code) in [
            (
                CollectErrorKind::PermissionDenied,
                MonitorErrorCode::PermissionDenied,
            ),
            (CollectErrorKind::Unsupported, MonitorErrorCode::Unsupported),
            (CollectErrorKind::Io, MonitorErrorCode::Io),
            (CollectErrorKind::Loss, MonitorErrorCode::OutputLimit),
            (CollectErrorKind::Interrupted, MonitorErrorCode::Timeout),
            (
                CollectErrorKind::Malformed,
                MonitorErrorCode::SchemaMismatch,
            ),
        ] {
            assert_eq!(collect_error_code(kind), code);
        }
    }

    #[test]
    fn counter_projection_requires_monotonic_adjacent_values() {
        let elapsed = Some(Duration::from_secs(2));
        assert_eq!(
            project_counter(Some(30), Some(10), elapsed)
                .unwrap()
                .rate_per_second(),
            10.0
        );
        assert!(project_counter(Some(9), Some(10), elapsed).is_none());
        assert!(project_counter(Some(30), None, elapsed).is_none());
        assert!(project_counter(Some(30), Some(10), None).is_none());
    }

    #[test]
    fn tcp_info_rate_and_rtt_sentinels_remain_unavailable_after_projection() {
        let diagnostics = project_tcp_diagnostics(
            sock_diag::SocketTcpInfo {
                pacing_rate_bytes_per_second: Some(u64::MAX),
                max_pacing_rate_bytes_per_second: Some(u64::MAX),
                min_rtt_micros: Some(u32::MAX),
                delivery_rate_bytes_per_second: Some(0),
                ..sock_diag::SocketTcpInfo::default()
            },
            None,
        );

        assert_eq!(diagnostics.pacing_rate_bytes_per_second, None);
        assert_eq!(diagnostics.max_pacing_rate_bytes_per_second, None);
        assert_eq!(diagnostics.min_rtt_micros, None);
        assert_eq!(diagnostics.delivery_rate_bytes_per_second, None);
    }

    #[test]
    fn projector_uses_identity_and_query_completion_time_for_tcp_rates() {
        let first_at = Instant::now();
        let mut projector = SocketProjector::default();
        let first = projector.project(
            1,
            Duration::from_secs(1),
            Duration::from_millis(1),
            bounded_at(
                first_at,
                vec![raw_socket(1, RawProtocol::Tcp, 1, 100, 10_000, 200, 20_000)],
            ),
            OwnerSnapshot::empty(),
        );
        assert_eq!(first.sockets()[0].receive_traffic().segments(), Some(100));
        assert_eq!(first.sockets()[0].receive_traffic().bytes(), Some(10_000));
        assert!(first.sockets()[0]
            .receive_traffic()
            .segments_per_second()
            .is_none());

        let second = projector.project(
            2,
            Duration::from_secs(3),
            Duration::from_millis(1),
            bounded_at(
                first_at + Duration::from_secs(2),
                vec![raw_socket(1, RawProtocol::Tcp, 1, 120, 12_000, 240, 24_000)],
            ),
            OwnerSnapshot::empty(),
        );
        let socket = &second.sockets()[0];
        assert_eq!(socket.receive_traffic().segments_per_second(), Some(10.0));
        assert_eq!(socket.receive_traffic().bits_per_second(), Some(8_000.0));
        assert_eq!(socket.send_traffic().segments_per_second(), Some(20.0));
        assert_eq!(socket.send_traffic().bits_per_second(), Some(16_000.0));

        let replacement = projector.project(
            3,
            Duration::from_secs(4),
            Duration::from_millis(1),
            bounded_at(
                first_at + Duration::from_secs(3),
                vec![raw_socket(2, RawProtocol::Tcp, 1, 140, 14_000, 280, 28_000)],
            ),
            OwnerSnapshot::empty(),
        );
        assert!(replacement.sockets()[0]
            .receive_traffic()
            .segments_per_second()
            .is_none());
        assert!(replacement.sockets()[0]
            .send_traffic()
            .bits_per_second()
            .is_none());
    }

    #[test]
    fn pending_owner_lookup_does_not_mark_successful_socket_counters_unavailable() {
        assert!(matches!(
            collection_health(QUERY_COUNT, &[], false, SocketProcessCoverage::Pending),
            ProviderHealth::Fresh
        ));
        assert_eq!(
            process_map_summary(SocketProcessCoverage::Pending, None, true),
            "pending refreshing"
        );
        assert_eq!(
            process_map_summary(
                SocketProcessCoverage::Complete,
                Some(Duration::from_secs(9)),
                false
            ),
            "complete age 9.0s"
        );
    }

    #[test]
    fn limit_baseline_uses_query_time_and_breaks_on_gap_reset_or_replacement() {
        let at = Instant::now();
        let mut projector = SocketProjector::default();
        let mut sample = |sequence: u64, seed: Option<u32>, busy: u64, rwnd: u64| {
            let sockets = seed
                .map(|seed| {
                    let mut raw = raw_socket(seed, RawProtocol::Tcp, 1, 1, 1, 1, 1);
                    let tcp = raw.tcp_info.as_mut().unwrap();
                    tcp.busy_time_micros = Some(busy);
                    tcp.receive_window_limited_micros = Some(rwnd);
                    tcp.send_buffer_limited_micros = Some(0);
                    raw
                })
                .into_iter()
                .collect();
            projector.project(
                sequence,
                Duration::from_secs(sequence * 10),
                Duration::from_secs(3),
                bounded_at(at + Duration::from_secs(sequence), sockets),
                OwnerSnapshot::empty(),
            )
        };
        let first = sample(1, Some(1), 10_000_000, 9_000_000);
        assert!(first.sockets()[0].tcp().unwrap().limit_interval.is_none());
        let second = sample(2, Some(1), 10_100_000, 9_072_000);
        let tcp = second.sockets()[0].tcp().unwrap();
        assert_eq!(tcp.limit_interval.unwrap().elapsed, Duration::from_secs(1));
        assert_eq!(tcp.limit_reason().0, "RWND");
        sample(3, None, 0, 0);
        let after_gap = sample(4, Some(1), 10_200_000, 9_073_000);
        assert!(after_gap.sockets()[0]
            .tcp()
            .unwrap()
            .limit_interval
            .is_none());
        let reset = sample(5, Some(1), 10, 2);
        assert!(reset.sockets()[0].tcp().unwrap().limit_interval.is_none());
        let replacement = sample(6, Some(2), 20_000_000, 10_000_000);
        assert!(replacement.sockets()[0]
            .tcp()
            .unwrap()
            .limit_interval
            .is_none());
    }

    #[test]
    #[ignore = "live loopback, process attribution and one-second cadence probe"]
    fn live_socket_owner_cache_and_counter_cadence() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            (client, server)
        }
        let mut connection = pair();
        let session =
            SocketTableSession::start(Duration::from_secs(1), SystemPaths::default()).unwrap();
        let mut sequence = 0;
        let mut retired = None;
        let mut owned_first = false;
        let mut owned_replacement = false;
        let mut observed_rates = 0;
        let mut previous_at = None;
        let mut intervals = Vec::new();
        for tick in 0..15 {
            if tick == 5 {
                connection = pair();
            }
            connection.0.write_all(&[7; 1024]).unwrap();
            connection.1.read_exact(&mut [0; 1024]).unwrap();
            let snapshot = session
                .wait_after(sequence, Duration::from_secs(3))
                .unwrap()
                .expect("counter worker must keep sampling");
            assert_eq!(snapshot.sequence(), sequence + 1);
            sequence = snapshot.sequence();
            let port = connection.0.local_addr().unwrap().port();
            let row = snapshot
                .sockets()
                .iter()
                .find(|row| row.local().port() == port && row.state() == "ESTABLISHED")
                .expect("live loopback connection");
            let owned = row
                .owners()
                .iter()
                .any(|owner| owner.pid() == std::process::id());
            if tick < 5 {
                owned_first |= owned;
                retired = Some(row.row_key().clone());
            } else {
                owned_replacement |= owned;
                assert!(snapshot.socket(retired.as_ref().unwrap()).is_none());
            }
            if row
                .send_traffic()
                .bits_per_second()
                .is_some_and(|rate| rate > 0.0)
            {
                observed_rates += 1;
            }
            if let Some(previous) = previous_at {
                intervals.push(
                    snapshot
                        .attempted_at()
                        .saturating_sub(previous)
                        .as_secs_f64(),
                );
            }
            previous_at = Some(snapshot.attempted_at());
            println!(
                "{}",
                serde_json::json!({
                    "sequence": sequence, "at_s": snapshot.attempted_at().as_secs_f64(),
                    "counter_collection_ms": snapshot.collection_duration().as_secs_f64() * 1000.0,
                    "process_map": snapshot.process_map_summary(), "test_connection_owned": owned,
                    "tx_bits_per_second": row.send_traffic().bits_per_second(),
                    "processes_last_scan": snapshot.scanned_processes(), "fds_last_scan": snapshot.scanned_fds(),
                })
            );
        }
        session.shutdown().unwrap();
        assert!(owned_first && owned_replacement);
        assert!(observed_rates >= 10);
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        assert!((0.9..1.1).contains(&mean), "mean counter interval {mean}");
        println!("mean_interval_s={mean:.6} observed_rate_samples={observed_rates}");
    }

    #[test]
    fn udp_time_wait_and_listen_never_expose_tcp_traffic_accounting() {
        for (protocol, state) in [
            (RawProtocol::Udp, 7),
            (RawProtocol::Tcp, 6),
            (RawProtocol::Tcp, 10),
        ] {
            let mut socket = raw_socket(1, protocol, state, 100, 10_000, 200, 20_000);
            socket.congestion_algorithm = Some("cubic".to_owned());
            let projected = project_socket(&socket, None, Some(Duration::from_secs(1)), &[], 1, 0);

            assert_eq!(projected.receive_traffic().segments(), None);
            assert_eq!(projected.receive_traffic().bytes(), None);
            assert_eq!(projected.send_traffic().segments(), None);
            assert_eq!(projected.send_traffic().bytes(), None);
            assert_eq!(projected.receive_queue(), 11);
            assert_eq!(projected.send_queue(), 12);
            assert_eq!(projected.tcp(), None);
            assert_eq!(projected.congestion_algorithm(), None);
        }
    }

    #[test]
    fn protocol_specific_state_names_do_not_call_udp_unconnected_closed() {
        assert_eq!(socket_state(RawProtocol::Tcp, 1), "ESTABLISHED");
        assert_eq!(socket_state(RawProtocol::Tcp, 10), "LISTEN");
        assert_eq!(socket_state(RawProtocol::Udp, 7), "UNCONN");
        assert_eq!(socket_state(RawProtocol::Udp, 99), "STATE#99");
    }

    #[test]
    fn snapshots_and_owners_redact_private_identity_from_debug() {
        let snapshot = synthetic_socket_table_snapshot();
        let debug = format!("{snapshot:?} {:?}", snapshot.sockets()[0]);
        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("198.51.100.20"));
        assert!(!debug.contains("client-worker"));
        assert!(!debug.contains("1234"));
    }

    #[test]
    fn socket_detail_tracks_current_identity_through_reordering_missing_and_recovery() {
        let first = synthetic_socket_table_snapshot_at(2);
        let key = first.sockets()[0].row_key().clone();
        let mut detail = SocketDetailState::start(&first, key.clone()).unwrap();
        assert_eq!(detail.socket(), first.socket(&key).unwrap());
        assert_eq!(detail.opened_at(), Duration::from_secs(2));

        let reordered = synthetic_socket_table_snapshot_reordered_at(3);
        detail.record(&reordered);
        assert!(detail.observed_latest());
        assert_eq!(detail.key(), &key);
        assert_eq!(detail.socket(), reordered.socket(&key).unwrap());

        let missing = synthetic_socket_table_snapshot_without_tcp_at(4);
        detail.record(&missing);
        assert!(!detail.observed_latest());
        assert_eq!(detail.socket(), reordered.socket(&key).unwrap());
        assert_eq!(detail.last_at(), Duration::from_secs(4));

        let recovered = synthetic_socket_table_snapshot_with_rtt_at(5, 20_000);
        detail.record(&recovered);
        assert!(detail.observed_latest());
        assert_eq!(detail.key(), &key);
        assert_eq!(detail.socket(), recovered.socket(&key).unwrap());
        assert_eq!(detail.last_sequence, 5);
        assert_eq!(detail.last_at(), Duration::from_secs(5));
        assert_eq!(detail.opened_at(), Duration::from_secs(2));
    }

    #[test]
    fn socket_detail_does_not_follow_replacement_at_the_same_position_or_endpoint() {
        let first = synthetic_socket_table_snapshot_at(2);
        let key = first.sockets()[0].row_key().clone();
        let mut detail = SocketDetailState::start(&first, key.clone()).unwrap();
        let mut replacement = (*synthetic_socket_table_snapshot_at(3)).clone();
        let mut sockets = replacement.sockets.to_vec();
        sockets[0].row_key = SocketRowKey::new(
            &SocketIdentity::synthetic(RawFamily::Ipv4, RawProtocol::Tcp, 99),
            3,
            0,
        );
        replacement.sockets = sockets.into();

        detail.record(&replacement);

        assert!(!detail.observed_latest());
        assert_eq!(detail.key(), &key);
        assert_eq!(detail.socket(), first.socket(&key).unwrap());
        assert_eq!(detail.last_sequence, 3);
    }

    #[test]
    fn socket_detail_clone_remains_immutable_while_latest_updates_and_disappears() {
        let first = synthetic_socket_table_snapshot_at(2);
        let key = first.sockets()[0].row_key().clone();
        let mut latest = SocketDetailState::start(&first, key.clone()).unwrap();
        let frozen = latest.clone();

        latest.record(&synthetic_socket_table_snapshot_with_rtt_at(3, 20_000));
        assert_ne!(latest.socket(), frozen.socket());
        latest.record(&synthetic_socket_table_snapshot_without_tcp_at(4));

        assert!(!latest.observed_latest());
        assert!(frozen.observed_latest());
        assert_eq!(frozen.socket(), first.socket(&key).unwrap());
        assert_eq!(frozen.key(), &key);
        assert_eq!(frozen.last_sequence, 2);
        assert_eq!(frozen.opened_at(), Duration::from_secs(2));
        assert_eq!(frozen.last_at(), Duration::from_secs(2));
        assert_eq!(latest.socket().tcp().unwrap().rtt_micros, 20_000);
    }

    #[test]
    fn socket_detail_filters_old_sequences_and_keeps_time_monotonic() {
        let first = synthetic_socket_table_snapshot_at(5);
        let key = first.sockets()[0].row_key().clone();
        let mut detail = SocketDetailState::start(&first, key.clone()).unwrap();
        for sequence in [5, 4] {
            let mut stale = (*synthetic_socket_table_snapshot_without_tcp_at(sequence)).clone();
            stale.attempted_at = Duration::from_secs(100);
            detail.record(&stale);
            assert!(detail.observed_latest());
            assert_eq!(detail.socket(), first.socket(&key).unwrap());
            assert_eq!(detail.last_sequence, 5);
            assert_eq!(detail.last_at(), Duration::from_secs(5));
        }

        let mut newer = (*synthetic_socket_table_snapshot_with_rtt_at(6, 20_000)).clone();
        newer.attempted_at = Duration::from_secs(3);
        detail.record(&newer);
        assert_eq!(detail.socket(), newer.socket(&key).unwrap());
        assert_eq!(detail.last_sequence, 6);
        assert_eq!(detail.last_at(), Duration::from_secs(5));

        detail.record(&synthetic_socket_table_snapshot_without_tcp_at(7));
        assert!(!detail.observed_latest());
        assert_eq!(detail.last_sequence, 7);
        assert_eq!(detail.last_at(), Duration::from_secs(7));
    }

    #[test]
    fn socket_detail_open_boundary_preserves_selected_identity_and_initial_visibility() {
        let selected = synthetic_socket_table_snapshot_at(2);
        let key = selected.sockets()[0].row_key().clone();
        let current = synthetic_socket_table_snapshot_with_rtt_at(9, 20_000);
        let missing = synthetic_socket_table_snapshot_without_tcp_at(9);

        for initial in [&current, &missing] {
            let detail = SocketDetailState::start_at(
                &selected,
                initial,
                key.clone(),
                Duration::from_secs(8),
            )
            .unwrap();
            assert_eq!(detail.key(), &key);
            assert_eq!(detail.opened_at(), Duration::from_secs(9));
            assert_eq!(detail.last_at(), Duration::from_secs(9));
            assert_eq!(detail.last_sequence, 9);
            assert_eq!(detail.observed_latest(), initial.socket(&key).is_some());
            assert_eq!(
                detail.socket(),
                initial
                    .socket(&key)
                    .unwrap_or(selected.socket(&key).unwrap())
            );
        }

        let paused =
            SocketDetailState::start_at(&selected, &selected, key.clone(), Duration::from_secs(10))
                .unwrap();
        assert_eq!(paused.opened_at(), Duration::from_secs(10));
        assert_eq!(paused.last_at(), Duration::from_secs(10));
        assert_eq!(paused.last_sequence, 2);
        assert!(paused.observed_latest());
        assert!(SocketDetailState::start(&missing, key.clone()).is_none());
        assert!(SocketDetailState::start_at(&missing, &current, key, Duration::ZERO).is_none());
    }

    #[test]
    fn socket_detail_debug_redacts_identity_tuple_and_owner() {
        let snapshot = synthetic_socket_table_snapshot();
        let detail =
            SocketDetailState::start(&snapshot, snapshot.sockets()[0].row_key().clone()).unwrap();
        let debug = format!("{detail:?} {:?}", detail.key());

        assert!(!debug.contains("192.0.2.10"));
        assert!(!debug.contains("198.51.100.20"));
        assert!(!debug.contains("client-worker"));
        assert!(!debug.contains("1234"));
    }

    #[test]
    fn socket_table_session_rejects_zero_interval() {
        assert!(SocketTableSession::start(Duration::ZERO, SystemPaths::default()).is_err());
    }
}
