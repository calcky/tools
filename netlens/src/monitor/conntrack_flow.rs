use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Context;

use crate::collect::conntrack_flow::{
    self, AddressFamily, CollectErrorKind, FlowCollection, FlowCounters, FlowIdentity, FlowTuple,
    IcmpTupleKey, RawConntrackFlow,
};
use crate::collect::SystemPaths;

use super::{CounterSpan, MonitorError, MonitorErrorCode, ProviderHealth};

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConntrackEndpoint {
    address: IpAddr,
    port: Option<u16>,
}

impl ConntrackEndpoint {
    pub(crate) const fn address(&self) -> IpAddr {
        self.address
    }

    pub(crate) const fn port(&self) -> Option<u16> {
        self.port
    }
}

impl fmt::Debug for ConntrackEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConntrackEndpoint(<redacted>)")
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConntrackTuple {
    source: ConntrackEndpoint,
    destination: ConntrackEndpoint,
    icmp: Option<ConntrackIcmpKey>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConntrackIcmpKey {
    icmp_type: u8,
    code: u8,
    id: u16,
}

impl ConntrackIcmpKey {
    pub(crate) const fn icmp_type(self) -> u8 {
        self.icmp_type
    }

    pub(crate) const fn code(self) -> u8 {
        self.code
    }

    pub(crate) const fn id(self) -> u16 {
        self.id
    }
}

impl ConntrackTuple {
    pub(crate) fn source(&self) -> &ConntrackEndpoint {
        &self.source
    }

    pub(crate) fn destination(&self) -> &ConntrackEndpoint {
        &self.destination
    }

    pub(crate) const fn icmp(&self) -> Option<ConntrackIcmpKey> {
        self.icmp
    }
}

impl fmt::Debug for ConntrackTuple {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConntrackTuple(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConntrackTraffic {
    packets: Option<u64>,
    bytes: Option<u64>,
    packet_interval: Option<CounterSpan>,
    byte_interval: Option<CounterSpan>,
}

impl ConntrackTraffic {
    pub(crate) const fn packet_interval(&self) -> Option<CounterSpan> {
        self.packet_interval
    }

    pub(crate) const fn byte_interval(&self) -> Option<CounterSpan> {
        self.byte_interval
    }

    pub(crate) const fn packets(&self) -> Option<u64> {
        self.packets
    }

    pub(crate) const fn bytes(&self) -> Option<u64> {
        self.bytes
    }

    pub(crate) fn packets_per_second(&self) -> Option<f64> {
        self.packet_interval.map(CounterSpan::rate_per_second)
    }

    pub(crate) fn bits_per_second(&self) -> Option<f64> {
        self.byte_interval
            .map(|interval| interval.rate_per_second() * 8.0)
    }

    fn interval_packets(&self) -> u64 {
        self.packet_interval.map_or(0, CounterSpan::delta)
    }

    fn interval_bytes(&self) -> u64 {
        self.byte_interval.map_or(0, CounterSpan::delta)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ConntrackFlowSnapshot {
    family: AddressFamily,
    protocol: u8,
    protocol_name: String,
    state: Option<String>,
    timeout_seconds: Option<u64>,
    zone: u16,
    ct_mark: Option<u32>,
    original: ConntrackTuple,
    reply: ConntrackTuple,
    original_traffic: ConntrackTraffic,
    reply_traffic: ConntrackTraffic,
    offloaded: bool,
    hardware_offloaded: bool,
}

impl ConntrackFlowSnapshot {
    pub(crate) const fn family(&self) -> AddressFamily {
        self.family
    }

    pub(crate) fn key(&self) -> ConntrackFlowKey {
        ConntrackFlowKey {
            family: self.family,
            protocol: self.protocol,
            zone: self.zone,
            original: self.original.clone(),
            reply: self.reply.clone(),
        }
    }

    pub(crate) fn total_bytes(&self) -> Option<u128> {
        Some(u128::from(self.original_traffic.bytes()?) + u128::from(self.reply_traffic.bytes()?))
    }

    pub(crate) fn total_packets(&self) -> Option<u128> {
        Some(
            u128::from(self.original_traffic.packets()?)
                + u128::from(self.reply_traffic.packets()?),
        )
    }

    pub(crate) fn total_bits_per_second(&self) -> Option<f64> {
        Some(self.original_traffic.bits_per_second()? + self.reply_traffic.bits_per_second()?)
    }

    pub(crate) fn total_packets_per_second(&self) -> Option<f64> {
        Some(
            self.original_traffic.packets_per_second()?
                + self.reply_traffic.packets_per_second()?,
        )
    }

    pub(crate) const fn protocol(&self) -> u8 {
        self.protocol
    }

    pub(crate) fn protocol_name(&self) -> &str {
        &self.protocol_name
    }

    pub(crate) fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    pub(crate) const fn timeout_seconds(&self) -> Option<u64> {
        self.timeout_seconds
    }

    pub(crate) const fn zone(&self) -> u16 {
        self.zone
    }

    pub(crate) const fn ct_mark(&self) -> Option<u32> {
        self.ct_mark
    }

    pub(crate) fn original(&self) -> &ConntrackTuple {
        &self.original
    }

    pub(crate) fn reply(&self) -> &ConntrackTuple {
        &self.reply
    }

    pub(crate) const fn original_traffic(&self) -> ConntrackTraffic {
        self.original_traffic
    }

    pub(crate) const fn reply_traffic(&self) -> ConntrackTraffic {
        self.reply_traffic
    }

    pub(crate) const fn offloaded(&self) -> bool {
        self.offloaded
    }

    pub(crate) const fn hardware_offloaded(&self) -> bool {
        self.hardware_offloaded
    }

    pub(crate) fn matches_filter(&self, filter: &ConntrackFlowFilter) -> bool {
        let endpoints = [
            self.original.source(),
            self.original.destination(),
            self.reply.source(),
            self.reply.destination(),
        ]
        .map(|endpoint| (endpoint.address(), endpoint.port()));
        filter.matches(self.protocol, endpoints[0], endpoints[1], &endpoints)
    }

    fn interval_bytes(&self) -> u64 {
        self.original_traffic
            .interval_bytes()
            .saturating_add(self.reply_traffic.interval_bytes())
    }

    fn interval_packets(&self) -> u64 {
        self.original_traffic
            .interval_packets()
            .saturating_add(self.reply_traffic.interval_packets())
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ConntrackFlowKey {
    family: AddressFamily,
    protocol: u8,
    zone: u16,
    original: ConntrackTuple,
    reply: ConntrackTuple,
}

impl ConntrackFlowKey {
    pub(crate) fn matches(&self, flow: &ConntrackFlowSnapshot) -> bool {
        self.family == flow.family
            && self.protocol == flow.protocol
            && self.zone == flow.zone
            && self.original == flow.original
            && self.reply == flow.reply
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ConntrackSort {
    #[default]
    Bandwidth,
    TxBandwidth,
    RxBandwidth,
    TxPps,
    RxPps,
    Bytes,
    TxBytes,
    RxBytes,
    Packets,
    TxPackets,
    RxPackets,
    TxAverage,
    RxAverage,
    Protocol,
    State,
    Original,
    Mark,
}

impl ConntrackSort {
    pub(crate) const ALL: [Self; 17] = [
        Self::Bandwidth,
        Self::TxBandwidth,
        Self::RxBandwidth,
        Self::TxPps,
        Self::RxPps,
        Self::Bytes,
        Self::TxBytes,
        Self::RxBytes,
        Self::Packets,
        Self::TxPackets,
        Self::RxPackets,
        Self::TxAverage,
        Self::RxAverage,
        Self::Protocol,
        Self::State,
        Self::Original,
        Self::Mark,
    ];

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Bandwidth => "total bandwidth",
            Self::TxBandwidth => "TX bandwidth",
            Self::RxBandwidth => "RX bandwidth",
            Self::TxPps => "TX PPS",
            Self::RxPps => "RX PPS",
            Self::Bytes => "total bytes",
            Self::TxBytes => "TX bytes",
            Self::RxBytes => "RX bytes",
            Self::Packets => "total packets",
            Self::TxPackets => "TX packets",
            Self::RxPackets => "RX packets",
            Self::TxAverage => "TX avg pkt byte",
            Self::RxAverage => "RX avg pkt byte",
            Self::Protocol => "protocol",
            Self::State => "state",
            Self::Original => "original endpoints",
            Self::Mark => "CT mark",
        }
    }

    pub(crate) fn next(self) -> Self {
        let position = Self::ALL.iter().position(|sort| *sort == self).unwrap();
        Self::ALL[(position + 1) % Self::ALL.len()]
    }

    pub(crate) fn compare(
        self,
        left: &ConntrackFlowSnapshot,
        right: &ConntrackFlowSnapshot,
        descending: bool,
    ) -> Ordering {
        let order = match self {
            Self::Protocol => compare_available(
                Some(left.protocol_name()),
                Some(right.protocol_name()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::State => {
                compare_available(left.state(), right.state(), descending, |a, b| a.cmp(b))
            }
            Self::Original => compare_available(
                Some(left.original()),
                Some(right.original()),
                descending,
                |a, b| a.cmp(b),
            ),
            Self::Mark => compare_available(left.ct_mark(), right.ct_mark(), descending, u32::cmp),
            Self::Packets | Self::TxPackets | Self::RxPackets => {
                let value = |flow: &ConntrackFlowSnapshot| {
                    let tx = flow.original_traffic.packets().map(u128::from);
                    let rx = flow.reply_traffic.packets().map(u128::from);
                    match self {
                        Self::Packets => tx.zip(rx).map(|(tx, rx)| tx + rx),
                        Self::TxPackets => tx,
                        _ => rx,
                    }
                };
                compare_available(value(left), value(right), descending, u128::cmp)
            }
            Self::Bytes => compare_available(
                left.total_bytes(),
                right.total_bytes(),
                descending,
                u128::cmp,
            ),
            Self::TxBytes => compare_available(
                left.original_traffic.bytes(),
                right.original_traffic.bytes(),
                descending,
                u64::cmp,
            ),
            Self::RxBytes => compare_available(
                left.reply_traffic.bytes(),
                right.reply_traffic.bytes(),
                descending,
                u64::cmp,
            ),
            _ => {
                let value = |flow: &ConntrackFlowSnapshot| match self {
                    Self::Bandwidth => flow.total_bits_per_second(),
                    Self::TxBandwidth => flow.original_traffic.bits_per_second(),
                    Self::RxBandwidth => flow.reply_traffic.bits_per_second(),
                    Self::TxPps => flow.original_traffic.packets_per_second(),
                    Self::RxPps => flow.reply_traffic.packets_per_second(),
                    Self::TxAverage => average_packet(flow.original_traffic),
                    Self::RxAverage => average_packet(flow.reply_traffic),
                    _ => unreachable!(),
                };
                compare_available(value(left), value(right), descending, f64::total_cmp)
            }
        };
        order
            .then_with(|| left.family.cmp(&right.family))
            .then_with(|| left.protocol.cmp(&right.protocol))
            .then_with(|| left.zone.cmp(&right.zone))
            .then_with(|| left.original.cmp(&right.original))
            .then_with(|| left.reply.cmp(&right.reply))
    }
}

pub(crate) fn average_packet(traffic: ConntrackTraffic) -> Option<f64> {
    traffic
        .bytes()
        .zip(traffic.packets())
        .and_then(|(bytes, packets)| (packets > 0).then(|| bytes as f64 / packets as f64))
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

impl fmt::Debug for ConntrackFlowSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConntrackFlowSnapshot")
            .field("protocol", &self.protocol)
            .field("tuple", &"<redacted>")
            .field("original_traffic", &self.original_traffic)
            .field("reply_traffic", &self.reply_traffic)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ConntrackTableSnapshot {
    sequence: u64,
    attempted_at: Duration,
    collection_duration: Duration,
    health: ProviderHealth,
    total_entries: Option<u64>,
    accounting_enabled: Option<bool>,
    truncated: bool,
    rejected_lines: usize,
    flows: Arc<[ConntrackFlowSnapshot]>,
}

impl ConntrackTableSnapshot {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn attempted_at(&self) -> Duration {
        self.attempted_at
    }

    pub(crate) const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub(crate) fn health(&self) -> &ProviderHealth {
        &self.health
    }

    pub(crate) const fn total_entries(&self) -> Option<u64> {
        self.total_entries
    }

    pub(crate) const fn accounting_enabled(&self) -> Option<bool> {
        self.accounting_enabled
    }

    pub(crate) const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) const fn rejected_lines(&self) -> usize {
        self.rejected_lines
    }

    pub(crate) fn flows(&self) -> &[ConntrackFlowSnapshot] {
        &self.flows
    }
}

impl fmt::Debug for ConntrackTableSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConntrackTableSnapshot")
            .field("sequence", &self.sequence)
            .field("health", &self.health)
            .field("flow_count", &self.flows.len())
            .field("total_entries", &self.total_entries)
            .finish()
    }
}

pub(crate) use super::connection_filter::ConnectionFilter as ConntrackFlowFilter;

#[derive(Default)]
struct FlowProjector {
    previous: Option<(Duration, BTreeMap<FlowIdentity, PreviousCounters>)>,
}

#[derive(Clone, Copy)]
struct PreviousCounters {
    original: FlowCounters,
    reply: FlowCounters,
}

impl FlowProjector {
    fn project(
        &mut self,
        sequence: u64,
        attempted_at: Duration,
        collection_duration: Duration,
        collection: FlowCollection,
    ) -> Arc<ConntrackTableSnapshot> {
        let elapsed = self
            .previous
            .as_ref()
            .and_then(|(previous_at, _)| attempted_at.checked_sub(*previous_at))
            .filter(|elapsed| *elapsed > Duration::ZERO);
        let previous = self.previous.as_ref().map(|(_, values)| values);
        let mut next = BTreeMap::new();
        let mut flows = collection
            .flows
            .into_iter()
            .map(|flow| {
                let identity = flow.identity();
                let before = previous.and_then(|values| values.get(&identity));
                let projected = project_flow(&flow, before, elapsed);
                next.insert(
                    identity,
                    PreviousCounters {
                        original: flow.original_counters,
                        reply: flow.reply_counters,
                    },
                );
                projected
            })
            .collect::<Vec<_>>();
        flows.sort_by(compare_flow_activity);
        self.previous = Some((attempted_at, next));

        let missing_accounting = flows.iter().filter(|flow| {
            flow.original_traffic.packets.is_none()
                || flow.original_traffic.bytes.is_none()
                || flow.reply_traffic.packets.is_none()
                || flow.reply_traffic.bytes.is_none()
        });
        let missing_accounting = missing_accounting.count();
        let health = collection_health(
            collection.truncated,
            collection.rejected_lines,
            missing_accounting,
        );
        Arc::new(ConntrackTableSnapshot {
            sequence,
            attempted_at,
            collection_duration,
            health,
            total_entries: collection.total_entries,
            accounting_enabled: collection.accounting_enabled,
            truncated: collection.truncated,
            rejected_lines: collection.rejected_lines,
            flows: flows.into(),
        })
    }

    fn project_error(
        &mut self,
        sequence: u64,
        attempted_at: Duration,
        collection_duration: Duration,
        error: conntrack_flow::CollectError,
    ) -> Arc<ConntrackTableSnapshot> {
        self.previous = None;
        let code = match error.kind() {
            CollectErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
            CollectErrorKind::Unsupported => MonitorErrorCode::Unsupported,
            CollectErrorKind::Io => MonitorErrorCode::Io,
        };
        let error = monitor_error(code, error);
        let health = match code {
            MonitorErrorCode::PermissionDenied => {
                ProviderHealth::PermissionDenied { reason: error }
            }
            MonitorErrorCode::Unsupported => ProviderHealth::Unsupported { reason: error },
            _ => ProviderHealth::Error { error },
        };
        Arc::new(ConntrackTableSnapshot {
            sequence,
            attempted_at,
            collection_duration,
            health,
            total_entries: None,
            accounting_enabled: None,
            truncated: false,
            rejected_lines: 0,
            flows: Arc::from([]),
        })
    }
}

fn project_flow(
    flow: &RawConntrackFlow,
    previous: Option<&PreviousCounters>,
    elapsed: Option<Duration>,
) -> ConntrackFlowSnapshot {
    ConntrackFlowSnapshot {
        family: flow.family,
        protocol: flow.protocol,
        protocol_name: flow.protocol_name.clone(),
        state: flow.state.clone(),
        timeout_seconds: flow.timeout_seconds,
        zone: flow.zone,
        ct_mark: flow.ct_mark,
        original: project_tuple(&flow.original),
        reply: project_tuple(&flow.reply),
        original_traffic: project_traffic(
            flow.original_counters,
            previous.map(|value| value.original),
            elapsed,
        ),
        reply_traffic: project_traffic(
            flow.reply_counters,
            previous.map(|value| value.reply),
            elapsed,
        ),
        offloaded: flow.offloaded,
        hardware_offloaded: flow.hardware_offloaded,
    }
}

fn project_tuple(tuple: &FlowTuple) -> ConntrackTuple {
    ConntrackTuple {
        source: ConntrackEndpoint {
            address: tuple.source.address,
            port: tuple.source.port,
        },
        destination: ConntrackEndpoint {
            address: tuple.destination.address,
            port: tuple.destination.port,
        },
        icmp: tuple.icmp.map(project_icmp_key),
    }
}

fn project_icmp_key(key: IcmpTupleKey) -> ConntrackIcmpKey {
    ConntrackIcmpKey {
        icmp_type: key.icmp_type,
        code: key.code,
        id: key.id,
    }
}

fn project_traffic(
    current: FlowCounters,
    previous: Option<FlowCounters>,
    elapsed: Option<Duration>,
) -> ConntrackTraffic {
    ConntrackTraffic {
        packets: current.packets,
        bytes: current.bytes,
        packet_interval: project_counter(
            current.packets,
            previous.and_then(|v| v.packets),
            elapsed,
        ),
        byte_interval: project_counter(current.bytes, previous.and_then(|v| v.bytes), elapsed),
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

fn compare_flow_activity(left: &ConntrackFlowSnapshot, right: &ConntrackFlowSnapshot) -> Ordering {
    right
        .interval_bytes()
        .cmp(&left.interval_bytes())
        .then_with(|| right.interval_packets().cmp(&left.interval_packets()))
        .then_with(|| left.protocol.cmp(&right.protocol))
        .then_with(|| left.original.cmp(&right.original))
        .then_with(|| left.reply.cmp(&right.reply))
}

fn collection_health(
    truncated: bool,
    rejected_lines: usize,
    missing_accounting: usize,
) -> ProviderHealth {
    if !truncated && rejected_lines == 0 && missing_accounting == 0 {
        return ProviderHealth::Fresh;
    }
    let mut reasons = Vec::new();
    if truncated {
        reasons.push("flow table collection stopped at a configured bound".to_owned());
    }
    if rejected_lines > 0 {
        reasons.push(format!("rejected {rejected_lines} malformed flow rows"));
    }
    if missing_accounting > 0 {
        reasons.push(format!(
            "{missing_accounting} flows have no complete packet/byte accounting"
        ));
    }
    ProviderHealth::Partial {
        warning: monitor_error(MonitorErrorCode::SchemaMismatch, reasons.join("; ")),
    }
}

fn monitor_error(code: MonitorErrorCode, diagnostic: impl fmt::Display) -> MonitorError {
    let mut diagnostic = diagnostic.to_string();
    diagnostic.retain(|character| character.is_ascii_graphic() || character == ' ');
    diagnostic.truncate(256);
    MonitorError::new(code, diagnostic)
        .expect("conntrack flow diagnostics are bounded printable ASCII")
}

struct LatestState {
    snapshot: Option<Arc<ConntrackTableSnapshot>>,
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

    fn publish(&self, snapshot: Arc<ConntrackTableSnapshot>) {
        let mut state = self.state.lock().expect("conntrack latest mutex poisoned");
        state.snapshot = Some(snapshot);
        self.changed.notify_all();
    }

    fn close(&self, error: Option<String>) {
        let mut state = self.state.lock().expect("conntrack latest mutex poisoned");
        state.closed = true;
        state.error = error;
        self.changed.notify_all();
    }
}

pub(crate) struct ConntrackFlowSession {
    latest: Arc<LatestSlot>,
    stop: mpsc::SyncSender<()>,
    worker: Option<JoinHandle<()>>,
}

impl ConntrackFlowSession {
    pub(crate) fn start(interval: Duration, paths: SystemPaths) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !interval.is_zero(),
            "conntrack flow interval must be positive"
        );
        let (stop, stop_receiver) = mpsc::sync_channel(1);
        let latest = Arc::new(LatestSlot::new());
        let worker_latest = Arc::clone(&latest);
        let worker = thread::Builder::new()
            .name("netlens-conntrack-flow".to_owned())
            .spawn(move || run_worker(interval, paths, stop_receiver, &worker_latest))
            .context("spawn conntrack flow worker")?;
        Ok(Self {
            latest,
            stop,
            worker: Some(worker),
        })
    }

    pub(crate) fn wait_after(
        &self,
        sequence: u64,
        timeout: Duration,
    ) -> anyhow::Result<Option<Arc<ConntrackTableSnapshot>>> {
        let state = self
            .latest
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("conntrack latest mutex poisoned"))?;
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
            .map_err(|_| anyhow::anyhow!("conntrack latest mutex poisoned"))?;
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
                anyhow::bail!("conntrack flow worker stopped: {error}");
            }
        }
        Ok(None)
    }

    pub(crate) fn shutdown(mut self) -> anyhow::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.stop.try_send(());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("conntrack flow worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for ConntrackFlowSession {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run_worker(
    interval: Duration,
    paths: SystemPaths,
    stop: mpsc::Receiver<()>,
    latest: &LatestSlot,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session_start = Instant::now();
        let mut deadline = session_start;
        let mut sequence = 0_u64;
        let mut projector = FlowProjector::default();
        loop {
            let started = Instant::now();
            let result = conntrack_flow::collect(&paths.proc_root);
            let finished = Instant::now();
            let attempted_at = finished.saturating_duration_since(session_start);
            let collection_duration = finished
                .saturating_duration_since(started)
                .min(attempted_at);
            sequence = sequence.saturating_add(1);
            let snapshot = match result {
                Ok(collection) => {
                    projector.project(sequence, attempted_at, collection_duration, collection)
                }
                Err(error) => {
                    projector.project_error(sequence, attempted_at, collection_duration, error)
                }
            };
            latest.publish(snapshot);

            deadline += interval;
            while deadline <= Instant::now() {
                deadline += interval;
            }
            match stop.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }));
    latest.close(result.err().map(|_| "worker panicked".to_owned()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::conntrack_flow::{
        AddressFamily, FlowEndpoint as RawEndpoint, IcmpTupleKey,
    };

    fn raw_flow(
        source: &str,
        source_port: u16,
        packets: (u64, u64),
        bytes: (u64, u64),
    ) -> RawConntrackFlow {
        let source: IpAddr = source.parse().unwrap();
        let (family, remote) = match source {
            IpAddr::V4(_) => (AddressFamily::Ipv4, "198.51.100.2".parse().unwrap()),
            IpAddr::V6(_) => (AddressFamily::Ipv6, "2001:db8::2".parse().unwrap()),
        };
        RawConntrackFlow {
            family,
            protocol: 6,
            protocol_name: "tcp".to_owned(),
            state: Some("ESTABLISHED".to_owned()),
            timeout_seconds: Some(60),
            zone: 0,
            ct_mark: Some(0),
            original: FlowTuple {
                source: RawEndpoint {
                    address: source,
                    port: Some(source_port),
                },
                destination: RawEndpoint {
                    address: remote,
                    port: Some(443),
                },
                icmp: None,
            },
            reply: FlowTuple {
                source: RawEndpoint {
                    address: remote,
                    port: Some(443),
                },
                destination: RawEndpoint {
                    address: source,
                    port: Some(source_port),
                },
                icmp: None,
            },
            original_counters: FlowCounters {
                packets: Some(packets.0),
                bytes: Some(bytes.0),
            },
            reply_counters: FlowCounters {
                packets: Some(packets.1),
                bytes: Some(bytes.1),
            },
            offloaded: false,
            hardware_offloaded: false,
        }
    }

    fn collection(flows: Vec<RawConntrackFlow>) -> FlowCollection {
        FlowCollection {
            total_entries: Some(flows.len() as u64),
            accounting_enabled: Some(true),
            truncated: false,
            rejected_lines: 0,
            flows,
        }
    }

    fn icmp_flow(id: u16, packets: u64, bytes: u64) -> RawConntrackFlow {
        let mut flow = raw_flow("192.0.2.10", 0, (packets, packets), (bytes, bytes));
        flow.protocol = 1;
        flow.protocol_name = "icmp".to_owned();
        flow.original.source.port = None;
        flow.original.destination.port = None;
        flow.original.icmp = Some(IcmpTupleKey {
            icmp_type: 8,
            code: 0,
            id,
        });
        flow.reply.source.port = None;
        flow.reply.destination.port = None;
        flow.reply.icmp = Some(IcmpTupleKey {
            icmp_type: 0,
            code: 0,
            id,
        });
        flow
    }

    #[test]
    fn adjacent_samples_project_directional_rates_and_sort_by_bandwidth() {
        let mut projector = FlowProjector::default();
        projector.project(
            1,
            Duration::from_secs(1),
            Duration::from_millis(1),
            collection(vec![
                raw_flow("192.0.2.1", 1000, (10, 20), (100, 200)),
                raw_flow("192.0.2.2", 2000, (10, 20), (100, 200)),
            ]),
        );
        let snapshot = projector.project(
            2,
            Duration::from_secs(2),
            Duration::from_millis(1),
            collection(vec![
                raw_flow("192.0.2.1", 1000, (12, 23), (200, 400)),
                raw_flow("192.0.2.2", 2000, (20, 30), (1100, 2200)),
            ]),
        );

        assert_eq!(snapshot.flows()[0].original().source().port(), Some(2000));
        assert_eq!(
            snapshot.flows()[0].original_traffic().packets_per_second(),
            Some(10.0)
        );
        assert_eq!(
            snapshot.flows()[0].reply_traffic().bits_per_second(),
            Some(16_000.0)
        );
    }

    #[test]
    fn concurrent_icmp_ids_keep_independent_counter_history() {
        let mut projector = FlowProjector::default();
        projector.project(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            collection(vec![icmp_flow(1, 10, 100), icmp_flow(2, 20, 200)]),
        );
        let snapshot = projector.project(
            2,
            Duration::from_secs(2),
            Duration::ZERO,
            collection(vec![icmp_flow(1, 11, 200), icmp_flow(2, 30, 1_200)]),
        );

        assert_eq!(snapshot.flows().len(), 2);
        for flow in snapshot.flows() {
            let id = flow.original().icmp().unwrap().id();
            let expected_pps = if id == 1 { 1.0 } else { 10.0 };
            assert_eq!(
                flow.original_traffic().packets_per_second(),
                Some(expected_pps)
            );
        }
    }

    #[test]
    fn first_reset_and_gap_samples_do_not_create_rates() {
        let mut projector = FlowProjector::default();
        let first = projector.project(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.1", 1000, (10, 20), (100, 200))]),
        );
        assert_eq!(
            first.flows()[0].original_traffic().packets_per_second(),
            None
        );

        let reset = projector.project(
            2,
            Duration::from_secs(2),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.1", 1000, (1, 2), (10, 20))]),
        );
        assert_eq!(
            reset.flows()[0].original_traffic().packets_per_second(),
            None
        );

        projector.project_error(
            3,
            Duration::from_secs(3),
            Duration::ZERO,
            conntrack_flow::CollectError::io(
                "fixture",
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            ),
        );
        let recovered = projector.project(
            4,
            Duration::from_secs(4),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.1", 1000, (3, 4), (30, 40))]),
        );
        assert_eq!(
            recovered.flows()[0].original_traffic().packets_per_second(),
            None
        );
    }

    #[test]
    fn collection_failures_empty_tables_and_missing_accounting_stay_distinct() {
        let mut projector = FlowProjector::default();
        let denied = projector.project_error(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            conntrack_flow::CollectError::io(
                "fixture",
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            ),
        );
        assert!(matches!(
            denied.health(),
            ProviderHealth::PermissionDenied { .. }
        ));

        let unsupported = projector.project_error(
            2,
            Duration::from_secs(2),
            Duration::ZERO,
            conntrack_flow::CollectError::io(
                "fixture",
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
            ),
        );
        assert!(matches!(
            unsupported.health(),
            ProviderHealth::Unsupported { .. }
        ));

        let empty = projector.project(
            3,
            Duration::from_secs(3),
            Duration::ZERO,
            collection(Vec::new()),
        );
        assert!(matches!(empty.health(), ProviderHealth::Fresh));
        assert!(empty.flows().is_empty());

        let mut without_accounting = raw_flow("192.0.2.10", 12345, (1, 1), (1, 1));
        without_accounting.original_counters = FlowCounters::default();
        without_accounting.reply_counters = FlowCounters::default();
        let missing = projector.project(
            4,
            Duration::from_secs(4),
            Duration::ZERO,
            collection(vec![without_accounting]),
        );
        assert!(matches!(missing.health(), ProviderHealth::Partial { .. }));
        assert_eq!(missing.flows()[0].original_traffic().packets(), None);
        assert_eq!(
            missing.flows()[0].original_traffic().bits_per_second(),
            None
        );

        let mut truncated_collection = collection(Vec::new());
        truncated_collection.truncated = true;
        let truncated = projector.project(
            5,
            Duration::from_secs(5),
            Duration::ZERO,
            truncated_collection,
        );
        assert!(matches!(truncated.health(), ProviderHealth::Partial { .. }));
        assert!(truncated.truncated());
    }

    #[test]
    fn disappearing_flows_are_removed_and_reappearance_has_no_old_delta() {
        let mut projector = FlowProjector::default();
        projector.project(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.10", 12345, (1, 1), (10, 10))]),
        );
        let empty = projector.project(
            2,
            Duration::from_secs(2),
            Duration::ZERO,
            collection(Vec::new()),
        );
        assert!(empty.flows().is_empty());

        let reappeared = projector.project(
            3,
            Duration::from_secs(3),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.10", 12345, (9, 9), (90, 90))]),
        );
        assert_eq!(
            reappeared.flows()[0]
                .original_traffic()
                .packets_per_second(),
            None
        );
    }

    #[test]
    fn filter_matches_any_tuple_side_and_combines_terms_with_and() {
        let mut projector = FlowProjector::default();
        let mut nat_flow = raw_flow("192.0.2.10", 12345, (1, 1), (1, 1));
        nat_flow.reply.source.address = "10.0.0.2".parse().unwrap();
        nat_flow.reply.source.port = Some(8443);
        let snapshot = projector.project(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            collection(vec![nat_flow]),
        );
        let flow = &snapshot.flows()[0];
        for query in [
            "192.0.2.10",
            "198.51.100.2",
            "10.0.0.2",
            "443",
            "8443",
            "192.0.2.10 443",
            "10.0.0.2 8443",
        ] {
            let filter = ConntrackFlowFilter::parse(query).unwrap().unwrap();
            assert!(flow.matches_filter(&filter), "{query}");
        }
        let filter = ConntrackFlowFilter::parse("192.0.2.10 53")
            .unwrap()
            .unwrap();
        assert!(!flow.matches_filter(&filter));

        let ipv6 = projector.project(
            2,
            Duration::from_secs(2),
            Duration::ZERO,
            collection(vec![raw_flow("2001:db8::10", 5353, (1, 1), (1, 1))]),
        );
        let filter = ConntrackFlowFilter::parse("2001:db8::10 5353")
            .unwrap()
            .unwrap();
        assert!(ipv6.flows()[0].matches_filter(&filter));
    }

    #[test]
    fn structured_filters_combine_protocol_with_independent_nat_host_and_port() {
        let mut raw = raw_flow("192.0.2.10", 12345, (1, 1), (1, 1));
        raw.reply.source.address = "10.0.0.2".parse().unwrap();
        raw.reply.source.port = Some(8443);
        let flow = project_flow(&raw, None, None);
        for (host, port, proto, expected) in [
            ("10.0.0.2", "443", "TCP", true),
            ("192.0.2.10", "8443", "6", true),
            ("198.51.100.2", "12345", "all", true),
            ("10.0.0.2", "443", "UDP", false),
            ("10.0.0.3", "443", "TCP", false),
            ("10.0.0.2", "80", "TCP", false),
        ] {
            let filter = ConntrackFlowFilter::from_fields(host, port, proto)
                .unwrap()
                .unwrap();
            assert_eq!(flow.matches_filter(&filter), expected);
            let parsed = ConntrackFlowFilter::parse(filter.query()).unwrap().unwrap();
            assert_eq!(flow.matches_filter(&parsed), expected);
        }
        for (query, expected) in [
            (
                "src=192.0.2.0/24 sport=12345 dst=198.51.100.2 dport=443",
                true,
            ),
            ("host=10.0.0.0/8 port=8443", true),
            ("dst=10.0.0.0/8", false),
            ("dport=8443", false),
        ] {
            let filter = ConntrackFlowFilter::parse(query).unwrap().unwrap();
            assert_eq!(flow.matches_filter(&filter), expected, "{query}");
        }
        assert!(ConntrackFlowFilter::from_fields("", "", "all")
            .unwrap()
            .is_none());
        let ipv6 = project_flow(&raw_flow("2001:db8::10", 0, (0, 0), (0, 0)), None, None);
        let filter = ConntrackFlowFilter::from_fields("[2001:0db8::10]", "0", "tcp")
            .unwrap()
            .unwrap();
        assert!(ipv6.matches_filter(&filter));
        for query in ["tcp", "proto=6", "host=10.0.0.2 port=443 proto=tcp"] {
            assert!(flow.matches_filter(&ConntrackFlowFilter::parse(query).unwrap().unwrap()));
        }
        for query in [
            "proto=256",
            "port=65536",
            "host=example.org",
            "tcp udp tcp udp tcp udp tcp udp tcp",
        ] {
            assert!(ConntrackFlowFilter::parse(query).is_err(), "{query}");
        }
        assert!(ConntrackFlowFilter::parse(&"6 ".repeat(300)).is_err());
        assert!(ConntrackFlowFilter::from_fields("", "", &"x".repeat(1000)).is_err());
    }

    #[test]
    fn stable_key_excludes_values_and_includes_zone_nat_family_and_icmp() {
        let mut raw = raw_flow("192.0.2.10", 12345, (1, 1), (1, 1));
        let key = project_flow(&raw, None, None).key();
        raw.state = Some("TIME_WAIT".to_owned());
        raw.timeout_seconds = Some(1);
        raw.original_counters.bytes = Some(1000);
        raw.offloaded = true;
        assert!(key.matches(&project_flow(&raw, None, None)));
        raw.zone = 1;
        assert!(!key.matches(&project_flow(&raw, None, None)));
        raw.zone = 0;
        raw.reply.source.port = Some(8443);
        assert!(!key.matches(&project_flow(&raw, None, None)));
        raw.reply.source.port = Some(443);
        raw.family = AddressFamily::Ipv6;
        assert!(!key.matches(&project_flow(&raw, None, None)));
        let icmp_key = project_flow(&icmp_flow(1, 1, 1), None, None).key();
        assert!(!icmp_key.matches(&project_flow(&icmp_flow(2, 1, 1), None, None)));
        assert!(!format!("{key:?}").contains("192.0.2.10"));
    }

    #[test]
    fn all_sort_modes_use_numeric_values_and_keep_missing_after_zero_in_both_orders() {
        let previous = PreviousCounters {
            original: FlowCounters {
                packets: Some(0),
                bytes: Some(0),
            },
            reply: FlowCounters {
                packets: Some(0),
                bytes: Some(0),
            },
        };
        let low = project_flow(
            &raw_flow("192.0.2.1", 1, (2, 4), (10, 30)),
            Some(&previous),
            Some(Duration::from_secs(2)),
        );
        let high = project_flow(
            &raw_flow("192.0.2.2", 2, (10, 20), (100, 300)),
            Some(&previous),
            Some(Duration::from_secs(2)),
        );
        let zero = project_flow(
            &raw_flow("192.0.2.3", 3, (0, 0), (0, 0)),
            Some(&previous),
            Some(Duration::from_secs(2)),
        );
        let mut raw = raw_flow("192.0.2.4", 4, (0, 0), (0, 0));
        raw.original_counters = FlowCounters::default();
        raw.reply_counters = FlowCounters::default();
        let missing = project_flow(&raw, Some(&previous), Some(Duration::from_secs(2)));
        for sort in ConntrackSort::ALL {
            if matches!(
                sort,
                ConntrackSort::Protocol
                    | ConntrackSort::State
                    | ConntrackSort::Original
                    | ConntrackSort::Mark
            ) {
                continue;
            }
            for descending in [false, true] {
                let mut flows = [&missing, &high, &zero, &low];
                flows.sort_by(|left, right| sort.compare(left, right, descending));
                let keys = flows.map(ConntrackFlowSnapshot::key);
                let expected = if descending {
                    [&high, &low, &zero, &missing]
                } else if matches!(sort, ConntrackSort::TxAverage | ConntrackSort::RxAverage) {
                    [&low, &high, &zero, &missing]
                } else {
                    [&zero, &low, &high, &missing]
                };
                assert_eq!(keys, expected.map(ConntrackFlowSnapshot::key), "{sort:?}");
            }
        }
        assert_eq!(missing.total_bytes(), None);
        assert_eq!(zero.total_bytes(), Some(0));
        assert_eq!(missing.total_packets_per_second(), None);
        assert_eq!(zero.total_packets_per_second(), Some(0.0));
    }

    #[test]
    fn identity_sorts_keep_missing_state_and_mark_last_in_both_directions() {
        let low = project_flow(&raw_flow("192.0.2.1", 1, (2, 4), (10, 30)), None, None);
        let mut low = low;
        low.protocol_name = "tcp".into();
        low.state = Some("ESTABLISHED".into());
        low.ct_mark = Some(0);
        let mut high = project_flow(&raw_flow("192.0.2.2", 2, (2, 4), (10, 30)), None, None);
        high.protocol_name = "udp".into();
        high.state = Some("TIME_WAIT".into());
        high.ct_mark = Some(u32::MAX);
        let mut missing = high.clone();
        missing.state = None;
        missing.ct_mark = None;
        for sort in [
            ConntrackSort::Protocol,
            ConntrackSort::State,
            ConntrackSort::Original,
            ConntrackSort::Mark,
        ] {
            assert_eq!(sort.compare(&low, &high, false), Ordering::Less, "{sort:?}");
            assert_eq!(
                sort.compare(&low, &high, true),
                Ordering::Greater,
                "{sort:?}"
            );
        }
        for sort in [ConntrackSort::State, ConntrackSort::Mark] {
            for descending in [true, false] {
                assert_eq!(sort.compare(&missing, &low, descending), Ordering::Greater);
                assert_eq!(sort.compare(&missing, &high, descending), Ordering::Greater);
            }
        }
    }

    #[test]
    fn directional_sorts_use_the_requested_direction_and_exact_large_totals() {
        let previous = PreviousCounters {
            original: FlowCounters {
                packets: Some(0),
                bytes: Some(0),
            },
            reply: FlowCounters {
                packets: Some(0),
                bytes: Some(0),
            },
        };
        let tx = project_flow(
            &raw_flow("192.0.2.1", 1, (100, 1), (100, 1)),
            Some(&previous),
            Some(Duration::from_secs(1)),
        );
        let rx = project_flow(
            &raw_flow("192.0.2.2", 2, (1, 100), (1, 100)),
            Some(&previous),
            Some(Duration::from_secs(1)),
        );
        for sort in [
            ConntrackSort::TxBytes,
            ConntrackSort::TxPps,
            ConntrackSort::TxBandwidth,
            ConntrackSort::TxPackets,
        ] {
            assert_eq!(sort.compare(&tx, &rx, true), Ordering::Less);
        }
        for sort in [
            ConntrackSort::RxBytes,
            ConntrackSort::RxPps,
            ConntrackSort::RxBandwidth,
            ConntrackSort::RxPackets,
        ] {
            assert_eq!(sort.compare(&tx, &rx, true), Ordering::Greater);
        }
        let maximum = project_flow(
            &raw_flow("192.0.2.2", 2, (u64::MAX, u64::MAX), (u64::MAX, u64::MAX)),
            None,
            None,
        );
        let lesser = project_flow(
            &raw_flow("192.0.2.1", 1, (1, 1), (u64::MAX - 1, u64::MAX - 1)),
            None,
            None,
        );
        assert_eq!(maximum.total_bytes(), Some(u128::from(u64::MAX) * 2));
        assert_eq!(maximum.total_packets(), Some(u128::from(u64::MAX) * 2));
        for sort in [
            ConntrackSort::Bytes,
            ConntrackSort::TxBytes,
            ConntrackSort::RxBytes,
            ConntrackSort::Packets,
            ConntrackSort::TxPackets,
            ConntrackSort::RxPackets,
        ] {
            assert_eq!(sort.compare(&maximum, &lesser, true), Ordering::Less);
        }
        let mut partial = maximum.clone();
        partial.reply_traffic.bytes = None;
        assert_eq!(partial.total_bytes(), None);
        assert_eq!(
            ConntrackSort::Bytes.compare(&partial, &lesser, true),
            Ordering::Greater
        );
    }

    #[test]
    fn flow_and_filter_debug_redact_addresses() {
        let mut projector = FlowProjector::default();
        let snapshot = projector.project(
            1,
            Duration::from_secs(1),
            Duration::ZERO,
            collection(vec![raw_flow("192.0.2.10", 12345, (1, 1), (1, 1))]),
        );
        let debug = format!("{:?}", snapshot.flows()[0]);
        assert!(!debug.contains("192.0.2.10"), "{debug}");
        let filter = ConntrackFlowFilter::parse("192.0.2.10 443")
            .unwrap()
            .unwrap();
        let debug = format!("{filter:?}");
        assert!(!debug.contains("192.0.2.10"), "{debug}");
    }

    #[test]
    fn flow_session_rejects_a_zero_interval() {
        assert!(ConntrackFlowSession::start(Duration::ZERO, SystemPaths::default()).is_err());
    }
}
