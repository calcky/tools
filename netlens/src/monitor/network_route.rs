use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::Context;

#[cfg(test)]
use crate::collect::network_route::RouteMetrics;
use crate::collect::network_route::{
    self, CollectError, CollectErrorKind, Dump, RouteLookupRequest,
};
pub(crate) use crate::collect::network_route::{
    IpFamily, IpPrefix, NeighbourRow, RouteNexthop, RouteRow, RuleRow,
};
use crate::collect::valid_interface_name;

use super::{MonitorError, MonitorErrorCode, ProviderHealth, MAX_DIAGNOSTIC_BYTES};

const FAMILY_QUERY_COUNT: u8 = 2;
const IP_FAMILIES: [IpFamily; 2] = [IpFamily::Ipv4, IpFamily::Ipv6];
const NUD_FAILED: u16 = 0x20;
const MAX_LOOKUP_INPUT_BYTES: usize = 256;
const BACKGROUND_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventorySnapshot<T> {
    health: ProviderHealth,
    family_health: [ProviderHealth; 2],
    attempted_at: Duration,
    collection_duration: Duration,
    completed_queries: u8,
    failed_queries: u8,
    observed_rows: usize,
    truncated: bool,
    rows: Arc<[T]>,
}

impl<T> InventorySnapshot<T> {
    pub(crate) const fn health(&self) -> &ProviderHealth {
        &self.health
    }

    pub(crate) const fn family_health(&self, family: IpFamily) -> &ProviderHealth {
        &self.family_health[family_index(family)]
    }

    pub(crate) const fn attempted_at(&self) -> Duration {
        self.attempted_at
    }

    pub(crate) const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub(crate) const fn completed_queries(&self) -> u8 {
        self.completed_queries
    }

    pub(crate) const fn failed_queries(&self) -> u8 {
        self.failed_queries
    }

    pub(crate) const fn observed_rows(&self) -> usize {
        self.observed_rows
    }

    pub(crate) const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn rows(&self) -> &[T] {
        &self.rows
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct InventoryChangeTotals {
    route_additions: u64,
    route_removals: u64,
    rule_additions: u64,
    rule_removals: u64,
    neighbour_additions: u64,
    neighbour_removals: u64,
    neighbour_updates: u64,
    neighbour_state_changes: u64,
    neighbour_failed_transitions: u64,
}

impl InventoryChangeTotals {
    pub(crate) const fn route_additions(self) -> u64 {
        self.route_additions
    }

    pub(crate) const fn route_removals(self) -> u64 {
        self.route_removals
    }

    pub(crate) const fn rule_additions(self) -> u64 {
        self.rule_additions
    }

    pub(crate) const fn rule_removals(self) -> u64 {
        self.rule_removals
    }

    pub(crate) const fn neighbour_additions(self) -> u64 {
        self.neighbour_additions
    }

    pub(crate) const fn neighbour_removals(self) -> u64 {
        self.neighbour_removals
    }

    pub(crate) const fn neighbour_updates(self) -> u64 {
        self.neighbour_updates
    }

    pub(crate) const fn neighbour_state_changes(self) -> u64 {
        self.neighbour_state_changes
    }

    pub(crate) const fn neighbour_failed_transitions(self) -> u64 {
        self.neighbour_failed_transitions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetworkRouteSnapshot {
    sequence: u64,
    elapsed: Duration,
    collection_duration: Duration,
    routes: InventorySnapshot<RouteRow>,
    rules: InventorySnapshot<RuleRow>,
    neighbours: InventorySnapshot<NeighbourRow>,
    changes: InventoryChangeTotals,
}

impl NetworkRouteSnapshot {
    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub(crate) const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub(crate) const fn routes(&self) -> &InventorySnapshot<RouteRow> {
        &self.routes
    }

    pub(crate) const fn rules(&self) -> &InventorySnapshot<RuleRow> {
        &self.rules
    }

    pub(crate) const fn neighbours(&self) -> &InventorySnapshot<NeighbourRow> {
        &self.neighbours
    }

    pub(crate) const fn changes(&self) -> InventoryChangeTotals {
        self.changes
    }
}

struct FamilyAttempt<T> {
    attempted_at: Duration,
    collection_duration: Duration,
    ipv4: Result<Dump<T>, CollectError>,
    ipv6: Result<Dump<T>, CollectError>,
}

struct InventoryProjector<T> {
    last_complete: [Option<(Duration, Arc<[T]>)>; 2],
}

impl<T> Default for InventoryProjector<T> {
    fn default() -> Self {
        Self {
            last_complete: std::array::from_fn(|_| None),
        }
    }
}

struct FamilyProjection<T> {
    health: ProviderHealth,
    rows: Arc<[T]>,
    observed_rows: usize,
    completed: bool,
    truncated: bool,
}

impl<T> InventoryProjector<T>
where
    T: Clone + Ord,
{
    fn project(&mut self, attempt: FamilyAttempt<T>) -> InventorySnapshot<T> {
        let ipv4 = project_family(
            &mut self.last_complete[family_index(IpFamily::Ipv4)],
            attempt.attempted_at,
            attempt.ipv4,
        );
        let ipv6 = project_family(
            &mut self.last_complete[family_index(IpFamily::Ipv6)],
            attempt.attempted_at,
            attempt.ipv6,
        );
        let completed_queries = u8::from(ipv4.completed) + u8::from(ipv6.completed);
        let failed_queries = FAMILY_QUERY_COUNT.saturating_sub(completed_queries);
        let observed_rows = ipv4.observed_rows.saturating_add(ipv6.observed_rows);
        let truncated = ipv4.truncated || ipv6.truncated;
        let health = combined_family_health(&ipv4.health, &ipv6.health);
        let family_health = [ipv4.health, ipv6.health];
        let mut rows = ipv4
            .rows
            .iter()
            .chain(ipv6.rows.iter())
            .cloned()
            .collect::<Vec<_>>();
        rows.sort();
        InventorySnapshot {
            health,
            family_health,
            attempted_at: attempt.attempted_at,
            collection_duration: attempt.collection_duration,
            completed_queries,
            failed_queries,
            observed_rows,
            truncated,
            rows: rows.into(),
        }
    }
}

fn project_family<T>(
    last_complete: &mut Option<(Duration, Arc<[T]>)>,
    attempted_at: Duration,
    result: Result<Dump<T>, CollectError>,
) -> FamilyProjection<T>
where
    T: Ord,
{
    match result {
        Ok(mut dump) => {
            dump.rows.sort();
            let rows: Arc<[T]> = dump.rows.into();
            let health = if dump.truncated {
                ProviderHealth::Partial {
                    warning: monitor_error(
                        MonitorErrorCode::OutputLimit,
                        "retention limit reached; family table is incomplete",
                    ),
                }
            } else {
                *last_complete = Some((attempted_at, Arc::clone(&rows)));
                ProviderHealth::Fresh
            };
            FamilyProjection {
                health,
                rows,
                observed_rows: dump.observed_rows,
                completed: true,
                truncated: dump.truncated,
            }
        }
        Err(error) => {
            let cause = monitor_error(monitor_error_code(error.kind()), error.to_string());
            if let Some((last_success_at, rows)) = last_complete {
                FamilyProjection {
                    health: ProviderHealth::Stale {
                        last_success_at: *last_success_at,
                        age: attempted_at.saturating_sub(*last_success_at),
                        cause,
                    },
                    rows: Arc::clone(rows),
                    observed_rows: 0,
                    completed: false,
                    truncated: false,
                }
            } else {
                FamilyProjection {
                    health: ProviderHealth::Error { error: cause },
                    rows: Arc::from([]),
                    observed_rows: 0,
                    completed: false,
                    truncated: false,
                }
            }
        }
    }
}

const fn family_index(family: IpFamily) -> usize {
    match family {
        IpFamily::Ipv4 => 0,
        IpFamily::Ipv6 => 1,
    }
}

fn combined_family_health(ipv4: &ProviderHealth, ipv6: &ProviderHealth) -> ProviderHealth {
    match (ipv4, ipv6) {
        (ProviderHealth::Fresh, ProviderHealth::Fresh) => ProviderHealth::Fresh,
        (
            ProviderHealth::Stale {
                last_success_at: ipv4_success,
                age: ipv4_age,
                ..
            },
            ProviderHealth::Stale {
                last_success_at: ipv6_success,
                age: ipv6_age,
                ..
            },
        ) => ProviderHealth::Stale {
            last_success_at: (*ipv4_success).min(*ipv6_success),
            age: (*ipv4_age).max(*ipv6_age),
            cause: combined_family_error(ipv4, ipv6),
        },
        (ProviderHealth::Error { .. }, ProviderHealth::Error { .. }) => ProviderHealth::Error {
            error: combined_family_error(ipv4, ipv6),
        },
        _ => ProviderHealth::Partial {
            warning: combined_family_error(ipv4, ipv6),
        },
    }
}

fn combined_family_error(ipv4: &ProviderHealth, ipv6: &ProviderHealth) -> MonitorError {
    let code = health_error(ipv4)
        .or_else(|| health_error(ipv6))
        .map_or(MonitorErrorCode::Io, MonitorError::code);
    monitor_error(
        code,
        format!(
            "IPv4 {}; IPv6 {}",
            health_diagnostic(ipv4),
            health_diagnostic(ipv6)
        ),
    )
}

fn health_diagnostic(health: &ProviderHealth) -> String {
    health_error(health).map_or_else(
        || health.as_str().to_owned(),
        |error| format!("{} ({})", health.as_str(), error.diagnostic()),
    )
}

fn health_error(health: &ProviderHealth) -> Option<&MonitorError> {
    match health {
        ProviderHealth::Fresh => None,
        ProviderHealth::Partial { warning } => Some(warning),
        ProviderHealth::Stale { cause, .. } => Some(cause),
        ProviderHealth::Unsupported { reason } | ProviderHealth::PermissionDenied { reason } => {
            Some(reason)
        }
        ProviderHealth::Error { error } => Some(error),
    }
}

fn monitor_error_code(kind: CollectErrorKind) -> MonitorErrorCode {
    match kind {
        CollectErrorKind::InvalidRequest | CollectErrorKind::Parse => MonitorErrorCode::Parse,
        CollectErrorKind::PermissionDenied => MonitorErrorCode::PermissionDenied,
        CollectErrorKind::Unsupported => MonitorErrorCode::Unsupported,
        CollectErrorKind::NotFound => MonitorErrorCode::NotFound,
        CollectErrorKind::Timeout => MonitorErrorCode::Timeout,
        CollectErrorKind::OutputLimit => MonitorErrorCode::OutputLimit,
        CollectErrorKind::Io | CollectErrorKind::Loss | CollectErrorKind::Interrupted => {
            MonitorErrorCode::Io
        }
    }
}

fn monitor_error(code: MonitorErrorCode, diagnostic: impl AsRef<str>) -> MonitorError {
    let diagnostic = diagnostic
        .as_ref()
        .bytes()
        .filter(|byte| (0x20..=0x7e).contains(byte))
        .take(MAX_DIAGNOSTIC_BYTES)
        .map(char::from)
        .collect::<String>();
    MonitorError::new(
        code,
        if diagnostic.is_empty() {
            "network route inventory failed".to_owned()
        } else {
            diagnostic
        },
    )
    .expect("sanitized inventory diagnostics satisfy the monitor contract")
}

#[derive(Default)]
struct ChangeProjector {
    routes: [Option<BTreeSet<RouteIdentity>>; 2],
    rules: [Option<BTreeSet<RuleRow>>; 2],
    neighbours: [Option<BTreeMap<NeighbourIdentity, NeighbourRow>>; 2],
    totals: InventoryChangeTotals,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RouteIdentity {
    family: IpFamily,
    destination: IpPrefix,
    source: IpPrefix,
    tos: u8,
    table: u32,
    priority: Option<u32>,
    protocol: u8,
    scope: u8,
    route_type: u8,
    preferred_source: Option<IpAddr>,
    nexthops: Vec<RouteNexthopIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RouteNexthopIdentity {
    ifindex: Option<u32>,
    gateway: Option<IpAddr>,
    via: Option<IpAddr>,
    weight: u16,
    configuration_flags: u8,
}

impl From<&RouteNexthop> for RouteNexthopIdentity {
    fn from(nexthop: &RouteNexthop) -> Self {
        Self {
            ifindex: nexthop.ifindex,
            gateway: nexthop.gateway,
            via: nexthop.via,
            weight: nexthop.weight,
            configuration_flags: nexthop.configuration_flags(),
        }
    }
}

impl From<&RouteRow> for RouteIdentity {
    fn from(row: &RouteRow) -> Self {
        Self {
            family: row.family,
            destination: row.destination.clone(),
            source: row.source.clone(),
            tos: row.tos,
            table: row.table,
            priority: row.priority,
            protocol: row.protocol,
            scope: row.scope,
            route_type: row.route_type,
            preferred_source: row.preferred_source,
            nexthops: row
                .nexthops
                .iter()
                .map(RouteNexthopIdentity::from)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NeighbourIdentity {
    family: IpFamily,
    address: IpAddr,
    ifindex: u32,
}

impl ChangeProjector {
    fn update_routes(&mut self, snapshot: &InventorySnapshot<RouteRow>) {
        for family in IP_FAMILIES {
            if !snapshot.family_health(family).is_fresh() {
                continue;
            }
            let current = snapshot
                .rows()
                .iter()
                .filter(|row| row.family == family)
                .map(RouteIdentity::from)
                .collect::<BTreeSet<_>>();
            if let Some(previous) = &self.routes[family_index(family)] {
                self.totals.route_additions = self
                    .totals
                    .route_additions
                    .saturating_add(current.difference(previous).count() as u64);
                self.totals.route_removals = self
                    .totals
                    .route_removals
                    .saturating_add(previous.difference(&current).count() as u64);
            }
            self.routes[family_index(family)] = Some(current);
        }
    }

    fn update_rules(&mut self, snapshot: &InventorySnapshot<RuleRow>) {
        for family in IP_FAMILIES {
            if !snapshot.family_health(family).is_fresh() {
                continue;
            }
            let current = snapshot
                .rows()
                .iter()
                .filter(|row| row.family == family)
                .cloned()
                .collect::<BTreeSet<_>>();
            if let Some(previous) = &self.rules[family_index(family)] {
                self.totals.rule_additions = self
                    .totals
                    .rule_additions
                    .saturating_add(current.difference(previous).count() as u64);
                self.totals.rule_removals = self
                    .totals
                    .rule_removals
                    .saturating_add(previous.difference(&current).count() as u64);
            }
            self.rules[family_index(family)] = Some(current);
        }
    }

    fn update_neighbours(&mut self, snapshot: &InventorySnapshot<NeighbourRow>) {
        for family in IP_FAMILIES {
            if !snapshot.family_health(family).is_fresh() {
                continue;
            }
            let current = snapshot
                .rows()
                .iter()
                .filter(|row| row.family == family)
                .cloned()
                .map(|row| {
                    (
                        NeighbourIdentity {
                            family: row.family,
                            address: row.address,
                            ifindex: row.ifindex,
                        },
                        row,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            if let Some(previous) = &self.neighbours[family_index(family)] {
                self.totals.neighbour_additions = self.totals.neighbour_additions.saturating_add(
                    current
                        .keys()
                        .filter(|key| !previous.contains_key(key))
                        .count() as u64,
                );
                self.totals.neighbour_removals = self.totals.neighbour_removals.saturating_add(
                    previous
                        .keys()
                        .filter(|key| !current.contains_key(key))
                        .count() as u64,
                );
                for (identity, row) in &current {
                    let Some(old) = previous.get(identity) else {
                        continue;
                    };
                    if neighbour_observation_changed(old, row) {
                        self.totals.neighbour_updates =
                            self.totals.neighbour_updates.saturating_add(1);
                    }
                    if old.state != row.state {
                        self.totals.neighbour_state_changes =
                            self.totals.neighbour_state_changes.saturating_add(1);
                        if old.state & NUD_FAILED == 0 && row.state & NUD_FAILED != 0 {
                            self.totals.neighbour_failed_transitions =
                                self.totals.neighbour_failed_transitions.saturating_add(1);
                        }
                    }
                }
            }
            self.neighbours[family_index(family)] = Some(current);
        }
    }
}

fn neighbour_observation_changed(old: &NeighbourRow, current: &NeighbourRow) -> bool {
    old.link_address != current.link_address
        || old.state != current.state
        || old.flags != current.flags
        || old.neighbour_type != current.neighbour_type
        || old.probes != current.probes
}

#[derive(Default)]
struct NetworkRouteProjector {
    route: InventoryProjector<RouteRow>,
    rule: InventoryProjector<RuleRow>,
    neighbour: InventoryProjector<NeighbourRow>,
    changes: ChangeProjector,
}

impl NetworkRouteProjector {
    fn project(
        &mut self,
        sequence: u64,
        routes: FamilyAttempt<RouteRow>,
        rules: FamilyAttempt<RuleRow>,
        neighbours: FamilyAttempt<NeighbourRow>,
    ) -> Arc<NetworkRouteSnapshot> {
        let elapsed = neighbours.attempted_at;
        let collection_duration = routes
            .collection_duration
            .saturating_add(rules.collection_duration)
            .saturating_add(neighbours.collection_duration);
        let routes = self.route.project(routes);
        let rules = self.rule.project(rules);
        let neighbours = self.neighbour.project(neighbours);
        self.changes.update_routes(&routes);
        self.changes.update_rules(&rules);
        self.changes.update_neighbours(&neighbours);
        Arc::new(NetworkRouteSnapshot {
            sequence,
            elapsed,
            collection_duration,
            routes,
            rules,
            neighbours,
            changes: self.changes.totals,
        })
    }
}

fn collect_family_pair<T>(
    session_start: Instant,
    collect: fn(IpFamily) -> Result<Dump<T>, CollectError>,
) -> FamilyAttempt<T> {
    let started = Instant::now();
    let ipv4 = collect(IpFamily::Ipv4);
    let ipv6 = collect(IpFamily::Ipv6);
    let finished = Instant::now();
    FamilyAttempt {
        attempted_at: finished.saturating_duration_since(session_start),
        collection_duration: finished.saturating_duration_since(started),
        ipv4,
        ipv6,
    }
}

struct LatestState {
    snapshot: Option<Arc<NetworkRouteSnapshot>>,
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

    fn publish(&self, snapshot: Arc<NetworkRouteSnapshot>) {
        let mut state = self
            .state
            .lock()
            .expect("network route latest mutex poisoned");
        state.snapshot = Some(snapshot);
        self.changed.notify_all();
    }

    fn close(&self, error: Option<String>) {
        let mut state = self
            .state
            .lock()
            .expect("network route latest mutex poisoned");
        state.closed = true;
        state.error = error;
        self.changed.notify_all();
    }
}

enum WorkerCommand {
    Foreground(bool),
    Stop,
}

pub(crate) struct NetworkRouteSession {
    latest: Arc<LatestSlot>,
    control: mpsc::Sender<WorkerCommand>,
    foreground: AtomicBool,
    worker: Option<JoinHandle<()>>,
}

impl NetworkRouteSession {
    pub(crate) fn start(interval: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !interval.is_zero(),
            "network route interval must be positive"
        );
        let (control, control_receiver) = mpsc::channel();
        let latest = Arc::new(LatestSlot::new());
        let worker_latest = Arc::clone(&latest);
        let worker = thread::Builder::new()
            .name("netlens-network-route".to_owned())
            .spawn(move || run_worker(interval, control_receiver, &worker_latest))
            .context("spawn network route worker")?;
        Ok(Self {
            latest,
            control,
            foreground: AtomicBool::new(false),
            worker: Some(worker),
        })
    }

    pub(crate) fn set_foreground(&self, foreground: bool) {
        if self.foreground.swap(foreground, Ordering::Relaxed) != foreground {
            let _ = self.control.send(WorkerCommand::Foreground(foreground));
        }
    }

    pub(crate) fn wait_after(
        &self,
        sequence: u64,
        timeout: Duration,
    ) -> anyhow::Result<Option<Arc<NetworkRouteSnapshot>>> {
        let state = self
            .latest
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("network route latest mutex poisoned"))?;
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
            .map_err(|_| anyhow::anyhow!("network route latest mutex poisoned"))?;
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
                anyhow::bail!("network route worker stopped: {error}");
            }
        }
        Ok(None)
    }

    pub(crate) fn shutdown(mut self) -> anyhow::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.control.send(WorkerCommand::Stop);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("network route worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for NetworkRouteSession {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run_worker(interval: Duration, control: mpsc::Receiver<WorkerCommand>, latest: &LatestSlot) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session_start = Instant::now();
        let mut deadline = session_start;
        let mut sequence = 0_u64;
        let mut projector = NetworkRouteProjector::default();
        let mut refresh_interval = interval.max(BACKGROUND_REFRESH_INTERVAL);
        loop {
            let routes = collect_family_pair(session_start, network_route::collect_routes);
            let rules = collect_family_pair(session_start, network_route::collect_rules);
            let neighbours = collect_family_pair(session_start, network_route::collect_neighbours);
            sequence = sequence.saturating_add(1);
            latest.publish(projector.project(sequence, routes, rules, neighbours));

            deadline += refresh_interval;
            while deadline <= Instant::now() {
                deadline += refresh_interval;
            }
            match control.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(WorkerCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(WorkerCommand::Foreground(mut foreground)) => {
                    while let Ok(command) = control.try_recv() {
                        match command {
                            WorkerCommand::Stop => return,
                            WorkerCommand::Foreground(value) => foreground = value,
                        }
                    }
                    refresh_interval = if foreground {
                        interval
                    } else {
                        interval.max(BACKGROUND_REFRESH_INTERVAL)
                    };
                    deadline = Instant::now();
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }));
    latest.close(result.err().map(|_| "worker panicked".to_owned()));
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RouteLookupQuery {
    input: String,
    destination: IpAddr,
    source: Option<IpAddr>,
    input_interface: Option<String>,
    output_interface: Option<String>,
    mark: Option<u32>,
    uid: Option<u32>,
    tos: Option<u8>,
}

impl fmt::Debug for RouteLookupQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteLookupQuery")
            .field("input", &"<redacted>")
            .field("destination", &"<redacted>")
            .field("source", &self.source.map(|_| "<redacted>"))
            .field("input_interface", &self.input_interface)
            .field("output_interface", &self.output_interface)
            .field("mark", &self.mark)
            .field("uid", &self.uid)
            .field("tos", &self.tos)
            .finish()
    }
}

impl RouteLookupQuery {
    pub(crate) fn parse(input: &str) -> Result<Self, &'static str> {
        let input = input.trim();
        if input.is_empty() {
            return Err("enter a destination IP address");
        }
        if input.len() > MAX_LOOKUP_INPUT_BYTES || !input.is_ascii() {
            return Err("route lookup input is too long or contains non-ASCII text");
        }
        let mut fields = input.split_ascii_whitespace();
        let destination = fields
            .next()
            .and_then(|value| IpAddr::from_str(value).ok())
            .ok_or("destination must be an IPv4 or IPv6 address")?;
        let mut query = Self {
            input: input.to_owned(),
            destination,
            source: None,
            input_interface: None,
            output_interface: None,
            mark: None,
            uid: None,
            tos: None,
        };
        while let Some(keyword) = fields.next() {
            let value = fields
                .next()
                .ok_or("route lookup option is missing a value")?;
            match keyword {
                "from" if query.source.is_none() => {
                    query.source = Some(
                        IpAddr::from_str(value)
                            .map_err(|_| "source must be an IPv4 or IPv6 address")?,
                    );
                }
                "iif" if query.input_interface.is_none() => {
                    if !valid_interface_name(value) {
                        return Err("iif is not a valid Linux interface name");
                    }
                    query.input_interface = Some(value.to_owned());
                }
                "oif" if query.output_interface.is_none() => {
                    if !valid_interface_name(value) {
                        return Err("oif is not a valid Linux interface name");
                    }
                    query.output_interface = Some(value.to_owned());
                }
                "mark" if query.mark.is_none() => query.mark = Some(parse_u32(value)?),
                "uid" if query.uid.is_none() => query.uid = Some(parse_u32(value)?),
                "tos" if query.tos.is_none() => query.tos = Some(parse_u8(value)?),
                "from" | "iif" | "oif" | "mark" | "uid" | "tos" => {
                    return Err("route lookup option was specified more than once");
                }
                _ => return Err("unknown route lookup option"),
            }
        }
        if query
            .source
            .is_some_and(|source| source.is_ipv4() != destination.is_ipv4())
        {
            return Err("source and destination address families must match");
        }
        Ok(query)
    }

    pub(crate) fn input(&self) -> &str {
        &self.input
    }

    fn request(&self) -> Result<RouteLookupRequest, String> {
        Ok(RouteLookupRequest {
            destination: self.destination,
            source: self.source,
            input_ifindex: resolve_interface(self.input_interface.as_deref())?,
            output_ifindex: resolve_interface(self.output_interface.as_deref())?,
            mark: self.mark,
            uid: self.uid,
            tos: self.tos,
        })
    }
}

fn parse_u32(value: &str) -> Result<u32, &'static str> {
    value
        .strip_prefix("0x")
        .map_or_else(|| value.parse(), |hex| u32::from_str_radix(hex, 16))
        .map_err(|_| "route lookup numeric option is invalid")
}

fn parse_u8(value: &str) -> Result<u8, &'static str> {
    let value = parse_u32(value)?;
    u8::try_from(value).map_err(|_| "tos must be between 0 and 255")
}

fn resolve_interface(interface: Option<&str>) -> Result<Option<u32>, String> {
    let Some(interface) = interface else {
        return Ok(None);
    };
    let name = CString::new(interface).expect("validated interface names contain no NUL byte");
    let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if ifindex == 0 {
        Err(format!(
            "interface {interface} does not exist in this network namespace"
        ))
    } else {
        Ok(Some(ifindex))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RouteLookupOutcome {
    query: RouteLookupQuery,
    result: Result<RouteRow, String>,
}

impl RouteLookupOutcome {
    pub(crate) const fn query(&self) -> &RouteLookupQuery {
        &self.query
    }

    pub(crate) const fn result(&self) -> &Result<RouteRow, String> {
        &self.result
    }
}

pub(crate) fn execute_route_lookup(query: RouteLookupQuery) -> RouteLookupOutcome {
    let result = query.request().and_then(|request| {
        network_route::lookup_route(&request).map_err(|error| error.to_string())
    });
    RouteLookupOutcome { query, result }
}

#[cfg(test)]
pub(crate) fn synthetic_network_route_snapshot(sequence: u64) -> Arc<NetworkRouteSnapshot> {
    let attempted_at = Duration::from_secs(sequence.max(1));
    fn inventory<T>(rows: Vec<T>, attempted_at: Duration) -> InventorySnapshot<T> {
        InventorySnapshot {
            health: ProviderHealth::Fresh,
            family_health: [ProviderHealth::Fresh, ProviderHealth::Fresh],
            attempted_at,
            collection_duration: Duration::from_millis(2),
            completed_queries: FAMILY_QUERY_COUNT,
            failed_queries: 0,
            observed_rows: rows.len(),
            truncated: false,
            rows: Arc::from(rows),
        }
    }
    let route = RouteRow {
        family: IpFamily::Ipv4,
        destination: IpPrefix {
            address: "0.0.0.0".parse().expect("fixture IPv4 address"),
            prefix_len: 0,
        },
        source: IpPrefix {
            address: "0.0.0.0".parse().expect("fixture IPv4 address"),
            prefix_len: 0,
        },
        tos: 0,
        table: 254,
        priority: Some(100),
        protocol: 2,
        scope: 0,
        route_type: 1,
        flags: 0,
        preferred_source: Some("192.0.2.2".parse().expect("fixture IPv4 address")),
        nexthops: vec![RouteNexthop {
            ifindex: Some(2),
            interface: Some("eth0".to_owned()),
            gateway: Some("192.0.2.1".parse().expect("fixture IPv4 address")),
            via: None,
            weight: 1,
            flags: 0,
        }],
        nexthops_truncated: false,
        metrics: RouteMetrics {
            mtu: Some(1_500),
            ..RouteMetrics::default()
        },
        cache: None,
        expires: None,
        unsupported_encapsulation: false,
    };
    let rule = RuleRow {
        family: IpFamily::Ipv4,
        destination: IpPrefix {
            address: "0.0.0.0".parse().expect("fixture IPv4 address"),
            prefix_len: 0,
        },
        source: IpPrefix {
            address: "192.0.2.0".parse().expect("fixture IPv4 address"),
            prefix_len: 24,
        },
        tos: 0,
        table: 254,
        action: 1,
        flags: 0,
        priority: Some(32_766),
        fwmark: None,
        fwmask: None,
        input_interface: None,
        output_interface: None,
        goto_priority: None,
        suppress_prefix_len: None,
        suppress_interface_group: None,
        l3mdev: None,
        uid_range: None,
        tunnel_id: None,
        flow: None,
        protocol: None,
    };
    let neighbour = NeighbourRow {
        family: IpFamily::Ipv4,
        address: "192.0.2.1".parse().expect("fixture IPv4 address"),
        ifindex: 2,
        interface: Some("eth0".to_owned()),
        link_address: None,
        state: 0x02,
        flags: 0,
        neighbour_type: 1,
        probes: Some(1),
        cache: None,
    };
    Arc::new(NetworkRouteSnapshot {
        sequence,
        elapsed: attempted_at,
        collection_duration: Duration::from_millis(6),
        routes: inventory(vec![route], attempted_at),
        rules: inventory(vec![rule], attempted_at),
        neighbours: inventory(vec![neighbour], attempted_at),
        changes: InventoryChangeTotals::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_route_page_wakes_existing_session_and_preserves_sequence() {
        let session = NetworkRouteSession::start(Duration::from_secs(60)).unwrap();
        let first = session
            .wait_after(0, Duration::from_secs(2))
            .unwrap()
            .unwrap();
        session.set_foreground(true);
        let second = session
            .wait_after(first.sequence(), Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(second.sequence(), first.sequence() + 1);
        assert!(second.elapsed() >= first.elapsed());
        session.set_foreground(true);
        assert!(session
            .wait_after(second.sequence(), Duration::from_millis(30))
            .unwrap()
            .is_none());
        session.shutdown().unwrap();
    }

    #[test]
    fn parses_route_lookup_selectors_and_rejects_family_mismatch() {
        let query = RouteLookupQuery::parse(
            "198.51.100.7 from 192.0.2.1 mark 0x20 uid 1000 tos 16 iif lo oif lo",
        )
        .unwrap();
        assert_eq!(query.destination, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(query.source, Some("192.0.2.1".parse::<IpAddr>().unwrap()));
        assert_eq!(query.mark, Some(0x20));
        assert_eq!(query.uid, Some(1000));
        assert_eq!(query.tos, Some(16));
        assert_eq!(query.input_interface.as_deref(), Some("lo"));
        assert_eq!(query.output_interface.as_deref(), Some("lo"));
        assert!(RouteLookupQuery::parse("198.51.100.7 from 2001:db8::1").is_err());
        assert!(RouteLookupQuery::parse("198.51.100.7 mark 1 mark 2").is_err());
        assert!(RouteLookupQuery::parse("198.51.100.7 sport 443").is_err());
    }

    #[test]
    fn lookup_debug_output_redacts_addresses() {
        let query = RouteLookupQuery::parse("198.51.100.7 from 192.0.2.1").unwrap();
        let debug = format!("{query:?}");
        assert!(!debug.contains("198.51.100.7"));
        assert!(!debug.contains("192.0.2.1"));
    }

    #[test]
    fn inventory_projector_keeps_failed_family_stale_and_publishes_fresh_family() {
        let mut projector = InventoryProjector::default();
        let fresh = projector.project(FamilyAttempt {
            attempted_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(2),
            ipv4: Ok(Dump {
                rows: vec![test_route(IpFamily::Ipv4)],
                observed_rows: 1,
                truncated: false,
            }),
            ipv6: Ok(Dump {
                rows: vec![test_route(IpFamily::Ipv6)],
                observed_rows: 1,
                truncated: false,
            }),
        });
        assert!(fresh.health().is_fresh());
        assert_eq!(fresh.rows().len(), 2);

        let mut updated_ipv6 = test_route(IpFamily::Ipv6);
        updated_ipv6.priority = Some(200);
        let mixed = projector.project(FamilyAttempt {
            attempted_at: Duration::from_secs(2),
            collection_duration: Duration::from_millis(2),
            ipv4: Err(CollectError::test_error(
                CollectErrorKind::Io,
                "IPv4 failed",
            )),
            ipv6: Ok(Dump {
                rows: vec![updated_ipv6.clone()],
                observed_rows: 1,
                truncated: false,
            }),
        });
        assert_eq!(mixed.rows().len(), 2);
        assert!(mixed.rows().contains(&test_route(IpFamily::Ipv4)));
        assert!(mixed.rows().contains(&updated_ipv6));
        assert!(matches!(
            mixed.family_health(IpFamily::Ipv4),
            ProviderHealth::Stale { .. }
        ));
        assert!(mixed.family_health(IpFamily::Ipv6).is_fresh());
        assert!(matches!(mixed.health(), ProviderHealth::Partial { .. }));

        let mut changes = ChangeProjector::default();
        changes.update_routes(&fresh);
        changes.update_routes(&mixed);
        assert_eq!(changes.totals.route_additions(), 1);
        assert_eq!(changes.totals.route_removals(), 1);
    }

    #[test]
    fn route_changes_skip_truncated_and_failed_family_snapshots() {
        let mut inventory = InventoryProjector::default();
        let mut changes = ChangeProjector::default();
        let ipv4_baseline = test_route(IpFamily::Ipv4);
        let ipv6_baseline = test_route(IpFamily::Ipv6);
        let baseline = inventory.project(FamilyAttempt {
            attempted_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(2),
            ipv4: Ok(Dump {
                rows: vec![ipv4_baseline.clone()],
                observed_rows: 1,
                truncated: false,
            }),
            ipv6: Ok(Dump {
                rows: vec![ipv6_baseline.clone()],
                observed_rows: 1,
                truncated: false,
            }),
        });
        changes.update_routes(&baseline);

        let mut truncated_route = ipv4_baseline.clone();
        truncated_route.priority = Some(100);
        let partial = inventory.project(FamilyAttempt {
            attempted_at: Duration::from_secs(2),
            collection_duration: Duration::from_millis(2),
            ipv4: Ok(Dump {
                rows: vec![truncated_route.clone()],
                observed_rows: 2,
                truncated: true,
            }),
            ipv6: Ok(Dump {
                rows: vec![ipv6_baseline.clone()],
                observed_rows: 1,
                truncated: false,
            }),
        });
        assert!(partial.rows().contains(&truncated_route));
        changes.update_routes(&partial);

        let stale = inventory.project(FamilyAttempt {
            attempted_at: Duration::from_secs(3),
            collection_duration: Duration::from_millis(2),
            ipv4: Err(CollectError::test_error(
                CollectErrorKind::Io,
                "IPv4 failed",
            )),
            ipv6: Ok(Dump {
                rows: vec![ipv6_baseline.clone()],
                observed_rows: 1,
                truncated: false,
            }),
        });
        assert!(stale.rows().contains(&ipv4_baseline));
        assert!(!stale.rows().contains(&truncated_route));
        changes.update_routes(&stale);
        assert_eq!(changes.totals.route_additions(), 0);
        assert_eq!(changes.totals.route_removals(), 0);

        let mut recovered_route = ipv4_baseline.clone();
        recovered_route.priority = Some(200);
        let recovered = inventory.project(FamilyAttempt {
            attempted_at: Duration::from_secs(4),
            collection_duration: Duration::from_millis(2),
            ipv4: Ok(Dump {
                rows: vec![recovered_route],
                observed_rows: 1,
                truncated: false,
            }),
            ipv6: Ok(Dump {
                rows: vec![ipv6_baseline],
                observed_rows: 1,
                truncated: false,
            }),
        });
        changes.update_routes(&recovered);
        assert_eq!(changes.totals.route_additions(), 1);
        assert_eq!(changes.totals.route_removals(), 1);
    }

    #[test]
    fn neighbour_cache_age_progress_does_not_count_as_an_update() {
        let mut projector = ChangeProjector::default();
        let mut neighbour = test_neighbour();
        neighbour.cache = Some(crate::collect::network_route::NeighbourCacheInfo {
            confirmed_age: Duration::from_secs(1),
            used_age: Duration::from_secs(2),
            updated_age: Duration::from_secs(3),
            references: 1,
        });
        projector.update_neighbours(&test_neighbour_snapshot(neighbour.clone()));

        let cache = neighbour.cache.as_mut().unwrap();
        cache.confirmed_age += Duration::from_secs(1);
        cache.used_age += Duration::from_secs(1);
        cache.updated_age += Duration::from_secs(1);
        projector.update_neighbours(&test_neighbour_snapshot(neighbour.clone()));

        assert_eq!(projector.totals.neighbour_updates(), 0);

        neighbour.probes = Some(2);
        projector.update_neighbours(&test_neighbour_snapshot(neighbour.clone()));
        assert_eq!(projector.totals.neighbour_updates(), 1);

        neighbour.interface = Some("wan0".to_owned());
        neighbour.cache.as_mut().unwrap().references = 2;
        projector.update_neighbours(&test_neighbour_snapshot(neighbour));
        assert_eq!(projector.totals.neighbour_updates(), 1);
    }

    #[test]
    fn route_cache_age_progress_does_not_count_as_remove_and_add() {
        let mut projector = ChangeProjector::default();
        let mut route = test_route(IpFamily::Ipv4);
        route.cache = Some(crate::collect::network_route::RouteCacheInfo {
            client_references: 1,
            last_use: Duration::from_secs(1),
            expires: Some(Duration::from_secs(30)),
            error: 0,
            used: 2,
            id: 3,
            timestamp_ticks: 4,
            timestamp_age: Duration::from_secs(5),
        });
        route.expires = Some(Duration::from_secs(30));
        projector.update_routes(&test_route_snapshot(route.clone()));

        let cache = route.cache.as_mut().unwrap();
        cache.last_use += Duration::from_secs(1);
        cache.expires = Some(Duration::from_secs(29));
        cache.timestamp_age += Duration::from_secs(1);
        route.expires = Some(Duration::from_secs(29));
        projector.update_routes(&test_route_snapshot(route.clone()));

        assert_eq!(projector.totals.route_additions(), 0);
        assert_eq!(projector.totals.route_removals(), 0);

        route.priority = Some(100);
        projector.update_routes(&test_route_snapshot(route));
        assert_eq!(projector.totals.route_additions(), 1);
        assert_eq!(projector.totals.route_removals(), 1);
    }

    #[test]
    fn resolved_interface_name_does_not_change_route_identity() {
        let mut projector = ChangeProjector::default();
        let mut route = test_route(IpFamily::Ipv4);
        route.nexthops.push(RouteNexthop {
            ifindex: Some(2),
            interface: Some("eth0".to_owned()),
            gateway: Some("192.0.2.1".parse().unwrap()),
            via: None,
            weight: 1,
            flags: 0,
        });
        projector.update_routes(&test_route_snapshot(route.clone()));

        route.nexthops[0].interface = Some("wan0".to_owned());
        projector.update_routes(&test_route_snapshot(route.clone()));
        assert_eq!(projector.totals.route_additions(), 0);
        assert_eq!(projector.totals.route_removals(), 0);

        route.nexthops[0].interface = None;
        route.nexthops[0].flags = 0x01 | 0x08 | 0x10 | 0x20 | 0x40;
        projector.update_routes(&test_route_snapshot(route.clone()));
        assert_eq!(projector.totals.route_additions(), 0);
        assert_eq!(projector.totals.route_removals(), 0);

        route.nexthops[0].flags |= 0x04;
        projector.update_routes(&test_route_snapshot(route.clone()));
        assert_eq!(projector.totals.route_additions(), 1);
        assert_eq!(projector.totals.route_removals(), 1);

        route.nexthops[0].ifindex = Some(3);
        projector.update_routes(&test_route_snapshot(route));
        assert_eq!(projector.totals.route_additions(), 2);
        assert_eq!(projector.totals.route_removals(), 2);
    }

    #[test]
    fn tos_specific_routes_have_distinct_identities() {
        let first = test_route(IpFamily::Ipv4);
        let mut second = first.clone();
        second.tos = 0x10;

        let identities = [&first, &second]
            .into_iter()
            .map(RouteIdentity::from)
            .collect::<BTreeSet<_>>();

        assert_eq!(identities.len(), 2);
    }

    fn test_route(family: IpFamily) -> RouteRow {
        RouteRow {
            family,
            destination: IpPrefix {
                address: match family {
                    IpFamily::Ipv4 => "0.0.0.0".parse().unwrap(),
                    IpFamily::Ipv6 => "::".parse().unwrap(),
                },
                prefix_len: 0,
            },
            source: IpPrefix {
                address: match family {
                    IpFamily::Ipv4 => "0.0.0.0".parse().unwrap(),
                    IpFamily::Ipv6 => "::".parse().unwrap(),
                },
                prefix_len: 0,
            },
            tos: 0,
            table: 254,
            priority: None,
            protocol: 2,
            scope: 0,
            route_type: 1,
            flags: 0,
            preferred_source: None,
            nexthops: Vec::new(),
            nexthops_truncated: false,
            metrics: RouteMetrics::default(),
            cache: None,
            expires: None,
            unsupported_encapsulation: false,
        }
    }

    fn test_neighbour() -> NeighbourRow {
        NeighbourRow {
            family: IpFamily::Ipv4,
            address: "192.0.2.1".parse().unwrap(),
            ifindex: 2,
            interface: Some("eth0".to_owned()),
            link_address: None,
            state: 0x02,
            flags: 0,
            neighbour_type: 1,
            probes: Some(1),
            cache: None,
        }
    }

    fn test_neighbour_snapshot(row: NeighbourRow) -> InventorySnapshot<NeighbourRow> {
        InventorySnapshot {
            health: ProviderHealth::Fresh,
            family_health: [ProviderHealth::Fresh, ProviderHealth::Fresh],
            attempted_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(1),
            completed_queries: FAMILY_QUERY_COUNT,
            failed_queries: 0,
            observed_rows: 1,
            truncated: false,
            rows: Arc::from(vec![row]),
        }
    }

    fn test_route_snapshot(row: RouteRow) -> InventorySnapshot<RouteRow> {
        InventorySnapshot {
            health: ProviderHealth::Fresh,
            family_health: [ProviderHealth::Fresh, ProviderHealth::Fresh],
            attempted_at: Duration::from_secs(1),
            collection_duration: Duration::from_millis(1),
            completed_queries: FAMILY_QUERY_COUNT,
            failed_queries: 0,
            observed_rows: 1,
            truncated: false,
            rows: Arc::from(vec![row]),
        }
    }
}
