use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{mpsc, Arc, Condvar, Mutex, Once};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::collect::SystemPaths;

use super::focus::CollectionFocus;
use super::history::{HistoryObservation, HistoryProjection, HistoryStore};
use super::model::{EngineSeriesProjection, ValidatedEngineRows};
use super::{
    BaselineOrigin, CounterBits, CounterContinuity, CounterSpan, EngineTelemetry, GaugeChange,
    GaugeSummary, MetricId, MetricKind, MetricLabels, MetricReading, MonitorError, MonitorPlan,
    MonitorSnapshot, MonitorValidationError, ProjectedValue, ProviderHealth, ProviderId,
    ProviderSample, ProviderSnapshot, ReadingOutcome, SeriesId, SeriesSnapshot, SeriesValue,
    StateValue, UnavailableReason, MAX_ADMITTED_SERIES, RAW_PRIVATE_NIC_METRIC_ID,
};

static MONITOR_WORKER_PANIC_HOOK: Once = Once::new();

fn install_monitor_worker_panic_hook() {
    MONITOR_WORKER_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic| {
            if thread::current().name() != Some("netlens-monitor") {
                previous(panic);
            }
        }));
    });
}

pub(crate) trait MonitorCollector: Send + 'static {
    fn hardirq_snapshot(&self) -> Option<Arc<super::hardirq::HardirqSnapshot>> {
        None
    }
    fn set_focus(&mut self, _section: CollectionFocus) {}
    fn collection_focus(&self) -> Option<CollectionFocus> {
        None
    }
    fn collect(&mut self, session_start: Instant) -> Vec<ProviderSample>;
    fn network_namespace(&self) -> Option<String>;
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct SeriesKey {
    metric: MetricId,
    labels: MetricLabels,
}

#[derive(Clone, Copy)]
struct Candidate<'a> {
    source: &'a ProviderId,
    provider_index: usize,
    outcome: &'a ReadingOutcome,
    priority: usize,
    observed_at: Duration,
}

#[derive(Clone)]
enum RawSeries {
    Counter {
        last: u64,
        bits: Option<CounterBits>,
        last_at: Duration,
        since_delta: u64,
    },
    Gauge {
        last: u64,
        last_at: Duration,
        min: u64,
        max: u64,
        sum: u128,
        count: u64,
    },
    State {
        last: StateValue,
        last_at: Duration,
        changed_at: Option<Duration>,
    },
}

struct SeriesState {
    id: SeriesId,
    source: ProviderId,
    first_seen: Duration,
    baseline_origin: BaselineOrigin,
    baseline_at: Duration,
    had_gap: bool,
    raw: Option<RawSeries>,
    last_projection: Option<(Duration, EngineSeriesProjection)>,
    spare_projection: Option<SeriesSnapshot>,
}

struct SeriesEntry {
    key: SeriesKey,
    state: Option<SeriesState>,
}

struct ReadingSlot {
    key: SeriesKey,
    index: Option<usize>,
    priority: usize,
}

#[derive(Default)]
struct ProviderRuntime {
    last_success_at: Option<Duration>,
    last_sample: Option<ProviderSample>,
    unavailable_readings: u32,
    slots: Vec<ReadingSlot>,
}

pub(crate) struct MonitorEngine {
    focus: Option<CollectionFocus>,
    generation: u64,
    sequence: u64,
    started_at_unix_ms: u64,
    providers: BTreeMap<ProviderId, ProviderRuntime>,
    series_index: HashMap<SeriesKey, usize>,
    series: Vec<SeriesEntry>,
    history: HistoryStore,
    telemetry: EngineTelemetry,
}

impl MonitorEngine {
    pub(crate) fn new(
        started_at_unix_ms: u64,
        interval: Duration,
    ) -> Result<Self, MonitorValidationError> {
        Ok(Self {
            focus: None,
            generation: 1,
            sequence: 0,
            started_at_unix_ms,
            providers: BTreeMap::new(),
            series_index: HashMap::new(),
            series: Vec::new(),
            history: HistoryStore::new(interval),
            telemetry: EngineTelemetry::default(),
        })
    }

    fn set_focus(&mut self, focus: Option<CollectionFocus>) {
        if self.focus == focus {
            return;
        }
        self.focus = focus;
        for entry in &mut self.series {
            if let Some(state) = &mut entry.state {
                if focus.is_some_and(|focus| !focus.allows_provider(state.source.as_str())) {
                    // Counter rates must restart; cached configuration may return
                    // with its original timestamp and remains the same observation.
                    if matches!(state.raw, Some(RawSeries::Counter { .. }) | None) {
                        state.had_gap = true;
                        state.last_projection = None;
                    }
                }
            }
        }
    }

    pub(crate) fn note_skipped_snapshot(&mut self) {
        self.telemetry.skipped_snapshots = self.telemetry.skipped_snapshots.saturating_add(1);
    }

    pub(crate) fn note_missed_samples(&mut self, count: u64) {
        self.telemetry.provider_missed_samples =
            self.telemetry.provider_missed_samples.saturating_add(count);
    }

    pub(crate) fn ingest(
        &mut self,
        elapsed: Duration,
        samples: Vec<ProviderSample>,
        network_namespace: Option<String>,
    ) -> Result<Arc<MonitorSnapshot>, MonitorValidationError> {
        self.telemetry.samples_scheduled = self.telemetry.samples_scheduled.saturating_add(1);

        let mut provider_ids = BTreeSet::new();
        let mut provider_health = BTreeMap::new();
        let mut provider_rows = Vec::with_capacity(samples.len());
        let mut new_keys = BTreeSet::new();
        let mut changed_layouts = BTreeSet::new();

        for sample in &samples {
            if !provider_ids.insert(sample.provider().clone()) {
                return Err(MonitorValidationError::DuplicateProvider);
            }
            let runtime = self.providers.entry(sample.provider().clone()).or_default();
            let same_readings = runtime
                .last_sample
                .as_ref()
                .is_some_and(|previous| std::ptr::eq(previous.readings(), sample.readings()));
            let same_layout = same_readings
                || (runtime.slots.len() == sample.readings().len()
                    && runtime
                        .slots
                        .iter()
                        .zip(sample.readings())
                        .all(|(slot, reading)| {
                            slot.key.metric == *reading.metric()
                                && slot.key.labels == *reading.labels()
                        }));
            if !same_layout {
                changed_layouts.insert(sample.provider().clone());
                for reading in sample.readings() {
                    let key = SeriesKey {
                        metric: reading.metric().clone(),
                        labels: reading.labels().clone(),
                    };
                    if !self.series_index.contains_key(&key) {
                        new_keys.insert(key);
                    }
                }
            } else {
                // Rejected identities remain retryable and count once per cycle.
                new_keys.extend(
                    runtime
                        .slots
                        .iter()
                        .filter(|slot| slot.index.is_none())
                        .map(|slot| slot.key.clone()),
                );
            }
            let health = project_provider_health(sample.health(), sample.finished_at(), runtime);
            if sample.health().allows_readings() {
                runtime.last_success_at = Some(sample.finished_at());
            }
            if !same_readings {
                runtime.unavailable_readings = sample
                    .readings()
                    .iter()
                    .filter(|reading| matches!(reading.outcome(), ReadingOutcome::Unavailable(_)))
                    .count()
                    .try_into()
                    .unwrap_or(u32::MAX);
            }
            runtime.last_sample = Some(sample.clone());
            provider_rows.push(ProviderSnapshot::new(
                sample.provider().clone(),
                health.clone(),
                sample.finished_at(),
                sample.collection_duration(),
                runtime.unavailable_readings,
            )?);
            provider_health.insert(sample.provider().clone(), (provider_rows.len() - 1, health));
        }

        // IDs are assigned only on schema changes and remain in admission order.
        for key in new_keys {
            if self.series.len() == MAX_ADMITTED_SERIES {
                self.telemetry.rejected_series = self.telemetry.rejected_series.saturating_add(1);
                continue;
            }
            let index = self.series.len();
            self.series_index.insert(key.clone(), index);
            self.series.push(SeriesEntry { key, state: None });
        }
        let mut candidates: Vec<Option<Candidate>> = vec![None; self.series.len()];
        for (provider_index, sample) in samples.iter().enumerate() {
            let runtime = self
                .providers
                .get_mut(sample.provider())
                .expect("provider was registered");
            if changed_layouts.contains(sample.provider()) {
                runtime.slots = sample
                    .readings()
                    .iter()
                    .map(|reading| {
                        let key = SeriesKey {
                            metric: reading.metric().clone(),
                            labels: reading.labels().clone(),
                        };
                        let priority = reading
                            .metric()
                            .descriptor()
                            .ok_or(MonitorValidationError::UnknownMetric)?
                            .source_priority(sample.provider())
                            .ok_or(MonitorValidationError::MetricSourceMismatch)?;
                        Ok(ReadingSlot {
                            index: self.series_index.get(&key).copied(),
                            key,
                            priority,
                        })
                    })
                    .collect::<Result<_, MonitorValidationError>>()?;
            }
            for (reading, slot) in sample.readings().iter().zip(&runtime.slots) {
                let Some(index) = slot.index else { continue };
                let candidate = Candidate {
                    source: sample.provider(),
                    provider_index,
                    outcome: reading.outcome(),
                    priority: slot.priority,
                    observed_at: sample.finished_at(),
                };
                match &candidates[index] {
                    Some(current) if !candidate_precedes(&candidate, current) => {}
                    _ => {
                        candidates[index] = Some(candidate);
                    }
                }
            }
        }

        let first_cycle = self.sequence == 0;
        let mut rows = ValidatedEngineRows::new(elapsed, provider_rows, self.series.len())?;
        for (index, candidate) in candidates.into_iter().enumerate() {
            match candidate {
                Some(Candidate {
                    source,
                    provider_index,
                    outcome: ReadingOutcome::Observed(reading),
                    observed_at,
                    ..
                }) => {
                    let row = self.project_observed(
                        index,
                        source,
                        reading,
                        observed_at,
                        first_cycle,
                        elapsed,
                    )?;
                    rows.push(row, Some(provider_index))?;
                }
                Some(Candidate {
                    source,
                    provider_index,
                    outcome: ReadingOutcome::Unavailable(reason),
                    observed_at,
                    ..
                }) => {
                    self.admit_unavailable_series(index, source, observed_at, first_cycle)?;
                    if let Some(row) =
                        self.project_gap(index, elapsed, Some((source, *reason)), &provider_health)?
                    {
                        rows.push(row, Some(provider_index))?;
                    }
                }
                None => {
                    if self.series[index].state.as_ref().is_some_and(|state| {
                        self.focus
                            .is_some_and(|focus| !focus.allows_provider(state.source.as_str()))
                    }) {
                        continue;
                    }
                    if let Some(row) = self.project_gap(index, elapsed, None, &provider_health)? {
                        let provider_index = provider_health
                            .get(row.snapshot().source())
                            .map(|(index, _)| *index);
                        rows.push(row, provider_index)?;
                    }
                }
            }
        }

        self.sequence = self.sequence.saturating_add(1);
        self.telemetry.samples_completed = self.telemetry.samples_completed.saturating_add(1);
        self.telemetry.history_buckets = rows.history_buckets();
        self.telemetry.history_bytes = self.telemetry.history_buckets.saturating_mul(128);
        MonitorSnapshot::from_engine(
            self.generation,
            self.sequence,
            self.started_at_unix_ms,
            network_namespace,
            rows,
            self.telemetry,
        )
        .map(Arc::new)
    }

    fn project_observed(
        &mut self,
        index: usize,
        source: &ProviderId,
        reading: &MetricReading,
        observed_at: Duration,
        first_cycle: bool,
        elapsed: Duration,
    ) -> Result<EngineSeriesProjection, MonitorValidationError> {
        // A scheduled cache hit is the same observation, not a zero-length sample.
        let entry = &mut self.series[index];
        let key = &entry.key;
        if let Some(state) = &entry.state {
            if !state.had_gap && state.source == *source {
                if let Some((at, snapshot)) = &state.last_projection {
                    if *at == observed_at {
                        return snapshot.clone().at(elapsed);
                    }
                }
            }
        }
        let is_new = entry.state.is_none();
        if is_new {
            let first_seen = if first_cycle {
                Duration::ZERO
            } else {
                observed_at
            };
            let baseline_origin = if first_cycle {
                BaselineOrigin::SessionStart
            } else {
                BaselineOrigin::FirstObserved
            };
            let id = SeriesId::new(index as u64 + 1)?;
            let raw = raw_from_reading(reading.clone(), observed_at);
            entry.state = Some(SeriesState {
                id,
                source: source.clone(),
                first_seen,
                baseline_origin,
                baseline_at: first_seen,
                had_gap: false,
                raw: Some(raw),
                last_projection: None,
                spare_projection: None,
            });
            if key.metric.as_str() != RAW_PRIVATE_NIC_METRIC_ID {
                if let Some(value) = numeric_reading(reading) {
                    self.history.record(
                        id,
                        HistoryObservation::new(
                            first_seen,
                            observed_at,
                            value,
                            0,
                            Duration::ZERO,
                            false,
                        ),
                    );
                }
            }
        }

        let suppress_gauge_projection = key.metric.as_str() == RAW_PRIVATE_NIC_METRIC_ID;
        let state = entry
            .state
            .as_mut()
            .expect("series was inserted before projection");
        if is_new {
            let value = first_series_value(
                state
                    .raw
                    .as_ref()
                    .expect("a newly observed series has a raw value"),
                observed_at,
                None,
                state.baseline_at,
            )?;
            let history = self.history.projection(state.id)?;
            let snapshot = series_snapshot(key, state, value, history)?;
            let snapshot = EngineSeriesProjection::new(snapshot, elapsed)?;
            state.spare_projection = state
                .last_projection
                .replace((observed_at, snapshot.clone()))
                .map(|(_, row)| row.into_snapshot());
            return Ok(snapshot);
        }
        let source_changed = state.source != *source;
        let recovered = state.had_gap || source_changed;
        if source_changed {
            state.source = source.clone();
        }
        state.had_gap = false;
        let value = update_raw_series(
            state,
            reading.clone(),
            observed_at,
            recovered,
            suppress_gauge_projection,
        )?;
        let history_value = numeric_series_value(&value);
        if key.metric.as_str() != RAW_PRIVATE_NIC_METRIC_ID {
            if let Some((current, delta, reset, interval)) = history_value {
                self.history.record(
                    state.id,
                    HistoryObservation::new(
                        observed_at.saturating_sub(interval),
                        observed_at,
                        current,
                        delta,
                        interval,
                        reset,
                    ),
                );
            }
        }
        let history = self.history.projection(state.id)?;
        let snapshot = series_snapshot(key, state, value, history)?;
        let snapshot = EngineSeriesProjection::new(snapshot, elapsed)?;
        state.spare_projection = state
            .last_projection
            .replace((observed_at, snapshot.clone()))
            .map(|(_, row)| row.into_snapshot());
        Ok(snapshot)
    }

    fn admit_unavailable_series(
        &mut self,
        index: usize,
        source: &ProviderId,
        observed_at: Duration,
        first_cycle: bool,
    ) -> Result<(), MonitorValidationError> {
        let entry = &mut self.series[index];
        if entry.state.is_some() {
            return Ok(());
        }

        let first_seen = if first_cycle {
            Duration::ZERO
        } else {
            observed_at
        };
        let baseline_origin = if first_cycle {
            BaselineOrigin::SessionStart
        } else {
            BaselineOrigin::FirstObserved
        };
        let id = SeriesId::new(index as u64 + 1)?;
        entry.state = Some(SeriesState {
            id,
            source: source.clone(),
            first_seen,
            baseline_origin,
            baseline_at: first_seen,
            had_gap: false,
            raw: None,
            last_projection: None,
            spare_projection: None,
        });
        Ok(())
    }

    fn project_gap(
        &mut self,
        index: usize,
        elapsed: Duration,
        reported_unavailable: Option<(&ProviderId, UnavailableReason)>,
        provider_health: &BTreeMap<ProviderId, (usize, ProviderHealth)>,
    ) -> Result<Option<EngineSeriesProjection>, MonitorValidationError> {
        let entry = &mut self.series[index];
        let key = &entry.key;
        let Some(state) = entry.state.as_mut() else {
            return Ok(None);
        };
        if let Some((source, _)) = reported_unavailable {
            if state.source != *source {
                state.source = source.clone();
            }
        }
        if !state.had_gap {
            self.history.record_gap(state.id, elapsed);
        }
        state.had_gap = true;
        let history = self.history.projection(state.id)?;
        let health = provider_health.get(&state.source).map(|(_, health)| health);
        let metric = key
            .metric
            .descriptor()
            .ok_or(MonitorValidationError::UnknownMetric)?;
        let value = if let Some((_, reason)) = reported_unavailable {
            unavailable_series_value(metric.kind, reason)
        } else {
            match health {
                Some(ProviderHealth::Stale { cause, .. }) => match state.raw.as_ref() {
                    Some(raw) => stale_series_value(raw, elapsed, cause.code()),
                    None => unavailable_series_value(metric.kind, UnavailableReason::Missing),
                },
                Some(ProviderHealth::Partial { warning }) => match state.raw.as_ref() {
                    Some(raw) => stale_series_value(raw, elapsed, warning.code()),
                    None => unavailable_series_value(metric.kind, UnavailableReason::Missing),
                },
                Some(ProviderHealth::Fresh) => {
                    unavailable_series_value(metric.kind, UnavailableReason::Missing)
                }
                Some(
                    ProviderHealth::Unsupported { .. }
                    | ProviderHealth::PermissionDenied { .. }
                    | ProviderHealth::Error { .. },
                )
                | None => return Ok(None),
            }
        };
        let snapshot = series_snapshot(key, state, value, history)?;
        let snapshot = EngineSeriesProjection::new(snapshot, elapsed)?;
        state.spare_projection = state
            .last_projection
            .replace((elapsed, snapshot.clone()))
            .map(|(_, row)| row.into_snapshot());
        Ok(Some(snapshot))
    }
}

fn candidate_precedes(candidate: &Candidate<'_>, current: &Candidate<'_>) -> bool {
    let candidate_observed = matches!(candidate.outcome, ReadingOutcome::Observed(_));
    let current_observed = matches!(current.outcome, ReadingOutcome::Observed(_));
    (candidate_observed && !current_observed)
        || (candidate_observed == current_observed && candidate.priority < current.priority)
}

fn project_provider_health(
    health: &ProviderHealth,
    finished_at: Duration,
    runtime: &ProviderRuntime,
) -> ProviderHealth {
    if health.allows_readings() {
        return health.clone();
    }
    let Some(last_success_at) = runtime.last_success_at else {
        return health.clone();
    };
    let Some(cause) = provider_error(health) else {
        return health.clone();
    };
    ProviderHealth::Stale {
        last_success_at,
        age: finished_at.saturating_sub(last_success_at),
        cause,
    }
}

fn provider_error(health: &ProviderHealth) -> Option<MonitorError> {
    match health {
        ProviderHealth::Stale { cause, .. } => Some(cause.clone()),
        ProviderHealth::Partial { warning } => Some(warning.clone()),
        ProviderHealth::Unsupported { reason } | ProviderHealth::PermissionDenied { reason } => {
            Some(reason.clone())
        }
        ProviderHealth::Error { error } => Some(error.clone()),
        ProviderHealth::Fresh => None,
    }
}

fn raw_from_reading(reading: MetricReading, observed_at: Duration) -> RawSeries {
    match reading {
        MetricReading::Counter { value, bits } => RawSeries::Counter {
            last: value,
            bits,
            last_at: observed_at,
            since_delta: 0,
        },
        MetricReading::Gauge(value) => RawSeries::Gauge {
            last: value,
            last_at: observed_at,
            min: value,
            max: value,
            sum: u128::from(value),
            count: 1,
        },
        MetricReading::State(value) => RawSeries::State {
            last: value,
            last_at: observed_at,
            changed_at: None,
        },
    }
}

fn numeric_reading(reading: &MetricReading) -> Option<u64> {
    match reading {
        MetricReading::Counter { value, .. } | MetricReading::Gauge(value) => Some(*value),
        MetricReading::State(_) => None,
    }
}

fn update_raw_series(
    state: &mut SeriesState,
    reading: MetricReading,
    observed_at: Duration,
    recovered: bool,
    suppress_gauge_projection: bool,
) -> Result<SeriesValue, MonitorValidationError> {
    if recovered {
        state.baseline_origin = BaselineOrigin::RecoveredAfterGap;
        state.baseline_at = observed_at;
        state.raw = Some(raw_from_reading(reading, observed_at));
        return first_series_value(
            state
                .raw
                .as_ref()
                .expect("a recovered series has a raw value"),
            observed_at,
            Some(CounterContinuity::RecoveredAfterGap),
            state.baseline_at,
        );
    }

    match (&mut state.raw, reading) {
        (
            Some(RawSeries::Counter {
                last,
                bits,
                last_at,
                since_delta,
            }),
            MetricReading::Counter {
                value,
                bits: current_bits,
            },
        ) => {
            let sample_elapsed = observed_at.saturating_sub(*last_at);
            let continuity = counter_continuity(*last, value, *bits, current_bits, sample_elapsed);
            let reset = matches!(continuity, CounterContinuity::Reset);
            let delta = match continuity {
                CounterContinuity::Continuous { delta, .. }
                | CounterContinuity::Wrapped { delta, .. } => delta,
                CounterContinuity::FirstSample
                | CounterContinuity::Reset
                | CounterContinuity::RecoveredAfterGap => 0,
            };
            if reset {
                state.baseline_origin = BaselineOrigin::Reset;
                state.baseline_at = observed_at;
                *since_delta = 0;
            } else {
                *since_delta = since_delta.saturating_add(delta);
            }
            *last = value;
            *bits = current_bits;
            *last_at = observed_at;
            let since_baseline = (!reset)
                .then(|| observed_at.saturating_sub(state.baseline_at))
                .filter(|elapsed| *elapsed > Duration::ZERO)
                .map(|elapsed| CounterSpan::new(*since_delta, elapsed))
                .transpose()?;
            Ok(SeriesValue::Counter {
                current: ProjectedValue::Fresh { value, observed_at },
                interval: Some(continuity),
                since_baseline,
            })
        }
        (
            Some(RawSeries::Gauge {
                last,
                last_at,
                min,
                max,
                sum,
                count,
            }),
            MetricReading::Gauge(value),
        ) => {
            if suppress_gauge_projection {
                *last = value;
                *last_at = observed_at;
                return Ok(SeriesValue::Gauge {
                    current: ProjectedValue::Fresh { value, observed_at },
                    interval: None,
                    since_baseline: None,
                });
            }
            let interval = observed_at.saturating_sub(*last_at);
            let change = (interval > Duration::ZERO)
                .then(|| GaugeChange::new(i128::from(value) - i128::from(*last), interval))
                .transpose()?;
            *last = value;
            *last_at = observed_at;
            *min = (*min).min(value);
            *max = (*max).max(value);
            *sum = sum.saturating_add(u128::from(value));
            *count = count.saturating_add(1);
            let summary_elapsed = observed_at.saturating_sub(state.baseline_at);
            let since_baseline = (summary_elapsed > Duration::ZERO)
                .then(|| GaugeSummary::new(*min, *max, *sum, *count, summary_elapsed))
                .transpose()?;
            Ok(SeriesValue::Gauge {
                current: ProjectedValue::Fresh { value, observed_at },
                interval: change,
                since_baseline,
            })
        }
        (
            Some(RawSeries::State {
                last,
                last_at,
                changed_at,
            }),
            MetricReading::State(value),
        ) => {
            if last != &value {
                *last = value.clone();
                *changed_at = Some(observed_at);
            }
            *last_at = observed_at;
            let continuity_start = changed_at.unwrap_or(state.baseline_at);
            Ok(SeriesValue::State {
                current: ProjectedValue::Fresh { value, observed_at },
                changed_at: *changed_at,
                continuous_for: Some(observed_at.saturating_sub(continuity_start)),
            })
        }
        _ => Err(MonitorValidationError::MetricKindMismatch),
    }
}

fn first_series_value(
    raw: &RawSeries,
    observed_at: Duration,
    counter_continuity: Option<CounterContinuity>,
    baseline_at: Duration,
) -> Result<SeriesValue, MonitorValidationError> {
    match raw {
        RawSeries::Counter { last, .. } => Ok(SeriesValue::Counter {
            current: ProjectedValue::Fresh {
                value: *last,
                observed_at,
            },
            interval: counter_continuity.or(Some(CounterContinuity::FirstSample)),
            since_baseline: None,
        }),
        RawSeries::Gauge { last, .. } => Ok(SeriesValue::Gauge {
            current: ProjectedValue::Fresh {
                value: *last,
                observed_at,
            },
            interval: None,
            since_baseline: None,
        }),
        RawSeries::State { last, .. } => Ok(SeriesValue::State {
            current: ProjectedValue::Fresh {
                value: last.clone(),
                observed_at,
            },
            changed_at: None,
            continuous_for: Some(observed_at.saturating_sub(baseline_at)),
        }),
    }
}

fn counter_continuity(
    previous: u64,
    current: u64,
    previous_bits: Option<CounterBits>,
    current_bits: Option<CounterBits>,
    elapsed: Duration,
) -> CounterContinuity {
    if current >= previous {
        return CounterContinuity::Continuous {
            delta: current - previous,
            elapsed,
        };
    }
    let Some(bits) = previous_bits.filter(|bits| Some(*bits) == current_bits) else {
        return CounterContinuity::Reset;
    };
    let maximum = match bits {
        CounterBits::Bits32 => u64::from(u32::MAX),
        CounterBits::Bits64 => u64::MAX,
    };
    let maximum = u128::from(maximum);
    if u128::from(previous) < maximum * 3 / 4 || u128::from(current) > maximum / 4 {
        return CounterContinuity::Reset;
    }
    let delta = maximum - u128::from(previous) + 1 + u128::from(current);
    match u64::try_from(delta) {
        Ok(delta) => CounterContinuity::Wrapped {
            delta,
            elapsed,
            bits,
        },
        Err(_) => CounterContinuity::Reset,
    }
}

fn numeric_series_value(value: &SeriesValue) -> Option<(u64, u64, bool, Duration)> {
    match value {
        SeriesValue::Counter {
            current: ProjectedValue::Fresh { value, .. },
            interval,
            ..
        } => {
            let (delta, reset, elapsed) = match interval {
                Some(CounterContinuity::Continuous { delta, elapsed })
                | Some(CounterContinuity::Wrapped { delta, elapsed, .. }) => {
                    (*delta, false, *elapsed)
                }
                Some(CounterContinuity::Reset) => (0, true, Duration::ZERO),
                Some(CounterContinuity::FirstSample | CounterContinuity::RecoveredAfterGap)
                | None => (0, false, Duration::ZERO),
            };
            Some((*value, delta, reset, elapsed))
        }
        SeriesValue::Gauge {
            current: ProjectedValue::Fresh { value, .. },
            ..
        } => Some((*value, 0, false, Duration::ZERO)),
        SeriesValue::Counter { .. } | SeriesValue::Gauge { .. } | SeriesValue::State { .. } => None,
    }
}

fn stale_series_value(
    raw: &RawSeries,
    elapsed: Duration,
    cause: super::MonitorErrorCode,
) -> SeriesValue {
    match raw {
        RawSeries::Counter { last, last_at, .. } => SeriesValue::Counter {
            current: ProjectedValue::Stale {
                last: *last,
                observed_at: *last_at,
                age: elapsed.saturating_sub(*last_at),
                cause,
            },
            interval: None,
            since_baseline: None,
        },
        RawSeries::Gauge { last, last_at, .. } => SeriesValue::Gauge {
            current: ProjectedValue::Stale {
                last: *last,
                observed_at: *last_at,
                age: elapsed.saturating_sub(*last_at),
                cause,
            },
            interval: None,
            since_baseline: None,
        },
        RawSeries::State { last, last_at, .. } => SeriesValue::State {
            current: ProjectedValue::Stale {
                last: last.clone(),
                observed_at: *last_at,
                age: elapsed.saturating_sub(*last_at),
                cause,
            },
            changed_at: None,
            continuous_for: None,
        },
    }
}

fn unavailable_series_value(kind: MetricKind, reason: UnavailableReason) -> SeriesValue {
    match kind {
        MetricKind::Counter => SeriesValue::Counter {
            current: ProjectedValue::Unavailable { reason },
            interval: None,
            since_baseline: None,
        },
        MetricKind::Gauge => SeriesValue::Gauge {
            current: ProjectedValue::Unavailable { reason },
            interval: None,
            since_baseline: None,
        },
        MetricKind::State => SeriesValue::State {
            current: ProjectedValue::Unavailable { reason },
            changed_at: None,
            continuous_for: None,
        },
    }
}

fn series_snapshot(
    key: &SeriesKey,
    state: &mut SeriesState,
    value: SeriesValue,
    history: HistoryProjection<'_>,
) -> Result<SeriesSnapshot, MonitorValidationError> {
    if let Some(spare) = state.spare_projection.take() {
        return spare.reproject(
            &state.source,
            state.baseline_origin,
            state.baseline_at,
            value,
            history,
        );
    }
    let metric = key
        .metric
        .descriptor()
        .ok_or(MonitorValidationError::UnknownMetric)?;
    let owner = match &state.last_projection {
        Some((_, previous)) => previous.snapshot().provider().clone(),
        None => ProviderId::new(metric.owner)?,
    };
    SeriesSnapshot::new(
        state.id,
        owner,
        state.source.clone(),
        key.metric.clone(),
        key.labels.clone(),
        state.first_seen,
        state.baseline_origin,
        state.baseline_at,
        value,
        history.coverage(),
    )
    .and_then(|snapshot| snapshot.with_history(history))
}

struct LatestState {
    snapshot: Option<Arc<MonitorSnapshot>>,
    last_observed_sequence: u64,
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
                last_observed_sequence: 0,
                closed: false,
                error: None,
            }),
            changed: Condvar::new(),
        }
    }

    fn publish(&self, snapshot: Arc<MonitorSnapshot>) -> bool {
        let mut state = self.state.lock().expect("latest snapshot mutex poisoned");
        let skipped = state
            .snapshot
            .as_ref()
            .is_some_and(|current| current.sequence() > state.last_observed_sequence);
        state.snapshot = Some(snapshot);
        self.changed.notify_all();
        skipped
    }

    fn close(&self, error: Option<String>) {
        let mut state = self.state.lock().expect("latest snapshot mutex poisoned");
        state.closed = true;
        state.error = error;
        self.changed.notify_all();
    }
}

enum WorkerCommand {
    Focus(CollectionFocus),
    Stop,
}

pub struct MonitorSession {
    latest: Arc<LatestSlot>,
    control: mpsc::Sender<WorkerCommand>,
    focus: Mutex<CollectionFocus>,
    worker: Option<JoinHandle<()>>,
}

impl MonitorSession {
    pub fn start(plan: MonitorPlan, paths: SystemPaths) -> anyhow::Result<Self> {
        let collector = super::providers::BuiltinCollector::new(paths);
        Self::start_with_collector(plan, Box::new(collector))
    }

    pub(crate) fn start_with_collector(
        plan: MonitorPlan,
        mut collector: Box<dyn MonitorCollector>,
    ) -> anyhow::Result<Self> {
        plan.validate().context("validate monitor plan")?;
        install_monitor_worker_panic_hook();
        let interval = plan.interval().get();
        let focus = plan.initial_section().into();
        collector.set_focus(focus);
        let started_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_millis()
            .try_into()
            .context("system timestamp does not fit in u64")?;
        let (control, control_receiver) = mpsc::channel();
        let latest = Arc::new(LatestSlot::new());
        let worker_latest = Arc::clone(&latest);
        let worker = thread::Builder::new()
            .name("netlens-monitor".to_owned())
            .spawn(move || {
                run_worker(
                    interval,
                    started_at_unix_ms,
                    collector,
                    control_receiver,
                    &worker_latest,
                );
            })
            .context("spawn monitor worker")?;
        Ok(Self {
            latest,
            control,
            focus: Mutex::new(focus),
            worker: Some(worker),
        })
    }

    pub(crate) fn set_focus(&self, section: impl Into<CollectionFocus>) {
        let section = section.into();
        let mut focus = self.focus.lock().expect("monitor focus mutex poisoned");
        if *focus != section {
            *focus = section;
            let _ = self.control.send(WorkerCommand::Focus(section));
        }
    }

    pub fn wait_after(
        &self,
        sequence: u64,
        timeout: Duration,
    ) -> anyhow::Result<Option<Arc<MonitorSnapshot>>> {
        let state = self
            .latest
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("latest snapshot mutex poisoned"))?;
        let (mut state, _) = self
            .latest
            .changed
            .wait_timeout_while(state, timeout, |state| {
                !state.closed
                    && state
                        .snapshot
                        .as_ref()
                        .is_none_or(|snapshot| snapshot.sequence() <= sequence)
            })
            .map_err(|_| anyhow::anyhow!("latest snapshot mutex poisoned"))?;
        if let Some(snapshot) = state
            .snapshot
            .as_ref()
            .filter(|snapshot| snapshot.sequence() > sequence)
            .cloned()
        {
            state.last_observed_sequence = snapshot.sequence();
            return Ok(Some(snapshot));
        }
        if state.closed {
            if let Some(error) = &state.error {
                anyhow::bail!("monitor worker stopped: {error}");
            }
        }
        Ok(None)
    }

    pub fn shutdown(mut self) -> anyhow::Result<()> {
        self.stop_and_join()
    }

    fn stop_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.control.send(WorkerCommand::Stop);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("monitor worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for MonitorSession {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

fn run_worker(
    interval: Duration,
    started_at_unix_ms: u64,
    mut collector: Box<dyn MonitorCollector>,
    control: mpsc::Receiver<WorkerCommand>,
    latest: &LatestSlot,
) {
    let result = catch_unwind(AssertUnwindSafe(
        || -> Result<(), MonitorValidationError> {
            let session_start = Instant::now();
            let mut deadline = session_start;
            let mut engine = MonitorEngine::new(started_at_unix_ms, interval)?;
            loop {
                let samples = collector.collect(session_start);
                engine.set_focus(collector.collection_focus());
                let elapsed = samples
                    .iter()
                    .map(ProviderSample::finished_at)
                    .max()
                    .unwrap_or_else(|| session_start.elapsed());
                let mut snapshot =
                    engine.ingest(elapsed, samples, collector.network_namespace())?;
                Arc::make_mut(&mut snapshot).hardirq = collector.hardirq_snapshot();
                if latest.publish(snapshot) {
                    engine.note_skipped_snapshot();
                }

                deadline += interval;
                let now = Instant::now();
                let mut missed = 0_u64;
                while deadline <= now {
                    deadline += interval;
                    missed = missed.saturating_add(1);
                }
                engine.note_missed_samples(missed);
                match control.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(WorkerCommand::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Ok(WorkerCommand::Focus(section)) => {
                        collector.set_focus(section);
                        // Coalesce navigation while collection was in flight.
                        while let Ok(command) = control.try_recv() {
                            match command {
                                WorkerCommand::Stop => return Ok(()),
                                WorkerCommand::Focus(section) => collector.set_focus(section),
                            }
                        }
                        deadline = Instant::now();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            Ok(())
        },
    ));
    let error = match result {
        Ok(result) => result.err().map(|error| error.to_string()),
        Err(_) => Some("monitor worker panicked".to_owned()),
    };
    latest.close(error);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{
        HistoryCoverage, MetricLabel, MetricLabels, MonitorSection, SampleReading, OWNER_SOCKET,
    };

    const SOURCE: &str = "linux.proc.net.snmp";
    const METRIC: &str = "linux.socket.tcp.retransmitted_segments";

    #[test]
    fn suspended_cached_settings_and_gauges_keep_their_original_observation() {
        let labels = MetricLabels::new([
            (MetricLabel::Interface, "eth0".into()),
            (MetricLabel::Ifindex, "2".into()),
            (MetricLabel::Statistic, "Speed".into()),
        ])
        .unwrap();
        for (source, metric, labels, reading) in [
            (
                "linux.ethtool.link_text",
                "linux.nic.setting",
                labels,
                MetricReading::State(StateValue::new("1000Mb/s").unwrap()),
            ),
            (
                "linux.proc.net.sockstat",
                "linux.socket.tcp.in_use",
                MetricLabels::default(),
                MetricReading::Gauge(7),
            ),
        ] {
            let sample = ProviderSample::new(
                ProviderId::new(source).unwrap(),
                Duration::from_secs(2),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![SampleReading::observed(
                    MetricId::new(metric).unwrap(),
                    labels,
                    reading,
                )],
            )
            .unwrap();
            let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
            engine.set_focus(Some(MonitorSection::Overview.into()));
            engine.ingest(Duration::from_secs(1), vec![], None).unwrap();
            let first = engine
                .ingest(Duration::from_secs(2), vec![sample.clone()], None)
                .unwrap();
            engine.set_focus(Some(MonitorSection::Hardirq.into()));
            assert!(engine
                .ingest(Duration::from_secs(3), vec![], None)
                .unwrap()
                .series()
                .is_empty());
            engine.set_focus(Some(MonitorSection::Overview.into()));
            let resumed = engine
                .ingest(Duration::from_secs(4), vec![sample], None)
                .unwrap();
            assert_eq!(resumed.series()[0], first.series()[0]);
            assert_eq!(
                resumed.providers()[0].last_attempt_at(),
                Duration::from_secs(2)
            );
        }
    }

    #[test]
    fn suspended_sources_disappear_and_resume_with_a_fresh_rate_baseline() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine.set_focus(Some(MonitorSection::Socket.into()));
        let mut identity = None;
        for (at, value, expected_rate) in [(1, 10, None), (2, 20, Some(10.0))] {
            let snapshot = engine
                .ingest(
                    Duration::from_secs(at),
                    vec![sample(at, value, ProviderHealth::Fresh)],
                    None,
                )
                .unwrap();
            let row = &snapshot.series()[0];
            identity = Some(row.id());
            let SeriesValue::Counter { interval, .. } = row.value() else {
                panic!("expected counter")
            };
            assert_eq!(
                interval.and_then(CounterContinuity::rate_per_second),
                expected_rate
            );
        }

        engine.set_focus(Some(MonitorSection::Hardirq.into()));
        for at in [3, 9] {
            let snapshot = engine
                .ingest(Duration::from_secs(at), Vec::new(), None)
                .unwrap();
            assert!(snapshot.series().is_empty());
            assert!(snapshot.providers().is_empty());
        }
        engine.set_focus(Some(MonitorSection::Socket.into()));
        for (at, value, expected_rate) in [(10, 10_000, None), (11, 10_010, Some(10.0))] {
            let snapshot = engine
                .ingest(
                    Duration::from_secs(at),
                    vec![sample(at, value, ProviderHealth::Fresh)],
                    None,
                )
                .unwrap();
            let row = &snapshot.series()[0];
            assert_eq!(Some(row.id()), identity);
            let SeriesValue::Counter { interval, .. } = row.value() else {
                panic!("expected counter")
            };
            assert_eq!(
                interval.and_then(CounterContinuity::rate_per_second),
                expected_rate
            );
        }
        let missing = engine
            .ingest(
                Duration::from_secs(12),
                vec![sample(
                    12,
                    0,
                    ProviderHealth::Error {
                        error: MonitorError::new(
                            super::super::MonitorErrorCode::Io,
                            "failed probe",
                        )
                        .unwrap(),
                    },
                )],
                None,
            )
            .unwrap();
        assert!(matches!(
            missing.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Stale { last: 10_010, .. },
                ..
            }
        ));
    }

    fn sample(at: u64, value: u64, health: ProviderHealth) -> ProviderSample {
        let readings = if health.allows_readings() {
            vec![SampleReading::observed(
                MetricId::new(METRIC).unwrap(),
                MetricLabels::default(),
                MetricReading::Counter { value, bits: None },
            )]
        } else {
            Vec::new()
        };
        ProviderSample::new(
            ProviderId::new(SOURCE).unwrap(),
            Duration::from_secs(at),
            Duration::from_millis(1),
            health,
            readings,
        )
        .unwrap()
    }

    fn rebuild_with_public_constructor(snapshot: &MonitorSnapshot) -> MonitorSnapshot {
        MonitorSnapshot::new(
            snapshot.generation(),
            snapshot.sequence(),
            snapshot.started_at_unix_ms(),
            snapshot.elapsed(),
            snapshot.network_namespace().map(str::to_owned),
            snapshot.providers().to_vec(),
            snapshot.series().to_vec(),
            snapshot.telemetry(),
        )
        .unwrap()
    }

    #[test]
    fn reversed_cached_provider_order_preserves_fresh_stale_and_unavailable_rows() {
        let gauges = ProviderSample::new(
            ProviderId::new("linux.proc.net.sockstat").unwrap(),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![
                SampleReading::observed(
                    MetricId::new("linux.socket.tcp.in_use").unwrap(),
                    MetricLabels::default(),
                    MetricReading::Gauge(7),
                ),
                SampleReading::unavailable(
                    MetricId::new("linux.socket.udp.in_use").unwrap(),
                    MetricLabels::default(),
                    UnavailableReason::InvalidValue,
                ),
            ],
        )
        .unwrap();
        let initial = vec![sample(1, 10, ProviderHealth::Fresh), gauges.clone()];
        let mut reordered = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut reference = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        for engine in [&mut reordered, &mut reference] {
            engine
                .ingest(Duration::from_secs(1), initial.clone(), None)
                .unwrap();
        }
        let failed = sample(
            2,
            0,
            ProviderHealth::Error {
                error: MonitorError::new(super::super::MonitorErrorCode::Io, "failed").unwrap(),
            },
        );
        let mut retained = Vec::new();
        for at in 2..=6 {
            let ordered = vec![failed.clone(), gauges.clone()];
            let mut input = ordered.clone();
            if at % 2 == 0 {
                input.reverse();
            }
            let snapshot = reordered
                .ingest(Duration::from_secs(at), input, None)
                .unwrap();
            let expected = reference
                .ingest(Duration::from_secs(at), ordered, None)
                .unwrap();
            assert_eq!(snapshot, expected);
            assert_eq!(*snapshot, rebuild_with_public_constructor(&snapshot));
            assert_eq!(snapshot.series().len(), 3);
            for row in snapshot.series() {
                match row.metric().as_str() {
                    METRIC => assert!(matches!(row.value(), SeriesValue::Counter {
                        current: ProjectedValue::Stale { last: 10, observed_at, age, .. }, ..
                    } if *observed_at == Duration::from_secs(1) && *age == Duration::from_secs(at - 1))),
                    "linux.socket.tcp.in_use" => {
                        assert!(matches!(row.value(), SeriesValue::Gauge {
                            current: ProjectedValue::Fresh { value: 7, observed_at }, ..
                        } if *observed_at == Duration::from_secs(1)));
                        assert_eq!(row.history().bucket_count(), 1);
                    }
                    "linux.socket.udp.in_use" => assert!(matches!(
                        row.value(),
                        SeriesValue::Gauge {
                            current: ProjectedValue::Unavailable {
                                reason: UnavailableReason::InvalidValue
                            },
                            ..
                        }
                    )),
                    metric => panic!("unexpected metric: {metric}"),
                }
            }
            retained.push((snapshot, expected));
        }
        for (snapshot, expected) in retained {
            assert_eq!(snapshot, expected);
        }
    }

    #[test]
    fn equal_values_with_new_timestamps_keep_observations_and_full_validation() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut retained = Vec::new();
        for at in 1..=40 {
            let input = sample(at, 10, ProviderHealth::Fresh);
            let snapshot = engine
                .ingest(Duration::from_secs(at), vec![input.clone()], None)
                .unwrap();
            let full = rebuild_with_public_constructor(&snapshot);
            assert_eq!(*snapshot, full);
            let row = &snapshot.series()[0];
            assert_eq!(row.history().end(), Some(Duration::from_secs(at)));
            assert_eq!(
                row.history_buckets()
                    .iter()
                    .map(|bucket| bucket.count())
                    .sum::<u64>(),
                at
            );
            if at > 1 {
                assert!(matches!(row.value(), SeriesValue::Counter {
                    current: ProjectedValue::Fresh { value: 10, observed_at },
                    interval: Some(CounterContinuity::Continuous { delta: 0, elapsed }), ..
                } if *observed_at == Duration::from_secs(at) && *elapsed == Duration::from_secs(1)));
            }
            let cached = engine
                .ingest(
                    Duration::from_secs(at) + Duration::from_millis(500),
                    vec![input],
                    None,
                )
                .unwrap();
            assert_eq!(cached.series(), snapshot.series());
            assert_eq!(*cached, rebuild_with_public_constructor(&cached));
            retained.push((snapshot, full));
        }
        assert_eq!(
            retained.last().unwrap().0.series()[0]
                .history_buckets()
                .len(),
            16
        );
        for (snapshot, full) in retained {
            assert_eq!(*snapshot, full);
        }
    }

    #[test]
    fn counter_keeps_a_stable_id_and_since_start_delta() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let first = engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let second = engine
            .ingest(
                Duration::from_secs(2),
                vec![sample(2, 15, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();

        assert_eq!(first.series()[0].id(), second.series()[0].id());
        assert_eq!(second.series()[0].provider().as_str(), OWNER_SOCKET);
        assert!(matches!(
            second.series()[0].value(),
            SeriesValue::Counter {
                interval: Some(CounterContinuity::Continuous { delta: 5, .. }),
                since_baseline: Some(span),
                ..
            } if span.delta() == 5
        ));
        assert_eq!(second.series()[0].history_buckets().len(), 2);
        assert_eq!(second.series()[0].history_buckets()[1].delta(), 5);
        assert_eq!(
            second.series()[0].history_buckets()[1].start(),
            Duration::from_secs(1)
        );
        assert_eq!(
            second.series()[0].history_buckets()[1].end(),
            Duration::from_secs(2)
        );
        assert_eq!(
            second.series()[0].history_buckets()[1].trend_rate_per_second(),
            Some(5.0)
        );
    }

    #[test]
    fn unknown_width_decrease_is_a_reset() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let snapshot = engine
            .ingest(
                Duration::from_secs(2),
                vec![sample(2, 2, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();

        assert!(matches!(
            snapshot.series()[0].value(),
            SeriesValue::Counter {
                interval: Some(CounterContinuity::Reset),
                since_baseline: None,
                ..
            }
        ));
        assert_eq!(
            snapshot.series()[0].baseline_origin(),
            BaselineOrigin::Reset
        );
    }

    #[test]
    fn cached_counter_samples_preserve_rates_history_and_real_intervals() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let second = engine
            .ingest(
                Duration::from_secs(6),
                vec![sample(6, 35, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        for now in 7..11 {
            let cached = engine
                .ingest(
                    Duration::from_secs(now),
                    vec![sample(6, 35, ProviderHealth::Fresh)],
                    None,
                )
                .unwrap();
            assert_eq!(cached.series(), second.series());
            assert_eq!(
                cached.providers()[0].last_attempt_at(),
                Duration::from_secs(6)
            );
        }
        let next = engine
            .ingest(
                Duration::from_secs(11),
                vec![sample(11, 85, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        assert!(matches!(next.series()[0].value(), SeriesValue::Counter {
            interval: Some(CounterContinuity::Continuous { delta: 50, elapsed }),
            since_baseline: Some(span), ..
        } if *elapsed == Duration::from_secs(5) && span.delta() == 75));
    }

    #[test]
    fn cached_gauges_do_not_bias_summary_or_history() {
        let gauge = |at, value| {
            ProviderSample::new(
                ProviderId::new("linux.proc.net.sockstat").unwrap(),
                Duration::from_secs(at),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![SampleReading::observed(
                    MetricId::new("linux.socket.tcp.in_use").unwrap(),
                    MetricLabels::default(),
                    MetricReading::Gauge(value),
                )],
            )
            .unwrap()
        };
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(Duration::from_secs(1), vec![gauge(1, 10)], None)
            .unwrap();
        let second = engine
            .ingest(Duration::from_secs(2), vec![gauge(2, 20)], None)
            .unwrap();
        for now in 3..6 {
            let cached = engine
                .ingest(Duration::from_secs(now), vec![gauge(2, 20)], None)
                .unwrap();
            assert_eq!(cached.series(), second.series());
        }
        let next = engine
            .ingest(Duration::from_secs(6), vec![gauge(6, 30)], None)
            .unwrap();
        assert!(matches!(next.series()[0].value(), SeriesValue::Gauge {
            since_baseline: Some(summary), ..
        } if summary.count() == 3 && summary.average() == 20.0));
    }

    #[test]
    fn cached_failure_keeps_one_gap_and_recovery_starts_a_new_baseline() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let failed = sample(
            6,
            0,
            ProviderHealth::Error {
                error: MonitorError::new(super::super::MonitorErrorCode::Io, "probe failed")
                    .unwrap(),
            },
        );
        for now in 6..11 {
            let snapshot = engine
                .ingest(Duration::from_secs(now), vec![failed.clone()], None)
                .unwrap();
            assert!(matches!(
                snapshot.series()[0].value(),
                SeriesValue::Counter {
                    current: ProjectedValue::Stale { last: 10, .. },
                    interval: None,
                    ..
                }
            ));
            assert_eq!(snapshot.series()[0].history().gaps(), 1);
        }
        let recovered = engine
            .ingest(
                Duration::from_secs(11),
                vec![sample(11, 50, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        assert!(matches!(
            recovered.series()[0].value(),
            SeriesValue::Counter {
                interval: Some(CounterContinuity::RecoveredAfterGap),
                ..
            }
        ));
        let next = engine
            .ingest(
                Duration::from_secs(16),
                vec![sample(16, 75, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        assert!(matches!(next.series()[0].value(), SeriesValue::Counter {
            interval: Some(CounterContinuity::Continuous { delta: 25, elapsed }), ..
        } if *elapsed == Duration::from_secs(5)));
    }

    #[test]
    fn failed_provider_keeps_the_previous_value_as_stale() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let error = MonitorError::new(super::super::MonitorErrorCode::Io, "read failed").unwrap();
        let snapshot = engine
            .ingest(
                Duration::from_secs(2),
                vec![sample(2, 0, ProviderHealth::Error { error })],
                None,
            )
            .unwrap();

        assert_eq!(snapshot.providers()[0].health().as_str(), "stale");
        assert!(matches!(
            snapshot.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Stale { last: 10, .. },
                ..
            }
        ));
    }

    #[test]
    fn partial_provider_keeps_current_rows_fresh_and_missing_rows_stale() {
        fn nic_sample(at: u64, health: ProviderHealth, values: &[(&str, u64)]) -> ProviderSample {
            let readings = values
                .iter()
                .map(|(interface, value)| {
                    SampleReading::observed(
                        MetricId::new(RAW_PRIVATE_NIC_METRIC_ID).unwrap(),
                        MetricLabels::new([
                            (MetricLabel::Interface, (*interface).to_owned()),
                            (
                                MetricLabel::Ifindex,
                                if *interface == "eth0" { "2" } else { "3" }.to_owned(),
                            ),
                            (MetricLabel::Statistic, "driver_stat".to_owned()),
                        ])
                        .unwrap(),
                        MetricReading::Gauge(*value),
                    )
                })
                .collect();
            ProviderSample::new(
                ProviderId::new("linux.ethtool.text").unwrap(),
                Duration::from_secs(at),
                Duration::ZERO,
                health,
                readings,
            )
            .unwrap()
        }

        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![nic_sample(
                    1,
                    ProviderHealth::Fresh,
                    &[("eth0", 10), ("eth1", 20)],
                )],
                None,
            )
            .unwrap();
        let warning = MonitorError::new(
            super::super::MonitorErrorCode::Timeout,
            "eth1 collection timed out",
        )
        .unwrap();
        let snapshot = engine
            .ingest(
                Duration::from_secs(2),
                vec![nic_sample(
                    2,
                    ProviderHealth::Partial { warning },
                    &[("eth0", 11)],
                )],
                None,
            )
            .unwrap();

        assert!(matches!(
            snapshot.providers()[0].health(),
            ProviderHealth::Partial { warning }
                if warning.code() == super::super::MonitorErrorCode::Timeout
        ));
        let eth0 = snapshot
            .series()
            .iter()
            .find(|series| series.labels().get(MetricLabel::Interface) == Some("eth0"))
            .unwrap();
        let eth1 = snapshot
            .series()
            .iter()
            .find(|series| series.labels().get(MetricLabel::Interface) == Some("eth1"))
            .unwrap();
        assert!(matches!(
            eth0.value(),
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh { value: 11, .. },
                ..
            }
        ));
        assert!(matches!(
            eth1.value(),
            SeriesValue::Gauge {
                current: ProjectedValue::Stale {
                    last: 20,
                    cause: super::super::MonitorErrorCode::Timeout,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn partial_provider_preserves_an_explicit_unavailable_reason() {
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![sample(1, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        let warning = MonitorError::new(
            super::super::MonitorErrorCode::Timeout,
            "some fields timed out",
        )
        .unwrap();
        let missing = SampleReading::unavailable(
            MetricId::new(METRIC).unwrap(),
            MetricLabels::default(),
            UnavailableReason::InvalidValue,
        );
        let partial = ProviderSample::new(
            ProviderId::new(SOURCE).unwrap(),
            Duration::from_secs(2),
            Duration::ZERO,
            ProviderHealth::Partial { warning },
            vec![missing],
        )
        .unwrap();

        let snapshot = engine
            .ingest(Duration::from_secs(2), vec![partial], None)
            .unwrap();

        assert!(matches!(
            snapshot.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Unavailable {
                    reason: UnavailableReason::InvalidValue
                },
                ..
            }
        ));
    }

    #[test]
    fn first_unavailable_reading_is_visible_and_recovers_with_the_same_id() {
        let missing = SampleReading::unavailable(
            MetricId::new(METRIC).unwrap(),
            MetricLabels::default(),
            UnavailableReason::Missing,
        );
        let unavailable = ProviderSample::new(
            ProviderId::new(SOURCE).unwrap(),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![missing],
        )
        .unwrap();
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let first = engine
            .ingest(Duration::from_secs(1), vec![unavailable], None)
            .unwrap();

        assert_eq!(first.series().len(), 1);
        assert!(matches!(
            first.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Unavailable {
                    reason: UnavailableReason::Missing
                },
                ..
            }
        ));

        let second = engine
            .ingest(
                Duration::from_secs(2),
                vec![sample(2, 10, ProviderHealth::Fresh)],
                None,
            )
            .unwrap();
        assert_eq!(first.series()[0].id(), second.series()[0].id());
        assert_eq!(
            second.series()[0].baseline_origin(),
            BaselineOrigin::RecoveredAfterGap
        );
        assert!(matches!(
            second.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Fresh { value: 10, .. },
                interval: Some(CounterContinuity::RecoveredAfterGap),
                ..
            }
        ));
    }

    #[test]
    fn bits64_wrap_requires_the_previous_value_to_be_in_the_top_quarter() {
        assert_eq!(
            counter_continuity(
                u64::MAX / 2,
                1,
                Some(CounterBits::Bits64),
                Some(CounterBits::Bits64),
                Duration::from_secs(1),
            ),
            CounterContinuity::Reset
        );
        assert!(matches!(
            counter_continuity(
                u64::MAX - 2,
                1,
                Some(CounterBits::Bits64),
                Some(CounterBits::Bits64),
                Duration::from_secs(1),
            ),
            CounterContinuity::Wrapped { delta: 4, .. }
        ));
    }

    #[test]
    fn raw_private_gauges_never_project_rate_or_since_baseline() {
        fn raw_private_sample(at: u64, value: u64) -> ProviderSample {
            let labels = MetricLabels::new([
                (MetricLabel::Interface, "eth0".to_owned()),
                (MetricLabel::Ifindex, "2".to_owned()),
                (MetricLabel::Statistic, "vendor_counter".to_owned()),
            ])
            .unwrap();
            let reading = SampleReading::observed(
                MetricId::new(RAW_PRIVATE_NIC_METRIC_ID).unwrap(),
                labels,
                MetricReading::Gauge(value),
            );
            ProviderSample::new(
                ProviderId::new("linux.ethtool.netlink").unwrap(),
                Duration::from_secs(at),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![reading],
            )
            .unwrap()
        }

        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        engine
            .ingest(
                Duration::from_secs(1),
                vec![raw_private_sample(1, 10)],
                None,
            )
            .unwrap();
        let snapshot = engine
            .ingest(
                Duration::from_secs(2),
                vec![raw_private_sample(2, 15)],
                None,
            )
            .unwrap();

        assert!(matches!(
            snapshot.series()[0].value(),
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh { value: 15, .. },
                interval: None,
                since_baseline: None,
            }
        ));
        assert_eq!(snapshot.series()[0].history(), HistoryCoverage::empty());
        assert!(snapshot.series()[0].history_buckets().is_empty());
    }

    #[test]
    fn link_fallback_sources_keep_one_canonical_interface_series() {
        fn link_sample(source: &str, at: u64, value: u64) -> ProviderSample {
            let labels = MetricLabels::new([
                (MetricLabel::Interface, "eth0".to_owned()),
                (MetricLabel::Ifindex, "2".to_owned()),
            ])
            .unwrap();
            let reading = SampleReading::observed(
                MetricId::new("linux.netdevice.rx_packets").unwrap(),
                labels,
                MetricReading::Counter {
                    value,
                    bits: Some(CounterBits::Bits64),
                },
            );
            ProviderSample::new(
                ProviderId::new(source).unwrap(),
                Duration::from_secs(at),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![reading],
            )
            .unwrap()
        }

        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let rtnetlink = engine
            .ingest(
                Duration::from_secs(1),
                vec![link_sample("linux.rtnetlink.link_stats", 1, 10)],
                None,
            )
            .unwrap();
        let sysfs = engine
            .ingest(
                Duration::from_secs(2),
                vec![link_sample("linux.sysfs.net.statistics", 2, 11)],
                None,
            )
            .unwrap();
        let recovered = engine
            .ingest(
                Duration::from_secs(3),
                vec![link_sample("linux.rtnetlink.link_stats", 3, 12)],
                None,
            )
            .unwrap();

        assert_eq!(rtnetlink.series().len(), 1);
        assert_eq!(sysfs.series().len(), 1);
        assert_eq!(recovered.series().len(), 1);
        assert_eq!(rtnetlink.series()[0].id(), sysfs.series()[0].id());
        assert_eq!(sysfs.series()[0].id(), recovered.series()[0].id());
        assert_eq!(
            recovered.series()[0].baseline_origin(),
            BaselineOrigin::RecoveredAfterGap
        );

        // Compare incremental ingestion with full candidate selection, including
        // a cached fallback, preferred-source recovery, and provider disappearance.
        let mut incremental = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut full = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let primary = "linux.rtnetlink.link_stats";
        let fallback = "linux.sysfs.net.statistics";
        let failed = ProviderSample::new(
            ProviderId::new(primary).unwrap(),
            Duration::from_secs(3),
            Duration::ZERO,
            ProviderHealth::Error {
                error: MonitorError::new(super::super::MonitorErrorCode::Io, "read failed")
                    .unwrap(),
            },
            Vec::new(),
        )
        .unwrap();
        let fallback_reading = link_sample(fallback, 9, 90);
        let unavailable = ProviderSample::new(
            ProviderId::new(fallback).unwrap(),
            Duration::from_secs(9),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![SampleReading::unavailable(
                fallback_reading.readings()[0].metric().clone(),
                fallback_reading.readings()[0].labels().clone(),
                UnavailableReason::Missing,
            )],
        )
        .unwrap();
        let mut retained = Vec::new();
        for (index, samples) in [
            vec![link_sample(primary, 1, 10), link_sample(fallback, 1, 10)],
            vec![link_sample(primary, 2, 20), link_sample(fallback, 2, 20)],
            vec![failed.clone(), link_sample(fallback, 2, 20)],
            vec![failed, link_sample(fallback, 4, 40)],
            vec![link_sample(primary, 5, 50), link_sample(fallback, 4, 40)],
            vec![link_sample(primary, 5, 50), link_sample(fallback, 4, 40)],
            vec![],
            vec![link_sample(primary, 8, 80), link_sample(fallback, 8, 80)],
            vec![unavailable],
            vec![link_sample(fallback, 10, 100)],
            vec![link_sample(primary, 11, 110)],
        ]
        .into_iter()
        .enumerate()
        {
            for runtime in full.providers.values_mut() {
                runtime.last_sample = None;
                runtime.slots.clear();
            }
            let at = Duration::from_secs(index as u64 + 1);
            let actual = incremental.ingest(at, samples.clone(), None).unwrap();
            let expected = full.ingest(at, samples, None).unwrap();
            assert_eq!(actual, expected, "cycle {}", index + 1);
            assert_eq!(*actual, rebuild_with_public_constructor(&actual));
            retained.push((actual, expected));
        }
        for (actual, expected) in retained {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn collector_panic_closes_the_latest_slot_instead_of_hanging() {
        struct PanicCollector;

        impl MonitorCollector for PanicCollector {
            fn collect(&mut self, _session_start: Instant) -> Vec<ProviderSample> {
                panic!("private collector panic payload");
            }

            fn network_namespace(&self) -> Option<String> {
                None
            }
        }

        let session =
            MonitorSession::start_with_collector(MonitorPlan::default(), Box::new(PanicCollector))
                .unwrap();
        let error = session
            .wait_after(0, Duration::from_secs(1))
            .unwrap_err()
            .to_string();

        assert!(error.contains("monitor worker panicked"));
        assert!(!error.contains("private collector panic payload"));
        session.shutdown().unwrap();
    }

    #[test]
    fn focus_change_wakes_worker_without_waiting_for_long_interval() {
        struct FocusCollector {
            focus: CollectionFocus,
            observations: mpsc::Sender<CollectionFocus>,
        }
        impl MonitorCollector for FocusCollector {
            fn set_focus(&mut self, section: CollectionFocus) {
                self.focus = section;
            }
            fn collect(&mut self, _start: Instant) -> Vec<ProviderSample> {
                self.observations.send(self.focus).unwrap();
                Vec::new()
            }
            fn network_namespace(&self) -> Option<String> {
                None
            }
        }
        let (sender, receiver) = mpsc::channel();
        let plan = MonitorPlan::from_parts(
            super::super::SamplingInterval::new(Duration::from_secs(60)).unwrap(),
            MonitorSection::Nic,
            super::super::CollectionSection::ALL,
            None,
        )
        .unwrap();
        let session = MonitorSession::start_with_collector(
            plan,
            Box::new(FocusCollector {
                focus: MonitorSection::Overview.into(),
                observations: sender,
            }),
        )
        .unwrap();
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            CollectionFocus::from(MonitorSection::Nic)
        );
        session.set_focus(MonitorSection::Tc);
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
            CollectionFocus::from(MonitorSection::Tc)
        );
        session.set_focus(MonitorSection::Tc);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        session.shutdown().unwrap();
    }

    #[test]
    fn monitor_worker_panic_hook_suppresses_stderr_payload() {
        const CHILD_ENV: &str = "NETLENS_MONITOR_PANIC_HOOK_CHILD";
        const TEST_NAME: &str =
            "monitor::session::tests::monitor_worker_panic_hook_suppresses_stderr_payload";

        if std::env::var_os(CHILD_ENV).is_some() {
            struct PanicCollector;

            impl MonitorCollector for PanicCollector {
                fn collect(&mut self, _session_start: Instant) -> Vec<ProviderSample> {
                    panic!("private monitor panic canary");
                }

                fn network_namespace(&self) -> Option<String> {
                    None
                }
            }

            let session = MonitorSession::start_with_collector(
                MonitorPlan::default(),
                Box::new(PanicCollector),
            )
            .unwrap();
            let error = session
                .wait_after(0, Duration::from_secs(1))
                .unwrap_err()
                .to_string();
            assert!(error.contains("monitor worker panicked"));
            session.shutdown().unwrap();
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "child test failed: {output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.is_empty(),
            "monitor panic reached stderr: {stderr:?}"
        );
    }

    #[test]
    fn reused_snapshot_buffers_match_fresh_storage_through_gaps_and_resets() {
        let mut reused = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut fresh = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut retained = Vec::new();
        for at in 1..=60 {
            let health = if at == 13 || at == 14 {
                ProviderHealth::Error {
                    error: MonitorError::new(super::super::MonitorErrorCode::Io, "read failed")
                        .unwrap(),
                }
            } else {
                ProviderHealth::Fresh
            };
            let value = if at < 30 { at * 10 } else { (at - 30) * 5 };
            let input = sample(at, value, health);
            for entry in &mut fresh.series {
                if let Some(state) = &mut entry.state {
                    state.spare_projection = None;
                }
            }
            let expected = fresh
                .ingest(Duration::from_secs(at), vec![input.clone()], None)
                .unwrap();
            let actual = reused
                .ingest(Duration::from_secs(at), vec![input], None)
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(*actual, rebuild_with_public_constructor(&actual));
            if at % 7 == 0 {
                retained.push((actual, expected));
            }
        }
        for (actual, expected) in retained {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn changed_labels_with_the_same_reading_count_rebuild_the_slot_mapping() {
        let make_sample = |at: u64, cpu: &str, value: u64| {
            ProviderSample::new(
                ProviderId::new("linux.proc.net.softnet_stat").unwrap(),
                Duration::from_secs(at),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![SampleReading::observed(
                    MetricId::new("linux.softirq.softnet.processed").unwrap(),
                    MetricLabels::new([(MetricLabel::Cpu, cpu.to_owned())]).unwrap(),
                    MetricReading::Counter { value, bits: None },
                )],
            )
            .unwrap()
        };
        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let initial = engine
            .ingest(Duration::from_secs(1), vec![make_sample(1, "0", 10)], None)
            .unwrap();
        let changed = engine
            .ingest(Duration::from_secs(2), vec![make_sample(2, "1", 20)], None)
            .unwrap();
        assert_eq!(changed.series().len(), 2);
        assert_eq!(changed.series()[0].id(), initial.series()[0].id());
        assert_eq!(
            changed.series()[0].labels().get(MetricLabel::Cpu),
            Some("0")
        );
        assert_eq!(
            changed.series()[1].labels().get(MetricLabel::Cpu),
            Some("1")
        );
        assert!(matches!(
            changed.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Unavailable { .. },
                ..
            }
        ));
        let next = engine
            .ingest(Duration::from_secs(3), vec![make_sample(3, "1", 25)], None)
            .unwrap();
        assert!(matches!(
            next.series()[1].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Fresh { value: 25, .. },
                ..
            }
        ));
        assert_eq!(next.series()[1].id(), changed.series()[1].id());
        // Older immutable snapshots must not change when a slot is reused.
        assert!(matches!(
            initial.series()[0].value(),
            SeriesValue::Counter {
                current: ProjectedValue::Fresh { value: 10, .. },
                ..
            }
        ));
    }

    #[test]
    fn new_series_are_rejected_at_capacity_without_stopping_snapshots() {
        const SOFTNET_METRIC: &str = "linux.softirq.softnet.processed";
        const SOFTNET_SOURCE: &str = "linux.proc.net.softnet_stat";

        let mut engine = MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let source = ProviderId::new(SOFTNET_SOURCE).unwrap();
        let metric = MetricId::new(SOFTNET_METRIC).unwrap();
        for cpu in 0..MAX_ADMITTED_SERIES {
            let labels = MetricLabels::new([(MetricLabel::Cpu, cpu.to_string())]).unwrap();
            let key = SeriesKey {
                metric: metric.clone(),
                labels,
            };
            engine.series_index.insert(key.clone(), cpu);
            engine.series.push(SeriesEntry { key, state: None });
            engine
                .project_observed(
                    cpu,
                    &source,
                    &MetricReading::Counter {
                        value: 1,
                        bits: None,
                    },
                    Duration::from_secs(1),
                    true,
                    Duration::from_secs(1),
                )
                .unwrap();
        }

        let overflow_labels =
            MetricLabels::new([(MetricLabel::Cpu, MAX_ADMITTED_SERIES.to_string())]).unwrap();
        let overflow = SampleReading::observed(
            metric,
            overflow_labels,
            MetricReading::Counter {
                value: 2,
                bits: None,
            },
        );
        let sample = ProviderSample::new(
            source,
            Duration::from_secs(2),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![overflow],
        )
        .unwrap();

        let snapshot = engine
            .ingest(Duration::from_secs(2), vec![sample], None)
            .unwrap();

        assert_eq!(snapshot.series().len(), MAX_ADMITTED_SERIES);
        assert_eq!(snapshot.telemetry().rejected_series, 1);
        assert_eq!(snapshot.telemetry().evicted_series, 0);
        assert_eq!(snapshot.sequence(), 1);
    }
}
