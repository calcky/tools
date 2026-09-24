use super::catalog::{metric_catalog, MetricDescriptor};
use super::dashboard::{placement_for, BlockScope, DashboardBlock, PlacementScope};
use super::model::{
    CounterContinuity, DisplayMeaning, MetricId, MetricScope, MetricUnit, MonitorSnapshot,
    ProjectedValue, ProviderHealth, SeriesSnapshot, SeriesValue, UnavailableReason,
};

const CAPACITY_WARN_BASIS_POINTS: u64 = 8_000;
const CAPACITY_CRIT_BASIS_POINTS: u64 = 9_500;
const PRESSURE_WARN_BASIS_POINTS: u64 = 5_000;
const PRESSURE_CRIT_BASIS_POINTS: u64 = 8_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkHealth {
    Ok,
    Warn,
    Crit,
    Unknown,
}

impl NetworkHealth {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Crit => "CRIT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceCoverage {
    Fresh,
    Partial,
    Stale,
    Unsupported,
}

impl EvidenceCoverage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Partial => "partial",
            Self::Stale => "stale",
            Self::Unsupported => "unsupported",
        }
    }

    pub fn combine(values: impl IntoIterator<Item = Self>) -> Self {
        let mut saw_fresh = false;
        let mut saw_partial = false;
        let mut saw_stale = false;
        let mut saw_unsupported = false;
        for value in values {
            match value {
                Self::Fresh => saw_fresh = true,
                Self::Partial => saw_partial = true,
                Self::Stale => saw_stale = true,
                Self::Unsupported => saw_unsupported = true,
            }
        }
        if saw_partial || (saw_fresh && (saw_stale || saw_unsupported)) {
            Self::Partial
        } else if saw_fresh {
            Self::Fresh
        } else if saw_stale {
            Self::Stale
        } else {
            Self::Unsupported
        }
    }
}

impl From<&ProviderHealth> for EvidenceCoverage {
    fn from(value: &ProviderHealth) -> Self {
        match value {
            ProviderHealth::Fresh => Self::Fresh,
            ProviderHealth::Partial { .. } => Self::Partial,
            ProviderHealth::Stale { .. } => Self::Stale,
            ProviderHealth::Unsupported { .. } => Self::Unsupported,
            ProviderHealth::PermissionDenied { .. } | ProviderHealth::Error { .. } => Self::Partial,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleOrigin {
    BuiltInSemantic,
    ConfiguredThreshold,
    HistoricalChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthRule {
    PositiveIntervalRate,
    PositiveGauge,
    CapacityUtilization,
    PressureUtilization,
    LinkState,
    FreshIntervalRequired,
    FreshValueRequired,
    CollectionStatus,
    SemanticThresholdRequired,
    OpaqueInformation,
}

impl HealthRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PositiveIntervalRate => "fresh interval rate must remain at zero",
            Self::PositiveGauge => "fresh gauge must remain at zero",
            Self::CapacityUtilization => "capacity utilization crossed its built-in threshold",
            Self::PressureUtilization => "pressure utilization crossed its built-in threshold",
            Self::LinkState => "link state must be up",
            Self::FreshIntervalRequired => "a continuous fresh interval is required",
            Self::FreshValueRequired => "a fresh observed value is required",
            Self::CollectionStatus => "the per-interface collection attempt must be complete",
            Self::SemanticThresholdRequired => {
                "an absolute gauge needs a configured capacity threshold"
            }
            Self::OpaqueInformation => "opaque source data has no health semantics",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum HealthValue {
    RatePerSecond(f64),
    Gauge(u64),
    BasisPoints(u64),
    State(String),
    Continuity(&'static str),
    Unavailable(UnavailableReason),
}

#[derive(Clone, Debug, PartialEq)]
pub enum HealthThreshold {
    RatePerSecond(f64),
    Gauge(u64),
    BasisPoints(u64),
    State(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
pub struct HealthCause {
    metric: MetricId,
    condition: NetworkHealth,
    observed: HealthValue,
    rule: HealthRule,
    threshold: Option<HealthThreshold>,
    origin: RuleOrigin,
}

impl HealthCause {
    pub fn metric(&self) -> &MetricId {
        &self.metric
    }

    pub const fn condition(&self) -> NetworkHealth {
        self.condition
    }

    pub const fn observed(&self) -> &HealthValue {
        &self.observed
    }

    pub const fn rule(&self) -> HealthRule {
        self.rule
    }

    pub const fn threshold(&self) -> Option<&HealthThreshold> {
        self.threshold.as_ref()
    }

    pub const fn origin(&self) -> RuleOrigin {
        self.origin
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MetricAssessment {
    health: NetworkHealth,
    coverage: EvidenceCoverage,
    contributes_to_health: bool,
    causes: Vec<HealthCause>,
}

impl MetricAssessment {
    pub const fn health(&self) -> NetworkHealth {
        self.health
    }

    pub const fn coverage(&self) -> EvidenceCoverage {
        self.coverage
    }

    pub const fn contributes_to_health(&self) -> bool {
        self.contributes_to_health
    }

    pub fn causes(&self) -> &[HealthCause] {
        &self.causes
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Assessment {
    health: NetworkHealth,
    coverage: EvidenceCoverage,
    causes: Vec<HealthCause>,
}

impl Assessment {
    pub const fn health(&self) -> NetworkHealth {
        self.health
    }

    pub const fn coverage(&self) -> EvidenceCoverage {
        self.coverage
    }

    pub fn causes(&self) -> &[HealthCause] {
        &self.causes
    }

    pub fn from_metrics<'a>(metrics: impl IntoIterator<Item = &'a MetricAssessment>) -> Self {
        let metrics = metrics.into_iter().collect::<Vec<_>>();
        let coverage = EvidenceCoverage::combine(metrics.iter().map(|metric| metric.coverage));
        let mut causes = metrics
            .iter()
            .filter(|metric| metric.contributes_to_health)
            .flat_map(|metric| metric.causes.iter().cloned())
            .collect::<Vec<_>>();
        causes.sort_by(compare_health_causes);

        let contributing = metrics
            .iter()
            .copied()
            .filter(|metric| metric.contributes_to_health)
            .collect::<Vec<_>>();
        let health = if contributing
            .iter()
            .any(|metric| metric.health == NetworkHealth::Crit)
        {
            NetworkHealth::Crit
        } else if contributing
            .iter()
            .any(|metric| metric.health == NetworkHealth::Warn)
        {
            NetworkHealth::Warn
        } else if coverage == EvidenceCoverage::Fresh
            && !contributing.is_empty()
            && contributing
                .iter()
                .all(|metric| metric.health == NetworkHealth::Ok)
        {
            NetworkHealth::Ok
        } else {
            NetworkHealth::Unknown
        };
        Self {
            health,
            coverage,
            causes,
        }
    }
}

pub(crate) fn compare_health_causes(left: &HealthCause, right: &HealthCause) -> std::cmp::Ordering {
    cause_condition_priority(left.condition())
        .cmp(&cause_condition_priority(right.condition()))
        .then_with(|| unknown_cause_priority(left).cmp(&unknown_cause_priority(right)))
        .then_with(|| left.metric().as_str().cmp(right.metric().as_str()))
}

const fn cause_condition_priority(condition: NetworkHealth) -> u8 {
    match condition {
        NetworkHealth::Crit => 0,
        NetworkHealth::Warn => 1,
        NetworkHealth::Unknown => 2,
        NetworkHealth::Ok => 3,
    }
}

fn unknown_cause_priority(cause: &HealthCause) -> u8 {
    if cause.condition() != NetworkHealth::Unknown {
        return 0;
    }
    if cause.rule() == HealthRule::CollectionStatus {
        return match cause.observed() {
            HealthValue::State(status)
                if matches!(status.as_str(), "unsupported" | "command_not_found") =>
            {
                2
            }
            _ => 0,
        };
    }
    if matches!(
        cause.observed(),
        HealthValue::Unavailable(UnavailableReason::NotApplicable)
    ) {
        2
    } else {
        1
    }
}

pub fn assess_series(series: &SeriesSnapshot) -> MetricAssessment {
    let descriptor = series
        .metric()
        .descriptor()
        .expect("validated monitor series always reference a catalog metric");
    let coverage = coverage_for_value(series.value());
    let unavailable = unavailable_cause(series);
    if let Some(cause) = unavailable {
        return MetricAssessment {
            health: NetworkHealth::Unknown,
            coverage,
            contributes_to_health: descriptor.display != DisplayMeaning::InformationOnly,
            causes: vec![cause],
        };
    }

    if descriptor.display == DisplayMeaning::InformationOnly {
        return unknown(
            series,
            coverage,
            false,
            current_health_value(series.value()),
            HealthRule::OpaqueInformation,
        );
    }

    match series.value() {
        SeriesValue::Counter { interval, .. } => {
            assess_counter(series, descriptor, coverage, *interval)
        }
        SeriesValue::Gauge { current, .. } => {
            let ProjectedValue::Fresh { value, .. } = current else {
                unreachable!("non-fresh values returned above")
            };
            assess_gauge(series, descriptor, coverage, *value)
        }
        SeriesValue::State { current, .. } => {
            let ProjectedValue::Fresh { value, .. } = current else {
                unreachable!("non-fresh values returned above")
            };
            assess_state(series, descriptor, coverage, value.as_str())
        }
    }
}

pub fn assess_snapshot_series(
    snapshot: &MonitorSnapshot,
    series: &SeriesSnapshot,
) -> MetricAssessment {
    let ethtool_coverage = ethtool_interface_coverage(snapshot, series);
    assess_snapshot_series_with_ethtool_coverage(snapshot, series, ethtool_coverage)
}

fn assess_snapshot_series_with_ethtool_coverage(
    snapshot: &MonitorSnapshot,
    series: &SeriesSnapshot,
    ethtool_coverage: Option<EvidenceCoverage>,
) -> MetricAssessment {
    let mut assessment = assess_series(series);
    let provider_coverage = ethtool_coverage.unwrap_or_else(|| {
        snapshot
            .providers()
            .iter()
            .find(|provider| provider.provider() == series.source())
            .map(|provider| EvidenceCoverage::from(provider.health()))
            .unwrap_or(EvidenceCoverage::Unsupported)
    });
    assessment.coverage = EvidenceCoverage::combine([assessment.coverage, provider_coverage]);
    assessment
}

fn ethtool_interface_coverage(
    snapshot: &MonitorSnapshot,
    series: &SeriesSnapshot,
) -> Option<EvidenceCoverage> {
    let status_metric = match series.source().as_str() {
        "linux.ethtool.link_text" => super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
        "linux.ethtool.text" => super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
        _ => return None,
    };
    let interface = series.labels().get(super::MetricLabel::Interface)?;
    let ifindex = series.labels().get(super::MetricLabel::Ifindex)?;
    snapshot
        .series()
        .iter()
        .find(|candidate| {
            candidate.source() == series.source()
                && candidate.metric().as_str() == status_metric
                && candidate.labels().get(super::MetricLabel::Interface) == Some(interface)
                && candidate.labels().get(super::MetricLabel::Ifindex) == Some(ifindex)
        })
        .map(|status| assess_series(status).coverage())
}

#[derive(Default)]
struct EttoolBlockCoverage {
    settings: Option<EvidenceCoverage>,
    statistics: Option<EvidenceCoverage>,
}

impl EttoolBlockCoverage {
    fn from_block(block: &DashboardBlock<'_>) -> Self {
        let mut coverage = Self::default();
        for series in block
            .rx()
            .iter()
            .chain(block.tx())
            .chain(block.shared())
            .map(|placed| placed.series())
        {
            match series.metric().as_str() {
                super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID => {
                    coverage.settings = Some(assess_series(series).coverage());
                }
                super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID => {
                    coverage.statistics = Some(assess_series(series).coverage());
                }
                _ => {}
            }
        }
        coverage
    }

    fn for_series(&self, series: &SeriesSnapshot) -> Option<EvidenceCoverage> {
        match series.source().as_str() {
            "linux.ethtool.link_text" => self.settings,
            "linux.ethtool.text" => self.statistics,
            _ => None,
        }
    }
}

pub fn assess_dashboard_block(
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
) -> Assessment {
    let ethtool_coverage = EttoolBlockCoverage::from_block(block);
    let present_metrics = block
        .rx()
        .iter()
        .chain(block.tx())
        .chain(block.shared())
        .map(|placed| placed.series().metric().as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut metrics = block
        .rx()
        .iter()
        .chain(block.tx())
        .chain(block.shared())
        .map(|placed| {
            let series = placed.series();
            assess_snapshot_series_with_ethtool_coverage(
                snapshot,
                series,
                ethtool_coverage.for_series(series),
            )
        })
        .collect::<Vec<_>>();

    metrics.extend(
        metric_catalog()
            .iter()
            .filter(|descriptor| descriptor.minimum)
            .filter(|descriptor| metric_has_stable_presence(descriptor))
            .filter(|descriptor| !present_metrics.contains(descriptor.id))
            .filter(|descriptor| placement_matches_block(descriptor, block))
            .map(|descriptor| missing_metric_assessment(snapshot, descriptor)),
    );
    Assessment::from_metrics(metrics.iter())
}

fn placement_matches_block(descriptor: &MetricDescriptor, block: &DashboardBlock<'_>) -> bool {
    let Some(placement) = placement_for(descriptor) else {
        return false;
    };
    if placement.block_kind() != block.key().kind() {
        return false;
    }
    matches!(
        (placement.scope(), block.key().scope()),
        (PlacementScope::Global, BlockScope::Global)
            | (PlacementScope::Host, BlockScope::Host)
            | (PlacementScope::Interface, BlockScope::Interface(_))
    )
}

fn metric_has_stable_presence(descriptor: &MetricDescriptor) -> bool {
    !matches!(
        descriptor.scope,
        MetricScope::Rule | MetricScope::TrafficControlObject | MetricScope::Source
    )
}

fn missing_metric_assessment(
    snapshot: &MonitorSnapshot,
    descriptor: &MetricDescriptor,
) -> MetricAssessment {
    let provider_coverages = descriptor
        .sources
        .iter()
        .filter_map(|source| {
            snapshot
                .providers()
                .iter()
                .find(|provider| provider.provider().as_str() == source.provider)
                .map(|provider| EvidenceCoverage::from(provider.health()))
        })
        .collect::<Vec<_>>();
    let mut coverage = EvidenceCoverage::combine(provider_coverages.iter().copied());
    if provider_coverages.contains(&EvidenceCoverage::Fresh) {
        coverage = EvidenceCoverage::Partial;
    }
    let reason = if coverage == EvidenceCoverage::Unsupported {
        UnavailableReason::NotApplicable
    } else {
        UnavailableReason::Missing
    };
    MetricAssessment {
        health: NetworkHealth::Unknown,
        coverage,
        contributes_to_health: true,
        causes: vec![HealthCause {
            metric: MetricId::new(descriptor.id)
                .expect("dashboard descriptors have validated metric identifiers"),
            condition: NetworkHealth::Unknown,
            observed: HealthValue::Unavailable(reason),
            rule: HealthRule::FreshValueRequired,
            threshold: None,
            origin: RuleOrigin::BuiltInSemantic,
        }],
    }
}

fn assess_counter(
    series: &SeriesSnapshot,
    descriptor: &MetricDescriptor,
    coverage: EvidenceCoverage,
    interval: Option<CounterContinuity>,
) -> MetricAssessment {
    let Some(continuity) = interval else {
        return unknown(
            series,
            coverage,
            true,
            HealthValue::Continuity("missing"),
            HealthRule::FreshIntervalRequired,
        );
    };
    let Some(rate) = continuity.rate_per_second() else {
        return unknown(
            series,
            coverage,
            true,
            HealthValue::Continuity(continuity_name(continuity)),
            HealthRule::FreshIntervalRequired,
        );
    };

    if matches!(
        descriptor.display,
        DisplayMeaning::Drop | DisplayMeaning::Error | DisplayMeaning::Pressure
    ) && rate > 0.0
    {
        return with_threshold_cause(
            series,
            coverage,
            NetworkHealth::Warn,
            HealthValue::RatePerSecond(rate),
            HealthRule::PositiveIntervalRate,
            HealthThreshold::RatePerSecond(0.0),
        );
    }
    healthy(coverage)
}

fn assess_gauge(
    series: &SeriesSnapshot,
    descriptor: &MetricDescriptor,
    coverage: EvidenceCoverage,
    value: u64,
) -> MetricAssessment {
    if descriptor.unit == MetricUnit::BasisPoints {
        let (rule, warn, crit) = match (descriptor.id, descriptor.display) {
            ("linux.netfilter.conntrack.utilization", _) => (
                HealthRule::CapacityUtilization,
                CAPACITY_WARN_BASIS_POINTS,
                CAPACITY_CRIT_BASIS_POINTS,
            ),
            (_, DisplayMeaning::Capacity) => (
                HealthRule::CapacityUtilization,
                CAPACITY_WARN_BASIS_POINTS,
                CAPACITY_CRIT_BASIS_POINTS,
            ),
            (_, DisplayMeaning::Pressure) => (
                HealthRule::PressureUtilization,
                PRESSURE_WARN_BASIS_POINTS,
                PRESSURE_CRIT_BASIS_POINTS,
            ),
            _ => return healthy(coverage),
        };
        if value >= crit {
            return with_threshold_cause(
                series,
                coverage,
                NetworkHealth::Crit,
                HealthValue::BasisPoints(value),
                rule,
                HealthThreshold::BasisPoints(crit),
            );
        }
        if value >= warn {
            return with_threshold_cause(
                series,
                coverage,
                NetworkHealth::Warn,
                HealthValue::BasisPoints(value),
                rule,
                HealthThreshold::BasisPoints(warn),
            );
        }
        return healthy(coverage);
    }

    match descriptor.display {
        DisplayMeaning::Drop | DisplayMeaning::Error if value > 0 => with_threshold_cause(
            series,
            coverage,
            NetworkHealth::Warn,
            HealthValue::Gauge(value),
            HealthRule::PositiveGauge,
            HealthThreshold::Gauge(0),
        ),
        DisplayMeaning::Pressure if value > 0 => unknown(
            series,
            coverage,
            false,
            HealthValue::Gauge(value),
            HealthRule::SemanticThresholdRequired,
        ),
        DisplayMeaning::Capacity => unknown(
            series,
            coverage,
            false,
            HealthValue::Gauge(value),
            HealthRule::SemanticThresholdRequired,
        ),
        _ => healthy(coverage),
    }
}

fn assess_state(
    series: &SeriesSnapshot,
    descriptor: &MetricDescriptor,
    coverage: EvidenceCoverage,
    value: &str,
) -> MetricAssessment {
    if matches!(
        descriptor.id,
        super::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID
            | super::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID
    ) {
        return match value {
            "complete" => coverage_only(coverage),
            "unsupported" | "command_not_found" => with_threshold_cause(
                series,
                EvidenceCoverage::Unsupported,
                NetworkHealth::Unknown,
                HealthValue::State(value.to_owned()),
                HealthRule::CollectionStatus,
                HealthThreshold::State("complete"),
            ),
            "refresh_pending"
            | "partial_schema_mismatch"
            | "partial_cardinality_limit"
            | "permission_denied"
            | "interface_unavailable"
            | "timed_out"
            | "output_limit"
            | "invalid_output"
            | "command_failed"
            | "io_error" => with_threshold_cause(
                series,
                EvidenceCoverage::Partial,
                NetworkHealth::Unknown,
                HealthValue::State(value.to_owned()),
                HealthRule::CollectionStatus,
                HealthThreshold::State("complete"),
            ),
            _ => unreachable!("ethtool status values are catalog validated"),
        };
    }
    if descriptor.id != "linux.nic.link_state" {
        return unknown(
            series,
            coverage,
            descriptor.display != DisplayMeaning::InformationOnly,
            HealthValue::State(value.to_owned()),
            HealthRule::OpaqueInformation,
        );
    }
    match value {
        "up" => healthy(coverage),
        "down" => with_threshold_cause(
            series,
            coverage,
            NetworkHealth::Warn,
            HealthValue::State(value.to_owned()),
            HealthRule::LinkState,
            HealthThreshold::State("up"),
        ),
        "lower_layer_down" | "not_present" => with_threshold_cause(
            series,
            coverage,
            NetworkHealth::Crit,
            HealthValue::State(value.to_owned()),
            HealthRule::LinkState,
            HealthThreshold::State("up"),
        ),
        _ => unknown(
            series,
            coverage,
            true,
            HealthValue::State(value.to_owned()),
            HealthRule::LinkState,
        ),
    }
}

fn healthy(coverage: EvidenceCoverage) -> MetricAssessment {
    MetricAssessment {
        health: NetworkHealth::Ok,
        coverage,
        contributes_to_health: true,
        causes: Vec::new(),
    }
}

fn coverage_only(coverage: EvidenceCoverage) -> MetricAssessment {
    MetricAssessment {
        health: NetworkHealth::Unknown,
        coverage,
        contributes_to_health: false,
        causes: Vec::new(),
    }
}

fn unknown(
    series: &SeriesSnapshot,
    coverage: EvidenceCoverage,
    contributes_to_health: bool,
    observed: HealthValue,
    rule: HealthRule,
) -> MetricAssessment {
    MetricAssessment {
        health: NetworkHealth::Unknown,
        coverage,
        contributes_to_health,
        causes: vec![HealthCause {
            metric: series.metric().clone(),
            condition: NetworkHealth::Unknown,
            observed,
            rule,
            threshold: None,
            origin: RuleOrigin::BuiltInSemantic,
        }],
    }
}

fn with_threshold_cause(
    series: &SeriesSnapshot,
    coverage: EvidenceCoverage,
    health: NetworkHealth,
    observed: HealthValue,
    rule: HealthRule,
    threshold: HealthThreshold,
) -> MetricAssessment {
    MetricAssessment {
        health,
        coverage,
        contributes_to_health: true,
        causes: vec![HealthCause {
            metric: series.metric().clone(),
            condition: health,
            observed,
            rule,
            threshold: Some(threshold),
            origin: RuleOrigin::BuiltInSemantic,
        }],
    }
}

fn coverage_for_value(value: &SeriesValue) -> EvidenceCoverage {
    let projected = match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            ProjectedRef::Numeric(current)
        }
        SeriesValue::State { current, .. } => ProjectedRef::State(current),
    };
    match projected {
        ProjectedRef::Numeric(ProjectedValue::Fresh { .. })
        | ProjectedRef::State(ProjectedValue::Fresh { .. }) => EvidenceCoverage::Fresh,
        ProjectedRef::Numeric(ProjectedValue::Stale { .. })
        | ProjectedRef::State(ProjectedValue::Stale { .. }) => EvidenceCoverage::Stale,
        ProjectedRef::Numeric(ProjectedValue::Unavailable { reason })
        | ProjectedRef::State(ProjectedValue::Unavailable { reason }) => match reason {
            UnavailableReason::NotApplicable => EvidenceCoverage::Unsupported,
            _ => EvidenceCoverage::Partial,
        },
    }
}

enum ProjectedRef<'a> {
    Numeric(&'a ProjectedValue<u64>),
    State(&'a ProjectedValue<super::model::StateValue>),
}

fn unavailable_cause(series: &SeriesSnapshot) -> Option<HealthCause> {
    let observed = match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            projected_unavailable(current)
        }
        SeriesValue::State { current, .. } => projected_unavailable(current),
    }?;
    Some(HealthCause {
        metric: series.metric().clone(),
        condition: NetworkHealth::Unknown,
        observed,
        rule: HealthRule::FreshValueRequired,
        threshold: None,
        origin: RuleOrigin::BuiltInSemantic,
    })
}

fn projected_unavailable<T>(value: &ProjectedValue<T>) -> Option<HealthValue> {
    match value {
        ProjectedValue::Fresh { .. } => None,
        ProjectedValue::Stale { .. } => Some(HealthValue::Continuity("stale")),
        ProjectedValue::Unavailable { reason } => Some(HealthValue::Unavailable(*reason)),
    }
}

fn current_health_value(value: &SeriesValue) -> HealthValue {
    match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            match current {
                ProjectedValue::Fresh { value, .. } | ProjectedValue::Stale { last: value, .. } => {
                    HealthValue::Gauge(*value)
                }
                ProjectedValue::Unavailable { reason } => HealthValue::Unavailable(*reason),
            }
        }
        SeriesValue::State { current, .. } => match current {
            ProjectedValue::Fresh { value, .. } | ProjectedValue::Stale { last: value, .. } => {
                HealthValue::State(value.as_str().to_owned())
            }
            ProjectedValue::Unavailable { reason } => HealthValue::Unavailable(*reason),
        },
    }
}

const fn continuity_name(value: CounterContinuity) -> &'static str {
    match value {
        CounterContinuity::FirstSample => "first_sample",
        CounterContinuity::Continuous { .. } => "continuous",
        CounterContinuity::Wrapped { .. } => "wrapped",
        CounterContinuity::Reset => "reset",
        CounterContinuity::RecoveredAfterGap => "recovered_after_gap",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::monitor::{
        descriptor, BaselineOrigin, CounterSpan, EngineTelemetry, HistoryCoverage, MetricLabels,
        MonitorError, MonitorErrorCode, ProviderId, ProviderSnapshot, SeriesId, StateValue,
    };

    fn counter(metric: &str, delta: Option<CounterContinuity>) -> SeriesSnapshot {
        let descriptor = descriptor(metric).unwrap();
        let baseline = match delta {
            Some(CounterContinuity::Reset) => (BaselineOrigin::Reset, Duration::from_secs(2)),
            Some(CounterContinuity::RecoveredAfterGap) => {
                (BaselineOrigin::RecoveredAfterGap, Duration::from_secs(2))
            }
            _ => (BaselineOrigin::SessionStart, Duration::ZERO),
        };
        SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(descriptor.sources[0].provider).unwrap(),
            MetricId::new(metric).unwrap(),
            MetricLabels::default(),
            Duration::ZERO,
            baseline.0,
            baseline.1,
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(2),
                },
                interval: delta,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn gauge(metric: &str, value: u64) -> SeriesSnapshot {
        let descriptor = descriptor(metric).unwrap();
        let labels = if metric == "linux.nic.raw_private" {
            MetricLabels::new([
                (crate::monitor::MetricLabel::Interface, "eth0".to_owned()),
                (crate::monitor::MetricLabel::Ifindex, "2".to_owned()),
                (
                    crate::monitor::MetricLabel::Statistic,
                    "opaque_counter".to_owned(),
                ),
            ])
            .unwrap()
        } else {
            MetricLabels::default()
        };
        SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(descriptor.sources[0].provider).unwrap(),
            MetricId::new(metric).unwrap(),
            labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value,
                    observed_at: Duration::from_secs(2),
                },
                interval: None,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn link_state(value: &str) -> SeriesSnapshot {
        let descriptor = descriptor("linux.nic.link_state").unwrap();
        let labels = crate::monitor::MetricLabels::new([
            (crate::monitor::MetricLabel::Interface, "eth0".to_owned()),
            (crate::monitor::MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new("linux.sysfs.net.nic").unwrap(),
            MetricId::new(descriptor.id).unwrap(),
            labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: StateValue::new(value).unwrap(),
                    observed_at: Duration::from_secs(2),
                },
                changed_at: None,
                continuous_for: Some(Duration::from_secs(2)),
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn interface_state(
        id: u64,
        metric: &str,
        source: &str,
        interface: &str,
        ifindex: u32,
        value: &str,
    ) -> SeriesSnapshot {
        let descriptor = descriptor(metric).unwrap();
        let labels = MetricLabels::new([
            (crate::monitor::MetricLabel::Interface, interface.to_owned()),
            (crate::monitor::MetricLabel::Ifindex, ifindex.to_string()),
        ])
        .unwrap();
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(source).unwrap(),
            MetricId::new(metric).unwrap(),
            labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: StateValue::new(value).unwrap(),
                    observed_at: Duration::from_secs(2),
                },
                changed_at: None,
                continuous_for: Some(Duration::from_secs(2)),
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn raw_private_gauge(id: u64, interface: &str, ifindex: u32) -> SeriesSnapshot {
        let descriptor = descriptor(crate::monitor::RAW_PRIVATE_NIC_METRIC_ID).unwrap();
        let labels = MetricLabels::new([
            (crate::monitor::MetricLabel::Interface, interface.to_owned()),
            (crate::monitor::MetricLabel::Ifindex, ifindex.to_string()),
            (
                crate::monitor::MetricLabel::Statistic,
                "driver_counter".to_owned(),
            ),
        ])
        .unwrap();
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new("linux.ethtool.text").unwrap(),
            MetricId::new(descriptor.id).unwrap(),
            labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value: 7,
                    observed_at: Duration::from_secs(2),
                },
                interval: None,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    #[test]
    fn fresh_zero_error_rate_is_ok_and_positive_rate_is_explainable_warn() {
        let zero = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 0,
                elapsed: Duration::from_secs(1),
            }),
        );
        let assessment = assess_series(&zero);
        assert_eq!(assessment.health(), NetworkHealth::Ok);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Fresh);
        assert!(assessment.causes().is_empty());

        let errors = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 5,
                elapsed: Duration::from_secs(1),
            }),
        );
        let assessment = assess_series(&errors);
        assert_eq!(assessment.health(), NetworkHealth::Warn);
        assert_eq!(
            assessment.causes()[0].metric().as_str(),
            errors.metric().as_str()
        );
        assert_eq!(
            assessment.causes()[0].observed(),
            &HealthValue::RatePerSecond(5.0)
        );
        assert_eq!(
            assessment.causes()[0].threshold(),
            Some(&HealthThreshold::RatePerSecond(0.0))
        );
        assert_eq!(assessment.causes()[0].origin(), RuleOrigin::BuiltInSemantic);
    }

    #[test]
    fn first_reset_and_gap_samples_are_unknown_not_zero() {
        for interval in [
            CounterContinuity::FirstSample,
            CounterContinuity::Reset,
            CounterContinuity::RecoveredAfterGap,
        ] {
            let series = counter("linux.socket.tcp.established_resets", Some(interval));
            let assessment = assess_series(&series);
            assert_eq!(assessment.health(), NetworkHealth::Unknown);
            assert_eq!(assessment.coverage(), EvidenceCoverage::Fresh);
            assert_eq!(
                assessment.causes()[0].rule(),
                HealthRule::FreshIntervalRequired
            );
        }
    }

    #[test]
    fn basis_point_capacity_has_stable_warn_and_crit_thresholds() {
        for (value, expected) in [
            (7_999, NetworkHealth::Ok),
            (8_000, NetworkHealth::Warn),
            (9_500, NetworkHealth::Crit),
        ] {
            let series = gauge("linux.netfilter.conntrack.utilization", value);
            let assessment = assess_series(&series);
            assert_eq!(assessment.health(), expected);
            if matches!(expected, NetworkHealth::Warn | NetworkHealth::Crit) {
                assert!(assessment.causes()[0].threshold().is_some());
            }
        }
    }

    #[test]
    fn link_state_rules_are_typed_and_explainable() {
        for (state, expected) in [
            ("up", NetworkHealth::Ok),
            ("down", NetworkHealth::Warn),
            ("lower_layer_down", NetworkHealth::Crit),
            ("unknown", NetworkHealth::Unknown),
        ] {
            let series = link_state(state);
            let assessment = assess_series(&series);
            assert_eq!(assessment.health(), expected);
            if matches!(expected, NetworkHealth::Warn | NetworkHealth::Crit) {
                assert_eq!(
                    assessment.causes()[0].threshold(),
                    Some(&HealthThreshold::State("up"))
                );
            }
        }
    }

    #[test]
    fn opaque_metric_cannot_turn_a_healthy_block_into_ok_or_warn() {
        let opaque = gauge("linux.nic.raw_private", 42);
        let opaque = assess_series(&opaque);
        assert_eq!(opaque.health(), NetworkHealth::Unknown);
        assert!(!opaque.contributes_to_health());
        assert_eq!(
            Assessment::from_metrics([&opaque]).health(),
            NetworkHealth::Unknown
        );

        let healthy = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 0,
                elapsed: Duration::from_secs(1),
            }),
        );
        let healthy = assess_series(&healthy);
        assert_eq!(
            Assessment::from_metrics([&opaque, &healthy]).health(),
            NetworkHealth::Ok
        );
    }

    #[test]
    fn mixed_fresh_and_stale_evidence_is_partial_but_keeps_observed_warning() {
        assert_eq!(
            EvidenceCoverage::combine([EvidenceCoverage::Fresh, EvidenceCoverage::Stale]),
            EvidenceCoverage::Partial
        );
        assert_eq!(
            EvidenceCoverage::combine([EvidenceCoverage::Unsupported]),
            EvidenceCoverage::Unsupported
        );
        let denied = ProviderHealth::PermissionDenied {
            reason: MonitorError::new(MonitorErrorCode::PermissionDenied, "access denied").unwrap(),
        };
        let failed = ProviderHealth::Error {
            error: MonitorError::new(MonitorErrorCode::Io, "collector failed").unwrap(),
        };
        assert_eq!(EvidenceCoverage::from(&denied), EvidenceCoverage::Partial);
        assert_eq!(EvidenceCoverage::from(&failed), EvidenceCoverage::Partial);

        let warning = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 1,
                elapsed: Duration::from_secs(1),
            }),
        );
        let warning = assess_series(&warning);
        let mut stale = counter(
            "linux.socket.tcp.retransmitted_segments",
            Some(CounterContinuity::Continuous {
                delta: 0,
                elapsed: Duration::from_secs(1),
            }),
        );
        stale = SeriesSnapshot::new(
            stale.id(),
            stale.provider().clone(),
            stale.source().clone(),
            stale.metric().clone(),
            stale.labels().clone(),
            stale.first_seen(),
            stale.baseline_origin(),
            stale.baseline_at(),
            SeriesValue::Counter {
                current: ProjectedValue::Stale {
                    last: 100,
                    observed_at: Duration::from_secs(1),
                    age: Duration::from_secs(1),
                    cause: crate::monitor::MonitorErrorCode::Timeout,
                },
                interval: None,
                since_baseline: Some(CounterSpan::new(100, Duration::from_secs(1)).unwrap()),
            },
            stale.history(),
        )
        .unwrap();
        let stale = assess_series(&stale);
        let block = Assessment::from_metrics([&warning, &stale]);
        assert_eq!(block.health(), NetworkHealth::Warn);
        assert_eq!(block.coverage(), EvidenceCoverage::Partial);
    }

    #[test]
    fn provider_coverage_does_not_turn_fresh_zero_into_network_ok() {
        let series = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 0,
                elapsed: Duration::from_secs(1),
            }),
        );
        let source = series.source().clone();
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                source,
                ProviderHealth::Partial {
                    warning: MonitorError::new(
                        MonitorErrorCode::Timeout,
                        "some protocol fields timed out",
                    )
                    .unwrap(),
                },
                Duration::from_secs(2),
                Duration::ZERO,
                1,
            )
            .unwrap()],
            vec![series.clone()],
            EngineTelemetry::default(),
        )
        .unwrap();

        let assessment = assess_snapshot_series(&snapshot, &series);
        assert_eq!(assessment.health(), NetworkHealth::Ok);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Partial);
        assert_eq!(
            Assessment::from_metrics([&assessment]).health(),
            NetworkHealth::Unknown
        );
    }

    #[test]
    fn complete_collection_status_is_fresh_coverage_not_network_health() {
        let status = interface_state(
            1,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth0",
            2,
            "complete",
        );

        let assessment = assess_series(&status);
        assert_eq!(assessment.health(), NetworkHealth::Unknown);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Fresh);
        assert!(!assessment.contributes_to_health());
        assert!(assessment.causes().is_empty());
        assert_eq!(
            Assessment::from_metrics([&assessment]).health(),
            NetworkHealth::Unknown
        );
    }

    #[test]
    fn pending_settings_refresh_is_partial_coverage_not_interface_failure() {
        let status = interface_state(
            1,
            crate::monitor::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
            "linux.ethtool.link_text",
            "eth0",
            2,
            "refresh_pending",
        );

        let assessment = assess_series(&status);
        assert_eq!(assessment.health(), NetworkHealth::Unknown);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Partial);
        assert!(assessment.contributes_to_health());
        assert_eq!(assessment.causes().len(), 1);
        assert_eq!(assessment.causes()[0].rule(), HealthRule::CollectionStatus);
        assert_eq!(
            assessment.causes()[0].observed(),
            &HealthValue::State("refresh_pending".to_owned())
        );
        assert_eq!(
            assessment.causes()[0].threshold(),
            Some(&HealthThreshold::State("complete"))
        );
    }

    #[test]
    fn per_interface_ethtool_status_isolates_only_the_matching_interface() {
        let eth0 = interface_state(
            1,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth0",
            2,
            "complete",
        );
        let eth1 = interface_state(
            2,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth1",
            3,
            "timed_out",
        );
        let eth0_payload = raw_private_gauge(3, "eth0", 2);
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                ProviderId::new("linux.ethtool.text").unwrap(),
                ProviderHealth::Partial {
                    warning: MonitorError::new(
                        MonitorErrorCode::Timeout,
                        "eth1 statistics timed out",
                    )
                    .unwrap(),
                },
                Duration::from_secs(2),
                Duration::ZERO,
                3,
            )
            .unwrap()],
            vec![eth0.clone(), eth1.clone(), eth0_payload.clone()],
            EngineTelemetry::default(),
        )
        .unwrap();

        let eth0 = assess_snapshot_series(&snapshot, &eth0);
        assert_eq!(eth0.health(), NetworkHealth::Unknown);
        assert_eq!(eth0.coverage(), EvidenceCoverage::Fresh);
        assert!(!eth0.contributes_to_health());

        let eth1 = assess_snapshot_series(&snapshot, &eth1);
        assert_eq!(eth1.health(), NetworkHealth::Unknown);
        assert_eq!(eth1.coverage(), EvidenceCoverage::Partial);
        assert_eq!(eth1.causes()[0].rule(), HealthRule::CollectionStatus);
        assert_eq!(
            eth1.causes()[0].threshold(),
            Some(&HealthThreshold::State("complete"))
        );

        let eth0_payload = assess_snapshot_series(&snapshot, &eth0_payload);
        assert_eq!(eth0_payload.coverage(), EvidenceCoverage::Fresh);
        assert!(!eth0_payload.contributes_to_health());
    }

    #[test]
    fn why_priority_orders_health_actionable_missing_and_unsupported_causes() {
        let critical = assess_series(&link_state("lower_layer_down"));
        let warning = assess_series(&link_state("down"));
        let timeout = assess_series(&interface_state(
            2,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth0",
            2,
            "timed_out",
        ));
        let unavailable = |metric, coverage, observed| MetricAssessment {
            health: NetworkHealth::Unknown,
            coverage,
            contributes_to_health: true,
            causes: vec![HealthCause {
                metric: MetricId::new(metric).unwrap(),
                condition: NetworkHealth::Unknown,
                observed,
                rule: HealthRule::FreshValueRequired,
                threshold: None,
                origin: RuleOrigin::BuiltInSemantic,
            }],
        };
        let missing = unavailable(
            "linux.nic.fec.corrected",
            EvidenceCoverage::Partial,
            HealthValue::Unavailable(UnavailableReason::Missing),
        );
        let stale = unavailable(
            "linux.socket.tcp.established_resets",
            EvidenceCoverage::Stale,
            HealthValue::Continuity("stale"),
        );
        let not_applicable = unavailable(
            "linux.nic.fec.uncorrectable",
            EvidenceCoverage::Unsupported,
            HealthValue::Unavailable(UnavailableReason::NotApplicable),
        );
        let command_missing = assess_series(&interface_state(
            3,
            crate::monitor::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
            "linux.ethtool.link_text",
            "eth0",
            2,
            "command_not_found",
        ));
        let unsupported = assess_series(&interface_state(
            4,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth0",
            2,
            "unsupported",
        ));

        let assessment = Assessment::from_metrics([
            &unsupported,
            &stale,
            &critical,
            &not_applicable,
            &missing,
            &command_missing,
            &timeout,
            &warning,
        ]);
        let ordered = assessment
            .causes()
            .iter()
            .map(|cause| cause.metric().as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            [
                "linux.nic.link_state",
                "linux.nic.link_state",
                crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
                "linux.nic.fec.corrected",
                "linux.socket.tcp.established_resets",
                crate::monitor::NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
                crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
                "linux.nic.fec.uncorrectable",
            ]
        );
        assert_eq!(assessment.causes()[0].condition(), NetworkHealth::Crit);
        assert_eq!(assessment.causes()[1].condition(), NetworkHealth::Warn);
        assert_eq!(
            assessment.causes()[2].observed(),
            &HealthValue::State("timed_out".to_owned())
        );
    }

    #[test]
    fn non_ethtool_interface_series_still_inherits_partial_provider_coverage() {
        let series = link_state("up");
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                series.source().clone(),
                ProviderHealth::Partial {
                    warning: MonitorError::new(
                        MonitorErrorCode::Io,
                        "some interfaces could not be read",
                    )
                    .unwrap(),
                },
                Duration::from_secs(2),
                Duration::ZERO,
                1,
            )
            .unwrap()],
            vec![series.clone()],
            EngineTelemetry::default(),
        )
        .unwrap();

        let assessment = assess_snapshot_series(&snapshot, &series);
        assert_eq!(assessment.health(), NetworkHealth::Ok);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Partial);
    }

    #[test]
    fn dashboard_block_reuses_matching_ethtool_status_coverage() {
        let status = interface_state(
            1,
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
            "linux.ethtool.text",
            "eth0",
            2,
            "complete",
        );
        let payload = raw_private_gauge(2, "eth0", 2);
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                ProviderId::new("linux.ethtool.text").unwrap(),
                ProviderHealth::Partial {
                    warning: MonitorError::new(
                        MonitorErrorCode::Timeout,
                        "another interface timed out",
                    )
                    .unwrap(),
                },
                Duration::from_secs(2),
                Duration::ZERO,
                2,
            )
            .unwrap()],
            vec![status, payload.clone()],
            EngineTelemetry::default(),
        )
        .unwrap();
        let dashboard = crate::monitor::dashboard::build_dashboard(&snapshot);
        let block = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block
                    .shared()
                    .iter()
                    .any(|placed| placed.series() == &payload)
            })
            .unwrap();
        let coverage = EttoolBlockCoverage::from_block(block);

        let assessment = assess_snapshot_series_with_ethtool_coverage(
            &snapshot,
            &payload,
            coverage.for_series(&payload),
        );
        assert_eq!(assessment.coverage(), EvidenceCoverage::Fresh);
    }

    #[test]
    fn dashboard_block_keeps_network_health_separate_from_missing_evidence() {
        let series = counter(
            "linux.socket.tcp.established_resets",
            Some(CounterContinuity::Continuous {
                delta: 3,
                elapsed: Duration::from_secs(1),
            }),
        );
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                series.source().clone(),
                ProviderHealth::Fresh,
                Duration::from_secs(2),
                Duration::ZERO,
                0,
            )
            .unwrap()],
            vec![series],
            EngineTelemetry::default(),
        )
        .unwrap();
        let dashboard = crate::monitor::dashboard::build_dashboard(&snapshot);
        let transport = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().kind()
                    == crate::monitor::dashboard::BlockKind::PacketStage(
                        crate::monitor::dashboard::PacketStage::Transport,
                    )
            })
            .unwrap();

        let assessment = assess_dashboard_block(&snapshot, transport);
        assert_eq!(assessment.health(), NetworkHealth::Warn);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Partial);
        assert!(assessment.causes().iter().any(|cause| {
            cause.metric().as_str() == "linux.socket.tcp.established_resets"
                && cause.condition() == NetworkHealth::Warn
                && cause.threshold().is_some()
        }));

        let netfilter = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().kind()
                    == crate::monitor::dashboard::BlockKind::PacketStage(
                        crate::monitor::dashboard::PacketStage::NetfilterConntrack,
                    )
            })
            .unwrap();
        let assessment = assess_dashboard_block(&snapshot, netfilter);
        assert_eq!(assessment.health(), NetworkHealth::Unknown);
        assert_eq!(assessment.coverage(), EvidenceCoverage::Unsupported);
    }
}
