//! Collection availability, separate from network fault/pressure assessment.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::{Hash, Hasher};

use crate::monitor::{
    metric_catalog, MetricDescriptor, MetricLabel, MonitorSnapshot, ProjectedValue, ProviderHealth,
    SeriesSnapshot, SeriesValue, NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
    NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CollectionHealth {
    Healthy,
    Degraded,
    NoData,
}

/// Allocation-free key for the parts of collection state that affect the
/// session-level status. Provider diagnostic text may change without changing
/// its status category, so it is intentionally excluded.
pub(super) fn status_key(snapshot: &MonitorSnapshot) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    snapshot.series().len().hash(&mut hasher);
    for provider in snapshot.providers() {
        provider.provider().as_str().hash(&mut hasher);
        provider.health().as_str().hash(&mut hasher);
    }
    hasher.finish()
}

/// Unsupported alternatives do not imply a failure when their complete collection
/// scope is covered. Other provider failures are never suppressed by a fallback.
pub(super) fn collection_health(snapshot: &MonitorSnapshot) -> CollectionHealth {
    if snapshot.providers().iter().any(|provider| {
        !matches!(
            provider.health(),
            ProviderHealth::Fresh | ProviderHealth::Unsupported { .. }
        )
    }) {
        return CollectionHealth::Degraded;
    }
    let fresh_sources: HashSet<_> = snapshot
        .providers()
        .iter()
        .filter(|provider| provider.health().is_fresh())
        .map(|provider| provider.provider().as_str())
        .collect();
    let mut required = BTreeMap::new();
    for provider in snapshot
        .providers()
        .iter()
        .filter(|provider| !provider.health().is_fresh())
    {
        let unsupported = provider.provider().as_str();
        // Both adapters perform the same complete qdisc dump. Empty dumps count
        // as coverage; this case never allocates a metric or interface index.
        let tc_alternative = match unsupported {
            "linux.tc.json" => Some("linux.rtnetlink.tc"),
            "linux.rtnetlink.tc" => Some("linux.tc.json"),
            _ => None,
        };
        if let Some(alternative) = tc_alternative {
            if !fresh_sources.contains(alternative) {
                return CollectionHealth::Degraded;
            }
            continue;
        }
        let mut found = false;
        for metric in metric_catalog().iter().filter(|metric| {
            metric
                .sources
                .iter()
                .any(|source| source.provider == unsupported)
        }) {
            found = true;
            // CPU, rule, queue and opaque statistic namespaces cannot be proven
            // complete merely because one metric was observed elsewhere.
            if metric
                .allowed_labels
                .iter()
                .any(|label| !matches!(label, MetricLabel::Interface | MetricLabel::Ifindex))
                || !metric
                    .sources
                    .iter()
                    .any(|source| fresh_sources.contains(source.provider))
            {
                return CollectionHealth::Degraded;
            }
            required.insert(metric.id, metric);
        }
        if !found {
            return CollectionHealth::Degraded;
        }
    }

    let mut coverage = Coverage::default();
    let mut observed = false;
    for series in snapshot.series() {
        // A cached value does not become healthy because another provider succeeded.
        if !fresh_sources.contains(series.source().as_str()) || stale(series.value()) {
            return CollectionHealth::Degraded;
        }
        if !matches!(
            series.metric().as_str(),
            NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID | NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID
        ) {
            observed |= fresh(series.value());
        }
        // The ordinary fresh path only scans values and checks source membership.
        // Candidate fallback metrics and inventory are indexed together, once.
        if !required.is_empty() {
            if let Some(identity) = interface(series) {
                coverage.interfaces.insert(identity);
            }
            if required.contains_key(series.metric().as_str()) {
                coverage
                    .metrics
                    .entry(series.metric().as_str())
                    .or_default()
                    .push(series);
            }
        }
    }
    if required
        .values()
        .any(|metric| !coverage.metric_covered(metric))
    {
        CollectionHealth::Degraded
    } else if observed {
        CollectionHealth::Healthy
    } else {
        CollectionHealth::NoData
    }
}

#[derive(Default)]
struct Coverage<'a> {
    metrics: BTreeMap<&'a str, Vec<&'a SeriesSnapshot>>,
    interfaces: BTreeSet<(&'a str, &'a str)>,
}

impl Coverage<'_> {
    fn metric_covered(&self, metric: &MetricDescriptor) -> bool {
        let Some(rows) = self.metrics.get(metric.id).filter(|rows| !rows.is_empty()) else {
            return false;
        };
        if !rows
            .iter()
            .all(|series| metric.source_is_allowed(series.source()) && fresh(series.value()))
        {
            return false;
        }
        if metric.required_labels.contains(&MetricLabel::Interface) {
            let identities: BTreeSet<_> =
                rows.iter().filter_map(|series| interface(series)).collect();
            !self.interfaces.is_empty()
                && identities == self.interfaces
                && rows.iter().all(|series| interface(series).is_some())
        } else {
            rows.len() == 1 && rows[0].labels().iter().next().is_none()
        }
    }
}

fn interface(series: &SeriesSnapshot) -> Option<(&str, &str)> {
    Some((
        series.labels().get(MetricLabel::Ifindex)?,
        series.labels().get(MetricLabel::Interface)?,
    ))
}

fn fresh(value: &SeriesValue) -> bool {
    match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            matches!(current, ProjectedValue::Fresh { .. })
        }
        SeriesValue::State { current, .. } => matches!(current, ProjectedValue::Fresh { .. }),
    }
}

fn stale(value: &SeriesValue) -> bool {
    match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            matches!(current, ProjectedValue::Stale { .. })
        }
        SeriesValue::State { current, .. } => matches!(current, ProjectedValue::Stale { .. }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::session::MonitorEngine;
    use crate::monitor::{
        CounterBits, MetricId, MetricLabels, MetricReading, MonitorError, MonitorErrorCode,
        ProviderId, ProviderSample, SampleReading, UnavailableReason,
    };
    use std::sync::Arc;
    use std::time::Duration;

    fn unsupported() -> ProviderHealth {
        ProviderHealth::Unsupported {
            reason: MonitorError::new(MonitorErrorCode::Unsupported, "fixture unavailable")
                .unwrap(),
        }
    }

    fn sample(
        source: &str,
        health: ProviderHealth,
        readings: Vec<SampleReading>,
    ) -> ProviderSample {
        ProviderSample::new(
            ProviderId::new(source).unwrap(),
            Duration::from_secs(4),
            Duration::ZERO,
            health,
            readings,
        )
        .unwrap()
    }

    fn snapshot(samples: Vec<ProviderSample>) -> Arc<MonitorSnapshot> {
        MonitorEngine::new(1, Duration::from_secs(1))
            .unwrap()
            .ingest(Duration::from_secs(4), samples, None)
            .unwrap()
    }

    fn global() -> ProviderSample {
        sample(
            "linux.proc.net.snmp",
            ProviderHealth::Fresh,
            vec![SampleReading::observed(
                MetricId::new("linux.socket.tcp.current_established").unwrap(),
                MetricLabels::default(),
                MetricReading::Gauge(0),
            )],
        )
    }

    fn link_readings(covered_source: &str, interfaces: &[(&str, u32)]) -> Vec<SampleReading> {
        metric_catalog()
            .iter()
            .filter(|metric| {
                metric
                    .sources
                    .iter()
                    .any(|source| source.provider == covered_source)
            })
            .flat_map(|metric| {
                interfaces.iter().map(move |(name, index)| {
                    SampleReading::observed(
                        MetricId::new(metric.id).unwrap(),
                        MetricLabels::new([
                            (MetricLabel::Interface, (*name).to_owned()),
                            (MetricLabel::Ifindex, index.to_string()),
                        ])
                        .unwrap(),
                        MetricReading::Counter {
                            value: 0,
                            bits: Some(CounterBits::Bits64),
                        },
                    )
                })
            })
            .collect()
    }

    #[test]
    fn tc_fallback_is_redundant_in_both_directions_including_empty_dumps() {
        for (primary, backup) in [
            ("linux.rtnetlink.tc", "linux.tc.json"),
            ("linux.tc.json", "linux.rtnetlink.tc"),
        ] {
            let snapshot = snapshot(vec![
                global(),
                sample(primary, ProviderHealth::Fresh, vec![]),
                sample(backup, unsupported(), vec![]),
            ]);
            assert_eq!(collection_health(&snapshot), CollectionHealth::Healthy);
        }
    }

    #[test]
    fn an_unrelated_success_or_unobserved_link_provider_cannot_cover_a_backup() {
        for unsupported_source in [
            "linux.tc.json",
            "linux.rtnetlink.link_stats",
            "fixture.unknown",
        ] {
            let snapshot = snapshot(vec![
                global(),
                sample(unsupported_source, unsupported(), vec![]),
            ]);
            assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
        }
        let snapshot = snapshot(vec![
            global(),
            sample("linux.rtnetlink.link_stats", ProviderHealth::Fresh, vec![]),
            sample("linux.sysfs.net.statistics", unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
    }

    #[test]
    fn link_coverage_requires_every_declared_metric_on_every_interface() {
        let source = "linux.sysfs.net.statistics";
        let all = link_readings(source, &[("eth0", 2), ("eth1", 3)]);
        let complete = snapshot(vec![
            sample(
                "linux.rtnetlink.link_stats",
                ProviderHealth::Fresh,
                all.clone(),
            ),
            sample(source, unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&complete), CollectionHealth::Healthy);
        let mut incomplete = all;
        incomplete.retain(|reading| {
            !(reading.metric().as_str() == "linux.netdevice.rx_bytes"
                && reading.labels().get(MetricLabel::Ifindex) == Some("3"))
        });
        let incomplete = snapshot(vec![
            sample(
                "linux.rtnetlink.link_stats",
                ProviderHealth::Fresh,
                incomplete,
            ),
            sample(source, unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&incomplete), CollectionHealth::Degraded);
    }

    #[test]
    fn proc_link_counters_cannot_cover_rtnetlink_drop_and_driver_error_fields() {
        let snapshot = snapshot(vec![
            sample(
                "linux.proc.net.dev",
                ProviderHealth::Fresh,
                link_readings("linux.proc.net.dev", &[("eth0", 2)]),
            ),
            sample("linux.rtnetlink.link_stats", unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
    }

    #[test]
    fn missing_metric_values_do_not_count_as_fresh_fallback_coverage() {
        let mut readings = link_readings("linux.sysfs.net.statistics", &[("eth0", 2)]);
        let removed = readings.remove(0);
        readings.push(SampleReading::unavailable(
            removed.metric().clone(),
            removed.labels().clone(),
            UnavailableReason::Missing,
        ));
        let snapshot = snapshot(vec![
            sample(
                "linux.rtnetlink.link_stats",
                ProviderHealth::Fresh,
                readings,
            ),
            sample("linux.sysfs.net.statistics", unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
    }

    #[test]
    fn failed_or_partial_collection_is_not_suppressed_by_a_working_alternative() {
        let error = MonitorError::new(MonitorErrorCode::Io, "fixture failure").unwrap();
        for health in [
            ProviderHealth::Error {
                error: error.clone(),
            },
            ProviderHealth::PermissionDenied {
                reason: MonitorError::new(MonitorErrorCode::PermissionDenied, "fixture denied")
                    .unwrap(),
            },
            ProviderHealth::Partial {
                warning: error.clone(),
            },
            ProviderHealth::Stale {
                last_success_at: Duration::from_secs(1),
                age: Duration::from_secs(3),
                cause: error,
            },
        ] {
            for (failed, replacement) in [
                ("linux.rtnetlink.tc", "linux.tc.json"),
                ("linux.tc.json", "linux.rtnetlink.tc"),
            ] {
                let snapshot = snapshot(vec![
                    global(),
                    sample(failed, health.clone(), vec![]),
                    sample(replacement, ProviderHealth::Fresh, vec![]),
                ]);
                assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
            }
        }
    }

    #[test]
    fn empty_success_is_not_presented_as_observed_data() {
        assert_eq!(
            collection_health(&snapshot(vec![])),
            CollectionHealth::NoData
        );
        let snapshot = snapshot(vec![
            sample("linux.rtnetlink.tc", ProviderHealth::Fresh, vec![]),
            sample("linux.tc.json", unsupported(), vec![]),
        ]);
        assert_eq!(collection_health(&snapshot), CollectionHealth::NoData);
    }

    #[test]
    fn fresh_values_still_require_known_source_health() {
        let base = snapshot(vec![global()]);
        let unknown_source = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(4),
            None,
            vec![],
            base.series().to_vec(),
            crate::monitor::EngineTelemetry::default(),
        );
        // MonitorSnapshot rejects a series whose provider is absent, so an
        // unknown source cannot be presented as fresh through the public model.
        assert!(unknown_source.is_err());
        assert_eq!(collection_health(&base), CollectionHealth::Healthy);
    }

    #[test]
    fn a_fresh_provider_does_not_hide_a_stale_series() {
        use crate::monitor::{BaselineOrigin, HistoryCoverage, SeriesId};
        let base = snapshot(vec![global()]);
        let stale = SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            ProviderId::new(crate::monitor::OWNER_SOCKET).unwrap(),
            ProviderId::new("linux.proc.net.snmp").unwrap(),
            MetricId::new("linux.socket.tcp.current_established").unwrap(),
            MetricLabels::default(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Gauge {
                current: ProjectedValue::Stale {
                    last: 0,
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                interval: None,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap();
        let stale = MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(4),
            None,
            base.providers().to_vec(),
            vec![stale],
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        assert_eq!(collection_health(&stale), CollectionHealth::Degraded);
    }

    #[test]
    fn unsupported_ethtool_fec_cannot_be_hidden_by_link_state_coverage() {
        let snapshot = snapshot(vec![
            global(),
            sample("linux.ethtool.netlink", unsupported(), vec![]),
            sample(
                "linux.sysfs.net.nic",
                ProviderHealth::Fresh,
                vec![SampleReading::observed(
                    MetricId::new("linux.nic.link_state").unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, "eth0".to_owned()),
                        (MetricLabel::Ifindex, "2".to_owned()),
                    ])
                    .unwrap(),
                    MetricReading::State(crate::monitor::StateValue::new("up").unwrap()),
                )],
            ),
        ]);
        assert_eq!(collection_health(&snapshot), CollectionHealth::Degraded);
    }
}
