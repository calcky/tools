use std::collections::{BTreeMap, BTreeSet};

use crate::monitor::{
    CollectionSection, CounterContinuity, InterfaceViewAnchor, MetricLabel, MetricLabels,
    MonitorSnapshot, ProjectedValue, SeriesSnapshot, SeriesValue,
};

const RX_PACKETS: &str = "linux.netdevice.rx_packets";
const RX_BYTES: &str = "linux.netdevice.rx_bytes";
const RX_ERRORS: &str = "linux.netdevice.rx_errors";
const RX_DROPS: &str = "linux.netdevice.rx_dropped";
const TX_PACKETS: &str = "linux.netdevice.tx_packets";
const TX_BYTES: &str = "linux.netdevice.tx_bytes";
const TX_ERRORS: &str = "linux.netdevice.tx_errors";
const TX_DROPS: &str = "linux.netdevice.tx_dropped";

pub(super) const GLOBAL_DASHBOARD_BLOCK_COUNT: usize = 5;
pub(super) const GLOBAL_DASHBOARD_BLOCK_ROWS: usize = 5;
pub(super) const NETFILTER_DASHBOARD_BLOCK_ROWS: usize = 3;
pub(super) const GLOBAL_DASHBOARD_ROW_COUNT: usize = (GLOBAL_DASHBOARD_BLOCK_COUNT - 1)
    * GLOBAL_DASHBOARD_BLOCK_ROWS
    + NETFILTER_DASHBOARD_BLOCK_ROWS;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct InterfaceKey {
    ifindex: u32,
    name: String,
}

impl InterfaceKey {
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    pub(super) const fn ifindex(&self) -> u32 {
        self.ifindex
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct DirectionSummary {
    pub(super) packets_per_second: Option<f64>,
    pub(super) bits_per_second: Option<f64>,
    pub(super) errors_per_second: Option<f64>,
    pub(super) drops_per_second: Option<f64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct RxTxSummary {
    pub(super) rx: DirectionSummary,
    pub(super) tx: DirectionSummary,
}

#[derive(Debug, PartialEq)]
pub(super) struct InterfaceBlock {
    pub(super) key: InterfaceKey,
    pub(super) summary: RxTxSummary,
    pub(super) rows: Vec<usize>,
    summary_rows: Vec<usize>,
}

#[derive(Debug, PartialEq)]
pub(super) struct GroupedSection {
    pub(super) interfaces: Vec<InterfaceBlock>,
    pub(super) unscoped: Vec<usize>,
}

impl GroupedSection {
    pub(super) fn refresh(
        &mut self,
        previous: &MonitorSnapshot,
        snapshot: &MonitorSnapshot,
        anchored: bool,
    ) -> bool {
        // Row indexes and ordering depend on identity, not the current source or value.
        // A visibility transition rebuilds the groups, including previously hidden rows.
        if previous.generation() != snapshot.generation()
            || previous.series().len() != snapshot.series().len()
            || !previous
                .series()
                .iter()
                .zip(snapshot.series())
                .all(|(old, new)| {
                    old.id() == new.id()
                        && old.metric() == new.metric()
                        && old.labels() == new.labels()
                        && (anchored
                            || is_fresh_down_link_state(old) == is_fresh_down_link_state(new))
                })
        {
            return false;
        }
        for block in &mut self.interfaces {
            block.summary = RxTxSummary::default();
            for &index in &block.summary_rows {
                update_summary(&mut block.summary, &snapshot.series()[index]);
            }
        }
        true
    }
}

pub(super) fn is_interface_grouped(section: CollectionSection) -> bool {
    matches!(
        section,
        CollectionSection::Tc
            | CollectionSection::Netdevice
            | CollectionSection::Nic
            | CollectionSection::Hardirq
    )
}

pub(super) fn group_section(
    snapshot: &MonitorSnapshot,
    section: CollectionSection,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> GroupedSection {
    // Borrow interface names during grouping; allocate each name only once in the result.
    let mut groups = BTreeMap::<(u32, &str), (Vec<usize>, RxTxSummary, Vec<usize>)>::new();
    let mut unscoped = Vec::new();
    let hidden_interfaces = if anchor.is_none() {
        snapshot
            .series()
            .iter()
            .filter(|series| is_fresh_down_link_state(series))
            .filter_map(borrowed_interface_key)
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };

    for (index, series) in snapshot.series().iter().enumerate() {
        let summary_metric = summary_metric(series.metric().as_str());
        let in_section = series
            .metric()
            .descriptor()
            .is_some_and(|metric| metric.primary_section == section);
        if (!in_section && summary_metric.is_none())
            || !matches_anchor(series, anchor, interface_name_alias)
        {
            continue;
        }
        let key = borrowed_interface_key(series);
        if key
            .as_ref()
            .is_some_and(|key| hidden_interfaces.contains(key))
        {
            continue;
        }
        if let Some(key) = key {
            let (rows, summary, summary_rows) = groups.entry(key).or_default();
            if summary_metric.is_some() {
                summary_rows.push(index);
                update_summary(summary, series);
            }
            if in_section {
                rows.push(index);
            }
        } else if in_section {
            unscoped.push(index);
        }
    }

    let interfaces = groups
        .into_iter()
        .map(|((ifindex, name), (mut rows, summary, summary_rows))| {
            rows.sort_by_key(|index| series_order(&snapshot.series()[*index]));
            let key = InterfaceKey {
                ifindex,
                name: name.to_owned(),
            };
            InterfaceBlock {
                key,
                summary,
                rows,
                summary_rows,
            }
        })
        .collect();
    GroupedSection {
        interfaces,
        unscoped,
    }
}

fn update_summary(summary: &mut RxTxSummary, series: &SeriesSnapshot) {
    let rate = interval_rate(series);
    match series.metric().as_str() {
        RX_PACKETS => summary.rx.packets_per_second = rate,
        RX_BYTES => summary.rx.bits_per_second = rate.map(|value| value * 8.0),
        RX_ERRORS => summary.rx.errors_per_second = rate,
        RX_DROPS => summary.rx.drops_per_second = rate,
        TX_PACKETS => summary.tx.packets_per_second = rate,
        TX_BYTES => summary.tx.bits_per_second = rate.map(|value| value * 8.0),
        TX_ERRORS => summary.tx.errors_per_second = rate,
        TX_DROPS => summary.tx.drops_per_second = rate,
        _ => unreachable!("known summary metric"),
    }
}

pub(super) fn grouped_row_count(grouped: &GroupedSection) -> usize {
    grouped
        .interfaces
        .iter()
        .map(|block| 3_usize.saturating_add(block.rows.len()))
        .sum::<usize>()
        .saturating_add(grouped.unscoped.len())
}

#[cfg(test)]
pub(super) fn section_row_count(
    snapshot: &MonitorSnapshot,
    section: CollectionSection,
    anchor: Option<&InterfaceViewAnchor>,
    alias: Option<&str>,
) -> usize {
    let hidden: BTreeSet<_> = snapshot
        .series()
        .iter()
        .filter(|row| anchor.is_none() && is_fresh_down_link_state(row))
        .filter_map(borrowed_interface_key)
        .collect();
    let mut interfaces = BTreeSet::new();
    let mut count = 0;
    for row in snapshot
        .series()
        .iter()
        .filter(|row| matches_anchor(row, anchor, alias))
    {
        let key = borrowed_interface_key(row);
        if key.is_some_and(|key| hidden.contains(&key)) {
            continue;
        }
        let in_section = row
            .metric()
            .descriptor()
            .is_some_and(|metric| metric.primary_section == section);
        count += usize::from(in_section);
        if in_section || summary_metric(row.metric().as_str()).is_some() {
            if let Some(key) = key {
                interfaces.insert(key);
            }
        }
    }
    count + 3 * interfaces.len()
}

pub(super) fn matches_anchor(
    series: &SeriesSnapshot,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> bool {
    labels_match_anchor(series.labels(), anchor, interface_name_alias)
}

pub(super) fn labels_match_anchor(
    labels: &MetricLabels,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> bool {
    let Some(anchor) = anchor else {
        return true;
    };
    let interface = labels.get(MetricLabel::Interface);
    let ifindex = labels.get(MetricLabel::Ifindex);
    if interface.is_none() && ifindex.is_none() {
        return true;
    }
    match anchor {
        InterfaceViewAnchor::Name { name } => interface == Some(name.as_str()),
        InterfaceViewAnchor::Ifindex { ifindex: selected } => {
            ifindex
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|value| value == selected.get())
                || interface_name_alias.is_some_and(|name| interface == Some(name))
        }
    }
}

pub(super) fn is_fresh_down_link_state(series: &SeriesSnapshot) -> bool {
    if series.metric().as_str() != "linux.nic.link_state" {
        return false;
    }
    matches!(
        series.value(),
        SeriesValue::State {
            current: ProjectedValue::Fresh { value, .. },
            ..
        } if value.as_str() == "down"
    )
}

fn borrowed_interface_key(series: &SeriesSnapshot) -> Option<(u32, &str)> {
    let name = series.labels().get(MetricLabel::Interface)?;
    let ifindex = series
        .labels()
        .get(MetricLabel::Ifindex)?
        .parse::<u32>()
        .ok()?;
    Some((ifindex, name))
}

fn interval_rate(series: &SeriesSnapshot) -> Option<f64> {
    let SeriesValue::Counter {
        current: ProjectedValue::Fresh { .. },
        interval:
            Some(
                CounterContinuity::Continuous { delta, elapsed }
                | CounterContinuity::Wrapped { delta, elapsed, .. },
            ),
        ..
    } = series.value()
    else {
        return None;
    };
    (*elapsed > std::time::Duration::ZERO).then(|| *delta as f64 / elapsed.as_secs_f64())
}

fn summary_metric(metric: &str) -> Option<&'static str> {
    Some(match metric {
        RX_PACKETS => RX_PACKETS,
        RX_BYTES => RX_BYTES,
        RX_ERRORS => RX_ERRORS,
        RX_DROPS => RX_DROPS,
        TX_PACKETS => TX_PACKETS,
        TX_BYTES => TX_BYTES,
        TX_ERRORS => TX_ERRORS,
        TX_DROPS => TX_DROPS,
        _ => return None,
    })
}

fn series_order(series: &SeriesSnapshot) -> (u8, u64, &str) {
    let direction = match series.labels().get(MetricLabel::Direction) {
        Some("ingress" | "rx") => 0,
        Some("egress" | "tx") => 1,
        _ => 2,
    };
    let row = series
        .labels()
        .get(MetricLabel::RowId)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    (direction, row, series.metric().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{
        BaselineOrigin, CounterSpan, HistoryCoverage, MetricId, MetricLabels, ProviderHealth,
        ProviderId, ProviderSnapshot, SeriesId, StateValue,
    };
    use std::time::Duration;

    fn counter(id: u64, metric: &str, interface: &str, ifindex: u32, delta: u64) -> SeriesSnapshot {
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new("linux.monitor.netdevice").unwrap(),
            ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
            MetricId::new(metric).unwrap(),
            MetricLabels::new([
                (MetricLabel::Interface, interface.to_owned()),
                (MetricLabel::Ifindex, ifindex.to_string()),
            ])
            .unwrap(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: delta,
                    observed_at: Duration::from_secs(1),
                },
                interval: Some(CounterContinuity::Continuous {
                    delta,
                    elapsed: Duration::from_secs(1),
                }),
                since_baseline: Some(CounterSpan::new(delta, Duration::from_secs(1)).unwrap()),
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn discontinuous_counter(
        id: u64,
        metric: &str,
        current: ProjectedValue<u64>,
        interval: Option<CounterContinuity>,
        baseline_origin: BaselineOrigin,
        baseline_at: Duration,
    ) -> SeriesSnapshot {
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new("linux.monitor.netdevice").unwrap(),
            ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
            MetricId::new(metric).unwrap(),
            MetricLabels::new([
                (MetricLabel::Interface, "eth0".to_owned()),
                (MetricLabel::Ifindex, "2".to_owned()),
            ])
            .unwrap(),
            Duration::ZERO,
            baseline_origin,
            baseline_at,
            SeriesValue::Counter {
                current,
                interval,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn link_state(id: u64, interface: &str, ifindex: u32, state: &str) -> SeriesSnapshot {
        let metric = "linux.nic.link_state";
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(crate::monitor::descriptor(metric).unwrap().owner).unwrap(),
            ProviderId::new("linux.sysfs.net.nic").unwrap(),
            MetricId::new(metric).unwrap(),
            MetricLabels::new([
                (MetricLabel::Interface, interface.to_owned()),
                (MetricLabel::Ifindex, ifindex.to_string()),
            ])
            .unwrap(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: StateValue::new(state).unwrap(),
                    observed_at: Duration::from_secs(1),
                },
                changed_at: None,
                continuous_for: Some(Duration::from_secs(1)),
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn snapshot_with_link_states(series: Vec<SeriesSnapshot>) -> MonitorSnapshot {
        MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(1),
            None,
            vec![
                ProviderSnapshot::new(
                    ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
                    ProviderHealth::Fresh,
                    Duration::from_secs(1),
                    Duration::ZERO,
                    0,
                )
                .unwrap(),
                ProviderSnapshot::new(
                    ProviderId::new("linux.sysfs.net.nic").unwrap(),
                    ProviderHealth::Fresh,
                    Duration::from_secs(1),
                    Duration::ZERO,
                    0,
                )
                .unwrap(),
                ProviderSnapshot::new(
                    ProviderId::new("linux.proc.net.dev").unwrap(),
                    ProviderHealth::Fresh,
                    Duration::from_secs(1),
                    Duration::ZERO,
                    0,
                )
                .unwrap(),
            ],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap()
    }

    #[test]
    fn cached_grouping_refreshes_summaries_and_source_changes() {
        let previous = snapshot_with_link_states(vec![
            counter(1, RX_PACKETS, "eth0", 2, 10),
            counter(2, TX_BYTES, "eth0", 2, 20),
            link_state(3, "eth0", 2, "up"),
        ]);
        let changed = counter(2, TX_BYTES, "eth0", 2, 90);
        let changed = SeriesSnapshot::new(
            changed.id(),
            changed.provider().clone(),
            ProviderId::new("linux.proc.net.dev").unwrap(),
            changed.metric().clone(),
            changed.labels().clone(),
            changed.first_seen(),
            changed.baseline_origin(),
            changed.baseline_at(),
            changed.value().clone(),
            changed.history(),
        )
        .unwrap();
        let next = snapshot_with_link_states(vec![
            discontinuous_counter(
                1,
                RX_PACKETS,
                ProjectedValue::Unavailable {
                    reason: crate::monitor::UnavailableReason::Missing,
                },
                None,
                BaselineOrigin::SessionStart,
                Duration::ZERO,
            ),
            changed,
            link_state(3, "eth0", 2, "unknown"),
        ]);
        for section in [
            CollectionSection::Nic,
            CollectionSection::Netdevice,
            CollectionSection::Tc,
            CollectionSection::Hardirq,
        ] {
            for (anchor, alias) in [
                (None, None),
                (Some(InterfaceViewAnchor::named("eth0").unwrap()), None),
                (Some(InterfaceViewAnchor::indexed(9).unwrap()), Some("eth0")),
            ] {
                let mut cached = group_section(&previous, section, anchor.as_ref(), alias);
                let rows = cached.interfaces[0].rows.as_ptr();
                assert!(cached.refresh(&previous, &next, anchor.is_some()));
                assert_eq!(cached.interfaces[0].rows.as_ptr(), rows);
                assert_eq!(
                    cached,
                    group_section(&next, section, anchor.as_ref(), alias)
                );
                assert_eq!(cached.interfaces[0].summary.rx.packets_per_second, None);
                assert_eq!(cached.interfaces[0].summary.tx.bits_per_second, Some(720.0));
            }
        }
    }

    #[test]
    fn cached_grouping_rebuilds_for_layout_and_down_visibility_changes() {
        let previous = snapshot_with_link_states(vec![
            counter(1, RX_PACKETS, "eth0", 2, 10),
            link_state(2, "eth0", 2, "up"),
        ]);
        for rows in [
            vec![
                counter(1, RX_PACKETS, "eth0", 2, 20),
                link_state(2, "eth0", 2, "down"),
            ],
            vec![
                counter(1, RX_PACKETS, "renamed", 2, 20),
                link_state(2, "renamed", 2, "up"),
            ],
            vec![
                counter(1, RX_PACKETS, "eth0", 9, 20),
                link_state(2, "eth0", 9, "up"),
            ],
            vec![
                counter(1, TX_PACKETS, "eth0", 2, 20),
                link_state(2, "eth0", 2, "up"),
            ],
            vec![
                counter(2, RX_PACKETS, "eth0", 2, 20),
                link_state(1, "eth0", 2, "up"),
            ],
            vec![counter(1, RX_PACKETS, "eth0", 2, 20)],
            vec![
                counter(1, RX_PACKETS, "eth0", 2, 20),
                link_state(2, "eth0", 2, "up"),
                counter(3, TX_PACKETS, "eth1", 3, 30),
            ],
        ] {
            let next = snapshot_with_link_states(rows);
            let mut cached = group_section(&previous, CollectionSection::Nic, None, None);
            assert!(!cached.refresh(&previous, &next, false));
        }

        let down = snapshot_with_link_states(vec![
            counter(1, RX_PACKETS, "eth0", 2, 20),
            link_state(2, "eth0", 2, "down"),
        ]);
        let mut hidden = group_section(&down, CollectionSection::Nic, None, None);
        assert!(hidden.interfaces.is_empty());
        assert!(!hidden.refresh(&down, &previous, false));
        let anchor = InterfaceViewAnchor::named("eth0").unwrap();
        let mut anchored = group_section(&previous, CollectionSection::Nic, Some(&anchor), None);
        assert!(anchored.refresh(&previous, &down, true));
        assert_eq!(
            anchored,
            group_section(&down, CollectionSection::Nic, Some(&anchor), None)
        );
    }

    #[test]
    fn two_interfaces_never_share_direction_summaries() {
        let series = vec![
            counter(1, RX_PACKETS, "eth0", 2, 10),
            counter(2, RX_BYTES, "eth0", 2, 100),
            counter(3, RX_ERRORS, "eth0", 2, 1),
            counter(4, RX_DROPS, "eth0", 2, 2),
            counter(5, TX_PACKETS, "eth0", 2, 20),
            counter(6, TX_BYTES, "eth0", 2, 200),
            counter(7, TX_ERRORS, "eth0", 2, 3),
            counter(8, TX_DROPS, "eth0", 2, 4),
            counter(9, RX_PACKETS, "eth1", 3, 30),
            counter(10, RX_BYTES, "eth1", 3, 300),
            counter(11, RX_ERRORS, "eth1", 3, 5),
            counter(12, RX_DROPS, "eth1", 3, 6),
            counter(13, TX_PACKETS, "eth1", 3, 40),
            counter(14, TX_BYTES, "eth1", 3, 400),
            counter(15, TX_ERRORS, "eth1", 3, 7),
            counter(16, TX_DROPS, "eth1", 3, 8),
        ];
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(1),
            None,
            vec![ProviderSnapshot::new(
                ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
                ProviderHealth::Fresh,
                Duration::from_secs(1),
                Duration::ZERO,
                0,
            )
            .unwrap()],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();

        let grouped = group_section(&snapshot, CollectionSection::Netdevice, None, None);

        for section in CollectionSection::ALL {
            for anchor in [None, Some(InterfaceViewAnchor::named("eth0").unwrap())] {
                assert_eq!(
                    section_row_count(&snapshot, section, anchor.as_ref(), None),
                    grouped_row_count(&group_section(&snapshot, section, anchor.as_ref(), None)),
                );
            }
        }

        assert_eq!(grouped.interfaces.len(), 2);
        assert_eq!(grouped.interfaces[0].key.name(), "eth0");
        assert_eq!(
            grouped.interfaces[0].summary.rx.packets_per_second,
            Some(10.0)
        );
        assert_eq!(
            grouped.interfaces[0].summary.tx.bits_per_second,
            Some(1_600.0)
        );
        assert_eq!(
            grouped.interfaces[0].summary.rx.errors_per_second,
            Some(1.0)
        );
        assert_eq!(grouped.interfaces[0].summary.tx.drops_per_second, Some(4.0));
        assert_eq!(grouped.interfaces[1].key.name(), "eth1");
        assert_eq!(
            grouped.interfaces[1].summary.rx.packets_per_second,
            Some(30.0)
        );
        assert_eq!(
            grouped.interfaces[1].summary.tx.bits_per_second,
            Some(3_200.0)
        );
        assert_eq!(
            grouped.interfaces[1].summary.rx.errors_per_second,
            Some(5.0)
        );
        assert_eq!(grouped.interfaces[1].summary.tx.drops_per_second, Some(8.0));
    }

    #[test]
    fn grouped_sections_hide_fresh_down_interfaces_unless_anchored() {
        let snapshot = snapshot_with_link_states(vec![
            counter(1, RX_PACKETS, "eth0", 2, 10),
            link_state(2, "eth0", 2, "up"),
            counter(3, RX_PACKETS, "eth1", 3, 20),
            link_state(4, "eth1", 3, "down"),
            counter(5, RX_PACKETS, "bond0", 4, 30),
            link_state(6, "bond0", 4, "lower_layer_down"),
        ]);

        let grouped = group_section(&snapshot, CollectionSection::Netdevice, None, None);
        assert_eq!(
            grouped
                .interfaces
                .iter()
                .map(|block| block.key.name())
                .collect::<Vec<_>>(),
            ["eth0", "bond0"]
        );

        let anchor = InterfaceViewAnchor::named("eth1").unwrap();
        let grouped = group_section(&snapshot, CollectionSection::Netdevice, Some(&anchor), None);
        assert_eq!(grouped.interfaces.len(), 1);
        assert_eq!(grouped.interfaces[0].key.name(), "eth1");
    }

    #[test]
    fn discontinuous_or_unavailable_samples_do_not_become_zero_rates() {
        let series = vec![
            discontinuous_counter(
                1,
                RX_PACKETS,
                ProjectedValue::Unavailable {
                    reason: crate::monitor::UnavailableReason::Missing,
                },
                None,
                BaselineOrigin::SessionStart,
                Duration::ZERO,
            ),
            discontinuous_counter(
                2,
                RX_BYTES,
                ProjectedValue::Stale {
                    last: 100,
                    observed_at: Duration::from_secs(1),
                    age: Duration::from_secs(1),
                    cause: crate::monitor::MonitorErrorCode::Io,
                },
                None,
                BaselineOrigin::SessionStart,
                Duration::ZERO,
            ),
            discontinuous_counter(
                3,
                RX_ERRORS,
                ProjectedValue::Fresh {
                    value: 1,
                    observed_at: Duration::from_secs(2),
                },
                Some(CounterContinuity::Reset),
                BaselineOrigin::Reset,
                Duration::from_secs(2),
            ),
            discontinuous_counter(
                4,
                RX_DROPS,
                ProjectedValue::Fresh {
                    value: 1,
                    observed_at: Duration::from_secs(2),
                },
                Some(CounterContinuity::RecoveredAfterGap),
                BaselineOrigin::RecoveredAfterGap,
                Duration::from_secs(2),
            ),
        ];
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(2),
            None,
            vec![ProviderSnapshot::new(
                ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
                ProviderHealth::Fresh,
                Duration::from_secs(2),
                Duration::ZERO,
                0,
            )
            .unwrap()],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();

        let grouped = group_section(&snapshot, CollectionSection::Netdevice, None, None);
        assert_eq!(grouped.interfaces.len(), 1);
        assert_eq!(
            grouped.interfaces[0].summary.rx,
            DirectionSummary::default()
        );
    }
}
