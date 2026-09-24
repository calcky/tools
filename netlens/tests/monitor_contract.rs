use std::collections::BTreeSet;
use std::time::Duration;

use netlens::model::Layer;
use netlens::monitor::catalog::aggregation_compatible;
use netlens::monitor::dashboard::{
    build_dashboard, paths_are_reverse, placement_for, Attribution, BlockKind, BlockScope,
    DisplaySlot, ExecutionContext, Lane, PacketStage, PlacementScope, RX_PATH, TX_PATH,
};
use netlens::monitor::health::{
    assess_dashboard_block, assess_series, EvidenceCoverage, NetworkHealth, RuleOrigin,
};
use netlens::monitor::{
    descriptor, metric_catalog, minimum_descriptors, validate_catalog, AggregationDomain,
    AggregationPolicy, BaselineOrigin, CollectionSection, CounterBits, CounterContinuity,
    CounterSpan, DisplayMeaning, EngineTelemetry, GaugeChange, GaugeSummary, HistoryCoverage,
    InterfaceViewAnchor, MetricId, MetricKind, MetricLabel, MetricLabels, MetricReading,
    MetricScope, MetricUnit, MonitorError, MonitorErrorCode, MonitorPlan, MonitorSection,
    MonitorSnapshot, MonitorValidationError, ProjectedValue, ProviderHealth, ProviderId,
    ProviderSample, ProviderSnapshot, ReadingOutcome, SampleReading, SamplingInterval, SeriesId,
    SeriesSnapshot, SeriesValue, StateValue, StateValuePolicy, UnavailableReason,
    MAX_ADMITTED_SERIES, MAX_DIAGNOSTIC_BYTES, MAX_HISTORY_BUCKETS, MAX_HISTORY_BYTES,
    MAX_LABEL_VALUE_BYTES, MAX_PROVIDERS, MAX_READINGS_PER_PROVIDER, OWNER_NETDEVICE, OWNER_NIC,
    OWNER_SOCKET, RAW_NIC_SETTING_METRIC_ID, RAW_PRIVATE_NIC_METRIC_ID,
};
use serde_json::{json, Value};

fn id(value: &str) -> MetricId {
    MetricId::new(value).unwrap()
}

fn provider(value: &str) -> ProviderId {
    ProviderId::new(value).unwrap()
}

fn labels(values: &[(MetricLabel, &str)]) -> MetricLabels {
    MetricLabels::new(
        values
            .iter()
            .map(|(label, value)| (*label, (*value).to_owned())),
    )
    .unwrap()
}

fn fresh_provider_snapshot(provider_name: &str, elapsed: Duration) -> ProviderSnapshot {
    ProviderSnapshot::new(
        provider(provider_name),
        ProviderHealth::Fresh,
        elapsed,
        Duration::from_millis(5),
        0,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn counter_series(
    series_id: u64,
    baseline_origin: BaselineOrigin,
    first_seen: Duration,
    baseline_at: Duration,
    current: ProjectedValue<u64>,
    interval: Option<CounterContinuity>,
    since_baseline: Option<CounterSpan>,
    history: HistoryCoverage,
) -> SeriesSnapshot {
    SeriesSnapshot::new(
        SeriesId::new(series_id).unwrap(),
        provider(OWNER_SOCKET),
        provider("linux.proc.net.snmp"),
        id("linux.socket.tcp.segments_in"),
        MetricLabels::default(),
        first_seen,
        baseline_origin,
        baseline_at,
        SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        },
        history,
    )
    .unwrap()
}

#[test]
fn monitor_sections_do_not_extend_report_layers() {
    assert_eq!(CollectionSection::ALL.len(), 7);
    assert_eq!(MonitorSection::ALL.len(), 9);
    assert_eq!(Layer::ALL.len(), 13);
    assert_eq!(Layer::ALL[0], Layer::Socket);
    assert_eq!(Layer::ALL[12], Layer::KernelBypass);
    assert!(Layer::ALL
        .iter()
        .all(|layer| !matches!(layer.as_str(), "softirq" | "hardirq")));
    assert_eq!(
        MonitorSection::Softirq.collection_section(),
        Some(CollectionSection::Softirq)
    );
    assert_eq!(
        MonitorSection::Hardirq.collection_section(),
        Some(CollectionSection::Hardirq)
    );
}

#[test]
fn dashboard_paths_and_catalog_placements_are_closed_contracts() {
    assert!(paths_are_reverse(&RX_PATH, &TX_PATH));
    assert_eq!(PacketStage::ALL, TX_PATH);
    assert_eq!(RX_PATH.first(), Some(&PacketStage::NicPhy));
    assert_eq!(RX_PATH.last(), Some(&PacketStage::SocketApplication));
    assert!(metric_catalog()
        .iter()
        .all(|descriptor| placement_for(descriptor).is_some()));
}

#[test]
fn interface_kind_is_a_strict_sysfs_identity_metric_in_the_nic_block() {
    let metric = descriptor("linux.nic.interface_kind").unwrap();
    assert_eq!(metric.primary_section, CollectionSection::Nic);
    assert_eq!(metric.kind, MetricKind::State);
    assert_eq!(metric.unit, MetricUnit::State);
    assert_eq!(metric.scope, MetricScope::Interface);
    assert_eq!(metric.display, DisplayMeaning::InformationOnly);
    assert!(!metric.minimum);
    assert_eq!(
        metric.required_labels,
        &[MetricLabel::Interface, MetricLabel::Ifindex]
    );
    assert_eq!(
        metric.state_values,
        StateValuePolicy::Closed(&["physical", "virtual"])
    );
    assert_eq!(metric.sources.len(), 1);
    assert_eq!(metric.sources[0].provider, "linux.sysfs.net.nic");
    assert_eq!(metric.sources[0].raw_metric, "interface.kind");

    let placement = placement_for(metric).unwrap();
    assert_eq!(placement.scope(), PlacementScope::Interface);
    assert_eq!(
        placement.block_kind(),
        BlockKind::PacketStage(PacketStage::NicPhy)
    );
    assert_eq!(placement.lane(), Lane::Shared);
    assert_eq!(placement.attribution(), Attribution::Exact);
    assert_eq!(placement.display(), DisplaySlot::Summary { rank: 5 });
}

#[test]
fn ethtool_outcomes_are_strict_interface_status_metrics() {
    for (id, provider_name, raw_metric, stage) in [
        (
            "linux.nic.ethtool_settings_status",
            "linux.ethtool.link_text",
            "collection.status",
            PacketStage::NicPhy,
        ),
        (
            "linux.nic.ethtool_statistics_status",
            "linux.ethtool.text",
            "collection.status",
            PacketStage::DriverNapi,
        ),
    ] {
        let metric = descriptor(id).unwrap();
        assert_eq!(metric.primary_section, CollectionSection::Nic);
        assert_eq!(metric.kind, MetricKind::State);
        assert_eq!(metric.scope, MetricScope::Interface);
        assert_eq!(metric.display, DisplayMeaning::State);
        assert!(metric.required_labels.contains(&MetricLabel::Interface));
        assert!(metric.required_labels.contains(&MetricLabel::Ifindex));
        assert_eq!(
            metric.state_values,
            StateValuePolicy::Closed(&[
                "complete",
                "refresh_pending",
                "partial_schema_mismatch",
                "partial_cardinality_limit",
                "unsupported",
                "command_not_found",
                "permission_denied",
                "interface_unavailable",
                "timed_out",
                "output_limit",
                "invalid_output",
                "command_failed",
                "io_error",
            ])
        );
        assert_eq!(metric.sources[0].provider, provider_name);
        assert_eq!(metric.sources[0].raw_metric, raw_metric);

        let placement = placement_for(metric).unwrap();
        assert_eq!(placement.scope(), PlacementScope::Interface);
        assert_eq!(placement.block_kind(), BlockKind::PacketStage(stage));
        assert_eq!(placement.lane(), Lane::Shared);
        assert_eq!(placement.attribution(), Attribution::Opaque);
    }
}

#[test]
fn health_warning_exposes_metric_observation_rule_and_threshold() {
    let metric = descriptor("linux.socket.tcp.established_resets").unwrap();
    let series = SeriesSnapshot::new(
        SeriesId::new(1).unwrap(),
        provider(metric.owner),
        provider(metric.sources[0].provider),
        id(metric.id),
        MetricLabels::default(),
        Duration::ZERO,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        SeriesValue::Counter {
            current: ProjectedValue::Fresh {
                value: 10,
                observed_at: Duration::from_secs(1),
            },
            interval: Some(CounterContinuity::Continuous {
                delta: 2,
                elapsed: Duration::from_secs(1),
            }),
            since_baseline: Some(CounterSpan::new(2, Duration::from_secs(1)).unwrap()),
        },
        HistoryCoverage::empty(),
    )
    .unwrap();

    let assessment = assess_series(&series);
    assert_eq!(assessment.health(), NetworkHealth::Warn);
    assert_eq!(assessment.coverage(), EvidenceCoverage::Fresh);
    assert_eq!(assessment.causes().len(), 1);
    let cause = &assessment.causes()[0];
    assert_eq!(cause.metric().as_str(), metric.id);
    assert_eq!(cause.origin(), RuleOrigin::BuiltInSemantic);
    assert!(cause.threshold().is_some());
}

#[test]
fn synthetic_dashboard_tree_and_health_are_deterministic() {
    let error_metric = descriptor("linux.socket.tcp.established_resets").unwrap();
    let error = SeriesSnapshot::new(
        SeriesId::new(1).unwrap(),
        provider(error_metric.owner),
        provider(error_metric.sources[0].provider),
        id(error_metric.id),
        MetricLabels::default(),
        Duration::ZERO,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        SeriesValue::Counter {
            current: ProjectedValue::Fresh {
                value: 3,
                observed_at: Duration::from_secs(1),
            },
            interval: Some(CounterContinuity::Continuous {
                delta: 3,
                elapsed: Duration::from_secs(1),
            }),
            since_baseline: Some(CounterSpan::new(3, Duration::from_secs(1)).unwrap()),
        },
        HistoryCoverage::empty(),
    )
    .unwrap();
    let link_metric = descriptor("linux.nic.link_state").unwrap();
    let link = |series_id, interface: &str, ifindex: &str, state: &str| {
        SeriesSnapshot::new(
            SeriesId::new(series_id).unwrap(),
            provider(link_metric.owner),
            provider("linux.sysfs.net.nic"),
            id(link_metric.id),
            labels(&[
                (MetricLabel::Interface, interface),
                (MetricLabel::Ifindex, ifindex),
            ]),
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
    };
    let snapshot = MonitorSnapshot::new(
        1,
        1,
        0,
        Duration::from_secs(1),
        None,
        vec![
            fresh_provider_snapshot(error_metric.sources[0].provider, Duration::from_secs(1)),
            fresh_provider_snapshot("linux.sysfs.net.nic", Duration::from_secs(1)),
        ],
        vec![
            error,
            link(2, "eth0", "2", "up"),
            link(3, "eth1", "3", "down"),
        ],
        EngineTelemetry::default(),
    )
    .unwrap();

    let dashboard = build_dashboard(&snapshot);
    assert_eq!(dashboard.blocks().len(), 15);
    assert_eq!(
        dashboard
            .blocks()
            .iter()
            .take(5)
            .map(|block| block.key().kind())
            .collect::<Vec<_>>(),
        vec![
            BlockKind::PacketStage(PacketStage::SocketApplication),
            BlockKind::PacketStage(PacketStage::Transport),
            BlockKind::PacketStage(PacketStage::NetworkRoute),
            BlockKind::PacketStage(PacketStage::NetfilterConntrack),
            BlockKind::ExecutionContext(ExecutionContext::Softirq),
        ]
    );
    for (offset, interface, ifindex) in [(5, "eth0", 2), (10, "eth1", 3)] {
        assert!(dashboard.blocks()[offset..offset + 5].iter().all(|block| {
            matches!(
                block.key().scope(),
                BlockScope::Interface(identity)
                    if identity.name() == interface && identity.ifindex().get() == ifindex
            )
        }));
    }

    let transport = assess_dashboard_block(&snapshot, &dashboard.blocks()[1]);
    assert_eq!(transport.health(), NetworkHealth::Warn);
    assert_eq!(
        transport.causes()[0].metric().as_str(),
        "linux.socket.tcp.established_resets"
    );
    let eth0_phy = assess_dashboard_block(&snapshot, &dashboard.blocks()[8]);
    assert_eq!(eth0_phy.health(), NetworkHealth::Unknown);
    assert_eq!(eth0_phy.coverage(), EvidenceCoverage::Partial);
    let eth1_phy = assess_dashboard_block(&snapshot, &dashboard.blocks()[13]);
    assert_eq!(eth1_phy.health(), NetworkHealth::Warn);
    assert_eq!(eth1_phy.coverage(), EvidenceCoverage::Partial);
    assert_eq!(
        eth1_phy.causes()[0].metric().as_str(),
        "linux.nic.link_state"
    );
    assert!(eth1_phy.causes()[0].threshold().is_some());
}

#[test]
fn sampling_interval_has_closed_boundaries_and_precision() {
    assert_eq!(
        SamplingInterval::new(Duration::from_millis(249)),
        Err(MonitorValidationError::IntervalOutOfRange)
    );
    assert!(SamplingInterval::new(Duration::from_millis(250)).is_ok());
    assert!(SamplingInterval::new(Duration::from_secs(60)).is_ok());
    assert_eq!(
        SamplingInterval::new(Duration::from_millis(60_001)),
        Err(MonitorValidationError::IntervalOutOfRange)
    );
    assert_eq!(
        SamplingInterval::new(Duration::from_micros(250_001)),
        Err(MonitorValidationError::IntervalPrecision)
    );
    assert_eq!("1s".parse::<SamplingInterval>().unwrap().as_millis(), 1_000);
    assert_eq!(
        "forever".parse::<SamplingInterval>(),
        Err(MonitorValidationError::InvalidInterval)
    );
}

fn valid_plan_json() -> Value {
    json!({
        "intervalMs": 1000,
        "initialSection": "overview",
        "enabledSections": [
            "socket", "netfilter", "tc", "netdevice", "nic", "softirq", "hardirq"
        ],
        "interfaceAnchor": null
    })
}

#[test]
fn monitor_plan_rejects_batch_policy_and_bpf_fields_at_the_boundary() {
    for (field, value) in [
        ("durationMs", json!(10_000)),
        ("flow", json!({})),
        ("pid", json!(42)),
        ("cgroup", json!("/system.slice")),
        ("failOn", json!("warning")),
        ("strictCoverage", json!(true)),
        ("bpfMode", json!("automatic")),
    ] {
        let mut plan = valid_plan_json();
        plan.as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        let error = serde_json::from_value::<MonitorPlan>(plan)
            .expect_err("batch-only field must be rejected");
        assert!(
            error.to_string().contains("unknown field"),
            "{field}: {error}"
        );
    }
}

#[test]
fn monitor_plan_validates_section_sets_and_view_anchor() {
    let plan: MonitorPlan = serde_json::from_value(valid_plan_json()).unwrap();
    assert_eq!(plan.interval().as_millis(), 1_000);
    assert_eq!(plan.enabled_sections().len(), 7);

    let mut duplicate = valid_plan_json();
    duplicate["enabledSections"] = json!(["socket", "socket"]);
    assert!(serde_json::from_value::<MonitorPlan>(duplicate)
        .unwrap_err()
        .to_string()
        .contains("unique"));

    assert_eq!(
        MonitorPlan::from_parts(
            SamplingInterval::default(),
            MonitorSection::Nic,
            [CollectionSection::Socket],
            None,
        ),
        Err(MonitorValidationError::InitialSectionDisabled)
    );
    assert_eq!(
        MonitorPlan::from_parts(
            SamplingInterval::default(),
            MonitorSection::Overview,
            [],
            None,
        ),
        Err(MonitorValidationError::EmptyEnabledSections)
    );
    assert_eq!(
        InterfaceViewAnchor::named("../eth0"),
        Err(MonitorValidationError::InvalidInterfaceAnchor)
    );
    for name in ["eth\u{1b}[2J", "eth\u{7}0", "eth\u{7f}0"] {
        assert_eq!(
            InterfaceViewAnchor::named(name),
            Err(MonitorValidationError::InvalidInterfaceAnchor),
            "control characters must not reach the terminal: {name:?}"
        );
    }
    assert!(InterfaceViewAnchor::named("veth.100-1").is_ok());
    assert!(InterfaceViewAnchor::indexed(2).is_ok());
    assert_eq!(
        InterfaceViewAnchor::indexed(0),
        Err(MonitorValidationError::InvalidInterfaceAnchor)
    );
}

#[test]
fn monitor_plan_validates_and_round_trips_multiple_interface_names() {
    let anchor =
        InterfaceViewAnchor::named_many(["eth1".to_owned(), "eth0".to_owned(), "eth1".to_owned()])
            .unwrap();
    let mut wire = valid_plan_json();
    wire["interfaceAnchor"] = json!({"kind": "names", "names": ["eth0", "eth1"]});
    let plan: MonitorPlan = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(plan.interface_anchor(), Some(&anchor));
    assert_eq!(
        serde_json::to_value(plan).unwrap()["interfaceAnchor"],
        wire["interfaceAnchor"]
    );
    for names in [
        json!([]),
        json!([""]),
        json!(["eth0", "../eth1"]),
        json!(["eth0", "eth\u{1b}[2J"]),
    ] {
        wire["interfaceAnchor"] = json!({"kind": "names", "names": names});
        assert!(serde_json::from_value::<MonitorPlan>(wire.clone()).is_err());
    }
    assert_eq!(
        InterfaceViewAnchor::named_many(["eth0".to_owned(), "eth0".to_owned()]).unwrap(),
        InterfaceViewAnchor::named("eth0").unwrap()
    );
}

#[test]
fn catalog_is_closed_unique_and_complete_for_seven_collection_sections() {
    validate_catalog().unwrap();
    assert!(!metric_catalog().is_empty());

    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for metric in metric_catalog() {
        assert!(ids.insert(metric.id), "duplicate metric {}", metric.id);
        assert!(CollectionSection::ALL.contains(&metric.primary_section));
        assert!(!metric.sources.is_empty());
        for source in metric.sources {
            assert!(
                sources.insert((source.provider, source.raw_metric)),
                "duplicate raw owner {}:{}",
                source.provider,
                source.raw_metric
            );
        }
    }
    for section in CollectionSection::ALL {
        assert!(minimum_descriptors(section).next().is_some(), "{section:?}");
    }
}

#[test]
fn link_statistics_have_one_canonical_mapping_per_primary_source() {
    const MAPPINGS: &[(&str, &str, CollectionSection)] = &[
        (
            "rx_packets",
            "linux.netdevice.rx_packets",
            CollectionSection::Netdevice,
        ),
        (
            "tx_packets",
            "linux.netdevice.tx_packets",
            CollectionSection::Netdevice,
        ),
        (
            "rx_bytes",
            "linux.netdevice.rx_bytes",
            CollectionSection::Netdevice,
        ),
        (
            "tx_bytes",
            "linux.netdevice.tx_bytes",
            CollectionSection::Netdevice,
        ),
        (
            "rx_errors",
            "linux.netdevice.rx_errors",
            CollectionSection::Netdevice,
        ),
        (
            "tx_errors",
            "linux.netdevice.tx_errors",
            CollectionSection::Netdevice,
        ),
        (
            "rx_dropped",
            "linux.netdevice.rx_dropped",
            CollectionSection::Netdevice,
        ),
        (
            "tx_dropped",
            "linux.netdevice.tx_dropped",
            CollectionSection::Netdevice,
        ),
        (
            "multicast",
            "linux.netdevice.multicast",
            CollectionSection::Netdevice,
        ),
        ("collisions", "linux.nic.collisions", CollectionSection::Nic),
        (
            "rx_length_errors",
            "linux.nic.rx_length_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_over_errors",
            "linux.nic.rx_over_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_crc_errors",
            "linux.nic.rx_crc_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_frame_errors",
            "linux.nic.rx_frame_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_fifo_errors",
            "linux.nic.rx_fifo_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_missed_errors",
            "linux.nic.rx_missed_errors",
            CollectionSection::Nic,
        ),
        (
            "tx_aborted_errors",
            "linux.nic.tx_aborted_errors",
            CollectionSection::Nic,
        ),
        (
            "tx_carrier_errors",
            "linux.nic.tx_carrier_errors",
            CollectionSection::Nic,
        ),
        (
            "tx_fifo_errors",
            "linux.nic.tx_fifo_errors",
            CollectionSection::Nic,
        ),
        (
            "tx_heartbeat_errors",
            "linux.nic.tx_heartbeat_errors",
            CollectionSection::Nic,
        ),
        (
            "tx_window_errors",
            "linux.nic.tx_window_errors",
            CollectionSection::Nic,
        ),
        (
            "rx_compressed",
            "linux.netdevice.rx_compressed",
            CollectionSection::Netdevice,
        ),
        (
            "tx_compressed",
            "linux.netdevice.tx_compressed",
            CollectionSection::Netdevice,
        ),
        (
            "rx_nohandler",
            "linux.netdevice.rx_nohandler",
            CollectionSection::Netdevice,
        ),
        (
            "rx_otherhost_dropped",
            "linux.netdevice.rx_otherhost_dropped",
            CollectionSection::Netdevice,
        ),
        (
            "carrier_changes",
            "linux.nic.carrier_changes",
            CollectionSection::Nic,
        ),
    ];

    for (raw_metric, canonical_id, section) in MAPPINGS {
        for provider in ["linux.rtnetlink.link_stats", "linux.sysfs.net.statistics"] {
            let matches = metric_catalog()
                .iter()
                .filter(|descriptor| {
                    descriptor.sources.iter().any(|source| {
                        source.provider == provider && source.raw_metric == *raw_metric
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "{provider}:{raw_metric}");
            assert_eq!(matches[0].id, *canonical_id, "{provider}:{raw_metric}");
            assert_eq!(
                matches[0].primary_section, *section,
                "{provider}:{raw_metric}"
            );
        }
    }

    for (raw_metric, canonical_id) in [
        ("rx_compressed", "linux.netdevice.rx_compressed"),
        ("tx_compressed", "linux.netdevice.tx_compressed"),
    ] {
        let matches = metric_catalog()
            .iter()
            .filter(|descriptor| {
                descriptor.sources.iter().any(|source| {
                    source.provider == "linux.proc.net.dev" && source.raw_metric == raw_metric
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "linux.proc.net.dev:{raw_metric}");
        assert_eq!(matches[0].id, canonical_id);
    }

    for canonical_id in [
        "linux.netdevice.rx_dropped",
        "linux.nic.rx_frame_errors",
        "linux.nic.tx_carrier_errors",
    ] {
        assert_eq!(
            descriptor(canonical_id)
                .unwrap()
                .source_priority(&provider("linux.proc.net.dev")),
            None,
            "{canonical_id} must not use a folded proc net/dev counter"
        );
    }
}

#[test]
fn catalog_preserves_host_scope_and_non_drop_pressure_semantics() {
    for metric in [
        "linux.socket.tcp.orphaned",
        "linux.socket.tcp.allocated",
        "linux.socket.tcp.memory_pages",
        "linux.socket.udp.memory_pages",
    ] {
        assert_eq!(
            descriptor(metric).unwrap().scope,
            MetricScope::Host,
            "{metric}"
        );
    }
    assert_eq!(
        descriptor("linux.netfilter.conntrack.invalid")
            .unwrap()
            .domain,
        AggregationDomain::IpPacket
    );
    assert_eq!(
        descriptor("linux.netfilter.conntrack.early_drop")
            .unwrap()
            .display,
        DisplayMeaning::Pressure
    );
    assert_eq!(
        descriptor("linux.softirq.softnet.time_squeeze")
            .unwrap()
            .domain,
        AggregationDomain::PollCycle
    );
    let received_rps = descriptor("linux.softirq.softnet.received_rps").unwrap();
    assert_eq!(received_rps.kind, MetricKind::Counter);
    assert_eq!(received_rps.unit, MetricUnit::Occurrences);
    assert_eq!(received_rps.domain, AggregationDomain::Interrupt);
    assert_eq!(received_rps.title, "RPS softirq/IPI triggers");
    assert_eq!(
        received_rps.description,
        "RPS softirq/IPI trigger occurrences received by each CPU; this is not a packet count."
    );
    for metric in [
        "linux.softirq.softnet.backlog_len",
        "linux.softirq.softnet.input_qlen",
        "linux.softirq.softnet.process_qlen",
    ] {
        let descriptor = descriptor(metric).unwrap();
        assert_eq!(descriptor.kind, MetricKind::Gauge);
        assert_eq!(descriptor.unit, MetricUnit::Occurrences);
        assert_eq!(descriptor.scope, MetricScope::Cpu);
        assert_eq!(descriptor.domain, AggregationDomain::QueueEntry);
    }
    for metric in [
        "linux.softirq.config.netdev_budget",
        "linux.softirq.config.netdev_budget_usecs",
        "linux.softirq.config.dev_weight",
        "linux.softirq.config.netdev_max_backlog",
    ] {
        let descriptor = descriptor(metric).unwrap();
        assert_eq!(descriptor.kind, MetricKind::Gauge);
        assert_eq!(descriptor.scope, MetricScope::Host);
        assert_eq!(descriptor.display, DisplayMeaning::InformationOnly);
        assert_eq!(descriptor.aggregation, AggregationPolicy::None);
        assert_eq!(descriptor.sources[0].provider, "linux.proc.sys.net.core");
    }
    assert_eq!(
        descriptor("linux.softirq.config.netdev_budget_usecs")
            .unwrap()
            .unit,
        MetricUnit::SourceUnits
    );
    assert!(descriptor("linux.nic.tx_fifo_errors").is_some());
}

#[test]
fn fallback_provenance_does_not_create_a_second_canonical_series() {
    let metric = descriptor("linux.netdevice.rx_packets").unwrap();
    assert_eq!(
        metric.source_priority(&provider("linux.rtnetlink.link_stats")),
        Some(0)
    );
    assert_eq!(
        metric.source_priority(&provider("linux.sysfs.net.statistics")),
        Some(1)
    );
    assert_eq!(
        metric.source_priority(&provider("linux.proc.net.dev")),
        Some(2)
    );

    let make_row = |series_id, source: &str, value| {
        SeriesSnapshot::new(
            SeriesId::new(series_id).unwrap(),
            provider(OWNER_NETDEVICE),
            provider(source),
            id("linux.netdevice.rx_packets"),
            labels(&[(MetricLabel::Interface, "eth0")]),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value,
                    observed_at: Duration::from_secs(1),
                },
                interval: Some(CounterContinuity::FirstSample),
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    };
    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(1),
            None,
            vec![
                fresh_provider_snapshot("linux.rtnetlink.link_stats", Duration::from_secs(1),),
                fresh_provider_snapshot("linux.sysfs.net.statistics", Duration::from_secs(1),),
            ],
            vec![
                make_row(1, "linux.rtnetlink.link_stats", 10),
                make_row(2, "linux.sysfs.net.statistics", 10),
            ],
            EngineTelemetry::default(),
        ),
        Err(MonitorValidationError::DuplicateSeries)
    );
}

#[test]
fn raw_private_nic_statistics_are_information_only_source_units() {
    let raw = descriptor(RAW_PRIVATE_NIC_METRIC_ID).unwrap();
    assert_eq!(raw.primary_section, CollectionSection::Nic);
    assert_eq!(raw.kind, MetricKind::Gauge);
    assert_eq!(raw.unit, MetricUnit::SourceUnits);
    assert_eq!(raw.scope, MetricScope::Source);
    assert_eq!(raw.display, DisplayMeaning::InformationOnly);
    assert_eq!(raw.aggregation, AggregationPolicy::None);
    assert_eq!(
        raw.required_labels,
        &[
            MetricLabel::Interface,
            MetricLabel::Ifindex,
            MetricLabel::Statistic,
        ]
    );
    assert!(!raw.minimum);
    assert!(!raw.display.higher_is_worse());

    let incomplete = SampleReading::observed(
        id(RAW_PRIVATE_NIC_METRIC_ID),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Statistic, "vendor_counter"),
        ]),
        MetricReading::Gauge(10),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.ethtool.netlink"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![incomplete],
        ),
        Err(MonitorValidationError::MetricLabelsMismatch)
    );

    let raw_labels = labels(&[
        (MetricLabel::Interface, "eth0"),
        (MetricLabel::Ifindex, "2"),
        (MetricLabel::Statistic, "vendor_counter"),
    ]);
    assert_eq!(
        SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            provider(OWNER_NIC),
            provider("linux.ethtool.netlink"),
            id(RAW_PRIVATE_NIC_METRIC_ID),
            raw_labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value: 10,
                    observed_at: Duration::from_secs(1),
                },
                interval: Some(GaugeChange::new(1, Duration::from_secs(1)).unwrap()),
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        ),
        Err(MonitorValidationError::InvalidSeriesProjection)
    );
}

#[test]
fn ethtool_settings_are_bounded_opaque_state() {
    let setting = descriptor(RAW_NIC_SETTING_METRIC_ID).unwrap();
    assert_eq!(setting.primary_section, CollectionSection::Nic);
    assert_eq!(setting.kind, MetricKind::State);
    assert_eq!(setting.unit, MetricUnit::State);
    assert_eq!(setting.scope, MetricScope::Source);
    assert_eq!(setting.display, DisplayMeaning::InformationOnly);
    assert_eq!(
        setting.required_labels,
        &[
            MetricLabel::Interface,
            MetricLabel::Ifindex,
            MetricLabel::Statistic,
        ]
    );
    assert!(!setting.minimum);

    let incomplete = SampleReading::observed(
        id(RAW_NIC_SETTING_METRIC_ID),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Statistic, "Speed"),
        ]),
        MetricReading::State(StateValue::new("10000Mb/s").unwrap()),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.ethtool.link_text"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![incomplete],
        ),
        Err(MonitorValidationError::MetricLabelsMismatch)
    );

    let reading = SampleReading::observed(
        id(RAW_NIC_SETTING_METRIC_ID),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Ifindex, "2"),
            (MetricLabel::Statistic, "Speed"),
        ]),
        MetricReading::State(StateValue::new("10000Mb/s").unwrap()),
    );
    ProviderSample::new(
        provider("linux.ethtool.link_text"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![reading],
    )
    .unwrap();
}

#[test]
fn output_label_vocabulary_has_no_raw_irq_or_queue_identity() {
    for label in MetricLabel::ALL {
        assert_ne!(label.as_str(), "irq");
        assert_ne!(label.as_str(), "irq_number");
        assert_ne!(label.as_str(), "queue");
        assert_ne!(label.as_str(), "queue_id");
    }
    for metric in metric_catalog() {
        assert!(metric
            .allowed_labels
            .iter()
            .all(|label| !matches!(label.as_str(), "irq" | "irq_number" | "queue" | "queue_id")));
    }
}

#[test]
fn labels_ids_and_diagnostics_are_bounded_and_printable() {
    let valid_id = format!("a.{}", "a".repeat(126));
    assert_eq!(valid_id.len(), 128);
    assert!(ProviderId::new(valid_id).is_ok());
    assert_eq!(
        ProviderId::new(format!("a.{}", "a".repeat(127))),
        Err(MonitorValidationError::InvalidIdentifier)
    );

    for (length, valid) in [
        (0, false),
        (1, true),
        (MAX_LABEL_VALUE_BYTES, true),
        (129, false),
    ] {
        let result = MetricLabels::new([(MetricLabel::Statistic, "x".repeat(length))]);
        assert_eq!(result.is_ok(), valid, "label length {length}");
    }
    assert_eq!(
        MetricLabels::new([(MetricLabel::Statistic, "line\nbreak".to_owned())]),
        Err(MonitorValidationError::InvalidLabelValue {
            label: MetricLabel::Statistic
        })
    );
    assert_eq!(
        MetricLabels::new([(MetricLabel::Interface, "eth\u{1b}[2J".to_owned())]),
        Err(MonitorValidationError::InvalidLabelValue {
            label: MetricLabel::Interface
        })
    );
    assert_eq!(
        MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Cpu, "0".to_owned()),
            (MetricLabel::Protocol, "tcp".to_owned()),
            (MetricLabel::IpVersion, "4".to_owned()),
            (MetricLabel::Direction, "rx".to_owned()),
            (MetricLabel::Family, "inet".to_owned()),
            (MetricLabel::Table, "filter".to_owned()),
            (MetricLabel::Chain, "input".to_owned()),
        ]),
        Err(MonitorValidationError::TooManyLabels)
    );

    assert!(MonitorError::new(MonitorErrorCode::Parse, "x".repeat(MAX_DIAGNOSTIC_BYTES)).is_ok());
    assert_eq!(
        MonitorError::new(
            MonitorErrorCode::Parse,
            "x".repeat(MAX_DIAGNOSTIC_BYTES + 1)
        ),
        Err(MonitorValidationError::InvalidDiagnostic)
    );
    assert_eq!(
        MonitorError::new(MonitorErrorCode::Internal, "panic\npayload"),
        Err(MonitorValidationError::InvalidDiagnostic)
    );
}

#[test]
fn provider_samples_distinguish_zero_unavailable_and_health_failures() {
    let metric = id("linux.socket.tcp.segments_in");
    let zero = SampleReading::observed(
        metric.clone(),
        MetricLabels::default(),
        MetricReading::Counter {
            value: 0,
            bits: None,
        },
    );
    let missing = SampleReading::unavailable(
        id("linux.socket.tcp.segments_out"),
        MetricLabels::default(),
        UnavailableReason::Missing,
    );
    let sample = ProviderSample::new(
        provider("linux.proc.net.snmp"),
        Duration::from_secs(1),
        Duration::from_millis(2),
        ProviderHealth::Fresh,
        vec![missing, zero],
    )
    .unwrap();
    assert_eq!(sample.readings().len(), 2);
    assert!(sample.readings().iter().any(|reading| matches!(
        reading.outcome(),
        ReadingOutcome::Observed(MetricReading::Counter {
            value: 0,
            bits: None
        })
    )));
    assert!(sample.readings().iter().any(|reading| matches!(
        reading.outcome(),
        ReadingOutcome::Unavailable(UnavailableReason::Missing)
    )));

    let permission =
        MonitorError::new(MonitorErrorCode::PermissionDenied, "access denied").unwrap();
    let denied = ProviderSample::new(
        provider("linux.proc.net.snmp"),
        Duration::from_secs(1),
        Duration::from_millis(2),
        ProviderHealth::PermissionDenied { reason: permission },
        vec![],
    )
    .unwrap();
    assert_eq!(denied.health().as_str(), "permission_denied");

    let warning = MonitorError::new(MonitorErrorCode::Timeout, "one interface timed out").unwrap();
    let partial = ProviderSample::new(
        provider("linux.proc.net.snmp"),
        Duration::from_secs(1),
        Duration::from_millis(2),
        ProviderHealth::Partial { warning },
        vec![SampleReading::observed(
            metric,
            MetricLabels::default(),
            MetricReading::Counter {
                value: 1,
                bits: None,
            },
        )],
    )
    .unwrap();
    assert_eq!(partial.health().as_str(), "partial");
    assert!(partial.health().allows_readings());
    assert!(!partial.health().is_fresh());
    assert_eq!(partial.readings().len(), 1);

    let link = SampleReading::observed(
        id("linux.netdevice.rx_packets"),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Ifindex, "2"),
        ]),
        MetricReading::Counter {
            value: u64::from(u32::MAX),
            bits: Some(CounterBits::Bits32),
        },
    );
    let sample = ProviderSample::new(
        provider("linux.rtnetlink.link_stats"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![link],
    )
    .unwrap();
    assert!(matches!(
        sample.readings()[0].outcome(),
        ReadingOutcome::Observed(MetricReading::Counter {
            bits: Some(CounterBits::Bits32),
            ..
        })
    ));
}

#[test]
fn non_fresh_samples_cannot_smuggle_values_or_mismatched_health_codes() {
    let reading = SampleReading::observed(
        id("linux.socket.tcp.segments_in"),
        MetricLabels::default(),
        MetricReading::Counter {
            value: 1,
            bits: None,
        },
    );
    let cause = MonitorError::new(MonitorErrorCode::Timeout, "collector timeout").unwrap();
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.net.snmp"),
            Duration::from_secs(2),
            Duration::from_millis(2),
            ProviderHealth::Stale {
                last_success_at: Duration::from_secs(1),
                age: Duration::from_secs(1),
                cause,
            },
            vec![reading],
        ),
        Err(MonitorValidationError::NonFreshProviderHasReadings)
    );

    let wrong = MonitorError::new(MonitorErrorCode::Parse, "not unsupported").unwrap();
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.net.snmp"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Unsupported { reason: wrong },
            vec![],
        ),
        Err(MonitorValidationError::InvalidProviderHealth)
    );
}

#[test]
fn sample_catalog_validation_rejects_wrong_source_kind_and_labels() {
    let metric = id("linux.socket.tcp.segments_in");
    let wrong_kind = SampleReading::observed(
        metric.clone(),
        MetricLabels::default(),
        MetricReading::Gauge(1),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.net.snmp"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![wrong_kind],
        ),
        Err(MonitorValidationError::MetricKindMismatch)
    );

    let reading = SampleReading::observed(
        metric.clone(),
        MetricLabels::default(),
        MetricReading::Counter {
            value: 1,
            bits: None,
        },
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.softirqs"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![reading],
        ),
        Err(MonitorValidationError::MetricSourceMismatch)
    );

    let reading = SampleReading::observed(
        metric,
        labels(&[(MetricLabel::Cpu, "0")]),
        MetricReading::Counter {
            value: 1,
            bits: None,
        },
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.net.snmp"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![reading],
        ),
        Err(MonitorValidationError::MetricLabelsMismatch)
    );
}

#[test]
fn tc_rows_require_opaque_row_and_execution_identity() {
    let incomplete = SampleReading::observed(
        id("linux.tc.packets"),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Ifindex, "2"),
            (MetricLabel::Direction, "egress"),
            (MetricLabel::ObjectKind, "qdisc"),
        ]),
        MetricReading::Counter {
            value: 1,
            bits: None,
        },
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.rtnetlink.tc"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![incomplete],
        ),
        Err(MonitorValidationError::MetricLabelsMismatch)
    );

    let complete = SampleReading::observed(
        id("linux.tc.packets"),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Ifindex, "2"),
            (MetricLabel::Direction, "egress"),
            (MetricLabel::ObjectKind, "qdisc"),
            (MetricLabel::QdiscKind, "fq_codel"),
            (MetricLabel::RowId, "1"),
            (MetricLabel::Execution, "software"),
        ]),
        MetricReading::Counter {
            value: 1,
            bits: None,
        },
    );
    ProviderSample::new(
        provider("linux.rtnetlink.tc"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![complete],
    )
    .unwrap();
}

#[test]
fn state_values_follow_descriptor_allowlists() {
    let incomplete_kind = SampleReading::observed(
        id("linux.nic.interface_kind"),
        labels(&[(MetricLabel::Interface, "eth0")]),
        MetricReading::State(StateValue::new("physical").unwrap()),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.sysfs.net.nic"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![incomplete_kind],
        ),
        Err(MonitorValidationError::MetricLabelsMismatch)
    );

    let kind_labels = labels(&[
        (MetricLabel::Interface, "eth0"),
        (MetricLabel::Ifindex, "2"),
    ]);
    let physical = SampleReading::observed(
        id("linux.nic.interface_kind"),
        kind_labels.clone(),
        MetricReading::State(StateValue::new("physical").unwrap()),
    );
    ProviderSample::new(
        provider("linux.sysfs.net.nic"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![physical],
    )
    .unwrap();

    let invented_kind = SampleReading::observed(
        id("linux.nic.interface_kind"),
        kind_labels,
        MetricReading::State(StateValue::new("container").unwrap()),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.sysfs.net.nic"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![invented_kind],
        ),
        Err(MonitorValidationError::InvalidStateValue)
    );

    let link_labels = labels(&[(MetricLabel::Interface, "eth0")]);
    let up = SampleReading::observed(
        id("linux.nic.link_state"),
        link_labels.clone(),
        MetricReading::State(StateValue::new("up").unwrap()),
    );
    ProviderSample::new(
        provider("linux.ethtool.netlink"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![up],
    )
    .unwrap();

    let invented = SampleReading::observed(
        id("linux.nic.link_state"),
        link_labels,
        MetricReading::State(StateValue::new("carrier_ok").unwrap()),
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.ethtool.netlink"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![invented],
        ),
        Err(MonitorValidationError::InvalidStateValue)
    );

    let affinity = SampleReading::observed(
        id("linux.hardirq.affinity"),
        labels(&[
            (MetricLabel::Interface, "eth0"),
            (MetricLabel::Ifindex, "2"),
        ]),
        MetricReading::State(StateValue::new("0-3,8").unwrap()),
    );
    ProviderSample::new(
        provider("linux.proc.interrupts"),
        Duration::from_secs(1),
        Duration::ZERO,
        ProviderHealth::Fresh,
        vec![affinity],
    )
    .unwrap();
}

#[test]
fn aggregation_requires_same_metric_and_only_declared_reducible_labels() {
    let net_rx = id("linux.softirq.net_rx");
    let cpu0 = labels(&[(MetricLabel::Cpu, "0")]);
    let cpu1 = labels(&[(MetricLabel::Cpu, "1")]);
    assert!(aggregation_compatible(
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu0,
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu1,
        MetricScope::Host
    ));
    assert!(!aggregation_compatible(
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu0,
        &provider("linux.proc.net.softnet_stat"),
        &net_rx,
        &cpu1,
        MetricScope::Host
    ));
    assert!(!aggregation_compatible(
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu0,
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu0,
        MetricScope::Host
    ));
    assert!(!aggregation_compatible(
        &provider("linux.proc.softirqs"),
        &net_rx,
        &cpu0,
        &provider("linux.proc.softirqs"),
        &id("linux.softirq.net_tx"),
        &cpu1,
        MetricScope::Host
    ));

    let irq = id("linux.hardirq.network_interrupts");
    let eth0 = labels(&[
        (MetricLabel::Interface, "eth0"),
        (MetricLabel::Ifindex, "2"),
        (MetricLabel::Cpu, "0"),
    ]);
    let eth1 = labels(&[
        (MetricLabel::Interface, "eth1"),
        (MetricLabel::Ifindex, "3"),
        (MetricLabel::Cpu, "1"),
    ]);
    assert!(!aggregation_compatible(
        &provider("linux.proc.interrupts"),
        &irq,
        &eth0,
        &provider("linux.proc.interrupts"),
        &irq,
        &eth1,
        MetricScope::Host
    ));

    let rx_packets = id("linux.netdevice.rx_packets");
    let if0 = labels(&[(MetricLabel::Interface, "eth0")]);
    let if1 = labels(&[(MetricLabel::Interface, "eth1")]);
    assert!(!aggregation_compatible(
        &provider("linux.rtnetlink.link_stats"),
        &rx_packets,
        &if0,
        &provider("linux.rtnetlink.link_stats"),
        &rx_packets,
        &if1,
        MetricScope::Host
    ));
}

#[test]
fn snapshot_keeps_interval_baseline_history_and_provider_health_immutable() {
    let elapsed = Duration::from_secs(2);
    let history =
        HistoryCoverage::new(Duration::ZERO, elapsed, Duration::from_secs(1), 3, 0, false).unwrap();
    let row = counter_series(
        1,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        Duration::ZERO,
        ProjectedValue::Fresh {
            value: 150,
            observed_at: elapsed,
        },
        Some(CounterContinuity::Continuous {
            delta: 10,
            elapsed: Duration::from_secs(1),
        }),
        Some(CounterSpan::new(50, elapsed).unwrap()),
        history,
    );
    let telemetry = EngineTelemetry {
        history_buckets: 3,
        history_bytes: 512,
        ..EngineTelemetry::default()
    };
    let snapshot = MonitorSnapshot::new(
        1,
        1,
        1_700_000_000_000,
        elapsed,
        Some("net:[4026531840]".to_owned()),
        vec![fresh_provider_snapshot("linux.proc.net.snmp", elapsed)],
        vec![row],
        telemetry,
    )
    .unwrap();

    assert_eq!(snapshot.generation(), 1);
    assert_eq!(snapshot.sequence(), 1);
    assert_eq!(snapshot.series().len(), 1);
    assert_eq!(snapshot.providers().len(), 1);
    assert_eq!(snapshot.network_namespace(), Some("net:[4026531840]"));
    assert_eq!(
        snapshot.series()[0].baseline_origin(),
        BaselineOrigin::SessionStart
    );
    assert_eq!(snapshot.series()[0].history().bucket_count(), 3);
    assert_eq!(snapshot.clone(), snapshot);
}

#[test]
fn stale_gap_and_reset_do_not_emit_continuous_since_start_values() {
    let elapsed = Duration::from_secs(3);
    let stale_with_delta = counter_series(
        1,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        Duration::ZERO,
        ProjectedValue::Stale {
            last: 20,
            observed_at: Duration::from_secs(2),
            age: Duration::from_secs(1),
            cause: MonitorErrorCode::Timeout,
        },
        Some(CounterContinuity::Continuous {
            delta: 2,
            elapsed: Duration::from_secs(1),
        }),
        Some(CounterSpan::new(20, Duration::from_secs(2)).unwrap()),
        HistoryCoverage::empty(),
    );
    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            elapsed,
            None,
            vec![fresh_provider_snapshot("linux.proc.net.snmp", elapsed)],
            vec![stale_with_delta],
            EngineTelemetry::default(),
        ),
        Err(MonitorValidationError::InvalidSeriesProjection)
    );

    let reset_with_old_origin = counter_series(
        2,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        Duration::ZERO,
        ProjectedValue::Fresh {
            value: 1,
            observed_at: elapsed,
        },
        Some(CounterContinuity::Reset),
        None,
        HistoryCoverage::empty(),
    );
    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            elapsed,
            None,
            vec![fresh_provider_snapshot("linux.proc.net.snmp", elapsed)],
            vec![reset_with_old_origin],
            EngineTelemetry::default(),
        ),
        Err(MonitorValidationError::InvalidSeriesProjection)
    );
}

#[test]
fn late_and_recovered_series_have_explicit_non_session_baselines() {
    let elapsed = Duration::from_secs(4);
    let late = counter_series(
        1,
        BaselineOrigin::FirstObserved,
        Duration::from_secs(2),
        Duration::from_secs(2),
        ProjectedValue::Fresh {
            value: 10,
            observed_at: elapsed,
        },
        Some(CounterContinuity::Continuous {
            delta: 4,
            elapsed: Duration::from_secs(1),
        }),
        Some(CounterSpan::new(6, Duration::from_secs(2)).unwrap()),
        HistoryCoverage::new(
            Duration::from_secs(2),
            elapsed,
            Duration::from_secs(1),
            3,
            1,
            false,
        )
        .unwrap(),
    );
    assert_eq!(late.first_seen(), Duration::from_secs(2));
    assert_eq!(late.baseline_origin(), BaselineOrigin::FirstObserved);

    let recovered = counter_series(
        2,
        BaselineOrigin::RecoveredAfterGap,
        Duration::ZERO,
        Duration::from_secs(3),
        ProjectedValue::Fresh {
            value: 12,
            observed_at: elapsed,
        },
        Some(CounterContinuity::RecoveredAfterGap),
        None,
        HistoryCoverage::empty(),
    );
    assert_eq!(
        recovered.baseline_origin(),
        BaselineOrigin::RecoveredAfterGap
    );
}

#[test]
fn stale_gauges_cannot_add_interval_or_average_samples() {
    let value = SeriesValue::Gauge {
        current: ProjectedValue::Stale {
            last: 50,
            observed_at: Duration::from_secs(1),
            age: Duration::from_secs(1),
            cause: MonitorErrorCode::Timeout,
        },
        interval: Some(GaugeChange::new(5, Duration::from_secs(1)).unwrap()),
        since_baseline: Some(GaugeSummary::new(40, 50, 90, 2, Duration::from_secs(1)).unwrap()),
    };
    let row = SeriesSnapshot::new(
        SeriesId::new(1).unwrap(),
        provider(OWNER_SOCKET),
        provider("linux.proc.net.sockstat"),
        id("linux.socket.used"),
        MetricLabels::default(),
        Duration::ZERO,
        BaselineOrigin::SessionStart,
        Duration::ZERO,
        value,
        HistoryCoverage::empty(),
    )
    .unwrap();
    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![fresh_provider_snapshot(
                "linux.proc.net.sockstat",
                Duration::from_secs(2)
            )],
            vec![row],
            EngineTelemetry::default(),
        ),
        Err(MonitorValidationError::InvalidSeriesProjection)
    );
}

#[test]
fn cardinality_and_history_budgets_are_explicit() {
    assert_eq!(MAX_PROVIDERS, 64);
    assert_eq!(MAX_READINGS_PER_PROVIDER, 4_096);
    assert_eq!(MAX_ADMITTED_SERIES, 16_384);
    assert_eq!(MAX_HISTORY_BUCKETS, 262_144);
    assert_eq!(MAX_HISTORY_BYTES, 64 * 1024 * 1024);

    let reading = SampleReading::unavailable(
        id("linux.socket.tcp.segments_in"),
        MetricLabels::default(),
        UnavailableReason::Missing,
    );
    assert_eq!(
        ProviderSample::new(
            provider("linux.proc.net.snmp"),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![reading; MAX_READINGS_PER_PROVIDER + 1],
        ),
        Err(MonitorValidationError::TooManyProviderReadings)
    );

    let providers = (0..=MAX_PROVIDERS)
        .map(|index| {
            fresh_provider_snapshot(&format!("test.provider{index}"), Duration::from_secs(1))
        })
        .collect();
    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(1),
            None,
            providers,
            vec![],
            EngineTelemetry::default(),
        ),
        Err(MonitorValidationError::TooManyProviders)
    );

    assert_eq!(
        MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(1),
            None,
            vec![],
            vec![],
            EngineTelemetry {
                history_buckets: MAX_HISTORY_BUCKETS + 1,
                ..EngineTelemetry::default()
            },
        ),
        Err(MonitorValidationError::HistoryBudgetExceeded)
    );
}
