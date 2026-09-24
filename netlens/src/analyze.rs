use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    metric_measurement_identity, Confidence, Direction, Disposition, EvidenceContext,
    EvidenceDescriptor, EvidenceForm, EvidenceKind, EvidenceRef, EvidenceRole, Finding, HookRef,
    Layer, Measurement, MeasurementBound, MeasurementDomain, MeasurementScope, MeasurementUnit,
    MetricDelta, MetricKey, NamespacedName, Observation, Outcome, PathRole, Severity, Signal,
    StageId, SubjectRef, ATTR_SKB_REASON_NAME, ATTR_UDP_RECEIVE_ADMISSION_CAUSE,
    METRIC_SOCK_DIAG_DROPS,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum FindingMeasurementIdentity {
    Metric {
        provider: String,
        identity: String,
    },
    Observation {
        provider: String,
        event_type: String,
    },
}

type FindingKey = (
    String,
    FindingMeasurementIdentity,
    EvidenceDescriptor,
    Option<NamespacedName>,
    Option<NamespacedName>,
    BTreeSet<SubjectRef>,
);

#[derive(Clone, Copy)]
enum CountPolicy {
    Maximum,
    Sum,
}

fn apply_count(finding: &mut Finding, count: u64, policy: CountPolicy) {
    finding.count = match policy {
        CountPolicy::Maximum => finding.count.max(count),
        CountPolicy::Sum => finding.count.saturating_add(count),
    };
}

struct FindingSpec {
    id: &'static str,
    layer: Layer,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    summary: &'static str,
    stage: &'static str,
    direction: Option<Direction>,
    path_role: Option<PathRole>,
    disposition: Option<Disposition>,
    signal: Option<Signal>,
    role: EvidenceRole,
    domain: MeasurementDomain,
    scope: MeasurementScope,
}

pub fn findings(metrics: &[MetricDelta], observations: &[Observation]) -> Vec<Finding> {
    let mut findings: BTreeMap<FindingKey, Finding> = BTreeMap::new();

    for metric in metrics {
        let Some(count) = metric.values.delta.filter(|value| *value > 0) else {
            continue;
        };
        let Some(spec) = classify_metric_type(metric.metric_type.as_str()) else {
            continue;
        };
        let descriptor = metric.meta.descriptor.clone();
        let key = (
            spec.id.to_owned(),
            FindingMeasurementIdentity::Metric {
                provider: metric.meta.provider.as_str().to_owned(),
                identity: metric_measurement_identity(metric.metric_type.as_str()).to_owned(),
            },
            descriptor.clone(),
            metric.meta.execution_domain.clone(),
            metric.meta.transition.clone(),
            metric.meta.subjects.iter().cloned().collect(),
        );

        let finding = findings.entry(key).or_insert_with(|| Finding {
            id: spec.id.to_owned(),
            layer: metric.meta.layer,
            execution_domain: metric.meta.execution_domain.clone(),
            transition: metric.meta.transition.clone(),
            descriptor: descriptor.clone(),
            severity: spec.severity,
            confidence: spec.confidence,
            title: spec.title.to_owned(),
            summary: spec.summary.to_owned(),
            count: 0,
            evidence: Vec::new(),
        });

        // Only registered overlapping counters share a measurement identity.
        // Their maximum is a conservative de-duplication bound.
        apply_count(finding, count, CountPolicy::Maximum);
        finding.evidence.push(EvidenceRef {
            kind: EvidenceKind::Metric,
            id: metric.meta.id.clone(),
        });
    }

    add_drop_observations(&mut findings, observations);

    let mut findings: Vec<_> = findings.into_values().collect();
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.layer.cmp(&right.layer))
            .then_with(|| left.id.cmp(&right.id))
    });
    findings
}

pub fn drop_reason_layer(reason: &str) -> Option<Layer> {
    match reason {
        "NETFILTER_DROP" => Some(Layer::Netfilter),
        "QDISC_DROP" => Some(Layer::Tc),
        reason if reason.starts_with("TC_") => Some(Layer::Tc),
        "XDP" => Some(Layer::Xdp),
        "OTHERHOST" | "UNICAST_IN_L2_MULTICAST" | "CPU_BACKLOG" | "UNHANDLED_PROTO" => {
            Some(Layer::Netdevice)
        }
        "TAP_FILTER"
        | "TAP_TXFILTER"
        | "VXLAN_INVALID_HDR"
        | "VXLAN_VNI_NOT_FOUND"
        | "VXLAN_ENTRY_EXISTS"
        | "MAC_INVALID_SOURCE"
        | "IP_TUNNEL_ECN"
        | "TUNNEL_TXINFO"
        | "LOCAL_MAC" => Some(Layer::VirtualDevice),
        reason if reason.starts_with("XFRM_") => Some(Layer::Xfrm),
        reason
            if reason.starts_with("NEIGH")
                || matches!(reason, "IP_INNOROUTES" | "IP_OUTNOROUTES") =>
        {
            Some(Layer::Route)
        }
        reason
            if reason.starts_with("IP_")
                || reason.starts_with("IPV6")
                || reason.starts_with("FRAG_")
                || matches!(
                    reason,
                    "PKT_TOO_BIG" | "DUP_FRAG" | "ICMP_CSUM" | "INVALID_PROTO"
                ) =>
        {
            Some(Layer::Network)
        }
        reason if reason.starts_with("TCP_") || matches!(reason, "TCP_CSUM" | "UDP_CSUM") => {
            Some(Layer::Transport)
        }
        "NO_SOCKET" | "SOCKET_FILTER" | "SOCKET_RCVBUFF" | "SOCKET_BACKLOG" | "PROTO_MEM"
        | "PACKET_SOCK_ERROR" => Some(Layer::Socket),
        _ => None,
    }
}

fn add_drop_observations(
    findings: &mut BTreeMap<FindingKey, Finding>,
    observations: &[Observation],
) {
    for observation in observations {
        if !matches!(
            observation.meta.descriptor.outcome.disposition,
            Some(Disposition::Dropped | Disposition::Rejected)
        ) {
            continue;
        }
        let event_finding = socket_event_finding(observation);
        let reason_name = observation
            .attributes
            .get(ATTR_SKB_REASON_NAME)
            .and_then(crate::model::AttributeValue::as_str);
        let (id, title, summary, severity, confidence) = match event_finding {
            Some((id, title, summary)) => (
                id.to_owned(),
                title.to_owned(),
                summary.to_owned(),
                Severity::Warning,
                Confidence::Direct,
            ),
            None => match reason_name {
                Some(reason) => {
                    let summary = if reason == "NOT_SPECIFIED" {
                        "The running kernel marked this drop reason as unspecified; no root cause or layer was inferred."
                        .to_owned()
                    } else if observation.meta.layer.is_some() {
                        format!(
                        "The running kernel directly reported {reason}; policy and protocol drops may be expected behavior."
                    )
                    } else {
                        format!(
                        "The running kernel directly reported {reason}, but this reason does not identify a single network layer."
                    )
                    };
                    (
                        format!("drop_reason.{}", reason.to_ascii_lowercase()),
                        format!("Kernel drop reason {reason}"),
                        summary,
                        drop_reason_severity(reason),
                        if reason == "NOT_SPECIFIED" {
                            Confidence::Suspected
                        } else {
                            Confidence::Direct
                        },
                    )
                }
                None => continue,
            },
        };
        let descriptor = observation.meta.descriptor.clone();
        let key = (
            id.clone(),
            FindingMeasurementIdentity::Observation {
                provider: observation.meta.provider.as_str().to_owned(),
                event_type: observation.event_type.as_str().to_owned(),
            },
            descriptor.clone(),
            observation.meta.execution_domain.clone(),
            observation.meta.transition.clone(),
            observation.meta.subjects.iter().cloned().collect(),
        );
        let finding = findings.entry(key).or_insert_with(|| Finding {
            id,
            layer: observation.meta.layer,
            execution_domain: observation.meta.execution_domain.clone(),
            transition: observation.meta.transition.clone(),
            descriptor: descriptor.clone(),
            severity,
            confidence,
            title,
            summary,
            count: 0,
            evidence: Vec::new(),
        });
        apply_count(finding, 1, CountPolicy::Sum);
        finding.evidence.push(EvidenceRef {
            kind: EvidenceKind::Observation,
            id: observation.meta.id.clone(),
        });
    }
}

fn socket_event_finding(
    observation: &Observation,
) -> Option<(&'static str, &'static str, &'static str)> {
    let stage = observation
        .meta
        .descriptor
        .stage
        .as_ref()
        .map(StageId::as_str);
    let cause_matches_stage = match observation
        .attributes
        .get(ATTR_UDP_RECEIVE_ADMISSION_CAUSE)
        .and_then(crate::model::AttributeValue::as_str)
    {
        Some("receive_buffer") => stage == Some("socket.receive_queue"),
        Some("protocol_memory") => stage == Some("socket.protocol_memory"),
        Some(_) => false,
        None => true,
    };
    if !cause_matches_stage {
        return None;
    }

    crate::model::socket_causal_finding_contract(
        observation.meta.provider.as_str(),
        observation.event_type.as_str(),
        stage,
    )
    .map(|contract| (contract.id, contract.title, contract.summary))
}

pub fn skb_free_descriptor(
    reason: Option<&str>,
    disposition: Option<Disposition>,
    cpu: u32,
    protocol: u16,
) -> EvidenceDescriptor {
    let stage = reason.and_then(drop_reason_stage);
    let direction = reason.and_then(drop_reason_direction);
    let path_role = reason.and_then(drop_reason_path_role);
    let hook = reason.and_then(drop_reason_hook);
    let causal = matches!(
        disposition,
        Some(Disposition::Dropped | Disposition::Rejected)
    ) && reason != Some("NOT_SPECIFIED");
    EvidenceDescriptor {
        stage,
        hook,
        direction,
        path_role,
        context: EvidenceContext {
            cpu: Some(cpu),
            protocol: (protocol != 0).then_some(protocol),
            ..EvidenceContext::default()
        },
        outcome: Outcome {
            disposition,
            signal: None,
        },
        form: EvidenceForm::Event,
        role: if causal {
            EvidenceRole::Causal
        } else {
            EvidenceRole::Context
        },
        measurement: Measurement {
            unit: MeasurementUnit::Occurrences,
            domain: Some(MeasurementDomain::Skb),
            scope: Some(MeasurementScope::Host),
            bound: Some(MeasurementBound::Exact),
        },
    }
}

pub(crate) fn drop_reason_stage(reason: &str) -> Option<StageId> {
    let value = match reason {
        "NO_SOCKET" => "socket.lookup",
        "SOCKET_FILTER" => "socket.filter",
        "SOCKET_RCVBUFF" => "socket.receive_queue",
        "SOCKET_BACKLOG" => "socket.backlog",
        "PROTO_MEM" | "PACKET_SOCK_ERROR" => "socket.unspecified",
        "NETFILTER_DROP" => "netfilter.unspecified",
        "QDISC_DROP" => "qdisc.unspecified",
        "TC_INGRESS" => "tc.ingress",
        "TC_EGRESS" => "tc.egress",
        reason if reason.starts_with("TC_") => "tc.unspecified",
        "CPU_BACKLOG" => "netdevice.rx_backlog",
        "XDP" => "xdp.generic",
        "OTHERHOST" | "UNICAST_IN_L2_MULTICAST" | "UNHANDLED_PROTO" => "netdevice.unspecified",
        "TAP_FILTER"
        | "TAP_TXFILTER"
        | "VXLAN_INVALID_HDR"
        | "VXLAN_VNI_NOT_FOUND"
        | "VXLAN_ENTRY_EXISTS"
        | "MAC_INVALID_SOURCE"
        | "IP_TUNNEL_ECN"
        | "TUNNEL_TXINFO"
        | "LOCAL_MAC" => "virtual.unspecified",
        "XFRM_POLICY" => "xfrm.policy",
        reason if reason.starts_with("XFRM_") => "xfrm.unspecified",
        reason if reason.starts_with("NEIGH") => "route.neighbor",
        "IP_INNOROUTES" | "IP_OUTNOROUTES" => "route.lookup",
        reason if reason.starts_with("FRAG_") || reason == "DUP_FRAG" => "network.fragmentation",
        "PKT_TOO_BIG" => "network.mtu",
        reason
            if reason.starts_with("IP_")
                || reason.starts_with("IPV6")
                || matches!(reason, "ICMP_CSUM" | "INVALID_PROTO") =>
        {
            "network.receive_validation"
        }
        reason if reason.starts_with("TCP_") || matches!(reason, "TCP_CSUM" | "UDP_CSUM") => {
            "transport.unspecified"
        }
        _ => return None,
    };
    Some(StageId::new(value).expect("built-in stage identifiers are valid"))
}

fn drop_reason_direction(reason: &str) -> Option<Direction> {
    if matches!(
        reason,
        "TC_EGRESS" | "QDISC_DROP" | "BPF_CGROUP_EGRESS" | "IP_OUTNOROUTES" | "NO_TX_TARGET"
    ) {
        Some(Direction::Egress)
    } else if matches!(
        reason,
        "TC_INGRESS"
            | "CPU_BACKLOG"
            | "NO_SOCKET"
            | "SOCKET_FILTER"
            | "SOCKET_RCVBUFF"
            | "SOCKET_BACKLOG"
    ) {
        Some(Direction::Ingress)
    } else {
        None
    }
}

fn drop_reason_path_role(reason: &str) -> Option<PathRole> {
    matches!(
        reason,
        "NO_SOCKET" | "SOCKET_FILTER" | "SOCKET_RCVBUFF" | "SOCKET_BACKLOG"
    )
    .then_some(PathRole::LocalInput)
}

fn drop_reason_hook(reason: &str) -> Option<HookRef> {
    let name = match reason {
        "TC_INGRESS" => "ingress",
        "TC_EGRESS" => "egress",
        "XDP" => "generic",
        _ => return None,
    };
    let family = if reason == "XDP" { "xdp" } else { "tc" };
    Some(HookRef::new(family, name).expect("built-in hook identifiers are valid"))
}

fn counter_descriptor(spec: &FindingSpec, key: &MetricKey) -> EvidenceDescriptor {
    let direction = spec.direction.or_else(|| metric_direction(&key.metric));
    let cpu = key.labels.get("cpu").and_then(|value| value.parse().ok());
    let ifindex = key
        .labels
        .get("ifindex")
        .and_then(|value| value.parse().ok())
        .and_then(|value| crate::model::IfIndex::new(value).ok());
    let mut context = EvidenceContext {
        cpu,
        ..EvidenceContext::default()
    };
    match direction {
        Some(Direction::Ingress) => context.ingress_ifindex = ifindex,
        Some(Direction::Egress) => context.egress_ifindex = ifindex,
        None => {}
    }
    EvidenceDescriptor {
        stage: Some(StageId::new(spec.stage).expect("built-in stage identifiers are valid")),
        hook: None,
        direction,
        path_role: spec.path_role,
        context,
        outcome: Outcome {
            disposition: spec.disposition,
            signal: spec.signal,
        },
        form: EvidenceForm::CounterDelta,
        role: spec.role,
        measurement: Measurement {
            unit: MeasurementUnit::Occurrences,
            domain: Some(spec.domain),
            scope: Some(if cpu.is_some() {
                MeasurementScope::Cpu
            } else {
                spec.scope
            }),
            bound: Some(MeasurementBound::Exact),
        },
    }
}

pub(crate) fn metric_contract(
    key: &MetricKey,
) -> Option<(crate::model::NamespacedName, Layer, EvidenceDescriptor)> {
    let metric_type = canonical_metric_type(key)?;
    let spec = classify_parts(&key.group, &key.metric)?;
    let mut descriptor = counter_descriptor(&spec, key);
    if metric_type == crate::model::METRIC_SOCK_DIAG_DROPS {
        // Two u32 endpoints cannot prove that the counter did not wrap a full cycle.
        descriptor.measurement.bound = Some(MeasurementBound::LowerBound);
    }
    Some((
        crate::model::NamespacedName::new(metric_type)
            .expect("registered metric types are namespaced"),
        spec.layer,
        descriptor,
    ))
}

pub(crate) fn sock_diag_metric_contract() -> (crate::model::NamespacedName, EvidenceDescriptor) {
    (
        crate::model::NamespacedName::new(METRIC_SOCK_DIAG_DROPS)
            .expect("registered metric types are namespaced"),
        EvidenceDescriptor {
            stage: None,
            hook: None,
            direction: None,
            path_role: None,
            context: EvidenceContext::default(),
            outcome: Outcome::default(),
            form: EvidenceForm::CounterDelta,
            role: EvidenceRole::Context,
            measurement: Measurement {
                unit: MeasurementUnit::SourceUnits,
                domain: None,
                scope: Some(MeasurementScope::Socket),
                bound: Some(MeasurementBound::LowerBound),
            },
        },
    )
}

fn canonical_metric_type(key: &MetricKey) -> Option<&'static str> {
    match (key.group.as_str(), key.metric.as_str()) {
        ("Udp", "RcvbufErrors") => Some("linux.mib.udp.rcvbuf_errors"),
        ("UdpLite", "RcvbufErrors") => Some("linux.mib.udp_lite.rcvbuf_errors"),
        ("TcpExt", "ListenDrops") => Some("linux.mib.tcp_ext.listen_drops"),
        ("TcpExt", "ListenOverflows") => Some("linux.mib.tcp_ext.listen_overflows"),
        ("TcpExt", "TCPBacklogDrop") => Some("linux.mib.tcp_ext.tcp_backlog_drop"),
        ("Tcp", "RetransSegs") => Some("linux.mib.tcp.retrans_segs"),
        ("TcpExt", "TCPSynRetrans") => Some("linux.mib.tcp_ext.tcp_syn_retrans"),
        ("softnet" | "softnet_cpu", "dropped") => Some("linux.softnet.dropped"),
        ("softnet" | "softnet_cpu", "time_squeeze") => Some("linux.softnet.time_squeeze"),
        ("softnet" | "softnet_cpu", "flow_limit_count") => Some("linux.softnet.flow_limit_count"),
        ("link", "rx_dropped") => Some("linux.link.rx_dropped"),
        ("link", "tx_dropped") => Some("linux.link.tx_dropped"),
        ("link", "rx_missed_errors") => Some("linux.link.rx_missed_errors"),
        ("link", "rx_fifo_errors") => Some("linux.link.rx_fifo_errors"),
        ("link", "tx_fifo_errors") => Some("linux.link.tx_fifo_errors"),
        ("link", "rx_errors") => Some("linux.link.rx_errors"),
        ("link", "tx_errors") => Some("linux.link.tx_errors"),
        ("link", "rx_crc_errors") => Some("linux.link.rx_crc_errors"),
        ("link", "tx_carrier_errors") => Some("linux.link.tx_carrier_errors"),
        ("Ip", "InDiscards") => Some("linux.mib.ip.in_discards"),
        ("Ip", "OutDiscards") => Some("linux.mib.ip.out_discards"),
        ("Ip", "InHdrErrors") => Some("linux.mib.ip.in_hdr_errors"),
        ("Ip", "InAddrErrors") => Some("linux.mib.ip.in_addr_errors"),
        ("Ip", "OutNoRoutes") => Some("linux.mib.ip.out_no_routes"),
        _ => None,
    }
}

fn classify_metric_type(metric_type: &str) -> Option<FindingSpec> {
    let (group, metric) = match metric_type {
        "linux.mib.udp.rcvbuf_errors" => ("Udp", "RcvbufErrors"),
        "linux.mib.udp_lite.rcvbuf_errors" => ("UdpLite", "RcvbufErrors"),
        "linux.mib.tcp_ext.listen_drops" => ("TcpExt", "ListenDrops"),
        "linux.mib.tcp_ext.listen_overflows" => ("TcpExt", "ListenOverflows"),
        "linux.mib.tcp_ext.tcp_backlog_drop" => ("TcpExt", "TCPBacklogDrop"),
        "linux.mib.tcp.retrans_segs" => ("Tcp", "RetransSegs"),
        "linux.mib.tcp_ext.tcp_syn_retrans" => ("TcpExt", "TCPSynRetrans"),
        "linux.softnet.dropped" => ("softnet", "dropped"),
        "linux.softnet.time_squeeze" => ("softnet", "time_squeeze"),
        "linux.softnet.flow_limit_count" => ("softnet", "flow_limit_count"),
        "linux.link.rx_dropped" => ("link", "rx_dropped"),
        "linux.link.tx_dropped" => ("link", "tx_dropped"),
        "linux.link.rx_missed_errors" => ("link", "rx_missed_errors"),
        "linux.link.rx_fifo_errors" => ("link", "rx_fifo_errors"),
        "linux.link.tx_fifo_errors" => ("link", "tx_fifo_errors"),
        "linux.link.rx_errors" => ("link", "rx_errors"),
        "linux.link.tx_errors" => ("link", "tx_errors"),
        "linux.link.rx_crc_errors" => ("link", "rx_crc_errors"),
        "linux.link.tx_carrier_errors" => ("link", "tx_carrier_errors"),
        "linux.mib.ip.in_discards" => ("Ip", "InDiscards"),
        "linux.mib.ip.out_discards" => ("Ip", "OutDiscards"),
        "linux.mib.ip.in_hdr_errors" => ("Ip", "InHdrErrors"),
        "linux.mib.ip.in_addr_errors" => ("Ip", "InAddrErrors"),
        "linux.mib.ip.out_no_routes" => ("Ip", "OutNoRoutes"),
        _ => return None,
    };
    classify_parts(group, metric)
}

fn metric_direction(metric: &str) -> Option<Direction> {
    if metric.starts_with("rx_") || metric.starts_with("In") {
        Some(Direction::Ingress)
    } else if metric.starts_with("tx_") || metric.starts_with("Out") {
        Some(Direction::Egress)
    } else {
        None
    }
}

fn drop_reason_severity(reason: &str) -> Severity {
    if matches!(
        reason,
        "NO_SOCKET"
            | "OTHERHOST"
            | "NETFILTER_DROP"
            | "SOCKET_FILTER"
            | "BPF_CGROUP_EGRESS"
            | "TC_EGRESS"
            | "TC_INGRESS"
            | "XDP"
            | "TAP_FILTER"
            | "TAP_TXFILTER"
            | "QUEUE_PURGE"
    ) || reason.starts_with("TCP_OLD_")
        || reason.starts_with("TCP_OFO")
    {
        Severity::Info
    } else {
        Severity::Warning
    }
}

fn classify_parts(group: &str, metric: &str) -> Option<FindingSpec> {
    match (group, metric) {
        ("Udp", "RcvbufErrors") | ("UdpLite", "RcvbufErrors") => Some(FindingSpec {
            id: "socket.receive_buffer_overflow",
            layer: Layer::Socket,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "Socket receive buffer overflow",
            summary: "The kernel dropped datagrams because a socket receive buffer was full.",
            stage: "socket.receive_queue",
            direction: Some(Direction::Ingress),
            path_role: Some(PathRole::LocalInput),
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::Datagram,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("TcpExt", "ListenDrops") | ("TcpExt", "ListenOverflows") => Some(FindingSpec {
            id: "socket.listen_queue_overflow",
            layer: Layer::Socket,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "TCP listen queue overflow",
            summary: "TCP connection attempts were dropped at a listening socket queue.",
            stage: "socket.listen_queue",
            direction: Some(Direction::Ingress),
            path_role: Some(PathRole::LocalInput),
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::Connection,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("TcpExt", "TCPBacklogDrop") => Some(FindingSpec {
            id: "socket.backlog_drop",
            layer: Layer::Socket,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "TCP socket backlog drops",
            summary: "TCP packets were dropped while the receiving socket backlog was full.",
            stage: "socket.backlog",
            direction: Some(Direction::Ingress),
            path_role: Some(PathRole::LocalInput),
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::Skb,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("Tcp", "RetransSegs") | ("TcpExt", "TCPSynRetrans") => Some(FindingSpec {
            id: "transport.tcp_retransmission",
            layer: Layer::Transport,
            severity: Severity::Info,
            confidence: Confidence::Correlated,
            title: "TCP retransmissions observed",
            summary: "Retransmissions indicate end-to-end loss or delay but do not identify a local drop layer.",
            stage: "transport.retransmission",
            direction: None,
            path_role: None,
            disposition: None,
            signal: Some(Signal::Retransmission),
            role: EvidenceRole::Symptom,
            domain: MeasurementDomain::TcpSegment,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("softnet", "dropped") | ("softnet_cpu", "dropped") => Some(FindingSpec {
            id: "netdevice.softnet_backlog_drop",
            layer: Layer::Netdevice,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "CPU network backlog drops",
            summary: "The per-CPU network input backlog dropped packets before protocol processing.",
            stage: "netdevice.rx_backlog",
            direction: Some(Direction::Ingress),
            path_role: None,
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::Skb,
            scope: MeasurementScope::Host,
        }),
        ("softnet", "time_squeeze") | ("softnet_cpu", "time_squeeze") => {
            Some(FindingSpec {
            id: "netdevice.softnet_time_squeeze",
            layer: Layer::Netdevice,
            severity: Severity::Info,
            confidence: Confidence::Correlated,
            title: "Network softirq budget exhausted",
            summary: "Network receive processing exhausted its time or packet budget during the capture window.",
            stage: "netdevice.softirq",
            direction: Some(Direction::Ingress),
            path_role: None,
            disposition: None,
            signal: Some(Signal::Pressure),
            role: EvidenceRole::Context,
            domain: MeasurementDomain::PollCycle,
            scope: MeasurementScope::Host,
            })
        }
        ("softnet", "flow_limit_count") | ("softnet_cpu", "flow_limit_count") => {
            Some(FindingSpec {
                id: "netdevice.rps_flow_limit_drop",
                layer: Layer::Netdevice,
                severity: Severity::Warning,
                confidence: Confidence::Direct,
                title: "RPS flow limit drops",
                summary: "Receive Packet Steering dropped packets from a dominant flow while the target CPU backlog was under pressure.",
                stage: "netdevice.rps_backlog",
                direction: Some(Direction::Ingress),
                path_role: None,
                disposition: Some(Disposition::Dropped),
                signal: None,
                role: EvidenceRole::Causal,
                domain: MeasurementDomain::Skb,
                scope: MeasurementScope::Host,
            })
        }
        ("link", "rx_dropped") | ("link", "tx_dropped") => Some(FindingSpec {
            id: "netdevice.link_drop",
            layer: Layer::Netdevice,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "Network interface drops",
            summary: "A network interface drop counter increased during the capture window.",
            stage: "netdevice.unspecified",
            direction: None,
            path_role: None,
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::InterfacePacket,
            scope: MeasurementScope::Interface,
        }),
        ("link", "rx_missed_errors") => Some(FindingSpec {
            id: "driver.rx_missed",
            layer: Layer::Driver,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "NIC receive ring misses",
            summary: "The host or device missed received packets, commonly because receive buffers were unavailable.",
            stage: "driver.rx_queue",
            direction: Some(Direction::Ingress),
            path_role: None,
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::WireFrame,
            scope: MeasurementScope::Interface,
        }),
        ("link", "rx_fifo_errors") | ("link", "tx_fifo_errors") => Some(FindingSpec {
            id: "driver.fifo_error",
            layer: Layer::Driver,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "Interface FIFO errors",
            summary: "A driver or device FIFO error counter increased during the capture window.",
            stage: "driver.unspecified",
            direction: None,
            path_role: None,
            disposition: None,
            signal: Some(Signal::Error),
            role: EvidenceRole::Context,
            domain: MeasurementDomain::InterfacePacket,
            scope: MeasurementScope::Interface,
        }),
        ("link", "rx_errors") | ("link", "tx_errors") => Some(FindingSpec {
            id: "driver.link_error",
            layer: Layer::Driver,
            severity: Severity::Warning,
            confidence: Confidence::Correlated,
            title: "Interface errors",
            summary: "An aggregate network interface error counter increased; inspect detailed driver and NIC counters.",
            stage: "driver.unspecified",
            direction: None,
            path_role: None,
            disposition: None,
            signal: Some(Signal::Error),
            role: EvidenceRole::Context,
            domain: MeasurementDomain::InterfacePacket,
            scope: MeasurementScope::Interface,
        }),
        ("link", "rx_crc_errors") | ("link", "tx_carrier_errors") => Some(FindingSpec {
            id: "nic.physical_link_error",
            layer: Layer::Nic,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "Physical link errors",
            summary: "CRC or carrier errors increased, indicating a NIC, cable, transceiver, or link issue.",
            stage: "nic.phy",
            direction: None,
            path_role: None,
            disposition: None,
            signal: Some(Signal::Error),
            role: EvidenceRole::Context,
            domain: MeasurementDomain::WireFrame,
            scope: MeasurementScope::Interface,
        }),
        ("Ip", "InDiscards") | ("Ip", "OutDiscards") => Some(FindingSpec {
            id: "network.ip_discard",
            layer: Layer::Network,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "IP layer discards",
            summary: "The IP layer discarded packets during the capture window.",
            stage: "network.unspecified",
            direction: None,
            path_role: None,
            disposition: Some(Disposition::Dropped),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::L3Packet,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("Ip", "InHdrErrors") | ("Ip", "InAddrErrors") => Some(FindingSpec {
            id: "network.ip_receive_validation_error",
            layer: Layer::Network,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "IP receive validation errors",
            summary: "The IP stack rejected input packets because of header or address errors.",
            stage: "network.receive_validation",
            direction: Some(Direction::Ingress),
            path_role: None,
            disposition: Some(Disposition::Rejected),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::L3Packet,
            scope: MeasurementScope::NetworkNamespace,
        }),
        ("Ip", "OutNoRoutes") => Some(FindingSpec {
            id: "route.no_route",
            layer: Layer::Route,
            severity: Severity::Warning,
            confidence: Confidence::Direct,
            title: "IP route lookup failures",
            summary: "The IP stack could not find a route for locally generated output packets.",
            stage: "route.lookup",
            direction: Some(Direction::Egress),
            path_role: Some(PathRole::LocalOutput),
            disposition: Some(Disposition::Rejected),
            signal: None,
            role: EvidenceRole::Causal,
            domain: MeasurementDomain::L3Packet,
            scope: MeasurementScope::NetworkNamespace,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AttributeValue, Attributes, EvidenceId, EvidenceMeta, RawMetricDelta, RawObservation,
        EVENT_SOCKET_RECEIVE_QUEUE_FULL, EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
        PROVIDER_SOCKET_RECEIVE_QUEUE_FULL, PROVIDER_UDP_RECEIVE_ADMISSION,
    };

    fn delta(group: &str, metric: &str, count: u64) -> MetricDelta {
        normalized_delta(
            MetricKey::new(source_for_group(group), group, metric),
            count,
        )
    }

    fn normalized_delta(key: MetricKey, count: u64) -> MetricDelta {
        let raw = RawMetricDelta {
            key,
            start: Some(1),
            end: Some(1 + count),
            delta: Some(count),
            reset: false,
        };
        crate::normalize::normalize(vec![raw], Vec::new())
            .unwrap()
            .metrics
            .pop()
            .expect("test metric is registered")
    }

    fn source_for_group(group: &str) -> &'static str {
        match group {
            "softnet" | "softnet_cpu" => "proc_softnet",
            "link" => "rtnetlink_link_stats",
            _ => "proc_net_snmp",
        }
    }

    #[test]
    fn classifies_socket_overflow() {
        let findings = findings(&[delta("Udp", "RcvbufErrors", 7)], &[]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].layer, Some(Layer::Socket));
        assert_eq!(findings[0].confidence, Confidence::Direct);
        assert_eq!(findings[0].count, 7);
    }

    #[test]
    fn retransmission_is_only_correlated_evidence() {
        let findings = findings(&[delta("Tcp", "RetransSegs", 3)], &[]);

        assert_eq!(findings[0].layer, Some(Layer::Transport));
        assert_eq!(findings[0].confidence, Confidence::Correlated);
    }

    #[test]
    fn related_listen_counters_are_not_summed() {
        let findings = findings(
            &[
                delta("TcpExt", "ListenDrops", 4),
                delta("TcpExt", "ListenOverflows", 4),
            ],
            &[],
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 4);
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn disjoint_udp_protocol_counters_remain_separate() {
        let findings = findings(
            &[
                delta("Udp", "RcvbufErrors", 4),
                delta("UdpLite", "RcvbufErrors", 7),
            ],
            &[],
        );

        assert_eq!(findings.len(), 2);
        let mut counts: Vec<_> = findings.iter().map(|finding| finding.count).collect();
        counts.sort_unstable();
        assert_eq!(counts, vec![4, 7]);
        assert!(findings.iter().all(|finding| finding.evidence.len() == 1));
    }

    #[test]
    fn softnet_cpu_evidence_does_not_double_count_the_aggregate() {
        let cpu_zero = normalized_delta(
            MetricKey::new("proc_softnet", "softnet_cpu", "dropped").with_label("cpu", "0"),
            2,
        );
        let cpu_one = normalized_delta(
            MetricKey::new("proc_softnet", "softnet_cpu", "dropped").with_label("cpu", "1"),
            3,
        );

        let findings = findings(&[delta("softnet", "dropped", 5), cpu_zero, cpu_one], &[]);

        assert_eq!(findings.len(), 3);
        let mut counts: Vec<_> = findings.iter().map(|finding| finding.count).collect();
        counts.sort_unstable();
        assert_eq!(counts, vec![2, 3, 5]);
        assert!(findings
            .iter()
            .all(|finding| finding.id == "netdevice.softnet_backlog_drop"));
    }

    #[test]
    fn classifies_rps_flow_limit_as_an_aggregate_direct_drop() {
        let findings = findings(&[delta("softnet", "flow_limit_count", 4)], &[]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "netdevice.rps_flow_limit_drop");
        assert_eq!(findings[0].layer, Some(Layer::Netdevice));
        assert_eq!(findings[0].confidence, Confidence::Direct);
        assert_eq!(findings[0].count, 4);
        assert_eq!(
            findings[0].descriptor.outcome.disposition,
            Some(Disposition::Dropped)
        );
    }

    #[test]
    fn ignores_zero_counters() {
        assert!(findings(&[delta("Udp", "RcvbufErrors", 0)], &[]).is_empty());
    }

    #[test]
    fn causal_socket_events_use_their_registered_finding_profiles() {
        for (observation, id, title) in [
            (
                causal_observation(
                    PROVIDER_UDP_RECEIVE_ADMISSION,
                    EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
                    "socket.receive_queue",
                    Some("receive_buffer"),
                    1,
                ),
                "socket.receive_queue_rejection",
                "UDP receive queue rejection",
            ),
            (
                causal_observation(
                    PROVIDER_UDP_RECEIVE_ADMISSION,
                    EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
                    "socket.protocol_memory",
                    Some("protocol_memory"),
                    2,
                ),
                "socket.protocol_memory_rejection",
                "UDP protocol memory rejection",
            ),
            (
                causal_observation(
                    PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
                    EVENT_SOCKET_RECEIVE_QUEUE_FULL,
                    "socket.receive_queue",
                    None,
                    3,
                ),
                "socket.receive_queue_rejection",
                "Generic socket receive queue rejection",
            ),
        ] {
            let findings = findings(&[], &[observation]);

            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].id, id);
            assert_eq!(findings[0].title, title);
            assert_eq!(findings[0].severity, Severity::Warning);
            assert_eq!(findings[0].confidence, Confidence::Direct);
            assert_eq!(findings[0].count, 1);
        }
    }

    #[test]
    fn causal_socket_counts_only_matching_event_occurrences() {
        let first = causal_observation(
            PROVIDER_UDP_RECEIVE_ADMISSION,
            EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
            "socket.receive_queue",
            Some("receive_buffer"),
            1,
        );
        let second = causal_observation(
            PROVIDER_UDP_RECEIVE_ADMISSION,
            EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
            "socket.receive_queue",
            Some("receive_buffer"),
            2,
        );
        let generic = causal_observation(
            PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
            EVENT_SOCKET_RECEIVE_QUEUE_FULL,
            "socket.receive_queue",
            None,
            3,
        );

        let findings = findings(&[], &[first, second, generic]);

        assert_eq!(findings.len(), 2);
        let mut counts: Vec<_> = findings.iter().map(|finding| finding.count).collect();
        counts.sort_unstable();
        assert_eq!(counts, vec![1, 2]);
        assert!(findings
            .iter()
            .all(|finding| finding.id == "socket.receive_queue_rejection"));
        assert!(findings
            .iter()
            .all(|finding| !finding.summary.contains("one skb")));
    }

    #[test]
    fn classifies_dynamic_drop_reason_by_name() {
        let observation = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));

        let findings = findings(&[], &[observation]);
        assert_eq!(findings[0].layer, Some(Layer::Netfilter));
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].count, 1);
    }

    #[test]
    fn aggregated_observations_keep_every_evidence_reference() {
        let first = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));
        let second = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));

        let findings = findings(&[], &[first, second]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 2);
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn subject_reference_order_does_not_split_a_finding() {
        let first_subject = crate::model::SubjectRef {
            role: crate::model::SubjectRole::Primary,
            id: crate::model::SubjectId::new("s_00000000000000000000000000000000_1").unwrap(),
        };
        let second_subject = crate::model::SubjectRef {
            role: crate::model::SubjectRole::Peer,
            id: crate::model::SubjectId::new("s_00000000000000000000000000000000_2").unwrap(),
        };
        let mut first = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));
        first.meta.subjects = vec![first_subject.clone(), second_subject.clone()];
        let mut second = first.clone();
        second.meta.subjects = vec![second_subject, first_subject];

        let findings = findings(&[], &[first, second]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 2);
        assert_eq!(findings[0].evidence.len(), 2);
    }

    #[test]
    fn maps_representative_runtime_reason_names_to_layers() {
        let cases = [
            ("NO_SOCKET", Some(Layer::Socket)),
            ("TCP_RESET", Some(Layer::Transport)),
            ("NETFILTER_DROP", Some(Layer::Netfilter)),
            ("IP_INHDR", Some(Layer::Network)),
            ("NEIGH_QUEUEFULL", Some(Layer::Route)),
            ("XFRM_POLICY", Some(Layer::Xfrm)),
            ("TC_CHAIN_NOTFOUND", Some(Layer::Tc)),
            ("CPU_BACKLOG", Some(Layer::Netdevice)),
            ("VXLAN_INVALID_HDR", Some(Layer::VirtualDevice)),
            ("XDP", Some(Layer::Xdp)),
            ("FULL_RING", None),
            ("NOT_SPECIFIED", None),
            ("FUTURE_REASON", None),
        ];

        for (reason, expected) in cases {
            assert_eq!(drop_reason_layer(reason), expected, "reason {reason}");
        }
    }

    #[test]
    fn reports_generic_drop_reason_without_inventing_a_layer() {
        let observation = observation(Some(58), Some("NOMEM"), Some(Disposition::Dropped));

        let findings = findings(&[], &[observation]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].layer, None);
        assert_eq!(findings[0].confidence, Confidence::Direct);
        assert!(findings[0].summary.contains("does not identify a single"));
    }

    #[test]
    fn unknown_runtime_reason_is_preserved_without_a_drop_finding() {
        let observation = observation(Some(0x1_0001), None, None);

        let findings = findings(&[], &[observation]);
        assert!(findings.is_empty());
    }

    #[test]
    fn unspecified_reason_is_not_presented_as_a_direct_root_cause() {
        let observation = observation(Some(2), Some("NOT_SPECIFIED"), Some(Disposition::Dropped));

        let findings = findings(&[], &[observation]);
        assert_eq!(findings[0].layer, None);
        assert_eq!(findings[0].confidence, Confidence::Suspected);
        assert!(findings[0].summary.contains("no root cause"));
    }

    #[test]
    fn consumed_skb_free_is_not_a_drop_finding() {
        let observation = observation(Some(1), Some("SKB_CONSUMED"), Some(Disposition::Consumed));

        assert!(findings(&[], &[observation]).is_empty());
    }

    #[test]
    fn different_stages_remain_distinct() {
        let first = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));
        let mut second = first.clone();
        second.meta.descriptor.stage = Some(StageId::new("netfilter.forward").unwrap());

        let findings = findings(&[], &[first, second]);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.count == 1));
    }

    #[test]
    fn incompatible_packet_domains_are_never_combined() {
        let first = observation(Some(8), Some("NETFILTER_DROP"), Some(Disposition::Dropped));
        let mut second = first.clone();
        second.meta.descriptor.measurement.domain = Some(MeasurementDomain::GroAggregate);

        let findings = findings(&[], &[first, second]);

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.count == 1));
    }

    #[test]
    fn pressure_signal_is_not_a_drop_outcome() {
        let findings = findings(&[delta("softnet", "time_squeeze", 4)], &[]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].descriptor.outcome.disposition, None);
        assert_eq!(
            findings[0].descriptor.outcome.signal,
            Some(Signal::Pressure)
        );
        assert_eq!(findings[0].descriptor.role, EvidenceRole::Context);
    }

    fn observation(
        reason: Option<u32>,
        reason_name: Option<&str>,
        disposition: Option<Disposition>,
    ) -> Observation {
        let descriptor = skb_free_descriptor(reason_name, disposition, 0, 0x0800);
        let raw = RawObservation {
            monotonic_ns: 1,
            reason,
            reason_name: reason_name.map(str::to_owned),
            layer: reason_name.and_then(drop_reason_layer),
            scope_provenance: crate::model::EvidenceScopeProvenance::observed(&descriptor.context),
            descriptor,
            source_mode: crate::model::BpfMode::ReasonRing,
        };
        crate::normalize::normalize(Vec::new(), vec![raw])
            .unwrap()
            .observations
            .pop()
            .unwrap()
    }

    fn causal_observation(
        provider: &str,
        event_type: &str,
        stage: &str,
        cause: Option<&str>,
        ordinal: u64,
    ) -> Observation {
        let mut attributes = Attributes::default();
        if let Some(cause) = cause {
            attributes
                .insert(
                    NamespacedName::new(ATTR_UDP_RECEIVE_ADMISSION_CAUSE).unwrap(),
                    AttributeValue::String(cause.to_owned()),
                )
                .unwrap();
        }
        Observation {
            meta: EvidenceMeta {
                id: EvidenceId::new(format!("e_22222222222222222222222222222222_{ordinal}"))
                    .unwrap(),
                provider: NamespacedName::new(provider).unwrap(),
                layer: Some(Layer::Socket),
                execution_domain: Some(NamespacedName::new("linux.kernel").unwrap()),
                transition: None,
                descriptor: EvidenceDescriptor {
                    stage: Some(StageId::new(stage).unwrap()),
                    hook: None,
                    direction: Some(Direction::Ingress),
                    path_role: Some(PathRole::LocalInput),
                    context: EvidenceContext::default(),
                    outcome: Outcome {
                        disposition: Some(Disposition::Rejected),
                        signal: None,
                    },
                    form: EvidenceForm::Event,
                    role: EvidenceRole::Causal,
                    measurement: Measurement {
                        unit: MeasurementUnit::Occurrences,
                        domain: Some(MeasurementDomain::Skb),
                        scope: Some(MeasurementScope::Host),
                        bound: Some(MeasurementBound::Exact),
                    },
                },
                subjects: Vec::new(),
            },
            event_type: NamespacedName::new(event_type).unwrap(),
            monotonic_ns: ordinal,
            attributes,
        }
    }
}
