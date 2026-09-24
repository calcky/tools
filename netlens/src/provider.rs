use crate::capture::ProviderFilterSupport;
use crate::model::{
    CoverageIntegrity, CoverageVisibility, EvidenceForm, FilterSupport, Layer, SubjectKind,
    EVENT_SKB_FREE, EVENT_SOCKET_RECEIVE_QUEUE_FULL, EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
    PROVIDER_KFREE_SKB, PROVIDER_LINK, PROVIDER_NWDIAG_CORE, PROVIDER_PROC_PROTOCOL,
    PROVIDER_SOCKET_RECEIVE_QUEUE_FULL, PROVIDER_SOCK_DIAG, PROVIDER_SOFTNET,
    PROVIDER_UDP_RECEIVE_ADMISSION,
};

const COUNTER_DELTA_FORMS: [EvidenceForm; 1] = [EvidenceForm::CounterDelta];
const EVENT_FORMS: [EvidenceForm; 1] = [EvidenceForm::Event];

const PROC_LAYERS: [CapabilityLayerDescriptor; 4] = [
    CapabilityLayerDescriptor::baseline(Layer::Socket, FilterSupport::BroaderOnly),
    CapabilityLayerDescriptor::baseline(Layer::Transport, FilterSupport::BroaderOnly),
    CapabilityLayerDescriptor::baseline(Layer::Network, FilterSupport::BroaderOnly),
    CapabilityLayerDescriptor::baseline(Layer::Route, FilterSupport::BroaderOnly),
];
const SOFTNET_LAYERS: [CapabilityLayerDescriptor; 1] = [CapabilityLayerDescriptor::baseline(
    Layer::Netdevice,
    FilterSupport::BroaderOnly,
)];
const LINK_LAYERS: [CapabilityLayerDescriptor; 3] = [
    CapabilityLayerDescriptor::baseline(Layer::Netdevice, FilterSupport::BroaderOnly),
    CapabilityLayerDescriptor::baseline(Layer::Driver, FilterSupport::UserspaceExact),
    CapabilityLayerDescriptor::baseline(Layer::Nic, FilterSupport::UserspaceExact),
];
const SOCK_DIAG_LAYERS: [CapabilityLayerDescriptor; 1] = [CapabilityLayerDescriptor::baseline(
    Layer::Socket,
    FilterSupport::BroaderOnly,
)];
const SOCKET_EVENT_LAYERS: [CapabilityLayerDescriptor; 1] =
    [CapabilityLayerDescriptor::baseline_event(Layer::Socket)];
const KFREE_LAYERS: [CapabilityLayerDescriptor; 10] = [
    CapabilityLayerDescriptor::dynamic(Layer::Socket),
    CapabilityLayerDescriptor::dynamic(Layer::Transport),
    CapabilityLayerDescriptor::dynamic(Layer::Network),
    CapabilityLayerDescriptor::dynamic(Layer::Netfilter),
    CapabilityLayerDescriptor::dynamic(Layer::Route),
    CapabilityLayerDescriptor::dynamic(Layer::Xfrm),
    CapabilityLayerDescriptor::dynamic(Layer::VirtualDevice),
    CapabilityLayerDescriptor::dynamic(Layer::Tc),
    CapabilityLayerDescriptor::dynamic(Layer::Netdevice),
    CapabilityLayerDescriptor::dynamic(Layer::Xdp),
];

const LINK_SUBJECT_KINDS: [SubjectKind; 3] =
    [SubjectKind::Queue, SubjectKind::Interface, SubjectKind::Hop];
const SOCK_DIAG_SUBJECT_KINDS: [SubjectKind; 1] = [SubjectKind::Socket];
const CORE_SUBJECT_KINDS: [SubjectKind; 7] = [
    SubjectKind::Socket,
    SubjectKind::Rule,
    SubjectKind::Program,
    SubjectKind::Queue,
    SubjectKind::Interface,
    SubjectKind::Hop,
    SubjectKind::FlowDomain,
];
const KFREE_OBSERVATION_TYPES: [&str; 1] = [EVENT_SKB_FREE];
const UDP_RECEIVE_ADMISSION_OBSERVATION_TYPES: [&str; 1] = [EVENT_UDP_RECEIVE_ADMISSION_FAILURE];
const SOCKET_RECEIVE_QUEUE_FULL_OBSERVATION_TYPES: [&str; 1] = [EVENT_SOCKET_RECEIVE_QUEUE_FULL];
const KFREE_CAPABILITY_SOURCE_ALIASES: [&str; 1] = ["kfree_skb_tracepoint"];

const PROC_STAGES: [CapabilityStageDescriptor; 7] = [
    CapabilityStageDescriptor::new(
        Layer::Socket,
        "socket.receive_queue",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Socket,
        "socket.listen_queue",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Socket,
        "socket.backlog",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Transport,
        "transport.retransmission",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Network,
        "network.unspecified",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Network,
        "network.receive_validation",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
    CapabilityStageDescriptor::new(
        Layer::Route,
        "route.lookup",
        "linux.kernel",
        "protocol counters are current-network-namespace aggregates",
    ),
];

const SOFTNET_STAGES: [CapabilityStageDescriptor; 3] = [
    CapabilityStageDescriptor::new(
        Layer::Netdevice,
        "netdevice.rx_backlog",
        "linux.kernel",
        "softnet counters are host-wide and not interface- or flow-scoped",
    ),
    CapabilityStageDescriptor::new(
        Layer::Netdevice,
        "netdevice.softirq",
        "linux.kernel",
        "softnet counters are host-wide and not interface- or flow-scoped",
    ),
    CapabilityStageDescriptor::new(
        Layer::Netdevice,
        "netdevice.rps_backlog",
        "linux.kernel",
        "softnet counters are host-wide and not interface- or flow-scoped",
    ),
];

const LINK_STAGES: [CapabilityStageDescriptor; 4] = [
    CapabilityStageDescriptor::new(
        Layer::Netdevice,
        "netdevice.unspecified",
        "linux.kernel",
        "generic link counters do not identify an exact execution point",
    ),
    CapabilityStageDescriptor::new(
        Layer::Driver,
        "driver.rx_queue",
        "linux.kernel",
        "generic link counters do not identify an exact execution point",
    ),
    CapabilityStageDescriptor::new(
        Layer::Driver,
        "driver.unspecified",
        "linux.kernel",
        "generic link counters do not identify an exact execution point",
    ),
    CapabilityStageDescriptor::new(
        Layer::Nic,
        "nic.phy",
        "linux.hardware",
        "generic link counters expose only a limited physical-device signal",
    ),
];
const UDP_RECEIVE_ADMISSION_STAGES: [CapabilityStageDescriptor; 2] = [
    CapabilityStageDescriptor::event(
        Layer::Socket,
        "socket.receive_queue",
        "linux.kernel",
        "provider adapter is not implemented; future events are host-wide and source-partial",
    ),
    CapabilityStageDescriptor::event(
        Layer::Socket,
        "socket.protocol_memory",
        "linux.kernel",
        "provider adapter is not implemented; future events are host-wide and source-partial",
    ),
];
const SOCKET_RECEIVE_QUEUE_FULL_STAGES: [CapabilityStageDescriptor; 1] =
    [CapabilityStageDescriptor::event(
        Layer::Socket,
        "socket.receive_queue",
        "linux.kernel",
        "provider adapter is not implemented; the tracepoint covers only the generic helper occupancy rejection",
    )];

const PROC_METRIC_SOURCES: [&str; 2] = ["proc_net_snmp", "proc_net_netstat"];
const SOFTNET_METRIC_SOURCES: [&str; 1] = ["proc_softnet"];
const LINK_METRIC_SOURCES: [&str; 3] = ["rtnetlink_link_stats", "sys_class_net", "proc_net_dev"];
const SOCK_DIAG_METRIC_SOURCES: [&str; 1] = ["sock_diag_skmeminfo"];

const PROC_METRIC_PREFIXES: [&str; 1] = ["linux.mib."];
const SOFTNET_METRIC_PREFIXES: [&str; 1] = ["linux.softnet."];
const LINK_METRIC_PREFIXES: [&str; 1] = ["linux.link."];
const SOCK_DIAG_METRIC_PREFIXES: [&str; 1] = ["linux.sock_diag."];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TelemetryCounterRule {
    Required,
    NotApplicable,
    Optional,
    AllOrNone(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TelemetryApplicability {
    pub bpf_events_seen: TelemetryCounterRule,
    pub bpf_output_lost: TelemetryCounterRule,
    pub transport_events_received: TelemetryCounterRule,
    pub transport_events_lost: TelemetryCounterRule,
    pub user_events_dropped: TelemetryCounterRule,
    pub netlink_loss_events: TelemetryCounterRule,
    pub netlink_dump_interruptions: TelemetryCounterRule,
    pub parse_errors: TelemetryCounterRule,
}

impl TelemetryApplicability {
    pub const fn as_array(self) -> [TelemetryCounterRule; 8] {
        [
            self.bpf_events_seen,
            self.bpf_output_lost,
            self.transport_events_received,
            self.transport_events_lost,
            self.user_events_dropped,
            self.netlink_loss_events,
            self.netlink_dump_interruptions,
            self.parse_errors,
        ]
    }
}

const PARSE_ONLY_TELEMETRY: TelemetryApplicability = TelemetryApplicability {
    bpf_events_seen: TelemetryCounterRule::NotApplicable,
    bpf_output_lost: TelemetryCounterRule::NotApplicable,
    transport_events_received: TelemetryCounterRule::NotApplicable,
    transport_events_lost: TelemetryCounterRule::NotApplicable,
    user_events_dropped: TelemetryCounterRule::NotApplicable,
    netlink_loss_events: TelemetryCounterRule::NotApplicable,
    netlink_dump_interruptions: TelemetryCounterRule::NotApplicable,
    parse_errors: TelemetryCounterRule::Required,
};

const NETLINK_TELEMETRY: TelemetryApplicability = TelemetryApplicability {
    bpf_events_seen: TelemetryCounterRule::NotApplicable,
    bpf_output_lost: TelemetryCounterRule::NotApplicable,
    transport_events_received: TelemetryCounterRule::NotApplicable,
    transport_events_lost: TelemetryCounterRule::NotApplicable,
    user_events_dropped: TelemetryCounterRule::NotApplicable,
    netlink_loss_events: TelemetryCounterRule::Required,
    netlink_dump_interruptions: TelemetryCounterRule::Required,
    parse_errors: TelemetryCounterRule::Required,
};

const EVENT_TELEMETRY: TelemetryApplicability = TelemetryApplicability {
    bpf_events_seen: TelemetryCounterRule::AllOrNone("event path"),
    bpf_output_lost: TelemetryCounterRule::AllOrNone("event path"),
    transport_events_received: TelemetryCounterRule::AllOrNone("event path"),
    transport_events_lost: TelemetryCounterRule::AllOrNone("event path"),
    user_events_dropped: TelemetryCounterRule::AllOrNone("event path"),
    netlink_loss_events: TelemetryCounterRule::NotApplicable,
    netlink_dump_interruptions: TelemetryCounterRule::NotApplicable,
    parse_errors: TelemetryCounterRule::AllOrNone("event path"),
};

const UNCONSTRAINED_TELEMETRY: TelemetryApplicability = TelemetryApplicability {
    bpf_events_seen: TelemetryCounterRule::Optional,
    bpf_output_lost: TelemetryCounterRule::Optional,
    transport_events_received: TelemetryCounterRule::Optional,
    transport_events_lost: TelemetryCounterRule::Optional,
    user_events_dropped: TelemetryCounterRule::Optional,
    netlink_loss_events: TelemetryCounterRule::Optional,
    netlink_dump_interruptions: TelemetryCounterRule::Optional,
    parse_errors: TelemetryCounterRule::Optional,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderActivation {
    Always,
    RuntimeReady,
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NetworkNamespaceScope {
    Current,
    HostWide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterfaceScope {
    AllVisible,
    RequestedPathWhenComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectionScope {
    Unspecified,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScopeDescriptor {
    pub activation: ProviderActivation,
    pub network_namespace: NetworkNamespaceScope,
    pub interface: InterfaceScope,
    pub direction: DirectionScope,
    pub filter_support: ProviderFilterSupport,
    pub complete_interface_path_support: Option<FilterSupport>,
}

impl ScopeDescriptor {
    pub fn filter_support(self, interface_path_complete: bool) -> ProviderFilterSupport {
        let mut support = self.filter_support;
        if interface_path_complete {
            if let Some(exact) = self.complete_interface_path_support {
                support.interface_path = exact;
            }
        }
        support
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityCoverage {
    BaselineCounters,
    ContextCounters,
    DeclaredEvents,
    DynamicEvents,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationSemantics {
    Generic,
    SkbFree,
    UdpReceiveAdmission,
    SocketReceiveQueueFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetricSemantics {
    Generic,
    SocketDrops,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityLayerCoverage {
    pub forms: &'static [EvidenceForm],
    pub visibility: CoverageVisibility,
    pub filter_support: FilterSupport,
    pub integrity: CoverageIntegrity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityLayerDescriptor {
    pub layer: Layer,
    pub baseline: Option<CapabilityLayerCoverage>,
}

impl CapabilityLayerDescriptor {
    const fn baseline(layer: Layer, filter_support: FilterSupport) -> Self {
        Self {
            layer,
            baseline: Some(CapabilityLayerCoverage {
                forms: &COUNTER_DELTA_FORMS,
                visibility: CoverageVisibility::Partial,
                filter_support,
                integrity: CoverageIntegrity::Unknown,
            }),
        }
    }

    const fn dynamic(layer: Layer) -> Self {
        Self {
            layer,
            baseline: None,
        }
    }

    const fn baseline_event(layer: Layer) -> Self {
        Self {
            layer,
            baseline: Some(CapabilityLayerCoverage {
                forms: &EVENT_FORMS,
                visibility: CoverageVisibility::Partial,
                filter_support: FilterSupport::BroaderOnly,
                integrity: CoverageIntegrity::Unknown,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityStageDescriptor {
    pub layer: Layer,
    pub stage: &'static str,
    pub execution_domain: &'static str,
    pub forms: &'static [EvidenceForm],
    pub visibility: CoverageVisibility,
    pub filter_support: FilterSupport,
    pub integrity: CoverageIntegrity,
    pub limitation: &'static str,
}

impl CapabilityStageDescriptor {
    const fn new(
        layer: Layer,
        stage: &'static str,
        execution_domain: &'static str,
        limitation: &'static str,
    ) -> Self {
        Self {
            layer,
            stage,
            execution_domain,
            forms: &COUNTER_DELTA_FORMS,
            visibility: CoverageVisibility::Partial,
            filter_support: FilterSupport::BroaderOnly,
            integrity: CoverageIntegrity::Unknown,
            limitation,
        }
    }

    const fn event(
        layer: Layer,
        stage: &'static str,
        execution_domain: &'static str,
        limitation: &'static str,
    ) -> Self {
        Self {
            layer,
            stage,
            execution_domain,
            forms: &EVENT_FORMS,
            visibility: CoverageVisibility::Partial,
            filter_support: FilterSupport::BroaderOnly,
            integrity: CoverageIntegrity::Unknown,
            limitation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderDescriptor {
    pub name: &'static str,
    pub owned_layers: &'static [CapabilityLayerDescriptor],
    pub metric_sources: &'static [&'static str],
    pub metric_type_prefixes: &'static [&'static str],
    pub capability_source_aliases: &'static [&'static str],
    pub observation_types: &'static [&'static str],
    pub observation_semantics: ObservationSemantics,
    pub metric_semantics: MetricSemantics,
    pub subject_kinds: &'static [SubjectKind],
    pub telemetry: TelemetryApplicability,
    pub scope: Option<ScopeDescriptor>,
    pub capability_coverage: CapabilityCoverage,
    pub capability_stages: &'static [CapabilityStageDescriptor],
}

impl ProviderDescriptor {
    pub fn owns_layer(self, layer: Layer) -> bool {
        self.owned_layers.iter().any(|owned| owned.layer == layer)
    }

    pub fn owned_layer_ids(self) -> impl Iterator<Item = Layer> {
        self.owned_layers.iter().map(|owned| owned.layer)
    }

    pub fn supports_metric_type(self, metric_type: &str) -> bool {
        self.metric_type_prefixes
            .iter()
            .any(|prefix| metric_type.starts_with(prefix))
    }

    pub fn supports_observation_type(self, event_type: &str) -> bool {
        self.observation_types.contains(&event_type)
    }

    pub fn supports_subject_kind(self, kind: SubjectKind) -> bool {
        self.subject_kinds.contains(&kind)
    }
}

const fn filter_support(
    network_namespace: FilterSupport,
    interface_path: FilterSupport,
    direction: FilterSupport,
) -> ProviderFilterSupport {
    ProviderFilterSupport {
        layers: FilterSupport::UserspaceExact,
        network_namespace,
        interface_path,
        direction,
        protocol: FilterSupport::BroaderOnly,
        source_address: FilterSupport::BroaderOnly,
        destination_address: FilterSupport::BroaderOnly,
        source_port: FilterSupport::BroaderOnly,
        destination_port: FilterSupport::BroaderOnly,
    }
}

pub(crate) const PROVIDERS: &[ProviderDescriptor] = &[
    ProviderDescriptor {
        name: PROVIDER_PROC_PROTOCOL,
        owned_layers: &PROC_LAYERS,
        metric_sources: &PROC_METRIC_SOURCES,
        metric_type_prefixes: &PROC_METRIC_PREFIXES,
        capability_source_aliases: &[],
        observation_types: &[],
        observation_semantics: ObservationSemantics::Generic,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &[],
        telemetry: PARSE_ONLY_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::Always,
            network_namespace: NetworkNamespaceScope::Current,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::KernelExact,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::BaselineCounters,
        capability_stages: &PROC_STAGES,
    },
    ProviderDescriptor {
        name: PROVIDER_SOFTNET,
        owned_layers: &SOFTNET_LAYERS,
        metric_sources: &SOFTNET_METRIC_SOURCES,
        metric_type_prefixes: &SOFTNET_METRIC_PREFIXES,
        capability_source_aliases: &[],
        observation_types: &[],
        observation_semantics: ObservationSemantics::Generic,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &[],
        telemetry: PARSE_ONLY_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::Always,
            network_namespace: NetworkNamespaceScope::HostWide,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::BaselineCounters,
        capability_stages: &SOFTNET_STAGES,
    },
    ProviderDescriptor {
        name: PROVIDER_LINK,
        owned_layers: &LINK_LAYERS,
        metric_sources: &LINK_METRIC_SOURCES,
        metric_type_prefixes: &LINK_METRIC_PREFIXES,
        capability_source_aliases: &[],
        observation_types: &[],
        observation_semantics: ObservationSemantics::Generic,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &LINK_SUBJECT_KINDS,
        telemetry: NETLINK_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::Always,
            network_namespace: NetworkNamespaceScope::Current,
            interface: InterfaceScope::RequestedPathWhenComplete,
            direction: DirectionScope::Requested,
            filter_support: filter_support(
                FilterSupport::KernelExact,
                FilterSupport::BroaderOnly,
                FilterSupport::UserspaceExact,
            ),
            complete_interface_path_support: Some(FilterSupport::UserspaceExact),
        }),
        capability_coverage: CapabilityCoverage::BaselineCounters,
        capability_stages: &LINK_STAGES,
    },
    ProviderDescriptor {
        name: PROVIDER_SOCK_DIAG,
        owned_layers: &SOCK_DIAG_LAYERS,
        metric_sources: &SOCK_DIAG_METRIC_SOURCES,
        metric_type_prefixes: &SOCK_DIAG_METRIC_PREFIXES,
        capability_source_aliases: &[],
        observation_types: &[],
        observation_semantics: ObservationSemantics::Generic,
        metric_semantics: MetricSemantics::SocketDrops,
        subject_kinds: &SOCK_DIAG_SUBJECT_KINDS,
        telemetry: NETLINK_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::Always,
            network_namespace: NetworkNamespaceScope::Current,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::KernelExact,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::ContextCounters,
        capability_stages: &[],
    },
    ProviderDescriptor {
        name: PROVIDER_KFREE_SKB,
        owned_layers: &KFREE_LAYERS,
        metric_sources: &[],
        metric_type_prefixes: &[],
        capability_source_aliases: &KFREE_CAPABILITY_SOURCE_ALIASES,
        observation_types: &KFREE_OBSERVATION_TYPES,
        observation_semantics: ObservationSemantics::SkbFree,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &[],
        telemetry: EVENT_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::RuntimeReady,
            network_namespace: NetworkNamespaceScope::HostWide,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::DynamicEvents,
        capability_stages: &[],
    },
    ProviderDescriptor {
        name: PROVIDER_UDP_RECEIVE_ADMISSION,
        owned_layers: &SOCKET_EVENT_LAYERS,
        metric_sources: &[],
        metric_type_prefixes: &[],
        capability_source_aliases: &[],
        observation_types: &UDP_RECEIVE_ADMISSION_OBSERVATION_TYPES,
        observation_semantics: ObservationSemantics::UdpReceiveAdmission,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &[],
        telemetry: EVENT_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::NotImplemented,
            network_namespace: NetworkNamespaceScope::HostWide,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::DeclaredEvents,
        capability_stages: &UDP_RECEIVE_ADMISSION_STAGES,
    },
    ProviderDescriptor {
        name: PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
        owned_layers: &SOCKET_EVENT_LAYERS,
        metric_sources: &[],
        metric_type_prefixes: &[],
        capability_source_aliases: &[],
        observation_types: &SOCKET_RECEIVE_QUEUE_FULL_OBSERVATION_TYPES,
        observation_semantics: ObservationSemantics::SocketReceiveQueueFull,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &[],
        telemetry: EVENT_TELEMETRY,
        scope: Some(ScopeDescriptor {
            activation: ProviderActivation::NotImplemented,
            network_namespace: NetworkNamespaceScope::HostWide,
            interface: InterfaceScope::AllVisible,
            direction: DirectionScope::Unspecified,
            filter_support: filter_support(
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
                FilterSupport::BroaderOnly,
            ),
            complete_interface_path_support: None,
        }),
        capability_coverage: CapabilityCoverage::DeclaredEvents,
        capability_stages: &SOCKET_RECEIVE_QUEUE_FULL_STAGES,
    },
    ProviderDescriptor {
        name: PROVIDER_NWDIAG_CORE,
        owned_layers: &[],
        metric_sources: &[],
        metric_type_prefixes: &[],
        capability_source_aliases: &[],
        observation_types: &[],
        observation_semantics: ObservationSemantics::Generic,
        metric_semantics: MetricSemantics::Generic,
        subject_kinds: &CORE_SUBJECT_KINDS,
        telemetry: UNCONSTRAINED_TELEMETRY,
        scope: None,
        capability_coverage: CapabilityCoverage::None,
        capability_stages: &[],
    },
];

pub(crate) fn descriptor(name: &str) -> Option<&'static ProviderDescriptor> {
    PROVIDERS.iter().find(|provider| provider.name == name)
}

pub(crate) fn capture_descriptors() -> impl Iterator<Item = &'static ProviderDescriptor> + Clone {
    PROVIDERS.iter().filter(|provider| provider.scope.is_some())
}

pub(crate) fn descriptor_for_metric_source(source: &str) -> Option<&'static ProviderDescriptor> {
    PROVIDERS
        .iter()
        .find(|provider| provider.metric_sources.contains(&source))
}

pub(crate) fn descriptor_for_capability_source(
    source: &str,
) -> Option<&'static ProviderDescriptor> {
    descriptor(source).or_else(|| {
        PROVIDERS.iter().find(|provider| {
            provider.metric_sources.contains(&source)
                || provider.capability_source_aliases.contains(&source)
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::model::StageId;

    use super::*;

    const REQUIRED_PROVIDERS: [&str; 8] = [
        PROVIDER_PROC_PROTOCOL,
        PROVIDER_SOFTNET,
        PROVIDER_LINK,
        PROVIDER_SOCK_DIAG,
        PROVIDER_KFREE_SKB,
        PROVIDER_UDP_RECEIVE_ADMISSION,
        PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
        PROVIDER_NWDIAG_CORE,
    ];

    fn validate_registry(registry: &[ProviderDescriptor], required: &[&str]) -> Result<(), String> {
        let mut names = BTreeSet::new();
        let mut metric_sources = BTreeSet::new();
        let mut capability_sources = BTreeSet::new();
        let mut observation_types = BTreeSet::new();
        for provider in registry {
            if !names.insert(provider.name) {
                return Err(format!("duplicate provider descriptor {}", provider.name));
            }
            for source in std::iter::once(provider.name)
                .chain(provider.metric_sources.iter().copied())
                .chain(provider.capability_source_aliases.iter().copied())
            {
                if !capability_sources.insert(source) {
                    return Err(format!("duplicate capability source {source}"));
                }
            }
            if provider.scope.is_some() && provider.owned_layers.is_empty() {
                return Err(format!(
                    "capture provider {} has no owned layers",
                    provider.name
                ));
            }
            match provider.capability_coverage {
                CapabilityCoverage::BaselineCounters | CapabilityCoverage::DeclaredEvents
                    if provider.capability_stages.is_empty() =>
                {
                    return Err(format!(
                        "stage-owning provider {} has no capability stages",
                        provider.name
                    ));
                }
                CapabilityCoverage::ContextCounters if !provider.capability_stages.is_empty() => {
                    return Err(format!(
                        "context provider {} declares causal capability stages",
                        provider.name
                    ));
                }
                _ => {}
            }
            let mut layers = BTreeSet::new();
            for owned in provider.owned_layers {
                if !layers.insert(owned.layer) {
                    return Err(format!("provider {} repeats an owned layer", provider.name));
                }
                match provider.capability_coverage {
                    CapabilityCoverage::BaselineCounters
                    | CapabilityCoverage::ContextCounters
                    | CapabilityCoverage::DeclaredEvents
                        if owned.baseline.is_none() =>
                    {
                        return Err(format!(
                            "static provider {} has a layer without baseline coverage",
                            provider.name
                        ));
                    }
                    CapabilityCoverage::DynamicEvents | CapabilityCoverage::None
                        if owned.baseline.is_some() =>
                    {
                        return Err(format!(
                            "non-static provider {} has static layer coverage",
                            provider.name
                        ));
                    }
                    _ => {}
                }
            }
            let mut stages = BTreeSet::new();
            for stage in provider.capability_stages {
                if !provider.owns_layer(stage.layer) {
                    return Err(format!(
                        "provider {} stage {} is outside its owned layers",
                        provider.name, stage.stage
                    ));
                }
                let stage_id = StageId::new(stage.stage).map_err(|error| error.to_string())?;
                if stage_id.layer() != Some(stage.layer) {
                    return Err(format!(
                        "provider {} stage {} conflicts with its layer",
                        provider.name, stage.stage
                    ));
                }
                if !stages.insert((stage.stage, stage.execution_domain)) {
                    return Err(format!(
                        "provider {} repeats capability stage {}",
                        provider.name, stage.stage
                    ));
                }
                if stage.forms.is_empty() {
                    return Err(format!(
                        "provider {} stage {} has no evidence forms",
                        provider.name, stage.stage
                    ));
                }
            }
            for source in provider.metric_sources {
                if !metric_sources.insert(*source) {
                    return Err(format!("duplicate metric source {source}"));
                }
            }
            for event_type in provider.observation_types {
                if !observation_types.insert(*event_type) {
                    return Err(format!("duplicate observation type {event_type}"));
                }
            }
            let subject_kinds: BTreeSet<_> = provider.subject_kinds.iter().copied().collect();
            if subject_kinds.len() != provider.subject_kinds.len() {
                return Err(format!("provider {} repeats a subject kind", provider.name));
            }
        }
        for name in required {
            if !names.contains(name) {
                return Err(format!("missing provider descriptor {name}"));
            }
        }
        Ok(())
    }

    #[test]
    fn registry_is_unique_complete_and_internally_consistent() {
        validate_registry(PROVIDERS, &REQUIRED_PROVIDERS).unwrap();
        assert_eq!(
            PROVIDERS
                .iter()
                .map(|provider| provider.name)
                .collect::<Vec<_>>(),
            REQUIRED_PROVIDERS
        );
    }

    #[test]
    fn duplicate_and_missing_descriptors_fail_registry_validation() {
        let mut duplicate = PROVIDERS.to_vec();
        duplicate.push(PROVIDERS[0]);
        assert!(validate_registry(&duplicate, &REQUIRED_PROVIDERS)
            .unwrap_err()
            .contains("duplicate provider descriptor"));

        assert!(validate_registry(&PROVIDERS[1..], &REQUIRED_PROVIDERS)
            .unwrap_err()
            .contains("missing provider descriptor"));
    }

    #[test]
    fn capture_provider_and_metric_source_registry_matches_v5() {
        assert_eq!(
            capture_descriptors()
                .map(|provider| provider.name)
                .collect::<Vec<_>>(),
            [
                PROVIDER_PROC_PROTOCOL,
                PROVIDER_SOFTNET,
                PROVIDER_LINK,
                PROVIDER_SOCK_DIAG,
                PROVIDER_KFREE_SKB,
                PROVIDER_UDP_RECEIVE_ADMISSION,
                PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
            ]
        );
        for (source, provider) in [
            ("proc_net_snmp", PROVIDER_PROC_PROTOCOL),
            ("proc_net_netstat", PROVIDER_PROC_PROTOCOL),
            ("proc_softnet", PROVIDER_SOFTNET),
            ("rtnetlink_link_stats", PROVIDER_LINK),
            ("sys_class_net", PROVIDER_LINK),
            ("proc_net_dev", PROVIDER_LINK),
            ("sock_diag_skmeminfo", PROVIDER_SOCK_DIAG),
        ] {
            assert_eq!(
                descriptor_for_metric_source(source).map(|descriptor| descriptor.name),
                Some(provider)
            );
        }
        assert!(descriptor_for_metric_source("linux.unknown").is_none());
        assert_eq!(
            descriptor_for_capability_source("kfree_skb_tracepoint")
                .map(|descriptor| descriptor.name),
            Some(PROVIDER_KFREE_SKB)
        );
        assert_eq!(
            descriptor_for_capability_source("rtnetlink_link_stats")
                .map(|descriptor| descriptor.name),
            Some(PROVIDER_LINK)
        );
        assert!(descriptor_for_capability_source("linux.unknown").is_none());
        assert!(descriptor("linux.unknown").is_none());
    }

    #[test]
    fn owned_layers_match_existing_capture_contract() {
        assert_eq!(
            descriptor(PROVIDER_PROC_PROTOCOL)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [
                Layer::Socket,
                Layer::Transport,
                Layer::Network,
                Layer::Route
            ]
        );
        assert_eq!(
            descriptor(PROVIDER_SOFTNET)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [Layer::Netdevice]
        );
        assert_eq!(
            descriptor(PROVIDER_LINK)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [Layer::Netdevice, Layer::Driver, Layer::Nic]
        );
        assert_eq!(
            descriptor(PROVIDER_KFREE_SKB)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [
                Layer::Socket,
                Layer::Transport,
                Layer::Network,
                Layer::Netfilter,
                Layer::Route,
                Layer::Xfrm,
                Layer::VirtualDevice,
                Layer::Tc,
                Layer::Netdevice,
                Layer::Xdp,
            ]
        );
        assert_eq!(
            descriptor(PROVIDER_SOCK_DIAG)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [Layer::Socket]
        );
        assert_eq!(
            descriptor(PROVIDER_UDP_RECEIVE_ADMISSION)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [Layer::Socket]
        );
        assert_eq!(
            descriptor(PROVIDER_SOCKET_RECEIVE_QUEUE_FULL)
                .unwrap()
                .owned_layer_ids()
                .collect::<Vec<_>>(),
            [Layer::Socket]
        );
        assert!(descriptor(PROVIDER_NWDIAG_CORE)
            .unwrap()
            .owned_layers
            .is_empty());
    }

    #[test]
    fn socket_context_and_causal_event_profiles_remain_separate() {
        let sock_diag = descriptor(PROVIDER_SOCK_DIAG).unwrap();
        assert_eq!(
            sock_diag.capability_coverage,
            CapabilityCoverage::ContextCounters
        );
        assert!(sock_diag.capability_stages.is_empty());

        for (name, event_type, semantics, stages) in [
            (
                PROVIDER_UDP_RECEIVE_ADMISSION,
                EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
                ObservationSemantics::UdpReceiveAdmission,
                &["socket.receive_queue", "socket.protocol_memory"][..],
            ),
            (
                PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
                EVENT_SOCKET_RECEIVE_QUEUE_FULL,
                ObservationSemantics::SocketReceiveQueueFull,
                &["socket.receive_queue"][..],
            ),
        ] {
            let provider = descriptor(name).unwrap();
            let scope = provider.scope.unwrap();
            assert_eq!(
                provider.capability_coverage,
                CapabilityCoverage::DeclaredEvents
            );
            assert_eq!(provider.observation_types, [event_type]);
            assert_eq!(provider.observation_semantics, semantics);
            assert_eq!(provider.telemetry, EVENT_TELEMETRY);
            assert_eq!(scope.activation, ProviderActivation::NotImplemented);
            assert_eq!(scope.network_namespace, NetworkNamespaceScope::HostWide);
            assert_eq!(
                scope.filter_support(false).network_namespace,
                FilterSupport::BroaderOnly
            );
            assert_eq!(
                provider
                    .capability_stages
                    .iter()
                    .map(|stage| stage.stage)
                    .collect::<Vec<_>>(),
                stages
            );
        }
    }
}
