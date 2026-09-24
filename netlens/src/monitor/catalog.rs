use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use super::model::{
    AggregationDomain, AggregationPolicy, CollectionSection, DisplayMeaning, MetricId, MetricKind,
    MetricLabel, MetricLabels, MetricReading, MetricScope, MetricUnit, MonitorValidationError,
    ProjectedValue, ProviderId, ReadingOutcome, SampleReading, SeriesValue, StateValue,
    MAX_DIAGNOSTIC_BYTES, MAX_ID_BYTES, MAX_LABELS_PER_READING,
};

pub const RAW_PRIVATE_NIC_METRIC_ID: &str = "linux.nic.raw_private";
pub const RAW_NIC_SETTING_METRIC_ID: &str = "linux.nic.setting";
pub const NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID: &str = "linux.nic.ethtool_settings_status";
pub const NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID: &str = "linux.nic.ethtool_statistics_status";
pub const OWNER_SOCKET: &str = "linux.monitor.socket";
pub const OWNER_NETFILTER: &str = "linux.monitor.netfilter";
pub const OWNER_TC: &str = "linux.monitor.tc";
pub const OWNER_NETDEVICE: &str = "linux.monitor.netdevice";
pub const OWNER_NIC: &str = "linux.monitor.nic";
pub const OWNER_SOFTIRQ: &str = "linux.monitor.softirq";
pub const OWNER_HARDIRQ: &str = "linux.monitor.hardirq";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricSource {
    pub provider: &'static str,
    pub raw_metric: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateValuePolicy {
    NotApplicable,
    Closed(&'static [&'static str]),
    CpuList,
    Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricDescriptor {
    pub id: &'static str,
    pub owner: &'static str,
    pub primary_section: CollectionSection,
    pub kind: MetricKind,
    pub unit: MetricUnit,
    pub scope: MetricScope,
    pub domain: AggregationDomain,
    pub aggregation: AggregationPolicy,
    pub display: DisplayMeaning,
    pub required_labels: &'static [MetricLabel],
    pub allowed_labels: &'static [MetricLabel],
    pub state_values: StateValuePolicy,
    pub sources: &'static [MetricSource],
    pub title: &'static str,
    pub description: &'static str,
    pub minimum: bool,
}

impl MetricDescriptor {
    pub(crate) fn metric_id(self) -> MetricId {
        static IDS: LazyLock<HashMap<&'static str, MetricId>> = LazyLock::new(|| {
            metric_catalog()
                .iter()
                .map(|descriptor| {
                    (
                        descriptor.id,
                        MetricId::new(descriptor.id).expect("valid catalog metric ID"),
                    )
                })
                .collect()
        });
        IDS.get(self.id).expect("catalog descriptor").clone()
    }

    pub fn source_priority(self, provider: &ProviderId) -> Option<usize> {
        self.sources
            .iter()
            .position(|source| source.provider == provider.as_str())
    }

    pub fn source_is_allowed(self, provider: &ProviderId) -> bool {
        self.sources
            .iter()
            .any(|source| source.provider == provider.as_str())
    }

    pub fn labels_are_allowed(self, labels: &MetricLabels) -> bool {
        labels
            .iter()
            .all(|(label, _)| self.allowed_labels.contains(&label))
            && self
                .required_labels
                .iter()
                .all(|label| labels.get(*label).is_some())
    }

    pub fn can_roll_up(
        self,
        left: &MetricLabels,
        right: &MetricLabels,
        target_scope: MetricScope,
    ) -> bool {
        let AggregationPolicy::Sum {
            target_scope: declared_target,
            reducible_labels,
        } = self.aggregation
        else {
            return false;
        };
        if target_scope != declared_target || left.len() != right.len() {
            return false;
        }

        let mut saw_reduced_dimension = false;
        for (label, left_value) in left.iter() {
            let Some(right_value) = right.get(label) else {
                return false;
            };
            if left_value != right_value {
                if !reducible_labels.contains(&label) {
                    return false;
                }
                saw_reduced_dimension = true;
            }
        }
        saw_reduced_dimension
    }
}

const NONE: AggregationPolicy = AggregationPolicy::None;
const SUM_CPU_TO_HOST: AggregationPolicy = AggregationPolicy::Sum {
    target_scope: MetricScope::Host,
    reducible_labels: &[MetricLabel::Cpu],
};

const NO_LABELS: &[MetricLabel] = &[];
const CPU_LABEL: &[MetricLabel] = &[MetricLabel::Cpu];
const INTERFACE_REQUIRED: &[MetricLabel] = &[MetricLabel::Interface];
const INTERFACE_IDENTITY_REQUIRED: &[MetricLabel] = &[MetricLabel::Interface, MetricLabel::Ifindex];
const INTERFACE_ALLOWED: &[MetricLabel] = &[MetricLabel::Interface, MetricLabel::Ifindex];
const NETFILTER_CHAIN_REQUIRED: &[MetricLabel] = &[
    MetricLabel::Backend,
    MetricLabel::Family,
    MetricLabel::Table,
    MetricLabel::Chain,
];
const NETFILTER_CHAIN_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Backend,
    MetricLabel::Family,
    MetricLabel::Table,
    MetricLabel::Chain,
    MetricLabel::Hook,
    MetricLabel::Priority,
];
const NETFILTER_RULE_REQUIRED: &[MetricLabel] = &[
    MetricLabel::Backend,
    MetricLabel::Family,
    MetricLabel::Table,
    MetricLabel::Chain,
    MetricLabel::RowId,
    MetricLabel::Verdict,
];
const NETFILTER_RULE_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Backend,
    MetricLabel::Family,
    MetricLabel::Table,
    MetricLabel::Chain,
    MetricLabel::RowId,
    MetricLabel::Handle,
    MetricLabel::Verdict,
];
const QDISC_LABELS: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Direction,
    MetricLabel::ObjectKind,
    MetricLabel::QdiscKind,
    MetricLabel::RowId,
    MetricLabel::Execution,
];
const QDISC_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Direction,
    MetricLabel::ObjectKind,
    MetricLabel::QdiscKind,
    MetricLabel::RowId,
    MetricLabel::Execution,
    MetricLabel::QdiscAttachment,
];
const TC_LABELS: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Direction,
    MetricLabel::ObjectKind,
    MetricLabel::RowId,
    MetricLabel::Execution,
];
const TC_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Direction,
    MetricLabel::ObjectKind,
    MetricLabel::RowId,
    MetricLabel::Execution,
    MetricLabel::Verdict,
    MetricLabel::Action,
];
const HARDIRQ_REQUIRED: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Cpu,
];
const HARDIRQ_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Cpu,
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::InterruptClass,
];
const HARDIRQ_INTERFACE: &[MetricLabel] = &[MetricLabel::Interface, MetricLabel::Ifindex];
const RAW_PRIVATE_REQUIRED: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Statistic,
];
const RAW_PRIVATE_ALLOWED: &[MetricLabel] = &[
    MetricLabel::Interface,
    MetricLabel::Ifindex,
    MetricLabel::Statistic,
];

const LINK_STATES: &[&str] = &[
    "up",
    "down",
    "unknown",
    "dormant",
    "lower_layer_down",
    "not_present",
    "testing",
];
const INTERFACE_KINDS: &[&str] = &["physical", "virtual"];
const ETHTOOL_COLLECTION_STATUSES: &[&str] = &[
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
];

const fn owner_for_section(section: CollectionSection) -> &'static str {
    match section {
        CollectionSection::Socket => OWNER_SOCKET,
        CollectionSection::Netfilter => OWNER_NETFILTER,
        CollectionSection::Tc => OWNER_TC,
        CollectionSection::Netdevice => OWNER_NETDEVICE,
        CollectionSection::Nic => OWNER_NIC,
        CollectionSection::Softirq => OWNER_SOFTIRQ,
        CollectionSection::Hardirq => OWNER_HARDIRQ,
    }
}

macro_rules! source {
    ($provider:literal, $raw:literal) => {
        MetricSource {
            provider: $provider,
            raw_metric: $raw,
        }
    };
}

macro_rules! metric {
    (
        $id:literal, $section:ident, $kind:ident, $unit:ident, $scope:ident, $domain:ident,
        $aggregation:expr, $display:ident, $required:expr, $allowed:expr, $sources:expr,
        $title:literal, $description:literal, $minimum:expr
    ) => {
        MetricDescriptor {
            id: $id,
            primary_section: CollectionSection::$section,
            owner: owner_for_section(CollectionSection::$section),
            kind: MetricKind::$kind,
            unit: MetricUnit::$unit,
            scope: MetricScope::$scope,
            domain: AggregationDomain::$domain,
            aggregation: $aggregation,
            display: DisplayMeaning::$display,
            required_labels: $required,
            allowed_labels: $allowed,
            state_values: StateValuePolicy::NotApplicable,
            sources: $sources,
            title: $title,
            description: $description,
            minimum: $minimum,
        }
    };
}

macro_rules! network_counter {
    (
        $id:literal, $unit:ident, $display:ident, $provider:literal, $raw:literal,
        $title:literal, $description:literal
    ) => {
        metric!(
            $id,
            Socket,
            Counter,
            $unit,
            NetworkNamespace,
            IpPacket,
            NONE,
            $display,
            NO_LABELS,
            NO_LABELS,
            &[source!($provider, $raw)],
            $title,
            $description,
            false
        )
    };
}

macro_rules! state_metric {
    (
        $id:literal, $section:ident, $scope:ident, $required:expr, $allowed:expr,
        $policy:expr, $sources:expr, $title:literal, $description:literal, $minimum:expr
    ) => {
        MetricDescriptor {
            id: $id,
            primary_section: CollectionSection::$section,
            owner: owner_for_section(CollectionSection::$section),
            kind: MetricKind::State,
            unit: MetricUnit::State,
            scope: MetricScope::$scope,
            domain: AggregationDomain::SourceStatistic,
            aggregation: AggregationPolicy::None,
            display: DisplayMeaning::State,
            required_labels: $required,
            allowed_labels: $allowed,
            state_values: $policy,
            sources: $sources,
            title: $title,
            description: $description,
            minimum: $minimum,
        }
    };
}

static METRICS: &[MetricDescriptor] = &[
    metric!("linux.socket.tcp.memory_max_pages", Socket, Gauge, Pages, Host, Memory, NONE, Capacity, NO_LABELS, NO_LABELS,
        &[source!("linux.proc.sys.net.ipv4", "tcp_mem_max")], "TCP memory maximum", "Host TCP memory upper threshold from the third tcp_mem value, in kernel pages.", false),
    metric!("linux.socket.tcp.timeouts", Socket, Counter, Occurrences, NetworkNamespace, Connection, NONE, Pressure, NO_LABELS, NO_LABELS,
        &[source!("linux.proc.net.netstat", "TcpExt.TCPTimeouts")], "TCP timeouts", "TCP retransmission timeout events; not failed-connection counts.", false),
    metric!("linux.socket.udp.checksum_errors", Socket, Counter, Occurrences, NetworkNamespace, Datagram, NONE, Error, NO_LABELS, NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.InCsumErrors")], "UDP checksum errors", "IPv4 UDP checksum errors; included in InErrors.", false),
    metric!("linux.socket.udp6.checksum_errors", Socket, Counter, Occurrences, NetworkNamespace, Datagram, NONE, Error, NO_LABELS, NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6InCsumErrors")], "UDP6 checksum errors", "IPv6 UDP checksum errors; included in InErrors.", false),
    network_counter!("linux.socket.icmp.input_echo_requests", Occurrences, Activity, "linux.proc.net.snmp", "Icmp.InEchos", "ICMP echo requests in", "IPv4 Echo Request messages received."),
    network_counter!("linux.socket.icmp.output_echo_requests", Occurrences, Activity, "linux.proc.net.snmp", "Icmp.OutEchos", "ICMP echo requests out", "IPv4 Echo Request messages sent."),
    network_counter!("linux.socket.icmp.input_echo_replies", Occurrences, Activity, "linux.proc.net.snmp", "Icmp.InEchoReps", "ICMP echo replies in", "IPv4 Echo Reply messages received."),
    network_counter!("linux.socket.icmp.output_echo_replies", Occurrences, Activity, "linux.proc.net.snmp", "Icmp.OutEchoReps", "ICMP echo replies out", "IPv4 Echo Reply messages sent."),
    network_counter!("linux.socket.icmpv6.input_echo_requests", Occurrences, Activity, "linux.proc.net.snmp6", "Icmp6InEchos", "ICMPv6 echo requests in", "IPv6 Echo Request messages received."),
    network_counter!("linux.socket.icmpv6.output_echo_requests", Occurrences, Activity, "linux.proc.net.snmp6", "Icmp6OutEchos", "ICMPv6 echo requests out", "IPv6 Echo Request messages sent."),
    network_counter!("linux.socket.icmpv6.input_echo_replies", Occurrences, Activity, "linux.proc.net.snmp6", "Icmp6InEchoReplies", "ICMPv6 echo replies in", "IPv6 Echo Reply messages received."),
    network_counter!("linux.socket.icmpv6.output_echo_replies", Occurrences, Activity, "linux.proc.net.snmp6", "Icmp6OutEchoReplies", "ICMPv6 echo replies out", "IPv6 Echo Reply messages sent."),
    // Socket and protocol counters are current-network-namespace aggregates.
    metric!(
        "linux.socket.tcp.current_established",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.CurrEstab")],
        "TCP established",
        "TCP connections currently in ESTABLISHED or CLOSE-WAIT.",
        true
    ),
    metric!(
        "linux.socket.tcp.active_opens",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.ActiveOpens")],
        "TCP active opens",
        "TCP connections opened actively by this network namespace.",
        false
    ),
    metric!(
        "linux.socket.tcp.passive_opens",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.PassiveOpens")],
        "TCP passive opens",
        "TCP connections accepted passively in this network namespace.",
        false
    ),
    metric!(
        "linux.socket.tcp.failed_connection_attempts",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.AttemptFails")],
        "TCP failed attempts",
        "TCP connection attempts that did not reach ESTABLISHED.",
        false
    ),
    metric!(
        "linux.socket.tcp.established_resets",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.EstabResets")],
        "TCP established resets",
        "Established TCP connections reset before normal close.",
        true
    ),
    metric!(
        "linux.socket.tcp.segments_in",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        TcpSegment,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.InSegs")],
        "TCP segments in",
        "TCP segments received, using the kernel MIB segment domain.",
        true
    ),
    metric!(
        "linux.socket.tcp.segments_out",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        TcpSegment,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.OutSegs")],
        "TCP segments out",
        "TCP segments sent, using the kernel MIB segment domain.",
        true
    ),
    metric!(
        "linux.socket.tcp.retransmitted_segments",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        TcpSegment,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.RetransSegs")],
        "TCP retransmissions",
        "TCP retransmitted segments; this is a symptom, not a drop location.",
        true
    ),
    metric!(
        "linux.socket.tcp.resets_out",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        TcpSegment,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Tcp.OutRsts")],
        "TCP resets out",
        "TCP segments sent with the reset flag.",
        false
    ),
    metric!(
        "linux.socket.tcp.listen_overflows",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.netstat", "TcpExt.ListenOverflows")],
        "Listen overflows",
        "TCP listen queue overflow events reported by TcpExt.",
        true
    ),
    metric!(
        "linux.socket.tcp.listen_drops",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Drop,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.netstat", "TcpExt.ListenDrops")],
        "Listen drops",
        "TCP listen requests explicitly counted as dropped by TcpExt.",
        true
    ),
    metric!(
        "linux.socket.udp.datagrams_in",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.InDatagrams")],
        "UDP datagrams in",
        "UDP datagrams delivered to socket users in this namespace.",
        true
    ),
    metric!(
        "linux.socket.udp.datagrams_out",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.OutDatagrams")],
        "UDP datagrams out",
        "UDP datagrams sent by this network namespace.",
        true
    ),
    metric!(
        "linux.socket.udp.no_ports",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.NoPorts")],
        "UDP no port",
        "UDP datagrams for which no listening port was available.",
        false
    ),
    metric!(
        "linux.socket.udp.input_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.InErrors")],
        "UDP input errors",
        "UDP input errors from the namespace protocol MIB.",
        true
    ),
    metric!(
        "linux.socket.udp.receive_buffer_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Drop,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.RcvbufErrors")],
        "UDP receive buffer errors",
        "UDP datagrams rejected for receive-buffer pressure.",
        true
    ),
    metric!(
        "linux.socket.udp.send_buffer_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Udp.SndbufErrors")],
        "UDP send buffer errors",
        "UDP send attempts rejected for send-buffer pressure.",
        false
    ),
    metric!(
        "linux.socket.ip.receives",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Ip.InReceives")],
        "IP receives",
        "IPv4 input packets counted by the namespace IP MIB.",
        false
    ),
    metric!(
        "linux.socket.ip.delivers",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Ip.InDelivers")],
        "IP delivers",
        "IPv4 packets delivered to upper-layer protocols.",
        false
    ),
    metric!(
        "linux.socket.ip.output_requests",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Ip.OutRequests")],
        "IP output requests",
        "IPv4 packets supplied to IP for transmission.",
        false
    ),
    metric!(
        "linux.socket.ip.input_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Ip.InHdrErrors")],
        "IP header errors",
        "IPv4 packets rejected for invalid IP headers.",
        false
    ),
    metric!(
        "linux.socket.ip.output_discards",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Drop,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp", "Ip.OutDiscards")],
        "IP output discards",
        "IPv4 output packets discarded by the IP layer.",
        false
    ),
    metric!(
        "linux.socket.used",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "sockets.used")],
        "Sockets used",
        "Allocated sockets reported by the current namespace sockstat.",
        true
    ),
    metric!(
        "linux.socket.tcp.in_use",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "TCP.inuse")],
        "TCP sockets in use",
        "TCP sockets currently in use according to sockstat.",
        false
    ),
    metric!(
        "linux.socket.tcp.orphaned",
        Socket,
        Gauge,
        Occurrences,
        Host,
        Socket,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "TCP.orphan")],
        "TCP orphaned",
        "Host-wide TCP sockets without an attached userspace file.",
        false
    ),
    metric!(
        "linux.socket.tcp.time_wait",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Connection,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "TCP.tw")],
        "TCP time wait",
        "TCP connections currently retained in TIME-WAIT.",
        false
    ),
    metric!(
        "linux.socket.tcp.allocated",
        Socket,
        Gauge,
        Occurrences,
        Host,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "TCP.alloc")],
        "TCP allocated",
        "Host-wide allocated TCP sockets according to sockstat.",
        false
    ),
    metric!(
        "linux.socket.tcp.memory_pages",
        Socket,
        Gauge,
        Pages,
        Host,
        Memory,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "TCP.mem")],
        "TCP memory pages",
        "Host-wide TCP protocol memory in kernel page units.",
        true
    ),
    metric!(
        "linux.socket.udp.in_use",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "UDP.inuse")],
        "UDP sockets in use",
        "UDP sockets currently in use according to sockstat.",
        false
    ),
    metric!(
        "linux.socket.udp.memory_pages",
        Socket,
        Gauge,
        Pages,
        Host,
        Memory,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat", "UDP.mem")],
        "UDP memory pages",
        "Host-wide UDP protocol memory in kernel page units.",
        false
    ),
    metric!(
        "linux.socket.ipv6.receives",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Ip6InReceives")],
        "IPv6 receives",
        "IPv6 input packets counted by the namespace IPv6 MIB.",
        false
    ),
    metric!(
        "linux.socket.ipv6.delivers",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Ip6InDelivers")],
        "IPv6 delivers",
        "IPv6 packets delivered to upper-layer protocols.",
        false
    ),
    metric!(
        "linux.socket.ipv6.output_requests",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Ip6OutRequests")],
        "IPv6 output requests",
        "IPv6 packets supplied to IP for transmission.",
        false
    ),
    metric!(
        "linux.socket.ipv6.input_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Ip6InHdrErrors")],
        "IPv6 header errors",
        "IPv6 packets rejected for invalid IP headers.",
        false
    ),
    metric!(
        "linux.socket.ipv6.output_discards",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        IpPacket,
        NONE,
        Drop,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Ip6OutDiscards")],
        "IPv6 output discards",
        "IPv6 output packets discarded by the IP layer.",
        false
    ),
    network_counter!(
        "linux.socket.ip.forwarded_datagrams",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Ip.ForwDatagrams",
        "IPv4 forwarded datagrams",
        "IPv4 datagrams forwarded through this network namespace."
    ),
    network_counter!(
        "linux.socket.ip.input_address_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.InAddrErrors",
        "IPv4 address errors",
        "IPv4 input packets rejected because their destination address was invalid."
    ),
    network_counter!(
        "linux.socket.ip.input_unknown_protocols",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.InUnknownProtos",
        "IPv4 unknown protocols",
        "IPv4 packets delivered to an unknown or unsupported upper-layer protocol."
    ),
    network_counter!(
        "linux.socket.ip.input_discards",
        Occurrences,
        Drop,
        "linux.proc.net.snmp",
        "Ip.InDiscards",
        "IPv4 input discards",
        "Otherwise-valid IPv4 input packets discarded before upper-layer delivery."
    ),
    network_counter!(
        "linux.socket.ip.output_no_routes",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.OutNoRoutes",
        "IPv4 output no route",
        "Locally generated IPv4 packets discarded because no route was available."
    ),
    network_counter!(
        "linux.socket.ip.input_no_routes",
        Occurrences,
        Error,
        "linux.proc.net.netstat",
        "IpExt.InNoRoutes",
        "IPv4 input no route",
        "IPv4 input packets for which route lookup found no route."
    ),
    network_counter!(
        "linux.socket.ip.input_truncated_packets",
        Occurrences,
        Error,
        "linux.proc.net.netstat",
        "IpExt.InTruncatedPkts",
        "IPv4 truncated packets",
        "IPv4 input packets rejected because the received packet was truncated."
    ),
    network_counter!(
        "linux.socket.ip.input_checksum_errors",
        Occurrences,
        Error,
        "linux.proc.net.netstat",
        "IpExt.InCsumErrors",
        "IPv4 checksum errors",
        "IPv4 input packets rejected for an IP-header checksum error."
    ),
    network_counter!(
        "linux.socket.ip.input_octets",
        Bytes,
        Activity,
        "linux.proc.net.netstat",
        "IpExt.InOctets",
        "IPv4 input octets",
        "IPv4 input octets counted at the network layer."
    ),
    network_counter!(
        "linux.socket.ip.output_octets",
        Bytes,
        Activity,
        "linux.proc.net.netstat",
        "IpExt.OutOctets",
        "IPv4 output octets",
        "IPv4 output octets counted at the network layer."
    ),
    network_counter!(
        "linux.socket.ip.reassembly_requests",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Ip.ReasmReqds",
        "IPv4 reassembly requests",
        "IPv4 fragments received that required reassembly."
    ),
    network_counter!(
        "linux.socket.ip.reassembly_successes",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Ip.ReasmOKs",
        "IPv4 reassembly successes",
        "IPv4 datagrams successfully reassembled."
    ),
    network_counter!(
        "linux.socket.ip.reassembly_failures",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.ReasmFails",
        "IPv4 reassembly failures",
        "IPv4 datagrams that could not be reassembled."
    ),
    network_counter!(
        "linux.socket.ip.reassembly_timeouts",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.ReasmTimeout",
        "IPv4 reassembly timeouts",
        "IPv4 fragment reassembly queues that timed out."
    ),
    network_counter!(
        "linux.socket.ip.fragmentation_successes",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Ip.FragOKs",
        "IPv4 fragmentation successes",
        "IPv4 datagrams successfully fragmented for output."
    ),
    network_counter!(
        "linux.socket.ip.fragmentation_failures",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Ip.FragFails",
        "IPv4 fragmentation failures",
        "IPv4 datagrams that required fragmentation but could not be fragmented."
    ),
    network_counter!(
        "linux.socket.ip.fragments_created",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Ip.FragCreates",
        "IPv4 fragments created",
        "IPv4 output fragments created by the network layer."
    ),
    network_counter!(
        "linux.socket.ipv6.forwarded_datagrams",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6OutForwDatagrams",
        "IPv6 forwarded datagrams",
        "IPv6 datagrams forwarded through this network namespace."
    ),
    network_counter!(
        "linux.socket.ipv6.input_too_big_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6InTooBigErrors",
        "IPv6 input too big",
        "IPv6 input packets rejected because they exceeded an input size limit."
    ),
    network_counter!(
        "linux.socket.ipv6.input_no_routes",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6InNoRoutes",
        "IPv6 input no route",
        "IPv6 input packets for which route lookup found no route."
    ),
    network_counter!(
        "linux.socket.ipv6.input_address_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6InAddrErrors",
        "IPv6 address errors",
        "IPv6 input packets rejected because their destination address was invalid."
    ),
    network_counter!(
        "linux.socket.ipv6.input_unknown_protocols",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6InUnknownProtos",
        "IPv6 unknown protocols",
        "IPv6 packets delivered to an unknown or unsupported next-header protocol."
    ),
    network_counter!(
        "linux.socket.ipv6.input_truncated_packets",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6InTruncatedPkts",
        "IPv6 truncated packets",
        "IPv6 input packets rejected because the received packet was truncated."
    ),
    network_counter!(
        "linux.socket.ipv6.input_discards",
        Occurrences,
        Drop,
        "linux.proc.net.snmp6",
        "Ip6InDiscards",
        "IPv6 input discards",
        "Otherwise-valid IPv6 input packets discarded before upper-layer delivery."
    ),
    network_counter!(
        "linux.socket.ipv6.output_no_routes",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6OutNoRoutes",
        "IPv6 output no route",
        "IPv6 output packets discarded because no route was available."
    ),
    network_counter!(
        "linux.socket.ipv6.input_octets",
        Bytes,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6InOctets",
        "IPv6 input octets",
        "IPv6 input octets counted at the network layer."
    ),
    network_counter!(
        "linux.socket.ipv6.output_octets",
        Bytes,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6OutOctets",
        "IPv6 output octets",
        "IPv6 output octets counted at the network layer."
    ),
    network_counter!(
        "linux.socket.ipv6.reassembly_requests",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6ReasmReqds",
        "IPv6 reassembly requests",
        "IPv6 fragments received that required reassembly."
    ),
    network_counter!(
        "linux.socket.ipv6.reassembly_successes",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6ReasmOKs",
        "IPv6 reassembly successes",
        "IPv6 datagrams successfully reassembled."
    ),
    network_counter!(
        "linux.socket.ipv6.reassembly_failures",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6ReasmFails",
        "IPv6 reassembly failures",
        "IPv6 datagrams that could not be reassembled."
    ),
    network_counter!(
        "linux.socket.ipv6.reassembly_timeouts",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6ReasmTimeout",
        "IPv6 reassembly timeouts",
        "IPv6 fragment reassembly queues that timed out."
    ),
    network_counter!(
        "linux.socket.ipv6.fragmentation_successes",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6FragOKs",
        "IPv6 fragmentation successes",
        "Locally generated IPv6 packets successfully fragmented for output."
    ),
    network_counter!(
        "linux.socket.ipv6.fragmentation_failures",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Ip6FragFails",
        "IPv6 fragmentation failures",
        "Locally generated IPv6 packets that could not be fragmented."
    ),
    network_counter!(
        "linux.socket.ipv6.fragments_created",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Ip6FragCreates",
        "IPv6 fragments created",
        "IPv6 output fragments created for locally generated packets."
    ),
    network_counter!(
        "linux.socket.icmp.input_messages",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Icmp.InMsgs",
        "ICMPv4 input messages",
        "ICMPv4 messages received by this network namespace."
    ),
    network_counter!(
        "linux.socket.icmp.input_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Icmp.InErrors",
        "ICMPv4 input errors",
        "ICMPv4 messages rejected while being processed."
    ),
    network_counter!(
        "linux.socket.icmp.input_checksum_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Icmp.InCsumErrors",
        "ICMPv4 checksum errors",
        "ICMPv4 input messages rejected for checksum errors."
    ),
    network_counter!(
        "linux.socket.icmp.input_destination_unreachable",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.InDestUnreachs",
        "ICMPv4 destination unreachable",
        "ICMPv4 destination-unreachable messages received across all codes."
    ),
    network_counter!(
        "linux.socket.icmp.input_time_exceeded",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.InTimeExcds",
        "ICMPv4 time exceeded",
        "ICMPv4 time-exceeded messages received."
    ),
    network_counter!(
        "linux.socket.icmp.input_redirects",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.InRedirects",
        "ICMPv4 redirects received",
        "ICMPv4 redirect messages received."
    ),
    network_counter!(
        "linux.socket.icmp.output_messages",
        Occurrences,
        Activity,
        "linux.proc.net.snmp",
        "Icmp.OutMsgs",
        "ICMPv4 output messages",
        "ICMPv4 messages generated by this network namespace."
    ),
    network_counter!(
        "linux.socket.icmp.output_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp",
        "Icmp.OutErrors",
        "ICMPv4 output errors",
        "Failures while generating ICMPv4 messages."
    ),
    network_counter!(
        "linux.socket.icmp.output_destination_unreachable",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.OutDestUnreachs",
        "ICMPv4 destination unreachable sent",
        "ICMPv4 destination-unreachable messages generated across all codes."
    ),
    network_counter!(
        "linux.socket.icmp.output_time_exceeded",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.OutTimeExcds",
        "ICMPv4 time exceeded sent",
        "ICMPv4 time-exceeded messages generated."
    ),
    network_counter!(
        "linux.socket.icmp.output_redirects",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp",
        "Icmp.OutRedirects",
        "ICMPv4 redirects sent",
        "ICMPv4 redirect messages generated."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_messages",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Icmp6InMsgs",
        "ICMPv6 input messages",
        "ICMPv6 messages received by this network namespace."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Icmp6InErrors",
        "ICMPv6 input errors",
        "ICMPv6 messages rejected while being processed."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_checksum_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Icmp6InCsumErrors",
        "ICMPv6 checksum errors",
        "ICMPv6 input messages rejected for checksum errors."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_destination_unreachable",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6InDestUnreachs",
        "ICMPv6 destination unreachable",
        "ICMPv6 destination-unreachable messages received across all codes."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_packet_too_big",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6InPktTooBigs",
        "ICMPv6 packet too big",
        "ICMPv6 Packet Too Big messages received for path-MTU discovery."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_time_exceeded",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6InTimeExcds",
        "ICMPv6 time exceeded",
        "ICMPv6 time-exceeded messages received."
    ),
    network_counter!(
        "linux.socket.icmpv6.input_redirects",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6InRedirects",
        "ICMPv6 redirects received",
        "ICMPv6 redirect messages received."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_messages",
        Occurrences,
        Activity,
        "linux.proc.net.snmp6",
        "Icmp6OutMsgs",
        "ICMPv6 output messages",
        "ICMPv6 messages generated by this network namespace."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_errors",
        Occurrences,
        Error,
        "linux.proc.net.snmp6",
        "Icmp6OutErrors",
        "ICMPv6 output errors",
        "Failures while generating ICMPv6 messages."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_destination_unreachable",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6OutDestUnreachs",
        "ICMPv6 destination unreachable sent",
        "ICMPv6 destination-unreachable messages generated across all codes."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_packet_too_big",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6OutPktTooBigs",
        "ICMPv6 packet too big sent",
        "ICMPv6 Packet Too Big messages generated."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_time_exceeded",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6OutTimeExcds",
        "ICMPv6 time exceeded sent",
        "ICMPv6 time-exceeded messages generated."
    ),
    network_counter!(
        "linux.socket.icmpv6.output_redirects",
        Occurrences,
        InformationOnly,
        "linux.proc.net.snmp6",
        "Icmp6OutRedirects",
        "ICMPv6 redirects sent",
        "ICMPv6 redirect messages generated."
    ),
    metric!(
        "linux.socket.udp6.datagrams_in",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6InDatagrams")],
        "UDPv6 datagrams in",
        "UDPv6 datagrams delivered to socket users in this namespace.",
        true
    ),
    metric!(
        "linux.socket.udp6.datagrams_out",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Activity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6OutDatagrams")],
        "UDPv6 datagrams out",
        "UDPv6 datagrams sent by this network namespace.",
        true
    ),
    metric!(
        "linux.socket.udp6.no_ports",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6NoPorts")],
        "UDPv6 no port",
        "UDPv6 datagrams for which no listening port was available.",
        false
    ),
    metric!(
        "linux.socket.udp6.input_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6InErrors")],
        "UDPv6 input errors",
        "UDPv6 input errors from the namespace protocol MIB.",
        true
    ),
    metric!(
        "linux.socket.udp6.receive_buffer_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Drop,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6RcvbufErrors")],
        "UDPv6 receive buffer errors",
        "UDPv6 datagrams rejected for receive-buffer pressure.",
        true
    ),
    metric!(
        "linux.socket.udp6.send_buffer_errors",
        Socket,
        Counter,
        Occurrences,
        NetworkNamespace,
        Datagram,
        NONE,
        Error,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.snmp6", "Udp6SndbufErrors")],
        "UDPv6 send buffer errors",
        "UDPv6 send attempts rejected for send-buffer pressure.",
        false
    ),
    metric!(
        "linux.socket.tcp6.in_use",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat6", "TCP6.inuse")],
        "TCPv6 sockets in use",
        "TCPv6 sockets currently in use according to sockstat6.",
        false
    ),
    metric!(
        "linux.socket.udp6.in_use",
        Socket,
        Gauge,
        Occurrences,
        NetworkNamespace,
        Socket,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.net.sockstat6", "UDP6.inuse")],
        "UDPv6 sockets in use",
        "UDPv6 sockets currently in use according to sockstat6.",
        false
    ),
    // Netfilter retains conntrack and rule semantics; a rule hit is not inferred to be a drop.
    metric!(
        "linux.netfilter.conntrack.count",
        Netfilter,
        Gauge,
        Occurrences,
        NetworkNamespace,
        ConntrackEntry,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!(
            "linux.proc.netfilter.conntrack",
            "nf_conntrack_count"
        )],
        "Conntrack count",
        "Current conntrack table entries.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.maximum",
        Netfilter,
        Gauge,
        Occurrences,
        NetworkNamespace,
        ConntrackEntry,
        NONE,
        Capacity,
        NO_LABELS,
        NO_LABELS,
        &[source!(
            "linux.proc.netfilter.conntrack",
            "nf_conntrack_max"
        )],
        "Conntrack maximum",
        "Configured conntrack entry limit.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.utilization",
        Netfilter,
        Gauge,
        BasisPoints,
        NetworkNamespace,
        ConntrackEntry,
        NONE,
        Pressure,
        NO_LABELS,
        NO_LABELS,
        &[source!(
            "linux.proc.netfilter.conntrack",
            "derived.count_over_max"
        )],
        "Conntrack utilization",
        "Conntrack count divided by maximum in basis points.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.found",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        ConntrackEntry,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "found")],
        "Conntrack found",
        "Conntrack lookup hits counted per CPU.",
        false
    ),
    metric!(
        "linux.netfilter.conntrack.invalid",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        IpPacket,
        SUM_CPU_TO_HOST,
        Error,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "invalid")],
        "Conntrack invalid",
        "Packets classified invalid by conntrack, counted per CPU.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.insert",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        ConntrackEntry,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "insert")],
        "Conntrack insert",
        "Conntrack entries inserted, counted per CPU.",
        false
    ),
    metric!(
        "linux.netfilter.conntrack.insert_failed",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        ConntrackEntry,
        SUM_CPU_TO_HOST,
        Error,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "insert_failed")],
        "Conntrack insert failed",
        "Conntrack insert attempts that failed.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.drop",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        IpPacket,
        SUM_CPU_TO_HOST,
        Drop,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "drop")],
        "Conntrack drops",
        "Packets explicitly counted as dropped by conntrack.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.early_drop",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        ConntrackEntry,
        SUM_CPU_TO_HOST,
        Pressure,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "early_drop")],
        "Conntrack early evictions",
        "Conntrack entries evicted early under table pressure.",
        true
    ),
    metric!(
        "linux.netfilter.conntrack.search_restart",
        Netfilter,
        Counter,
        Occurrences,
        Cpu,
        ConntrackEntry,
        SUM_CPU_TO_HOST,
        Pressure,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.netfilter.conntrack", "search_restart")],
        "Conntrack search restarts",
        "Conntrack hash searches restarted under contention.",
        true
    ),
    metric!(
        "linux.netfilter.chain.rules",
        Netfilter,
        Gauge,
        SourceUnits,
        Chain,
        SourceStatistic,
        NONE,
        InformationOnly,
        NETFILTER_CHAIN_REQUIRED,
        NETFILTER_CHAIN_ALLOWED,
        &[
            source!("linux.nft.ruleset", "chain.rules"),
            source!("linux.iptables.ipv4", "chain.rules"),
            source!("linux.iptables.ipv6", "chain.rules")
        ],
        "Chain rules",
        "Number of rules currently present in one Netfilter chain.",
        false
    ),
    state_metric!(
        "linux.netfilter.chain.policy",
        Netfilter,
        Chain,
        NETFILTER_CHAIN_REQUIRED,
        NETFILTER_CHAIN_ALLOWED,
        StateValuePolicy::Opaque,
        &[
            source!("linux.nft.ruleset", "chain.policy"),
            source!("linux.iptables.ipv4", "chain.policy"),
            source!("linux.iptables.ipv6", "chain.policy")
        ],
        "Chain policy",
        "Configured base-chain policy; this is inventory, not a policy-drop counter.",
        false
    ),
    state_metric!(
        "linux.netfilter.chain.type",
        Netfilter,
        Chain,
        NETFILTER_CHAIN_REQUIRED,
        NETFILTER_CHAIN_ALLOWED,
        StateValuePolicy::Opaque,
        &[
            source!("linux.nft.ruleset", "chain.type"),
            source!("linux.iptables.ipv4", "chain.type"),
            source!("linux.iptables.ipv6", "chain.type")
        ],
        "Chain type",
        "nftables base-chain type such as filter, nat, or route when provided.",
        false
    ),
    metric!(
        "linux.netfilter.rule.position",
        Netfilter,
        Gauge,
        SourceUnits,
        Rule,
        SourceStatistic,
        NONE,
        InformationOnly,
        NETFILTER_RULE_REQUIRED,
        NETFILTER_RULE_ALLOWED,
        &[
            source!("linux.nft.ruleset", "rule.position"),
            source!("linux.iptables.ipv4", "rule.position"),
            source!("linux.iptables.ipv6", "rule.position")
        ],
        "Rule position",
        "Current one-based position of a rule in its source chain.",
        false
    ),
    state_metric!(
        "linux.netfilter.rule.expression",
        Netfilter,
        Rule,
        NETFILTER_RULE_REQUIRED,
        NETFILTER_RULE_ALLOWED,
        StateValuePolicy::Opaque,
        &[
            source!("linux.nft.ruleset", "rule.expression"),
            source!("linux.iptables.ipv4", "rule.expression"),
            source!("linux.iptables.ipv6", "rule.expression")
        ],
        "Rule expression",
        "Bounded printable rule match/action summary from the structured source inventory.",
        false
    ),
    metric!(
        "linux.netfilter.rule.packets",
        Netfilter,
        Counter,
        Occurrences,
        Rule,
        PolicyHit,
        NONE,
        Activity,
        NETFILTER_RULE_REQUIRED,
        NETFILTER_RULE_ALLOWED,
        &[
            source!("linux.nft.ruleset", "rule.packets"),
            source!("linux.iptables.ipv4", "rule.packets"),
            source!("linux.iptables.ipv6", "rule.packets")
        ],
        "Rule packets",
        "Packets matching an nftables rule; verdict remains an explicit label.",
        true
    ),
    metric!(
        "linux.netfilter.rule.bytes",
        Netfilter,
        Counter,
        Bytes,
        Rule,
        PolicyHit,
        NONE,
        Activity,
        NETFILTER_RULE_REQUIRED,
        NETFILTER_RULE_ALLOWED,
        &[
            source!("linux.nft.ruleset", "rule.bytes"),
            source!("linux.iptables.ipv4", "rule.bytes"),
            source!("linux.iptables.ipv6", "rule.bytes")
        ],
        "Rule bytes",
        "Bytes matching an nftables rule in its source measurement domain.",
        false
    ),
    // Qdiscs retain separate accounting points; attachment metadata never implies a sum.
    metric!(
        "linux.tc.packets",
        Tc,
        Counter,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Activity,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.packets"),
            source!("linux.tc.json", "object.packets")
        ],
        "TC packets",
        "Packets processed by the named TC object class and hook.",
        true
    ),
    metric!(
        "linux.tc.bytes",
        Tc,
        Counter,
        Bytes,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Activity,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.bytes"),
            source!("linux.tc.json", "object.bytes")
        ],
        "TC bytes",
        "Bytes processed by the named TC object class and hook.",
        true
    ),
    metric!(
        "linux.tc.drops",
        Tc,
        Counter,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Drop,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.drops"),
            source!("linux.tc.json", "object.drops")
        ],
        "TC drops",
        "Packets explicitly reported dropped by a qdisc or action.",
        true
    ),
    metric!(
        "linux.tc.overlimits",
        Tc,
        Counter,
        Occurrences,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Pressure,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.overlimits"),
            source!("linux.tc.json", "object.overlimits")
        ],
        "TC overlimits",
        "TC overlimit events; these are pressure, not necessarily drops.",
        true
    ),
    metric!(
        "linux.tc.requeues",
        Tc,
        Counter,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Pressure,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.requeues"),
            source!("linux.tc.json", "object.requeues")
        ],
        "TC requeues",
        "Packets requeued by traffic control.",
        true
    ),
    metric!(
        "linux.tc.backlog_packets",
        Tc,
        Gauge,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Pressure,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.backlog_packets"),
            source!("linux.tc.json", "object.qlen")
        ],
        "TC backlog packets",
        "Packets currently queued in the traffic-control object.",
        true
    ),
    metric!(
        "linux.tc.backlog_bytes",
        Tc,
        Gauge,
        Bytes,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Pressure,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.backlog_bytes"),
            source!("linux.tc.json", "object.backlog")
        ],
        "TC backlog bytes",
        "Bytes currently queued in the traffic-control object.",
        true
    ),
    metric!(
        "linux.tc.max_packet_bytes",
        Tc,
        Gauge,
        Bytes,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        InformationOnly,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.maxpacket"),
            source!("linux.tc.json", "object.maxpacket")
        ],
        "TC maximum packet",
        "Largest packet observed by a qdisc that exports the maxpacket statistic.",
        false
    ),
    metric!(
        "linux.tc.drop_overlimit",
        Tc,
        Counter,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Drop,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.drop_overlimit"),
            source!("linux.tc.json", "object.drop_overlimit")
        ],
        "TC overlimit drops",
        "Packets dropped when a qdisc-specific queue limit was reached.",
        false
    ),
    metric!(
        "linux.tc.new_flow_count",
        Tc,
        Counter,
        Occurrences,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Activity,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.new_flow_count"),
            source!("linux.tc.json", "object.new_flow_count")
        ],
        "TC new-flow events",
        "Packets that caused a qdisc to activate a new flow.",
        false
    ),
    metric!(
        "linux.tc.ecn_marks",
        Tc,
        Counter,
        SourceUnits,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Pressure,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.ecn_mark"),
            source!("linux.tc.json", "object.ecn_mark")
        ],
        "TC ECN marks",
        "Packets marked with ECN by a qdisc instead of being dropped.",
        false
    ),
    metric!(
        "linux.tc.new_flows_len",
        Tc,
        Gauge,
        Occurrences,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Activity,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.new_flows_len"),
            source!("linux.tc.json", "object.new_flows_len")
        ],
        "TC new-flow list length",
        "Flows currently held in a qdisc's new-flow list.",
        false
    ),
    metric!(
        "linux.tc.old_flows_len",
        Tc,
        Gauge,
        Occurrences,
        TrafficControlObject,
        SourceStatistic,
        NONE,
        Activity,
        QDISC_LABELS,
        QDISC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "object.old_flows_len"),
            source!("linux.tc.json", "object.old_flows_len")
        ],
        "TC old-flow list length",
        "Flows currently held in a qdisc's old-flow list.",
        false
    ),
    metric!(
        "linux.tc.policy_hits",
        Tc,
        Counter,
        Occurrences,
        TrafficControlObject,
        PolicyHit,
        NONE,
        Activity,
        TC_LABELS,
        TC_ALLOWED,
        &[
            source!("linux.rtnetlink.tc", "policy.hits"),
            source!("linux.tc.json", "policy.hits")
        ],
        "TC policy hits",
        "Filter or action hits without inferring a drop verdict.",
        false
    ),
    // Generic interface counters own their raw fields exactly once.
    metric!(
        "linux.netdevice.rx_packets",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_packets"),
            source!("linux.sysfs.net.statistics", "rx_packets"),
            source!("linux.proc.net.dev", "rx_packets")
        ],
        "RX packets",
        "Packets received by the kernel network device.",
        true
    ),
    metric!(
        "linux.netdevice.tx_packets",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_packets"),
            source!("linux.sysfs.net.statistics", "tx_packets"),
            source!("linux.proc.net.dev", "tx_packets")
        ],
        "TX packets",
        "Packets transmitted by the kernel network device.",
        true
    ),
    metric!(
        "linux.netdevice.rx_bytes",
        Netdevice,
        Counter,
        Bytes,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_bytes"),
            source!("linux.sysfs.net.statistics", "rx_bytes"),
            source!("linux.proc.net.dev", "rx_bytes")
        ],
        "RX bytes",
        "Bytes received by the kernel network device.",
        true
    ),
    metric!(
        "linux.netdevice.tx_bytes",
        Netdevice,
        Counter,
        Bytes,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_bytes"),
            source!("linux.sysfs.net.statistics", "tx_bytes"),
            source!("linux.proc.net.dev", "tx_bytes")
        ],
        "TX bytes",
        "Bytes transmitted by the kernel network device.",
        true
    ),
    metric!(
        "linux.netdevice.rx_errors",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_errors"),
            source!("linux.sysfs.net.statistics", "rx_errors"),
            source!("linux.proc.net.dev", "rx_errors")
        ],
        "RX errors",
        "Generic receive errors reported for the network device.",
        true
    ),
    metric!(
        "linux.netdevice.tx_errors",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_errors"),
            source!("linux.sysfs.net.statistics", "tx_errors"),
            source!("linux.proc.net.dev", "tx_errors")
        ],
        "TX errors",
        "Generic transmit errors reported for the network device.",
        true
    ),
    metric!(
        "linux.netdevice.rx_dropped",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_dropped"),
            source!("linux.sysfs.net.statistics", "rx_dropped")
        ],
        "RX dropped",
        "Packets explicitly counted as receive drops by the network device.",
        true
    ),
    metric!(
        "linux.netdevice.tx_dropped",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_dropped"),
            source!("linux.sysfs.net.statistics", "tx_dropped"),
            source!("linux.proc.net.dev", "tx_dropped")
        ],
        "TX dropped",
        "Packets explicitly counted as transmit drops by the network device.",
        true
    ),
    metric!(
        "linux.netdevice.multicast",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "multicast"),
            source!("linux.sysfs.net.statistics", "multicast"),
            source!("linux.proc.net.dev", "rx_multicast")
        ],
        "Multicast received",
        "Multicast packets received by the network device.",
        false
    ),
    metric!(
        "linux.netdevice.rx_compressed",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_compressed"),
            source!("linux.sysfs.net.statistics", "rx_compressed"),
            source!("linux.proc.net.dev", "rx_compressed")
        ],
        "RX compressed packets",
        "Compressed packets received by interfaces that support packet compression.",
        false
    ),
    metric!(
        "linux.netdevice.tx_compressed",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Activity,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_compressed"),
            source!("linux.sysfs.net.statistics", "tx_compressed"),
            source!("linux.proc.net.dev", "tx_compressed")
        ],
        "TX compressed packets",
        "Compressed packets transmitted by interfaces that support packet compression.",
        false
    ),
    metric!(
        "linux.netdevice.rx_nohandler",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_nohandler"),
            source!("linux.sysfs.net.statistics", "rx_nohandler")
        ],
        "RX no handler",
        "Received packets for which the device path found no protocol handler.",
        false
    ),
    metric!(
        "linux.netdevice.rx_otherhost_dropped",
        Netdevice,
        Counter,
        Occurrences,
        Interface,
        InterfacePacket,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_otherhost_dropped"),
            source!("linux.sysfs.net.statistics", "rx_otherhost_dropped")
        ],
        "RX other-host dropped",
        "Packets for another host dropped by the receive path.",
        false
    ),
    // NIC owns hardware-oriented generic fields and standard ethtool statistics.
    metric!(
        "linux.nic.rx_length_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_length_errors"),
            source!("linux.sysfs.net.statistics", "rx_length_errors")
        ],
        "RX length errors",
        "Receive frame length errors reported for the interface.",
        false
    ),
    metric!(
        "linux.nic.rx_over_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_over_errors"),
            source!("linux.sysfs.net.statistics", "rx_over_errors")
        ],
        "RX overrun errors",
        "Receive overrun errors reported for the interface.",
        false
    ),
    metric!(
        "linux.nic.rx_crc_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_crc_errors"),
            source!("linux.sysfs.net.statistics", "rx_crc_errors")
        ],
        "RX CRC errors",
        "Receive frames with verified CRC errors.",
        true
    ),
    metric!(
        "linux.nic.rx_frame_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_frame_errors"),
            source!("linux.sysfs.net.statistics", "rx_frame_errors")
        ],
        "RX frame errors",
        "Receive frame alignment or framing errors.",
        true
    ),
    metric!(
        "linux.nic.rx_fifo_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_fifo_errors"),
            source!("linux.sysfs.net.statistics", "rx_fifo_errors"),
            source!("linux.proc.net.dev", "rx_fifo_errors")
        ],
        "RX FIFO errors",
        "Receive FIFO errors reported by the interface statistics source.",
        true
    ),
    metric!(
        "linux.nic.rx_missed_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "rx_missed_errors"),
            source!("linux.sysfs.net.statistics", "rx_missed_errors")
        ],
        "RX missed errors",
        "Frames missed by the receive device or driver.",
        true
    ),
    metric!(
        "linux.nic.tx_aborted_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_aborted_errors"),
            source!("linux.sysfs.net.statistics", "tx_aborted_errors")
        ],
        "TX aborted errors",
        "Transmit attempts aborted by the interface.",
        false
    ),
    metric!(
        "linux.nic.tx_carrier_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_carrier_errors"),
            source!("linux.sysfs.net.statistics", "tx_carrier_errors")
        ],
        "TX carrier errors",
        "Transmit carrier errors reported by the interface.",
        true
    ),
    metric!(
        "linux.nic.tx_fifo_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_fifo_errors"),
            source!("linux.sysfs.net.statistics", "tx_fifo_errors"),
            source!("linux.proc.net.dev", "tx_fifo_errors")
        ],
        "TX FIFO errors",
        "Transmit FIFO errors reported by the interface statistics source.",
        true
    ),
    metric!(
        "linux.nic.tx_heartbeat_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_heartbeat_errors"),
            source!("linux.sysfs.net.statistics", "tx_heartbeat_errors")
        ],
        "TX heartbeat errors",
        "Transmit heartbeat errors reported by the interface.",
        false
    ),
    metric!(
        "linux.nic.tx_window_errors",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "tx_window_errors"),
            source!("linux.sysfs.net.statistics", "tx_window_errors")
        ],
        "TX window errors",
        "Transmit window errors reported by the interface.",
        false
    ),
    metric!(
        "linux.nic.collisions",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "collisions"),
            source!("linux.sysfs.net.statistics", "collisions"),
            source!("linux.proc.net.dev", "collisions")
        ],
        "Collisions",
        "Link-layer collisions reported by the interface.",
        false
    ),
    metric!(
        "linux.nic.carrier_changes",
        Nic,
        Counter,
        Occurrences,
        Interface,
        SourceStatistic,
        NONE,
        Pressure,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.rtnetlink.link_stats", "carrier_changes"),
            source!("linux.sysfs.net.statistics", "carrier_changes")
        ],
        "Carrier changes",
        "Link carrier transitions reported for the interface.",
        false
    ),
    metric!(
        "linux.nic.pause.rx_frames",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Pressure,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "pause.rx_frames"),
            source!("linux.ethtool.json", "pause.rx_frames")
        ],
        "RX pause frames",
        "Received Ethernet pause frames from standard ethtool statistics.",
        true
    ),
    metric!(
        "linux.nic.pause.tx_frames",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Pressure,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "pause.tx_frames"),
            source!("linux.ethtool.json", "pause.tx_frames")
        ],
        "TX pause frames",
        "Transmitted Ethernet pause frames from standard ethtool statistics.",
        true
    ),
    metric!(
        "linux.nic.fec.corrected",
        Nic,
        Counter,
        Occurrences,
        Interface,
        FecCodeword,
        NONE,
        Correction,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "fec.corrected"),
            source!("linux.ethtool.json", "fec.corrected")
        ],
        "FEC corrected",
        "FEC codewords corrected by the link hardware.",
        true
    ),
    metric!(
        "linux.nic.fec.uncorrectable",
        Nic,
        Counter,
        Occurrences,
        Interface,
        FecCodeword,
        NONE,
        Error,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "fec.uncorrectable"),
            source!("linux.ethtool.json", "fec.uncorrectable")
        ],
        "FEC uncorrectable",
        "FEC codewords the link hardware could not correct.",
        true
    ),
    MetricDescriptor {
        id: "linux.nic.interface_kind",
        primary_section: CollectionSection::Nic,
        owner: owner_for_section(CollectionSection::Nic),
        kind: MetricKind::State,
        unit: MetricUnit::State,
        scope: MetricScope::Interface,
        domain: AggregationDomain::SourceStatistic,
        aggregation: AggregationPolicy::None,
        display: DisplayMeaning::InformationOnly,
        required_labels: INTERFACE_IDENTITY_REQUIRED,
        allowed_labels: INTERFACE_ALLOWED,
        state_values: StateValuePolicy::Closed(INTERFACE_KINDS),
        sources: &[source!("linux.sysfs.net.nic", "interface.kind")],
        title: "Interface kind",
        description:
            "Physical or virtual interface classification from the sysfs device relationship.",
        minimum: false,
    },
    MetricDescriptor {
        id: NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
        primary_section: CollectionSection::Nic,
        owner: owner_for_section(CollectionSection::Nic),
        kind: MetricKind::State,
        unit: MetricUnit::State,
        scope: MetricScope::Interface,
        domain: AggregationDomain::SourceStatistic,
        aggregation: AggregationPolicy::None,
        display: DisplayMeaning::State,
        required_labels: INTERFACE_IDENTITY_REQUIRED,
        allowed_labels: INTERFACE_ALLOWED,
        state_values: StateValuePolicy::Closed(ETHTOOL_COLLECTION_STATUSES),
        sources: &[source!("linux.ethtool.link_text", "collection.status")],
        title: "ethtool settings status",
        description: "Per-interface outcome of the bounded ordinary-ethtool settings attempt.",
        minimum: false,
    },
    MetricDescriptor {
        id: NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
        primary_section: CollectionSection::Nic,
        owner: owner_for_section(CollectionSection::Nic),
        kind: MetricKind::State,
        unit: MetricUnit::State,
        scope: MetricScope::Interface,
        domain: AggregationDomain::SourceStatistic,
        aggregation: AggregationPolicy::None,
        display: DisplayMeaning::State,
        required_labels: INTERFACE_IDENTITY_REQUIRED,
        allowed_labels: INTERFACE_ALLOWED,
        state_values: StateValuePolicy::Closed(ETHTOOL_COLLECTION_STATUSES),
        sources: &[source!("linux.ethtool.text", "collection.status")],
        title: "ethtool statistics status",
        description: "Per-interface outcome of the bounded ethtool statistics attempt.",
        minimum: false,
    },
    state_metric!(
        "linux.nic.link_state",
        Nic,
        Interface,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        StateValuePolicy::Closed(LINK_STATES),
        &[
            source!("linux.ethtool.netlink", "link.state"),
            source!("linux.ethtool.json", "link.state"),
            source!("linux.sysfs.net.nic", "link.state")
        ],
        "Link state",
        "Current link state from a structured ethtool source.",
        true
    ),
    metric!(
        "linux.nic.mtu",
        Nic,
        Gauge,
        Bytes,
        Interface,
        SourceStatistic,
        NONE,
        InformationOnly,
        INTERFACE_IDENTITY_REQUIRED,
        INTERFACE_ALLOWED,
        &[source!("linux.sysfs.net.nic", "mtu")],
        "MTU",
        "Current interface maximum transmission unit in bytes, from the shared link inventory or sysfs fallback.",
        false
    ),
    MetricDescriptor {
        id: "linux.nic.setting",
        primary_section: CollectionSection::Nic,
        owner: owner_for_section(CollectionSection::Nic),
        kind: MetricKind::State,
        unit: MetricUnit::State,
        scope: MetricScope::Source,
        domain: AggregationDomain::SourceStatistic,
        aggregation: AggregationPolicy::None,
        display: DisplayMeaning::InformationOnly,
        required_labels: RAW_PRIVATE_REQUIRED,
        allowed_labels: RAW_PRIVATE_ALLOWED,
        state_values: StateValuePolicy::Opaque,
        sources: &[
            source!("linux.ethtool.link_text", "setting.*"),
            source!("linux.sysfs.net.nic", "setting.*")
        ],
        title: "NIC setting",
        description: "Current opaque interface setting reported by its source; no counter semantics are inferred.",
        minimum: false,
    },
    metric!(
        "linux.nic.ring_drops",
        Nic,
        Counter,
        Occurrences,
        Interface,
        WireFrame,
        NONE,
        Drop,
        INTERFACE_REQUIRED,
        INTERFACE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "ring.verified_drops"),
            source!("linux.ethtool.json", "ring.verified_drops")
        ],
        "Ring drops",
        "Verified queue statistics aggregated across hardware queues.",
        false
    ),
    metric!(
        "linux.nic.raw_private",
        Nic,
        Gauge,
        SourceUnits,
        Source,
        SourceStatistic,
        NONE,
        InformationOnly,
        RAW_PRIVATE_REQUIRED,
        RAW_PRIVATE_ALLOWED,
        &[
            source!("linux.ethtool.netlink", "raw_private.*"),
            source!("linux.ethtool.json", "raw_private.*"),
            source!("linux.ethtool.text", "raw_private.*")
        ],
        "Raw private statistic",
        "Unclassified driver statistic in source units; no rate or drop meaning is inferred.",
        false
    ),
    // SoftIRQ rows are per CPU and may only be reduced across the CPU label.
    metric!(
        "linux.softirq.net_rx",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        Interrupt,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.softirqs", "NET_RX")],
        "NET_RX softirq",
        "NET_RX softirq executions per CPU.",
        true
    ),
    metric!(
        "linux.softirq.net_tx",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        Interrupt,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.softirqs", "NET_TX")],
        "NET_TX softirq",
        "NET_TX softirq executions per CPU.",
        true
    ),
    metric!(
        "linux.softirq.softnet.processed",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        InterfacePacket,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "processed")],
        "Softnet processed",
        "Packets processed by softnet on each CPU.",
        true
    ),
    metric!(
        "linux.softirq.softnet.dropped",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        InterfacePacket,
        SUM_CPU_TO_HOST,
        Drop,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "dropped")],
        "Softnet dropped",
        "Packets explicitly dropped from the per-CPU softnet backlog.",
        true
    ),
    metric!(
        "linux.softirq.softnet.time_squeeze",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        PollCycle,
        SUM_CPU_TO_HOST,
        Pressure,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "time_squeeze")],
        "Softnet time squeeze",
        "Softnet poll loops that exhausted their processing budget; not a drop count.",
        true
    ),
    metric!(
        "linux.softirq.softnet.received_rps",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        Interrupt,
        SUM_CPU_TO_HOST,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "received_rps")],
        "RPS softirq/IPI triggers",
        "RPS softirq/IPI trigger occurrences received by each CPU; this is not a packet count.",
        false
    ),
    metric!(
        "linux.softirq.softnet.flow_limit",
        Softirq,
        Counter,
        Occurrences,
        Cpu,
        InterfacePacket,
        SUM_CPU_TO_HOST,
        Drop,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "flow_limit_count")],
        "Softnet flow limit",
        "Packets rejected by the per-CPU RPS flow limit.",
        false
    ),
    metric!(
        "linux.softirq.softnet.backlog_len",
        Softirq,
        Gauge,
        Occurrences,
        Cpu,
        QueueEntry,
        NONE,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "backlog_len")],
        "Softnet backlog length",
        "Current per-CPU softnet input and process queue length.",
        false
    ),
    metric!(
        "linux.softirq.softnet.input_qlen",
        Softirq,
        Gauge,
        Occurrences,
        Cpu,
        QueueEntry,
        NONE,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "input_qlen")],
        "Softnet input queue length",
        "Current per-CPU softnet input_pkt_queue length.",
        false
    ),
    metric!(
        "linux.softirq.softnet.process_qlen",
        Softirq,
        Gauge,
        Occurrences,
        Cpu,
        QueueEntry,
        NONE,
        Activity,
        CPU_LABEL,
        CPU_LABEL,
        &[source!("linux.proc.net.softnet_stat", "process_qlen")],
        "Softnet process queue length",
        "Current per-CPU softnet process_queue length.",
        false
    ),
    metric!(
        "linux.softirq.config.netdev_budget",
        Softirq,
        Gauge,
        Occurrences,
        Host,
        PollCycle,
        NONE,
        InformationOnly,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.sys.net.core", "netdev_budget")],
        "SoftIRQ packet budget",
        "Maximum packets processed across NAPI polls in one SoftIRQ cycle.",
        false
    ),
    metric!(
        "linux.softirq.config.netdev_budget_usecs",
        Softirq,
        Gauge,
        SourceUnits,
        Host,
        PollCycle,
        NONE,
        InformationOnly,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.sys.net.core", "netdev_budget_usecs")],
        "SoftIRQ time budget",
        "Maximum microseconds spent across NAPI polls in one SoftIRQ cycle.",
        false
    ),
    metric!(
        "linux.softirq.config.dev_weight",
        Softirq,
        Gauge,
        Occurrences,
        Host,
        PollCycle,
        NONE,
        InformationOnly,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.sys.net.core", "dev_weight")],
        "Softnet backlog weight",
        "Base packet-processing weight for per-CPU softnet backlog work.",
        false
    ),
    metric!(
        "linux.softirq.config.netdev_max_backlog",
        Softirq,
        Gauge,
        Occurrences,
        Host,
        QueueEntry,
        NONE,
        InformationOnly,
        NO_LABELS,
        NO_LABELS,
        &[source!("linux.proc.sys.net.core", "netdev_max_backlog")],
        "Softnet maximum backlog",
        "Maximum packets queued on a per-CPU input backlog.",
        false
    ),
    // Raw IRQ identity is retained only in the live table, outside metric labels.
    metric!(
        "linux.hardirq.interface_interrupts", Hardirq, Counter, Occurrences,
        Interface, Interrupt, NONE, Activity, HARDIRQ_INTERFACE, INTERFACE_ALLOWED,
        &[source!("linux.proc.interrupts", "interface_interrupts")],
        "Network hard IRQ total",
        "Network-device interrupts summed across CPUs when compact summaries are required.",
        true
    ),
    metric!(
        "linux.hardirq.network_interrupts",
        Hardirq,
        Counter,
        Occurrences,
        Cpu,
        Interrupt,
        SUM_CPU_TO_HOST,
        Activity,
        HARDIRQ_REQUIRED,
        HARDIRQ_ALLOWED,
        &[source!("linux.proc.interrupts", "network_interrupts")],
        "Network hard IRQ",
        "Network-device interrupt executions per CPU using verified device mapping.",
        true
    ),
    metric!(
        "linux.hardirq.imbalance",
        Hardirq,
        Gauge,
        BasisPoints,
        Interface,
        Interrupt,
        NONE,
        Pressure,
        HARDIRQ_INTERFACE,
        INTERFACE_ALLOWED,
        &[source!("linux.proc.interrupts", "derived.cpu_imbalance")],
        "Hard IRQ imbalance",
        "Per-interface CPU interrupt imbalance in basis points.",
        true
    ),
    state_metric!(
        "linux.hardirq.affinity",
        Hardirq,
        Interface,
        HARDIRQ_INTERFACE,
        INTERFACE_ALLOWED,
        StateValuePolicy::CpuList,
        &[source!("linux.proc.interrupts", "derived.affinity_cpulist")],
        "Hard IRQ affinity",
        "Aggregated CPU affinity list without raw IRQ or vector identity.",
        true
    ),
];

pub fn metric_catalog() -> &'static [MetricDescriptor] {
    METRICS
}

pub fn descriptor(id: &str) -> Option<&'static MetricDescriptor> {
    static BY_ID: LazyLock<HashMap<&'static str, &'static MetricDescriptor>> =
        LazyLock::new(|| METRICS.iter().map(|metric| (metric.id, metric)).collect());
    BY_ID.get(id).copied()
}

pub fn minimum_descriptors(
    section: CollectionSection,
) -> impl Iterator<Item = &'static MetricDescriptor> {
    METRICS
        .iter()
        .filter(move |descriptor| descriptor.primary_section == section && descriptor.minimum)
}

pub fn validate_catalog() -> Result<(), MonitorValidationError> {
    let mut metric_ids = BTreeSet::new();
    let mut source_metrics = BTreeSet::new();
    let mut minimum_sections = BTreeSet::new();

    for descriptor in METRICS {
        MetricId::new(descriptor.id)?;
        ProviderId::new(descriptor.owner)?;
        if descriptor.owner != owner_for_section(descriptor.primary_section) {
            return Err(MonitorValidationError::InvalidCatalog);
        }
        if !metric_ids.insert(descriptor.id) {
            return Err(MonitorValidationError::DuplicateCatalogMetric);
        }
        if descriptor.sources.is_empty()
            || descriptor.sources.len() > MAX_LABELS_PER_READING
            || descriptor.title.is_empty()
            || descriptor.title.len() > MAX_ID_BYTES
            || descriptor.description.is_empty()
            || descriptor.description.len() > MAX_DIAGNOSTIC_BYTES
            || !descriptor.title.is_ascii()
            || !descriptor.description.is_ascii()
            || descriptor.allowed_labels.len() > MAX_LABELS_PER_READING
        {
            return Err(MonitorValidationError::InvalidCatalog);
        }
        validate_unique_labels(descriptor.required_labels)?;
        validate_unique_labels(descriptor.allowed_labels)?;
        if descriptor
            .required_labels
            .iter()
            .any(|label| !descriptor.allowed_labels.contains(label))
        {
            return Err(MonitorValidationError::InvalidCatalog);
        }
        validate_descriptor_shape(descriptor)?;
        let mut descriptor_sources = BTreeSet::new();
        for source in descriptor.sources {
            ProviderId::new(source.provider)?;
            if source.raw_metric.is_empty()
                || source.raw_metric.len() > MAX_ID_BYTES
                || !source.raw_metric.is_ascii()
            {
                return Err(MonitorValidationError::InvalidCatalog);
            }
            if !descriptor_sources.insert(source.provider) {
                return Err(MonitorValidationError::InvalidCatalog);
            }
            if !source_metrics.insert((source.provider, source.raw_metric)) {
                return Err(MonitorValidationError::DuplicateCatalogSource);
            }
        }
        if descriptor.minimum {
            minimum_sections.insert(descriptor.primary_section);
        }
    }

    if CollectionSection::ALL
        .iter()
        .any(|section| !minimum_sections.contains(section))
    {
        return Err(MonitorValidationError::MissingCatalogSection);
    }
    Ok(())
}

fn validate_unique_labels(labels: &[MetricLabel]) -> Result<(), MonitorValidationError> {
    let unique: BTreeSet<_> = labels.iter().copied().collect();
    if unique.len() == labels.len() {
        Ok(())
    } else {
        Err(MonitorValidationError::InvalidCatalog)
    }
}

fn validate_descriptor_shape(descriptor: &MetricDescriptor) -> Result<(), MonitorValidationError> {
    match (descriptor.kind, descriptor.unit, descriptor.state_values) {
        (MetricKind::State, MetricUnit::State, StateValuePolicy::Closed(values))
            if !values.is_empty()
                && values
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= MAX_ID_BYTES) => {}
        (MetricKind::State, MetricUnit::State, StateValuePolicy::CpuList) => {}
        (MetricKind::State, MetricUnit::State, StateValuePolicy::Opaque) => {}
        (MetricKind::Counter | MetricKind::Gauge, unit, StateValuePolicy::NotApplicable)
            if unit != MetricUnit::State => {}
        _ => return Err(MonitorValidationError::InvalidCatalog),
    }
    match descriptor.aggregation {
        AggregationPolicy::None => {}
        AggregationPolicy::Sum {
            target_scope,
            reducible_labels,
        } if descriptor.kind == MetricKind::Counter
            && target_scope != descriptor.scope
            && !reducible_labels.is_empty()
            && reducible_labels
                .iter()
                .all(|label| descriptor.required_labels.contains(label)) => {}
        AggregationPolicy::Sum { .. } => return Err(MonitorValidationError::InvalidAggregation),
    }
    if descriptor.id == RAW_PRIVATE_NIC_METRIC_ID
        && !(descriptor.primary_section == CollectionSection::Nic
            && descriptor.kind == MetricKind::Gauge
            && descriptor.unit == MetricUnit::SourceUnits
            && descriptor.scope == MetricScope::Source
            && descriptor.display == DisplayMeaning::InformationOnly
            && descriptor.aggregation == AggregationPolicy::None
            && descriptor.required_labels.contains(&MetricLabel::Statistic))
    {
        return Err(MonitorValidationError::InvalidCatalog);
    }
    Ok(())
}

pub(crate) fn validate_sample_reading(
    provider: &ProviderId,
    reading: &SampleReading,
) -> Result<(), MonitorValidationError> {
    let descriptor = reading
        .metric()
        .descriptor()
        .ok_or(MonitorValidationError::UnknownMetric)?;
    validate_identity(provider, descriptor, reading.labels())?;
    validate_sample_outcome(reading)
}

pub(crate) fn validate_sample_outcome(
    reading: &SampleReading,
) -> Result<(), MonitorValidationError> {
    let descriptor = reading
        .metric()
        .descriptor()
        .ok_or(MonitorValidationError::UnknownMetric)?;
    if let ReadingOutcome::Observed(value) = reading.outcome() {
        validate_kind_and_state(descriptor, value)?;
    }
    Ok(())
}

pub(crate) fn validate_series(
    owner: &ProviderId,
    source: &ProviderId,
    metric: &MetricId,
    labels: &MetricLabels,
    value: &SeriesValue,
) -> Result<(), MonitorValidationError> {
    let descriptor = metric
        .descriptor()
        .ok_or(MonitorValidationError::UnknownMetric)?;
    if owner.as_str() != descriptor.owner {
        return Err(MonitorValidationError::MetricOwnerMismatch);
    }
    validate_identity(source, descriptor, labels)?;
    validate_series_projection(metric, value)
}

pub(crate) fn validate_series_projection(
    metric: &MetricId,
    value: &SeriesValue,
) -> Result<(), MonitorValidationError> {
    let descriptor = metric
        .descriptor()
        .ok_or(MonitorValidationError::UnknownMetric)?;
    if value.kind() != descriptor.kind {
        return Err(MonitorValidationError::MetricKindMismatch);
    }
    if metric.as_str() == RAW_PRIVATE_NIC_METRIC_ID
        && !matches!(
            value,
            SeriesValue::Gauge {
                interval: None,
                since_baseline: None,
                ..
            }
        )
    {
        return Err(MonitorValidationError::InvalidSeriesProjection);
    }
    if let SeriesValue::State { current, .. } = value {
        match current {
            ProjectedValue::Fresh { value, .. } | ProjectedValue::Stale { last: value, .. } => {
                validate_state_value(descriptor.state_values, value)?;
            }
            ProjectedValue::Unavailable { .. } => {}
        }
    }
    Ok(())
}

fn validate_identity(
    provider: &ProviderId,
    descriptor: &MetricDescriptor,
    labels: &MetricLabels,
) -> Result<(), MonitorValidationError> {
    if !descriptor.source_is_allowed(provider) {
        return Err(MonitorValidationError::MetricSourceMismatch);
    }
    if !descriptor.labels_are_allowed(labels) {
        return Err(MonitorValidationError::MetricLabelsMismatch);
    }
    Ok(())
}

fn validate_kind_and_state(
    descriptor: &MetricDescriptor,
    reading: &MetricReading,
) -> Result<(), MonitorValidationError> {
    if descriptor.kind != reading.kind() {
        return Err(MonitorValidationError::MetricKindMismatch);
    }
    if let MetricReading::State(value) = reading {
        validate_state_value(descriptor.state_values, value)?;
    }
    Ok(())
}

fn validate_state_value(
    policy: StateValuePolicy,
    value: &StateValue,
) -> Result<(), MonitorValidationError> {
    let valid = match policy {
        StateValuePolicy::Closed(values) => values.contains(&value.as_str()),
        StateValuePolicy::CpuList => valid_cpu_list(value.as_str()),
        StateValuePolicy::Opaque => true,
        StateValuePolicy::NotApplicable => false,
    };
    if valid {
        Ok(())
    } else {
        Err(MonitorValidationError::InvalidStateValue)
    }
}

fn valid_cpu_list(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',' || byte == b'-')
        && value.split(',').all(|range| {
            let mut bounds = range.split('-');
            let Some(first) = bounds.next() else {
                return false;
            };
            let Some(first) = first.parse::<u32>().ok() else {
                return false;
            };
            match (bounds.next(), bounds.next()) {
                (None, None) => true,
                (Some(last), None) => last.parse::<u32>().is_ok_and(|last| first <= last),
                _ => false,
            }
        })
}

pub fn aggregation_compatible(
    left_provider: &ProviderId,
    left_metric: &MetricId,
    left_labels: &MetricLabels,
    right_provider: &ProviderId,
    right_metric: &MetricId,
    right_labels: &MetricLabels,
    target_scope: MetricScope,
) -> bool {
    left_provider == right_provider
        && left_metric == right_metric
        && descriptor(left_metric.as_str()).is_some_and(|descriptor| {
            descriptor.can_roll_up(left_labels, right_labels, target_scope)
        })
}
