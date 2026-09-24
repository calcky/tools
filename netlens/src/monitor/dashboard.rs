use std::collections::{BTreeMap, BTreeSet};

use crate::model::IfIndex;

use super::catalog::{descriptor, MetricDescriptor};
use super::model::{MetricLabel, MonitorSnapshot, SeriesSnapshot};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PacketStage {
    SocketApplication,
    Transport,
    NetworkRoute,
    NetfilterConntrack,
    TrafficControl,
    NetdeviceCore,
    DriverNapi,
    NicPhy,
}

impl PacketStage {
    pub const ALL: [Self; 8] = TX_PATH;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SocketApplication => "socket_application",
            Self::Transport => "transport",
            Self::NetworkRoute => "network_route",
            Self::NetfilterConntrack => "netfilter_conntrack",
            Self::TrafficControl => "traffic_control",
            Self::NetdeviceCore => "netdevice_core",
            Self::DriverNapi => "driver_napi",
            Self::NicPhy => "nic_phy",
        }
    }
}

pub const TX_PATH: [PacketStage; 8] = [
    PacketStage::SocketApplication,
    PacketStage::Transport,
    PacketStage::NetworkRoute,
    PacketStage::NetfilterConntrack,
    PacketStage::TrafficControl,
    PacketStage::NetdeviceCore,
    PacketStage::DriverNapi,
    PacketStage::NicPhy,
];

pub const RX_PATH: [PacketStage; 8] = [
    PacketStage::NicPhy,
    PacketStage::DriverNapi,
    PacketStage::NetdeviceCore,
    PacketStage::TrafficControl,
    PacketStage::NetfilterConntrack,
    PacketStage::NetworkRoute,
    PacketStage::Transport,
    PacketStage::SocketApplication,
];

pub fn paths_are_reverse(rx: &[PacketStage], tx: &[PacketStage]) -> bool {
    rx.len() == tx.len()
        && rx
            .iter()
            .zip(tx.iter().rev())
            .all(|(rx_stage, tx_stage)| rx_stage == tx_stage)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ExecutionContext {
    Softirq,
    Hardirq,
}

impl ExecutionContext {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Softirq => "softirq",
            Self::Hardirq => "hardirq",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BlockKind {
    PacketStage(PacketStage),
    ExecutionContext(ExecutionContext),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InterfaceIdentity {
    ifindex: IfIndex,
    name: String,
}

impl InterfaceIdentity {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn ifindex(&self) -> IfIndex {
        self.ifindex
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BlockScope {
    Global,
    Host,
    Interface(InterfaceIdentity),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockKey {
    scope: BlockScope,
    kind: BlockKind,
}

impl BlockKey {
    fn new(scope: BlockScope, kind: BlockKind) -> Self {
        Self { scope, kind }
    }

    pub fn scope(&self) -> &BlockScope {
        &self.scope
    }

    pub const fn kind(&self) -> BlockKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlacementScope {
    Global,
    Host,
    Interface,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    Rx,
    Tx,
    Shared,
    FromLabel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolvedLane {
    Rx,
    Tx,
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attribution {
    Exact,
    Aggregate,
    Boundary { stages: [PacketStage; 2] },
    Opaque,
}

impl Attribution {
    pub const fn boundary_stages(self) -> Option<[PacketStage; 2]> {
        match self {
            Self::Boundary { stages } => Some(stages),
            Self::Exact | Self::Aggregate | Self::Opaque => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplaySlot {
    Summary { rank: u16 },
    Detail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricPlacement {
    scope: PlacementScope,
    block_kind: BlockKind,
    lane: Lane,
    attribution: Attribution,
    display: DisplaySlot,
}

impl MetricPlacement {
    const fn new(
        scope: PlacementScope,
        block_kind: BlockKind,
        lane: Lane,
        attribution: Attribution,
        display: DisplaySlot,
    ) -> Self {
        Self {
            scope,
            block_kind,
            lane,
            attribution,
            display,
        }
    }

    pub const fn scope(self) -> PlacementScope {
        self.scope
    }

    pub const fn block_kind(self) -> BlockKind {
        self.block_kind
    }

    pub const fn lane(self) -> Lane {
        self.lane
    }

    pub const fn attribution(self) -> Attribution {
        self.attribution
    }

    pub const fn display(self) -> DisplaySlot {
        self.display
    }
}

const DETAIL: DisplaySlot = DisplaySlot::Detail;
const NETDEVICE_DRIVER_BOUNDARY: Attribution = Attribution::Boundary {
    stages: [PacketStage::NetdeviceCore, PacketStage::DriverNapi],
};
const DRIVER_NIC_BOUNDARY: Attribution = Attribution::Boundary {
    stages: [PacketStage::DriverNapi, PacketStage::NicPhy],
};

const fn summary(rank: u16) -> DisplaySlot {
    DisplaySlot::Summary { rank }
}

const fn packet(
    scope: PlacementScope,
    stage: PacketStage,
    lane: Lane,
    attribution: Attribution,
    display: DisplaySlot,
) -> MetricPlacement {
    MetricPlacement::new(
        scope,
        BlockKind::PacketStage(stage),
        lane,
        attribution,
        display,
    )
}

const fn context(
    scope: PlacementScope,
    execution: ExecutionContext,
    lane: Lane,
    attribution: Attribution,
    display: DisplaySlot,
) -> MetricPlacement {
    MetricPlacement::new(
        scope,
        BlockKind::ExecutionContext(execution),
        lane,
        attribution,
        display,
    )
}

pub fn placement_for(descriptor: &MetricDescriptor) -> Option<MetricPlacement> {
    use Attribution::{Aggregate, Exact, Opaque};
    use Lane::{FromLabel, Rx, Shared, Tx};
    use PacketStage::{
        DriverNapi, NetdeviceCore, NetfilterConntrack, NetworkRoute, NicPhy, SocketApplication,
        TrafficControl, Transport,
    };
    use PlacementScope::{Global, Host, Interface};

    let placement = match descriptor.id {
        "linux.socket.tcp.current_established" => {
            packet(Global, SocketApplication, Shared, Aggregate, summary(20))
        }
        "linux.socket.tcp.active_opens" => packet(Global, Transport, Tx, Aggregate, DETAIL),
        "linux.socket.tcp.passive_opens" => packet(Global, Transport, Rx, Aggregate, DETAIL),
        "linux.socket.tcp.failed_connection_attempts" => {
            packet(Global, Transport, Shared, Aggregate, DETAIL)
        }
        "linux.socket.tcp.established_resets" => {
            packet(Global, Transport, Shared, Aggregate, DETAIL)
        }
        "linux.socket.tcp.segments_in" => packet(Global, Transport, Rx, Aggregate, summary(10)),
        "linux.socket.tcp.segments_out" => packet(Global, Transport, Tx, Aggregate, summary(10)),
        "linux.socket.tcp.retransmitted_segments" => {
            packet(Global, Transport, Tx, Aggregate, summary(20))
        }
        "linux.socket.tcp.resets_out" => packet(Global, Transport, Tx, Aggregate, summary(30)),
        "linux.socket.tcp.listen_overflows" => {
            packet(Global, SocketApplication, Rx, Aggregate, summary(20))
        }
        "linux.socket.tcp.listen_drops" => {
            packet(Global, SocketApplication, Rx, Aggregate, summary(10))
        }
        "linux.socket.udp.datagrams_in" => packet(Global, Transport, Rx, Aggregate, summary(40)),
        "linux.socket.udp.datagrams_out" => packet(Global, Transport, Tx, Aggregate, summary(40)),
        "linux.socket.udp.no_ports" => packet(Global, Transport, Rx, Aggregate, summary(50)),
        "linux.socket.udp.input_errors" => packet(Global, Transport, Rx, Aggregate, summary(60)),
        "linux.socket.udp.receive_buffer_errors" => {
            packet(Global, SocketApplication, Rx, Aggregate, summary(30))
        }
        "linux.socket.udp.send_buffer_errors" => {
            packet(Global, SocketApplication, Tx, Aggregate, summary(30))
        }
        "linux.socket.ip.receives" => packet(Global, NetworkRoute, Rx, Aggregate, summary(10)),
        "linux.socket.ip.delivers" => packet(Global, NetworkRoute, Rx, Aggregate, summary(20)),
        "linux.socket.ip.output_requests" => {
            packet(Global, NetworkRoute, Tx, Aggregate, summary(10))
        }
        "linux.socket.ip.input_errors" => packet(Global, NetworkRoute, Rx, Aggregate, summary(30)),
        "linux.socket.ip.output_discards" => {
            packet(Global, NetworkRoute, Tx, Aggregate, summary(20))
        }
        "linux.socket.used" => packet(Global, SocketApplication, Shared, Aggregate, summary(10)),
        "linux.socket.tcp.in_use" => {
            packet(Global, SocketApplication, Shared, Aggregate, summary(30))
        }
        "linux.socket.tcp.orphaned" => packet(Global, SocketApplication, Shared, Aggregate, DETAIL),
        "linux.socket.tcp.time_wait" => {
            packet(Global, SocketApplication, Shared, Aggregate, DETAIL)
        }
        "linux.socket.tcp.allocated" => {
            packet(Global, SocketApplication, Shared, Aggregate, DETAIL)
        }
        "linux.socket.tcp.memory_pages" | "linux.socket.tcp.memory_max_pages" => {
            packet(Global, SocketApplication, Shared, Aggregate, summary(40))
        }
        "linux.socket.udp.in_use" => {
            packet(Global, SocketApplication, Shared, Aggregate, summary(50))
        }
        "linux.socket.udp.memory_pages" => {
            packet(Global, SocketApplication, Shared, Aggregate, DETAIL)
        }
        "linux.socket.tcp.timeouts" => packet(Global, Transport, Tx, Aggregate, DETAIL),
        "linux.socket.udp.checksum_errors" | "linux.socket.udp6.checksum_errors" => {
            packet(Global, Transport, Rx, Aggregate, DETAIL)
        }
        "linux.socket.icmp.input_echo_requests"
        | "linux.socket.icmp.input_echo_replies"
        | "linux.socket.icmpv6.input_echo_requests"
        | "linux.socket.icmpv6.input_echo_replies" => {
            packet(Global, NetworkRoute, Rx, Aggregate, DETAIL)
        }
        "linux.socket.icmp.output_echo_requests"
        | "linux.socket.icmp.output_echo_replies"
        | "linux.socket.icmpv6.output_echo_requests"
        | "linux.socket.icmpv6.output_echo_replies" => {
            packet(Global, NetworkRoute, Tx, Aggregate, DETAIL)
        }
        "linux.socket.ipv6.receives" => packet(Global, NetworkRoute, Rx, Aggregate, summary(11)),
        "linux.socket.ipv6.delivers" => packet(Global, NetworkRoute, Rx, Aggregate, summary(21)),
        "linux.socket.ipv6.output_requests" => {
            packet(Global, NetworkRoute, Tx, Aggregate, summary(11))
        }
        "linux.socket.ipv6.input_errors" => {
            packet(Global, NetworkRoute, Rx, Aggregate, summary(31))
        }
        "linux.socket.ipv6.output_discards" => {
            packet(Global, NetworkRoute, Tx, Aggregate, summary(21))
        }
        "linux.socket.ip.forwarded_datagrams" | "linux.socket.ipv6.forwarded_datagrams" => {
            packet(Global, NetworkRoute, Shared, Aggregate, DETAIL)
        }
        "linux.socket.ip.input_address_errors"
        | "linux.socket.ip.input_unknown_protocols"
        | "linux.socket.ip.input_discards"
        | "linux.socket.ip.input_no_routes"
        | "linux.socket.ip.input_truncated_packets"
        | "linux.socket.ip.input_checksum_errors"
        | "linux.socket.ip.input_octets"
        | "linux.socket.ip.reassembly_requests"
        | "linux.socket.ip.reassembly_successes"
        | "linux.socket.ip.reassembly_failures"
        | "linux.socket.ip.reassembly_timeouts"
        | "linux.socket.ipv6.input_too_big_errors"
        | "linux.socket.ipv6.input_no_routes"
        | "linux.socket.ipv6.input_address_errors"
        | "linux.socket.ipv6.input_unknown_protocols"
        | "linux.socket.ipv6.input_truncated_packets"
        | "linux.socket.ipv6.input_discards"
        | "linux.socket.ipv6.input_octets"
        | "linux.socket.ipv6.reassembly_requests"
        | "linux.socket.ipv6.reassembly_successes"
        | "linux.socket.ipv6.reassembly_failures"
        | "linux.socket.ipv6.reassembly_timeouts"
        | "linux.socket.icmp.input_messages"
        | "linux.socket.icmp.input_errors"
        | "linux.socket.icmp.input_checksum_errors"
        | "linux.socket.icmp.input_destination_unreachable"
        | "linux.socket.icmp.input_time_exceeded"
        | "linux.socket.icmp.input_redirects"
        | "linux.socket.icmpv6.input_messages"
        | "linux.socket.icmpv6.input_errors"
        | "linux.socket.icmpv6.input_checksum_errors"
        | "linux.socket.icmpv6.input_destination_unreachable"
        | "linux.socket.icmpv6.input_packet_too_big"
        | "linux.socket.icmpv6.input_time_exceeded"
        | "linux.socket.icmpv6.input_redirects" => {
            packet(Global, NetworkRoute, Rx, Aggregate, DETAIL)
        }
        "linux.socket.ip.output_no_routes"
        | "linux.socket.ip.output_octets"
        | "linux.socket.ip.fragmentation_successes"
        | "linux.socket.ip.fragmentation_failures"
        | "linux.socket.ip.fragments_created"
        | "linux.socket.ipv6.output_no_routes"
        | "linux.socket.ipv6.output_octets"
        | "linux.socket.ipv6.fragmentation_successes"
        | "linux.socket.ipv6.fragmentation_failures"
        | "linux.socket.ipv6.fragments_created"
        | "linux.socket.icmp.output_messages"
        | "linux.socket.icmp.output_errors"
        | "linux.socket.icmp.output_destination_unreachable"
        | "linux.socket.icmp.output_time_exceeded"
        | "linux.socket.icmp.output_redirects"
        | "linux.socket.icmpv6.output_messages"
        | "linux.socket.icmpv6.output_errors"
        | "linux.socket.icmpv6.output_destination_unreachable"
        | "linux.socket.icmpv6.output_packet_too_big"
        | "linux.socket.icmpv6.output_time_exceeded"
        | "linux.socket.icmpv6.output_redirects" => {
            packet(Global, NetworkRoute, Tx, Aggregate, DETAIL)
        }
        "linux.socket.udp6.datagrams_in" => packet(Global, Transport, Rx, Aggregate, DETAIL),
        "linux.socket.udp6.datagrams_out" => packet(Global, Transport, Tx, Aggregate, DETAIL),
        "linux.socket.udp6.no_ports" => packet(Global, Transport, Rx, Aggregate, DETAIL),
        "linux.socket.udp6.input_errors" => packet(Global, Transport, Rx, Aggregate, DETAIL),
        "linux.socket.udp6.receive_buffer_errors" => {
            packet(Global, SocketApplication, Rx, Aggregate, DETAIL)
        }
        "linux.socket.udp6.send_buffer_errors" => {
            packet(Global, SocketApplication, Tx, Aggregate, DETAIL)
        }
        "linux.socket.tcp6.in_use" => packet(Global, SocketApplication, Shared, Aggregate, DETAIL),
        "linux.socket.udp6.in_use" => packet(Global, SocketApplication, Shared, Aggregate, DETAIL),
        "linux.netfilter.conntrack.count" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(10))
        }
        "linux.netfilter.conntrack.maximum" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(20))
        }
        "linux.netfilter.conntrack.utilization" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(30))
        }
        "linux.netfilter.conntrack.found" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, DETAIL)
        }
        "linux.netfilter.conntrack.invalid" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(40))
        }
        "linux.netfilter.conntrack.insert" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, DETAIL)
        }
        "linux.netfilter.conntrack.insert_failed" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(50))
        }
        "linux.netfilter.conntrack.drop" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(60))
        }
        "linux.netfilter.conntrack.early_drop" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(70))
        }
        "linux.netfilter.conntrack.search_restart" => {
            packet(Global, NetfilterConntrack, Shared, Aggregate, summary(80))
        }
        "linux.netfilter.chain.rules"
        | "linux.netfilter.chain.policy"
        | "linux.netfilter.chain.type"
        | "linux.netfilter.rule.position"
        | "linux.netfilter.rule.expression"
        | "linux.netfilter.rule.packets"
        | "linux.netfilter.rule.bytes" => packet(Global, NetfilterConntrack, Shared, Exact, DETAIL),
        "linux.tc.packets" => packet(Interface, TrafficControl, FromLabel, Exact, summary(10)),
        "linux.tc.bytes" => packet(Interface, TrafficControl, FromLabel, Exact, summary(20)),
        "linux.tc.drops" => packet(Interface, TrafficControl, FromLabel, Exact, summary(30)),
        "linux.tc.overlimits" => packet(Interface, TrafficControl, FromLabel, Exact, summary(40)),
        "linux.tc.requeues" => packet(Interface, TrafficControl, FromLabel, Exact, summary(50)),
        "linux.tc.backlog_packets" => {
            packet(Interface, TrafficControl, FromLabel, Exact, summary(60))
        }
        "linux.tc.backlog_bytes" => {
            packet(Interface, TrafficControl, FromLabel, Exact, summary(70))
        }
        "linux.tc.max_packet_bytes"
        | "linux.tc.drop_overlimit"
        | "linux.tc.new_flow_count"
        | "linux.tc.ecn_marks"
        | "linux.tc.new_flows_len"
        | "linux.tc.old_flows_len" => packet(Interface, TrafficControl, FromLabel, Exact, DETAIL),
        "linux.tc.policy_hits" => packet(Interface, TrafficControl, FromLabel, Exact, DETAIL),
        "linux.netdevice.rx_packets" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(10),
        ),
        "linux.netdevice.tx_packets" => packet(
            Interface,
            NetdeviceCore,
            Tx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(10),
        ),
        "linux.netdevice.rx_bytes" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(20),
        ),
        "linux.netdevice.tx_bytes" => packet(
            Interface,
            NetdeviceCore,
            Tx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(20),
        ),
        "linux.netdevice.rx_errors" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(30),
        ),
        "linux.netdevice.tx_errors" => packet(
            Interface,
            NetdeviceCore,
            Tx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(30),
        ),
        "linux.netdevice.rx_dropped" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(40),
        ),
        "linux.netdevice.tx_dropped" => packet(
            Interface,
            NetdeviceCore,
            Tx,
            NETDEVICE_DRIVER_BOUNDARY,
            summary(40),
        ),
        "linux.netdevice.multicast" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            DETAIL,
        ),
        "linux.netdevice.rx_compressed" => packet(
            Interface,
            NetdeviceCore,
            Rx,
            NETDEVICE_DRIVER_BOUNDARY,
            DETAIL,
        ),
        "linux.netdevice.tx_compressed" => packet(
            Interface,
            NetdeviceCore,
            Tx,
            NETDEVICE_DRIVER_BOUNDARY,
            DETAIL,
        ),
        "linux.netdevice.rx_nohandler" => packet(Interface, NetdeviceCore, Rx, Exact, DETAIL),
        "linux.netdevice.rx_otherhost_dropped" => {
            packet(Interface, NetdeviceCore, Rx, Exact, DETAIL)
        }
        "linux.nic.rx_length_errors" => packet(Interface, NicPhy, Rx, Exact, DETAIL),
        "linux.nic.rx_over_errors" => {
            packet(Interface, DriverNapi, Rx, DRIVER_NIC_BOUNDARY, DETAIL)
        }
        "linux.nic.rx_crc_errors" => packet(Interface, NicPhy, Rx, Exact, summary(20)),
        "linux.nic.rx_frame_errors" => packet(Interface, NicPhy, Rx, Exact, DETAIL),
        "linux.nic.rx_fifo_errors" => {
            packet(Interface, DriverNapi, Rx, DRIVER_NIC_BOUNDARY, summary(20))
        }
        "linux.nic.rx_missed_errors" => {
            packet(Interface, DriverNapi, Rx, DRIVER_NIC_BOUNDARY, summary(30))
        }
        "linux.nic.tx_aborted_errors" => {
            packet(Interface, DriverNapi, Tx, DRIVER_NIC_BOUNDARY, DETAIL)
        }
        "linux.nic.tx_carrier_errors" => packet(Interface, NicPhy, Tx, Exact, summary(20)),
        "linux.nic.tx_fifo_errors" => {
            packet(Interface, DriverNapi, Tx, DRIVER_NIC_BOUNDARY, DETAIL)
        }
        "linux.nic.tx_heartbeat_errors" => packet(Interface, NicPhy, Tx, Exact, DETAIL),
        "linux.nic.tx_window_errors" => packet(Interface, NicPhy, Tx, Exact, DETAIL),
        "linux.nic.collisions" => packet(Interface, NicPhy, Tx, Exact, DETAIL),
        "linux.nic.carrier_changes" => packet(Interface, NicPhy, Shared, Exact, summary(20)),
        "linux.nic.pause.rx_frames" => packet(Interface, NicPhy, Rx, Exact, summary(10)),
        "linux.nic.pause.tx_frames" => packet(Interface, NicPhy, Tx, Exact, summary(10)),
        "linux.nic.fec.corrected" => packet(Interface, NicPhy, Shared, Exact, summary(30)),
        "linux.nic.fec.uncorrectable" => packet(Interface, NicPhy, Shared, Exact, summary(40)),
        "linux.nic.interface_kind" => packet(Interface, NicPhy, Shared, Exact, summary(5)),
        "linux.nic.ethtool_settings_status" => {
            packet(Interface, NicPhy, Shared, Opaque, summary(6))
        }
        "linux.nic.ethtool_statistics_status" => {
            packet(Interface, DriverNapi, Shared, Opaque, summary(5))
        }
        "linux.nic.link_state" => packet(Interface, NicPhy, Shared, Exact, summary(10)),
        "linux.nic.mtu" => packet(Interface, NetdeviceCore, Shared, Exact, DETAIL),
        "linux.nic.setting" => packet(Interface, NicPhy, Shared, Opaque, DETAIL),
        "linux.nic.ring_drops" => packet(Interface, DriverNapi, Shared, Aggregate, summary(10)),
        "linux.nic.raw_private" => packet(Interface, DriverNapi, Shared, Opaque, DETAIL),
        "linux.softirq.net_rx" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(10))
        }
        "linux.softirq.net_tx" => {
            context(Host, ExecutionContext::Softirq, Tx, Aggregate, summary(10))
        }
        "linux.softirq.softnet.processed" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(20))
        }
        "linux.softirq.softnet.dropped" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(30))
        }
        "linux.softirq.softnet.time_squeeze" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(40))
        }
        "linux.softirq.softnet.received_rps" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(50))
        }
        "linux.softirq.softnet.flow_limit" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(60))
        }
        "linux.softirq.softnet.backlog_len" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(70))
        }
        "linux.softirq.softnet.input_qlen" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(80))
        }
        "linux.softirq.softnet.process_qlen" => {
            context(Host, ExecutionContext::Softirq, Rx, Aggregate, summary(90))
        }
        "linux.softirq.config.netdev_budget"
        | "linux.softirq.config.netdev_budget_usecs"
        | "linux.softirq.config.dev_weight"
        | "linux.softirq.config.netdev_max_backlog" => {
            context(Host, ExecutionContext::Softirq, Shared, Exact, DETAIL)
        }
        "linux.hardirq.network_interrupts" | "linux.hardirq.interface_interrupts" => context(
            Interface,
            ExecutionContext::Hardirq,
            Shared,
            Aggregate,
            summary(10),
        ),
        "linux.hardirq.imbalance" => context(
            Interface,
            ExecutionContext::Hardirq,
            Shared,
            Aggregate,
            summary(20),
        ),
        "linux.hardirq.affinity" => context(
            Interface,
            ExecutionContext::Hardirq,
            Shared,
            Aggregate,
            summary(30),
        ),
        _ => return None,
    };
    Some(placement)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnplacedReason {
    UnknownMetric,
    MissingCatalogPlacement,
    MissingInterfaceName,
    MissingIfindex,
    InvalidIfindex,
    MissingDirection,
    InvalidDirection,
}

impl UnplacedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMetric => "unknown metric",
            Self::MissingCatalogPlacement => "metric has no dashboard placement",
            Self::MissingInterfaceName => "interface-scoped metric has no interface name",
            Self::MissingIfindex => "interface-scoped metric has no ifindex",
            Self::InvalidIfindex => "interface-scoped metric has an invalid ifindex",
            Self::MissingDirection => "directional metric has no direction label",
            Self::InvalidDirection => "directional metric has an invalid direction label",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlacedSeries<'a> {
    series: &'a SeriesSnapshot,
    placement: MetricPlacement,
}

impl<'a> PlacedSeries<'a> {
    pub const fn series(&self) -> &'a SeriesSnapshot {
        self.series
    }

    pub const fn placement(&self) -> MetricPlacement {
        self.placement
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnplacedSeries<'a> {
    series: &'a SeriesSnapshot,
    reason: UnplacedReason,
}

impl<'a> UnplacedSeries<'a> {
    pub const fn series(&self) -> &'a SeriesSnapshot {
        self.series
    }

    pub const fn reason(&self) -> UnplacedReason {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashboardBlock<'a> {
    key: BlockKey,
    rx: Vec<PlacedSeries<'a>>,
    tx: Vec<PlacedSeries<'a>>,
    shared: Vec<PlacedSeries<'a>>,
}

impl<'a> DashboardBlock<'a> {
    fn empty(key: BlockKey) -> Self {
        Self {
            key,
            rx: Vec::new(),
            tx: Vec::new(),
            shared: Vec::new(),
        }
    }

    fn push(&mut self, series: &'a SeriesSnapshot, placement: MetricPlacement, lane: ResolvedLane) {
        let placed = PlacedSeries { series, placement };
        match lane {
            ResolvedLane::Rx => self.rx.push(placed),
            ResolvedLane::Tx => self.tx.push(placed),
            ResolvedLane::Shared => self.shared.push(placed),
        }
    }

    fn sort_series(&mut self) {
        sort_placed(&mut self.rx);
        sort_placed(&mut self.tx);
        sort_placed(&mut self.shared);
    }

    pub fn key(&self) -> &BlockKey {
        &self.key
    }

    pub fn rx(&self) -> &[PlacedSeries<'a>] {
        &self.rx
    }

    pub fn tx(&self) -> &[PlacedSeries<'a>] {
        &self.tx
    }

    pub fn shared(&self) -> &[PlacedSeries<'a>] {
        &self.shared
    }

    pub fn lane(&self, lane: ResolvedLane) -> &[PlacedSeries<'a>] {
        match lane {
            ResolvedLane::Rx => self.rx(),
            ResolvedLane::Tx => self.tx(),
            ResolvedLane::Shared => self.shared(),
        }
    }

    pub fn series_count(&self) -> usize {
        self.rx
            .len()
            .saturating_add(self.tx.len())
            .saturating_add(self.shared.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dashboard<'a> {
    blocks: Vec<DashboardBlock<'a>>,
    unplaced: Vec<UnplacedSeries<'a>>,
}

impl<'a> Dashboard<'a> {
    pub fn blocks(&self) -> &[DashboardBlock<'a>] {
        &self.blocks
    }

    pub fn unplaced(&self) -> &[UnplacedSeries<'a>] {
        &self.unplaced
    }

    pub fn block(&self, key: &BlockKey) -> Option<&DashboardBlock<'a>> {
        self.blocks.iter().find(|block| block.key() == key)
    }

    pub fn placed_series_count(&self) -> usize {
        self.blocks.iter().map(DashboardBlock::series_count).sum()
    }

    pub fn series_count(&self) -> usize {
        self.placed_series_count()
            .saturating_add(self.unplaced.len())
    }
}

pub fn build_dashboard(snapshot: &MonitorSnapshot) -> Dashboard<'_> {
    build_dashboard_filtered(snapshot, |_| true)
}

pub(crate) fn build_dashboard_for_interfaces<'a>(
    snapshot: &'a MonitorSnapshot,
    interfaces: &[InterfaceIdentity],
) -> Dashboard<'a> {
    build_dashboard_filtered(snapshot, |series| {
        let Some(name) = series.labels().get(MetricLabel::Interface) else {
            return true;
        };
        interfaces.iter().any(|identity| {
            identity.name() == name
                && series
                    .labels()
                    .get(MetricLabel::Ifindex)
                    .and_then(|index| index.parse::<u32>().ok())
                    == Some(identity.ifindex().get())
        })
    })
}

fn build_dashboard_filtered(
    snapshot: &MonitorSnapshot,
    include: impl Fn(&SeriesSnapshot) -> bool,
) -> Dashboard<'_> {
    let mut blocks = BTreeMap::<BlockKey, DashboardBlock<'_>>::new();
    let mut interfaces = BTreeSet::new();
    let mut unplaced = Vec::new();

    seed_block(
        &mut blocks,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::SocketApplication),
        ),
    );
    seed_block(
        &mut blocks,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::Transport),
        ),
    );
    seed_block(
        &mut blocks,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::NetworkRoute),
        ),
    );
    seed_block(
        &mut blocks,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::NetfilterConntrack),
        ),
    );
    seed_block(
        &mut blocks,
        BlockKey::new(
            BlockScope::Host,
            BlockKind::ExecutionContext(ExecutionContext::Softirq),
        ),
    );

    for series in snapshot.series().iter().filter(|series| include(series)) {
        let Some(descriptor) = descriptor(series.metric().as_str()) else {
            unplaced.push(UnplacedSeries {
                series,
                reason: UnplacedReason::UnknownMetric,
            });
            continue;
        };
        let Some(placement) = placement_for(descriptor) else {
            unplaced.push(UnplacedSeries {
                series,
                reason: UnplacedReason::MissingCatalogPlacement,
            });
            continue;
        };
        let scope = match placement.scope() {
            PlacementScope::Global => BlockScope::Global,
            PlacementScope::Host => BlockScope::Host,
            PlacementScope::Interface => match interface_identity(series) {
                Ok(identity) => {
                    interfaces.insert(identity.clone());
                    BlockScope::Interface(identity)
                }
                Err(reason) => {
                    unplaced.push(UnplacedSeries { series, reason });
                    continue;
                }
            },
        };
        let lane = match resolve_lane(series, placement.lane()) {
            Ok(lane) => lane,
            Err(reason) => {
                unplaced.push(UnplacedSeries { series, reason });
                continue;
            }
        };
        let key = BlockKey::new(scope, placement.block_kind());
        blocks
            .entry(key.clone())
            .or_insert_with(|| DashboardBlock::empty(key))
            .push(series, placement, lane);
    }

    for identity in &interfaces {
        for kind in interface_block_order() {
            let key = BlockKey::new(BlockScope::Interface(identity.clone()), kind);
            seed_block(&mut blocks, key);
        }
    }

    for block in blocks.values_mut() {
        block.sort_series();
    }

    let mut ordered = Vec::with_capacity(blocks.len());
    take_block(
        &mut blocks,
        &mut ordered,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::SocketApplication),
        ),
    );
    take_block(
        &mut blocks,
        &mut ordered,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::Transport),
        ),
    );
    take_block(
        &mut blocks,
        &mut ordered,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::NetworkRoute),
        ),
    );
    take_block(
        &mut blocks,
        &mut ordered,
        BlockKey::new(
            BlockScope::Global,
            BlockKind::PacketStage(PacketStage::NetfilterConntrack),
        ),
    );
    take_block(
        &mut blocks,
        &mut ordered,
        BlockKey::new(
            BlockScope::Host,
            BlockKind::ExecutionContext(ExecutionContext::Softirq),
        ),
    );
    for identity in interfaces {
        for kind in interface_block_order() {
            take_block(
                &mut blocks,
                &mut ordered,
                BlockKey::new(BlockScope::Interface(identity.clone()), kind),
            );
        }
    }
    ordered.extend(blocks.into_values());

    Dashboard {
        blocks: ordered,
        unplaced,
    }
}

fn interface_block_order() -> [BlockKind; 5] {
    [
        BlockKind::PacketStage(PacketStage::TrafficControl),
        BlockKind::PacketStage(PacketStage::NetdeviceCore),
        BlockKind::PacketStage(PacketStage::DriverNapi),
        BlockKind::PacketStage(PacketStage::NicPhy),
        BlockKind::ExecutionContext(ExecutionContext::Hardirq),
    ]
}

fn seed_block<'a>(blocks: &mut BTreeMap<BlockKey, DashboardBlock<'a>>, key: BlockKey) {
    blocks
        .entry(key.clone())
        .or_insert_with(|| DashboardBlock::empty(key));
}

fn take_block<'a>(
    blocks: &mut BTreeMap<BlockKey, DashboardBlock<'a>>,
    ordered: &mut Vec<DashboardBlock<'a>>,
    key: BlockKey,
) {
    if let Some(block) = blocks.remove(&key) {
        ordered.push(block);
    }
}

pub(crate) fn interface_identity(
    series: &SeriesSnapshot,
) -> Result<InterfaceIdentity, UnplacedReason> {
    let name = series
        .labels()
        .get(MetricLabel::Interface)
        .ok_or(UnplacedReason::MissingInterfaceName)?;
    let ifindex = series
        .labels()
        .get(MetricLabel::Ifindex)
        .ok_or(UnplacedReason::MissingIfindex)?
        .parse::<u32>()
        .ok()
        .and_then(|value| IfIndex::new(value).ok())
        .ok_or(UnplacedReason::InvalidIfindex)?;
    Ok(InterfaceIdentity {
        ifindex,
        name: name.to_owned(),
    })
}

pub(crate) fn resolve_lane(
    series: &SeriesSnapshot,
    placement: Lane,
) -> Result<ResolvedLane, UnplacedReason> {
    match placement {
        Lane::Rx => Ok(ResolvedLane::Rx),
        Lane::Tx => Ok(ResolvedLane::Tx),
        Lane::Shared => Ok(ResolvedLane::Shared),
        Lane::FromLabel => match series.labels().get(MetricLabel::Direction) {
            Some("ingress" | "rx") => Ok(ResolvedLane::Rx),
            Some("egress" | "tx") => Ok(ResolvedLane::Tx),
            Some(_) => Err(UnplacedReason::InvalidDirection),
            None => Err(UnplacedReason::MissingDirection),
        },
    }
}

fn sort_placed(series: &mut [PlacedSeries<'_>]) {
    series.sort_by(|left, right| {
        display_order(left.placement.display())
            .cmp(&display_order(right.placement.display()))
            .then_with(|| left.series.metric().cmp(right.series.metric()))
            .then_with(|| left.series.labels().cmp(right.series.labels()))
            .then_with(|| left.series.id().cmp(&right.series.id()))
    });
}

const fn display_order(display: DisplaySlot) -> (u8, u16) {
    match display {
        DisplaySlot::Summary { rank } => (0, rank),
        DisplaySlot::Detail => (1, 0),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use super::*;
    use crate::monitor::catalog::metric_catalog;
    use crate::monitor::model::{
        BaselineOrigin, CounterContinuity, CounterSpan, EngineTelemetry, HistoryCoverage, MetricId,
        MetricKind, MetricLabels, ProjectedValue, ProviderHealth, ProviderId, ProviderSnapshot,
        SeriesId, SeriesValue,
    };

    fn labels(values: &[(MetricLabel, &str)]) -> MetricLabels {
        MetricLabels::new(
            values
                .iter()
                .map(|(label, value)| (*label, (*value).to_owned())),
        )
        .unwrap()
    }

    fn interface_labels(name: &str, ifindex: &str) -> MetricLabels {
        labels(&[
            (MetricLabel::Interface, name),
            (MetricLabel::Ifindex, ifindex),
        ])
    }

    fn tc_labels(name: &str, ifindex: &str, direction: &str) -> MetricLabels {
        labels(&[
            (MetricLabel::Interface, name),
            (MetricLabel::Ifindex, ifindex),
            (MetricLabel::Direction, direction),
            (MetricLabel::ObjectKind, "qdisc"),
            (MetricLabel::QdiscKind, "fq_codel"),
            (MetricLabel::RowId, "1"),
            (MetricLabel::Execution, "software"),
        ])
    }

    fn series(id: u64, metric: &str, labels: MetricLabels) -> SeriesSnapshot {
        let descriptor = descriptor(metric).unwrap();
        let value = match descriptor.kind {
            MetricKind::Counter => SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: id,
                    observed_at: Duration::from_secs(1),
                },
                interval: Some(CounterContinuity::Continuous {
                    delta: id,
                    elapsed: Duration::from_secs(1),
                }),
                since_baseline: Some(CounterSpan::new(id, Duration::from_secs(1)).unwrap()),
            },
            MetricKind::Gauge => SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value: id,
                    observed_at: Duration::from_secs(1),
                },
                interval: None,
                since_baseline: None,
            },
            MetricKind::State => panic!("state test series needs an explicit valid state"),
        };
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(descriptor.sources[0].provider).unwrap(),
            MetricId::new(metric).unwrap(),
            labels,
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            value,
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn snapshot(series: Vec<SeriesSnapshot>) -> MonitorSnapshot {
        let sources: BTreeSet<_> = series.iter().map(|row| row.source().clone()).collect();
        let providers = sources
            .into_iter()
            .map(|provider| {
                ProviderSnapshot::new(
                    provider,
                    ProviderHealth::Fresh,
                    Duration::from_secs(1),
                    Duration::ZERO,
                    0,
                )
                .unwrap()
            })
            .collect();
        MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(1),
            None,
            providers,
            series,
            EngineTelemetry::default(),
        )
        .unwrap()
    }

    fn interface_block<'a>(
        dashboard: &'a Dashboard<'a>,
        name: &str,
        ifindex: u32,
        kind: BlockKind,
    ) -> &'a DashboardBlock<'a> {
        dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().kind() == kind
                    && matches!(
                        block.key().scope(),
                        BlockScope::Interface(identity)
                            if identity.name() == name && identity.ifindex().get() == ifindex
                    )
            })
            .unwrap()
    }

    fn block_series_ids(block: &DashboardBlock<'_>) -> Vec<u64> {
        block
            .rx()
            .iter()
            .chain(block.tx())
            .chain(block.shared())
            .map(|placed| placed.series().id().get())
            .collect()
    }

    #[test]
    fn rx_and_tx_paths_are_typed_reverses() {
        assert!(paths_are_reverse(&RX_PATH, &TX_PATH));
        assert_eq!(PacketStage::ALL, TX_PATH);

        let mut wrong_tx = TX_PATH;
        wrong_tx.swap(2, 3);
        assert!(!paths_are_reverse(&RX_PATH, &wrong_tx));
    }

    #[test]
    fn every_catalog_metric_has_one_explicit_placement() {
        let mut ids = BTreeSet::new();
        for metric in metric_catalog() {
            assert!(ids.insert(metric.id), "duplicate catalog id {}", metric.id);
            assert!(
                placement_for(metric).is_some(),
                "missing dashboard placement for {}",
                metric.id
            );
        }
        assert_eq!(ids.len(), metric_catalog().len());
    }

    #[test]
    fn extended_qdisc_statistics_are_tc_details() {
        for (metric_id, kind, unit) in [
            (
                "linux.tc.max_packet_bytes",
                MetricKind::Gauge,
                crate::monitor::MetricUnit::Bytes,
            ),
            (
                "linux.tc.drop_overlimit",
                MetricKind::Counter,
                crate::monitor::MetricUnit::SourceUnits,
            ),
            (
                "linux.tc.new_flow_count",
                MetricKind::Counter,
                crate::monitor::MetricUnit::Occurrences,
            ),
            (
                "linux.tc.ecn_marks",
                MetricKind::Counter,
                crate::monitor::MetricUnit::SourceUnits,
            ),
            (
                "linux.tc.new_flows_len",
                MetricKind::Gauge,
                crate::monitor::MetricUnit::Occurrences,
            ),
            (
                "linux.tc.old_flows_len",
                MetricKind::Gauge,
                crate::monitor::MetricUnit::Occurrences,
            ),
        ] {
            let metric = descriptor(metric_id).unwrap();
            let placement = placement_for(metric).unwrap();
            assert_eq!(metric.kind, kind, "{metric_id}");
            assert_eq!(metric.unit, unit, "{metric_id}");
            assert_eq!(
                placement.block_kind(),
                BlockKind::PacketStage(PacketStage::TrafficControl),
                "{metric_id}"
            );
            assert_eq!(placement.lane(), Lane::FromLabel, "{metric_id}");
            assert_eq!(placement.display(), DisplaySlot::Detail, "{metric_id}");
        }
        for (metric_id, raw_metric) in [
            ("linux.tc.backlog_packets", "object.qlen"),
            ("linux.tc.backlog_bytes", "object.backlog"),
            ("linux.tc.max_packet_bytes", "object.maxpacket"),
            ("linux.tc.drop_overlimit", "object.drop_overlimit"),
            ("linux.tc.new_flow_count", "object.new_flow_count"),
            ("linux.tc.ecn_marks", "object.ecn_mark"),
            ("linux.tc.new_flows_len", "object.new_flows_len"),
            ("linux.tc.old_flows_len", "object.old_flows_len"),
        ] {
            let source = descriptor(metric_id)
                .unwrap()
                .sources
                .iter()
                .find(|source| source.provider == "linux.tc.json")
                .unwrap();
            assert_eq!(source.raw_metric, raw_metric, "{metric_id}");
        }
    }

    #[test]
    fn nic_collection_is_split_across_netdevice_driver_and_phy() {
        let netdevice = placement_for(descriptor("linux.netdevice.rx_errors").unwrap()).unwrap();
        let driver = placement_for(descriptor("linux.nic.rx_missed_errors").unwrap()).unwrap();
        let phy = placement_for(descriptor("linux.nic.rx_crc_errors").unwrap()).unwrap();

        assert_eq!(
            netdevice.block_kind(),
            BlockKind::PacketStage(PacketStage::NetdeviceCore)
        );
        assert_eq!(
            netdevice.attribution().boundary_stages(),
            Some([PacketStage::NetdeviceCore, PacketStage::DriverNapi])
        );
        assert_eq!(
            driver.block_kind(),
            BlockKind::PacketStage(PacketStage::DriverNapi)
        );
        assert_eq!(
            driver.attribution().boundary_stages(),
            Some([PacketStage::DriverNapi, PacketStage::NicPhy])
        );
        assert_eq!(
            phy.block_kind(),
            BlockKind::PacketStage(PacketStage::NicPhy)
        );
        assert_eq!(phy.attribution(), Attribution::Exact);
    }

    #[test]
    fn socket_collection_is_split_across_socket_transport_and_network() {
        for (metric, stage) in [
            (
                "linux.socket.udp.receive_buffer_errors",
                PacketStage::SocketApplication,
            ),
            (
                "linux.socket.tcp.established_resets",
                PacketStage::Transport,
            ),
            ("linux.socket.ip.input_errors", PacketStage::NetworkRoute),
        ] {
            assert_eq!(
                placement_for(descriptor(metric).unwrap())
                    .unwrap()
                    .block_kind(),
                BlockKind::PacketStage(stage),
                "{metric}"
            );
        }
    }

    #[test]
    fn interface_identity_keeps_two_nics_separate() {
        let snapshot = snapshot(vec![
            series(
                1,
                "linux.netdevice.rx_packets",
                interface_labels("eth0", "2"),
            ),
            series(
                2,
                "linux.netdevice.tx_packets",
                interface_labels("eth1", "3"),
            ),
            series(3, "linux.hardirq.imbalance", interface_labels("eth0", "2")),
            series(4, "linux.hardirq.imbalance", interface_labels("eth1", "3")),
        ]);
        let dashboard = build_dashboard(&snapshot);

        let netdevice = BlockKind::PacketStage(PacketStage::NetdeviceCore);
        assert_eq!(
            block_series_ids(interface_block(&dashboard, "eth0", 2, netdevice)),
            vec![1]
        );
        assert_eq!(
            block_series_ids(interface_block(&dashboard, "eth1", 3, netdevice)),
            vec![2]
        );
        let hardirq = BlockKind::ExecutionContext(ExecutionContext::Hardirq);
        assert_eq!(
            block_series_ids(interface_block(&dashboard, "eth0", 2, hardirq)),
            vec![3]
        );
        assert_eq!(
            block_series_ids(interface_block(&dashboard, "eth1", 3, hardirq)),
            vec![4]
        );

        let unique_keys: BTreeSet<_> = dashboard
            .blocks()
            .iter()
            .map(|block| block.key().clone())
            .collect();
        assert_eq!(unique_keys.len(), dashboard.blocks().len());
        assert_eq!(dashboard.blocks().len(), 5 + 2 * 5);
    }

    #[test]
    fn host_softirq_never_enters_an_interface_block() {
        let snapshot = snapshot(vec![
            series(
                1,
                "linux.softirq.net_rx",
                labels(&[(MetricLabel::Cpu, "0")]),
            ),
            series(
                2,
                "linux.netdevice.rx_packets",
                interface_labels("eth0", "2"),
            ),
        ]);
        let dashboard = build_dashboard(&snapshot);

        let softirq = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().scope() == &BlockScope::Host
                    && block.key().kind() == BlockKind::ExecutionContext(ExecutionContext::Softirq)
            })
            .unwrap();
        assert_eq!(block_series_ids(softirq), vec![1]);
        assert!(dashboard.blocks().iter().all(|block| {
            !matches!(block.key().scope(), BlockScope::Interface(_))
                || !block_series_ids(block).contains(&1)
        }));
    }

    #[test]
    fn every_series_appears_exactly_once_in_a_lane_or_unplaced() {
        let snapshot = snapshot(vec![
            series(1, "linux.socket.ip.receives", MetricLabels::default()),
            series(2, "linux.tc.packets", tc_labels("eth0", "2", "ingress")),
            series(3, "linux.tc.packets", tc_labels("eth0", "2", "egress")),
            series(
                4,
                "linux.softirq.net_rx",
                labels(&[(MetricLabel::Cpu, "0")]),
            ),
            series(
                5,
                "linux.nic.ring_drops",
                labels(&[(MetricLabel::Interface, "eth0")]),
            ),
        ]);
        let dashboard = build_dashboard(&snapshot);

        let mut occurrences = BTreeMap::<u64, usize>::new();
        for block in dashboard.blocks() {
            for placed in block.rx().iter().chain(block.tx()).chain(block.shared()) {
                *occurrences.entry(placed.series().id().get()).or_default() += 1;
            }
        }
        for row in dashboard.unplaced() {
            *occurrences.entry(row.series().id().get()).or_default() += 1;
        }

        assert_eq!(dashboard.series_count(), 5);
        assert_eq!(occurrences.len(), 5);
        assert!(occurrences.values().all(|count| *count == 1));
        assert_eq!(dashboard.unplaced().len(), 1);
        assert_eq!(
            dashboard.unplaced()[0].reason(),
            UnplacedReason::MissingIfindex
        );
        let tc = interface_block(
            &dashboard,
            "eth0",
            2,
            BlockKind::PacketStage(PacketStage::TrafficControl),
        );
        assert_eq!(
            tc.rx()
                .iter()
                .map(|placed| placed.series().id().get())
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(
            tc.tx()
                .iter()
                .map(|placed| placed.series().id().get())
                .collect::<Vec<_>>(),
            vec![3]
        );
    }

    #[test]
    fn raw_private_names_remain_opaque() {
        let metric = descriptor("linux.nic.raw_private").unwrap();
        let placement = placement_for(metric).unwrap();
        assert_eq!(
            placement.block_kind(),
            BlockKind::PacketStage(PacketStage::DriverNapi)
        );
        assert_eq!(placement.lane(), Lane::Shared);
        assert_eq!(placement.attribution(), Attribution::Opaque);
        assert_eq!(placement.display(), DisplaySlot::Detail);

        let snapshot = snapshot(vec![series(
            1,
            "linux.nic.raw_private",
            labels(&[
                (MetricLabel::Interface, "eth0"),
                (MetricLabel::Ifindex, "2"),
                (MetricLabel::Statistic, "tx_timeout_drop"),
            ]),
        )]);
        let dashboard = build_dashboard(&snapshot);
        let driver = interface_block(
            &dashboard,
            "eth0",
            2,
            BlockKind::PacketStage(PacketStage::DriverNapi),
        );
        assert!(driver.rx().is_empty());
        assert!(driver.tx().is_empty());
        assert_eq!(block_series_ids(driver), vec![1]);
        assert_eq!(
            driver.shared()[0].placement().attribution(),
            Attribution::Opaque
        );
    }
}
