use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::monitor::dashboard::{BlockKind, ExecutionContext, PacketStage};
use crate::monitor::{
    CounterContinuity, MetricLabel, MonitorSnapshot, ProjectedValue, ProviderHealth,
    SeriesSnapshot, SeriesValue,
};

use super::theme;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Layer {
    Sockets,
    Transport,
    Network,
    Conntrack,
    Softirq,
}

impl Layer {
    pub(super) const ALL: [Self; 5] = [
        Self::Sockets,
        Self::Transport,
        Self::Network,
        Self::Conntrack,
        Self::Softirq,
    ];

    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Sockets => "SOCKETS",
            Self::Transport => "TRANSPORT",
            Self::Network => "NETWORK",
            Self::Conntrack => "CONNTRACK",
            Self::Softirq => "SOFTIRQ",
        }
    }

    pub(super) const fn kind(self) -> BlockKind {
        match self {
            Self::Sockets => BlockKind::PacketStage(PacketStage::SocketApplication),
            Self::Transport => BlockKind::PacketStage(PacketStage::Transport),
            Self::Network => BlockKind::PacketStage(PacketStage::NetworkRoute),
            Self::Conntrack => BlockKind::PacketStage(PacketStage::NetfilterConntrack),
            Self::Softirq => BlockKind::ExecutionContext(ExecutionContext::Softirq),
        }
    }

    pub(super) const fn color(self) -> Color {
        match self {
            Self::Sockets => theme::SOCKETS,
            Self::Transport => theme::TRANSPORT,
            Self::Network => theme::NETWORK,
            Self::Conntrack => theme::CONNTRACK,
            Self::Softirq => theme::SOFTIRQ,
        }
    }

    pub(super) fn from_kind(kind: BlockKind) -> Option<Self> {
        Self::ALL.into_iter().find(|layer| layer.kind() == kind)
    }
}

#[derive(Clone, Copy)]
enum Projection {
    Rate,
    Current,
    Memory,
    MemoryLimit,
}

struct Field {
    layer: Layer,
    section: &'static str,
    label: &'static str,
    ids: &'static [&'static str],
    projection: Projection,
    meaning: &'static str,
    warn: bool,
    overview: bool,
}

macro_rules! field {
    ($layer:ident, $section:literal, $label:literal, $projection:ident, $warn:literal, $overview:literal, [$($id:literal),+], $meaning:literal) => {
        Field { layer: Layer::$layer, section: $section, label: $label, ids: &[$($id),+], projection: Projection::$projection, meaning: $meaning, warn: $warn, overview: $overview }
    };
}

const FIELDS: &[Field] = &[
    field!(
        Sockets,
        "SOCKETS",
        "TCP inuse",
        Current,
        false,
        true,
        ["linux.socket.tcp.in_use", "linux.socket.tcp6.in_use"],
        "TCP sockets in use; IPv4 and IPv6 combined in this network namespace."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "TCP CurrEstab",
        Current,
        false,
        true,
        ["linux.socket.tcp.current_established"],
        "TCP sockets in ESTABLISHED or CLOSE_WAIT; includes both address families."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "TCP timewait",
        Current,
        false,
        true,
        ["linux.socket.tcp.time_wait"],
        "TCP sockets in TIME_WAIT."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "UDP inuse",
        Current,
        false,
        true,
        ["linux.socket.udp.in_use", "linux.socket.udp6.in_use"],
        "UDP sockets in use; IPv4 and IPv6 combined."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "TCP orphan",
        Current,
        false,
        true,
        ["linux.socket.tcp.orphaned"],
        "Host-wide TCP sockets without a user file descriptor."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "TCP mem / max",
        MemoryLimit,
        false,
        true,
        [
            "linux.socket.tcp.memory_pages",
            "linux.socket.tcp.memory_max_pages"
        ],
        "Host TCP allocated memory / tcp_mem maximum; kernel pages converted to MiB."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "ListenOverflows/s",
        Rate,
        true,
        true,
        ["linux.socket.tcp.listen_overflows"],
        "Listen accept-queue overflow events; may overlap with ListenDrops."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "ListenDrops/s",
        Rate,
        true,
        true,
        ["linux.socket.tcp.listen_drops"],
        "Requests dropped at listening sockets, including resource pressure."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "TCP alloc",
        Current,
        false,
        false,
        ["linux.socket.tcp.allocated"],
        "Host-wide allocated TCP sockets."
    ),
    field!(
        Sockets,
        "SOCKETS",
        "UDP memory",
        Memory,
        false,
        false,
        ["linux.socket.udp.memory_pages"],
        "Host-wide UDP socket memory, converted from pages to MiB."
    ),
    field!(
        Transport,
        "TCP",
        "InSegs/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.segments_in"],
        "TCP segments received, including retransmissions and errors."
    ),
    field!(
        Transport,
        "TCP",
        "OutSegs/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.segments_out"],
        "TCP segments sent; retransmitted segments have their own counter."
    ),
    field!(
        Transport,
        "TCP",
        "RetransSegs/s",
        Rate,
        true,
        true,
        ["linux.socket.tcp.retransmitted_segments"],
        "Retransmitted segments; not a measurement of packet loss."
    ),
    field!(
        Transport,
        "TCP",
        "OutRsts/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.resets_out"],
        "Segments sent with the RST flag."
    ),
    field!(
        Transport,
        "TCP",
        "EstabResets/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.established_resets"],
        "Transitions from ESTABLISHED or CLOSE_WAIT to CLOSED, not received RST packets."
    ),
    field!(
        Transport,
        "TCP",
        "ActiveOpens/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.active_opens"],
        "Active opens entering SYN_SENT."
    ),
    field!(
        Transport,
        "TCP",
        "PassiveOpens/s",
        Rate,
        false,
        true,
        ["linux.socket.tcp.passive_opens"],
        "Passive opens transitioning from LISTEN to SYN_RCVD."
    ),
    field!(
        Transport,
        "TCP",
        "AttemptFails/s",
        Rate,
        true,
        true,
        ["linux.socket.tcp.failed_connection_attempts"],
        "Failed TCP connection establishment attempts."
    ),
    field!(
        Transport,
        "TCP",
        "TCPTimeouts/s",
        Rate,
        true,
        true,
        ["linux.socket.tcp.timeouts"],
        "Retransmission timeout events; not failed-connection counts."
    ),
    field!(
        Transport,
        "UDP",
        "InDatagrams/s",
        Rate,
        false,
        true,
        [
            "linux.socket.udp.datagrams_in",
            "linux.socket.udp6.datagrams_in"
        ],
        "IPv4/IPv6 datagrams delivered to UDP users."
    ),
    field!(
        Transport,
        "UDP",
        "OutDatagrams/s",
        Rate,
        false,
        true,
        [
            "linux.socket.udp.datagrams_out",
            "linux.socket.udp6.datagrams_out"
        ],
        "IPv4/IPv6 datagrams sent by UDP users."
    ),
    field!(
        Transport,
        "UDP",
        "RcvbufErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.udp.receive_buffer_errors",
            "linux.socket.udp6.receive_buffer_errors"
        ],
        "UDP receive errors caused by insufficient socket buffer space."
    ),
    field!(
        Transport,
        "UDP",
        "SndbufErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.udp.send_buffer_errors",
            "linux.socket.udp6.send_buffer_errors"
        ],
        "UDP send errors caused by insufficient buffer space."
    ),
    field!(
        Transport,
        "UDP",
        "NoPorts/s",
        Rate,
        false,
        true,
        ["linux.socket.udp.no_ports", "linux.socket.udp6.no_ports"],
        "Datagrams received with no matching UDP socket."
    ),
    field!(
        Transport,
        "UDP",
        "InErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.udp.input_errors",
            "linux.socket.udp6.input_errors"
        ],
        "Total UDP input errors; buffer/checksum counters are components, not additional losses."
    ),
    field!(
        Transport,
        "UDP",
        "InCsumErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.udp.checksum_errors",
            "linux.socket.udp6.checksum_errors"
        ],
        "UDP checksum errors; included in InErrors."
    ),
    field!(
        Network,
        "IP",
        "IPv4 forward/s",
        Rate,
        false,
        true,
        ["linux.socket.ip.forwarded_datagrams"],
        "IPv4 datagrams forwarded through the network namespace."
    ),
    field!(
        Network,
        "IP",
        "IPv4 noRoute/s",
        Rate,
        true,
        true,
        ["linux.socket.ip.output_no_routes"],
        "IPv4 output packets with no route."
    ),
    field!(
        Network,
        "IP",
        "IPv4 inDiscard/s",
        Rate,
        true,
        true,
        ["linux.socket.ip.input_discards"],
        "IPv4 input discards excluding other explicitly counted errors."
    ),
    field!(
        Network,
        "IP",
        "IPv4 outDiscard/s",
        Rate,
        true,
        true,
        ["linux.socket.ip.output_discards"],
        "IPv4 output discards."
    ),
    field!(
        Network,
        "IP",
        "IPv4 reasmFail/s",
        Rate,
        true,
        true,
        ["linux.socket.ip.reassembly_failures"],
        "Failed IPv4 reassemblies; fragments and packets are different accounting domains."
    ),
    field!(
        Network,
        "IP",
        "IPv6 receive/s",
        Rate,
        false,
        true,
        ["linux.socket.ipv6.receives"],
        "IPv6 datagrams received."
    ),
    field!(
        Network,
        "IP",
        "IPv6 output/s",
        Rate,
        false,
        true,
        ["linux.socket.ipv6.output_requests"],
        "IPv6 output requests from upper layers."
    ),
    field!(
        Network,
        "IP",
        "IPv6 noRoute/s",
        Rate,
        true,
        true,
        ["linux.socket.ipv6.output_no_routes"],
        "IPv6 output packets with no route."
    ),
    field!(
        Network,
        "IP",
        "IPv4 receive/s",
        Rate,
        false,
        false,
        ["linux.socket.ip.receives"],
        "IPv4 datagrams received before IP validation."
    ),
    field!(
        Network,
        "IP",
        "IPv4 deliver/s",
        Rate,
        false,
        false,
        ["linux.socket.ip.delivers"],
        "IPv4 datagrams delivered to upper-layer protocols."
    ),
    field!(
        Network,
        "IP",
        "IPv4 headerErr/s",
        Rate,
        true,
        false,
        ["linux.socket.ip.input_errors"],
        "IPv4 input header errors."
    ),
    field!(
        Network,
        "IP",
        "IPv4 fragFail/s",
        Rate,
        true,
        false,
        ["linux.socket.ip.fragmentation_failures"],
        "IPv4 output datagrams that could not be fragmented."
    ),
    field!(
        Network,
        "IP",
        "IPv6 forward/s",
        Rate,
        false,
        false,
        ["linux.socket.ipv6.forwarded_datagrams"],
        "IPv6 datagrams forwarded."
    ),
    field!(
        Network,
        "IP",
        "IPv6 reasmFail/s",
        Rate,
        true,
        false,
        ["linux.socket.ipv6.reassembly_failures"],
        "Failed IPv6 reassemblies."
    ),
    field!(
        Network,
        "ICMP",
        "InMsgs/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.input_messages",
            "linux.socket.icmpv6.input_messages"
        ],
        "ICMPv4 and ICMPv6 messages received."
    ),
    field!(
        Network,
        "ICMP",
        "OutMsgs/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.output_messages",
            "linux.socket.icmpv6.output_messages"
        ],
        "ICMPv4 and ICMPv6 messages sent."
    ),
    field!(
        Network,
        "ICMP",
        "InUnreach/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.input_destination_unreachable",
            "linux.socket.icmpv6.input_destination_unreachable"
        ],
        "Destination Unreachable messages received, not local socket error counts."
    ),
    field!(
        Network,
        "ICMP",
        "OutUnreach/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.output_destination_unreachable",
            "linux.socket.icmpv6.output_destination_unreachable"
        ],
        "Destination Unreachable messages sent."
    ),
    field!(
        Network,
        "ICMP",
        "InTimeExcd/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.input_time_exceeded",
            "linux.socket.icmpv6.input_time_exceeded"
        ],
        "Time Exceeded messages received."
    ),
    field!(
        Network,
        "ICMP",
        "OutTimeExcd/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.output_time_exceeded",
            "linux.socket.icmpv6.output_time_exceeded"
        ],
        "Time Exceeded messages sent."
    ),
    field!(
        Network,
        "ICMP",
        "Echo requests in/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.input_echo_requests",
            "linux.socket.icmpv6.input_echo_requests"
        ],
        "Echo requests received."
    ),
    field!(
        Network,
        "ICMP",
        "Echo requests out/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.output_echo_requests",
            "linux.socket.icmpv6.output_echo_requests"
        ],
        "Echo requests sent."
    ),
    field!(
        Network,
        "ICMP",
        "Echo replies in/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.input_echo_replies",
            "linux.socket.icmpv6.input_echo_replies"
        ],
        "Echo replies received."
    ),
    field!(
        Network,
        "ICMP",
        "Echo replies out/s",
        Rate,
        false,
        true,
        [
            "linux.socket.icmp.output_echo_replies",
            "linux.socket.icmpv6.output_echo_replies"
        ],
        "Echo replies sent."
    ),
    field!(
        Network,
        "ICMP",
        "InErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.icmp.input_errors",
            "linux.socket.icmpv6.input_errors"
        ],
        "ICMP receive-processing errors; not counts of error-message types."
    ),
    field!(
        Network,
        "ICMP",
        "OutErrors/s",
        Rate,
        true,
        true,
        [
            "linux.socket.icmp.output_errors",
            "linux.socket.icmpv6.output_errors"
        ],
        "ICMP send-processing errors."
    ),
    field!(
        Network,
        "ICMP",
        "InCsumErrors/s",
        Rate,
        true,
        false,
        [
            "linux.socket.icmp.input_checksum_errors",
            "linux.socket.icmpv6.input_checksum_errors"
        ],
        "ICMP checksum errors; included in input errors, not additional losses."
    ),
    field!(
        Network,
        "ICMP",
        "v6 InTooBig/s",
        Rate,
        false,
        true,
        ["linux.socket.icmpv6.input_packet_too_big"],
        "IPv6 Packet Too Big messages received; IPv4 type 3/code 4 is not isolated here."
    ),
    field!(
        Network,
        "ICMP",
        "v6 OutTooBig/s",
        Rate,
        false,
        true,
        ["linux.socket.icmpv6.output_packet_too_big"],
        "IPv6 Packet Too Big messages sent."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "entries",
        Current,
        false,
        true,
        ["linux.netfilter.conntrack.count"],
        "Conntrack entries currently present in this namespace."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "maximum",
        Current,
        false,
        true,
        ["linux.netfilter.conntrack.maximum"],
        "Configured maximum conntrack table entries."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "insert/s",
        Rate,
        false,
        true,
        ["linux.netfilter.conntrack.insert"],
        "Conntrack insertion events across CPUs."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "insert_failed/s",
        Rate,
        true,
        true,
        ["linux.netfilter.conntrack.insert_failed"],
        "Failed insertions; not necessarily table-full drops."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "drop/s",
        Rate,
        true,
        true,
        ["linux.netfilter.conntrack.drop"],
        "Packets dropped by conntrack; not firewall rule counters."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "early_drop/s",
        Rate,
        true,
        true,
        ["linux.netfilter.conntrack.early_drop"],
        "Existing entries evicted to make space."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "invalid/s",
        Rate,
        false,
        true,
        ["linux.netfilter.conntrack.invalid"],
        "Packets classified invalid; this alone does not imply a firewall drop."
    ),
    field!(
        Conntrack,
        "CONNTRACK",
        "search_restart/s",
        Rate,
        false,
        true,
        ["linux.netfilter.conntrack.search_restart"],
        "Conntrack search restarts due to concurrent table changes."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "NET_RX calls/s",
        Rate,
        false,
        true,
        ["linux.softirq.net_rx"],
        "Host network receive softirq invocations across CPUs; not packet counts."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "NET_TX calls/s",
        Rate,
        false,
        true,
        ["linux.softirq.net_tx"],
        "Host network transmit softirq invocations across CPUs; not all TX work."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "processed pck/s",
        Rate,
        false,
        true,
        ["linux.softirq.softnet.processed"],
        "Packets processed by the per-CPU network backlog."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "dropped pck/s",
        Rate,
        true,
        true,
        ["linux.softirq.softnet.dropped"],
        "Packets dropped at the per-CPU input backlog."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "time_squeeze/s",
        Rate,
        true,
        true,
        ["linux.softirq.softnet.time_squeeze"],
        "Poll cycles that exhausted their packet/time budget; not packet drops."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "RPS IPI/s",
        Rate,
        false,
        true,
        ["linux.softirq.softnet.received_rps"],
        "Received RPS inter-processor wakeups."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "flow_limit/s",
        Rate,
        true,
        true,
        ["linux.softirq.softnet.flow_limit"],
        "Flow-limit drops under receive backlog pressure."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "backlog packets",
        Current,
        false,
        true,
        ["linux.softirq.softnet.backlog_len"],
        "Current backlog packets summed across CPUs, when exported by the kernel."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "netdev_budget",
        Current,
        false,
        true,
        ["linux.softirq.config.netdev_budget"],
        "Maximum packets per network polling cycle."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "budget_usecs",
        Current,
        false,
        true,
        ["linux.softirq.config.netdev_budget_usecs"],
        "Maximum microseconds per network polling cycle."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "dev_weight",
        Current,
        false,
        true,
        ["linux.softirq.config.dev_weight"],
        "Per-CPU backlog polling weight in packets."
    ),
    field!(
        Softirq,
        "SOFTIRQ",
        "max_backlog /CPU",
        Current,
        false,
        true,
        ["linux.softirq.config.netdev_max_backlog"],
        "Configured input backlog limit in packets per CPU."
    ),
];

#[derive(Debug)]
struct Value {
    field: &'static Field,
    text: String,
    cumulative: String,
    highlight: bool,
    unavailable: bool,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

#[derive(Debug)]
pub(super) struct Summary {
    values: Vec<Value>,
    namespace: String,
}

impl Summary {
    pub(super) fn new(snapshot: &MonitorSnapshot) -> Self {
        let mut index: HashMap<&str, Vec<&SeriesSnapshot>> = HashMap::new();
        let partial_sources: HashSet<_> = snapshot
            .providers()
            .iter()
            .filter(|provider| matches!(provider.health(), ProviderHealth::Partial { .. }))
            .map(|provider| provider.provider().as_str())
            .collect();
        let mut incomplete = HashSet::new();
        for series in snapshot.series() {
            let id = series.metric().as_str();
            if id.starts_with("linux.socket.")
                || id.starts_with("linux.softirq.")
                || id.starts_with("linux.netfilter.conntrack.")
            {
                index.entry(id).or_default().push(series);
                if partial_sources.contains(series.source().as_str()) {
                    incomplete.insert(id);
                }
            }
        }
        let values = FIELDS
            .iter()
            .map(|field| {
                let rates = matches!(field.projection, Projection::Rate);
                let projected = project(&index, &incomplete, field.ids, rates);
                let value = projected.ok();
                let cumulative = if rates {
                    projected_number(project(&index, &incomplete, field.ids, false), false)
                } else {
                    "-".to_owned()
                };
                let text = match field.projection {
                    Projection::Memory => projected.map(memory).unwrap_or_else(str::to_owned),
                    Projection::MemoryLimit => memory_ratio(
                        project(&index, &incomplete, &field.ids[..1], false),
                        project(&index, &incomplete, &field.ids[1..], false),
                    ),
                    _ => projected_number(projected, rates),
                };
                Value {
                    field,
                    text,
                    cumulative,
                    highlight: field.warn && value.is_some_and(|value| value > 0.0),
                    unavailable: projected.is_err()
                        || (matches!(field.projection, Projection::MemoryLimit)
                            && project(&index, &incomplete, &field.ids[1..], false).is_err()),
                }
            })
            .collect();
        Self {
            values,
            namespace: snapshot.network_namespace().unwrap_or("unknown").to_owned(),
        }
    }

    pub(super) fn lines(&self, layer: Layer, width: u16, selected: bool) -> Vec<Line<'static>> {
        let width = usize::from(width).max(1);
        let columns = if width < 56 {
            1
        } else {
            (width / 30).clamp(2, 8)
        };
        let fields: Vec<_> = overview_fields(layer)
            .iter()
            .take(columns * 2)
            .filter_map(|(section, label)| {
                self.values.iter().find(|value| {
                    value.field.layer == layer
                        && value.field.section == *section
                        && value.field.label == *label
                })
            })
            .collect();
        let signals: Vec<_> = self
            .values
            .iter()
            .filter(|value| value.field.layer == layer && value.highlight)
            .collect();
        let unavailable = self
            .values
            .iter()
            .filter(|value| {
                value.field.layer == layer
                    && value.unavailable
                    && (value.field.overview
                        || overview_fields(layer)
                            .contains(&(value.field.section, value.field.label)))
            })
            .count();
        let scope = match layer {
            Layer::Softirq => "host".to_owned(),
            Layer::Sockets => format!("{} | orphan/mem: host", self.namespace),
            _ => self.namespace.clone(),
        };
        let mut result = vec![colored_heading(
            fit(
                &format!(
                    "{}  {} signals | {} unavailable | {}",
                    layer.title(),
                    signals.len(),
                    unavailable,
                    scope
                ),
                width.saturating_sub(1),
            )
            .trim_end(),
            selected,
            layer.color(),
        )];
        let cell_width = width.saturating_sub(1 + (columns - 1) * 3) / columns;
        let extra: Vec<_> = signals
            .into_iter()
            .filter(|value| !fields.iter().any(|primary| std::ptr::eq(*primary, *value)))
            .collect();
        // Stable core slots plus one bounded row of nonzero signals. The heading
        // counts all signals and unavailable metrics; detail retains every field.
        for batch in fields.chunks(columns).chain(extra.chunks(columns).take(1)) {
            let mut spans = vec![Span::raw(" ")];
            for (index, value) in batch.iter().enumerate() {
                if index > 0 {
                    spans.push(Span::styled(
                        " \u{2502} ",
                        Style::default().fg(theme::DIVIDER),
                    ));
                }
                let text_width = value.text.len().min(cell_width);
                let label_width = cell_width.saturating_sub(text_width + 1);
                let label = overview_label(value.field);
                let label = fit(&label, label_width).trim_end().to_owned();
                spans.push(Span::styled(
                    label.clone(),
                    Style::default().fg(theme::TEXT),
                ));
                let text = fit(&value.text, text_width).trim_end().to_owned();
                let gap = usize::from(!label.is_empty() && !text.is_empty());
                spans.push(Span::styled(
                    format!("{}{text}", " ".repeat(gap)),
                    value_style(value),
                ));
                spans.push(Span::raw(
                    " ".repeat(cell_width.saturating_sub(label.len() + gap + text.len())),
                ));
            }
            for _ in batch.len()..columns {
                spans.push(Span::styled(
                    " \u{2502} ",
                    Style::default().fg(theme::DIVIDER),
                ));
                spans.push(Span::raw(" ".repeat(cell_width)));
            }
            result.push(Line::from(spans));
        }
        result
    }

    pub(super) fn detail_lines(&self, layer: Layer, width: u16) -> Vec<Line<'static>> {
        let width = usize::from(width).max(40);
        let label_width = 24;
        let value_width = self
            .values
            .iter()
            .filter(|value| value.field.layer == layer)
            .map(|value| value.text.len())
            .max()
            .unwrap_or(0)
            .max(18);
        let total_width = if width >= 100 {
            self.values
                .iter()
                .filter(|value| value.field.layer == layer)
                .map(|value| value.cumulative.len())
                .max()
                .unwrap_or(0)
                .max(18)
        } else {
            0
        };
        let meaning_width = width
            .saturating_sub(label_width + value_width + total_width + 5)
            .max(1);
        let mut lines = Vec::new();
        let mut section = "";
        for value in self
            .values
            .iter()
            .filter(|value| value.field.layer == layer)
        {
            if section != value.field.section {
                section = value.field.section;
                let scope = match layer {
                    Layer::Softirq => "host".to_owned(),
                    Layer::Sockets => format!("{} | orphan/alloc/mem: host", self.namespace),
                    _ => self.namespace.clone(),
                };
                lines.push(heading(
                    fit(&format!("{section}  {scope}"), width.saturating_sub(1)).trim_end(),
                    false,
                ));
                lines.push(Line::styled(
                    format!(
                        " {:label_width$} {:>value_width$} {}MEANING",
                        "METRIC",
                        "RATE / CURRENT",
                        if total_width > 0 {
                            format!("{:>total_width$} ", "CUMULATIVE")
                        } else {
                            String::new()
                        }
                    ),
                    Style::default().fg(theme::MUTED),
                ));
            }
            let meaning = wrap(value.field.meaning, meaning_width);
            for (index, part) in meaning.iter().enumerate() {
                let first = index == 0;
                let mut spans = vec![
                    Span::raw(" "),
                    Span::styled(
                        fit(if first { value.field.label } else { "" }, label_width),
                        Style::default().fg(theme::TEXT),
                    ),
                    Span::styled(
                        format!(" {:>value_width$} ", if first { &value.text } else { "" }),
                        value_style(value),
                    ),
                ];
                if total_width > 0 {
                    spans.push(Span::styled(
                        format!(
                            "{:>total_width$} ",
                            if first { &value.cumulative } else { "" }
                        ),
                        Style::default().fg(theme::MUTED),
                    ));
                }
                spans.push(Span::styled(
                    part.clone(),
                    Style::default().fg(theme::MUTED),
                ));
                lines.push(Line::from(spans));
            }
        }
        lines
    }
}

// Priority is independent of current values, so missing samples never shift slots.
fn overview_fields(layer: Layer) -> &'static [(&'static str, &'static str)] {
    match layer {
        Layer::Sockets => &[
            ("SOCKETS", "TCP inuse"),
            ("SOCKETS", "TCP mem / max"),
            ("SOCKETS", "UDP inuse"),
            ("SOCKETS", "TCP CurrEstab"),
            ("SOCKETS", "TCP timewait"),
            ("SOCKETS", "TCP orphan"),
            ("SOCKETS", "ListenOverflows/s"),
            ("SOCKETS", "ListenDrops/s"),
            ("SOCKETS", "TCP alloc"),
            ("SOCKETS", "UDP memory"),
        ],
        Layer::Transport => &[
            ("TCP", "InSegs/s"),
            ("TCP", "OutSegs/s"),
            ("UDP", "InDatagrams/s"),
            ("UDP", "OutDatagrams/s"),
            ("TCP", "RetransSegs/s"),
            ("TCP", "TCPTimeouts/s"),
            ("UDP", "RcvbufErrors/s"),
            ("UDP", "SndbufErrors/s"),
            ("TCP", "OutRsts/s"),
            ("TCP", "EstabResets/s"),
            ("TCP", "ActiveOpens/s"),
            ("TCP", "PassiveOpens/s"),
        ],
        Layer::Network => &[
            ("IP", "IPv4 receive/s"),
            ("IP", "IPv4 forward/s"),
            ("IP", "IPv6 receive/s"),
            ("IP", "IPv6 forward/s"),
            ("ICMP", "InMsgs/s"),
            ("ICMP", "OutMsgs/s"),
            ("IP", "IPv4 noRoute/s"),
            ("IP", "IPv6 noRoute/s"),
            ("IP", "IPv4 reasmFail/s"),
            ("IP", "IPv6 reasmFail/s"),
            ("ICMP", "InUnreach/s"),
            ("ICMP", "OutUnreach/s"),
        ],
        Layer::Conntrack => &[
            ("CONNTRACK", "entries"),
            ("CONNTRACK", "maximum"),
            ("CONNTRACK", "drop/s"),
            ("CONNTRACK", "early_drop/s"),
            ("CONNTRACK", "insert_failed/s"),
            ("CONNTRACK", "invalid/s"),
            ("CONNTRACK", "insert/s"),
            ("CONNTRACK", "search_restart/s"),
        ],
        Layer::Softirq => &[
            ("SOFTIRQ", "NET_RX calls/s"),
            ("SOFTIRQ", "NET_TX calls/s"),
            ("SOFTIRQ", "dropped pck/s"),
            ("SOFTIRQ", "time_squeeze/s"),
            ("SOFTIRQ", "backlog packets"),
            ("SOFTIRQ", "processed pck/s"),
            ("SOFTIRQ", "flow_limit/s"),
            ("SOFTIRQ", "RPS IPI/s"),
            ("SOFTIRQ", "netdev_budget"),
            ("SOFTIRQ", "budget_usecs"),
            ("SOFTIRQ", "dev_weight"),
            ("SOFTIRQ", "max_backlog /CPU"),
        ],
    }
}

fn overview_label(field: &Field) -> String {
    if matches!(field.section, "TCP" | "UDP" | "ICMP") {
        // Kernel TcpExt names already carrying TCP need only one protocol prefix.
        format!(
            "{} {}",
            field.section,
            field.label.strip_prefix("TCP").unwrap_or(field.label)
        )
    } else {
        field.label.to_owned()
    }
}

fn aggregate(
    index: &HashMap<&str, Vec<&SeriesSnapshot>>,
    ids: &[&str],
    rate: bool,
) -> Result<f64, &'static str> {
    let mut total = 0.0;
    for id in ids {
        let rows = index.get(id).ok_or("n/a")?;
        for series in rows {
            // Namespace/host summaries must never absorb interface-attributed readings.
            if series.labels().get(MetricLabel::Interface).is_some() {
                return Err("n/a");
            }
            total += match series.value() {
                SeriesValue::Counter {
                    current: ProjectedValue::Fresh { value, .. },
                    interval,
                    ..
                } => {
                    if rate {
                        match interval {
                            Some(CounterContinuity::Reset) => return Err("reset"),
                            Some(CounterContinuity::RecoveredAfterGap) => return Err("gap"),
                            Some(CounterContinuity::FirstSample) | None => return Err("warmup"),
                            Some(interval) => interval.rate_per_second().ok_or("n/a")?,
                        }
                    } else {
                        *value as f64
                    }
                }
                SeriesValue::Gauge {
                    current: ProjectedValue::Fresh { value, .. },
                    ..
                } if !rate => *value as f64,
                SeriesValue::Counter {
                    current: ProjectedValue::Stale { .. },
                    ..
                }
                | SeriesValue::Gauge {
                    current: ProjectedValue::Stale { .. },
                    ..
                } => return Err("stale"),
                _ => return Err("n/a"),
            };
        }
    }
    total.is_finite().then_some(total).ok_or("n/a")
}

fn project(
    index: &HashMap<&str, Vec<&SeriesSnapshot>>,
    incomplete: &HashSet<&str>,
    ids: &[&str],
    rate: bool,
) -> Result<f64, &'static str> {
    if ids.iter().any(|id| incomplete.contains(id)) {
        return Err("partial");
    }
    aggregate(index, ids, rate)
}

fn projected_number(value: Result<f64, &'static str>, rate: bool) -> String {
    value
        .map(|value| number(Some(value), rate))
        .unwrap_or_else(str::to_owned)
}

fn memory_ratio(current: Result<f64, &'static str>, maximum: Result<f64, &'static str>) -> String {
    let current = current.and_then(|pages| memory_mib(pages).ok_or("n/a"));
    let maximum = maximum.and_then(|pages| memory_mib(pages).ok_or("n/a"));
    let magnitude = current.unwrap_or(0.0).max(maximum.unwrap_or(0.0));
    let (scale, unit) = if magnitude >= 1_048_576.0 {
        (1_048_576.0, "TiB")
    } else if magnitude >= 65_536.0 {
        (1024.0, "GiB")
    } else {
        (1.0, "MiB")
    };
    let format = |value: Result<f64, &'static str>| {
        value
            .map(|value| number(Some(value / scale), true))
            .unwrap_or_else(str::to_owned)
    };
    format!("{} / {} {unit}", format(current), format(maximum))
}

fn number(value: Option<f64>, rate: bool) -> String {
    value.map_or_else(
        || "n/a".to_owned(),
        |value| {
            if rate && value > 0.0 && value < 100.0 {
                format!("{value:.1}")
            } else {
                format!("{value:.0}")
            }
        },
    )
}

fn memory_value(pages: Option<f64>) -> String {
    number(pages.and_then(memory_mib), true)
}

fn memory_mib(pages: f64) -> Option<f64> {
    static PAGE_BYTES: OnceLock<Option<f64>> = OnceLock::new();
    let page_bytes = *PAGE_BYTES.get_or_init(|| {
        // sysconf is a read-only process-local query; a failure remains unavailable.
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        (value > 0).then_some(value as f64)
    });
    page_bytes.map(|bytes| pages * bytes / 1_048_576.0)
}

fn memory(pages: f64) -> String {
    format!("{} MiB", memory_value(Some(pages)))
}
fn value_style(value: &Value) -> Style {
    Style::default().fg(if value.highlight {
        theme::WARN
    } else if value.text.contains("n/a") || value.text == "0" {
        theme::MUTED
    } else {
        theme::TEXT_STRONG
    })
}

pub(super) fn heading(text: &str, selected: bool) -> Line<'static> {
    colored_heading(text, selected, theme::TEXT_STRONG)
}

pub(super) fn colored_heading(text: &str, selected: bool, color: Color) -> Line<'static> {
    Line::styled(
        format!(" {text}"),
        Style::default()
            .fg(color)
            .bg(if selected {
                theme::SELECTED_BG
            } else {
                theme::CHROME_BG
            })
            .add_modifier(Modifier::BOLD),
    )
}

pub(super) fn fit(text: &str, width: usize) -> String {
    let value: String = text.chars().take(width).collect();
    format!("{value:width$}")
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in text.split_whitespace() {
        if !lines.last().unwrap().is_empty() && lines.last().unwrap().len() + word.len() + 1 > width
        {
            lines.push(String::new());
        }
        let line = lines.last_mut().unwrap();
        if !line.is_empty() {
            line.push(' ');
        }
        for character in word.chars() {
            if lines.last().unwrap().chars().count() >= width {
                lines.push(String::new());
            }
            lines.last_mut().unwrap().push(character);
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{
        BaselineOrigin, HistoryCoverage, MetricId, MetricLabels, ProviderId, SeriesId,
    };
    use std::time::Duration;

    fn counter(
        id: u64,
        metric: &str,
        delta: CounterContinuity,
        cpu: Option<u32>,
    ) -> SeriesSnapshot {
        let descriptor = crate::monitor::descriptor(metric).unwrap();
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(descriptor.sources[0].provider).unwrap(),
            MetricId::new(metric).unwrap(),
            MetricLabels::new(cpu.map(|cpu| (MetricLabel::Cpu, cpu.to_string()))).unwrap(),
            Duration::ZERO,
            if delta == CounterContinuity::Reset {
                BaselineOrigin::Reset
            } else {
                BaselineOrigin::SessionStart
            },
            if delta == CounterContinuity::Reset {
                Duration::from_secs(1)
            } else {
                Duration::ZERO
            },
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: 1000,
                    observed_at: Duration::from_secs(1),
                },
                interval: Some(delta),
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    #[test]
    fn displayed_fields_resolve_to_real_catalog_metrics_and_compatible_units() {
        for field in FIELDS {
            let first = crate::monitor::descriptor(field.ids[0]).unwrap();
            for id in field.ids {
                let descriptor =
                    crate::monitor::descriptor(id).unwrap_or_else(|| panic!("missing {id}"));
                assert_eq!(descriptor.kind, first.kind, "{}: {id}", field.label);
                assert_eq!(descriptor.unit, first.unit, "{}: {id}", field.label);
                assert_eq!(descriptor.scope, first.scope, "{}: {id}", field.label);
                if matches!(field.projection, Projection::Rate) {
                    assert_eq!(descriptor.kind, crate::monitor::MetricKind::Counter);
                }
            }
        }
    }

    #[test]
    fn rates_sum_cpus_but_do_not_treat_missing_family_or_reset_as_zero() {
        let metric = "linux.softirq.net_rx";
        let delta = CounterContinuity::Continuous {
            delta: 50,
            elapsed: Duration::from_millis(500),
        };
        let a = counter(1, metric, delta, Some(0));
        let b = counter(2, metric, delta, Some(1));
        let index = HashMap::from([(metric, vec![&a, &b])]);
        assert_eq!(aggregate(&index, &[metric], true), Ok(200.0));
        assert_eq!(aggregate(&index, &[metric], false), Ok(2000.0));
        assert_eq!(
            project(&index, &HashSet::from([metric]), &[metric], true),
            Err("partial")
        );
        assert_eq!(
            aggregate(&index, &[metric, "linux.softirq.net_tx"], true),
            Err("n/a")
        );
        for (continuity, expected) in [
            (CounterContinuity::Reset, "reset"),
            (CounterContinuity::FirstSample, "warmup"),
            (CounterContinuity::RecoveredAfterGap, "gap"),
        ] {
            let invalid = counter(3, metric, continuity, Some(2));
            let index = HashMap::from([(metric, vec![&a, &invalid])]);
            assert_eq!(aggregate(&index, &[metric], true), Err(expected));
        }
    }

    #[test]
    fn overview_keeps_core_slots_and_bounds_signals_without_losing_detail() {
        let mut summary = Summary {
            namespace: "net:[42]".to_owned(),
            values: FIELDS
                .iter()
                .map(|field| Value {
                    field,
                    text: "0".to_owned(),
                    cumulative: "0".to_owned(),
                    highlight: false,
                    unavailable: false,
                })
                .collect(),
        };
        for width in [80, 120, 160] {
            for layer in Layer::ALL {
                assert_eq!(summary.lines(layer, width, false).len(), 3);
            }
        }
        let labels = |summary: &Summary| {
            summary
                .lines(Layer::Network, 80, false)
                .iter()
                .skip(1)
                .take(2)
                .map(Line::to_string)
                .collect::<Vec<_>>()
        };
        let core = labels(&summary);
        for value in summary
            .values
            .iter_mut()
            .filter(|v| v.field.layer == Layer::Network && v.field.warn)
        {
            value.highlight = true;
            value.text = "2.0".to_owned();
        }
        assert_eq!(labels(&summary), core);
        let overview = summary.lines(Layer::Network, 80, false);
        assert_eq!(overview.len(), 4);
        assert!(overview[3].to_string().contains("IPv4 noRoute/s"));
        assert!(summary
            .detail_lines(Layer::Network, 160)
            .iter()
            .any(|line| line.to_string().contains("InCsumErrors/s")));
        let first = summary
            .values
            .iter_mut()
            .find(|v| v.field.label == "IPv4 receive/s")
            .unwrap();
        first.text = "partial".to_owned();
        first.unavailable = true;
        assert!(summary.lines(Layer::Network, 80, false)[1]
            .to_string()
            .contains("partial"));
    }

    #[test]
    fn overview_grid_grows_with_width_and_keeps_values_close_to_labels() {
        let summary = Summary {
            namespace: "net:[42]".to_owned(),
            values: FIELDS
                .iter()
                .map(|field| Value {
                    field,
                    text: "12".to_owned(),
                    cumulative: "24".to_owned(),
                    highlight: false,
                    unavailable: false,
                })
                .collect(),
        };
        for layer in Layer::ALL {
            for &(section, label) in overview_fields(layer) {
                assert!(
                    FIELDS.iter().any(|field| field.layer == layer
                        && field.section == section
                        && field.label == label),
                    "missing {section} {label}"
                );
            }
            for (width, columns) in [(78, 2), (118, 3), (158, 5), (198, 6), (258, 8)] {
                let lines = summary.lines(layer, width, false);
                assert_eq!(lines[0].style.fg, Some(layer.color()));
                assert!(lines.iter().all(|line| line.width() <= width as usize));
                for line in &lines[1..] {
                    assert_eq!(line.to_string().matches('\u{2502}').count(), columns - 1);
                }
            }
        }
        assert!(summary.lines(Layer::Sockets, 198, false)[1]
            .to_string()
            .contains("TCP inuse 12"));
        assert!(summary.lines(Layer::Transport, 198, false)[1]
            .to_string()
            .contains("TCP Timeouts/s 12"));
    }

    #[test]
    fn overview_and_meaning_columns_fit_supported_widths() {
        let summary = Summary {
            namespace: "n".repeat(128),
            values: FIELDS
                .iter()
                .map(|field| Value {
                    field,
                    text: if matches!(field.projection, Projection::MemoryLimit) {
                        "1048576 / 2097152 MiB".to_owned()
                    } else {
                        "1234567".to_owned()
                    },
                    cumulative: u64::MAX.to_string(),
                    highlight: false,
                    unavailable: false,
                })
                .collect(),
        };
        for width in [80, 100, 120, 160, 200] {
            for layer in Layer::ALL {
                for line in summary
                    .lines(layer, width, false)
                    .into_iter()
                    .chain(summary.detail_lines(layer, width))
                {
                    assert!(
                        line.width() <= width as usize,
                        "{} width {width}: {line:?}",
                        layer.title()
                    );
                }
            }
        }
        assert!(summary.detail_lines(Layer::Softirq, 120)[0]
            .to_string()
            .contains("host"));
        assert!(memory_ratio(Ok(1_048_576.0 * 256.0), Ok(2_097_152.0 * 256.0)).ends_with("TiB"));
    }
}
