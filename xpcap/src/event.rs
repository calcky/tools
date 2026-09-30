use anyhow::{bail, Result};
use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::icmpv6::Icmpv6Packet;
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::sll::SLLPacket;
use pnet_packet::tcp::{TcpFlags, TcpOptionNumbers, TcpPacket};
use pnet_packet::udp::UdpPacket;
use pnet_packet::vlan::VlanPacket;
use pnet_packet::Packet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const HEADER_SIZE: usize = 48;
pub const MAX_SNAPLEN: usize = 9216;
pub const FLAG_PARTIAL: u8 = 1;
pub const FLAG_REDIRECT_META: u8 = 2;
pub const FLAG_XDP_FRAGS: u8 = 4;
pub const FLAG_COOKED: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Stage {
    XdpIn = 1,
    XdpOut = 2,
    Redirect = 3,
    XskRx = 4,
    XskTx = 5,
    Pcap = 6,
}

impl Stage {
    pub const ALL: [Self; 6] = [
        Self::XdpIn,
        Self::XdpOut,
        Self::Redirect,
        Self::XskRx,
        Self::XskTx,
        Self::Pcap,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::XdpIn => "xdp-in",
            Self::XdpOut => "xdp-out",
            Self::Redirect => "redirect",
            Self::XskRx => "xsk-rx",
            Self::XskTx => "xsk-tx",
            Self::Pcap => "pcap",
        }
    }

    pub fn bit(self) -> u32 {
        1 << (self as u8 - 1)
    }
}

impl TryFrom<u8> for Stage {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::XdpIn,
            2 => Self::XdpOut,
            3 => Self::Redirect,
            4 => Self::XskRx,
            5 => Self::XskTx,
            6 => Self::Pcap,
            _ => bail!("unknown capture stage {value}"),
        })
    }
}

#[derive(Debug)]
pub struct Event<'a> {
    pub ts_ns: u64,
    pub ifindex: u32,
    pub queue: u32,
    pub prog_id: u32,
    pub map_id: u32,
    pub map_index: u32,
    pub to_ifindex: u32,
    pub packet_len: u32,
    pub result: i32,
    pub stage: Stage,
    pub action: u8,
    pub flags: u8,
    pub packet: &'a [u8],
}

impl<'a> Event<'a> {
    pub fn label(&self) -> &'static str {
        match self.stage {
            Stage::XskRx => "xsk-in",
            Stage::XskTx => "xsk-out",
            Stage::Pcap if self.action == 1 => "pcap-out",
            Stage::Pcap => "pcap-in",
            _ => self.stage.name(),
        }
    }

    pub fn packet(
        ifindex: u32,
        ts_ns: u64,
        outgoing: bool,
        packet_len: u32,
        packet: &'a [u8],
    ) -> Self {
        Self {
            ts_ns,
            ifindex,
            queue: u32::MAX,
            prog_id: 0,
            map_id: 0,
            map_index: 0,
            to_ifindex: 0,
            packet_len,
            result: 0,
            stage: Stage::Pcap,
            action: u8::from(outgoing),
            flags: u8::from(packet.len() < packet_len as usize),
            packet,
        }
    }

    pub fn cooked_packet(
        ifindex: u32,
        ts_ns: u64,
        outgoing: bool,
        packet_len: u32,
        packet: &'a [u8],
    ) -> Self {
        let mut event = Self::packet(ifindex, ts_ns, outgoing, packet_len, packet);
        event.flags |= FLAG_COOKED;
        event
    }

    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            bail!("short perf event");
        }
        let u32_at = |offset| u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap());
        let cap_len = u32_at(36) as usize;
        let expected = HEADER_SIZE + cap_len;
        if cap_len > MAX_SNAPLEN
            || cap_len > u32_at(32) as usize
            || data.len() < expected
            || data.len() - expected > 7
        {
            bail!("invalid capture length");
        }
        Ok(Self {
            ts_ns: u64::from_ne_bytes(data[0..8].try_into().unwrap()),
            ifindex: u32_at(8),
            queue: u32_at(12),
            prog_id: u32_at(16),
            map_id: u32_at(20),
            map_index: u32_at(24),
            to_ifindex: u32_at(28),
            packet_len: u32_at(32),
            result: i32::from_ne_bytes(data[40..44].try_into().unwrap()),
            stage: Stage::try_from(data[44])?,
            action: data[45],
            flags: data[47],
            packet: &data[HEADER_SIZE..expected],
        })
    }

    pub fn detail(&self) -> String {
        self.format_detail(true, false)
    }

    pub fn terminal_detail(&self) -> String {
        self.terminal_detail_with_options(false)
    }

    pub fn terminal_detail_with_options(&self, verbose: bool) -> String {
        self.format_detail(false, verbose)
    }

    pub fn link_detail(&self) -> String {
        let cooked = self.flags & FLAG_COOKED != 0;
        let (mut text, mut kind, mut offset) = if cooked {
            if self.packet.len() < 16 {
                return format!("[|sll], length {}: ", self.packet_len);
            }
            let Some(header) = SLLPacket::new(self.packet) else {
                return format!("[|sll], length {}: ", self.packet_len);
            };
            let packet_type = match header.get_packet_type() {
                0 => "host".to_string(),
                1 => "broadcast".to_string(),
                2 => "multicast".to_string(),
                3 => "otherhost".to_string(),
                4 => "outgoing".to_string(),
                other => format!("type {other}"),
            };
            let mut text = format!("SLL {packet_type}");
            let address = header.get_link_layer_address();
            let length = (header.get_link_layer_address_len() as usize).min(address.len());
            if length > 0 {
                text.push_str(&format!(", addr {}", hex_address(&address[..length])));
            }
            (text, header.get_protocol().0, 16)
        } else {
            if self.packet.len() < 14 {
                return format!("[|ether], length {}: ", self.packet_len);
            }
            let Some(header) = EthernetPacket::new(self.packet) else {
                return format!("[|ether], length {}: ", self.packet_len);
            };
            (
                format!("{} > {}", header.get_source(), header.get_destination()),
                header.get_ethertype().0,
                14,
            )
        };
        text.push_str(&format!(
            ", ethertype {} (0x{kind:04x})",
            ethertype_name(kind)
        ));
        for _ in 0..2 {
            if !matches!(kind, 0x8100 | 0x88a8) {
                break;
            }
            let Some(tag) = self
                .packet
                .get(offset..offset + 4)
                .and_then(VlanPacket::new)
            else {
                text.push_str(", [|vlan]");
                break;
            };
            text.push_str(&format!(", vlan {}", tag.get_vlan_identifier()));
            if tag.get_priority_code_point().0 != 0 {
                text.push_str(&format!(", p {}", tag.get_priority_code_point().0));
            }
            if tag.get_drop_eligible_indicator() != 0 {
                text.push_str(", dei 1");
            }
            kind = tag.get_ethertype().0;
            offset += 4;
            text.push_str(&format!(
                ", ethertype {} (0x{kind:04x})",
                ethertype_name(kind)
            ));
        }
        format!("{text}, length {}: ", self.packet_len)
    }

    fn format_detail(&self, include_capture_metadata: bool, verbose: bool) -> String {
        let mut parts = Vec::new();
        if self.prog_id != 0 {
            parts.push(format!("prog={}", self.prog_id));
        }
        if self.stage == Stage::XdpOut {
            const ACTIONS: [&str; 5] = ["ABORTED", "DROP", "PASS", "TX", "REDIRECT"];
            parts.push(format!(
                "action={}",
                ACTIONS.get(self.action as usize).unwrap_or(&"UNKNOWN")
            ));
        }
        if self.stage == Stage::Redirect {
            if self.flags & FLAG_REDIRECT_META != 0 {
                parts.push(format!(
                    "map={} index={} to_ifindex={}",
                    self.map_id, self.map_index, self.to_ifindex
                ));
            } else {
                parts.push("target=unavailable".into());
            }
            parts.push(format!("result={}", self.result));
        }
        if include_capture_metadata && self.stage == Stage::XskTx {
            parts.push(format!(
                "path={}",
                match self.action {
                    0 => "generic",
                    1 => "single",
                    2 => "batch",
                    3 => "generic-direct-attempt",
                    _ => "unknown",
                }
            ));
        }
        if include_capture_metadata && self.stage == Stage::Pcap {
            parts.push(
                if self.action == 1 {
                    "direction=tx"
                } else {
                    "direction=rx"
                }
                .into(),
            );
        }
        if self.flags & FLAG_PARTIAL != 0 && (include_capture_metadata || self.stage != Stage::Pcap)
        {
            parts.push("partial".into());
        }
        if self.flags & FLAG_XDP_FRAGS != 0 {
            parts.push("multi-buffer".into());
        }
        let cooked = self.flags & FLAG_COOKED != 0;
        let tuple = if include_capture_metadata {
            packet_tuple_with_link(self.packet, cooked)
        } else {
            terminal_packet_tuple(self.packet, cooked, self.packet_len, verbose)
        };
        if let Some(tuple) = tuple {
            if include_capture_metadata {
                parts.push(tuple);
            } else {
                parts.insert(0, tuple);
            }
        }
        parts.join(" ")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PacketFields {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub ports: Option<(u16, u16)>,
}

struct PacketView<'a> {
    fields: PacketFields,
    transport: &'a [u8],
    transport_len: usize,
    transport_valid: bool,
}

fn hex_address(address: &[u8]) -> String {
    address
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ethertype_name(kind: u16) -> &'static str {
    match kind {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x8100 => "802.1Q",
        0x86dd => "IPv6",
        0x88a8 => "802.1ad",
        _ => "unknown",
    }
}

fn frame_type(packet: &[u8], cooked: bool) -> Option<(u16, usize)> {
    let (type_offset, mut offset) = if cooked { (14, 16) } else { (12, 14) };
    if packet.len() < offset {
        return None;
    }
    let mut kind = u16::from_be_bytes([packet[type_offset], packet[type_offset + 1]]);
    for _ in 0..2 {
        if kind != 0x8100 && kind != 0x88a8 {
            break;
        }
        if packet.len() < offset + 4 {
            return None;
        }
        kind = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        offset += 4;
    }
    Some((kind, offset))
}

pub fn packet_fields(packet: &[u8]) -> Option<PacketFields> {
    packet_fields_with_link(packet, false)
}

fn packet_fields_with_link(packet: &[u8], cooked: bool) -> Option<PacketFields> {
    packet_view(packet, cooked).map(|view| view.fields)
}

fn packet_view(packet: &[u8], cooked: bool) -> Option<PacketView<'_>> {
    let (kind, offset) = frame_type(packet, cooked)?;
    let (src, dst, proto, payload, ip_end, ports_valid) = match kind {
        0x0800 if packet.len() >= offset + 20 => {
            let ihl = ((packet[offset] & 0x0f) as usize) * 4;
            if packet[offset] >> 4 != 4 || ihl < 20 || packet.len() < offset + ihl {
                return None;
            }
            let declared = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            let ip_len = if declared == 0 {
                packet.len() - offset
            } else {
                declared
            };
            if ip_len < ihl {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset + 12],
                    packet[offset + 13],
                    packet[offset + 14],
                    packet[offset + 15],
                )),
                IpAddr::V4(Ipv4Addr::new(
                    packet[offset + 16],
                    packet[offset + 17],
                    packet[offset + 18],
                    packet[offset + 19],
                )),
                packet[offset + 9],
                offset + ihl,
                offset + ip_len,
                u16::from_be_bytes([packet[offset + 6], packet[offset + 7]]) & 0x1fff == 0,
            )
        }
        0x86dd if packet.len() >= offset + 40 => {
            if packet[offset] >> 4 != 6 {
                return None;
            }
            let src: [u8; 16] = packet[offset + 8..offset + 24].try_into().ok()?;
            let dst: [u8; 16] = packet[offset + 24..offset + 40].try_into().ok()?;
            let mut next = packet[offset + 6];
            let mut payload = offset + 40;
            let declared = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]) as usize;
            let ip_end = if declared == 0 {
                packet.len()
            } else {
                payload + declared
            };
            let mut ports_valid = true;
            for _ in 0..4 {
                if !matches!(next, 0 | 43 | 44 | 60) {
                    break;
                }
                if packet.len() < payload + 8 {
                    ports_valid = false;
                    break;
                }
                let length = if next == 44 {
                    if u16::from_be_bytes([packet[payload + 2], packet[payload + 3]]) & 0xfff8 != 0
                    {
                        ports_valid = false;
                    }
                    8
                } else {
                    (packet[payload + 1] as usize + 1) * 8
                };
                if packet.len() < payload + length {
                    ports_valid = false;
                    break;
                }
                next = packet[payload];
                payload += length;
            }
            (
                IpAddr::V6(Ipv6Addr::from(src)),
                IpAddr::V6(Ipv6Addr::from(dst)),
                next,
                payload,
                ip_end,
                ports_valid,
            )
        }
        _ => return None,
    };
    let transport_len = ip_end.saturating_sub(payload);
    let transport = packet.get(payload..packet.len().min(ip_end)).unwrap_or(&[]);
    let ports = if ports_valid && (proto == 6 || proto == 17) && transport.len() >= 4 {
        Some((
            u16::from_be_bytes([transport[0], transport[1]]),
            u16::from_be_bytes([transport[2], transport[3]]),
        ))
    } else {
        None
    };
    Some(PacketView {
        fields: PacketFields {
            src,
            dst,
            protocol: proto,
            ports,
        },
        transport,
        transport_len,
        transport_valid: ports_valid,
    })
}

pub fn packet_tuple(packet: &[u8]) -> Option<String> {
    packet_tuple_with_link(packet, false)
}

fn packet_tuple_with_link(packet: &[u8], cooked: bool) -> Option<String> {
    let Some(fields) = packet_fields_with_link(packet, cooked) else {
        return frame_type(packet, cooked).map(|(kind, _)| format!("ethertype=0x{kind:04x}"));
    };
    let protocol = match fields.protocol {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmp6",
        _ => "ip",
    };
    if let Some((sport, dport)) = fields.ports {
        Some(format!(
            "{protocol} {}:{sport} > {}:{dport}",
            fields.src, fields.dst
        ))
    } else {
        Some(format!("{protocol} {} > {}", fields.src, fields.dst))
    }
}

fn terminal_packet_tuple(
    packet: &[u8],
    cooked: bool,
    frame_len: u32,
    verbose: bool,
) -> Option<String> {
    let Some(view) = packet_view(packet, cooked) else {
        return Some(match frame_type(packet, cooked) {
            Some((kind, _)) => format!("ethertype 0x{kind:04x}, frame length {frame_len}"),
            None => format!("[|link], frame length {frame_len}"),
        });
    };
    let fields = &view.fields;
    let family = if fields.src.is_ipv6() { "IP6" } else { "IP" };
    let (src, dst) = if let Some((sport, dport)) = fields.ports {
        (
            format!("{}.{sport}", fields.src),
            format!("{}.{dport}", fields.dst),
        )
    } else {
        (fields.src.to_string(), fields.dst.to_string())
    };
    let detail = match fields.protocol {
        6 if view.transport_valid => tcp_summary(view.transport, view.transport_len),
        17 if view.transport_valid => udp_summary(view.transport, view.transport_len),
        1 => icmp_summary(view.transport, view.transport_len, false),
        58 => icmp_summary(view.transport, view.transport_len, true),
        protocol => format!("proto {protocol}, length {}", view.transport_len),
    };
    let ip_detail = if verbose {
        ip_verbose_detail(packet, cooked, fields.protocol)
            .map(|detail| format!(" ({detail})"))
            .unwrap_or_default()
    } else {
        String::new()
    };
    Some(format!("{family}{ip_detail} {src} > {dst}: {detail}"))
}

fn ip_verbose_detail(packet: &[u8], cooked: bool, protocol: u8) -> Option<String> {
    let (kind, offset) = frame_type(packet, cooked)?;
    let bytes = packet.get(offset..)?;
    let protocol_name = match protocol {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMP6",
        _ => "unknown",
    };
    match kind {
        0x0800 => {
            let ip = Ipv4Packet::new(bytes)?;
            let header_len = ip.get_header_length() as usize * 4;
            if ip.get_version() != 4 || header_len < 20 || header_len > bytes.len() {
                return None;
            }
            let flags = ip.get_flags();
            let flags = match (
                flags & Ipv4Flags::DontFragment != 0,
                flags & Ipv4Flags::MoreFragments != 0,
            ) {
                (true, true) => "DF,MF",
                (true, false) => "DF",
                (false, true) => "MF",
                (false, false) => "none",
            };
            let tos = (ip.get_dscp() << 2) | ip.get_ecn();
            Some(format!(
                "tos 0x{tos:02x}, ttl {}, id {}, offset {}, flags [{flags}], proto {protocol_name} ({protocol}), length {}, cksum 0x{:04x}",
                ip.get_ttl(),
                ip.get_identification(),
                ip.get_fragment_offset() as usize * 8,
                ip.get_total_length(),
                ip.get_checksum(),
            ))
        }
        0x86dd => {
            let ip = Ipv6Packet::new(bytes)?;
            if ip.get_version() != 6 {
                return None;
            }
            Some(format!(
                "tc 0x{:02x}, flowlabel 0x{:05x}, hlim {}, next {protocol_name} ({protocol}), plen {}",
                ip.get_traffic_class(),
                ip.get_flow_label(),
                ip.get_hop_limit(),
                ip.get_payload_length(),
            ))
        }
        _ => None,
    }
}

fn tcp_summary(bytes: &[u8], wire_len: usize) -> String {
    let Some(tcp) = TcpPacket::new(bytes) else {
        return "[|tcp]".into();
    };
    let header_len = tcp.get_data_offset() as usize * 4;
    if header_len < 20 || header_len > bytes.len() || header_len > wire_len {
        return "[|tcp]".into();
    }
    let flags = tcp.get_flags();
    let mut flag_text = String::new();
    for (bit, label) in [
        (TcpFlags::FIN, 'F'),
        (TcpFlags::SYN, 'S'),
        (TcpFlags::RST, 'R'),
        (TcpFlags::PSH, 'P'),
        (TcpFlags::ACK, '.'),
        (TcpFlags::URG, 'U'),
        (TcpFlags::ECE, 'E'),
        (TcpFlags::CWR, 'W'),
    ] {
        if flags & bit != 0 {
            flag_text.push(label);
        }
    }
    if flag_text.is_empty() {
        flag_text.push_str("none");
    }
    let payload_len = wire_len - header_len;
    let mut text = format!("Flags [{flag_text}]");
    if payload_len > 0 {
        let seq = tcp.get_sequence();
        text.push_str(&format!(
            ", seq {seq}:{}",
            seq.wrapping_add(payload_len as u32)
        ));
    } else if flags & (TcpFlags::SYN | TcpFlags::FIN) != 0 {
        text.push_str(&format!(", seq {}", tcp.get_sequence()));
    }
    if flags & TcpFlags::ACK != 0 {
        text.push_str(&format!(", ack {}", tcp.get_acknowledgement()));
    }
    text.push_str(&format!(", win {}", tcp.get_window()));
    if flags & TcpFlags::URG != 0 {
        text.push_str(&format!(", urg {}", tcp.get_urgent_ptr()));
    }
    let options: Vec<_> = tcp
        .get_options_iter()
        .filter_map(format_tcp_option)
        .collect();
    if !options.is_empty() {
        text.push_str(&format!(", options [{}]", options.join(",")));
    }
    text.push_str(&format!(", length {payload_len}"));
    text
}

fn format_tcp_option(option: pnet_packet::tcp::TcpOptionPacket<'_>) -> Option<String> {
    let data = option.payload();
    match option.get_number() {
        TcpOptionNumbers::EOL => None,
        TcpOptionNumbers::NOP => Some("nop".into()),
        TcpOptionNumbers::MSS if data.len() == 2 => {
            Some(format!("mss {}", u16::from_be_bytes([data[0], data[1]])))
        }
        TcpOptionNumbers::WSCALE if data.len() == 1 => Some(format!("wscale {}", data[0])),
        TcpOptionNumbers::SACK_PERMITTED => Some("sackOK".into()),
        TcpOptionNumbers::TIMESTAMPS if data.len() == 8 => {
            let val = u32::from_be_bytes(data[..4].try_into().ok()?);
            let ecr = u32::from_be_bytes(data[4..].try_into().ok()?);
            Some(format!("TS val {val} ecr {ecr}"))
        }
        TcpOptionNumbers::SACK if data.len() >= 8 && data.len().is_multiple_of(8) => {
            let blocks = data
                .as_chunks::<8>()
                .0
                .iter()
                .map(|block| {
                    let left = u32::from_be_bytes(block[..4].try_into().unwrap());
                    let right = u32::from_be_bytes(block[4..].try_into().unwrap());
                    format!("{left}:{right}")
                })
                .collect::<Vec<_>>();
            Some(format!("sack {}", blocks.join(" ")))
        }
        number => Some(format!("opt {}", number.0)),
    }
}

fn udp_summary(bytes: &[u8], wire_len: usize) -> String {
    let Some(udp) = UdpPacket::new(bytes) else {
        return "[|udp]".into();
    };
    if wire_len < 8 || udp.get_length() < 8 {
        return "[bad udp length]".into();
    }
    format!("UDP, length {}", udp.get_length() as usize - 8)
}

fn icmp_summary(bytes: &[u8], wire_len: usize, v6: bool) -> String {
    let (kind, code) = if v6 {
        let Some(packet) = Icmpv6Packet::new(bytes) else {
            return "[|icmp6]".into();
        };
        (packet.get_icmpv6_type().0, packet.get_icmpv6_code().0)
    } else {
        let Some(packet) = IcmpPacket::new(bytes) else {
            return "[|icmp]".into();
        };
        (packet.get_icmp_type().0, packet.get_icmp_code().0)
    };
    let label = match (v6, kind) {
        (false, 8) | (true, 128) => "echo request",
        (false, 0) | (true, 129) => "echo reply",
        (false, 3) | (true, 1) => "destination unreachable",
        (false, 11) | (true, 3) => "time exceeded",
        (true, 2) => "packet too big",
        _ => {
            return format!(
                "ICMP{} type {kind} code {code}, length {wire_len}",
                if v6 { "6" } else { "" }
            )
        }
    };
    let prefix = if v6 { "ICMP6" } else { "ICMP" };
    if matches!((v6, kind), (false, 8 | 0) | (true, 128 | 129)) {
        if let Some(echo) = bytes.get(4..8) {
            let id = u16::from_be_bytes([echo[0], echo[1]]);
            let seq = u16::from_be_bytes([echo[2], echo[3]]);
            return format!("{prefix} {label}, id {id}, seq {seq}, length {wire_len}");
        }
        return format!("{prefix} {label} [|icmp]");
    }
    format!("{prefix} {label} (code {code}), length {wire_len}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_and_invalid_events() {
        assert!(Event::parse(&[0; 10]).is_err());
        let mut raw = [0; HEADER_SIZE];
        raw[44] = 99;
        assert!(Event::parse(&raw).is_err());
        raw[44] = 1;
        raw[36..40].copy_from_slice(&5u32.to_ne_bytes());
        assert!(Event::parse(&raw).is_err());
    }

    #[test]
    fn conventional_packet_marks_direction_and_truncation() {
        let event = Event::packet(2, 123, true, 100, &[0u8; 14]);
        assert_eq!(event.stage, Stage::Pcap);
        assert_eq!(event.label(), "pcap-out");
        assert_eq!(event.queue, u32::MAX);
        assert!(event.detail().contains("direction=tx"));
        assert!(!event.terminal_detail().contains("direction="));
        assert!(event.detail().contains("partial"));
        assert!(!event.terminal_detail().contains("partial"));
        let event = Event::packet(2, 123, false, 14, &[0u8; 14]);
        assert_eq!(event.label(), "pcap-in");
        assert!(event.detail().contains("direction=rx"));
        assert!(!event.terminal_detail().contains("direction="));
        assert!(!event.detail().contains("partial"));
    }

    #[test]
    fn cooked_packet_has_tcpdump_style_summary() {
        let mut packet = vec![0u8; 16 + 20 + 8];
        packet[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        packet[16] = 0x45;
        packet[25] = 17;
        packet[28..32].copy_from_slice(&[192, 0, 2, 1]);
        packet[32..36].copy_from_slice(&[192, 0, 2, 2]);
        packet[36..38].copy_from_slice(&1234u16.to_be_bytes());
        packet[38..40].copy_from_slice(&9000u16.to_be_bytes());
        packet[40..42].copy_from_slice(&8u16.to_be_bytes());
        let event = Event::cooked_packet(3, 1, false, packet.len() as u32, &packet);
        assert!(event
            .terminal_detail()
            .contains("IP 192.0.2.1.1234 > 192.0.2.2.9000: UDP"));
        assert!(event
            .detail()
            .contains("udp 192.0.2.1:1234 > 192.0.2.2:9000"));
    }

    #[test]
    fn ethernet_vlan_and_cooked_link_headers_are_distinct() {
        let mut frame = ipv4_frame(17, &[0; 8]);
        frame[..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.link_detail(),
            format!(
                "06:07:08:09:0a:0b > 00:01:02:03:04:05, ethertype IPv4 (0x0800), length {}: ",
                frame.len()
            )
        );

        let mut tagged = Vec::from(&frame[..14]);
        tagged[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        tagged.extend_from_slice(&[0x60, 0x64, 0x08, 0x00]);
        tagged.extend_from_slice(&frame[14..]);
        let event = Event::packet(2, 1, false, tagged.len() as u32, &tagged);
        let link = event.link_detail();
        assert!(link.contains("ethertype 802.1Q (0x8100), vlan 100, p 3, ethertype IPv4 (0x0800)"));
        assert!(event.terminal_detail().contains("IP 192.0.2.1"));

        let mut cooked = vec![0u8; 16 + frame.len() - 14];
        cooked[0..2].copy_from_slice(&4u16.to_be_bytes());
        cooked[2..4].copy_from_slice(&1u16.to_be_bytes());
        cooked[4..6].copy_from_slice(&6u16.to_be_bytes());
        cooked[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
        cooked[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        cooked[16..].copy_from_slice(&frame[14..]);
        let event = Event::cooked_packet(2, 1, true, cooked.len() as u32, &cooked);
        let link = event.link_detail();
        assert!(link.starts_with("SLL outgoing, addr 06:07:08:09:0a:0b, ethertype IPv4 (0x0800)"));
        assert!(!link.contains(" > "));
    }

    #[test]
    fn truncated_link_headers_do_not_invent_addresses_or_tags() {
        let frame = ipv4_frame(17, &[0; 8]);
        for caplen in 0..18 {
            let event = Event::packet(2, 1, false, frame.len() as u32, &frame[..caplen]);
            let link = event.link_detail();
            if caplen < 14 {
                assert!(link.starts_with("[|ether]"));
            }
        }
        let mut vlan = Vec::from(&frame[..14]);
        vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        vlan.extend_from_slice(&[0x00, 0x64, 0x08, 0x00]);
        let event = Event::packet(2, 1, false, vlan.len() as u32, &vlan[..16]);
        assert!(event.link_detail().contains("[|vlan]"));

        let cooked = [0u8; 16];
        for caplen in 0..16 {
            let event = Event::cooked_packet(2, 1, false, 16, &cooked[..caplen]);
            assert!(event.link_detail().starts_with("[|sll]"));
        }
    }

    #[test]
    fn verbose_ipv4_reports_header_fields_without_changing_default() {
        let mut frame = ipv4_frame(6, &[0; 20]);
        frame[15] = 0x10;
        frame[18..20].copy_from_slice(&42u16.to_be_bytes());
        frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        frame[22] = 64;
        frame[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
        frame[46] = 5 << 4;
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert!(!event.terminal_detail().contains("ttl"));
        assert!(event.terminal_detail_with_options(true).contains(
            "IP (tos 0x10, ttl 64, id 42, offset 0, flags [DF], proto TCP (6), length 40, cksum 0x1234)"
        ));
    }

    fn ipv4_frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + transport.len()];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        frame[23] = protocol;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        frame[34..].copy_from_slice(transport);
        frame
    }

    #[test]
    fn tcp_syn_options_and_data_use_payload_length() {
        let mut syn = [0u8; 24];
        syn[0..2].copy_from_slice(&1234u16.to_be_bytes());
        syn[2..4].copy_from_slice(&443u16.to_be_bytes());
        syn[4..8].copy_from_slice(&100u32.to_be_bytes());
        syn[12] = 6 << 4;
        syn[13] = TcpFlags::SYN;
        syn[14..16].copy_from_slice(&64240u16.to_be_bytes());
        syn[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        let frame = ipv4_frame(6, &syn);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.terminal_detail(),
            "IP 192.0.2.1.1234 > 192.0.2.2.443: Flags [S], seq 100, win 64240, options [mss 1460], length 0"
        );

        let mut data = vec![0u8; 25];
        data[0..2].copy_from_slice(&443u16.to_be_bytes());
        data[2..4].copy_from_slice(&1234u16.to_be_bytes());
        data[4..8].copy_from_slice(&200u32.to_be_bytes());
        data[8..12].copy_from_slice(&101u32.to_be_bytes());
        data[12] = 5 << 4;
        data[13] = TcpFlags::PSH | TcpFlags::ACK;
        data[14..16].copy_from_slice(&4096u16.to_be_bytes());
        let frame = ipv4_frame(6, &data);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.terminal_detail(),
            "IP 192.0.2.1.443 > 192.0.2.2.1234: Flags [P.], seq 200:205, ack 101, win 4096, length 5"
        );
    }

    #[test]
    fn udp_icmp_and_short_tcp_do_not_report_frame_length_as_payload() {
        let mut udp = [0u8; 12];
        udp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&12u16.to_be_bytes());
        let frame = ipv4_frame(17, &udp);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.terminal_detail(),
            "IP 192.0.2.1.1234 > 192.0.2.2.53: UDP, length 4"
        );

        let mut echo = [0u8; 12];
        echo[0] = 8;
        echo[4..6].copy_from_slice(&42u16.to_be_bytes());
        echo[6..8].copy_from_slice(&7u16.to_be_bytes());
        let frame = ipv4_frame(1, &echo);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.terminal_detail(),
            "IP 192.0.2.1 > 192.0.2.2: ICMP echo request, id 42, seq 7, length 12"
        );

        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 5 << 4;
        let frame = ipv4_frame(6, &tcp);
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame[..38]);
        assert!(event.terminal_detail().contains("[|tcp]"));
        assert!(!event.terminal_detail().contains("seq "));
    }

    #[test]
    fn ipv6_extension_header_reaches_udp_payload() {
        let mut frame = vec![0u8; 14 + 40 + 8 + 12];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&20u16.to_be_bytes());
        frame[20] = 0;
        frame[21] = 64;
        frame[22..38].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame[38..54].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        frame[54] = 17;
        frame[62..64].copy_from_slice(&1234u16.to_be_bytes());
        frame[64..66].copy_from_slice(&9000u16.to_be_bytes());
        frame[66..68].copy_from_slice(&12u16.to_be_bytes());
        let event = Event::packet(2, 1, false, frame.len() as u32, &frame);
        assert_eq!(
            event.terminal_detail(),
            "IP6 ::1.1234 > ::1.9000: UDP, length 4"
        );
        assert!(event
            .terminal_detail_with_options(true)
            .contains("IP6 (tc 0x00, flowlabel 0x00000, hlim 64, next UDP (17), plen 20)"));
    }

    #[test]
    fn every_tcp_capture_prefix_is_safe_to_format() {
        let mut tcp = [0u8; 24];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 6 << 4;
        tcp[13] = TcpFlags::SYN;
        tcp[20..24].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        let frame = ipv4_frame(6, &tcp);
        for caplen in 0..frame.len() {
            let event = Event::packet(2, 1, false, frame.len() as u32, &frame[..caplen]);
            let text = event.terminal_detail();
            if caplen < frame.len() {
                assert!(!text.contains("mss 1460"));
            }
        }
    }

    #[test]
    fn complete_multi_buffer_packet_is_not_marked_partial() {
        let mut event = Event::packet(2, 123, false, 14, &[0u8; 14]);
        event.stage = Stage::XdpIn;
        event.flags = FLAG_XDP_FRAGS;
        assert!(event.detail().contains("multi-buffer"));
        assert!(!event.detail().contains("partial"));
    }

    #[test]
    fn decodes_event_and_stage_details() {
        let mut raw = vec![0; HEADER_SIZE + 16];
        raw[8..12].copy_from_slice(&7u32.to_ne_bytes());
        raw[12..16].copy_from_slice(&3u32.to_ne_bytes());
        raw[32..36].copy_from_slice(&100u32.to_ne_bytes());
        raw[36..40].copy_from_slice(&14u32.to_ne_bytes());
        raw[44] = Stage::XskTx as u8;
        raw[45] = 2;
        raw[47] = FLAG_PARTIAL;
        let event = Event::parse(&raw).unwrap();
        assert_eq!(event.ifindex, 7);
        assert_eq!(event.queue, 3);
        assert_eq!(event.packet.len(), 14);
        assert!(event.detail().contains("path=batch"));
        assert!(!event.terminal_detail().contains("path="));
        assert!(event.detail().contains("partial"));
    }

    #[test]
    fn does_not_invent_ports_for_noninitial_fragments() {
        let mut v4 = vec![0u8; 14 + 20 + 8];
        v4[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        v4[14] = 0x45;
        v4[20..22].copy_from_slice(&1u16.to_be_bytes());
        v4[23] = 17;
        v4[34..38].copy_from_slice(&[0, 1, 0, 2]);
        let text = packet_tuple(&v4).unwrap();
        assert!(text.starts_with("udp "));
        assert!(!text.contains(":1"));

        let mut v6 = vec![0u8; 14 + 40 + 8 + 8];
        v6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        v6[14] = 0x60;
        v6[20] = 44;
        v6[54] = 17;
        v6[56..58].copy_from_slice(&8u16.to_be_bytes());
        v6[62..66].copy_from_slice(&[0, 1, 0, 2]);
        let text = packet_tuple(&v6).unwrap();
        assert!(text.starts_with("udp "));
        assert!(!text.contains(":1"));
    }
}
