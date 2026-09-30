use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const HEADER_SIZE: usize = 48;
pub const MAX_SNAPLEN: usize = 9216;
pub const FLAG_PARTIAL: u8 = 1;
pub const FLAG_REDIRECT_META: u8 = 2;
pub const FLAG_XDP_FRAGS: u8 = 4;

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
        self.format_detail(true)
    }

    pub fn terminal_detail(&self) -> String {
        self.format_detail(false)
    }

    fn format_detail(&self, include_capture_metadata: bool) -> String {
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
        if self.flags & FLAG_PARTIAL != 0 {
            parts.push("partial".into());
        }
        if self.flags & FLAG_XDP_FRAGS != 0 {
            parts.push("multi-buffer".into());
        }
        if let Some(tuple) = packet_tuple(self.packet) {
            parts.push(tuple);
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

fn ethernet_type(packet: &[u8]) -> Option<(u16, usize)> {
    if packet.len() < 14 {
        return None;
    }
    let mut kind = u16::from_be_bytes([packet[12], packet[13]]);
    let mut offset = 14;
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
    let (kind, offset) = ethernet_type(packet)?;
    let (src, dst, proto, payload, ports_valid) = match kind {
        0x0800 if packet.len() >= offset + 20 => {
            let ihl = ((packet[offset] & 0x0f) as usize) * 4;
            if packet[offset] >> 4 != 4 || ihl < 20 || packet.len() < offset + ihl {
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
                ports_valid,
            )
        }
        _ => return None,
    };
    let ports = if ports_valid && (proto == 6 || proto == 17) && packet.len() >= payload + 4 {
        Some((
            u16::from_be_bytes([packet[payload], packet[payload + 1]]),
            u16::from_be_bytes([packet[payload + 2], packet[payload + 3]]),
        ))
    } else {
        None
    };
    Some(PacketFields {
        src,
        dst,
        protocol: proto,
        ports,
    })
}

pub fn packet_tuple(packet: &[u8]) -> Option<String> {
    let Some(fields) = packet_fields(packet) else {
        return ethernet_type(packet).map(|(kind, _)| format!("ethertype=0x{kind:04x}"));
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
        let event = Event::packet(2, 123, false, 14, &[0u8; 14]);
        assert_eq!(event.label(), "pcap-in");
        assert!(event.detail().contains("direction=rx"));
        assert!(!event.terminal_detail().contains("direction="));
        assert!(!event.detail().contains("partial"));
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
