use crate::event::{Event, FLAG_COOKED};
use std::collections::HashMap;
use std::io::{self, Write};

pub struct PcapngWriter<W: Write> {
    output: W,
    interfaces: HashMap<u32, u32>,
}

impl<W: Write> PcapngWriter<W> {
    pub fn new(output: W) -> io::Result<Self> {
        let mut writer = Self {
            output,
            interfaces: HashMap::new(),
        };
        let mut body = Vec::new();
        body.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&u64::MAX.to_le_bytes());
        writer.block(0x0a0d0d0a, &body)?;
        Ok(writer)
    }

    fn block(&mut self, kind: u32, body: &[u8]) -> io::Result<()> {
        let size = 12 + body.len();
        let size = u32::try_from(size).map_err(|_| io::Error::other("pcapng block too large"))?;
        self.output.write_all(&kind.to_le_bytes())?;
        self.output.write_all(&size.to_le_bytes())?;
        self.output.write_all(body)?;
        self.output.write_all(&size.to_le_bytes())
    }

    fn option(body: &mut Vec<u8>, kind: u16, bytes: &[u8]) {
        body.extend_from_slice(&kind.to_le_bytes());
        body.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        body.extend_from_slice(bytes);
        body.resize(body.len().div_ceil(4) * 4, 0);
    }

    pub fn add_interface(&mut self, ifindex: u32, name: &str) -> io::Result<()> {
        self.add_interface_with_link(ifindex, name, 1)
    }

    pub fn add_cooked_any(&mut self) -> io::Result<()> {
        self.add_interface_with_link(0, "any", 113)
    }

    fn add_interface_with_link(&mut self, ifindex: u32, name: &str, link: u16) -> io::Result<()> {
        if self.interfaces.contains_key(&ifindex) {
            return Ok(());
        }
        let mut body = Vec::new();
        body.extend_from_slice(&link.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&9216u32.to_le_bytes());
        Self::option(&mut body, 2, name.as_bytes()); // if_name
        Self::option(&mut body, 9, &[9]); // nanosecond timestamps
        Self::option(&mut body, 0, &[]);
        self.block(1, &body)?;
        self.interfaces
            .insert(ifindex, self.interfaces.len() as u32);
        Ok(())
    }

    pub fn write_event(&mut self, event: &Event<'_>, wall_ns: u64, extra: &str) -> io::Result<()> {
        let ifindex = if event.flags & FLAG_COOKED != 0 {
            0
        } else {
            event.ifindex
        };
        let Some(&id) = self.interfaces.get(&ifindex) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown interface",
            ));
        };
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&((wall_ns >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(wall_ns as u32).to_le_bytes());
        body.extend_from_slice(&(event.packet.len() as u32).to_le_bytes());
        body.extend_from_slice(&event.packet_len.to_le_bytes());
        body.extend_from_slice(event.packet);
        body.resize(body.len().div_ceil(4) * 4, 0);
        let queue = if event.stage == crate::event::Stage::Pcap {
            "-".to_string()
        } else {
            event.queue.to_string()
        };
        let mut comment = format!("stage={} queue={} {}", event.label(), queue, event.detail());
        if !extra.is_empty() {
            comment.push(' ');
            comment.push_str(extra);
        }
        Self::option(&mut body, 1, comment.as_bytes());
        Self::option(&mut body, 0, &[]);
        self.block(6, &body)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Stage;
    use std::process::Command;

    #[test]
    fn writes_valid_block_lengths_and_comment() {
        let mut bytes = Vec::new();
        let mut out = PcapngWriter::new(&mut bytes).unwrap();
        out.add_interface(3, "eth0").unwrap();
        out.write_event(
            &Event {
                ts_ns: 1,
                ifindex: 3,
                queue: 2,
                prog_id: 0,
                map_id: 0,
                map_index: 0,
                to_ifindex: 0,
                packet_len: 4,
                result: 0,
                stage: Stage::XskTx,
                action: 0,
                flags: 0,
                packet: &[1, 2, 3, 4],
            },
            1_000_000_005,
            "",
        )
        .unwrap();
        let mut offset = 0;
        for expected_kind in [0x0a0d0d0a, 1, 6] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                expected_kind
            );
            let size =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
            assert_eq!(
                u32::from_le_bytes(bytes[offset + size - 4..offset + size].try_into().unwrap())
                    as usize,
                size
            );
            offset += size;
        }
        assert_eq!(offset, bytes.len());
        assert!(bytes.windows(13).any(|window| window == b"stage=xsk-out"));
        assert!(bytes.windows(12).any(|window| window == b"path=generic"));
    }

    #[test]
    fn conventional_packet_comment_keeps_direction_without_queue() {
        let mut bytes = Vec::new();
        let mut writer = PcapngWriter::new(&mut bytes).unwrap();
        writer.add_interface(2, "eth0").unwrap();
        writer
            .write_event(&Event::packet(2, 1, true, 14, &[0u8; 14]), 1, "")
            .unwrap();
        assert!(bytes
            .windows(20)
            .any(|part| part == b"stage=pcap-out queue"));
        assert!(bytes.windows(7).any(|part| part == b"queue=-"));
        assert!(bytes.windows(12).any(|part| part == b"direction=tx"));
    }

    #[test]
    fn xdp_comment_names_program_stage_without_packet_direction() {
        let mut bytes = Vec::new();
        let mut writer = PcapngWriter::new(&mut bytes).unwrap();
        writer.add_interface(2, "eth0").unwrap();
        let mut event = Event::packet(2, 1, false, 14, &[0u8; 14]);
        event.stage = Stage::XdpExit;
        event.action = 3;
        writer.write_event(&event, 1, "").unwrap();
        assert!(bytes.windows(14).any(|part| part == b"stage=xdp-exit"));
        assert!(bytes.windows(9).any(|part| part == b"action=TX"));
        assert!(!bytes.windows(10).any(|part| part == b"direction="));
    }

    #[test]
    fn any_packet_uses_cooked_link_type_and_xsk_keeps_ethernet() {
        let mut bytes = Vec::new();
        let mut writer = PcapngWriter::new(&mut bytes).unwrap();
        writer.add_cooked_any().unwrap();
        writer.add_interface(3, "eth0").unwrap();
        writer
            .write_event(&Event::cooked_packet(3, 1, false, 16, &[0u8; 16]), 1, "")
            .unwrap();
        let mut xsk = Event::packet(3, 2, false, 14, &[0u8; 14]);
        xsk.stage = Stage::XskRx;
        writer.write_event(&xsk, 2, "").unwrap();
        let mut offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert_eq!(
            u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap()),
            113
        );
        offset += u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        assert_eq!(
            u16::from_le_bytes(bytes[offset + 8..offset + 10].try_into().unwrap()),
            1
        );
        offset += u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        assert_eq!(
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()),
            0
        );
        offset += u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap()) as usize;
        assert_eq!(
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()),
            1
        );
    }

    #[test]
    fn tshark_reads_packet_and_comment_when_available() {
        if Command::new("tshark").arg("--version").output().is_err() {
            return;
        }
        let path = std::env::temp_dir().join(format!("xpcap-test-{}.pcapng", std::process::id()));
        let packet = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17,
            0, 0, 192, 0, 2, 1, 192, 0, 2, 2, 0x12, 0x34, 0x23, 0x28, 0, 8, 0, 0,
        ];
        {
            let mut writer = PcapngWriter::new(std::fs::File::create(&path).unwrap()).unwrap();
            writer.add_interface(1, "eth0").unwrap();
            writer
                .write_event(
                    &Event {
                        ts_ns: 1,
                        ifindex: 1,
                        queue: 0,
                        prog_id: 0,
                        map_id: 0,
                        map_index: 0,
                        to_ifindex: 0,
                        packet_len: packet.len() as u32,
                        result: 0,
                        stage: Stage::XdpEntry,
                        action: 0,
                        flags: 0,
                        packet: &packet,
                    },
                    1_000_000_000,
                    "",
                )
                .unwrap();
        }
        let output = Command::new("tshark")
            .args([
                "-r",
                path.to_str().unwrap(),
                "-T",
                "fields",
                "-e",
                "udp.dstport",
            ])
            .output()
            .unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "9000");
    }
}
