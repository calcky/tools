use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::io;
use std::path::Path;
use std::time::Instant;

use crate::collect::rtnetlink::{self, RouteSocket};

use super::{
    CollectError, CollectErrorKind, QdiscIdentity, QdiscRow, COMMAND_TIMEOUT, MAX_QDISC_OBJECTS,
    MAX_STDOUT_BYTES,
};

const TCMSG_LEN: usize = 20;
const HEADER_LEN: usize = 16;
const RECEIVE_BYTES: usize = 64 * 1024;
const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const TC_H_ROOT: u32 = u32::MAX;

/// A private route socket keeps multipart replies separate from link collection.
#[derive(Debug, Default)]
pub(crate) struct QdiscCollector {
    socket: Option<RouteSocket>,
    buffer: Vec<u8>,
}

impl QdiscCollector {
    pub(crate) fn collect(
        &mut self,
        sys_root: &Path,
        interface: Option<&str>,
    ) -> Result<Vec<QdiscRow>, CollectError> {
        if sys_root != Path::new("/sys") {
            return Err(CollectError::new(
                CollectErrorKind::Unsupported,
                "native TC requires the live /sys namespace",
            ));
        }
        if interface.is_some_and(|name| !super::valid_interface_name(name)) {
            return Err(CollectError::new(
                CollectErrorKind::InvalidRequest,
                "invalid native TC interface",
            ));
        }
        let result = self.dump().and_then(|dump| {
            let mut names = BTreeMap::new();
            let mut identities = BTreeSet::new();
            let mut rows = Vec::with_capacity(dump.len());
            for payload in dump {
                let row = parse_qdisc(&payload, |index| {
                    if let Some(name) = names.get(&index) {
                        return Ok(String::clone(name));
                    }
                    let mut name = [0; libc::IFNAMSIZ];
                    let pointer = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
                    if pointer.is_null() {
                        return Err(CollectError::io(
                            "resolve native TC ifindex",
                            io::Error::last_os_error(),
                        ));
                    }
                    let name = unsafe { CStr::from_ptr(name.as_ptr()) }
                        .to_str()
                        .map_err(|_| CollectError::schema("native TC interface name is not UTF-8"))?
                        .to_owned();
                    if !super::valid_interface_name(&name)
                        || super::read_ifindex(sys_root, &name)? != index
                    {
                        return Err(CollectError::schema(
                            "native TC interface identity changed during collection",
                        ));
                    }
                    names.insert(index, name.clone());
                    Ok(name)
                })?;
                if !identities.insert(row.identity.clone()) {
                    return Err(CollectError::schema("duplicate native qdisc identity"));
                }
                if interface.is_none_or(|selected| row.interface == selected) {
                    rows.push(row);
                }
            }
            Ok(rows)
        });
        if result.is_err() {
            // Discard pending multipart replies after any incomplete or undecodable dump.
            self.socket = None;
        }
        result
    }

    fn dump(&mut self) -> Result<Vec<Vec<u8>>, CollectError> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        if self.socket.is_none() {
            let socket = rtnetlink::open_route_socket().map_err(transport_error)?;
            let flags = unsafe { libc::fcntl(socket.raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe { libc::fcntl(socket.raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                    < 0
            {
                return Err(CollectError::io(
                    "configure native TC socket",
                    io::Error::last_os_error(),
                ));
            }
            self.socket = Some(socket);
        }
        let socket = self.socket.as_mut().expect("native TC socket opened");
        let sequence = rtnetlink::send_dump_request(socket, RTM_GETQDISC, &[0; TCMSG_LEN])
            .map_err(transport_error)?;
        if self.buffer.is_empty() {
            self.buffer.resize(RECEIVE_BYTES, 0);
        }
        let mut dump = Dump::default();
        while !dump.done {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(timeout)?;
            let mut descriptor = libc::pollfd {
                fd: socket.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe {
                libc::poll(
                    &mut descriptor,
                    1,
                    remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
                )
            };
            if ready == 0 {
                return Err(timeout());
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(CollectError::io("poll native TC dump", error));
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(CollectError::new(
                    CollectErrorKind::Io,
                    "native TC socket reported loss or disconnection",
                ));
            }
            let received = match rtnetlink::receive_datagram(socket, &mut self.buffer) {
                Ok(received) => received,
                Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => continue,
                Err(error) => return Err(transport_error(error)),
            };
            dump.datagram(&self.buffer[..received], sequence, socket.port_id())?;
        }
        Ok(dump.payloads)
    }
}

fn timeout() -> CollectError {
    CollectError::new(
        CollectErrorKind::Timeout,
        "native TC qdisc dump exceeded its deadline",
    )
}

fn transport_error(error: rtnetlink::CollectError) -> CollectError {
    match error.raw_os_error() {
        Some(libc::EOPNOTSUPP | libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT) => {
            CollectError::new(CollectErrorKind::Unsupported, error.to_string())
        }
        Some(errno) => CollectError::io("native TC transport", io::Error::from_raw_os_error(errno)),
        None => CollectError::new(
            CollectErrorKind::Io,
            format!("native TC transport: {error}"),
        ),
    }
}

#[derive(Default)]
struct Dump {
    payloads: Vec<Vec<u8>>,
    bytes: usize,
    done: bool,
}

impl Dump {
    fn datagram(&mut self, bytes: &[u8], sequence: u32, port: u32) -> Result<(), CollectError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| CollectError::schema("TC dump byte count overflow"))?;
        if self.bytes > MAX_STDOUT_BYTES {
            return Err(CollectError::new(
                CollectErrorKind::OutputLimit,
                "native TC dump exceeded its byte limit",
            ));
        }
        if bytes.is_empty() {
            return Err(CollectError::schema("empty native TC datagram"));
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let bytes = &bytes[offset..];
            if self.done || bytes.len() < HEADER_LEN {
                return Err(CollectError::schema(
                    "truncated or trailing TC netlink message",
                ));
            }
            let length = u32_at(bytes, 0) as usize;
            if length < HEADER_LEN || length > bytes.len() {
                return Err(CollectError::schema("invalid TC netlink message length"));
            }
            let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
            if u32_at(bytes, 8) != sequence || u32_at(bytes, 12) != port || flags & 0x10 != 0 {
                return Err(CollectError::schema(
                    "native TC dump sequence, destination or interruption mismatch",
                ));
            }
            let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
            let payload = &bytes[HEADER_LEN..length];
            match kind {
                RTM_NEWQDISC => {
                    if flags & libc::NLM_F_MULTI as u16 == 0 {
                        return Err(CollectError::schema("TC reply is not a multipart dump"));
                    }
                    if self.payloads.len() >= MAX_QDISC_OBJECTS {
                        return Err(CollectError::new(
                            CollectErrorKind::CardinalityLimit,
                            "native TC dump exceeds the qdisc object limit",
                        ));
                    }
                    self.payloads.push(payload.to_vec());
                }
                3 => {
                    if !payload.is_empty() {
                        if payload.len() < 4 {
                            return Err(CollectError::schema("short TC dump completion"));
                        }
                        kernel_status(payload)?;
                    }
                    self.done = true;
                }
                2 => {
                    if payload.len() < HEADER_LEN + 4 {
                        return Err(CollectError::schema("short TC netlink error"));
                    }
                    kernel_status(payload)?;
                    return Err(CollectError::schema("unexpected TC dump acknowledgement"));
                }
                _ => {
                    return Err(CollectError::schema(
                        "unexpected TC dump message type or overrun",
                    ))
                }
            }
            let aligned = align(length);
            if aligned > bytes.len() && length != bytes.len() {
                return Err(CollectError::schema("truncated TC message padding"));
            }
            offset += aligned.min(bytes.len());
        }
        Ok(())
    }
}

fn kernel_status(payload: &[u8]) -> Result<(), CollectError> {
    let status = i32::from_ne_bytes(
        payload[..4]
            .try_into()
            .expect("checked kernel status length"),
    );
    match status {
        0 => Ok(()),
        i32::MIN..=-1 if status != i32::MIN => {
            let kind = if -status == libc::EOPNOTSUPP {
                CollectErrorKind::Unsupported
            } else if matches!(-status, libc::EPERM | libc::EACCES) {
                CollectErrorKind::PermissionDenied
            } else {
                CollectErrorKind::Io
            };
            Err(CollectError::new(
                kind,
                format!(
                    "native TC kernel error: {}",
                    io::Error::from_raw_os_error(-status)
                ),
            ))
        }
        _ => Err(CollectError::schema("invalid TC kernel status")),
    }
}

fn parse_qdisc(
    payload: &[u8],
    mut interface: impl FnMut(u32) -> Result<String, CollectError>,
) -> Result<QdiscRow, CollectError> {
    if payload.len() < TCMSG_LEN {
        return Err(CollectError::schema("short native tcmsg"));
    }
    let ifindex = u32_at(payload, 4);
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(CollectError::schema("invalid native TC ifindex"));
    }
    let handle = u32_at(payload, 8);
    let parent = u32_at(payload, 12);
    if handle & 0xffff != 0 {
        return Err(CollectError::schema("unexpected qdisc handle minor"));
    }
    let attributes = attributes(&payload[TCMSG_LEN..], 9)?;
    let kind = attributes
        .get(&1)
        .ok_or_else(|| CollectError::schema("native TC kind is missing"))?;
    let kind = kind
        .strip_suffix(&[0])
        .ok_or_else(|| CollectError::schema("native TC kind is not terminated"))?;
    let kind = std::str::from_utf8(kind)
        .map_err(|_| CollectError::schema("native TC kind is not UTF-8"))?;
    super::validate_identity_part(kind, "kind", 0)?;
    let interface = interface(ifindex)?;
    let mut row = QdiscRow {
        identity: QdiscIdentity {
            interface: interface.clone(),
            ifindex,
            kind: kind.to_owned(),
            handle: Some(format!("{:x}:", handle >> 16)),
            parent: (parent != 0 && parent != TC_H_ROOT).then(|| class_id(parent)),
            root: parent == TC_H_ROOT,
        },
        interface,
        ifindex,
        counter_bits: super::QdiscCounterBits::default(),
        packets: None,
        bytes: None,
        drops: None,
        overlimits: None,
        requeues: None,
        backlog_bytes: None,
        backlog_packets: None,
        max_packet_bytes: None,
        drop_overlimit: None,
        new_flow_count: None,
        ecn_marks: None,
        new_flows_len: None,
        old_flows_len: None,
    };
    let mut app = attributes.get(&4).copied();
    if let Some(stats) = attributes.get(&7) {
        let stats = self::attributes(stats, 6)?;
        if let Some(basic) = stats.get(&1) {
            require_len(basic, 12, "TCA_STATS_BASIC")?;
            row.bytes = Some(u64_at(basic, 0));
            row.packets = Some(u64::from(u32_at(basic, 8)));
            row.counter_bits.bytes = Some(64);
            row.counter_bits.packets = Some(32);
        }
        if let Some(packets) = stats.get(&8) {
            require_len(packets, 8, "TCA_STATS_PKT64")?;
            row.packets = Some(u64_at(packets, 0));
            row.counter_bits.packets = Some(64);
        }
        if let Some(queue) = stats.get(&3) {
            require_len(queue, 20, "TCA_STATS_QUEUE")?;
            row.backlog_packets = Some(u64::from(u32_at(queue, 0)));
            row.backlog_bytes = Some(u64::from(u32_at(queue, 4)));
            row.drops = Some(u64::from(u32_at(queue, 8)));
            row.requeues = Some(u64::from(u32_at(queue, 12)));
            row.overlimits = Some(u64::from(u32_at(queue, 16)));
            row.counter_bits.drops = Some(32);
            row.counter_bits.requeues = Some(32);
            row.counter_bits.overlimits = Some(32);
        }
        app = stats.get(&4).copied().or(app);
    } else if let Some(stats) = attributes.get(&3) {
        require_len(stats, 36, "TCA_STATS")?;
        row.bytes = Some(u64_at(stats, 0));
        row.packets = Some(u64::from(u32_at(stats, 8)));
        row.drops = Some(u64::from(u32_at(stats, 12)));
        row.overlimits = Some(u64::from(u32_at(stats, 16)));
        row.backlog_packets = Some(u64::from(u32_at(stats, 28)));
        row.backlog_bytes = Some(u64::from(u32_at(stats, 32)));
        row.counter_bits.bytes = Some(64);
        row.counter_bits.packets = Some(32);
        row.counter_bits.drops = Some(32);
        row.counter_bits.overlimits = Some(32);
    }
    if let Some(app) = app {
        if kind != "fq_codel" {
            // Other tc plugins can export the same optional statistic names. Keep
            // the JSON adapter's coverage until their binary layouts are supported.
            return Err(CollectError::new(
                CollectErrorKind::Unsupported,
                format!("native TC extended statistics for {kind} are not decoded"),
            ));
        }
        require_len(app, 28, "fq_codel qdisc statistics")?;
        if u32_at(app, 0) != 0 {
            return Err(CollectError::schema(
                "fq_codel statistics are not qdisc statistics",
            ));
        }
        row.max_packet_bytes = Some(u32_at(app, 4));
        row.drop_overlimit = Some(u32_at(app, 8));
        row.ecn_marks = Some(u32_at(app, 12));
        row.new_flow_count = Some(u32_at(app, 16));
        row.new_flows_len = Some(u32_at(app, 20));
        row.old_flows_len = Some(u32_at(app, 24));
    }
    Ok(row)
}

fn class_id(value: u32) -> String {
    let major = value >> 16;
    let minor = value & 0xffff;
    if major == 0 {
        format!(":{minor:x}")
    } else if minor == 0 {
        format!("{major:x}:")
    } else {
        format!("{major:x}:{minor:x}")
    }
}

fn attributes(mut bytes: &[u8], padding_kind: u16) -> Result<BTreeMap<u16, &[u8]>, CollectError> {
    let mut attributes = BTreeMap::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(CollectError::schema("truncated TC attribute header"));
        }
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        let raw_kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        let kind = raw_kind & 0x3fff;
        if length < 4 || length > bytes.len() || raw_kind & 0x4000 != 0 {
            return Err(CollectError::schema(
                "invalid TC attribute length or byte order",
            ));
        }
        // Padding attributes may repeat; each statistic and metadata attribute may not.
        if kind != 0 && kind != padding_kind && attributes.insert(kind, &bytes[4..length]).is_some()
        {
            return Err(CollectError::schema("duplicate TC attribute"));
        }
        let aligned = align(length);
        if aligned > bytes.len() && length != bytes.len() {
            return Err(CollectError::schema("truncated TC attribute padding"));
        }
        bytes = &bytes[aligned.min(bytes.len())..];
    }
    Ok(attributes)
}

fn require_len(bytes: &[u8], len: usize, field: &str) -> Result<(), CollectError> {
    if bytes.len() < len {
        Err(CollectError::schema(format!("short {field}")))
    } else {
        Ok(())
    }
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked TC field length"),
    )
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("checked TC field length"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = Vec::with_capacity(align(length));
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(length), 0);
        bytes
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect()
    }

    fn payload(kind: &str, parent: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0; TCMSG_LEN];
        bytes[4..8].copy_from_slice(&2_u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&0x10000_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&parent.to_ne_bytes());
        bytes.extend(attribute(1, format!("{kind}\0").as_bytes()));
        for attr in attrs {
            bytes.extend(attr);
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<QdiscRow, CollectError> {
        parse_qdisc(bytes, |_| Ok("eth0".to_owned()))
    }

    fn message(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
        let length = HEADER_LEN + payload.len();
        let mut bytes = (length as u32).to_ne_bytes().to_vec();
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(flags.to_ne_bytes());
        bytes.extend(7_u32.to_ne_bytes());
        bytes.extend(42_u32.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(align(length), 0);
        bytes
    }

    #[test]
    fn decodes_stats2_packet64_and_fq_codel_exactly_like_json() {
        let mut basic = 1234567890123_u64.to_ne_bytes().to_vec();
        basic.extend(7_u32.to_ne_bytes());
        let mut stats = attribute(1, &basic);
        stats.extend(attribute(3, &words(&[5, 600, 7, 8, 9])));
        stats.extend(attribute(6, &[]));
        stats.extend(attribute(8, &5000000007_u64.to_ne_bytes()));
        stats.extend(attribute(6, &[]));
        stats.extend(attribute(4, &words(&[0, 1514, 11, 12, 13, 14, 15])));
        let decoded = decode(&payload(
            "fq_codel",
            TC_H_ROOT,
            &[attribute(7 | 0x8000, &stats)],
        ))
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("class/net/eth0")).unwrap();
        std::fs::write(root.path().join("class/net/eth0/ifindex"), "2\n").unwrap();
        let expected = super::super::parse_qdiscs_for_test(br#"[
            {"dev":"eth0","kind":"fq_codel","handle":"1:","root":true,
             "bytes":1234567890123,"packets":5000000007,"drops":7,"requeues":8,
             "overlimits":9,"qlen":5,"backlog":600,"maxpacket":1514,
             "drop_overlimit":11,"ecn_mark":12,"new_flow_count":13,"new_flows_len":14,"old_flows_len":15}
        ]"#, root.path()).unwrap();
        assert_eq!(decoded.counter_bits.packets, Some(64));
        assert_eq!(decoded.counter_bits.bytes, Some(64));
        assert_eq!(decoded.counter_bits.drops, Some(32));
        assert_eq!(decoded.counter_bits.requeues, Some(32));
        assert_eq!(decoded.counter_bits.overlimits, Some(32));
        let mut expected = expected[0].clone();
        assert_eq!(
            expected.counter_bits,
            super::super::QdiscCounterBits::default()
        );
        expected.counter_bits = decoded.counter_bits;
        assert_eq!(decoded, expected);
    }

    #[test]
    fn legacy_and_absent_statistics_keep_missing_fields_missing() {
        let mut stats = 9000_u64.to_ne_bytes().to_vec();
        stats.extend(words(&[100, 2, 3, 0, 0, 4, 500]));
        let row = decode(&payload("pfifo", 1, &[attribute(3, &stats)])).unwrap();
        assert_eq!(row.counter_bits.packets, Some(32));
        assert_eq!(row.counter_bits.drops, Some(32));
        assert_eq!(row.counter_bits.overlimits, Some(32));
        assert_eq!(row.counter_bits.requeues, None);
        let mut basic = 123_u64.to_ne_bytes().to_vec();
        basic.extend(4_u32.to_ne_bytes());
        let basic_row = decode(&payload(
            "mq",
            TC_H_ROOT,
            &[attribute(7, &attribute(1, &basic))],
        ))
        .unwrap();
        assert_eq!(basic_row.counter_bits.packets, Some(32));
        assert_eq!(basic_row.counter_bits.bytes, Some(64));
        assert_eq!(row.attachment(), (false, Some("1:"), Some(":1")));
        assert_eq!(
            (row.bytes, row.packets, row.drops, row.overlimits),
            (Some(9000), Some(100), Some(2), Some(3))
        );
        assert_eq!(
            (row.backlog_packets, row.backlog_bytes, row.requeues),
            (Some(4), Some(500), None)
        );
        let row = decode(&payload("noqueue", TC_H_ROOT, &[])).unwrap();
        assert_eq!(
            (row.packets, row.drops, row.backlog_bytes, row.requeues),
            (None, None, None, None)
        );
        let row = decode(&payload(
            "fq_codel",
            TC_H_ROOT,
            &[attribute(7, &attribute(7, &[0; 16]))],
        ))
        .unwrap();
        assert_eq!(
            (row.bytes, row.packets),
            (None, None),
            "hardware statistics must not masquerade as software statistics"
        );
        let row = decode(&payload(
            "fq_codel",
            TC_H_ROOT,
            &[attribute(7, &[]), attribute(3, &stats)],
        ))
        .unwrap();
        assert_eq!(
            row.packets, None,
            "an explicitly partial stats2 must not invent legacy coverage"
        );
    }

    #[test]
    fn malformed_attributes_statistics_and_unimplemented_xstats_are_rejected() {
        for attr in [
            vec![0, 0, 1, 0],
            vec![3, 0, 1, 0],
            vec![10, 0, 1, 0],
            vec![5, 0, 1, 0, 1, 0],
            vec![1, 2, 3],
        ] {
            assert!(decode(&payload("fq_codel", TC_H_ROOT, &[attr])).is_err());
        }
        for (kind, len) in [(1, 11), (3, 19), (8, 7), (4, 27)] {
            assert!(decode(&payload(
                "fq_codel",
                TC_H_ROOT,
                &[attribute(7, &attribute(kind, &vec![0; len]))]
            ))
            .is_err());
        }
        assert!(decode(&payload(
            "fq_codel",
            TC_H_ROOT,
            &[attribute(1, b"fq_codel\0")]
        ))
        .is_err());
        assert!(decode(&payload(
            "fq_codel",
            TC_H_ROOT,
            &[attribute(7, &attribute(3 | 0x4000, &[0; 20]))]
        ))
        .is_err());
        let class_stats = attribute(7, &attribute(4, &words(&[1, 1, 2, 3, 4, 5, 6])));
        assert!(decode(&payload("fq_codel", TC_H_ROOT, &[class_stats])).is_err());
        assert_eq!(
            decode(&payload("cake", TC_H_ROOT, &[attribute(4, &[0; 32])]))
                .unwrap_err()
                .kind(),
            CollectErrorKind::Unsupported
        );
        for length in 0..TCMSG_LEN {
            assert!(decode(&vec![0; length]).is_err());
        }
    }

    #[test]
    fn root_ingress_and_parent_handles_preserve_kernel_identity() {
        for (parent, expected, root) in [
            (TC_H_ROOT, None, true),
            (0, None, false),
            (1, Some(":1"), false),
            (0x10001, Some("1:1"), false),
            (0xfffffff1, Some("ffff:fff1"), false),
        ] {
            let row = decode(&payload("fq_codel", parent, &[])).unwrap();
            assert_eq!(row.attachment(), (root, Some("1:"), expected));
        }
        let row = decode(&payload("ingress", 0xfffffff1, &[])).unwrap();
        assert_eq!(row.direction(), Some(super::super::QdiscDirection::Ingress));
    }

    #[test]
    fn multipart_dump_requires_matching_complete_noninterrupted_bounded_messages() {
        let qdisc = message(RTM_NEWQDISC, 2, &payload("noqueue", TC_H_ROOT, &[]));
        let done = message(3, 2, &[0; 4]);
        let mut dump = Dump::default();
        dump.datagram(&qdisc, 7, 42).unwrap();
        assert!(!dump.done);
        dump.datagram(&done, 7, 42).unwrap();
        assert!(dump.done);
        assert_eq!(dump.payloads.len(), 1);
        assert!(dump.datagram(&qdisc, 7, 42).is_err());
        for (seq, port) in [(8, 42), (7, 41)] {
            assert!(Dump::default().datagram(&qdisc, seq, port).is_err());
        }
        for bytes in [
            message(RTM_NEWQDISC, 0x12, &[0; 20]),
            message(RTM_NEWQDISC, 0, &[0; 20]),
            message(4, 2, &[]),
            message(3, 2, &[1, 2]),
            vec![0; 15],
        ] {
            assert!(Dump::default().datagram(&bytes, 7, 42).is_err());
        }
        let mut error = (-libc::EPERM).to_ne_bytes().to_vec();
        error.resize(20, 0);
        assert_eq!(
            Dump::default()
                .datagram(&message(2, 0, &error), 7, 42)
                .unwrap_err()
                .kind(),
            CollectErrorKind::PermissionDenied
        );
        let mut dump = Dump {
            bytes: MAX_STDOUT_BYTES,
            ..Dump::default()
        };
        assert_eq!(
            dump.datagram(&done, 7, 42).unwrap_err().kind(),
            CollectErrorKind::OutputLimit
        );
        let mut dump = Dump::default();
        for _ in 0..MAX_QDISC_OBJECTS {
            dump.datagram(&qdisc, 7, 42).unwrap();
        }
        assert_eq!(
            dump.datagram(&qdisc, 7, 42).unwrap_err().kind(),
            CollectErrorKind::CardinalityLimit
        );
        let mut empty = Dump::default();
        empty.datagram(&done, 7, 42).unwrap();
        assert!(empty.done && empty.payloads.is_empty());
    }

    #[test]
    fn nonlive_sysfs_and_invalid_interfaces_do_not_open_a_socket() {
        let mut collector = QdiscCollector::default();
        assert_eq!(
            collector
                .collect(Path::new("/fixture/sys"), None)
                .unwrap_err()
                .kind(),
            CollectErrorKind::Unsupported
        );
        assert_eq!(
            collector
                .collect(Path::new("/sys"), Some("bad/name"))
                .unwrap_err()
                .kind(),
            CollectErrorKind::InvalidRequest
        );
        assert!(collector.socket.is_none());
        assert!(collector.buffer.is_empty());
    }

    #[test]
    #[ignore = "requires read-only access to live NETLINK_ROUTE and tc"]
    fn live_native_qdiscs_match_json_metadata_and_reuse_socket() {
        let mut collector = QdiscCollector::default();
        let first = collector.collect(Path::new("/sys"), None).unwrap();
        let fd = collector.socket.as_ref().unwrap().raw_fd();
        let pointer = collector.buffer.as_ptr();
        let second = collector.collect(Path::new("/sys"), None).unwrap();
        assert_eq!(fd, collector.socket.as_ref().unwrap().raw_fd());
        assert_eq!(pointer, collector.buffer.as_ptr());
        let json = super::super::collect_qdiscs(Path::new("/sys"), None).unwrap();
        let identities = |rows: &[QdiscRow]| {
            rows.iter()
                .map(|row| row.identity.clone())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(identities(&first), identities(&second));
        assert_eq!(identities(&second), identities(&json));
        for row in &second {
            let reference = json
                .iter()
                .find(|other| other.identity == row.identity)
                .unwrap();
            assert_eq!(row.bytes.is_some(), reference.bytes.is_some());
            assert_eq!(row.packets.is_some(), reference.packets.is_some());
            assert_eq!(row.requeues.is_some(), reference.requeues.is_some());
            assert_eq!(row.ecn_marks.is_some(), reference.ecn_marks.is_some());
            if let (Some(before), Some(after)) = (row.packets, reference.packets) {
                assert!(after >= before);
            }
        }
        eprintln!("native TC: {} qdiscs match tc JSON identity/statistic availability; socket and buffer reused", second.len());
    }
}
