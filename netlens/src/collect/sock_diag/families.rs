use super::*;

pub(super) fn table_queries() -> Vec<Query> {
    let mut queries = Query::ALL.to_vec();
    for protocol in [255, 33, 132, 262] {
        for family in [2, 10] {
            queries.push(Query { family, protocol });
        }
    }
    for family in [1, 17, 16, 40, 30, 44] {
        queries.push(Query {
            family,
            protocol: if family == 16 { 255 } else { 0 },
        });
    }
    queries
}

pub(super) fn request(q: Query, seq: u32, pid: u32, info: bool) -> Vec<u8> {
    if !matches!(q.family, 1 | 17 | 16 | 40 | 30 | 44) {
        let mut bytes = build_request_with_tcp_info(q, seq, pid, info).to_vec();
        if q.protocol > 255 {
            bytes.extend_from_slice(&8_u16.to_ne_bytes());
            bytes.extend_from_slice(&3_u16.to_ne_bytes()); // INET_DIAG_REQ_PROTOCOL
            bytes.extend_from_slice(&u32::from(q.protocol).to_ne_bytes());
            let len = bytes.len() as u32;
            put_u32(&mut bytes[..4], len);
        }
        return bytes;
    }
    let len = match q.family {
        1 | 40 => 24,
        30 => 8,
        _ => 20,
    };
    let mut bytes = vec![0; NLMSG_HEADER_LEN + len];
    put_u32(&mut bytes[..4], (NLMSG_HEADER_LEN + len) as u32);
    put_u16(&mut bytes[4..6], SOCK_DIAG_BY_FAMILY);
    put_u16(
        &mut bytes[6..8],
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
    );
    put_u32(&mut bytes[8..12], seq);
    put_u32(&mut bytes[12..16], pid);
    bytes[16] = q.family;
    bytes[17] = q.protocol as u8;
    let req = &mut bytes[16..];
    match q.family {
        1 => {
            put_u32(&mut req[4..8], u32::MAX);
            put_u32(&mut req[12..16], 1 | 4 | 16 | 32 | 64);
        }
        17 => put_u32(&mut req[8..12], 1 | 16),
        16 => put_u32(&mut req[8..12], 1 | 2 | 8),
        40 | 30 => put_u32(&mut req[4..8], u32::MAX),
        44 => put_u32(&mut req[8..12], 31),
        _ => unreachable!(),
    }
    bytes
}

fn require(bytes: &[u8], len: usize) -> Result<(), CollectError> {
    if bytes.len() < len {
        Err(CollectError::parse("truncated socket diagnostic field"))
    } else {
        Ok(())
    }
}

fn attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, CollectError> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        require(bytes, 4)?;
        let len = read_u16(&bytes[..2]) as usize;
        if len < 4 || align(len) > bytes.len() {
            return Err(CollectError::parse(
                "invalid socket attribute length/padding",
            ));
        }
        let kind = read_u16(&bytes[2..4]) & NLA_TYPE_MASK;
        if out.iter().any(|(seen, _)| *seen == kind) {
            return Err(CollectError::parse("duplicate socket attribute"));
        }
        out.push((kind, &bytes[4..len]));
        bytes = &bytes[align(len)..];
    }
    Ok(out)
}

fn u32_value(bytes: &[u8]) -> Result<u32, CollectError> {
    require(bytes, 4)?;
    Ok(read_u32(&bytes[..4]))
}

// Socket paths may contain control characters and arbitrary bytes. Never pass
// them through to a terminal unescaped (including abstract names with NULs).
fn unix_name(bytes: &[u8]) -> String {
    let abstract_name = bytes.first() == Some(&0);
    let mut name = String::new();
    for (index, byte) in bytes.iter().copied().enumerate() {
        if index == 0 && abstract_name {
            name.push('@');
        } else if !abstract_name && byte == 0 {
            break;
        } else if (0x20..=0x7e).contains(&byte) && byte != b'\\' {
            name.push(char::from(byte));
        } else {
            name.push_str(&format!("\\x{byte:02x}"));
        }
    }
    name
}

pub(super) fn empty(q: Query, inode: u32, cookie: [u32; 2]) -> RawSocket {
    RawSocket {
        identity: SocketIdentity {
            family: q.family,
            protocol: q.protocol,
            inode,
            cookie,
        },
        family: q.family(),
        protocol: q.protocol(),
        state: 7,
        timer: 0,
        retransmits: 0,
        local: SocketEndpoint::Unspecified,
        remote: SocketEndpoint::Unspecified,
        bound_ifindex: 0,
        expires_millis: 0,
        receive_queue: 0,
        send_queue: 0,
        uid: 0,
        memory: None,
        tcp_info: None,
        congestion_algorithm: None,
        details: SocketDetails {
            uid_unavailable: true,
            queue_kind: QueueKind::Unavailable,
            ..Default::default()
        },
    }
}

pub(super) fn parse(q: Query, bytes: &[u8]) -> Result<RawSocket, CollectError> {
    if q.family == 30 {
        return tipc(q, bytes);
    }
    let (len, inode_at, cookie_at) = match q.family {
        1 | 17 | 44 => (16, 4, 8),
        16 => (28, 16, 20),
        40 => (32, 20, 24),
        _ => return Err(CollectError::parse("unknown socket diagnostic family")),
    };
    require(bytes, len)?;
    if bytes[0] != q.family {
        return Err(CollectError::parse("socket diagnostic family mismatch"));
    }
    let inode = read_u32(&bytes[inode_at..inode_at + 4]);
    let mut socket = empty(
        q,
        inode,
        [
            read_u32(&bytes[cookie_at..cookie_at + 4]),
            read_u32(&bytes[cookie_at + 4..cookie_at + 8]),
        ],
    );
    socket.details.socket_type = bytes[1];
    let attributes = attrs(&bytes[len..])?;
    let value = |kind| {
        attributes
            .iter()
            .find(|(id, _)| *id == kind)
            .map(|(_, val)| *val)
    };
    let (memory_id, uid_id) = match q.family {
        1 => (5, Some(7)),
        17 => (6, Some(5)),
        16 => (0, None),
        44 => (8, Some(2)),
        _ => (u16::MAX, None),
    };
    if let Some(data) = value(memory_id) {
        socket.memory = Some(parse_skmeminfo(data)?);
    }
    if let Some(data) = uid_id.and_then(value) {
        socket.uid = u32_value(data)?;
        socket.details.uid_unavailable = false;
    }
    match q.family {
        1 => {
            socket.state = bytes[2];
            socket.local = SocketEndpoint::Unix {
                name: value(0).map(unix_name),
                inode,
            };
            if let Some(peer) = value(2) {
                socket.remote = SocketEndpoint::Unix {
                    name: None,
                    inode: u32_value(peer)?,
                };
            }
            if let Some(queues) = value(4) {
                require(queues, 8)?;
                socket.receive_queue = read_u32(&queues[..4]);
                socket.send_queue = read_u32(&queues[4..8]);
                socket.details.queue_kind = if socket.state == 10 {
                    QueueKind::Backlog
                } else if bytes[1] == 2 {
                    QueueKind::UnixDatagram
                } else {
                    QueueKind::UnixStream
                };
            }
        }
        17 => {
            let protocol = read_u16(&bytes[2..4]);
            if let Some(info) = value(0) {
                socket.bound_ifindex = u32_value(info)?;
            }
            socket.local = SocketEndpoint::Link {
                ifindex: socket.bound_ifindex,
                selector: format!("0x{protocol:04x}"),
            };
            memory_queues(&mut socket);
        }
        16 => {
            socket.state = bytes[3];
            socket.local = SocketEndpoint::Netlink {
                protocol: bytes[2],
                port_id: read_u32(&bytes[4..8]),
            };
            socket.remote = SocketEndpoint::Netlink {
                protocol: bytes[2],
                port_id: read_u32(&bytes[8..12]),
            };
            socket.details.field("DST GROUP", read_u32(&bytes[12..16]));
            if let Some(groups) = value(1) {
                if groups.len() % 4 != 0 {
                    return Err(CollectError::parse("invalid netlink groups"));
                }
                socket.details.field(
                    "GROUP MASK (u32)",
                    groups
                        .chunks_exact(4)
                        .map(|v| format!("{:08x}", read_u32(v)))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            memory_queues(&mut socket);
        }
        40 => {
            socket.state = bytes[2];
            socket.local = SocketEndpoint::Vsock {
                cid: read_u32(&bytes[4..8]),
                port: read_u32(&bytes[8..12]),
            };
            socket.remote = SocketEndpoint::Vsock {
                cid: read_u32(&bytes[12..16]),
                port: read_u32(&bytes[16..20]),
            };
        }
        44 => {
            if let Some(info) = value(1) {
                require(info, 8)?;
                socket.bound_ifindex = read_u32(&info[..4]);
                socket.local = SocketEndpoint::Link {
                    ifindex: socket.bound_ifindex,
                    selector: format!("q{}", read_u32(&info[4..8])),
                };
            }
            for (id, label) in [
                (3, "RX RING ENTRIES"),
                (4, "TX RING ENTRIES"),
                (6, "FILL RING ENTRIES"),
                (7, "COMPLETION RING ENTRIES"),
            ] {
                if let Some(data) = value(id) {
                    socket.details.field(label, u32_value(data)?);
                }
            }
            if let Some(data) = value(5) {
                require(data, 40)?;
                socket.details.field("UMEM BYTES", read_u64(&data[..8]));
                for (at, label) in [
                    (8, "UMEM ID"),
                    (16, "CHUNK BYTES"),
                    (20, "HEADROOM"),
                    (32, "UMEM FLAGS"),
                ] {
                    socket.details.field(label, read_u32(&data[at..at + 4]));
                }
            }
            if let Some(data) = value(9) {
                require(data, 48)?;
                for (index, label) in [
                    "RX DROPPED",
                    "RX INVALID",
                    "RX FULL",
                    "FILL EMPTY",
                    "TX INVALID",
                    "TX EMPTY",
                ]
                .iter()
                .enumerate()
                {
                    socket
                        .details
                        .field(label, read_u64(&data[index * 8..index * 8 + 8]));
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(socket)
}

fn memory_queues(socket: &mut RawSocket) {
    if let Some(memory) = socket.memory {
        socket.receive_queue = memory.receive_allocated;
        socket.send_queue = memory.send_allocated;
        socket.details.queue_kind = QueueKind::Memory;
    }
}

fn tipc(q: Query, bytes: &[u8]) -> Result<RawSocket, CollectError> {
    let top = attrs(bytes)?;
    let socket = top
        .iter()
        .find(|(id, _)| *id == 2)
        .ok_or_else(|| CollectError::parse("missing TIPC socket"))?;
    let fields = attrs(socket.1)?;
    let get = |id| {
        fields
            .iter()
            .find(|(kind, _)| *kind == id)
            .map(|(_, v)| *v)
            .ok_or_else(|| CollectError::parse("missing TIPC field"))
    };
    let cookie = get(10)?;
    require(cookie, 8)?;
    let mut out = empty(
        q,
        u32_value(get(7)?)?,
        [read_u32(&cookie[..4]), read_u32(&cookie[4..8])],
    );
    out.state = u32_value(get(9)?)?
        .try_into()
        .map_err(|_| CollectError::parse("invalid TIPC state"))?;
    out.uid = u32_value(get(8)?)?;
    out.details.uid_unavailable = false;
    out.details.socket_type = u32_value(get(6)?)?
        .try_into()
        .map_err(|_| CollectError::parse("invalid TIPC type"))?;
    out.local = SocketEndpoint::Tipc {
        node: u32_value(get(1)?)?,
        reference: u32_value(get(2)?)?,
    };
    if let Ok(con) = get(3) {
        let fields = attrs(con)?;
        let get = |id| {
            fields
                .iter()
                .find(|(kind, _)| *kind == id)
                .map(|(_, v)| *v)
                .ok_or_else(|| CollectError::parse("missing TIPC peer"))
        };
        out.remote = SocketEndpoint::Tipc {
            node: u32_value(get(2)?)?,
            reference: u32_value(get(3)?)?,
        };
    }
    for (id, val) in attrs(get(5)?)? {
        match id {
            0 => {
                out.receive_queue = u32_value(val)?;
                out.details.queue_kind = QueueKind::DatagramCount;
            }
            1 => out.send_queue = u32_value(val)?,
            4 => out.details.field("TIPC DROPS", u32_value(val)?),
            _ => {}
        }
    }
    Ok(out)
}

pub(super) fn inet_field(
    q: Query,
    id: u16,
    val: &[u8],
    details: &mut SocketDetails,
) -> Result<(), CollectError> {
    if id == 10 && q.protocol == 255 {
        require(val, 1)?;
        details.ip_protocol = Some(val[0]);
        details.field("IP PROTOCOL", val[0]);
    }
    if q.protocol == 132 && matches!(id, 12 | 13) {
        if val.len() % 128 != 0 {
            return Err(CollectError::parse("invalid SCTP address list"));
        }
        let mut addresses = Vec::new();
        for addr in val.chunks_exact(128) {
            let family = match read_u16(&addr[..2]) {
                2 => SocketFamily::Ipv4,
                10 => SocketFamily::Ipv6,
                _ => return Err(CollectError::parse("invalid SCTP address family")),
            };
            let offset = if family == SocketFamily::Ipv4 { 4 } else { 8 };
            addresses
                .push(parse_endpoint(family, &addr[2..4], &addr[offset..offset + 16]).to_string());
        }
        details.field(
            if id == 12 {
                "LOCAL ADDRESSES"
            } else {
                "PEER ADDRESSES"
            },
            addresses.join(", "),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(family: u8) -> Query {
        Query {
            family,
            protocol: if family == 16 { 255 } else { 0 },
        }
    }
    fn header(family: u8, len: usize) -> Vec<u8> {
        let mut bytes = vec![0; len];
        bytes[0] = family;
        bytes[1] = 1;
        bytes
    }
    fn attr(bytes: &mut Vec<u8>, id: u16, value: &[u8]) {
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&id.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize(align(bytes.len()), 0);
    }
    fn number(bytes: &mut Vec<u8>, id: u16, value: u32) {
        attr(bytes, id, &value.to_ne_bytes());
    }

    #[test]
    fn requests_cover_ss_families_and_extended_mptcp_protocol() {
        let queries = table_queries();
        assert_eq!(queries.len(), 18);
        for q in queries {
            let req = request(q, 77, 42, true);
            assert_eq!(read_u32(&req[..4]) as usize, req.len());
            assert_eq!(req[16], q.family);
            assert_eq!(read_u32(&req[8..12]), 77);
            if q.protocol == 262 {
                assert_eq!(read_u32(&req[76..80]), 262);
            }
        }
        assert_eq!(read_u32(&request(q(1), 1, 1, true)[28..32]), 117);
        assert_eq!(request(q(16), 1, 1, true)[17], 255);
    }

    #[test]
    fn sctp_address_attributes_use_sockaddr_storage_records() {
        let q = Query {
            family: 2,
            protocol: 132,
        };
        let mut value = [0_u8; 128];
        value[..2].copy_from_slice(&2_u16.to_ne_bytes());
        value[2..4].copy_from_slice(&9000_u16.to_be_bytes());
        value[4..8].copy_from_slice(&[192, 0, 2, 1]);
        let mut details = SocketDetails::default();
        inet_field(q, 12, &value, &mut details).unwrap();
        inet_field(q, 13, &value, &mut details).unwrap();
        assert_eq!(
            details.fields,
            [
                ("LOCAL ADDRESSES".to_owned(), "192.0.2.1:9000".to_owned()),
                ("PEER ADDRESSES".to_owned(), "192.0.2.1:9000".to_owned())
            ]
        );
        assert!(inet_field(q, 12, &value[..127], &mut details).is_err());
    }

    #[test]
    fn unix_paths_peers_and_queue_units_are_preserved_without_terminal_escapes() {
        let mut bytes = header(1, 16);
        bytes[1] = 2;
        bytes[2] = 1;
        put_u32(&mut bytes[4..8], 100);
        attr(&mut bytes, 0, b"\0service\x1b[31m\0");
        number(&mut bytes, 2, 200);
        attr(&mut bytes, 4, &[3, 0, 0, 0, 4, 0, 0, 0]);
        number(&mut bytes, 7, 1000);
        let socket = parse(q(1), &bytes).unwrap();
        assert_eq!(socket.local.to_string(), "@service\\x1b[31m\\x00 #100");
        assert_eq!(socket.remote.to_string(), "* #200");
        assert_eq!(socket.uid, 1000);
        assert!(!socket.details.uid_unavailable);
        assert_eq!(socket.details.queue_kind, QueueKind::UnixDatagram);
        bytes[2] = 10;
        assert_eq!(
            parse(q(1), &bytes).unwrap().details.queue_kind,
            QueueKind::Backlog
        );
        assert_eq!(unix_name(b"/run/test\0"), "/run/test");
    }

    #[test]
    fn vsock_keeps_32bit_cids_and_ports_and_unknown_queues() {
        let mut bytes = header(40, 32);
        bytes[2] = 1;
        put_u32(&mut bytes[4..8], u32::MAX);
        put_u32(&mut bytes[8..12], 1_000_000);
        put_u32(&mut bytes[12..16], 2);
        put_u32(&mut bytes[16..20], 900_000);
        let socket = parse(q(40), &bytes).unwrap();
        assert_eq!(socket.local.to_string(), "4294967295:1000000");
        assert_eq!(socket.remote.to_string(), "2:900000");
        assert_eq!(socket.details.queue_kind, QueueKind::Unavailable);
        assert!(socket.details.uid_unavailable);
    }

    #[test]
    fn packet_and_netlink_preserve_protocol_and_memory_semantics() {
        for (family, len, mem_id) in [(17, 16, 6), (16, 28, 0)] {
            let mut bytes = header(family, len);
            bytes[2] = 3;
            let mut mem = vec![0; 36];
            put_u32(&mut mem[..4], 120);
            put_u32(&mut mem[8..12], 64);
            attr(&mut bytes, mem_id, &mem);
            if family == 17 {
                number(&mut bytes, 0, 7);
            } else {
                put_u32(&mut bytes[4..8], 123456);
            }
            let socket = parse(q(family), &bytes).unwrap();
            assert_eq!(socket.details.queue_kind, QueueKind::Memory);
            assert_eq!(socket.receive_queue, 120);
            assert_eq!(socket.send_queue, 64);
            assert_eq!(
                socket.local.to_string(),
                if family == 17 {
                    "if7:0x0003"
                } else {
                    "nl3:123456"
                }
            );
        }
    }

    #[test]
    fn xdp_ring_configuration_is_not_queue_occupancy() {
        let mut bytes = header(44, 16);
        attr(&mut bytes, 1, &[7, 0, 0, 0, 4, 0, 0, 0]);
        number(&mut bytes, 3, 1024);
        let mut stats = vec![0; 48];
        stats[..8].copy_from_slice(&123_u64.to_ne_bytes());
        attr(&mut bytes, 9, &stats);
        let socket = parse(q(44), &bytes).unwrap();
        assert_eq!(socket.local.to_string(), "if7:q4");
        assert_eq!(socket.details.queue_kind, QueueKind::Unavailable);
        assert!(socket
            .details
            .fields
            .contains(&("RX RING ENTRIES".into(), "1024".into())));
        assert!(socket
            .details
            .fields
            .contains(&("RX DROPPED".into(), "123".into())));
    }

    #[test]
    fn tipc_nested_diagnostics_are_packet_counts() {
        let mut fields = Vec::new();
        for (id, val) in [(1, 0xaabb), (2, 100), (6, 1), (7, 200), (8, 1000), (9, 1)] {
            number(&mut fields, id, val);
        }
        attr(&mut fields, 10, &99_u64.to_ne_bytes());
        let mut stats = Vec::new();
        number(&mut stats, 0, 3);
        number(&mut stats, 1, 7);
        number(&mut stats, 4, 9);
        attr(&mut fields, 5, &stats);
        let mut con = Vec::new();
        number(&mut con, 2, 0xbbcc);
        number(&mut con, 3, 300);
        attr(&mut fields, 3, &con);
        let mut bytes = Vec::new();
        attr(&mut bytes, 2, &fields);
        let socket = parse(q(30), &bytes).unwrap();
        assert_eq!(socket.local.to_string(), "aabb:100");
        assert_eq!(socket.remote.to_string(), "bbcc:300");
        assert_eq!(socket.details.queue_kind, QueueKind::DatagramCount);
        assert_eq!(socket.receive_queue, 3);
        assert_eq!(socket.send_queue, 7);
        for end in 0..bytes.len() {
            assert!(parse(q(30), &bytes[..end]).is_err());
        }
    }

    #[test]
    fn parsers_reject_truncation_duplicate_fields_and_wrong_family() {
        for (family, len) in [(1, 16), (17, 16), (16, 28), (40, 32), (44, 16)] {
            let bytes = header(family, len);
            for end in 0..len {
                assert!(parse(q(family), &bytes[..end]).is_err());
            }
            let mut bad = bytes.clone();
            bad[0] = 255;
            assert!(parse(q(family), &bad).is_err());
            let mut bad = bytes.clone();
            bad.extend_from_slice(&[3, 0, 1, 0]);
            assert!(parse(q(family), &bad).is_err());
            let mut bad = bytes;
            number(&mut bad, 99, 1);
            number(&mut bad, 99, 2);
            assert!(parse(q(family), &bad).is_err());
        }
        let mut bytes = header(1, 16);
        attr(&mut bytes, 4, &[0; 4]);
        assert!(parse(q(1), &bytes).is_err());
    }

    #[test]
    #[ignore = "live kernel family availability and UNIX socket ownership"]
    fn live_all_families_and_unix_socketpair() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::net::UnixStream;
        let (left, _right) = UnixStream::pair().unwrap();
        let inode = std::fs::metadata(format!("/proc/self/fd/{}", left.as_raw_fd()))
            .unwrap()
            .ino() as u32;
        let collected = collect_table_current_namespace();
        for result in &collected.queries {
            match &result.outcome {
                Ok(rows) => eprintln!(
                    "{}{}: {} sockets",
                    result.protocol.label(),
                    result.family.label(),
                    rows.len()
                ),
                Err(error) => {
                    eprintln!(
                        "{}{}: {error}",
                        result.protocol.label(),
                        result.family.label()
                    );
                    assert_eq!(error.kind(), CollectErrorKind::Unsupported);
                }
            }
        }
        let rows = collected
            .queries
            .iter()
            .find(|r| r.family == SocketFamily::Unix)
            .unwrap()
            .outcome
            .as_ref()
            .unwrap();
        let row = rows
            .iter()
            .find(|row| row.identity.inode() == inode)
            .expect("UNIX endpoint retained");
        assert_eq!(row.state, 1);
        assert!(matches!(row.remote,SocketEndpoint::Unix { inode, .. } if inode > 0));
        assert!(row.identity.is_matchable());
    }
}
