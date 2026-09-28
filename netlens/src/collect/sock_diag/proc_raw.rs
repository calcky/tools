// Some kernels enable RAW sockets but omit CONFIG_INET_RAW_DIAG. Like ss,
// read their proc table in that case; never invent a stable kernel cookie.
use std::io::{BufRead, Read};

use super::*;

pub(super) fn collect(
    q: Query,
    cancelled: Option<&AtomicBool>,
) -> Result<Option<SockDiagDump>, CollectError> {
    let path = if q.family == 2 {
        "/proc/self/net/raw"
    } else {
        "/proc/self/net/raw6"
    };
    let file = std::fs::File::open(path).map_err(|e| CollectError::io("read RAW proc table", e))?;
    let mut reader = io::BufReader::new(file);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| CollectError::io("read RAW header", e))?;
    if !line.contains("local_address") || !line.contains("inode") {
        return Err(CollectError::parse("unknown RAW proc table header"));
    }
    let mut dump = SockDiagDump {
        samples: Vec::new(),
        sockets: Vec::new(),
        observed_sockets: 0,
        table_truncated: false,
    };
    loop {
        if is_cancelled(cancelled) {
            return Ok(None);
        }
        line.clear();
        let read = (&mut reader)
            .take(4097)
            .read_line(&mut line)
            .map_err(|e| CollectError::io("read RAW proc row", e))?;
        if read == 0 {
            break;
        }
        if read > 4096 || dump.observed_sockets >= MAX_SAMPLES_PER_QUERY {
            return Err(CollectError::loss("RAW proc table limit exceeded"));
        }
        let socket = parse_line(q, &line)?;
        dump.observed_sockets += 1;
        if dump.sockets.len() < MAX_TABLE_SAMPLES_PER_QUERY {
            dump.sockets.push(socket);
        } else {
            dump.table_truncated = true;
        }
    }
    Ok(Some(dump))
}

fn parse_line(q: Query, line: &str) -> Result<RawSocket, CollectError> {
    let invalid = || CollectError::parse("malformed RAW proc row");
    let fields: Vec<_> = line.split_ascii_whitespace().collect();
    if fields.len() < 10 {
        return Err(invalid());
    }
    let hex = |v: &str| u32::from_str_radix(v, 16).map_err(|_| invalid());
    let addr = |v: &str| -> Result<(IpAddr, u8), CollectError> {
        let (ip, protocol) = v.split_once(':').ok_or_else(invalid)?;
        let len = if q.family == 2 { 8 } else { 32 };
        if ip.len() != len || !ip.is_ascii() {
            return Err(invalid());
        }
        let mut bytes = [0; 16];
        for i in 0..len / 8 {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&hex(&ip[i * 8..i * 8 + 8])?.to_ne_bytes());
        }
        let ip = if q.family == 2 {
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        } else {
            IpAddr::V6(Ipv6Addr::from(bytes))
        };
        Ok((ip, hex(protocol)?.try_into().map_err(|_| invalid())?))
    };
    let (local, protocol) = addr(fields[1])?;
    let (remote, _) = addr(fields[2])?;
    let (tx, rx) = fields[4].split_once(':').ok_or_else(invalid)?;
    let inode = fields[9].parse().map_err(|_| invalid())?;
    let mut socket = families::empty(q, inode, INET_DIAG_NOCOOKIE);
    socket.state = hex(fields[3])?.try_into().map_err(|_| invalid())?;
    socket.uid = fields[7].parse().map_err(|_| invalid())?;
    socket.receive_queue = hex(rx)?;
    socket.send_queue = hex(tx)?;
    socket.local = SocketEndpoint::Raw {
        address: local,
        protocol,
    };
    socket.remote = SocketEndpoint::Raw {
        address: remote,
        protocol,
    };
    socket.details.uid_unavailable = false;
    socket.details.queue_kind = QueueKind::Bytes;
    socket.details.field(
        "SOURCE",
        "proc fallback; no stable cookie or process attribution",
    );
    socket.details.field("IP PROTOCOL", protocol);
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_raw_has_protocols_not_ports_and_no_synthetic_cookie() {
        let row = parse_line(Query { family:2, protocol:255 }, "1: 0100007F:0001 00000000:0000 07 00000010:00000020 00:00000000 00000000 1000 0 123 2 0 0").unwrap();
        assert_eq!(row.local.to_string(), "127.0.0.1 (ip#1)");
        assert_eq!(row.receive_queue, 32);
        assert_eq!(row.send_queue, 16);
        assert_eq!(row.uid, 1000);
        assert!(!row.identity.is_matchable());
        assert_eq!(row.local.filter_endpoint().unwrap().1, None);
        assert!(parse_line(Query::IPV4_TCP, "invalid").is_err());
    }
}
