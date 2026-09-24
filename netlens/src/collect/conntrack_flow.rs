use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;

pub(crate) const MAX_RETAINED_FLOWS: usize = 4_096;
const MAX_SCANNED_LINES: usize = 16_384;
const MAX_LINE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FlowEndpoint {
    pub(crate) address: IpAddr,
    pub(crate) port: Option<u16>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FlowTuple {
    pub(crate) source: FlowEndpoint,
    pub(crate) destination: FlowEndpoint,
    pub(crate) icmp: Option<IcmpTupleKey>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IcmpTupleKey {
    pub(crate) icmp_type: u8,
    pub(crate) code: u8,
    pub(crate) id: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FlowCounters {
    pub(crate) packets: Option<u64>,
    pub(crate) bytes: Option<u64>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RawConntrackFlow {
    pub(crate) family: AddressFamily,
    pub(crate) protocol: u8,
    pub(crate) protocol_name: String,
    pub(crate) state: Option<String>,
    pub(crate) timeout_seconds: Option<u64>,
    pub(crate) zone: u16,
    pub(crate) ct_mark: Option<u32>,
    pub(crate) original: FlowTuple,
    pub(crate) reply: FlowTuple,
    pub(crate) original_counters: FlowCounters,
    pub(crate) reply_counters: FlowCounters,
    pub(crate) offloaded: bool,
    pub(crate) hardware_offloaded: bool,
}

impl RawConntrackFlow {
    pub(crate) fn identity(&self) -> FlowIdentity {
        FlowIdentity {
            family: self.family,
            protocol: self.protocol,
            zone: self.zone,
            original: self.original.clone(),
            reply: self.reply.clone(),
        }
    }
}

impl fmt::Debug for RawConntrackFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawConntrackFlow")
            .field("family", &self.family)
            .field("protocol", &self.protocol)
            .field("tuple", &"<redacted>")
            .field(
                "has_original_counters",
                &self.original_counters.packets.is_some(),
            )
            .field("has_reply_counters", &self.reply_counters.packets.is_some())
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct FlowIdentity {
    pub(crate) family: AddressFamily,
    pub(crate) protocol: u8,
    pub(crate) zone: u16,
    pub(crate) original: FlowTuple,
    pub(crate) reply: FlowTuple,
}

pub(crate) struct FlowCollection {
    pub(crate) flows: Vec<RawConntrackFlow>,
    pub(crate) total_entries: Option<u64>,
    pub(crate) accounting_enabled: Option<bool>,
    pub(crate) truncated: bool,
    pub(crate) rejected_lines: usize,
}

impl fmt::Debug for FlowCollection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowCollection")
            .field("flow_count", &self.flows.len())
            .field("total_entries", &self.total_entries)
            .field("accounting_enabled", &self.accounting_enabled)
            .field("truncated", &self.truncated)
            .field("rejected_lines", &self.rejected_lines)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectErrorKind {
    PermissionDenied,
    Unsupported,
    Io,
}

#[derive(Debug)]
pub(crate) struct CollectError {
    kind: CollectErrorKind,
    message: String,
}

impl CollectError {
    pub(crate) fn io(context: &str, error: io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::PermissionDenied => CollectErrorKind::PermissionDenied,
            io::ErrorKind::NotFound => CollectErrorKind::Unsupported,
            _ => CollectErrorKind::Io,
        };
        Self {
            kind,
            message: format!("{context}: {error}"),
        }
    }

    pub(crate) const fn kind(&self) -> CollectErrorKind {
        self.kind
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub(crate) fn collect(proc_root: &Path) -> Result<FlowCollection, CollectError> {
    let path = proc_root.join("net/nf_conntrack");
    let file = File::open(&path)
        .map_err(|error| CollectError::io("open /proc/net/nf_conntrack", error))?;
    let total_entries = read_small_u64(&proc_root.join("sys/net/netfilter/nf_conntrack_count"));
    let accounting_enabled = read_small_u64(&proc_root.join("sys/net/netfilter/nf_conntrack_acct"))
        .map(|value| value != 0);
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut flows = Vec::new();
    let mut rejected_lines = 0_usize;
    let mut scanned_lines = 0_usize;
    let mut truncated = false;

    loop {
        if scanned_lines >= MAX_SCANNED_LINES || flows.len() >= MAX_RETAINED_FLOWS {
            truncated = true;
            break;
        }
        let Some(line_was_too_long) = read_bounded_line(&mut reader, &mut line)
            .map_err(|error| CollectError::io("read /proc/net/nf_conntrack", error))?
        else {
            break;
        };
        if line.is_empty() && !line_was_too_long {
            continue;
        }
        scanned_lines = scanned_lines.saturating_add(1);
        if line_was_too_long {
            rejected_lines = rejected_lines.saturating_add(1);
            continue;
        }
        match std::str::from_utf8(&line)
            .ok()
            .and_then(|value| parse_line(value).ok())
        {
            Some(flow) => flows.push(flow),
            None => rejected_lines = rejected_lines.saturating_add(1),
        }
    }
    truncated |= total_entries.is_some_and(|total| total > flows.len() as u64);

    Ok(FlowCollection {
        flows,
        total_entries,
        accounting_enabled,
        truncated,
        rejected_lines,
    })
}

fn read_small_u64(path: &Path) -> Option<u64> {
    let value = std::fs::read_to_string(path).ok()?;
    (value.len() <= 32).then_some(())?;
    value.trim().parse().ok()
}

fn read_bounded_line<R: BufRead>(reader: &mut R, output: &mut Vec<u8>) -> io::Result<Option<bool>> {
    output.clear();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!output.is_empty() || too_long).then_some(too_long));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content_len = newline.unwrap_or(consumed);
        let remaining = MAX_LINE_BYTES.saturating_sub(output.len());
        too_long |= content_len > remaining;
        if remaining > 0 {
            output.extend_from_slice(&available[..content_len.min(remaining)]);
        }
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(too_long));
        }
    }
}

#[derive(Default)]
struct TupleBuilder {
    source: Option<IpAddr>,
    destination: Option<IpAddr>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    packets: Option<u64>,
    bytes: Option<u64>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    icmp_id: Option<u16>,
}

impl TupleBuilder {
    fn finish(self, family: AddressFamily) -> Result<(FlowTuple, FlowCounters), ()> {
        let source = self.source.ok_or(())?;
        let destination = self.destination.ok_or(())?;
        if address_family(source) != family || address_family(destination) != family {
            return Err(());
        }
        if self.source_port.is_some() != self.destination_port.is_some() {
            return Err(());
        }
        let icmp = match (self.icmp_type, self.icmp_code, self.icmp_id) {
            (Some(icmp_type), Some(code), Some(id)) => Some(IcmpTupleKey {
                icmp_type,
                code,
                id,
            }),
            (None, None, None) => None,
            _ => return Err(()),
        };
        if self.source_port.is_some() && icmp.is_some() {
            return Err(());
        }
        Ok((
            FlowTuple {
                source: FlowEndpoint {
                    address: source,
                    port: self.source_port,
                },
                destination: FlowEndpoint {
                    address: destination,
                    port: self.destination_port,
                },
                icmp,
            },
            FlowCounters {
                packets: self.packets,
                bytes: self.bytes,
            },
        ))
    }
}

fn parse_line(line: &str) -> Result<RawConntrackFlow, ()> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 7 {
        return Err(());
    }
    let family = match fields[0] {
        "ipv4" => AddressFamily::Ipv4,
        "ipv6" => AddressFamily::Ipv6,
        _ => return Err(()),
    };
    let protocol_name = fields[2];
    if protocol_name.is_empty()
        || protocol_name.len() > 16
        || !protocol_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(());
    }
    let protocol = fields[3].parse::<u8>().map_err(|_| ())?;
    // Linux omits the procfs timeout while IPS_OFFLOAD is set.
    let (timeout_seconds, mut index) = match fields[4].parse::<u64>() {
        Ok(timeout) => (Some(timeout), 5),
        Err(_) if fields[4].starts_with("src=") => (None, 4),
        Err(_) => return Err(()),
    };
    let state = fields
        .get(index)
        .filter(|value| !value.contains('=') && !value.starts_with('['));
    if state.is_some() {
        index += 1;
    }
    let state = state
        .copied()
        .filter(|value| value.len() <= 32 && value.is_ascii())
        .map(str::to_owned);
    let mut tuples = [TupleBuilder::default(), TupleBuilder::default()];
    let mut direction = 0_usize;
    let mut zone = 0_u16;
    let mut ct_mark = None;
    let mut offloaded = false;
    let mut hardware_offloaded = false;

    for field in &fields[index..] {
        match *field {
            "[OFFLOAD]" => {
                offloaded = true;
                continue;
            }
            "[HW_OFFLOAD]" => {
                hardware_offloaded = true;
                continue;
            }
            _ => {}
        }
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        if name == "src" && tuples[direction].source.is_some() {
            direction = 1;
        }
        let tuple = &mut tuples[direction];
        match name {
            "src" => tuple.source = value.parse().ok(),
            "dst" => tuple.destination = value.parse().ok(),
            "sport" => tuple.source_port = value.parse().ok(),
            "dport" => tuple.destination_port = value.parse().ok(),
            "packets" => tuple.packets = value.parse().ok(),
            "bytes" => tuple.bytes = value.parse().ok(),
            "type" => tuple.icmp_type = value.parse().ok(),
            "code" => tuple.icmp_code = value.parse().ok(),
            "id" => tuple.icmp_id = value.parse().ok(),
            "zone" => zone = value.parse().map_err(|_| ())?,
            "mark" => ct_mark = parse_u32(value),
            _ => {}
        }
    }
    let [original, reply] = tuples;
    let (original, original_counters) = original.finish(family)?;
    let (reply, reply_counters) = reply.finish(family)?;
    if timeout_seconds.is_none() && !offloaded && !hardware_offloaded {
        return Err(());
    }
    if matches!(protocol, 1 | 58) && (original.icmp.is_none() || reply.icmp.is_none()) {
        return Err(());
    }
    Ok(RawConntrackFlow {
        family,
        protocol,
        protocol_name: protocol_name.to_owned(),
        state,
        timeout_seconds,
        zone,
        ct_mark,
        original,
        reply,
        original_counters,
        reply_counters,
        offloaded,
        hardware_offloaded,
    })
}

fn parse_u32(value: &str) -> Option<u32> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |hex| u32::from_str_radix(hex, 16).ok(),
        )
}

fn address_family(address: IpAddr) -> AddressFamily {
    match address {
        IpAddr::V4(_) => AddressFamily::Ipv4,
        IpAddr::V6(_) => AddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn collect_dump(dump: &str) -> FlowCollection {
        let root = TempDir::new().unwrap();
        fs::create_dir_all(root.path().join("net")).unwrap();
        fs::write(root.path().join("net/nf_conntrack"), dump).unwrap();
        collect(root.path()).unwrap()
    }

    #[test]
    fn parses_ipv4_nat_tuples_counters_zone_and_offload() {
        let flow = parse_line(
            "ipv4 2 tcp 6 431999 ESTABLISHED \
             src=192.0.2.10 dst=198.51.100.20 sport=54321 dport=443 packets=12 bytes=1200 \
             src=10.0.0.2 dst=192.0.2.10 sport=8443 dport=54321 packets=8 bytes=4000 \
             [ASSURED] [OFFLOAD] mark=0 zone=7 use=2",
        )
        .unwrap();

        assert_eq!(flow.family, AddressFamily::Ipv4);
        assert_eq!(flow.protocol, 6);
        assert_eq!(flow.protocol_name, "tcp");
        assert_eq!(flow.state.as_deref(), Some("ESTABLISHED"));
        assert_eq!(flow.timeout_seconds, Some(431_999));
        assert_eq!(flow.zone, 7);
        assert_eq!(flow.ct_mark, Some(0));
        assert_eq!(flow.original.source.address.to_string(), "192.0.2.10");
        assert_eq!(flow.original.destination.port, Some(443));
        assert_eq!(flow.reply.source.address.to_string(), "10.0.0.2");
        assert_eq!(flow.original_counters.packets, Some(12));
        assert_eq!(flow.reply_counters.bytes, Some(4000));
        assert!(flow.offloaded);
        assert!(!flow.hardware_offloaded);
    }

    #[test]
    fn parses_legacy_offload_row_without_timeout_but_rejects_other_missing_timeouts() {
        let row = "ipv4 2 tcp 6 \
                   src=192.0.2.10 dst=198.51.100.20 sport=54321 dport=443 packets=12 bytes=1200 \
                   src=198.51.100.20 dst=192.0.2.10 sport=443 dport=54321 packets=8 bytes=4000 \
                   [OFFLOAD] mark=0 zone=7 use=2";
        let flow = parse_line(row).unwrap();

        assert_eq!(flow.timeout_seconds, None);
        assert_eq!(flow.state, None);
        assert_eq!(flow.ct_mark, Some(0));
        assert!(flow.offloaded);

        assert!(parse_line(&row.replace(" [OFFLOAD]", "")).is_err());
    }

    #[test]
    fn parses_ipv6_udp_without_accounting_or_ports_loss() {
        let flow = parse_line(
            "ipv6 10 udp 17 29 src=2001:db8::1 dst=2001:db8::2 sport=5353 dport=5353 \
             src=2001:db8::2 dst=2001:db8::1 sport=5353 dport=5353 [UNREPLIED] use=1",
        )
        .unwrap();

        assert_eq!(flow.family, AddressFamily::Ipv6);
        assert_eq!(flow.original.source.port, Some(5353));
        assert_eq!(flow.reply.destination.address.to_string(), "2001:db8::1");
        assert_eq!(flow.original_counters, FlowCounters::default());
        assert_eq!(flow.reply_counters, FlowCounters::default());
    }

    #[test]
    fn parses_icmp_tuple_without_transport_ports() {
        let flow = parse_line(
            "ipv4 2 icmp 1 29 src=192.0.2.1 dst=198.51.100.1 type=8 code=0 id=3 packets=1 bytes=84 \
             src=198.51.100.1 dst=192.0.2.1 type=0 code=0 id=3 packets=1 bytes=84 mark=0 use=1",
        )
        .unwrap();

        assert_eq!(flow.original.source.port, None);
        assert_eq!(flow.reply.destination.port, None);
        assert_eq!(flow.original_counters.bytes, Some(84));
        let original = flow.original.icmp.unwrap();
        let reply = flow.reply.icmp.unwrap();
        assert_eq!((original.icmp_type, original.code, original.id), (8, 0, 3));
        assert_eq!((reply.icmp_type, reply.code, reply.id), (0, 0, 3));
        assert_eq!(flow.ct_mark, Some(0));
    }

    #[test]
    fn parses_decimal_and_hex_conntrack_marks() {
        let decimal = parse_line(
            "ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=1 dport=2 \
             src=198.51.100.1 dst=192.0.2.1 sport=2 dport=1 mark=305419896 use=1",
        )
        .unwrap();
        let hexadecimal = parse_line(
            "ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=1 dport=2 \
             src=198.51.100.1 dst=192.0.2.1 sport=2 dport=1 mark=0x12345678 use=1",
        )
        .unwrap();
        assert_eq!(decimal.ct_mark, Some(0x1234_5678));
        assert_eq!(hexadecimal.ct_mark, Some(0x1234_5678));
    }

    #[test]
    fn raw_debug_never_exposes_tuple_addresses() {
        let flow = parse_line(
            "ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=1 dport=2 packets=1 bytes=2 \
             src=198.51.100.1 dst=192.0.2.1 sport=2 dport=1 packets=1 bytes=2 use=1",
        )
        .unwrap();
        let debug = format!("{flow:?}");
        assert!(!debug.contains("192.0.2.1"), "{debug}");
        assert!(!debug.contains("198.51.100.1"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn bounded_line_reader_discards_oversized_lines_and_recovers() {
        let oversized = format!("{}\nvalid\n", "x".repeat(MAX_LINE_BYTES + 32));
        let mut reader = BufReader::new(oversized.as_bytes());
        let mut line = Vec::new();
        assert_eq!(
            read_bounded_line(&mut reader, &mut line).unwrap(),
            Some(true)
        );
        assert_eq!(line.len(), MAX_LINE_BYTES);
        assert_eq!(
            read_bounded_line(&mut reader, &mut line).unwrap(),
            Some(false)
        );
        assert_eq!(line, b"valid");
        assert_eq!(read_bounded_line(&mut reader, &mut line).unwrap(), None);
    }

    #[test]
    fn collection_stops_at_the_retained_flow_limit() {
        let row = "ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=1 dport=2 \
                   packets=1 bytes=2 src=198.51.100.1 dst=192.0.2.1 sport=2 dport=1 \
                   packets=1 bytes=2 use=1\n";
        let collection = collect_dump(&row.repeat(MAX_RETAINED_FLOWS + 1));

        assert_eq!(collection.flows.len(), MAX_RETAINED_FLOWS);
        assert!(collection.truncated);
        assert_eq!(collection.rejected_lines, 0);
    }

    #[test]
    fn collection_never_scans_beyond_the_line_limit() {
        let collection = collect_dump(&"malformed\n".repeat(MAX_SCANNED_LINES + 1));

        assert!(collection.flows.is_empty());
        assert_eq!(collection.rejected_lines, MAX_SCANNED_LINES);
        assert!(collection.truncated);
    }
}
