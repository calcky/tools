use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use crate::model::{MetricKey, MetricSample};

use super::valid_interface_name;

const ALIGNMENT: usize = 4;
const NLMSG_HEADER_LEN: usize = 16;
const IFINFO_MESSAGE_LEN: usize = 16;
const RTATTR_HEADER_LEN: usize = 4;
const RECEIVE_BUFFER_LEN: usize = 1024 * 1024;
// Bound only the optional handoff; larger inventories use independent collection.
const MAX_SHARED_LINKS: usize = 4096;
#[cfg(test)]
const REQUEST_SEQUENCE: u32 = 1;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLM_F_DUMP_INTR: u16 = 0x10;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWSTATS: u16 = 92;
const RTM_GETSTATS: u16 = 94;
const IFSTATS_MESSAGE_LEN: usize = 12;

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_STATS: u16 = 7;
const IFLA_TXQLEN: u16 = 13;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_STATS64: u16 = 23;
const IFLA_CARRIER_CHANGES: u16 = 35;
const NLA_TYPE_MASK: u16 = 0x3fff;

// Linux 4.14 exposes the first 24 fields. Newer kernels may append fields;
// only names whose UAPI meaning is known here are emitted.
const LINK_STAT_NAMES: [&str; 25] = [
    "rx_packets",
    "tx_packets",
    "rx_bytes",
    "tx_bytes",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
    "multicast",
    "collisions",
    "rx_length_errors",
    "rx_over_errors",
    "rx_crc_errors",
    "rx_frame_errors",
    "rx_fifo_errors",
    "rx_missed_errors",
    "tx_aborted_errors",
    "tx_carrier_errors",
    "tx_fifo_errors",
    "tx_heartbeat_errors",
    "tx_window_errors",
    "rx_compressed",
    "tx_compressed",
    "rx_nohandler",
    "rx_otherhost_dropped",
];
const MIN_LINK_STATS_FIELDS: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorKind {
    Io,
    Loss,
    Interrupted,
    Parse,
}

#[derive(Debug)]
pub struct CollectError {
    kind: ErrorKind,
    message: String,
    errno: Option<i32>,
}

impl CollectError {
    pub(super) fn raw_os_error(&self) -> Option<i32> {
        self.errno
    }

    fn io(context: &str, error: io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            errno: error.raw_os_error(),
            message: format!("{context}: {error}"),
        }
    }

    fn loss(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Loss,
            errno: None,
            message: message.into(),
        }
    }

    fn parse(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Parse,
            errno: None,
            message: message.into(),
        }
    }

    fn interrupted(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Interrupted,
            errno: None,
            message: message.into(),
        }
    }

    pub const fn loss_events(&self) -> u64 {
        if matches!(self.kind, ErrorKind::Loss) {
            1
        } else {
            0
        }
    }

    pub const fn dumps_interrupted(&self) -> u64 {
        if matches!(self.kind, ErrorKind::Interrupted) {
            1
        } else {
            0
        }
    }

    pub const fn parse_errors(&self) -> u64 {
        if matches!(self.kind, ErrorKind::Parse) {
            1
        } else {
            0
        }
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub fn probe() -> Result<(), CollectError> {
    collect_link_stats(None).map(drop)
}

pub fn collect_link_stats(interface: Option<&str>) -> Result<Vec<MetricSample>, CollectError> {
    collect_link_counters(interface).map(link_metrics)
}

#[derive(Debug)]
pub(crate) struct LinkCounters {
    pub interface: String,
    pub ifindex: u32,
    pub counter_bits: u8,
    pub values: Vec<u64>,
    pub carrier_changes: Option<u32>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LinkMetadata {
    pub ifindex: u32,
    pub name: String,
    pub operstate: Option<u8>,
    pub tx_queue_len: Option<u32>,
    pub mtu: Option<u32>,
}

// Consumed within one collection cycle; never retained with cached samples.
#[derive(Debug)]
pub(crate) struct FreshLinkMetadata {
    pub started_at: Instant,
    pub links: Vec<LinkMetadata>,
}

impl LinkCounters {
    pub(crate) fn counters(&self) -> impl Iterator<Item = (&'static str, u64, u8)> + '_ {
        LINK_STAT_NAMES
            .iter()
            .copied()
            .zip(self.values.iter().copied())
            .map(|(name, value)| (name, value, self.counter_bits))
            .chain(
                self.carrier_changes
                    .map(|value| ("carrier_changes", u64::from(value), 32)),
            )
    }
}

fn link_metrics(links: Vec<LinkCounters>) -> Vec<MetricSample> {
    let mut metrics = Vec::new();
    for link in links {
        let ifindex = link.ifindex.to_string();
        for (name, value, bits) in link.counters() {
            metrics.push(MetricSample {
                key: MetricKey::new("rtnetlink_link_stats", "link", name)
                    .with_label("counter_bits", if bits == 64 { "64" } else { "32" })
                    .with_label("ifindex", &ifindex)
                    .with_label("interface", &link.interface),
                value,
            });
        }
    }
    metrics.sort_by(|left, right| left.key.cmp(&right.key));
    metrics
}

pub(crate) fn collect_link_counters(
    interface: Option<&str>,
) -> Result<Vec<LinkCounters>, CollectError> {
    if interface.is_some_and(|name| !valid_interface_name(name)) {
        return Err(CollectError::parse(format!(
            "invalid interface name {interface:?}"
        )));
    }

    match collect_targeted_counters(interface) {
        Err(error) if error.errno == Some(libc::EOPNOTSUPP) => collect_legacy_counters(interface),
        result => result,
    }
}

fn collect_targeted_counters(interface: Option<&str>) -> Result<Vec<LinkCounters>, CollectError> {
    Context::default()
        .collect_targeted(interface, false)
        .map(|(links, _)| links)
}

// Independent callers retain a fresh socket and buffer for each invocation.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_link_counters_with_metadata(
    share_metadata: bool,
) -> Result<(Vec<LinkCounters>, Option<FreshLinkMetadata>), CollectError> {
    Context::default().collect(share_metadata)
}

#[derive(Debug, Default)]
pub(crate) struct Context {
    socket: Option<RouteSocket>,
    buffer: Vec<u8>,
    sequence: u32,
}

impl Context {
    pub(crate) fn collect(
        &mut self,
        share_metadata: bool,
    ) -> Result<(Vec<LinkCounters>, Option<FreshLinkMetadata>), CollectError> {
        match self.collect_targeted(None, share_metadata) {
            Err(error) if error.errno == Some(libc::EOPNOTSUPP) => {
                self.collect_legacy(None).map(|links| (links, None))
            }
            result => result,
        }
    }

    fn collect_targeted(
        &mut self,
        interface: Option<&str>,
        share_metadata: bool,
    ) -> Result<(Vec<LinkCounters>, Option<FreshLinkMetadata>), CollectError> {
        self.with_socket(open_route_socket, |socket, buffer| {
            collect_targeted_with_metadata(socket, buffer, interface, share_metadata)
        })
    }

    fn collect_legacy(
        &mut self,
        interface: Option<&str>,
    ) -> Result<Vec<LinkCounters>, CollectError> {
        self.with_socket(open_route_socket, |socket, buffer| {
            let sequence = send_getlink_request(socket)?;
            let mut parser = DumpParser::new(interface);
            receive_dump(socket, buffer, &mut parser, sequence)?;
            parser.finish()
        })
    }

    fn with_socket<T>(
        &mut self,
        open: impl FnOnce() -> Result<RouteSocket, CollectError>,
        collect: impl FnOnce(&mut RouteSocket, &mut [u8]) -> Result<T, CollectError>,
    ) -> Result<T, CollectError> {
        // Reserve sequences for both metadata brackets and GETSTATS. Reopen
        // before wrap so a delayed reply can never match a reused sequence.
        if self.sequence > u32::MAX - 3 {
            self.socket = None;
            self.sequence = 0;
        }
        if self.socket.is_none() {
            let mut socket = open()?;
            socket.sequence = self.sequence;
            self.socket = Some(socket);
        }
        self.buffer.resize(RECEIVE_BUFFER_LEN, 0);
        let mut socket = self.socket.take().expect("initialized above");
        let result = collect(&mut socket, &mut self.buffer);
        self.sequence = socket.sequence;
        // Only a complete successful transaction may reuse this socket.
        // Errors or unwinding can leave replies queued for the old request.
        if result.is_ok() {
            self.socket = Some(socket);
        }
        result
    }
}

fn collect_targeted_with_metadata(
    socket: &mut RouteSocket,
    buffer: &mut [u8],
    interface: Option<&str>,
    share_metadata: bool,
) -> Result<(Vec<LinkCounters>, Option<FreshLinkMetadata>), CollectError> {
    let mut metadata_request = [0; IFINFO_MESSAGE_LEN + 8];
    put_u16(&mut metadata_request[16..18], 8);
    put_u16(&mut metadata_request[18..20], 29); // IFLA_EXT_MASK
    put_u32(&mut metadata_request[20..24], 1 << 3); // RTEXT_FILTER_SKIP_STATS (4.14)
    let sequence = send_dump_request(socket, libc::RTM_GETLINK, &metadata_request)?;
    let before = read_dump(socket, buffer, DumpMode::Metadata, sequence)?;

    // RTM_GETSTATS (Linux 4.7+) requests only IFLA_STATS_LINK_64. The
    // surrounding metadata dumps detect renames and index reuse under a new
    // name. UAPI has no generation to detect identical name-and-index reuse.
    let mut payload = [0; IFSTATS_MESSAGE_LEN];
    put_u32(&mut payload[8..12], 1);
    let sequence = send_dump_request(socket, RTM_GETSTATS, &payload)?;
    let statistics = read_dump(socket, buffer, DumpMode::Statistics, sequence)?;

    let started_at = Instant::now();
    let sequence = send_dump_request(socket, libc::RTM_GETLINK, &metadata_request)?;
    let mut parser = DumpParser::new(None);
    parser.mode = DumpMode::Metadata;
    parser.inventory = share_metadata.then(Vec::new);
    receive_dump(socket, buffer, &mut parser, sequence)?;
    finish_shared_dump(parser, &before, statistics, interface, started_at)
}

fn finish_shared_dump(
    mut parser: DumpParser<'_>,
    before: &[LinkCounters],
    statistics: Vec<LinkCounters>,
    interface: Option<&str>,
    started_at: Instant,
) -> Result<(Vec<LinkCounters>, Option<FreshLinkMetadata>), CollectError> {
    let inventory = parser.inventory.take();
    let metadata = parser.finish()?;
    verify_metadata_identities(before, &metadata)?;
    let counters = join_dumps(metadata, statistics, interface)?;
    Ok((
        counters,
        inventory.map(|links| FreshLinkMetadata { started_at, links }),
    ))
}

fn verify_metadata_identities(
    before: &[LinkCounters],
    after: &[LinkCounters],
) -> Result<(), CollectError> {
    let identities: BTreeMap<_, _> = before
        .iter()
        .map(|link| (link.ifindex, link.interface.as_str()))
        .collect();
    if before.len() != after.len()
        || before.len() != identities.len()
        || after
            .iter()
            .any(|link| identities.get(&link.ifindex).copied() != Some(link.interface.as_str()))
    {
        return Err(CollectError::interrupted(
            "interface identity changed while collecting link statistics",
        ));
    }
    Ok(())
}

fn read_dump(
    socket: &RouteSocket,
    buffer: &mut [u8],
    mode: DumpMode,
    sequence: u32,
) -> Result<Vec<LinkCounters>, CollectError> {
    let mut parser = DumpParser::new(None);
    parser.mode = mode;
    receive_dump(socket, buffer, &mut parser, sequence)?;
    parser.finish()
}

fn receive_dump(
    socket: &RouteSocket,
    buffer: &mut [u8],
    parser: &mut DumpParser<'_>,
    sequence: u32,
) -> Result<(), CollectError> {
    while !parser.done {
        let received = receive_datagram(socket, buffer)?;
        parser.parse_datagram(&buffer[..received], sequence, socket.port_id)?;
    }
    Ok(())
}

fn join_dumps(
    mut metadata: Vec<LinkCounters>,
    statistics: Vec<LinkCounters>,
    selected: Option<&str>,
) -> Result<Vec<LinkCounters>, CollectError> {
    let statistic_count = statistics.len();
    let mut statistics: BTreeMap<_, _> = statistics
        .into_iter()
        .map(|link| (link.ifindex, link))
        .collect();
    if statistic_count != statistics.len() {
        return Err(CollectError::parse(
            "statistics dump contains duplicate interfaces",
        ));
    }
    if metadata.len() != statistics.len() {
        return Err(CollectError::interrupted(
            "interface inventory changed between metadata and statistics dumps",
        ));
    }
    for link in &mut metadata {
        let statistics = statistics.remove(&link.ifindex).ok_or_else(|| {
            CollectError::interrupted(
                "interface identity changed between metadata and statistics dumps",
            )
        })?;
        link.values = statistics.values;
        link.counter_bits = statistics.counter_bits;
    }
    if !statistics.is_empty() {
        return Err(CollectError::interrupted(
            "statistics dump contains unmatched interfaces",
        ));
    }
    if let Some(selected) = selected {
        metadata.retain(|link| link.interface == selected);
    }
    if metadata.is_empty() {
        return Err(CollectError::parse(
            "selected interface not found in link dumps",
        ));
    }
    Ok(metadata)
}

fn collect_legacy_counters(interface: Option<&str>) -> Result<Vec<LinkCounters>, CollectError> {
    Context::default().collect_legacy(interface)
}

#[derive(Debug)]
pub(super) struct RouteSocket {
    fd: OwnedFd,
    port_id: u32,
    sequence: u32,
}

impl RouteSocket {
    pub(super) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn port_id(&self) -> u32 {
        self.port_id
    }

    fn next_sequence(&mut self) -> Result<u32, CollectError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| CollectError::parse("NETLINK_ROUTE request sequence exhausted"))?;
        Ok(self.sequence)
    }
}

pub(super) fn open_route_socket() -> Result<RouteSocket, CollectError> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw_fd < 0 {
        return Err(CollectError::io(
            "create NETLINK_ROUTE socket",
            io::Error::last_os_error(),
        ));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(CollectError::io(
            "bind NETLINK_ROUTE socket",
            io::Error::last_os_error(),
        ));
    }

    let mut bound_address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut bound_address_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockname(
            fd.as_raw_fd(),
            std::ptr::from_mut(&mut bound_address).cast::<libc::sockaddr>(),
            &mut bound_address_len,
        )
    };
    if result < 0 {
        return Err(CollectError::io(
            "read NETLINK_ROUTE port ID",
            io::Error::last_os_error(),
        ));
    }
    if bound_address_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || bound_address.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || bound_address.nl_pid == 0
    {
        return Err(CollectError::parse(
            "NETLINK_ROUTE socket has an invalid local address",
        ));
    }

    let timeval = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(CollectError::io(
            "set NETLINK_ROUTE receive timeout",
            io::Error::last_os_error(),
        ));
    }

    Ok(RouteSocket {
        fd,
        port_id: bound_address.nl_pid,
        sequence: 0,
    })
}

fn send_getlink_request(socket: &mut RouteSocket) -> Result<u32, CollectError> {
    send_dump_request(socket, libc::RTM_GETLINK, &[0; IFINFO_MESSAGE_LEN])
}

pub(super) fn send_dump_request(
    socket: &mut RouteSocket,
    kind: u16,
    payload: &[u8],
) -> Result<u32, CollectError> {
    let sequence = socket.next_sequence()?;
    let mut request = vec![0; NLMSG_HEADER_LEN];
    request.extend_from_slice(payload);
    let request_len = request.len() as u32;
    put_u32(&mut request[0..4], request_len);
    put_u16(&mut request[4..6], kind);
    put_u16(
        &mut request[6..8],
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
    );
    put_u32(&mut request[8..12], sequence);
    put_u32(&mut request[12..16], socket.port_id);

    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;

    loop {
        let sent = unsafe {
            libc::sendto(
                socket.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                std::ptr::from_ref(&kernel).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent >= 0 {
            if sent as usize != request.len() {
                return Err(CollectError::io(
                    "send RTM_GETLINK request",
                    io::Error::new(io::ErrorKind::WriteZero, "short netlink datagram write"),
                ));
            }
            return Ok(sequence);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(CollectError::io("send RTM_GETLINK request", error));
        }
    }
}

pub(super) fn receive_datagram(
    socket: &RouteSocket,
    buffer: &mut [u8],
) -> Result<usize, CollectError> {
    loop {
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut source_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        let received = unsafe {
            libc::recvfrom(
                socket.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                std::ptr::from_mut(&mut source).cast::<libc::sockaddr>(),
                &mut source_len,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(CollectError::loss(
                    "NETLINK_ROUTE receive queue overflowed; link dump is incomplete",
                ));
            }
            return Err(CollectError::io("receive RTM_GETLINK response", error));
        }
        let received = received as usize;
        if received == 0 {
            return Err(CollectError::parse(
                "NETLINK_ROUTE returned an empty datagram",
            ));
        }
        if received > buffer.len() {
            return Err(CollectError::loss(format!(
                "NETLINK_ROUTE datagram needs {received} bytes, exceeding the {}-byte receive buffer",
                buffer.len()
            )));
        }
        if source_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
            || source.nl_groups != 0
        {
            return Err(CollectError::parse(
                "RTM_GETLINK response did not originate from the kernel",
            ));
        }
        return Ok(received);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DumpMode {
    Full,
    Metadata,
    Statistics,
}

struct DumpParser<'a> {
    interface: Option<&'a str>,
    links: Vec<LinkCounters>,
    seen_ifindices: BTreeSet<i32>,
    seen_interface_names: BTreeSet<String>,
    matched_interface: bool,
    done: bool,
    mode: DumpMode,
    inventory: Option<Vec<LinkMetadata>>,
}

impl<'a> DumpParser<'a> {
    fn new(interface: Option<&'a str>) -> Self {
        Self {
            interface,
            links: Vec::new(),
            seen_ifindices: BTreeSet::new(),
            seen_interface_names: BTreeSet::new(),
            matched_interface: false,
            done: false,
            mode: DumpMode::Full,
            inventory: None,
        }
    }

    fn parse_datagram(
        &mut self,
        datagram: &[u8],
        sequence: u32,
        port_id: u32,
    ) -> Result<(), CollectError> {
        let mut offset = 0_usize;
        while offset < datagram.len() {
            if datagram.len() - offset < NLMSG_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated netlink message header in RTM_GETLINK response",
                ));
            }
            let header = &datagram[offset..offset + NLMSG_HEADER_LEN];
            let message_len = read_u32(&header[0..4]) as usize;
            let message_type = read_u16(&header[4..6]);
            let flags = read_u16(&header[6..8]);
            let message_sequence = read_u32(&header[8..12]);
            let sender_port = read_u32(&header[12..16]);
            if message_len < NLMSG_HEADER_LEN || message_len > datagram.len() - offset {
                return Err(CollectError::parse(format!(
                    "invalid netlink message length {message_len} in {}-byte remainder",
                    datagram.len() - offset
                )));
            }
            if message_sequence != sequence || sender_port != port_id {
                return Err(CollectError::parse(
                    "unexpected netlink destination or sequence in RTM_GETLINK response",
                ));
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(CollectError::interrupted(
                    "kernel interrupted the RTM_GETLINK dump; link statistics are incomplete",
                ));
            }

            let payload = &datagram[offset + NLMSG_HEADER_LEN..offset + message_len];
            // The NIC inventory parser requires complete alignment, only link
            // messages, and a terminal DONE with no trailing messages.
            if self.inventory.is_some()
                && (align(message_len) > datagram.len() - offset
                    || !matches!(message_type, RTM_NEWLINK | NLMSG_DONE)
                    || self.done
                    || (message_type == NLMSG_DONE
                        && (offset + align(message_len) != datagram.len()
                            || (!payload.is_empty() && payload.len() != 4))))
            {
                self.inventory = None;
            }
            match message_type {
                NLMSG_NOOP => {}
                NLMSG_ERROR => parse_netlink_error(payload)?,
                NLMSG_DONE => {
                    parse_done_error(payload)?;
                    self.done = true;
                }
                NLMSG_OVERRUN => {
                    return Err(CollectError::loss(
                        "kernel reported NETLINK_ROUTE message overrun; link dump is incomplete",
                    ));
                }
                RTM_NEWLINK if self.mode != DumpMode::Statistics => self.parse_link(payload)?,
                RTM_NEWSTATS if self.mode == DumpMode::Statistics => {
                    self.parse_statistics(payload)?
                }
                RTM_NEWLINK | RTM_NEWSTATS => {
                    return Err(CollectError::parse("unexpected link dump response type"))
                }
                _ => {}
            }

            let aligned_len = align(message_len);
            if aligned_len > datagram.len() - offset {
                if message_len == datagram.len() - offset {
                    offset = datagram.len();
                } else {
                    return Err(CollectError::parse(
                        "truncated netlink message alignment padding",
                    ));
                }
            } else {
                offset += aligned_len;
            }
        }
        Ok(())
    }

    fn parse_link(&mut self, payload: &[u8]) -> Result<(), CollectError> {
        if payload.len() < IFINFO_MESSAGE_LEN {
            return Err(CollectError::parse(
                "RTM_NEWLINK payload is shorter than ifinfomsg",
            ));
        }
        let ifindex = read_i32(&payload[4..8]);
        if ifindex <= 0 {
            return Err(CollectError::parse(format!(
                "RTM_NEWLINK contains invalid ifindex {ifindex}"
            )));
        }

        let mut interface_name = None;
        let mut stats64 = None;
        let mut stats32 = None;
        let mut carrier_changes = None;
        let mut operstate = None;
        let mut tx_queue_len = None;
        let mut mtu = None;
        let mut offset = IFINFO_MESSAGE_LEN;
        while offset < payload.len() {
            if payload.len() - offset < RTATTR_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated RTM_NEWLINK attribute header",
                ));
            }
            let attribute_len = read_u16(&payload[offset..offset + 2]) as usize;
            let attribute_type = read_u16(&payload[offset + 2..offset + 4]) & NLA_TYPE_MASK;
            if attribute_len < RTATTR_HEADER_LEN || attribute_len > payload.len() - offset {
                return Err(CollectError::parse(format!(
                    "invalid RTM_NEWLINK attribute length {attribute_len}"
                )));
            }
            let value = &payload[offset + RTATTR_HEADER_LEN..offset + attribute_len];
            if self.inventory.is_some()
                && (read_u16(&payload[offset + 2..offset + 4]) & 0x4000 != 0
                    || align(attribute_len) > payload.len() - offset)
            {
                self.inventory = None;
            }
            match attribute_type {
                IFLA_MTU if self.inventory.is_some() => {
                    if value.len() != 4 || mtu.replace(read_u32(value)).is_some() {
                        self.inventory = None;
                    }
                }
                IFLA_OPERSTATE if self.inventory.is_some() => {
                    if value.len() != 1 || operstate.replace(value[0]).is_some() {
                        self.inventory = None;
                    }
                }
                IFLA_TXQLEN if self.inventory.is_some() => {
                    if value.len() != 4 || tx_queue_len.replace(read_u32(value)).is_some() {
                        self.inventory = None;
                    }
                }
                IFLA_IFNAME => set_once(
                    &mut interface_name,
                    parse_interface_name(value)?,
                    "IFLA_IFNAME",
                )?,
                IFLA_STATS64 => set_once(
                    &mut stats64,
                    parse_stats(value, size_of::<u64>())?,
                    "IFLA_STATS64",
                )?,
                IFLA_STATS => set_once(
                    &mut stats32,
                    parse_stats(value, size_of::<u32>())?,
                    "IFLA_STATS",
                )?,
                IFLA_CARRIER_CHANGES => {
                    if value.len() != size_of::<u32>() {
                        return Err(CollectError::parse(format!(
                            "IFLA_CARRIER_CHANGES has {} bytes; expected {}",
                            value.len(),
                            size_of::<u32>()
                        )));
                    }
                    set_once(
                        &mut carrier_changes,
                        read_u32(value),
                        "IFLA_CARRIER_CHANGES",
                    )?;
                }
                _ => {}
            }

            let aligned_len = align(attribute_len);
            if aligned_len > payload.len() - offset {
                if attribute_len == payload.len() - offset {
                    offset = payload.len();
                } else {
                    return Err(CollectError::parse(
                        "truncated RTM_NEWLINK attribute alignment padding",
                    ));
                }
            } else {
                offset += aligned_len;
            }
        }

        let interface_name = interface_name
            .ok_or_else(|| CollectError::parse("RTM_NEWLINK is missing IFLA_IFNAME"))?;
        if !self.seen_ifindices.insert(ifindex) {
            return Err(CollectError::parse(format!(
                "RTM_GETLINK dump contains duplicate ifindex {ifindex}"
            )));
        }
        if !self.seen_interface_names.insert(interface_name.clone()) {
            return Err(CollectError::parse(format!(
                "RTM_GETLINK dump contains duplicate interface name {interface_name:?}"
            )));
        }
        let (values, counter_bits) = stats64
            .map(|values| (values, 64))
            .or_else(|| stats32.map(|values| (values, 32)))
            .or_else(|| (self.mode == DumpMode::Metadata).then(|| (Vec::new(), 64)))
            .ok_or_else(|| CollectError::parse("RTM_NEWLINK is missing link statistics"))?;
        if self
            .interface
            .is_some_and(|selected| selected != interface_name)
        {
            return Ok(());
        }

        self.matched_interface = true;
        if self.inventory.as_ref().is_some_and(|links| {
            links.len() >= MAX_SHARED_LINKS || !valid_interface_name(&interface_name)
        }) {
            self.inventory = None;
        }
        if let Some(inventory) = &mut self.inventory {
            inventory.push(LinkMetadata {
                ifindex: ifindex as u32,
                name: interface_name.clone(),
                operstate,
                tx_queue_len,
                mtu,
            });
        }
        self.links.push(LinkCounters {
            interface: interface_name,
            ifindex: ifindex as u32,
            counter_bits,
            values,
            carrier_changes,
        });
        Ok(())
    }

    fn parse_statistics(&mut self, payload: &[u8]) -> Result<(), CollectError> {
        if payload.len() < IFSTATS_MESSAGE_LEN {
            return Err(CollectError::parse(
                "RTM_NEWSTATS payload is shorter than if_stats_msg",
            ));
        }
        let ifindex = read_i32(&payload[4..8]);
        if ifindex <= 0 || !self.seen_ifindices.insert(ifindex) {
            return Err(CollectError::parse(
                "invalid or duplicate RTM_NEWSTATS ifindex",
            ));
        }
        if read_u32(&payload[8..12]) & 1 == 0 {
            return Err(CollectError::parse(
                "RTM_NEWSTATS omitted the requested link statistics filter",
            ));
        }
        let mut values = None;
        let mut offset = IFSTATS_MESSAGE_LEN;
        while offset < payload.len() {
            if payload.len() - offset < RTATTR_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated RTM_NEWSTATS attribute header",
                ));
            }
            let length = read_u16(&payload[offset..offset + 2]) as usize;
            let kind = read_u16(&payload[offset + 2..offset + 4]) & NLA_TYPE_MASK;
            if length < RTATTR_HEADER_LEN || length > payload.len() - offset {
                return Err(CollectError::parse("invalid RTM_NEWSTATS attribute length"));
            }
            if kind == 1 {
                set_once(
                    &mut values,
                    parse_stats(&payload[offset + RTATTR_HEADER_LEN..offset + length], 8)?,
                    "IFLA_STATS_LINK_64",
                )?;
            }
            let aligned = align(length);
            if aligned > payload.len() - offset && length != payload.len() - offset {
                return Err(CollectError::parse(
                    "truncated RTM_NEWSTATS attribute padding",
                ));
            }
            offset += aligned.min(payload.len() - offset);
        }
        let values =
            values.ok_or_else(|| CollectError::parse("RTM_NEWSTATS omitted IFLA_STATS_LINK_64"))?;
        self.matched_interface = true;
        self.links.push(LinkCounters {
            interface: String::new(),
            ifindex: ifindex as u32,
            counter_bits: 64,
            values,
            carrier_changes: None,
        });
        Ok(())
    }

    fn finish(self) -> Result<Vec<LinkCounters>, CollectError> {
        if !self.done {
            return Err(CollectError::interrupted(
                "RTM_GETLINK response ended without NLMSG_DONE",
            ));
        }
        if !self.matched_interface {
            return Err(CollectError::parse(match self.interface {
                Some(interface) => format!("interface {interface} not found in RTM_GETLINK dump"),
                None => "RTM_GETLINK dump contained no interfaces".to_owned(),
            }));
        }
        Ok(self.links)
    }
}

fn parse_netlink_error(payload: &[u8]) -> Result<(), CollectError> {
    let nlmsgerr_len = size_of::<i32>() + NLMSG_HEADER_LEN;
    if payload.len() < nlmsgerr_len {
        return Err(CollectError::parse(
            "NLMSG_ERROR payload is shorter than nlmsgerr",
        ));
    }
    let code = read_i32(&payload[..size_of::<i32>()]);
    if code == 0 {
        return Err(CollectError::parse(
            "unexpected netlink ACK for RTM_GETLINK request",
        ));
    }
    if code == i32::MIN || code > 0 {
        return Err(CollectError::parse(format!(
            "NLMSG_ERROR contains invalid errno {code}"
        )));
    }
    Err(CollectError::io(
        "kernel rejected RTM_GETLINK request",
        io::Error::from_raw_os_error(-code),
    ))
}

fn parse_done_error(payload: &[u8]) -> Result<(), CollectError> {
    if payload.is_empty() {
        return Ok(());
    }
    if payload.len() < size_of::<i32>() {
        return Err(CollectError::parse(
            "NLMSG_DONE payload is shorter than a completion code",
        ));
    }
    let code = read_i32(&payload[..size_of::<i32>()]);
    if code == 0 {
        Ok(())
    } else if code == i32::MIN || code > 0 {
        Err(CollectError::parse(format!(
            "NLMSG_DONE contains invalid completion code {code}"
        )))
    } else {
        Err(CollectError::io(
            "kernel failed RTM_GETLINK dump",
            io::Error::from_raw_os_error(-code),
        ))
    }
}

fn parse_interface_name(value: &[u8]) -> Result<String, CollectError> {
    if value.len() > libc::IFNAMSIZ {
        return Err(CollectError::parse(format!(
            "IFLA_IFNAME exceeds Linux IFNAMSIZ: {} bytes",
            value.len()
        )));
    }
    let Some(nul) = value.iter().position(|byte| *byte == 0) else {
        return Err(CollectError::parse("IFLA_IFNAME is not NUL-terminated"));
    };
    if nul == 0 || nul + 1 != value.len() {
        return Err(CollectError::parse(
            "IFLA_IFNAME contains bytes after its terminator",
        ));
    }
    std::str::from_utf8(&value[..nul])
        .map(str::to_owned)
        .map_err(|error| CollectError::parse(format!("IFLA_IFNAME is not valid UTF-8: {error}")))
}

fn parse_stats(value: &[u8], width: usize) -> Result<Vec<u64>, CollectError> {
    let minimum_len = MIN_LINK_STATS_FIELDS * width;
    if value.len() < minimum_len || value.len() % width != 0 {
        return Err(CollectError::parse(format!(
            "link statistics payload has {} bytes; expected at least {minimum_len} in {width}-byte fields",
            value.len()
        )));
    }
    let field_count = (value.len() / width).min(LINK_STAT_NAMES.len());
    let mut values = Vec::with_capacity(field_count);
    for field in value[..field_count * width].chunks_exact(width) {
        values.push(match width {
            4 => u64::from(read_u32(field)),
            8 => read_u64(field),
            _ => unreachable!("link statistic width is fixed by the UAPI"),
        });
    }
    Ok(values)
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), CollectError> {
    if slot.replace(value).is_some() {
        Err(CollectError::parse(format!(
            "RTM_NEWLINK contains duplicate {name} attributes"
        )))
    } else {
        Ok(())
    }
}

const fn align(length: usize) -> usize {
    (length + ALIGNMENT - 1) & !(ALIGNMENT - 1)
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes(bytes.try_into().expect("u16 slice length is checked"))
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes(bytes.try_into().expect("u32 slice length is checked"))
}

fn read_i32(bytes: &[u8]) -> i32 {
    i32::from_ne_bytes(bytes.try_into().expect("i32 slice length is checked"))
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_ne_bytes(bytes.try_into().expect("u64 slice length is checked"))
}

fn put_u16(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_socket() -> (RouteSocket, std::os::unix::net::UnixStream) {
        let (fd, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (
            RouteSocket {
                fd: fd.into(),
                port_id: 0,
                sequence: 0,
            },
            peer,
        )
    }

    fn test_fd_identity(fd: libc::c_int) -> io::Result<(libc::dev_t, libc::ino_t)> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        loop {
            // SAFETY: fstat initializes the writable stat on success. A closed
            // or concurrently reused descriptor is intentionally supported.
            if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } == 0 {
                let metadata = unsafe { metadata.assume_init() };
                return Ok((metadata.st_dev, metadata.st_ino));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn assert_local_socket_closed(fd: libc::c_int, identity: (libc::dev_t, libc::ino_t)) {
        // Other tests may reuse the descriptor number or fork with a temporary
        // copy of the endpoint. Peer EOF cannot prove this process closed its FD.
        match test_fd_identity(fd) {
            Ok(current) => assert_ne!(current, identity, "local socket descriptor is still open"),
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EBADF)),
        }
    }

    #[test]
    fn local_socket_close_is_observable_while_an_inherited_endpoint_remains_open() {
        use std::io::Read;

        let mut context = Context::default();
        let (socket, mut peer) = test_socket();
        let fd = socket.fd.as_raw_fd();
        let identity = test_fd_identity(fd).unwrap();
        // Model the reference a concurrent fork retains until exec, even when
        // the parent's socket was created with CLOEXEC.
        let inherited = socket.fd.try_clone().unwrap();
        let result: Result<(), _> = context.with_socket(
            || Ok(socket),
            |_, _| Err(CollectError::interrupted("incomplete dump")),
        );
        assert!(result.is_err());
        assert!(context.socket.is_none());
        assert_local_socket_closed(fd, identity);
        assert_eq!(test_fd_identity(inherited.as_raw_fd()).unwrap(), identity);
        loop {
            match peer.read(&mut [0]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
                    break;
                }
            }
        }
    }

    #[test]
    fn context_reuses_one_socket_and_buffer_without_retaining_parsed_observations() {
        let mut context = Context::default();
        assert!(context.socket.is_none());
        assert!(context.buffer.is_empty());
        let (socket, _peer) = test_socket();
        let mut initial_socket = Some(socket);
        let mut buffer_address = None;
        for cycle in 0..3_u32 {
            let links = context
                .with_socket(
                    || {
                        Ok(initial_socket
                            .take()
                            .expect("socket reopened after successful collection"))
                    },
                    |socket, buffer| {
                        assert_eq!(buffer.len(), RECEIVE_BUFFER_LEN);
                        if let Some(address) = buffer_address {
                            assert_eq!(buffer.as_ptr() as usize, address);
                            assert_eq!(buffer[RECEIVE_BUFFER_LEN - 1], 0xa5);
                        } else {
                            buffer_address = Some(buffer.as_ptr() as usize);
                        }
                        buffer[RECEIVE_BUFFER_LEN - 1] = 0xa5;
                        for phase in 1..=3 {
                            assert_eq!(socket.next_sequence()?, cycle * 3 + phase);
                        }
                        let name = if cycle == 0 { "eth0" } else { "lo" };
                        let values = vec![u64::from(cycle); if cycle == 0 { 25 } else { 24 }];
                        let mut bytes = link_message(
                            socket.sequence,
                            cycle as i32 + 1,
                            name,
                            Some(&values),
                            None,
                            None,
                        );
                        bytes.extend(done_message(socket.sequence, 0));
                        buffer[..bytes.len()].copy_from_slice(&bytes);
                        let mut parser = DumpParser::new(None);
                        parser.parse_datagram(
                            &buffer[..bytes.len()],
                            socket.sequence,
                            socket.port_id,
                        )?;
                        parser.finish()
                    },
                )
                .unwrap();
            assert_eq!(links.len(), 1);
            assert_eq!(links[0].ifindex, cycle + 1);
            assert!(links[0]
                .values
                .iter()
                .all(|value| *value == u64::from(cycle)));
            assert_eq!(links[0].values.len(), if cycle == 0 { 25 } else { 24 });
        }
        assert_eq!(context.sequence, 9);
    }

    #[test]
    fn context_discards_failed_socket_and_reconnects_without_reusing_sequence_or_buffer_allocation()
    {
        for error in [
            CollectError::io("receive", io::Error::from_raw_os_error(libc::EAGAIN)),
            CollectError::io(
                "unsupported",
                io::Error::from_raw_os_error(libc::EOPNOTSUPP),
            ),
            CollectError::io("receive", io::Error::from_raw_os_error(libc::ENOBUFS)),
            CollectError::loss("truncated"),
            CollectError::interrupted("unfinished"),
            CollectError::parse("bad reply"),
        ] {
            let expected = (error.kind, error.errno, error.to_string());
            let mut context = Context::default();
            let (socket, _peer) = test_socket();
            let fd = socket.fd.as_raw_fd();
            let identity = test_fd_identity(fd).unwrap();
            let result: Result<(), _> = context.with_socket(
                || Ok(socket),
                |socket, _| {
                    assert_eq!(socket.next_sequence()?, 1);
                    Err(error)
                },
            );
            let error = result.unwrap_err();
            assert_eq!((error.kind, error.errno, error.to_string()), expected);
            assert!(context.socket.is_none());
            assert_local_socket_closed(fd, identity);
            let buffer_address = context.buffer.as_ptr();
            let (replacement, _peer) = test_socket();
            context
                .with_socket(
                    || Ok(replacement),
                    |socket, buffer| {
                        assert_eq!(socket.next_sequence()?, 2);
                        assert_eq!(buffer.as_ptr(), buffer_address);
                        Ok(())
                    },
                )
                .unwrap();
            assert!(context.socket.is_some());
        }
    }

    #[test]
    fn incomplete_interrupted_and_delayed_dump_replies_invalidate_context() {
        let incomplete = link_message(2, 1, "lo", Some(&[0; 24]), None, None);
        let mut interrupted = incomplete.clone();
        interrupted.extend(done_message(2, NLM_F_DUMP_INTR));
        for (bytes, expected) in [
            (incomplete, ErrorKind::Interrupted),
            (interrupted, ErrorKind::Interrupted),
            (done_message(1, 0), ErrorKind::Parse),
            (message(NLMSG_OVERRUN, 0, 2, &[]), ErrorKind::Loss),
        ] {
            let mut context = Context::default();
            let (socket, _peer) = test_socket();
            context
                .with_socket(|| Ok(socket), |socket, _| socket.next_sequence())
                .unwrap();
            let error = context
                .with_socket(
                    || panic!("healthy socket should be reused"),
                    |socket, buffer| {
                        let sequence = socket.next_sequence()?;
                        buffer[..bytes.len()].copy_from_slice(&bytes);
                        let mut parser = DumpParser::new(None);
                        parser.parse_datagram(&buffer[..bytes.len()], sequence, socket.port_id)?;
                        parser.finish()
                    },
                )
                .unwrap_err();
            assert_eq!(error.kind, expected);
            assert!(context.socket.is_none());
        }
    }

    #[test]
    fn sequence_wrap_reopens_before_next_three_dump_transaction() {
        let mut context = Context {
            sequence: u32::MAX - 3,
            ..Context::default()
        };
        let (socket, _peer) = test_socket();
        let fd = socket.fd.as_raw_fd();
        let identity = test_fd_identity(fd).unwrap();
        context
            .with_socket(
                || Ok(socket),
                |socket, _| {
                    for expected in [u32::MAX - 2, u32::MAX - 1, u32::MAX] {
                        assert_eq!(socket.next_sequence()?, expected);
                    }
                    Ok(())
                },
            )
            .unwrap();
        let (replacement, _peer) = test_socket();
        let buffer_address = context.buffer.as_ptr();
        context
            .with_socket(
                || {
                    assert_local_socket_closed(fd, identity);
                    Ok(replacement)
                },
                |socket, buffer| {
                    assert_eq!(buffer.as_ptr(), buffer_address);
                    assert_eq!(socket.next_sequence()?, 1);
                    Ok(())
                },
            )
            .unwrap();
        let socket = context.socket.as_mut().unwrap();
        socket.sequence = u32::MAX;
        assert!(socket.next_sequence().is_err());
        assert_eq!(socket.sequence, u32::MAX);
    }

    #[test]
    fn opening_failure_does_not_allocate_buffer_or_run_collection() {
        let mut context = Context::default();
        let result: Result<(), _> = context.with_socket(
            || {
                Err(CollectError::io(
                    "open",
                    io::Error::from_raw_os_error(libc::EMFILE),
                ))
            },
            |_, _| panic!("collection ran without a socket"),
        );
        assert_eq!(result.unwrap_err().errno, Some(libc::EMFILE));
        assert!(context.socket.is_none());
        assert!(context.buffer.is_empty());
    }

    fn stats_message(ifindex: i32, values: &[u64]) -> Vec<u8> {
        let mut payload = vec![0; IFSTATS_MESSAGE_LEN];
        put_u32(&mut payload[4..8], ifindex as u32);
        put_u32(&mut payload[8..12], 1);
        let values: Vec<_> = values
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect();
        push_attribute(&mut payload, 1, &values);
        message(RTM_NEWSTATS, 0, REQUEST_SEQUENCE, &payload)
    }

    fn parse_mode(
        mut datagram: Vec<u8>,
        mode: DumpMode,
    ) -> Result<Vec<LinkCounters>, CollectError> {
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));
        let mut parser = DumpParser::new(None);
        parser.mode = mode;
        parser.parse_datagram(&datagram, REQUEST_SEQUENCE, 0)?;
        parser.finish()
    }

    fn shared_parser(datagram: &[u8]) -> Result<DumpParser<'static>, CollectError> {
        let mut parser = DumpParser::new(None);
        parser.mode = DumpMode::Metadata;
        parser.inventory = Some(Vec::new());
        parser.parse_datagram(datagram, REQUEST_SEQUENCE, 0)?;
        Ok(parser)
    }

    #[test]
    fn shared_names_require_exactly_one_trailing_nul_and_nic_compatible_ascii() {
        for bytes in [
            b"eth0".as_slice(),
            b"eth0\0\0",
            b"eth\0x\0",
            b"eth0\0x",
            b"\xff\0",
            b"abcdefghijklmnop\0",
        ] {
            assert!(parse_interface_name(bytes).is_err(), "accepted {bytes:?}");
        }
        assert_eq!(parse_interface_name(b"eth0\0").unwrap(), "eth0");
        for name in [
            "eth0",
            "eth.1",
            "eth:1",
            ".",
            "..",
            "eth/0",
            "eth 0",
            "eth\t0",
            "eth\u{e9}",
        ] {
            let mut datagram = link_message(REQUEST_SEQUENCE, 2, name, None, None, None);
            datagram.extend(done_message(REQUEST_SEQUENCE, 0));
            let parser = shared_parser(&datagram).unwrap();
            assert_eq!(
                parser.inventory.is_some(),
                valid_interface_name(name),
                "{name:?}"
            );
            // Inventory restrictions must not change public counter parsing.
            assert_eq!(parser.finish().unwrap()[0].interface, name);
        }
    }

    #[test]
    fn shared_final_metadata_preserves_fields_and_counter_projection() {
        for (operstate, tx_queue_len, mtu) in
            [(None, None, None), (Some(6), Some(1000), Some(9000))]
        {
            let before_bytes = link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, Some(3));
            let before = parse_mode(before_bytes.clone(), DumpMode::Metadata).unwrap();
            let mut payload = before_bytes[NLMSG_HEADER_LEN..].to_vec();
            if let Some(value) = operstate {
                push_attribute(&mut payload, IFLA_OPERSTATE, &[value]);
            }
            if let Some(value) = tx_queue_len {
                push_attribute(&mut payload, IFLA_TXQLEN, &u32::to_ne_bytes(value));
            }
            if let Some(value) = mtu {
                push_attribute(&mut payload, IFLA_MTU, &u32::to_ne_bytes(value));
            }
            let final_message = message(RTM_NEWLINK, 0, REQUEST_SEQUENCE, &payload);
            let mut datagram = final_message.clone();
            datagram.extend(done_message(REQUEST_SEQUENCE, 0));
            let started_at = Instant::now();
            let statistics =
                || parse_mode(stats_message(2, &[42; 25]), DumpMode::Statistics).unwrap();
            let (counters, metadata) = finish_shared_dump(
                shared_parser(&datagram).unwrap(),
                &before,
                statistics(),
                None,
                started_at,
            )
            .unwrap();
            let metadata = metadata.unwrap();
            assert_eq!(metadata.started_at, started_at);
            assert_eq!(
                metadata.links,
                vec![LinkMetadata {
                    ifindex: 2,
                    name: "eth0".to_owned(),
                    operstate,
                    tx_queue_len,
                    mtu,
                }]
            );
            let independent = parse_mode(final_message, DumpMode::Metadata).unwrap();
            assert_eq!(
                link_metrics(counters),
                link_metrics(join_dumps(independent, statistics(), None).unwrap())
            );
        }
    }

    #[test]
    fn invalid_inventory_only_attributes_disable_sharing_without_losing_counters() {
        let cases = [
            vec![(IFLA_OPERSTATE, vec![])],
            vec![(IFLA_OPERSTATE, vec![6, 6])],
            vec![(IFLA_TXQLEN, vec![0; 3])],
            vec![(IFLA_MTU, vec![0; 3])],
            vec![(IFLA_OPERSTATE, vec![6]), (IFLA_OPERSTATE, vec![6])],
            vec![(IFLA_TXQLEN, vec![0; 4]), (IFLA_TXQLEN, vec![0; 4])],
            vec![(IFLA_MTU, vec![0; 4]), (IFLA_MTU, vec![0; 4])],
            vec![(IFLA_OPERSTATE | 0x4000, vec![6])],
        ];
        for attributes in cases {
            let base = link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, None);
            let mut payload = base[NLMSG_HEADER_LEN..].to_vec();
            for (kind, value) in attributes {
                push_attribute(&mut payload, kind, &value);
            }
            let mut datagram = message(RTM_NEWLINK, 0, REQUEST_SEQUENCE, &payload);
            datagram.extend(done_message(REQUEST_SEQUENCE, 0));
            let parser = shared_parser(&datagram).unwrap();
            assert!(parser.inventory.is_none());
            let mut ordinary = DumpParser::new(None);
            ordinary.mode = DumpMode::Metadata;
            ordinary
                .parse_datagram(&datagram, REQUEST_SEQUENCE, 0)
                .unwrap();
            assert_eq!(
                link_metrics(parser.finish().unwrap()),
                link_metrics(ordinary.finish().unwrap())
            );
        }
    }

    #[test]
    fn shared_dump_requires_completion_and_coherent_bracketing_identities() {
        let before = parse_mode(
            link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, None),
            DumpMode::Metadata,
        )
        .unwrap();
        for (index, name, complete) in [(2, "eth0", false), (3, "eth0", true), (2, "eth1", true)] {
            let mut datagram = link_message(REQUEST_SEQUENCE, index, name, None, None, None);
            if complete {
                datagram.extend(done_message(REQUEST_SEQUENCE, 0));
            }
            assert!(finish_shared_dump(
                shared_parser(&datagram).unwrap(),
                &before,
                parse_mode(stats_message(2, &[42; 25]), DumpMode::Statistics).unwrap(),
                None,
                Instant::now()
            )
            .is_err());
        }
        let mut datagram = link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, None);
        datagram.extend(done_message(REQUEST_SEQUENCE, NLM_F_DUMP_INTR));
        assert!(shared_parser(&datagram).is_err());
    }

    #[test]
    fn shared_inventory_budget_falls_back_without_truncating_counter_inventory() {
        let mut parser = DumpParser::new(None);
        parser.mode = DumpMode::Metadata;
        parser.inventory = Some(Vec::new());
        for index in 1..=MAX_SHARED_LINKS + 1 {
            parser
                .parse_datagram(
                    &link_message(
                        REQUEST_SEQUENCE,
                        index as i32,
                        &format!("eth{index}"),
                        None,
                        None,
                        None,
                    ),
                    REQUEST_SEQUENCE,
                    0,
                )
                .unwrap();
        }
        parser
            .parse_datagram(&done_message(REQUEST_SEQUENCE, 0), REQUEST_SEQUENCE, 0)
            .unwrap();
        assert!(parser.inventory.is_none());
        assert_eq!(parser.finish().unwrap().len(), MAX_SHARED_LINKS + 1);
    }

    #[test]
    fn targeted_stats_join_preserves_all_fields_and_carrier_width() {
        for fields in [24, 25] {
            let values: Vec<_> = (1..=fields).collect();
            let stats = parse_mode(stats_message(2, &values), DumpMode::Statistics).unwrap();
            let metadata = parse_mode(
                link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, Some(7)),
                DumpMode::Metadata,
            )
            .unwrap();
            let actual = link_metrics(join_dumps(metadata, stats, None).unwrap());
            let mut expected =
                link_message(REQUEST_SEQUENCE, 2, "eth0", Some(&values), None, Some(7));
            expected.extend(done_message(REQUEST_SEQUENCE, 0));
            assert_eq!(actual, parse_fixture(&expected, None).unwrap());
            assert_eq!(actual.len(), fields as usize + 1);
        }
    }

    #[test]
    fn targeted_stats_rejects_duplicates_truncation_loss_and_incoherent_joins() {
        let values = vec![42; 25];
        let mut duplicate = stats_message(2, &values);
        duplicate.extend(stats_message(2, &values));
        assert_eq!(
            parse_mode(duplicate, DumpMode::Statistics)
                .unwrap_err()
                .parse_errors(),
            1
        );
        assert_eq!(
            parse_mode(stats_message(2, &[1; 23]), DumpMode::Statistics)
                .unwrap_err()
                .parse_errors(),
            1
        );
        assert_eq!(
            parse_mode(stats_message(0, &values), DumpMode::Statistics)
                .unwrap_err()
                .parse_errors(),
            1
        );
        let mut interrupted = stats_message(2, &values);
        put_u16(&mut interrupted[6..8], NLM_F_DUMP_INTR);
        assert_eq!(
            parse_mode(interrupted, DumpMode::Statistics)
                .unwrap_err()
                .dumps_interrupted(),
            1
        );
        assert_eq!(
            parse_mode(
                message(NLMSG_OVERRUN, 0, REQUEST_SEQUENCE, &[]),
                DumpMode::Statistics
            )
            .unwrap_err()
            .loss_events(),
            1
        );
        let metadata = parse_mode(
            link_message(REQUEST_SEQUENCE, 3, "eth0", None, None, None),
            DumpMode::Metadata,
        )
        .unwrap();
        let stats = parse_mode(stats_message(2, &values), DumpMode::Statistics).unwrap();
        assert_eq!(
            join_dumps(metadata, stats, None)
                .unwrap_err()
                .dumps_interrupted(),
            1
        );
        let stats = parse_mode(stats_message(2, &values), DumpMode::Statistics).unwrap();
        assert_eq!(
            join_dumps(Vec::new(), stats, None)
                .unwrap_err()
                .dumps_interrupted(),
            1
        );
    }

    #[test]
    fn bracketing_metadata_rejects_rename_or_replacement_with_same_index() {
        let before = parse_mode(
            link_message(REQUEST_SEQUENCE, 2, "eth0", None, None, None),
            DumpMode::Metadata,
        )
        .unwrap();
        let renamed = parse_mode(
            link_message(REQUEST_SEQUENCE, 2, "eth1", None, None, None),
            DumpMode::Metadata,
        )
        .unwrap();
        assert_eq!(
            verify_metadata_identities(&before, &renamed)
                .unwrap_err()
                .dumps_interrupted(),
            1
        );
        let replaced = parse_mode(
            link_message(REQUEST_SEQUENCE, 3, "eth0", None, None, None),
            DumpMode::Metadata,
        )
        .unwrap();
        assert_eq!(
            verify_metadata_identities(&before, &replaced)
                .unwrap_err()
                .dumps_interrupted(),
            1
        );
        verify_metadata_identities(&before, &before).unwrap();
    }

    #[test]
    fn fallback_is_limited_to_explicit_unsupported_kernel_errors() {
        let mut payload = vec![0; size_of::<i32>() + NLMSG_HEADER_LEN];
        for code in [libc::EOPNOTSUPP, libc::EPERM, libc::EINVAL, libc::ENOBUFS] {
            payload[..4].copy_from_slice(&(-code).to_ne_bytes());
            let error = parse_mode(
                message(NLMSG_ERROR, 0, REQUEST_SEQUENCE, &payload),
                DumpMode::Statistics,
            )
            .unwrap_err();
            assert_eq!(
                error.errno == Some(libc::EOPNOTSUPP),
                code == libc::EOPNOTSUPP
            );
        }
        assert_eq!(CollectError::loss("lost").errno, None);
        assert_eq!(CollectError::parse("bad").errno, None);
        assert_eq!(CollectError::interrupted("churn").errno, None);
    }

    #[test]
    #[ignore = "read-only targeted/full dump value-bounds validation on live hardware"]
    fn live_targeted_stats_preserve_all_fields_with_bounded_values() {
        let describe = |links: Vec<LinkCounters>| {
            links
                .into_iter()
                .map(|link| {
                    let values = link
                        .counters()
                        .map(|(name, value, bits)| (name, (value, bits)))
                        .collect::<BTreeMap<_, _>>();
                    ((link.ifindex, link.interface), values)
                })
                .collect::<BTreeMap<_, _>>()
        };
        for _ in 0..3 {
            let before = describe(collect_legacy_counters(None).unwrap());
            let actual = describe(collect_targeted_counters(None).unwrap());
            let after = describe(collect_legacy_counters(None).unwrap());
            assert_eq!(
                before.keys().collect::<Vec<_>>(),
                actual.keys().collect::<Vec<_>>()
            );
            assert_eq!(
                after.keys().collect::<Vec<_>>(),
                actual.keys().collect::<Vec<_>>()
            );
            let mut count = 0;
            for (identity, fields) in &actual {
                let lower = &before[identity];
                let upper = &after[identity];
                assert_eq!(
                    fields.keys().collect::<Vec<_>>(),
                    lower.keys().collect::<Vec<_>>()
                );
                assert_eq!(
                    fields.keys().collect::<Vec<_>>(),
                    upper.keys().collect::<Vec<_>>()
                );
                for (name, (value, bits)) in fields {
                    assert_eq!(*bits, lower[name].1, "width: {identity:?} {name}");
                    assert_eq!(*bits, upper[name].1, "width: {identity:?} {name}");
                    assert!(
                        lower[name].0 <= *value && *value <= upper[name].0,
                        "value/reset: {identity:?} {name}: {} <= {} <= {}",
                        lower[name].0,
                        value,
                        upper[name].0
                    );
                    count += 1;
                }
            }
            eprintln!("targeted GETSTATS: {} interfaces, {count} fields, all widths and value bounds match", actual.len());
        }
    }

    #[test]
    #[ignore = "manual read-only persistent/independent parity over 120 polls; requires stable identities and no counter resets"]
    fn live_context_matches_independent_fields_and_metadata_over_120_polls() {
        let describe_metadata = |metadata: FreshLinkMetadata| {
            metadata
                .links
                .into_iter()
                .map(|link| {
                    (
                        (link.ifindex, link.name),
                        (link.operstate, link.tx_queue_len, link.mtu),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let mut context = Context::default();
        let mut retained_resources = None;
        let mut fields_checked = 0;
        for poll in 0..120_u32 {
            let (before, before_metadata) = collect_link_counters_with_metadata(true).unwrap();
            let share_metadata = poll % 2 == 0;
            let (actual, metadata) = context.collect(share_metadata).unwrap();
            let (after, after_metadata) = collect_link_counters_with_metadata(true).unwrap();
            let before = link_metrics(before);
            let actual = link_metrics(actual);
            let after = link_metrics(after);
            assert!(!actual.is_empty());
            assert_eq!(actual.len(), before.len());
            assert_eq!(actual.len(), after.len());
            for ((lower, actual), upper) in before.iter().zip(&actual).zip(&after) {
                // Canonical keys include identity, field name and counter width.
                assert_eq!(actual.key, lower.key, "field/schema at poll {poll}");
                assert_eq!(actual.key, upper.key, "field/schema at poll {poll}");
                assert!(
                    lower.value <= actual.value && actual.value <= upper.value,
                    "value/reset at poll {poll}: {:?}: {} <= {} <= {}",
                    actual.key,
                    lower.value,
                    actual.value,
                    upper.value
                );
            }
            fields_checked += actual.len();
            if share_metadata {
                let metadata = metadata.expect("current-cycle metadata");
                let before_metadata = before_metadata.unwrap();
                let after_metadata = after_metadata.unwrap();
                assert!(before_metadata.started_at <= metadata.started_at);
                assert!(metadata.started_at <= after_metadata.started_at);
                let metadata = describe_metadata(metadata);
                assert_eq!(
                    metadata,
                    describe_metadata(before_metadata),
                    "metadata at poll {poll}"
                );
                assert_eq!(
                    metadata,
                    describe_metadata(after_metadata),
                    "metadata at poll {poll}"
                );
            } else {
                assert!(
                    metadata.is_none(),
                    "metadata retained from a previous cycle"
                );
            }
            let socket = context.socket.as_ref().unwrap();
            let resources = (
                socket.fd.as_raw_fd(),
                socket.port_id,
                context.buffer.as_ptr(),
            );
            if let Some(expected) = retained_resources {
                assert_eq!(resources, expected, "resources replaced at poll {poll}");
            } else {
                retained_resources = Some(resources);
            }
            assert_eq!(context.sequence, (poll + 1) * 3);
            let mut timeout = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let mut length = size_of::<libc::timeval>() as libc::socklen_t;
            // SAFETY: the live socket and writable timeval/length remain valid.
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        socket.fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        std::ptr::from_mut(&mut timeout).cast(),
                        &mut length,
                    )
                },
                0
            );
            assert_eq!(length as usize, size_of::<libc::timeval>());
            assert_eq!((timeout.tv_sec, timeout.tv_usec), (2, 0));
        }
        eprintln!("persistent rtnetlink: 120 polls, {fields_checked} counter fields/widths/value bounds matched; fresh metadata matched, socket/buffer reused, receive timeout unchanged");
    }

    #[test]
    fn parses_stats64_and_prefers_it_over_stats32() {
        let mut datagram = link_message(
            REQUEST_SEQUENCE,
            7,
            "eth0",
            Some(&(100_u64..125).collect::<Vec<_>>()),
            Some(&(1_u32..25).collect::<Vec<_>>()),
            None,
        );
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));

        let metrics = parse_fixture(&datagram, Some("eth0")).unwrap();

        assert_eq!(metrics.len(), 25);
        let rx_packets = metrics
            .iter()
            .find(|sample| sample.key.metric == "rx_packets")
            .unwrap();
        assert_eq!(rx_packets.value, 100);
        assert_eq!(rx_packets.key.labels["counter_bits"], "64");
        assert_eq!(rx_packets.key.labels["ifindex"], "7");
        assert_eq!(rx_packets.key.labels["interface"], "eth0");
        assert_eq!(
            metrics
                .iter()
                .find(|sample| sample.key.metric == "rx_otherhost_dropped")
                .unwrap()
                .value,
            124
        );
    }

    #[test]
    fn accepts_linux_4_14_stats64_prefix_and_filters_interfaces() {
        let first_stats: Vec<_> = (10_u64..34).collect();
        let second_stats: Vec<_> = (100_u64..124).collect();
        let mut datagram = link_message(REQUEST_SEQUENCE, 1, "lo", Some(&first_stats), None, None);
        datagram.extend(link_message(
            REQUEST_SEQUENCE,
            2,
            "eth0",
            Some(&second_stats),
            None,
            None,
        ));
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));

        let metrics = parse_fixture(&datagram, Some("eth0")).unwrap();

        assert_eq!(metrics.len(), 24);
        assert!(metrics
            .iter()
            .all(|sample| sample.key.labels["interface"] == "eth0"));
        assert!(!metrics
            .iter()
            .any(|sample| sample.key.metric == "rx_otherhost_dropped"));
    }

    #[test]
    fn falls_back_to_32_bit_link_statistics() {
        let stats: Vec<_> = (1_u32..25).collect();
        let mut datagram = link_message(REQUEST_SEQUENCE, 3, "veth0", None, Some(&stats), None);
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));

        let metrics = parse_fixture(&datagram, None).unwrap();

        assert_eq!(metrics.len(), 24);
        assert_eq!(metrics[0].key.source, "rtnetlink_link_stats");
        assert_eq!(metrics[0].key.labels["counter_bits"], "32");
        assert!(metrics.iter().any(|sample| sample.value == 24));
    }

    #[test]
    fn parses_carrier_changes_as_an_independent_32_bit_counter() {
        let stats: Vec<_> = (100_u64..124).collect();
        let mut datagram = link_message(REQUEST_SEQUENCE, 3, "eth0", Some(&stats), None, Some(7));
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));

        let metrics = parse_fixture(&datagram, Some("eth0")).unwrap();
        let carrier_changes = metrics
            .iter()
            .find(|sample| sample.key.metric == "carrier_changes")
            .unwrap();

        assert_eq!(metrics.len(), 25);
        assert_eq!(carrier_changes.value, 7);
        assert_eq!(carrier_changes.key.labels["counter_bits"], "32");
        assert_eq!(carrier_changes.key.labels["ifindex"], "3");
        assert_eq!(carrier_changes.key.labels["interface"], "eth0");
        assert_eq!(
            metrics
                .iter()
                .find(|sample| sample.key.metric == "tx_carrier_errors")
                .unwrap()
                .value,
            117
        );
    }

    #[test]
    fn every_emitted_link_metric_has_one_catalog_owner() {
        for raw_metric in LINK_STAT_NAMES
            .iter()
            .copied()
            .chain(std::iter::once("carrier_changes"))
        {
            let owners = crate::monitor::metric_catalog()
                .iter()
                .filter(|descriptor| {
                    descriptor.sources.iter().any(|source| {
                        source.provider == "linux.rtnetlink.link_stats"
                            && source.raw_metric == raw_metric
                    })
                })
                .count();
            assert_eq!(owners, 1, "rtnetlink field {raw_metric}");
        }
    }

    #[test]
    fn rejects_truncated_attributes_as_parse_errors() {
        let mut datagram = link_message(
            REQUEST_SEQUENCE,
            3,
            "eth0",
            Some(&(1_u64..25).collect::<Vec<_>>()),
            None,
            None,
        );
        let attribute_offset = NLMSG_HEADER_LEN + IFINFO_MESSAGE_LEN;
        put_u16(
            &mut datagram[attribute_offset..attribute_offset + 2],
            u16::MAX,
        );

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.parse_errors(), 1);
        assert_eq!(error.loss_events(), 0);
        assert_eq!(error.dumps_interrupted(), 0);
        assert!(error.to_string().contains("attribute length"));
    }

    #[test]
    fn treats_interrupted_dump_as_observation_loss() {
        let datagram = done_message(REQUEST_SEQUENCE, NLM_F_DUMP_INTR);

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.loss_events(), 0);
        assert_eq!(error.dumps_interrupted(), 1);
        assert_eq!(error.parse_errors(), 0);
        assert!(error.to_string().contains("interrupted"));
    }

    #[test]
    fn counts_netlink_overrun_as_a_loss_event() {
        let datagram = message(NLMSG_OVERRUN, 0, REQUEST_SEQUENCE, &[]);

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.loss_events(), 1);
        assert_eq!(error.dumps_interrupted(), 0);
        assert_eq!(error.parse_errors(), 0);
        assert!(error.to_string().contains("overrun"));
    }

    #[test]
    fn reports_kernel_netlink_errno_without_counting_parse_or_loss() {
        let mut payload = vec![0_u8; size_of::<i32>() + NLMSG_HEADER_LEN];
        payload[..size_of::<i32>()].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        let datagram = message(NLMSG_ERROR, 0, REQUEST_SEQUENCE, &payload);

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.loss_events(), 0);
        assert_eq!(error.dumps_interrupted(), 0);
        assert_eq!(error.parse_errors(), 0);
        assert!(error.to_string().contains("Operation not permitted"));
    }

    #[test]
    fn rejects_wrong_sequence() {
        let datagram = done_message(REQUEST_SEQUENCE + 1, 0);

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.parse_errors(), 1);
        assert!(error.to_string().contains("sequence"));
    }

    #[test]
    fn redacts_netlink_port_ids_from_parser_errors() {
        const PRIVATE_PORT_ID: u32 = 0x1234;
        let mut datagram = done_message(REQUEST_SEQUENCE, 0);
        put_u32(&mut datagram[12..16], PRIVATE_PORT_ID);
        let mut parser = DumpParser::new(None);

        let error = parser
            .parse_datagram(&datagram, REQUEST_SEQUENCE, 0)
            .unwrap_err();
        let message = error.to_string();

        assert_eq!(error.parse_errors(), 1);
        assert!(message.contains("destination"));
        assert!(!message.contains(&PRIVATE_PORT_ID.to_string()));
    }

    #[test]
    fn rejects_duplicate_interfaces_before_metric_keys_can_collide() {
        let stats: Vec<_> = (1_u64..25).collect();
        let mut datagram = link_message(REQUEST_SEQUENCE, 2, "eth0", Some(&stats), None, None);
        datagram.extend(link_message(
            REQUEST_SEQUENCE,
            2,
            "eth0",
            Some(&stats),
            None,
            None,
        ));
        datagram.extend(done_message(REQUEST_SEQUENCE, 0));

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.parse_errors(), 1);
        assert!(error.to_string().contains("duplicate ifindex"));
    }

    #[test]
    fn rejects_non_utf8_interface_names() {
        let stats: Vec<_> = (1_u64..25).collect();
        let mut payload = vec![0_u8; IFINFO_MESSAGE_LEN];
        payload[4..8].copy_from_slice(&2_i32.to_ne_bytes());
        push_attribute(&mut payload, IFLA_IFNAME, &[0xff, 0]);
        let value: Vec<_> = stats.iter().flat_map(|value| value.to_ne_bytes()).collect();
        push_attribute(&mut payload, IFLA_STATS64, &value);
        let datagram = message(RTM_NEWLINK, 0, REQUEST_SEQUENCE, &payload);

        let error = parse_fixture(&datagram, None).unwrap_err();

        assert_eq!(error.parse_errors(), 1);
        assert!(error.to_string().contains("UTF-8"));
    }

    #[test]
    fn collects_loopback_from_the_running_network_namespace() {
        let metrics = collect_link_stats(Some("lo")).unwrap();

        assert!(metrics.iter().any(|sample| {
            sample.key.metric == "rx_packets"
                && sample.key.labels.get("interface").map(String::as_str) == Some("lo")
                && sample.key.labels.contains_key("ifindex")
        }));
    }

    fn parse_fixture(
        datagram: &[u8],
        interface: Option<&str>,
    ) -> Result<Vec<MetricSample>, CollectError> {
        let mut parser = DumpParser::new(interface);
        parser.parse_datagram(datagram, REQUEST_SEQUENCE, 0)?;
        parser.finish().map(link_metrics)
    }

    fn link_message(
        sequence: u32,
        ifindex: i32,
        name: &str,
        stats64: Option<&[u64]>,
        stats32: Option<&[u32]>,
        carrier_changes: Option<u32>,
    ) -> Vec<u8> {
        let mut payload = vec![0_u8; IFINFO_MESSAGE_LEN];
        payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        push_attribute(&mut payload, IFLA_IFNAME, &[name.as_bytes(), &[0]].concat());
        if let Some(stats) = stats32 {
            let value: Vec<_> = stats.iter().flat_map(|value| value.to_ne_bytes()).collect();
            push_attribute(&mut payload, IFLA_STATS, &value);
        }
        if let Some(stats) = stats64 {
            let value: Vec<_> = stats.iter().flat_map(|value| value.to_ne_bytes()).collect();
            push_attribute(&mut payload, IFLA_STATS64, &value);
        }
        if let Some(value) = carrier_changes {
            push_attribute(&mut payload, IFLA_CARRIER_CHANGES, &value.to_ne_bytes());
        }
        message(RTM_NEWLINK, 0, sequence, &payload)
    }

    fn done_message(sequence: u32, flags: u16) -> Vec<u8> {
        message(NLMSG_DONE, flags, sequence, &[])
    }

    fn message(message_type: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let message_len = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = vec![0_u8; align(message_len)];
        put_u32(&mut bytes[0..4], message_len as u32);
        put_u16(&mut bytes[4..6], message_type);
        put_u16(&mut bytes[6..8], flags);
        put_u32(&mut bytes[8..12], sequence);
        bytes[NLMSG_HEADER_LEN..message_len].copy_from_slice(payload);
        bytes
    }

    fn push_attribute(payload: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
        let attribute_len = RTATTR_HEADER_LEN + value.len();
        let offset = payload.len();
        payload.resize(offset + align(attribute_len), 0);
        put_u16(&mut payload[offset..offset + 2], attribute_len as u16);
        put_u16(&mut payload[offset + 2..offset + 4], attribute_type);
        payload[offset + RTATTR_HEADER_LEN..offset + attribute_len].copy_from_slice(value);
    }
}
