use std::ffi::CStr;
use std::fmt;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

const ALIGNMENT: usize = 4;
const NLMSG_HEADER_LEN: usize = 16;
const ROUTE_MESSAGE_LEN: usize = 12;
const RULE_MESSAGE_LEN: usize = 12;
const NEIGHBOUR_MESSAGE_LEN: usize = 12;
const RTATTR_HEADER_LEN: usize = 4;
const RTNEXTHOP_LEN: usize = 8;
const RTNH_F_PERVASIVE: u8 = 0x02;
const RTNH_F_ONLINK: u8 = 0x04;

const MAX_RETAINED_ROUTES: usize = 4_096;
const MAX_RETAINED_RULES: usize = 1_024;
const MAX_RETAINED_NEIGHBOURS: usize = 4_096;
const MAX_NEXTHOPS_PER_ROUTE: usize = 256;
const MAX_RETAINED_NEXTHOPS: usize = 16_384;
const MAX_SCANNED_MESSAGES: usize = 65_536;
const MAX_SCANNED_BYTES: usize = 64 * 1024 * 1024;
const RECEIVE_BUFFER_LEN: usize = 1024 * 1024;
const MAX_LINK_ADDRESS_LEN: usize = 32;
// Linux glibc and musl use selector 2 for _SC_CLK_TCK. libc does not expose
// the symbolic constant on every supported target.
const SYSCONF_CLK_TCK: libc::c_int = 2;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_MULTI: u16 = 0x02;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const RTM_NEWRULE: u16 = 32;
const RTM_GETRULE: u16 = 34;
const RTM_F_LOOKUP_TABLE: u32 = 0x1000;

const RTA_DST: u16 = 1;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_PREFSRC: u16 = 7;
const RTA_METRICS: u16 = 8;
const RTA_MULTIPATH: u16 = 9;
const RTA_CACHEINFO: u16 = 12;
const RTA_TABLE: u16 = 15;
const RTA_MARK: u16 = 16;
const RTA_VIA: u16 = 18;
const RTA_ENCAP_TYPE: u16 = 21;
const RTA_ENCAP: u16 = 22;
const RTA_EXPIRES: u16 = 23;
const RTA_UID: u16 = 25;

const RTAX_MTU: u16 = 2;
const RTAX_ADVMSS: u16 = 8;
const RTAX_HOPLIMIT: u16 = 10;
const RTAX_INITCWND: u16 = 11;
const RTAX_INITRWND: u16 = 14;

const FRA_DST: u16 = 1;
const FRA_SRC: u16 = 2;
const FRA_IIFNAME: u16 = 3;
const FRA_GOTO: u16 = 4;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FLOW: u16 = 11;
const FRA_TUN_ID: u16 = 12;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_OIFNAME: u16 = 17;
const FRA_L3MDEV: u16 = 19;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;

const NLA_TYPE_MASK: u16 = 0x3fff;

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    const fn address_len(self) -> usize {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
        }
    }

    const fn prefix_bits(self) -> u8 {
        match self {
            Self::Ipv4 => 32,
            Self::Ipv6 => 128,
        }
    }

    const fn netlink_value(self) -> u8 {
        match self {
            Self::Ipv4 => libc::AF_INET as u8,
            Self::Ipv6 => libc::AF_INET6 as u8,
        }
    }

    fn from_netlink(value: u16) -> Result<Self, CollectError> {
        match i32::from(value) {
            libc::AF_INET => Ok(Self::Ipv4),
            libc::AF_INET6 => Ok(Self::Ipv6),
            _ => Err(CollectError::parse("unsupported IP address family")),
        }
    }

    const fn unspecified(self) -> IpAddr {
        match self {
            Self::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }

    const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Dump<T> {
    pub(crate) rows: Vec<T>,
    pub(crate) observed_rows: usize,
    pub(crate) truncated: bool,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IpPrefix {
    pub(crate) address: IpAddr,
    pub(crate) prefix_len: u8,
}

impl fmt::Debug for IpPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpPrefix")
            .field("address", &"<redacted>")
            .field("prefix_len", &self.prefix_len)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RouteMetrics {
    pub(crate) mtu: Option<u32>,
    pub(crate) advmss: Option<u32>,
    pub(crate) hoplimit: Option<u32>,
    pub(crate) initcwnd: Option<u32>,
    pub(crate) initrwnd: Option<u32>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RouteCacheInfo {
    pub(crate) client_references: u32,
    pub(crate) last_use: Duration,
    pub(crate) expires: Option<Duration>,
    pub(crate) error: i32,
    pub(crate) used: u32,
    pub(crate) id: u32,
    pub(crate) timestamp_ticks: u32,
    pub(crate) timestamp_age: Duration,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RouteNexthop {
    pub(crate) ifindex: Option<u32>,
    pub(crate) interface: Option<String>,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) via: Option<IpAddr>,
    pub(crate) weight: u16,
    pub(crate) flags: u8,
}

impl RouteNexthop {
    pub(crate) const fn configuration_flags(&self) -> u8 {
        self.flags & (RTNH_F_PERVASIVE | RTNH_F_ONLINK)
    }
}

impl fmt::Debug for RouteNexthop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteNexthop")
            .field("ifindex", &self.ifindex)
            .field("interface", &self.interface)
            .field("gateway", &self.gateway.map(|_| "<redacted>"))
            .field("via", &self.via.map(|_| "<redacted>"))
            .field("weight", &self.weight)
            .field("flags", &self.flags)
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RouteRow {
    pub(crate) family: IpFamily,
    pub(crate) destination: IpPrefix,
    pub(crate) source: IpPrefix,
    pub(crate) tos: u8,
    pub(crate) table: u32,
    pub(crate) priority: Option<u32>,
    pub(crate) protocol: u8,
    pub(crate) scope: u8,
    pub(crate) route_type: u8,
    pub(crate) flags: u32,
    pub(crate) preferred_source: Option<IpAddr>,
    pub(crate) nexthops: Vec<RouteNexthop>,
    pub(crate) nexthops_truncated: bool,
    pub(crate) metrics: RouteMetrics,
    pub(crate) cache: Option<RouteCacheInfo>,
    pub(crate) expires: Option<Duration>,
    pub(crate) unsupported_encapsulation: bool,
}

impl fmt::Debug for RouteRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteRow")
            .field("family", &self.family)
            .field("destination", &self.destination)
            .field("source", &self.source)
            .field("tos", &self.tos)
            .field("table", &self.table)
            .field("priority", &self.priority)
            .field("protocol", &self.protocol)
            .field("scope", &self.scope)
            .field("route_type", &self.route_type)
            .field("flags", &self.flags)
            .field(
                "preferred_source",
                &self.preferred_source.map(|_| "<redacted>"),
            )
            .field("nexthops", &self.nexthops)
            .field("nexthops_truncated", &self.nexthops_truncated)
            .field("metrics", &self.metrics)
            .field("cache", &self.cache)
            .field("expires", &self.expires)
            .field("unsupported_encapsulation", &self.unsupported_encapsulation)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuleUidRange {
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuleRow {
    pub(crate) family: IpFamily,
    pub(crate) destination: IpPrefix,
    pub(crate) source: IpPrefix,
    pub(crate) tos: u8,
    pub(crate) table: u32,
    pub(crate) action: u8,
    pub(crate) flags: u32,
    pub(crate) priority: Option<u32>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) fwmask: Option<u32>,
    pub(crate) input_interface: Option<String>,
    pub(crate) output_interface: Option<String>,
    pub(crate) goto_priority: Option<u32>,
    pub(crate) suppress_prefix_len: Option<u32>,
    pub(crate) suppress_interface_group: Option<u32>,
    pub(crate) l3mdev: Option<u8>,
    pub(crate) uid_range: Option<RuleUidRange>,
    pub(crate) tunnel_id: Option<u64>,
    pub(crate) flow: Option<u32>,
    pub(crate) protocol: Option<u8>,
}

impl fmt::Debug for RuleRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuleRow")
            .field("family", &self.family)
            .field("destination", &self.destination)
            .field("source", &self.source)
            .field("tos", &self.tos)
            .field("table", &self.table)
            .field("action", &self.action)
            .field("flags", &self.flags)
            .field("priority", &self.priority)
            .field("fwmark", &self.fwmark)
            .field("fwmask", &self.fwmask)
            .field("input_interface", &self.input_interface)
            .field("output_interface", &self.output_interface)
            .field("goto_priority", &self.goto_priority)
            .field("suppress_prefix_len", &self.suppress_prefix_len)
            .field("suppress_interface_group", &self.suppress_interface_group)
            .field("l3mdev", &self.l3mdev)
            .field("uid_range", &self.uid_range)
            .field("tunnel_id", &self.tunnel_id)
            .field("flow", &self.flow)
            .field("protocol", &self.protocol)
            .finish()
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct LinkAddress(Vec<u8>);

impl LinkAddress {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for LinkAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinkAddress")
            .field("bytes", &"<redacted>")
            .field("len", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NeighbourCacheInfo {
    pub(crate) confirmed_age: Duration,
    pub(crate) used_age: Duration,
    pub(crate) updated_age: Duration,
    pub(crate) references: u32,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NeighbourRow {
    pub(crate) family: IpFamily,
    pub(crate) address: IpAddr,
    pub(crate) ifindex: u32,
    pub(crate) interface: Option<String>,
    pub(crate) link_address: Option<LinkAddress>,
    pub(crate) state: u16,
    pub(crate) flags: u8,
    pub(crate) neighbour_type: u8,
    pub(crate) probes: Option<u32>,
    pub(crate) cache: Option<NeighbourCacheInfo>,
}

impl fmt::Debug for NeighbourRow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NeighbourRow")
            .field("family", &self.family)
            .field("address", &"<redacted>")
            .field("ifindex", &self.ifindex)
            .field("interface", &self.interface)
            .field("link_address", &self.link_address)
            .field("state", &self.state)
            .field("flags", &self.flags)
            .field("neighbour_type", &self.neighbour_type)
            .field("probes", &self.probes)
            .field("cache", &self.cache)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RouteLookupRequest {
    pub(crate) destination: IpAddr,
    pub(crate) source: Option<IpAddr>,
    pub(crate) input_ifindex: Option<u32>,
    pub(crate) output_ifindex: Option<u32>,
    pub(crate) mark: Option<u32>,
    pub(crate) uid: Option<u32>,
    pub(crate) tos: Option<u8>,
}

impl fmt::Debug for RouteLookupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteLookupRequest")
            .field("destination", &"<redacted>")
            .field("source", &self.source.map(|_| "<redacted>"))
            .field("input_ifindex", &self.input_ifindex)
            .field("output_ifindex", &self.output_ifindex)
            .field("mark", &self.mark)
            .field("uid", &self.uid)
            .field("tos", &self.tos)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectErrorKind {
    InvalidRequest,
    PermissionDenied,
    Unsupported,
    NotFound,
    Io,
    Timeout,
    Loss,
    Interrupted,
    Parse,
    OutputLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectError {
    kind: CollectErrorKind,
    message: String,
}

impl CollectError {
    fn new(kind: CollectErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn io(context: &str, error: io::Error) -> Self {
        let kind = match error.raw_os_error() {
            Some(libc::EACCES | libc::EPERM) => CollectErrorKind::PermissionDenied,
            Some(libc::EAFNOSUPPORT | libc::EOPNOTSUPP) => CollectErrorKind::Unsupported,
            Some(libc::ESRCH | libc::ENOENT | libc::ENETUNREACH) => CollectErrorKind::NotFound,
            _ if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
            {
                CollectErrorKind::Timeout
            }
            _ => CollectErrorKind::Io,
        };
        Self::new(kind, format!("{context}: {error}"))
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::InvalidRequest, message)
    }

    fn parse(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::Parse, message)
    }

    fn loss(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::Loss, message)
    }

    fn interrupted(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::Interrupted, message)
    }

    fn output_limit(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::OutputLimit, message)
    }

    pub(crate) const fn kind(&self) -> CollectErrorKind {
        self.kind
    }

    #[cfg(test)]
    pub(crate) fn test_error(kind: CollectErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, message)
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub(crate) fn collect_routes(family: IpFamily) -> Result<Dump<RouteRow>, CollectError> {
    let ticks_per_second = clock_ticks_per_second()?;
    let mut retention = RouteRetention::default();
    let mut dump = collect_dump(
        family,
        RTM_GETROUTE,
        RTM_NEWROUTE,
        MAX_RETAINED_ROUTES,
        |payload| parse_route(payload, family, ticks_per_second),
        |row: &mut RouteRow| retention.adjust(row),
    )?;
    dump.rows.sort();
    Ok(dump)
}

#[derive(Default)]
struct RouteRetention {
    retained_nexthops: usize,
}

impl RouteRetention {
    fn adjust(&mut self, row: &mut RouteRow) -> bool {
        let available = MAX_RETAINED_NEXTHOPS.saturating_sub(self.retained_nexthops);
        if row.nexthops.len() > available {
            row.nexthops.truncate(available);
            row.nexthops_truncated = true;
        }
        self.retained_nexthops = self.retained_nexthops.saturating_add(row.nexthops.len());
        row.nexthops_truncated
    }
}

pub(crate) fn collect_rules(family: IpFamily) -> Result<Dump<RuleRow>, CollectError> {
    let mut dump = collect_dump(
        family,
        RTM_GETRULE,
        RTM_NEWRULE,
        MAX_RETAINED_RULES,
        |payload| parse_rule(payload, family),
        |_| false,
    )?;
    dump.rows.sort();
    Ok(dump)
}

/// Returns normal neighbour entries in the current network namespace.
/// Linux requires a separate NTF_PROXY request for proxy entries.
pub(crate) fn collect_neighbours(family: IpFamily) -> Result<Dump<NeighbourRow>, CollectError> {
    let ticks_per_second = clock_ticks_per_second()?;
    let mut dump = collect_dump(
        family,
        RTM_GETNEIGH,
        RTM_NEWNEIGH,
        MAX_RETAINED_NEIGHBOURS,
        |payload| parse_neighbour(payload, family, ticks_per_second),
        |_| false,
    )?;
    dump.rows.sort();
    Ok(dump)
}

pub(crate) fn lookup_route(request: &RouteLookupRequest) -> Result<RouteRow, CollectError> {
    validate_lookup_request(request)?;
    let family = IpFamily::of(request.destination);
    let ticks_per_second = clock_ticks_per_second()?;
    let socket = RouteSocket::open()?;
    let sequence = next_sequence();
    let bytes = build_lookup_request(request, sequence, socket.port_id)?;
    send_request(&socket, &bytes, "send RTM_GETROUTE lookup")?;

    let mut decoder = MessageDecoder::new_single(sequence, socket.port_id);
    let mut route = None;
    let mut buffer = vec![0_u8; RECEIVE_BUFFER_LEN];
    while !decoder.done {
        let received = match receive_datagram(&socket, &mut buffer) {
            Ok(received) => received,
            Err(error) if error.kind() == CollectErrorKind::Timeout => {
                return Err(CollectError::interrupted(
                    "RTM_GETROUTE lookup timed out before response completion",
                ));
            }
            Err(error) => return Err(error),
        };
        decoder.parse_datagram(&buffer[..received], RTM_NEWROUTE, &mut |payload| {
            if route.is_some() {
                return Err(CollectError::parse(
                    "RTM_GETROUTE lookup returned multiple route messages",
                ));
            }
            let parsed = parse_route(payload, family, ticks_per_second)?;
            route = Some(parsed.row);
            Ok(())
        })?;
    }
    route.ok_or_else(|| {
        CollectError::new(
            CollectErrorKind::NotFound,
            "RTM_GETROUTE lookup completed without a route",
        )
    })
}

struct ParsedRow<T> {
    row: T,
    truncated: bool,
}

struct BoundedRows<T> {
    rows: Vec<T>,
    observed_rows: usize,
    truncated: bool,
    limit: usize,
}

impl<T> BoundedRows<T> {
    fn new(limit: usize) -> Self {
        Self {
            rows: Vec::with_capacity(limit.min(256)),
            observed_rows: 0,
            truncated: false,
            limit,
        }
    }

    fn observe<A>(&mut self, mut parsed: ParsedRow<T>, adjust: &mut A)
    where
        A: FnMut(&mut T) -> bool,
    {
        self.observed_rows += 1;
        self.truncated |= parsed.truncated;
        if self.rows.len() == self.limit {
            self.truncated = true;
            return;
        }
        self.truncated |= adjust(&mut parsed.row);
        self.rows.push(parsed.row);
    }

    fn finish(self) -> Dump<T> {
        Dump {
            rows: self.rows,
            observed_rows: self.observed_rows,
            truncated: self.truncated,
        }
    }
}

fn collect_dump<T, P, A>(
    family: IpFamily,
    request_type: u16,
    response_type: u16,
    retained_limit: usize,
    mut parse: P,
    mut adjust: A,
) -> Result<Dump<T>, CollectError>
where
    P: FnMut(&[u8]) -> Result<ParsedRow<T>, CollectError>,
    A: FnMut(&mut T) -> bool,
{
    let socket = RouteSocket::open()?;
    let sequence = next_sequence();
    let request = build_dump_request(request_type, family, sequence, socket.port_id);
    send_request(&socket, &request, "send rtnetlink dump request")?;

    let mut decoder = MessageDecoder::new(sequence, socket.port_id);
    let mut rows = BoundedRows::new(retained_limit);
    let mut buffer = vec![0_u8; RECEIVE_BUFFER_LEN];
    while !decoder.done {
        let received = match receive_datagram(&socket, &mut buffer) {
            Ok(received) => received,
            Err(error) if error.kind() == CollectErrorKind::Timeout => {
                return Err(CollectError::interrupted(
                    "rtnetlink dump ended without NLMSG_DONE",
                ));
            }
            Err(error) => return Err(error),
        };
        decoder.parse_datagram(&buffer[..received], response_type, &mut |payload| {
            rows.observe(parse(payload)?, &mut adjust);
            Ok(())
        })?;
    }
    decoder.require_done()?;
    Ok(rows.finish())
}

struct RouteSocket {
    fd: OwnedFd,
    port_id: u32,
}

impl RouteSocket {
    fn open() -> Result<Self, CollectError> {
        // SAFETY: socket is called with a valid Linux netlink domain/type/protocol tuple.
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
        // SAFETY: raw_fd is newly returned by socket and ownership is transferred once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: zero is a valid initialization for sockaddr_nl before fields are set.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: address points to a fully initialized sockaddr_nl of the supplied length.
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

        // SAFETY: zero is a valid initialization for the getsockname output buffer.
        let mut bound: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut bound_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: bound and bound_len are writable output buffers of the advertised size.
        let result = unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                std::ptr::from_mut(&mut bound).cast::<libc::sockaddr>(),
                &mut bound_len,
            )
        };
        if result < 0 {
            return Err(CollectError::io(
                "read NETLINK_ROUTE port ID",
                io::Error::last_os_error(),
            ));
        }
        if bound_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
            || bound.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || bound.nl_pid == 0
            || bound.nl_groups != 0
        {
            return Err(CollectError::parse(
                "NETLINK_ROUTE socket has an invalid local address",
            ));
        }

        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        // SAFETY: timeout points to a timeval with the correct length for SO_RCVTIMEO.
        let result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::from_ref(&timeout).cast(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(CollectError::io(
                "set NETLINK_ROUTE receive timeout",
                io::Error::last_os_error(),
            ));
        }

        Ok(Self {
            fd,
            port_id: bound.nl_pid,
        })
    }
}

fn next_sequence() -> u32 {
    loop {
        let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        if sequence != 0 {
            return sequence;
        }
    }
}

fn send_request(socket: &RouteSocket, request: &[u8], context: &str) -> Result<(), CollectError> {
    // SAFETY: zero is a valid initialization before setting the netlink family.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    loop {
        // SAFETY: request and kernel remain valid for the duration of sendto.
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
                    context,
                    io::Error::new(io::ErrorKind::WriteZero, "short netlink datagram write"),
                ));
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(CollectError::io(context, error));
        }
    }
}

fn receive_datagram(socket: &RouteSocket, buffer: &mut [u8]) -> Result<usize, CollectError> {
    loop {
        // SAFETY: zero is a valid initialization for recvmsg output structures.
        let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        // SAFETY: zeroed msghdr is initialized below before recvmsg reads it.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_name = std::ptr::from_mut(&mut source).cast();
        message.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        message.msg_iov = std::ptr::from_mut(&mut vector);
        message.msg_iovlen = 1;

        // SAFETY: message references writable source and buffer storage for this call.
        let received = unsafe { libc::recvmsg(socket.fd.as_raw_fd(), &mut message, 0) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(CollectError::loss(
                    "NETLINK_ROUTE receive queue overflowed; response is incomplete",
                ));
            }
            return Err(CollectError::io("receive NETLINK_ROUTE response", error));
        }
        let received = received as usize;
        if received == 0 {
            return Err(CollectError::parse(
                "NETLINK_ROUTE returned an empty datagram",
            ));
        }
        if message.msg_flags & libc::MSG_TRUNC != 0 || received > buffer.len() {
            return Err(CollectError::loss(
                "NETLINK_ROUTE datagram exceeded the receive buffer",
            ));
        }
        validate_kernel_sender(&source, message.msg_namelen)?;
        return Ok(received);
    }
}

fn validate_kernel_sender(
    source: &libc::sockaddr_nl,
    source_len: libc::socklen_t,
) -> Result<(), CollectError> {
    if source_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || source.nl_pid != 0
        || source.nl_groups != 0
    {
        Err(CollectError::parse(
            "NETLINK_ROUTE response did not originate from the kernel",
        ))
    } else {
        Ok(())
    }
}

struct MessageDecoder {
    mode: ResponseMode,
    sequence: u32,
    port_id: u32,
    messages_scanned: usize,
    bytes_scanned: usize,
    done: bool,
    multipart_response: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseMode {
    Dump,
    Single,
}

impl MessageDecoder {
    const fn new(sequence: u32, port_id: u32) -> Self {
        Self::with_mode(sequence, port_id, ResponseMode::Dump)
    }

    const fn new_single(sequence: u32, port_id: u32) -> Self {
        Self::with_mode(sequence, port_id, ResponseMode::Single)
    }

    const fn with_mode(sequence: u32, port_id: u32, mode: ResponseMode) -> Self {
        Self {
            mode,
            sequence,
            port_id,
            messages_scanned: 0,
            bytes_scanned: 0,
            done: false,
            multipart_response: false,
        }
    }

    fn parse_datagram<F>(
        &mut self,
        datagram: &[u8],
        response_type: u16,
        on_response: &mut F,
    ) -> Result<(), CollectError>
    where
        F: FnMut(&[u8]) -> Result<(), CollectError>,
    {
        self.bytes_scanned = self
            .bytes_scanned
            .checked_add(datagram.len())
            .ok_or_else(|| CollectError::output_limit("rtnetlink byte count overflowed"))?;
        if self.bytes_scanned > MAX_SCANNED_BYTES {
            return Err(CollectError::output_limit(
                "rtnetlink response exceeded the byte scan limit",
            ));
        }

        let mut offset = 0_usize;
        while offset < datagram.len() {
            if self.done {
                return Err(CollectError::parse(
                    "rtnetlink response contains data after NLMSG_DONE",
                ));
            }
            if datagram.len() - offset < NLMSG_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated netlink message header in rtnetlink response",
                ));
            }
            if self.messages_scanned == MAX_SCANNED_MESSAGES {
                return Err(CollectError::output_limit(
                    "rtnetlink response exceeded the message scan limit",
                ));
            }
            self.messages_scanned += 1;

            let header = &datagram[offset..offset + NLMSG_HEADER_LEN];
            let message_len = read_u32(&header[0..4]) as usize;
            let message_type = read_u16(&header[4..6]);
            let flags = read_u16(&header[6..8]);
            let sequence = read_u32(&header[8..12]);
            let destination_port = read_u32(&header[12..16]);
            if message_len < NLMSG_HEADER_LEN || message_len > datagram.len() - offset {
                return Err(CollectError::parse(format!(
                    "invalid netlink message length {message_len}"
                )));
            }
            if sequence != self.sequence || destination_port != self.port_id {
                return Err(CollectError::parse(
                    "unexpected netlink destination or sequence in rtnetlink response",
                ));
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(CollectError::interrupted(
                    "kernel interrupted the rtnetlink response",
                ));
            }

            let payload = &datagram[offset + NLMSG_HEADER_LEN..offset + message_len];
            match message_type {
                NLMSG_NOOP => {}
                NLMSG_ERROR => parse_netlink_error(payload)?,
                NLMSG_DONE => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(CollectError::parse(
                            "rtnetlink NLMSG_DONE response is not multipart",
                        ));
                    }
                    parse_done_error(payload)?;
                    self.done = true;
                }
                NLMSG_OVERRUN => {
                    return Err(CollectError::loss(
                        "kernel reported a NETLINK_ROUTE message overrun",
                    ));
                }
                message_type if message_type == response_type => {
                    let multipart = flags & NLM_F_MULTI != 0;
                    if self.mode == ResponseMode::Dump && !multipart {
                        return Err(CollectError::parse(
                            "rtnetlink dump response is not multipart",
                        ));
                    }
                    if self.mode == ResponseMode::Single && self.multipart_response && !multipart {
                        return Err(CollectError::parse(
                            "rtnetlink response changed multipart framing",
                        ));
                    }
                    on_response(payload)?;
                    self.multipart_response |= multipart;
                    if self.mode == ResponseMode::Single && !multipart {
                        self.done = true;
                    }
                }
                _ => {
                    return Err(CollectError::parse(format!(
                        "unexpected netlink message type {message_type} in rtnetlink response"
                    )));
                }
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

    fn require_done(&self) -> Result<(), CollectError> {
        if self.done {
            Ok(())
        } else {
            Err(CollectError::interrupted(
                "rtnetlink dump ended without NLMSG_DONE",
            ))
        }
    }
}

fn parse_netlink_error(payload: &[u8]) -> Result<(), CollectError> {
    let required = size_of::<i32>() + NLMSG_HEADER_LEN;
    if payload.len() < required {
        return Err(CollectError::parse(
            "NLMSG_ERROR payload is shorter than nlmsgerr",
        ));
    }
    let code = read_i32(&payload[..size_of::<i32>()]);
    if code == 0 {
        return Err(CollectError::parse("unexpected netlink ACK"));
    }
    if code == i32::MIN || code > 0 {
        return Err(CollectError::parse("NLMSG_ERROR contains an invalid errno"));
    }
    Err(CollectError::io(
        "kernel rejected rtnetlink request",
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
        Err(CollectError::parse(
            "NLMSG_DONE contains an invalid completion code",
        ))
    } else {
        Err(CollectError::io(
            "kernel failed rtnetlink response",
            io::Error::from_raw_os_error(-code),
        ))
    }
}

fn build_dump_request(request_type: u16, family: IpFamily, sequence: u32, port_id: u32) -> Vec<u8> {
    let mut request = vec![0_u8; NLMSG_HEADER_LEN + ROUTE_MESSAGE_LEN];
    let request_len = request.len() as u32;
    put_u32(&mut request[0..4], request_len);
    put_u16(&mut request[4..6], request_type);
    put_u16(&mut request[6..8], NLM_F_REQUEST | NLM_F_DUMP);
    put_u32(&mut request[8..12], sequence);
    put_u32(&mut request[12..16], port_id);
    request[NLMSG_HEADER_LEN] = family.netlink_value();
    request
}

fn validate_lookup_request(request: &RouteLookupRequest) -> Result<(), CollectError> {
    let family = IpFamily::of(request.destination);
    if request
        .source
        .is_some_and(|source| IpFamily::of(source) != family)
    {
        return Err(CollectError::invalid_request(
            "route lookup source and destination families differ",
        ));
    }
    if request.input_ifindex == Some(0) || request.output_ifindex == Some(0) {
        return Err(CollectError::invalid_request(
            "route lookup interface indices must be non-zero",
        ));
    }
    Ok(())
}

fn build_lookup_request(
    request: &RouteLookupRequest,
    sequence: u32,
    port_id: u32,
) -> Result<Vec<u8>, CollectError> {
    validate_lookup_request(request)?;
    let family = IpFamily::of(request.destination);
    let mut bytes = vec![0_u8; NLMSG_HEADER_LEN + ROUTE_MESSAGE_LEN];
    put_u16(&mut bytes[4..6], RTM_GETROUTE);
    put_u16(&mut bytes[6..8], NLM_F_REQUEST);
    put_u32(&mut bytes[8..12], sequence);
    put_u32(&mut bytes[12..16], port_id);
    bytes[NLMSG_HEADER_LEN] = family.netlink_value();
    bytes[NLMSG_HEADER_LEN + 1] = family.prefix_bits();
    bytes[NLMSG_HEADER_LEN + 2] = request.source.map_or(0, |_| family.prefix_bits());
    bytes[NLMSG_HEADER_LEN + 3] = request.tos.unwrap_or(0);
    put_u32(
        &mut bytes[NLMSG_HEADER_LEN + 8..NLMSG_HEADER_LEN + 12],
        RTM_F_LOOKUP_TABLE,
    );
    push_attribute(&mut bytes, RTA_DST, &address_bytes(request.destination));
    if let Some(source) = request.source {
        push_attribute(&mut bytes, RTA_SRC, &address_bytes(source));
    }
    if let Some(ifindex) = request.input_ifindex {
        push_attribute(&mut bytes, RTA_IIF, &ifindex.to_ne_bytes());
    }
    if let Some(ifindex) = request.output_ifindex {
        push_attribute(&mut bytes, RTA_OIF, &ifindex.to_ne_bytes());
    }
    if let Some(mark) = request.mark {
        push_attribute(&mut bytes, RTA_MARK, &mark.to_ne_bytes());
    }
    if let Some(uid) = request.uid {
        push_attribute(&mut bytes, RTA_UID, &uid.to_ne_bytes());
    }
    let request_len = u32::try_from(bytes.len())
        .map_err(|_| CollectError::invalid_request("route lookup request is too large"))?;
    put_u32(&mut bytes[0..4], request_len);
    Ok(bytes)
}

fn parse_route(
    payload: &[u8],
    expected_family: IpFamily,
    ticks_per_second: u64,
) -> Result<ParsedRow<RouteRow>, CollectError> {
    if payload.len() < ROUTE_MESSAGE_LEN {
        return Err(CollectError::parse(
            "RTM_NEWROUTE payload is shorter than rtmsg",
        ));
    }
    let family = parse_expected_family(payload[0], expected_family, "RTM_NEWROUTE")?;
    let destination_len = payload[1];
    let source_len = payload[2];
    validate_prefix_len(family, destination_len, "route destination")?;
    validate_prefix_len(family, source_len, "route source")?;

    let mut destination = None;
    let mut source = None;
    let header_table = u32::from(payload[4]);
    let mut extended_table = None;
    let mut priority = None;
    let mut preferred_source = None;
    let mut output_ifindex = None;
    let mut gateway = None;
    let mut via = None;
    let mut metrics = None;
    let mut cache = None;
    let mut expires = None;
    let mut multipath = None;
    let mut unsupported_encapsulation = false;

    let mut attributes = Attributes::new(&payload[ROUTE_MESSAGE_LEN..], "RTM_NEWROUTE");
    while let Some(attribute) = attributes.next()? {
        match attribute.kind {
            RTA_DST => set_once(
                &mut destination,
                parse_prefix_address(family, destination_len, attribute.value)?,
                "RTA_DST",
                "RTM_NEWROUTE",
            )?,
            RTA_SRC => set_once(
                &mut source,
                parse_prefix_address(family, source_len, attribute.value)?,
                "RTA_SRC",
                "RTM_NEWROUTE",
            )?,
            RTA_TABLE => set_once(
                &mut extended_table,
                parse_u32(attribute.value, "RTA_TABLE")?,
                "RTA_TABLE",
                "RTM_NEWROUTE",
            )?,
            RTA_PRIORITY => set_once(
                &mut priority,
                parse_u32(attribute.value, "RTA_PRIORITY")?,
                "RTA_PRIORITY",
                "RTM_NEWROUTE",
            )?,
            RTA_PREFSRC => set_once(
                &mut preferred_source,
                parse_ip_address(family, attribute.value, "RTA_PREFSRC")?,
                "RTA_PREFSRC",
                "RTM_NEWROUTE",
            )?,
            RTA_OIF => set_once(
                &mut output_ifindex,
                parse_ifindex(attribute.value, "RTA_OIF")?,
                "RTA_OIF",
                "RTM_NEWROUTE",
            )?,
            RTA_GATEWAY => set_once(
                &mut gateway,
                parse_ip_address(family, attribute.value, "RTA_GATEWAY")?,
                "RTA_GATEWAY",
                "RTM_NEWROUTE",
            )?,
            RTA_VIA => set_once(
                &mut via,
                parse_via(attribute.value)?,
                "RTA_VIA",
                "RTM_NEWROUTE",
            )?,
            RTA_METRICS => set_once(
                &mut metrics,
                parse_route_metrics(attribute.value)?,
                "RTA_METRICS",
                "RTM_NEWROUTE",
            )?,
            RTA_CACHEINFO => set_once(
                &mut cache,
                parse_route_cache(attribute.value, ticks_per_second)?,
                "RTA_CACHEINFO",
                "RTM_NEWROUTE",
            )?,
            RTA_EXPIRES => set_once(
                &mut expires,
                ticks_to_duration(
                    u64::from(parse_u32(attribute.value, "RTA_EXPIRES")?),
                    ticks_per_second,
                ),
                "RTA_EXPIRES",
                "RTM_NEWROUTE",
            )?,
            RTA_MULTIPATH => set_once(
                &mut multipath,
                attribute.value,
                "RTA_MULTIPATH",
                "RTM_NEWROUTE",
            )?,
            RTA_ENCAP_TYPE | RTA_ENCAP => unsupported_encapsulation = true,
            _ => {}
        }
    }

    let destination = finish_prefix(family, destination_len, destination, "route destination")?;
    let source = finish_prefix(family, source_len, source, "route source")?;
    let mut nexthops = Vec::new();
    if output_ifindex.is_some() || gateway.is_some() || via.is_some() {
        nexthops.push(RouteNexthop {
            ifindex: output_ifindex,
            interface: output_ifindex.and_then(interface_name),
            gateway,
            via,
            weight: 1,
            flags: 0,
        });
    }
    let mut nexthops_truncated = false;
    if let Some(value) = multipath {
        let parsed = parse_multipath(value, family)?;
        nexthops.extend(parsed.nexthops);
        nexthops_truncated |= parsed.truncated;
        unsupported_encapsulation |= parsed.unsupported_encapsulation;
    }
    if nexthops.len() > MAX_NEXTHOPS_PER_ROUTE {
        nexthops.truncate(MAX_NEXTHOPS_PER_ROUTE);
        nexthops_truncated = true;
    }

    Ok(ParsedRow {
        row: RouteRow {
            family,
            destination,
            source,
            tos: payload[3],
            table: extended_table.unwrap_or(header_table),
            priority,
            protocol: payload[5],
            scope: payload[6],
            route_type: payload[7],
            flags: read_u32(&payload[8..12]),
            preferred_source,
            nexthops,
            nexthops_truncated,
            metrics: metrics.unwrap_or_default(),
            cache,
            expires,
            unsupported_encapsulation,
        },
        truncated: nexthops_truncated,
    })
}

struct ParsedMultipath {
    nexthops: Vec<RouteNexthop>,
    truncated: bool,
    unsupported_encapsulation: bool,
}

fn parse_multipath(value: &[u8], family: IpFamily) -> Result<ParsedMultipath, CollectError> {
    if value.is_empty() {
        return Err(CollectError::parse("RTA_MULTIPATH contains no nexthops"));
    }
    let mut nexthops = Vec::new();
    let mut truncated = false;
    let mut unsupported_encapsulation = false;
    let mut offset = 0_usize;
    while offset < value.len() {
        if value.len() - offset < RTNEXTHOP_LEN {
            return Err(CollectError::parse("truncated rtnexthop header"));
        }
        let nexthop_len = read_u16(&value[offset..offset + 2]) as usize;
        if nexthop_len < RTNEXTHOP_LEN || nexthop_len > value.len() - offset {
            return Err(CollectError::parse("invalid rtnexthop length"));
        }
        let flags = value[offset + 2];
        let weight = u16::from(value[offset + 3]) + 1;
        let raw_ifindex = read_i32(&value[offset + 4..offset + 8]);
        if raw_ifindex < 0 {
            return Err(CollectError::parse(
                "rtnexthop contains a negative interface index",
            ));
        }
        let ifindex = (raw_ifindex != 0).then_some(raw_ifindex as u32);
        let mut gateway = None;
        let mut via = None;
        let mut attributes = Attributes::new(
            &value[offset + RTNEXTHOP_LEN..offset + nexthop_len],
            "rtnexthop",
        );
        while let Some(attribute) = attributes.next()? {
            match attribute.kind {
                RTA_GATEWAY => set_once(
                    &mut gateway,
                    parse_ip_address(family, attribute.value, "rtnexthop RTA_GATEWAY")?,
                    "RTA_GATEWAY",
                    "rtnexthop",
                )?,
                RTA_VIA => set_once(
                    &mut via,
                    parse_via(attribute.value)?,
                    "RTA_VIA",
                    "rtnexthop",
                )?,
                RTA_ENCAP_TYPE | RTA_ENCAP => unsupported_encapsulation = true,
                _ => {}
            }
        }
        if nexthops.len() < MAX_NEXTHOPS_PER_ROUTE {
            nexthops.push(RouteNexthop {
                ifindex,
                interface: ifindex.and_then(interface_name),
                gateway,
                via,
                weight,
                flags,
            });
        } else {
            truncated = true;
        }

        let aligned_len = align(nexthop_len);
        if aligned_len > value.len() - offset {
            if nexthop_len == value.len() - offset {
                offset = value.len();
            } else {
                return Err(CollectError::parse("truncated rtnexthop alignment padding"));
            }
        } else {
            offset += aligned_len;
        }
    }
    Ok(ParsedMultipath {
        nexthops,
        truncated,
        unsupported_encapsulation,
    })
}

fn parse_route_metrics(value: &[u8]) -> Result<RouteMetrics, CollectError> {
    let mut metrics = RouteMetrics::default();
    let mut attributes = Attributes::new(value, "RTA_METRICS");
    while let Some(attribute) = attributes.next()? {
        let slot = match attribute.kind {
            RTAX_MTU => Some((&mut metrics.mtu, "RTAX_MTU")),
            RTAX_ADVMSS => Some((&mut metrics.advmss, "RTAX_ADVMSS")),
            RTAX_HOPLIMIT => Some((&mut metrics.hoplimit, "RTAX_HOPLIMIT")),
            RTAX_INITCWND => Some((&mut metrics.initcwnd, "RTAX_INITCWND")),
            RTAX_INITRWND => Some((&mut metrics.initrwnd, "RTAX_INITRWND")),
            _ => None,
        };
        if let Some((slot, name)) = slot {
            set_once(slot, parse_u32(attribute.value, name)?, name, "RTA_METRICS")?;
        }
    }
    Ok(metrics)
}

fn parse_route_cache(value: &[u8], ticks_per_second: u64) -> Result<RouteCacheInfo, CollectError> {
    if value.len() < 32 {
        return Err(CollectError::parse(
            "RTA_CACHEINFO is shorter than rta_cacheinfo",
        ));
    }
    let raw_expires = read_i32(&value[8..12]);
    Ok(RouteCacheInfo {
        client_references: read_u32(&value[0..4]),
        last_use: ticks_to_duration(u64::from(read_u32(&value[4..8])), ticks_per_second),
        expires: (raw_expires >= 0)
            .then(|| ticks_to_duration(raw_expires as u64, ticks_per_second)),
        error: read_i32(&value[12..16]),
        used: read_u32(&value[16..20]),
        id: read_u32(&value[20..24]),
        timestamp_ticks: read_u32(&value[24..28]),
        timestamp_age: ticks_to_duration(u64::from(read_u32(&value[28..32])), ticks_per_second),
    })
}

fn parse_rule(
    payload: &[u8],
    expected_family: IpFamily,
) -> Result<ParsedRow<RuleRow>, CollectError> {
    if payload.len() < RULE_MESSAGE_LEN {
        return Err(CollectError::parse(
            "RTM_NEWRULE payload is shorter than fib_rule_hdr",
        ));
    }
    let family = parse_expected_family(payload[0], expected_family, "RTM_NEWRULE")?;
    let destination_len = payload[1];
    let source_len = payload[2];
    validate_prefix_len(family, destination_len, "rule destination")?;
    validate_prefix_len(family, source_len, "rule source")?;

    let mut destination = None;
    let mut source = None;
    let header_table = u32::from(payload[4]);
    let mut extended_table = None;
    let mut priority = None;
    let mut fwmark = None;
    let mut fwmask = None;
    let mut input_interface = None;
    let mut output_interface = None;
    let mut goto_priority = None;
    let mut suppress_prefix_len = None;
    let mut suppress_interface_group = None;
    let mut l3mdev = None;
    let mut uid_range = None;
    let mut tunnel_id = None;
    let mut flow = None;
    let mut protocol = None;

    let mut attributes = Attributes::new(&payload[RULE_MESSAGE_LEN..], "RTM_NEWRULE");
    while let Some(attribute) = attributes.next()? {
        match attribute.kind {
            FRA_DST => set_once(
                &mut destination,
                parse_prefix_address(family, destination_len, attribute.value)?,
                "FRA_DST",
                "RTM_NEWRULE",
            )?,
            FRA_SRC => set_once(
                &mut source,
                parse_prefix_address(family, source_len, attribute.value)?,
                "FRA_SRC",
                "RTM_NEWRULE",
            )?,
            FRA_TABLE => set_once(
                &mut extended_table,
                parse_u32(attribute.value, "FRA_TABLE")?,
                "FRA_TABLE",
                "RTM_NEWRULE",
            )?,
            FRA_PRIORITY => set_once(
                &mut priority,
                parse_u32(attribute.value, "FRA_PRIORITY")?,
                "FRA_PRIORITY",
                "RTM_NEWRULE",
            )?,
            FRA_FWMARK => set_once(
                &mut fwmark,
                parse_u32(attribute.value, "FRA_FWMARK")?,
                "FRA_FWMARK",
                "RTM_NEWRULE",
            )?,
            FRA_FWMASK => set_once(
                &mut fwmask,
                parse_u32(attribute.value, "FRA_FWMASK")?,
                "FRA_FWMASK",
                "RTM_NEWRULE",
            )?,
            FRA_IIFNAME => set_once(
                &mut input_interface,
                parse_interface_name(attribute.value, "FRA_IIFNAME")?,
                "FRA_IIFNAME",
                "RTM_NEWRULE",
            )?,
            FRA_OIFNAME => set_once(
                &mut output_interface,
                parse_interface_name(attribute.value, "FRA_OIFNAME")?,
                "FRA_OIFNAME",
                "RTM_NEWRULE",
            )?,
            FRA_GOTO => set_once(
                &mut goto_priority,
                parse_u32(attribute.value, "FRA_GOTO")?,
                "FRA_GOTO",
                "RTM_NEWRULE",
            )?,
            FRA_SUPPRESS_PREFIXLEN => set_once(
                &mut suppress_prefix_len,
                parse_u32(attribute.value, "FRA_SUPPRESS_PREFIXLEN")?,
                "FRA_SUPPRESS_PREFIXLEN",
                "RTM_NEWRULE",
            )?,
            FRA_SUPPRESS_IFGROUP => set_once(
                &mut suppress_interface_group,
                parse_u32(attribute.value, "FRA_SUPPRESS_IFGROUP")?,
                "FRA_SUPPRESS_IFGROUP",
                "RTM_NEWRULE",
            )?,
            FRA_L3MDEV => set_once(
                &mut l3mdev,
                parse_u8(attribute.value, "FRA_L3MDEV")?,
                "FRA_L3MDEV",
                "RTM_NEWRULE",
            )?,
            FRA_UID_RANGE => set_once(
                &mut uid_range,
                parse_uid_range(attribute.value)?,
                "FRA_UID_RANGE",
                "RTM_NEWRULE",
            )?,
            FRA_TUN_ID => set_once(
                &mut tunnel_id,
                parse_be_u64(attribute.value, "FRA_TUN_ID")?,
                "FRA_TUN_ID",
                "RTM_NEWRULE",
            )?,
            FRA_FLOW => set_once(
                &mut flow,
                parse_u32(attribute.value, "FRA_FLOW")?,
                "FRA_FLOW",
                "RTM_NEWRULE",
            )?,
            FRA_PROTOCOL => set_once(
                &mut protocol,
                parse_u8(attribute.value, "FRA_PROTOCOL")?,
                "FRA_PROTOCOL",
                "RTM_NEWRULE",
            )?,
            _ => {}
        }
    }

    Ok(ParsedRow {
        row: RuleRow {
            family,
            destination: finish_prefix(family, destination_len, destination, "rule destination")?,
            source: finish_prefix(family, source_len, source, "rule source")?,
            tos: payload[3],
            table: extended_table.unwrap_or(header_table),
            action: payload[7],
            flags: read_u32(&payload[8..12]),
            priority,
            fwmark,
            fwmask,
            input_interface,
            output_interface,
            goto_priority,
            suppress_prefix_len,
            suppress_interface_group,
            l3mdev,
            uid_range,
            tunnel_id,
            flow,
            protocol,
        },
        truncated: false,
    })
}

fn parse_uid_range(value: &[u8]) -> Result<RuleUidRange, CollectError> {
    if value.len() != 8 {
        return Err(CollectError::parse("FRA_UID_RANGE has an invalid length"));
    }
    let range = RuleUidRange {
        start: read_u32(&value[0..4]),
        end: read_u32(&value[4..8]),
    };
    if range.start > range.end {
        return Err(CollectError::parse("FRA_UID_RANGE starts after it ends"));
    }
    Ok(range)
}

fn parse_neighbour(
    payload: &[u8],
    expected_family: IpFamily,
    ticks_per_second: u64,
) -> Result<ParsedRow<NeighbourRow>, CollectError> {
    if payload.len() < NEIGHBOUR_MESSAGE_LEN {
        return Err(CollectError::parse(
            "RTM_NEWNEIGH payload is shorter than ndmsg",
        ));
    }
    let family = parse_expected_family(payload[0], expected_family, "RTM_NEWNEIGH")?;
    let raw_ifindex = read_i32(&payload[4..8]);
    if raw_ifindex <= 0 {
        return Err(CollectError::parse(
            "RTM_NEWNEIGH contains an invalid interface index",
        ));
    }
    let ifindex = raw_ifindex as u32;
    let mut address = None;
    let mut link_address = None;
    let mut cache = None;
    let mut probes = None;
    let mut attributes = Attributes::new(&payload[NEIGHBOUR_MESSAGE_LEN..], "RTM_NEWNEIGH");
    while let Some(attribute) = attributes.next()? {
        match attribute.kind {
            NDA_DST => set_once(
                &mut address,
                parse_ip_address(family, attribute.value, "NDA_DST")?,
                "NDA_DST",
                "RTM_NEWNEIGH",
            )?,
            NDA_LLADDR => {
                if attribute.value.len() > MAX_LINK_ADDRESS_LEN {
                    return Err(CollectError::parse(
                        "NDA_LLADDR exceeds the supported link-address length",
                    ));
                }
                set_once(
                    &mut link_address,
                    LinkAddress(attribute.value.to_vec()),
                    "NDA_LLADDR",
                    "RTM_NEWNEIGH",
                )?;
            }
            NDA_CACHEINFO => set_once(
                &mut cache,
                parse_neighbour_cache(attribute.value, ticks_per_second)?,
                "NDA_CACHEINFO",
                "RTM_NEWNEIGH",
            )?,
            NDA_PROBES => set_once(
                &mut probes,
                parse_u32(attribute.value, "NDA_PROBES")?,
                "NDA_PROBES",
                "RTM_NEWNEIGH",
            )?,
            _ => {}
        }
    }
    let address = address.ok_or_else(|| CollectError::parse("RTM_NEWNEIGH is missing NDA_DST"))?;
    Ok(ParsedRow {
        row: NeighbourRow {
            family,
            address,
            ifindex,
            interface: interface_name(ifindex),
            link_address,
            state: read_u16(&payload[8..10]),
            flags: payload[10],
            neighbour_type: payload[11],
            probes,
            cache,
        },
        truncated: false,
    })
}

fn parse_neighbour_cache(
    value: &[u8],
    ticks_per_second: u64,
) -> Result<NeighbourCacheInfo, CollectError> {
    if value.len() < 16 {
        return Err(CollectError::parse(
            "NDA_CACHEINFO is shorter than nda_cacheinfo",
        ));
    }
    Ok(NeighbourCacheInfo {
        confirmed_age: ticks_to_duration(u64::from(read_u32(&value[0..4])), ticks_per_second),
        used_age: ticks_to_duration(u64::from(read_u32(&value[4..8])), ticks_per_second),
        updated_age: ticks_to_duration(u64::from(read_u32(&value[8..12])), ticks_per_second),
        references: read_u32(&value[12..16]),
    })
}

struct Attribute<'a> {
    kind: u16,
    value: &'a [u8],
}

struct Attributes<'a> {
    bytes: &'a [u8],
    offset: usize,
    context: &'static str,
}

impl<'a> Attributes<'a> {
    const fn new(bytes: &'a [u8], context: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            context,
        }
    }

    fn next(&mut self) -> Result<Option<Attribute<'a>>, CollectError> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        if self.bytes.len() - self.offset < RTATTR_HEADER_LEN {
            return Err(CollectError::parse(format!(
                "truncated {} attribute header",
                self.context
            )));
        }
        let attribute_len = read_u16(&self.bytes[self.offset..self.offset + 2]) as usize;
        let kind = read_u16(&self.bytes[self.offset + 2..self.offset + 4]) & NLA_TYPE_MASK;
        if attribute_len < RTATTR_HEADER_LEN || attribute_len > self.bytes.len() - self.offset {
            return Err(CollectError::parse(format!(
                "invalid {} attribute length",
                self.context
            )));
        }
        let value = &self.bytes[self.offset + RTATTR_HEADER_LEN..self.offset + attribute_len];
        let aligned_len = align(attribute_len);
        if aligned_len > self.bytes.len() - self.offset {
            if attribute_len == self.bytes.len() - self.offset {
                self.offset = self.bytes.len();
            } else {
                return Err(CollectError::parse(format!(
                    "truncated {} attribute alignment padding",
                    self.context
                )));
            }
        } else {
            self.offset += aligned_len;
        }
        Ok(Some(Attribute { kind, value }))
    }
}

fn parse_expected_family(
    value: u8,
    expected: IpFamily,
    context: &str,
) -> Result<IpFamily, CollectError> {
    let family = IpFamily::from_netlink(u16::from(value))?;
    if family != expected {
        return Err(CollectError::parse(format!(
            "{context} returned an unexpected address family"
        )));
    }
    Ok(family)
}

fn validate_prefix_len(
    family: IpFamily,
    prefix_len: u8,
    context: &str,
) -> Result<(), CollectError> {
    if prefix_len > family.prefix_bits() {
        Err(CollectError::parse(format!(
            "{context} prefix length exceeds its address family"
        )))
    } else {
        Ok(())
    }
}

fn parse_prefix_address(
    family: IpFamily,
    prefix_len: u8,
    value: &[u8],
) -> Result<IpAddr, CollectError> {
    validate_prefix_len(family, prefix_len, "IP")?;
    let required = usize::from(prefix_len).div_ceil(8);
    if value.len() < required || value.len() > family.address_len() {
        return Err(CollectError::parse(
            "IP prefix attribute has an invalid address length",
        ));
    }
    let mut octets = [0_u8; 16];
    octets[..value.len()].copy_from_slice(value);
    normalize_prefix(&mut octets[..family.address_len()], prefix_len);
    Ok(match family {
        IpFamily::Ipv4 => IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
        IpFamily::Ipv6 => IpAddr::V6(Ipv6Addr::from(octets)),
    })
}

fn normalize_prefix(octets: &mut [u8], prefix_len: u8) {
    let whole_bytes = usize::from(prefix_len / 8);
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        octets[whole_bytes..].fill(0);
    } else {
        octets[whole_bytes] &= u8::MAX << (8 - remaining_bits);
        octets[whole_bytes + 1..].fill(0);
    }
}

fn finish_prefix(
    family: IpFamily,
    prefix_len: u8,
    address: Option<IpAddr>,
    context: &str,
) -> Result<IpPrefix, CollectError> {
    if prefix_len != 0 && address.is_none() {
        return Err(CollectError::parse(format!(
            "{context} prefix is missing its address attribute"
        )));
    }
    Ok(IpPrefix {
        address: address.unwrap_or_else(|| family.unspecified()),
        prefix_len,
    })
}

fn parse_ip_address(family: IpFamily, value: &[u8], context: &str) -> Result<IpAddr, CollectError> {
    if value.len() != family.address_len() {
        return Err(CollectError::parse(format!(
            "{context} has an invalid address length"
        )));
    }
    Ok(match family {
        IpFamily::Ipv4 => IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
        IpFamily::Ipv6 => {
            let octets: [u8; 16] = value.try_into().expect("IPv6 length was checked");
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    })
}

fn parse_via(value: &[u8]) -> Result<IpAddr, CollectError> {
    if value.len() < size_of::<u16>() {
        return Err(CollectError::parse("RTA_VIA is shorter than rtvia"));
    }
    let family = IpFamily::from_netlink(read_u16(&value[0..2]))?;
    parse_ip_address(family, &value[2..], "RTA_VIA")
}

fn parse_interface_name(value: &[u8], context: &str) -> Result<String, CollectError> {
    if value.len() > libc::IFNAMSIZ {
        return Err(CollectError::parse(format!(
            "{context} exceeds Linux IFNAMSIZ"
        )));
    }
    let Some(terminator) = value.iter().position(|byte| *byte == 0) else {
        return Err(CollectError::parse(format!(
            "{context} is not NUL-terminated"
        )));
    };
    if terminator == 0 || terminator + 1 != value.len() {
        return Err(CollectError::parse(format!(
            "{context} has an invalid terminator"
        )));
    }
    let name = std::str::from_utf8(&value[..terminator])
        .map_err(|_| CollectError::parse(format!("{context} is not valid UTF-8")))?;
    if !super::valid_interface_name(name) {
        return Err(CollectError::parse(format!(
            "{context} contains an invalid interface name"
        )));
    }
    Ok(name.to_owned())
}

fn interface_name(ifindex: u32) -> Option<String> {
    let mut buffer = [0 as libc::c_char; libc::IFNAMSIZ];
    // SAFETY: buffer is writable for IFNAMSIZ bytes, as required by if_indextoname.
    let pointer = unsafe { libc::if_indextoname(ifindex, buffer.as_mut_ptr()) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: if_indextoname returns a NUL-terminated string in buffer on success.
    let name = unsafe { CStr::from_ptr(pointer) }.to_str().ok()?;
    super::valid_interface_name(name).then(|| name.to_owned())
}

fn parse_ifindex(value: &[u8], context: &str) -> Result<u32, CollectError> {
    let ifindex = parse_u32(value, context)?;
    if ifindex == 0 {
        Err(CollectError::parse(format!(
            "{context} contains a zero interface index"
        )))
    } else {
        Ok(ifindex)
    }
}

fn parse_u8(value: &[u8], context: &str) -> Result<u8, CollectError> {
    if value.len() != 1 {
        Err(CollectError::parse(format!(
            "{context} has an invalid scalar length"
        )))
    } else {
        Ok(value[0])
    }
}

fn parse_u32(value: &[u8], context: &str) -> Result<u32, CollectError> {
    if value.len() != size_of::<u32>() {
        Err(CollectError::parse(format!(
            "{context} has an invalid scalar length"
        )))
    } else {
        Ok(read_u32(value))
    }
}

fn parse_be_u64(value: &[u8], context: &str) -> Result<u64, CollectError> {
    if value.len() != size_of::<u64>() {
        Err(CollectError::parse(format!(
            "{context} has an invalid scalar length"
        )))
    } else {
        Ok(u64::from_be_bytes(
            value.try_into().expect("u64 length was checked"),
        ))
    }
}

fn set_once<T>(
    slot: &mut Option<T>,
    value: T,
    attribute: &str,
    context: &str,
) -> Result<(), CollectError> {
    if slot.replace(value).is_some() {
        Err(CollectError::parse(format!(
            "{context} contains duplicate {attribute} attributes"
        )))
    } else {
        Ok(())
    }
}

fn clock_ticks_per_second() -> Result<u64, CollectError> {
    // SAFETY: _SC_CLK_TCK is a read-only sysconf query with no pointer arguments.
    let ticks = unsafe { libc::sysconf(SYSCONF_CLK_TCK) };
    if ticks <= 0 {
        Err(CollectError::io("read USER_HZ", io::Error::last_os_error()))
    } else {
        Ok(ticks as u64)
    }
}

fn ticks_to_duration(ticks: u64, ticks_per_second: u64) -> Duration {
    let seconds = ticks / ticks_per_second;
    let remainder = ticks % ticks_per_second;
    let nanos = (u128::from(remainder) * 1_000_000_000_u128 / u128::from(ticks_per_second)) as u32;
    Duration::new(seconds, nanos)
}

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    }
}

fn push_attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let attribute_len = RTATTR_HEADER_LEN + value.len();
    let offset = bytes.len();
    bytes.resize(offset + align(attribute_len), 0);
    put_u16(&mut bytes[offset..offset + 2], attribute_len as u16);
    put_u16(&mut bytes[offset + 2..offset + 4], kind);
    bytes[offset + RTATTR_HEADER_LEN..offset + attribute_len].copy_from_slice(value);
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

fn put_u16(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEQUENCE: u32 = 0x1234;
    const PORT_ID: u32 = 0x5678;
    const TEST_HZ: u64 = 100;

    #[test]
    fn parses_ipv4_default_route_with_extended_table_and_single_nexthop() {
        let mut payload = route_payload(IpFamily::Ipv4, 0, 0);
        payload[3] = 0x2e;
        payload[4] = 254;
        payload[5] = 250;
        payload[6] = 251;
        payload[7] = 252;
        put_u32(&mut payload[8..12], 0xa5a5_5a5a);
        push_attribute(&mut payload, RTA_TABLE, &1_000_u32.to_ne_bytes());
        push_attribute(&mut payload, RTA_PRIORITY, &77_u32.to_ne_bytes());
        push_attribute(&mut payload, RTA_OIF, &1_u32.to_ne_bytes());
        push_attribute(&mut payload, RTA_GATEWAY, &[192, 0, 2, 1]);
        push_attribute(&mut payload, RTA_PREFSRC, &[198, 51, 100, 9]);
        push_attribute(&mut payload, 3_000, &[1, 2, 3]);

        let parsed = parse_route(&payload, IpFamily::Ipv4, TEST_HZ).unwrap();
        let route = parsed.row;

        assert_eq!(route.destination.prefix_len, 0);
        assert_eq!(route.destination.address, Ipv4Addr::UNSPECIFIED);
        assert_eq!(route.source.prefix_len, 0);
        assert_eq!(route.tos, 0x2e);
        assert_eq!(route.table, 1_000);
        assert_eq!(route.priority, Some(77));
        assert_eq!(route.protocol, 250);
        assert_eq!(route.scope, 251);
        assert_eq!(route.route_type, 252);
        assert_eq!(route.flags, 0xa5a5_5a5a);
        assert_eq!(
            route.preferred_source,
            Some("198.51.100.9".parse().unwrap())
        );
        assert_eq!(route.nexthops.len(), 1);
        assert_eq!(route.nexthops[0].ifindex, Some(1));
        assert_eq!(
            route.nexthops[0].gateway,
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(route.nexthops[0].weight, 1);
        assert!(!parsed.truncated);
    }

    #[test]
    fn parses_compact_ipv6_prefix_and_weighted_multipath() {
        let mut payload = route_payload(IpFamily::Ipv6, 65, 0);
        push_attribute(
            &mut payload,
            RTA_DST,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0xff],
        );
        let mut multipath = Vec::new();
        push_nexthop(
            &mut multipath,
            1,
            0x80,
            0,
            Some(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
        );
        push_nexthop(
            &mut multipath,
            2,
            0x04,
            9,
            Some(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets()),
        );
        push_attribute(&mut payload, RTA_MULTIPATH, &multipath);

        let route = parse_route(&payload, IpFamily::Ipv6, TEST_HZ).unwrap().row;

        assert_eq!(route.destination.prefix_len, 65);
        assert_eq!(
            route.destination.address,
            "2001:db8:1:2:8000::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(route.nexthops.len(), 2);
        assert_eq!(route.nexthops[0].weight, 1);
        assert_eq!(route.nexthops[0].flags, 0x80);
        assert_eq!(route.nexthops[1].weight, 10);
        assert_eq!(
            route.nexthops[1].gateway,
            Some("2001:db8::2".parse().unwrap())
        );
    }

    #[test]
    fn parses_route_metrics_cache_expiry_and_encapsulation_marker() {
        let mut payload = route_payload(IpFamily::Ipv4, 24, 0);
        push_attribute(&mut payload, RTA_DST, &[203, 0, 113]);
        let mut metrics = Vec::new();
        push_attribute(&mut metrics, RTAX_MTU, &1_400_u32.to_ne_bytes());
        push_attribute(&mut metrics, RTAX_ADVMSS, &1_360_u32.to_ne_bytes());
        push_attribute(&mut metrics, RTAX_HOPLIMIT, &63_u32.to_ne_bytes());
        push_attribute(&mut metrics, RTAX_INITCWND, &12_u32.to_ne_bytes());
        push_attribute(&mut metrics, RTAX_INITRWND, &24_u32.to_ne_bytes());
        push_attribute(&mut metrics, 4_000, &[0xaa]);
        push_attribute(&mut payload, RTA_METRICS, &metrics);
        let cache_fields = [2_u32, 250, 300, 9, 11, 12, 13, 450];
        let cache: Vec<_> = cache_fields
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect();
        push_attribute(&mut payload, RTA_CACHEINFO, &cache);
        push_attribute(&mut payload, RTA_EXPIRES, &125_u32.to_ne_bytes());
        push_attribute(&mut payload, RTA_ENCAP_TYPE, &7_u16.to_ne_bytes());
        push_attribute(&mut payload, RTA_ENCAP, &[1, 2, 3, 4]);

        let route = parse_route(&payload, IpFamily::Ipv4, TEST_HZ).unwrap().row;

        assert_eq!(route.metrics.mtu, Some(1_400));
        assert_eq!(route.metrics.advmss, Some(1_360));
        assert_eq!(route.metrics.hoplimit, Some(63));
        assert_eq!(route.metrics.initcwnd, Some(12));
        assert_eq!(route.metrics.initrwnd, Some(24));
        let cache = route.cache.unwrap();
        assert_eq!(cache.client_references, 2);
        assert_eq!(cache.last_use, Duration::from_millis(2_500));
        assert_eq!(cache.expires, Some(Duration::from_secs(3)));
        assert_eq!(cache.error, 9);
        assert_eq!(cache.timestamp_age, Duration::from_millis(4_500));
        assert_eq!(route.expires, Some(Duration::from_millis(1_250)));
        assert!(route.unsupported_encapsulation);
    }

    #[test]
    fn parses_rule_selectors_and_linux_4_14_optional_fields() {
        let mut payload = rule_payload(IpFamily::Ipv4, 24, 16);
        payload[3] = 0x20;
        payload[4] = 254;
        payload[7] = 222;
        put_u32(&mut payload[8..12], 0xdead_beef);
        push_attribute(&mut payload, FRA_DST, &[192, 0, 2]);
        push_attribute(&mut payload, FRA_SRC, &[198, 51]);
        push_attribute(&mut payload, FRA_TABLE, &1_001_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_PRIORITY, &100_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_FWMARK, &0x1200_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_FWMASK, &0xff00_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_IIFNAME, b"eth0\0");
        push_attribute(&mut payload, FRA_OIFNAME, b"wan0\0");
        push_attribute(&mut payload, FRA_GOTO, &200_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_SUPPRESS_PREFIXLEN, &32_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_SUPPRESS_IFGROUP, &7_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_L3MDEV, &[1]);
        let uid_range: Vec<_> = [1_000_u32, 2_000]
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect();
        push_attribute(&mut payload, FRA_UID_RANGE, &uid_range);
        push_attribute(
            &mut payload,
            FRA_TUN_ID,
            &0x0102_0304_0506_0708_u64.to_be_bytes(),
        );
        push_attribute(&mut payload, FRA_FLOW, &0x1020_3040_u32.to_ne_bytes());
        push_attribute(&mut payload, FRA_PROTOCOL, &[199]);
        push_attribute(&mut payload, 3_333, &[9, 8, 7]);

        let rule = parse_rule(&payload, IpFamily::Ipv4).unwrap().row;

        assert_eq!(
            rule.destination.address,
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(rule.source.address, "198.51.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(rule.tos, 0x20);
        assert_eq!(rule.table, 1_001);
        assert_eq!(rule.action, 222);
        assert_eq!(rule.flags, 0xdead_beef);
        assert_eq!(rule.priority, Some(100));
        assert_eq!(rule.fwmark, Some(0x1200));
        assert_eq!(rule.fwmask, Some(0xff00));
        assert_eq!(rule.input_interface.as_deref(), Some("eth0"));
        assert_eq!(rule.output_interface.as_deref(), Some("wan0"));
        assert_eq!(rule.goto_priority, Some(200));
        assert_eq!(rule.suppress_prefix_len, Some(32));
        assert_eq!(rule.suppress_interface_group, Some(7));
        assert_eq!(rule.l3mdev, Some(1));
        assert_eq!(
            rule.uid_range,
            Some(RuleUidRange {
                start: 1_000,
                end: 2_000
            })
        );
        assert_eq!(rule.tunnel_id, Some(0x0102_0304_0506_0708));
        assert_eq!(rule.flow, Some(0x1020_3040));
        assert_eq!(rule.protocol, Some(199));
    }

    #[test]
    fn parses_neighbour_without_lladdr_and_with_user_hz_ages() {
        let mut payload = neighbour_payload(IpFamily::Ipv4, 1);
        put_u16(&mut payload[8..10], 0x8123);
        payload[10] = 0xe1;
        payload[11] = 0xf2;
        push_attribute(&mut payload, NDA_DST, &[203, 0, 113, 44]);
        push_attribute(&mut payload, NDA_PROBES, &5_u32.to_ne_bytes());
        let cache: Vec<_> = [100_u32, 250, 999, 3]
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect();
        push_attribute(&mut payload, NDA_CACHEINFO, &cache);

        let neighbour = parse_neighbour(&payload, IpFamily::Ipv4, TEST_HZ)
            .unwrap()
            .row;

        assert_eq!(neighbour.address, "203.0.113.44".parse::<IpAddr>().unwrap());
        assert_eq!(neighbour.ifindex, 1);
        assert!(neighbour.link_address.is_none());
        assert_eq!(neighbour.state, 0x8123);
        assert_eq!(neighbour.flags, 0xe1);
        assert_eq!(neighbour.neighbour_type, 0xf2);
        assert_eq!(neighbour.probes, Some(5));
        let cache = neighbour.cache.unwrap();
        assert_eq!(cache.confirmed_age, Duration::from_secs(1));
        assert_eq!(cache.used_age, Duration::from_millis(2_500));
        assert_eq!(cache.updated_age, Duration::from_millis(9_990));
        assert_eq!(cache.references, 3);
    }

    #[test]
    fn accepts_twenty_byte_link_address_and_redacts_it_from_debug() {
        let mut payload = neighbour_payload(IpFamily::Ipv6, 1);
        let address = "2001:db8::99".parse::<Ipv6Addr>().unwrap().octets();
        let link_address: Vec<_> = (0_u8..20).collect();
        push_attribute(&mut payload, NDA_DST, &address);
        push_attribute(&mut payload, NDA_LLADDR, &link_address);

        let neighbour = parse_neighbour(&payload, IpFamily::Ipv6, TEST_HZ)
            .unwrap()
            .row;

        assert_eq!(
            neighbour.link_address.as_ref().unwrap().as_bytes(),
            link_address
        );
        let debug = format!("{neighbour:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("2001:db8"));
        assert!(!debug.contains("0, 1, 2"));
    }

    #[test]
    fn rejects_malformed_families_prefixes_attributes_and_link_addresses() {
        let mut wrong_family = route_payload(IpFamily::Ipv6, 0, 0);
        assert_parse_error(parse_route(&wrong_family, IpFamily::Ipv4, TEST_HZ));

        wrong_family[0] = IpFamily::Ipv4.netlink_value();
        wrong_family[1] = 33;
        assert_parse_error(parse_route(&wrong_family, IpFamily::Ipv4, TEST_HZ));

        let missing_prefix = route_payload(IpFamily::Ipv4, 24, 0);
        assert_parse_error(parse_route(&missing_prefix, IpFamily::Ipv4, TEST_HZ));

        let mut short_prefix = route_payload(IpFamily::Ipv4, 25, 0);
        push_attribute(&mut short_prefix, RTA_DST, &[192, 0, 2]);
        assert_parse_error(parse_route(&short_prefix, IpFamily::Ipv4, TEST_HZ));

        let mut invalid_attribute = route_payload(IpFamily::Ipv4, 0, 0);
        invalid_attribute.extend_from_slice(&[3, 0, RTA_DST as u8, 0]);
        assert_parse_error(parse_route(&invalid_attribute, IpFamily::Ipv4, TEST_HZ));

        let mut missing_padding = route_payload(IpFamily::Ipv4, 0, 0);
        missing_padding.extend_from_slice(&[5, 0, 99, 0, 1, 0]);
        assert_parse_error(parse_route(&missing_padding, IpFamily::Ipv4, TEST_HZ));

        let mut neighbour = neighbour_payload(IpFamily::Ipv4, 1);
        push_attribute(&mut neighbour, NDA_DST, &[192, 0, 2, 1]);
        push_attribute(
            &mut neighbour,
            NDA_LLADDR,
            &[0xaa; MAX_LINK_ADDRESS_LEN + 1],
        );
        assert_parse_error(parse_neighbour(&neighbour, IpFamily::Ipv4, TEST_HZ));

        let mut rule = rule_payload(IpFamily::Ipv4, 0, 0);
        let reversed: Vec<_> = [2_u32, 1]
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect();
        push_attribute(&mut rule, FRA_UID_RANGE, &reversed);
        assert_parse_error(parse_rule(&rule, IpFamily::Ipv4));
    }

    #[test]
    fn rejects_duplicate_extended_table_attributes() {
        let mut route = route_payload(IpFamily::Ipv4, 0, 0);
        push_attribute(&mut route, RTA_TABLE, &1_u32.to_ne_bytes());
        push_attribute(&mut route, RTA_TABLE, &2_u32.to_ne_bytes());
        assert_parse_error(parse_route(&route, IpFamily::Ipv4, TEST_HZ));

        let mut rule = rule_payload(IpFamily::Ipv4, 0, 0);
        push_attribute(&mut rule, FRA_TABLE, &1_u32.to_ne_bytes());
        push_attribute(&mut rule, FRA_TABLE, &2_u32.to_ne_bytes());
        assert_parse_error(parse_rule(&rule, IpFamily::Ipv4));
    }

    #[test]
    fn enforces_per_route_and_total_retained_nexthop_bounds() {
        let mut payload = route_payload(IpFamily::Ipv4, 0, 0);
        let mut multipath = Vec::new();
        for ifindex in 1..=MAX_NEXTHOPS_PER_ROUTE + 1 {
            push_nexthop(&mut multipath, ifindex as i32, 0, 0, None);
        }
        push_attribute(&mut payload, RTA_MULTIPATH, &multipath);
        let parsed = parse_route(&payload, IpFamily::Ipv4, TEST_HZ).unwrap();
        assert_eq!(parsed.row.nexthops.len(), MAX_NEXTHOPS_PER_ROUTE);
        assert!(parsed.row.nexthops_truncated);
        assert!(parsed.truncated);

        let mut retention = RouteRetention {
            retained_nexthops: MAX_RETAINED_NEXTHOPS - 2,
        };
        let mut row = sample_route(4);
        assert!(retention.adjust(&mut row));
        assert_eq!(row.nexthops.len(), 2);
        assert_eq!(retention.retained_nexthops, MAX_RETAINED_NEXTHOPS);
    }

    #[test]
    fn row_retention_truncation_still_drains_through_done() {
        let mut datagram = Vec::new();
        for table in [3_u8, 2, 1] {
            let mut payload = route_payload(IpFamily::Ipv4, 0, 0);
            payload[4] = table;
            datagram.extend(message(
                RTM_NEWROUTE,
                NLM_F_MULTI,
                SEQUENCE,
                PORT_ID,
                &payload,
            ));
        }
        datagram.extend(done_message(SEQUENCE, PORT_ID, NLM_F_MULTI));

        let mut decoder = MessageDecoder::new(SEQUENCE, PORT_ID);
        let mut rows = BoundedRows::new(2);
        decoder
            .parse_datagram(&datagram, RTM_NEWROUTE, &mut |payload| {
                rows.observe(parse_route(payload, IpFamily::Ipv4, TEST_HZ)?, &mut |_| {
                    false
                });
                Ok(())
            })
            .unwrap();

        decoder.require_done().unwrap();
        let dump = rows.finish();
        assert_eq!(dump.observed_rows, 3);
        assert_eq!(dump.rows.len(), 2);
        assert!(dump.truncated);
    }

    #[test]
    fn rejects_non_multipart_dump_data_and_done_messages() {
        let payload = route_payload(IpFamily::Ipv4, 0, 0);
        let data = message(RTM_NEWROUTE, 0, SEQUENCE, PORT_ID, &payload);
        let done = done_message(SEQUENCE, PORT_ID, 0);

        for datagram in [data, done] {
            let mut decoder = MessageDecoder::new(SEQUENCE, PORT_ID);
            let error = decoder
                .parse_datagram(&datagram, RTM_NEWROUTE, &mut |_| Ok(()))
                .unwrap_err();
            assert_eq!(error.kind(), CollectErrorKind::Parse);
            assert!(error.to_string().contains("multipart"));
        }
    }

    #[test]
    fn lookup_decoder_accepts_single_response_or_waits_for_multipart_done() {
        let payload = route_payload(IpFamily::Ipv4, 0, 0);
        let single = message(RTM_NEWROUTE, 0, SEQUENCE, PORT_ID, &payload);
        let mut decoder = MessageDecoder::new_single(SEQUENCE, PORT_ID);
        let mut responses = 0;
        decoder
            .parse_datagram(&single, RTM_NEWROUTE, &mut |_| {
                responses += 1;
                Ok(())
            })
            .unwrap();
        assert!(decoder.done);
        assert_eq!(responses, 1);

        let multipart = message(RTM_NEWROUTE, NLM_F_MULTI, SEQUENCE, PORT_ID, &payload);
        let mut decoder = MessageDecoder::new_single(SEQUENCE, PORT_ID);
        decoder
            .parse_datagram(&multipart, RTM_NEWROUTE, &mut |_| Ok(()))
            .unwrap();
        assert!(!decoder.done);
        decoder
            .parse_datagram(
                &done_message(SEQUENCE, PORT_ID, NLM_F_MULTI),
                RTM_NEWROUTE,
                &mut |_| Ok(()),
            )
            .unwrap();
        assert!(decoder.done);
    }

    #[test]
    fn decoder_rejects_multipart_framing_changes_and_accepts_empty_dump() {
        let payload = route_payload(IpFamily::Ipv4, 0, 0);
        let multipart = message(RTM_NEWROUTE, NLM_F_MULTI, SEQUENCE, PORT_ID, &payload);

        let mut lookup = MessageDecoder::new_single(SEQUENCE, PORT_ID);
        lookup
            .parse_datagram(&multipart, RTM_NEWROUTE, &mut |_| Ok(()))
            .unwrap();
        let mut callbacks = 0;
        let non_multipart = message(RTM_NEWROUTE, 0, SEQUENCE, PORT_ID, &payload);
        let error = lookup
            .parse_datagram(&non_multipart, RTM_NEWROUTE, &mut |_| {
                callbacks += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert_eq!(callbacks, 0);

        let mut lookup = MessageDecoder::new_single(SEQUENCE, PORT_ID);
        lookup
            .parse_datagram(&multipart, RTM_NEWROUTE, &mut |_| Ok(()))
            .unwrap();
        let error = lookup
            .parse_datagram(
                &done_message(SEQUENCE, PORT_ID, 0),
                RTM_NEWROUTE,
                &mut |_| Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Parse);

        let mut dump = MessageDecoder::new(SEQUENCE, PORT_ID);
        dump.parse_datagram(
            &done_message(SEQUENCE, PORT_ID, NLM_F_MULTI),
            RTM_NEWROUTE,
            &mut |_| Ok(()),
        )
        .unwrap();
        dump.require_done().unwrap();
    }

    #[test]
    fn builds_lookup_request_with_all_supported_selectors() {
        let request = RouteLookupRequest {
            destination: "192.0.2.9".parse().unwrap(),
            source: Some("198.51.100.7".parse().unwrap()),
            input_ifindex: Some(2),
            output_ifindex: Some(3),
            mark: Some(4),
            uid: Some(5),
            tos: Some(0x10),
        };
        let bytes = build_lookup_request(&request, SEQUENCE, PORT_ID).unwrap();

        assert_eq!(read_u32(&bytes[0..4]) as usize, bytes.len());
        assert_eq!(read_u16(&bytes[4..6]), RTM_GETROUTE);
        assert_eq!(read_u16(&bytes[6..8]), NLM_F_REQUEST);
        assert_eq!(read_u32(&bytes[8..12]), SEQUENCE);
        assert_eq!(read_u32(&bytes[12..16]), PORT_ID);
        assert_eq!(bytes[16], IpFamily::Ipv4.netlink_value());
        assert_eq!(bytes[17], 32);
        assert_eq!(bytes[18], 32);
        assert_eq!(bytes[19], 0x10);
        assert_eq!(read_u32(&bytes[24..28]), RTM_F_LOOKUP_TABLE);

        let attributes = collect_attributes(&bytes[28..]).unwrap();
        assert_eq!(attributes[0], (RTA_DST, vec![192, 0, 2, 9]));
        assert_eq!(attributes[1], (RTA_SRC, vec![198, 51, 100, 7]));
        assert_eq!(read_u32(&attributes[2].1), 2);
        assert_eq!(read_u32(&attributes[3].1), 3);
        assert_eq!(read_u32(&attributes[4].1), 4);
        assert_eq!(read_u32(&attributes[5].1), 5);
    }

    #[test]
    fn rejects_lookup_family_mismatch_and_zero_interface_index() {
        let mismatch = RouteLookupRequest {
            destination: "192.0.2.1".parse().unwrap(),
            source: Some("2001:db8::1".parse().unwrap()),
            input_ifindex: None,
            output_ifindex: None,
            mark: None,
            uid: None,
            tos: None,
        };
        assert_eq!(
            build_lookup_request(&mismatch, SEQUENCE, PORT_ID)
                .unwrap_err()
                .kind(),
            CollectErrorKind::InvalidRequest
        );

        let zero_ifindex = RouteLookupRequest {
            destination: "2001:db8::1".parse().unwrap(),
            source: None,
            input_ifindex: Some(0),
            output_ifindex: None,
            mark: None,
            uid: None,
            tos: None,
        };
        assert_eq!(
            validate_lookup_request(&zero_ifindex).unwrap_err().kind(),
            CollectErrorKind::InvalidRequest
        );
    }

    #[test]
    fn handles_netlink_errors_sequence_interruption_overrun_and_missing_done() {
        let mut error_payload = vec![0_u8; size_of::<i32>() + NLMSG_HEADER_LEN];
        error_payload[..4].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        let error_message = message(NLMSG_ERROR, 0, SEQUENCE, PORT_ID, &error_payload);
        let error = decode_control(&error_message).unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::PermissionDenied);

        let wrong_sequence = done_message(SEQUENCE + 1, PORT_ID, 0);
        assert_eq!(
            decode_control(&wrong_sequence).unwrap_err().kind(),
            CollectErrorKind::Parse
        );

        let interrupted = done_message(SEQUENCE, PORT_ID, NLM_F_DUMP_INTR);
        assert_eq!(
            decode_control(&interrupted).unwrap_err().kind(),
            CollectErrorKind::Interrupted
        );

        let overrun = message(NLMSG_OVERRUN, 0, SEQUENCE, PORT_ID, &[]);
        assert_eq!(
            decode_control(&overrun).unwrap_err().kind(),
            CollectErrorKind::Loss
        );

        let payload = route_payload(IpFamily::Ipv4, 0, 0);
        let route = message(RTM_NEWROUTE, NLM_F_MULTI, SEQUENCE, PORT_ID, &payload);
        let mut decoder = MessageDecoder::new(SEQUENCE, PORT_ID);
        decoder
            .parse_datagram(&route, RTM_NEWROUTE, &mut |_| Ok(()))
            .unwrap();
        assert_eq!(
            decoder.require_done().unwrap_err().kind(),
            CollectErrorKind::Interrupted
        );
    }

    #[test]
    fn rejects_messages_after_done_and_enforces_scan_limits() {
        let mut after_done = done_message(SEQUENCE, PORT_ID, NLM_F_MULTI);
        after_done.extend(message(NLMSG_NOOP, 0, SEQUENCE, PORT_ID, &[]));
        assert_eq!(
            decode_control(&after_done).unwrap_err().kind(),
            CollectErrorKind::Parse
        );

        let done = done_message(SEQUENCE, PORT_ID, NLM_F_MULTI);
        let mut message_limited = MessageDecoder::new(SEQUENCE, PORT_ID);
        message_limited.messages_scanned = MAX_SCANNED_MESSAGES;
        assert_eq!(
            message_limited
                .parse_datagram(&done, RTM_NEWROUTE, &mut |_| Ok(()))
                .unwrap_err()
                .kind(),
            CollectErrorKind::OutputLimit
        );

        let mut byte_limited = MessageDecoder::new(SEQUENCE, PORT_ID);
        byte_limited.bytes_scanned = MAX_SCANNED_BYTES;
        assert_eq!(
            byte_limited
                .parse_datagram(&done, RTM_NEWROUTE, &mut |_| Ok(()))
                .unwrap_err()
                .kind(),
            CollectErrorKind::OutputLimit
        );
    }

    #[test]
    fn validates_kernel_sender_without_exposing_port_ids() {
        // SAFETY: zero is a valid sockaddr_nl initialization for this parser test.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sender.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        validate_kernel_sender(&sender, size_of::<libc::sockaddr_nl>() as libc::socklen_t).unwrap();

        sender.nl_pid = 0xfeed_beef;
        let error =
            validate_kernel_sender(&sender, size_of::<libc::sockaddr_nl>() as libc::socklen_t)
                .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(!error.to_string().contains("4276993775"));
    }

    #[test]
    fn address_bearing_debug_output_is_redacted() {
        const IPV4_CANARY: &str = "203.0.113.231";
        const IPV6_CANARY: &str = "2001:db8:dead:beef::231";
        let mut route = sample_route(1);
        route.destination.address = IPV4_CANARY.parse().unwrap();
        route.preferred_source = Some(IPV4_CANARY.parse().unwrap());
        route.nexthops[0].gateway = Some(IPV6_CANARY.parse().unwrap());
        let request = RouteLookupRequest {
            destination: IPV4_CANARY.parse().unwrap(),
            source: Some("198.51.100.231".parse().unwrap()),
            input_ifindex: None,
            output_ifindex: None,
            mark: None,
            uid: None,
            tos: None,
        };

        let debug = format!("{route:?} {request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(IPV4_CANARY));
        assert!(!debug.contains(IPV6_CANARY));
        assert!(!debug.contains("198.51.100.231"));
    }

    #[test]
    fn current_namespace_route_rule_and_neighbour_dumps_complete() {
        let routes = collect_routes(IpFamily::Ipv4).unwrap();
        assert!(routes.observed_rows >= routes.rows.len());

        let rules = collect_rules(IpFamily::Ipv4).unwrap();
        assert!(rules.observed_rows >= rules.rows.len());

        // An empty neighbour table is a complete and valid dump.
        let neighbours = collect_neighbours(IpFamily::Ipv4).unwrap();
        assert!(neighbours.observed_rows >= neighbours.rows.len());

        let lookup = lookup_route(&RouteLookupRequest {
            destination: Ipv4Addr::LOCALHOST.into(),
            source: None,
            input_ifindex: None,
            output_ifindex: None,
            mark: None,
            uid: None,
            tos: None,
        })
        .unwrap();
        assert_eq!(lookup.family, IpFamily::Ipv4);
    }

    fn route_payload(family: IpFamily, destination_len: u8, source_len: u8) -> Vec<u8> {
        let mut payload = vec![0_u8; ROUTE_MESSAGE_LEN];
        payload[0] = family.netlink_value();
        payload[1] = destination_len;
        payload[2] = source_len;
        payload
    }

    fn rule_payload(family: IpFamily, destination_len: u8, source_len: u8) -> Vec<u8> {
        let mut payload = vec![0_u8; RULE_MESSAGE_LEN];
        payload[0] = family.netlink_value();
        payload[1] = destination_len;
        payload[2] = source_len;
        payload
    }

    fn neighbour_payload(family: IpFamily, ifindex: i32) -> Vec<u8> {
        let mut payload = vec![0_u8; NEIGHBOUR_MESSAGE_LEN];
        payload[0] = family.netlink_value();
        payload[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        payload
    }

    fn push_nexthop(
        multipath: &mut Vec<u8>,
        ifindex: i32,
        flags: u8,
        hops: u8,
        gateway: Option<&[u8]>,
    ) {
        let offset = multipath.len();
        multipath.resize(offset + RTNEXTHOP_LEN, 0);
        multipath[offset + 2] = flags;
        multipath[offset + 3] = hops;
        multipath[offset + 4..offset + 8].copy_from_slice(&ifindex.to_ne_bytes());
        if let Some(gateway) = gateway {
            push_attribute(multipath, RTA_GATEWAY, gateway);
        }
        let nexthop_len = multipath.len() - offset;
        put_u16(
            &mut multipath[offset..offset + 2],
            u16::try_from(nexthop_len).unwrap(),
        );
        multipath.resize(offset + align(nexthop_len), 0);
    }

    fn sample_route(nexthops: usize) -> RouteRow {
        RouteRow {
            family: IpFamily::Ipv4,
            destination: IpPrefix {
                address: Ipv4Addr::UNSPECIFIED.into(),
                prefix_len: 0,
            },
            source: IpPrefix {
                address: Ipv4Addr::UNSPECIFIED.into(),
                prefix_len: 0,
            },
            tos: 0,
            table: 254,
            priority: None,
            protocol: 2,
            scope: 0,
            route_type: 1,
            flags: 0,
            preferred_source: None,
            nexthops: (1..=nexthops)
                .map(|ifindex| RouteNexthop {
                    ifindex: Some(ifindex as u32),
                    interface: None,
                    gateway: None,
                    via: None,
                    weight: 1,
                    flags: 0,
                })
                .collect(),
            nexthops_truncated: false,
            metrics: RouteMetrics::default(),
            cache: None,
            expires: None,
            unsupported_encapsulation: false,
        }
    }

    fn message(
        message_type: u16,
        flags: u16,
        sequence: u32,
        port_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let message_len = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = vec![0_u8; align(message_len)];
        put_u32(&mut bytes[0..4], message_len as u32);
        put_u16(&mut bytes[4..6], message_type);
        put_u16(&mut bytes[6..8], flags);
        put_u32(&mut bytes[8..12], sequence);
        put_u32(&mut bytes[12..16], port_id);
        bytes[NLMSG_HEADER_LEN..message_len].copy_from_slice(payload);
        bytes
    }

    fn done_message(sequence: u32, port_id: u32, flags: u16) -> Vec<u8> {
        message(NLMSG_DONE, flags, sequence, port_id, &[])
    }

    fn decode_control(datagram: &[u8]) -> Result<(), CollectError> {
        let mut decoder = MessageDecoder::new(SEQUENCE, PORT_ID);
        decoder.parse_datagram(datagram, RTM_NEWROUTE, &mut |_| Ok(()))
    }

    fn collect_attributes(bytes: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, CollectError> {
        let mut attributes = Attributes::new(bytes, "test");
        let mut collected = Vec::new();
        while let Some(attribute) = attributes.next()? {
            collected.push((attribute.kind, attribute.value.to_vec()));
        }
        Ok(collected)
    }

    fn assert_parse_error<T>(result: Result<T, CollectError>) {
        let error = match result {
            Ok(_) => panic!("expected a parser error"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), CollectErrorKind::Parse);
    }
}
