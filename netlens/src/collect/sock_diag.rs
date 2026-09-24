use std::fmt;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ALIGNMENT: usize = 4;
const NLMSG_HEADER_LEN: usize = 16;
const INET_DIAG_REQ_V2_LEN: usize = 56;
const INET_DIAG_MSG_LEN: usize = 72;
const RTATTR_HEADER_LEN: usize = 4;

const RECEIVE_BUFFER_LEN: usize = 1024 * 1024;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const MAX_SAMPLES_PER_QUERY: usize = 1_000_000;
const MAX_TABLE_SAMPLES_PER_QUERY: usize = 4_096;

const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const NLM_F_MULTI: u16 = 0x02;
const NLM_F_DUMP_INTR: u16 = 0x10;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_SKMEMINFO: u16 = 7;
const TCP_CA_NAME_MAX: usize = 16;
const SK_MEMINFO_RMEM_ALLOC: usize = 0;
const SK_MEMINFO_RCVBUF: usize = 1;
const SK_MEMINFO_WMEM_ALLOC: usize = 2;
const SK_MEMINFO_SNDBUF: usize = 3;
const SK_MEMINFO_FWD_ALLOC: usize = 4;
const SK_MEMINFO_WMEM_QUEUED: usize = 5;
const SK_MEMINFO_OPTMEM: usize = 6;
const SK_MEMINFO_BACKLOG: usize = 7;
const SK_MEMINFO_DROPS: usize = 8;
const NLA_TYPE_MASK: u16 = 0x3fff;
const INET_DIAG_NOCOOKIE: [u32; 2] = [u32::MAX; 2];

const TCP_INFO_MIN_LEN: usize = 104;
const TCP_INFO_V4_14_LEN: usize = 192;
const TCP_INFO_OPTIONS_OFFSET: usize = 5;
const TCP_INFO_WINDOW_SCALE_OFFSET: usize = 6;
const TCP_INFO_APP_LIMITED_OFFSET: usize = 7;
const TCP_INFO_RTO_OFFSET: usize = 8;
const TCP_INFO_ATO_OFFSET: usize = 12;
const TCP_INFO_SND_MSS_OFFSET: usize = 16;
const TCP_INFO_RCV_MSS_OFFSET: usize = 20;
const TCP_INFO_UNACKED_OFFSET: usize = 24;
const TCP_INFO_SACKED_OFFSET: usize = 28;
const TCP_INFO_LOST_OFFSET: usize = 32;
const TCP_INFO_RETRANS_OFFSET: usize = 36;
const TCP_INFO_FACKETS_OFFSET: usize = 40;
const TCP_INFO_LAST_DATA_SENT_OFFSET: usize = 44;
const TCP_INFO_LAST_ACK_SENT_OFFSET: usize = 48;
const TCP_INFO_LAST_DATA_RECEIVED_OFFSET: usize = 52;
const TCP_INFO_LAST_ACK_RECEIVED_OFFSET: usize = 56;
const TCP_INFO_PMTU_OFFSET: usize = 60;
const TCP_INFO_RCV_SSTHRESH_OFFSET: usize = 64;
const TCP_INFO_RTT_OFFSET: usize = 68;
const TCP_INFO_RTTVAR_OFFSET: usize = 72;
const TCP_INFO_SND_SSTHRESH_OFFSET: usize = 76;
const TCP_INFO_SND_CWND_OFFSET: usize = 80;
const TCP_INFO_ADVMSS_OFFSET: usize = 84;
const TCP_INFO_REORDERING_OFFSET: usize = 88;
const TCP_INFO_RCV_RTT_OFFSET: usize = 92;
const TCP_INFO_RCV_SPACE_OFFSET: usize = 96;
const TCP_INFO_TOTAL_RETRANS_OFFSET: usize = 100;
const TCP_INFO_PACING_RATE_OFFSET: usize = 104;
const TCP_INFO_MAX_PACING_RATE_OFFSET: usize = 112;
const TCP_INFO_BYTES_ACKED_OFFSET: usize = 120;
const TCP_INFO_BYTES_RECEIVED_OFFSET: usize = 128;
const TCP_INFO_SEGS_OUT_OFFSET: usize = 136;
const TCP_INFO_SEGS_IN_OFFSET: usize = 140;
const TCP_INFO_NOTSENT_BYTES_OFFSET: usize = 144;
const TCP_INFO_MIN_RTT_OFFSET: usize = 148;
const TCP_INFO_DATA_SEGS_IN_OFFSET: usize = 152;
const TCP_INFO_DATA_SEGS_OUT_OFFSET: usize = 156;
const TCP_INFO_DELIVERY_RATE_OFFSET: usize = 160;
const TCP_INFO_BUSY_TIME_OFFSET: usize = 168;
const TCP_INFO_RWND_LIMITED_OFFSET: usize = 176;
const TCP_INFO_SNDBUF_LIMITED_OFFSET: usize = 184;
// Later kernels append other counters before adding the two window fields.
const TCP_INFO_SND_WND_OFFSET: usize = 228;
const TCP_INFO_RCV_WND_OFFSET: usize = 232;

const TCP_INFO_OPTION_WINDOW_SCALE: u8 = 1 << 2;

const QUERY_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Query {
    family: u8,
    protocol: u8,
}

impl Query {
    const IPV4_TCP: Self = Self {
        family: libc::AF_INET as u8,
        protocol: libc::IPPROTO_TCP as u8,
    };

    const IPV6_UDP: Self = Self {
        family: libc::AF_INET6 as u8,
        protocol: libc::IPPROTO_UDP as u8,
    };

    const IPV4_UDP: Self = Self {
        family: libc::AF_INET as u8,
        protocol: libc::IPPROTO_UDP as u8,
    };

    const IPV6_TCP: Self = Self {
        family: libc::AF_INET6 as u8,
        protocol: libc::IPPROTO_TCP as u8,
    };

    const ALL: [Self; QUERY_COUNT] = [
        Self::IPV4_TCP,
        Self::IPV4_UDP,
        Self::IPV6_TCP,
        Self::IPV6_UDP,
    ];

    const fn label(self) -> &'static str {
        match (self.family as i32, self.protocol as i32) {
            (libc::AF_INET, libc::IPPROTO_TCP) => "IPv4 TCP",
            (libc::AF_INET, libc::IPPROTO_UDP) => "IPv4 UDP",
            (libc::AF_INET6, libc::IPPROTO_TCP) => "IPv6 TCP",
            (libc::AF_INET6, libc::IPPROTO_UDP) => "IPv6 UDP",
            _ => "unsupported socket query",
        }
    }

    const fn family(self) -> SocketFamily {
        match self.family as i32 {
            libc::AF_INET => SocketFamily::Ipv4,
            libc::AF_INET6 => SocketFamily::Ipv6,
            _ => unreachable!(),
        }
    }

    const fn protocol(self) -> SocketProtocol {
        match self.protocol as i32 {
            libc::IPPROTO_TCP => SocketProtocol::Tcp,
            libc::IPPROTO_UDP => SocketProtocol::Udp,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SocketEndpoint {
    pub(crate) address: IpAddr,
    pub(crate) port: u16,
}

impl fmt::Debug for SocketEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketEndpoint(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketMemory {
    pub(crate) receive_allocated: u32,
    pub(crate) receive_limit: u32,
    pub(crate) send_allocated: u32,
    pub(crate) send_limit: u32,
    pub(crate) forward_allocated: u32,
    pub(crate) send_queued: u32,
    pub(crate) option_memory: u32,
    pub(crate) backlog: u32,
    pub(crate) drops: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SocketTcpInfo {
    pub(crate) state: u8,
    pub(crate) congestion_state: u8,
    pub(crate) retransmit_timeouts: u8,
    pub(crate) probes: u8,
    pub(crate) backoff: u8,
    pub(crate) options: u8,
    pub(crate) send_window_scale: Option<u8>,
    pub(crate) receive_window_scale: Option<u8>,
    pub(crate) delivery_rate_app_limited: bool,
    pub(crate) retransmission_timeout_micros: u32,
    pub(crate) ack_timeout_micros: u32,
    pub(crate) send_mss_bytes: u32,
    pub(crate) receive_mss_bytes: u32,
    pub(crate) unacked_segments: u32,
    pub(crate) sacked_segments: u32,
    pub(crate) lost_segments: u32,
    pub(crate) retransmitted_segments: u32,
    pub(crate) fackets: u32,
    pub(crate) last_data_sent_millis: u32,
    pub(crate) last_ack_sent_millis: u32, // Linux 4.14 does not populate this field.
    pub(crate) last_data_received_millis: u32,
    pub(crate) last_ack_received_millis: u32,
    pub(crate) path_mtu_bytes: u32,
    pub(crate) receive_ssthresh_bytes: u32,
    pub(crate) rtt_micros: u32,
    pub(crate) rtt_variance_micros: u32,
    // TCP_INFINITE_SSTHRESH (0x7fff_ffff) means no finite threshold yet.
    pub(crate) send_ssthresh_segments: u32,
    pub(crate) send_cwnd_segments: u32,
    pub(crate) advertised_mss_bytes: u32,
    pub(crate) reordering_segments: u32,
    pub(crate) receive_rtt_micros: u32,
    // Receive-buffer autotuning sample, not the current advertised receive window.
    pub(crate) receive_space_bytes: u32,
    pub(crate) total_retransmitted_segments: u32,
    // u64::MAX is the kernel's unlimited-rate sentinel.
    pub(crate) pacing_rate_bytes_per_second: Option<u64>,
    pub(crate) max_pacing_rate_bytes_per_second: Option<u64>,
    pub(crate) bytes_acked: Option<u64>,
    pub(crate) bytes_received: Option<u64>,
    pub(crate) segments_out: Option<u32>,
    pub(crate) segments_in: Option<u32>,
    pub(crate) notsent_bytes: Option<u32>,
    // u32::MAX is the kernel's no-sample sentinel.
    pub(crate) min_rtt_micros: Option<u32>,
    pub(crate) data_segments_in: Option<u32>,
    pub(crate) data_segments_out: Option<u32>,
    pub(crate) delivery_rate_bytes_per_second: Option<u64>,
    pub(crate) busy_time_micros: Option<u64>,
    pub(crate) receive_window_limited_micros: Option<u64>,
    pub(crate) send_buffer_limited_micros: Option<u64>,
    // Peer's advertised receive window after scaling; absent before Linux 5.4.
    pub(crate) send_window_bytes: Option<u32>,
    // Local advertised receive window after scaling; absent before Linux 6.2.
    pub(crate) receive_window_bytes: Option<u32>,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct SocketIdentity {
    family: u8,
    protocol: u8,
    cookie: [u32; 2],
    inode: u32,
}

impl SocketIdentity {
    pub(crate) fn is_matchable(&self) -> bool {
        self.cookie != INET_DIAG_NOCOOKIE && self.inode != 0
    }

    pub(crate) const fn inode(&self) -> u32 {
        self.inode
    }

    #[cfg(test)]
    pub(crate) fn synthetic_reusing_inode(&self, cookie: u32) -> Self {
        let mut replacement = self.clone();
        replacement.cookie = [cookie, cookie.wrapping_mul(17)];
        replacement
    }

    #[cfg(test)]
    pub(crate) const fn synthetic(
        family: SocketFamily,
        protocol: SocketProtocol,
        seed: u32,
    ) -> Self {
        Self {
            family: match family {
                SocketFamily::Ipv4 => libc::AF_INET as u8,
                SocketFamily::Ipv6 => libc::AF_INET6 as u8,
            },
            protocol: match protocol {
                SocketProtocol::Tcp => libc::IPPROTO_TCP as u8,
                SocketProtocol::Udp => libc::IPPROTO_UDP as u8,
            },
            cookie: [seed, seed.wrapping_mul(17)],
            inode: seed.wrapping_add(100),
        }
    }
}

impl fmt::Debug for SocketIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketIdentity(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SocketDropSample {
    pub(crate) identity: SocketIdentity,
    pub(crate) drops: Option<u32>,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct RawSocket {
    pub(crate) identity: SocketIdentity,
    pub(crate) family: SocketFamily,
    pub(crate) protocol: SocketProtocol,
    pub(crate) state: u8,
    pub(crate) timer: u8,
    pub(crate) retransmits: u8,
    pub(crate) local: SocketEndpoint,
    pub(crate) remote: SocketEndpoint,
    pub(crate) bound_ifindex: u32,
    pub(crate) expires_millis: u32,
    pub(crate) receive_queue: u32,
    pub(crate) send_queue: u32,
    pub(crate) uid: u32,
    pub(crate) memory: Option<SocketMemory>,
    pub(crate) tcp_info: Option<SocketTcpInfo>,
    pub(crate) congestion_algorithm: Option<String>,
}

impl fmt::Debug for RawSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawSocket(<redacted>)")
    }
}

#[derive(Debug)]
pub(crate) struct SocketTableCollection {
    pub(crate) queries: Vec<SocketTableQueryResult>,
}

#[derive(Debug)]
pub(crate) struct SocketTableQueryResult {
    pub(crate) family: SocketFamily,
    pub(crate) protocol: SocketProtocol,
    pub(crate) completed_at: Instant,
    pub(crate) observed_sockets: usize,
    pub(crate) truncated: bool,
    pub(crate) outcome: Result<Vec<RawSocket>, CollectError>,
}

impl fmt::Debug for SocketDropSample {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketDropSample")
            .field("identity", &self.identity)
            .field("drops", &self.drops)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SockDiagProbe {
    pub completed_queries: usize,
    pub unsupported_queries: usize,
    pub socket_count: usize,
    pub sockets_without_skmeminfo: usize,
}

#[derive(Debug)]
pub(crate) struct SockDiagSnapshot {
    pub(crate) queries: Vec<SockDiagQueryResult>,
}

#[derive(Debug)]
pub(crate) struct SockDiagQueryResult {
    query: Query,
    pub(crate) outcome: Result<SockDiagDump, CollectError>,
}

#[derive(Debug)]
pub(crate) struct SockDiagDump {
    pub(crate) samples: Vec<SocketDropSample>,
    sockets: Vec<RawSocket>,
    observed_sockets: usize,
    table_truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SocketDropDelta {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) delta: Option<u64>,
    pub(crate) reset: bool,
}

#[derive(Debug, Default)]
pub(crate) struct SockDiagDeltaReport {
    pub(crate) deltas: Vec<SocketDropDelta>,
    pub(crate) errors: Vec<String>,
    pub(crate) completed_query_pairs: usize,
    pub(crate) sockets_without_skmeminfo: usize,
    pub(crate) netlink_loss_events: u64,
    pub(crate) netlink_dump_interruptions: u64,
    pub(crate) parse_errors: u64,
}

impl SockDiagDeltaReport {
    pub(crate) fn is_complete(&self) -> bool {
        self.completed_query_pairs == QUERY_COUNT
            && self.errors.is_empty()
            && self.sockets_without_skmeminfo == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectErrorKind {
    PermissionDenied,
    Unsupported,
    Io,
    Loss,
    Interrupted,
    Malformed,
}

#[derive(Debug)]
pub(crate) struct CollectError {
    kind: CollectErrorKind,
    message: String,
}

impl CollectError {
    fn io(context: &str, error: io::Error) -> Self {
        let kind = match error.raw_os_error() {
            Some(libc::EPERM | libc::EACCES) => CollectErrorKind::PermissionDenied,
            Some(libc::EOPNOTSUPP | libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT | libc::ENOENT) => {
                CollectErrorKind::Unsupported
            }
            _ => CollectErrorKind::Io,
        };
        Self {
            kind,
            message: format!("{context}: {error}"),
        }
    }

    fn loss(message: impl Into<String>) -> Self {
        Self {
            kind: CollectErrorKind::Loss,
            message: message.into(),
        }
    }

    fn interrupted(message: impl Into<String>) -> Self {
        Self {
            kind: CollectErrorKind::Interrupted,
            message: message.into(),
        }
    }

    fn parse(message: impl Into<String>) -> Self {
        Self {
            kind: CollectErrorKind::Malformed,
            message: message.into(),
        }
    }

    fn for_query(mut self, query: Query) -> Self {
        self.message = format!("{} dump: {}", query.label(), self.message);
        self
    }

    pub(crate) const fn kind(&self) -> CollectErrorKind {
        self.kind
    }

    const fn loss_events(&self) -> u64 {
        matches!(self.kind, CollectErrorKind::Loss) as u64
    }

    const fn dumps_interrupted(&self) -> u64 {
        matches!(self.kind, CollectErrorKind::Interrupted) as u64
    }

    const fn parse_errors(&self) -> u64 {
        matches!(self.kind, CollectErrorKind::Malformed) as u64
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub(crate) fn collect_current_namespace() -> SockDiagSnapshot {
    collect_with(collect_query)
}

#[cfg(test)]
pub(crate) fn collect_table_current_namespace() -> SocketTableCollection {
    collect_table_current_namespace_with(None)
        .expect("a socket table collection without a cancellation token cannot be cancelled")
}

#[cfg(test)]
pub(crate) fn collect_table_current_namespace_until(
    cancelled: &AtomicBool,
) -> Option<SocketTableCollection> {
    collect_table_current_namespace_with(Some(cancelled))
}

#[cfg(test)]
fn collect_table_current_namespace_with(
    cancelled: Option<&AtomicBool>,
) -> Option<SocketTableCollection> {
    Context::default().collect_table(cancelled)
}

#[derive(Default)]
pub(crate) struct Context {
    socket: Option<DiagSocket>,
    buffer: Vec<u8>,
    sequence: u32,
}

impl Context {
    pub(crate) fn collect_table(
        &mut self,
        cancelled: Option<&AtomicBool>,
    ) -> Option<SocketTableCollection> {
        let mut queries = Vec::with_capacity(QUERY_COUNT);
        for query in Query::ALL {
            if is_cancelled(cancelled) {
                self.socket = None;
                return None;
            }
            let collected = self.query(query, true, cancelled);
            let completed_at = Instant::now();
            let outcome = match collected {
                Ok(Some(dump)) => SocketTableQueryResult {
                    family: query.family(),
                    protocol: query.protocol(),
                    completed_at,
                    observed_sockets: dump.observed_sockets,
                    truncated: dump.table_truncated,
                    outcome: Ok(dump.sockets),
                },
                Ok(None) => return None,
                Err(error) => SocketTableQueryResult {
                    family: query.family(),
                    protocol: query.protocol(),
                    completed_at,
                    observed_sockets: 0,
                    truncated: false,
                    outcome: Err(error.for_query(query)),
                },
            };
            queries.push(outcome);
        }
        Some(SocketTableCollection { queries })
    }
}

fn is_cancelled(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
}

pub(crate) fn calculate_deltas(
    start: SockDiagSnapshot,
    end: SockDiagSnapshot,
) -> SockDiagDeltaReport {
    let mut report = SockDiagDeltaReport::default();
    for (start, end) in start.queries.into_iter().zip(end.queries) {
        assert_eq!(
            start.query, end.query,
            "sock_diag snapshots use the same fixed query order"
        );
        match (start.outcome, end.outcome) {
            (Ok(start), Ok(end)) => {
                report.completed_query_pairs += 1;
                report.sockets_without_skmeminfo = report.sockets_without_skmeminfo.saturating_add(
                    start
                        .samples
                        .iter()
                        .chain(&end.samples)
                        .filter(|sample| sample.drops.is_none())
                        .count(),
                );
                match_dump_samples(&start.samples, &end.samples, &mut report.deltas);
            }
            (start, end) => {
                if let Err(error) = start {
                    account_delta_error("start", error, &mut report);
                }
                if let Err(error) = end {
                    account_delta_error("end", error, &mut report);
                }
            }
        }
    }
    report
}

fn match_dump_samples(
    start: &[SocketDropSample],
    end: &[SocketDropSample],
    deltas: &mut Vec<SocketDropDelta>,
) {
    let (mut start_index, mut end_index) = (0, 0);
    while let (Some(before), Some(after)) = (start.get(start_index), end.get(end_index)) {
        match before.identity.cmp(&after.identity) {
            std::cmp::Ordering::Less => start_index += 1,
            std::cmp::Ordering::Greater => end_index += 1,
            std::cmp::Ordering::Equal => {
                if before.identity.is_matchable() {
                    if let (Some(before), Some(after)) = (before.drops, after.drops) {
                        if after > before {
                            deltas.push(SocketDropDelta {
                                start: u64::from(before),
                                end: u64::from(after),
                                delta: Some(u64::from(after - before)),
                                reset: false,
                            });
                        } else if after < before {
                            // A 32-bit wrap and an exact identity reuse are indistinguishable
                            // across two dumps, so a decrease cannot produce a drop delta.
                            deltas.push(SocketDropDelta {
                                start: u64::from(before),
                                end: u64::from(after),
                                delta: None,
                                reset: true,
                            });
                        }
                    }
                }
                start_index += 1;
                end_index += 1;
            }
        }
    }
}

fn account_delta_error(phase: &str, error: CollectError, report: &mut SockDiagDeltaReport) {
    report.netlink_loss_events = report
        .netlink_loss_events
        .saturating_add(error.loss_events());
    report.netlink_dump_interruptions = report
        .netlink_dump_interruptions
        .saturating_add(error.dumps_interrupted());
    report.parse_errors = report.parse_errors.saturating_add(error.parse_errors());
    report.errors.push(format!("{phase} snapshot: {error}"));
}

fn collect_with(
    mut collector: impl FnMut(Query) -> Result<SockDiagDump, CollectError>,
) -> SockDiagSnapshot {
    SockDiagSnapshot {
        queries: Query::ALL
            .into_iter()
            .map(|query| SockDiagQueryResult {
                query,
                outcome: collector(query).map_err(|error| error.for_query(query)),
            })
            .collect(),
    }
}

pub(crate) fn probe() -> Result<SockDiagProbe, String> {
    let snapshot = collect_current_namespace();
    let fatal_errors: Vec<_> = snapshot
        .queries
        .iter()
        .filter_map(|result| match &result.outcome {
            Err(error)
                if result.query.family == libc::AF_INET6 as u8
                    && matches!(error.kind, CollectErrorKind::Unsupported) =>
            {
                None
            }
            Err(error) => Some(error),
            Ok(_) => None,
        })
        .collect();
    if !fatal_errors.is_empty() {
        let details = fatal_errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        let netlink_loss_events = fatal_errors
            .iter()
            .map(|error| error.loss_events())
            .sum::<u64>();
        let interrupted_dumps = fatal_errors
            .iter()
            .map(|error| error.dumps_interrupted())
            .sum::<u64>();
        let parse_errors = fatal_errors
            .iter()
            .map(|error| error.parse_errors())
            .sum::<u64>();
        return Err(format!(
            "completed {}/{} socket diagnostic dumps; netlink loss events: {}; interrupted dumps: {}; parse errors: {}; {details}",
            snapshot
                .queries
                .iter()
                .filter(|result| result.outcome.is_ok())
                .count(),
            QUERY_COUNT,
            netlink_loss_events,
            interrupted_dumps,
            parse_errors,
        ));
    }

    let dumps: Vec<_> = snapshot
        .queries
        .iter()
        .filter_map(|result| result.outcome.as_ref().ok())
        .collect();
    Ok(SockDiagProbe {
        completed_queries: dumps.len(),
        unsupported_queries: snapshot
            .queries
            .iter()
            .filter(|result| {
                matches!(
                    &result.outcome,
                    Err(CollectError {
                        kind: CollectErrorKind::Unsupported,
                        ..
                    })
                )
            })
            .count(),
        socket_count: dumps.iter().map(|dump| dump.samples.len()).sum(),
        sockets_without_skmeminfo: dumps
            .iter()
            .flat_map(|dump| &dump.samples)
            .filter(|sample| sample.drops.is_none())
            .count(),
    })
}

fn collect_query(query: Query) -> Result<SockDiagDump, CollectError> {
    Context::default().query(query, false, None).map(|dump| {
        dump.expect("a socket diagnostic query without a cancellation token cannot be cancelled")
    })
}

impl Context {
    fn query(
        &mut self,
        query: Query,
        retain_table: bool,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Option<SockDiagDump>, CollectError> {
        if is_cancelled(cancelled) {
            self.socket = None;
            return Ok(None);
        }
        let socket = match self.socket.take() {
            Some(socket) => socket,
            None => open_socket()?,
        };
        self.sequence = self.sequence.wrapping_add(1).max(1);
        send_request(&socket, query, retain_table, self.sequence)?;

        let mut parser = if retain_table {
            DumpParser::new_table(query)
        } else {
            DumpParser::new(query)
        };
        self.buffer.resize(RECEIVE_BUFFER_LEN, 0);
        while !parser.done {
            let received = if let Some(cancelled) = cancelled {
                let Some(received) = receive_datagram_until(&socket, &mut self.buffer, cancelled)?
                else {
                    return Ok(None);
                };
                received
            } else {
                receive_datagram(&socket, &mut self.buffer)?
            };
            parser.parse_datagram(&self.buffer[..received], self.sequence, socket.port_id)?;
        }
        let dump = parser.finish()?;
        // Only a fully validated dump may leave a channel available for reuse.
        self.socket = Some(socket);
        Ok(Some(dump))
    }
}

struct DiagSocket {
    fd: OwnedFd,
    port_id: u32,
}

fn open_socket() -> Result<DiagSocket, CollectError> {
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw_fd < 0 {
        return Err(CollectError::io(
            "create NETLINK_SOCK_DIAG socket",
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
            "bind NETLINK_SOCK_DIAG socket",
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
            "read NETLINK_SOCK_DIAG port ID",
            io::Error::last_os_error(),
        ));
    }
    if bound_address_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
        || bound_address.nl_family != libc::AF_NETLINK as libc::sa_family_t
        || bound_address.nl_pid == 0
    {
        return Err(CollectError::parse(
            "NETLINK_SOCK_DIAG socket has an invalid local address",
        ));
    }

    let timeval = libc::timeval {
        tv_sec: RECEIVE_TIMEOUT.as_secs() as _,
        tv_usec: RECEIVE_TIMEOUT.subsec_micros() as _,
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
            "set NETLINK_SOCK_DIAG receive timeout",
            io::Error::last_os_error(),
        ));
    }

    Ok(DiagSocket {
        fd,
        port_id: bound_address.nl_pid,
    })
}

fn send_request(
    socket: &DiagSocket,
    query: Query,
    include_tcp_info: bool,
    sequence: u32,
) -> Result<(), CollectError> {
    let request = build_request_with_tcp_info(query, sequence, socket.port_id, include_tcp_info);
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
                    "send SOCK_DIAG_BY_FAMILY request",
                    io::Error::new(io::ErrorKind::WriteZero, "short netlink datagram write"),
                ));
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(CollectError::io("send SOCK_DIAG_BY_FAMILY request", error));
        }
    }
}

fn receive_datagram(socket: &DiagSocket, buffer: &mut [u8]) -> Result<usize, CollectError> {
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
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) {
                return Err(CollectError::interrupted(
                    "NETLINK_SOCK_DIAG timed out before NLMSG_DONE",
                ));
            }
            if error.raw_os_error() == Some(libc::ENOBUFS) {
                return Err(CollectError::loss(
                    "NETLINK_SOCK_DIAG receive queue overflowed; socket dump is incomplete",
                ));
            }
            return Err(CollectError::io(
                "receive NETLINK_SOCK_DIAG response",
                error,
            ));
        }
        let received = received as usize;
        if received == 0 {
            return Err(CollectError::interrupted(
                "NETLINK_SOCK_DIAG ended before NLMSG_DONE",
            ));
        }
        if received > buffer.len() {
            return Err(CollectError::loss(format!(
                "NETLINK_SOCK_DIAG datagram needs {received} bytes, exceeding the {}-byte receive buffer",
                buffer.len()
            )));
        }
        if source_len < size_of::<libc::sockaddr_nl>() as libc::socklen_t
            || source.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || source.nl_pid != 0
            || source.nl_groups != 0
        {
            return Err(CollectError::parse(
                "SOCK_DIAG_BY_FAMILY response did not originate from the kernel",
            ));
        }
        return Ok(received);
    }
}

fn receive_datagram_until(
    socket: &DiagSocket,
    buffer: &mut [u8],
    cancelled: &AtomicBool,
) -> Result<Option<usize>, CollectError> {
    let deadline = Instant::now() + RECEIVE_TIMEOUT;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CollectError::interrupted(
                "NETLINK_SOCK_DIAG timed out before NLMSG_DONE",
            ));
        }
        let wait = remaining.min(CANCEL_POLL_INTERVAL);
        let timeout_millis = wait.as_millis().max(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: socket.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(std::ptr::from_mut(&mut descriptor), 1, timeout_millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(CollectError::io(
                "wait for NETLINK_SOCK_DIAG response",
                error,
            ));
        }
        if ready == 0 {
            continue;
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(CollectError::io(
                "wait for NETLINK_SOCK_DIAG response",
                io::Error::from_raw_os_error(libc::EBADF),
            ));
        }
        return receive_datagram(socket, buffer).map(Some);
    }
}

fn build_request(
    query: Query,
    sequence: u32,
    port_id: u32,
) -> [u8; NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN] {
    build_request_with_tcp_info(query, sequence, port_id, false)
}

fn build_request_with_tcp_info(
    query: Query,
    sequence: u32,
    port_id: u32,
    include_tcp_info: bool,
) -> [u8; NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN] {
    let mut request = [0_u8; NLMSG_HEADER_LEN + INET_DIAG_REQ_V2_LEN];
    let request_len = request.len() as u32;
    put_u32(&mut request[0..4], request_len);
    put_u16(&mut request[4..6], SOCK_DIAG_BY_FAMILY);
    put_u16(
        &mut request[6..8],
        (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
    );
    put_u32(&mut request[8..12], sequence);
    put_u32(&mut request[12..16], port_id);
    request[16] = query.family;
    request[17] = query.protocol;
    request[18] = 1 << (INET_DIAG_SKMEMINFO - 1);
    if include_tcp_info {
        request[18] |= 1 << (INET_DIAG_INFO - 1);
        if query.protocol == libc::IPPROTO_TCP as u8 {
            request[18] |= 1 << (INET_DIAG_CONG - 1);
        }
    }
    put_u32(&mut request[20..24], u32::MAX);
    request
}

struct DumpParser {
    query: Query,
    samples: Vec<SocketDropSample>,
    sockets: Vec<RawSocket>,
    retain_table: bool,
    sample_limit: usize,
    observed_sockets: usize,
    table_truncated: bool,
    done: bool,
}

impl DumpParser {
    fn new(query: Query) -> Self {
        Self {
            query,
            samples: Vec::new(),
            sockets: Vec::new(),
            retain_table: false,
            sample_limit: MAX_SAMPLES_PER_QUERY,
            observed_sockets: 0,
            table_truncated: false,
            done: false,
        }
    }

    fn new_table(query: Query) -> Self {
        Self {
            retain_table: true,
            sample_limit: MAX_TABLE_SAMPLES_PER_QUERY,
            ..Self::new(query)
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
            if self.done {
                return Err(CollectError::parse(
                    "SOCK_DIAG_BY_FAMILY response contains a message after NLMSG_DONE",
                ));
            }
            if datagram.len() - offset < NLMSG_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated netlink message header in SOCK_DIAG_BY_FAMILY response",
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
                    "invalid netlink message length {message_len} in {}-byte SOCK_DIAG_BY_FAMILY remainder",
                    datagram.len() - offset
                )));
            }
            if message_sequence != sequence {
                return Err(CollectError::parse(format!(
                    "unexpected netlink sequence {message_sequence}; expected {sequence}"
                )));
            }
            if sender_port != port_id {
                return Err(CollectError::parse(
                    "unexpected netlink destination port ID in SOCK_DIAG_BY_FAMILY response",
                ));
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                return Err(CollectError::interrupted(
                    "kernel interrupted the SOCK_DIAG_BY_FAMILY dump; socket data is incomplete",
                ));
            }

            let payload = &datagram[offset + NLMSG_HEADER_LEN..offset + message_len];
            match message_type {
                NLMSG_NOOP => {}
                NLMSG_ERROR => parse_netlink_error(payload)?,
                NLMSG_DONE => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(CollectError::parse(
                            "SOCK_DIAG_BY_FAMILY NLMSG_DONE response is not multipart",
                        ));
                    }
                    parse_done_error(payload)?;
                    self.done = true;
                }
                NLMSG_OVERRUN => {
                    return Err(CollectError::loss(
                        "kernel reported a NETLINK_SOCK_DIAG overrun; socket dump is incomplete",
                    ));
                }
                SOCK_DIAG_BY_FAMILY => {
                    if flags & NLM_F_MULTI == 0 {
                        return Err(CollectError::parse(
                            "SOCK_DIAG_BY_FAMILY dump response is not multipart",
                        ));
                    }
                    self.parse_socket(payload)?;
                }
                _ => {
                    return Err(CollectError::parse(format!(
                        "unexpected netlink message type {message_type} in SOCK_DIAG_BY_FAMILY response"
                    )));
                }
            }

            let aligned_len = align(message_len);
            if aligned_len > datagram.len() - offset {
                return Err(CollectError::parse(
                    "truncated netlink message alignment padding in SOCK_DIAG_BY_FAMILY response",
                ));
            } else {
                offset += aligned_len;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<SockDiagDump, CollectError> {
        if self.done {
            self.samples
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            if self
                .samples
                .windows(2)
                .any(|pair| pair[0].identity == pair[1].identity)
            {
                return Err(CollectError::parse(
                    "SOCK_DIAG_BY_FAMILY dump contains a duplicate private socket identity",
                ));
            }
            self.sockets
                .sort_by(|left, right| left.identity.cmp(&right.identity));
            if self
                .sockets
                .windows(2)
                .any(|pair| pair[0].identity == pair[1].identity)
            {
                return Err(CollectError::parse(
                    "SOCK_DIAG_BY_FAMILY dump contains a duplicate private socket identity",
                ));
            }
            Ok(SockDiagDump {
                samples: self.samples,
                sockets: self.sockets,
                observed_sockets: self.observed_sockets,
                table_truncated: self.table_truncated,
            })
        } else {
            Err(CollectError::interrupted(
                "SOCK_DIAG_BY_FAMILY response ended without NLMSG_DONE",
            ))
        }
    }

    fn parse_socket(&mut self, payload: &[u8]) -> Result<(), CollectError> {
        if payload.len() < INET_DIAG_MSG_LEN {
            return Err(CollectError::parse(format!(
                "SOCK_DIAG_BY_FAMILY payload has {} bytes; expected at least {INET_DIAG_MSG_LEN}",
                payload.len()
            )));
        }
        if payload[0] != self.query.family {
            return Err(CollectError::parse(format!(
                "SOCK_DIAG_BY_FAMILY response family {} does not match requested family {}",
                payload[0], self.query.family
            )));
        }

        let identity = SocketIdentity {
            family: self.query.family,
            protocol: self.query.protocol,
            cookie: [read_u32(&payload[44..48]), read_u32(&payload[48..52])],
            inode: read_u32(&payload[68..72]),
        };
        let retain_table_socket = self.retain_table && self.sockets.len() < self.sample_limit;
        if self.retain_table {
            self.observed_sockets = self.observed_sockets.saturating_add(1);
            self.table_truncated |= !retain_table_socket;
        } else if self.samples.len() >= self.sample_limit {
            return Err(CollectError::loss(format!(
                "SOCK_DIAG_BY_FAMILY dump exceeds the {}-socket safety limit",
                self.sample_limit
            )));
        }

        let mut drops = None;
        let mut memory = None;
        let mut tcp_info = None;
        let mut congestion_algorithm = None;
        let mut offset = INET_DIAG_MSG_LEN;
        while offset < payload.len() {
            if payload.len() - offset < RTATTR_HEADER_LEN {
                return Err(CollectError::parse(
                    "truncated SOCK_DIAG_BY_FAMILY attribute header",
                ));
            }
            let attribute_len = read_u16(&payload[offset..offset + 2]) as usize;
            let raw_attribute_type = read_u16(&payload[offset + 2..offset + 4]);
            let attribute_type = raw_attribute_type & NLA_TYPE_MASK;
            if attribute_len < RTATTR_HEADER_LEN || attribute_len > payload.len() - offset {
                return Err(CollectError::parse(format!(
                    "invalid SOCK_DIAG_BY_FAMILY attribute length {attribute_len}"
                )));
            }
            let value = &payload[offset + RTATTR_HEADER_LEN..offset + attribute_len];
            if attribute_type == INET_DIAG_SKMEMINFO {
                if raw_attribute_type != INET_DIAG_SKMEMINFO {
                    return Err(CollectError::parse(
                        "INET_DIAG_SKMEMINFO uses unsupported netlink attribute flags",
                    ));
                }
                if drops.is_some() {
                    return Err(CollectError::parse(
                        "SOCK_DIAG_BY_FAMILY response contains duplicate INET_DIAG_SKMEMINFO attributes",
                    ));
                }
                let parsed = parse_skmeminfo(value)?;
                drops = Some(parsed.drops);
                if self.retain_table {
                    memory = Some(parsed);
                }
            } else if attribute_type == INET_DIAG_INFO && self.retain_table {
                if raw_attribute_type != INET_DIAG_INFO {
                    return Err(CollectError::parse(
                        "INET_DIAG_INFO uses unsupported netlink attribute flags",
                    ));
                }
                if tcp_info.is_some() {
                    return Err(CollectError::parse(
                        "SOCK_DIAG_BY_FAMILY response contains duplicate INET_DIAG_INFO attributes",
                    ));
                }
                if self.query.protocol != libc::IPPROTO_TCP as u8 {
                    return Err(CollectError::parse(
                        "non-TCP SOCK_DIAG_BY_FAMILY response contains INET_DIAG_INFO",
                    ));
                }
                tcp_info = Some(parse_tcp_info(value)?);
            } else if attribute_type == INET_DIAG_CONG && self.retain_table {
                if raw_attribute_type != INET_DIAG_CONG {
                    return Err(CollectError::parse(
                        "INET_DIAG_CONG uses unsupported netlink attribute flags",
                    ));
                }
                if congestion_algorithm.is_some() {
                    return Err(CollectError::parse(
                        "SOCK_DIAG_BY_FAMILY response contains duplicate INET_DIAG_CONG attributes",
                    ));
                }
                if self.query.protocol != libc::IPPROTO_TCP as u8 {
                    return Err(CollectError::parse(
                        "non-TCP SOCK_DIAG_BY_FAMILY response contains INET_DIAG_CONG",
                    ));
                }
                congestion_algorithm = Some(parse_congestion_algorithm(value)?);
            }

            let aligned_len = align(attribute_len);
            if aligned_len > payload.len() - offset {
                return Err(CollectError::parse(
                    "truncated SOCK_DIAG_BY_FAMILY attribute alignment padding",
                ));
            } else {
                offset += aligned_len;
            }
        }

        if retain_table_socket {
            self.sockets.push(RawSocket {
                identity,
                family: self.query.family(),
                protocol: self.query.protocol(),
                state: payload[1],
                timer: payload[2],
                retransmits: payload[3],
                local: parse_endpoint(self.query.family(), &payload[4..6], &payload[8..24]),
                remote: parse_endpoint(self.query.family(), &payload[6..8], &payload[24..40]),
                bound_ifindex: read_u32(&payload[40..44]),
                expires_millis: read_u32(&payload[52..56]),
                receive_queue: read_u32(&payload[56..60]),
                send_queue: read_u32(&payload[60..64]),
                uid: read_u32(&payload[64..68]),
                memory,
                tcp_info,
                congestion_algorithm,
            });
        } else if !self.retain_table {
            self.samples.push(SocketDropSample { identity, drops });
        }
        Ok(())
    }
}

fn parse_endpoint(family: SocketFamily, port: &[u8], address: &[u8]) -> SocketEndpoint {
    let address = match family {
        SocketFamily::Ipv4 => IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        )),
        SocketFamily::Ipv6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(address).expect("IPv6 inet_diag address length is checked"),
        )),
    };
    SocketEndpoint {
        address,
        port: u16::from_be_bytes(
            port.try_into()
                .expect("inet_diag port field length is checked"),
        ),
    }
}

fn parse_skmeminfo(value: &[u8]) -> Result<SocketMemory, CollectError> {
    let minimum_len = (SK_MEMINFO_DROPS + 1) * size_of::<u32>();
    if value.len() < minimum_len || value.len() % size_of::<u32>() != 0 {
        return Err(CollectError::parse(format!(
            "INET_DIAG_SKMEMINFO has {} bytes; expected at least {minimum_len} bytes in u32 fields",
            value.len()
        )));
    }
    let field = |index| {
        let offset = index * size_of::<u32>();
        read_u32(&value[offset..offset + size_of::<u32>()])
    };
    Ok(SocketMemory {
        receive_allocated: field(SK_MEMINFO_RMEM_ALLOC),
        receive_limit: field(SK_MEMINFO_RCVBUF),
        send_allocated: field(SK_MEMINFO_WMEM_ALLOC),
        send_limit: field(SK_MEMINFO_SNDBUF),
        forward_allocated: field(SK_MEMINFO_FWD_ALLOC),
        send_queued: field(SK_MEMINFO_WMEM_QUEUED),
        option_memory: field(SK_MEMINFO_OPTMEM),
        backlog: field(SK_MEMINFO_BACKLOG),
        drops: field(SK_MEMINFO_DROPS),
    })
}

fn parse_congestion_algorithm(value: &[u8]) -> Result<String, CollectError> {
    if !(2..=TCP_CA_NAME_MAX).contains(&value.len()) {
        return Err(CollectError::parse(format!(
            "INET_DIAG_CONG has {} bytes; expected 1-{} name bytes followed by NUL",
            value.len(),
            TCP_CA_NAME_MAX - 1,
        )));
    }
    let Some(name) = value.strip_suffix(&[0]) else {
        return Err(CollectError::parse(
            "INET_DIAG_CONG is not terminated by NUL",
        ));
    };
    if !name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.'))
    {
        return Err(CollectError::parse(
            "INET_DIAG_CONG contains a non-identifier character",
        ));
    }
    Ok(String::from_utf8(name.to_vec())
        .expect("INET_DIAG_CONG identifier validation accepts only ASCII"))
}

fn parse_tcp_info(value: &[u8]) -> Result<SocketTcpInfo, CollectError> {
    if value.len() < TCP_INFO_MIN_LEN {
        return Err(CollectError::parse(format!(
            "INET_DIAG_INFO has {} bytes; expected at least {TCP_INFO_MIN_LEN} bytes",
            value.len()
        )));
    }
    let options = value[TCP_INFO_OPTIONS_OFFSET];
    let (send_window_scale, receive_window_scale) =
        parse_tcp_window_scales(options, value[TCP_INFO_WINDOW_SCALE_OFFSET]);
    let required_u32 = |offset| read_u32(&value[offset..offset + size_of::<u32>()]);
    Ok(SocketTcpInfo {
        state: value[0],
        congestion_state: value[1],
        retransmit_timeouts: value[2],
        probes: value[3],
        backoff: value[4],
        options,
        send_window_scale,
        receive_window_scale,
        delivery_rate_app_limited: tcp_info_single_bit(value[TCP_INFO_APP_LIMITED_OFFSET]),
        retransmission_timeout_micros: required_u32(TCP_INFO_RTO_OFFSET),
        ack_timeout_micros: required_u32(TCP_INFO_ATO_OFFSET),
        send_mss_bytes: required_u32(TCP_INFO_SND_MSS_OFFSET),
        receive_mss_bytes: required_u32(TCP_INFO_RCV_MSS_OFFSET),
        unacked_segments: required_u32(TCP_INFO_UNACKED_OFFSET),
        sacked_segments: required_u32(TCP_INFO_SACKED_OFFSET),
        lost_segments: required_u32(TCP_INFO_LOST_OFFSET),
        retransmitted_segments: required_u32(TCP_INFO_RETRANS_OFFSET),
        fackets: required_u32(TCP_INFO_FACKETS_OFFSET),
        last_data_sent_millis: required_u32(TCP_INFO_LAST_DATA_SENT_OFFSET),
        last_ack_sent_millis: required_u32(TCP_INFO_LAST_ACK_SENT_OFFSET),
        last_data_received_millis: required_u32(TCP_INFO_LAST_DATA_RECEIVED_OFFSET),
        last_ack_received_millis: required_u32(TCP_INFO_LAST_ACK_RECEIVED_OFFSET),
        path_mtu_bytes: required_u32(TCP_INFO_PMTU_OFFSET),
        receive_ssthresh_bytes: required_u32(TCP_INFO_RCV_SSTHRESH_OFFSET),
        rtt_micros: required_u32(TCP_INFO_RTT_OFFSET),
        rtt_variance_micros: required_u32(TCP_INFO_RTTVAR_OFFSET),
        send_ssthresh_segments: required_u32(TCP_INFO_SND_SSTHRESH_OFFSET),
        send_cwnd_segments: required_u32(TCP_INFO_SND_CWND_OFFSET),
        advertised_mss_bytes: required_u32(TCP_INFO_ADVMSS_OFFSET),
        reordering_segments: required_u32(TCP_INFO_REORDERING_OFFSET),
        receive_rtt_micros: required_u32(TCP_INFO_RCV_RTT_OFFSET),
        receive_space_bytes: required_u32(TCP_INFO_RCV_SPACE_OFFSET),
        total_retransmitted_segments: required_u32(TCP_INFO_TOTAL_RETRANS_OFFSET),
        pacing_rate_bytes_per_second: read_optional_u64(value, TCP_INFO_PACING_RATE_OFFSET),
        max_pacing_rate_bytes_per_second: read_optional_u64(value, TCP_INFO_MAX_PACING_RATE_OFFSET),
        bytes_acked: read_optional_u64(value, TCP_INFO_BYTES_ACKED_OFFSET),
        bytes_received: read_optional_u64(value, TCP_INFO_BYTES_RECEIVED_OFFSET),
        segments_out: read_optional_u32(value, TCP_INFO_SEGS_OUT_OFFSET),
        segments_in: read_optional_u32(value, TCP_INFO_SEGS_IN_OFFSET),
        notsent_bytes: read_optional_u32(value, TCP_INFO_NOTSENT_BYTES_OFFSET),
        min_rtt_micros: read_optional_u32(value, TCP_INFO_MIN_RTT_OFFSET),
        data_segments_in: read_optional_u32(value, TCP_INFO_DATA_SEGS_IN_OFFSET),
        data_segments_out: read_optional_u32(value, TCP_INFO_DATA_SEGS_OUT_OFFSET),
        delivery_rate_bytes_per_second: read_optional_u64(value, TCP_INFO_DELIVERY_RATE_OFFSET),
        busy_time_micros: read_optional_u64(value, TCP_INFO_BUSY_TIME_OFFSET),
        receive_window_limited_micros: read_optional_u64(value, TCP_INFO_RWND_LIMITED_OFFSET),
        send_buffer_limited_micros: read_optional_u64(value, TCP_INFO_SNDBUF_LIMITED_OFFSET),
        send_window_bytes: read_optional_u32(value, TCP_INFO_SND_WND_OFFSET),
        receive_window_bytes: read_optional_u32(value, TCP_INFO_RCV_WND_OFFSET),
    })
}

fn parse_tcp_window_scales(options: u8, scales: u8) -> (Option<u8>, Option<u8>) {
    if options & TCP_INFO_OPTION_WINDOW_SCALE == 0 {
        return (None, None);
    }
    if cfg!(target_endian = "little") {
        (Some(scales & 0x0f), Some(scales >> 4))
    } else {
        (Some(scales >> 4), Some(scales & 0x0f))
    }
}

fn tcp_info_single_bit(value: u8) -> bool {
    if cfg!(target_endian = "little") {
        value & 1 != 0
    } else {
        value & (1 << 7) != 0
    }
}

fn read_optional_u32(value: &[u8], offset: usize) -> Option<u32> {
    value.get(offset..offset + size_of::<u32>()).map(read_u32)
}

fn read_optional_u64(value: &[u8], offset: usize) -> Option<u64> {
    value.get(offset..offset + size_of::<u64>()).map(read_u64)
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
            "unexpected netlink ACK for SOCK_DIAG_BY_FAMILY request",
        ));
    }
    if code == i32::MIN || code > 0 {
        return Err(CollectError::parse(format!(
            "NLMSG_ERROR contains invalid errno {code}"
        )));
    }
    Err(CollectError::io(
        "kernel rejected SOCK_DIAG_BY_FAMILY request",
        io::Error::from_raw_os_error(-code),
    ))
}

fn parse_done_error(payload: &[u8]) -> Result<(), CollectError> {
    if payload.len() != size_of::<i32>() {
        return Err(CollectError::parse(
            "NLMSG_DONE payload is not exactly one completion code",
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
            "kernel failed SOCK_DIAG_BY_FAMILY dump",
            io::Error::from_raw_os_error(-code),
        ))
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

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_ne_bytes(bytes.try_into().expect("u64 slice length is checked"))
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
    use std::fs;
    use std::mem::size_of;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    use super::*;

    const SEQUENCE: u32 = 19;
    const PORT_ID: u32 = 0x1234;
    const INET_DIAG_SOCKID_LEN: usize = 48;

    #[test]
    fn diagnostic_context_reuses_complete_queries_and_discards_failed_or_cancelled_channels() {
        let mut context = Context::default();
        let query = Query::ALL[2];
        context.query(query, true, None).unwrap().unwrap();
        let port = context.socket.as_ref().unwrap().port_id;
        let buffer = context.buffer.as_ptr();
        let sequence = context.sequence;
        context.query(query, true, None).unwrap().unwrap();
        assert_eq!(context.socket.as_ref().unwrap().port_id, port);
        assert_eq!(context.buffer.as_ptr(), buffer);
        assert_eq!(context.sequence, sequence + 1);
        let invalid = Query {
            family: 255,
            ..query
        };
        assert!(context.query(invalid, true, None).is_err());
        assert!(context.socket.is_none());
        context.query(query, true, None).unwrap().unwrap();
        assert!(context.socket.is_some());
        let cancelled = AtomicBool::new(true);
        assert!(context.collect_table(Some(&cancelled)).is_none());
        assert!(context.socket.is_none());
        assert_eq!(context.buffer.as_ptr(), buffer);
    }

    #[test]
    fn builds_four_linux_4_14_compatible_skmeminfo_dump_requests() {
        for query in Query::ALL {
            let request = build_request(query, SEQUENCE, PORT_ID);

            assert_eq!(read_u32(&request[0..4]), request.len() as u32);
            assert_eq!(read_u16(&request[4..6]), SOCK_DIAG_BY_FAMILY);
            assert_eq!(
                read_u16(&request[6..8]),
                (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16
            );
            assert_eq!(read_u32(&request[8..12]), SEQUENCE);
            assert_eq!(read_u32(&request[12..16]), PORT_ID);
            assert_eq!(request[16], query.family);
            assert_eq!(request[17], query.protocol);
            assert_eq!(request[18], 1 << (INET_DIAG_SKMEMINFO - 1));
            assert_eq!(request[19], 0);
            assert_eq!(read_u32(&request[20..24]), u32::MAX);
            assert!(request[24..].iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn table_requests_add_tcp_info_and_tcp_congestion_without_changing_drop_requests() {
        for query in Query::ALL {
            let drop_request = build_request(query, SEQUENCE, PORT_ID);
            let table_request = build_request_with_tcp_info(query, SEQUENCE, PORT_ID, true);
            let congestion = if query.protocol == libc::IPPROTO_TCP as u8 {
                1 << (INET_DIAG_CONG - 1)
            } else {
                0
            };

            assert_eq!(
                drop_request[18],
                1 << (INET_DIAG_SKMEMINFO - 1),
                "{}",
                query.label()
            );
            assert_eq!(
                table_request[18],
                (1 << (INET_DIAG_SKMEMINFO - 1)) | (1 << (INET_DIAG_INFO - 1)) | congestion,
                "{}",
                query.label()
            );
            assert_eq!(&drop_request[..18], &table_request[..18]);
            assert_eq!(&drop_request[19..], &table_request[19..]);
        }
    }

    #[test]
    fn table_collection_honors_a_preexisting_cancellation() {
        let cancelled = AtomicBool::new(true);

        assert!(collect_table_current_namespace_until(&cancelled).is_none());
    }

    #[test]
    fn table_parser_decodes_ipv4_base_memory_and_linux_4_14_tcp_info() {
        let mut payload = diag_payload(Query::IPV4_TCP, 0x31);
        payload[1] = 1;
        payload[2] = 4;
        payload[3] = 2;
        payload[4..6].copy_from_slice(&44_321_u16.to_be_bytes());
        payload[6..8].copy_from_slice(&443_u16.to_be_bytes());
        payload[8..12].copy_from_slice(&[192, 0, 2, 10]);
        payload[24..28].copy_from_slice(&[198, 51, 100, 7]);
        payload[40..44].copy_from_slice(&7_u32.to_ne_bytes());
        payload[52..56].copy_from_slice(&1_250_u32.to_ne_bytes());
        payload[56..60].copy_from_slice(&2_048_u32.to_ne_bytes());
        payload[60..64].copy_from_slice(&4_096_u32.to_ne_bytes());
        payload[64..68].copy_from_slice(&1_001_u32.to_ne_bytes());
        push_skmeminfo_values(&mut payload, [11, 12, 13, 14, 15, 16, 17, 18, 19]);
        push_tcp_info(&mut payload, TCP_INFO_V4_14_LEN, 10_001, 20_002, 301, 302);
        push_congestion_algorithm(&mut payload, "cubic");
        let mut datagram = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        datagram.extend(done_message(0));

        let sockets = parse_table_fixture(Query::IPV4_TCP, &datagram).unwrap();
        let socket = &sockets[0];

        assert_eq!(socket.family, SocketFamily::Ipv4);
        assert_eq!(socket.protocol, SocketProtocol::Tcp);
        assert_eq!((socket.state, socket.timer, socket.retransmits), (1, 4, 2));
        assert_eq!(
            socket.local,
            SocketEndpoint {
                address: "192.0.2.10".parse().unwrap(),
                port: 44_321,
            }
        );
        assert_eq!(
            socket.remote,
            SocketEndpoint {
                address: "198.51.100.7".parse().unwrap(),
                port: 443,
            }
        );
        assert_eq!(socket.bound_ifindex, 7);
        assert_eq!(socket.expires_millis, 1_250);
        assert_eq!(socket.receive_queue, 2_048);
        assert_eq!(socket.send_queue, 4_096);
        assert_eq!(socket.uid, 1_001);
        assert_eq!(socket.identity.inode(), 149);
        assert_eq!(
            socket.memory,
            Some(SocketMemory {
                receive_allocated: 11,
                receive_limit: 12,
                send_allocated: 13,
                send_limit: 14,
                forward_allocated: 15,
                send_queued: 16,
                option_memory: 17,
                backlog: 18,
                drops: 19,
            })
        );
        let tcp_info = socket.tcp_info.expect("TCP fixture includes tcp_info");
        assert_eq!(tcp_info.bytes_acked, Some(10_001));
        assert_eq!(tcp_info.bytes_received, Some(20_002));
        assert_eq!(tcp_info.segments_out, Some(301));
        assert_eq!(tcp_info.segments_in, Some(302));
        assert_eq!(tcp_info.send_window_bytes, None);
        assert_eq!(tcp_info.receive_window_bytes, None);
        assert_eq!(socket.congestion_algorithm.as_deref(), Some("cubic"));
    }

    #[test]
    fn table_parser_decodes_ipv6_and_preserves_missing_optional_attributes() {
        let mut payload = diag_payload(Query::IPV6_UDP, 0x41);
        payload[1] = 7;
        payload[4..6].copy_from_slice(&53_u16.to_be_bytes());
        payload[6..8].copy_from_slice(&53_000_u16.to_be_bytes());
        payload[8..24].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        payload[24..40].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        let mut datagram = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        datagram.extend(done_message(0));

        let sockets = parse_table_fixture(Query::IPV6_UDP, &datagram).unwrap();
        let socket = &sockets[0];

        assert_eq!(socket.family, SocketFamily::Ipv6);
        assert_eq!(socket.protocol, SocketProtocol::Udp);
        assert_eq!(socket.state, 7);
        assert_eq!(
            socket.local.address,
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(socket.local.port, 53);
        assert_eq!(
            socket.remote.address,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(socket.remote.port, 53_000);
        assert_eq!(socket.memory, None);
        assert_eq!(socket.tcp_info, None);
        assert_eq!(socket.congestion_algorithm, None);
    }

    #[test]
    fn tcp_info_prefix_exposes_only_fields_wholly_present() {
        let mut value = vec![0_u8; TCP_INFO_BYTES_RECEIVED_OFFSET + size_of::<u64>()];
        value[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + size_of::<u64>()]
            .copy_from_slice(&91_u64.to_ne_bytes());
        value[TCP_INFO_BYTES_RECEIVED_OFFSET..TCP_INFO_BYTES_RECEIVED_OFFSET + size_of::<u64>()]
            .copy_from_slice(&92_u64.to_ne_bytes());

        let info = parse_tcp_info(&value).unwrap();
        assert_eq!(info.bytes_acked, Some(91));
        assert_eq!(info.bytes_received, Some(92));
        assert_eq!(info.segments_out, None);
        assert_eq!(info.segments_in, None);
        assert_eq!(info.notsent_bytes, None);
        assert_eq!(info.send_window_bytes, None);
        assert_eq!(info.receive_window_bytes, None);

        let error = parse_tcp_info(&value[..TCP_INFO_MIN_LEN - 1]).unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Malformed);
        assert!(error.to_string().contains("INET_DIAG_INFO"));
    }

    #[test]
    fn tcp_info_parser_decodes_the_linux_4_14_layout() {
        let mut value = vec![0_u8; TCP_INFO_V4_14_LEN];
        value[0..6].copy_from_slice(&[1, 2, 3, 4, 5, TCP_INFO_OPTION_WINDOW_SCALE]);
        value[TCP_INFO_WINDOW_SCALE_OFFSET] = packed_window_scales(6, 7);
        value[TCP_INFO_APP_LIMITED_OFFSET] = packed_single_bit(true);

        let required_u32 = [
            (TCP_INFO_RTO_OFFSET, 101),
            (TCP_INFO_ATO_OFFSET, 102),
            (TCP_INFO_SND_MSS_OFFSET, 103),
            (TCP_INFO_RCV_MSS_OFFSET, 104),
            (TCP_INFO_UNACKED_OFFSET, 105),
            (TCP_INFO_SACKED_OFFSET, 106),
            (TCP_INFO_LOST_OFFSET, 107),
            (TCP_INFO_RETRANS_OFFSET, 108),
            (TCP_INFO_FACKETS_OFFSET, 109),
            (TCP_INFO_LAST_DATA_SENT_OFFSET, 110),
            (TCP_INFO_LAST_ACK_SENT_OFFSET, 111),
            (TCP_INFO_LAST_DATA_RECEIVED_OFFSET, 112),
            (TCP_INFO_LAST_ACK_RECEIVED_OFFSET, 113),
            (TCP_INFO_PMTU_OFFSET, 114),
            (TCP_INFO_RCV_SSTHRESH_OFFSET, 115),
            (TCP_INFO_RTT_OFFSET, 116),
            (TCP_INFO_RTTVAR_OFFSET, 117),
            (TCP_INFO_SND_SSTHRESH_OFFSET, 118),
            (TCP_INFO_SND_CWND_OFFSET, 119),
            (TCP_INFO_ADVMSS_OFFSET, 120),
            (TCP_INFO_REORDERING_OFFSET, 121),
            (TCP_INFO_RCV_RTT_OFFSET, 122),
            (TCP_INFO_RCV_SPACE_OFFSET, 123),
            (TCP_INFO_TOTAL_RETRANS_OFFSET, 124),
            (TCP_INFO_SEGS_OUT_OFFSET, 125),
            (TCP_INFO_SEGS_IN_OFFSET, 126),
            (TCP_INFO_NOTSENT_BYTES_OFFSET, 127),
            (TCP_INFO_MIN_RTT_OFFSET, 128),
            (TCP_INFO_DATA_SEGS_IN_OFFSET, 129),
            (TCP_INFO_DATA_SEGS_OUT_OFFSET, 130),
        ];
        for (offset, field) in required_u32 {
            put_tcp_info_u32(&mut value, offset, field);
        }
        for (offset, field) in [
            (TCP_INFO_PACING_RATE_OFFSET, 201),
            (TCP_INFO_MAX_PACING_RATE_OFFSET, 202),
            (TCP_INFO_BYTES_ACKED_OFFSET, 203),
            (TCP_INFO_BYTES_RECEIVED_OFFSET, 204),
            (TCP_INFO_DELIVERY_RATE_OFFSET, 205),
            (TCP_INFO_BUSY_TIME_OFFSET, 206),
            (TCP_INFO_RWND_LIMITED_OFFSET, 207),
            (TCP_INFO_SNDBUF_LIMITED_OFFSET, 208),
        ] {
            put_tcp_info_u64(&mut value, offset, field);
        }

        let info = parse_tcp_info(&value).unwrap();

        assert_eq!(
            (
                info.state,
                info.congestion_state,
                info.retransmit_timeouts,
                info.probes,
                info.backoff,
                info.options,
            ),
            (1, 2, 3, 4, 5, TCP_INFO_OPTION_WINDOW_SCALE)
        );
        assert_eq!(info.send_window_scale, Some(6));
        assert_eq!(info.receive_window_scale, Some(7));
        assert!(info.delivery_rate_app_limited);
        assert_eq!(info.retransmission_timeout_micros, 101);
        assert_eq!(info.ack_timeout_micros, 102);
        assert_eq!(info.send_mss_bytes, 103);
        assert_eq!(info.receive_mss_bytes, 104);
        assert_eq!(info.unacked_segments, 105);
        assert_eq!(info.sacked_segments, 106);
        assert_eq!(info.lost_segments, 107);
        assert_eq!(info.retransmitted_segments, 108);
        assert_eq!(info.fackets, 109);
        assert_eq!(info.last_data_sent_millis, 110);
        assert_eq!(info.last_ack_sent_millis, 111);
        assert_eq!(info.last_data_received_millis, 112);
        assert_eq!(info.last_ack_received_millis, 113);
        assert_eq!(info.path_mtu_bytes, 114);
        assert_eq!(info.receive_ssthresh_bytes, 115);
        assert_eq!(info.rtt_micros, 116);
        assert_eq!(info.rtt_variance_micros, 117);
        assert_eq!(info.send_ssthresh_segments, 118);
        assert_eq!(info.send_cwnd_segments, 119);
        assert_eq!(info.advertised_mss_bytes, 120);
        assert_eq!(info.reordering_segments, 121);
        assert_eq!(info.receive_rtt_micros, 122);
        assert_eq!(info.receive_space_bytes, 123);
        assert_eq!(info.total_retransmitted_segments, 124);
        assert_eq!(info.pacing_rate_bytes_per_second, Some(201));
        assert_eq!(info.max_pacing_rate_bytes_per_second, Some(202));
        assert_eq!(info.bytes_acked, Some(203));
        assert_eq!(info.bytes_received, Some(204));
        assert_eq!(info.segments_out, Some(125));
        assert_eq!(info.segments_in, Some(126));
        assert_eq!(info.notsent_bytes, Some(127));
        assert_eq!(info.min_rtt_micros, Some(128));
        assert_eq!(info.data_segments_in, Some(129));
        assert_eq!(info.data_segments_out, Some(130));
        assert_eq!(info.delivery_rate_bytes_per_second, Some(205));
        assert_eq!(info.busy_time_micros, Some(206));
        assert_eq!(info.receive_window_limited_micros, Some(207));
        assert_eq!(info.send_buffer_limited_micros, Some(208));
        assert_eq!(info.send_window_bytes, None);
        assert_eq!(info.receive_window_bytes, None);
    }

    #[test]
    fn tcp_info_offsets_match_the_append_only_linux_uapi() {
        assert_eq!((TCP_INFO_MIN_LEN, TCP_INFO_V4_14_LEN), (104, 192));
        assert_eq!(
            [
                TCP_INFO_RTO_OFFSET,
                TCP_INFO_ATO_OFFSET,
                TCP_INFO_SND_MSS_OFFSET,
                TCP_INFO_RCV_MSS_OFFSET,
                TCP_INFO_UNACKED_OFFSET,
                TCP_INFO_SACKED_OFFSET,
                TCP_INFO_LOST_OFFSET,
                TCP_INFO_RETRANS_OFFSET,
                TCP_INFO_FACKETS_OFFSET,
                TCP_INFO_LAST_DATA_SENT_OFFSET,
                TCP_INFO_LAST_ACK_SENT_OFFSET,
                TCP_INFO_LAST_DATA_RECEIVED_OFFSET,
                TCP_INFO_LAST_ACK_RECEIVED_OFFSET,
                TCP_INFO_PMTU_OFFSET,
                TCP_INFO_RCV_SSTHRESH_OFFSET,
                TCP_INFO_RTT_OFFSET,
                TCP_INFO_RTTVAR_OFFSET,
                TCP_INFO_SND_SSTHRESH_OFFSET,
                TCP_INFO_SND_CWND_OFFSET,
                TCP_INFO_ADVMSS_OFFSET,
                TCP_INFO_REORDERING_OFFSET,
                TCP_INFO_RCV_RTT_OFFSET,
                TCP_INFO_RCV_SPACE_OFFSET,
                TCP_INFO_TOTAL_RETRANS_OFFSET,
            ],
            [
                8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88,
                92, 96, 100,
            ]
        );
        assert_eq!(
            [
                TCP_INFO_PACING_RATE_OFFSET,
                TCP_INFO_MAX_PACING_RATE_OFFSET,
                TCP_INFO_BYTES_ACKED_OFFSET,
                TCP_INFO_BYTES_RECEIVED_OFFSET,
                TCP_INFO_SEGS_OUT_OFFSET,
                TCP_INFO_SEGS_IN_OFFSET,
                TCP_INFO_NOTSENT_BYTES_OFFSET,
                TCP_INFO_MIN_RTT_OFFSET,
                TCP_INFO_DATA_SEGS_IN_OFFSET,
                TCP_INFO_DATA_SEGS_OUT_OFFSET,
                TCP_INFO_DELIVERY_RATE_OFFSET,
                TCP_INFO_BUSY_TIME_OFFSET,
                TCP_INFO_RWND_LIMITED_OFFSET,
                TCP_INFO_SNDBUF_LIMITED_OFFSET,
                TCP_INFO_SND_WND_OFFSET,
                TCP_INFO_RCV_WND_OFFSET,
            ],
            [104, 112, 120, 128, 136, 140, 144, 148, 152, 156, 160, 168, 176, 184, 228, 232,]
        );
        assert_eq!(TCP_INFO_SND_WND_OFFSET + size_of::<u32>(), 232);
        assert_eq!(TCP_INFO_RCV_WND_OFFSET + size_of::<u32>(), 236);
    }

    #[test]
    fn tcp_info_parser_requires_complete_modern_window_fields() {
        let mut value = vec![0_u8; TCP_INFO_RCV_WND_OFFSET + size_of::<u32>()];
        put_tcp_info_u32(&mut value, TCP_INFO_SND_WND_OFFSET, 65_535);
        put_tcp_info_u32(&mut value, TCP_INFO_RCV_WND_OFFSET, 131_070);

        let before_send_window = parse_tcp_info(&value[..TCP_INFO_SND_WND_OFFSET]).unwrap();
        let partial_send_window =
            parse_tcp_info(&value[..TCP_INFO_SND_WND_OFFSET + size_of::<u32>() - 1]).unwrap();
        let complete_send_window =
            parse_tcp_info(&value[..TCP_INFO_SND_WND_OFFSET + size_of::<u32>()]).unwrap();
        let partial_receive_window =
            parse_tcp_info(&value[..TCP_INFO_RCV_WND_OFFSET + size_of::<u32>() - 1]).unwrap();
        let complete_receive_window = parse_tcp_info(&value).unwrap();

        assert_eq!(before_send_window.send_window_bytes, None);
        assert_eq!(partial_send_window.send_window_bytes, None);
        assert_eq!(complete_send_window.send_window_bytes, Some(65_535));
        assert_eq!(complete_send_window.receive_window_bytes, None);
        assert_eq!(partial_receive_window.receive_window_bytes, None);
        assert_eq!(complete_receive_window.send_window_bytes, Some(65_535));
        assert_eq!(complete_receive_window.receive_window_bytes, Some(131_070));
    }

    #[test]
    fn tcp_info_window_scales_require_the_negotiated_option() {
        let mut value = vec![0_u8; TCP_INFO_MIN_LEN];
        value[TCP_INFO_WINDOW_SCALE_OFFSET] = packed_window_scales(6, 7);

        let info = parse_tcp_info(&value).unwrap();

        assert_eq!(info.send_window_scale, None);
        assert_eq!(info.receive_window_scale, None);
        assert!(!info.delivery_rate_app_limited);
    }

    #[test]
    fn table_parser_rejects_invalid_tcp_info_attributes() {
        let mut duplicate_payload = diag_payload(Query::IPV4_TCP, 1);
        push_attribute(
            &mut duplicate_payload,
            INET_DIAG_INFO,
            &[0; TCP_INFO_MIN_LEN],
        );
        push_attribute(
            &mut duplicate_payload,
            INET_DIAG_INFO,
            &[0; TCP_INFO_MIN_LEN],
        );

        let mut flagged_payload = diag_payload(Query::IPV4_TCP, 2);
        push_attribute(
            &mut flagged_payload,
            INET_DIAG_INFO | 0x8000,
            &[0; TCP_INFO_MIN_LEN],
        );

        let mut short_payload = diag_payload(Query::IPV4_TCP, 3);
        push_attribute(
            &mut short_payload,
            INET_DIAG_INFO,
            &[0; TCP_INFO_MIN_LEN - 1],
        );

        let mut udp_payload = diag_payload(Query::IPV4_UDP, 4);
        push_attribute(&mut udp_payload, INET_DIAG_INFO, &[0; TCP_INFO_MIN_LEN]);

        for (query, payload) in [
            (Query::IPV4_TCP, duplicate_payload),
            (Query::IPV4_TCP, flagged_payload),
            (Query::IPV4_TCP, short_payload),
            (Query::IPV4_UDP, udp_payload),
        ] {
            let datagram = message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                SEQUENCE,
                PORT_ID,
                &payload,
            );
            let error = parse_table_fixture(query, &datagram).unwrap_err();
            assert_eq!(error.kind(), CollectErrorKind::Malformed);
            assert!(error.to_string().contains("INET_DIAG_INFO"));
        }
    }

    #[test]
    fn congestion_algorithm_parser_accepts_the_bounded_kernel_identifier() {
        assert_eq!(
            parse_congestion_algorithm(b"abcdefghijklmno\0").unwrap(),
            "abcdefghijklmno"
        );
        assert_eq!(
            parse_congestion_algorithm(b"bbr_v2-test.1\0").unwrap(),
            "bbr_v2-test.1"
        );
    }

    #[test]
    fn table_parser_rejects_invalid_congestion_algorithm_attributes() {
        let mut duplicate = diag_payload(Query::IPV4_TCP, 1);
        push_congestion_algorithm(&mut duplicate, "cubic");
        push_congestion_algorithm(&mut duplicate, "reno");

        let mut flagged = diag_payload(Query::IPV4_TCP, 2);
        push_attribute(&mut flagged, INET_DIAG_CONG | 0x8000, b"cubic\0");

        let mut udp = diag_payload(Query::IPV4_UDP, 3);
        push_congestion_algorithm(&mut udp, "cubic");

        let mut unterminated = diag_payload(Query::IPV4_TCP, 4);
        push_attribute(&mut unterminated, INET_DIAG_CONG, b"cubic");

        let mut overlong = diag_payload(Query::IPV4_TCP, 5);
        let mut overlong_name = vec![b'a'; TCP_CA_NAME_MAX];
        overlong_name.push(0);
        push_attribute(&mut overlong, INET_DIAG_CONG, &overlong_name);

        let mut empty = diag_payload(Query::IPV4_TCP, 6);
        push_attribute(&mut empty, INET_DIAG_CONG, b"\0");

        let mut whitespace = diag_payload(Query::IPV4_TCP, 7);
        push_attribute(&mut whitespace, INET_DIAG_CONG, b"cu bic\0");

        let mut interior_nul = diag_payload(Query::IPV4_TCP, 8);
        push_attribute(&mut interior_nul, INET_DIAG_CONG, b"cu\0bic\0");

        let mut non_ascii = diag_payload(Query::IPV4_TCP, 9);
        push_attribute(&mut non_ascii, INET_DIAG_CONG, &[0xff, 0]);

        for (query, payload) in [
            (Query::IPV4_TCP, duplicate),
            (Query::IPV4_TCP, flagged),
            (Query::IPV4_UDP, udp),
            (Query::IPV4_TCP, unterminated),
            (Query::IPV4_TCP, overlong),
            (Query::IPV4_TCP, empty),
            (Query::IPV4_TCP, whitespace),
            (Query::IPV4_TCP, interior_nul),
            (Query::IPV4_TCP, non_ascii),
        ] {
            let datagram = message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                SEQUENCE,
                PORT_ID,
                &payload,
            );
            let error = parse_table_fixture(query, &datagram).unwrap_err();
            assert_eq!(error.kind(), CollectErrorKind::Malformed);
            assert!(error.to_string().contains("INET_DIAG_CONG"));
        }
    }

    #[test]
    fn tcp_info_parser_reads_known_fields_and_ignores_an_append_only_newer_suffix() {
        let mut value = vec![0xa5; TCP_INFO_V4_14_LEN + 64];
        value[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + size_of::<u64>()]
            .copy_from_slice(&11_u64.to_ne_bytes());
        value[TCP_INFO_SEGS_OUT_OFFSET..TCP_INFO_SEGS_OUT_OFFSET + size_of::<u32>()]
            .copy_from_slice(&12_u32.to_ne_bytes());
        put_tcp_info_u32(&mut value, TCP_INFO_SND_WND_OFFSET, 13);
        put_tcp_info_u32(&mut value, TCP_INFO_RCV_WND_OFFSET, 14);

        let info = parse_tcp_info(&value).unwrap();

        assert_eq!(info.bytes_acked, Some(11));
        assert_eq!(info.segments_out, Some(12));
        assert_eq!(info.send_window_bytes, Some(13));
        assert_eq!(info.receive_window_bytes, Some(14));
    }

    #[test]
    fn raw_socket_debug_redacts_tuple_and_kernel_identity() {
        let mut payload = diag_payload(Query::IPV4_TCP, 0x55);
        payload[4..6].copy_from_slice(&49_123_u16.to_be_bytes());
        payload[8..12].copy_from_slice(&[203, 0, 113, 246]);
        payload[64..68].copy_from_slice(&2_345_u32.to_ne_bytes());
        push_congestion_algorithm(&mut payload, "cubic");
        let mut datagram = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        datagram.extend(done_message(0));

        let socket = parse_table_fixture(Query::IPV4_TCP, &datagram)
            .unwrap()
            .remove(0);
        let rendered = format!("{socket:?}");

        assert_eq!(rendered, "RawSocket(<redacted>)");
        for private in ["203.0.113.246", "49123", "2345", "185273099", "cubic"] {
            assert!(!rendered.contains(private));
        }
    }

    #[test]
    fn parses_skmeminfo_and_preserves_missing_extension() {
        let mut datagram = diag_message(Query::IPV4_TCP, 1, Some(27));
        datagram.extend(diag_message(Query::IPV4_TCP, 2, None));
        datagram.extend(done_message(0));

        let samples = parse_fixture(Query::IPV4_TCP, &datagram).unwrap();

        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].drops, Some(27));
        assert_eq!(samples[1].drops, None);
        assert_ne!(samples[0].identity, samples[1].identity);
    }

    #[test]
    fn skips_unknown_attributes() {
        let mut payload = diag_payload(Query::IPV6_UDP, 4);
        push_attribute(&mut payload, 321, &[1, 2, 3, 4]);
        push_skmeminfo(&mut payload, 9);
        let mut datagram = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        datagram.extend(done_message(0));

        let samples = parse_fixture(Query::IPV6_UDP, &datagram).unwrap();

        assert_eq!(samples[0].drops, Some(9));
    }

    #[test]
    fn accepts_empty_multi_datagram_and_extended_skmeminfo_dumps() {
        let mut parser = DumpParser::new(Query::IPV4_TCP);
        let first = diag_message(Query::IPV4_TCP, 1, None);
        parser.parse_datagram(&first, SEQUENCE, PORT_ID).unwrap();

        let mut payload = diag_payload(Query::IPV4_TCP, 2);
        push_extended_skmeminfo(&mut payload, 41);
        let second = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        parser.parse_datagram(&second, SEQUENCE, PORT_ID).unwrap();
        parser
            .parse_datagram(&done_message(0), SEQUENCE, PORT_ID)
            .unwrap();

        let samples = parser.finish().unwrap().samples;
        assert_eq!(samples.len(), 2);
        assert!(samples.iter().any(|sample| sample.drops == Some(41)));

        let empty = parse_fixture(Query::IPV4_TCP, &done_message(0)).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn rejects_wrong_sequence_or_port() {
        let wrong_sequence = message(NLMSG_DONE, NLM_F_MULTI, SEQUENCE + 1, PORT_ID, &[]);
        let wrong_port = message(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT_ID + 1, &[]);

        let error = parse_fixture(Query::IPV4_TCP, &wrong_sequence).unwrap_err();
        assert_eq!(error.parse_errors(), 1);
        assert!(error.to_string().contains("sequence"));

        let error = parse_fixture(Query::IPV4_TCP, &wrong_port).unwrap_err();
        let message = error.to_string();
        assert_eq!(error.parse_errors(), 1);
        assert!(message.contains("port ID"));
        assert!(!message.contains(&PORT_ID.to_string()));
        assert!(!message.contains(&(PORT_ID + 1).to_string()));
    }

    #[test]
    fn rejects_non_multipart_data_and_done_responses() {
        let payload = diag_payload(Query::IPV4_TCP, 1);
        let data = message(SOCK_DIAG_BY_FAMILY, 0, SEQUENCE, PORT_ID, &payload);
        let done = message(NLMSG_DONE, 0, SEQUENCE, PORT_ID, &0_i32.to_ne_bytes());

        for datagram in [data, done] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.parse_errors(), 1);
            assert!(error.to_string().contains("multipart"));
        }
    }

    #[test]
    fn rejects_wrong_family_and_short_diag_payload() {
        let wrong_family = diag_message(Query::IPV6_UDP, 1, Some(1));
        let short = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &[0; INET_DIAG_MSG_LEN - 1],
        );

        for datagram in [wrong_family, short] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.parse_errors(), 1);
        }
    }

    #[test]
    fn rejects_malformed_or_duplicate_skmeminfo() {
        let mut short_payload = diag_payload(Query::IPV4_TCP, 1);
        push_attribute(
            &mut short_payload,
            INET_DIAG_SKMEMINFO,
            &[0; SK_MEMINFO_DROPS * size_of::<u32>()],
        );
        let short = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &short_payload,
        );

        let mut duplicate_payload = diag_payload(Query::IPV4_TCP, 1);
        push_skmeminfo(&mut duplicate_payload, 1);
        push_skmeminfo(&mut duplicate_payload, 2);
        let duplicate = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &duplicate_payload,
        );

        for datagram in [short, duplicate] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.parse_errors(), 1);
            assert!(error.to_string().contains("SKMEMINFO"));
        }
    }

    #[test]
    fn rejects_known_attribute_flags_and_duplicate_private_identity() {
        let mut flagged_payload = diag_payload(Query::IPV4_TCP, 1);
        let values = [0_u32; SK_MEMINFO_DROPS + 1];
        let bytes: Vec<_> = values.into_iter().flat_map(u32::to_ne_bytes).collect();
        push_attribute(&mut flagged_payload, INET_DIAG_SKMEMINFO | 0x8000, &bytes);
        let flagged = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &flagged_payload,
        );

        let mut duplicate_identity = diag_message(Query::IPV4_TCP, 7, Some(1));
        duplicate_identity.extend(diag_message(Query::IPV4_TCP, 7, Some(2)));
        duplicate_identity.extend(done_message(0));

        for datagram in [flagged, duplicate_identity] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.kind, CollectErrorKind::Malformed);
        }
    }

    #[test]
    fn rejects_truncated_attribute_and_alignment_padding() {
        let mut payload = diag_payload(Query::IPV4_TCP, 1);
        payload.extend([5, 0, INET_DIAG_SKMEMINFO as u8, 0, 1]);
        let truncated_attribute = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );

        let payload = diag_payload(Query::IPV4_TCP, 1);
        let mut truncated_padding = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        );
        let truncated_message_len = (truncated_padding.len() - 1) as u32;
        put_u32(&mut truncated_padding[0..4], truncated_message_len);

        for datagram in [truncated_attribute, truncated_padding] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.parse_errors(), 1);
        }
    }

    #[test]
    fn classifies_overrun_dump_interruption_and_kernel_error() {
        let overrun = message(NLMSG_OVERRUN, NLM_F_MULTI, SEQUENCE, PORT_ID, &[]);
        let interrupted = done_message(NLM_F_DUMP_INTR);
        let mut error_payload = vec![0_u8; size_of::<i32>() + NLMSG_HEADER_LEN];
        error_payload[..size_of::<i32>()].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        let kernel_error = message(NLMSG_ERROR, 0, SEQUENCE, PORT_ID, &error_payload);

        let error = parse_fixture(Query::IPV4_TCP, &overrun).unwrap_err();
        assert_eq!(error.loss_events(), 1);
        let error = parse_fixture(Query::IPV4_TCP, &interrupted).unwrap_err();
        assert_eq!(error.dumps_interrupted(), 1);
        let error = parse_fixture(Query::IPV4_TCP, &kernel_error).unwrap_err();
        assert_eq!(error.kind, CollectErrorKind::PermissionDenied);
        assert!(error.to_string().contains("Operation not permitted"));
    }

    #[test]
    fn classifies_unsupported_io_ack_and_done_errors() {
        let unsupported = error_message(-libc::EOPNOTSUPP);
        let io_error = error_message(-libc::EIO);
        let zero_ack = error_message(0);
        let positive_errno = error_message(libc::EPERM);
        let minimum_errno = error_message(i32::MIN);
        let done_error = message(
            NLMSG_DONE,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &(-libc::EIO).to_ne_bytes(),
        );

        assert_eq!(
            parse_fixture(Query::IPV4_TCP, &unsupported)
                .unwrap_err()
                .kind,
            CollectErrorKind::Unsupported
        );
        assert_eq!(
            parse_fixture(Query::IPV4_TCP, &io_error).unwrap_err().kind,
            CollectErrorKind::Io
        );
        for datagram in [zero_ack, positive_errno, minimum_errno] {
            assert_eq!(
                parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err().kind,
                CollectErrorKind::Malformed
            );
        }
        assert_eq!(
            parse_fixture(Query::IPV4_TCP, &done_error)
                .unwrap_err()
                .kind,
            CollectErrorKind::Io
        );
    }

    #[test]
    fn requires_done_and_rejects_messages_after_done() {
        let without_done = diag_message(Query::IPV4_TCP, 1, Some(1));
        let mut after_done = done_message(0);
        after_done.extend(diag_message(Query::IPV4_TCP, 1, Some(1)));

        let error = parse_fixture(Query::IPV4_TCP, &without_done).unwrap_err();
        assert_eq!(error.dumps_interrupted(), 1);
        let error = parse_fixture(Query::IPV4_TCP, &after_done).unwrap_err();
        assert_eq!(error.parse_errors(), 1);
    }

    #[test]
    fn rejects_duplicate_done_unexpected_message_and_short_done() {
        let mut duplicate_done = done_message(0);
        duplicate_done.extend(done_message(0));
        let unexpected = message(99, NLM_F_MULTI, SEQUENCE, PORT_ID, &[]);
        let short_done = message(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT_ID, &[]);
        let long_done = message(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT_ID, &[0; 8]);

        for datagram in [duplicate_done, unexpected, short_done, long_done] {
            let error = parse_fixture(Query::IPV4_TCP, &datagram).unwrap_err();
            assert_eq!(error.kind, CollectErrorKind::Malformed);
        }
    }

    #[test]
    fn enforces_per_query_sample_limit_without_returning_a_prefix() {
        let mut parser = DumpParser::new(Query::IPV4_TCP);
        parser.sample_limit = 1;
        let mut datagram = diag_message(Query::IPV4_TCP, 1, Some(1));
        datagram.extend(diag_message(Query::IPV4_TCP, 2, Some(2)));

        let error = parser
            .parse_datagram(&datagram, SEQUENCE, PORT_ID)
            .unwrap_err();

        assert_eq!(error.kind, CollectErrorKind::Loss);
        assert_eq!(parser.samples.len(), 1);
        assert!(!parser.done);
    }

    #[test]
    fn table_limit_reports_all_observed_sockets_and_returns_a_bounded_prefix() {
        let mut parser = DumpParser::new_table(Query::IPV4_TCP);
        parser.sample_limit = 1;
        let mut datagram = diag_message(Query::IPV4_TCP, 1, Some(1));
        datagram.extend(diag_message(Query::IPV4_TCP, 2, Some(2)));
        datagram.extend(done_message(0));

        parser.parse_datagram(&datagram, SEQUENCE, PORT_ID).unwrap();
        let dump = parser.finish().unwrap();

        assert_eq!(dump.sockets.len(), 1);
        assert_eq!(dump.observed_sockets, 2);
        assert!(dump.table_truncated);
    }

    #[test]
    fn localizes_query_failure_and_retains_other_complete_dumps() {
        let snapshot = collect_with(|query| {
            if query == Query::IPV4_UDP {
                Err(CollectError::io(
                    "test query",
                    io::Error::from_raw_os_error(libc::EOPNOTSUPP),
                ))
            } else {
                Ok(SockDiagDump {
                    samples: Vec::new(),
                    sockets: Vec::new(),
                    observed_sockets: 0,
                    table_truncated: false,
                })
            }
        });

        assert_eq!(snapshot.queries.len(), QUERY_COUNT);
        assert_eq!(
            snapshot
                .queries
                .iter()
                .filter(|result| result.outcome.is_ok())
                .count(),
            3
        );
        let failed = snapshot
            .queries
            .iter()
            .find(|result| result.query == Query::IPV4_UDP)
            .unwrap();
        assert_eq!(
            failed.outcome.as_ref().unwrap_err().kind,
            CollectErrorKind::Unsupported
        );
    }

    #[test]
    fn matches_only_identical_private_socket_identities() {
        let start = snapshot_with_samples(
            Query::IPV4_UDP,
            vec![sample(1, 4), sample(2, 7), sample(3, 11)],
        );
        let mut reused_cookie = sample(2, 19);
        reused_cookie.identity.inode += 1;
        let end = snapshot_with_samples(
            Query::IPV4_UDP,
            vec![sample(1, 9), reused_cookie, sample(4, 23)],
        );

        let report = calculate_deltas(start, end);

        assert_eq!(report.completed_query_pairs, QUERY_COUNT);
        assert_eq!(
            report.deltas,
            [SocketDropDelta {
                start: 4,
                end: 9,
                delta: Some(5),
                reset: false,
            }]
        );
    }

    #[test]
    fn cookie_or_inode_reuse_and_socket_churn_do_not_create_deltas() {
        let original = sample(7, 2);
        let mut reused_cookie = sample(7, 20);
        reused_cookie.identity.inode += 1;
        let mut reused_inode = sample(7, 30);
        reused_inode.identity.cookie[0] += 1;

        for replacement in [reused_cookie, reused_inode, sample(8, 40)] {
            let start = snapshot_with_samples(Query::IPV4_TCP, vec![original.clone()]);
            let end = snapshot_with_samples(Query::IPV4_TCP, vec![replacement]);
            assert!(calculate_deltas(start, end).deltas.is_empty());
        }
    }

    #[test]
    fn unavailable_cookie_or_inode_is_never_used_as_delta_identity() {
        let mut no_cookie = sample(9, 1);
        no_cookie.identity.cookie = INET_DIAG_NOCOOKIE;
        let mut no_inode = sample(10, 1);
        no_inode.identity.inode = 0;

        for before in [no_cookie, no_inode] {
            let mut after = before.clone();
            after.drops = Some(99);
            let start = snapshot_with_samples(Query::IPV4_UDP, vec![before]);
            let end = snapshot_with_samples(Query::IPV4_UDP, vec![after]);
            assert!(calculate_deltas(start, end).deltas.is_empty());
        }
    }

    #[test]
    fn decreasing_32_bit_counter_is_a_reset_not_a_wrapped_delta() {
        let start = snapshot_with_samples(Query::IPV6_UDP, vec![sample(1, u32::MAX - 2)]);
        let end = snapshot_with_samples(Query::IPV6_UDP, vec![sample(1, 3)]);

        let report = calculate_deltas(start, end);

        assert_eq!(
            report.deltas,
            [SocketDropDelta {
                start: u64::from(u32::MAX - 2),
                end: 3,
                delta: None,
                reset: true,
            }]
        );
    }

    #[test]
    fn partial_query_failure_retains_other_deltas_and_degrades_coverage() {
        let start = collect_with(|query| {
            if query == Query::IPV6_TCP {
                Err(CollectError::loss("test overrun"))
            } else {
                Ok(SockDiagDump {
                    samples: match query {
                        Query::IPV4_TCP => vec![sample(2, 3)],
                        Query::IPV4_UDP => vec![sample_with_drops(1, None)],
                        _ => Vec::new(),
                    },
                    sockets: Vec::new(),
                    observed_sockets: 0,
                    table_truncated: false,
                })
            }
        });
        let end = collect_with(|query| {
            if query == Query::IPV6_TCP {
                Err(CollectError::interrupted("test interruption"))
            } else {
                Ok(SockDiagDump {
                    samples: match query {
                        Query::IPV4_TCP => vec![sample(2, 7)],
                        Query::IPV4_UDP => vec![sample(1, 4)],
                        _ => Vec::new(),
                    },
                    sockets: Vec::new(),
                    observed_sockets: 0,
                    table_truncated: false,
                })
            }
        });

        let report = calculate_deltas(start, end);

        assert_eq!(report.completed_query_pairs, QUERY_COUNT - 1);
        assert_eq!(report.sockets_without_skmeminfo, 1);
        assert_eq!(report.netlink_loss_events, 1);
        assert_eq!(report.netlink_dump_interruptions, 1);
        assert_eq!(report.errors.len(), 2);
        assert_eq!(
            report.deltas,
            [SocketDropDelta {
                start: 3,
                end: 7,
                delta: Some(4),
                reset: false,
            }]
        );
        assert!(!report.is_complete());
    }

    #[test]
    fn debug_output_redacts_private_socket_identity() {
        let mut datagram = diag_message(Query::IPV4_TCP, 0x55, Some(0x1122_3344));
        datagram.extend(done_message(0));
        let sample = parse_fixture(Query::IPV4_TCP, &datagram).unwrap().remove(0);

        assert_eq!(
            format!("{sample:?}"),
            "SocketDropSample { identity: SocketIdentity(<redacted>), drops: Some(287454020) }"
        );
        let rendered = format!("{sample:?}");
        assert!(!rendered.contains("1482118741"));
        assert!(!rendered.contains("185273099"));
    }

    #[test]
    fn every_prefix_and_deterministic_arbitrary_input_is_panic_free() {
        let mut valid = diag_message(Query::IPV4_TCP, 1, Some(1));
        valid.extend(done_message(0));
        for prefix_len in 0..valid.len() {
            let mut parser = DumpParser::new(Query::IPV4_TCP);
            let _ = parser.parse_datagram(&valid[..prefix_len], SEQUENCE, PORT_ID);
            let _ = parser.finish();
        }

        let mut table_payload = diag_payload(Query::IPV4_TCP, 2);
        push_tcp_info(&mut table_payload, TCP_INFO_V4_14_LEN, 1, 2, 3, 4);
        let mut valid_table = message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &table_payload,
        );
        valid_table.extend(done_message(0));
        for prefix_len in 0..valid_table.len() {
            let mut parser = DumpParser::new_table(Query::IPV4_TCP);
            let _ = parser.parse_datagram(&valid_table[..prefix_len], SEQUENCE, PORT_ID);
            let _ = parser.finish();
        }

        let mut state = 0x9e37_79b9_u32;
        for length in 0..256 {
            let mut bytes = vec![0_u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let mut parser = DumpParser::new(Query::IPV6_UDP);
            let _ = parser.parse_datagram(&bytes, SEQUENCE, PORT_ID);
            let mut table_parser = DumpParser::new_table(Query::IPV6_UDP);
            let _ = table_parser.parse_datagram(&bytes, SEQUENCE, PORT_ID);
        }
    }

    #[test]
    fn collects_ipv4_tcp_and_udp_from_running_network_namespace() {
        let snapshot = collect_current_namespace();
        let table = collect_table_current_namespace();

        assert_eq!(snapshot.queries.len(), QUERY_COUNT);
        assert_eq!(table.queries.len(), QUERY_COUNT);
        for query in [Query::IPV4_TCP, Query::IPV4_UDP] {
            let result = snapshot
                .queries
                .iter()
                .find(|result| result.query == query)
                .unwrap();
            assert!(result.outcome.is_ok(), "{query:?}: {:?}", result.outcome);
            let table_result = table
                .queries
                .iter()
                .find(|result| {
                    result.family == query.family() && result.protocol == query.protocol()
                })
                .unwrap();
            assert!(
                table_result.outcome.is_ok(),
                "{query:?}: {:?}",
                table_result.outcome
            );
        }
        for result in snapshot
            .queries
            .iter()
            .filter(|result| result.query.family == libc::AF_INET6 as u8)
        {
            if let Err(error) = &result.outcome {
                assert_eq!(error.kind, CollectErrorKind::Unsupported);
            }
        }
    }

    #[test]
    fn slow_udp_reader_produces_a_current_namespace_socket_delta() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receive_buffer: libc::c_int = 4_096;
        let result = unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::from_ref(&receive_buffer).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(result, 0, "set SO_RCVBUF: {}", io::Error::last_os_error());
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();

        let start = collect_query(Query::IPV4_UDP).unwrap();
        let payload = [0x5a_u8; 1_400];
        for _ in 0..20_000 {
            sender.send(&payload).unwrap();
        }
        let end = collect_query(Query::IPV4_UDP).unwrap();
        assert_socket_drop_counter_increased(&receiver, &start, &end, "slow UDP reader");
    }

    #[test]
    fn classic_socket_filter_rejection_increments_generic_sk_drops() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut instructions = [libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        let program = libc::sock_fprog {
            len: instructions.len() as u16,
            filter: instructions.as_mut_ptr(),
        };
        let result = unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                std::ptr::from_ref(&program).cast(),
                size_of::<libc::sock_fprog>() as libc::socklen_t,
            )
        };
        assert_eq!(
            result,
            0,
            "attach classic socket filter: {}",
            io::Error::last_os_error()
        );

        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        let start = collect_query(Query::IPV4_UDP).unwrap();
        for _ in 0..256 {
            sender.send(&[0x5a_u8; 64]).unwrap();
        }
        let end = collect_query(Query::IPV4_UDP).unwrap();
        assert_socket_drop_counter_increased(&receiver, &start, &end, "socket-filter rejection");
    }

    fn assert_socket_drop_counter_increased(
        socket: &UdpSocket,
        start: &SockDiagDump,
        end: &SockDiagDump,
        trigger: &str,
    ) {
        let metadata = fs::metadata(format!("/proc/self/fd/{}", socket.as_raw_fd())).unwrap();
        let inode = u32::try_from(metadata.ino()).expect("socket inode fits inet_diag u32 field");
        let before = start
            .samples
            .iter()
            .find(|sample| sample.identity.inode == inode)
            .expect("target socket is present in the start sock_diag dump");
        let after = end
            .samples
            .iter()
            .find(|sample| sample.identity == before.identity)
            .expect("target socket is present with the same identity in the end sock_diag dump");
        let before_drops = before
            .drops
            .expect("target socket exposes SK_MEMINFO_DROPS at the start boundary");
        let after_drops = after
            .drops
            .expect("target socket exposes SK_MEMINFO_DROPS at the end boundary");

        assert!(
            after_drops > before_drops,
            "{trigger} did not increase the target socket's SK_MEMINFO_DROPS: {before_drops} -> {after_drops}"
        );
    }

    fn parse_fixture(query: Query, datagram: &[u8]) -> Result<Vec<SocketDropSample>, CollectError> {
        let mut parser = DumpParser::new(query);
        parser.parse_datagram(datagram, SEQUENCE, PORT_ID)?;
        Ok(parser.finish()?.samples)
    }

    fn parse_table_fixture(query: Query, datagram: &[u8]) -> Result<Vec<RawSocket>, CollectError> {
        let mut parser = DumpParser::new_table(query);
        parser.parse_datagram(datagram, SEQUENCE, PORT_ID)?;
        Ok(parser.finish()?.sockets)
    }

    fn snapshot_with_samples(query: Query, samples: Vec<SocketDropSample>) -> SockDiagSnapshot {
        collect_with(|candidate| {
            let mut samples = if candidate == query {
                samples.clone()
            } else {
                Vec::new()
            };
            samples.sort_by(|left, right| left.identity.cmp(&right.identity));
            Ok(SockDiagDump {
                samples,
                sockets: Vec::new(),
                observed_sockets: 0,
                table_truncated: false,
            })
        })
    }

    fn sample(seed: u32, drops: u32) -> SocketDropSample {
        sample_with_drops(seed, Some(drops))
    }

    fn sample_with_drops(seed: u32, drops: Option<u32>) -> SocketDropSample {
        SocketDropSample {
            identity: SocketIdentity {
                family: libc::AF_INET as u8,
                protocol: libc::IPPROTO_UDP as u8,
                cookie: [seed, seed.wrapping_mul(17)],
                inode: seed.wrapping_add(100),
            },
            drops,
        }
    }

    fn diag_message(query: Query, identity_seed: u8, drops: Option<u32>) -> Vec<u8> {
        let mut payload = diag_payload(query, identity_seed);
        if let Some(drops) = drops {
            push_skmeminfo(&mut payload, drops);
        }
        message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_MULTI,
            SEQUENCE,
            PORT_ID,
            &payload,
        )
    }

    fn diag_payload(query: Query, identity_seed: u8) -> Vec<u8> {
        let mut payload = vec![0_u8; INET_DIAG_MSG_LEN];
        payload[0] = query.family;
        payload[1] = 1;
        for (index, byte) in payload[4..4 + INET_DIAG_SOCKID_LEN].iter_mut().enumerate() {
            *byte = identity_seed.wrapping_add(index as u8);
        }
        payload[68..72].copy_from_slice(&(u32::from(identity_seed) + 100).to_ne_bytes());
        payload
    }

    fn push_skmeminfo(payload: &mut Vec<u8>, drops: u32) {
        let mut values = [0_u32; SK_MEMINFO_DROPS + 1];
        values[SK_MEMINFO_DROPS] = drops;
        push_skmeminfo_values(payload, values);
    }

    fn push_skmeminfo_values(payload: &mut Vec<u8>, values: [u32; SK_MEMINFO_DROPS + 1]) {
        let bytes: Vec<_> = values.into_iter().flat_map(u32::to_ne_bytes).collect();
        push_attribute(payload, INET_DIAG_SKMEMINFO, &bytes);
    }

    fn push_tcp_info(
        payload: &mut Vec<u8>,
        length: usize,
        bytes_acked: u64,
        bytes_received: u64,
        segments_out: u32,
        segments_in: u32,
    ) {
        let mut value = vec![0_u8; length];
        value[TCP_INFO_BYTES_ACKED_OFFSET..TCP_INFO_BYTES_ACKED_OFFSET + size_of::<u64>()]
            .copy_from_slice(&bytes_acked.to_ne_bytes());
        value[TCP_INFO_BYTES_RECEIVED_OFFSET..TCP_INFO_BYTES_RECEIVED_OFFSET + size_of::<u64>()]
            .copy_from_slice(&bytes_received.to_ne_bytes());
        value[TCP_INFO_SEGS_OUT_OFFSET..TCP_INFO_SEGS_OUT_OFFSET + size_of::<u32>()]
            .copy_from_slice(&segments_out.to_ne_bytes());
        value[TCP_INFO_SEGS_IN_OFFSET..TCP_INFO_SEGS_IN_OFFSET + size_of::<u32>()]
            .copy_from_slice(&segments_in.to_ne_bytes());
        push_attribute(payload, INET_DIAG_INFO, &value);
    }

    fn push_congestion_algorithm(payload: &mut Vec<u8>, name: &str) {
        assert!(name.len() < TCP_CA_NAME_MAX);
        let mut value = name.as_bytes().to_vec();
        value.push(0);
        push_attribute(payload, INET_DIAG_CONG, &value);
    }

    fn put_tcp_info_u32(value: &mut [u8], offset: usize, field: u32) {
        value[offset..offset + size_of::<u32>()].copy_from_slice(&field.to_ne_bytes());
    }

    fn put_tcp_info_u64(value: &mut [u8], offset: usize, field: u64) {
        value[offset..offset + size_of::<u64>()].copy_from_slice(&field.to_ne_bytes());
    }

    fn packed_window_scales(send: u8, receive: u8) -> u8 {
        if cfg!(target_endian = "little") {
            send | (receive << 4)
        } else {
            (send << 4) | receive
        }
    }

    fn packed_single_bit(value: bool) -> u8 {
        match (cfg!(target_endian = "little"), value) {
            (_, false) => 0,
            (true, true) => 1,
            (false, true) => 1 << 7,
        }
    }

    fn push_extended_skmeminfo(payload: &mut Vec<u8>, drops: u32) {
        let mut values = [0_u32; SK_MEMINFO_DROPS + 2];
        values[SK_MEMINFO_DROPS] = drops;
        let bytes: Vec<_> = values.into_iter().flat_map(u32::to_ne_bytes).collect();
        push_attribute(payload, INET_DIAG_SKMEMINFO, &bytes);
    }

    fn push_attribute(payload: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
        let attribute_len = RTATTR_HEADER_LEN + value.len();
        let offset = payload.len();
        payload.resize(offset + align(attribute_len), 0);
        put_u16(&mut payload[offset..offset + 2], attribute_len as u16);
        put_u16(&mut payload[offset + 2..offset + 4], attribute_type);
        payload[offset + RTATTR_HEADER_LEN..offset + attribute_len].copy_from_slice(value);
    }

    fn done_message(flags: u16) -> Vec<u8> {
        message(
            NLMSG_DONE,
            NLM_F_MULTI | flags,
            SEQUENCE,
            PORT_ID,
            &0_i32.to_ne_bytes(),
        )
    }

    fn error_message(code: i32) -> Vec<u8> {
        let mut payload = vec![0_u8; size_of::<i32>() + NLMSG_HEADER_LEN];
        payload[..size_of::<i32>()].copy_from_slice(&code.to_ne_bytes());
        message(NLMSG_ERROR, 0, SEQUENCE, PORT_ID, &payload)
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
}
