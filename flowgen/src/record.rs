//! Version 1 recordings: 32-byte header, 40-byte events and a 40-byte footer.
//! All integers are little endian. Header flags: bit 0 TCP, bit 1 server.
//! Events contain flow/seq/time/value (u64), len (u32), kind (u8), then a
//! 24-bit FNV-1a integrity check. This detects damage, not malicious edits.
//! Footer kind 255 stores written events in flow and dropped events in seq.
//! A missing/invalid footer never turns an incomplete recording into loss.

use hdrhistogram::Histogram;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

pub(crate) const EVENT_SIZE: usize = 40;
const HEADER_SIZE: usize = 32;
const MAGIC: &[u8; 8] = b"FGRLOG\r\n";
const VERSION: u16 = 1;
const BATCH_EVENTS: usize = 1024;
const QUEUED_BATCHES: usize = 8;
pub const KINDS: usize = 18;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Kind {
    Open = 0,
    Ready = 1,
    Sent = 2,
    Response = 3,
    Timeout = 4,
    Canceled = 5,
    Closed = 6,
    Failed = 7,
    ServerRequest = 8,
    ServerResponse = 9,
    Duplicate = 10,
    Late = 11,
    Invalid = 12,
    Limited = 13,
    /// Request-send batch: value is the number of missed send slots.
    Skipped = 14,
    Reordered = 15,
    /// Scheduler batch: value is the number of sessions not started.
    SessionSkipped = 16,
    /// Diagnostic annotation; does not imply an additional Failed outcome.
    Error = 17,
}

impl Kind {
    fn from_byte(value: u8) -> io::Result<Self> {
        const KINDS: [Kind; 18] = [
            Kind::Open,
            Kind::Ready,
            Kind::Sent,
            Kind::Response,
            Kind::Timeout,
            Kind::Canceled,
            Kind::Closed,
            Kind::Failed,
            Kind::ServerRequest,
            Kind::ServerResponse,
            Kind::Duplicate,
            Kind::Late,
            Kind::Invalid,
            Kind::Limited,
            Kind::Skipped,
            Kind::Reordered,
            Kind::SessionSkipped,
            Kind::Error,
        ];
        KINDS
            .get(value as usize)
            .copied()
            .ok_or_else(|| invalid("unknown event kind"))
    }
}

/// Stable stage codes used in Error.value. Errno 0 means no OS errno is available.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ErrorStage {
    Socket = 1,
    Bind = 2,
    Connect = 3,
    Register = 4,
    Send = 5,
    Receive = 6,
    Decode = 7,
    SetupTimeout = 8,
    SendTimeout = 9,
    Interest = 10,
}

impl ErrorStage {
    /// Pack a raw_os_error() result; None uses errno 0 for non-OS failures.
    pub const fn encode(self, errno: Option<i32>) -> u64 {
        pack_error(
            self,
            match errno {
                Some(errno) => errno,
                None => 0,
            },
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Bind => "bind",
            Self::Connect => "connect",
            Self::Register => "register",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Decode => "decode",
            Self::SetupTimeout => "setup_timeout",
            Self::SendTimeout => "send_timeout",
            Self::Interest => "interest",
        }
    }
}

/// Pack the stage in the upper 32 bits and the signed errno bits in the lower 32.
pub const fn pack_error(stage: ErrorStage, errno: i32) -> u64 {
    ((stage as u64) << 32) | (errno as u32 as u64)
}

/// Decode Error.value, rejecting unknown stage codes without truncating them.
pub fn unpack_error(value: u64) -> Option<(ErrorStage, i32)> {
    let stage = match value >> 32 {
        1 => ErrorStage::Socket,
        2 => ErrorStage::Bind,
        3 => ErrorStage::Connect,
        4 => ErrorStage::Register,
        5 => ErrorStage::Send,
        6 => ErrorStage::Receive,
        7 => ErrorStage::Decode,
        8 => ErrorStage::SetupTimeout,
        9 => ErrorStage::SendTimeout,
        10 => ErrorStage::Interest,
        _ => return None,
    };
    Some((stage, value as u32 as i32))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    pub flow: u64,
    pub seq: u64,
    pub time_ns: u64,
    /// Client values: RTT nanoseconds for Response, setup nanoseconds for Ready,
    /// and the monotonic send timestamp for Sent. Server Ready is an ACK marker,
    /// not a client setup sample. Skipped carries a missed request-send count.
    /// SessionSkipped carries a session count; Error
    /// carries pack_error(stage, errno). Other kinds have outcome-specific values.
    pub value: u64,
    pub len: u32,
    pub kind: Kind,
}

impl Event {
    /// Record a scheduling batch without opening a session. Flow may be zero
    /// for worker-wide scheduling; count is the number of skipped sessions.
    pub fn session_skipped(flow: u64, time_ns: u64, count: u64) -> Self {
        Self {
            flow,
            seq: 0,
            time_ns,
            value: count,
            len: 0,
            kind: Kind::SessionSkipped,
        }
    }

    /// Annotate an error. Emit Failed separately when a session actually fails.
    /// Use error.raw_os_error().unwrap_or(0) for an io::Error's errno.
    pub fn error(flow: u64, seq: u64, time_ns: u64, stage: ErrorStage, errno: i32) -> Self {
        Self {
            flow,
            seq,
            time_ns,
            value: stage.encode(Some(errno)),
            len: 0,
            kind: Kind::Error,
        }
    }

    pub fn error_details(self) -> Option<(ErrorStage, i32)> {
        (self.kind == Kind::Error)
            .then(|| unpack_error(self.value))
            .flatten()
    }

    pub(crate) fn encode(self) -> [u8; EVENT_SIZE] {
        let mut bytes = [0; EVENT_SIZE];
        self.encode_unsealed(&mut bytes);
        seal(&mut bytes);
        bytes
    }

    // Recorder batches defer integrity work until the writer owns the buffer.
    // The trailer may contain an old checksum and must be sealed before IO.
    fn encode_unsealed(self, bytes: &mut [u8; EVENT_SIZE]) {
        bytes[0..8].copy_from_slice(&self.flow.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.seq.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.time_ns.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.value.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.len.to_le_bytes());
        bytes[36] = self.kind as u8;
    }

    pub(crate) fn decode(bytes: &[u8; EVENT_SIZE]) -> io::Result<Self> {
        verify(bytes)?;
        let event = Self {
            flow: word(bytes, 0),
            seq: word(bytes, 8),
            time_ns: word(bytes, 16),
            value: word(bytes, 24),
            len: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            kind: Kind::from_byte(bytes[36])?,
        };
        if event.kind == Kind::Error && event.error_details().is_none() {
            return Err(invalid("unknown error stage"));
        }
        Ok(event)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c9dc5_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x01000193)
    })
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn seal(bytes: &mut [u8; EVENT_SIZE]) {
    let check = checksum(&bytes[..37]).to_le_bytes();
    bytes[37..40].copy_from_slice(&check[..3]);
}

fn verify(bytes: &[u8; EVENT_SIZE]) -> io::Result<()> {
    if bytes[37..40] != checksum(&bytes[..37]).to_le_bytes()[..3] {
        return Err(invalid("record checksum mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub run: u64,
    pub tcp: bool,
    pub server: bool,
}

impl Header {
    fn encode(self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0; HEADER_SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        bytes[12..14].copy_from_slice(&(EVENT_SIZE as u16).to_le_bytes());
        bytes[14] = u8::from(self.tcp) | (u8::from(self.server) << 1);
        bytes[16..24].copy_from_slice(&self.run.to_le_bytes());
        let check = checksum(&bytes[..28]);
        bytes[28..32].copy_from_slice(&check.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8; HEADER_SIZE]) -> io::Result<Self> {
        if &bytes[..8] != MAGIC
            || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION
            || u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize != HEADER_SIZE
            || u16::from_le_bytes(bytes[12..14].try_into().unwrap()) as usize != EVENT_SIZE
            || bytes[14] & !3 != 0
            || bytes[15] != 0
            || bytes[24..28] != [0; 4]
            || bytes[28..32] != checksum(&bytes[..28]).to_le_bytes()
        {
            return Err(invalid("invalid or unsupported recording header"));
        }
        Ok(Self {
            run: word(bytes, 16),
            tcp: bytes[14] & 1 != 0,
            server: bytes[14] & 2 != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecordSummary {
    pub dropped: u64,
    pub events: u64,
}

const SUMMARY_COUNTER_COLUMNS: &str =
    "open,ready,sent,response_records,timeout,canceled,closed,failed,server_request,server_response,duplicate,late,invalid,limited,skipped,reordered,session_skipped,error";

/// Selects how a worker records events. Events is the historical v1 `.fgr`
/// recorder; Summary writes one bounded aggregate per worker; Off does no
/// recording work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mode {
    #[default]
    Events,
    Summary,
    Off,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("events") || value.eq_ignore_ascii_case("full") {
            Some(Self::Events)
        } else if value.eq_ignore_ascii_case("summary") {
            Some(Self::Summary)
        } else if value.eq_ignore_ascii_case("off") {
            Some(Self::Off)
        } else {
            None
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::Summary => "summary",
            Self::Off => "off",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Mode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or("expected events, summary, or off")
    }
}

impl Mode {
    /// Compatibility alias for integrations that used the earlier name.
    #[allow(dead_code, non_upper_case_globals)]
    pub const Full: Self = Self::Events;
}

fn summary_histogram() -> io::Result<Histogram<u64>> {
    Histogram::new_with_max(u64::MAX, 3).map_err(io::Error::other)
}

/// Bounded aggregate data from one worker. Response samples are the `value`
/// of each successful Response event, already measured by the client. The
/// histogram uses three significant digits and can be merged without replaying
/// events. Min/max, mean, and mdev retain the raw values; histogram quantiles
/// have the histogram's documented equivalent-value precision. Summary mode
/// intentionally has no per-session or jitter statistic.
#[derive(Clone)]
pub struct RecordingSummary {
    run: u64,
    tcp: bool,
    server: bool,
    events: u64,
    counts: [u64; KINDS],
    rtt: Option<Histogram<u64>>,
    min: Option<u64>,
    max: Option<u64>,
    mean: f64,
    m2: f64,
}

#[allow(dead_code)]
impl RecordingSummary {
    pub(crate) fn new(run: u64, tcp: bool, server: bool) -> io::Result<Self> {
        Ok(Self {
            run,
            tcp,
            server,
            events: 0,
            counts: [0; KINDS],
            rtt: Some(summary_histogram()?),
            min: None,
            max: None,
            mean: 0.0,
            m2: 0.0,
        })
    }

    fn empty() -> Self {
        Self {
            run: 0,
            tcp: false,
            server: false,
            events: 0,
            counts: [0; KINDS],
            rtt: None,
            min: None,
            max: None,
            mean: 0.0,
            m2: 0.0,
        }
    }

    pub fn run(&self) -> u64 {
        self.run
    }

    pub fn tcp(&self) -> bool {
        self.tcp
    }

    pub fn server(&self) -> bool {
        self.server
    }

    /// Number of event records seen by this worker, including non-Response events.
    pub fn events(&self) -> u64 {
        self.events
    }

    /// Logical count for a kind. Skipped and SessionSkipped use their event
    /// values, matching offline analysis; all other kinds count records.
    pub fn count(&self, kind: Kind) -> u64 {
        self.counts[kind as usize]
    }

    pub fn response_samples(&self) -> u64 {
        self.rtt.as_ref().map_or(0, Histogram::len)
    }

    pub fn response_min_ns(&self) -> Option<u64> {
        self.min
    }

    pub fn response_max_ns(&self) -> Option<u64> {
        self.max
    }

    pub fn response_avg_ns(&self) -> Option<f64> {
        (self.response_samples() != 0).then_some(self.mean)
    }

    pub fn response_mdev_ns(&self) -> Option<f64> {
        (self.response_samples() != 0)
            .then(|| (self.m2.max(0.0) / self.response_samples() as f64).sqrt())
    }

    pub fn response_quantile_ns(&self, quantile: f64) -> Option<u64> {
        self.rtt
            .as_ref()
            .filter(|rtt| !rtt.is_empty())
            .map(|rtt| rtt.value_at_quantile(quantile))
    }

    /// Merge another worker's aggregate. Worker identity must match so a
    /// caller cannot silently combine unrelated runs or endpoint roles.
    pub fn merge(&mut self, other: &Self) -> io::Result<()> {
        if (self.run, self.tcp, self.server) != (other.run, other.tcp, other.server) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording summaries have different worker identities",
            ));
        }
        let left = self.response_samples();
        let right = other.response_samples();
        if right != 0 {
            self.min = Some(match (self.min, other.min) {
                (Some(left), Some(right)) => left.min(right),
                (None, Some(right)) => right,
                (Some(left), None) => left,
                (None, None) => unreachable!(),
            });
            self.max = Some(match (self.max, other.max) {
                (Some(left), Some(right)) => left.max(right),
                (None, Some(right)) => right,
                (Some(left), None) => left,
                (None, None) => unreachable!(),
            });
            if self.rtt.is_none() {
                self.rtt = Some(summary_histogram()?);
            }
            self.rtt
                .as_mut()
                .unwrap()
                .add(other.rtt.as_ref().unwrap())
                .map_err(io::Error::other)?;
            if left == 0 {
                self.mean = other.mean;
                self.m2 = other.m2;
            } else {
                let total = left + right;
                let delta = other.mean - self.mean;
                self.mean += delta * right as f64 / total as f64;
                self.m2 += other.m2 + delta * delta * left as f64 * right as f64 / total as f64;
            }
        }
        self.events = self.events.saturating_add(other.events);
        for (to, from) in self.counts.iter_mut().zip(other.counts) {
            *to = to.saturating_add(from);
        }
        Ok(())
    }

    /// Write one aggregate row and mergeable histogram rows for this worker.
    /// `record_type=histogram` values are HDR equivalent values, with counts.
    pub fn write_csv(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "record_type,run,protocol,role,events,{SUMMARY_COUNTER_COLUMNS},rtt_samples,rtt_min_ns,rtt_avg_ns,rtt_max_ns,rtt_mdev_ns,rtt_p50_ns,rtt_p95_ns,rtt_p99_ns,histogram_value_ns,histogram_count\naggregate,{},{},{},{}",
            self.run,
            if self.tcp { "tcp" } else { "udp" },
            if self.server { "server" } else { "client" },
            self.events
        )?;
        for count in self.counts {
            write!(out, ",{count}")?;
        }
        let Some(rtt) = self.rtt.as_ref().filter(|rtt| !rtt.is_empty()) else {
            write!(out, ",0,NA,NA,NA,NA,NA,NA,NA,,")?;
            writeln!(out)?;
            return Ok(());
        };
        {
            write!(
                out,
                ",{},{},{:.3},{},{:.3},{},{},{},,",
                rtt.len(),
                self.min.unwrap(),
                self.mean,
                self.max.unwrap(),
                self.response_mdev_ns().unwrap(),
                rtt.value_at_quantile(0.50),
                rtt.value_at_quantile(0.95),
                rtt.value_at_quantile(0.99)
            )?;
        }
        writeln!(out)?;
        for value in rtt.iter_recorded() {
            write!(
                out,
                "histogram,{},{},{},",
                self.run,
                if self.tcp { "tcp" } else { "udp" },
                if self.server { "server" } else { "client" },
            )?;
            for _ in 0..27 {
                write!(out, ",")?;
            }
            writeln!(
                out,
                "{},{}",
                value.value_iterated_to(),
                value.count_at_value()
            )?;
        }
        Ok(())
    }

    pub fn write_console(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(rtt) = self.rtt.as_ref().filter(|rtt| !rtt.is_empty()) else {
            return writeln!(out, "RTT summary: unavailable (samples=0)");
        };
        writeln!(
            out,
            "RTT summary: samples={} min/avg/max/mdev = {:.6}/{:.6}/{:.6}/{:.6} ms p50/p95/p99 = {:.6}/{:.6}/{:.6} ms",
            rtt.len(),
            self.min.unwrap() as f64 / 1e6,
            self.mean / 1e6,
            self.max.unwrap() as f64 / 1e6,
            self.response_mdev_ns().unwrap() / 1e6,
            rtt.value_at_quantile(0.50) as f64 / 1e6,
            rtt.value_at_quantile(0.95) as f64 / 1e6,
            rtt.value_at_quantile(0.99) as f64 / 1e6,
        )
    }

    fn push(&mut self, event: Event) {
        self.events = self.events.saturating_add(1);
        let count = if matches!(event.kind, Kind::Skipped | Kind::SessionSkipped) {
            event.value
        } else {
            1
        };
        self.counts[event.kind as usize] = self.counts[event.kind as usize].saturating_add(count);
        if event.kind != Kind::Response {
            return;
        }
        self.rtt
            .as_mut()
            .unwrap()
            .record(event.value)
            .expect("u64 response latency must fit summary histogram");
        let count = self.rtt.as_ref().unwrap().len();
        self.min = Some(self.min.map_or(event.value, |min| min.min(event.value)));
        self.max = Some(self.max.map_or(event.value, |max| max.max(event.value)));
        let delta = event.value as f64 - self.mean;
        self.mean += delta / count as f64;
        self.m2 += delta * (event.value as f64 - self.mean);
    }
}

pub struct SummaryRecorder {
    path: PathBuf,
    summary: RecordingSummary,
}

impl SummaryRecorder {
    fn create(path: &Path, run: u64, tcp: bool, server: bool) -> io::Result<Self> {
        Ok(Self {
            path: path.to_owned(),
            summary: RecordingSummary::new(run, tcp, server)?,
        })
    }

    /// Finish the aggregate recording and write its bounded worker summary.
    /// This file is aggregate CSV, never a v1 event stream.
    fn finish(self) -> io::Result<(RecordSummary, RecordingSummary)> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)?;
        self.summary.write_csv(&mut file)?;
        file.flush()?;
        Ok((
            RecordSummary {
                dropped: 0,
                events: self.summary.events,
            },
            self.summary,
        ))
    }
}

/// Recording facade for main integration. Existing Recorder remains available
/// for callers that require the full v1 event stream.
#[allow(clippy::large_enum_variant)]
pub enum Recording {
    Events(Recorder),
    Summary(SummaryRecorder),
    Off,
}

impl Recording {
    pub fn create(path: &Path, run: u64, tcp: bool, server: bool, mode: Mode) -> io::Result<Self> {
        match mode {
            Mode::Events => Ok(Self::Events(Recorder::create(path, run, tcp, server)?)),
            Mode::Summary => Ok(Self::Summary(SummaryRecorder::create(
                path, run, tcp, server,
            )?)),
            Mode::Off => Ok(Self::Off),
        }
    }

    pub fn mode(&self) -> Mode {
        match self {
            Self::Events(_) => Mode::Events,
            Self::Summary(_) => Mode::Summary,
            Self::Off => Mode::Off,
        }
    }

    pub fn push(&mut self, event: Event) {
        match self {
            Self::Events(recorder) => recorder.push(event),
            Self::Summary(recorder) => recorder.summary.push(event),
            Self::Off => {}
        }
    }

    pub fn dropped(&self) -> u64 {
        match self {
            Self::Events(recorder) => recorder.dropped(),
            Self::Summary(_) | Self::Off => 0,
        }
    }

    /// Returns aggregate data for summary mode; full/off intentionally return
    /// an empty aggregate because they do not maintain summary state.
    #[allow(dead_code)]
    pub fn summary(&self) -> RecordingSummary {
        match self {
            Self::Events(_) | Self::Off => RecordingSummary::empty(),
            Self::Summary(recorder) => recorder.summary.clone(),
        }
    }

    pub fn finish_with_summary(self) -> io::Result<(RecordSummary, RecordingSummary)> {
        match self {
            Self::Events(recorder) => Ok((recorder.finish()?, RecordingSummary::empty())),
            Self::Summary(recorder) => recorder.finish(),
            Self::Off => Ok((RecordSummary::default(), RecordingSummary::empty())),
        }
    }

    pub fn finish(self) -> io::Result<RecordSummary> {
        self.finish_with_summary().map(|(summary, _)| summary)
    }
}

struct Batch {
    bytes: Box<[u8]>,
    events: usize,
}

impl Batch {
    fn push(&mut self, event: Event) {
        let start = self.events * EVENT_SIZE;
        event.encode_unsealed(
            (&mut self.bytes[start..start + EVENT_SIZE])
                .try_into()
                .unwrap(),
        );
        self.events += 1;
    }

    fn seal(&mut self) {
        // Independent FNV chains hide the multiply dependency within each
        // record. Never include unused slots in a partial, recycled batch.
        let (groups, remainder) =
            self.bytes[..self.events * EVENT_SIZE].as_chunks_mut::<{ 4 * EVENT_SIZE }>();
        for group in groups {
            let mut hashes = [0x811c9dc5_u32; 4];
            for offset in 0..37 {
                for (lane, hash) in hashes.iter_mut().enumerate() {
                    *hash = (*hash ^ u32::from(group[lane * EVENT_SIZE + offset]))
                        .wrapping_mul(0x01000193);
                }
            }
            for (lane, hash) in hashes.into_iter().enumerate() {
                let start = lane * EVENT_SIZE + 37;
                group[start..start + 3].copy_from_slice(&hash.to_le_bytes()[..3]);
            }
        }
        for bytes in remainder.as_chunks_mut::<EVENT_SIZE>().0 {
            seal(bytes);
        }
    }
}

type WriterResult = io::Result<(File, u64)>;

/// One recorder per network worker. After create, push does no disk IO,
/// allocation or blocking channel operations. Ten preallocated 40 KiB batches
/// bound queued, current and writer-owned storage to 400 KiB per recorder.
/// The producer serializes directly into a batch; the writer seals checksums
/// before IO. Event::encode still returns a complete, checksummed v1 record.
/// finish may block; call it after the network loop. Dropping without finish
/// deliberately leaves no footer, even if the background writer drains.
pub struct Recorder {
    sender: SyncSender<Batch>,
    spare: Receiver<Batch>,
    current: Option<Batch>,
    dropped: Arc<AtomicU64>,
    writer: JoinHandle<WriterResult>,
}

impl Recorder {
    pub fn create(path: &Path, run: u64, tcp: bool, server: bool) -> io::Result<Self> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&Header { run, tcp, server }.encode())?;
        Self::with_file(file)
    }

    fn with_file(mut file: File) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Batch>(QUEUED_BATCHES);
        let (recycle, spare) = mpsc::sync_channel(QUEUED_BATCHES + 2);
        for _ in 0..QUEUED_BATCHES + 2 {
            recycle
                .send(Batch {
                    bytes: vec![0; BATCH_EVENTS * EVENT_SIZE].into_boxed_slice(),
                    events: 0,
                })
                .map_err(|_| io::Error::other("initializing recorder buffers"))?;
        }
        let dropped = Arc::new(AtomicU64::new(0));
        let writer_dropped = Arc::clone(&dropped);
        let writer = thread::Builder::new()
            .name("flowgen-record".into())
            .spawn(move || {
                let mut written = 0_u64;
                let mut failure = None;
                while let Ok(mut batch) = receiver.recv() {
                    if failure.is_none() {
                        batch.seal();
                        match file.write_all(&batch.bytes[..batch.events * EVENT_SIZE]) {
                            Ok(()) => written += batch.events as u64,
                            Err(error) => failure = Some(error),
                        }
                    }
                    if failure.is_some() {
                        writer_dropped.fetch_add(batch.events as u64, Ordering::Relaxed);
                    }
                    // After IO failure, drain/count until the sender closes so
                    // concurrently enqueued batches cannot escape accounting.
                    batch.events = 0;
                    let _ = recycle.try_send(batch);
                }
                match failure {
                    Some(error) => Err(error),
                    None => Ok((file, written)),
                }
            })?;
        Ok(Self {
            sender,
            spare,
            current: None,
            dropped,
            writer,
        })
    }

    pub fn push(&mut self, event: Event) {
        if self.current.is_none() {
            self.current = self.spare.try_recv().ok();
        }
        let Some(batch) = self.current.as_mut() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        batch.push(event);
        if batch.events == BATCH_EVENTS {
            let batch = self.current.take().unwrap();
            if let Err(TrySendError::Full(mut batch) | TrySendError::Disconnected(mut batch)) =
                self.sender.try_send(batch)
            {
                self.dropped
                    .fetch_add(batch.events as u64, Ordering::Relaxed);
                batch.events = 0;
                self.current = Some(batch);
            }
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn finish(mut self) -> io::Result<RecordSummary> {
        if let Some(batch) = self.current.take().filter(|b| b.events != 0) {
            if let Err(error) = self.sender.send(batch) {
                self.dropped
                    .fetch_add(error.0.events as u64, Ordering::Relaxed);
            }
        }
        drop(self.sender);
        let (mut file, events) = self
            .writer
            .join()
            .map_err(|_| io::Error::other("recording writer panicked"))??;
        let summary = RecordSummary {
            dropped: self.dropped.load(Ordering::Relaxed),
            events,
        };
        let mut footer = Event {
            flow: events,
            seq: summary.dropped,
            time_ns: 0,
            value: 0,
            len: 0,
            kind: Kind::Open,
        }
        .encode();
        footer[36] = 255;
        seal(&mut footer);
        file.write_all(&footer)?;
        file.flush()?;
        Ok(summary)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadStatus {
    pub events: u64,
    /// Unknown until a valid footer has been read.
    pub dropped: Option<u64>,
    /// Valid footer, exact event count, no trailing data and no dropped events.
    pub complete: bool,
    pub truncated: bool,
    pub corrupt: bool,
}

/// Streaming reader. Consume next_event to None before inspecting status.
/// Damage stops at the last verified record and is exposed through status;
/// actual IO errors propagate. An invalid/truncated header fails construction.
pub struct Reader<R> {
    inner: R,
    pub header: Header,
    pub status: ReadStatus,
    ended: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(mut inner: R) -> io::Result<Self> {
        let mut bytes = [0; HEADER_SIZE];
        inner.read_exact(&mut bytes)?;
        Ok(Self {
            inner,
            header: Header::decode(&bytes)?,
            status: ReadStatus::default(),
            ended: false,
        })
    }

    pub fn next_event(&mut self) -> io::Result<Option<Event>> {
        if self.ended {
            return Ok(None);
        }
        let mut bytes = [0; EVENT_SIZE];
        if let Err(error) = self.inner.read_exact(&mut bytes) {
            self.ended = true;
            if error.kind() == io::ErrorKind::UnexpectedEof {
                self.status.truncated = true;
                return Ok(None);
            }
            return Err(error);
        }
        if bytes[36] == 255 {
            self.ended = true;
            if verify(&bytes).is_err()
                || word(&bytes, 0) != self.status.events
                || bytes[16..36] != [0; 20]
            {
                self.status.corrupt = true;
                return Ok(None);
            }
            self.status.dropped = Some(word(&bytes, 8));
            let mut extra = [0; 1];
            loop {
                match self.inner.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => {
                        self.status.corrupt = true;
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
            self.status.complete = self.status.dropped == Some(0) && !self.status.corrupt;
            return Ok(None);
        }
        match Event::decode(&bytes) {
            Ok(event) => {
                self.status.events += 1;
                Ok(Some(event))
            }
            Err(_) => {
                self.status.corrupt = true;
                self.ended = true;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicUsize;

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "flowgen-record-{}-{}.fgr",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn event(kind: Kind) -> Event {
        if kind == Kind::Error {
            return Event::error(7, 8, 123, ErrorStage::Connect, 111);
        }
        Event {
            flow: 7,
            seq: 8,
            time_ns: 123,
            value: 456,
            len: 128,
            kind,
        }
    }

    #[test]
    fn recording_modes_have_explicit_parse_and_lifecycle_semantics() {
        assert_eq!(Mode::parse("EVENTS"), Some(Mode::Events));
        assert_eq!(Mode::parse("FULL"), Some(Mode::Events));
        assert_eq!(Mode::parse("summary"), Some(Mode::Summary));
        assert_eq!(Mode::parse("Off"), Some(Mode::Off));
        assert_eq!(Mode::parse("unknown"), None);
        assert_eq!(Mode::Events.as_str(), "events");
        assert_eq!("summary".parse::<Mode>(), Ok(Mode::Summary));
        assert_eq!(Mode::Events, Mode::Full);
        assert_eq!(Mode::Summary.as_str(), "summary");
        assert_eq!(Mode::Off.as_str(), "off");

        let off_path = path();
        let mut off = Recording::create(&off_path, 1, false, false, Mode::Off).unwrap();
        off.push(event(Kind::Response));
        assert_eq!(off.dropped(), 0);
        assert_eq!(off.finish().unwrap(), RecordSummary::default());
        assert!(!off_path.exists());

        let full_path = path();
        let mut full = Recording::create(&full_path, 1, false, false, Mode::Events).unwrap();
        assert_eq!(full.mode(), Mode::Events);
        full.push(event(Kind::Response));
        assert_eq!(full.finish().unwrap().events, 1);
        let mut reader = Reader::new(File::open(&full_path).unwrap()).unwrap();
        assert_eq!(reader.next_event().unwrap(), Some(event(Kind::Response)));
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.complete);
        std::fs::remove_file(full_path).unwrap();
    }

    #[test]
    fn summary_mode_aggregates_responses_and_writes_mergeable_worker_csv() {
        let path = path();
        let mut recording = Recording::create(&path, 9, true, false, Mode::Summary).unwrap();
        for response in [100, 200, 300] {
            recording.push(Event {
                flow: response,
                seq: 1,
                time_ns: 0,
                value: response,
                len: 0,
                kind: Kind::Response,
            });
        }
        recording.push(Event::session_skipped(0, 0, 4));
        recording.push(Event {
            flow: 0,
            seq: 0,
            time_ns: 0,
            value: 0,
            len: 0,
            kind: Kind::Failed,
        });
        let summary = recording.summary();
        assert_eq!(summary.run(), 9);
        assert!(summary.tcp());
        assert!(!summary.server());
        assert_eq!(summary.events(), 5);
        assert_eq!(summary.count(Kind::Response), 3);
        assert_eq!(summary.count(Kind::SessionSkipped), 4);
        assert_eq!(summary.count(Kind::Failed), 1);
        assert_eq!(summary.response_samples(), 3);
        assert_eq!(summary.response_min_ns(), Some(100));
        assert_eq!(summary.response_max_ns(), Some(300));
        assert_eq!(summary.response_avg_ns(), Some(200.0));
        assert_eq!(
            summary.response_mdev_ns(),
            Some((20_000.0_f64 / 3.0).sqrt())
        );
        assert!(summary.response_quantile_ns(0.50).unwrap() >= 100);
        let mut console = Vec::new();
        summary.write_console(&mut console).unwrap();
        let console = String::from_utf8(console).unwrap();
        assert!(console.contains("samples=3"));
        assert!(console.contains("min/avg/max/mdev"));
        assert!(console.contains("p50/p95/p99"));

        let mut merged = summary.clone();
        merged.merge(&summary).unwrap();
        assert_eq!(merged.events(), 10);
        assert_eq!(merged.response_samples(), 6);
        assert_eq!(merged.response_avg_ns(), Some(200.0));
        let mut wrong = RecordingSummary::new(10, true, false).unwrap();
        assert_eq!(
            wrong.merge(&summary).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );

        assert_eq!(
            recording.finish().unwrap(),
            RecordSummary {
                dropped: 0,
                events: 5
            }
        );
        let csv = std::fs::read_to_string(&path).unwrap();
        assert!(csv
            .lines()
            .next()
            .unwrap()
            .starts_with("record_type,run,protocol,role"));
        assert!(csv
            .lines()
            .any(|line| line.starts_with("aggregate,9,tcp,client,5,")));
        assert_eq!(
            csv.lines()
                .filter(|line| line.starts_with("histogram,"))
                .count(),
            3
        );
        for line in csv.lines() {
            assert_eq!(line.split(',').count(), 33, "CSV column count: {line}");
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn finished_worker_summaries_merge_unequal_and_empty_rtt_samples() {
        let mut aggregate = RecordingSummary::new(42, false, false).unwrap();
        for samples in [&[][..], &[100][..], &[200, 300, 400][..], &[][..]] {
            let path = path();
            let mut worker = Recording::create(&path, 42, false, false, Mode::Summary).unwrap();
            for &value in samples {
                worker.push(Event {
                    value,
                    ..event(Kind::Response)
                });
            }
            worker.push(Event::session_skipped(0, 0, 2));
            let (counts, summary) = worker.finish_with_summary().unwrap();
            assert_eq!(counts.events, samples.len() as u64 + 1);
            assert_eq!(counts.dropped, 0);
            aggregate.merge(&summary).unwrap();
            std::fs::remove_file(path).unwrap();
        }
        assert_eq!(aggregate.events(), 8);
        assert_eq!(aggregate.count(Kind::SessionSkipped), 8);
        assert_eq!(aggregate.count(Kind::Response), 4);
        assert_eq!(aggregate.response_samples(), 4);
        assert_eq!(aggregate.response_min_ns(), Some(100));
        assert_eq!(aggregate.response_max_ns(), Some(400));
        assert_eq!(aggregate.response_avg_ns(), Some(250.0));
        assert_eq!(aggregate.response_mdev_ns(), Some(12_500.0_f64.sqrt()));
        assert_eq!(aggregate.response_quantile_ns(0.5), Some(200));
        assert_eq!(aggregate.response_quantile_ns(0.99), Some(400));
        let mut console = Vec::new();
        aggregate.write_console(&mut console).unwrap();
        let console = String::from_utf8(console).unwrap();
        assert_eq!(console.lines().count(), 1);
        assert!(console.contains("samples=4"));
    }

    #[test]
    fn summary_rtt_histogram_does_not_clamp_u64_response_values() {
        let path = path();
        let mut recording = Recording::create(&path, 3, false, true, Mode::Summary).unwrap();
        recording.push(Event {
            flow: 1,
            seq: 1,
            time_ns: 0,
            value: u64::MAX,
            len: 0,
            kind: Kind::Response,
        });
        let summary = recording.summary();
        assert_eq!(summary.response_samples(), 1);
        assert!(summary.response_max_ns().unwrap() >= u64::MAX - 1_000_000_000);
        assert!(summary.response_quantile_ns(0.99).unwrap() >= u64::MAX - 1);
        recording.finish().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    fn legacy_encode(event: Event) -> [u8; EVENT_SIZE] {
        let mut bytes = [0; EVENT_SIZE];
        bytes[0..8].copy_from_slice(&event.flow.to_le_bytes());
        bytes[8..16].copy_from_slice(&event.seq.to_le_bytes());
        bytes[16..24].copy_from_slice(&event.time_ns.to_le_bytes());
        bytes[24..32].copy_from_slice(&event.value.to_le_bytes());
        bytes[32..36].copy_from_slice(&event.len.to_le_bytes());
        bytes[36] = event.kind as u8;
        seal(&mut bytes);
        bytes
    }

    fn varied_event(index: usize) -> Event {
        let mut value = event(Kind::from_byte((index % 18) as u8).unwrap());
        value.flow = (index as u64).wrapping_mul(0xfedcba9876543211);
        value.seq = index as u64;
        value.time_ns = u64::MAX - index as u64;
        value.len = index as u32;
        if value.kind != Kind::Error {
            value.value = (index as u64).wrapping_mul(0x8123456789abcdef);
        }
        value
    }

    #[test]
    fn batch_encoding_matches_legacy_bytes_after_reuse_and_partial_batches() {
        let mut batch = Batch {
            bytes: vec![0xa5; BATCH_EVENTS * EVENT_SIZE].into_boxed_slice(),
            events: 0,
        };
        for (round, count) in [BATCH_EVENTS, 7, 1, 0, 1023, 4, 2, 3]
            .into_iter()
            .enumerate()
        {
            batch.events = 0;
            let untouched = batch.bytes[count * EVENT_SIZE..].to_vec();
            for index in 0..count {
                batch.push(varied_event(round * BATCH_EVENTS + index));
            }
            batch.seal();
            for index in 0..count {
                let event = varied_event(round * BATCH_EVENTS + index);
                let actual = &batch.bytes[index * EVENT_SIZE..(index + 1) * EVENT_SIZE];
                assert_eq!(actual, legacy_encode(event));
                assert_eq!(actual, event.encode());
                assert_eq!(Event::decode(actual.try_into().unwrap()).unwrap(), event);
            }
            assert_eq!(&batch.bytes[count * EVENT_SIZE..], untouched);
        }
    }

    #[test]
    fn recorder_full_and_partial_batches_match_legacy_stream() {
        let path = path();
        let mut recorder = Recorder::create(&path, 42, true, true).unwrap();
        let count = BATCH_EVENTS * 2 + 7;
        let mut expected = Header {
            run: 42,
            tcp: true,
            server: true,
        }
        .encode()
        .to_vec();
        for index in 0..count {
            let event = varied_event(index);
            expected.extend_from_slice(&legacy_encode(event));
            recorder.push(event);
        }
        let summary = recorder.finish().unwrap();
        assert_eq!(summary.events, count as u64);
        assert_eq!(summary.dropped, 0);
        let mut footer = [0; EVENT_SIZE];
        footer[..8].copy_from_slice(&(count as u64).to_le_bytes());
        footer[36] = 255;
        seal(&mut footer);
        expected.extend_from_slice(&footer);
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    #[ignore = "manual release-mode encoding/checksum microbenchmark"]
    fn benchmark_record_encoding() {
        use std::hint::black_box;
        use std::time::Instant;

        const ROUNDS: usize = 2048;
        let events: Vec<_> = (0..BATCH_EVENTS).map(varied_event).collect();
        let mut batch = Batch {
            bytes: vec![0; BATCH_EVENTS * EVENT_SIZE].into_boxed_slice(),
            events: BATCH_EVENTS,
        };
        for mode in 0..4 {
            let mut samples = Vec::new();
            for _ in 0..5 {
                let start = Instant::now();
                for _ in 0..ROUNDS {
                    match mode {
                        0 => {
                            for (index, event) in black_box(&events).iter().enumerate() {
                                batch.bytes[index * EVENT_SIZE..(index + 1) * EVENT_SIZE]
                                    .copy_from_slice(&legacy_encode(*event));
                            }
                        }
                        1 => {
                            batch.events = 0;
                            for event in black_box(&events) {
                                batch.push(*event);
                            }
                        }
                        2 => {
                            for bytes in batch.bytes[..batch.events * EVENT_SIZE]
                                .as_chunks_mut::<EVENT_SIZE>()
                                .0
                            {
                                seal(bytes);
                            }
                        }
                        3 => batch.seal(),
                        _ => unreachable!(),
                    }
                    black_box(&batch.bytes);
                }
                samples.push(start.elapsed().as_nanos() as f64 / (ROUNDS * BATCH_EVENTS) as f64);
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "{}: median {:.2} ns/event (5 samples, {} events/sample)",
                [
                    "legacy producer",
                    "direct producer",
                    "scalar writer checksum",
                    "interleaved writer checksum"
                ][mode],
                samples[2],
                ROUNDS * BATCH_EVENTS
            );
        }
    }

    #[test]
    fn roundtrip_all_kinds_and_create_new() {
        let path = path();
        let mut recorder = Recorder::create(&path, 42, true, false).unwrap();
        assert!(Recorder::create(&path, 42, true, false).is_err());
        for kind in 0..18 {
            recorder.push(event(Kind::from_byte(kind).unwrap()));
        }
        assert_eq!(recorder.dropped(), 0);
        assert_eq!(
            recorder.finish().unwrap(),
            RecordSummary {
                dropped: 0,
                events: 18
            }
        );
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        assert_eq!(
            reader.header,
            Header {
                run: 42,
                tcp: true,
                server: false
            }
        );
        for kind in 0..18 {
            assert_eq!(
                reader.next_event().unwrap(),
                Some(event(Kind::from_byte(kind).unwrap()))
            );
        }
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.complete);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn error_values_preserve_all_stages_and_signed_errno() {
        let stages = [
            (ErrorStage::Socket, "socket"),
            (ErrorStage::Bind, "bind"),
            (ErrorStage::Connect, "connect"),
            (ErrorStage::Register, "register"),
            (ErrorStage::Send, "send"),
            (ErrorStage::Receive, "receive"),
            (ErrorStage::Decode, "decode"),
            (ErrorStage::SetupTimeout, "setup_timeout"),
            (ErrorStage::SendTimeout, "send_timeout"),
            (ErrorStage::Interest, "interest"),
        ];
        for (index, (stage, name)) in stages.into_iter().enumerate() {
            assert_eq!(stage as u32, index as u32 + 1);
            assert_eq!(stage.as_str(), name);
            assert_eq!(unpack_error(stage.encode(None)), Some((stage, 0)));
            for errno in [0, 1, 111, -1, i32::MIN, i32::MAX] {
                let packed = pack_error(stage, errno);
                assert_eq!(stage.encode(Some(errno)), packed);
                assert_eq!(packed >> 32, stage as u64);
                assert_eq!(packed as u32, errno as u32);
                assert_eq!(unpack_error(packed), Some((stage, errno)));
                let event = Event::error(7, 8, 123, stage, errno);
                let decoded = Event::decode(&event.encode()).unwrap();
                assert_eq!(decoded, event);
                assert_eq!(decoded.error_details(), Some((stage, errno)));
                assert_eq!(decoded.len, 0);
                assert_eq!(decoded.kind, Kind::Error);
            }
        }
        let mut other = event(Kind::Failed);
        other.value = pack_error(ErrorStage::Connect, 111);
        assert_eq!(other.error_details(), None);
        for value in [0, 11_u64 << 32, 0x101_u64 << 32, u64::MAX] {
            assert_eq!(unpack_error(value), None);
            let mut error = event(Kind::Error);
            error.value = value;
            assert_eq!(error.error_details(), None);
            assert_eq!(
                Event::decode(&error.encode()).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn session_skip_batch_is_distinct_from_request_skip() {
        let skipped = Event::session_skipped(7, 123, 42);
        assert_eq!(skipped.flow, 7);
        assert_eq!(skipped.seq, 0);
        assert_eq!(skipped.time_ns, 123);
        assert_eq!(skipped.value, 42);
        assert_eq!(skipped.len, 0);
        assert_eq!(skipped.kind, Kind::SessionSkipped);
        assert_eq!(Event::decode(&skipped.encode()).unwrap(), skipped);
        assert_eq!(Kind::Skipped as u8, 14);
        assert_eq!(Kind::Reordered as u8, 15);
        assert_eq!(Kind::SessionSkipped as u8, 16);
        assert_eq!(Kind::Error as u8, 17);
    }

    #[test]
    fn frozen_v1_recording_remains_readable_and_byte_identical() {
        // Independently encoded v1 header, request Skipped event, and footer.
        // This fixture does not use today's writer to construct the input.
        let hex = concat!(
            "4647524c4f470d0a01002000280000002a00000000000000000000005e8803dd",
            "070000000000000008000000000000007b00000000000000c801000000000000",
            "800000000e30e286",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "00000000ff2123a5",
        );
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut reader = Reader::new(Cursor::new(&bytes)).unwrap();
        assert_eq!(reader.header.run, 42);
        assert!(!reader.header.tcp);
        assert!(!reader.header.server);
        assert_eq!(reader.header.encode(), bytes[..HEADER_SIZE]);
        let expected = event(Kind::Skipped);
        assert_eq!(reader.next_event().unwrap(), Some(expected));
        assert_eq!(
            expected.encode(),
            bytes[HEADER_SIZE..HEADER_SIZE + EVENT_SIZE]
        );
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.complete);
        assert_eq!(reader.status.events, 1);
        assert_eq!(reader.status.dropped, Some(0));
    }

    #[test]
    fn unknown_error_stage_stops_reader_at_verified_prefix() {
        let mut bytes = Header {
            run: 1,
            tcp: false,
            server: false,
        }
        .encode()
        .to_vec();
        bytes.extend_from_slice(&event(Kind::Open).encode());
        let mut error = event(Kind::Error);
        error.value = 11_u64 << 32;
        bytes.extend_from_slice(&error.encode());
        let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
        assert_eq!(reader.next_event().unwrap(), Some(event(Kind::Open)));
        assert!(reader.next_event().unwrap().is_none());
        assert_eq!(reader.status.events, 1);
        assert!(reader.status.corrupt);
        assert!(!reader.status.complete);
        assert!(reader.next_event().unwrap().is_none());
    }

    #[test]
    fn truncated_at_every_byte_preserves_verified_prefix() {
        let path = path();
        let mut recorder = Recorder::create(&path, 42, false, true).unwrap();
        recorder.push(event(Kind::Sent));
        recorder.push(event(Kind::Response));
        recorder.finish().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        for end in 0..bytes.len() {
            let result = Reader::new(Cursor::new(&bytes[..end]));
            if end < HEADER_SIZE {
                assert!(result.is_err());
                continue;
            }
            let mut reader = result.unwrap();
            while reader.next_event().unwrap().is_some() {}
            assert!(reader.status.truncated);
            assert!(!reader.status.complete);
            assert_eq!(
                reader.status.events as usize,
                ((end - HEADER_SIZE) / EVENT_SIZE).min(2)
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn corrupt_headers_records_footer_and_trailing_data() {
        let path = path();
        let mut recorder = Recorder::create(&path, 42, true, true).unwrap();
        recorder.push(event(Kind::Sent));
        recorder.push(event(Kind::Response));
        recorder.finish().unwrap();
        let original = std::fs::read(&path).unwrap();
        for at in 0..original.len() {
            let mut bytes = original.clone();
            bytes[at] ^= 0x80;
            let result = Reader::new(Cursor::new(bytes));
            if at < HEADER_SIZE {
                assert!(result.is_err());
                continue;
            }
            let mut reader = result.unwrap();
            while reader.next_event().unwrap().is_some() {}
            assert!(reader.status.corrupt);
            assert!(!reader.status.complete);
        }
        let mut bytes = original;
        bytes.push(0);
        let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
        while reader.next_event().unwrap().is_some() {}
        assert!(reader.status.corrupt);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn stalled_writer_drops_without_growing_buffers() {
        // Replace the writer channel with a receiver deliberately never drained.
        let path = path();
        let mut recorder = Recorder::create(&path, 1, false, false).unwrap();
        let (blocked, _receiver) = mpsc::sync_channel(1);
        let original = std::mem::replace(&mut recorder.sender, blocked);
        drop(original);
        for _ in 0..BATCH_EVENTS * 4 {
            recorder.push(event(Kind::Sent));
        }
        assert_eq!(recorder.dropped(), (BATCH_EVENTS * 3) as u64);
        drop(recorder.sender);
        recorder.writer.join().unwrap().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dropped_batches_preserve_retained_events_and_exact_footer_accounting() {
        let path = path();
        let mut recorder = Recorder::create(&path, 1, false, false).unwrap();
        let (blocked, receiver) = mpsc::sync_channel(1);
        let original = std::mem::replace(&mut recorder.sender, blocked);
        // Keep the actual writer waiting while two full batches are rejected.
        let count = BATCH_EVENTS * 3 + 7;
        for index in 0..count {
            recorder.push(varied_event(index));
        }
        assert_eq!(recorder.dropped(), (BATCH_EVENTS * 2) as u64);
        // Forward the accepted batch and let finish flush the reused partial one.
        original.send(receiver.try_recv().unwrap()).unwrap();
        recorder.sender = original;
        let summary = recorder.finish().unwrap();
        assert_eq!(summary.events, (BATCH_EVENTS + 7) as u64);
        assert_eq!(summary.dropped, (BATCH_EVENTS * 2) as u64);
        assert_eq!(summary.events + summary.dropped, count as u64);
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        for index in (0..BATCH_EVENTS).chain(BATCH_EVENTS * 3..count) {
            assert_eq!(reader.next_event().unwrap(), Some(varied_event(index)));
        }
        assert!(reader.next_event().unwrap().is_none());
        assert_eq!(reader.status.events, summary.events);
        assert_eq!(reader.status.dropped, Some(summary.dropped));
        assert!(!reader.status.complete);
        assert!(!reader.status.corrupt);
        assert!(!reader.status.truncated);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn exhausted_buffers_drop_without_encoding_or_waiting() {
        let path = path();
        let mut recorder = Recorder::create(&path, 1, false, false).unwrap();
        let mut held = Vec::new();
        while let Ok(batch) = recorder.spare.try_recv() {
            held.push(batch);
        }
        assert_eq!(held.len(), QUEUED_BATCHES + 2);
        recorder.push(event(Kind::Sent));
        assert_eq!(recorder.dropped(), 1);
        assert!(recorder.current.is_none());
        recorder.current = held.pop();
        recorder.push(event(Kind::Response));
        let summary = recorder.finish().unwrap();
        assert_eq!(summary.events, 1);
        assert_eq!(summary.dropped, 1);
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        assert_eq!(reader.next_event().unwrap(), Some(event(Kind::Response)));
        assert!(reader.next_event().unwrap().is_none());
        assert_eq!(reader.status.dropped, Some(1));
        assert!(!reader.status.corrupt);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_drain_without_finish_leaves_no_footer() {
        let path = path();
        let mut recorder = Recorder::create(&path, 1, false, false).unwrap();
        for index in 0..BATCH_EVENTS + 7 {
            recorder.push(varied_event(index));
        }
        // Join only to make the test deterministic; abandon the partial batch.
        drop(recorder.current);
        drop(recorder.sender);
        let (_, written) = recorder.writer.join().unwrap().unwrap();
        assert_eq!(written, BATCH_EVENTS as u64);
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        for index in 0..BATCH_EVENTS {
            assert_eq!(reader.next_event().unwrap(), Some(varied_event(index)));
        }
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.truncated);
        assert!(!reader.status.complete);
        assert!(!reader.status.corrupt);
        assert_eq!(reader.status.dropped, None);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn footer_exposes_logging_gaps() {
        let path = path();
        let recorder = Recorder::create(&path, 1, false, false).unwrap();
        recorder.dropped.store(19, Ordering::Relaxed);
        let summary = recorder.finish().unwrap();
        assert_eq!(summary.dropped, 19);
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        assert!(reader.next_event().unwrap().is_none());
        assert_eq!(reader.status.dropped, Some(19));
        assert!(!reader.status.complete);
        assert!(!reader.status.truncated);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn writer_io_failure_counts_every_event_and_leaves_no_footer() {
        let path = path();
        File::create(&path)
            .unwrap()
            .write_all(
                &Header {
                    run: 1,
                    tcp: false,
                    server: false,
                }
                .encode(),
            )
            .unwrap();
        // A read-only descriptor deterministically fails the writer's write_all.
        let mut recorder = Recorder::with_file(File::open(&path).unwrap()).unwrap();
        let dropped = Arc::clone(&recorder.dropped);
        let count = BATCH_EVENTS * 3 + 7;
        for _ in 0..count {
            recorder.push(event(Kind::Sent));
        }
        assert!(recorder.finish().is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), count as u64);
        let mut reader = Reader::new(File::open(&path).unwrap()).unwrap();
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.truncated);
        assert_eq!(reader.status.dropped, None);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn validated_checksums_do_not_bypass_kind_or_footer_count_checks() {
        let path = path();
        let mut recorder = Recorder::create(&path, 1, false, false).unwrap();
        recorder.push(event(Kind::Sent));
        recorder.finish().unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let footer: &mut [u8; EVENT_SIZE] =
            (&mut bytes[HEADER_SIZE + EVENT_SIZE..]).try_into().unwrap();
        footer[0] = 2;
        seal(footer);
        let mut reader = Reader::new(Cursor::new(&bytes)).unwrap();
        assert!(reader.next_event().unwrap().is_some());
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.corrupt);
        let record: &mut [u8; EVENT_SIZE] = (&mut bytes[HEADER_SIZE..HEADER_SIZE + EVENT_SIZE])
            .try_into()
            .unwrap();
        record[36] = 99;
        seal(record);
        let mut reader = Reader::new(Cursor::new(&bytes)).unwrap();
        assert!(reader.next_event().unwrap().is_none());
        assert!(reader.status.corrupt);
        std::fs::remove_file(path).unwrap();
    }
}
