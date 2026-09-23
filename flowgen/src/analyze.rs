//! Bounded-memory offline analysis of all immediate-directory *.fgr files.
//!
//! Output: sessions.csv, summary.csv (per run/protocol/role), recordings.csv,
//! errors.csv (diagnostic counts by stage/errno), forward.csv (UDP sessions)
//! and forward-summary.csv (UDP runs).
//! CSV times are nanoseconds; console times are milliseconds. Empty CSV
//! measurements are `NA`. RTT/jitter moments use
//! unbucketed samples; mdev is population standard deviation. Quantiles use
//! HDR histograms with 3 significant digits (about 0.1% relative precision).
//! Session means are rounded to integer nanoseconds for their distribution.
//! A Response means a first on-time completion; Duplicate/Late never add RTT.
//! Reordered is a separate annotation, so a reordered success still needs its
//! Response record. Repeated Response records for a sequence are deduplicated.
//! Client Ready.value supplies one setup sample per session; server Ready is
//! only an acknowledgement marker and does not supply setup latency.
//! SessionSkipped.value counts scheduler skips without creating sessions. Error
//! is diagnostic only; Failed remains the sole session-failure event counter.
//! Skipped.value counts missed request-send slots, while events counts records.
//! Response timeout % is unique timed-out Sent / (unique Sent - canceled Sent).
//! Unsent cancellations do not reduce that denominator. Late is separate, and
//! incomplete logs, unresolved requests or contradictory outcomes suppress %.
//! This is TCP request timeout or UDP round-trip probe timeout, not path loss.
//! Forward UDP reconciliation joins unique client Sent to server ServerRequest
//! by (run, flow, seq), including sends subsequently canceled by the client.
//! It requires complete logs and matching client-final.txt/server-final.txt
//! manifests: raw Sent and ServerRequest counts must equal the endpoint totals.
//! These small end manifests establish completeness, not authentication. No
//! endpoint clocks are compared. Manifests cover one run; others remain partial.
//!
//! Sort chunks contain at most 65,536 entries, with 32-way multipass merging.
//! Only one session, one run/role/protocol group, four totals and three worst
//! sessions are held in memory. Even an arbitrarily long single session is
//! streamed. Temporary file names are generated from counters, not retained
//! in an unbounded list. Full-u64 HDR histograms are themselves bounded.

use crate::record::{unpack_error, Event, Header, Kind, ReadStatus, Reader, EVENT_SIZE};
use hdrhistogram::Histogram;
use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

const CHUNK_ENTRIES: usize = 65_536;
const MERGE_FAN_IN: usize = 32;
const IO_BUFFER: usize = 64 * 1024;
const ENTRY_SIZE: usize = 16 + EVENT_SIZE;
const KINDS: usize = 18;
const COUNTER_COLUMNS: &str = "open,ready,sent,response_records,timeout,canceled,closed,failed,server_request,server_response,duplicate,late,invalid,limited,skipped,reordered,session_skipped,error";
const METRIC_COLUMNS: &str = "rtt_samples,rtt_min_ns,rtt_avg_ns,rtt_max_ns,rtt_mdev_ns,rtt_p50_ns,rtt_p95_ns,rtt_p99_ns,jitter_pairs,jitter_avg_ns,jitter_p95_ns,jitter_p99_ns";
const QUALITY_COLUMNS: &str = "incomplete,logging_dropped,unknown_dropped_files,truncated_files,corrupt_files,unknown_header_files,conflicting_sequences";
const SETUP_COLUMNS: &str = "setup_samples,setup_avg_ns,setup_p50_ns,setup_p95_ns,setup_p99_ns";
const TIMEOUT_COLUMNS: &str = "sent_unique,sent_canceled_unique,unsent_canceled_unique,sent_timeout_unique,sent_late_unique,unresolved_sent_unique,orphan_outcomes_unique,conflicting_outcomes_unique,response_timeout_denominator,response_timeout_pct,response_timeout_status";
const FORWARD_COLUMNS: &str = "observed_sent_unique,observed_server_request_unique,observed_matched_unique,observed_server_only_unique,forward_delivered_unique,forward_missing_unique,forward_missing_pct,forward_status,client_files,server_files,logging_dropped,unknown_dropped_files,truncated_files,corrupt_files,unknown_header_files,run_client_sent_records,run_server_request_records,manifest_client_sent,manifest_server_request,manifest_status";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Group {
    run: u64,
    tcp: bool,
    server: bool,
}

impl From<Header> for Group {
    fn from(header: Header) -> Self {
        Self {
            run: header.run,
            tcp: header.tcp,
            server: header.server,
        }
    }
}

impl Group {
    fn protocol(self) -> &'static str {
        if self.tcp {
            "tcp"
        } else {
            "udp"
        }
    }
    fn role(self) -> &'static str {
        if self.server {
            "server"
        } else {
            "client"
        }
    }
    fn total_index(self) -> usize {
        usize::from(self.tcp) * 2 + usize::from(self.server)
    }
    fn write_csv(self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "{},{},{}", self.run, self.protocol(), self.role())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    group: Group,
    metadata: bool,
    event: Event,
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        let key = |entry: &Self| {
            (
                entry.group,
                !entry.metadata,
                entry.event.flow,
                entry.event.seq,
                entry.event.kind,
                entry.event.time_ns,
                entry.event.value,
                entry.event.len,
            )
        };
        key(self).cmp(&key(other))
    }
}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Entry {
    fn metadata(group: Group, status: ReadStatus) -> Self {
        Self {
            group,
            metadata: true,
            event: Event {
                flow: 1,
                seq: status.dropped.unwrap_or(0),
                time_ns: 0,
                value: 0,
                len: u32::from(status.dropped.is_none())
                    | (u32::from(status.truncated) << 1)
                    | (u32::from(status.corrupt) << 2),
                kind: Kind::Open,
            },
        }
    }

    fn write(self, out: &mut impl Write) -> io::Result<()> {
        let mut bytes = [0; ENTRY_SIZE];
        bytes[..8].copy_from_slice(&self.group.run.to_le_bytes());
        bytes[8] = u8::from(self.group.tcp) | (u8::from(self.group.server) << 1);
        bytes[9] = u8::from(self.metadata);
        bytes[16..].copy_from_slice(&self.event.encode());
        out.write_all(&bytes)
    }

    fn read(input: &mut impl Read) -> io::Result<Option<Self>> {
        let mut bytes = [0; ENTRY_SIZE];
        loop {
            match input.read(&mut bytes[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        input.read_exact(&mut bytes[1..])?;
        if bytes[8] & !3 != 0 || bytes[9] > 1 || bytes[10..16] != [0; 6] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "damaged temporary sort run",
            ));
        }
        Ok(Some(Self {
            group: Group {
                run: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
                tcp: bytes[8] & 1 != 0,
                server: bytes[8] & 2 != 0,
            },
            metadata: bytes[9] != 0,
            event: Event::decode(bytes[16..].try_into().unwrap())?,
        }))
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(dir: &Path) -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        for _ in 0..1024 {
            let path = dir.join(format!(
                ".flowgen-analysis-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate analysis scratch directory",
        ))
    }

    fn run_path(&self, stage: u64, index: u64) -> PathBuf {
        self.0.join(format!("sort-{stage}-{index}.bin"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn output(path: &Path) -> io::Result<BufWriter<File>> {
    Ok(BufWriter::with_capacity(
        IO_BUFFER,
        OpenOptions::new().write(true).create_new(true).open(path)?,
    ))
}

struct Sorter {
    scratch: Scratch,
    chunk: Vec<Entry>,
    chunk_limit: usize,
    fan_in: usize,
    runs: u64,
}

impl Sorter {
    fn new(dir: &Path, chunk_limit: usize, fan_in: usize) -> io::Result<Self> {
        if chunk_limit == 0 || fan_in < 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sort bounds",
            ));
        }
        Ok(Self {
            scratch: Scratch::new(dir)?,
            chunk: Vec::with_capacity(chunk_limit),
            chunk_limit,
            fan_in,
            runs: 0,
        })
    }

    fn push(&mut self, entry: Entry) -> io::Result<()> {
        self.chunk.push(entry);
        if self.chunk.len() == self.chunk_limit {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> io::Result<()> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        self.chunk.sort_unstable();
        let mut out = output(&self.scratch.run_path(0, self.runs))?;
        for entry in &self.chunk {
            entry.write(&mut out)?;
        }
        out.flush()?;
        self.chunk.clear();
        self.runs += 1;
        Ok(())
    }

    fn merge(&mut self) -> io::Result<Option<PathBuf>> {
        self.spill()?;
        let mut stage = 0;
        let mut runs = self.runs;
        while runs > 1 {
            let mut next = 0;
            let mut start = 0;
            while start < runs {
                let end = (start + self.fan_in as u64).min(runs);
                merge_runs(&self.scratch, stage, start, end, next)?;
                for index in start..end {
                    fs::remove_file(self.scratch.run_path(stage, index))?;
                }
                next += 1;
                start = end;
            }
            runs = next;
            stage += 1;
        }
        Ok((runs == 1).then(|| self.scratch.run_path(stage, 0)))
    }
}

fn merge_runs(
    scratch: &Scratch,
    stage: u64,
    start: u64,
    end: u64,
    destination: u64,
) -> io::Result<()> {
    let mut sources = Vec::with_capacity((end - start) as usize);
    let mut heap = BinaryHeap::new();
    for index in start..end {
        let mut reader =
            BufReader::with_capacity(IO_BUFFER, File::open(scratch.run_path(stage, index))?);
        if let Some(entry) = Entry::read(&mut reader)? {
            heap.push(Reverse((entry, sources.len())));
        }
        sources.push(reader);
    }
    let mut out = output(&scratch.run_path(stage + 1, destination))?;
    while let Some(Reverse((entry, source))) = heap.pop() {
        entry.write(&mut out)?;
        if let Some(next) = Entry::read(&mut sources[source])? {
            heap.push(Reverse((next, source)));
        }
    }
    out.flush()
}

struct Samples {
    count: u64,
    min: u64,
    max: u64,
    mean: f64,
    m2: f64,
    histogram: Histogram<u64>,
}

impl Default for Samples {
    fn default() -> Self {
        Self {
            count: 0,
            min: u64::MAX,
            max: 0,
            mean: 0.0,
            m2: 0.0,
            histogram: Histogram::new(3).expect("valid HDR precision"),
        }
    }
}

impl Samples {
    fn add(&mut self, value: u64) -> io::Result<()> {
        self.histogram.record(value).map_err(io::Error::other)?;
        self.count += 1;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
        let delta = value as f64 - self.mean;
        self.mean += delta / self.count as f64;
        self.m2 += delta * (value as f64 - self.mean);
        Ok(())
    }

    fn mdev(&self) -> f64 {
        (self.m2.max(0.0) / self.count as f64).sqrt()
    }
    fn quantile(&self, q: f64) -> u64 {
        self.histogram.value_at_quantile(q)
    }

    fn write_rtt(&self, out: &mut impl Write) -> io::Result<()> {
        if self.count == 0 {
            return write!(out, "0,NA,NA,NA,NA,NA,NA,NA");
        }
        write!(
            out,
            "{},{},{:.3},{},{:.3},{},{},{}",
            self.count,
            self.min,
            self.mean,
            self.max,
            self.mdev(),
            self.quantile(0.50),
            self.quantile(0.95),
            self.quantile(0.99)
        )
    }

    fn write_jitter(&self, out: &mut impl Write) -> io::Result<()> {
        if self.count == 0 {
            return write!(out, "0,NA,NA,NA");
        }
        write!(
            out,
            "{},{:.3},{},{}",
            self.count,
            self.mean,
            self.quantile(0.95),
            self.quantile(0.99)
        )
    }

    fn write_setup(&self, out: &mut impl Write) -> io::Result<()> {
        if self.count == 0 {
            return write!(out, "0,NA,NA,NA,NA");
        }
        write!(
            out,
            "{},{:.3},{},{},{}",
            self.count,
            self.mean,
            self.quantile(0.50),
            self.quantile(0.95),
            self.quantile(0.99)
        )
    }
}

#[derive(Default)]
struct Quality {
    files: u64,
    dropped: u64,
    unknown: u64,
    truncated: u64,
    corrupt: u64,
}

impl Quality {
    fn add(&mut self, entry: Entry) {
        self.files += 1;
        self.dropped += entry.event.seq;
        self.unknown += u64::from(entry.event.len & 1 != 0);
        self.truncated += u64::from(entry.event.len & 2 != 0);
        self.corrupt += u64::from(entry.event.len & 4 != 0);
    }

    fn incomplete(&self, bad_headers: u64, conflicts: u64) -> bool {
        self.dropped != 0
            || self.unknown != 0
            || self.truncated != 0
            || self.corrupt != 0
            || bad_headers != 0
            || conflicts != 0
    }

    fn write_csv(&self, out: &mut impl Write, bad_headers: u64, conflicts: u64) -> io::Result<()> {
        write!(
            out,
            "{},{},{},{},{},{},{}",
            self.incomplete(bad_headers, conflicts),
            self.dropped,
            self.unknown,
            self.truncated,
            self.corrupt,
            bad_headers,
            conflicts
        )
    }
}

#[derive(Default)]
struct Timeouts {
    sent: u64,
    canceled: u64,
    unsent_canceled: u64,
    timed_out: u64,
    late: u64,
    unresolved: u64,
    orphaned: u64,
    conflicting: u64,
}

impl Timeouts {
    fn observe(&mut self, sequence: &Sequence) {
        if !sequence.client {
            return;
        }
        if sequence.sent {
            self.sent += 1;
            self.canceled += u64::from(sequence.canceled);
            self.timed_out += u64::from(sequence.timed_out);
            self.late += u64::from(sequence.late);
            let outcomes = u8::from(sequence.canceled)
                + u8::from(sequence.timed_out)
                + u8::from(sequence.response.is_some());
            self.unresolved += u64::from(outcomes == 0);
            self.conflicting += u64::from(outcomes > 1);
        } else {
            self.unsent_canceled += u64::from(sequence.canceled);
            self.orphaned +=
                u64::from(sequence.timed_out || sequence.late || sequence.response.is_some());
        }
    }

    fn add(&mut self, other: &Self) {
        self.sent += other.sent;
        self.canceled += other.canceled;
        self.unsent_canceled += other.unsent_canceled;
        self.timed_out += other.timed_out;
        self.late += other.late;
        self.unresolved += other.unresolved;
        self.orphaned += other.orphaned;
        self.conflicting += other.conflicting;
    }

    fn denominator(&self) -> u64 {
        self.sent - self.canceled
    }

    fn status(&self, server: bool, incomplete: bool) -> &'static str {
        if server {
            "server_role"
        } else if incomplete {
            "incomplete_logs"
        } else if self.conflicting != 0 || self.orphaned != 0 {
            "inconsistent_outcomes"
        } else if self.unresolved != 0 {
            "unresolved_requests"
        } else if self.denominator() == 0 {
            "no_eligible_sent"
        } else {
            "available"
        }
    }

    fn write_csv(&self, out: &mut impl Write, server: bool, incomplete: bool) -> io::Result<()> {
        write!(
            out,
            "{},{},{},{},{},{},{},{},{},",
            self.sent,
            self.canceled,
            self.unsent_canceled,
            self.timed_out,
            self.late,
            self.unresolved,
            self.orphaned,
            self.conflicting,
            self.denominator()
        )?;
        let status = self.status(server, incomplete);
        if status == "available" {
            write!(
                out,
                "{:.6}",
                100.0 * self.timed_out as f64 / self.denominator() as f64
            )?;
        } else {
            write!(out, "NA")?;
        }
        write!(out, ",{status}")
    }
}

#[derive(Default)]
struct Aggregate {
    quality: Quality,
    sessions: u64,
    no_response: u64,
    events: u64,
    counts: [u64; KINDS],
    conflicts: u64,
    rtt: Samples,
    jitter: Samples,
    session_means: Samples,
    setup: Samples,
    timeouts: Timeouts,
}

impl Aggregate {
    fn add_session(&mut self, session: &Session) -> io::Result<()> {
        self.sessions += 1;
        self.no_response += u64::from(session.rtt.count == 0);
        self.events += session.events;
        self.conflicts += session.conflicts;
        self.timeouts.add(&session.timeouts);
        for (to, from) in self.counts.iter_mut().zip(session.counts) {
            *to += from;
        }
        if session.rtt.count != 0 {
            self.session_means.add(session.rtt.mean.round() as u64)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Sequence {
    seq: u64,
    response: Option<Event>,
    client: bool,
    sent: bool,
    timed_out: bool,
    canceled: bool,
    late: bool,
}

struct Session {
    flow: u64,
    events: u64,
    counts: [u64; KINDS],
    conflicts: u64,
    rtt: Samples,
    jitter: Samples,
    sequence: Option<Sequence>,
    previous: Option<(u64, u64)>,
    setup_event: Option<Event>,
    setup: Samples,
    timeouts: Timeouts,
}

impl Session {
    fn new(flow: u64) -> Self {
        Self {
            flow,
            events: 0,
            counts: [0; KINDS],
            conflicts: 0,
            rtt: Samples::default(),
            jitter: Samples::default(),
            sequence: None,
            previous: None,
            setup_event: None,
            setup: Samples::default(),
            timeouts: Timeouts::default(),
        }
    }

    fn push(
        &mut self,
        event: Event,
        server: bool,
        group: &mut Aggregate,
        total: &mut Aggregate,
    ) -> io::Result<()> {
        if self
            .sequence
            .as_ref()
            .is_some_and(|seq| seq.seq != event.seq)
        {
            self.finish_sequence(group, total)?;
        }
        let sequence = self.sequence.get_or_insert_with(|| Sequence {
            seq: event.seq,
            client: !server,
            ..Sequence::default()
        });
        self.events += 1;
        self.counts[event.kind as usize] += if event.kind == Kind::Skipped {
            event.value
        } else {
            1
        };
        if event.kind == Kind::Response && !server {
            if sequence.response.is_some() {
                self.counts[Kind::Duplicate as usize] += 1;
            } else {
                // Sorting by time within kind chooses the earliest completion.
                sequence.response = Some(event);
            }
        }
        match event.kind {
            Kind::Sent => sequence.sent = true,
            Kind::Timeout => sequence.timed_out = true,
            Kind::Canceled => sequence.canceled = true,
            Kind::Late => sequence.late = true,
            Kind::Ready
                if !server
                    && self.setup_event.is_none_or(|ready| {
                        (event.time_ns, event.value) < (ready.time_ns, ready.value)
                    }) =>
            {
                self.setup_event = Some(event);
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_sequence(&mut self, group: &mut Aggregate, total: &mut Aggregate) -> io::Result<()> {
        let Some(sequence) = self.sequence.take() else {
            return Ok(());
        };
        self.timeouts.observe(&sequence);
        let Some(response) = sequence.response else {
            return Ok(());
        };
        if sequence.timed_out || sequence.canceled {
            self.conflicts += 1;
            self.previous = None;
            return Ok(());
        }
        for samples in [&mut self.rtt, &mut group.rtt, &mut total.rtt] {
            samples.add(response.value)?;
        }
        if let Some((seq, value)) = self.previous {
            if seq.checked_add(1) == Some(sequence.seq) {
                let jitter = value.abs_diff(response.value);
                for samples in [&mut self.jitter, &mut group.jitter, &mut total.jitter] {
                    samples.add(jitter)?;
                }
            }
        }
        self.previous = Some((sequence.seq, response.value));
        Ok(())
    }
}

struct Worst {
    group: Group,
    flow: u64,
    mean: f64,
    samples: u64,
    incomplete: bool,
}

fn counts_csv(out: &mut impl Write, counts: &[u64; KINDS]) -> io::Result<()> {
    for count in counts {
        write!(out, ",{count}")?;
    }
    Ok(())
}

fn finish_session(
    mut session: Session,
    key: Group,
    group: &mut Aggregate,
    total: &mut Aggregate,
    bad_headers: u64,
    out: &mut impl Write,
    worst: &mut Vec<Worst>,
) -> io::Result<()> {
    session.finish_sequence(group, total)?;
    if let Some(ready) = session.setup_event {
        for samples in [&mut session.setup, &mut group.setup, &mut total.setup] {
            samples.add(ready.value)?;
        }
    }
    group.add_session(&session)?;
    total.add_session(&session)?;
    key.write_csv(out)?;
    write!(out, ",{},{}", session.flow, session.events)?;
    counts_csv(out, &session.counts)?;
    write!(out, ",")?;
    session.rtt.write_rtt(out)?;
    write!(out, ",")?;
    session.jitter.write_jitter(out)?;
    write!(out, ",")?;
    session.setup.write_setup(out)?;
    write!(out, ",")?;
    session
        .timeouts
        .write_csv(out, key.server, group.quality.incomplete(bad_headers, 0))?;
    write!(out, ",")?;
    group
        .quality
        .write_csv(out, bad_headers, session.conflicts)?;
    writeln!(out)?;
    if session.rtt.count != 0 {
        worst.push(Worst {
            group: key,
            flow: session.flow,
            mean: session.rtt.mean,
            samples: session.rtt.count,
            incomplete: group.quality.incomplete(bad_headers, session.conflicts),
        });
        worst.sort_unstable_by(|a, b| {
            b.mean
                .total_cmp(&a.mean)
                .then_with(|| a.group.cmp(&b.group))
                .then_with(|| a.flow.cmp(&b.flow))
        });
        worst.truncate(3);
    }
    Ok(())
}

fn write_group(
    out: &mut impl Write,
    key: Group,
    group: &Aggregate,
    bad_headers: u64,
) -> io::Result<()> {
    key.write_csv(out)?;
    write!(
        out,
        ",{},{},{}",
        group.sessions, group.no_response, group.events
    )?;
    counts_csv(out, &group.counts)?;
    write!(out, ",")?;
    group.rtt.write_rtt(out)?;
    write!(out, ",")?;
    group.jitter.write_jitter(out)?;
    write!(out, ",")?;
    group.session_means.write_rtt(out)?;
    write!(out, ",")?;
    group.setup.write_setup(out)?;
    write!(out, ",")?;
    group
        .timeouts
        .write_csv(out, key.server, group.quality.incomplete(bad_headers, 0))?;
    write!(out, ",")?;
    group.quality.write_csv(out, bad_headers, group.conflicts)?;
    writeln!(out)
}

fn quoted(out: &mut impl Write, value: &str) -> io::Result<()> {
    write!(out, "\"{}\"", value.replace('"', "\"\""))
}

// Reuse the bounded external sorter with the packed error as its primary key.
// Original flow/sequence/time are irrelevant to diagnostic occurrence counts.
fn error_entry(mut entry: Entry) -> Option<Entry> {
    if entry.metadata || entry.event.kind != Kind::Error {
        return None;
    }
    entry.event.flow = entry.event.value;
    entry.event.seq = 0;
    entry.event.time_ns = 0;
    entry.event.len = 0;
    Some(entry)
}

fn write_errors(sorter: &mut Sorter, dir: &Path) -> io::Result<()> {
    let mut out = output(&dir.join("errors.csv"))?;
    writeln!(out, "run,protocol,role,stage,errno,count")?;
    let write_count = |out: &mut BufWriter<File>, key: Group, value, count| {
        let (stage, errno) = unpack_error(value)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown error stage"))?;
        key.write_csv(out)?;
        writeln!(out, ",{},{errno},{count}", stage.as_str())
    };
    if let Some(sorted) = sorter.merge()? {
        let mut input = BufReader::with_capacity(IO_BUFFER, File::open(sorted)?);
        let mut active = None;
        let mut count = 0_u64;
        while let Some(entry) = Entry::read(&mut input)? {
            let key = (entry.group, entry.event.value);
            if active != Some(key) {
                if let Some((group, value)) = active {
                    write_count(&mut out, group, value, count)?;
                }
                active = Some(key);
                count = 0;
            }
            count += 1;
        }
        if let Some((group, value)) = active {
            write_count(&mut out, group, value, count)?;
        }
    }
    out.flush()
}

// Normalize only the temporary sort key. Distinct event kinds retain endpoint
// identity; metadata uses Open for client and Ready for server. Disk log kinds
// and the public Recorder API are unchanged.
fn forward_entry(mut entry: Entry) -> Option<Entry> {
    if entry.group.tcp {
        return None;
    }
    if entry.metadata {
        entry.event.kind = if entry.group.server {
            Kind::Ready
        } else {
            Kind::Open
        };
    } else if !matches!(
        (entry.group.server, entry.event.kind),
        (false, Kind::Sent) | (true, Kind::ServerRequest)
    ) {
        return None;
    }
    entry.group.server = false;
    Some(entry)
}

fn forward_count_entry(key: Group, aggregate: &Aggregate) -> Option<Entry> {
    if key.tcp {
        return None;
    }
    let kind = if key.server {
        Kind::ServerRequest
    } else {
        Kind::Sent
    };
    Some(Entry {
        group: Group {
            server: false,
            ..key
        },
        metadata: true,
        event: Event {
            flow: 0,
            seq: 0,
            time_ns: 0,
            value: aggregate.counts[kind as usize],
            len: 0,
            kind,
        },
    })
}

#[derive(Clone, Copy)]
struct FinalManifest {
    run: u64,
    count: u64,
    complete: bool,
}

enum ManifestInput {
    Missing,
    Invalid,
    Present(FinalManifest),
}

impl ManifestInput {
    fn load(path: &Path, server: bool) -> io::Result<Self> {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::Missing),
            Err(error) => return Err(error),
        };
        // Bound even a malformed or unexpectedly huge manifest before parsing.
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Ok(Self::Invalid);
        }
        let parsed = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| Self::parse(text, server));
        Ok(parsed.map_or(Self::Invalid, Self::Present))
    }

    fn parse(text: &str, server: bool) -> Option<FinalManifest> {
        let keys: &[&str] = if server {
            &[
                "run",
                "request",
                "response",
                "request_bytes",
                "response_bytes",
                "active",
                "failed",
                "limited",
                "invalid",
                "complete",
            ]
        } else {
            &["run", "sent", "received", "timeout", "canceled", "complete"]
        };
        let mut values = [None; 10];
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let value = fields.next()?;
            if fields.next().is_some() {
                return None;
            }
            if let Some(index) = keys.iter().position(|expected| *expected == key) {
                if values[index].replace(value).is_some() {
                    return None;
                }
            }
        }
        let mut numbers = [0_u64; 10];
        for index in 0..keys.len() - 1 {
            numbers[index] = values[index]?.parse().ok()?;
        }
        // The existing server END report has no complete field: all counters
        // must be present. Honor an explicit false if future writers add it.
        let complete = match values[keys.len() - 1] {
            Some("true") => true,
            Some("false") => false,
            None if server => true,
            _ => return None,
        };
        Some(FinalManifest {
            run: numbers[0],
            count: numbers[1],
            complete,
        })
    }
}

struct Manifests {
    client: ManifestInput,
    server: ManifestInput,
}

impl Manifests {
    fn load(dir: &Path) -> io::Result<Self> {
        Ok(Self {
            client: ManifestInput::load(&dir.join("client-final.txt"), false)?,
            server: ManifestInput::load(&dir.join("server-final.txt"), true)?,
        })
    }

    fn check(&self, run: u64) -> ManifestCheck {
        let inputs = [&self.client, &self.server];
        let expected = inputs.map(|input| match input {
            ManifestInput::Present(m) => Some(m.count),
            _ => None,
        });
        let status = if inputs.iter().any(|m| matches!(m, ManifestInput::Missing)) {
            "missing_manifests"
        } else if inputs.iter().any(|m| matches!(m, ManifestInput::Invalid)) {
            "invalid_manifests"
        } else if inputs
            .iter()
            .any(|m| matches!(m, ManifestInput::Present(m) if m.run != run))
        {
            "manifest_run_mismatch"
        } else if inputs
            .iter()
            .any(|m| matches!(m, ManifestInput::Present(m) if !m.complete))
        {
            "incomplete_manifests"
        } else {
            "available"
        };
        ManifestCheck { expected, status }
    }
}

struct ManifestCheck {
    expected: [Option<u64>; 2],
    status: &'static str,
}

impl Default for ManifestCheck {
    fn default() -> Self {
        Self {
            expected: [None; 2],
            status: "missing_manifests",
        }
    }
}

impl ManifestCheck {
    fn status(&self, raw: [u64; 2]) -> &'static str {
        if self.status != "available" {
            self.status
        } else if self.expected != raw.map(Some) {
            "manifest_count_mismatch"
        } else {
            "available"
        }
    }
}

#[derive(Default)]
struct ForwardCounts {
    sent: u64,
    received: u64,
    matched: u64,
    server_only: u64,
}

impl ForwardCounts {
    fn add(&mut self, other: &Self) {
        self.sent += other.sent;
        self.received += other.received;
        self.matched += other.matched;
        self.server_only += other.server_only;
    }

    fn status(&self, run: &ForwardRun, bad_headers: u64) -> &'static str {
        let quality = &run.quality;
        if quality[0].files == 0 {
            "missing_client"
        } else if quality[1].files == 0 {
            "missing_server"
        } else if quality.iter().any(|q| q.incomplete(bad_headers, 0)) {
            "incomplete_logs"
        } else if run.manifest.status(run.raw) != "available" {
            run.manifest.status(run.raw)
        } else if self.server_only != 0 {
            "unmatched_server_requests"
        } else {
            "available"
        }
    }

    fn write_csv(
        &self,
        out: &mut impl Write,
        run: &ForwardRun,
        bad_headers: u64,
    ) -> io::Result<()> {
        write!(
            out,
            "{},{},{},{},",
            self.sent, self.received, self.matched, self.server_only
        )?;
        let quality = &run.quality;
        let status = self.status(run, bad_headers);
        if status == "available" {
            write!(out, "{},{},", self.matched, self.sent - self.matched)?;
            if self.sent == 0 {
                write!(out, "NA")?;
            } else {
                write!(
                    out,
                    "{:.6}",
                    100.0 * (self.sent - self.matched) as f64 / self.sent as f64
                )?;
            }
        } else {
            write!(out, "NA,NA,NA")?;
        }
        write!(
            out,
            ",{status},{},{},{},{},{},{},{}",
            quality[0].files,
            quality[1].files,
            quality[0].dropped + quality[1].dropped,
            quality[0].unknown + quality[1].unknown,
            quality[0].truncated + quality[1].truncated,
            quality[0].corrupt + quality[1].corrupt,
            bad_headers
        )?;
        write!(out, ",{},{}", run.raw[0], run.raw[1])?;
        for expected in run.manifest.expected {
            match expected {
                Some(n) => write!(out, ",{n}")?,
                None => write!(out, ",NA")?,
            }
        }
        writeln!(out, ",{}", run.manifest.status(run.raw))
    }
}

#[derive(Default)]
struct ForwardSequence {
    seq: u64,
    sent: bool,
    received: bool,
}

struct ForwardSession {
    flow: u64,
    sequence: Option<ForwardSequence>,
    counts: ForwardCounts,
}

impl ForwardSession {
    fn new(flow: u64) -> Self {
        Self {
            flow,
            sequence: None,
            counts: ForwardCounts::default(),
        }
    }

    fn push(&mut self, event: Event) {
        if self
            .sequence
            .as_ref()
            .is_some_and(|seq| seq.seq != event.seq)
        {
            self.finish_sequence();
        }
        let sequence = self.sequence.get_or_insert_with(|| ForwardSequence {
            seq: event.seq,
            ..ForwardSequence::default()
        });
        match event.kind {
            Kind::Sent => sequence.sent = true,
            Kind::ServerRequest => sequence.received = true,
            _ => unreachable!("forward sorter contains only endpoint markers"),
        }
    }

    fn finish_sequence(&mut self) {
        if let Some(sequence) = self.sequence.take() {
            self.counts.sent += u64::from(sequence.sent);
            self.counts.received += u64::from(sequence.received);
            self.counts.matched += u64::from(sequence.sent && sequence.received);
            self.counts.server_only += u64::from(!sequence.sent && sequence.received);
        }
    }
}

#[derive(Default)]
struct ForwardRun {
    quality: [Quality; 2],
    counts: ForwardCounts,
    raw: [u64; 2],
    manifest: ManifestCheck,
}

impl ForwardRun {
    fn finish_session(
        &mut self,
        mut session: ForwardSession,
        run: u64,
        bad_headers: u64,
        out: &mut impl Write,
    ) -> io::Result<()> {
        session.finish_sequence();
        self.counts.add(&session.counts);
        write!(out, "{run},{},", session.flow)?;
        session.counts.write_csv(out, self, bad_headers)
    }

    fn finish_run(
        &self,
        run: u64,
        bad_headers: u64,
        out: &mut impl Write,
        report: &mut ForwardReport,
    ) -> io::Result<()> {
        write!(out, "{run},")?;
        self.counts.write_csv(out, self, bad_headers)?;
        if self.counts.status(self, bad_headers) == "available" {
            report.available_runs += 1;
            report.counts.add(&self.counts);
        } else {
            report.unavailable_runs += 1;
        }
        Ok(())
    }
}

#[derive(Default)]
struct ForwardReport {
    available_runs: u64,
    unavailable_runs: u64,
    counts: ForwardCounts,
}

fn reconcile_forward(
    sorter: &mut Sorter,
    destination: &Path,
    bad_headers: u64,
    manifests: &Manifests,
) -> io::Result<ForwardReport> {
    let sorted = sorter.merge()?;
    let mut sessions = output(&destination.join("forward.csv"))?;
    let mut summary = output(&destination.join("forward-summary.csv"))?;
    writeln!(sessions, "run,flow,{FORWARD_COLUMNS}")?;
    writeln!(summary, "run,{FORWARD_COLUMNS}")?;
    let mut report = ForwardReport::default();
    let mut current_run = None;
    let mut run = ForwardRun::default();
    let mut session: Option<ForwardSession> = None;
    if let Some(sorted) = sorted {
        let mut input = BufReader::with_capacity(IO_BUFFER, File::open(sorted)?);
        while let Some(entry) = Entry::read(&mut input)? {
            if current_run != Some(entry.group.run) {
                if let Some(id) = current_run {
                    if let Some(session) = session.take() {
                        run.finish_session(session, id, bad_headers, &mut sessions)?;
                    }
                    run.finish_run(id, bad_headers, &mut summary, &mut report)?;
                }
                current_run = Some(entry.group.run);
                run = ForwardRun {
                    manifest: manifests.check(entry.group.run),
                    ..ForwardRun::default()
                };
            }
            if entry.metadata {
                match entry.event.kind {
                    Kind::Open => run.quality[0].add(entry),
                    Kind::Ready => run.quality[1].add(entry),
                    Kind::Sent => run.raw[0] += entry.event.value,
                    Kind::ServerRequest => run.raw[1] += entry.event.value,
                    _ => unreachable!("invalid forward metadata"),
                }
                continue;
            }
            if session
                .as_ref()
                .is_some_and(|session| session.flow != entry.event.flow)
            {
                run.finish_session(
                    session.take().unwrap(),
                    entry.group.run,
                    bad_headers,
                    &mut sessions,
                )?;
            }
            session
                .get_or_insert_with(|| ForwardSession::new(entry.event.flow))
                .push(entry.event);
        }
    }
    if let Some(id) = current_run {
        if let Some(session) = session {
            run.finish_session(session, id, bad_headers, &mut sessions)?;
        }
        run.finish_run(id, bad_headers, &mut summary, &mut report)?;
    }
    sessions.flush()?;
    summary.flush()?;
    Ok(report)
}

struct Report {
    files: u64,
    bad_headers: u64,
    totals: [Aggregate; 4],
    worst: Vec<Worst>,
    forward: ForwardReport,
}

/// Analyze completed worker recordings. Report files are replaced only after
/// the complete sort/analysis succeeds. Incomplete logs still produce reports;
/// corrupt headers conservatively mark all groups incomplete because their
/// ownership cannot be established. Timeout rates describe end-to-end request
/// outcomes; forward missing rates require complete UDP endpoint logs whose raw
/// counters match both final manifests for the run.
pub fn run(dir: &Path) -> io::Result<()> {
    require_event_recording(dir)?;
    let report = analyze(dir, CHUNK_ENTRIES, MERGE_FAN_IN)?;
    let stdout = io::stdout();
    write_report(&report, dir, &mut stdout.lock(), console::color_enabled())
}

fn require_event_recording(dir: &Path) -> io::Result<()> {
    match fs::read_to_string(dir.join("run.txt")) {
        Ok(metadata) => {
            for line in metadata.lines() {
                let mut fields = line.split_whitespace();
                if fields.next() == Some("recording") {
                    let mode = fields.next().and_then(crate::record::Mode::parse);
                    if mode != Some(crate::record::Mode::Events) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "offline analysis requires events recording mode; summary/off runs do not contain per-request event logs",
                        ));
                    }
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Legacy event directories have no recording-mode metadata. Server summary
    // directories may have only CSV files, and off directories may be empty.
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "fgr") && entry.file_type()?.is_file()
        {
            return Ok(());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "offline analysis requires events recording mode and *.fgr files; summary/off recordings cannot be analyzed",
    ))
}

#[path = "analyze_console.rs"]
mod console;

fn write_report(report: &Report, dir: &Path, out: &mut impl Write, color: bool) -> io::Result<()> {
    console::write(report, dir, out, color)
}

fn analyze(dir: &Path, chunk_limit: usize, fan_in: usize) -> io::Result<Report> {
    let manifests = Manifests::load(dir)?;
    let mut sorter = Sorter::new(dir, chunk_limit, fan_in)?;
    let mut recordings = output(&sorter.scratch.0.join("recordings.csv"))?;
    writeln!(
        recordings,
        "file,run,protocol,role,events,dropped,complete,truncated,corrupt,error"
    )?;
    let mut files = 0;
    let mut bad_headers = 0;
    for item in fs::read_dir(dir)? {
        let item = item?;
        if item
            .path()
            .extension()
            .is_none_or(|extension| extension != "fgr")
            || !item.file_type()?.is_file()
        {
            continue;
        }
        files += 1;
        quoted(&mut recordings, &item.file_name().to_string_lossy())?;
        write!(recordings, ",")?;
        let input = BufReader::with_capacity(IO_BUFFER, File::open(item.path())?);
        let mut reader = match Reader::new(input) {
            Ok(reader) => reader,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
                ) =>
            {
                bad_headers += 1;
                write!(
                    recordings,
                    "NA,NA,NA,0,NA,false,{},{},",
                    error.kind() == io::ErrorKind::UnexpectedEof,
                    error.kind() == io::ErrorKind::InvalidData
                )?;
                quoted(&mut recordings, &error.to_string())?;
                writeln!(recordings)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        let group = Group::from(reader.header);
        while let Some(event) = reader.next_event()? {
            sorter.push(Entry {
                group,
                metadata: false,
                event,
            })?;
        }
        group.write_csv(&mut recordings)?;
        write!(recordings, ",{},", reader.status.events)?;
        match reader.status.dropped {
            Some(n) => write!(recordings, "{n}")?,
            None => write!(recordings, "NA")?,
        }
        writeln!(
            recordings,
            ",{},{},{},",
            reader.status.complete, reader.status.truncated, reader.status.corrupt
        )?;
        sorter.push(Entry::metadata(group, reader.status))?;
    }
    recordings.flush()?;
    let sorted = sorter.merge()?;
    let mut sessions = output(&sorter.scratch.0.join("sessions.csv"))?;
    let mut summary = output(&sorter.scratch.0.join("summary.csv"))?;
    writeln!(
        sessions,
        "run,protocol,role,flow,events,{COUNTER_COLUMNS},{METRIC_COLUMNS},{SETUP_COLUMNS},{TIMEOUT_COLUMNS},{QUALITY_COLUMNS}"
    )?;
    writeln!(summary, "run,protocol,role,sessions,sessions_without_rtt,events,{COUNTER_COLUMNS},{METRIC_COLUMNS},session_mean_samples,session_mean_min_ns,session_mean_avg_ns,session_mean_max_ns,session_mean_mdev_ns,session_mean_p50_ns,session_mean_p95_ns,session_mean_p99_ns,{SETUP_COLUMNS},{TIMEOUT_COLUMNS},{QUALITY_COLUMNS}")?;
    let mut report = Report {
        files,
        bad_headers,
        totals: std::array::from_fn(|_| Aggregate::default()),
        worst: Vec::with_capacity(4),
        forward: ForwardReport::default(),
    };
    let mut forward_sorter = Sorter::new(dir, chunk_limit, fan_in)?;
    let mut error_sorter = Sorter::new(dir, chunk_limit, fan_in)?;
    let mut active_group = None;
    let mut group = Aggregate::default();
    let mut session: Option<Session> = None;
    if let Some(sorted) = sorted {
        let mut input = BufReader::with_capacity(IO_BUFFER, File::open(sorted)?);
        while let Some(entry) = Entry::read(&mut input)? {
            if let Some(forward) = forward_entry(entry) {
                forward_sorter.push(forward)?;
            }
            if let Some(error) = error_entry(entry) {
                error_sorter.push(error)?;
            }
            if active_group != Some(entry.group) {
                if let Some(key) = active_group {
                    if let Some(session) = session.take() {
                        finish_session(
                            session,
                            key,
                            &mut group,
                            &mut report.totals[key.total_index()],
                            bad_headers,
                            &mut sessions,
                            &mut report.worst,
                        )?;
                    }
                    write_group(&mut summary, key, &group, bad_headers)?;
                    if let Some(counts) = forward_count_entry(key, &group) {
                        forward_sorter.push(counts)?;
                    }
                }
                active_group = Some(entry.group);
                group = Aggregate::default();
            }
            let total = &mut report.totals[entry.group.total_index()];
            if entry.metadata {
                group.quality.add(entry);
                total.quality.add(entry);
                continue;
            }
            if entry.event.kind == Kind::SessionSkipped {
                for aggregate in [&mut group, total] {
                    aggregate.events += 1;
                    aggregate.counts[Kind::SessionSkipped as usize] += entry.event.value;
                }
                continue;
            }
            if session
                .as_ref()
                .is_some_and(|session| session.flow != entry.event.flow)
            {
                finish_session(
                    session.take().unwrap(),
                    entry.group,
                    &mut group,
                    total,
                    bad_headers,
                    &mut sessions,
                    &mut report.worst,
                )?;
            }
            session
                .get_or_insert_with(|| Session::new(entry.event.flow))
                .push(entry.event, entry.group.server, &mut group, total)?;
        }
    }
    if let Some(key) = active_group {
        if let Some(session) = session {
            finish_session(
                session,
                key,
                &mut group,
                &mut report.totals[key.total_index()],
                bad_headers,
                &mut sessions,
                &mut report.worst,
            )?;
        }
        write_group(&mut summary, key, &group, bad_headers)?;
        if let Some(counts) = forward_count_entry(key, &group) {
            forward_sorter.push(counts)?;
        }
    }
    sessions.flush()?;
    summary.flush()?;
    drop((sessions, summary, recordings));
    write_errors(&mut error_sorter, &sorter.scratch.0)?;
    report.forward = reconcile_forward(
        &mut forward_sorter,
        &sorter.scratch.0,
        bad_headers,
        &manifests,
    )?;
    for name in [
        "sessions.csv",
        "summary.csv",
        "recordings.csv",
        "errors.csv",
        "forward.csv",
        "forward-summary.csv",
    ] {
        fs::rename(sorter.scratch.0.join(name), dir.join(name))?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{ErrorStage, Recorder};
    use std::collections::HashMap;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "flowgen-analyze-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, AtomicOrdering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn record(&self, name: &str, run: u64, tcp: bool, server: bool, events: &[Event]) {
            let mut recorder = Recorder::create(&self.0.join(name), run, tcp, server).unwrap();
            for event in events {
                recorder.push(*event);
            }
            let result = recorder.finish().unwrap();
            assert_eq!(result.dropped, 0);
        }
        fn rows(&self, name: &str) -> Vec<HashMap<String, String>> {
            let text = fs::read_to_string(self.0.join(name)).unwrap();
            let mut lines = text.lines();
            let header: Vec<_> = lines.next().unwrap().split(',').collect();
            lines
                .map(|line| {
                    let cells: Vec<_> = line.split(',').collect();
                    assert_eq!(header.len(), cells.len(), "CSV column count");
                    header
                        .iter()
                        .zip(cells)
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect()
                })
                .collect()
        }

        fn manifests(&self, run: u64, sent: u64, request: u64, complete: bool) {
            fs::write(self.0.join("client-final.txt"), format!("run {run}\nsent {sent}\nreceived 0\ntimeout 0\ncanceled 0\ncomplete {complete}\n")).unwrap();
            fs::write(self.0.join("server-final.txt"), format!("run {run}\nrequest {request}\nresponse {request}\nrequest_bytes {}\nresponse_bytes {}\nactive 0\nfailed 0\nlimited 0\ninvalid 0\n", request * 128, request * 128)).unwrap();
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn event(flow: u64, seq: u64, kind: Kind, value: u64) -> Event {
        Event {
            flow,
            seq,
            kind,
            value,
            time_ns: seq,
            len: 128,
        }
    }

    #[test]
    fn offline_analysis_rejects_summary_and_off_metadata() {
        for mode in ["summary", "off"] {
            let dir = TestDir::new();
            fs::write(dir.0.join("run.txt"), format!("recording {mode}\n")).unwrap();
            let error = run(&dir.0).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("requires events recording mode"));
        }
    }

    #[test]
    fn session_skips_count_batches_without_creating_sessions_or_request_outcomes() {
        let dir = TestDir::new();
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                Event::session_skipped(0, 100, 20),
                Event::session_skipped(0, 101, 3),
                event(1, 0, Kind::Open, 0),
                event(1, 0, Kind::Skipped, 7),
                event(1, 1, Kind::Sent, 0),
                event(1, 1, Kind::Response, 10),
            ],
        );
        // Include a run containing nothing but scheduler skips.
        dir.record(
            "b.fgr",
            2,
            false,
            false,
            &[Event::session_skipped(0, 200, 4)],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        let total = &report.totals[0];
        assert_eq!(total.counts[Kind::SessionSkipped as usize], 27);
        assert_eq!(total.counts[Kind::Skipped as usize], 7);
        assert_eq!(total.events, 7);
        assert_eq!(total.sessions, 1);
        assert_eq!(total.no_response, 0);
        assert_eq!(total.timeouts.sent, 1);
        assert_eq!(total.timeouts.orphaned, 0);
        assert_eq!(total.timeouts.unresolved, 0);
        let sessions = dir.rows("sessions.csv");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["flow"], "1");
        assert_eq!(sessions[0]["skipped"], "7");
        assert_eq!(sessions[0]["session_skipped"], "0");
        let rows = dir.rows("summary.csv");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["session_skipped"], "23");
        assert_eq!(rows[0]["skipped"], "7");
        assert_eq!(rows[0]["response_timeout_pct"], "0.000000");
        assert_eq!(rows[1]["session_skipped"], "4");
        assert_eq!(rows[1]["events"], "1");
        assert_eq!(rows[1]["sessions"], "0");
        assert_eq!(rows[1]["sessions_without_rtt"], "0");
        assert_eq!(rows[1]["response_timeout_status"], "no_eligible_sent");
        assert!(dir.rows("errors.csv").is_empty());
        let mut console = Vec::new();
        write_report(&report, &dir.0, &mut console, false).unwrap();
        let console = String::from_utf8(console).unwrap();
        let normalized = console.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains("Send skipped 7"));
        assert!(normalized.contains("Session skipped 27"));
    }

    #[test]
    fn errors_aggregate_by_stage_errno_and_group_without_double_counting_failed() {
        let dir = TestDir::new();
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                event(1, 0, Kind::Open, 0),
                Event::error(1, 0, 1, ErrorStage::Connect, 111),
                event(1, 0, Kind::Failed, 0),
                Event::error(2, 0, 2, ErrorStage::Bind, 111),
                Event::error(3, 0, 3, ErrorStage::Connect, 113),
                Event::error(4, 0, 4, ErrorStage::SetupTimeout, 0),
                Event::error(5, 0, 5, ErrorStage::Decode, -1),
            ],
        );
        dir.record(
            "b.fgr",
            1,
            false,
            false,
            &[Event::error(6, 7, 100, ErrorStage::Connect, 111)],
        );
        for (name, run, tcp, server) in [
            ("c.fgr", 2, false, false),
            ("d.fgr", 1, true, false),
            ("e.fgr", 1, false, true),
        ] {
            dir.record(
                name,
                run,
                tcp,
                server,
                &[Event::error(1, 0, 1, ErrorStage::Connect, 111)],
            );
        }
        // Force multiple merge passes, including for the error sorter.
        let report = analyze(&dir.0, 1, 2).unwrap();
        let rows = dir.rows("errors.csv");
        assert_eq!(rows.len(), 8);
        let counts: HashMap<_, _> = rows
            .iter()
            .map(|row| {
                (
                    (
                        row["run"].as_str(),
                        row["protocol"].as_str(),
                        row["role"].as_str(),
                        row["stage"].as_str(),
                        row["errno"].as_str(),
                    ),
                    row["count"].as_str(),
                )
            })
            .collect();
        assert_eq!(counts[&("1", "udp", "client", "connect", "111")], "2");
        for key in [
            ("1", "udp", "client", "bind", "111"),
            ("1", "udp", "client", "connect", "113"),
            ("1", "udp", "client", "setup_timeout", "0"),
            ("1", "udp", "client", "decode", "-1"),
            ("2", "udp", "client", "connect", "111"),
            ("1", "tcp", "client", "connect", "111"),
            ("1", "udp", "server", "connect", "111"),
        ] {
            assert_eq!(counts[&key], "1");
        }
        let summary = dir.rows("summary.csv");
        let row = summary
            .iter()
            .find(|row| row["run"] == "1" && row["protocol"] == "udp" && row["role"] == "client")
            .unwrap();
        assert_eq!(row["failed"], "1");
        assert_eq!(row["error"], "6");
        assert_eq!(row["incomplete"], "false");
        assert_eq!(row["sent_unique"], "0");
        assert_eq!(row["orphan_outcomes_unique"], "0");
        assert_eq!(report.totals[0].counts[Kind::Failed as usize], 1);
        let sessions = dir.rows("sessions.csv");
        let failed = sessions
            .iter()
            .find(|row| {
                row["run"] == "1"
                    && row["flow"] == "1"
                    && row["protocol"] == "udp"
                    && row["role"] == "client"
            })
            .unwrap();
        assert_eq!(failed["failed"], "1");
        assert_eq!(failed["error"], "1");
        // Reports must be deterministic across sort bounds and replacement runs.
        let original = fs::read(dir.0.join("errors.csv")).unwrap();
        analyze(&dir.0, 32, 4).unwrap();
        assert_eq!(fs::read(dir.0.join("errors.csv")).unwrap(), original);
    }

    #[test]
    fn legacy_failed_events_have_no_invented_error_details() {
        let dir = TestDir::new();
        dir.record(
            "old.fgr",
            1,
            false,
            false,
            &[
                event(1, 0, Kind::Open, 0),
                event(1, 0, Kind::Failed, 111),
                event(1, 0, Kind::Skipped, 5),
            ],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        assert_eq!(report.totals[0].counts[Kind::Failed as usize], 1);
        assert_eq!(report.totals[0].counts[Kind::Skipped as usize], 5);
        let summary = dir.rows("summary.csv");
        assert_eq!(summary[0]["skipped"], "5");
        assert_eq!(summary[0]["session_skipped"], "0");
        assert_eq!(summary[0]["error"], "0");
        assert_eq!(summary[0]["incomplete"], "false");
        assert!(dir.rows("errors.csv").is_empty());
    }

    #[test]
    fn legacy_request_skip_batches_sum_values_across_recordings() {
        let dir = TestDir::new();
        // Frozen v1 fixture: run 42, flow 7, one Skipped record with value 456.
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
        fs::write(dir.0.join("legacy.fgr"), bytes).unwrap();
        dir.record(
            "worker.fgr",
            42,
            false,
            false,
            &[
                event(7, 0, Kind::Skipped, 7),
                event(7, 1, Kind::Skipped, 0),
                event(7, 2, Kind::Skipped, 1),
            ],
        );
        let report = analyze(&dir.0, 1, 2).unwrap();
        let total = &report.totals[0];
        assert_eq!(total.events, 4);
        assert_eq!(total.sessions, 1);
        assert_eq!(total.counts[Kind::Skipped as usize], 464);
        for name in ["sessions.csv", "summary.csv"] {
            let rows = dir.rows(name);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["skipped"], "464");
            assert_eq!(rows[0]["events"], "4");
            assert_eq!(rows[0]["session_skipped"], "0");
            assert_eq!(rows[0]["sent_unique"], "0");
            assert_eq!(rows[0]["orphan_outcomes_unique"], "0");
            assert_eq!(rows[0]["incomplete"], "false");
        }
    }

    #[test]
    fn jitter_uses_sequence_order_and_excludes_duplicates_late_and_gaps() {
        let dir = TestDir::new();
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                event(7, 3, Kind::Response, 40),
                event(7, 1, Kind::Response, 10),
                event(7, 2, Kind::Response, 30),
                event(7, 2, Kind::Duplicate, 999),
                event(7, 2, Kind::Reordered, 0),
                event(7, 4, Kind::Timeout, 0),
                event(7, 4, Kind::Late, 999),
                event(7, 5, Kind::Response, 100),
                event(7, 6, Kind::Canceled, 0),
                event(7, 7, Kind::Response, 200),
                event(8, 8, Kind::Response, 999),
                event(9, 1, Kind::Sent, 0),
            ],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        let total = &report.totals[0];
        assert_eq!(total.rtt.count, 6);
        assert_eq!(total.jitter.count, 2);
        assert_eq!(total.jitter.mean, 15.0);
        assert_eq!(total.jitter.quantile(0.95), 20);
        assert_eq!(total.counts[Kind::Timeout as usize], 1);
        assert_eq!(total.counts[Kind::Duplicate as usize], 1);
        assert_eq!(total.counts[Kind::Late as usize], 1);
        assert_eq!(total.counts[Kind::Reordered as usize], 1);
        assert_eq!(total.no_response, 1);
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[2]["sent"], "1");
        assert_eq!(rows[2]["rtt_avg_ns"], "NA");
        assert_eq!(rows[2]["jitter_avg_ns"], "NA");
    }

    #[test]
    fn weighted_quantiles_differ_from_session_mean_distribution() {
        let dir = TestDir::new();
        let mut events: Vec<_> = (1..=99)
            .map(|seq| event(1, seq, Kind::Response, 10))
            .collect();
        events.push(event(2, 1, Kind::Response, 1000));
        dir.record("a.fgr", 1, true, false, &events);
        let report = analyze(&dir.0, 7, 3).unwrap();
        let total = &report.totals[2];
        assert_eq!(total.rtt.count, 100);
        assert!((total.rtt.mean - 19.9).abs() < 1e-9);
        assert_eq!(total.rtt.quantile(0.50), 10);
        assert_eq!(total.rtt.quantile(0.95), 10);
        assert_eq!(total.rtt.quantile(0.99), 10);
        assert_eq!(total.session_means.count, 2);
        assert_eq!(total.session_means.mean, 505.0);
        assert_eq!(total.session_means.quantile(0.95), 1000);
        assert_eq!(total.jitter.count, 98);
        assert_eq!(total.jitter.mean, 0.0);
        assert!((total.rtt.mdev() - 98.50375627355538).abs() < 1e-8);
        dir.rows("summary.csv");
    }

    #[test]
    fn isolates_run_flow_protocol_and_role_and_merges_workers() {
        let dir = TestDir::new();
        dir.record("a.fgr", 1, false, false, &[event(1, 1, Kind::Response, 10)]);
        dir.record("b.fgr", 1, false, false, &[event(1, 2, Kind::Response, 30)]);
        dir.record(
            "c.fgr",
            2,
            false,
            false,
            &[event(1, 3, Kind::Response, 999)],
        );
        dir.record("d.fgr", 1, true, false, &[event(1, 3, Kind::Response, 888)]);
        dir.record(
            "e.fgr",
            1,
            false,
            true,
            &[
                event(1, 3, Kind::Response, 777),
                event(1, 1, Kind::ServerRequest, 0),
            ],
        );
        dir.record(
            "f.fgr",
            2,
            false,
            true,
            &[event(1, 4, Kind::ServerResponse, 0)],
        );
        let report = analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(report.totals[0].sessions, 2);
        assert_eq!(report.totals[0].rtt.count, 3);
        assert_eq!(report.totals[0].jitter.count, 1);
        assert_eq!(report.totals[0].jitter.mean, 20.0);
        assert_eq!(report.totals[1].sessions, 2);
        assert_eq!(report.totals[1].rtt.count, 0);
        assert_eq!(report.totals[2].rtt.count, 1);
        assert_eq!(report.totals[2].jitter.count, 0);
        assert_eq!(dir.rows("sessions.csv").len(), 5);
        assert_eq!(dir.rows("summary.csv").len(), 5);
    }

    #[test]
    fn repeated_responses_use_earliest_and_conflicting_outcomes_are_incomplete() {
        let dir = TestDir::new();
        let mut later = event(1, 1, Kind::Response, 999);
        later.time_ns = 100;
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                later,
                event(1, 1, Kind::Response, 10),
                event(1, 2, Kind::Response, 30),
                event(1, 3, Kind::Response, 40),
                event(1, 3, Kind::Timeout, 0),
                event(1, 4, Kind::Response, 100),
            ],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        assert_eq!(report.totals[0].rtt.count, 3);
        assert_eq!(report.totals[0].rtt.min, 10);
        assert_eq!(report.totals[0].rtt.max, 100);
        assert_eq!(report.totals[0].jitter.count, 1);
        assert_eq!(report.totals[0].counts[Kind::Duplicate as usize], 1);
        assert_eq!(report.totals[0].conflicts, 1);
        assert_eq!(dir.rows("sessions.csv")[0]["incomplete"], "true");
    }

    #[test]
    fn truncated_corrupt_and_bad_header_logs_preserve_flags() {
        let dir = TestDir::new();
        for name in ["truncated.fgr", "corrupt.fgr", "bad.fgr"] {
            dir.record(
                name,
                1,
                false,
                false,
                &[event(1, 1, Kind::Sent, 0), event(1, 1, Kind::Response, 10)],
            );
        }
        let path = dir.0.join("truncated.fgr");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(32 + 40)
            .unwrap();
        let path = dir.0.join("corrupt.fgr");
        let mut bytes = fs::read(&path).unwrap();
        bytes[72] ^= 1;
        fs::write(&path, bytes).unwrap();
        let path = dir.0.join("bad.fgr");
        fs::write(path, b"bad").unwrap();
        let report = analyze(&dir.0, 2, 2).unwrap();
        assert_eq!(report.bad_headers, 1);
        assert_eq!(report.totals[0].quality.truncated, 1);
        assert_eq!(report.totals[0].quality.corrupt, 1);
        assert_eq!(report.totals[0].quality.unknown, 2);
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows[0]["incomplete"], "true");
        assert_eq!(rows[0]["unknown_header_files"], "1");
        assert_eq!(rows[0]["rtt_avg_ns"], "NA");
        assert_eq!(dir.rows("recordings.csv").len(), 3);
    }

    #[test]
    fn empty_and_single_samples_are_unavailable_or_exact_as_appropriate() {
        let mut samples = Samples::default();
        let mut text = Vec::new();
        samples.write_rtt(&mut text).unwrap();
        assert_eq!(String::from_utf8(text).unwrap(), "0,NA,NA,NA,NA,NA,NA,NA");
        samples.add(0).unwrap();
        assert_eq!(samples.quantile(0.99), 0);
        assert_eq!(samples.mdev(), 0.0);
        samples.add(u64::MAX).unwrap();
        assert_eq!(samples.max, u64::MAX);
        let dir = TestDir::new();
        dir.record("empty.fgr", 1, false, false, &[]);
        let report = analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(report.totals[0].sessions, 0);
        assert_eq!(report.totals[0].rtt.count, 0);
        assert_eq!(dir.rows("sessions.csv").len(), 0);
        assert_eq!(dir.rows("summary.csv")[0]["rtt_avg_ns"], "NA");
        // Repeated analysis replaces its own reports and cleans scratch runs.
        analyze(&dir.0, 1, 2).unwrap();
        assert!(dir.rows("errors.csv").is_empty());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 7);
    }

    #[test]
    fn external_sort_matches_total_order_across_many_merge_passes() {
        let dir = TestDir::new();
        let mut sorter = Sorter::new(&dir.0, 3, 2).unwrap();
        let mut expected = Vec::new();
        for n in (0..257).rev() {
            let entry = Entry {
                group: Group {
                    run: n % 3,
                    tcp: n % 2 == 0,
                    server: false,
                },
                metadata: false,
                event: event(n % 5, n, Kind::Response, n * 3),
            };
            expected.push(entry);
            sorter.push(entry).unwrap();
            assert!(sorter.chunk.len() < 3);
            assert_eq!(sorter.chunk.capacity(), 3);
        }
        expected.sort_unstable();
        let mut input = BufReader::new(File::open(sorter.merge().unwrap().unwrap()).unwrap());
        for entry in expected {
            assert_eq!(Entry::read(&mut input).unwrap(), Some(entry));
        }
        assert!(Entry::read(&mut input).unwrap().is_none());
        assert_eq!(fs::read_dir(&sorter.scratch.0).unwrap().count(), 1);
    }

    #[test]
    fn sequence_overflow_never_wraps_jitter_into_a_different_pair() {
        let dir = TestDir::new();
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                event(1, u64::MAX, Kind::Response, 10),
                event(1, 0, Kind::Response, 30),
                event(2, 1, Kind::Response, 40),
            ],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        assert_eq!(report.totals[0].rtt.count, 3);
        assert_eq!(report.totals[0].jitter.count, 0);
    }

    #[test]
    fn known_logging_gaps_are_incomplete_without_claiming_truncation() {
        let key = Group {
            run: 42,
            tcp: false,
            server: false,
        };
        let mut quality = Quality::default();
        quality.add(Entry::metadata(
            key,
            ReadStatus {
                events: 10,
                dropped: Some(7),
                complete: false,
                truncated: false,
                corrupt: false,
            },
        ));
        assert_eq!(quality.dropped, 7);
        assert_eq!(quality.unknown, 0);
        assert!(quality.incomplete(0, 0));
        let mut csv = Vec::new();
        quality.write_csv(&mut csv, 0, 0).unwrap();
        assert_eq!(String::from_utf8(csv).unwrap(), "true,7,0,0,0,0,0");
    }

    #[test]
    fn missing_footer_affects_its_whole_group_but_not_another_run() {
        let dir = TestDir::new();
        dir.record("a.fgr", 1, false, false, &[event(1, 1, Kind::Response, 10)]);
        dir.record("b.fgr", 1, false, false, &[event(2, 1, Kind::Response, 20)]);
        dir.record("c.fgr", 2, false, false, &[event(1, 1, Kind::Response, 30)]);
        OpenOptions::new()
            .write(true)
            .open(dir.0.join("a.fgr"))
            .unwrap()
            .set_len(32 + 40)
            .unwrap();
        analyze(&dir.0, 2, 2).unwrap();
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows[0]["incomplete"], "true");
        assert_eq!(rows[1]["incomplete"], "true");
        assert_eq!(rows[2]["incomplete"], "false");
        assert_eq!(rows[0]["rtt_avg_ns"], "10.000");
    }

    #[test]
    fn timeout_rate_deduplicates_sends_and_excludes_only_sent_cancellations() {
        for tcp in [false, true] {
            let dir = TestDir::new();
            dir.record(
                "client.fgr",
                1,
                tcp,
                false,
                &[
                    event(1, 1, Kind::Sent, 999),
                    event(1, 1, Kind::Sent, 999),
                    event(1, 1, Kind::Response, 10),
                    event(1, 1, Kind::Duplicate, 0),
                    event(1, 2, Kind::Sent, 999),
                    event(1, 2, Kind::Timeout, 0),
                    event(1, 2, Kind::Timeout, 0),
                    event(1, 2, Kind::Late, 0),
                    event(1, 3, Kind::Sent, 999),
                    event(1, 3, Kind::Canceled, 0),
                    event(1, 4, Kind::Canceled, 0),
                    event(1, 5, Kind::Sent, 999),
                    event(1, 5, Kind::Response, 20),
                ],
            );
            let report = analyze(&dir.0, 2, 2).unwrap();
            for name in ["sessions.csv", "summary.csv"] {
                let rows = dir.rows(name);
                assert_eq!(rows[0]["sent_unique"], "4");
                assert_eq!(rows[0]["sent_canceled_unique"], "1");
                assert_eq!(rows[0]["unsent_canceled_unique"], "1");
                assert_eq!(rows[0]["sent_timeout_unique"], "1");
                assert_eq!(rows[0]["sent_late_unique"], "1");
                assert_eq!(rows[0]["response_timeout_denominator"], "3");
                assert_eq!(rows[0]["response_timeout_pct"], "33.333333");
                assert_eq!(rows[0]["response_timeout_status"], "available");
            }
            let mut console = Vec::new();
            write_report(&report, &dir.0, &mut console, false).unwrap();
            let console = String::from_utf8(console).unwrap();
            if tcp {
                assert!(!console.contains("UDP delivery"));
                assert!(!console.contains("Forward reconciliation requires"));
            }
            let label = if tcp { "TCP/client" } else { "UDP/client" };
            assert!(console
                .lines()
                .any(|line| line.trim_start_matches("| ").starts_with(label)
                    && line.contains("33.3333")));
        }
    }

    #[test]
    fn unresolved_conflicting_unsent_and_truncated_outcomes_cannot_claim_a_rate() {
        let dir = TestDir::new();
        dir.record(
            "a.fgr",
            1,
            false,
            false,
            &[
                event(1, 1, Kind::Sent, 0),
                event(2, 1, Kind::Sent, 0),
                event(2, 1, Kind::Timeout, 0),
                event(2, 1, Kind::Response, 10),
                event(3, 1, Kind::Canceled, 0),
                event(4, 1, Kind::Timeout, 0),
                event(5, 1, Kind::Sent, 0),
                event(5, 1, Kind::Canceled, 0),
            ],
        );
        analyze(&dir.0, 2, 2).unwrap();
        let rows = dir.rows("sessions.csv");
        for row in &rows {
            assert_eq!(row["response_timeout_pct"], "NA");
        }
        assert_eq!(rows[0]["response_timeout_status"], "unresolved_requests");
        assert_eq!(rows[1]["response_timeout_status"], "inconsistent_outcomes");
        assert_eq!(rows[2]["response_timeout_status"], "no_eligible_sent");
        assert_eq!(rows[3]["response_timeout_status"], "inconsistent_outcomes");
        assert_eq!(rows[4]["response_timeout_status"], "no_eligible_sent");
        dir.record(
            "b.fgr",
            2,
            false,
            false,
            &[event(1, 1, Kind::Sent, 0), event(1, 1, Kind::Timeout, 0)],
        );
        let path = dir.0.join("b.fgr");
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(32 + 2 * 40)
            .unwrap();
        analyze(&dir.0, 2, 2).unwrap();
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows.last().unwrap()["response_timeout_pct"], "NA");
        assert_eq!(
            rows.last().unwrap()["response_timeout_status"],
            "incomplete_logs"
        );
    }

    #[test]
    fn setup_uses_first_client_ready_per_session_and_excludes_server_markers() {
        let dir = TestDir::new();
        let mut later = event(1, 0, Kind::Ready, 999);
        later.time_ns = 100;
        dir.record(
            "client.fgr",
            1,
            false,
            false,
            &[
                later,
                event(1, 0, Kind::Ready, 10),
                event(2, 0, Kind::Ready, 30),
                event(3, 0, Kind::Open, 0),
            ],
        );
        dir.record(
            "server.fgr",
            1,
            false,
            true,
            &[event(1, 0, Kind::Ready, 777)],
        );
        let report = analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(report.totals[0].setup.count, 2);
        assert_eq!(report.totals[0].setup.mean, 20.0);
        assert_eq!(report.totals[1].setup.count, 0);
        let rows = dir.rows("summary.csv");
        assert_eq!(rows[0]["setup_avg_ns"], "20.000");
        assert_eq!(rows[0]["setup_p50_ns"], "10");
        assert_eq!(rows[0]["setup_p95_ns"], "30");
        assert_eq!(rows[0]["setup_p99_ns"], "30");
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows[2]["setup_avg_ns"], "NA");
        assert_eq!(rows[3]["setup_avg_ns"], "NA");
    }

    #[test]
    fn forward_joins_unique_sequences_but_verifies_raw_manifest_counts() {
        let dir = TestDir::new();
        dir.record(
            "client-a.fgr",
            7,
            false,
            false,
            &[
                event(1, 3, Kind::Sent, 777),
                event(1, 1, Kind::Sent, 777),
                event(1, 3, Kind::Canceled, 0),
                event(2, 1, Kind::Sent, 777),
                event(1, 3, Kind::ServerRequest, 0), // Wrong role cannot supply delivery.
            ],
        );
        dir.record(
            "client-b.fgr",
            7,
            false,
            false,
            &[event(1, 2, Kind::Sent, 777), event(1, 1, Kind::Sent, 777)],
        );
        dir.record(
            "server-a.fgr",
            7,
            false,
            true,
            &[
                event(1, 2, Kind::ServerRequest, 0),
                event(1, 2, Kind::ServerRequest, 0),
                event(2, 1, Kind::ServerRequest, 0),
                event(1, 3, Kind::Sent, 0),
            ],
        );
        let mut arrival = event(1, 1, Kind::ServerRequest, 0);
        arrival.time_ns = u64::MAX; // Endpoint clocks are unrelated.
        dir.record("server-b.fgr", 7, false, true, &[arrival]);
        dir.record(
            "other-client.fgr",
            8,
            false,
            false,
            &[event(1, 3, Kind::Sent, 0)],
        );
        dir.record(
            "other-server.fgr",
            8,
            false,
            true,
            &[event(1, 3, Kind::ServerRequest, 0)],
        );
        dir.record(
            "tcp.fgr",
            7,
            true,
            true,
            &[event(1, 3, Kind::ServerRequest, 0)],
        );
        dir.manifests(7, 5, 4, true);
        let report = analyze(&dir.0, 2, 2).unwrap();
        assert_eq!(report.forward.available_runs, 1);
        assert_eq!(report.forward.unavailable_runs, 1);
        assert_eq!(report.forward.counts.sent, 4);
        assert_eq!(report.forward.counts.matched, 3);
        let rows = dir.rows("forward-summary.csv");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["observed_sent_unique"], "4");
        assert_eq!(rows[0]["run_client_sent_records"], "5");
        assert_eq!(rows[0]["run_server_request_records"], "4");
        assert_eq!(rows[0]["forward_delivered_unique"], "3");
        assert_eq!(rows[0]["forward_missing_unique"], "1");
        assert_eq!(rows[0]["forward_missing_pct"], "25.000000");
        assert_eq!(rows[0]["client_files"], "2");
        assert_eq!(rows[0]["server_files"], "2");
        assert_eq!(rows[1]["forward_missing_pct"], "NA");
        assert_eq!(rows[1]["forward_status"], "manifest_run_mismatch");
        let rows = dir.rows("forward.csv");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["forward_missing_pct"], "33.333333");
    }

    #[test]
    fn forward_requires_both_complete_roles_and_preserves_observed_matches() {
        for missing_server in [true, false] {
            let dir = TestDir::new();
            dir.record(
                "only.fgr",
                1,
                false,
                !missing_server,
                &[event(
                    1,
                    1,
                    if missing_server {
                        Kind::Sent
                    } else {
                        Kind::ServerRequest
                    },
                    0,
                )],
            );
            dir.manifests(1, 1, 1, true);
            let report = analyze(&dir.0, 1, 2).unwrap();
            assert_eq!(report.forward.available_runs, 0);
            let rows = dir.rows("forward-summary.csv");
            assert_eq!(
                rows[0]["forward_status"],
                if missing_server {
                    "missing_server"
                } else {
                    "missing_client"
                }
            );
            assert_eq!(rows[0]["forward_missing_pct"], "NA");
        }
        for truncated_server in [false, true] {
            let dir = TestDir::new();
            dir.record(
                "client.fgr",
                1,
                false,
                false,
                &[event(1, 1, Kind::Sent, 0), event(1, 2, Kind::Sent, 0)],
            );
            dir.record(
                "server.fgr",
                1,
                false,
                true,
                &[event(1, 1, Kind::ServerRequest, 0)],
            );
            dir.manifests(1, 2, 1, true);
            let path = dir.0.join(if truncated_server {
                "server.fgr"
            } else {
                "client.fgr"
            });
            let len = fs::metadata(&path).unwrap().len();
            OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(len - 40)
                .unwrap();
            analyze(&dir.0, 1, 2).unwrap();
            for name in ["forward.csv", "forward-summary.csv"] {
                let rows = dir.rows(name);
                assert_eq!(rows[0]["observed_matched_unique"], "1");
                assert_eq!(rows[0]["forward_delivered_unique"], "NA");
                assert_eq!(rows[0]["forward_missing_unique"], "NA");
                assert_eq!(rows[0]["forward_missing_pct"], "NA");
                assert_eq!(rows[0]["forward_status"], "incomplete_logs");
                assert_eq!(rows[0]["truncated_files"], "1");
            }
        }
    }

    #[test]
    fn omitted_productive_worker_logs_cannot_be_reported_as_forward_loss() {
        for missing_server in [true, false] {
            let dir = TestDir::new();
            dir.record("client.fgr", 1, false, false, &[event(1, 1, Kind::Sent, 0)]);
            dir.record(
                "server.fgr",
                1,
                false,
                true,
                &[event(1, 1, Kind::ServerRequest, 0)],
            );
            dir.record(
                "omitted.fgr",
                1,
                false,
                missing_server,
                &[event(
                    2,
                    1,
                    if missing_server {
                        Kind::ServerRequest
                    } else {
                        Kind::Sent
                    },
                    0,
                )],
            );
            dir.manifests(
                1,
                if missing_server { 1 } else { 2 },
                if missing_server { 2 } else { 1 },
                true,
            );
            fs::remove_file(dir.0.join("omitted.fgr")).unwrap();
            let report = analyze(&dir.0, 1, 2).unwrap();
            assert_eq!(report.forward.available_runs, 0);
            for name in ["forward.csv", "forward-summary.csv"] {
                let rows = dir.rows(name);
                assert_eq!(rows[0]["forward_status"], "manifest_count_mismatch");
                assert_eq!(rows[0]["forward_missing_pct"], "NA");
            }
        }
    }

    #[test]
    fn absent_false_invalid_or_wrong_run_manifests_cannot_establish_completeness() {
        let dir = TestDir::new();
        dir.record("client.fgr", 1, false, false, &[event(1, 1, Kind::Sent, 0)]);
        dir.record(
            "server.fgr",
            1,
            false,
            true,
            &[event(1, 1, Kind::ServerRequest, 0)],
        );
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "missing_manifests"
        );
        dir.manifests(1, 1, 1, false);
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "incomplete_manifests"
        );
        dir.manifests(99, 1, 1, true);
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "manifest_run_mismatch"
        );
        dir.manifests(1, 1, 1, true);
        fs::write(dir.0.join("server-final.txt"), b"run 1\nrequest 1\n").unwrap();
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "invalid_manifests"
        );
        fs::write(dir.0.join("server-final.txt"), vec![b'x'; 8193]).unwrap();
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "invalid_manifests"
        );
        dir.manifests(1, 1, 1, true);
        dir.record("empty-worker.fgr", 1, false, true, &[]);
        fs::remove_file(dir.0.join("empty-worker.fgr")).unwrap();
        analyze(&dir.0, 1, 2).unwrap();
        assert_eq!(
            dir.rows("forward-summary.csv")[0]["forward_status"],
            "available"
        );
    }

    #[test]
    fn forward_orphan_server_requests_and_unknown_headers_suppress_exact_results() {
        let dir = TestDir::new();
        dir.record("client.fgr", 1, false, false, &[event(1, 1, Kind::Sent, 0)]);
        dir.record(
            "server.fgr",
            1,
            false,
            true,
            &[event(1, 2, Kind::ServerRequest, 0)],
        );
        dir.manifests(1, 1, 1, true);
        analyze(&dir.0, 1, 2).unwrap();
        let rows = dir.rows("forward-summary.csv");
        assert_eq!(rows[0]["observed_server_only_unique"], "1");
        assert_eq!(rows[0]["forward_status"], "unmatched_server_requests");
        assert_eq!(rows[0]["forward_missing_pct"], "NA");
        fs::write(dir.0.join("unknown.fgr"), b"bad header").unwrap();
        analyze(&dir.0, 1, 2).unwrap();
        let rows = dir.rows("forward-summary.csv");
        assert_eq!(rows[0]["forward_status"], "incomplete_logs");
        assert_eq!(rows[0]["unknown_header_files"], "1");
    }

    #[test]
    fn console_uses_milliseconds_while_csv_keeps_nanoseconds() {
        let dir = TestDir::new();
        dir.record(
            "client.fgr",
            1,
            false,
            false,
            &[
                event(1, 0, Kind::Ready, 3_000_000),
                event(1, 1, Kind::Sent, 999),
                event(1, 1, Kind::Response, 1_250_000),
                event(1, 2, Kind::Sent, 999),
                event(1, 2, Kind::Response, 2_250_000),
            ],
        );
        let report = analyze(&dir.0, 2, 2).unwrap();
        let mut out = Vec::new();
        write_report(&report, &dir.0, &mut out, false).unwrap();
        let out = String::from_utf8(out).unwrap();
        let row = |label: &str| -> Vec<&str> {
            out.lines()
                .find(|line| line.trim_start_matches("| ").starts_with(label))
                .unwrap()
                .split_whitespace()
                .filter(|cell| *cell != "|")
                .collect()
        };
        assert_eq!(
            &row("UDP/RTT")[1..6],
            ["2", "1.25000", "1.75000", "2.25000", "0.50000"]
        );
        assert_eq!(
            &row("UDP/Mean")[1..6],
            ["1", "1.75000", "1.75000", "1.75000", "0.00000"]
        );
        assert_eq!(
            &row("UDP/Setup")[1..6],
            ["1", "3.00000", "3.00000", "3.00000", "0.00000"]
        );
        assert_eq!(&row("UDP/Jitter")[1..6], ["1", "-", "1.00000", "-", "-"]);
        assert!(out.contains("P50") && out.contains("P95") && out.contains("P99"));
        assert!(out.contains("UDP delivery: NA"));
        assert!(out.lines().all(|line| line.len() <= 120));
        assert!(out.contains("| Event counts") && out.contains("| Timeout accounting"));
        assert!(!out.contains('\x1b'));
        assert!(!out.contains("1250000"));
        let rows = dir.rows("sessions.csv");
        assert_eq!(rows[0]["rtt_min_ns"], "1250000");
        assert_eq!(rows[0]["rtt_avg_ns"], "1750000.000");
        assert_eq!(rows[0]["setup_avg_ns"], "3000000.000");
    }
}
