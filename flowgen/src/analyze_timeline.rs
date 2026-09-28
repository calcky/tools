use super::{output, Entry, Event, Group, Kind, Samples, Sorter, IO_BUFFER, KINDS};
use std::fs::File;
use std::io::{self, BufReader, Seek, Write};
use std::path::Path;

const SECOND: u64 = 1_000_000_000;
const MAX_BUCKETS: u64 = 3600;

#[derive(Default)]
pub(super) struct Lifetime {
    open: Option<Event>,
    ready: Option<Event>,
    closed: Option<Event>,
    failed: Option<Event>,
}

impl Lifetime {
    pub(super) fn observe(&mut self, event: Event) {
        let slot = match event.kind {
            Kind::Open => &mut self.open,
            Kind::Ready => &mut self.ready,
            Kind::Closed => &mut self.closed,
            Kind::Failed => &mut self.failed,
            _ => return,
        };
        if slot.is_none_or(|old| event.time_ns < old.time_ns) {
            *slot = Some(event);
        }
    }

    pub(super) fn finish(&self, group: Group, timeline: &mut Timeline) -> io::Result<()> {
        for event in [self.open, self.ready, self.closed].into_iter().flatten() {
            timeline.push(group, event)?;
        }
        // Setup can fail before there is a socket to close. Remove that attempt
        // from observed live sessions without inventing a Closed record.
        if self.open.is_some() && self.closed.is_none() {
            if let Some(mut event) = self.failed {
                event.kind = Kind::Closed;
                event.value = 1;
                timeline.push(group, event)?;
            }
        }
        Ok(())
    }
}

pub(super) struct Timeline {
    sorter: Sorter,
    clients: bool,
}

impl Timeline {
    pub(super) fn new(dir: &Path, chunk_limit: usize, fan_in: usize) -> io::Result<Self> {
        Ok(Self {
            sorter: Sorter::new(dir, chunk_limit, fan_in)?,
            clients: false,
        })
    }

    pub(super) fn file(&mut self, group: Group) -> io::Result<()> {
        if !group.server {
            self.clients = true;
            self.sorter
                .push(Entry::metadata(group, super::ReadStatus::default()))?;
        }
        Ok(())
    }

    pub(super) fn push(&mut self, group: Group, mut event: Event) -> io::Result<()> {
        if group.server {
            return Ok(());
        }
        // The existing external sort's primary key is flow. Re-key to time;
        // the original identity has already been matched and deduplicated.
        event.flow = event.time_ns;
        self.sorter.push(Entry {
            group,
            event,
            metadata: false,
        })
    }

    pub(super) fn finish(mut self, dir: &Path, source: &Path) -> io::Result<bool> {
        let load = crate::attainment::Load::from_metadata(&crate::html_report::metadata(source)?);
        let mut load_sent = 0_u64;
        let mut load_client = false;
        let mut out = output(&dir.join("timeseries.csv"))?;
        writeln!(out, "run,protocol,role,start_s,end_s,bucket_s,active_sessions,sent_pps,response_pps,send_mbps,response_mbps,open_s,ready_s,closed_s,timeout_s,failed_s,late_s,duplicate_s,reordered_s,invalid_s,limited_s,skipped_s,session_skipped_s,canceled_s,rtt_samples,rtt_min_ns,rtt_avg_ns,rtt_max_ns,rtt_mdev_ns,rtt_p50_ns,rtt_p95_ns,rtt_p99_ns,rtt_p90_ns,on_time_pps")?;
        if let Some(path) = self.sorter.merge()? {
            let mut input = BufReader::with_capacity(IO_BUFFER, File::open(path)?);
            loop {
                let start = input.stream_position()?;
                let Some(first) = Entry::read(&mut input)? else {
                    break;
                };
                let key = first.group;
                if load.is_some_and(|l| l.run == key.run && l.tcp == key.tcp && !key.server) {
                    load_client = true;
                }
                let mut last = first.event.time_ns;
                let end = loop {
                    let position = input.stream_position()?;
                    match Entry::read(&mut input)? {
                        Some(entry) if entry.group == key => last = last.max(entry.event.time_ns),
                        _ => break position,
                    }
                };
                let seconds = last / SECOND + 1;
                let width = seconds.div_ceil(MAX_BUCKETS).max(1) * SECOND;
                input.seek(io::SeekFrom::Start(start))?;
                let mut bucket = Bucket::default();
                let mut index = 0;
                let mut active = 0_i64;
                while input.stream_position()? < end {
                    let entry = Entry::read(&mut input)?.expect("scanned time entry");
                    if entry.metadata {
                        continue;
                    }
                    if entry.event.kind == Kind::Sent
                        && load.is_some_and(|l| l.contains(key.run, key.tcp, entry.event.time_ns))
                    {
                        load_sent += 1;
                    }
                    let target = entry.event.time_ns / width;
                    while index < target {
                        bucket.write(key, index, width, active, &mut out)?;
                        bucket = Bucket::default();
                        index += 1;
                    }
                    match entry.event.kind {
                        Kind::Open => active += 1,
                        Kind::Closed => active -= 1,
                        _ => {}
                    }
                    bucket.push(entry.event)?;
                }
                bucket.write(key, index, width, active, &mut out)?;
            }
        }
        out.flush()?;
        crate::attainment::write(source, dir, load_client.then_some(load_sent))?;
        Ok(self.clients)
    }
}

#[derive(Default)]
struct Bucket {
    counts: [u64; KINDS],
    sent_bytes: u128,
    response_bytes: u128,
    rtt: Samples,
}

impl Bucket {
    fn push(&mut self, event: Event) -> io::Result<()> {
        if event.kind == Kind::Closed && event.value == 1 {
            return Ok(());
        }
        self.counts[event.kind as usize] +=
            if matches!(event.kind, Kind::Skipped | Kind::SessionSkipped) {
                event.value
            } else {
                1
            };
        if event.kind == Kind::Sent {
            self.sent_bytes += event.len as u128;
        }
        if matches!(event.kind, Kind::Response | Kind::Late | Kind::Duplicate) {
            self.response_bytes += event.len as u128;
        }
        if event.kind == Kind::Response {
            self.rtt.add(event.value)?;
        }
        Ok(())
    }

    fn write(
        &self,
        group: Group,
        index: u64,
        width: u64,
        active: i64,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let seconds = width as f64 / SECOND as f64;
        group.write_csv(out)?;
        write!(
            out,
            ",{:.6},{:.6},{seconds:.6},{}",
            index as f64 * seconds,
            (index + 1) as f64 * seconds,
            active.max(0)
        )?;
        for kind in [Kind::Sent, Kind::Response] {
            let count = if kind == Kind::Response {
                self.counts[Kind::Response as usize] as u128
                    + self.counts[Kind::Late as usize] as u128
                    + self.counts[Kind::Duplicate as usize] as u128
            } else {
                self.counts[kind as usize] as u128
            };
            write!(out, ",{:.6}", count as f64 / seconds)?;
        }
        for bytes in [self.sent_bytes, self.response_bytes] {
            write!(out, ",{:.6}", bytes as f64 * 8.0 / seconds / 1e6)?;
        }
        for kind in [
            Kind::Open,
            Kind::Ready,
            Kind::Closed,
            Kind::Timeout,
            Kind::Failed,
            Kind::Late,
            Kind::Duplicate,
            Kind::Reordered,
            Kind::Invalid,
            Kind::Limited,
            Kind::Skipped,
            Kind::SessionSkipped,
            Kind::Canceled,
        ] {
            write!(out, ",{:.6}", self.counts[kind as usize] as f64 / seconds)?;
        }
        write!(out, ",")?;
        self.rtt.write_rtt(out)?;
        if self.rtt.count == 0 {
            write!(out, ",NA")?;
        } else {
            write!(out, ",{}", self.rtt.quantile(0.90))?;
        }
        writeln!(out, ",{:.6}", self.rtt.count as f64 / seconds)
    }
}
