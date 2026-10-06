use crate::model::{
    bucket_upper_ns, Counters, Health, Kind, Latency, PathKey, Row, Snapshot, BUCKETS,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const SCHEMA_VERSION: u32 = 1;
const MAX_CHART_SNAPSHOTS: u64 = 2_000;
const MAX_CHART_ROWS: u64 = 100_000;
const TEMPLATE: &str = include_str!("report.html");
const DATA_MARKER: &str = "/*SKBTOP_DATA*/";

#[derive(Serialize)]
struct Metadata {
    tool: &'static str,
    units: serde_json::Value,
    semantics: serde_json::Value,
    histogram_upper_us: Vec<f64>,
    stages: [&'static str; 3],
}

fn metadata() -> Metadata {
    Metadata {
        tool: "skbtop",
        units: serde_json::json!({
            "latency": "microseconds", "sum_ns": "nanoseconds",
            "newest_at_ns": "monotonic nanoseconds; completion observation timestamp used for sample ordering",
            "pps": "skb observations/second", "bps": "bits/second",
            "bytes": "skb bytes", "elapsed_secs": "seconds", "unix_ms": "milliseconds since Unix epoch"
        }),
        semantics: serde_json::json!({
            "counts": "Kernel skb observations, not wire frames. GRO/GSO, cloning and segmentation can change skb counts and sizes.",
            "interval": "IN PPS/IN bit/s use in_packets/in_bytes; OUT PPS/OUT bit/s use out_packets/out_bytes. Rates use the actual interval duration. IN and OUT describe the start and end of one directed skb path, not reverse traffic.",
            "accounting": "Path IN observations are booked when local delivery or the first egress queue identifies the path, using skb->len saved at the start hook. OUT observations are booked at local delivery or a driver result of NETDEV_TX_OK, using the end skb length. Bookings can fall in different intervals; headers, cloning and GSO also change lengths/counts. IN minus OUT is not a loss measurement.",
            "total": "Latest cumulative counters and total_latency for every path identity, including paths absent from the last snapshot.",
            "latency": "Min/max and sum_ns are collector measurements. Newest uses the latest completed sample's monotonic observation timestamp, not map read order; unknown or incomplete newest updates remain null. Percentiles are histogram estimates; merged percentiles come from cumulative histogram counts, never averages of percentiles.",
            "identity": "kind, network namespace, ingress/egress interface indices and generations; FORWARD pairs group both directions without merging their measurements.",
            "histogram": "Collector bucket counts in original index order. Empty stages have no latency measurements.",
            "stages": "INPUT records only STACK: tp_btf/netif_receive_skb inside __netif_receive_skb_core to fentry/ip_protocol_deliver_rcu or fentry/ip6_protocol_deliver_rcu; QUEUE and TOTAL slots are empty. OUTPUT starts at fentry/__ip_local_out or fentry/__ip6_local_out; FORWARD starts at the RX core hook. STACK ends and QUEUE starts at tp_btf/net_dev_queue, triggered by trace_net_dev_queue(skb) in __dev_queue_xmit before qdisc processing. QUEUE ends at tp_btf/net_dev_start_xmit in xmit_one for the attempt confirmed by tp_btf/net_dev_xmit with NETDEV_TX_OK; TOTAL independently spans start to that attempt entry. Elapsed time includes retries/queued work, not CPU time, application response time or NIC wire time.",
            "chart_data": "Uniformly sampled Snapshot projections retain original timestamps, keys, rates and interval latency metrics; full snapshots remain in snapshots.jsonl. All path summaries are retained. Browser interface generations and integers beyond 2^53-1 are decimal strings to preserve identity and counts.",
            "reconciliation": "Sum actual interval_secs, including first/last partial intervals. Compare each path's summed interval counters, samples, sum_ns and histogram counts with its latest cumulative row. Differences can indicate earlier unrecorded history, live collection boundaries, gaps or collector health errors; cumulative rows remain authoritative."
        }),
        histogram_upper_us: (0..BUCKETS)
            .map(|i| bucket_upper_ns(i) as f64 / 1_000.0)
            .collect(),
        stages: ["STACK", "QUEUE", "TOTAL"],
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DiskRecord {
    Header {
        schema_version: u32,
    },
    Snapshot {
        schema_version: u32,
        snapshot: Snapshot,
    },
    Footer {
        schema_version: u32,
        snapshots: u64,
        complete: bool,
    },
}

/// A recording retains no snapshot history in memory. The caller should call
/// finish after its interrupt-controlled collection loop; Drop is a fallback.
pub struct Recorder {
    directory: PathBuf,
    stream: BufWriter<File>,
    summary_file: Option<File>,
    html_file: Option<File>,
    failure: Option<String>,
    finished: bool,
}

impl Recorder {
    pub fn create(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)
            .with_context(|| format!("create recording directory {}", directory.display()))?;
        // Check all names before reserving any; create_new also closes the race.
        for name in ["snapshots.jsonl", "summary.json", "report.html"] {
            let path = directory.join(name);
            if path.try_exists()? {
                bail!("recording file already exists: {}", path.display());
            }
        }
        let reserve = |name: &str| {
            let path = directory.join(name);
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!(
                        "reserve recording file {} (existing data preserved)",
                        path.display()
                    )
                })
        };
        let mut stream = BufWriter::new(reserve("snapshots.jsonl")?);
        let summary_file = reserve("summary.json")?;
        let html_file = reserve("report.html")?;
        serde_json::to_writer(
            &mut stream,
            &serde_json::json!({
                "type": "header", "schema_version": SCHEMA_VERSION,
                "metadata": metadata()
            }),
        )?;
        stream.write_all(b"\n")?;
        stream.flush().context("flush recording header")?;
        Ok(Self {
            directory: directory.to_path_buf(),
            stream,
            summary_file: Some(summary_file),
            html_file: Some(html_file),
            failure: None,
            finished: false,
        })
    }

    pub fn write(&mut self, snapshot: &Snapshot) -> Result<()> {
        if self.finished {
            bail!("recording is already finalized");
        }
        if let Some(error) = &self.failure {
            bail!("recording previously failed: {error}");
        }
        #[derive(Serialize)]
        struct Record<'a> {
            r#type: &'static str,
            schema_version: u32,
            snapshot: &'a Snapshot,
        }
        let result = (|| -> Result<()> {
            // Serialize one interval before writing so serialization errors
            // cannot leave half a JSON record on disk.
            let mut bytes = serde_json::to_vec(&Record {
                r#type: "snapshot",
                schema_version: SCHEMA_VERSION,
                snapshot,
            })
            .context("serialize snapshot")?;
            bytes.push(b'\n');
            self.stream.write_all(&bytes).context("append snapshot")?;
            self.stream.flush().context("flush snapshot")?;
            Ok(())
        })();
        if let Err(error) = &result {
            self.failure = Some(format!("{error:#}"));
        }
        result
    }

    pub fn finish(&mut self) -> Result<PathBuf> {
        let path = self.directory.join("report.html");
        if self.finished {
            return self
                .failure
                .as_ref()
                .map_or(Ok(path), |e| Err(anyhow!(e.clone())));
        }
        let mut errors = self.failure.iter().cloned().collect::<Vec<_>>();
        if let Err(error) = self.stream.flush() {
            errors.push(format!("flush recording: {error}"));
        }
        let mut builder = SummaryBuilder::default();
        if let Err(error) = visit_recording(
            &self.directory.join("snapshots.jsonl"),
            false,
            |snapshot| builder.observe(&snapshot),
            &mut errors,
        ) {
            errors.push(format!("read recording: {error:#}"));
        }
        // A newline isolates a possibly torn final write from the footer.
        let footer_result = (|| -> Result<()> {
            let mut file = File::open(self.directory.join("snapshots.jsonl"))?;
            if file.metadata()?.len() > 0 {
                file.seek(SeekFrom::End(-1))?;
                let mut last = [0];
                file.read_exact(&mut last)?;
                if last[0] != b'\n' {
                    self.stream.write_all(b"\n")?;
                }
            }
            serde_json::to_writer(
                &mut self.stream,
                &serde_json::json!({
                    "type": "footer", "schema_version": SCHEMA_VERSION,
                    "snapshots": builder.count, "complete": errors.is_empty(), "errors": errors
                }),
            )?;
            self.stream.write_all(b"\n")?;
            self.stream.flush()?;
            Ok(())
        })();
        if let Err(error) = footer_result {
            errors.push(format!("write recording footer: {error:#}"));
        }

        let summary = builder.finish(errors.clone());
        match summary {
            Ok(mut summary) => {
                errors = summary.errors.clone();
                let summary_result = (|| -> Result<()> {
                    let mut out = BufWriter::new(
                        self.summary_file
                            .take()
                            .context("summary file unavailable")?,
                    );
                    serde_json::to_writer_pretty(&mut out, &summary)?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                    Ok(())
                })();
                if let Err(error) = summary_result {
                    errors.push(format!("write summary.json: {error:#}"));
                    summary.complete = false;
                    summary.errors = errors.clone();
                }
                let html_result = (|| -> Result<()> {
                    let mut out =
                        BufWriter::new(self.html_file.take().context("HTML file unavailable")?);
                    write_html(&mut out, &summary, |emit| {
                        let mut index = 0;
                        let mut read_errors = Vec::new();
                        visit_recording(
                            &self.directory.join("snapshots.jsonl"),
                            true,
                            |snapshot| {
                                if summary.keep_chart_snapshot(index) {
                                    emit(&snapshot)?;
                                }
                                index += 1;
                                Ok(())
                            },
                            &mut read_errors,
                        )
                    })?;
                    out.flush()?;
                    Ok(())
                })();
                if let Err(error) = html_result {
                    errors.push(format!("write report.html: {error:#}"));
                }
            }
            Err(error) => errors.push(format!("summarize recording: {error:#}")),
        }
        self.finished = true;
        if errors.is_empty() {
            self.failure = None;
            Ok(path)
        } else {
            let error = format!(
                "recording incomplete; available data preserved in {}: {}",
                self.directory.display(),
                errors.join("; ")
            );
            self.failure = Some(error.clone());
            Err(anyhow!(error))
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
    }
}

fn visit_recording(
    path: &Path,
    require_footer: bool,
    mut visit: impl FnMut(Snapshot) -> Result<()>,
    errors: &mut Vec<String>,
) -> Result<()> {
    let reader = BufReader::new(File::open(path)?);
    let mut header = false;
    let mut footer = false;
    let mut count = 0;
    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record = match serde_json::from_str::<DiskRecord>(&line) {
            Ok(record) => record,
            Err(error) => {
                errors.push(format!(
                    "invalid JSONL record on line {}: {error}",
                    index + 1
                ));
                continue;
            }
        };
        match record {
            DiskRecord::Header { schema_version } => {
                if header || count > 0 || schema_version != SCHEMA_VERSION {
                    errors.push(format!("invalid recording header on line {}", index + 1));
                }
                header = true;
            }
            DiskRecord::Snapshot {
                schema_version,
                snapshot,
            } => {
                if !header || footer || schema_version != SCHEMA_VERSION {
                    errors.push(format!("invalid snapshot envelope on line {}", index + 1));
                    continue;
                }
                visit(snapshot)?;
                count += 1;
            }
            DiskRecord::Footer {
                schema_version,
                snapshots,
                complete,
            } => {
                if footer || schema_version != SCHEMA_VERSION || snapshots != count || !complete {
                    errors.push(format!(
                        "incomplete or inconsistent recording footer on line {}",
                        index + 1
                    ));
                }
                footer = true;
            }
        }
    }
    if !header {
        errors.push("recording header missing".into());
    }
    if !footer && require_footer {
        errors.push("recording footer missing".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize)]
struct Extrema {
    min: Option<f64>,
    max: Option<f64>,
}

impl Extrema {
    fn observe(&mut self, value: f64) {
        if value.is_finite() {
            self.min = Some(self.min.map_or(value, |v| v.min(value)));
            self.max = Some(self.max.map_or(value, |v| v.max(value)));
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct RateExtrema {
    pps: Extrema,
    bps: Extrema,
    in_pps: Extrema,
    in_bps: Extrema,
}

impl RateExtrema {
    fn observe(&mut self, row: &Row) {
        self.pps.observe(row.pps);
        self.bps.observe(row.bps);
        self.in_pps.observe(row.in_pps);
        self.in_bps.observe(row.in_bps);
    }
}

#[derive(Serialize)]
struct PathSummary {
    row: Row,
    observed_snapshots: u64,
    first_unix_ms: u64,
    last_unix_ms: u64,
    rate_extrema: RateExtrema,
    interval_total: Counters,
    interval_latency: [Latency; 3],
    reconciliation: PathReconciliation,
}

#[derive(Default, Serialize)]
struct PathReconciliation {
    counters_match: bool,
    stage_samples_match: [bool; 3],
    stage_sums_match: [bool; 3],
    stage_histograms_match: [bool; 3],
    error: Option<String>,
}

#[derive(Default, Serialize)]
struct IntervalReconciliation {
    summed_interval_secs: f64,
    first_interval_secs: Option<f64>,
    last_interval_secs: Option<f64>,
    start_elapsed_secs: Option<f64>,
    end_elapsed_secs: Option<f64>,
    elapsed_span_secs: Option<f64>,
    duration_difference_secs: Option<f64>,
    durations_match: bool,
    counters_match: bool,
    latency_matches: bool,
}

#[derive(Serialize)]
struct KindSummary {
    kind: Kind,
    paths: usize,
    total: Option<Counters>,
    total_latency: Option<[Latency; 3]>,
    aggregation_error: Option<String>,
}

#[derive(Serialize)]
struct Summary {
    schema_version: u32,
    metadata: Metadata,
    complete: bool,
    errors: Vec<String>,
    snapshot_count: u64,
    started_unix_ms: Option<u64>,
    ended_unix_ms: Option<u64>,
    elapsed_secs: f64,
    chart_stride: u64,
    chart_snapshot_count: u64,
    paths: Vec<PathSummary>,
    kinds: Vec<KindSummary>,
    health: Health,
    reconciliation: IntervalReconciliation,
}

impl Summary {
    fn keep_chart_snapshot(&self, index: u64) -> bool {
        index.is_multiple_of(self.chart_stride) || index + 1 == self.snapshot_count
    }
}

#[derive(Default)]
struct SummaryBuilder {
    paths: BTreeMap<PathKey, PathSummary>,
    count: u64,
    max_rows: u64,
    start: Option<u64>,
    end: Option<u64>,
    elapsed: f64,
    health: Health,
    reconciliation: IntervalReconciliation,
}

impl SummaryBuilder {
    fn observe(&mut self, snapshot: &Snapshot) -> Result<()> {
        self.count += 1;
        if snapshot.interval_secs.is_finite() && snapshot.interval_secs >= 0.0 {
            self.reconciliation.summed_interval_secs += snapshot.interval_secs;
            self.reconciliation
                .first_interval_secs
                .get_or_insert(snapshot.interval_secs);
            self.reconciliation.last_interval_secs = Some(snapshot.interval_secs);
            if snapshot.elapsed_secs.is_finite() {
                self.reconciliation
                    .start_elapsed_secs
                    .get_or_insert(snapshot.elapsed_secs - snapshot.interval_secs);
                self.reconciliation.end_elapsed_secs = Some(snapshot.elapsed_secs);
            }
        }
        self.max_rows = self.max_rows.max(snapshot.rows.len() as u64);
        self.start = Some(
            self.start
                .map_or(snapshot.unix_ms, |v| v.min(snapshot.unix_ms)),
        );
        self.end = Some(
            self.end
                .map_or(snapshot.unix_ms, |v| v.max(snapshot.unix_ms)),
        );
        if snapshot.elapsed_secs.is_finite() {
            self.elapsed = self.elapsed.max(snapshot.elapsed_secs);
        }
        self.health = snapshot.health.clone();
        for row in &snapshot.rows {
            let path = self.paths.entry(row.key).or_insert_with(|| PathSummary {
                row: row.clone(),
                observed_snapshots: 0,
                first_unix_ms: snapshot.unix_ms,
                last_unix_ms: snapshot.unix_ms,
                rate_extrema: RateExtrema::default(),
                interval_total: Counters::default(),
                interval_latency: std::array::from_fn(|_| Latency::default()),
                reconciliation: PathReconciliation::default(),
            });
            path.row = row.clone();
            path.observed_snapshots += 1;
            path.first_unix_ms = path.first_unix_ms.min(snapshot.unix_ms);
            path.last_unix_ms = path.last_unix_ms.max(snapshot.unix_ms);
            path.rate_extrema.observe(row);
            if path.reconciliation.error.is_none() {
                let result = (|| -> Result<()> {
                    add_counters(&mut path.interval_total, &row.interval)?;
                    for (sum, latency) in path.interval_latency.iter_mut().zip(&row.latency) {
                        merge_latency(sum, latency)?;
                    }
                    Ok(())
                })();
                if let Err(error) = result {
                    path.reconciliation.error = Some(format!("{error:#}"));
                }
            }
        }
        Ok(())
    }

    fn finish(self, mut errors: Vec<String>) -> Result<Summary> {
        let mut paths = self.paths.into_values().collect::<Vec<_>>();
        for path in &mut paths {
            for latency in &mut path.interval_latency {
                finish_latency(latency);
            }
            let available = path.reconciliation.error.is_none();
            path.reconciliation.counters_match =
                available && counters_equal(&path.interval_total, &path.row.total);
            for stage in 0..3 {
                let interval = &path.interval_latency[stage];
                let total = &path.row.total_latency[stage];
                path.reconciliation.stage_samples_match[stage] =
                    available && interval.samples == total.samples;
                path.reconciliation.stage_sums_match[stage] =
                    available && interval.sum_ns == total.sum_ns;
                path.reconciliation.stage_histograms_match[stage] = available
                    && (0..BUCKETS).all(|i| {
                        interval.histogram.get(i).copied().unwrap_or(0)
                            == total.histogram.get(i).copied().unwrap_or(0)
                    });
            }
            if let Some(error) = &path.reconciliation.error {
                errors.push(format!(
                    "path {:?} interval reconciliation unavailable: {error}",
                    path.row.key
                ));
            }
        }
        let mut reconciliation = self.reconciliation;
        reconciliation.elapsed_span_secs = reconciliation
            .start_elapsed_secs
            .zip(reconciliation.end_elapsed_secs)
            .map(|(start, end)| end - start);
        reconciliation.duration_difference_secs = reconciliation
            .elapsed_span_secs
            .map(|span| reconciliation.summed_interval_secs - span);
        reconciliation.durations_match =
            reconciliation
                .duration_difference_secs
                .is_none_or(|difference| {
                    difference.abs() <= 1e-6 * reconciliation.summed_interval_secs.max(1.0)
                });
        reconciliation.counters_match = paths.iter().all(|path| path.reconciliation.counters_match);
        reconciliation.latency_matches = paths.iter().all(|path| {
            path.reconciliation
                .stage_samples_match
                .into_iter()
                .chain(path.reconciliation.stage_sums_match)
                .chain(path.reconciliation.stage_histograms_match)
                .all(|v| v)
        });
        let mut kinds = Vec::new();
        for kind in [Kind::Input, Kind::Output, Kind::Forward] {
            let rows = paths
                .iter()
                .filter(|p| p.row.key.kind == kind)
                .map(|p| &p.row)
                .collect::<Vec<_>>();
            let aggregate = (|| -> Result<(Counters, [Latency; 3])> {
                let mut total = Counters::default();
                let mut total_latency = std::array::from_fn(|_| Latency::default());
                for row in &rows {
                    add_counters(&mut total, &row.total)?;
                    for (merged, latency) in total_latency.iter_mut().zip(&row.total_latency) {
                        merge_latency(merged, latency)?;
                    }
                }
                for latency in &mut total_latency {
                    finish_latency(latency);
                }
                Ok((total, total_latency))
            })();
            let (total, total_latency, aggregation_error) = match aggregate {
                Ok((total, latency)) => (Some(total), Some(latency), None),
                Err(error) => {
                    let error = format!("{:?} aggregate unavailable: {error:#}", kind);
                    errors.push(error.clone());
                    (None, None, Some(error))
                }
            };
            kinds.push(KindSummary {
                kind,
                paths: rows.len(),
                total,
                total_latency,
                aggregation_error,
            });
        }
        let budget = MAX_CHART_SNAPSHOTS
            .min(MAX_CHART_ROWS / self.max_rows.max(1))
            .max(2);
        // Leave one slot for the last interval, which is always included.
        let chart_stride = self.count.saturating_sub(1).div_ceil(budget - 1).max(1);
        let chart_snapshot_count = if self.count == 0 {
            0
        } else {
            (self.count - 1) / chart_stride
                + 1
                + u64::from(!(self.count - 1).is_multiple_of(chart_stride))
        };
        Ok(Summary {
            schema_version: SCHEMA_VERSION,
            metadata: metadata(),
            complete: errors.is_empty(),
            errors,
            snapshot_count: self.count,
            started_unix_ms: self.start,
            ended_unix_ms: self.end,
            elapsed_secs: self.elapsed,
            chart_stride,
            chart_snapshot_count,
            paths,
            kinds,
            health: self.health,
            reconciliation,
        })
    }
}

fn counters_equal(a: &Counters, b: &Counters) -> bool {
    a.in_packets == b.in_packets
        && a.in_bytes == b.in_bytes
        && a.out_packets == b.out_packets
        && a.out_bytes == b.out_bytes
        && a.route == b.route
        && a.bridge == b.bridge
        && a.combo == b.combo
        && a.freed == b.freed
}

fn add_counters(target: &mut Counters, source: &Counters) -> Result<()> {
    for (a, b) in [
        (&mut target.in_packets, source.in_packets),
        (&mut target.in_bytes, source.in_bytes),
        (&mut target.out_packets, source.out_packets),
        (&mut target.out_bytes, source.out_bytes),
        (&mut target.route, source.route),
        (&mut target.bridge, source.bridge),
        (&mut target.combo, source.combo),
        (&mut target.freed, source.freed),
    ] {
        *a = a.checked_add(b).context("cumulative counter overflow")?;
    }
    Ok(())
}

fn merge_latency(target: &mut Latency, source: &Latency) -> Result<()> {
    target.samples = target
        .samples
        .checked_add(source.samples)
        .context("latency sample overflow")?;
    target.sum_ns = target
        .sum_ns
        .checked_add(source.sum_ns)
        .context("latency sum overflow")?;
    if source.samples > 0 {
        if source.newest_at_ns > target.newest_at_ns {
            target.newest_at_ns = source.newest_at_ns;
            target.newest_us = source.newest_us;
        }
        if let Some(value) = source.min_us.filter(|v| v.is_finite()) {
            target.min_us = Some(target.min_us.map_or(value, |v| v.min(value)));
        }
        if let Some(value) = source.max_us.filter(|v| v.is_finite()) {
            target.max_us = Some(target.max_us.map_or(value, |v| v.max(value)));
        }
    }
    target
        .histogram
        .resize(target.histogram.len().max(source.histogram.len()), 0);
    for (a, b) in target.histogram.iter_mut().zip(&source.histogram) {
        *a = a.checked_add(*b).context("histogram count overflow")?;
    }
    Ok(())
}

fn finish_latency(latency: &mut Latency) {
    if latency.samples == 0 {
        return;
    }
    latency.avg_us = Some(latency.sum_ns as f64 / latency.samples as f64 / 1_000.0);
    // Bucket decoding is shared with the collector's logarithmic histogram.
    let percentile = |percent: u128| {
        let rank = (u128::from(latency.samples) * percent).div_ceil(100);
        let mut count = 0u128;
        for (bucket, samples) in latency.histogram.iter().enumerate() {
            count += u128::from(*samples);
            if count >= rank {
                let value = bucket_upper_ns(bucket) as f64 / 1_000.0;
                return Some(
                    value
                        .max(latency.min_us.unwrap_or(value))
                        .min(latency.max_us.unwrap_or(value)),
                );
            }
        }
        None
    };
    latency.p50_us = percentile(50);
    latency.p90_us = percentile(90);
    latency.p95_us = percentile(95);
    latency.p99_us = percentile(99);
}

#[derive(Serialize)]
struct ChartLatency {
    samples: u64,
    avg_us: Option<f64>,
    p50_us: Option<f64>,
    p90_us: Option<f64>,
    p95_us: Option<f64>,
    p99_us: Option<f64>,
}

#[derive(Serialize)]
struct ChartRow {
    key: serde_json::Value,
    pps: f64,
    bps: f64,
    in_pps: f64,
    in_bps: f64,
    latency: [ChartLatency; 3],
}

#[derive(Serialize)]
struct ChartSnapshot {
    sequence: u64,
    elapsed_secs: f64,
    interval_secs: f64,
    unix_ms: u64,
    rows: Vec<ChartRow>,
}

fn browser_key(key: &PathKey) -> serde_json::Value {
    // JavaScript numbers cannot represent every u64 interface generation.
    serde_json::json!({
        "kind": key.kind, "netns": key.netns, "ingress": key.ingress, "egress": key.egress,
        "ingress_generation": key.ingress_generation.to_string(),
        "egress_generation": key.egress_generation.to_string()
    })
}

impl From<&Snapshot> for ChartSnapshot {
    fn from(snapshot: &Snapshot) -> Self {
        Self {
            sequence: snapshot.sequence,
            elapsed_secs: snapshot.elapsed_secs,
            interval_secs: snapshot.interval_secs,
            unix_ms: snapshot.unix_ms,
            rows: snapshot
                .rows
                .iter()
                .map(|row| ChartRow {
                    key: browser_key(&row.key),
                    pps: row.pps,
                    bps: row.bps,
                    in_pps: row.in_pps,
                    in_bps: row.in_bps,
                    latency: std::array::from_fn(|stage| {
                        let value = &row.latency[stage];
                        ChartLatency {
                            samples: value.samples,
                            avg_us: value.avg_us,
                            p50_us: value.p50_us,
                            p90_us: value.p90_us,
                            p95_us: value.p95_us,
                            p99_us: value.p99_us,
                        }
                    }),
                })
                .collect(),
        }
    }
}

struct ScriptWriter<W>(W);

impl<W: Write> Write for ScriptWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;
        let mut index = 0;
        while index < bytes.len() {
            let escape: Option<(&[u8], usize)> = match bytes[index] {
                b'<' => Some((b"\\u003c", 1)),
                b'>' => Some((b"\\u003e", 1)),
                b'&' => Some((b"\\u0026", 1)),
                0xe2 if bytes.get(index..index + 3) == Some(&[0xe2, 0x80, 0xa8]) => {
                    Some((b"\\u2028", 3))
                }
                0xe2 if bytes.get(index..index + 3) == Some(&[0xe2, 0x80, 0xa9]) => {
                    Some((b"\\u2029", 3))
                }
                _ => None,
            };
            if let Some((escape, length)) = escape {
                self.0.write_all(&bytes[start..index])?;
                self.0.write_all(escape)?;
                index += length;
                start = index;
            } else {
                index += 1;
            }
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn write_html<W: Write>(
    out: &mut W,
    summary: &Summary,
    snapshots: impl FnOnce(&mut dyn FnMut(&Snapshot) -> Result<()>) -> Result<()>,
) -> Result<()> {
    let (before, after) = TEMPLATE
        .split_once(DATA_MARKER)
        .context("HTML data marker missing")?;
    out.write_all(before.as_bytes())?;
    out.write_all(b"{\"summary\":")?;
    let mut browser_summary = serde_json::to_value(summary)?;
    for (value, path) in browser_summary["paths"]
        .as_array_mut()
        .context("summary paths missing")?
        .iter_mut()
        .zip(&summary.paths)
    {
        value["row"]["key"] = browser_key(&path.row.key);
    }
    browser_large_integers(&mut browser_summary);
    serde_json::to_writer(ScriptWriter(&mut *out), &browser_summary)?;
    out.write_all(b",\"snapshots\":[")?;
    let mut first = true;
    snapshots(&mut |snapshot| {
        if !first {
            out.write_all(b",")?;
        }
        first = false;
        serde_json::to_writer(ScriptWriter(&mut *out), &ChartSnapshot::from(snapshot))?;
        Ok(())
    })?;
    out.write_all(b"]}")?;
    out.write_all(after.as_bytes())?;
    Ok(())
}

fn browser_large_integers(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => values.iter_mut().for_each(browser_large_integers),
        serde_json::Value::Object(values) => values.values_mut().for_each(browser_large_integers),
        serde_json::Value::Number(number) => {
            if let Some(integer) = number.as_u64().filter(|v| *v > 9_007_199_254_740_991) {
                *value = serde_json::Value::String(integer.to_string());
            }
        }
        _ => {}
    }
}

/// Render the same standalone report without creating a recording directory.
#[allow(dead_code)]
pub fn render_html(snapshots: &[Snapshot]) -> Result<String> {
    let mut builder = SummaryBuilder::default();
    for snapshot in snapshots {
        builder.observe(snapshot)?;
    }
    let summary = builder.finish(Vec::new())?;
    let mut out = Vec::new();
    write_html(&mut out, &summary, |emit| {
        for (index, snapshot) in snapshots.iter().enumerate() {
            if summary.keep_chart_snapshot(index as u64) {
                emit(snapshot)?;
            }
        }
        Ok(())
    })?;
    String::from_utf8(out).context("HTML is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::bucket_index;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "skbtop-report-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn latency(values: &[(u64, u64)]) -> Latency {
        let mut histogram = vec![0; BUCKETS];
        let mut samples = 0;
        let mut sum = 0;
        for &(ns, count) in values {
            histogram[bucket_index(ns)] += count;
            samples += count;
            sum += ns * count;
        }
        Latency::from_raw(
            samples,
            sum,
            values.iter().map(|v| v.0).min().unwrap_or(0),
            values.iter().map(|v| v.0).max().unwrap_or(0),
            histogram,
        )
    }

    #[test]
    fn merged_newest_uses_completion_time_and_old_recordings_remain_readable() {
        let mut earlier = latency(&[(500, 1)]);
        earlier.newest_us = Some(0.5);
        earlier.newest_at_ns = Some(100);
        let mut later = latency(&[(200, 1)]);
        later.newest_us = Some(0.2);
        later.newest_at_ns = Some(200);
        let mut merged = Latency::default();
        merge_latency(&mut merged, &later).unwrap();
        merge_latency(&mut merged, &earlier).unwrap();
        finish_latency(&mut merged);
        assert_eq!(merged.newest_us, Some(0.2));
        assert_eq!(merged.avg_us, Some(0.35));
        later.newest_at_ns = Some(300);
        later.newest_us = None;
        merge_latency(&mut merged, &later).unwrap();
        assert_eq!(merged.newest_us, None);
        let mut old = serde_json::to_value(&earlier).unwrap();
        old.as_object_mut().unwrap().remove("newest_us");
        old.as_object_mut().unwrap().remove("newest_at_ns");
        let old: Latency = serde_json::from_value(old).unwrap();
        assert_eq!(old.newest_us, None);
        assert_eq!(old.newest_at_ns, None);
        assert_eq!(old.avg_us, Some(0.5));
    }

    fn row(
        kind: Kind,
        ingress: u32,
        egress: u32,
        packets: u64,
        rate: f64,
        values: &[(u64, u64)],
    ) -> Row {
        let measured = latency(values);
        Row {
            key: PathKey {
                kind,
                ingress,
                egress,
                netns: 7,
                ingress_generation: u64::from(ingress),
                egress_generation: u64::from(egress),
            },
            ingress_name: if ingress == 0 {
                String::new()
            } else {
                format!("eth{ingress}")
            },
            egress_name: if egress == 0 {
                String::new()
            } else {
                format!("eth{egress}")
            },
            interval: Counters {
                in_packets: 1,
                out_packets: 1,
                ..Counters::default()
            },
            total: Counters {
                in_packets: packets,
                in_bytes: packets * 128,
                out_packets: packets,
                out_bytes: packets * 128,
                ..Counters::default()
            },
            latency: std::array::from_fn(|stage| {
                if kind.latency_stages().contains(&stage) {
                    measured.clone()
                } else {
                    Latency::default()
                }
            }),
            total_latency: std::array::from_fn(|stage| {
                if kind.latency_stages().contains(&stage) {
                    measured.clone()
                } else {
                    Latency::default()
                }
            }),
            pending: 0,
            pps: rate,
            bps: rate * 1024.0,
            in_pps: rate + 1.0,
            in_bps: (rate + 1.0) * 1024.0,
        }
    }

    fn snapshot(sequence: u64, rows: Vec<Row>) -> Snapshot {
        Snapshot {
            sequence,
            elapsed_secs: sequence as f64,
            interval_secs: 1.0,
            unix_ms: 1_770_000_000_000 + sequence * 1000,
            rows,
            interfaces: Vec::new(),
            health: Health::default(),
        }
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_reader(File::open(path).unwrap()).unwrap()
    }
    fn html_data(html: &str) -> Value {
        let marker = "<script id=\"recording-data\" type=\"application/json\">";
        serde_json::from_str(
            html.split_once(marker)
                .unwrap()
                .1
                .split_once("</script>")
                .unwrap()
                .0,
        )
        .unwrap()
    }

    #[test]
    fn streams_flushed_schema_records_and_finalizes_once() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        let expected = snapshot(1, vec![row(Kind::Input, 1, 0, 8, 2.0, &[(1000, 8)])]);
        recorder.write(&expected).unwrap();
        let records = fs::read_to_string(directory.0.join("snapshots.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["schema_version"], 1);
        assert_eq!(records[0]["metadata"]["units"]["latency"], "microseconds");
        assert!(records[0]["metadata"]["semantics"]["counts"]
            .as_str()
            .unwrap()
            .contains("not wire frames"));
        assert_eq!(
            records[1]["snapshot"],
            serde_json::to_value(&expected).unwrap()
        );
        let html = recorder.finish().unwrap();
        let original = fs::read(directory.0.join("snapshots.jsonl")).unwrap();
        assert_eq!(recorder.finish().unwrap(), html);
        assert_eq!(
            fs::read(directory.0.join("snapshots.jsonl")).unwrap(),
            original
        );
        assert!(recorder.write(&expected).is_err());
        let footer = serde_json::from_slice::<Value>(
            original
                .split(|b| *b == b'\n')
                .rev()
                .find(|s| !s.is_empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(footer["type"], "footer");
        assert_eq!(footer["snapshots"], 1);
        assert_eq!(footer["complete"], true);
        let summary = read_json(&directory.0.join("summary.json"));
        assert_eq!(summary["paths"][0]["row"]["total"]["out_packets"], 8);
        assert_eq!(
            html_data(&fs::read_to_string(html).unwrap())["summary"]["snapshot_count"],
            1
        );
    }

    #[test]
    fn refuses_each_existing_artifact_without_changing_anything() {
        for name in ["snapshots.jsonl", "summary.json", "report.html"] {
            let directory = TestDirectory::new();
            let path = directory.0.join(name);
            fs::write(&path, b"existing recording").unwrap();
            assert!(Recorder::create(&directory.0).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"existing recording");
            assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
        }
    }

    #[test]
    fn empty_recording_and_render_are_valid() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        let path = recorder.finish().unwrap();
        let summary = read_json(&directory.0.join("summary.json"));
        assert_eq!(summary["snapshot_count"], 0);
        assert_eq!(summary["started_unix_ms"], Value::Null);
        assert!(summary["paths"].as_array().unwrap().is_empty());
        assert_eq!(
            summary["kinds"][0]["total_latency"][0]["p99_us"],
            Value::Null
        );
        let html = fs::read_to_string(path).unwrap();
        assert!(html.contains("No snapshots recorded"));
        assert_eq!(html_data(&html), html_data(&render_html(&[]).unwrap()));
    }

    #[test]
    fn cumulative_final_rows_merge_histograms_without_averaging_percentiles() {
        let first = row(Kind::Forward, 1, 2, 50, 91.0, &[(1000, 50)]);
        let mut final_first = row(Kind::Forward, 1, 2, 90, 7.0, &[(1000, 90)]);
        final_first.latency = std::array::from_fn(|_| latency(&[(50_000, 1)]));
        let other = row(Kind::Forward, 2, 1, 10, 4.0, &[(10_000, 10)]);
        let missing_last = row(Kind::Input, 3, 0, 6, 0.0, &[(700, 6)]);
        let mut builder = SummaryBuilder::default();
        builder
            .observe(&snapshot(1, vec![first, missing_last]))
            .unwrap();
        builder
            .observe(&snapshot(2, vec![final_first, other]))
            .unwrap();
        let summary = builder.finish(vec![]).unwrap();
        assert_eq!(summary.paths.len(), 3);
        let group = &summary.kinds[2];
        let merged = &group.total_latency.as_ref().unwrap()[2];
        assert_eq!(group.total.as_ref().unwrap().out_packets, 100);
        assert_eq!(merged.samples, 100);
        assert_eq!(merged.avg_us, Some(1.9));
        assert_eq!(merged.min_us, Some(1.0));
        assert_eq!(merged.max_us, Some(10.0));
        assert_eq!(merged.p50_us, Some(1.023));
        assert_eq!(merged.p90_us, Some(1.023));
        assert_eq!(merged.p95_us, Some(10.0));
        assert_eq!(merged.p99_us, Some(10.0));
        assert_eq!(merged.histogram[bucket_index(1000)], 90);
        assert_eq!(merged.histogram[bucket_index(10_000)], 10);
        let path = summary
            .paths
            .iter()
            .find(|p| p.row.key.ingress == 1)
            .unwrap();
        assert_eq!(path.rate_extrema.pps.min, Some(7.0));
        assert_eq!(path.rate_extrema.pps.max, Some(91.0));
        assert_eq!(path.row.total_latency[2].samples, 90);
        assert_eq!(summary.kinds[0].total.as_ref().unwrap().out_packets, 6);
    }

    #[test]
    fn reconciliation_includes_first_and_last_partial_intervals_and_zero_length_stop() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        for (sequence, elapsed, duration, cumulative, delta) in [
            (1, 0.25, 0.25, 2, 2),
            (2, 1.25, 1.0, 6, 4),
            (3, 1.375, 0.125, 7, 1),
            (4, 1.375, 0.0, 7, 0),
        ] {
            let mut path = row(
                Kind::Output,
                0,
                1,
                cumulative,
                if duration > 0.0 {
                    delta as f64 / duration
                } else {
                    0.0
                },
                &[(1000, cumulative)],
            );
            let interval = row(Kind::Output, 0, 1, delta, 0.0, &[(1000, delta)]);
            path.interval = interval.total;
            path.latency = interval.latency;
            let mut value = snapshot(sequence, vec![path]);
            value.elapsed_secs = elapsed;
            value.interval_secs = duration;
            value.unix_ms = 1_770_000_000_000 + (elapsed * 1000.0) as u64;
            recorder.write(&value).unwrap();
        }
        recorder.finish().unwrap();
        let summary = read_json(&directory.0.join("summary.json"));
        let reconciliation = &summary["reconciliation"];
        assert_eq!(reconciliation["summed_interval_secs"], 1.375);
        assert_eq!(reconciliation["first_interval_secs"], 0.25);
        assert_eq!(reconciliation["last_interval_secs"], 0.0);
        assert_eq!(reconciliation["start_elapsed_secs"], 0.0);
        assert_eq!(reconciliation["elapsed_span_secs"], 1.375);
        assert_eq!(reconciliation["duration_difference_secs"], 0.0);
        assert_eq!(reconciliation["durations_match"], true);
        assert_eq!(reconciliation["counters_match"], true);
        assert_eq!(reconciliation["latency_matches"], true);
        assert_eq!(summary["paths"][0]["interval_total"]["out_packets"], 7);
        assert_eq!(summary["paths"][0]["interval_latency"][2]["samples"], 7);
        assert_eq!(summary["paths"][0]["rate_extrema"]["pps"]["max"], 8.0);
    }

    #[test]
    fn reconciliation_reports_gaps_without_replacing_cumulative_measurements() {
        let mut first = snapshot(1, vec![row(Kind::Input, 1, 0, 2, 1.0, &[(1000, 2)])]);
        first.elapsed_secs = 5.0;
        let mut last = snapshot(2, vec![row(Kind::Input, 1, 0, 7, 1.0, &[(1000, 7)])]);
        last.elapsed_secs = 7.0;
        last.interval_secs = 0.5;
        let data = html_data(&render_html(&[first, last]).unwrap());
        assert_eq!(
            data["summary"]["reconciliation"]["summed_interval_secs"],
            1.5
        );
        assert_eq!(data["summary"]["reconciliation"]["elapsed_span_secs"], 3.0);
        assert_eq!(
            data["summary"]["reconciliation"]["duration_difference_secs"],
            -1.5
        );
        assert_eq!(data["summary"]["reconciliation"]["durations_match"], false);
        assert_eq!(data["summary"]["reconciliation"]["counters_match"], false);
        assert_eq!(data["summary"]["reconciliation"]["latency_matches"], false);
        assert_eq!(
            data["summary"]["paths"][0]["row"]["total"]["out_packets"],
            7
        );
        assert_eq!(data["summary"]["complete"], true);
    }

    #[test]
    fn aggregate_overflow_preserves_all_paths_and_finalizes_incomplete_reports() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        let mut first = row(Kind::Input, 1, 0, 1, 0.0, &[(1000, 1)]);
        first.total.out_packets = u64::MAX;
        recorder
            .write(&snapshot(
                1,
                vec![first, row(Kind::Input, 2, 0, 1, 0.0, &[(1000, 1)])],
            ))
            .unwrap();
        assert!(recorder
            .finish()
            .unwrap_err()
            .to_string()
            .contains("overflow"));
        let summary = read_json(&directory.0.join("summary.json"));
        assert_eq!(summary["complete"], false);
        assert_eq!(summary["paths"].as_array().unwrap().len(), 2);
        assert_eq!(summary["kinds"][0]["total"], Value::Null);
        let data = html_data(&fs::read_to_string(directory.0.join("report.html")).unwrap());
        assert_eq!(
            data["summary"]["paths"][0]["row"]["total"]["out_packets"],
            u64::MAX.to_string()
        );
    }

    #[test]
    fn torn_final_line_preserves_valid_data_and_returns_error() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        recorder
            .write(&snapshot(
                1,
                vec![row(Kind::Output, 0, 1, 4, 1.0, &[(900, 4)])],
            ))
            .unwrap();
        recorder
            .stream
            .write_all(b"{\"type\":\"snapshot\",\"snapshot\":")
            .unwrap();
        recorder.stream.flush().unwrap();
        let error = recorder.finish().unwrap_err().to_string();
        assert!(error.contains("invalid JSONL record"));
        assert!(recorder.finish().is_err());
        let log = fs::read_to_string(directory.0.join("snapshots.jsonl")).unwrap();
        assert!(log.contains("{\"type\":\"snapshot\",\"snapshot\":\n"));
        let footer = serde_json::from_str::<Value>(log.lines().last().unwrap()).unwrap();
        assert_eq!(footer["complete"], false);
        assert_eq!(footer["snapshots"], 1);
        let summary = read_json(&directory.0.join("summary.json"));
        assert_eq!(summary["complete"], false);
        assert_eq!(summary["snapshot_count"], 1);
        assert_eq!(summary["paths"][0]["row"]["total"]["out_packets"], 4);
        let data = html_data(&fs::read_to_string(directory.0.join("report.html")).unwrap());
        assert_eq!(data["summary"]["complete"], false);
        assert_eq!(data["snapshots"].as_array().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_failure_still_generates_reports_from_flushed_history() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        let data = snapshot(1, vec![row(Kind::Input, 1, 0, 1, 1.0, &[(900, 1)])]);
        recorder.write(&data).unwrap();
        recorder.stream = BufWriter::new(OpenOptions::new().write(true).open("/dev/full").unwrap());
        assert!(recorder.write(&data).is_err());
        assert!(recorder.write(&data).is_err());
        assert!(recorder.finish().is_err());
        let summary = read_json(&directory.0.join("summary.json"));
        assert_eq!(summary["snapshot_count"], 1);
        assert_eq!(summary["complete"], false);
        assert_eq!(
            html_data(&fs::read_to_string(directory.0.join("report.html")).unwrap())["snapshots"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn summary_failure_preserves_log_and_still_attempts_html() {
        let directory = TestDirectory::new();
        let mut recorder = Recorder::create(&directory.0).unwrap();
        recorder.write(&snapshot(1, vec![])).unwrap();
        recorder.summary_file = Some(OpenOptions::new().write(true).open("/dev/full").unwrap());
        assert!(recorder
            .finish()
            .unwrap_err()
            .to_string()
            .contains("summary.json"));
        let data = html_data(&fs::read_to_string(directory.0.join("report.html")).unwrap());
        assert_eq!(data["summary"]["complete"], false);
        assert!(data["summary"]["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|error| error.as_str().unwrap().contains("summary.json")));
    }

    #[test]
    fn drop_finalizes_an_interrupted_collection_scope() {
        let directory = TestDirectory::new();
        {
            let mut recorder = Recorder::create(&directory.0).unwrap();
            recorder.write(&snapshot(1, vec![])).unwrap();
        }
        assert_eq!(
            read_json(&directory.0.join("summary.json"))["snapshot_count"],
            1
        );
        assert!(fs::metadata(directory.0.join("report.html")).unwrap().len() > 0);
    }

    #[test]
    fn script_json_and_labels_cannot_break_out_and_generations_stay_exact() {
        let mut path = row(Kind::Input, 1, 0, 2, 1.0, &[(1000, 2)]);
        path.ingress_name = "</script><img src=x onerror=alert(1)>&\"\u{2028}\u{2029}".into();
        path.key.ingress_generation = 9_007_199_254_740_993;
        let original = path.ingress_name.clone();
        let html = render_html(&[snapshot(1, vec![path])]).unwrap();
        assert!(!html.contains("</script><img"));
        assert!(html.contains("\\u003c/script\\u003e\\u003cimg"));
        assert!(html.contains("\\u0026"));
        assert!(html.contains("\\u2028\\u2029"));
        assert_eq!(html.matches("</script>").count(), 2);
        assert!(!html.contains("innerHTML"));
        assert!(!html.contains("fetch("));
        assert!(!html.contains("<script src="));
        let data = html_data(&html);
        assert_eq!(data["summary"]["paths"][0]["row"]["ingress_name"], original);
        assert_eq!(
            data["summary"]["paths"][0]["row"]["key"]["ingress_generation"],
            "9007199254740993"
        );
        assert_eq!(
            data["snapshots"][0]["rows"][0]["key"]["ingress_generation"],
            "9007199254740993"
        );
    }

    #[test]
    fn chart_downsampling_keeps_every_path_and_exact_unselected_peaks() {
        let mut snapshots = Vec::new();
        for index in 0..4_001 {
            let rare = index == 1;
            let mut rows = vec![row(
                Kind::Forward,
                1,
                2,
                index + 1,
                if rare { 999.0 } else { 1.0 },
                &[(1000, 1)],
            )];
            if rare {
                rows.push(row(Kind::Input, 3, 0, 17, 22.0, &[(20_000, 17)]));
            }
            snapshots.push(snapshot(index + 1, rows));
        }
        let html = render_html(&snapshots).unwrap();
        let data = html_data(&html);
        assert!(data["snapshots"].as_array().unwrap().len() <= MAX_CHART_SNAPSHOTS as usize);
        assert_eq!(data["summary"]["paths"].as_array().unwrap().len(), 2);
        assert_eq!(data["summary"]["snapshot_count"], 4001);
        let forward = data["summary"]["paths"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["row"]["key"]["kind"] == "Forward")
            .unwrap();
        assert_eq!(forward["rate_extrema"]["pps"]["max"], 999.0);
        assert_eq!(forward["row"]["total"]["out_packets"], 4001);
        assert_eq!(
            data["snapshots"].as_array().unwrap().last().unwrap()["sequence"],
            4001
        );
        assert!(data["snapshots"][0]["rows"][0]["latency"][0]
            .get("histogram")
            .is_none());
    }

    #[test]
    fn input_summary_retains_only_stack_samples() {
        let input = row(Kind::Input, 1, 0, 3, 3.0, &[(1000, 3)]);
        let mut builder = SummaryBuilder::default();
        builder.observe(&snapshot(1, vec![input])).unwrap();
        let summary = builder.finish(vec![]).unwrap();
        for stages in [
            &summary.paths[0].row.total_latency,
            summary.kinds[0].total_latency.as_ref().unwrap(),
        ] {
            assert_eq!(stages[0].samples, 3);
            for latency in &stages[1..] {
                assert_eq!(latency.samples, 0);
                assert_eq!(latency.sum_ns, 0);
                assert!(latency.histogram.iter().all(|count| *count == 0));
                assert_eq!(latency.avg_us, None);
            }
        }
    }

    #[test]
    fn browser_fixtures_when_requested() {
        let Some(directory) = std::env::var_os("SKBTOP_REPORT_TEST_OUTPUT") else {
            return;
        };
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory).unwrap();
        let snapshots = (1..=10)
            .map(|index| {
                let mut input = row(
                    Kind::Input,
                    1,
                    0,
                    index * 3,
                    index as f64,
                    &[(1000, index * 3)],
                );
                input.key.ingress_generation = 9_007_199_254_740_993;
                input.ingress_name =
                    "</script><img src=x onerror=window.INJECTED=1>&long-interface-name".into();
                let mut rows = vec![
                    input,
                    row(
                        Kind::Output,
                        0,
                        2,
                        index * 2,
                        index as f64 * 2.0,
                        &[(3000, index * 2)],
                    ),
                    row(
                        Kind::Forward,
                        1,
                        2,
                        index * 8,
                        index as f64 * 8.0,
                        &[(2000, index * 8)],
                    ),
                    row(
                        Kind::Forward,
                        2,
                        1,
                        index * 5,
                        index as f64 * 5.0,
                        &[(4000, index * 5)],
                    ),
                    row(
                        Kind::Forward,
                        3,
                        4,
                        index * 4,
                        index as f64 * 4.0,
                        &[(6000, index * 4)],
                    ),
                ];
                if index < 4 {
                    rows.push(row(
                        Kind::Forward,
                        4,
                        3,
                        index,
                        index as f64,
                        &[(8000, index)],
                    ));
                }
                snapshot(index, rows)
            })
            .collect::<Vec<_>>();
        fs::write(
            directory.join("populated.html"),
            render_html(&snapshots).unwrap(),
        )
        .unwrap();
        fs::write(directory.join("empty.html"), render_html(&[]).unwrap()).unwrap();
        let mut huge = row(Kind::Input, 1, 0, 1, 0.0, &[(1000, 1)]);
        huge.total.out_packets = u64::MAX - 15;
        let small = row(Kind::Input, 2, 0, 9, 0.0, &[(1000, 9)]);
        fs::write(
            directory.join("large-counts.html"),
            render_html(&[snapshot(1, vec![huge, small])]).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn render_actual_recordings_when_requested() {
        let Some(inputs) = std::env::var_os("SKBTOP_REPORT_RECORDING_INPUTS") else {
            return;
        };
        let output = PathBuf::from(
            std::env::var_os("SKBTOP_REPORT_TEST_OUTPUT").expect("report output directory"),
        );
        fs::create_dir_all(&output).unwrap();
        for directory in std::env::split_paths(&inputs) {
            let mut snapshots = Vec::new();
            let mut errors = Vec::new();
            visit_recording(
                &directory.join("snapshots.jsonl"),
                true,
                |snapshot| {
                    snapshots.push(snapshot);
                    Ok(())
                },
                &mut errors,
            )
            .unwrap();
            assert!(errors.is_empty(), "actual recording errors: {errors:?}");
            let name = format!(
                "{}-current.html",
                directory.file_name().unwrap().to_string_lossy()
            );
            fs::write(output.join(name), render_html(&snapshots).unwrap()).unwrap();
        }
    }
}
