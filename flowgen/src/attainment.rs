use crate::{html_report, stats::Stats};
use serde_json::Value;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

const SECOND: u64 = 1_000_000_000;
const MAX_GAP: u64 = SECOND / 2;

pub(crate) struct Recorder {
    out: csv::Writer<BufWriter<File>>,
    run: u64,
    target: u64,
}

impl Recorder {
    pub(crate) fn create(dir: &Path, run: u64, target: u64) -> io::Result<Self> {
        let file = File::options()
            .create_new(true)
            .write(true)
            .open(dir.join("readiness-samples.csv"))?;
        let mut out = csv::Writer::from_writer(BufWriter::new(file));
        out.write_record(["run", "time_ns", "ready", "deficit"])?;
        Ok(Self { out, run, target })
    }

    pub(crate) fn sample(&mut self, time: u64, stats: &Stats) -> io::Result<()> {
        let ready = stats.ready.load(Relaxed);
        self.out.write_record([
            self.run.to_string(),
            time.to_string(),
            ready.to_string(),
            self.target.saturating_sub(ready).to_string(),
        ])?;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Load {
    pub run: u64,
    pub tcp: bool,
    pub start: u64,
    pub end: u64,
}

impl Load {
    pub(crate) fn from_metadata(meta: &Value) -> Option<Self> {
        let start = integer(meta, "load_start_ns")?;
        let end = integer(meta, "drain_start_ns")?;
        (end > start).then_some(Self {
            run: integer(meta, "run")?,
            tcp: meta["protocol"] == "tcp",
            start,
            end,
        })
    }

    pub(crate) fn contains(&self, run: u64, tcp: bool, time: u64) -> bool {
        run == self.run && tcp == self.tcp && time >= self.start && time < self.end
    }
}

fn integer(meta: &Value, key: &str) -> Option<u64> {
    meta[key].as_str()?.parse().ok()
}

fn number(meta: &Value, key: &str) -> Option<f64> {
    meta[key]
        .as_str()?
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
}

#[derive(Default)]
struct Gauge {
    covered: u64,
    weighted: u128,
    min: Option<u64>,
    max_deficit: u64,
}

impl Gauge {
    fn add(&mut self, duration: u64, ready: u64, target: u64) {
        if duration == 0 {
            return;
        }
        self.covered += duration;
        self.weighted += duration as u128 * ready as u128;
        self.min = Some(self.min.map_or(ready, |old| old.min(ready)));
        self.max_deficit = self.max_deficit.max(target.saturating_sub(ready));
    }

    fn avg(&self) -> Option<f64> {
        (self.covered > 0).then(|| self.weighted as f64 / self.covered as f64)
    }
}

fn field(value: Option<f64>) -> String {
    value.map_or_else(|| "NA".into(), |v| v.to_string())
}

// Sampling gaps over 500 ms are unknown, not a held Ready value. Integrate
// shorter intervals using the left sample and expose their temporal coverage.
fn readiness(
    dir: &Path,
    meta: &Value,
    load: Option<Load>,
    out: &mut csv::Writer<File>,
) -> io::Result<(Gauge, bool)> {
    let Some(run) = integer(meta, "run") else {
        return Ok((Gauge::default(), false));
    };
    let target = integer(meta, "sessions").unwrap_or(0);
    let end = integer(meta, "end_ns").unwrap_or(0);
    let width = end.div_ceil(SECOND).div_ceil(3600).max(1) * SECOND;
    let mut buckets: Vec<Gauge> = (0..end.div_ceil(width).min(3600))
        .map(|_| Gauge::default())
        .collect();
    let mut input = match csv::Reader::from_path(dir.join("readiness-samples.csv")) {
        Ok(input) => input,
        Err(e) if matches!(e.kind(), csv::ErrorKind::Io(error) if error.kind() == io::ErrorKind::NotFound) =>
        {
            return Ok((Gauge::default(), false));
        }
        Err(e) => return Err(e.into()),
    };
    if !input
        .headers()
        .is_ok_and(|headers| headers.iter().eq(["run", "time_ns", "ready", "deficit"]))
    {
        return Ok((Gauge::default(), false));
    }
    let mut previous: Option<(u64, u64)> = None;
    let mut total = Gauge::default();
    let mut valid = true;
    for row in input.records() {
        let row = match row {
            Ok(row) => row,
            Err(_) => {
                valid = false;
                break;
            }
        };
        let values: Option<Vec<u64>> = row.iter().map(|v| v.parse().ok()).collect();
        let Some(values) = values else {
            valid = false;
            break;
        };
        let (id, time, ready, deficit) = (values[0], values[1], values[2], values[3]);
        if id != run || time > end || deficit != target.saturating_sub(ready) {
            valid = false;
            break;
        }
        if let Some((start, old_ready)) = previous {
            if time <= start {
                valid = false;
                break;
            }
            if time - start <= MAX_GAP {
                if let Some(load) = load {
                    total.add(
                        time.min(load.end).saturating_sub(start.max(load.start)),
                        old_ready,
                        target,
                    );
                }
                let mut position = start;
                while position < time {
                    let index = (position / width) as usize;
                    let next = time.min((index as u64 + 1).saturating_mul(width));
                    if let Some(bucket) = buckets.get_mut(index) {
                        bucket.add(next - position, old_ready, target);
                    }
                    position = next;
                }
            }
        }
        previous = Some((time, ready));
    }
    if !valid {
        return Ok((Gauge::default(), false));
    }
    for (i, bucket) in buckets.iter().enumerate() {
        let start = i as u64 * width;
        let finish = end.min(start.saturating_add(width));
        out.write_record([
            run.to_string(),
            meta["protocol"].as_str().unwrap_or("NA").into(),
            "client".into(),
            field(Some(start as f64 / SECOND as f64)),
            field(Some(finish as f64 / SECOND as f64)),
            field(bucket.avg()),
            field(bucket.avg().map(|v| (target as f64 - v).max(0.0))),
            field(Some(
                100.0 * bucket.covered as f64 / (finish - start) as f64,
            )),
        ])?;
    }
    Ok((total, true))
}

pub(crate) fn write(dir: &Path, scratch: &Path, sent: Option<u64>) -> io::Result<()> {
    let meta = html_report::metadata(dir)?;
    let mut incomplete = meta["complete"] == "false";
    if scratch.join("summary.csv").is_file() {
        let mut summary = csv::Reader::from_path(scratch.join("summary.csv"))?;
        let headers = summary.headers()?.clone();
        for row in summary.records() {
            let row = row?;
            let value = |name: &str| {
                headers
                    .iter()
                    .position(|key| key == name)
                    .and_then(|i| row.get(i))
            };
            if value("run") == meta["run"].as_str()
                && value("protocol") == meta["protocol"].as_str()
                && value("role") == Some("client")
            {
                incomplete |= value("incomplete") == Some("true");
            }
        }
    }
    let load = Load::from_metadata(&meta);
    let seconds = load.map(|l| (l.end - l.start) as f64 / SECOND as f64);
    let target = integer(&meta, "sessions").map(|v| v as f64);
    let mut samples = csv::Writer::from_path(scratch.join("readiness.csv"))?;
    samples.write_record([
        "run",
        "protocol",
        "role",
        "start_s",
        "end_s",
        "ready_sessions",
        "deficit_sessions",
        "coverage_pct",
    ])?;
    let (gauge, valid) = readiness(dir, &meta, load, &mut samples)?;
    samples.flush()?;
    let coverage = seconds.map(|v| 100.0 * gauge.covered as f64 / SECOND as f64 / v);
    let sample_status = if !valid {
        "unavailable"
    } else if load.is_none() {
        "no_load"
    } else if load.is_some_and(|l| gauge.covered == l.end - l.start) {
        "sampled"
    } else {
        "partial"
    };
    let mut out = csv::Writer::from_path(scratch.join("attainment.csv"))?;
    out.write_record([
        "run",
        "protocol",
        "role",
        "load_s",
        "metric",
        "target",
        "actual",
        "attainment_pct",
        "status",
        "coverage_pct",
        "ready_min",
        "max_deficit",
        "load_sent",
        "recording_status",
    ])?;
    let ready = gauge.avg();
    let pps = sent.zip(seconds).map(|(n, d)| n as f64 / d);
    let turnover = integer(&meta, "load_rotations")
        .zip(seconds)
        .map(|(n, d)| n as f64 / d);
    for (metric, goal, actual, status) in [
        ("ready", target, ready, sample_status),
        (
            "request_pps",
            target
                .zip(number(&meta, "pps_per_session"))
                .map(|(a, b)| a * b),
            pps,
            if pps.is_some() {
                "observed"
            } else {
                "unavailable"
            },
        ),
        (
            "turnover",
            number(&meta, "turnover"),
            turnover,
            if turnover.is_some() {
                "initiated"
            } else {
                "unavailable"
            },
        ),
    ] {
        out.write_record([
            meta["run"].as_str().unwrap_or("NA").into(),
            meta["protocol"].as_str().unwrap_or("NA").into(),
            "client".into(),
            field(seconds),
            metric.into(),
            field(goal),
            field(actual),
            field(
                actual
                    .zip(goal)
                    .filter(|(_, g)| *g > 0.0 && !incomplete)
                    .map(|(a, g)| 100.0 * a / g),
            ),
            status.into(),
            if metric == "ready" && valid {
                field(coverage)
            } else {
                "NA".into()
            },
            if metric == "ready" {
                gauge.min.map_or_else(|| "NA".into(), |v| v.to_string())
            } else {
                "NA".into()
            },
            if metric == "ready" && ready.is_some() {
                gauge.max_deficit.to_string()
            } else {
                "NA".into()
            },
            if metric == "request_pps" {
                sent.map_or_else(|| "NA".into(), |v| v.to_string())
            } else {
                "NA".into()
            },
            if incomplete {
                "INCOMPLETE".into()
            } else {
                "COMPLETE".into()
            },
        ])?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "flowgen-attainment-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Relaxed)
            ));
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("run.txt"), "run 7\nprotocol udp\nsessions 100\npps_per_session 2\nturnover 10\nload_start_ns 200000000\ndrain_start_ns 600000000\nend_ns 800000000\nload_rotations 4\ncomplete true\n").unwrap();
            Self(dir)
        }

        fn samples(&self, samples: &[(u64, u64)]) {
            let mut recorder = Recorder::create(&self.0, 7, 100).unwrap();
            let stats = Stats::default();
            for &(time, ready) in samples {
                stats.ready.store(ready, Relaxed);
                recorder.sample(time, &stats).unwrap();
            }
            recorder.finish().unwrap();
        }

        fn rows(&self, name: &str) -> Vec<HashMap<String, String>> {
            let mut reader = csv::Reader::from_path(self.0.join(name)).unwrap();
            let headers = reader.headers().unwrap().clone();
            reader
                .records()
                .map(|row| {
                    headers
                        .iter()
                        .zip(row.unwrap().iter())
                        .map(|(k, v)| (k.into(), v.into()))
                        .collect()
                })
                .collect()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn exact_load_window_excludes_warmup_drain_and_other_groups() {
        let meta =
            json!({"run":"7", "protocol":"tcp", "load_start_ns":"10", "drain_start_ns":"20"});
        let load = Load::from_metadata(&meta).unwrap();
        assert!(!load.contains(7, true, 9));
        assert!(load.contains(7, true, 10));
        assert!(load.contains(7, true, 19));
        assert!(!load.contains(7, true, 20));
        assert!(!load.contains(8, true, 15));
        assert!(!load.contains(7, false, 15));
        assert!(
            Load::from_metadata(&json!({"load_start_ns":"20", "drain_start_ns":"10"})).is_none()
        );
    }

    #[test]
    fn readiness_is_time_weighted_and_does_not_include_drain() {
        let f = Fixture::new();
        f.samples(&[
            (0, 0),
            (200_000_000, 100),
            (300_000_000, 80),
            (400_000_000, 90),
            (600_000_000, 0),
            (800_000_000, 0),
        ]);
        write(&f.0, &f.0, Some(39)).unwrap();
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[0]["actual"], "90");
        assert_eq!(rows[0]["ready_min"], "80");
        assert_eq!(rows[0]["max_deficit"], "20");
        assert_eq!(rows[0]["coverage_pct"], "100");
        assert_eq!(rows[0]["status"], "sampled");
        assert_eq!(rows[1]["actual"], "97.5");
        assert_eq!(rows[1]["target"], "200");
        assert_eq!(rows[2]["actual"], "10");
        assert_eq!(rows[2]["status"], "initiated");
    }

    #[test]
    fn legacy_and_summary_do_not_invent_ready_or_exact_send_counts() {
        let f = Fixture::new();
        write(&f.0, &f.0, Some(40)).unwrap();
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[0]["actual"], "NA");
        assert_eq!(rows[0]["status"], "unavailable");
        assert_eq!(rows[1]["actual"], "100");
        assert!(f.rows("readiness.csv").is_empty());
        f.samples(&[(0, 100), (400_000_000, 100), (800_000_000, 0)]);
        write(&f.0, &f.0, None).unwrap();
        assert_eq!(f.rows("attainment.csv")[1]["actual"], "NA");
    }

    #[test]
    fn missing_intervals_are_partial_not_zero_or_held_ready() {
        let f = Fixture::new();
        fs::write(f.0.join("run.txt"), "run 7\nprotocol udp\nsessions 100\nload_start_ns 0\ndrain_start_ns 1000000000\nend_ns 1000000000\n").unwrap();
        f.samples(&[
            (0, 100),
            (100_000_000, 100),
            (800_000_000, 80),
            (900_000_000, 90),
            (SECOND, 0),
        ]);
        write(&f.0, &f.0, None).unwrap();
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[0]["actual"], "90");
        assert_eq!(rows[0]["coverage_pct"], "30");
        assert_eq!(rows[0]["status"], "partial");
        assert_eq!(f.rows("readiness.csv")[0]["coverage_pct"], "30");
    }

    #[test]
    fn invalid_samples_cannot_leak_a_partial_gauge_as_valid() {
        for text in [
            "run,time_ns,ready,deficit\n8,0,100,0\n7,100,100,0\n",
            "run,time_ns,ready,deficit\n7,0,100,1\n7,100,100,0\n",
            "run,time_ns,ready,deficit\n7,100,100,0\n7,0,100,0\n",
            "run,time_ns,ready,deficit\n7,0,100,0\n7,900000000,100,0\n",
            "run,time_ns,ready,deficit\n7,0,100,0\n7,100,100\n",
        ] {
            let f = Fixture::new();
            fs::write(f.0.join("readiness-samples.csv"), text).unwrap();
            write(&f.0, &f.0, None).unwrap();
            assert_eq!(f.rows("attainment.csv")[0]["actual"], "NA");
            assert!(f.rows("readiness.csv").is_empty());
        }
    }

    #[test]
    fn interrupted_runs_and_missing_load_do_not_certify_attainment() {
        let f = Fixture::new();
        let text = fs::read_to_string(f.0.join("run.txt")).unwrap();
        fs::write(
            f.0.join("run.txt"),
            text.replace("complete true", "complete false"),
        )
        .unwrap();
        write(&f.0, &f.0, Some(80)).unwrap();
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[1]["attainment_pct"], "NA");
        assert_eq!(rows[1]["recording_status"], "INCOMPLETE");
        fs::write(
            f.0.join("run.txt"),
            "run 7\nprotocol udp\nsessions 100\nend_ns 800000000\n",
        )
        .unwrap();
        f.samples(&[(0, 0), (400_000_000, 80), (800_000_000, 0)]);
        write(&f.0, &f.0, Some(80)).unwrap();
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[0]["status"], "no_load");
        assert_eq!(rows[1]["actual"], "NA");
    }

    #[test]
    fn bounded_chart_buckets_and_zero_turnover_target() {
        let f = Fixture::new();
        fs::write(f.0.join("run.txt"), "run 7\nprotocol udp\nsessions 100\nload_start_ns 0\ndrain_start_ns 7200000000000\nend_ns 7200000000000\nturnover 0\nload_rotations 0\n").unwrap();
        f.samples(&[(0, 100), (100_000_000, 100)]);
        write(&f.0, &f.0, Some(0)).unwrap();
        assert_eq!(f.rows("readiness.csv").len(), 3600);
        let rows = f.rows("attainment.csv");
        assert_eq!(rows[2]["actual"], "0");
        assert_eq!(rows[2]["attainment_pct"], "NA");
    }

    #[test]
    fn small_positive_values_keep_csv_precision_and_extreme_metadata_is_bounded() {
        assert_eq!(field(Some(1e-10)).parse::<f64>().unwrap(), 1e-10);
        let f = Fixture::new();
        fs::write(f.0.join("run.txt"), format!("run 7\nprotocol udp\nsessions 100\nload_start_ns 0\ndrain_start_ns {}\nend_ns {}\n", u64::MAX, u64::MAX)).unwrap();
        f.samples(&[(0, 100), (100_000_000, 100)]);
        write(&f.0, &f.0, None).unwrap();
        assert!(f.rows("readiness.csv").len() <= 3600);
    }
}
