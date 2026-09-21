use std::{collections::BTreeMap, fs, time::Instant};

type Result<T> = std::result::Result<T, String>;
pub const PATH: &str = "/proc/net/softnet_stat";

#[derive(Debug, Default)]
pub struct Counters {
    pub events: [u32; 5],
    pub backlog: Option<u32>,
}

pub type Snapshot = BTreeMap<u32, Counters>;

#[derive(Debug)]
pub struct Sample {
    pub at: Instant,
    pub data: Result<Snapshot>,
}

pub fn parse(text: &str, legacy_cpus: &[u32]) -> Result<Snapshot> {
    let mut result = BTreeMap::new();
    for (line, text) in text.lines().filter(|s| !s.trim().is_empty()).enumerate() {
        let fields = text.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 11 {
            return Err(format!("line {}: expected at least 11 fields", line + 1));
        }
        let number = |column: usize| {
            u32::from_str_radix(fields[column], 16)
                .map_err(|_| format!("line {}: invalid hex field {}", line + 1, column + 1))
        };
        let cpu = if fields.len() >= 13 {
            number(12)?
        } else {
            *legacy_cpus.get(line).ok_or("legacy CPU map unavailable")?
        };
        let counters = Counters {
            events: [number(0)?, number(1)?, number(2)?, number(9)?, number(10)?],
            backlog: (fields.len() >= 12).then(|| number(11)).transpose()?,
        };
        if result.insert(cpu, counters).is_some() {
            return Err(format!("duplicate CPU{cpu}"));
        }
    }
    if result.is_empty() {
        return Err("no CPU records".into());
    }
    if !legacy_cpus.is_empty() && result.len() != legacy_cpus.len() {
        return Err("legacy CPU map changed during sampling".into());
    }
    Ok(result)
}

fn cpu_list(text: &str) -> Result<Vec<u32>> {
    let mut result = Vec::new();
    for range in text.trim().split(',') {
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        let start = start
            .parse::<u32>()
            .map_err(|_| "invalid online CPU list")?;
        let end = end.parse::<u32>().map_err(|_| "invalid online CPU list")?;
        if end < start || end - start > 1_000_000 {
            return Err("invalid online CPU range".into());
        }
        result.extend(start..=end);
    }
    Ok(result)
}

pub fn read() -> Sample {
    let data = (|| {
        let text = fs::read_to_string(PATH).map_err(|e| e.to_string())?;
        let modern = text
            .lines()
            .any(|line| line.split_whitespace().count() >= 13);
        let cpus = if modern {
            Vec::new()
        } else {
            cpu_list(
                &fs::read_to_string("/sys/devices/system/cpu/online").map_err(|e| e.to_string())?,
            )?
        };
        parse(&text, &cpus)
    })();
    Sample {
        at: Instant::now(),
        data,
    }
}

#[derive(Debug, Default)]
pub struct Values {
    pub events: [u64; 5],
    pub backlog: Option<u64>,
}

#[derive(Debug)]
pub struct Cpu {
    pub id: u32,
    pub values: Values,
}

#[derive(Debug, Default)]
pub struct Report {
    pub status: Option<String>,
    pub total: Values,
    pub rows: Vec<Cpu>,
    pub elapsed: f64,
    pub delta: bool,
    pub peak: u64,
}

// These kernel counters are u32. Only a decrease across the wrap boundary is
// treated as wraparound; other decreases establish a fresh per-CPU baseline.
fn difference(old: u32, new: u32) -> Option<u32> {
    if new >= old || (old >= 0xf000_0000 && new <= 0x0fff_ffff) {
        Some(new.wrapping_sub(old))
    } else {
        None
    }
}

impl Report {
    pub fn new(old: Option<&Sample>, new: Option<&Sample>, delta: bool) -> Self {
        let mut report = Self {
            delta,
            ..Self::default()
        };
        let Some(new) = new else {
            report.status = Some("sampling...".into());
            return report;
        };
        let current = match &new.data {
            Ok(data) => data,
            Err(error) => {
                report.status = Some(format!("unavailable: {error}"));
                return report;
            }
        };
        let previous = old.and_then(|sample| sample.data.as_ref().ok());
        report.elapsed = old.map_or(0.0, |s| {
            new.at.saturating_duration_since(s.at).as_secs_f64()
        });
        if previous.is_none() || report.elapsed <= 0.0 {
            report.status = Some("sampling...".into());
            return report;
        }
        let previous = previous.unwrap();
        report.total.backlog = Some(0);
        for (&id, counters) in current {
            let mut events = [0_u64; 5];
            if let Some(old) = previous.get(&id) {
                let deltas: [Option<u32>; 5] =
                    std::array::from_fn(|i| difference(old.events[i], counters.events[i]));
                if deltas.iter().all(Option::is_some) {
                    events = deltas.map(|n| u64::from(n.unwrap()));
                }
            }
            for (total, event) in report.total.events.iter_mut().zip(events) {
                *total += event;
            }
            let backlog = counters.backlog.map(u64::from);
            report.total.backlog = report.total.backlog.zip(backlog).map(|(a, b)| a + b);
            report.peak = report.peak.max(events[0]);
            if events.iter().any(|n| *n != 0) || backlog.is_some_and(|n| n != 0) {
                report.rows.push(Cpu {
                    id,
                    values: Values { events, backlog },
                });
            }
        }
        // Put CPUs with drops first, then budget exhaustion; keep numeric order
        // within each group so ordinary activity does not constantly reorder rows.
        report.rows.sort_by_key(|cpu| {
            (
                !(cpu.values.events[1] > 0 || cpu.values.events[4] > 0),
                cpu.values.events[2] == 0,
                cpu.id,
            )
        });
        report
    }

    pub fn value(&self, count: u64) -> String {
        if self.delta {
            count.to_string()
        } else {
            format!("{:.2}", count as f64 / self.elapsed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn record(cpu: u32, processed: u32, dropped: u32, backlog: u32) -> String {
        format!(
            "{processed:08x} {dropped:08x} 00000000 0 0 0 0 0 0 0 0 {backlog:08x} {cpu:08x} 0 0\n"
        )
    }

    #[test]
    fn modern_ids_legacy_mapping_and_validation() {
        let data = parse(&(record(4, 100, 0, 2) + &record(28, 200, 1, 3)), &[]).unwrap();
        assert_eq!(data.keys().copied().collect::<Vec<_>>(), [4, 28]);
        assert_eq!(data[&28].events, [200, 1, 0, 0, 0]);
        let legacy = "ff 1 2 0 0 0 0 0 99 3 4\n";
        let cpus = cpu_list("2,4-5").unwrap();
        assert_eq!(cpus, [2, 4, 5]);
        assert_eq!(parse(legacy, &[28]).unwrap()[&28].events, [255, 1, 2, 3, 4]);
        assert!(parse(legacy, &[28]).unwrap()[&28].backlog.is_none());
        assert!(parse(legacy, &cpus).is_err());
        assert!(parse(legacy, &[]).is_err());
        for text in [
            "",
            "0 0 0",
            "xx 0 0 0 0 0 0 0 0 0 0 0 1",
            "100000000 0 0 0 0 0 0 0 0 0 0 0 1",
        ] {
            assert!(parse(text, &[]).is_err());
        }
        assert!(parse(&(record(1, 0, 0, 0) + &record(1, 0, 0, 0)), &[]).is_err());
    }

    #[test]
    fn rates_totals_gauges_hotplug_wrap_and_reset() {
        let at = Instant::now();
        let old = Sample {
            at,
            data: parse(
                &(record(28, u32::MAX - 9, 2, 100)
                    + &record(40, 100, 0, 0)
                    + &record(50, 999, 0, 0)),
                &[],
            ),
        };
        let new = Sample {
            at: at + Duration::from_secs(2),
            data: parse(
                &(record(28, 10, 3, 2) + &record(40, 5, 0, 0) + &record(60, 10000, 0, 8)),
                &[],
            ),
        };
        let report = Report::new(Some(&old), Some(&new), false);
        assert_eq!(report.total.events, [20, 1, 0, 0, 0]);
        assert_eq!(report.total.backlog, Some(10));
        assert_eq!(report.value(20), "10.00");
        assert_eq!(report.value(1), "0.50");
        assert_eq!(
            report.rows.iter().map(|r| r.id).collect::<Vec<_>>(),
            [28, 60]
        );
        assert_eq!(Report::new(Some(&old), Some(&new), true).value(20), "20");
        assert_eq!(report.peak, 20);
    }

    #[test]
    fn baseline_errors_and_recovery_never_show_boot_counts() {
        let at = Instant::now();
        let good = Sample {
            at,
            data: parse(&record(0, 9999, 100, 2), &[]),
        };
        let bad = Sample {
            at,
            data: Err("permission denied".into()),
        };
        assert_eq!(
            Report::new(None, Some(&good), false).status.as_deref(),
            Some("sampling...")
        );
        assert!(Report::new(Some(&good), Some(&bad), false)
            .status
            .unwrap()
            .contains("permission denied"));
        let recovered = Sample {
            at: at + Duration::from_secs(1),
            data: parse(&record(0, 10000, 100, 1), &[]),
        };
        assert!(Report::new(Some(&bad), Some(&recovered), false)
            .rows
            .is_empty());
    }
}
