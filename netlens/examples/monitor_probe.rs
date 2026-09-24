//! Bounded sampling probe for performance and cadence checks on a target host.
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use netlens::collect::SystemPaths;
use netlens::monitor::{
    CollectionSection, MetricLabel, MonitorPlan, MonitorSection, MonitorSession, SamplingInterval,
};

fn main() -> anyhow::Result<()> {
    let section: MonitorSection = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "overview".into())
        .parse()?;
    let seconds: u64 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "65".into())
        .parse()?;
    anyhow::ensure!(
        (6..=3600).contains(&seconds),
        "duration must be 6..=3600 seconds"
    );
    let plan = MonitorPlan::from_parts(
        SamplingInterval::default(),
        section,
        CollectionSection::ALL,
        None,
    )?;
    let session = MonitorSession::start(plan, SystemPaths::default())?;
    let start = Instant::now();
    let mut sequence = 0;
    let mut previous = None;
    let mut first = None;
    let mut intervals = Vec::new();
    let mut missed_start = 0;
    let mut reported = false;
    while start.elapsed() < Duration::from_secs(seconds + 10) {
        let Some(snapshot) = session.wait_after(sequence, Duration::from_secs(2))? else {
            continue;
        };
        sequence = snapshot.sequence();
        if start.elapsed() < Duration::from_secs(5) {
            continue;
        }
        let at = snapshot.elapsed().as_secs_f64();
        if first.is_none() {
            first = Some(at);
            missed_start = snapshot.telemetry().provider_missed_samples;
        }
        if let Some(previous) = previous {
            intervals.push(at - previous);
        }
        previous = Some(at);
        if start.elapsed() >= Duration::from_secs(seconds) {
            netlens::monitor::MonitorSnapshot::new(
                snapshot.generation(),
                snapshot.sequence(),
                snapshot.started_at_unix_ms(),
                snapshot.elapsed(),
                snapshot.network_namespace().map(str::to_owned),
                snapshot.providers().to_vec(),
                snapshot.series().to_vec(),
                snapshot.telemetry(),
            )?;
            let interfaces: BTreeSet<_> = snapshot
                .series()
                .iter()
                .filter_map(|row| row.labels().get(MetricLabel::Interface))
                .collect();
            println!("section={section} interval=1s samples={} series={} interfaces={} elapsed={:.3}s mean={:.3}s min={:.3}s max={:.3}s steady_missed={} rejected={} skipped={}",
                intervals.len() + 1, snapshot.series().len(), interfaces.len(), at - first.unwrap(),
                intervals.iter().sum::<f64>() / intervals.len().max(1) as f64,
                intervals.iter().copied().reduce(f64::min).unwrap_or(0.0),
                intervals.iter().copied().reduce(f64::max).unwrap_or(0.0),
                snapshot.telemetry().provider_missed_samples - missed_start,
                snapshot.telemetry().rejected_series, snapshot.telemetry().skipped_snapshots);
            reported = true;
            break;
        }
    }
    anyhow::ensure!(
        reported,
        "no final snapshot within the ten-second grace period"
    );
    session.shutdown()
}
