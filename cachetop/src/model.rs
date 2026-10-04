use crate::perf::Snapshot;

#[derive(Clone, Debug, Default)]
pub struct Rates {
    pub cycles: Option<f64>,
    pub instructions: Option<f64>,
    pub llc_reads: Option<f64>,
    pub llc_misses: Option<f64>,
    pub migrations: Option<f64>,
    pub running_pct: Option<f64>,
}

impl Rates {
    pub fn ipc(&self) -> Option<f64> {
        ratio(self.instructions, self.cycles)
    }

    pub fn llc_hit_pct(&self) -> Option<f64> {
        let reads = self.llc_reads?;
        let misses = self.llc_misses?;
        (reads > 0.0 && misses <= reads).then_some(100.0 * (1.0 - misses / reads))
    }

    pub fn mpki(&self) -> Option<f64> {
        ratio(self.llc_misses, self.instructions).map(|value| value * 1000.0)
    }
}

fn ratio(numerator: Option<f64>, denominator: Option<f64>) -> Option<f64> {
    let denominator = denominator?;
    (denominator > 0.0).then_some(numerator? / denominator)
}

pub fn delta(previous: &Snapshot, current: &Snapshot, seconds: f64, llc: bool) -> Rates {
    if previous.counts.len() != current.counts.len() || seconds <= 0.0 {
        return Rates::default();
    }
    let enabled = current.enabled.saturating_sub(previous.enabled) as f64;
    let running = current.running.saturating_sub(previous.running) as f64;
    let idle = enabled == 0.0
        && running == 0.0
        && current
            .counts
            .iter()
            .zip(&previous.counts)
            .all(|(new, old)| new == old);
    let scaled = |index: usize| {
        if running > 0.0 {
            Some(
                current.counts[index].saturating_sub(previous.counts[index]) as f64 * enabled
                    / running
                    / seconds,
            )
        } else if idle {
            Some(0.0)
        } else {
            None
        }
    };
    Rates {
        cycles: scaled(0),
        instructions: scaled(1),
        llc_reads: (llc && current.counts.len() >= 4)
            .then(|| scaled(2))
            .flatten(),
        llc_misses: (llc && current.counts.len() >= 4)
            .then(|| scaled(3))
            .flatten(),
        migrations: current
            .migrations
            .zip(previous.migrations)
            .map(|(new, old)| new.saturating_sub(old) as f64 / seconds),
        running_pct: (enabled > 0.0).then_some(100.0 * running / enabled),
    }
}

#[derive(Clone, Debug)]
pub struct Row {
    pub id: u32,
    pub name: String,
    pub last_cpu: Option<i32>,
    pub rates: Rates,
}

pub fn total(rows: &[Row]) -> Rates {
    let sum = |field: fn(&Rates) -> Option<f64>| -> Option<f64> {
        rows.iter().map(|row| field(&row.rates)).sum()
    };
    Rates {
        cycles: sum(|rates| rates.cycles),
        instructions: sum(|rates| rates.instructions),
        llc_reads: sum(|rates| rates.llc_reads),
        llc_misses: sum(|rates| rates.llc_misses),
        migrations: sum(|rates| rates.migrations),
        running_pct: rows
            .iter()
            .filter_map(|row| row.rates.running_pct)
            .reduce(f64::min),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(counts: &[u64], enabled: u64, running: u64, migrations: u64) -> Snapshot {
        Snapshot {
            counts: counts.to_vec(),
            enabled,
            running,
            migrations: Some(migrations),
        }
    }

    #[test]
    fn multiplex_scales_group_and_reports_coverage() {
        let first = sample(&[10, 20, 30, 6], 10, 10, 1);
        let next = sample(&[110, 220, 130, 26], 1010, 510, 3);
        let rates = delta(&first, &next, 2.0, true);
        assert_eq!(rates.cycles, Some(100.0));
        assert_eq!(rates.instructions, Some(200.0));
        assert_eq!(rates.llc_reads, Some(100.0));
        assert_eq!(rates.llc_misses, Some(20.0));
        assert_eq!(rates.llc_hit_pct(), Some(80.0));
        assert_eq!(rates.mpki(), Some(100.0));
        assert_eq!(rates.ipc(), Some(2.0));
        assert_eq!(rates.running_pct, Some(50.0));
        assert_eq!(rates.migrations, Some(1.0));
    }

    #[test]
    fn missing_llc_and_zero_running_are_not_zero_hits() {
        let first = sample(&[0, 0], 0, 0, 0);
        let next = sample(&[0, 0], 100, 0, 0);
        let rates = delta(&first, &next, 1.0, false);
        assert_eq!(rates.cycles, None);
        assert_eq!(rates.llc_hit_pct(), None);
        assert_eq!(rates.mpki(), None);
        assert_eq!(rates.running_pct, Some(0.0));
    }

    #[test]
    fn incomplete_rows_do_not_make_a_partial_host_hit_rate() {
        let full = Row {
            id: 0,
            name: "0".into(),
            last_cpu: None,
            rates: Rates {
                cycles: Some(10.0),
                instructions: Some(10.0),
                llc_reads: Some(10.0),
                llc_misses: Some(2.0),
                ..Rates::default()
            },
        };
        let partial = Row {
            id: 1,
            name: "1".into(),
            last_cpu: None,
            rates: Rates {
                cycles: Some(10.0),
                instructions: Some(10.0),
                ..Rates::default()
            },
        };
        let sum = total(&[full, partial]);
        assert_eq!(sum.ipc(), Some(1.0));
        assert_eq!(sum.llc_hit_pct(), None);
    }

    #[test]
    fn idle_thread_contributes_zero_without_hiding_active_thread() {
        let idle = sample(&[0, 0, 0, 0], 0, 0, 0);
        let active = sample(&[100, 100, 10, 2], 100, 100, 0);
        let idle_rate = delta(&idle, &idle, 1.0, true);
        let active_rate = delta(&idle, &active, 1.0, true);
        assert_eq!(idle_rate.llc_reads, Some(0.0));
        assert_eq!(idle_rate.running_pct, None);
        let aggregate = total(&[
            Row {
                id: 1,
                name: "sleep".into(),
                last_cpu: None,
                rates: idle_rate,
            },
            Row {
                id: 2,
                name: "run".into(),
                last_cpu: None,
                rates: active_rate,
            },
        ]);
        assert_eq!(aggregate.llc_hit_pct(), Some(80.0));
        assert_eq!(aggregate.running_pct, Some(100.0));
    }
}
