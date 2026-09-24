use std::sync::Arc;
use std::time::Duration;

use crate::collect::irq::{NetworkIrqData, NetworkIrqRow};

// Raw IRQ identity belongs to this bounded live table, not historical metric labels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HardirqSnapshot {
    pub at: Duration,
    pub data: Arc<NetworkIrqData>,
    pub previous: Option<(Duration, Arc<NetworkIrqData>)>,
    pub error: Option<String>,
}

impl HardirqSnapshot {
    pub(crate) fn next(
        previous: Option<&Self>,
        at: Duration,
        data: Result<NetworkIrqData, String>,
    ) -> Self {
        match data {
            Ok(data) => Self {
                at,
                data: Arc::new(data),
                previous: previous
                    .filter(|old| old.error.is_none() && old.at < at)
                    .map(|old| (old.at, Arc::clone(&old.data))),
                error: None,
            },
            Err(error) => Self {
                at,
                data: previous
                    .map(|old| Arc::clone(&old.data))
                    .unwrap_or_default(),
                previous: None,
                error: Some(error),
            },
        }
    }

    pub(crate) fn rates(&self, row: &NetworkIrqRow) -> Option<Vec<f64>> {
        if self.error.is_some() {
            return None;
        }
        let (before, data) = self.previous.as_ref()?;
        let elapsed = self.at.checked_sub(*before)?.as_secs_f64();
        if elapsed <= 0.0 || data.cpus != self.data.cpus {
            return None;
        }
        let old = data
            .rows
            .binary_search_by_key(&row.irq, |row| row.irq)
            .ok()
            .map(|index| &data.rows[index])?;
        if row.interfaces != old.interfaces
            || row.action != old.action
            || row.counts.len() != old.counts.len()
        {
            return None;
        }
        row.counts
            .iter()
            .zip(&old.counts)
            .map(|(value, before)| {
                value
                    .checked_sub(*before)
                    .map(|delta| delta as f64 / elapsed)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data(value: u64) -> NetworkIrqData {
        NetworkIrqData {
            cpus: vec![0, 4],
            rows: vec![NetworkIrqRow {
                irq: 40,
                interfaces: vec![("eth0".to_owned(), 2)],
                counts: vec![value, 20],
                action: "eth0-rx-0".to_owned(),
            }],
        }
    }
    #[test]
    fn rates_use_actual_time_and_never_bridge_resets_errors_or_irq_reuse() {
        let first = HardirqSnapshot::next(None, Duration::from_secs(1), Ok(data(10)));
        assert!(first.rates(&first.data.rows[0]).is_none());
        let next = HardirqSnapshot::next(Some(&first), Duration::from_millis(2250), Ok(data(35)));
        assert_eq!(next.rates(&next.data.rows[0]), Some(vec![20.0, 0.0]));
        let reset = HardirqSnapshot::next(Some(&next), Duration::from_secs(3), Ok(data(1)));
        assert!(reset.rates(&reset.data.rows[0]).is_none());
        let failed = HardirqSnapshot::next(
            Some(&next),
            Duration::from_secs(3),
            Err("permission denied".to_owned()),
        );
        assert_eq!(failed.data, next.data);
        assert!(failed.rates(&failed.data.rows[0]).is_none());
        let recovered = HardirqSnapshot::next(Some(&failed), Duration::from_secs(4), Ok(data(40)));
        assert!(recovered.rates(&recovered.data.rows[0]).is_none());
        for (index, mut changed) in [data(40), data(40)].into_iter().enumerate() {
            if index == 0 {
                changed.rows[0].interfaces[0].1 = 3;
            } else {
                changed.rows[0].action = "replacement-vector".to_owned();
            }
            let reused = HardirqSnapshot::next(Some(&next), Duration::from_secs(4), Ok(changed));
            assert!(reused.rates(&reused.data.rows[0]).is_none());
        }
        let mut changed = data(40);
        changed.cpus = vec![0, 5];
        let online = HardirqSnapshot::next(Some(&next), Duration::from_secs(4), Ok(changed));
        assert!(online.rates(&online.data.rows[0]).is_none());
    }
}
