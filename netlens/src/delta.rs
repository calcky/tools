use std::collections::{BTreeMap, BTreeSet};

use crate::model::{MetricKey, MetricSample, RawMetricDelta};

pub fn calculate(start: Vec<MetricSample>, end: Vec<MetricSample>) -> Vec<RawMetricDelta> {
    let start = into_map(start);
    let end = into_map(end);
    let keys: BTreeSet<_> = start.keys().chain(end.keys()).cloned().collect();

    keys.into_iter()
        .map(|key| {
            let start_value = start.get(&key).copied();
            let end_value = end.get(&key).copied();
            let (delta, reset) = match (start_value, end_value) {
                (Some(before), Some(after)) if after >= before => (Some(after - before), false),
                (Some(_), Some(_)) => (None, true),
                _ => (None, false),
            };

            RawMetricDelta {
                key,
                start: start_value,
                end: end_value,
                delta,
                reset,
            }
        })
        .collect()
}

fn into_map(samples: Vec<MetricSample>) -> BTreeMap<MetricKey, u64> {
    samples
        .into_iter()
        .map(|sample| (sample.key, sample.value))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, value: u64) -> MetricSample {
        MetricSample {
            key: MetricKey::new("test", "group", name),
            value,
        }
    }

    #[test]
    fn calculates_increase_and_unchanged_values() {
        let deltas = calculate(
            vec![sample("drops", 10), sample("errors", 4)],
            vec![sample("drops", 13), sample("errors", 4)],
        );

        assert_eq!(deltas[0].delta, Some(3));
        assert_eq!(deltas[1].delta, Some(0));
        assert!(!deltas[0].reset);
    }

    #[test]
    fn marks_decreasing_counter_as_reset() {
        let deltas = calculate(vec![sample("drops", 10)], vec![sample("drops", 2)]);

        assert_eq!(deltas[0].delta, None);
        assert!(deltas[0].reset);
    }

    #[test]
    fn does_not_invent_delta_for_appearing_or_disappearing_counter() {
        let deltas = calculate(vec![sample("gone", 10)], vec![sample("new", 2)]);

        assert!(deltas.iter().all(|delta| delta.delta.is_none()));
        assert!(deltas.iter().all(|delta| !delta.reset));
    }
}
