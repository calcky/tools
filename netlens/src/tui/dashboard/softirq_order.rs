use std::cmp::Ordering;

use super::{
    CounterContinuity, ProjectedValue, SeriesSnapshot, SeriesValue, SoftirqProjection, TimeView,
};

pub(super) enum SortValue {
    Integer(u64),
    Rate(f64),
}

impl SortValue {
    pub(super) fn compare(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Integer(left), Self::Integer(right)) => left.cmp(&right),
            (Self::Rate(left), Self::Rate(right)) => left.total_cmp(&right),
            _ => unreachable!("a sort column has one numeric projection"),
        }
    }
}

pub(super) fn softirq_sort_value(
    series: &SeriesSnapshot,
    projection: SoftirqProjection,
    time_view: TimeView,
) -> Option<SortValue> {
    if matches!(projection, SoftirqProjection::Current) {
        return match series.value() {
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh { value, .. },
                ..
            } => Some(SortValue::Integer(*value)),
            _ => None,
        };
    }
    let SeriesValue::Counter {
        current: ProjectedValue::Fresh { .. },
        interval,
        since_baseline,
    } = series.value()
    else {
        return None;
    };
    if matches!(
        interval,
        Some(
            CounterContinuity::FirstSample
                | CounterContinuity::Reset
                | CounterContinuity::RecoveredAfterGap
        )
    ) {
        return None;
    }
    match (time_view, projection) {
        (TimeView::Interval, SoftirqProjection::Delta) => {
            super::softirq_continuity_delta(interval.as_ref()?).map(SortValue::Integer)
        }
        (TimeView::SinceBaseline, SoftirqProjection::Delta) => since_baseline
            .as_ref()
            .map(|span| SortValue::Integer(span.delta())),
        (_, SoftirqProjection::Rate) => {
            let rate = match time_view {
                TimeView::Interval => interval.as_ref()?.rate_per_second()?,
                TimeView::SinceBaseline => since_baseline.as_ref()?.rate_per_second(),
            };
            rate.is_finite().then_some(SortValue::Rate(rate))
        }
        (_, SoftirqProjection::Current) => unreachable!("gauges return above"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_keep_u64_precision_and_rates_use_raw_values() {
        assert_eq!(
            SortValue::Integer(u64::MAX).compare(SortValue::Integer(u64::MAX - 1)),
            Ordering::Greater
        );
        assert_eq!(
            SortValue::Rate(0.49).compare(SortValue::Rate(0.48)),
            Ordering::Greater
        );
        assert_eq!(
            SortValue::Rate(1.0).compare(SortValue::Rate(1.0)),
            Ordering::Equal
        );
    }
}
