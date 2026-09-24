use std::collections::{HashMap, VecDeque};
use std::mem;
use std::time::Duration;

use super::{
    HistoryBucket, HistoryCoverage, MonitorValidationError, SeriesId, MAX_ADMITTED_SERIES,
    MAX_HISTORY_BUCKETS_PER_SERIES,
};

impl HistoryBucket {
    fn observed(observation: HistoryObservation) -> Self {
        let HistoryObservation {
            start,
            end,
            value,
            delta,
            trend_elapsed,
            reset,
        } = observation;
        Self {
            start,
            end,
            min: value,
            max: value,
            first: value,
            last: value,
            sum: u128::from(value),
            count: 1,
            delta,
            trend_delta: delta,
            trend_elapsed,
            resets: u64::from(reset),
            gaps: 0,
        }
    }

    fn gap(at: Duration) -> Self {
        Self {
            start: at,
            end: at,
            min: 0,
            max: 0,
            first: 0,
            last: 0,
            sum: 0,
            count: 0,
            delta: 0,
            trend_delta: 0,
            trend_elapsed: Duration::ZERO,
            resets: 0,
            gaps: 1,
        }
    }

    fn merge(self, newer: Self) -> Self {
        let (min, max, first, last) = match (self.count, newer.count) {
            (0, 0) => (0, 0, 0, 0),
            (0, _) => (newer.min, newer.max, newer.first, newer.last),
            (_, 0) => (self.min, self.max, self.first, self.last),
            (_, _) => (
                self.min.min(newer.min),
                self.max.max(newer.max),
                self.first,
                newer.last,
            ),
        };
        let (trend_delta, trend_elapsed) = peak_interval(self, newer);
        Self {
            start: self.start,
            end: newer.end,
            min,
            max,
            first,
            last,
            sum: self.sum.saturating_add(newer.sum),
            count: self.count.saturating_add(newer.count),
            delta: self.delta.saturating_add(newer.delta),
            trend_delta,
            trend_elapsed,
            resets: self.resets.saturating_add(newer.resets),
            gaps: self.gaps.saturating_add(newer.gaps),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct HistoryObservation {
    start: Duration,
    end: Duration,
    value: u64,
    delta: u64,
    trend_elapsed: Duration,
    reset: bool,
}

impl HistoryObservation {
    pub(super) const fn new(
        start: Duration,
        end: Duration,
        value: u64,
        delta: u64,
        trend_elapsed: Duration,
        reset: bool,
    ) -> Self {
        Self {
            start,
            end,
            value,
            delta,
            trend_elapsed,
            reset,
        }
    }
}

fn peak_interval(left: HistoryBucket, right: HistoryBucket) -> (u64, Duration) {
    match (left.trend_rate_per_second(), right.trend_rate_per_second()) {
        (Some(left_rate), Some(right_rate)) if left_rate >= right_rate => {
            (left.trend_delta, left.trend_elapsed)
        }
        (Some(_), Some(_)) | (None, Some(_)) => (right.trend_delta, right.trend_elapsed),
        (Some(_), None) => (left.trend_delta, left.trend_elapsed),
        (None, None) => (0, Duration::ZERO),
    }
}

#[derive(Clone, Debug)]
pub struct HistoryStore {
    base_resolution: Duration,
    max_buckets_per_series: usize,
    series: Vec<Option<SeriesHistory>>,
    sparse_series: HashMap<SeriesId, SeriesHistory>,
    series_count: usize,
}

#[derive(Clone, Debug, Default)]
struct SeriesHistory {
    points: VecDeque<HistoryBucket>,
    compacted: bool,
    resolution: Duration,
    gaps: u64,
    validation_error: Option<MonitorValidationError>,
}

impl SeriesHistory {
    fn new(limit: usize) -> Self {
        Self {
            points: VecDeque::with_capacity(limit.min(MAX_HISTORY_BUCKETS_PER_SERIES)),
            ..Self::default()
        }
    }
}

type HistorySlices<'a> = (&'a [HistoryBucket], &'a [HistoryBucket]);

pub(super) struct HistoryProjection<'a> {
    coverage: HistoryCoverage,
    slices: HistorySlices<'a>,
    validation_error: Option<MonitorValidationError>,
}

impl<'a> HistoryProjection<'a> {
    pub(super) fn coverage(&self) -> HistoryCoverage {
        self.coverage
    }

    pub(super) fn validated_parts(
        self,
    ) -> Result<(HistoryCoverage, HistorySlices<'a>), MonitorValidationError> {
        if let Some(error) = self.validation_error {
            return Err(error);
        }
        Ok((self.coverage, self.slices))
    }
}

impl HistoryStore {
    pub fn new(base_resolution: Duration) -> Self {
        Self::with_bucket_limit(base_resolution, MAX_HISTORY_BUCKETS_PER_SERIES)
    }

    pub(super) fn with_bucket_limit(
        base_resolution: Duration,
        max_buckets_per_series: usize,
    ) -> Self {
        assert!(
            max_buckets_per_series >= 2,
            "history needs at least two buckets per series"
        );
        Self {
            base_resolution,
            max_buckets_per_series,
            series: Vec::new(),
            sparse_series: HashMap::new(),
            series_count: 0,
        }
    }

    pub(super) fn record(&mut self, series: SeriesId, observation: HistoryObservation) {
        self.push(series, HistoryBucket::observed(observation));
    }

    pub fn record_gap(&mut self, series: SeriesId, at: Duration) {
        self.push(series, HistoryBucket::gap(at));
    }

    pub fn points(&self, series: SeriesId) -> impl Iterator<Item = &HistoryBucket> {
        self.get(series)
            .into_iter()
            .flat_map(|history| &history.points)
    }

    pub fn buckets(&self, series: SeriesId) -> Vec<HistoryBucket> {
        self.get(series)
            .map(|history| history.points.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn coverage(&self, series: SeriesId) -> Result<HistoryCoverage, MonitorValidationError> {
        self.projection(series)
            .map(|projection| projection.coverage)
    }

    pub(super) fn projection(
        &self,
        series: SeriesId,
    ) -> Result<HistoryProjection<'_>, MonitorValidationError> {
        let Some(history) = self.get(series) else {
            return Ok(HistoryProjection {
                coverage: HistoryCoverage::empty(),
                slices: (&[], &[]),
                validation_error: None,
            });
        };
        let points = &history.points;
        let Some(first) = points.front() else {
            return Ok(HistoryProjection {
                coverage: HistoryCoverage::empty(),
                slices: (&[], &[]),
                validation_error: None,
            });
        };
        let last = points.back().expect("non-empty history has a final bucket");
        let coverage = HistoryCoverage::new(
            first.start,
            last.end,
            self.base_resolution.max(history.resolution),
            points.len() as u64,
            history.gaps,
            history.compacted,
        )?;
        Ok(HistoryProjection {
            coverage,
            slices: points.as_slices(),
            validation_error: history.validation_error.clone(),
        })
    }

    pub fn bucket_count(&self) -> u64 {
        self.series
            .iter()
            .filter_map(Option::as_ref)
            .chain(self.sparse_series.values())
            .map(|history| history.points.len() as u64)
            .sum()
    }

    pub fn estimated_bytes(&self) -> u64 {
        self.bucket_count()
            .saturating_mul(mem::size_of::<HistoryBucket>() as u64)
    }

    fn push(&mut self, series: SeriesId, point: HistoryBucket) {
        let is_new = self.get(series).is_none();
        if is_new && self.series_count == MAX_ADMITTED_SERIES {
            return;
        }
        self.series_count += usize::from(is_new);
        // Monitor IDs are dense and bounded. Public callers may also use sparse
        // IDs; those retain map storage without allocating up to their numeric ID.
        let history = if series.get() <= MAX_ADMITTED_SERIES as u64 {
            let index = series.get() as usize - 1;
            if self.series.len() <= index {
                self.series.resize_with(index + 1, || None);
            }
            self.series[index]
                .get_or_insert_with(|| SeriesHistory::new(self.max_buckets_per_series))
        } else {
            self.sparse_series
                .entry(series)
                .or_insert_with(|| SeriesHistory::new(self.max_buckets_per_series))
        };
        history.resolution = history
            .resolution
            .max(point.end.saturating_sub(point.start));
        history.gaps = history.gaps.saturating_add(point.gaps);
        let points = &mut history.points;
        let previously_invalid = history.validation_error.is_some();
        let mut validation_error = point.validate().err();
        if points.back().is_some_and(|last| last.end > point.start) {
            validation_error = Some(MonitorValidationError::InvalidHistoryBucket);
        }
        // Make room before appending: a full bounded ring must not double its
        // allocation merely to hold the soon-to-be-compacted extra bucket.
        if points.len() == self.max_buckets_per_series {
            let oldest = points.pop_front().expect("history reached its capacity");
            let next = points.pop_front().expect("history has a second bucket");
            let merged = oldest.merge(next);
            validation_error = validation_error.or_else(|| merged.validate().err());
            history.resolution = history
                .resolution
                .max(merged.end.saturating_sub(merged.start));
            points.push_front(merged);
            history.compacted = true;
        }
        points.push_back(point);
        // Unchanged buckets and boundaries retain their previous validation.
        // Recheck everything after an invalid update: compaction may remove it.
        history.validation_error = if previously_invalid {
            let mut previous_end = None;
            points
                .iter()
                .try_for_each(|bucket| {
                    bucket.validate()?;
                    if previous_end.is_some_and(|end| end > bucket.start) {
                        return Err(MonitorValidationError::InvalidHistoryBucket);
                    }
                    previous_end = Some(bucket.end);
                    Ok(())
                })
                .err()
        } else {
            validation_error
        };
    }

    fn get(&self, series: SeriesId) -> Option<&SeriesHistory> {
        if series.get() <= MAX_ADMITTED_SERIES as u64 {
            self.series
                .get(series.get() as usize - 1)
                .and_then(Option::as_ref)
        } else {
            self.sparse_series.get(&series)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u64) -> SeriesId {
        SeriesId::new(value).unwrap()
    }

    #[test]
    fn dense_and_large_sparse_ids_share_the_same_admission_limit() {
        let mut history = HistoryStore::new(Duration::from_secs(1));
        history.record_gap(id(u64::MAX), Duration::from_secs(1));
        assert!(history.series.is_empty());
        for value in 1..MAX_ADMITTED_SERIES as u64 {
            history.record_gap(id(value), Duration::from_secs(1));
        }
        history.record_gap(id(MAX_ADMITTED_SERIES as u64), Duration::from_secs(1));
        assert_eq!(history.bucket_count(), MAX_ADMITTED_SERIES as u64);
        assert_eq!(
            history.coverage(id(MAX_ADMITTED_SERIES as u64)).unwrap(),
            HistoryCoverage::empty()
        );
        history.record_gap(id(u64::MAX), Duration::from_secs(2));
        assert_eq!(history.coverage(id(u64::MAX)).unwrap().gaps(), 2);
        assert_eq!(history.bucket_count(), MAX_ADMITTED_SERIES as u64 + 1);
    }

    #[test]
    fn compaction_is_bounded_and_retains_the_full_session_span() {
        let mut history = HistoryStore::new(Duration::from_secs(1));
        for second in 1..=100 {
            let end = Duration::from_secs(second);
            history.record(
                id(1),
                HistoryObservation::new(
                    end.saturating_sub(Duration::from_secs(1)),
                    end,
                    second,
                    1,
                    Duration::from_secs(1),
                    false,
                ),
            );
        }

        let coverage = history.coverage(id(1)).unwrap();
        assert_eq!(coverage.start(), Some(Duration::ZERO));
        assert_eq!(coverage.end(), Some(Duration::from_secs(100)));
        assert_eq!(
            coverage.bucket_count(),
            MAX_HISTORY_BUCKETS_PER_SERIES as u64
        );
        assert!(coverage.compacted());
        assert!(coverage.resolution() > Duration::from_secs(1));
    }

    #[test]
    fn full_histories_compact_without_growing_their_allocation() {
        for limit in [2, MAX_HISTORY_BUCKETS_PER_SERIES, 120] {
            for series in [id(1), id(u64::MAX)] {
                let mut history = HistoryStore::with_bucket_limit(Duration::from_secs(1), limit);
                for second in 1..=limit {
                    history.record_gap(series, Duration::from_secs(second as u64));
                }
                let capacity = history.get(series).unwrap().points.capacity();
                for second in limit + 1..=limit * 4 {
                    history.record_gap(series, Duration::from_secs(second as u64));
                    let stored = history.get(series).unwrap();
                    assert_eq!(stored.points.capacity(), capacity);
                    assert_eq!(stored.points.len(), limit);
                    assert!(stored.validation_error.is_none());
                    let coverage = history.coverage(series).unwrap();
                    assert_eq!(coverage.gaps(), second as u64);
                    assert_eq!(coverage.start(), Some(Duration::from_secs(1)));
                    assert_eq!(coverage.end(), Some(Duration::from_secs(second as u64)));
                }
            }
        }
    }

    #[test]
    fn gaps_survive_compaction() {
        let mut history = HistoryStore::new(Duration::from_secs(1));
        history.record(
            id(1),
            HistoryObservation::new(
                Duration::ZERO,
                Duration::from_secs(1),
                10,
                0,
                Duration::ZERO,
                false,
            ),
        );
        history.record_gap(id(1), Duration::from_secs(2));
        history.record(
            id(1),
            HistoryObservation::new(
                Duration::from_secs(3),
                Duration::from_secs(3),
                12,
                2,
                Duration::ZERO,
                false,
            ),
        );

        assert_eq!(history.coverage(id(1)).unwrap().gaps(), 1);
    }

    #[test]
    fn incremental_coverage_matches_all_retained_buckets() {
        let mut history = HistoryStore::new(Duration::from_millis(250));
        for tick in 1..=200 {
            let at = Duration::from_millis(tick * 300);
            if tick % 7 == 0 {
                history.record_gap(id(1), at);
            } else {
                history.record(
                    id(1),
                    HistoryObservation::new(
                        at - Duration::from_millis(300),
                        at,
                        tick,
                        1,
                        Duration::from_millis(300),
                        false,
                    ),
                );
            }
            let points = history.buckets(id(1));
            let coverage = history.coverage(id(1)).unwrap();
            assert_eq!(
                coverage.resolution(),
                points.iter().fold(Duration::from_millis(250), |r, p| r
                    .max(p.end() - p.start()))
            );
            assert_eq!(coverage.gaps(), points.iter().map(|p| p.gaps).sum::<u64>());
            assert_eq!(coverage.bucket_count(), points.len() as u64);
        }
    }

    #[test]
    fn incremental_validation_matches_full_validation_after_every_mutation() {
        for limit in [2, 3, 8, MAX_HISTORY_BUCKETS_PER_SERIES] {
            let mut history = HistoryStore::with_bucket_limit(Duration::from_secs(1), limit);
            for tick in 1..=500_u64 {
                let end = Duration::from_secs(tick);
                let mut bucket = HistoryBucket::observed(HistoryObservation::new(
                    end - Duration::from_secs(1),
                    end,
                    tick,
                    tick % 17,
                    Duration::from_secs(1),
                    tick % 31 == 0,
                ));
                match tick % 23 {
                    0 => bucket = HistoryBucket::gap(end),
                    1 if tick > 1 => bucket.start = end - Duration::from_secs(2),
                    2 => bucket.min = tick + 1,
                    3 => bucket.count = 0,
                    4 => bucket.trend_elapsed = Duration::from_secs(2),
                    5 => bucket.sum = 0,
                    6 => bucket.end = bucket.start.saturating_sub(Duration::from_secs(1)),
                    7 => bucket.resets = 2,
                    _ => {}
                }
                history.push(id(1), bucket);
                if let Ok(projection) = history.projection(id(1)) {
                    let expected = super::super::model::validate_history_buckets(
                        projection.coverage(),
                        &history.buckets(id(1)),
                    );
                    let actual = projection.validated_parts().map(|_| ());
                    assert_eq!(actual, expected, "limit={limit} tick={tick}");
                }
            }
        }
    }

    #[test]
    fn compaction_can_recover_from_an_invalid_boundary() {
        let mut history = HistoryStore::with_bucket_limit(Duration::from_secs(1), 2);
        for second in [3, 1, 4] {
            history.record_gap(id(1), Duration::from_secs(second));
        }
        assert!(history
            .projection(id(1))
            .unwrap()
            .validated_parts()
            .is_err());
        history.record_gap(id(1), Duration::from_secs(5));
        let projection = history.projection(id(1)).unwrap();
        assert!(super::super::model::validate_history_buckets(
            projection.coverage(),
            &history.buckets(id(1)),
        )
        .is_ok());
        assert!(projection.validated_parts().is_ok());
    }

    #[test]
    fn merged_bucket_is_validated_after_saturating_arithmetic() {
        let mut history = HistoryStore::with_bucket_limit(Duration::from_secs(1), 2);
        let bucket = |second| HistoryBucket {
            start: Duration::from_secs(second - 1),
            end: Duration::from_secs(second),
            min: u64::MAX,
            max: u64::MAX,
            first: u64::MAX,
            last: u64::MAX,
            sum: u128::from(u64::MAX) * u128::from(u64::MAX),
            count: u64::MAX,
            delta: 0,
            trend_delta: 0,
            trend_elapsed: Duration::ZERO,
            resets: 0,
            gaps: 0,
        };
        assert!(bucket(1).validate().is_ok());
        for second in 1..=3 {
            history.push(id(1), bucket(second));
        }
        let projection = history.projection(id(1)).unwrap();
        assert_eq!(
            projection.validated_parts().map(|_| ()),
            Err(MonitorValidationError::InvalidHistoryBucket)
        );
    }

    #[test]
    fn compaction_keeps_an_observed_peak_instead_of_an_average_rate() {
        let mut history = HistoryStore::new(Duration::from_secs(1));
        let mut value = 0_u64;
        for second in 1..=MAX_HISTORY_BUCKETS_PER_SERIES as u64 + 2 {
            let delta = if second == 2 { 100 } else { 1 };
            value += delta;
            let end = Duration::from_secs(second);
            history.record(
                id(1),
                HistoryObservation::new(
                    end - Duration::from_secs(1),
                    end,
                    value,
                    delta,
                    Duration::from_secs(1),
                    false,
                ),
            );
        }

        let buckets = history.buckets(id(1));
        assert!(buckets[0].end() > buckets[0].start());
        assert_eq!(buckets[0].trend_rate_per_second(), Some(100.0));
        assert_ne!(
            buckets[0].trend_rate_per_second(),
            Some(buckets[0].delta() as f64 / (buckets[0].end() - buckets[0].start()).as_secs_f64())
        );
    }

    #[test]
    fn custom_bucket_limit_does_not_change_the_default_history_contract() {
        let mut custom = HistoryStore::with_bucket_limit(Duration::from_secs(1), 120);
        let mut default = HistoryStore::new(Duration::from_secs(1));
        for second in 1..=100 {
            let end = Duration::from_secs(second);
            let observation = HistoryObservation::new(
                end - Duration::from_secs(1),
                end,
                second,
                0,
                Duration::ZERO,
                false,
            );
            custom.record(id(1), observation);
            default.record(id(1), observation);
        }

        let custom_coverage = custom.coverage(id(1)).unwrap();
        assert_eq!(custom_coverage.bucket_count(), 100);
        assert_eq!(custom_coverage.resolution(), Duration::from_secs(1));
        assert!(!custom_coverage.compacted());
        assert_eq!(
            default.coverage(id(1)).unwrap().bucket_count(),
            MAX_HISTORY_BUCKETS_PER_SERIES as u64
        );
    }
}
