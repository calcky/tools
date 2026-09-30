use crate::{process::Memory, process::RuntimeMemory};

const MIB: i64 = 1024 * 1024;

#[derive(Clone, Copy)]
pub struct Point {
    pub rss: i64,
    pub anonymous: i64,
    pub file_shmem: i64,
    pub inuse: i64,
    pub retained_heap: Option<i64>,
}

impl Point {
    pub fn new(memory: Memory, inuse: i64, runtime: Option<RuntimeMemory>) -> Self {
        Self {
            rss: memory.rss as i64,
            anonymous: memory.anonymous as i64,
            file_shmem: memory.file.saturating_add(memory.shmem) as i64,
            inuse,
            retained_heap: runtime.map(|r| r.heap_sys.saturating_sub(r.heap_released) as i64),
        }
    }
}

pub struct Hint {
    pub title: &'static str,
    pub evidence: String,
}

pub fn analyze(points: &[Point]) -> Hint {
    if points.len() < 3 {
        return Hint {
            title: "Collecting evidence; need 3 paired samples",
            evidence: format!(
                "{} / 3 samples. A single RSS snapshot cannot identify a leak.",
                points.len()
            ),
        };
    }
    let first = points[0];
    let last = points[points.len() - 1];
    let rss = last.rss - first.rss;
    let heap = last.inuse - first.inuse;
    let anon = last.anonymous - first.anonymous;
    let file = last.file_shmem - first.file_shmem;
    let retained = last
        .retained_heap
        .zip(first.retained_heap)
        .map(|(a, b)| a - b);
    let threshold = (first.rss / 20).max(16 * MIB);
    let title = if rss < threshold {
        "No substantial RSS growth over this window"
    } else if heap >= 8 * MIB && heap >= rss / 2 {
        "RSS growth tracks live Go heap; inspect growing stacks"
    } else if retained.is_some_and(|delta| delta >= 8 * MIB && delta >= rss / 2) {
        "RSS growth tracks Go heap retained by the runtime"
    } else if file >= rss / 2 {
        "RSS growth is mostly file/shared resident pages"
    } else if anon >= rss / 2 && heap < rss / 4 {
        "Anonymous RSS grew without matching live-heap growth"
    } else {
        "RSS grew, but available counters do not isolate a source"
    };
    Hint {
        title,
        evidence: format!(
            "{} samples | RSS {rss:+.1} MiB | heap {heap:+.1} MiB | anon {anon:+.1} MiB{retained}",
            points.len(),
            rss = rss as f64 / MIB as f64,
            heap = heap as f64 / MIB as f64,
            anon = anon as f64 / MIB as f64,
            retained = retained
                .map(|n| format!(" | held {:+.1} MiB", n as f64 / MIB as f64))
                .unwrap_or_default(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(rss: i64, inuse: i64, retained: i64) -> Point {
        Point {
            rss: rss * MIB,
            anonymous: rss * MIB,
            file_shmem: 0,
            inuse: inuse * MIB,
            retained_heap: Some(retained * MIB),
        }
    }

    #[test]
    fn requires_trend_and_distinguishes_heap_sources() {
        assert!(analyze(&[point(100, 50, 70)]).title.contains("Collecting"));
        assert!(
            analyze(&[point(100, 50, 70), point(115, 60, 80), point(140, 90, 110)])
                .title
                .contains("live Go heap")
        );
        assert!(
            analyze(&[point(100, 50, 70), point(115, 51, 85), point(140, 52, 110)])
                .title
                .contains("retained")
        );
        assert!(
            analyze(&[point(100, 50, 70), point(115, 51, 71), point(140, 52, 72)])
                .title
                .contains("Anonymous")
        );
    }
}
