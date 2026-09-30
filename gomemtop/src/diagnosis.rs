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

fn size(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / MIB as f64)
}

fn share(part: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        (part as f64 * 100.0 / total as f64).round() as u64
    }
}

pub fn report(memory: Memory, runtime: Option<RuntimeMemory>, points: &[Point]) -> Vec<String> {
    let mut lines = vec![format!(
        "RSS {} | anon {} | file {} | shmem {}",
        size(memory.rss),
        size(memory.anonymous),
        size(memory.file),
        size(memory.shmem)
    )];
    let Some(runtime) = runtime else {
        lines.insert(
            0,
            "Go runtime counters unavailable; RSS source is unresolved.".into(),
        );
        lines.push("Check the pprof MemStats error before attributing RSS.".into());
        return lines;
    };
    let held = runtime.heap_sys.saturating_sub(runtime.heap_released);
    let idle_kept = runtime
        .heap_idle
        .and_then(|n| n.checked_sub(runtime.heap_released));
    let span_slack = runtime
        .heap_inuse
        .zip(runtime.heap_alloc)
        .and_then(|(inuse, alloc)| inuse.checked_sub(alloc));
    let major_heap = memory.rss > 0 && held >= memory.rss.saturating_mul(7) / 10;
    lines.insert(
        0,
        if major_heap {
            "Most RSS aligns with Go heap pages; this is not a leak verdict."
        } else {
            "Go heap counters explain only part of RSS; inspect other mappings."
        }
        .into(),
    );
    lines.push(match runtime.heap_alloc {
        Some(alloc) => format!(
            "Allocated heap (HeapAlloc) {} ({}% RSS)",
            size(alloc),
            share(alloc, memory.rss)
        ),
        None => "Allocated heap (HeapAlloc) unavailable".into(),
    });
    lines.push(match idle_kept {
        Some(idle) => format!(
            "Idle kept (HeapIdle - HeapReleased) {} ({}% RSS)",
            size(idle),
            share(idle, memory.rss)
        ),
        None => "Idle kept unavailable (missing/inconsistent heap counters)".into(),
    });
    lines.push(match span_slack {
        Some(slack) => format!(
            "Span slack (HeapInuse - HeapAlloc) {} ({}% RSS)",
            size(slack),
            share(slack, memory.rss)
        ),
        None => "Span slack unavailable (missing/inconsistent heap counters)".into(),
    });
    lines.push(format!(
        "Heap held (HeapSys - HeapReleased) {} (~{}% RSS)",
        size(held),
        share(held, memory.rss)
    ));
    lines.push(if held <= memory.rss {
        format!(
            "RSS - held estimate ~{}; stack {}, runtime/file/native",
            size(memory.rss - held),
            runtime.stack_inuse.map(size).unwrap_or_else(|| "?".into())
        )
    } else {
        "Heap-held estimate exceeds RSS; snapshots/pages are not additive.".into()
    });
    lines.push(analyze(points).evidence);
    lines.push(
        if runtime
            .heap_alloc
            .is_some_and(|n| share(n, memory.rss) >= 35)
        {
            "Optimize: inspect top inuse_space stacks; confirm retention after GC."
        } else if !major_heap {
            "Optimize: inspect cgo, mmap, stacks and file-backed mappings."
        } else {
            "Optimize: compare post-GC heap profiles under the same load."
        }
        .into(),
    );
    lines.push(
        if idle_kept.is_some_and(|n| share(n, memory.rss) >= 10)
            && span_slack.is_some_and(|n| share(n, memory.rss) >= 10)
        {
            "Optimize: profile allocation churn; trial GOMEMLIMIT, measure GC cost."
        } else if idle_kept.is_some_and(|n| share(n, memory.rss) >= 10) {
            "Optimize: trial GOMEMLIMIT for RSS; measure GC CPU and latency."
        } else if span_slack.is_some_and(|n| share(n, memory.rss) >= 10) {
            "Optimize: profile allocation sizes and short-lived object churn."
        } else {
            "Optimize: watch RSS and post-GC HeapAlloc over a longer window."
        }
        .into(),
    );
    lines.push("Limit: counters are not an exact RSS partition or leak verdict.".into());
    lines
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

    #[test]
    fn explains_go_heap_breakdown_without_claiming_leak() {
        let mib = MIB as u64;
        let memory = Memory {
            rss: 434 * mib,
            anonymous: 424 * mib,
            file: 10 * mib,
            ..Memory::default()
        };
        let runtime = RuntimeMemory {
            heap_alloc: Some(234 * mib),
            heap_inuse: Some(318 * mib),
            heap_idle: Some(192 * mib),
            heap_sys: 510 * mib,
            heap_released: 108 * mib,
            stack_inuse: Some(2 * mib),
            sys: 531 * mib,
            num_gc: Some(441),
        };
        let lines = report(memory, Some(runtime), &[point(434, 234, 402)]);
        assert!(lines[0].contains("Go heap pages"));
        assert!(lines
            .iter()
            .any(|line| line.contains("Idle kept") && line.contains("84.0 MiB")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Span slack") && line.contains("84.0 MiB")));
        assert!(lines.iter().any(|line| line.contains("GOMEMLIMIT")));
        assert!(lines
            .iter()
            .any(|line| line.contains("not an exact RSS partition")));
    }

    #[test]
    fn partial_runtime_counters_do_not_invent_breakdown() {
        let runtime = RuntimeMemory {
            heap_sys: 100,
            heap_released: 20,
            sys: 150,
            ..RuntimeMemory::default()
        };
        let lines = report(
            Memory {
                rss: 100,
                ..Memory::default()
            },
            Some(runtime),
            &[],
        );
        assert!(lines
            .iter()
            .any(|line| line.contains("HeapAlloc) unavailable")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Span slack unavailable")));
    }

    #[test]
    fn flags_rss_outside_go_heap_without_false_residual() {
        let mib = MIB as u64;
        let memory = Memory {
            rss: 400 * mib,
            anonymous: 100 * mib,
            file: 300 * mib,
            ..Memory::default()
        };
        let runtime = RuntimeMemory {
            heap_sys: 100 * mib,
            heap_released: 20 * mib,
            sys: 120 * mib,
            ..RuntimeMemory::default()
        };
        let lines = report(memory, Some(runtime), &[]);
        assert!(lines[0].contains("other mappings"));
        assert!(lines.iter().any(|line| line.contains("cgo, mmap")));
        let mut runtime = runtime;
        runtime.heap_sys = 500 * mib;
        runtime.heap_released = 0;
        let lines = report(memory, Some(runtime), &[]);
        assert!(lines.iter().any(|line| line.contains("exceeds RSS")));
    }
}
