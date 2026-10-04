use crate::{
    model::{self, Rates, Row},
    perf::{Group, Snapshot},
};
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    time::Instant,
};

const MAX_THREADS: usize = 4096;

#[derive(Clone, Debug)]
struct Task {
    id: u32,
    start_time: u64,
    name: String,
    last_cpu: Option<i32>,
}

struct Counter {
    task: Task,
    group: Group,
    previous: Snapshot,
}

pub struct Sample {
    pub rows: Vec<Row>,
    pub total: Rates,
    pub elapsed: f64,
    pub observed: usize,
    pub live: usize,
}

pub struct Collector {
    pid: Option<u32>,
    process_start: Option<u64>,
    counters: BTreeMap<u32, Counter>,
    previous: Instant,
}

fn parse_cpu_list(input: &str) -> Result<Vec<u32>> {
    let mut cpus = BTreeSet::new();
    for range in input.trim().split(',') {
        let (first, last) = match range.split_once('-') {
            Some((first, last)) => (first.parse::<u32>()?, last.parse::<u32>()?),
            None => {
                let cpu = range.parse::<u32>()?;
                (cpu, cpu)
            }
        };
        if last < first || last - first > 65536 {
            bail!("invalid online CPU range: {range}");
        }
        cpus.extend(first..=last);
    }
    if cpus.is_empty() {
        bail!("no online CPUs found");
    }
    Ok(cpus.into_iter().collect())
}

fn parse_task_stat(input: &str, id: u32) -> Result<Task> {
    let open = input.find('(').context("missing task name")?;
    let close = input.rfind(')').context("missing task name end")?;
    let fields: Vec<_> = input[close + 1..].split_whitespace().collect();
    let start_time = fields.get(19).context("missing task start time")?.parse()?;
    let last_cpu = fields.get(36).and_then(|value| value.parse().ok());
    Ok(Task {
        id,
        start_time,
        name: input[open + 1..close].to_owned(),
        last_cpu,
    })
}

fn task(pid: u32, tid: u32) -> Result<Task> {
    let stat = fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat"))?;
    parse_task_stat(&stat, tid)
}

fn online_cpus() -> Result<BTreeMap<u32, Task>> {
    let input =
        fs::read_to_string("/sys/devices/system/cpu/online").context("read online CPU list")?;
    Ok(parse_cpu_list(&input)?
        .into_iter()
        .map(|id| {
            (
                id,
                Task {
                    id,
                    start_time: 0,
                    name: format!("CPU{id}"),
                    last_cpu: None,
                },
            )
        })
        .collect())
}

fn threads(pid: u32) -> Result<BTreeMap<u32, Task>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = entry?;
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        match task(pid, tid) {
            Ok(value) => {
                result.insert(tid, value);
            }
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
        if result.len() > MAX_THREADS {
            bail!("process has more than {MAX_THREADS} threads; refusing to open excessive perf events");
        }
    }
    Ok(result)
}

impl Collector {
    pub fn new(pid: Option<u32>) -> Result<Self> {
        let process_start = if let Some(pid) = pid {
            Some(
                task(pid, pid)
                    .with_context(|| format!("read process {pid}"))?
                    .start_time,
            )
        } else {
            None
        };
        let mut collector = Self {
            pid,
            process_start,
            counters: BTreeMap::new(),
            previous: Instant::now(),
        };
        let candidates = collector.candidates()?;
        collector.refresh(&candidates)?;
        if collector.counters.is_empty() {
            bail!("no perf counters could be opened");
        }
        collector.previous = Instant::now();
        Ok(collector)
    }

    fn candidates(&self) -> Result<BTreeMap<u32, Task>> {
        if let Some(pid) = self.pid {
            let process = task(pid, pid).with_context(|| format!("process {pid} exited"))?;
            if Some(process.start_time) != self.process_start {
                bail!("process {pid} was replaced (PID reused)");
            }
            threads(pid)
        } else {
            online_cpus()
        }
    }

    fn refresh(&mut self, candidates: &BTreeMap<u32, Task>) -> Result<()> {
        for (&id, info) in candidates {
            if let Some(counter) = self.counters.get_mut(&id) {
                if counter.task.start_time == info.start_time {
                    counter.task = info.clone();
                    continue;
                }
                self.counters.remove(&id);
            }
            let pid = self.pid.map_or(-1, |_| id as i32);
            let cpu = self.pid.map_or(id as i32, |_| -1);
            let group = match Group::open_best(pid, cpu) {
                Ok(group) => group,
                Err(error)
                    if self.pid.is_some()
                        && matches!(error.raw_os_error(), Some(libc::ESRCH | libc::ENOENT)) =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("open PMU for {} {id}; check perf_event_paranoid/CAP_PERFMON and available PMU events", if self.pid.is_some() { "TID" } else { "CPU" })
                    });
                }
            };
            if let Some(process) = self.pid {
                match task(process, id) {
                    Ok(current) if current.start_time == info.start_time => {}
                    Ok(_) => continue,
                    Err(error)
                        if error
                            .downcast_ref::<io::Error>()
                            .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            let previous = group
                .read()
                .with_context(|| format!("read PMU baseline for {id}"))?;
            self.counters.insert(
                id,
                Counter {
                    task: info.clone(),
                    group,
                    previous,
                },
            );
        }
        Ok(())
    }

    pub fn sample(&mut self) -> Result<Sample> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.previous).as_secs_f64();
        self.previous = now;
        let candidates = self.candidates()?;
        let mut rows = Vec::with_capacity(self.counters.len());
        for counter in self.counters.values_mut() {
            let current = counter.group.read().with_context(|| {
                format!(
                    "read PMU for {} {}",
                    if self.pid.is_some() { "TID" } else { "CPU" },
                    counter.task.id
                )
            })?;
            let rates = model::delta(&counter.previous, &current, elapsed, counter.group.llc);
            counter.previous = current;
            rows.push(Row {
                id: counter.task.id,
                name: counter.task.name.clone(),
                last_cpu: candidates
                    .get(&counter.task.id)
                    .filter(|task| task.start_time == counter.task.start_time)
                    .and_then(|task| task.last_cpu)
                    .or(counter.task.last_cpu),
                rates,
            });
        }
        let observed = rows.len();
        let total = model::total(&rows);
        self.counters.retain(|id, counter| {
            candidates
                .get(id)
                .is_some_and(|info| info.start_time == counter.task.start_time)
        });
        self.refresh(&candidates)?;
        Ok(Sample {
            rows,
            total,
            elapsed,
            observed,
            live: candidates.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_list_accepts_sparse_ranges() {
        assert_eq!(
            parse_cpu_list("0-2,4,8-9\n").unwrap(),
            vec![0, 1, 2, 4, 8, 9]
        );
        assert!(parse_cpu_list("4-2").is_err());
    }

    #[test]
    fn task_stat_handles_parentheses_in_name() {
        let mut fields = vec!["0"; 37];
        fields[19] = "12345";
        fields[36] = "7";
        let stat = format!("10 (x) y) {}", fields.join(" "));
        let task = parse_task_stat(&stat, 10).unwrap();
        assert_eq!(task.name, "x) y");
        assert_eq!(task.start_time, 12345);
        assert_eq!(task.last_cpu, Some(7));
    }
}
