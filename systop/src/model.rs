use crate::collect::{Latency, ProcKey, Raw, ThreadKey, LATENCY_BUCKETS, MAX_SYSCALL};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct SyscallRow {
    pub id: u32,
    pub name: String,
    pub rate: f64,
    pub share: f64,
    pub time_ms_s: f64,
    pub avg_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct ProcessRow {
    pub pid: u32,
    pub start: u64,
    pub comm: String,
    pub rate: f64,
    pub share: f64,
    pub time_ms_s: f64,
    pub avg_ms: Option<f64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessFilter {
    pub pid: u32,
    pub start: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadFilter {
    pub tid: u32,
    pub start: u64,
}

#[derive(Clone, Debug)]
pub struct View {
    pub seconds: f64,
    pub total_rate: f64,
    pub process_keys: usize,
    pub inflight: usize,
    pub selected_rate: f64,
    pub syscalls: Vec<SyscallRow>,
    pub processes: Vec<ProcessRow>,
    pub threads: Vec<ProcessRow>,
    pub thread_target: Option<u32>,
    pub thread_filter: Option<ThreadFilter>,
    pub thread_keys: usize,
    pub thread_fail_rate: f64,
    pub invalid_rate: f64,
    pub attribution_fail_rate: f64,
    pub latency_fail_rate: f64,
    pub completed_rate: f64,
    pub start_fail_rate: f64,
    pub unmatched_rate: f64,
    pub process_miss_rate: f64,
    pub abandoned_rate: f64,
    pub latency_enabled: bool,
    pub sort_time: bool,
    pub pid_filter: Option<ProcessFilter>,
    pub syscall_filter: Option<u32>,
}

impl View {
    pub fn sort(&mut self, time: bool) {
        self.sort_time = time && self.latency_enabled;
        if self.sort_time {
            self.syscalls
                .sort_by(|a, b| b.time_ms_s.total_cmp(&a.time_ms_s).then(a.id.cmp(&b.id)));
            self.processes.sort_by(|a, b| {
                b.time_ms_s
                    .total_cmp(&a.time_ms_s)
                    .then(a.pid.cmp(&b.pid))
                    .then(a.start.cmp(&b.start))
            });
            self.threads.sort_by(|a, b| {
                b.time_ms_s
                    .total_cmp(&a.time_ms_s)
                    .then(a.pid.cmp(&b.pid))
                    .then(a.start.cmp(&b.start))
            });
        } else {
            self.syscalls
                .sort_by(|a, b| b.rate.total_cmp(&a.rate).then(a.id.cmp(&b.id)));
            self.processes.sort_by(|a, b| {
                b.rate
                    .total_cmp(&a.rate)
                    .then(a.pid.cmp(&b.pid))
                    .then(a.start.cmp(&b.start))
            });
            self.threads.sort_by(|a, b| {
                b.rate
                    .total_cmp(&a.rate)
                    .then(a.pid.cmp(&b.pid))
                    .then(a.start.cmp(&b.start))
            });
        }
    }
}

pub fn syscall_name(id: u32) -> String {
    let names = [
        (libc::SYS_read as u32, "read"),
        (libc::SYS_write as u32, "write"),
        (libc::SYS_close as u32, "close"),
        (libc::SYS_openat as u32, "openat"),
        (libc::SYS_futex as u32, "futex"),
        (libc::SYS_sendto as u32, "sendto"),
        (libc::SYS_recvfrom as u32, "recvfrom"),
        (libc::SYS_sendmsg as u32, "sendmsg"),
        (libc::SYS_recvmsg as u32, "recvmsg"),
        (libc::SYS_connect as u32, "connect"),
        (libc::SYS_epoll_pwait as u32, "epoll_pwait"),
        (libc::SYS_epoll_ctl as u32, "epoll_ctl"),
        (libc::SYS_ppoll as u32, "ppoll"),
        (libc::SYS_fcntl as u32, "fcntl"),
        (libc::SYS_bpf as u32, "bpf"),
        (libc::SYS_socket as u32, "socket"),
        (libc::SYS_setsockopt as u32, "setsockopt"),
        (libc::SYS_getsockopt as u32, "getsockopt"),
        (libc::SYS_getdents64 as u32, "getdents64"),
        (libc::SYS_nanosleep as u32, "nanosleep"),
        (libc::SYS_clock_nanosleep as u32, "clock_nanosleep"),
        (libc::SYS_accept4 as u32, "accept4"),
        (libc::SYS_clone as u32, "clone"),
        (libc::SYS_munmap as u32, "munmap"),
        (libc::SYS_mprotect as u32, "mprotect"),
        (libc::SYS_ioctl as u32, "ioctl"),
        (libc::SYS_prctl as u32, "prctl"),
        (libc::SYS_getpid as u32, "getpid"),
        (libc::SYS_gettid as u32, "gettid"),
        (libc::SYS_clock_gettime as u32, "clock_gettime"),
        (libc::SYS_exit as u32, "exit"),
        (libc::SYS_exit_group as u32, "exit_group"),
        (libc::SYS_readv as u32, "readv"),
        (libc::SYS_writev as u32, "writev"),
        (libc::SYS_sendmmsg as u32, "sendmmsg"),
        (libc::SYS_recvmmsg as u32, "recvmmsg"),
        (libc::SYS_epoll_create1 as u32, "epoll_create1"),
        (libc::SYS_eventfd2 as u32, "eventfd2"),
        (libc::SYS_timerfd_settime as u32, "timerfd_settime"),
        (libc::SYS_io_uring_enter as u32, "io_uring_enter"),
        (libc::SYS_epoll_pwait2 as u32, "epoll_pwait2"),
    ];
    #[cfg(not(target_arch = "arm"))]
    if id == libc::SYS_newfstatat as u32 {
        return "newfstatat".into();
    }
    #[cfg(target_arch = "arm")]
    if id == libc::SYS_mmap2 as u32 {
        return "mmap2".into();
    }
    #[cfg(not(target_arch = "arm"))]
    if id == libc::SYS_mmap as u32 {
        return "mmap".into();
    }
    names
        .iter()
        .find(|(number, _)| *number == id)
        .map(|(_, name)| (*name).to_owned())
        .unwrap_or_else(|| format!("sys_{id}"))
}

fn delta(old: u64, new: u64) -> u64 {
    if new >= old {
        new - old
    } else {
        new
    }
}

fn average_ms(count: u64, total_ns: u64) -> Option<f64> {
    (count > 0).then(|| total_ns as f64 / count as f64 / 1_000_000.0)
}

// Log2 microsecond buckets provide an upper-bound estimate, not an exact percentile.
fn p95_ms(buckets: &[u64; LATENCY_BUCKETS]) -> Option<f64> {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = (total * 95).div_ceil(100);
    let mut seen = 0;
    for (index, count) in buckets.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return Some((1_u64 << (index + 1)) as f64 / 1000.0);
        }
    }
    None
}

fn latency_delta(old: &Latency, new: &Latency) -> Latency {
    let mut result = Latency {
        completed: delta(old.completed, new.completed),
        total_ns: delta(old.total_ns, new.total_ns),
        ..Latency::default()
    };
    for index in 0..LATENCY_BUCKETS {
        result.buckets[index] = delta(old.buckets[index], new.buckets[index]);
    }
    result
}

pub fn build(
    old: &Raw,
    new: &Raw,
    pid_filter: Option<ProcessFilter>,
    syscall_filter: Option<u32>,
    thread_filter: Option<ThreadFilter>,
) -> View {
    let seconds = new
        .at
        .saturating_duration_since(old.at)
        .as_secs_f64()
        .max(0.000_001);
    let global: Vec<u64> = new
        .syscall
        .iter()
        .zip(&old.syscall)
        .map(|(current, previous)| delta(*previous, *current))
        .collect();
    let total: u64 = global.iter().sum();
    let latency_enabled = new.latency.is_some();
    let global_latency: Vec<Latency> = new.latency.as_ref().zip(old.latency.as_ref()).map_or_else(
        || vec![Latency::default(); MAX_SYSCALL],
        |(current, previous)| {
            current
                .iter()
                .zip(previous)
                .map(|(new, old)| latency_delta(old, new))
                .collect()
        },
    );
    let mut focused = vec![0_u64; MAX_SYSCALL];
    let mut focused_latency = vec![(0_u64, 0_u64); MAX_SYSCALL];
    let mut processes: HashMap<(u32, u64), (String, u64, u64, u64)> = HashMap::new();
    for (ProcKey { start, pid, id }, value) in &new.process {
        let previous = old
            .process
            .get(&ProcKey {
                start: *start,
                pid: *pid,
                id: *id,
            })
            .map(|entry| entry.count)
            .unwrap_or(0);
        let count = delta(previous, value.count);
        let previous = old.process.get(&ProcKey {
            start: *start,
            pid: *pid,
            id: *id,
        });
        let completed = delta(
            previous.map(|entry| entry.completed).unwrap_or(0),
            value.completed,
        );
        let total_ns = delta(
            previous.map(|entry| entry.total_ns).unwrap_or(0),
            value.total_ns,
        );
        if count == 0 && completed == 0 {
            continue;
        }
        if new.thread_target.is_none()
            && pid_filter.is_none_or(|selected| {
                selected.pid == *pid && selected.start.is_none_or(|started| started == *start)
            })
        {
            focused[*id as usize] = focused[*id as usize].saturating_add(count);
            let latency = &mut focused_latency[*id as usize];
            latency.0 += completed;
            latency.1 += total_ns;
        }
        if syscall_filter.is_none_or(|selected| selected == *id) {
            let entry = processes
                .entry((*pid, *start))
                .or_insert_with(|| (value.comm.clone(), 0, 0, 0));
            entry.1 = entry.1.saturating_add(count);
            entry.2 += completed;
            entry.3 += total_ns;
        }
    }
    let mut threads: HashMap<(u32, u64), (String, u64, u64, u64)> = HashMap::new();
    for (ThreadKey { start, tid, id }, value) in &new.threads {
        let previous = old.threads.get(&ThreadKey {
            start: *start,
            tid: *tid,
            id: *id,
        });
        let count = delta(previous.map(|entry| entry.count).unwrap_or(0), value.count);
        let completed = delta(
            previous.map(|entry| entry.completed).unwrap_or(0),
            value.completed,
        );
        let total_ns = delta(
            previous.map(|entry| entry.total_ns).unwrap_or(0),
            value.total_ns,
        );
        if count == 0 && completed == 0 {
            continue;
        }
        if thread_filter.is_none_or(|selected| selected.tid == *tid && selected.start == *start) {
            focused[*id as usize] = focused[*id as usize].saturating_add(count);
            focused_latency[*id as usize].0 += completed;
            focused_latency[*id as usize].1 += total_ns;
        }
        if syscall_filter.is_none_or(|selected| selected == *id) {
            let entry = threads
                .entry((*tid, *start))
                .or_insert_with(|| (value.comm.clone(), 0, 0, 0));
            entry.1 = entry.1.saturating_add(count);
            entry.2 += completed;
            entry.3 += total_ns;
        }
    }
    let sys_counts = if pid_filter.is_some() {
        &focused
    } else {
        &global
    };
    let selected: u64 = sys_counts.iter().sum();
    let process_denominator = syscall_filter
        .and_then(|id| global.get(id as usize).copied())
        .unwrap_or(total)
        .max(1);
    let thread_denominator = threads.values().map(|entry| entry.1).sum::<u64>().max(1);
    let mut syscalls: Vec<_> = sys_counts
        .iter()
        .enumerate()
        .filter(|(id, count)| {
            **count > 0
                || (latency_enabled
                    && if pid_filter.is_some() {
                        focused_latency[*id].0 > 0
                    } else {
                        global_latency[*id].completed > 0
                    })
        })
        .map(|(id, count)| SyscallRow {
            id: id as u32,
            name: syscall_name(id as u32),
            rate: *count as f64 / seconds,
            share: *count as f64 / selected.max(1) as f64,
            time_ms_s: if pid_filter.is_some() {
                focused_latency[id].1 as f64 / 1_000_000.0 / seconds
            } else {
                global_latency[id].total_ns as f64 / 1_000_000.0 / seconds
            },
            avg_ms: if !latency_enabled {
                None
            } else if pid_filter.is_some() {
                average_ms(focused_latency[id].0, focused_latency[id].1)
            } else {
                average_ms(global_latency[id].completed, global_latency[id].total_ns)
            },
            p95_ms: if pid_filter.is_some() {
                None
            } else {
                latency_enabled
                    .then(|| p95_ms(&global_latency[id].buckets))
                    .flatten()
            },
        })
        .collect();
    syscalls.sort_by(|a, b| b.rate.total_cmp(&a.rate).then(a.id.cmp(&b.id)));
    let mut process_rows: Vec<_> = processes
        .into_iter()
        .map(
            |((pid, start), (comm, count, completed, total_ns))| ProcessRow {
                pid,
                start,
                comm,
                rate: count as f64 / seconds,
                share: count as f64 / process_denominator as f64,
                time_ms_s: total_ns as f64 / 1_000_000.0 / seconds,
                avg_ms: latency_enabled
                    .then(|| average_ms(completed, total_ns))
                    .flatten(),
            },
        )
        .collect();
    process_rows.sort_by(|a, b| {
        b.rate
            .total_cmp(&a.rate)
            .then(a.pid.cmp(&b.pid))
            .then(a.start.cmp(&b.start))
    });
    let mut thread_rows: Vec<_> = threads
        .into_iter()
        .map(
            |((tid, start), (comm, count, completed, total_ns))| ProcessRow {
                pid: tid,
                start,
                comm,
                rate: count as f64 / seconds,
                share: count as f64 / thread_denominator as f64,
                time_ms_s: total_ns as f64 / 1_000_000.0 / seconds,
                avg_ms: latency_enabled
                    .then(|| average_ms(completed, total_ns))
                    .flatten(),
            },
        )
        .collect();
    thread_rows.sort_by(|a, b| b.rate.total_cmp(&a.rate).then(a.pid.cmp(&b.pid)));
    View {
        seconds,
        total_rate: total as f64 / seconds,
        process_keys: new.process.len(),
        inflight: new.inflight,
        selected_rate: selected as f64 / seconds,
        syscalls,
        processes: process_rows,
        threads: thread_rows,
        thread_target: new.thread_target,
        thread_filter,
        thread_keys: new.threads.len(),
        thread_fail_rate: delta(old.errors[7], new.errors[7]) as f64 / seconds,
        invalid_rate: delta(old.errors[0], new.errors[0]) as f64 / seconds,
        attribution_fail_rate: delta(old.errors[1], new.errors[1]) as f64 / seconds,
        latency_fail_rate: delta(old.errors[2], new.errors[2]) as f64 / seconds,
        completed_rate: global_latency
            .iter()
            .map(|entry| entry.completed)
            .sum::<u64>() as f64
            / seconds,
        start_fail_rate: delta(old.errors[3], new.errors[3]) as f64 / seconds,
        unmatched_rate: delta(old.errors[4], new.errors[4]) as f64 / seconds,
        process_miss_rate: delta(old.errors[5], new.errors[5]) as f64 / seconds,
        abandoned_rate: delta(old.errors[6], new.errors[6]) as f64 / seconds,
        latency_enabled,
        sort_time: false,
        pid_filter,
        syscall_filter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::{ProcCount, ThreadKey};
    use std::time::{Duration, Instant};

    fn samples() -> (Raw, Raw) {
        let at = Instant::now();
        let mut old = Raw::empty(at);
        let mut new = Raw::empty(at + Duration::from_secs(2));
        old.syscall[libc::SYS_read as usize] = 10;
        new.syscall[libc::SYS_read as usize] = 30;
        new.syscall[libc::SYS_write as usize] = 10;
        old.process.insert(
            ProcKey {
                start: 1,
                pid: 100,
                id: libc::SYS_read as u32,
            },
            ProcCount {
                count: 2,
                comm: "first".into(),
                completed: 0,
                total_ns: 0,
            },
        );
        new.process.insert(
            ProcKey {
                start: 1,
                pid: 100,
                id: libc::SYS_read as u32,
            },
            ProcCount {
                count: 14,
                comm: "first".into(),
                completed: 0,
                total_ns: 0,
            },
        );
        new.process.insert(
            ProcKey {
                start: 2,
                pid: 100,
                id: libc::SYS_write as u32,
            },
            ProcCount {
                count: 8,
                comm: "reused".into(),
                completed: 0,
                total_ns: 0,
            },
        );
        (old, new)
    }

    #[test]
    fn rates_and_pid_lifetimes() {
        let (old, new) = samples();
        let view = build(&old, &new, None, None, None);
        assert_eq!(view.total_rate, 15.0);
        assert_eq!(view.process_keys, 2);
        assert_eq!(view.processes.len(), 2);
        assert_eq!(view.processes[0].comm, "first");
        assert_eq!(view.processes[0].rate, 6.0);
        assert_eq!(view.syscalls[0].name, "read");
        assert_eq!(view.syscalls[0].rate, 10.0);
    }

    #[test]
    fn filters_and_counter_reset() {
        let (mut old, mut new) = samples();
        let view = build(
            &old,
            &new,
            Some(ProcessFilter {
                pid: 100,
                start: Some(2),
            }),
            Some(libc::SYS_write as u32),
            None,
        );
        assert_eq!(view.selected_rate, 4.0);
        assert_eq!(view.processes.len(), 1);
        assert_eq!(view.processes[0].comm, "reused");
        old.syscall[libc::SYS_read as usize] = 100;
        new.syscall[libc::SYS_read as usize] = 5;
        assert_eq!(build(&old, &new, None, None, None).syscalls[1].rate, 2.5);
    }

    #[test]
    fn pid_mode_separates_threads_and_tid_reuse() {
        let (mut old, mut new) = samples();
        old.thread_target = Some(100);
        new.thread_target = Some(100);
        let read = libc::SYS_read as u32;
        let write = libc::SYS_write as u32;
        for (start, tid, id, count, completed, total_ns) in [
            (1, 101, read, 12, 6, 12_000_000),
            (2, 102, write, 8, 2, 8_000_000),
            (3, 101, read, 4, 1, 1_000_000),
        ] {
            new.threads.insert(
                ThreadKey { start, tid, id },
                ProcCount {
                    count,
                    comm: format!("worker-{start}"),
                    completed,
                    total_ns,
                },
            );
        }
        old.threads.insert(
            ThreadKey {
                start: 1,
                tid: 101,
                id: read,
            },
            ProcCount {
                count: 2,
                comm: "worker-1".into(),
                completed: 1,
                total_ns: 1_000_000,
            },
        );
        old.latency = Some(vec![Latency::default(); MAX_SYSCALL]);
        new.latency = Some(vec![Latency::default(); MAX_SYSCALL]);
        let pid = Some(ProcessFilter {
            pid: 100,
            start: None,
        });
        let view = build(&old, &new, pid, None, None);
        assert_eq!(view.threads.len(), 3);
        assert_eq!(view.threads.iter().map(|row| row.rate).sum::<f64>(), 11.0);
        assert_eq!(
            view.syscalls
                .iter()
                .find(|row| row.id == read)
                .unwrap()
                .rate,
            7.0
        );
        let focused = build(
            &old,
            &new,
            pid,
            None,
            Some(ThreadFilter { tid: 101, start: 1 }),
        );
        assert_eq!(focused.selected_rate, 5.0);
        assert_eq!(focused.syscalls.len(), 1);
        assert_eq!(focused.syscalls[0].avg_ms, Some(2.2));
        assert_eq!(focused.threads.len(), 3);
        let by_syscall = build(&old, &new, pid, Some(write), None);
        assert_eq!(by_syscall.threads.len(), 1);
        assert_eq!(by_syscall.threads[0].pid, 102);
    }

    #[test]
    fn unknown_syscall_has_number() {
        assert_eq!(syscall_name(999), "sys_999");
        assert_eq!(
            syscall_name(libc::SYS_clock_nanosleep as u32),
            "clock_nanosleep"
        );
        assert_eq!(
            syscall_name(libc::SYS_io_uring_enter as u32),
            "io_uring_enter"
        );
    }

    #[test]
    fn latency_counts_completions_even_without_new_enters() {
        let (mut old, mut new) = samples();
        let id = libc::SYS_read as usize;
        old.syscall[id] = 30;
        new.syscall[id] = 30;
        old.process
            .get_mut(&ProcKey {
                start: 1,
                pid: 100,
                id: id as u32,
            })
            .unwrap()
            .count = 14;
        let process = new
            .process
            .get_mut(&ProcKey {
                start: 1,
                pid: 100,
                id: id as u32,
            })
            .unwrap();
        process.completed = 2;
        process.total_ns = 6_000_000;
        let mut old_latency = vec![Latency::default(); MAX_SYSCALL];
        old_latency[id].completed = 1;
        old_latency[id].total_ns = 2_000_000;
        old_latency[id].buckets[10] = 1;
        let mut new_latency = old_latency.clone();
        new_latency[id].completed = 3;
        new_latency[id].total_ns = 8_000_000;
        new_latency[id].buckets[11] = 2;
        old.latency = Some(old_latency);
        new.latency = Some(new_latency);

        let view = build(&old, &new, None, Some(id as u32), None);
        let read = view
            .syscalls
            .iter()
            .find(|row| row.id == id as u32)
            .unwrap();
        assert_eq!(read.rate, 0.0);
        assert_eq!(read.avg_ms, Some(3.0));
        assert_eq!(read.p95_ms, Some(4.096));
        let process = view
            .processes
            .iter()
            .find(|row| row.comm == "first")
            .unwrap();
        assert_eq!(process.avg_ms, Some(3.0));

        let focused = build(
            &old,
            &new,
            Some(ProcessFilter {
                pid: 100,
                start: Some(1),
            }),
            None,
            None,
        );
        let read = focused
            .syscalls
            .iter()
            .find(|row| row.id == id as u32)
            .unwrap();
        assert_eq!(read.avg_ms, Some(3.0));
        assert_eq!(read.p95_ms, None);
    }

    #[test]
    fn time_sort_surfaces_rare_slow_calls_and_reports_gaps() {
        let (mut old, mut new) = samples();
        let read = libc::SYS_read as usize;
        let write = libc::SYS_write as usize;
        let old_latency = vec![Latency::default(); MAX_SYSCALL];
        let mut new_latency = old_latency.clone();
        new_latency[read].completed = 20;
        new_latency[read].total_ns = 20_000_000;
        new_latency[write].completed = 2;
        new_latency[write].total_ns = 200_000_000;
        old.latency = Some(old_latency);
        new.latency = Some(new_latency);
        new.errors[3] = 4;
        new.errors[4] = 6;
        new.errors[5] = 2;
        new.errors[6] = 2;
        let mut view = build(&old, &new, None, None, None);
        assert_eq!(view.syscalls[0].name, "read");
        view.sort(true);
        assert_eq!(view.syscalls[0].name, "write");
        assert_eq!(view.syscalls[0].time_ms_s, 100.0);
        assert_eq!(view.completed_rate, 11.0);
        assert_eq!(view.start_fail_rate, 2.0);
        assert_eq!(view.unmatched_rate, 3.0);
        assert_eq!(view.process_miss_rate, 1.0);
        assert_eq!(view.abandoned_rate, 1.0);
        view.sort(false);
        assert_eq!(view.syscalls[0].name, "read");
    }
}
