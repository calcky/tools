use anyhow::{bail, Context, Result};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use std::{collections::HashMap, time::Instant};

const BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"));
pub const MAX_SYSCALL: usize = 1024;
pub const PROC_CAPACITY: usize = 65536;
pub const LATENCY_BUCKETS: usize = 32;

#[derive(Clone, Debug, Default)]
pub struct Latency {
    pub completed: u64,
    pub total_ns: u64,
    pub buckets: [u64; LATENCY_BUCKETS],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProcKey {
    pub start: u64,
    pub pid: u32,
    pub id: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadKey {
    pub start: u64,
    pub tid: u32,
    pub id: u32,
}

#[derive(Clone, Debug)]
pub struct ProcCount {
    pub count: u64,
    pub comm: String,
    pub completed: u64,
    pub total_ns: u64,
}

#[derive(Clone, Debug)]
pub struct Raw {
    pub at: Instant,
    pub syscall: Vec<u64>,
    pub process: HashMap<ProcKey, ProcCount>,
    pub threads: HashMap<ThreadKey, ProcCount>,
    pub thread_target: Option<u32>,
    pub inflight: usize,
    pub latency: Option<Vec<Latency>>,
    pub errors: [u64; 8],
}

impl Raw {
    #[cfg(test)]
    pub fn empty(at: Instant) -> Self {
        Self {
            at,
            syscall: vec![0; MAX_SYSCALL],
            process: HashMap::new(),
            threads: HashMap::new(),
            thread_target: None,
            inflight: 0,
            latency: None,
            errors: [0; 8],
        }
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub struct Probe {
    object: Object,
    _link: Link,
    _thread_link: Option<Link>,
    _latency_links: Option<(Link, Link, Link)>,
    thread_target: Option<u32>,
}

impl Probe {
    pub fn attach(with_latency: bool, thread_target: Option<u32>) -> Result<Self> {
        let mut object = ObjectBuilder::default()
            .open_memory(BPF)
            .context("open systop BPF object")?
            .load()
            .context("load systop BPF: kernel BTF and BPF/tracing permissions are required")?;
        if let Some(pid) = thread_target {
            object
                .maps_mut()
                .find(|map| map.name() == "target_pid")
                .context("missing target_pid BPF map")?
                .update(&0_u32.to_ne_bytes(), &pid.to_ne_bytes(), MapFlags::ANY)
                .context("set thread target PID")?;
        }
        let program = object
            .progs_mut()
            .find(|program| program.name() == "on_sys_enter")
            .context("missing on_sys_enter BPF program")?;
        let link = program
            .attach_raw_tracepoint("sys_enter")
            .context("attach sys_enter: check tracepoint and BPF permissions")?;
        let thread_link = if thread_target.is_some() {
            Some(
                object
                    .progs_mut()
                    .find(|program| program.name() == "on_thread_enter")
                    .context("missing on_thread_enter BPF program")?
                    .attach_raw_tracepoint("sys_enter")
                    .context("attach thread sys_enter")?,
            )
        } else {
            None
        };
        let latency_links = if with_latency {
            let enter = object
                .progs_mut()
                .find(|program| program.name() == "on_latency_enter")
                .context("missing on_latency_enter BPF program")?
                .attach_raw_tracepoint("sys_enter")
                .context("attach latency sys_enter")?;
            let exit = object
                .progs_mut()
                .find(|program| program.name() == "on_latency_exit")
                .context("missing on_latency_exit BPF program")?
                .attach_raw_tracepoint("sys_exit")
                .context("attach latency sys_exit: check tracepoint and BPF permissions")?;
            let thread_exit = object
                .progs_mut()
                .find(|program| program.name() == "on_thread_exit")
                .context("missing on_thread_exit BPF program")?
                .attach_raw_tracepoint("sched_process_exit")
                .context("attach sched_process_exit: check tracepoint and BPF permissions")?;
            Some((enter, exit, thread_exit))
        } else {
            None
        };
        Ok(Self {
            object,
            _link: link,
            _thread_link: thread_link,
            _latency_links: latency_links,
            thread_target,
        })
    }

    fn map(&self, name: &str) -> Result<libbpf_rs::MapImpl<'_>> {
        self.object
            .maps()
            .find(|map| map.name() == name)
            .with_context(|| format!("missing BPF map {name}"))
    }

    pub fn read(&self) -> Result<Raw> {
        let mut raw = Raw {
            at: Instant::now(),
            syscall: vec![0; MAX_SYSCALL],
            process: HashMap::new(),
            threads: HashMap::new(),
            thread_target: self.thread_target,
            inflight: 0,
            latency: self
                ._latency_links
                .as_ref()
                .map(|_| vec![Latency::default(); MAX_SYSCALL]),
            errors: [0; 8],
        };
        let syscall = self.map("syscall_counts")?;
        for (id, count) in raw.syscall.iter_mut().enumerate() {
            if let Some(per_cpu) =
                syscall.lookup_percpu(&(id as u32).to_ne_bytes(), MapFlags::ANY)?
            {
                *count = per_cpu.iter().map(|bytes| u64_at(bytes, 0)).sum();
            }
        }
        let process = self.map("proc_calls")?;
        for bytes in process.keys() {
            if bytes.len() != 16 {
                bail!("invalid process BPF key length")
            }
            let Some(value) = process.lookup(&bytes, MapFlags::ANY)? else {
                continue;
            };
            if value.len() < 40 {
                bail!("invalid process BPF value length")
            }
            raw.process.insert(
                ProcKey {
                    start: u64_at(&bytes, 0),
                    pid: u32_at(&bytes, 8),
                    id: u32_at(&bytes, 12),
                },
                ProcCount {
                    count: u64_at(&value, 0),
                    comm: String::from_utf8_lossy(
                        value[8..24]
                            .split(|byte| *byte == 0)
                            .next()
                            .unwrap_or_default(),
                    )
                    .into_owned(),
                    completed: u64_at(&value, 24),
                    total_ns: u64_at(&value, 32),
                },
            );
        }
        if self.thread_target.is_some() {
            let threads = self.map("thread_calls")?;
            for bytes in threads.keys() {
                if bytes.len() != 16 {
                    bail!("invalid thread BPF key length")
                }
                let Some(value) = threads.lookup(&bytes, MapFlags::ANY)? else {
                    continue;
                };
                if value.len() < 40 {
                    bail!("invalid thread BPF value length")
                }
                raw.threads.insert(
                    ThreadKey {
                        start: u64_at(&bytes, 0),
                        tid: u32_at(&bytes, 8),
                        id: u32_at(&bytes, 12),
                    },
                    ProcCount {
                        count: u64_at(&value, 0),
                        comm: String::from_utf8_lossy(
                            value[8..24]
                                .split(|byte| *byte == 0)
                                .next()
                                .unwrap_or_default(),
                        )
                        .into_owned(),
                        completed: u64_at(&value, 24),
                        total_ns: u64_at(&value, 32),
                    },
                );
            }
        }
        if let Some(latencies) = &mut raw.latency {
            raw.inflight = self.map("syscall_starts")?.keys().count();
            let map = self.map("syscall_latency")?;
            for key in map.keys() {
                if key.len() != 4 {
                    bail!("invalid latency BPF key length")
                }
                let id = u32_at(&key, 0) as usize;
                if id >= MAX_SYSCALL {
                    continue;
                }
                if let Some(per_cpu) = map.lookup_percpu(&key, MapFlags::ANY)? {
                    for value in per_cpu {
                        if value.len() < 16 + 8 * LATENCY_BUCKETS {
                            bail!("invalid latency BPF value length")
                        }
                        let target = &mut latencies[id];
                        target.completed = target.completed.saturating_add(u64_at(&value, 0));
                        target.total_ns = target.total_ns.saturating_add(u64_at(&value, 8));
                        for (index, bucket) in target.buckets.iter_mut().enumerate() {
                            *bucket = bucket.saturating_add(u64_at(&value, 16 + 8 * index));
                        }
                    }
                }
            }
        }
        let errors = self.map("errors")?;
        for (id, count) in raw.errors.iter_mut().enumerate() {
            if let Some(per_cpu) =
                errors.lookup_percpu(&(id as u32).to_ne_bytes(), MapFlags::ANY)?
            {
                *count = per_cpu.iter().map(|bytes| u64_at(bytes, 0)).sum();
            }
        }
        raw.at = Instant::now();
        Ok(raw)
    }
}
