use anyhow::{bail, Context, Result};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use std::{
    collections::BTreeMap,
    fs,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    interfaces::Inventory,
    model::{Counters, Health, Kind, Latency, PathKey, Row, Snapshot, BUCKETS},
};

const BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"));
const STAGE_SIZE: usize = 64 + BUCKETS * 8;
const STAT_SIZE: usize = 72 + 3 * STAGE_SIZE;
const GLOBAL_SIZE: usize = 8 * 8;
const PERIOD_KEY_SIZE: usize = 40;
const INTERVAL_LATENCY_SIZE: usize = 48 + BUCKETS * 4;
const INTERVAL_TIMINGS_SIZE: usize = 3 * INTERVAL_LATENCY_SIZE;
const WRITER_SIZE: usize = 2 * 8;
const BATCH_SCRATCH_BYTES: usize = 4 * 1024 * 1024;
const ERROR_NAMES: [&str; 18] = [
    "association_capacity",
    "unrecorded_path_events",
    "interval_capacity",
    "unmatched_queue",
    "unmatched_result",
    "expired_associations",
    "freed_before_completion",
    "unsupported_conversion",
    "map_update_failure",
    "driver_busy",
    "clone_failure",
    "interface_generation_mismatch",
    "fragmentation",
    "reassembly",
    "integrity",
    "unknown_exit",
    "unclassified_forward",
    "newest_contention",
];

#[derive(Clone, Default)]
struct RawLatency {
    samples: u64,
    sum: u64,
    min: u64,
    max: u64,
    newest_at: u64,
    newest_ns: Option<u64>,
    bins: Vec<u64>,
}
impl RawLatency {
    fn merge(&mut self, other: &Self) {
        if other.samples == 0 {
            return;
        }
        self.min = if self.samples == 0 {
            other.min
        } else {
            self.min.min(other.min)
        };
        self.samples = self.samples.saturating_add(other.samples);
        self.sum = self.sum.saturating_add(other.sum);
        self.max = self.max.max(other.max);
        if other.newest_at >= self.newest_at {
            self.newest_at = other.newest_at;
            self.newest_ns = other.newest_ns;
        }
        self.bins.resize(BUCKETS, 0);
        for (a, b) in self.bins.iter_mut().zip(&other.bins) {
            *a = a.saturating_add(*b);
        }
    }
    fn latency(&self) -> Latency {
        let mut result = Latency::from_raw(
            self.samples,
            self.sum,
            self.min,
            self.max,
            self.bins.clone(),
        );
        result.newest_at_ns = (self.samples > 0 && self.newest_at > 0).then_some(self.newest_at);
        result.newest_us = self
            .newest_ns
            .filter(|_| self.samples > 0)
            .map(|ns| ns as f64 / 1_000.0);
        result
    }
}
#[derive(Clone, Default)]
struct RawStats {
    counts: [u64; 8],
    pending: u64,
    stages: [RawLatency; 3],
}
impl RawStats {
    fn parse_traffic<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut result = Self::default();
        for value in values {
            if value.len() != GLOBAL_SIZE {
                bail!("invalid BPF period traffic ABI: {} bytes", value.len());
            }
            for (i, count) in result.counts.iter_mut().enumerate() {
                *count = count.saturating_add(u64_at(value, i * 8)?);
            }
        }
        Ok(result)
    }
    fn parse_timings<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut result = Self::default();
        for value in values {
            if value.len() != INTERVAL_TIMINGS_SIZE {
                bail!("invalid BPF interval timings ABI: {} bytes", value.len());
            }
            for (i, stage) in result.stages.iter_mut().enumerate() {
                let base = i * INTERVAL_LATENCY_SIZE;
                stage.merge_interval(&value[base..base + INTERVAL_LATENCY_SIZE])?;
            }
        }
        Ok(result)
    }
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != STAT_SIZE {
            bail!("invalid BPF statistics ABI: {} bytes", bytes.len());
        }
        let mut result = Self::default();
        for (i, count) in result.counts.iter_mut().enumerate() {
            *count = u64_at(bytes, i * 8)?;
        }
        result.pending = u64_at(bytes, 64)?;
        for (i, stage) in result.stages.iter_mut().enumerate() {
            let base = 72 + i * STAGE_SIZE;
            let seq = u64_at(bytes, base + 32)?;
            let at = u64_at(bytes, base + 40)?;
            let missed = u64_at(bytes, base + 56)?;
            *stage = RawLatency {
                samples: u64_at(bytes, base)?,
                sum: u64_at(bytes, base + 8)?,
                min: u64_at(bytes, base + 16)?.saturating_sub(1),
                max: u64_at(bytes, base + 24)?,
                newest_at: at.max(missed),
                newest_ns: (seq & 1 == 0 && at > 0 && at >= missed)
                    .then(|| u64_at(bytes, base + 48))
                    .transpose()?,
                bins: (0..BUCKETS)
                    .map(|b| u64_at(bytes, base + 64 + b * 8))
                    .collect::<Result<_>>()?,
            };
        }
        Ok(result)
    }
    fn counters(&self) -> Counters {
        counters(self.counts)
    }
    fn merge(&mut self, other: &Self) {
        for (a, b) in self.counts.iter_mut().zip(other.counts) {
            *a = a.saturating_add(b);
        }
        merge_stages(&mut self.stages, &other.stages);
    }
}

impl RawLatency {
    fn merge_interval(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != INTERVAL_LATENCY_SIZE {
            bail!("invalid BPF interval latency ABI: {} bytes", bytes.len());
        }
        let samples = u64_at(bytes, 0)?;
        if samples == 0 {
            return Ok(());
        }
        self.merge(&Self {
            samples,
            sum: u64_at(bytes, 8)?,
            min: u64_at(bytes, 16)?.saturating_sub(1),
            max: u64_at(bytes, 24)?,
            newest_at: u64_at(bytes, 32)?,
            newest_ns: Some(u64_at(bytes, 40)?),
            bins: Vec::new(),
        });
        for (b, bin) in self.bins.iter_mut().enumerate() {
            *bin = bin.saturating_add(u64::from(u32_at(bytes, 48 + b * 4)?));
        }
        Ok(())
    }
}

fn counters(counts: [u64; 8]) -> Counters {
    let [in_packets, in_bytes, out_packets, out_bytes, route, bridge, combo, freed] = counts;
    Counters {
        in_packets,
        in_bytes,
        out_packets,
        out_bytes,
        route,
        bridge,
        combo,
        freed,
    }
}

fn global_counters(values: &[Vec<u8>]) -> Result<Counters> {
    let mut counts = [0u64; 8];
    for value in values {
        if value.len() != GLOBAL_SIZE {
            bail!("invalid BPF global counters ABI: {} bytes", value.len());
        }
        for (i, count) in counts.iter_mut().enumerate() {
            *count = count.saturating_add(u64_at(value, i * 8)?);
        }
    }
    Ok(counters(counts))
}

fn merge_stages(target: &mut [RawLatency; 3], source: &[RawLatency; 3]) {
    for (a, b) in target.iter_mut().zip(source) {
        a.merge(b);
    }
}

struct IntervalCutoff {
    safe_epoch: u64,
    final_partial: bool,
}
impl IntervalCutoff {
    fn read(end_epoch: u64, final_partial: bool, writers: &[Vec<u8>]) -> Result<Self> {
        if writers.is_empty() {
            bail!("missing BPF interval writers");
        }
        let mut safe_epoch = end_epoch;
        for (cpu, value) in writers.iter().enumerate() {
            if value.len() != WRITER_SIZE {
                bail!("invalid BPF interval writer ABI: {} bytes", value.len());
            }
            let depth = u64_at(value, 0)?;
            let epoch = u64_at(value, 8)?;
            if depth > 0 {
                if final_partial {
                    bail!("interval writer still active after detach: CPU {cpu}, depth {depth}, epoch {epoch}; final snapshot cannot consume remaining periods");
                }
                safe_epoch = safe_epoch.min(epoch);
            }
        }
        Ok(Self {
            safe_epoch,
            final_partial,
        })
    }

    fn retires(&self, epoch: u64) -> bool {
        self.final_partial || epoch < self.safe_epoch
    }
}

#[derive(Default)]
struct PeriodSnapshot {
    interval: BTreeMap<PathKey, RawStats>,
    live: BTreeMap<PathKey, RawStats>,
    late_records: u64,
}
impl PeriodSnapshot {
    fn record(
        &mut self,
        path: PathKey,
        epoch: u64,
        value: &RawStats,
        cutoff: &IntervalCutoff,
        next_epoch: u64,
        sealed: &mut BTreeMap<PathKey, RawStats>,
    ) {
        let target = if cutoff.retires(epoch) {
            // Delayed records belong to the snapshot that safely retires them,
            // even if their original interval has already been reported.
            self.interval.entry(path).or_default().merge(value);
            if epoch < next_epoch {
                self.late_records = self.late_records.saturating_add(1);
            }
            sealed
        } else {
            &mut self.live
        };
        target.entry(path).or_default().merge(value);
    }

    fn cumulative_stats(
        &self,
        path: PathKey,
        fallback: &RawStats,
        sealed: &BTreeMap<PathKey, RawStats>,
    ) -> RawStats {
        let mut total = sealed.get(&path).cloned().unwrap_or_default();
        if let Some(live) = self.live.get(&path) {
            total.merge(live);
        }
        // Shared paths retain only capacity fallback plus the current Pending.
        // Fallback has no epoch and cannot be assigned to a closed interval.
        total.merge(fallback);
        total.pending = fallback.pending;
        total
    }

    #[cfg(test)]
    fn cumulative_latency(
        &self,
        path: PathKey,
        total: &RawStats,
        sealed: &BTreeMap<PathKey, RawStats>,
    ) -> [Latency; 3] {
        let stages = self.cumulative_stats(path, total, sealed).stages;
        std::array::from_fn(|i| stages[i].latency())
    }
}

pub fn monotonic_ns() -> u64 {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value);
    }
    value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        bytes
            .get(offset..offset + 8)
            .context("truncated BPF value")?
            .try_into()?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated BPF value")?
            .try_into()?,
    ))
}

struct BatchValues<'a> {
    bytes: &'a [u8],
    stride: usize,
    value_size: usize,
}
impl BatchValues<'_> {
    fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.bytes
            .chunks_exact(self.stride)
            .map(|v| &v[..self.value_size])
    }
}

struct MapBatch {
    cpus: usize,
    key_size: usize,
    value_size: usize,
    stride: usize,
    entry_size: usize,
    batch_size: usize,
    keys: Vec<u8>,
    values: Vec<u8>,
    previous: Vec<u8>,
    next: Vec<u8>,
    has_previous: bool,
    retired: Vec<u8>,
}

impl MapBatch {
    fn new(cpus: usize) -> Self {
        Self {
            cpus,
            key_size: 0,
            value_size: 0,
            stride: 0,
            entry_size: 0,
            batch_size: 0,
            keys: Vec::new(),
            values: Vec::new(),
            previous: Vec::new(),
            next: Vec::new(),
            has_previous: false,
            retired: Vec::new(),
        }
    }

    fn prepare(
        &mut self,
        key_size: usize,
        value_size: usize,
        limit: usize,
        per_cpu: bool,
    ) -> Result<()> {
        if self.cpus == 0 || key_size == 0 || value_size == 0 || limit == 0 {
            bail!("invalid BPF per-CPU batch dimensions");
        }
        self.key_size = key_size;
        self.value_size = value_size;
        self.stride = if per_cpu {
            value_size.checked_add(7).context("BPF value too large")? & !7
        } else {
            value_size
        };
        self.entry_size = self
            .stride
            .checked_mul(if per_cpu { self.cpus } else { 1 })
            .context("BPF CPU count too large")?;
        let bytes_per_entry = self
            .entry_size
            .checked_add(key_size)
            .context("BPF batch too large")?;
        self.batch_size = limit.min((BATCH_SCRATCH_BYTES / bytes_per_entry).max(1));
        self.reserve_batch()?;
        self.previous.resize(key_size.max(4), 0);
        self.next.resize(key_size.max(4), 0);
        self.has_previous = false;
        self.retired.clear();
        Ok(())
    }

    fn reserve_batch(&mut self) -> Result<()> {
        let key_bytes = self
            .batch_size
            .checked_mul(self.key_size)
            .context("BPF batch too large")?;
        let value_bytes = self
            .batch_size
            .checked_mul(self.entry_size)
            .context("BPF batch too large")?;
        // Keep the high-water lengths: switching to the small traffic map must
        // not make the next latency read zero the same large buffer again.
        if self.keys.len() < key_bytes {
            self.keys.resize(key_bytes, 0);
        }
        if self.values.len() < value_bytes {
            self.values.resize(value_bytes, 0);
        }
        Ok(())
    }

    fn grow_batch(&mut self, max_entries: usize) -> Result<()> {
        let size = self.batch_size.saturating_mul(2).min(max_entries);
        if size <= self.batch_size {
            bail!("BPF hash bucket exceeds map capacity");
        }
        self.batch_size = size;
        self.reserve_batch()
    }

    fn visit_entries(
        &mut self,
        count: usize,
        visit: &mut impl FnMut(&[u8], BatchValues<'_>) -> Result<bool>,
    ) -> Result<()> {
        if count > self.batch_size {
            bail!("BPF batch returned too many entries: {count}");
        }
        for index in 0..count {
            let raw = &self.keys[index * self.key_size..(index + 1) * self.key_size];
            let values = BatchValues {
                bytes: &self.values[index * self.entry_size..(index + 1) * self.entry_size],
                stride: self.stride,
                value_size: self.value_size,
            };
            if visit(raw, values)? {
                self.retired.extend_from_slice(raw);
            }
        }
        Ok(())
    }

    fn read(
        &mut self,
        map: &libbpf_rs::MapImpl<'_>,
        limit: usize,
        mut visit: impl FnMut(&[u8], BatchValues<'_>) -> Result<bool>,
    ) -> Result<()> {
        self.prepare(
            map.key_size() as usize,
            map.value_size() as usize,
            limit,
            map.map_type().is_percpu(),
        )?;
        let opts = libbpf_rs::libbpf_sys::bpf_map_batch_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_batch_opts>() as _,
            elem_flags: MapFlags::ANY.bits(),
            flags: MapFlags::ANY.bits(),
        };
        loop {
            let mut count = self.batch_size as u32;
            let previous = if self.has_previous {
                self.previous.as_mut_ptr()
            } else {
                std::ptr::null_mut()
            };
            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_lookup_batch(
                    map.as_fd().as_raw_fd(),
                    previous.cast(),
                    self.next.as_mut_ptr().cast(),
                    self.keys.as_mut_ptr().cast(),
                    self.values.as_mut_ptr().cast(),
                    &mut count,
                    &opts,
                )
            };
            let end = if ret == 0 {
                false
            } else {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::ENOENT) => true,
                    Some(libc::EINTR) => continue,
                    Some(libc::ENOSPC) if count == 0 => {
                        // Hash lookup must fit a whole bucket. Retry the same
                        // cursor with more room; the memory budget is a target.
                        self.grow_batch(map.max_entries() as usize)?;
                        continue;
                    }
                    _ => return Err(error.into()),
                }
            };
            // ENOENT can accompany the final nonempty batch, even a full one.
            self.visit_entries(count as usize, &mut visit)?;
            if end || count == 0 {
                break;
            }
            self.previous.copy_from_slice(&self.next);
            self.has_previous = true;
        }
        // Retire only after the whole traversal, so deleting a hash bucket
        // cannot invalidate the opaque cursor used for the next batch.
        for raw in self.retired.chunks_exact(self.key_size) {
            map.delete(raw)?;
        }
        Ok(())
    }
}
fn key(bytes: &[u8]) -> Result<PathKey> {
    if bytes.len() < 32 {
        bail!("invalid BPF path key");
    }
    let word = |off| u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap());
    Ok(PathKey {
        kind: match word(0) {
            1 => Kind::Input,
            2 => Kind::Output,
            3 => Kind::Forward,
            n => bail!("invalid path kind {n}"),
        },
        ingress: word(4),
        egress: word(8),
        netns: word(12),
        ingress_generation: u64_at(bytes, 16)?,
        egress_generation: u64_at(bytes, 24)?,
    })
}

pub struct Collector {
    object: Object,
    links: Vec<Link>,
    inventory: Inventory,
    synchronized: BTreeMap<u32, (u64, bool)>,
    pub started_ns: u64,
    stopped_ns: Option<u64>,
    cleanup_ns: u64,
    interval_ns: u64,
    consumed_ns: u64,
    next_epoch: u64,
    sequence: u64,
    capacity: u32,
    paths: u32,
    late_interval_records: u64,
    // Periods exist only for admitted paths. One merged entry per path keeps
    // this cache bounded by the path capacity, regardless of capture duration.
    sealed: BTreeMap<PathKey, RawStats>,
    batch: MapBatch,
}

impl Collector {
    pub fn attach(names: &[String], interval: f64, capacity: u32, paths: u32) -> Result<Self> {
        if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            bail!(
                "kernel BTF is unavailable; skbtop requires Linux 6.6+ with CONFIG_DEBUG_INFO_BTF"
            );
        }
        let inventory = Inventory::new(names)?;
        let mut open = ObjectBuilder::default()
            .open_memory(BPF)
            .context("open skbtop CO-RE object")?;
        for mut map in open.maps_mut() {
            let limit = match map.name().to_str() {
                Some("paths") => paths,
                Some("periods") => paths.checked_mul(4).context("path capacity too large")?,
                Some("interval_latency") => {
                    paths.checked_mul(4).context("path capacity too large")?
                }
                Some("origins" | "transmits") => capacity,
                _ => continue,
            };
            map.set_max_entries(limit)?;
        }
        let object = open.load().context("load skbtop: Linux 6.6+, BTF, required skb/IP/bridge probes and BPF/tracing permissions are required")?;
        let interval_ns = (interval * 1_000_000_000.0) as u64;
        let mut this = Self {
            object,
            links: Vec::new(),
            inventory,
            synchronized: BTreeMap::new(),
            started_ns: 0,
            stopped_ns: None,
            cleanup_ns: 0,
            interval_ns,
            consumed_ns: 0,
            next_epoch: 0,
            sequence: 0,
            capacity,
            paths,
            late_interval_records: 0,
            sealed: BTreeMap::new(),
            batch: MapBatch::new(libbpf_rs::num_possible_cpus()?),
        };
        this.refresh_interfaces()?;
        for prog in this.object.progs_mut() {
            let name = prog.name().to_string_lossy().into_owned();
            if name == "cleanup" {
                continue;
            }
            let link = prog.attach();
            this.links.push(link.with_context(|| {
                format!("attach {name}; required kernel observation point unavailable")
            })?);
        }
        this.started_ns = monotonic_ns();
        let netns = fs::metadata("/proc/self/ns/net")?.ino() as u32;
        let mut config = Vec::with_capacity(24);
        config.extend(netns.to_ne_bytes());
        config.extend(capacity.to_ne_bytes());
        config.extend(interval_ns.to_ne_bytes());
        config.extend(this.started_ns.to_ne_bytes());
        this.map(".data.scope")?
            .update(&0u32.to_ne_bytes(), &config, MapFlags::ANY)?;
        Ok(this)
    }

    fn map(&self, name: &str) -> Result<libbpf_rs::MapImpl<'_>> {
        self.object
            .maps()
            .find(|m| m.name() == name)
            .with_context(|| format!("missing BPF map {name}"))
    }

    pub fn refresh_interfaces(&mut self) -> Result<()> {
        self.inventory.refresh()?;
        let active: BTreeMap<_, _> = self
            .inventory
            .active()
            .into_iter()
            .map(|(i, g, e)| (i, (g, e)))
            .collect();
        let map = self.map("interfaces")?;
        for index in self.synchronized.keys().filter(|i| !active.contains_key(i)) {
            map.delete(&index.to_ne_bytes())?;
        }
        for (&index, &(generation, enabled)) in &active {
            if self.synchronized.get(&index) == Some(&(generation, enabled)) {
                continue;
            }
            let mut value = Vec::with_capacity(24);
            value.extend(generation.to_ne_bytes());
            value.extend(u32::from(enabled).to_ne_bytes());
            value.extend(0u32.to_ne_bytes());
            value.extend(0u64.to_ne_bytes());
            map.update(&index.to_ne_bytes(), &value, MapFlags::ANY)?;
        }
        self.synchronized = active;
        let now = monotonic_ns();
        if self.started_ns > 0
            && self.stopped_ns.is_none()
            && now.saturating_sub(self.cleanup_ns) >= 1_000_000_000
        {
            let packet = [0u8; 64];
            self.object
                .progs_mut()
                .find(|p| p.name() == "cleanup")
                .context("cleanup program missing")?
                .test_run(libbpf_rs::ProgramInput {
                    data_in: Some(&packet),
                    ..Default::default()
                })
                .context("expire skb associations")?;
            self.cleanup_ns = now;
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.stopped_ns.is_none() {
            let mut scope = self
                .map(".data.scope")?
                .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
                .context("missing collection scope")?;
            // Stop new observations without changing identities read by hooks
            // that were already running when the capture was stopped.
            scope[4..8].fill(0);
            self.map(".data.scope")?
                .update(&0u32.to_ne_bytes(), &scope, MapFlags::ANY)?;
            self.stopped_ns = Some(monotonic_ns());
            self.links.clear();
        }
        Ok(())
    }

    pub fn snapshot(&mut self, final_partial: bool) -> Result<Snapshot> {
        if final_partial {
            self.stop()?;
        }
        self.refresh_interfaces()?;
        let elapsed_ns = self
            .stopped_ns
            .unwrap_or_else(monotonic_ns)
            .saturating_sub(self.started_ns);
        let end_epoch = elapsed_ns / self.interval_ns;
        // A writer registers before choosing its epoch. Readers that start
        // after this check cannot write an epoch older than end_epoch. While
        // depth is nonzero, C must publish a conservative oldest-active epoch,
        // including during guard initialization and nested writes.
        let writers = self
            .map("interval_writers")?
            .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .context("missing BPF interval writers")?;
        let cutoff = IntervalCutoff::read(end_epoch, final_partial, &writers)?;
        let end_ns = if final_partial {
            elapsed_ns
        } else {
            end_epoch * self.interval_ns
        };
        let interval_secs = end_ns.saturating_sub(self.consumed_ns) as f64 / 1_000_000_000.0;
        let mut period_snapshot = PeriodSnapshot::default();
        {
            let periods = self
                .object
                .maps()
                .find(|m| m.name() == "periods")
                .context("missing BPF map periods")?;
            self.batch.read(&periods, 128, |raw, values| {
                if raw.len() != PERIOD_KEY_SIZE {
                    bail!("invalid BPF period key: {} bytes", raw.len());
                }
                let epoch = u64_at(raw, 32)?;
                let path = key(raw)?;
                let stats = RawStats::parse_traffic(values.iter())?;
                period_snapshot.record(
                    path,
                    epoch,
                    &stats,
                    &cutoff,
                    self.next_epoch,
                    &mut self.sealed,
                );
                Ok(cutoff.retires(epoch))
            })?;
        }
        {
            let latencies = self
                .object
                .maps()
                .find(|m| m.name() == "interval_latency")
                .context("missing BPF map interval_latency")?;
            // Read keys and all per-CPU values in kernel batches. This avoids
            // one syscall per CPU shard on high path counts.
            self.batch.read(&latencies, 64, |raw, values| {
                if raw.len() != PERIOD_KEY_SIZE {
                    bail!("invalid BPF interval latency key: {} bytes", raw.len());
                }
                let epoch = u64_at(raw, 32)?;
                let path = key(raw)?;
                let merged = RawStats::parse_timings(values.iter())?;
                period_snapshot.record(
                    path,
                    epoch,
                    &merged,
                    &cutoff,
                    self.next_epoch,
                    &mut self.sealed,
                );
                Ok(cutoff.retires(epoch))
            })?;
        }
        self.late_interval_records = self
            .late_interval_records
            .saturating_add(period_snapshot.late_records);
        let mut rows = Vec::new();
        let totals = self
            .object
            .maps()
            .find(|m| m.name() == "paths")
            .context("missing BPF map paths")?;
        self.batch.read(&totals, 128, |raw, values| {
            let path = key(raw)?;
            let fallback =
                RawStats::parse(values.iter().next().context("missing BPF path value")?)?;
            let total = period_snapshot.cumulative_stats(path, &fallback, &self.sealed);
            let delta = period_snapshot.interval.remove(&path).unwrap_or_default();
            let denominator = interval_secs.max(f64::EPSILON);
            rows.push(Row {
                key: path,
                ingress_name: self.inventory.label(path.ingress, path.ingress_generation),
                egress_name: self.inventory.label(path.egress, path.egress_generation),
                interval: delta.counters(),
                total: total.counters(),
                latency: std::array::from_fn(|i| delta.stages[i].latency()),
                total_latency: std::array::from_fn(|i| total.stages[i].latency()),
                pending: total.pending,
                pps: delta.counts[2] as f64 / denominator,
                bps: delta.counts[3] as f64 * 8.0 / denominator,
                in_pps: delta.counts[0] as f64 / denominator,
                in_bps: delta.counts[1] as f64 * 8.0 / denominator,
            });
            Ok(false)
        })?;
        rows.sort_by_key(|r| r.key);
        let mut errors = BTreeMap::new();
        let error_map = self.map("errors")?;
        for (i, name) in ERROR_NAMES.iter().enumerate() {
            let mut count = 0u64;
            if let Some(values) =
                error_map.lookup_percpu(&(i as u32).to_ne_bytes(), MapFlags::ANY)?
            {
                for value in values {
                    count = count.saturating_add(u64_at(&value, 0)?);
                }
            }
            errors.insert((*name).into(), count);
        }
        errors.insert("interface_event_gaps".into(), self.inventory.gaps);
        errors.insert("late_interval_records".into(), self.late_interval_records);
        let inflight = self
            .map("gauges")?
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .map(|v| u64_at(&v, 0))
            .transpose()?
            .unwrap_or(0);
        let global_values = self
            .map("global")?
            .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
            .context("missing BPF global counters")?;
        let global = global_counters(&global_values)?;
        self.sequence += 1;
        self.next_epoch = end_epoch;
        self.consumed_ns = end_ns;
        Ok(Snapshot {
            sequence: self.sequence,
            elapsed_secs: end_ns as f64 / 1_000_000_000.0,
            interval_secs,
            unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
            rows,
            interfaces: self.inventory.all(),
            health: Health {
                inflight,
                inflight_capacity: self.capacity as u64,
                path_capacity: self.paths as u64,
                global,
                errors,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> PathKey {
        PathKey {
            kind: Kind::Forward,
            ingress: 2,
            egress: 3,
            netns: 42,
            ingress_generation: 10,
            egress_generation: 20,
        }
    }

    fn sample(ns: u64, at: u64) -> RawStats {
        let mut bins = vec![0; BUCKETS];
        bins[crate::model::bucket_index(ns)] = 1;
        RawStats {
            counts: [1, 64, 1, 64, 1, 0, 0, 0],
            stages: std::array::from_fn(|_| RawLatency {
                samples: 1,
                sum: ns,
                min: ns,
                max: ns,
                newest_at: at,
                newest_ns: Some(ns),
                bins: bins.clone(),
            }),
            ..Default::default()
        }
    }

    fn writer(depth: u64, epoch: u64) -> Vec<u8> {
        [depth.to_ne_bytes(), epoch.to_ne_bytes()].concat()
    }

    #[test]
    fn batch_views_strip_cpu_padding_and_ignore_unused_tail() {
        let mut batch = MapBatch::new(2);
        batch.prepare(4, 9, 2, true).unwrap();
        batch.keys[..8].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
        batch.values.fill(0xff);
        batch.values[..9].fill(3);
        batch.values[16..25].fill(7);
        let mut visited = 0;
        batch
            .visit_entries(1, &mut |key, values| {
                visited += 1;
                assert_eq!(key, [1, 0, 0, 0]);
                let values: Vec<_> = values.iter().collect();
                assert_eq!(values, [&[3; 9][..], &[7; 9][..]]);
                Ok(true)
            })
            .unwrap();
        assert_eq!(visited, 1);
        assert_eq!(batch.retired, [1, 0, 0, 0]);
        batch
            .visit_entries(0, &mut |_, _| panic!("empty batch visited a key"))
            .unwrap();
        assert!(batch.visit_entries(3, &mut |_, _| Ok(false)).is_err());
    }

    #[test]
    fn shared_batch_values_are_single_shards_without_cpu_alignment() {
        let mut batch = MapBatch::new(64);
        batch.prepare(4, 9, 2, false).unwrap();
        batch.keys[..8].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
        batch.values[..9].fill(3);
        batch.values[9..18].fill(7);
        let mut seen = Vec::new();
        batch
            .visit_entries(2, &mut |key, values| {
                let shards: Vec<_> = values.iter().collect();
                assert_eq!(shards.len(), 1);
                assert_eq!(shards[0].len(), 9);
                seen.push((u32_at(key, 0)?, shards[0][0]));
                Ok(false)
            })
            .unwrap();
        assert_eq!(seen, [(1, 3), (2, 7)]);
    }

    #[test]
    fn high_cpu_batches_fit_budget_or_one_entry_and_reuse_buffers() {
        for cpus in [1, 16, 64, 256, 4096] {
            let mut batch = MapBatch::new(cpus);
            batch
                .prepare(PERIOD_KEY_SIZE, INTERVAL_TIMINGS_SIZE, 64, true)
                .unwrap();
            let bytes = batch.batch_size * (batch.entry_size + batch.key_size);
            assert!(bytes <= BATCH_SCRATCH_BYTES || batch.batch_size == 1);
            assert!((1..=64).contains(&batch.batch_size));
            let pointer = batch.values.as_ptr();
            let length = batch.values.len();
            batch.values[0] = 123;
            batch.retired.extend_from_slice(&[0; PERIOD_KEY_SIZE]);
            batch.has_previous = true;
            batch
                .prepare(PERIOD_KEY_SIZE, GLOBAL_SIZE, 128, true)
                .unwrap();
            batch
                .prepare(PERIOD_KEY_SIZE, INTERVAL_TIMINGS_SIZE, 64, true)
                .unwrap();
            assert_eq!(batch.values.as_ptr(), pointer);
            assert_eq!(batch.values.len(), length);
            assert_eq!(batch.values[0], 123);
            assert!(batch.retired.is_empty());
            assert!(!batch.has_previous);
        }
        assert!(MapBatch::new(0).prepare(40, 64, 128, true).is_err());
        assert!(MapBatch::new(16).prepare(40, usize::MAX, 64, true).is_err());
        assert!(MapBatch::new(16).prepare(40, 64, 0, true).is_err());
    }

    #[test]
    fn crowded_hash_bucket_growth_preserves_cursor_and_retired_keys() {
        let mut batch = MapBatch::new(2);
        batch.prepare(4, 64, 1, true).unwrap();
        batch.previous.copy_from_slice(&9u32.to_ne_bytes());
        batch.has_previous = true;
        batch.retired.extend_from_slice(&3u32.to_ne_bytes());
        batch.grow_batch(3).unwrap();
        assert_eq!(batch.batch_size, 2);
        assert_eq!(batch.previous, 9u32.to_ne_bytes());
        assert!(batch.has_previous);
        assert_eq!(batch.retired, 3u32.to_ne_bytes());
        batch.grow_batch(3).unwrap();
        assert_eq!(batch.batch_size, 3);
        assert!(batch.grow_batch(3).is_err());
    }

    #[test]
    fn streaming_batches_keep_epochs_isolated_and_save_only_retired_keys() {
        let mut batch = MapBatch::new(2);
        batch
            .prepare(PERIOD_KEY_SIZE, GLOBAL_SIZE, 1, true)
            .unwrap();
        let cutoff = IntervalCutoff::read(2, false, &[writer(0, 0)]).unwrap();
        let mut snapshot = PeriodSnapshot::default();
        let mut sealed = BTreeMap::new();
        let p = path();
        batch.keys[..32].copy_from_slice(
            &[
                3u32.to_ne_bytes().as_slice(),
                p.ingress.to_ne_bytes().as_slice(),
                p.egress.to_ne_bytes().as_slice(),
                p.netns.to_ne_bytes().as_slice(),
                p.ingress_generation.to_ne_bytes().as_slice(),
                p.egress_generation.to_ne_bytes().as_slice(),
            ]
            .concat(),
        );
        for (epoch, amount) in [(0u64, 3u64), (2, 7), (1, 11)] {
            batch.keys[32..40].copy_from_slice(&epoch.to_ne_bytes());
            for cpu in 0..2 {
                for count in 0..8 {
                    let offset = cpu * GLOBAL_SIZE + count * 8;
                    batch.values[offset..offset + 8].copy_from_slice(&amount.to_ne_bytes());
                }
            }
            batch
                .visit_entries(1, &mut |raw, values| {
                    let epoch = u64_at(raw, 32)?;
                    let stats = RawStats::parse_traffic(values.iter())?;
                    snapshot.record(key(raw)?, epoch, &stats, &cutoff, 0, &mut sealed);
                    Ok(cutoff.retires(epoch))
                })
                .unwrap();
        }
        assert_eq!(snapshot.interval[&p].counts, [28; 8]);
        assert_eq!(snapshot.live[&p].counts, [14; 8]);
        assert_eq!(sealed[&p].counts, [28; 8]);
        assert_eq!(
            snapshot
                .cumulative_stats(p, &RawStats::default(), &sealed)
                .counts,
            [42; 8]
        );
        let epochs: Vec<_> = batch
            .retired
            .as_chunks::<PERIOD_KEY_SIZE>()
            .0
            .iter()
            .map(|raw| u64_at(raw, 32).unwrap())
            .collect();
        assert_eq!(epochs, [0, 1]);
    }

    #[test]
    fn borrowed_interval_histograms_preserve_zero_newest_and_saturate() {
        let mut bytes = vec![0; INTERVAL_LATENCY_SIZE];
        let mut result = RawLatency::default();
        result.merge_interval(&bytes).unwrap();
        assert!(result.bins.is_empty());
        bytes[..8].copy_from_slice(&1u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&1u64.to_ne_bytes());
        bytes[32..40].copy_from_slice(&9u64.to_ne_bytes());
        bytes[48..52].copy_from_slice(&1u32.to_ne_bytes());
        result.merge_interval(&bytes).unwrap();
        assert_eq!(result.min, 0);
        assert_eq!(result.newest_ns, Some(0));
        assert_eq!(result.newest_at, 9);
        result.samples = u64::MAX;
        result.bins[0] = u64::MAX;
        result.merge_interval(&bytes).unwrap();
        assert_eq!(result.samples, u64::MAX);
        assert_eq!(result.bins[0], u64::MAX);
        assert!(result.merge_interval(&bytes[..48]).is_err());
    }

    #[test]
    fn open_epochs_are_not_accumulated_again_on_each_refresh() {
        let path = path();
        let value = sample(1000, 10);
        let mut sealed = BTreeMap::new();
        for _ in 0..3 {
            let cutoff = IntervalCutoff::read(0, false, &[writer(0, 0)]).unwrap();
            let mut snapshot = PeriodSnapshot::default();
            snapshot.record(path, 0, &value, &cutoff, 0, &mut sealed);
            assert!(snapshot.interval.is_empty());
            assert!(sealed.is_empty());
            assert_eq!(
                snapshot.cumulative_latency(path, &RawStats::default(), &sealed)[2].samples,
                1
            );
            assert_eq!(
                snapshot
                    .cumulative_stats(path, &RawStats::default(), &sealed)
                    .counts[2],
                1
            );
        }
        let cutoff = IntervalCutoff::read(1, false, &[writer(0, 0)]).unwrap();
        let mut snapshot = PeriodSnapshot::default();
        snapshot.record(path, 0, &value, &cutoff, 0, &mut sealed);
        assert_eq!(snapshot.interval[&path].counts[2], 1);
        assert_eq!(
            snapshot.cumulative_latency(path, &RawStats::default(), &sealed)[2].samples,
            1
        );
        let next = PeriodSnapshot::default();
        assert_eq!(
            next.cumulative_latency(path, &RawStats::default(), &sealed)[2].samples,
            1
        );
        assert_eq!(
            next.cumulative_stats(path, &RawStats::default(), &sealed)
                .counts[2],
            1
        );
    }

    #[test]
    fn active_writer_defers_retirement_and_late_data_is_preserved() {
        let path = path();
        let value = sample(2000, 20);
        let mut sealed = BTreeMap::new();
        let cutoff = IntervalCutoff::read(3, false, &[writer(0, 3), writer(2, 0)]).unwrap();
        assert!(!cutoff.retires(0));
        let mut busy = PeriodSnapshot::default();
        busy.record(path, 0, &value, &cutoff, 2, &mut sealed);
        assert_eq!(busy.late_records, 0);
        assert!(busy.interval.is_empty());
        assert!(sealed.is_empty());
        let cutoff = IntervalCutoff::read(3, false, &[writer(0, 0)]).unwrap();
        let mut resumed = PeriodSnapshot::default();
        resumed.record(path, 0, &value, &cutoff, 3, &mut sealed);
        assert_eq!(resumed.late_records, 1);
        assert_eq!(resumed.interval[&path].counts[2], 1);
        assert_eq!(
            resumed.cumulative_latency(path, &RawStats::default(), &sealed)[2].samples,
            1
        );
    }

    #[test]
    fn final_partial_merges_all_epochs_and_overflow_without_losing_extrema() {
        let path = path();
        let mut sealed = BTreeMap::new();
        let cutoff = IntervalCutoff::read(0, true, &[writer(0, 0)]).unwrap();
        let mut snapshot = PeriodSnapshot::default();
        snapshot.record(path, 0, &sample(0, 10), &cutoff, 0, &mut sealed);
        snapshot.record(path, 1, &sample(5000, 30), &cutoff, 0, &mut sealed);
        let fallback = sample(2000, 20);
        let total = snapshot.cumulative_latency(path, &fallback, &sealed);
        assert_eq!(total[2].samples, 3);
        assert_eq!(total[2].sum_ns, 7000);
        assert_eq!(total[2].min_us, Some(0.0));
        assert_eq!(total[2].max_us, Some(5.0));
        assert_eq!(total[2].newest_us, Some(5.0));
        assert_eq!(total[2].newest_at_ns, Some(30));
        assert_eq!(total[2].histogram.iter().sum::<u64>(), 3);
        assert_eq!(snapshot.interval[&path].counts[2], 2);
        let cumulative = snapshot.cumulative_stats(path, &fallback, &sealed);
        assert_eq!(cumulative.counts[2], 3);
        assert_eq!(cumulative.counts[3], 192);
    }

    #[test]
    fn grouped_percpu_timings_and_traffic_merge_without_cross_stage_mixup() {
        let traffic = |n: u64| [n; 8].into_iter().flat_map(u64::to_ne_bytes).collect();
        let stats =
            RawStats::parse_traffic([traffic(3), traffic(7)].iter().map(Vec::as_slice)).unwrap();
        assert_eq!(stats.counts, [10; 8]);
        assert!(RawStats::parse_traffic([vec![0; STAT_SIZE]].iter().map(Vec::as_slice)).is_err());
        assert!(RawStats::parse_timings(
            [vec![0; INTERVAL_LATENCY_SIZE]].iter().map(Vec::as_slice)
        )
        .is_err());
        assert_eq!(INTERVAL_TIMINGS_SIZE, 3216);
        let timings = |at: u64| {
            let mut bytes = vec![0; INTERVAL_TIMINGS_SIZE];
            for stage in 0..3 {
                let ns = (stage + 1) as u64 * at;
                let base = stage * INTERVAL_LATENCY_SIZE;
                for (offset, value) in [
                    (0, 1u64),
                    (8, ns),
                    (16, ns + 1),
                    (24, ns),
                    (32, at),
                    (40, ns),
                ] {
                    bytes[base + offset..base + offset + 8].copy_from_slice(&value.to_ne_bytes());
                }
                let bin = base + 48 + crate::model::bucket_index(ns) * 4;
                bytes[bin..bin + 4].copy_from_slice(&1u32.to_ne_bytes());
            }
            bytes
        };
        let group =
            RawStats::parse_timings([timings(10), timings(20)].iter().map(Vec::as_slice)).unwrap();
        for (i, stage) in group.stages.iter().enumerate() {
            assert_eq!(stage.samples, 2);
            assert_eq!(stage.sum, (i + 1) as u64 * 30);
            assert_eq!(stage.min, (i + 1) as u64 * 10);
            assert_eq!(stage.max, (i + 1) as u64 * 20);
            assert_eq!(stage.newest_ns, Some((i + 1) as u64 * 20));
            assert_eq!(stage.bins.iter().sum::<u64>(), 2);
        }
        let path = path();
        let cutoff = IntervalCutoff::read(1, false, &[writer(0, 0)]).unwrap();
        let mut sealed = BTreeMap::new();
        let mut snapshot = PeriodSnapshot::default();
        snapshot.record(path, 0, &stats, &cutoff, 0, &mut sealed);
        snapshot.record(path, 0, &group, &cutoff, 0, &mut sealed);
        let fallback = RawStats {
            counts: [2; 8],
            pending: 5,
            ..Default::default()
        };
        for _ in 0..3 {
            let total = snapshot.cumulative_stats(path, &fallback, &sealed);
            assert_eq!(total.counts, [12; 8]);
            assert_eq!(total.pending, 5);
            assert_eq!(total.stages[2].samples, 2);
        }
        assert_eq!(snapshot.interval[&path].counts, [10; 8]);
    }

    #[test]
    fn interval_cutoff_checks_guards_and_final_detach() {
        assert!(IntervalCutoff::read(3, true, &[writer(1, 0)]).is_err());
        assert!(IntervalCutoff::read(3, false, &[]).is_err());
        assert!(IntervalCutoff::read(3, false, &[vec![0; 8]]).is_err());
        let cutoff = IntervalCutoff::read(3, false, &[writer(1, 2), writer(0, 0)]).unwrap();
        assert!(cutoff.retires(1));
        assert!(!cutoff.retires(2));
        assert!(!cutoff.retires(3));
    }

    #[test]
    fn compact_global_percpu_counters_are_summed_and_abi_is_checked() {
        let values = |count: u64| [count; 8].into_iter().flat_map(u64::to_ne_bytes).collect();
        let total = global_counters(&[values(3), values(7)]).unwrap();
        assert_eq!(total.in_packets, 10);
        assert_eq!(total.out_bytes, 10);
        assert_eq!(total.freed, 10);
        assert!(global_counters(&[vec![0; 8]]).is_err());
        assert!(global_counters(&[vec![0; STAT_SIZE]]).is_err());
        assert_eq!(
            global_counters(&[values(u64::MAX), values(1)])
                .unwrap()
                .in_packets,
            u64::MAX
        );
    }

    #[test]
    fn histogram_merge_keeps_samples_not_mean_percentiles() {
        let mut a = RawLatency {
            samples: 100,
            sum: 100_000,
            min: 1000,
            max: 1000,
            newest_at: 10,
            newest_ns: Some(1000),
            bins: vec![0; BUCKETS],
        };
        a.bins[crate::model::bucket_index(1000)] = 100;
        let mut b = RawLatency {
            samples: 1,
            sum: 1_000_000,
            min: 1_000_000,
            max: 1_000_000,
            newest_at: 20,
            newest_ns: Some(1_000_000),
            bins: vec![0; BUCKETS],
        };
        b.bins[crate::model::bucket_index(1_000_000)] = 1;
        a.merge(&b);
        assert_eq!(a.samples, 101);
        assert!(a.latency().p99_us.unwrap() < 2.0);
        assert_eq!(a.max, 1_000_000);
        assert_eq!(a.latency().newest_us, Some(1000.0));
        b.newest_at = 5;
        b.newest_ns = Some(7);
        a.merge(&b);
        assert_eq!(a.latency().newest_us, Some(1000.0));
        b.newest_at = 30;
        b.newest_ns = None;
        a.merge(&b);
        assert_eq!(a.latency().newest_us, None);
        assert_eq!(a.latency().newest_at_ns, Some(30));
    }
    #[test]
    fn bpf_abi_lengths_are_checked() {
        assert_eq!(STAT_SIZE, 6408);
        assert!(RawStats::parse(&vec![0; STAT_SIZE]).is_ok());
        assert!(RawStats::parse(&[0; 8]).is_err());
        assert!(key(&[0; 32]).is_err());
    }

    #[test]
    fn newest_abi_preserves_zero_duration_and_rejects_incomplete_updates() {
        let mut bytes = vec![0; STAT_SIZE];
        let base = 72 + 2 * STAGE_SIZE;
        let set = |bytes: &mut [u8], offset, value: u64| {
            bytes[base + offset..base + offset + 8].copy_from_slice(&value.to_ne_bytes())
        };
        set(&mut bytes, 0, 1);
        set(&mut bytes, 32, 2);
        set(&mut bytes, 40, 100);
        set(&mut bytes, 48, 0);
        let read = |bytes: &[u8]| RawStats::parse(bytes).unwrap().stages[2].latency();
        assert_eq!(read(&bytes).newest_us, Some(0.0));
        assert_eq!(read(&bytes).newest_at_ns, Some(100));
        set(&mut bytes, 32, 3);
        assert_eq!(read(&bytes).newest_us, None);
        set(&mut bytes, 32, 4);
        set(&mut bytes, 56, 101);
        assert_eq!(read(&bytes).newest_us, None);
        assert_eq!(read(&bytes).newest_at_ns, Some(101));
        set(&mut bytes, 40, 102);
        set(&mut bytes, 48, 1234);
        assert_eq!(read(&bytes).newest_us, Some(1.234));
    }
}
