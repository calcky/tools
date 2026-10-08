use crate::kernel::MapMeta;
use anyhow::{bail, Context, Result};
use libbpf_rs::{libbpf_sys, MapHandle, MapType};
use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    os::fd::{AsFd, AsRawFd},
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_MAPS: usize = 8192;
const SCAN_MEMORY: usize = 16 * 1024 * 1024;
const SCAN_TIME: Duration = Duration::from_secs(2);

unsafe extern "C" {
    fn bpfmap_count_open(data: *const u8, len: usize) -> *mut c_void;
    fn bpfmap_count_close(reader: *mut c_void);
    fn bpfmap_count_read(reader: *mut c_void, out: *mut Record, capacity: usize) -> i32;
    fn bpfmap_count_map_ids(reader: *mut c_void, ids: *mut u32, capacity: usize) -> usize;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Kernel,
    Slots,
    Occupied,
    PartialSlots,
    Bytes,
    Scan,
    PartialScan,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct MapCount {
    pub value: Option<u64>,
    pub source: Source,
    pub scanned: u32,
    pub measured: Instant,
    pub duration: Duration,
    pub note: String,
}

impl MapCount {
    pub fn fallback(info: &MapMeta) -> Self {
        let slots = matches!(
            info.ty,
            MapType::Array | MapType::PercpuArray | MapType::StructOps
        );
        Self {
            value: slots.then_some(u64::from(info.max_entries)),
            source: if slots {
                Source::Slots
            } else {
                Source::Unknown
            },
            scanned: 0,
            measured: Instant::now(),
            duration: Duration::ZERO,
            note: if slots {
                "Fixed slots; zero values and per-CPU copies do not change this count"
            } else if info.ty == MapType::BloomFilter {
                "Bloom filters do not retain a recoverable distinct-element count"
            } else {
                "Count unavailable for this type/kernel; unsupported does not mean empty"
            }
            .into(),
        }
    }

    pub fn label(&self) -> String {
        let Some(value) = self.value else {
            return "-".into();
        };
        match self.source {
            Source::Slots => format!("{value} slots"),
            Source::Bytes => format!("{value} B"),
            Source::PartialSlots | Source::PartialScan => format!("{value} part"),
            _ => value.to_string(),
        }
    }

    pub fn description(&self) -> String {
        let source = match self.source {
            Source::Kernel => "kernel counter",
            Source::Slots => "fixed slots",
            Source::Occupied => "occupied slots",
            Source::PartialSlots => "occupied slots, incomplete",
            Source::Bytes => "buffer used bytes (includes record overhead)",
            Source::Scan => "distinct keys, completed scan",
            Source::PartialScan => "distinct keys, incomplete scan",
            Source::Unknown => "unavailable",
        };
        let age = if matches!(self.source, Source::Slots | Source::Unknown) {
            String::new()
        } else {
            format!(" | {:.1}s ago", self.measured.elapsed().as_secs_f64())
        };
        let scan = if self.scanned == 0 {
            String::new()
        } else {
            format!(" | {} scanned", self.scanned)
        };
        format!("{} | {}{}{}", self.label(), source, scan, age)
    }
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Record {
    id: u32,
    ty: u32,
    capacity: u32,
    kind: u32,
    count: i64,
    scanned: u32,
    reserved: u32,
}

fn decode(record: Record, duration: Duration) -> MapCount {
    let source = match record.kind {
        1 => Source::Kernel,
        2 => Source::Slots,
        3 => Source::Occupied,
        4 => Source::PartialSlots,
        5 => Source::Bytes,
        _ => Source::Unknown,
    };
    let suspicious =
        record.count < 0 || (record.kind != 0 && record.count as u64 > u64::from(record.capacity));
    let value = (source != Source::Unknown && !suspicious).then_some(record.count as u64);
    MapCount {
        value,
        source: if suspicious { Source::Unknown } else { source },
        scanned: record.scanned,
        measured: Instant::now(),
        duration,
        note: if suspicious {
            "Counter outside capacity; possibly concurrent update, not clamped"
        } else {
            match source {
                Source::Kernel => {
                    "Kernel-maintained count; concurrent changes are not an atomic snapshot"
                }
                Source::Slots => "Fixed slots, not nonzero or application-valid values",
                Source::Occupied => {
                    "Non-null references, not socket/packet totals; not an atomic snapshot"
                }
                Source::PartialSlots => "Slot scan budget reached; this is not the whole-map count",
                Source::Bytes => {
                    "Reserved/used buffer bytes, including headers and padding; not record count"
                }
                _ => "No supported read-only count; unavailable does not mean empty",
            }
        }
        .into(),
    }
}

struct Reader(*mut c_void);

impl Reader {
    fn open() -> Result<Self> {
        let object = include_bytes!(concat!(env!("OUT_DIR"), "/count.bpf.o"));
        let ptr = unsafe { bpfmap_count_open(object.as_ptr(), object.len()) };
        if ptr.is_null() {
            bail!("count iterator unavailable: requires kernel BTF, map iterator/kfunc and BPF privileges");
        }
        Ok(Self(ptr))
    }

    fn snapshot(&self) -> Result<Snapshot> {
        let mut records = vec![Record::default(); MAX_MAPS];
        let start = Instant::now();
        let count = unsafe { bpfmap_count_read(self.0, records.as_mut_ptr(), records.len()) };
        let duration = start.elapsed();
        if count < 0 {
            return Err(std::io::Error::from_raw_os_error(-count)).context("read map counts");
        }
        let mut internal = [0_u32; 16];
        let internal_len =
            unsafe { bpfmap_count_map_ids(self.0, internal.as_mut_ptr(), internal.len()) };
        let internal = internal[..internal_len].to_vec();
        let counts = records[..count as usize]
            .iter()
            .filter(|record| !internal.contains(&record.id))
            .map(|record| (record.id, decode(*record, duration)))
            .collect();
        Ok(Snapshot {
            counts,
            internal,
            duration,
            error: None,
        })
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        unsafe { bpfmap_count_close(self.0) };
    }
}

pub fn scannable(ty: MapType) -> bool {
    matches!(
        ty,
        MapType::Hash
            | MapType::PercpuHash
            | MapType::LruHash
            | MapType::LruPercpuHash
            | MapType::LpmTrie
            | MapType::HashOfMaps
            | MapType::Sockhash
            | MapType::StackTrace
            | MapType::CgroupStorage
            | MapType::PercpuCgroupStorage
    )
}

fn scan(info: &MapMeta) -> Result<MapCount> {
    if !scannable(info.ty) {
        bail!("This type has no non-destructive key scan; counts use the iterator when supported");
    }
    let key_size = info.key_size as usize;
    if key_size == 0 || key_size > 4096 {
        bail!("Key size outside the count scan budget");
    }
    let map = MapHandle::from_map_id(info.id)?;
    let mut previous = vec![0; key_size];
    let mut next = vec![0; key_size];
    let mut keys = HashSet::new();
    let limit = SCAN_MEMORY / (key_size + 80);
    let start = Instant::now();
    let mut calls = 0_u32;
    let mut complete = false;
    while start.elapsed() < SCAN_TIME && keys.len() < limit && calls < 1_000_000 {
        let key = if calls == 0 {
            std::ptr::null()
        } else {
            previous.as_ptr().cast()
        };
        let rc = unsafe {
            libbpf_sys::bpf_map_get_next_key(map.as_fd().as_raw_fd(), key, next.as_mut_ptr().cast())
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                complete = true;
                break;
            }
            return Err(error).context("scan map keys");
        }
        calls += 1;
        keys.insert(next.clone());
        std::mem::swap(&mut previous, &mut next);
    }
    Ok(MapCount {
        value: Some(keys.len() as u64),
        source: if complete {
            Source::Scan
        } else {
            Source::PartialScan
        },
        scanned: calls,
        measured: Instant::now(),
        duration: start.elapsed(),
        note: if complete {
            "Distinct keys observed during this scan; concurrent insert/delete is not a snapshot"
        } else {
            "Scan budget reached; observed keys are not the whole-map count"
        }
        .into(),
    })
}

pub struct Snapshot {
    pub counts: HashMap<u32, MapCount>,
    pub internal: Vec<u32>,
    pub duration: Duration,
    pub error: Option<String>,
}

enum Request {
    Snapshot {
        retry: bool,
    },
    Scan(MapMeta),
    References(u32),
    Xsk {
        id: u32,
        limit: usize,
        retry: bool,
    },
    Preview(Box<PreviewRequest>),
    Targets {
        info: MapMeta,
        limit: usize,
        anchor: Option<Vec<u8>>,
        generation: u64,
    },
    Program {
        map: u32,
        id: u32,
    },
}

pub struct PreviewRequest {
    pub info: MapMeta,
    pub limit: usize,
    pub previous: HashMap<Vec<u8>, Vec<u8>>,
    pub previous_time: Option<Instant>,
    pub query: crate::browse::Query,
    pub anchor: Option<Vec<u8>>,
    pub generation: u64,
}

pub enum Update {
    Snapshot(Snapshot),
    Scan(u32, Result<MapCount>),
    References(u32, crate::kernel::ProgramReferences),
    Xsk(u32, Result<crate::xsk::Snapshot>),
    Preview(u32, u64, Result<crate::kernel::Preview>),
    Targets(u32, u64, Result<crate::refs::Snapshot>),
    Program(u32, u32, Result<Vec<ratatui::text::Line<'static>>>),
}

pub struct Worker {
    requests: Option<Sender<Request>>,
    updates: Receiver<Update>,
    thread: Option<JoinHandle<()>>,
    busy: bool,
}

impl Worker {
    pub fn new() -> Self {
        let (requests, input) = mpsc::channel();
        let (output, updates) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut reader = Reader::open();
            let mut xsk_reader: Option<(u32, usize, Result<crate::xsk::Reader>)> = None;
            while let Ok(request) = input.recv() {
                let update = match request {
                    Request::Snapshot { retry } => {
                        if retry && reader.is_err() {
                            reader = Reader::open();
                        }
                        let mut snapshot = match reader.as_ref() {
                            Ok(reader) => reader.snapshot(),
                            Err(error) => Err(anyhow::anyhow!(error.to_string())),
                        }
                        .unwrap_or_else(|error| Snapshot {
                            counts: HashMap::new(),
                            internal: Vec::new(),
                            duration: Duration::ZERO,
                            error: Some(error.to_string()),
                        });
                        if let Some((_, _, Ok(reader))) = &xsk_reader {
                            snapshot.internal.extend(reader.internal_maps());
                            snapshot
                                .counts
                                .retain(|id, _| !snapshot.internal.contains(id));
                        }
                        Update::Snapshot(snapshot)
                    }
                    Request::Scan(info) => Update::Scan(info.id, scan(&info)),
                    Request::Preview(request) => {
                        let result = (|| {
                            let map = MapHandle::from_map_id(request.info.id)?;
                            let btf = crate::kernel::Btf::open(&request.info);
                            crate::kernel::preview(
                                &map,
                                &request.info,
                                btf.as_ref(),
                                crate::kernel::PreviewOptions {
                                    limit: request.limit,
                                    previous: &request.previous,
                                    previous_time: request.previous_time,
                                    query: &request.query,
                                    anchor: request.anchor.as_deref(),
                                },
                            )
                        })();
                        Update::Preview(request.info.id, request.generation, result)
                    }
                    Request::Targets {
                        info,
                        limit,
                        anchor,
                        generation,
                    } => Update::Targets(
                        info.id,
                        generation,
                        crate::refs::load_page(&info, limit, anchor.as_deref()),
                    ),
                    Request::Program { map, id } => {
                        Update::Program(map, id, crate::refs::program_lines(id))
                    }
                    Request::References(id) => {
                        Update::References(id, crate::kernel::program_references(id))
                    }
                    Request::Xsk { id, limit, retry } => {
                        if xsk_reader
                            .as_ref()
                            .is_none_or(|(old_id, old_limit, reader)| {
                                *old_id != id || *old_limit != limit || (retry && reader.is_err())
                            })
                        {
                            xsk_reader = Some((id, limit, crate::xsk::Reader::open(id, limit)));
                        }
                        let result = match &xsk_reader.as_ref().unwrap().2 {
                            Ok(reader) => reader.snapshot(),
                            Err(error) => Err(anyhow::anyhow!(error.to_string())),
                        };
                        Update::Xsk(id, result)
                    }
                };
                if output.send(update).is_err() {
                    break;
                }
            }
        });
        Self {
            requests: Some(requests),
            updates,
            thread: Some(thread),
            busy: false,
        }
    }

    pub fn request(&mut self, retry: bool) {
        if !self.busy {
            self.busy = self
                .requests
                .as_ref()
                .is_some_and(|tx| tx.send(Request::Snapshot { retry }).is_ok());
        }
    }

    pub fn scan(&mut self, info: MapMeta) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self
            .requests
            .as_ref()
            .is_some_and(|tx| tx.send(Request::Scan(info)).is_ok());
        self.busy
    }

    pub fn poll(&mut self) -> Option<Update> {
        let update = self.updates.try_recv().ok()?;
        self.busy = false;
        Some(update)
    }

    pub fn busy(&self) -> bool {
        self.busy
    }

    pub fn preview(&mut self, request: PreviewRequest) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self
            .requests
            .as_ref()
            .is_some_and(|tx| tx.send(Request::Preview(Box::new(request))).is_ok());
        self.busy
    }

    pub fn targets(
        &mut self,
        info: MapMeta,
        limit: usize,
        anchor: Option<Vec<u8>>,
        generation: u64,
    ) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self.requests.as_ref().is_some_and(|tx| {
            tx.send(Request::Targets {
                info,
                limit,
                anchor,
                generation,
            })
            .is_ok()
        });
        self.busy
    }

    pub fn program(&mut self, map: u32, id: u32) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self
            .requests
            .as_ref()
            .is_some_and(|tx| tx.send(Request::Program { map, id }).is_ok());
        self.busy
    }

    pub fn references(&mut self, id: u32) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self
            .requests
            .as_ref()
            .is_some_and(|tx| tx.send(Request::References(id)).is_ok());
        self.busy
    }

    pub fn xsk(&mut self, id: u32, limit: usize, retry: bool) -> bool {
        if self.busy {
            return false;
        }
        self.busy = self
            .requests
            .as_ref()
            .is_some_and(|tx| tx.send(Request::Xsk { id, limit, retry }).is_ok());
        self.busy
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.requests.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_zero_is_not_empty() {
        let count = decode(
            Record {
                count: 0,
                capacity: 128,
                ..Record::default()
            },
            Duration::ZERO,
        );
        assert_eq!(count.value, None);
        assert_eq!(count.label(), "-");
    }

    #[test]
    fn fixed_slots_and_buffer_bytes_have_units() {
        let slots = decode(
            Record {
                kind: 2,
                count: 7,
                capacity: 7,
                ..Record::default()
            },
            Duration::ZERO,
        );
        let bytes = decode(
            Record {
                kind: 5,
                count: 128,
                capacity: 4096,
                ..Record::default()
            },
            Duration::ZERO,
        );
        assert_eq!(slots.label(), "7 slots");
        assert_eq!(bytes.label(), "128 B");
    }

    #[test]
    fn partial_occupancy_never_looks_complete() {
        let count = decode(
            Record {
                kind: 4,
                count: 3,
                scanned: 16384,
                capacity: 32768,
                ..Record::default()
            },
            Duration::ZERO,
        );
        assert_eq!(count.label(), "3 part");
        assert!(count.description().contains("incomplete"));
    }

    #[test]
    fn inconsistent_counter_is_unknown_instead_of_clamped() {
        for value in [-1, 17] {
            let count = decode(
                Record {
                    kind: 1,
                    count: value,
                    capacity: 16,
                    ..Record::default()
                },
                Duration::ZERO,
            );
            assert_eq!(count.value, None);
            assert!(count.note.contains("not clamped"));
        }
    }

    #[test]
    fn destructive_or_slot_iterators_are_not_key_count_scans() {
        for ty in [
            MapType::Queue,
            MapType::Stack,
            MapType::RingBuf,
            MapType::Xskmap,
            MapType::ProgArray,
            MapType::ArrayOfMaps,
            MapType::BloomFilter,
        ] {
            assert!(!scannable(ty));
        }
        assert!(scannable(MapType::HashOfMaps));
        assert!(scannable(MapType::LpmTrie));
    }
}
