use crate::kernel::{self, Btf, MapMeta};
use anyhow::{bail, Context, Result};
use libbpf_rs::{libbpf_sys, MapCore, MapHandle, MapType, ProgramType};
use ratatui::text::Line;
use std::{
    collections::{HashMap, HashSet},
    io,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

const MAX_SLOTS: usize = 16384;
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 4096;
const MAX_DURATION: Duration = Duration::from_millis(50);
const MAX_PROGRAM_MAPS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Map,
    Program,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub raw_key: Vec<u8>,
    pub key: String,
    pub target_id: u32,
    pub target_name: String,
    pub description: String,
    pub kind: Kind,
}

pub struct Snapshot {
    pub entries: Vec<Entry>,
    /// An entry or traversal budget prevented a complete listing.
    pub truncated: bool,
    /// Failed key enumeration or value lookups; empty slots do not count.
    pub read_errors: usize,
    /// Slots/keys whose values were looked up, including empty slots and failures.
    pub scanned: usize,
    /// Coverage or target metadata is incomplete, including failed resolution.
    pub partial: bool,
    pub next_key: Option<Vec<u8>>,
}

pub fn supported(ty: MapType) -> bool {
    matches!(
        ty,
        MapType::ProgArray | MapType::ArrayOfMaps | MapType::HashOfMaps
    )
}

fn optional_result<T>(result: i32, value: T) -> io::Result<Option<T>> {
    if result == 0 {
        Ok(Some(value))
    } else {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(error)
        }
    }
}

fn decode_id(bytes: [u8; 4]) -> Option<u32> {
    let id = u32::from_ne_bytes(bytes);
    (id != 0).then_some(id)
}

fn lookup_id(map: &MapHandle, key: &[u8]) -> io::Result<Option<u32>> {
    let mut value = [0_u8; 4];
    // The syscall returns a native-endian object ID for FD-backed maps, not an FD.
    let result = unsafe {
        libbpf_sys::bpf_map_lookup_elem(
            map.as_fd().as_raw_fd(),
            key.as_ptr().cast(),
            value.as_mut_ptr().cast(),
        )
    };
    Ok(optional_result(result, value)?.and_then(decode_id))
}

fn next_key(map: &MapHandle, previous: Option<&[u8]>) -> io::Result<Option<Vec<u8>>> {
    let mut next = vec![0_u8; map.key_size() as usize];
    let result = unsafe {
        libbpf_sys::bpf_map_get_next_key(
            map.as_fd().as_raw_fd(),
            previous.map_or(std::ptr::null(), |key| key.as_ptr().cast()),
            next.as_mut_ptr().cast(),
        )
    };
    optional_result(result, next)
}

fn key_label(info: &MapMeta, key: &[u8]) -> String {
    if info.ty != MapType::HashOfMaps {
        if let Ok(bytes) = <[u8; 4]>::try_from(key) {
            return u32::from_ne_bytes(bytes).to_string();
        }
    }
    kernel::hex(key)
}

fn scan(
    info: &MapMeta,
    limit: usize,
    started: Instant,
    anchor: Option<&[u8]>,
    mut next: impl FnMut(Option<&[u8]>) -> io::Result<Option<Vec<u8>>>,
    mut lookup: impl FnMut(&[u8]) -> io::Result<Option<u32>>,
) -> Snapshot {
    let mut snapshot = Snapshot {
        entries: Vec::new(),
        truncated: false,
        read_errors: 0,
        scanned: 0,
        partial: false,
        next_key: None,
    };
    let mut previous = anchor.map(<[u8]>::to_vec);
    let mut seen = HashSet::new();
    let array = info.ty != MapType::HashOfMaps;
    let start_slot = if array {
        anchor
            .and_then(|key| <[u8; 4]>::try_from(key).ok())
            .map_or(0, |key| u32::from_ne_bytes(key) as usize + 1)
    } else {
        0
    };
    // Include the duplicate key retained for hash restart detection in this budget.
    let slot_bytes = info.key_size as usize * 2 + 4;
    let slots = MAX_SLOTS.min(MAX_SCAN_BYTES / slot_bytes);
    loop {
        if array && start_slot + snapshot.scanned >= info.max_entries as usize {
            break;
        }
        // Check before each syscall. An individual kernel call cannot be preempted here.
        if snapshot.scanned >= slots || started.elapsed() >= MAX_DURATION {
            snapshot.truncated = true;
            snapshot.partial = true;
            snapshot.next_key = previous.clone();
            break;
        }
        let key = if array {
            ((start_slot + snapshot.scanned) as u32)
                .to_ne_bytes()
                .to_vec()
        } else {
            match next(previous.as_deref()) {
                Ok(Some(key)) => key,
                Ok(None) => break,
                Err(_) => {
                    snapshot.read_errors += 1;
                    snapshot.partial = true;
                    break;
                }
            }
        };
        if key.len() != info.key_size as usize || (!array && !seen.insert(key.clone())) {
            // Concurrent deletion can restart hash iteration; never repeat rows indefinitely.
            snapshot.partial = true;
            snapshot.truncated = true;
            snapshot.next_key = previous.clone();
            break;
        }
        if started.elapsed() >= MAX_DURATION {
            snapshot.truncated = true;
            snapshot.partial = true;
            snapshot.next_key = previous.clone();
            break;
        }
        snapshot.scanned += 1;
        match lookup(&key) {
            Ok(Some(id)) if id != 0 => {
                if snapshot.entries.len() == limit {
                    snapshot.truncated = true;
                    snapshot.partial = true;
                    snapshot.next_key = previous.clone();
                    break;
                }
                snapshot.entries.push(Entry {
                    key: key_label(info, &key),
                    raw_key: key.clone(),
                    target_id: id,
                    target_name: "unavailable".into(),
                    description: "metadata unavailable (time budget)".into(),
                    kind: if info.ty == MapType::ProgArray {
                        Kind::Program
                    } else {
                        Kind::Map
                    },
                });
            }
            Ok(_) => {
                // ENOENT is an empty sparse slot (or a key removed during traversal).
                snapshot.partial |= !array;
            }
            Err(_) => {
                snapshot.read_errors += 1;
                snapshot.partial = true;
            }
        }
        previous = Some(key);
    }
    snapshot
}

fn program_fd(id: u32) -> Result<OwnedFd> {
    let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("open program ID {id}"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn query_program(fd: &OwnedFd, info: &mut libbpf_sys::bpf_prog_info) -> io::Result<()> {
    let mut size = std::mem::size_of_val(info) as u32;
    let result = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            (info as *mut libbpf_sys::bpf_prog_info).cast(),
            &mut size,
        )
    };
    if result != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn program_info(fd: &OwnedFd) -> Result<libbpf_sys::bpf_prog_info> {
    // No instruction, debug, symbol, or map-ID buffers are requested by this query.
    let mut info = libbpf_sys::bpf_prog_info::default();
    query_program(fd, &mut info).context("read program metadata")?;
    Ok(info)
}

fn program_name(info: &libbpf_sys::bpf_prog_info) -> String {
    let bytes = info
        .name
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let name = String::from_utf8_lossy(&bytes).into_owned();
    if name.is_empty() {
        "(unnamed)".into()
    } else {
        name
    }
}

fn resolve(kind: Kind, id: u32, started: Instant) -> Result<(String, String)> {
    match kind {
        Kind::Program => {
            let fd = program_fd(id)?;
            if started.elapsed() >= MAX_DURATION {
                bail!("time budget exhausted");
            }
            let info = program_info(&fd)?;
            Ok((
                program_name(&info),
                format!(
                    "{:?} ({}); creator UID {}; JIT {} B, translated {} B",
                    ProgramType::from(info.type_),
                    info.type_,
                    info.created_by_uid,
                    info.jited_prog_len,
                    info.xlated_prog_len,
                ),
            ))
        }
        Kind::Map => {
            let map = MapHandle::from_map_id(id).with_context(|| format!("open map ID {id}"))?;
            if started.elapsed() >= MAX_DURATION {
                bail!("time budget exhausted");
            }
            let info = MapMeta::from(map.info()?);
            let mut description = format!(
                "{:?}; key {} B, value {} B, capacity {}",
                info.ty, info.key_size, info.value_size, info.max_entries,
            );
            if started.elapsed() < MAX_DURATION {
                if let Some(btf) = Btf::open(&info) {
                    for (label, type_id) in [
                        ("key", info.btf_key_type_id),
                        ("value", info.btf_value_type_id),
                    ] {
                        if started.elapsed() >= MAX_DURATION {
                            break;
                        }
                        if let Some(name) = btf.type_name(type_id) {
                            description.push_str(&format!("; {label} type {name}"));
                        }
                    }
                }
            }
            let name = if info.name.is_empty() {
                "(unnamed)".into()
            } else {
                info.name
            };
            Ok((name, description))
        }
    }
}

fn resolved_entry(entry: &mut Entry, resolution: &Result<(String, String)>) -> bool {
    match resolution {
        Ok((name, description)) => {
            entry.target_name.clone_from(name);
            entry.description.clone_from(description);
            true
        }
        Err(error) => {
            entry.target_name = "unavailable".into();
            entry.description = format!("metadata unavailable: {error:#}");
            false
        }
    }
}

/// Call on the worker: the source map and all target handles are opened and closed here.
#[cfg(test)]
pub fn load(info: &MapMeta, limit: usize) -> Result<Snapshot> {
    load_page(info, limit, None)
}

pub fn load_page(info: &MapMeta, limit: usize, anchor: Option<&[u8]>) -> Result<Snapshot> {
    if !supported(info.ty) {
        bail!("read-only references are unsupported for {:?}", info.ty);
    }
    let started = Instant::now();
    let map =
        MapHandle::from_map_id(info.id).with_context(|| format!("open map ID {}", info.id))?;
    let actual = MapMeta::from(map.info()?);
    if !supported(actual.ty)
        || actual.value_size != 4
        || actual.key_size == 0
        || actual.key_size as usize > MAX_KEY_BYTES
        || (actual.ty != MapType::HashOfMaps && actual.key_size != 4)
    {
        bail!("unsupported reference map type or key/value layout");
    }
    if anchor.is_some_and(|key| key.len() != actual.key_size as usize) {
        bail!("Reference page key size mismatch");
    }
    let mut snapshot = scan(
        &actual,
        limit,
        started,
        anchor,
        |key| next_key(&map, key),
        |key| lookup_id(&map, key),
    );
    // Map-in-map lookup waits for an RCU grace period on Linux 6.6. Reserve a
    // separate metadata budget so a bounded scan can still resolve its results.
    let metadata_started = Instant::now();
    let btf = if snapshot.entries.is_empty() {
        None
    } else {
        Btf::open(&actual)
    };
    let mut targets = HashMap::new();
    for entry in &mut snapshot.entries {
        if metadata_started.elapsed() < MAX_DURATION {
            if let Some(key) = btf.as_ref().and_then(|btf| btf.key(&entry.raw_key)) {
                entry.key = key;
            }
        }
        if let Some(resolution) = targets.get(&entry.target_id) {
            snapshot.partial |= !resolved_entry(entry, resolution);
            continue;
        }
        if metadata_started.elapsed() >= MAX_DURATION {
            snapshot.partial = true;
            continue;
        }
        let resolution = resolve(entry.kind, entry.target_id, metadata_started);
        snapshot.partial |= !resolved_entry(entry, &resolution);
        targets.insert(entry.target_id, resolution);
    }
    Ok(snapshot)
}

fn program_map_ids(
    count: u32,
    mut query: impl FnMut(&mut libbpf_sys::bpf_prog_info) -> io::Result<()>,
) -> io::Result<(Vec<u32>, u32)> {
    if count == 0 {
        return Ok((Vec::new(), 0));
    }
    let mut ids = vec![0_u32; (count as usize).min(MAX_PROGRAM_MAPS)];
    // Never reuse returned instruction/debug lengths as input requests with null buffers.
    let mut info = libbpf_sys::bpf_prog_info {
        nr_map_ids: ids.len() as u32,
        map_ids: ids.as_mut_ptr() as u64,
        ..Default::default()
    };
    query(&mut info)?;
    ids.truncate((info.nr_map_ids as usize).min(ids.len()));
    Ok((ids, info.nr_map_ids))
}

fn program_detail_lines(
    info: &libbpf_sys::bpf_prog_info,
    maps: io::Result<(Vec<u32>, u32)>,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut field =
        |label: &str, value: String| lines.push(Line::raw(format!("{label:<16} | {value}")));
    field("Program ID", info.id.to_string());
    field("Name", program_name(info));
    field(
        "Type",
        format!("{:?} ({})", ProgramType::from(info.type_), info.type_),
    );
    field("Creator UID", info.created_by_uid.to_string());
    field("Tag", kernel::hex(&info.tag));
    field(
        "JIT length",
        format!("{} B (kernel-reported)", info.jited_prog_len),
    );
    field(
        "Translated length",
        format!("{} B (kernel-reported)", info.xlated_prog_len),
    );
    match maps {
        Ok((ids, total)) => {
            let ids = ids.into_iter().filter(|id| *id != 0).collect::<Vec<_>>();
            let coverage = if ids.len() == total as usize {
                format!("{} of {total}; complete", ids.len())
            } else {
                format!(
                    "{} of {total}; incomplete (at most {MAX_PROGRAM_MAPS} IDs)",
                    ids.len()
                )
            };
            field("Map ID coverage", coverage);
            field(
                "Referenced maps",
                if total == 0 {
                    "none".into()
                } else if ids.is_empty() {
                    "unavailable".into()
                } else {
                    ids.iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
        }
        Err(error) => {
            field(
                "Map ID coverage",
                format!("incomplete; {} IDs reported", info.nr_map_ids),
            );
            field("Referenced maps", format!("unavailable: {error}"));
        }
    }
    lines
}

pub fn program_lines(id: u32) -> Result<Vec<Line<'static>>> {
    let fd = program_fd(id)?;
    let info = program_info(&fd)?;
    let maps = program_map_ids(info.nr_map_ids, |query| query_program(&fd, query));
    Ok(program_detail_lines(&info, maps))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(ty: MapType, capacity: u32) -> MapMeta {
        MapMeta {
            id: 1,
            name: "refs".into(),
            kernel_name: "refs".into(),
            ty,
            key_size: 4,
            value_size: 4,
            max_entries: capacity,
            btf_id: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
        }
    }

    fn array_scan(
        capacity: u32,
        limit: usize,
        lookup: impl FnMut(&[u8]) -> io::Result<Option<u32>>,
    ) -> Snapshot {
        scan(
            &metadata(MapType::ProgArray, capacity),
            limit,
            Instant::now(),
            None,
            |_| panic!("array enumeration"),
            lookup,
        )
    }

    #[test]
    fn only_reference_types_are_supported() {
        for ty in [
            MapType::ProgArray,
            MapType::ArrayOfMaps,
            MapType::HashOfMaps,
        ] {
            assert!(supported(ty));
        }
        for ty in [
            MapType::Array,
            MapType::Hash,
            MapType::Devmap,
            MapType::DevmapHash,
            MapType::Cpumap,
            MapType::Sockmap,
            MapType::Sockhash,
            MapType::Xskmap,
            MapType::Queue,
            MapType::Stack,
            MapType::RingBuf,
        ] {
            assert!(!supported(ty));
        }
    }

    #[test]
    fn ids_use_native_endian_and_zero_is_empty() {
        assert_eq!(decode_id(0x0123_4567_u32.to_ne_bytes()), Some(0x0123_4567));
        assert_eq!(decode_id([0; 4]), None);
    }

    #[test]
    fn syscall_enoent_is_empty_and_other_errors_are_not() {
        let error =
            std::fs::File::open("/proc/self/bpfmap_nonexistent_reference_test").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
        assert_eq!(optional_result(-1, [0_u8; 4]).unwrap(), None);
        // Successful lookups must ignore a stale errno, including when ID zero is returned.
        assert_eq!(
            optional_result(0, [0_u8; 4]).unwrap().and_then(decode_id),
            None
        );
        assert_eq!(unsafe { libc::close(-1) }, -1);
        assert_eq!(
            optional_result(-1, [0_u8; 4]).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn holes_zero_and_failures_have_distinct_coverage() {
        let result = array_scan(6, 8, |key| {
            match u32::from_ne_bytes(key.try_into().unwrap()) {
                0 => Ok(Some(0)),
                2 => Err(io::Error::from_raw_os_error(libc::EACCES)),
                5 => Ok(Some(91)),
                _ => Ok(None),
            }
        });
        assert_eq!(result.scanned, 6);
        assert_eq!(result.read_errors, 1);
        assert!(result.partial);
        assert!(!result.truncated);
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].raw_key, 5_u32.to_ne_bytes());
        assert_eq!(result.entries[0].key, "5");
        assert_eq!(result.entries[0].target_id, 91);
        assert_eq!(result.entries[0].kind, Kind::Program);
        let empty = array_scan(6, 0, |_| Ok(None));
        assert_eq!(empty.scanned, 6);
        assert_eq!(empty.read_errors, 0);
        assert!(!empty.partial && !empty.truncated);
    }

    #[test]
    fn entry_limit_requires_an_additional_occupied_slot() {
        let exact = array_scan(8, 1, |key| Ok((key == 7_u32.to_ne_bytes()).then_some(91)));
        assert_eq!(exact.entries.len(), 1);
        assert!(!exact.truncated && !exact.partial);
        let more = array_scan(8, 1, |key| {
            Ok((key == 2_u32.to_ne_bytes() || key == 7_u32.to_ne_bytes()).then_some(91))
        });
        assert_eq!(more.entries.len(), 1);
        assert_eq!(more.scanned, 8);
        assert!(more.truncated && more.partial);
        let zero = array_scan(8, 0, |_| Ok(Some(91)));
        assert!(zero.entries.is_empty() && zero.truncated && zero.partial);
    }

    #[test]
    fn reference_pages_resume_without_skipping_the_lookahead_entry() {
        let info = metadata(MapType::ArrayOfMaps, 8);
        let first = array_scan(8, 1, |key| {
            Ok((key == 2_u32.to_ne_bytes() || key == 7_u32.to_ne_bytes()).then_some(91))
        });
        assert_eq!(first.next_key, Some(6_u32.to_ne_bytes().to_vec()));
        let next = scan(
            &info,
            1,
            Instant::now(),
            first.next_key.as_deref(),
            |_| panic!("array"),
            |key| Ok((key == 7_u32.to_ne_bytes()).then_some(91)),
        );
        assert_eq!(next.entries[0].raw_key, 7_u32.to_ne_bytes());
        assert!(!next.partial && next.next_key.is_none());
        let first = array_scan(32768, 4, |_| Ok(None));
        assert_eq!(first.next_key, Some(16383_u32.to_ne_bytes().to_vec()));
        let next = scan(
            &metadata(MapType::ProgArray, 32768),
            4,
            Instant::now(),
            first.next_key.as_deref(),
            |_| panic!("array"),
            |key| Ok((key == 20000_u32.to_ne_bytes()).then_some(91)),
        );
        assert_eq!(next.entries[0].key, "20000");
        assert!(!next.partial && next.next_key.is_none());
    }

    #[test]
    fn slot_byte_and_time_budgets_are_incomplete() {
        let slots = array_scan(32768, 4, |_| Ok(None));
        assert_eq!(slots.scanned, MAX_SLOTS);
        assert!(slots.truncated && slots.partial);
        let mut info = metadata(MapType::HashOfMaps, 1024);
        info.key_size = MAX_KEY_BYTES as u32;
        let mut index = 0_u32;
        let bytes = scan(
            &info,
            4,
            Instant::now(),
            None,
            |_| {
                let mut key = vec![0; MAX_KEY_BYTES];
                key[..4].copy_from_slice(&index.to_ne_bytes());
                index += 1;
                Ok(Some(key))
            },
            |_| Ok(None),
        );
        assert_eq!(bytes.scanned, MAX_SCAN_BYTES / (2 * MAX_KEY_BYTES + 4));
        assert!(bytes.truncated && bytes.partial);
        let timed = scan(
            &info,
            4,
            Instant::now() - MAX_DURATION,
            None,
            |_| panic!("after deadline"),
            |_| panic!("after deadline"),
        );
        assert_eq!(timed.scanned, 0);
        assert!(timed.truncated && timed.partial);
    }

    #[test]
    fn hash_restart_and_enumeration_failures_are_incomplete() {
        let info = metadata(MapType::HashOfMaps, 8);
        let restarted = scan(
            &info,
            8,
            Instant::now(),
            None,
            |_| Ok(Some(vec![1, 2, 3, 4])),
            |_| Ok(Some(77)),
        );
        assert_eq!(restarted.entries.len(), 1);
        assert_eq!(restarted.entries[0].kind, Kind::Map);
        assert_eq!(restarted.scanned, 1);
        assert!(restarted.truncated && restarted.partial);
        let denied = scan(
            &info,
            8,
            Instant::now(),
            None,
            |_| Err(io::Error::from_raw_os_error(libc::EACCES)),
            |_| panic!("no key"),
        );
        assert_eq!(denied.read_errors, 1);
        assert!(denied.partial && !denied.truncated);
        let empty = scan(
            &info,
            8,
            Instant::now(),
            None,
            |_| Ok(None),
            |_| panic!("no key"),
        );
        assert!(!empty.partial && !empty.truncated);
    }

    #[test]
    fn failed_resolution_retains_the_reference() {
        let mut result = array_scan(1, 1, |_| Ok(Some(123)));
        let entry = &mut result.entries[0];
        assert!(!resolved_entry(
            entry,
            &Err(anyhow::anyhow!("permission denied"))
        ));
        assert_eq!(entry.target_id, 123);
        assert_eq!(entry.target_name, "unavailable");
        assert!(entry.description.contains("permission denied"));
        assert!(!entry.description.contains("dangling"));
    }

    #[test]
    fn program_map_query_is_fresh_bounded_and_reports_growth() {
        let (ids, total) = program_map_ids(2, |query| {
            assert_eq!(query.nr_map_ids, 2);
            assert_ne!(query.map_ids, 0);
            assert_eq!(query.jited_prog_len, 0);
            assert_eq!(query.xlated_prog_len, 0);
            assert_eq!(query.jited_prog_insns, 0);
            assert_eq!(query.xlated_prog_insns, 0);
            assert_eq!(query.nr_line_info, 0);
            assert_eq!(query.line_info, 0);
            assert_eq!(query.nr_func_info, 0);
            assert_eq!(query.func_info, 0);
            assert_eq!(query.nr_jited_ksyms, 0);
            assert_eq!(query.jited_ksyms, 0);
            unsafe {
                std::slice::from_raw_parts_mut(query.map_ids as *mut u32, 2)
                    .copy_from_slice(&[10, 20]);
            }
            query.nr_map_ids = 3;
            Ok(())
        })
        .unwrap();
        assert_eq!(ids, [10, 20]);
        assert_eq!(total, 3);
        let (ids, total) = program_map_ids(70, |query| {
            assert_eq!(query.nr_map_ids, 64);
            let ids = unsafe { std::slice::from_raw_parts_mut(query.map_ids as *mut u32, 64) };
            for (index, id) in ids.iter_mut().enumerate() {
                *id = index as u32 + 1;
            }
            query.nr_map_ids = 70;
            Ok(())
        })
        .unwrap();
        let text = program_detail_lines(&libbpf_sys::bpf_prog_info::default(), Ok((ids, total)))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("64 of 70; incomplete"));
        assert!(text.contains("63, 64"));
        assert!(!text.contains("64, 65"));
        assert_eq!(
            program_map_ids(0, |_| panic!("no maps")).unwrap(),
            (vec![], 0)
        );
    }

    #[test]
    fn program_details_survive_map_query_failure() {
        let info = libbpf_sys::bpf_prog_info {
            id: 99,
            nr_map_ids: 3,
            created_by_uid: 1000,
            jited_prog_len: 128,
            xlated_prog_len: 64,
            ..Default::default()
        };
        let text = program_detail_lines(&info, Err(io::Error::from_raw_os_error(libc::EACCES)))
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Program ID       | 99"));
        assert!(text.contains("Creator UID      | 1000"));
        assert!(text.contains("128 B (kernel-reported)"));
        assert!(text.contains("incomplete; 3 IDs reported"));
        assert!(text.contains("unavailable"));
        assert!(!text.contains("Owner") && !text.contains("Attachment"));
    }
}
