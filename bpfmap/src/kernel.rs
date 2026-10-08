use anyhow::{bail, Context, Result};
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_MAPS: usize = 8192;
const MAX_PIN_NODES: usize = 2048;
const MAX_CELL_BYTES: usize = 4096;
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_PERCPU_ENTRY_BYTES: usize = 64 * 1024;

unsafe extern "C" {
    fn bpfmap_btf_open(id: u32) -> *mut c_void;
    fn bpfmap_btf_close(btf: *mut c_void);
    fn bpfmap_btf_map_name(
        btf: *mut c_void,
        kernel_name: *const c_char,
        map_type: u32,
        max_entries: u32,
        key_type: u32,
        value_type: u32,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn bpfmap_btf_format(
        btf: *mut c_void,
        type_id: u32,
        data: *const c_void,
        len: usize,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn bpfmap_btf_format_expanded(
        btf: *mut c_void,
        type_id: u32,
        data: *const c_void,
        len: usize,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn bpfmap_btf_addresses(
        btf: *mut c_void,
        type_id: u32,
        data: *const c_void,
        len: usize,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn bpfmap_btf_type_name(
        btf: *mut c_void,
        type_id: u32,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn bpfmap_btf_unsigned_size(btf: *mut c_void, type_id: u32) -> c_int;
    fn bpfmap_btf_struct_delta(
        btf: *mut c_void,
        type_id: u32,
        before: *const c_void,
        after: *const c_void,
        len: usize,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
}

pub struct Btf {
    ptr: *mut c_void,
    key_type: u32,
    value_type: u32,
    ipv4_key: bool,
}

impl Btf {
    pub fn open(info: &MapMeta) -> Option<Self> {
        if info.btf_id == 0 {
            return None;
        }
        let ptr = unsafe { bpfmap_btf_open(info.btf_id) };
        if ptr.is_null() {
            return None;
        }
        let mut btf = Self {
            ptr,
            key_type: info.btf_key_type_id,
            value_type: info.btf_value_type_id,
            ipv4_key: false,
        };
        // This verified schema uses packet-order IPv4 keys despite its u32 BTF type.
        btf.ipv4_key = info.ty == MapType::Hash
            && info.key_size == 4
            && info.value_size == 1
            && btf.map_name(info).as_deref() == Some("aiwan_xdp_local_ips");
        Some(btf)
    }

    fn map_name(&self, info: &MapMeta) -> Option<String> {
        let name = CString::new(info.kernel_name.as_str()).ok()?;
        let mut out = [0_u8; 1024];
        let result = unsafe {
            bpfmap_btf_map_name(
                self.ptr,
                name.as_ptr(),
                info.ty as u32,
                info.max_entries,
                info.btf_key_type_id,
                info.btf_value_type_id,
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        (result == 0)
            .then(|| {
                CStr::from_bytes_until_nul(&out)
                    .ok()?
                    .to_str()
                    .ok()
                    .map(str::to_owned)
            })
            .flatten()
    }

    fn render(&self, type_id: u32, bytes: &[u8]) -> Option<String> {
        if type_id == 0 {
            return None;
        }
        let mut out = vec![0_u8; 768];
        let result = unsafe {
            bpfmap_btf_format(
                self.ptr,
                type_id,
                bytes.as_ptr().cast(),
                bytes.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        if result == 0 {
            Some(
                CStr::from_bytes_until_nul(&out)
                    .ok()?
                    .to_string_lossy()
                    .into_owned(),
            )
        } else {
            None
        }
    }

    pub fn key(&self, bytes: &[u8]) -> Option<String> {
        if self.ipv4_key {
            self.key_addresses(bytes)
        } else {
            self.render(self.key_type, bytes)
        }
    }

    pub fn value(&self, bytes: &[u8]) -> Option<String> {
        self.render(self.value_type, bytes)
    }

    pub fn key_addresses(&self, bytes: &[u8]) -> Option<String> {
        if self.ipv4_key {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(octets).to_string())
        } else {
            self.addresses(self.key_type, bytes)
        }
    }

    pub fn addresses(&self, type_id: u32, bytes: &[u8]) -> Option<String> {
        let mut out = [0_u8; 1024];
        let result = unsafe {
            bpfmap_btf_addresses(
                self.ptr,
                type_id,
                bytes.as_ptr().cast(),
                bytes.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        (result == 0)
            .then(|| {
                CStr::from_bytes_until_nul(&out)
                    .ok()
                    .map(|text| text.to_string_lossy().into_owned())
            })
            .flatten()
    }

    pub fn expanded(&self, type_id: u32, bytes: &[u8]) -> Option<String> {
        let mut out = vec![0_u8; 16384];
        let result = unsafe {
            bpfmap_btf_format_expanded(
                self.ptr,
                type_id,
                bytes.as_ptr().cast(),
                bytes.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        (result == 0)
            .then(|| {
                CStr::from_bytes_until_nul(&out)
                    .ok()
                    .map(|text| text.to_string_lossy().into_owned())
            })
            .flatten()
    }

    pub fn type_name(&self, type_id: u32) -> Option<String> {
        let mut out = [0_u8; 512];
        let result =
            unsafe { bpfmap_btf_type_name(self.ptr, type_id, out.as_mut_ptr().cast(), out.len()) };
        (result == 0)
            .then(|| {
                CStr::from_bytes_until_nul(&out)
                    .ok()
                    .map(|text| text.to_string_lossy().into_owned())
            })
            .flatten()
    }

    pub fn unsigned_size(&self) -> Option<usize> {
        let size = unsafe { bpfmap_btf_unsigned_size(self.ptr, self.value_type) };
        (size > 0).then_some(size as usize)
    }

    pub fn struct_delta(&self, before: &[u8], after: &[u8]) -> Option<String> {
        if before.len() != after.len() || self.value_type == 0 {
            return None;
        }
        let mut out = [0_u8; 256];
        let result = unsafe {
            bpfmap_btf_struct_delta(
                self.ptr,
                self.value_type,
                before.as_ptr().cast(),
                after.as_ptr().cast(),
                after.len(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        if result != 0 {
            return None;
        }
        Some(
            CStr::from_bytes_until_nul(&out)
                .ok()?
                .to_string_lossy()
                .into_owned(),
        )
    }
}

impl Drop for Btf {
    fn drop(&mut self) {
        unsafe { bpfmap_btf_close(self.ptr) };
    }
}

#[derive(Clone)]
pub struct MapRow {
    pub info: MapMeta,
    pub pins: Vec<String>,
}

#[derive(Clone)]
pub struct MapMeta {
    pub id: u32,
    pub name: String,
    pub kernel_name: String,
    pub ty: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

impl From<libbpf_rs::MapInfo> for MapMeta {
    fn from(info: libbpf_rs::MapInfo) -> Self {
        let raw = info.info;
        let end = raw
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw.name.len());
        let name = String::from_utf8_lossy(
            &raw.name[..end]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>(),
        )
        .into_owned();
        Self {
            id: raw.id,
            kernel_name: name.clone(),
            name,
            ty: MapType::from(raw.type_),
            key_size: raw.key_size,
            value_size: raw.value_size,
            max_entries: raw.max_entries,
            btf_id: raw.btf_id,
            btf_key_type_id: raw.btf_key_type_id,
            btf_value_type_id: raw.btf_value_type_id,
        }
    }
}

pub struct Inventory {
    pub maps: Vec<MapRow>,
    pub pins_truncated: bool,
    pub maps_truncated: bool,
    pub inaccessible: usize,
}

#[derive(Clone, Default)]
pub struct Configuration {
    pub flags: u32,
    pub extra: u64,
    pub ifindex: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub memlock: Option<u64>,
    pub frozen: Option<bool>,
    pub cpus: Option<usize>,
    pub key_type: Option<String>,
    pub value_type: Option<String>,
    pub fdinfo_error: Option<String>,
}

pub fn configuration(map: &MapHandle, btf: Option<&Btf>) -> Result<Configuration> {
    let info = map.info()?.info;
    let fdinfo = libbpf_rs::MapFdInfo::from_fd(map.as_fd());
    let cpus = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
    Ok(Configuration {
        flags: info.map_flags,
        extra: info.map_extra,
        ifindex: info.ifindex,
        netns_dev: info.netns_dev,
        netns_ino: info.netns_ino,
        memlock: fdinfo.as_ref().ok().and_then(|fd| fd.memlock),
        frozen: fdinfo.as_ref().ok().and_then(|fd| fd.frozen),
        cpus: (cpus > 0 && MapType::from(info.type_).is_percpu()).then_some(cpus as usize),
        key_type: btf.and_then(|btf| btf.type_name(info.btf_key_type_id)),
        value_type: btf.and_then(|btf| btf.type_name(info.btf_value_type_id)),
        fdinfo_error: fdinfo.err().map(|error| error.to_string()),
    })
}

#[derive(Clone)]
pub struct ProgramReference {
    pub id: u32,
    pub name: String,
    pub ty: libbpf_rs::ProgramType,
    pub uid: u32,
}

#[derive(Clone)]
pub struct ProgramReferences {
    pub programs: Vec<ProgramReference>,
    pub inspected: usize,
    pub inaccessible: usize,
    pub partial: bool,
    pub error: Option<String>,
    pub measured: Instant,
}

fn program_info(fd: &OwnedFd, info: &mut libbpf_sys::bpf_prog_info) -> Result<()> {
    let mut len = std::mem::size_of_val(info) as u32;
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(
            fd.as_raw_fd(),
            (info as *mut libbpf_sys::bpf_prog_info).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("read program metadata");
    }
    Ok(())
}

fn program_map_query(ids: &mut [u32]) -> libbpf_sys::bpf_prog_info {
    // Returned instruction/debug lengths must not become requests with null buffers.
    libbpf_sys::bpf_prog_info {
        nr_map_ids: ids.len() as u32,
        map_ids: ids.as_mut_ptr() as u64,
        ..Default::default()
    }
}

pub fn program_references(map_id: u32) -> ProgramReferences {
    let mut result = ProgramReferences {
        programs: Vec::new(),
        inspected: 0,
        inaccessible: 0,
        partial: false,
        error: None,
        measured: Instant::now(),
    };
    let mut id = 0;
    loop {
        if result.inspected + result.inaccessible >= 4096
            || result.measured.elapsed() >= Duration::from_secs(1)
        {
            result.partial = true;
            break;
        }
        let mut next = 0;
        if unsafe { libbpf_sys::bpf_prog_get_next_id(id, &mut next) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                result.partial = true;
                result.error = Some(error.to_string());
            }
            break;
        }
        id = next;
        let fd = unsafe { libbpf_sys::bpf_prog_get_fd_by_id(id) };
        if fd < 0 {
            result.inaccessible += 1;
            result.error.get_or_insert_with(|| {
                format!("open program {id}: {}", std::io::Error::last_os_error())
            });
            continue;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut info = libbpf_sys::bpf_prog_info::default();
        if let Err(error) = program_info(&fd, &mut info) {
            result.inaccessible += 1;
            result
                .error
                .get_or_insert_with(|| format!("program {id}: {error:#}"));
            continue;
        }
        if info.nr_map_ids > 4096 {
            result.inaccessible += 1;
            result.error.get_or_insert_with(|| {
                format!("program {id}: map ID list exceeds 4096-entry budget")
            });
            continue;
        }
        let mut ids = vec![0_u32; info.nr_map_ids as usize];
        let mut query = program_map_query(&mut ids);
        if let Err(error) = program_info(&fd, &mut query) {
            result.inaccessible += 1;
            result
                .error
                .get_or_insert_with(|| format!("program {id} map IDs: {error:#}"));
            continue;
        }
        if query.nr_map_ids as usize > ids.len() {
            result.inaccessible += 1;
            result
                .error
                .get_or_insert_with(|| format!("program {id}: map ID list grew during query"));
            continue;
        }
        result.inspected += 1;
        if ids.contains(&map_id) {
            let name = info
                .name
                .iter()
                .take_while(|byte| **byte != 0)
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>();
            result.programs.push(ProgramReference {
                id: info.id,
                name: String::from_utf8_lossy(&name).into_owned(),
                ty: libbpf_rs::ProgramType::from(info.type_),
                uid: info.created_by_uid,
            });
        }
    }
    result.partial |= result.inaccessible != 0;
    result.measured = Instant::now();
    result
}

fn recover_names(maps: &mut [MapRow]) {
    let mut btfs = HashMap::new();
    for row in maps {
        if row.info.btf_id == 0 {
            continue;
        }
        let btf = btfs
            .entry(row.info.btf_id)
            .or_insert_with(|| Btf::open(&row.info));
        if let Some(name) = btf.as_ref().and_then(|btf| btf.map_name(&row.info)) {
            row.info.name = name;
        }
    }
}

fn id_from_fd(fd: i32) -> Option<u32> {
    // bpf_obj_get can open pinned programs too. fdinfo distinguishes map FDs.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let fdinfo = libbpf_rs::MapFdInfo::from_fd(borrowed).ok()?;
    if let Some(id) = fdinfo.map_id {
        return Some(id);
    }
    let mut info = libbpf_sys::bpf_map_info::default();
    let mut len = std::mem::size_of_val(&info) as u32;
    let rc = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(fd, (&mut info as *mut _) as *mut c_void, &mut len)
    };
    (rc == 0).then_some(info.id)
}

fn pinned_maps() -> (HashMap<u32, Vec<String>>, bool) {
    let mut paths = vec![PathBuf::from("/sys/fs/bpf")];
    let mut found: HashMap<u32, Vec<String>> = HashMap::new();
    let mut visited = 0;
    let mut incomplete = false;
    while let Some(path) = paths.pop() {
        let Ok(entries) = fs::read_dir(path) else {
            incomplete = true;
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_PIN_NODES {
                return (found, true);
            }
            let path = entry.path();
            let Ok(ty) = entry.file_type() else { continue };
            if ty.is_symlink() {
                continue;
            }
            if ty.is_dir() {
                paths.push(path);
                continue;
            }
            let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) else {
                continue;
            };
            let fd = unsafe { libbpf_sys::bpf_obj_get(path_c.as_ptr()) };
            if fd < 0 {
                continue;
            }
            if let Some(id) = id_from_fd(fd) {
                found
                    .entry(id)
                    .or_default()
                    .push(path.display().to_string());
            }
            unsafe { libc::close(fd) };
        }
    }
    (found, incomplete)
}

pub fn inventory() -> Result<Inventory> {
    let (mut pins, pins_truncated) = pinned_maps();
    let mut maps = Vec::new();
    let mut inaccessible = 0;
    let mut id = 0_u32;
    let mut maps_truncated = false;
    loop {
        if maps.len() + inaccessible >= MAX_MAPS {
            maps_truncated = true;
            break;
        }
        let mut next = 0_u32;
        let rc = unsafe { libbpf_sys::bpf_map_get_next_id(id, &mut next) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                break;
            }
            return Err(err).context("enumerate BPF maps; check CAP_SYS_ADMIN");
        }
        id = next;
        match MapHandle::from_map_id(id).and_then(|map| map.info()) {
            Ok(info) => {
                let info = MapMeta::from(info);
                maps.push(MapRow {
                    pins: pins.remove(&info.id).unwrap_or_default(),
                    info,
                });
            }
            Err(_) => inaccessible += 1,
        }
    }
    recover_names(&mut maps);
    Ok(Inventory {
        maps,
        pins_truncated,
        maps_truncated,
        inaccessible,
    })
}

pub fn inventory_id(id: u32) -> Result<Inventory> {
    let map = MapHandle::from_map_id(id).with_context(|| format!("open map ID {id}"))?;
    let info = MapMeta::from(map.info()?);
    let (mut pins, pins_truncated) = pinned_maps();
    let mut maps = vec![MapRow {
        pins: pins.remove(&id).unwrap_or_default(),
        info,
    }];
    recover_names(&mut maps);
    Ok(Inventory {
        maps,
        pins_truncated,
        maps_truncated: false,
        inaccessible: 0,
    })
}

pub fn previewable(ty: MapType) -> bool {
    matches!(
        ty,
        MapType::Hash
            | MapType::Array
            | MapType::PercpuHash
            | MapType::PercpuArray
            | MapType::LruHash
            | MapType::LruPercpuHash
            | MapType::LpmTrie
    )
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub raw_key: Vec<u8>,
    pub key: String,
    pub value: String,
    pub delta: String,
}

pub struct Preview {
    pub entries: Vec<Entry>,
    pub cpu_ids: Option<Vec<usize>>,
    pub truncated: bool,
    pub read_errors: usize,
    pub baseline: HashMap<Vec<u8>, Vec<u8>>,
    pub previous: HashMap<Vec<u8>, Vec<u8>>,
    pub measured: Instant,
    pub elapsed: Option<Duration>,
    pub next_key: Option<Vec<u8>>,
    pub partial: bool,
    pub scanned: usize,
}

impl Default for Preview {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            cpu_ids: None,
            truncated: false,
            read_errors: 0,
            baseline: HashMap::new(),
            previous: HashMap::new(),
            measured: Instant::now(),
            elapsed: None,
            next_key: None,
            partial: false,
            scanned: 0,
        }
    }
}

fn parse_cpu_ids(text: &str) -> Option<Vec<usize>> {
    let mut ids = Vec::new();
    for part in text.trim().split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let start = start.parse::<usize>().ok()?;
        let end = end.parse::<usize>().ok()?;
        if start > end || end >= 65536 || ids.len() + end - start + 1 > 65536 {
            return None;
        }
        ids.extend(start..=end);
    }
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return None;
    }
    Some(ids)
}

pub fn hex(bytes: &[u8]) -> String {
    const MAX_DISPLAY_BYTES: usize = 64;
    let mut out = String::with_capacity(bytes.len().min(MAX_DISPLAY_BYTES) * 2 + 24);
    out.push_str("0x");
    for byte in bytes.iter().take(MAX_DISPLAY_BYTES) {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    if bytes.len() > MAX_DISPLAY_BYTES {
        use std::fmt::Write;
        let _ = write!(out, "...(+{}B)", bytes.len() - MAX_DISPLAY_BYTES);
    }
    out
}

fn unsigned(bytes: &[u8]) -> Option<u64> {
    if !matches!(bytes.len(), 1 | 2 | 4 | 8) {
        return None;
    }
    let mut raw = [0_u8; 8];
    raw[..bytes.len()].copy_from_slice(bytes);
    Some(u64::from_ne_bytes(raw))
}

fn delta(old: Option<&Vec<u8>>, current: &[u8], unsigned_size: Option<usize>) -> String {
    let Some(old) = old else { return "new".into() };
    if old == current {
        return "=".into();
    }
    if unsigned_size != Some(current.len()) || old.len() != current.len() {
        return "changed".into();
    }
    match (unsigned(old), unsigned(current)) {
        (Some(before), Some(after)) if after >= before => format!("+{}", after - before),
        (Some(_), Some(_)) => "reset/-".into(),
        _ => "changed".into(),
    }
}

fn percpu_numeric_delta(old: Option<&Vec<u8>>, current: &[u8], value_size: usize) -> String {
    let Some(old) = old else { return "new".into() };
    if old == current {
        return "=".into();
    }
    if old.len() != current.len() {
        return "changed".into();
    }
    let sum = |values: &[u8]| {
        values
            .chunks_exact(value_size)
            .filter_map(unsigned)
            .map(u128::from)
            .sum::<u128>()
    };
    match (sum(old), sum(current)) {
        (before, after) if after > before => format!("+{}", after - before),
        (before, after) if after == before => "changed".into(),
        _ => "reset/-".into(),
    }
}

fn bounded_entries(
    key_size: usize,
    value_size: usize,
    cpus: usize,
    requested: usize,
) -> Result<usize> {
    let per_entry = value_size
        .next_multiple_of(8)
        .checked_mul(cpus)
        .and_then(|bytes| bytes.checked_add(key_size))
        .context("entry size overflow")?;
    if per_entry > MAX_PERCPU_ENTRY_BYTES {
        bail!(
            "entry exceeds {}-byte preview safety limit",
            MAX_PERCPU_ENTRY_BYTES
        );
    }
    Ok(requested.min(MAX_SCAN_BYTES / per_entry.max(1)))
}

pub struct PreviewOptions<'a> {
    pub limit: usize,
    pub previous: &'a HashMap<Vec<u8>, Vec<u8>>,
    pub previous_time: Option<Instant>,
    pub query: &'a crate::browse::Query,
    pub anchor: Option<&'a [u8]>,
}

pub fn preview(
    map: &MapHandle,
    info: &MapMeta,
    btf: Option<&Btf>,
    options: PreviewOptions<'_>,
) -> Result<Preview> {
    let PreviewOptions {
        limit,
        previous,
        previous_time,
        query,
        anchor,
    } = options;
    if !previewable(info.ty) {
        bail!("this map type is metadata-only; no read-only key/value iteration");
    }
    if info.key_size as usize > MAX_CELL_BYTES || info.value_size as usize > MAX_CELL_BYTES {
        bail!(
            "key or value exceeds {}-byte preview safety limit",
            MAX_CELL_BYTES
        );
    }
    let cpus = if info.ty.is_percpu() {
        let count = unsafe { libbpf_sys::libbpf_num_possible_cpus() };
        if count <= 0 {
            bail!("cannot determine possible CPU count")
        }
        count as usize
    } else {
        1
    };
    let cpu_ids = info
        .ty
        .is_percpu()
        .then(|| {
            fs::read_to_string("/sys/devices/system/cpu/possible")
                .ok()
                .and_then(|text| parse_cpu_ids(&text))
                .filter(|ids| ids.len() == cpus)
        })
        .flatten();
    let effective_limit = bounded_entries(
        info.key_size as usize,
        info.value_size as usize,
        cpus,
        limit,
    )?;
    let numeric_size = btf.and_then(Btf::unsigned_size);
    let mut entries = Vec::new();
    let mut baseline = HashMap::new();
    let mut read_errors = 0;
    let mut cursor = anchor.map(<[u8]>::to_vec);
    let mut seen = HashSet::new();
    let mut scanned = 0;
    let mut bytes_read: usize = 0;
    let start = Instant::now();
    let per_entry = info.key_size as usize + info.value_size as usize * cpus;
    let exact = match query {
        crate::browse::Query::Key(key) => Some(key),
        _ => None,
    };
    if exact.is_some() && info.ty == MapType::LpmTrie {
        bail!("LPM trie lookup uses longest-prefix matching, not an exact raw-key lookup; use text search instead");
    }
    if exact.is_some_and(|key| key.len() != info.key_size as usize) {
        bail!("Lookup key length does not match the map");
    }
    while entries.len() < effective_limit
        && scanned < 4096
        && bytes_read.saturating_add(per_entry) <= MAX_SCAN_BYTES
        && start.elapsed() < Duration::from_millis(50)
    {
        let key = if let Some(key) = exact {
            if scanned != 0 {
                break;
            }
            key.clone()
        } else {
            let Some(key) = next_key(map, info.key_size as usize, cursor.as_deref())? else {
                break;
            };
            key
        };
        cursor = Some(key.clone());
        scanned += 1;
        bytes_read += per_entry;
        if !seen.insert(key.clone()) {
            continue;
        }
        let value = if info.ty.is_percpu() {
            match map.lookup_percpu(&key, MapFlags::ANY) {
                Ok(Some(cpu_values)) => {
                    let raw = cpu_values.concat();
                    let display = if cpu_values.iter().all(|v| numeric_size == Some(v.len())) {
                        let sum: u128 = cpu_values
                            .iter()
                            .filter_map(|v| unsigned(v))
                            .map(u128::from)
                            .sum();
                        format!("sum={sum} ({} CPUs)", cpu_values.len())
                    } else {
                        let first = cpu_values
                            .first()
                            .map(|v| btf.and_then(|b| b.value(v)).unwrap_or_else(|| hex(v)))
                            .unwrap_or_else(|| "-".into());
                        let label = cpu_ids
                            .as_ref()
                            .and_then(|ids| ids.first())
                            .map_or_else(|| "copy0".into(), |id| format!("CPU{id}"));
                        format!("{label}={first} ({} CPUs)", cpu_values.len())
                    };
                    Some((raw, display))
                }
                Ok(None) => None,
                Err(_) => {
                    read_errors += 1;
                    None
                }
            }
        } else {
            match map.lookup(&key, MapFlags::ANY) {
                Ok(Some(raw)) => {
                    let display = btf.and_then(|b| b.value(&raw)).unwrap_or_else(|| hex(&raw));
                    Some((raw, display))
                }
                Ok(None) => None,
                Err(_) => {
                    read_errors += 1;
                    None
                }
            }
        };
        let Some((raw, display)) = value else {
            continue;
        };
        let key_text = btf.and_then(|b| b.key(&key)).unwrap_or_else(|| hex(&key));
        if !query.matches(&key_text, &display) {
            continue;
        }
        let change = if info.ty.is_percpu() {
            if let Some(size) = numeric_size {
                percpu_numeric_delta(previous.get(&key), &raw, size)
            } else {
                delta(previous.get(&key), &raw, None)
            }
        } else {
            previous
                .get(&key)
                .and_then(|old| btf.and_then(|btf| btf.struct_delta(old, &raw)))
                .unwrap_or_else(|| delta(previous.get(&key), &raw, numeric_size))
        };
        entries.push(Entry {
            raw_key: key.clone(),
            key: key_text,
            value: display,
            delta: change,
        });
        baseline.insert(key, raw);
    }
    let more =
        exact.is_none() && next_key(map, info.key_size as usize, cursor.as_deref())?.is_some();
    let next_key = more.then_some(cursor).flatten();
    let measured = Instant::now();
    let partial = more && entries.len() < effective_limit;
    Ok(Preview {
        entries,
        cpu_ids,
        truncated: more,
        read_errors,
        baseline,
        previous: previous.clone(),
        measured,
        elapsed: previous_time.and_then(|time| measured.checked_duration_since(time)),
        partial,
        scanned,
        next_key,
    })
}

fn next_key(map: &MapHandle, size: usize, previous: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    let mut next = vec![0; size];
    let key = previous.map_or(std::ptr::null(), |key| key.as_ptr().cast());
    let rc = unsafe {
        libbpf_sys::bpf_map_get_next_key(map.as_fd().as_raw_fd(), key, next.as_mut_ptr().cast())
    };
    if rc == 0 {
        return Ok(Some(next));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(error).context("read next map key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires tests/browse.c held alive and BPFMAP_TEST_HASH"]
    fn live_browse_paging_search_and_lookup() {
        let id: u32 = std::env::var("BPFMAP_TEST_HASH").unwrap().parse().unwrap();
        let map = MapHandle::from_map_id(id).unwrap();
        let info = MapMeta::from(map.info().unwrap());
        assert_eq!(info.name, "browse_fixture");
        let baseline = HashMap::new();
        let mut anchor = None;
        let mut keys = HashSet::new();
        loop {
            let page = preview(
                &map,
                &info,
                None,
                PreviewOptions {
                    limit: 7,
                    previous: &baseline,
                    previous_time: None,
                    query: &crate::browse::Query::All,
                    anchor: anchor.as_deref(),
                },
            )
            .unwrap();
            assert!(page.entries.len() <= 7 && page.read_errors == 0);
            for entry in &page.entries {
                assert!(keys.insert(entry.raw_key.clone()));
            }
            anchor = page.next_key;
            if anchor.is_none() {
                break;
            }
        }
        assert_eq!(keys.len(), 200);
        let key = 199_u32.to_ne_bytes().to_vec();
        for query in [
            crate::browse::Query::Text(hex(&key)),
            crate::browse::Query::Key(key.clone()),
        ] {
            let page = preview(
                &map,
                &info,
                None,
                PreviewOptions {
                    limit: 7,
                    previous: &baseline,
                    previous_time: None,
                    query: &query,
                    anchor: None,
                },
            )
            .unwrap();
            assert_eq!(page.entries.len(), 1);
            assert_eq!(page.entries[0].raw_key, key);
            assert_eq!(page.baseline[&key], 1990_u64.to_ne_bytes());
            assert_eq!(
                page.scanned,
                if matches!(query, crate::browse::Query::Key(_)) {
                    1
                } else {
                    200
                }
            );
        }
        let absent = crate::browse::Query::Key(999_u32.to_ne_bytes().to_vec());
        let page = preview(
            &map,
            &info,
            None,
            PreviewOptions {
                limit: 7,
                previous: &baseline,
                previous_time: None,
                query: &absent,
                anchor: None,
            },
        )
        .unwrap();
        assert!(page.entries.is_empty() && page.read_errors == 0 && !page.truncated);

        let options = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as _,
            map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
            ..Default::default()
        };
        let trie =
            MapHandle::create(MapType::LpmTrie, Some("browse_trie"), 8, 4, 8, &options).unwrap();
        let prefix = [8_u32.to_ne_bytes(), [10, 0, 0, 0]].concat();
        let address = [32_u32.to_ne_bytes(), [10, 1, 2, 3]].concat();
        trie.update(&prefix, &17_u32.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        assert_eq!(
            trie.lookup(&address, MapFlags::ANY).unwrap().unwrap(),
            17_u32.to_ne_bytes()
        );
        let info = MapMeta::from(trie.info().unwrap());
        let query = crate::browse::Query::Key(address);
        let result = preview(
            &trie,
            &info,
            None,
            PreviewOptions {
                limit: 7,
                previous: &baseline,
                previous_time: None,
                query: &query,
                anchor: None,
            },
        );
        assert!(result.err().unwrap().to_string().contains("longest-prefix"));
    }

    #[test]
    fn program_map_query_requests_no_instruction_or_debug_buffers() {
        let mut ids = [0_u32; 3];
        let query = program_map_query(&mut ids);
        assert_eq!(query.nr_map_ids, 3);
        assert_eq!(query.map_ids, ids.as_mut_ptr() as u64);
        assert_eq!(query.jited_prog_len, 0);
        assert_eq!(query.xlated_prog_len, 0);
        assert_eq!(query.nr_func_info, 0);
        assert_eq!(query.nr_line_info, 0);
        assert_eq!(query.nr_jited_ksyms, 0);
        assert_eq!(query.nr_jited_func_lens, 0);
    }

    #[test]
    fn cpu_ids_preserve_sparse_possible_cpu_numbers() {
        assert_eq!(parse_cpu_ids("0,2,5-6\n"), Some(vec![0, 2, 5, 6]));
        for text in ["", "4-2", "0,0", "0-999999", "not-a-cpu"] {
            assert_eq!(parse_cpu_ids(text), None);
        }
    }

    #[test]
    fn delta_handles_baseline_and_reset() {
        assert_eq!(delta(None, &5_u32.to_ne_bytes(), Some(4)), "new");
        assert_eq!(delta(None, &[1, 2, 3], None), "new");
        assert_eq!(delta(Some(&vec![1, 2, 3]), &[1, 2, 3], None), "=");
        assert_eq!(
            delta(
                Some(&5_u32.to_ne_bytes().to_vec()),
                &8_u32.to_ne_bytes(),
                Some(4)
            ),
            "+3"
        );
        assert_eq!(
            delta(
                Some(&8_u32.to_ne_bytes().to_vec()),
                &5_u32.to_ne_bytes(),
                Some(4)
            ),
            "reset/-"
        );
        assert_eq!(
            delta(Some(&[1, 2, 3].to_vec()), &[1, 2, 4], None),
            "changed"
        );
        assert_eq!(
            delta(
                Some(&5_u32.to_ne_bytes().to_vec()),
                &8_u32.to_ne_bytes(),
                None
            ),
            "changed"
        );
    }

    #[test]
    fn percpu_delta_distinguishes_unchanged_and_redistributed_values() {
        let bytes = |values: [u64; 2]| {
            values
                .into_iter()
                .flat_map(u64::to_ne_bytes)
                .collect::<Vec<_>>()
        };
        let old = bytes([1, 2]);
        assert_eq!(percpu_numeric_delta(None, &old, 8), "new");
        assert_eq!(percpu_numeric_delta(Some(&old), &old, 8), "=");
        assert_eq!(
            percpu_numeric_delta(Some(&old), &bytes([0, 3]), 8),
            "changed"
        );
        assert_eq!(percpu_numeric_delta(Some(&old), &bytes([2, 4]), 8), "+3");
        assert_eq!(
            percpu_numeric_delta(Some(&old), &bytes([0, 1]), 8),
            "reset/-"
        );
    }

    #[test]
    fn only_data_maps_are_previewable() {
        assert!(previewable(MapType::Hash));
        assert!(previewable(MapType::PercpuArray));
        assert!(!previewable(MapType::RingBuf));
        assert!(!previewable(MapType::Queue));
        assert!(!previewable(MapType::ProgArray));
    }

    #[test]
    fn hex_output_is_bounded() {
        let text = hex(&vec![0xab; 1024]);
        assert!(text.contains("(+960B)"));
        assert!(text.len() < 160);
    }

    #[test]
    fn scan_budget_caps_large_entries() {
        assert_eq!(bounded_entries(4, 4096, 1, 256).unwrap(), 256);
        assert_eq!(bounded_entries(4, 4096, 1, 1024).unwrap(), 511);
        assert!(bounded_entries(4, 4096, 64, 256).is_err());
        assert!(bounded_entries(4, usize::MAX / 2, 64, 256).is_err());
    }

    #[test]
    fn btf_decoder_formats_integer_and_identifies_unsigned_type() {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        assert!(!ptr.is_null());
        let name = CString::new("counter").unwrap();
        let id = unsafe { libbpf_sys::btf__add_int(ptr, name.as_ptr(), 8, 0) };
        assert!(id > 0);
        let btf = Btf {
            ptr: ptr.cast(),
            key_type: id as u32,
            value_type: id as u32,
            ipv4_key: false,
        };
        assert_eq!(btf.unsigned_size(), Some(8));
        let rendered = btf.value(&42_u64.to_ne_bytes()).unwrap();
        assert!(rendered.contains("42"), "{rendered}");
        assert_eq!(btf.type_name(id as u32).as_deref(), Some("counter"));
        assert_eq!(btf.type_name(0), None);
        assert_eq!(btf.type_name(10000), None);
        assert_eq!(btf.expanded(10000, &42_u64.to_ne_bytes()), None);
    }

    fn add_test_field(ptr: *mut libbpf_sys::btf, name: &str, ty: i32, offset: u32) {
        let name = CString::new(name).unwrap();
        assert_eq!(
            unsafe { libbpf_sys::btf__add_field(ptr, name.as_ptr(), ty, offset * 8, 0) },
            0
        );
    }

    #[test]
    fn ipv4_schema_uses_packet_bytes_and_preserves_original_value_and_search() {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        let name = CString::new("__u32").unwrap();
        let id = unsafe { libbpf_sys::btf__add_int(ptr, name.as_ptr(), 4, 0) };
        assert!(id > 0);
        let mut btf = Btf {
            ptr: ptr.cast(),
            key_type: id as u32,
            value_type: id as u32,
            ipv4_key: true,
        };
        let key = [192, 168, 200, 1];
        let display = btf.key(&key).unwrap();
        assert_eq!(display, "192.168.200.1");
        assert!(btf
            .expanded(id as u32, &key)
            .unwrap()
            .contains(&u32::from_ne_bytes(key).to_string()));
        assert!(crate::browse::Query::Text("192.168.200.1".into()).matches(&display, "1"));
        assert_eq!(crate::browse::parse_key("c0 a8 c8 01", 4).unwrap(), key);
        assert_eq!(btf.key_addresses(&[192, 168, 200]), None);
        assert_eq!(btf.addresses(id as u32, &key), None);
        assert!(!btf.value(&key).unwrap().contains("192.168.200.1"));
        btf.ipv4_key = false;
        assert_eq!(btf.key_addresses(&key), None);
    }

    #[test]
    fn typed_addresses_are_nested_and_network_order_but_integers_are_not_guessed() {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        let u32_name = CString::new("__u32").unwrap();
        let u8_name = CString::new("__u8").unwrap();
        let u32_id = unsafe { libbpf_sys::btf__add_int(ptr, u32_name.as_ptr(), 4, 0) };
        let u8_id = unsafe { libbpf_sys::btf__add_int(ptr, u8_name.as_ptr(), 1, 0) };
        let be32_name = CString::new("__be32").unwrap();
        let be32 = unsafe { libbpf_sys::btf__add_typedef(ptr, be32_name.as_ptr(), u32_id) };
        let bytes16 = unsafe { libbpf_sys::btf__add_array(ptr, u32_id, u8_id, 16) };
        let v4_name = CString::new("in_addr").unwrap();
        let v4 = unsafe { libbpf_sys::btf__add_struct(ptr, v4_name.as_ptr(), 4) };
        add_test_field(ptr, "s_addr", u32_id, 0);
        let v6_name = CString::new("in6_addr").unwrap();
        let v6 = unsafe { libbpf_sys::btf__add_struct(ptr, v6_name.as_ptr(), 16) };
        add_test_field(ptr, "bytes", bytes16, 0);
        let outer_name = CString::new("entry").unwrap();
        let outer = unsafe { libbpf_sys::btf__add_struct(ptr, outer_name.as_ptr(), 40) };
        for (name, ty, offset) in [
            ("source", v4, 0),
            ("daddr", be32, 4),
            ("src_ip", u32_id, 8),
            ("cookie", be32, 12),
            ("peer", v6, 16),
            ("counter", u32_id, 32),
            ("guess", u32_id, 36),
        ] {
            add_test_field(ptr, name, ty, offset);
        }
        let btf = Btf {
            ptr: ptr.cast(),
            key_type: outer as u32,
            value_type: outer as u32,
            ipv4_key: false,
        };
        let mut bytes = [0_u8; 40];
        bytes[..4].copy_from_slice(&[192, 0, 2, 1]);
        bytes[4..8].copy_from_slice(&[198, 51, 100, 2]);
        bytes[8..16].fill(255);
        let v6_bytes = "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        bytes[16..32].copy_from_slice(&v6_bytes);
        assert_eq!(
            btf.key_addresses(&bytes).as_deref(),
            Some("source=192.0.2.1; daddr=198.51.100.2; peer=2001:db8::1")
        );
        assert!(btf.value(&bytes).unwrap().contains("peer=2001:db8::1"));
        assert_eq!(btf.addresses(be32 as u32, &bytes[..4]), None);
        assert_eq!(btf.key_addresses(&bytes[..39]), None);
        assert_eq!(btf.addresses(10000, &bytes), None);
        assert_eq!(btf.addresses(v6 as u32, &[0; 16]).as_deref(), Some("::"));
    }

    #[test]
    fn verified_flow_addresses_respect_family_and_reject_ambiguous_layouts() {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        let u8_name = CString::new("__u8").unwrap();
        let u8_id = unsafe { libbpf_sys::btf__add_int(ptr, u8_name.as_ptr(), 1, 0) };
        let u16_name = CString::new("__u16").unwrap();
        let u16_id = unsafe { libbpf_sys::btf__add_int(ptr, u16_name.as_ptr(), 2, 0) };
        let bytes16 = unsafe { libbpf_sys::btf__add_array(ptr, u8_id, u8_id, 16) };
        let bytes4 = unsafe { libbpf_sys::btf__add_array(ptr, u8_id, u8_id, 4) };
        let v6_name = CString::new("aiwan_xdp_bpf_ipv6_key").unwrap();
        let v6 = unsafe { libbpf_sys::btf__add_struct(ptr, v6_name.as_ptr(), 16) };
        add_test_field(ptr, "bytes", bytes16, 0);
        let bad = unsafe { libbpf_sys::btf__add_struct(ptr, v6_name.as_ptr(), 16) };
        add_test_field(ptr, "bytes", bytes4, 0);
        let flow_name = CString::new("aiwan_xdp_bpf_flow_key").unwrap();
        let flow = unsafe { libbpf_sys::btf__add_struct(ptr, flow_name.as_ptr(), 40) };
        add_test_field(ptr, "source_address", bytes16, 0);
        add_test_field(ptr, "destination_address", bytes16, 16);
        add_test_field(ptr, "src_port", u16_id, 32);
        add_test_field(ptr, "dst_port", u16_id, 34);
        add_test_field(ptr, "protocol", u8_id, 36);
        add_test_field(ptr, "address_family", u8_id, 37);
        let btf = Btf {
            ptr: ptr.cast(),
            key_type: flow as u32,
            value_type: u8_id as u32,
            ipv4_key: false,
        };
        let mut key = [0_u8; 40];
        key[..4].copy_from_slice(&[192, 0, 2, 1]);
        key[16..20].copy_from_slice(&[198, 51, 100, 2]);
        assert_eq!(btf.key_addresses(&key), None);
        key[37] = 4;
        key[32..34].copy_from_slice(&774_u16.to_be_bytes());
        key[34..36].copy_from_slice(&11111_u16.to_be_bytes());
        key[36] = 6;
        assert_eq!(
            btf.key_addresses(&key).as_deref(),
            Some("source_address=192.0.2.1; destination_address=198.51.100.2")
        );
        assert_eq!(
            btf.key(&key).as_deref(),
            Some("192.0.2.1:774 -> 198.51.100.2:11111 TCP")
        );
        key[36] = 17;
        assert_eq!(
            btf.key(&key).as_deref(),
            Some("192.0.2.1:774 -> 198.51.100.2:11111 UDP")
        );
        key[36] = 1;
        assert_eq!(
            btf.key(&key).as_deref(),
            Some("192.0.2.1 -> 198.51.100.2 ICMP id=774")
        );
        key[37] = 6;
        key[36] = 6;
        let source = "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        let destination = "fe80::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
        key[..16].copy_from_slice(&source);
        key[16..32].copy_from_slice(&destination);
        assert_eq!(
            btf.key_addresses(&key).as_deref(),
            Some("source_address=2001:db8::1; destination_address=fe80::2")
        );
        assert_eq!(
            btf.key(&key).as_deref(),
            Some("[2001:db8::1]:774 -> [fe80::2]:11111 TCP")
        );
        assert_eq!(
            btf.addresses(v6 as u32, &destination).as_deref(),
            Some("fe80::2")
        );
        assert_eq!(btf.addresses(bad as u32, &destination), None);
        assert_eq!(btf.addresses(bytes16 as u32, &destination), None);
        assert_eq!(btf.addresses(flow as u32, &key[..37]), None);
    }

    fn name_fixture(same_key: bool) -> (Btf, MapMeta, u32) {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        assert!(!ptr.is_null());
        let integer = CString::new("u32").unwrap();
        let key4 = unsafe { libbpf_sys::btf__add_int(ptr, integer.as_ptr(), 4, 0) };
        let bytes = CString::new("ipv6_key").unwrap();
        let key16 = unsafe { libbpf_sys::btf__add_struct(ptr, bytes.as_ptr(), 16) };
        let one = unsafe { libbpf_sys::btf__add_array(ptr, key4, key4, 1) };
        let map_type = unsafe { libbpf_sys::btf__add_ptr(ptr, one) };
        let sixty_four = unsafe { libbpf_sys::btf__add_array(ptr, key4, key4, 64) };
        let max_entries = unsafe { libbpf_sys::btf__add_ptr(ptr, sixty_four) };
        let key4_ptr = unsafe { libbpf_sys::btf__add_ptr(ptr, key4) };
        let key16_ptr =
            unsafe { libbpf_sys::btf__add_ptr(ptr, if same_key { key4 } else { key16 }) };
        let mut vars = Vec::new();
        for (name, key) in [
            ("aiwan_xdp_local_ips", key4_ptr),
            ("aiwan_xdp_local_ipv6", key16_ptr),
        ] {
            let def = CString::new(format!("{name}_definition")).unwrap();
            let id = unsafe { libbpf_sys::btf__add_struct(ptr, def.as_ptr(), 32) };
            assert!(id > 0);
            for (index, (field, ty)) in [
                ("type", map_type),
                ("max_entries", max_entries),
                ("key", key),
                ("value", key4_ptr),
            ]
            .into_iter()
            .enumerate()
            {
                let field = CString::new(field).unwrap();
                assert_eq!(
                    unsafe {
                        libbpf_sys::btf__add_field(ptr, field.as_ptr(), ty, (index * 64) as u32, 0)
                    },
                    0
                );
            }
            let name = CString::new(name).unwrap();
            vars.push(unsafe { libbpf_sys::btf__add_var(ptr, name.as_ptr(), 1, id) });
        }
        let section = CString::new(".maps").unwrap();
        assert!(unsafe { libbpf_sys::btf__add_datasec(ptr, section.as_ptr(), 64) } > 0);
        for (index, id) in vars.into_iter().enumerate() {
            assert_eq!(
                unsafe { libbpf_sys::btf__add_datasec_var_info(ptr, id, (index * 32) as u32, 32) },
                0
            );
        }
        let btf = Btf {
            ptr: ptr.cast(),
            key_type: key4 as u32,
            value_type: key4 as u32,
            ipv4_key: false,
        };
        let info = MapMeta {
            id: 1,
            name: "aiwan_xdp_local".into(),
            kernel_name: "aiwan_xdp_local".into(),
            ty: MapType::Hash,
            key_size: 4,
            value_size: 4,
            max_entries: 64,
            btf_id: 1,
            btf_key_type_id: key4 as u32,
            btf_value_type_id: key4 as u32,
        };
        (btf, info, key16 as u32)
    }

    #[test]
    fn full_names_distinguish_colliding_kernel_prefixes_using_key_types() {
        let (btf, mut info, ipv6) = name_fixture(false);
        assert_eq!(btf.map_name(&info).as_deref(), Some("aiwan_xdp_local_ips"));
        info.btf_key_type_id = ipv6;
        assert_eq!(btf.map_name(&info).as_deref(), Some("aiwan_xdp_local_ipv6"));
        info.max_entries = 65;
        assert_eq!(btf.map_name(&info), None);
    }

    #[test]
    fn ambiguous_btf_names_are_not_guessed() {
        let (btf, info, _) = name_fixture(true);
        assert_eq!(btf.map_name(&info), None);
    }

    #[test]
    fn btf_decoder_formats_struct_fields_without_treating_them_as_counters() {
        let ptr = unsafe { libbpf_sys::btf__new_empty() };
        assert!(!ptr.is_null());
        let integer = CString::new("u32").unwrap();
        let int_id = unsafe { libbpf_sys::btf__add_int(ptr, integer.as_ptr(), 4, 0) };
        assert!(int_id > 0);
        let name = CString::new("stats").unwrap();
        let struct_id = unsafe { libbpf_sys::btf__add_struct(ptr, name.as_ptr(), 8) };
        assert!(struct_id > 0);
        let field_a = CString::new("packets").unwrap();
        let field_b = CString::new("bytes").unwrap();
        assert_eq!(
            unsafe { libbpf_sys::btf__add_field(ptr, field_a.as_ptr(), int_id, 0, 0) },
            0
        );
        assert_eq!(
            unsafe { libbpf_sys::btf__add_field(ptr, field_b.as_ptr(), int_id, 32, 0) },
            0
        );
        let btf = Btf {
            ptr: ptr.cast(),
            key_type: int_id as u32,
            value_type: struct_id as u32,
            ipv4_key: false,
        };
        assert_eq!(btf.unsigned_size(), None);
        let mut data = [0_u8; 8];
        data[..4].copy_from_slice(&3_u32.to_ne_bytes());
        data[4..].copy_from_slice(&42_u32.to_ne_bytes());
        let rendered = btf.value(&data).unwrap();
        assert_eq!(rendered, "packets=3 bytes=42");
        let expanded = btf.expanded(struct_id as u32, &data).unwrap();
        assert!(
            !expanded.chars().any(|ch| ch.is_control() && ch != '\n'),
            "BTF indentation must not move the real terminal cursor: {expanded:?}"
        );
        assert!(
            expanded.contains('\n') && expanded.contains("packets") && expanded.contains("bytes"),
            "{expanded}"
        );
        let mut newer = [0_u8; 8];
        newer[..4].copy_from_slice(&6_u32.to_ne_bytes());
        newer[4..].copy_from_slice(&142_u32.to_ne_bytes());
        let change = btf.struct_delta(&data, &newer).unwrap();
        assert!(
            change.contains("packets +3") && change.contains("bytes +100"),
            "{change}"
        );
    }
}
