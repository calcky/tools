use anyhow::{bail, Context, Result};
use libbpf_rs::{libbpf_sys, MapCore, MapFlags, MapHandle, MapType};
use std::{
    collections::HashMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs,
    os::{fd::BorrowedFd, unix::ffi::OsStrExt},
    path::PathBuf,
};

const MAX_MAPS: usize = 8192;
const MAX_PIN_NODES: usize = 2048;
const MAX_CELL_BYTES: usize = 4096;
const MAX_SCAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_PERCPU_ENTRY_BYTES: usize = 64 * 1024;

unsafe extern "C" {
    fn bpfmap_btf_open(id: u32) -> *mut c_void;
    fn bpfmap_btf_close(btf: *mut c_void);
    fn bpfmap_btf_format(
        btf: *mut c_void,
        type_id: u32,
        data: *const c_void,
        len: usize,
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
}

impl Btf {
    pub fn open(info: &MapMeta) -> Option<Self> {
        if info.btf_id == 0 {
            return None;
        }
        let ptr = unsafe { bpfmap_btf_open(info.btf_id) };
        (!ptr.is_null()).then_some(Self {
            ptr,
            key_type: info.btf_key_type_id,
            value_type: info.btf_value_type_id,
        })
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
        self.render(self.key_type, bytes)
    }

    pub fn value(&self, bytes: &[u8]) -> Option<String> {
        self.render(self.value_type, bytes)
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
            return Err(err).context("enumerate BPF maps; check CAP_BPF/CAP_SYS_ADMIN");
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
    Ok(Inventory {
        maps: vec![MapRow {
            pins: pins.remove(&id).unwrap_or_default(),
            info,
        }],
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
    pub key: String,
    pub value: String,
    pub delta: String,
}

pub struct Preview {
    pub entries: Vec<Entry>,
    pub truncated: bool,
    pub read_errors: usize,
    pub baseline: HashMap<Vec<u8>, Vec<u8>>,
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

pub fn preview(
    map: &MapHandle,
    info: &MapMeta,
    btf: Option<&Btf>,
    limit: usize,
    previous: &HashMap<Vec<u8>, Vec<u8>>,
) -> Result<Preview> {
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
    let mut keys = map.keys();
    for key in keys.by_ref().take(effective_limit) {
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
                        format!("CPU0={first} ({} CPUs)", cpu_values.len())
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
        let change = if info.ty.is_percpu() {
            if numeric_size.is_some() {
                let size = numeric_size.unwrap_or_default();
                let previous_sum = previous.get(&key).and_then(|old| {
                    (old.len() == raw.len()).then(|| {
                        old.chunks_exact(size)
                            .filter_map(unsigned)
                            .map(u128::from)
                            .sum::<u128>()
                    })
                });
                let current_sum: u128 = raw
                    .chunks_exact(size)
                    .filter_map(unsigned)
                    .map(u128::from)
                    .sum();
                match previous_sum {
                    None => "new".into(),
                    Some(old) if current_sum >= old => format!("+{}", current_sum - old),
                    Some(_) => "reset/-".into(),
                }
            } else if previous.get(&key).is_some_and(|old| old == &raw) {
                "=".into()
            } else {
                "changed".into()
            }
        } else {
            previous
                .get(&key)
                .and_then(|old| btf.and_then(|btf| btf.struct_delta(old, &raw)))
                .unwrap_or_else(|| delta(previous.get(&key), &raw, numeric_size))
        };
        let key_text = btf.and_then(|b| b.key(&key)).unwrap_or_else(|| hex(&key));
        entries.push(Entry {
            key: key_text,
            value: display,
            delta: change,
        });
        baseline.insert(key, raw);
    }
    // One extra kernel call tells us whether the preview is partial; no value is read.
    let truncated = keys.next().is_some();
    Ok(Preview {
        entries,
        truncated,
        read_errors,
        baseline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_handles_baseline_and_reset() {
        assert_eq!(delta(None, &5_u32.to_ne_bytes(), Some(4)), "new");
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
        };
        assert_eq!(btf.unsigned_size(), Some(8));
        let rendered = btf.value(&42_u64.to_ne_bytes()).unwrap();
        assert!(rendered.contains("42"), "{rendered}");
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
        };
        assert_eq!(btf.unsigned_size(), None);
        let mut data = [0_u8; 8];
        data[..4].copy_from_slice(&3_u32.to_ne_bytes());
        data[4..].copy_from_slice(&42_u32.to_ne_bytes());
        let rendered = btf.value(&data).unwrap();
        assert!(
            rendered.contains("packets") && rendered.contains("bytes"),
            "{rendered}"
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
