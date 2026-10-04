use anyhow::{bail, Context, Result};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use std::{collections::HashMap, fs, os::unix::fs::MetadataExt};

use crate::model::{Counters, Key};

const BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"));

pub struct Snapshot {
    pub rows: HashMap<Key, Counters>,
    pub errors: [u64; 2],
}

pub struct Collector {
    object: Object,
    _links: Vec<Link>,
}

impl Collector {
    pub fn attach(ifindex: u32) -> Result<Self> {
        let object = ObjectBuilder::default()
            .open_memory(BPF)
            .context("open napitop CO-RE object")?
            .load()
            .context("load NAPI probes: Linux 6.6+, BTF, __napi_poll, BPF and tracing permissions are required")?;
        let netns = fs::metadata("/proc/self/ns/net")
            .context("read current network namespace")?
            .ino() as u32;
        let mut scope = [0_u8; 8];
        scope[..4].copy_from_slice(&netns.to_ne_bytes());
        scope[4..].copy_from_slice(&ifindex.to_ne_bytes());
        object
            .maps()
            .find(|map| map.name() == "scope")
            .context("scope map missing")?
            .update(&0_u32.to_ne_bytes(), &scope, MapFlags::ANY)?;

        let links = vec![
            object
                .progs_mut()
                .find(|prog| prog.name() == "on_enter")
                .context("NAPI entry probe missing")?
                .attach_trace()
                .context("attach __napi_poll fentry; check BTF and trampoline support")?,
            object
                .progs_mut()
                .find(|prog| prog.name() == "on_poll")
                .context("NAPI poll probe missing")?
                .attach_raw_tracepoint("napi_poll")
                .context("attach napi:napi_poll tracepoint")?,
        ];
        Ok(Self {
            object,
            _links: links,
        })
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut rows = HashMap::new();
        let stats = self
            .object
            .maps()
            .find(|map| map.name() == "stats")
            .context("stats map missing")?;
        for raw in stats.keys() {
            let key = Key::parse(&raw).context("invalid NAPI key")?;
            if let Some(value) = stats.lookup(&raw, MapFlags::ANY)? {
                rows.insert(
                    key,
                    Counters::parse(&value).context("invalid NAPI counters")?,
                );
            }
        }
        let errors_map = self
            .object
            .maps()
            .find(|map| map.name() == "errors")
            .context("errors map missing")?;
        let mut errors = [0_u64; 2];
        for (i, error) in errors.iter_mut().enumerate() {
            let per_cpu = errors_map.lookup_percpu(&(i as u32).to_ne_bytes(), MapFlags::ANY)?;
            if let Some(values) = per_cpu {
                for value in values {
                    if value.len() != 8 {
                        bail!("invalid error counter");
                    }
                    *error = error.saturating_add(u64::from_ne_bytes(value.as_slice().try_into()?));
                }
            }
        }
        Ok(Snapshot { rows, errors })
    }
}

pub fn interface_index(name: &str) -> Result<u32> {
    let name = std::ffi::CString::new(name).context("interface name contains NUL")?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        bail!(
            "interface {} not found in current network namespace",
            name.to_string_lossy()
        );
    }
    Ok(index)
}

pub fn interface_name(index: u32) -> String {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    let result = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };
    if result.is_null() {
        return format!("if#{index}");
    }
    unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}
