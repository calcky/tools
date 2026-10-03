use anyhow::{bail, Context, Result};
use libbpf_rs::{
    btf::types::Enum, Btf, Link, MapCore, MapFlags, Object, ObjectBuilder, RingBuffer,
    RingBufferBuilder,
};
use std::{
    cell::Cell,
    collections::HashMap,
    fs,
    os::unix::fs::MetadataExt,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::SyncSender,
        Arc,
    },
};

const BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"));

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Key {
    pub location: u64,
    pub reason: u32,
    pub ifindex: u32,
    pub netns: u32,
    pub protocol: u16,
}

impl Key {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 24 {
            bail!("invalid drop key size: {}", bytes.len());
        }
        Ok(Self {
            location: u64::from_ne_bytes(bytes[0..8].try_into()?),
            reason: u32::from_ne_bytes(bytes[8..12].try_into()?),
            ifindex: u32::from_ne_bytes(bytes[12..16].try_into()?),
            netns: u32::from_ne_bytes(bytes[16..20].try_into()?),
            protocol: u16::from_ne_bytes(bytes[20..22].try_into()?),
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Focus {
    pub location: u64,
    pub reason: u32,
    pub ifindex: u32,
    pub netns: u32,
    pub mask: u32,
    pub generation: u32,
}

impl Focus {
    pub fn same_selection(self, other: Self) -> bool {
        self.location == other.location
            && self.reason == other.reason
            && self.ifindex == other.ifindex
            && self.netns == other.netns
            && self.mask == other.mask
    }

    fn bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0..8].copy_from_slice(&self.location.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.reason.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.ifindex.to_ne_bytes());
        bytes[16..20].copy_from_slice(&self.netns.to_ne_bytes());
        bytes[20..24].copy_from_slice(&self.mask.to_ne_bytes());
        bytes[24..28].copy_from_slice(&self.generation.to_ne_bytes());
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropEvent {
    pub timestamp_ns: u64,
    pub location: u64,
    pub reason: u32,
    pub ifindex: u32,
    pub ingress_ifindex: u32,
    pub netns: u32,
    pub length: u32,
    pub generation: u32,
    pub family: u8,
    pub l4_protocol: u8,
    pub status: u8,
    pub source_port: u16,
    pub dest_port: u16,
    pub source: [u8; 16],
    pub dest: [u8; 16],
}

impl DropEvent {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 80 {
            bail!("invalid skb sample size: {}", bytes.len());
        }
        Ok(Self {
            timestamp_ns: u64::from_ne_bytes(bytes[0..8].try_into()?),
            location: u64::from_ne_bytes(bytes[8..16].try_into()?),
            reason: u32::from_ne_bytes(bytes[16..20].try_into()?),
            ifindex: u32::from_ne_bytes(bytes[20..24].try_into()?),
            ingress_ifindex: u32::from_ne_bytes(bytes[24..28].try_into()?),
            netns: u32::from_ne_bytes(bytes[28..32].try_into()?),
            length: u32::from_ne_bytes(bytes[32..36].try_into()?),
            generation: u32::from_ne_bytes(bytes[36..40].try_into()?),
            family: bytes[40],
            l4_protocol: bytes[41],
            status: bytes[42],
            source_port: u16::from_ne_bytes(bytes[44..46].try_into()?),
            dest_port: u16::from_ne_bytes(bytes[46..48].try_into()?),
            source: bytes[48..64].try_into()?,
            dest: bytes[64..80].try_into()?,
        })
    }
}

#[derive(Default)]
pub struct Snapshot {
    pub drops: HashMap<Key, u64>,
    pub stacks: HashMap<u32, u64>,
    pub errors: [u64; 5],
}

pub struct Probe {
    object: Object,
    _link: Link,
    focus: Cell<Focus>,
}

fn sum_percpu(bytes: Vec<Vec<u8>>) -> Result<u64> {
    bytes.into_iter().try_fold(0_u64, |total, bytes| {
        if bytes.len() != 8 {
            bail!("invalid per-CPU counter size: {}", bytes.len());
        }
        Ok(total.saturating_add(u64::from_ne_bytes(bytes.as_slice().try_into()?)))
    })
}

impl Probe {
    pub fn current_focus(&self) -> Focus {
        self.focus.get()
    }

    pub fn attach(interface: Option<(u32, u32)>) -> Result<Self> {
        let mut object = ObjectBuilder::default()
            .open_memory(BPF)
            .context("open droptop CO-RE object")?
            .load()
            .context(
                "load droptop BPF: Linux 6.6+, BTF, BPF and tracing permissions are required",
            )?;
        if let Some((ifindex, netns)) = interface {
            let filter = Focus {
                ifindex,
                netns,
                mask: 2,
                ..Focus::default()
            };
            object
                .maps_mut()
                .find(|map| map.name() == "interface_filter")
                .context("interface filter map missing")?
                .update(&0_u32.to_ne_bytes(), &filter.bytes(), MapFlags::ANY)?;
        }
        let link = object
            .progs_mut()
            .find(|prog| prog.name() == "on_drop")
            .context("kfree_skb program missing")?
            .attach_raw_tracepoint("kfree_skb")
            .context("attach skb:kfree_skb; check tracepoint and BPF permissions")?;
        Ok(Self {
            object,
            _link: link,
            focus: Cell::new(Focus::default()),
        })
    }

    fn map(&self, name: &str) -> Result<libbpf_rs::MapImpl<'_>> {
        self.object
            .maps()
            .find(|map| map.name() == name)
            .with_context(|| format!("BPF map {name} missing"))
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut result = Snapshot::default();
        let map = self.map("drops")?;
        for raw in map.keys() {
            let key = Key::parse(&raw)?;
            if let Some(values) = map.lookup_percpu(&raw, MapFlags::ANY)? {
                result.drops.insert(key, sum_percpu(values)?);
            }
        }
        let map = self.map("stack_counts")?;
        for raw in map.keys() {
            let id = u32::from_ne_bytes(raw.as_slice().try_into()?);
            if let Some(values) = map.lookup_percpu(&raw, MapFlags::ANY)? {
                result.stacks.insert(id, sum_percpu(values)?);
            }
        }
        let map = self.map("errors")?;
        for (i, counter) in result.errors.iter_mut().enumerate() {
            if let Some(values) = map.lookup_percpu(&(i as u32).to_ne_bytes(), MapFlags::ANY)? {
                *counter = sum_percpu(values)?;
            }
        }
        Ok(result)
    }

    pub fn samples(
        &self,
        sender: SyncSender<DropEvent>,
        dropped: Arc<AtomicU64>,
    ) -> Result<RingBuffer<'_>> {
        let map = self.map("samples")?;
        let mut builder = RingBufferBuilder::new();
        builder.add(&map, move |bytes| {
            match DropEvent::parse(bytes) {
                Ok(event) => {
                    if sender.try_send(event).is_err() {
                        dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            0
        })?;
        Ok(builder.build()?)
    }

    pub fn stack(&self, id: u32) -> Result<Vec<u64>> {
        let Some(bytes) = self
            .map("stacks")?
            .lookup(&id.to_ne_bytes(), MapFlags::ANY)?
        else {
            return Ok(Vec::new());
        };
        if bytes.len() % 8 != 0 {
            bail!("invalid stack record size: {}", bytes.len());
        }
        Ok(bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| u64::from_ne_bytes(*chunk))
            .take_while(|address| *address != 0)
            .collect())
    }

    pub fn focus(&self, mut focus: Focus) -> Result<()> {
        let old = self.focus.get();
        focus.generation = old.generation;
        if focus == old {
            return Ok(());
        }
        focus.generation = old.generation.wrapping_add(1);
        let zero = 0_u32.to_ne_bytes();
        self.map("selected")?
            .update(&zero, &Focus::default().bytes(), MapFlags::ANY)?;
        for name in ["stack_counts", "stacks"] {
            let map = self.map(name)?;
            for key in map.keys().collect::<Vec<_>>() {
                map.delete(&key)?;
            }
        }
        self.map("selected")?
            .update(&zero, &focus.bytes(), MapFlags::ANY)?;
        self.focus.set(focus);
        Ok(())
    }
}

pub fn current_netns() -> Result<u32> {
    Ok(fs::metadata("/proc/self/ns/net")?.ino() as u32)
}

pub fn monotonic_ns() -> Result<u64> {
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime");
    }
    Ok(time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
}

pub fn interfaces(netns: u32) -> HashMap<(u32, u32), String> {
    let mut names = HashMap::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return names;
    };
    for entry in entries.flatten() {
        let Ok(index) = fs::read_to_string(entry.path().join("ifindex")) else {
            continue;
        };
        if let Ok(index) = index.trim().parse() {
            names.insert(
                (index, netns),
                entry.file_name().to_string_lossy().into_owned(),
            );
        }
    }
    names
}

pub fn interface(name: &str, netns: u32) -> Result<(u32, u32)> {
    if name.is_empty() || name.contains('/') {
        bail!("invalid interface name {name:?}");
    }
    let path = format!("/sys/class/net/{name}/ifindex");
    let ifindex = fs::read_to_string(&path)
        .with_context(|| format!("interface {name:?} not found in the current network namespace"))?
        .trim()
        .parse()
        .with_context(|| format!("invalid ifindex for {name}"))?;
    Ok((ifindex, netns))
}

pub fn reason_names() -> HashMap<u32, String> {
    let Ok(btf) = Btf::from_vmlinux() else {
        return HashMap::new();
    };
    let Some(reasons) = btf.type_by_name::<Enum>("skb_drop_reason") else {
        return HashMap::new();
    };
    reasons
        .iter()
        .filter_map(|member| {
            let value = u32::try_from(member.value).ok()?;
            let name = member.name?.to_string_lossy();
            Some((
                value,
                name.trim_start_matches("SKB_DROP_REASON_").to_owned(),
            ))
        })
        .collect()
}

pub fn kernel_symbols() -> Vec<(u64, String)> {
    let mut symbols: Vec<_> = fs::read_to_string("/proc/kallsyms")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            let name = fields.next()?;
            (address != 0).then(|| (address, name.to_owned()))
        })
        .collect();
    symbols.sort_by_key(|entry| entry.0);
    symbols
}

pub fn symbol(address: u64, symbols: &[(u64, String)]) -> String {
    if address == 0 {
        return "unknown".into();
    }
    let index = symbols.partition_point(|entry| entry.0 <= address);
    if index == 0 {
        return format!("0x{address:x}");
    }
    let (base, name) = &symbols[index - 1];
    format!("{name}+0x{:x}", address - base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_layout() {
        let mut bytes = [0_u8; 24];
        bytes[0..8].copy_from_slice(&0x1234_u64.to_ne_bytes());
        bytes[8..12].copy_from_slice(&5_u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&10_u32.to_ne_bytes());
        bytes[20..22].copy_from_slice(&0x800_u16.to_ne_bytes());
        assert_eq!(Key::parse(&bytes).unwrap().protocol, 0x800);
        assert_eq!(Key::parse(&bytes).unwrap().location, 0x1234);
        assert!(Key::parse(&bytes[..23]).is_err());
    }

    #[test]
    fn focus_layout() {
        let focus = Focus {
            location: 42,
            reason: 3,
            ifindex: 2,
            netns: 12,
            mask: 7,
            generation: 9,
        };
        assert_eq!(&focus.bytes()[20..24], &7_u32.to_ne_bytes());
        assert_eq!(&focus.bytes()[24..28], &9_u32.to_ne_bytes());
    }

    #[test]
    fn parses_sample_with_fixed_layout() {
        let mut bytes = [0_u8; 80];
        bytes[24..28].copy_from_slice(&4_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[40] = 4;
        bytes[41] = 17;
        bytes[44..46].copy_from_slice(&1234_u16.to_ne_bytes());
        bytes[48..52].copy_from_slice(&[192, 0, 2, 1]);
        let event = DropEvent::parse(&bytes).unwrap();
        assert_eq!(event.ingress_ifindex, 4);
        assert_eq!(event.generation, 7);
        assert_eq!(event.source_port, 1234);
        assert_eq!(&event.source[..4], &[192, 0, 2, 1]);
        assert!(DropEvent::parse(&bytes[..79]).is_err());
    }
}
