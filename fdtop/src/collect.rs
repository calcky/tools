use anyhow::{bail, Context, Result};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use std::collections::{HashMap, HashSet};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    pub start: u64,
    pub object: u64,
    pub pid: u32,
    pub fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub key: Key,
    pub ino: u64,
    pub dev: u32,
    pub kind: u32,
    pub comm: [u8; 16],
    pub name: [u8; 64],
    pub family: u32,
    pub protocol: u32,
    pub sport: u16,
    pub dport: u16,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub pad: u32,
}

impl Default for Identity {
    fn default() -> Self {
        // All fields are integers or byte arrays.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    pub bytes: u64,
    pub ops: u64,
    pub errors: u64,
    pub again: u64,
    pub restarts: u64,
    pub ns: u64,
    pub max_ns: u64,
    pub hist: [u64; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Record {
    pub id: Identity,
    pub rd: Metrics,
    pub wr: Metrics,
    pub calls: u64,
    pub last_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Pending {
    pub first: Key,
    pub second: Key,
    pub since: u64,
    pub addr: u64,
    pub requested: u64,
    pub op: u32,
    pub two: u32,
}

#[derive(Default)]
pub struct Snapshot {
    pub retired: HashSet<u64>,
    pub latency: bool,
    pub at: u64,
    pub records: HashMap<Key, Record>,
    pub pending: Vec<Pending>,
    pub gaps: [u64; 5],
}

/// # Safety
/// Implement only for C ABI records whose fields admit every bit pattern.
unsafe trait Wire: Copy {}
unsafe impl Wire for Record {}
unsafe impl Wire for Pending {}
unsafe impl Wire for u64 {}
fn decode<T: Wire>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != std::mem::size_of::<T>() {
        bail!("unexpected BPF record size: {}", bytes.len());
    }
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

pub fn now_ns() -> Result<u64> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return Err(std::io::Error::last_os_error()).context("clock_gettime");
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

pub struct Collector {
    latency: bool,
    object: Object,
    _links: Vec<Link>,
}

impl Collector {
    pub fn new(pid: Option<u32>, fd: Option<i32>, latency: bool) -> Result<Self> {
        let bytes: &[u8] = if latency {
            include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"))
        } else {
            include_bytes!(concat!(env!("OUT_DIR"), "/observe-light.bpf.o"))
        };
        let object = ObjectBuilder::default()
            .open_memory(bytes)?
            .load()
            .context("load I/O BPF probes: Linux 6.6+, BTF and BPF/tracing privileges required")?;
        let mut result = Self {
            latency,
            object,
            _links: Vec::new(),
        };
        let mut config = Vec::new();
        config.extend(pid.unwrap_or(0).to_ne_bytes());
        config.extend(std::process::id().to_ne_bytes());
        config.extend(fd.unwrap_or(-1).to_ne_bytes());
        config.extend(0_u32.to_ne_bytes());
        result
            .map("settings")?
            .update(&0_u32.to_ne_bytes(), &config, MapFlags::ANY)?;
        for (nr, op) in operations() {
            result.map("operations")?.update(
                &nr.to_ne_bytes(),
                &op.to_ne_bytes(),
                MapFlags::ANY,
            )?;
        }
        for name in ["release_file", "exit_task"] {
            let link = result
                .object
                .progs_mut()
                .find(|p| p.name() == name)
                .with_context(|| format!("missing BPF program {name}"))?
                .attach_trace()
                .with_context(|| format!("attach {name}"))?;
            result._links.push(link);
        }
        for (name, event) in [("leave", "sys_exit"), ("enter", "sys_enter")] {
            let link = result
                .object
                .progs_mut()
                .find(|p| p.name() == name)
                .with_context(|| format!("missing BPF program {name}"))?
                .attach_tracepoint(libbpf_rs::TracepointCategory::RawSyscalls, event)
                .with_context(|| format!("attach raw_syscalls/{event}"))?;
            result._links.push(link);
        }
        Ok(result)
    }

    fn map(&self, name: &str) -> Result<impl MapCore + '_> {
        self.object
            .maps()
            .find(|m| m.name() == name)
            .with_context(|| format!("missing BPF map {name}"))
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut result = Snapshot {
            latency: self.latency,
            ..Default::default()
        };
        // Read the retirement set first: records retired later may still be
        // changing during this scan and must survive until the next snapshot.
        let retired = self.map("retired")?;
        let dead: HashSet<u64> = retired
            .keys()
            .map(|key| decode::<u64>(&key))
            .collect::<Result<_>>()?;
        let records = self.map("records")?;
        for key in records.keys() {
            if let Some(bytes) = records.lookup(&key, MapFlags::ANY)? {
                let record: Record = decode(&bytes)?;
                result.records.insert(record.id.key, record);
            }
        }
        // Do not delete while iterating get_next_key: deleting the previous key
        // can restart a hash-map walk.
        for key in result
            .records
            .keys()
            .filter(|key| dead.contains(&key.object))
        {
            let mut bytes = Vec::with_capacity(24);
            bytes.extend(key.start.to_ne_bytes());
            bytes.extend(key.object.to_ne_bytes());
            bytes.extend(key.pid.to_ne_bytes());
            bytes.extend(key.fd.to_ne_bytes());
            records.delete(&bytes)?;
        }
        result.retired = dead.clone();
        for id in dead {
            retired.delete(&id.to_ne_bytes())?;
        }
        let pending = self.map("inflight")?;
        for key in pending.keys() {
            if let Some(bytes) = pending.lookup(&key, MapFlags::ANY)? {
                result.pending.push(decode(&bytes)?);
            }
        }
        for (i, value) in result.gaps.iter_mut().enumerate() {
            if let Some(bytes) = self
                .map("gaps")?
                .lookup(&(i as u32).to_ne_bytes(), MapFlags::ANY)?
            {
                *value = decode(&bytes)?;
            }
        }
        result.at = now_ns()?;
        Ok(result)
    }
}

fn operations() -> Vec<(u32, u32)> {
    use libc::*;
    let read = [
        SYS_read,
        SYS_pread64,
        SYS_readv,
        SYS_preadv,
        SYS_preadv2,
        SYS_recvfrom,
        SYS_recvmsg,
        SYS_mq_timedreceive,
    ];
    let write = [
        SYS_write,
        SYS_pwrite64,
        SYS_writev,
        SYS_pwritev,
        SYS_pwritev2,
        SYS_sendto,
        SYS_sendmsg,
    ];
    let mut ops: Vec<_> = read.into_iter().map(|n| (n as u32, 1)).collect();
    ops.extend(write.into_iter().map(|n| (n as u32, 2)));
    ops.extend([
        (SYS_sendmmsg as u32, 3),
        (SYS_recvmmsg as u32, 4),
        (SYS_mq_timedsend as u32, 5),
        (SYS_sendfile as u32, 6),
        (SYS_splice as u32, 7),
        (SYS_tee as u32, 9),
        (SYS_copy_file_range as u32, 8),
        (SYS_vmsplice as u32, 2),
    ]);
    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_layout_matches_bpf() {
        assert_eq!(std::mem::size_of::<Key>(), 24);
        assert_eq!(std::mem::size_of::<Identity>(), 168);
        assert_eq!(std::mem::size_of::<Metrics>(), 312);
        assert_eq!(std::mem::size_of::<Record>(), 808);
        assert_eq!(std::mem::size_of::<Pending>(), 80);
        assert!(decode::<Record>(&[0; 807]).is_err());
        assert_eq!(decode::<Record>(&[0; 808]).unwrap().rd.bytes, 0);
    }

    #[test]
    fn operations_fit_bpf_dispatch_array() {
        let ops = operations();
        let mut seen = HashSet::new();
        for (nr, op) in ops {
            assert!(nr < 512);
            assert!((1..=9).contains(&op));
            assert!(seen.insert(nr));
        }
    }
}
