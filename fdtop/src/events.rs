use crate::{
    collect::{now_ns, Identity},
    model::{clean, Filter, Frame},
};
use anyhow::{bail, Context, Result};
use libbpf_rs::{
    btf::types::Func, Btf, Link, MapCore, MapFlags, Object, ObjectBuilder, RingBuffer,
    RingBufferBuilder,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{self, Write},
    rc::Rc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const CAPACITY: usize = 8192;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Event {
    pub id: Identity,
    pub ns: u64,
    pub kind: u32,
    pub reason: u32,
    pub source: i32,
    pub tid: u32,
    pub ifindex: u32,
    pub queue: u32,
}

impl Event {
    pub fn action(&self) -> &'static str {
        match self.kind {
            0 => "EXISTING",
            1 => "OPEN",
            2 => "DUP",
            3 => "CLOSE",
            4 => "INHERIT",
            5 => "UPDATE",
            _ => "UNKNOWN",
        }
    }
    pub fn reason(&self) -> &'static str {
        match self.reason {
            1 => "replace",
            2 => "cloexec",
            3 => "table-release",
            4 => "fork",
            5 => "bind/connect",
            _ => "",
        }
    }
    pub fn label(&self) -> String {
        if self.id.family == 44 {
            if self.ifindex == 0 {
                return "XSK unbound".into();
            }
            return format!(
                "XSK {} q{} (ifindex {})",
                clean(&self.id.name),
                self.queue,
                self.ifindex
            );
        }
        if self.id.kind == 2 {
            return format!("{}:[{}]", self.id.kind_name(), self.id.ino);
        }
        self.id.object_name()
    }
}

pub struct Item {
    pub event: Event,
    pub label: String,
}

#[derive(Default)]
pub struct Store {
    pub history: VecDeque<Item>,
    pending: VecDeque<Item>,
    pub received: u64,
    pub filtered: u64,
    pub evicted: u64,
    pub output_dropped: u64,
    pub decode_errors: u64,
}
impl Store {
    fn insert(&mut self, event: Event, label: String, filter: &Filter) {
        self.received += 1;
        if filter.fd.is_some_and(|v| v != event.id.key.fd)
            || filter
                .name
                .as_ref()
                .is_some_and(|v| !clean(&event.id.comm).contains(v))
            || filter.kind.as_ref().is_some_and(|v| {
                v != event.id.kind_name() && !(v == "SOCKET" && event.id.kind == 2)
            })
        {
            self.filtered += 1;
            return;
        }
        if self.history.len() == CAPACITY {
            self.history.pop_front();
            self.evicted += 1;
        }
        if self.pending.len() == CAPACITY {
            self.pending.pop_front();
            self.output_dropped += 1;
        }
        self.history.push_back(Item {
            event,
            label: label.clone(),
        });
        self.pending.push_back(Item { event, label });
    }
    fn ingest(&mut self, bytes: &[u8], filter: &Filter) {
        if bytes.len() != std::mem::size_of::<Event>() {
            self.decode_errors += 1;
            return;
        }
        // Event contains only integers and arrays; ringbuf samples need not be aligned.
        let e = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Event>()) };
        if !(1..=5).contains(&e.kind) {
            self.decode_errors += 1;
            return;
        }
        self.insert(e, e.label(), filter);
    }
}

pub struct Collector {
    ring: RingBuffer<'static>,
    _links: Vec<Link>,
    object: Object,
    pub store: Rc<RefCell<Store>>,
    pub losses: [u64; 4],
    pub removal_hook: String,
    pub pid: Option<u32>,
    offset_ns: u64,
}

impl Collector {
    pub fn new(pid: Option<u32>, filter: &Filter, initial: &Frame) -> Result<Self> {
        let btf = Btf::from_vmlinux().context("FD events require kernel BTF")?;
        let removal = ["file_close_fd_locked", "pick_file"]
            .into_iter()
            .find(|n| btf.type_by_name::<Func<'_>>(n).is_some())
            .context("FD events unavailable: no file_close_fd_locked/pick_file hook")?;
        for name in [
            "fd_install",
            "do_dup2",
            "do_close_on_exec",
            "put_files_struct",
            "exit_files",
            "__fput",
        ] {
            if btf.type_by_name::<Func<'_>>(name).is_none() {
                bail!("FD events unavailable: required hook {name} missing");
            }
        }
        let mut opened = ObjectBuilder::default()
            .open_memory(include_bytes!(concat!(env!("OUT_DIR"), "/events.bpf.o")))?;
        opened
            .progs_mut()
            .find(|p| p.name() == "remove_fd")
            .context("missing removal probe")?
            .set_attach_target(0, Some(removal.into()))?;
        let object = opened.load().context("load FD lifecycle probes")?;
        let ops = object
            .maps()
            .find(|m| m.name() == "operations")
            .context("operations map")?;
        let operations = [
            (libc::SYS_dup, 1_u32),
            (libc::SYS_dup3, 1),
            (libc::SYS_fcntl, 3),
            (libc::SYS_bind, 2),
            (libc::SYS_connect, 2),
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_dup2, 1),
        ];
        for (nr, op) in operations {
            ops.update(&(nr as u32).to_ne_bytes(), &op.to_ne_bytes(), MapFlags::ANY)?;
        }
        let store = Rc::new(RefCell::new(Store::default()));
        let shared = Rc::clone(&store);
        let filter_cb = filter.clone();
        let ring = {
            let map = object
                .maps()
                .find(|m| m.name() == "events")
                .context("events map")?;
            let mut builder = RingBufferBuilder::new();
            builder.add(&map, move |data| {
                shared.borrow_mut().ingest(data, &filter_cb);
                0
            })?;
            builder.build()?
        };
        let mut links = Vec::new();
        // Keep events disabled until every required probe is attached.
        for prog in object.progs_mut() {
            let name = prog.name().to_string_lossy().into_owned();
            let link =
                match name.as_str() {
                    "event_enter" => prog
                        .attach_tracepoint(libbpf_rs::TracepointCategory::RawSyscalls, "sys_enter"),
                    "event_exit" => prog
                        .attach_tracepoint(libbpf_rs::TracepointCategory::RawSyscalls, "sys_exit"),
                    _ => prog.attach_trace(),
                }
                .with_context(|| format!("attach FD event probe {name}"))?;
            links.push(link);
        }
        let mono = now_ns()?;
        let real = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64;
        let mut config = Vec::new();
        config.extend(pid.unwrap_or(0).to_ne_bytes());
        config.extend(std::process::id().to_ne_bytes());
        config.extend(filter.fd.unwrap_or(-1).to_ne_bytes());
        config.extend(1_u32.to_ne_bytes());
        object
            .maps()
            .find(|m| m.name() == "settings")
            .context("settings map")?
            .update(&0_u32.to_ne_bytes(), &config, MapFlags::ANY)?;
        // This is an inventory observation, not a reconstructed OPEN. Its
        // timestamp is the baseline boundary; syscall activity can race it.
        for row in &initial.rows {
            if row.state != "open" || pid.is_none_or(|pid| row.total.id.key.pid != pid) {
                continue;
            }
            let mut id = row.total.id;
            id.key.object = 0;
            let e = Event {
                id,
                ns: mono,
                kind: 0,
                source: -1,
                ..Default::default()
            };
            store.borrow_mut().insert(e, row.object.clone(), filter);
        }
        Ok(Self {
            ring,
            _links: links,
            object,
            store,
            losses: [0; 4],
            removal_hook: removal.into(),
            pid,
            offset_ns: real.saturating_sub(mono),
        })
    }
    pub fn poll(&mut self) -> Result<()> {
        self.ring.poll(Duration::ZERO)?;
        let map = self
            .object
            .maps()
            .find(|m| m.name() == "losses")
            .context("losses map")?;
        for (i, value) in self.losses.iter_mut().enumerate() {
            if let Some(bytes) = map.lookup(&(i as u32).to_ne_bytes(), MapFlags::ANY)? {
                *value = u64::from_ne_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid event counter"))?,
                );
            }
        }
        Ok(())
    }
    pub fn time(&self, ns: u64) -> String {
        let real = ns.saturating_add(self.offset_ns);
        let seconds = (real / 1_000_000_000) as _;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
            return "?".into();
        }
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            (real / 1_000_000) % 1000
        )
    }
    pub fn print(&self, json: bool) -> io::Result<()> {
        let mut store = self.store.borrow_mut();
        let items: Vec<_> = store.pending.drain(..).collect();
        let mut out = io::stdout().lock();
        if json {
            let events:Vec<_>=items.iter().map(|item|{let e=&item.event; serde_json::json!({
                "monotonic_ns":e.ns,"unix_ns":e.ns.saturating_add(self.offset_ns),"pid":e.id.key.pid,"tid":e.tid,"process_start":e.id.key.start,
                "fd":e.id.key.fd,"event":e.action(),"reason":e.reason(),"source_fd":(e.source>=0).then_some(e.source),
                "event_object_id":e.id.key.object,"type":e.id.kind_name(),"inode":e.id.ino,"device":e.id.dev,"comm":clean(&e.id.comm),"object":item.label,
                "ifindex":(e.ifindex>0).then_some(e.ifindex),"queue":(e.ifindex>0).then_some(e.queue)})}).collect();
            writeln!(
                out,
                "{}",
                serde_json::json!({"view":"events","pid":self.pid,"events":events,"losses":self.losses,"history_evicted":store.evicted,"output_dropped":store.output_dropped,"decode_errors":store.decode_errors,"filtered":store.filtered,"removal_hook":self.removal_hook})
            )?;
        } else {
            writeln!(out,"\nfdtop events | received {} | lost {:?} | history evicted {} | output dropped {} | decode errors {}",store.received,self.losses,store.evicted,store.output_dropped,store.decode_errors)?;
            writeln!(
                out,
                "{:<12} {:>7} {:>6} {:<8} {:<8} {:>8}  OBJECT / REASON",
                "TIME", "PID", "FD", "EVENT", "TYPE", "OBJECT#"
            )?;
            for item in items {
                let e = item.event;
                writeln!(
                    out,
                    "{} {:>7} {:>6} {:<8} {:<8} {:>8}  {} {}{}",
                    self.time(e.ns),
                    e.id.key.pid,
                    e.id.key.fd,
                    e.action(),
                    e.id.kind_name(),
                    e.id.key.object,
                    item.label,
                    e.reason(),
                    if e.source >= 0 {
                        format!(" from FD {}", e.source)
                    } else {
                        String::new()
                    }
                )?;
            }
        }
        out.flush()
    }
    pub fn discard_output(&self) {
        self.store.borrow_mut().pending.clear();
    }

    pub fn finish(&mut self, print: bool, json: bool) -> Result<()> {
        // Stop producers before the final drain, including in-flight fexit
        // callbacks. Do not silently discard the tail on Ctrl+C or -c exit.
        self._links.clear();
        self.poll()?;
        if print && !self.store.borrow().pending.is_empty() {
            self.print(json)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_and_bounded_history() {
        assert_eq!(std::mem::size_of::<Event>(), 200);
        let mut s = Store::default();
        let f = Filter::default();
        s.ingest(&[0; 3], &f);
        assert_eq!(s.decode_errors, 1);
        for _ in 0..CAPACITY + 2 {
            s.insert(Event::default(), "x".into(), &f);
        }
        assert_eq!(s.history.len(), CAPACITY);
        assert_eq!(s.evicted, 2);
        assert_eq!(s.output_dropped, 2);
    }
    #[test]
    fn filters_and_xsk_binding() {
        let mut e = Event::default();
        e.id.kind = 2;
        e.id.family = 44;
        e.ifindex = 3;
        e.queue = 2;
        e.id.name[..4].copy_from_slice(b"eth0");
        assert_eq!(e.label(), "XSK eth0 q2 (ifindex 3)");
        let mut s = Store::default();
        s.insert(
            e,
            e.label(),
            &Filter {
                kind: Some("TCP".into()),
                ..Default::default()
            },
        );
        assert_eq!(s.filtered, 1);
        assert!(s.history.is_empty());
    }
}
