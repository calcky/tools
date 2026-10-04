use crate::{
    collect::{Identity, Key, Metrics, Record, Snapshot},
    metadata::{self, Resolver},
    model::{clean, Filter, Frame, Process, Row},
};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

struct Entry {
    id: Identity,
    object: String,
    access: &'static str,
    error: Option<String>,
}

fn start_ticks(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other("invalid process start time"))
}

fn ticks(ns: u64) -> u64 {
    (u128::from(ns) * unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u128 / 1_000_000_000) as u64
}

fn put(target: &mut [u8], value: &[u8]) {
    let count = target.len().min(value.len());
    target[..count].copy_from_slice(&value[..count]);
}

fn access(info: &str) -> &'static str {
    let flags = info
        .lines()
        .find_map(|s| s.strip_prefix("flags:"))
        .and_then(|s| u32::from_str_radix(s.trim(), 8).ok());
    match flags {
        Some(n) if n & libc::O_PATH as u32 != 0 => "path",
        Some(n) => match n & libc::O_ACCMODE as u32 {
            0 => "r",
            1 => "w",
            2 => "rw",
            _ => "-",
        },
        None => "-",
    }
}

fn entry(
    pid: u32,
    fd: i32,
    start: u64,
    comm: &str,
    process: Option<&OwnedFd>,
    resolver: &mut Resolver,
) -> io::Result<Entry> {
    let path = format!("/proc/{pid}/fd/{fd}");
    let before = fs::metadata(&path)?;
    let target = fs::read_link(&path)?;
    let object = clean(target.as_os_str().as_encoded_bytes());
    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
    let mut id = Identity {
        key: Key {
            pid,
            fd,
            start,
            object: 0,
        },
        ino: before.ino(),
        dev: (libc::major(before.dev()) << 20) | libc::minor(before.dev()),
        kind: match before.mode() & libc::S_IFMT {
            libc::S_IFSOCK => 2,
            libc::S_IFIFO => 3,
            libc::S_IFCHR => 4,
            libc::S_IFBLK => 5,
            _ => 1,
        },
        ..Default::default()
    };
    put(&mut id.comm, comm.trim_end().as_bytes());
    let name = object.strip_prefix("anon_inode:").unwrap_or(&object);
    put(&mut id.name, name.as_bytes());
    if object.starts_with("anon_inode:") {
        id.kind = 7;
    }
    // POSIX MQ descriptors are regular in stat, but their filesystem is mqueue.
    let cpath = std::ffi::CString::new(path.clone()).unwrap();
    let mut fsstat: libc::statfs = unsafe { std::mem::zeroed() };
    if id.kind == 1
        && unsafe { libc::statfs(cpath.as_ptr(), &mut fsstat) } == 0
        && fsstat.f_type == 0x19800202
    {
        id.kind = 6;
    }
    let after = fs::metadata(&path)?;
    if !metadata::matches(&id, after.ino(), after.dev()) {
        return Err(io::Error::other("FD changed during inventory"));
    }
    let mut result = Entry {
        id,
        object,
        access: access(&info),
        error: None,
    };
    if id.kind == 2 {
        let queried = (|| {
            let process = process.ok_or_else(|| io::Error::other("pidfd unavailable"))?;
            let duplicate = metadata::owned(unsafe {
                libc::syscall(libc::SYS_pidfd_getfd, process.as_raw_fd(), fd, 0) as i32
            })?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(duplicate.as_raw_fd(), &mut stat) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if !metadata::matches(&id, stat.st_ino, stat.st_dev) {
                return Err(io::Error::other("FD changed during socket query"));
            }
            result.id.family =
                metadata::socket_option(duplicate.as_raw_fd(), libc::SO_DOMAIN)? as u32;
            result.id.protocol =
                metadata::socket_option(duplicate.as_raw_fd(), libc::SO_PROTOCOL)? as u32;
            resolver.describe(duplicate.as_raw_fd(), &result.id)
        })();
        match queried {
            Ok(value) => result.object = value,
            Err(error) => result.error = Some(error.to_string()),
        }
    }
    Ok(result)
}

fn accepts(id: &Identity, filter: &Filter) -> bool {
    filter.fd.is_none_or(|fd| fd == id.key.fd)
        && filter
            .name
            .as_ref()
            .is_none_or(|name| clean(&id.comm).contains(name))
        && filter
            .kind
            .as_ref()
            .is_none_or(|kind| kind == id.kind_name() || (kind == "SOCKET" && id.kind == 2))
}

/// Proc inventory is deliberately scoped to a selected process, not the whole
/// machine. The BPF snapshot remains unchanged and is the sole counter source.
pub fn enrich(
    data: &mut Frame,
    snapshot: &Snapshot,
    pid: u32,
    filter: &Filter,
    resolver: &mut Resolver,
) {
    if let Err(error) = scan(data, snapshot, pid, filter, resolver) {
        data.inventory_error = Some(format!("PID {pid} inventory: {error}"));
    }
}

fn scan(
    data: &mut Frame,
    snapshot: &Snapshot,
    pid: u32,
    filter: &Filter,
    resolver: &mut Resolver,
) -> io::Result<()> {
    let began = start_ticks(pid)?;
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))?;
    let start = snapshot
        .records
        .keys()
        .find(|k| k.pid == pid && ticks(k.start) == began)
        .map_or_else(
            || {
                (u128::from(began) * 1_000_000_000
                    / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u128) as u64
            },
            |k| k.start,
        );
    let process =
        metadata::owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 }).ok();
    let mut entries = Vec::new();
    let mut failed = 0;
    let mut uncertain = HashSet::new();
    for item in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let item = item?;
        let Some(fd) = item
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
        else {
            continue;
        };
        if filter.fd.is_some_and(|wanted| fd != wanted) {
            continue;
        }
        if entries.len() >= 65536 {
            return Err(io::Error::other("FD inventory exceeds 65536 entries"));
        }
        match entry(pid, fd, start, &comm, process.as_ref(), resolver) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                failed += 1;
                uncertain.insert(fd);
            }
        }
    }
    if start_ticks(pid)? != began {
        return Err(io::Error::other(
            "process exited or PID reused during inventory",
        ));
    }
    merge(data, snapshot, pid, start, entries, filter);
    for row in &mut data.rows {
        if row.total.id.key.pid == pid
            && uncertain.contains(&row.total.id.key.fd)
            && row.state != "invalid"
        {
            row.state = "unconfirmed";
        }
    }
    if failed != 0 {
        data.inventory_error = Some(format!(
            "{failed} FDs changed or could not be read during inventory"
        ));
    }
    Ok(())
}

fn merge(
    data: &mut Frame,
    snapshot: &Snapshot,
    pid: u32,
    start: u64,
    entries: Vec<Entry>,
    filter: &Filter,
) {
    let mut joined = HashSet::new();
    let open: HashSet<_> = entries.iter().map(|e| e.id.key.fd).collect();
    let mut records: HashMap<i32, Vec<&Record>> = HashMap::new();
    for record in snapshot.records.values().filter(|r| {
        r.id.key.pid == pid
            && r.id.key.start == start
            && r.id.key.object != 0
            && !snapshot.retired.contains(&r.id.key.object)
    }) {
        records.entry(record.id.key.fd).or_default().push(record);
    }
    let indices: HashMap<_, _> = data
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.total.id.key, i))
        .collect();
    let mut ambiguous = HashSet::new();
    for entry in entries {
        let id = entry.id;
        // Reject retired generations even when a file was reopened on the same
        // number with the same inode. Ambiguous generations remain separate.
        let candidates: Vec<_> = records
            .get(&id.key.fd)
            .into_iter()
            .flatten()
            .copied()
            .filter(|r| {
                r.id.key.pid == pid
                    && r.id.key.start == start
                    && r.id.key.fd == id.key.fd
                    && r.id.ino == id.ino
                    && r.id.dev == id.dev
                    && r.id.kind == id.kind
                    && (id.kind != 7 || r.id.name == id.name)
                    && r.id.key.object != 0
                    && !snapshot.retired.contains(&r.id.key.object)
            })
            .collect();
        let existing = if candidates.len() == 1 {
            Some(candidates[0])
        } else {
            if candidates.len() > 1 {
                ambiguous.insert(id.key.fd);
            }
            None
        };
        let mut identity = existing.map_or(id, |r| r.id);
        if id.kind == 2 && id.family != 0 {
            identity.family = id.family;
            identity.protocol = id.protocol;
        }
        if !accepts(&identity, filter) {
            continue;
        }
        let row = if let Some(record) = existing {
            joined.insert(record.id.key);
            if let Some(&index) = indices.get(&record.id.key) {
                &mut data.rows[index]
            } else {
                data.rows.push(idle(*record));
                data.rows.last_mut().unwrap()
            }
        } else {
            data.rows.push(idle(Record {
                id: identity,
                ..Default::default()
            }));
            data.rows.last_mut().unwrap()
        };
        row.total.id = identity;
        row.access = entry.access;
        row.state = "open";
        if entry.error.is_none() || existing.is_none() {
            row.object = entry.object;
            row.metadata_source = if entry.error.is_none() {
                "live"
            } else {
                "proc"
            };
            row.metadata_age_ms = Some(0);
        }
        row.metadata_error = entry.error;
    }
    for row in &mut data.rows {
        if row.total.id.key.pid != pid || row.state == "open" || row.state == "invalid" {
            continue;
        }
        if !joined.contains(&row.total.id.key) {
            row.state = if ambiguous.contains(&row.total.id.key.fd) {
                "unconfirmed"
            } else if open.contains(&row.total.id.key.fd) {
                "reused"
            } else {
                "closed"
            };
        }
    }
    // Recompute only the selected process's display summary; inventory adds no I/O.
    data.processes.retain(|p| p.pid != pid);
    for row in data.rows.iter().filter(|r| r.total.id.key.pid == pid) {
        let key = row.total.id.key;
        let index = data
            .processes
            .iter()
            .position(|p| (p.pid, p.start) == (pid, key.start));
        let index = index.unwrap_or_else(|| {
            data.processes.push(Process {
                pid,
                start: key.start,
                comm: clean(&row.total.id.comm),
                ..Default::default()
            });
            data.processes.len() - 1
        });
        let p = &mut data.processes[index];
        p.rd.add(&row.rd);
        p.wr.add(&row.wr);
        p.calls += row.calls;
        p.pending += row.pending;
        p.wait_ms = p.wait_ms.max(row.wait_ms);
        p.fds += 1;
    }
}

fn idle(total: Record) -> Row {
    Row {
        total,
        rd: Metrics::default(),
        wr: Metrics::default(),
        calls: 0,
        pending: 0,
        wait_ms: 0.,
        object: total.id.object_name(),
        metadata_source: "observed",
        metadata_age_ms: None,
        metadata_error: None,
        access: "-",
        state: "open",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_access_flags() {
        assert_eq!(access("flags:\t0100000\n"), "r");
        assert_eq!(access("flags:\t0100001\n"), "w");
        assert_eq!(access("flags:\t0100002\n"), "rw");
        assert_eq!(access("flags:\t010000000\n"), "path");
        assert_eq!(access(""), "-");
    }
    #[test]
    fn self_inventory_includes_idle_file_pipe_and_listener() {
        let file = fs::File::open("/dev/null").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let snapshot = Snapshot::default();
        let mut data = crate::model::frame(&snapshot, &snapshot, &Filter::default());
        enrich(
            &mut data,
            &snapshot,
            std::process::id(),
            &Filter::default(),
            &mut Resolver::default(),
        );
        for fd in [file.as_raw_fd(), listener.as_raw_fd()] {
            let row = data.rows.iter().find(|r| r.total.id.key.fd == fd).unwrap();
            assert_eq!(row.state, "open");
            assert_eq!(row.ops(), 0);
        }
        assert_eq!(
            data.rows
                .iter()
                .find(|r| r.total.id.key.fd == file.as_raw_fd())
                .unwrap()
                .access,
            "r"
        );
    }
    #[test]
    fn retired_same_inode_never_merges_into_new_fd() {
        let mut record = Record::default();
        record.id.key = Key {
            pid: 42,
            start: 1,
            fd: 3,
            object: 7,
        };
        record.id.ino = 99;
        record.rd.ops = 2;
        let snapshot = Snapshot {
            records: [(record.id.key, record)].into(),
            retired: [7].into(),
            ..Default::default()
        };
        let mut data = crate::model::frame(&Snapshot::default(), &snapshot, &Filter::default());
        let mut id = record.id;
        id.key.object = 0;
        merge(
            &mut data,
            &snapshot,
            42,
            1,
            vec![Entry {
                id,
                object: "new".into(),
                access: "r",
                error: None,
            }],
            &Filter::default(),
        );
        assert_eq!(data.rows.len(), 2);
        assert_eq!(data.rows[0].state, "reused");
        assert_eq!(data.rows[0].rd.ops, 2);
        assert_eq!(data.rows[1].rd.ops, 0);
        assert_eq!(data.rows[1].state, "open");
    }

    #[test]
    fn idle_known_object_keeps_totals_without_recounting() {
        let mut record = Record::default();
        record.id.key = Key {
            pid: 42,
            start: 1,
            fd: 3,
            object: 7,
        };
        record.id.ino = 99;
        record.rd.ops = 2;
        record.rd.bytes = 100;
        let snapshot = Snapshot {
            records: [(record.id.key, record)].into(),
            ..Default::default()
        };
        let mut data = crate::model::frame(&snapshot, &snapshot, &Filter::default());
        assert!(data.rows.is_empty());
        let id = record.id;
        merge(
            &mut data,
            &snapshot,
            42,
            1,
            vec![Entry {
                id,
                object: "file".into(),
                access: "r",
                error: None,
            }],
            &Filter::default(),
        );
        assert_eq!(data.rows.len(), 1);
        assert_eq!(data.rows[0].ops(), 0);
        assert_eq!(data.rows[0].total.rd.bytes, 100);
        assert_eq!(data.rows[0].total.id.key.object, 7);
        assert_eq!(data.processes[0].rd.bytes, 0);
    }

    #[test]
    fn anonymous_inode_type_change_does_not_inherit_io() {
        let mut record = Record::default();
        record.id.key = Key {
            pid: 42,
            start: 1,
            fd: 3,
            object: 7,
        };
        record.id.kind = 7;
        record.id.ino = 99;
        put(&mut record.id.name, b"[eventfd]");
        record.rd.ops = 2;
        let snapshot = Snapshot {
            records: [(record.id.key, record)].into(),
            ..Default::default()
        };
        let mut data = crate::model::frame(&Snapshot::default(), &snapshot, &Filter::default());
        let mut id = record.id;
        id.name = [0; 64];
        id.key.object = 0;
        put(&mut id.name, b"[eventpoll]");
        merge(
            &mut data,
            &snapshot,
            42,
            1,
            vec![Entry {
                id,
                object: "epoll".into(),
                access: "rw",
                error: None,
            }],
            &Filter::default(),
        );
        assert_eq!(data.rows.len(), 2);
        assert_eq!(data.rows[0].state, "reused");
        assert_eq!(data.rows[1].total.id.kind_name(), "EPOLL");
        assert_eq!(data.rows[1].ops(), 0);
    }
}
