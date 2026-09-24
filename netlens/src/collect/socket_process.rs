use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_PROCESSES: usize = 65_536;
const MAX_SCANNED_FDS: usize = 262_144;
const MAX_OWNERS_PER_SOCKET: usize = 8;
const MAX_COMM_BYTES: usize = 64;

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SocketProcess {
    pub(crate) pid: u32,
    pub(crate) command: Option<String>,
    start_time: u64,
    fd: u32,
}

impl fmt::Debug for SocketProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SocketProcess(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessScanUnavailable {
    PermissionDenied,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessScanStatus {
    Complete,
    Partial {
        permission_denied_processes: usize,
        io_errors: usize,
        truncated: bool,
    },
    Unavailable(ProcessScanUnavailable),
}

pub(crate) struct SocketProcessScan {
    owners: BTreeMap<u32, Vec<SocketProcess>>,
    status: ProcessScanStatus,
    scanned_processes: usize,
    scanned_fds: usize,
}

impl SocketProcessScan {
    pub(crate) fn owners(&self, inode: u32) -> &[SocketProcess] {
        self.owners.get(&inode).map_or(&[], Vec::as_slice)
    }

    pub(crate) const fn status(&self) -> ProcessScanStatus {
        self.status
    }

    pub(crate) const fn scanned_processes(&self) -> usize {
        self.scanned_processes
    }

    pub(crate) const fn scanned_fds(&self) -> usize {
        self.scanned_fds
    }

    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            owners: BTreeMap::new(),
            status: ProcessScanStatus::Complete,
            scanned_processes: 0,
            scanned_fds: 0,
        }
    }
}

impl fmt::Debug for SocketProcessScan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SocketProcessScan")
            .field("mapped_socket_count", &self.owners.len())
            .field("status", &self.status)
            .field("scanned_processes", &self.scanned_processes)
            .field("scanned_fds", &self.scanned_fds)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct ScanLimits {
    processes: usize,
    fds: usize,
    owners_per_socket: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            processes: MAX_PROCESSES,
            fds: MAX_SCANNED_FDS,
            owners_per_socket: MAX_OWNERS_PER_SOCKET,
        }
    }
}

#[cfg(test)]
pub(crate) fn scan_socket_processes(
    proc_root: &Path,
    target_inodes: &BTreeSet<u32>,
) -> SocketProcessScan {
    scan_with_limits(proc_root, target_inodes, ScanLimits::default())
}

pub(crate) fn scan_socket_processes_until(
    proc_root: &Path,
    target_inodes: &BTreeSet<u32>,
    cancelled: &AtomicBool,
) -> Option<SocketProcessScan> {
    scan_with_limits_until(
        proc_root,
        target_inodes,
        ScanLimits::default(),
        Some(cancelled),
    )
}

#[cfg(test)]
fn scan_with_limits(
    proc_root: &Path,
    target_inodes: &BTreeSet<u32>,
    limits: ScanLimits,
) -> SocketProcessScan {
    scan_with_limits_until(proc_root, target_inodes, limits, None)
        .expect("a process scan without a cancellation token cannot be cancelled")
}

fn scan_with_limits_until(
    proc_root: &Path,
    target_inodes: &BTreeSet<u32>,
    limits: ScanLimits,
    cancelled: Option<&AtomicBool>,
) -> Option<SocketProcessScan> {
    if is_cancelled(cancelled) {
        return None;
    }
    if target_inodes.is_empty() {
        return Some(SocketProcessScan {
            owners: BTreeMap::new(),
            status: ProcessScanStatus::Complete,
            scanned_processes: 0,
            scanned_fds: 0,
        });
    }

    let entries = match fs::read_dir(proc_root) {
        Ok(entries) => entries,
        Err(error) => {
            let unavailable = if error.kind() == io::ErrorKind::PermissionDenied {
                ProcessScanUnavailable::PermissionDenied
            } else {
                ProcessScanUnavailable::Io
            };
            return Some(SocketProcessScan {
                owners: BTreeMap::new(),
                status: ProcessScanStatus::Unavailable(unavailable),
                scanned_processes: 0,
                scanned_fds: 0,
            });
        }
    };

    let mut pids = BinaryHeap::new();
    let mut processes_truncated = false;
    for entry in entries {
        if is_cancelled(cancelled) {
            return None;
        }
        let Some(pid) = entry
            .ok()
            .and_then(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        else {
            continue;
        };
        if pids.len() < limits.processes {
            pids.push(pid);
        } else {
            processes_truncated = true;
            if pids.peek().is_some_and(|largest| pid < *largest) {
                pids.pop();
                pids.push(pid);
            }
        }
    }
    let mut pids = pids.into_vec();
    pids.sort_unstable();
    pids.dedup();

    let mut owners = BTreeMap::<u32, Vec<SocketProcess>>::new();
    let mut permission_denied_processes = 0_usize;
    let mut io_errors = 0_usize;
    let mut scanned_processes = 0_usize;
    let mut scanned_fds = 0_usize;
    let mut fds_truncated = false;
    let mut owners_truncated = false;

    for pid in pids {
        if fds_truncated {
            break;
        }
        if is_cancelled(cancelled) {
            return None;
        }
        let process_root = proc_root.join(pid.to_string());
        let entries = match fs::read_dir(process_root.join("fd")) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                permission_denied_processes = permission_denied_processes.saturating_add(1);
                continue;
            }
            Err(_) => {
                io_errors = io_errors.saturating_add(1);
                continue;
            }
        };
        scanned_processes = scanned_processes.saturating_add(1);
        let mut entries = entries.peekable();
        if entries.peek().is_none() {
            continue;
        }
        let start_time = match read_start_time(&process_root.join("stat")) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                io_errors = io_errors.saturating_add(1);
                continue;
            }
        };
        let mut process_inodes = BTreeMap::new();
        for entry in entries {
            if is_cancelled(cancelled) {
                return None;
            }
            if scanned_fds >= limits.fds {
                fds_truncated = true;
                break;
            }
            scanned_fds = scanned_fds.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    io_errors = io_errors.saturating_add(1);
                    continue;
                }
            };
            let target = match fs::read_link(entry.path()) {
                Ok(target) => target,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => {
                    io_errors = io_errors.saturating_add(1);
                    continue;
                }
            };
            let Some(inode) = target.to_str().and_then(parse_socket_inode) else {
                continue;
            };
            if !target_inodes.contains(&inode) {
                continue;
            }
            let Some(fd) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            process_inodes.entry(inode).or_insert(fd);
        }
        if process_inodes.is_empty() {
            continue;
        }
        let command = read_command(&process_root.join("comm"));
        if read_start_time(&process_root.join("stat")).ok() != Some(start_time) {
            io_errors = io_errors.saturating_add(1);
            continue;
        }
        for (inode, fd) in process_inodes {
            let socket_owners = owners.entry(inode).or_default();
            if socket_owners.len() >= limits.owners_per_socket {
                owners_truncated = true;
                continue;
            }
            socket_owners.push(SocketProcess {
                pid,
                command: command.clone(),
                start_time,
                fd,
            });
        }
    }

    let truncated = processes_truncated || fds_truncated || owners_truncated;
    let status = if permission_denied_processes == 0 && io_errors == 0 && !truncated {
        ProcessScanStatus::Complete
    } else {
        ProcessScanStatus::Partial {
            permission_denied_processes,
            io_errors,
            truncated,
        }
    };
    Some(SocketProcessScan {
        owners,
        status,
        scanned_processes,
        scanned_fds,
    })
}

pub(crate) fn owner_is_current(proc_root: &Path, owner: &SocketProcess, inode: u32) -> bool {
    let process = proc_root.join(owner.pid.to_string());
    let stat = process.join("stat");
    read_start_time(&stat).ok() == Some(owner.start_time)
        && fs::read_link(process.join("fd").join(owner.fd.to_string()))
            .ok()
            .and_then(|target| target.to_str().and_then(parse_socket_inode))
            == Some(inode)
        && read_start_time(&stat).ok() == Some(owner.start_time)
}

fn read_start_time(path: &Path) -> io::Result<u64> {
    let mut text = String::new();
    File::open(path)?.take(8193).read_to_string(&mut text)?;
    if text.len() <= 8192 {
        if let Some(value) = parse_start_time(&text) {
            return Ok(value);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid process stat",
    ))
}

fn parse_start_time(text: &str) -> Option<u64> {
    // comm can contain spaces and parentheses; starttime is field 22.
    text.rsplit_once(") ")?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn is_cancelled(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
}

fn parse_socket_inode(target: &str) -> Option<u32> {
    let inode = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    (!inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| inode.parse::<u32>().ok())
        .flatten()
}

fn read_command(path: &Path) -> Option<String> {
    let file = File::open(path).ok()?;
    let mut bytes = Vec::with_capacity(MAX_COMM_BYTES);
    file.take((MAX_COMM_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_COMM_BYTES {
        bytes.truncate(MAX_COMM_BYTES);
    }
    let value = std::str::from_utf8(&bytes).ok()?.trim_end();
    let value = value
        .chars()
        .filter(|character| !character.is_control())
        .take(32)
        .collect::<String>();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;

    fn add_process(root: &Path, pid: u32, command: &str, links: &[(&str, &str)]) {
        let process = root.join(pid.to_string());
        let fds = process.join("fd");
        fs::create_dir_all(&fds).unwrap();
        fs::write(process.join("comm"), format!("{command}\n")).unwrap();
        fs::write(
            process.join("stat"),
            format!("{pid} ({command}) S {}123 0\n", "0 ".repeat(18)),
        )
        .unwrap();
        for (fd, target) in links {
            symlink(target, fds.join(fd)).unwrap();
        }
    }

    #[test]
    fn cached_owner_rejects_reused_pid_and_replaced_fd() {
        let root = TempDir::new().unwrap();
        add_process(root.path(), 20, "worker", &[("3", "socket:[42]")]);
        let scan = scan_socket_processes(root.path(), &BTreeSet::from([42]));
        let owner = &scan.owners(42)[0];
        assert!(owner_is_current(root.path(), owner, 42));
        assert!(!owner_is_current(root.path(), owner, 99));
        let stat = root.path().join("20/stat");
        fs::write(&stat, format!("20 (worker) S {}999 0\n", "0 ".repeat(18))).unwrap();
        assert!(!owner_is_current(root.path(), owner, 42));
        fs::write(&stat, format!("20 (worker) S {}123 0\n", "0 ".repeat(18))).unwrap();
        let fd = root.path().join("20/fd/3");
        fs::remove_file(&fd).unwrap();
        symlink("socket:[99]", &fd).unwrap();
        assert!(!owner_is_current(root.path(), owner, 42));
        fs::remove_file(&fd).unwrap();
        assert!(!owner_is_current(root.path(), owner, 42));
    }

    #[test]
    fn process_start_time_parser_handles_comm_parentheses_and_malformed_stat() {
        let text = format!("20 (a ) complicated ( name) S {}345 0\n", "0 ".repeat(18));
        assert_eq!(parse_start_time(&text), Some(345));
        assert_eq!(parse_start_time("20 (worker) S 1 2"), None);
        assert_eq!(parse_start_time("not a process stat"), None);
        assert_eq!(parse_start_time(&text.replace("345", "-1")), None);
    }

    #[test]
    fn maps_only_target_socket_inodes_in_stable_pid_order() {
        let root = TempDir::new().unwrap();
        add_process(
            root.path(),
            20,
            "second",
            &[("3", "socket:[42]"), ("4", "socket:[99]")],
        );
        add_process(
            root.path(),
            10,
            "first",
            &[("3", "socket:[42]"), ("4", "/tmp/not-a-socket")],
        );
        let targets = BTreeSet::from([42, 77]);

        let scan = scan_socket_processes(root.path(), &targets);

        assert_eq!(scan.status(), ProcessScanStatus::Complete);
        assert_eq!(
            scan.owners(42)
                .iter()
                .map(|owner| (owner.pid, owner.command.as_deref()))
                .collect::<Vec<_>>(),
            vec![(10, Some("first")), (20, Some("second"))]
        );
        assert!(scan.owners(77).is_empty());
        let debug = format!("{scan:?}");
        assert!(!debug.contains("first"));
        assert!(!debug.contains("42"));
    }

    #[test]
    fn scan_limits_are_visible_without_returning_unbounded_owners() {
        let root = TempDir::new().unwrap();
        add_process(
            root.path(),
            1,
            "one",
            &[("1", "socket:[7]"), ("2", "socket:[8]")],
        );
        add_process(root.path(), 2, "two", &[("1", "socket:[7]")]);
        let targets = BTreeSet::from([7, 8]);

        let scan = scan_with_limits(
            root.path(),
            &targets,
            ScanLimits {
                processes: 1,
                fds: 1,
                owners_per_socket: 1,
            },
        );

        assert!(matches!(
            scan.status(),
            ProcessScanStatus::Partial {
                truncated: true,
                ..
            }
        ));
        assert_eq!(scan.scanned_processes(), 1);
        assert_eq!(scan.scanned_fds(), 1);
        assert_eq!(scan.owners(7).len() + scan.owners(8).len(), 1);
        assert!(scan.owners.values().flatten().all(|owner| owner.pid == 1));
    }

    #[test]
    fn owner_limit_degrades_process_coverage() {
        let root = TempDir::new().unwrap();
        add_process(root.path(), 1, "one", &[("1", "socket:[7]")]);
        add_process(root.path(), 2, "two", &[("1", "socket:[7]")]);
        let targets = BTreeSet::from([7]);

        let scan = scan_with_limits(
            root.path(),
            &targets,
            ScanLimits {
                processes: 2,
                fds: 2,
                owners_per_socket: 1,
            },
        );

        assert!(matches!(
            scan.status(),
            ProcessScanStatus::Partial {
                truncated: true,
                ..
            }
        ));
        assert_eq!(scan.owners(7).len(), 1);
    }

    #[test]
    fn preexisting_cancellation_stops_process_scan() {
        let root = TempDir::new().unwrap();
        add_process(root.path(), 1, "one", &[("1", "socket:[7]")]);
        let targets = BTreeSet::from([7]);
        let cancelled = AtomicBool::new(true);

        assert!(scan_socket_processes_until(root.path(), &targets, &cancelled).is_none());
    }

    #[test]
    fn missing_proc_root_is_an_explicit_unavailable_status() {
        let root = TempDir::new().unwrap();
        let targets = BTreeSet::from([1]);
        let scan = scan_socket_processes(&root.path().join("missing"), &targets);

        assert_eq!(
            scan.status(),
            ProcessScanStatus::Unavailable(ProcessScanUnavailable::Io)
        );
        assert!(scan.owners(1).is_empty());
    }

    #[test]
    fn socket_inode_parser_rejects_lookalikes_and_overflow() {
        assert_eq!(parse_socket_inode("socket:[123]"), Some(123));
        for invalid in [
            "socket:[]",
            "socket:[1]suffix",
            "prefixsocket:[1]",
            "socket:[-1]",
            "socket:[4294967296]",
        ] {
            assert_eq!(parse_socket_inode(invalid), None, "{invalid}");
        }
    }
}
