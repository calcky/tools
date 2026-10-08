use crate::collect::comm_name;
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::Path,
    sync::mpsc::{self, Receiver, SyncSender},
    time::{Duration, Instant},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Owner {
    pub pid: u32,
    pub name: String,
}

#[derive(Default)]
pub struct Snapshot {
    pub holders: HashMap<u64, Vec<Owner>>,
    pub partial: bool,
}

impl Snapshot {
    pub fn process_names(&self, inode: u64) -> String {
        let Some(holders) = self.holders.get(&inode).filter(|_| inode != 0) else {
            return "-".into();
        };
        if holders.is_empty() {
            return "-".into();
        }
        let mut names = holders
            .iter()
            .take(2)
            .map(|owner| format!("{}({})", owner.name, owner.pid))
            .collect::<Vec<_>>()
            .join(", ");
        if holders.len() > 2 {
            names.push_str(&format!(" +{}", holders.len() - 2));
        }
        names
    }

    pub fn description(&self, inode: u64, paused: bool) -> String {
        if inode == 0 {
            return "PROC - | no socket inode available".into();
        }
        let Some(holders) = self.holders.get(&inode) else {
            return format!(
                "PROC - | socket {inode} | {}",
                if paused {
                    "lookup not captured"
                } else {
                    "FD lookup pending"
                }
            );
        };
        let names = if holders.is_empty() {
            "- (no FD holder found)".into()
        } else {
            self.process_names(inode)
        };
        format!(
            "PROC [{}FD snapshot] {names} | inode {inode}",
            if self.partial { "partial " } else { "" }
        )
    }
}

pub struct Collector {
    request: SyncSender<Vec<u64>>,
    results: Receiver<Snapshot>,
}

impl Collector {
    pub fn new() -> io::Result<Self> {
        let (request, incoming) = mpsc::sync_channel::<Vec<u64>>(1);
        let (outgoing, results) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("socket-owners".into())
            .spawn(move || {
                while let Ok(inodes) = incoming.recv() {
                    let result = lookup(
                        Path::new("/proc"),
                        &inodes,
                        25_000,
                        Duration::from_millis(50),
                    );
                    let _ = outgoing.try_send(result);
                }
            })?;
        Ok(Self { request, results })
    }

    pub fn request(&self, inodes: Vec<u64>) {
        let _ = self.request.try_send(inodes);
    }

    pub fn take(&self) -> Option<Snapshot> {
        self.results.try_iter().last()
    }
}

fn socket_inode(target: &Path) -> Option<u64> {
    target
        .to_str()?
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn start_time(process: &Path) -> io::Result<u64> {
    let stat = fs::read_to_string(process.join("stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|time| time.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

fn still_holds(process: &Path, fd: &Path, inode: u64, started: u64) -> bool {
    start_time(process).ok() == Some(started)
        && fs::read_link(fd).ok().as_deref().and_then(socket_inode) == Some(inode)
        && start_time(process).ok() == Some(started)
}

fn lookup(root: &Path, inodes: &[u64], limit: usize, budget: Duration) -> Snapshot {
    let mut result = Snapshot::default();
    let targets: HashSet<_> = inodes.iter().copied().filter(|inode| *inode != 0).collect();
    result
        .holders
        .extend(targets.iter().map(|&inode| (inode, Vec::new())));
    if targets.is_empty() {
        return result;
    }
    let Ok(processes) = fs::read_dir(root) else {
        result.partial = true;
        return result;
    };
    let deadline = Instant::now() + budget;
    let mut visited = 0;
    for process in processes {
        if Instant::now() >= deadline {
            result.partial = true;
            break;
        }
        let Ok(process) = process else {
            result.partial = true;
            continue;
        };
        let Some(pid) = process
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let process = process.path();
        let started = match start_time(&process) {
            Ok(time) => time,
            Err(error) => {
                result.partial |= error.kind() != io::ErrorKind::NotFound;
                continue;
            }
        };
        let descriptors = match fs::read_dir(process.join("fd")) {
            Ok(entries) => entries,
            Err(error) => {
                result.partial |= error.kind() != io::ErrorKind::NotFound;
                continue;
            }
        };
        let mut matches = HashMap::new();
        let mut exhausted = false;
        for descriptor in descriptors {
            if visited >= limit || Instant::now() >= deadline {
                result.partial = true;
                exhausted = true;
                break;
            }
            visited += 1;
            let Ok(descriptor) = descriptor else {
                result.partial = true;
                continue;
            };
            let target = match fs::read_link(descriptor.path()) {
                Ok(target) => target,
                Err(error) => {
                    result.partial |= error.kind() != io::ErrorKind::NotFound;
                    continue;
                }
            };
            if let Some(inode) = socket_inode(&target).filter(|inode| targets.contains(inode)) {
                matches.entry(inode).or_insert_with(|| descriptor.path());
            }
        }
        let name = fs::read(process.join("comm"))
            .map(|mut bytes| {
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                comm_name(&bytes)
            })
            .unwrap_or_else(|_| "-".into());
        for (inode, fd) in matches {
            // Confirm both the PID lifetime and descriptor again before naming a holder.
            if !still_holds(&process, &fd, inode, started) {
                result.partial = true;
                continue;
            }
            let holders = result.holders.get_mut(&inode).unwrap();
            if holders.len() == 8 {
                result.partial = true;
                continue;
            }
            holders.push(Owner {
                pid,
                name: name.clone(),
            });
        }
        if exhausted {
            break;
        }
    }
    for owners in result.holders.values_mut() {
        owners.sort_by_key(|owner| owner.pid);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::UdpSocket,
        os::fd::AsRawFd,
        os::unix::fs::symlink,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "droptop-owners-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn process(&self, pid: u32, name: &str, inode: u64) -> std::path::PathBuf {
            let process = self.0.join(pid.to_string());
            fs::create_dir_all(process.join("fd")).unwrap();
            fs::write(process.join("comm"), format!("{name}\n")).unwrap();
            let mut fields = vec!["0"; 20];
            fields[0] = "S";
            fields[19] = "100";
            fs::write(
                process.join("stat"),
                format!("{pid} ({name}) {}", fields.join(" ")),
            )
            .unwrap();
            symlink(format!("socket:[{inode}]"), process.join("fd/3")).unwrap();
            process
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn resolves_only_exact_socket_inode_holders_and_keeps_shared_processes() {
        let fixture = Fixture::new();
        let process = fixture.process(20, "app ) worker", 123);
        symlink("socket:[123]", process.join("fd/4")).unwrap();
        fixture.process(10, "child", 123);
        fixture.process(30, "unrelated", 456);
        let result = lookup(&fixture.0, &[123, 999], 100, Duration::from_secs(1));
        assert!(!result.partial);
        assert_eq!(
            result.holders[&123],
            vec![
                Owner {
                    pid: 10,
                    name: "child".into()
                },
                Owner {
                    pid: 20,
                    name: "app ) worker".into()
                }
            ]
        );
        assert!(result.holders[&999].is_empty());
        assert!(!result.holders.contains_key(&456));
    }

    #[test]
    fn resolves_a_live_socket_and_does_not_retain_a_closed_descriptor() {
        let fixture = Fixture::new();
        let pid = std::process::id();
        let process = Path::new("/proc").join(pid.to_string());
        symlink(&process, fixture.0.join(pid.to_string())).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = process.join("fd").join(socket.as_raw_fd().to_string());
        let inode = socket_inode(&fs::read_link(&fd).unwrap()).unwrap();
        let name = comm_name(
            fs::read(process.join("comm"))
                .unwrap()
                .strip_suffix(b"\n")
                .unwrap(),
        );
        let snapshot = lookup(&fixture.0, &[inode], 25_000, Duration::from_secs(2));
        assert!(!snapshot.partial);
        assert_eq!(snapshot.holders[&inode], vec![Owner { pid, name }]);
        drop(socket);
        let snapshot = lookup(&fixture.0, &[inode], 25_000, Duration::from_secs(2));
        assert!(!snapshot.partial);
        assert!(snapshot.holders[&inode].is_empty());
    }

    #[test]
    fn rejects_reused_pid_or_replaced_descriptor() {
        let fixture = Fixture::new();
        let process = fixture.process(20, "worker", 123);
        assert!(still_holds(&process, &process.join("fd/3"), 123, 100));
        assert!(!still_holds(&process, &process.join("fd/3"), 123, 99));
        fs::remove_file(process.join("fd/3")).unwrap();
        symlink("socket:[456]", process.join("fd/3")).unwrap();
        assert!(!still_holds(&process, &process.join("fd/3"), 123, 100));
    }

    #[test]
    fn invalid_process_lifetime_cannot_produce_an_owner() {
        let fixture = Fixture::new();
        let process = fixture.process(20, "worker", 123);
        fs::write(process.join("stat"), "20 (worker) invalid").unwrap();
        let snapshot = lookup(&fixture.0, &[123], 100, Duration::from_secs(1));
        assert!(snapshot.partial);
        assert!(snapshot.holders[&123].is_empty());
    }

    #[test]
    fn incomplete_scan_is_explicit_and_unknown_socket_does_not_get_an_owner() {
        let fixture = Fixture::new();
        fixture.process(20, "worker", 123);
        let result = lookup(&fixture.0, &[123], 0, Duration::from_secs(1));
        assert!(result.partial);
        assert!(result
            .description(123, false)
            .contains("partial FD snapshot"));
        assert_eq!(
            result.description(0, false),
            "PROC - | no socket inode available"
        );
        assert!(result
            .description(999, true)
            .contains("lookup not captured"));
        assert!(socket_inode(Path::new("not-socket:[123]")).is_none());
    }
}
