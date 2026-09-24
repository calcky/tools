use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::collect::sock_diag::SocketIdentity;
use crate::collect::socket_process::{self, SocketProcess, SocketProcessScan};

use super::{project_process_coverage, SocketProcessCoverage};

const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const NEW_SOCKET_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CACHE_AGE: Duration = Duration::from_secs(20);

pub(super) struct OwnerSnapshot {
    owners: BTreeMap<SocketIdentity, Vec<SocketProcess>>,
    pub(super) coverage: SocketProcessCoverage,
    pub(super) age: Option<Duration>,
    pub(super) refreshing: bool,
    pub(super) scanned_processes: usize,
    pub(super) scanned_fds: usize,
}

impl OwnerSnapshot {
    pub(super) fn owners(&self, identity: &SocketIdentity) -> &[SocketProcess] {
        self.owners.get(identity).map_or(&[], Vec::as_slice)
    }

    #[cfg(test)]
    pub(super) fn empty() -> Self {
        Self {
            owners: BTreeMap::new(),
            coverage: SocketProcessCoverage::Complete,
            age: None,
            refreshing: false,
            scanned_processes: 0,
            scanned_fds: 0,
        }
    }
}

struct Request {
    targets: BTreeSet<SocketIdentity>,
    started: Instant,
}

struct ScanResult {
    request: Request,
    scan: SocketProcessScan,
}

struct OwnerCache {
    entries: BTreeMap<SocketIdentity, Vec<SocketProcess>>,
    observed_at: Option<Instant>,
    last_request: Option<Instant>,
    coverage: SocketProcessCoverage,
    scanned_processes: usize,
    scanned_fds: usize,
}

impl Default for OwnerCache {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            observed_at: None,
            last_request: None,
            coverage: SocketProcessCoverage::Pending,
            scanned_processes: 0,
            scanned_fds: 0,
        }
    }
}

impl OwnerCache {
    fn accept(&mut self, result: ScanResult, current: &BTreeSet<SocketIdentity>) {
        // A cookie must survive both socket dumps around the asynchronous scan.
        self.entries = result
            .request
            .targets
            .intersection(current)
            .map(|identity| {
                (
                    identity.clone(),
                    result.scan.owners(identity.inode()).to_vec(),
                )
            })
            .collect();
        self.observed_at = Some(result.request.started);
        self.coverage = project_process_coverage(result.scan.status());
        self.scanned_processes = result.scan.scanned_processes();
        self.scanned_fds = result.scan.scanned_fds();
    }

    fn reconcile(
        &mut self,
        current: &BTreeSet<SocketIdentity>,
        now: Instant,
        mut valid: impl FnMut(&SocketProcess, u32) -> bool,
    ) {
        if self
            .observed_at
            .is_some_and(|at| now.saturating_duration_since(at) >= MAX_CACHE_AGE)
        {
            self.entries.clear();
        }
        self.entries.retain(|identity, owners| {
            current.contains(identity) && owners.iter().all(|owner| valid(owner, identity.inode()))
        });
    }

    fn due(&self, current: &BTreeSet<SocketIdentity>, now: Instant) -> bool {
        if current.is_empty() {
            return false;
        }
        let Some(last) = self.last_request else {
            return true;
        };
        let elapsed = now.saturating_duration_since(last);
        elapsed >= REFRESH_INTERVAL
            || elapsed >= NEW_SOCKET_INTERVAL
                && current.iter().any(|id| !self.entries.contains_key(id))
    }

    fn snapshot(
        &self,
        current: &BTreeSet<SocketIdentity>,
        now: Instant,
        refreshing: bool,
    ) -> OwnerSnapshot {
        let coverage = if current.is_empty() {
            SocketProcessCoverage::Complete
        } else if self.coverage == SocketProcessCoverage::Complete
            && current.iter().any(|id| !self.entries.contains_key(id))
        {
            SocketProcessCoverage::Pending
        } else {
            self.coverage
        };
        OwnerSnapshot {
            owners: self.entries.clone(),
            coverage,
            age: self.observed_at.map(|at| now.saturating_duration_since(at)),
            refreshing,
            scanned_processes: self.scanned_processes,
            scanned_fds: self.scanned_fds,
        }
    }
}

pub(super) struct OwnerService {
    requests: Option<mpsc::SyncSender<Request>>,
    results: mpsc::Receiver<ScanResult>,
    cancelled: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    in_flight: bool,
    cache: OwnerCache,
}

impl OwnerService {
    pub(super) fn start(proc_root: PathBuf) -> std::io::Result<Self> {
        Self::spawn(move |targets, cancelled| {
            let inodes = targets.iter().map(SocketIdentity::inode).collect();
            socket_process::scan_socket_processes_until(&proc_root, &inodes, cancelled)
        })
    }

    fn spawn<F>(mut scan: F) -> std::io::Result<Self>
    where
        F: FnMut(&BTreeSet<SocketIdentity>, &AtomicBool) -> Option<SocketProcessScan>
            + Send
            + 'static,
    {
        let (requests, request_rx) = mpsc::sync_channel::<Request>(1);
        let (result_tx, results) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel = Arc::clone(&cancelled);
        let worker = thread::Builder::new()
            .name("netlens-owners".into())
            .spawn(move || {
                while let Ok(request) = request_rx.recv() {
                    if cancel.load(Ordering::Acquire) {
                        break;
                    }
                    let Some(scan) = scan(&request.targets, &cancel) else {
                        break;
                    };
                    if result_tx.send(ScanResult { request, scan }).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests: Some(requests),
            results,
            cancelled,
            worker: Some(worker),
            in_flight: false,
            cache: OwnerCache::default(),
        })
    }

    pub(super) fn snapshot(
        &mut self,
        current: BTreeSet<SocketIdentity>,
        proc_root: &Path,
        now: Instant,
    ) -> OwnerSnapshot {
        match self.results.try_recv() {
            Ok(result) => {
                self.in_flight = false;
                self.cache.accept(result, &current);
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.requests = None;
                self.in_flight = false;
                self.cache.entries.clear();
                self.cache.coverage = SocketProcessCoverage::Unavailable;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        self.cache.reconcile(&current, now, |owner, inode| {
            socket_process::owner_is_current(proc_root, owner, inode)
        });
        if !self.in_flight && self.cache.due(&current, now) {
            if let Some(requests) = &self.requests {
                let request = Request {
                    targets: current.clone(),
                    started: now,
                };
                if requests.try_send(request).is_ok() {
                    self.in_flight = true;
                    self.cache.last_request = Some(now);
                }
            }
        }
        self.cache.snapshot(&current, now, self.in_flight)
    }
}

impl Drop for OwnerService {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::sock_diag::{SocketFamily, SocketProtocol};
    use crate::collect::socket_process::scan_socket_processes;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn identity(seed: u32) -> SocketIdentity {
        SocketIdentity::synthetic(SocketFamily::Ipv4, SocketProtocol::Tcp, seed)
    }

    fn result(root: &Path, targets: BTreeSet<SocketIdentity>, started: Instant) -> ScanResult {
        let inodes = targets.iter().map(SocketIdentity::inode).collect();
        ScanResult {
            scan: scan_socket_processes(root, &inodes),
            request: Request { targets, started },
        }
    }

    fn add_owner(root: &Path, inode: u32) {
        fs::create_dir_all(root.join("12/fd")).unwrap();
        fs::write(root.join("12/comm"), "worker\n").unwrap();
        fs::write(
            root.join("12/stat"),
            format!("12 (worker) S {}234 0\n", "0 ".repeat(18)),
        )
        .unwrap();
        symlink(format!("socket:[{inode}]"), root.join("12/fd/3")).unwrap();
    }

    #[test]
    fn stable_and_negative_results_refresh_at_ten_seconds_new_entries_are_batched() {
        let root = TempDir::new().unwrap();
        let now = Instant::now();
        let targets = BTreeSet::from([identity(1)]);
        let mut cache = OwnerCache::default();
        assert!(cache.due(&targets, now));
        cache.last_request = Some(now);
        cache.accept(result(root.path(), targets.clone(), now), &targets);
        assert!(cache.entries[&identity(1)].is_empty());
        assert!(!cache.due(&targets, now + Duration::from_secs(9)));
        assert!(cache.due(&targets, now + Duration::from_secs(10)));
        let expanded = BTreeSet::from([identity(1), identity(2)]);
        assert!(!cache.due(&expanded, now + Duration::from_secs(1)));
        assert!(cache.due(&expanded, now + Duration::from_secs(2)));
        assert_eq!(
            cache.snapshot(&expanded, now, false).coverage,
            SocketProcessCoverage::Pending
        );
        assert!(!cache.due(&BTreeSet::new(), now + Duration::from_secs(100)));
    }

    #[test]
    fn inode_reuse_and_delayed_results_never_transfer_cached_owners() {
        let root = TempDir::new().unwrap();
        let now = Instant::now();
        let old = identity(1);
        add_owner(root.path(), old.inode());
        let old_targets = BTreeSet::from([old.clone()]);
        let mut cache = OwnerCache::default();
        cache.accept(result(root.path(), old_targets.clone(), now), &old_targets);
        assert_eq!(
            cache.snapshot(&old_targets, now, false).owners(&old)[0].pid,
            12
        );
        let replacement = old.synthetic_reusing_inode(42);
        let new_targets = BTreeSet::from([replacement.clone()]);
        cache.reconcile(&new_targets, now, |_, _| true);
        assert!(cache.entries.is_empty());
        cache.accept(result(root.path(), old_targets, now), &new_targets);
        let snapshot = cache.snapshot(&new_targets, now, false);
        assert!(snapshot.owners(&replacement).is_empty());
        assert_eq!(snapshot.coverage, SocketProcessCoverage::Pending);
    }

    #[test]
    fn validation_and_expiry_remove_attribution_and_request_refresh() {
        let root = TempDir::new().unwrap();
        let now = Instant::now();
        let id = identity(1);
        add_owner(root.path(), id.inode());
        let targets = BTreeSet::from([id.clone()]);
        let mut cache = OwnerCache {
            last_request: Some(now),
            ..OwnerCache::default()
        };
        cache.accept(result(root.path(), targets.clone(), now), &targets);
        cache.reconcile(&targets, now, |owner, inode| {
            socket_process::owner_is_current(root.path(), owner, inode)
        });
        assert_eq!(cache.entries.len(), 1);
        fs::remove_file(root.path().join("12/fd/3")).unwrap();
        cache.reconcile(&targets, now, |owner, inode| {
            socket_process::owner_is_current(root.path(), owner, inode)
        });
        assert!(cache.entries.is_empty());
        assert!(cache.due(&targets, now + NEW_SOCKET_INTERVAL));
        cache.accept(result(root.path(), targets.clone(), now), &targets);
        assert!(cache.entries.contains_key(&id));
        cache.reconcile(&targets, now + MAX_CACHE_AGE, |_, _| true);
        assert!(cache.entries.is_empty());
        assert_eq!(
            cache.snapshot(&targets, now + MAX_CACHE_AGE, true).coverage,
            SocketProcessCoverage::Pending
        );
    }

    #[test]
    fn failed_scan_replaces_old_owners_and_retains_failure_coverage() {
        let root = TempDir::new().unwrap();
        let now = Instant::now();
        let id = identity(1);
        add_owner(root.path(), id.inode());
        let targets = BTreeSet::from([id.clone()]);
        let mut cache = OwnerCache::default();
        cache.accept(result(root.path(), targets.clone(), now), &targets);
        cache.accept(
            result(&root.path().join("missing"), targets.clone(), now),
            &targets,
        );
        let snapshot = cache.snapshot(&targets, now, false);
        assert!(snapshot.owners(&id).is_empty());
        assert_eq!(snapshot.coverage, SocketProcessCoverage::Unavailable);
    }

    #[test]
    fn slow_scan_does_not_block_counter_worker_or_queue_another_request() {
        let (started, started_rx) = mpsc::sync_channel(1);
        let (release, release_rx) = mpsc::sync_channel(1);
        let mut service = OwnerService::spawn(move |_, _| {
            started.send(()).unwrap();
            release_rx.recv().unwrap();
            Some(SocketProcessScan::empty())
        })
        .unwrap();
        let root = TempDir::new().unwrap();
        let now = Instant::now();
        let targets = BTreeSet::from([identity(1)]);
        let snapshot = service.snapshot(targets.clone(), root.path(), now);
        assert_eq!(snapshot.coverage, SocketProcessCoverage::Pending);
        assert!(snapshot.refreshing);
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (returned, returned_rx) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let snapshot = service.snapshot(targets, root.path(), now + Duration::from_secs(30));
            returned.send(snapshot).unwrap();
            service
        });
        let response = returned_rx.recv_timeout(Duration::from_secs(2));
        release.send(()).unwrap();
        let service = worker.join().unwrap();
        assert!(response.unwrap().refreshing);
        assert_eq!(service.cache.last_request, Some(now));
        drop(service);
    }

    #[test]
    fn shutdown_cancels_in_progress_scan_and_joins_worker() {
        let (started, started_rx) = mpsc::sync_channel(1);
        let (stopped, stopped_rx) = mpsc::sync_channel(1);
        let mut service = OwnerService::spawn(move |_, cancelled| {
            started.send(()).unwrap();
            while !cancelled.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            stopped.send(()).unwrap();
            None
        })
        .unwrap();
        let root = TempDir::new().unwrap();
        service.snapshot(BTreeSet::from([identity(1)]), root.path(), Instant::now());
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(service);
        stopped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }
}
