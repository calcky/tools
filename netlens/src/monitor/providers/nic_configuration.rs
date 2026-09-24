use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::NicCollectionTiming;
use crate::collect::nic::{self, capabilities::Identity};

pub(super) const STAGGER: Duration = Duration::from_secs(5);
type Inventory = Arc<BTreeMap<String, Identity>>;

#[derive(Debug)]
pub(super) struct Batch {
    pub collection: nic::NicCollection,
    pub timing: NicCollectionTiming,
    inventory: Inventory,
    valid: bool,
}

enum Command {
    Collect {
        collection: nic::NicCollection,
        root: PathBuf,
        start: Instant,
        stagger: Duration,
        inventory: Inventory,
    },
    Stop,
}

#[derive(Debug)]
struct Worker {
    control: mpsc::SyncSender<Command>,
    results: mpsc::Receiver<Batch>,
    cancelled: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    fn start() -> io::Result<Self> {
        let (control, receiver) = mpsc::sync_channel(1);
        let (sender, results) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let thread = thread::Builder::new()
            .name("netlens-nic-conf".into())
            .spawn(move || {
                run(
                    receiver,
                    sender,
                    &worker_cancelled,
                    &mut nic::NicCollector::default(),
                );
            })?;
        Ok(Self {
            control,
            results,
            cancelled,
            thread: Some(thread),
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.control.try_send(Command::Stop);
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Service {
    worker: Option<Worker>,
    pending: bool,
    inventory: Inventory,
    published: Option<Inventory>,
}

impl Service {
    #[cfg(test)]
    pub fn observe(&mut self, root: &Path, collection: &nic::NicCollection) {
        self.observe_inventory(Arc::new(nic::capabilities::inventory(root, collection)));
    }

    pub fn observe_inventory(&mut self, inventory: Inventory) {
        self.inventory = inventory;
    }

    pub fn current(&self) -> bool {
        self.published.as_ref() == Some(&self.inventory)
    }

    pub fn stop(&mut self) {
        self.worker = None;
        self.pending = false;
    }

    pub fn poll(&mut self) -> io::Result<Option<Batch>> {
        let Some(worker) = &self.worker else {
            return Ok(None);
        };
        match worker.results.try_recv() {
            Ok(batch) => {
                self.pending = false;
                if !batch.valid || batch.inventory != self.inventory {
                    return Ok(None);
                }
                self.published = Some(batch.inventory.clone());
                Ok(Some(batch))
            }
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.stop();
                Err(io::Error::other("NIC configuration worker stopped"))
            }
        }
    }

    pub fn request(
        &mut self,
        root: &Path,
        collection: &nic::NicCollection,
        start: Instant,
        stagger: Duration,
    ) -> io::Result<()> {
        if self.pending {
            return Ok(());
        }
        if self.worker.is_none() {
            self.worker = Some(Worker::start()?);
        }
        let mut collection = collection.clone();
        for interface in &mut collection.interfaces {
            interface.ethtool = nic::EthtoolOutcome::NotHardwareInterface;
        }
        self.worker
            .as_ref()
            .unwrap()
            .control
            .try_send(Command::Collect {
                collection,
                root: root.to_owned(),
                start,
                stagger,
                inventory: self.inventory.clone(),
            })
            .map_err(|_| io::Error::other("NIC configuration worker unavailable"))?;
        self.pending = true;
        Ok(())
    }
}

fn offset(stagger: Duration, index: usize, batches: usize) -> Duration {
    if batches < 2 {
        Duration::ZERO
    } else {
        stagger.mul_f64(index as f64 / (batches - 1) as f64)
    }
}

fn run(
    receiver: mpsc::Receiver<Command>,
    sender: mpsc::SyncSender<Batch>,
    cancelled: &AtomicBool,
    collector: &mut nic::NicCollector,
) {
    while let Ok(Command::Collect {
        mut collection,
        root,
        start,
        stagger,
        inventory,
    }) = receiver.recv()
    {
        if cancelled.load(Ordering::Acquire) {
            return;
        }
        collector.prepare_configuration(&root, &collection);
        let began = Instant::now();
        let batches = collection.interfaces.len().div_ceil(4);
        let mut duration = Duration::ZERO;
        for (index, interfaces) in collection.interfaces.chunks_mut(4).enumerate() {
            let deadline = began + offset(stagger, index, batches);
            if deadline > Instant::now() {
                match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    _ => return,
                }
            }
            if cancelled.load(Ordering::Acquire) {
                return;
            }
            let mut part = nic::NicCollection {
                interfaces: interfaces.to_vec(),
                errors: Vec::new(),
            };
            let attempted = Instant::now();
            collector.collect_configuration(&root, &mut part);
            duration += attempted.elapsed();
            interfaces.clone_from_slice(&part.interfaces);
        }
        if cancelled.load(Ordering::Acquire) {
            return;
        }
        let finished_at = start.elapsed();
        let result = Batch {
            valid: nic::capabilities::inventory(&root, &collection) == *inventory,
            collection,
            inventory,
            timing: NicCollectionTiming {
                finished_at,
                collection_duration: duration.min(finished_at),
            },
        };
        if sender.try_send(result).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn virtual_interfaces(root: &Path) -> nic::NicCollection {
        let interfaces = (0..8)
            .map(|index| {
                let name = format!("veth{index}");
                std::fs::create_dir_all(root.join("class/net").join(&name)).unwrap();
                nic::NicInterface {
                    interface: name,
                    ifindex: index + 1,
                    hardware_backed: false,
                    operstate: nic::OperState::Up,
                    sysfs: nic::NicSysfsInfo::default(),
                    channels: Vec::new(),
                    fallback_settings: Vec::new(),
                    settings: nic::EthtoolSettingsOutcome::NotHardwareInterface,
                    ethtool: nic::EthtoolOutcome::NotHardwareInterface,
                }
            })
            .collect();
        nic::NicCollection {
            interfaces,
            errors: Vec::new(),
        }
    }

    fn complete(service: &mut Service) -> Batch {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(batch) = service.poll().unwrap() {
                return batch;
            }
            assert!(Instant::now() < deadline, "configuration batch timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn worker_publishes_whole_batches_and_cancels_during_stagger_wait() {
        let root = tempfile::tempdir().unwrap();
        let collection = virtual_interfaces(root.path());
        let mut service = Service::default();
        let start = Instant::now();
        service.observe(root.path(), &collection);
        service
            .request(root.path(), &collection, start, Duration::ZERO)
            .unwrap();
        let first = complete(&mut service);
        assert_eq!(first.collection.interfaces.len(), 8);
        assert!(service.current());
        service
            .request(root.path(), &collection, start, Duration::from_millis(150))
            .unwrap();
        thread::sleep(Duration::from_millis(25));
        assert!(
            service.poll().unwrap().is_none(),
            "partial batches must not be published"
        );
        let second = complete(&mut service);
        assert!(second.timing.finished_at > first.timing.finished_at);
        assert!(
            second
                .timing
                .finished_at
                .saturating_sub(first.timing.finished_at)
                >= Duration::from_millis(150)
        );
        assert_eq!(second.collection.interfaces.len(), 8);
        service
            .request(root.path(), &collection, start, STAGGER)
            .unwrap();
        thread::sleep(Duration::from_millis(30));
        let stopped = Instant::now();
        service.stop();
        assert!(stopped.elapsed() < Duration::from_secs(1));
        assert!(service.worker.is_none());
        assert!(!service.pending);
        service
            .request(root.path(), &collection, start, Duration::ZERO)
            .unwrap();
        assert_eq!(complete(&mut service).collection.interfaces.len(), 8);
    }

    #[test]
    fn recurring_batches_span_the_window_without_delaying_a_single_batch() {
        assert_eq!(offset(STAGGER, 0, 1), Duration::ZERO);
        assert_eq!(offset(STAGGER, 0, 7), Duration::ZERO);
        assert_eq!(offset(STAGGER, 3, 7), Duration::from_millis(2500));
        assert_eq!(offset(STAGGER, 6, 7), STAGGER);
    }

    #[test]
    fn replacement_during_a_batch_cannot_publish_old_identity_settings() {
        let root = tempfile::tempdir().unwrap();
        let collection = virtual_interfaces(root.path());
        let mut service = Service::default();
        let start = Instant::now();
        service.observe(root.path(), &collection);
        service
            .request(root.path(), &collection, start, Duration::from_millis(150))
            .unwrap();
        thread::sleep(Duration::from_millis(25));
        let interface = root.path().join("class/net/veth0");
        std::fs::rename(&interface, root.path().join("removed")).unwrap();
        std::fs::create_dir(&interface).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while service.pending {
            assert!(service.poll().unwrap().is_none());
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(!service.current());
        service.observe(root.path(), &collection);
        service
            .request(root.path(), &collection, start, Duration::ZERO)
            .unwrap();
        assert_eq!(complete(&mut service).collection.interfaces.len(), 8);
        assert!(service.current());
    }

    #[test]
    fn completed_batch_is_discarded_after_inventory_change() {
        let (control, _) = mpsc::sync_channel(1);
        let (sender, results) = mpsc::sync_channel(1);
        let mut service = Service {
            worker: Some(Worker {
                control,
                results,
                cancelled: Arc::new(AtomicBool::new(false)),
                thread: None,
            }),
            pending: true,
            ..Service::default()
        };
        sender
            .send(Batch {
                valid: true,
                collection: nic::NicCollection::default(),
                timing: NicCollectionTiming {
                    finished_at: Duration::from_secs(1),
                    collection_duration: Duration::ZERO,
                },
                inventory: Arc::new(BTreeMap::from([(
                    "removed".into(),
                    Identity {
                        index: 2,
                        hardware: false,
                        driver: None,
                        directory: None,
                        device: None,
                    },
                )])),
            })
            .unwrap();
        assert!(service.poll().unwrap().is_none());
        assert!(!service.pending);
        assert!(!service.current());
    }
}
