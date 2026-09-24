use std::collections::BTreeMap;
use std::ffi::{CStr, OsStr};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr::NonNull;
use std::time::Instant;

use crate::collect::rtnetlink::FreshLinkMetadata;

use super::{
    netlink, EthtoolOutcome, EthtoolSettingsOutcome, NicCollection, NicCollectionError,
    NicCollectionErrorKind, NicInterface, NicSysfsInfo, OperState,
};

const QUEUE_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Context {
    socket: Option<netlink::Socket>,
    directories: BTreeMap<String, InterfaceDirectory>,
    max_cached_interfaces: usize,
}

impl Default for Context {
    fn default() -> Self {
        // Keep most of the descriptor budget free for other collectors and
        // bounded command pipes. Uncached directories are still read each poll.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one correctly sized rlimit.
        let max_descriptors = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            (limit.rlim_cur / 4).min(256) as usize
        } else {
            32
        };
        Self {
            socket: None,
            directories: BTreeMap::new(),
            // Each cached interface owns at most its directory and queue DIR.
            max_cached_interfaces: max_descriptors / 2,
        }
    }
}

#[derive(Debug)]
struct InterfaceDirectory {
    file: File,
    identity: (u64, u64),
    queues: Option<CachedQueues>,
}

#[derive(Debug)]
struct CachedQueues {
    identity: (u64, u64),
    directory: QueueDirectory,
    counts: (u32, u32),
    checked_at: Instant,
}

#[derive(Debug)]
struct QueueDirectory(NonNull<libc::DIR>);

// The directory has one owner, and readdir/rewinddir require &mut self.
unsafe impl Send for QueueDirectory {}

impl Drop for QueueDirectory {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the DIR and its descriptor.
        unsafe {
            libc::closedir(self.0.as_ptr());
        }
    }
}

impl QueueDirectory {
    fn open(parent: &File, identity: (u64, u64)) -> io::Result<Self> {
        let file = open_at(parent, c"queues", libc::O_RDONLY | libc::O_DIRECTORY)?;
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != identity {
            return Err(io::Error::other(
                "NIC queues changed while opening directory",
            ));
        }
        let fd = file.into_raw_fd();
        // SAFETY: fd is an owned open descriptor; fdopendir assumes ownership on success.
        let directory = unsafe { libc::fdopendir(fd) };
        match NonNull::new(directory) {
            Some(directory) => Ok(Self(directory)),
            None => {
                let error = io::Error::last_os_error();
                // SAFETY: failed fdopendir leaves descriptor ownership with us.
                unsafe {
                    libc::close(fd);
                }
                Err(error)
            }
        }
    }

    fn counts(&mut self) -> io::Result<(u32, u32)> {
        // SAFETY: the directory is valid and exclusively borrowed. Rewinding
        // causes new getdents reads, so queue additions/removals remain visible.
        unsafe {
            libc::rewinddir(self.0.as_ptr());
        }
        let mut rx = 0_u32;
        let mut tx = 0_u32;
        loop {
            // SAFETY: errno is thread-local; readdir uses our live DIR.
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(self.0.as_ptr()) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok((rx, tx))
                } else {
                    Err(error)
                };
            }
            // SAFETY: readdir returns a terminated name valid until its next call.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            let (digits, count) = match name.strip_prefix(b"rx-") {
                Some(digits) => (digits, &mut rx),
                None => match name.strip_prefix(b"tx-") {
                    Some(digits) => (digits, &mut tx),
                    None => continue,
                },
            };
            if digits.is_empty()
                || !digits.iter().all(u8::is_ascii_digit)
                || std::str::from_utf8(digits)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_none()
            {
                continue;
            }
            *count = count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("too many NIC queues"))?;
        }
    }
}

impl Context {
    #[cfg(test)]
    fn expire_queue_cache(&mut self) {
        for directory in self.directories.values_mut() {
            if let Some(queues) = directory.queues.as_mut() {
                queues.checked_at = Instant::now() - QUEUE_REFRESH_INTERVAL;
            }
        }
    }

    pub(super) fn collect_with_metadata(
        &mut self,
        sys_root: &Path,
        metadata: Option<FreshLinkMetadata>,
    ) -> io::Result<(NicCollection, Option<Instant>)> {
        self.collect_with_recollection(sys_root, metadata, Self::collect)
    }

    fn collect_with_recollection(
        &mut self,
        sys_root: &Path,
        metadata: Option<FreshLinkMetadata>,
        recollect: impl FnOnce(&mut Self, &Path) -> io::Result<NicCollection>,
    ) -> io::Result<(NicCollection, Option<Instant>)> {
        if let Some(metadata) = metadata {
            let links = metadata
                .links
                .into_iter()
                .map(|link| netlink::Link {
                    ifindex: link.ifindex,
                    name: link.name,
                    operstate: link.operstate,
                    tx_queue_len: link.tx_queue_len,
                    mtu: link.mtu,
                })
                .collect();
            match self.collect_links(sys_root, links) {
                Ok(collection) => return Ok((collection, Some(metadata.started_at))),
                Err(_) => self.directories.clear(),
            }
        }
        // A failed shared scan is only an optimization miss. Independently
        // observe inventory again before invoking the existing sysfs fallback.
        recollect(self, sys_root).map(|collection| (collection, None))
    }

    pub(super) fn collect(&mut self, sys_root: &Path) -> io::Result<NicCollection> {
        if self.socket.is_none() {
            self.socket = Some(netlink::Socket::new(libc::NETLINK_ROUTE)?);
        }
        let links = match self.socket.as_mut().expect("initialized above").links() {
            Ok(links) => links,
            Err(error) => {
                // Discard a possibly interrupted dump before the next attempt.
                self.socket = None;
                self.directories.clear();
                return Err(error);
            }
        };
        let result = self.collect_links(sys_root, links);
        if result.is_err() {
            self.directories.clear();
        }
        result
    }

    fn collect_links(
        &mut self,
        sys_root: &Path,
        mut links: Vec<netlink::Link>,
    ) -> io::Result<NicCollection> {
        links.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        self.directories
            .retain(|name, _| links.binary_search_by(|link| link.name.cmp(name)).is_ok());
        let mut collection = NicCollection::default();
        // Preserve discovery errors from non-interface class entries (for
        // example bonding_masters), as well as the existing provider health.
        let net_root = sys_root.join("class/net");
        let root = File::open(&net_root)?;
        let mut matched = 0;
        for entry in fs::read_dir(&net_root)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    collection.errors.push(NicCollectionError {
                        interface: None,
                        kind: NicCollectionErrorKind::DiscoverInterfaces,
                        detail: format!("{}: invalid directory entry: {error}", net_root.display()),
                    });
                    continue;
                }
            };
            let name = match entry.file_name().into_string() {
                Ok(name) if super::valid_interface_name(&name) => name,
                _ => {
                    collection.errors.push(NicCollectionError {
                        interface: None,
                        kind: NicCollectionErrorKind::InvalidInterfaceName,
                        detail: "ignored a sysfs interface entry with an invalid name".to_owned(),
                    });
                    continue;
                }
            };
            let link = match links.binary_search_by(|link| link.name.cmp(&name)) {
                Ok(index) => &links[index],
                Err(_) => {
                    match super::read_ifindex(&entry.path()) {
                        Ok(_) => {
                            return Err(io::Error::other("NIC inventory changed during link dump"))
                        }
                        Err(detail) => collection.errors.push(NicCollectionError {
                            interface: Some(name),
                            kind: NicCollectionErrorKind::ReadIfindex,
                            detail,
                        }),
                    }
                    continue;
                }
            };
            // Names have already passed IFNAMSIZ and ASCII validation.
            let mut terminated = [0; libc::IFNAMSIZ];
            terminated[..name.len()].copy_from_slice(name.as_bytes());
            let relative = CStr::from_bytes_until_nul(&terminated).expect("terminated name");
            let identity = identity_at(&root, relative)?;
            if self
                .directories
                .get(&name)
                .is_some_and(|cached| cached.identity != identity)
            {
                self.directories.remove(&name);
            }
            let mut uncached;
            let directory = if self.directories.contains_key(&name) {
                self.directories.get_mut(&name).expect("checked above")
            } else {
                let directory = InterfaceDirectory::open(&root, relative, identity)?;
                if self.directories.len() < self.max_cached_interfaces {
                    self.directories.entry(name.clone()).or_insert(directory)
                } else {
                    uncached = directory;
                    &mut uncached
                }
            };
            directory.verify_ifindex(link.ifindex)?;
            matched += 1;
            let hardware_backed = identity_at(&directory.file, c"device").is_ok();
            let queues = directory.queue_counts(false);
            let operstate = match link.operstate {
                Some(0) => OperState::Unknown,
                Some(1) => OperState::NotPresent,
                Some(2) => OperState::Down,
                Some(3) => OperState::LowerLayerDown,
                Some(4) => OperState::Testing,
                Some(5) => OperState::Dormant,
                Some(6) => OperState::Up,
                _ => match super::read_operstate(&entry.path()) {
                    Ok(state) => state,
                    Err(detail) => {
                        collection.errors.push(NicCollectionError {
                            interface: Some(link.name.clone()),
                            kind: NicCollectionErrorKind::ReadOperstate,
                            detail,
                        });
                        OperState::Unavailable
                    }
                },
            };
            let sysfs = NicSysfsInfo {
                driver: directory.driver_name(),
                rx_queue_count: queues.map(|(rx, _)| rx),
                tx_queue_count: queues.map(|(_, tx)| tx),
                tx_queue_len: link
                    .tx_queue_len
                    .or_else(|| super::read_optional_u32(&entry.path().join("tx_queue_len"))),
                mtu: link
                    .mtu
                    .or_else(|| super::read_optional_u32(&entry.path().join("mtu"))),
            };
            // An open directory pins the old object after rename/replacement.
            // Do not emit that detached object's fields under the current name.
            directory.verify_identity(&root, relative)?;
            collection.interfaces.push(NicInterface {
                ifindex: link.ifindex,
                interface: name,
                hardware_backed,
                operstate,
                sysfs,
                channels: Vec::new(),
                fallback_settings: Vec::new(),
                settings: EthtoolSettingsOutcome::NotHardwareInterface,
                ethtool: EthtoolOutcome::NotHardwareInterface,
            });
        }
        if matched != links.len() {
            return Err(io::Error::other("sysfs and netlink inventories differ"));
        }
        collection.interfaces.sort_by(|left, right| {
            left.ifindex
                .cmp(&right.ifindex)
                .then_with(|| left.interface.cmp(&right.interface))
        });
        Ok(collection)
    }
}

fn open_at(parent: &File, path: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: parent owns a live descriptor and path is terminated. No creation flags are used.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor with no other owner.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn identity_at(parent: &File, path: &CStr) -> io::Result<(u64, u64)> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstatat initializes one stat on success; parent/path remain live.
    if unsafe { libc::fstatat(parent.as_raw_fd(), path.as_ptr(), metadata.as_mut_ptr(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call initialized metadata.
    let metadata = unsafe { metadata.assume_init() };
    Ok((metadata.st_dev, metadata.st_ino))
}

impl InterfaceDirectory {
    fn open(parent: &File, name: &CStr, identity: (u64, u64)) -> io::Result<Self> {
        let file = open_at(parent, name, libc::O_PATH | libc::O_DIRECTORY)?;
        let metadata = file.metadata()?;
        if (metadata.dev(), metadata.ino()) != identity {
            return Err(io::Error::other(
                "NIC identity changed while opening directory",
            ));
        }
        Ok(Self {
            file,
            identity,
            queues: None,
        })
    }

    fn verify_identity(&self, root: &File, name: &CStr) -> io::Result<()> {
        if identity_at(root, name)? != self.identity {
            return Err(io::Error::other(
                "NIC identity changed while reading directory",
            ));
        }
        Ok(())
    }

    fn verify_ifindex(&self, expected: u32) -> io::Result<()> {
        let mut file = open_at(&self.file, c"ifindex", libc::O_RDONLY)?;
        let mut raw = [0; super::SYSFS_VALUE_LIMIT + 1];
        let mut length = 0;
        while length < raw.len() {
            match file.read(&mut raw[length..]) {
                Ok(0) => break,
                Ok(count) => length += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let actual = std::str::from_utf8(&raw[..length])
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok());
        if length > super::SYSFS_VALUE_LIMIT || actual != Some(expected) || expected == 0 {
            return Err(io::Error::other("NIC identity changed during link dump"));
        }
        Ok(())
    }

    fn driver_name(&self) -> Option<String> {
        let mut target = [0_u8; libc::PATH_MAX as usize];
        // SAFETY: target is writable for its full length; the path and fd are live.
        let length = unsafe {
            libc::readlinkat(
                self.file.as_raw_fd(),
                c"device/driver".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if length < 0 || length as usize == target.len() {
            return None;
        }
        let driver = Path::new(OsStr::from_bytes(&target[..length as usize]))
            .file_name()?
            .to_str()?;
        super::valid_setting_text(driver).then(|| driver.to_owned())
    }

    fn queue_counts(&mut self, force_refresh: bool) -> Option<(u32, u32)> {
        let identity = match identity_at(&self.file, c"queues") {
            Ok(identity) => identity,
            Err(_) => {
                self.queues = None;
                return None;
            }
        };
        let now = Instant::now();
        if self.queues.as_ref().is_some_and(|cached| {
            cached.identity == identity
                && !force_refresh
                && now.saturating_duration_since(cached.checked_at) < QUEUE_REFRESH_INTERVAL
        }) {
            return self.queues.as_ref().map(|cached| cached.counts);
        }
        if self
            .queues
            .as_ref()
            .is_none_or(|cached| cached.identity != identity)
        {
            self.queues = None;
            self.queues = Some(CachedQueues {
                identity,
                directory: QueueDirectory::open(&self.file, identity).ok()?,
                counts: (0, 0),
                checked_at: now,
            });
        }
        match self.queues.as_mut()?.directory.counts() {
            Ok(counts) => {
                let cached = self.queues.as_mut().expect("queue cache exists");
                cached.counts = counts;
                cached.checked_at = now;
                Some(counts)
            }
            Err(_) => {
                self.queues = None;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(path: &Path) -> InterfaceDirectory {
        let parent = File::open(path).unwrap();
        let identity = identity_at(&parent, c".").unwrap();
        InterfaceDirectory::open(&parent, c".", identity).unwrap()
    }

    fn links() -> Vec<netlink::Link> {
        vec![netlink::Link {
            ifindex: 2,
            name: "eth0".to_owned(),
            operstate: Some(6),
            tx_queue_len: Some(1000),
            mtu: Some(1500),
        }]
    }

    fn interface(path: &Path, driver: &str) {
        fs::create_dir_all(path.join("queues/rx-0")).unwrap();
        fs::create_dir_all(path.join("device")).unwrap();
        fs::write(path.join("ifindex"), "2\n").unwrap();
        fs::write(path.join("operstate"), "up\n").unwrap();
        fs::write(path.join("tx_queue_len"), "1000\n").unwrap();
        fs::write(path.join("mtu"), "1500\n").unwrap();
        std::os::unix::fs::symlink(format!("/drivers/{driver}"), path.join("device/driver"))
            .unwrap();
    }

    fn shared(links: Vec<netlink::Link>, started_at: Instant) -> FreshLinkMetadata {
        FreshLinkMetadata {
            started_at,
            links: links
                .into_iter()
                .map(|link| crate::collect::rtnetlink::LinkMetadata {
                    ifindex: link.ifindex,
                    name: link.name,
                    operstate: link.operstate,
                    tx_queue_len: link.tx_queue_len,
                    mtu: link.mtu,
                })
                .collect(),
        }
    }

    #[test]
    fn shared_inventory_matches_independent_fields_errors_and_current_sysfs() {
        let root = tempfile::tempdir().unwrap();
        let net = root.path().join("class/net");
        let path = net.join("eth0");
        interface(&path, "driver1");
        fs::write(net.join("bonding_masters"), "").unwrap();
        let mut context = Context::default();
        for iteration in 0..3 {
            if iteration == 1 {
                fs::create_dir(path.join("queues/tx-0")).unwrap();
                fs::remove_file(path.join("device/driver")).unwrap();
                std::os::unix::fs::symlink("/drivers/driver2", path.join("device/driver")).unwrap();
            } else if iteration == 2 {
                fs::rename(&path, root.path().join("old-eth0")).unwrap();
                interface(&path, "replacement-driver");
            }
            context.expire_queue_cache();
            let started_at = Instant::now();
            let (actual, observed) = context
                .collect_with_recollection(
                    root.path(),
                    Some(shared(links(), started_at)),
                    |_, _| panic!("unexpected recollection"),
                )
                .unwrap();
            assert_eq!(observed, Some(started_at));
            assert_eq!(
                actual,
                Context::default()
                    .collect_links(root.path(), links())
                    .unwrap()
            );
            assert_eq!(actual, super::super::collect_inventory(root.path()));
            assert_eq!(actual.errors.len(), 1);
        }
        let mut missing = links();
        missing[0].operstate = None;
        missing[0].tx_queue_len = None;
        missing[0].mtu = None;
        let (actual, _) = context
            .collect_with_recollection(
                root.path(),
                Some(shared(missing, Instant::now())),
                |_, _| panic!("unexpected recollection"),
            )
            .unwrap();
        assert_eq!(actual, super::super::collect_inventory(root.path()));
    }

    #[test]
    fn mismatched_shared_inventory_recollects_once_and_discards_shared_time() {
        let root = tempfile::tempdir().unwrap();
        interface(&root.path().join("class/net/eth0"), "driver1");
        for mutation in 0..5 {
            let mut stale = links();
            match mutation {
                0 => stale[0].ifindex = 3,
                1 => stale[0].name = "renamed".to_owned(),
                2 => stale.clear(),
                3 => stale.push(netlink::Link {
                    ifindex: 3,
                    name: "removed".to_owned(),
                    operstate: None,
                    tx_queue_len: None,
                    mtu: None,
                }),
                _ => {}
            }
            let mut attempts = 0;
            let mut context = Context::default();
            context.collect_links(root.path(), links()).unwrap();
            let metadata = (mutation != 4).then(|| shared(stale, Instant::now()));
            let (actual, observed) = context
                .collect_with_recollection(root.path(), metadata, |context, root| {
                    attempts += 1;
                    if mutation != 4 {
                        assert!(context.directories.is_empty());
                    }
                    context.collect_links(root, links())
                })
                .unwrap();
            assert_eq!(attempts, 1);
            assert_eq!(observed, None);
            assert_eq!(actual, super::super::collect_inventory(root.path()));
        }
    }

    #[test]
    fn mtu_uses_current_link_metadata_then_optional_sysfs_without_recollection() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("class/net/eth0");
        interface(&path, "driver1");
        let mut context = Context::default();
        for (link_mtu, expected) in [
            (Some(9000), Some(9000)),
            (Some(1500), Some(1500)),
            (None, Some(1500)),
        ] {
            let mut current = links();
            current[0].mtu = link_mtu;
            let (collection, _) = context
                .collect_with_recollection(
                    root.path(),
                    Some(shared(current, Instant::now())),
                    |_, _| panic!("MTU must not trigger a new inventory poll"),
                )
                .unwrap();
            assert_eq!(collection.interfaces[0].sysfs.mtu, expected);
        }
        fs::remove_file(path.join("mtu")).unwrap();
        let mut current = links();
        current[0].mtu = None;
        let collection = context.collect_links(root.path(), current).unwrap();
        assert_eq!(collection.interfaces[0].sysfs.mtu, None);
    }

    #[test]
    fn failed_shared_scan_still_attempts_independent_inventory_and_propagates_failure() {
        let root = tempfile::tempdir().unwrap();
        let mut attempts = 0;
        let error = Context::default()
            .collect_with_recollection(
                root.path(),
                Some(shared(links(), Instant::now())),
                |_, _| {
                    attempts += 1;
                    Err(io::Error::from_raw_os_error(libc::EIO))
                },
            )
            .unwrap_err();
        assert_eq!(attempts, 1);
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn replacement_between_link_dump_and_sysfs_scan_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("ifindex"), "2\n").unwrap();
        let directory = directory(root.path());
        directory.verify_ifindex(2).unwrap();
        fs::write(root.path().join("ifindex"), "3\n").unwrap();
        assert!(directory.verify_ifindex(2).is_err());
        directory.verify_ifindex(3).unwrap();
        fs::write(root.path().join("replacement"), "2\n").unwrap();
        fs::rename(root.path().join("replacement"), root.path().join("ifindex")).unwrap();
        directory.verify_ifindex(2).unwrap();
        fs::remove_file(root.path().join("ifindex")).unwrap();
        assert!(directory.verify_ifindex(2).is_err());
    }

    #[test]
    fn relative_ifindex_reader_preserves_validation_and_size_limit() {
        let root = tempfile::tempdir().unwrap();
        let directory = directory(root.path());
        for bytes in [
            b"  +2\n".as_slice(),
            b"0",
            b"",
            b"2\xff",
            b"not-an-index",
            &[b'2'; super::super::SYSFS_VALUE_LIMIT + 1],
        ] {
            fs::write(root.path().join("ifindex"), bytes).unwrap();
            assert_eq!(
                directory.verify_ifindex(2).is_ok(),
                super::super::read_ifindex(root.path()).is_ok_and(|value| value == 2)
            );
        }
    }

    #[test]
    fn cached_directory_observes_queue_changes_and_replacement() {
        let root = tempfile::tempdir().unwrap();
        let queues = root.path().join("queues");
        fs::create_dir(&queues).unwrap();
        fs::create_dir(queues.join("rx-0")).unwrap();
        fs::create_dir(queues.join("tx-0")).unwrap();
        let mut directory = directory(root.path());
        assert_eq!(directory.queue_counts(true), Some((1, 1)));
        fs::create_dir(queues.join("rx-1")).unwrap();
        fs::remove_dir(queues.join("tx-0")).unwrap();
        assert_eq!(directory.queue_counts(false), Some((1, 1)));
        assert_eq!(directory.queue_counts(true), Some((2, 0)));
        fs::rename(&queues, root.path().join("old-queues")).unwrap();
        fs::create_dir(&queues).unwrap();
        fs::create_dir(queues.join("tx-0")).unwrap();
        assert_eq!(directory.queue_counts(true), Some((0, 1)));
        fs::remove_dir_all(&queues).unwrap();
        assert_eq!(directory.queue_counts(true), None);
        assert!(directory.queues.is_none());
    }

    #[test]
    fn directory_budget_does_not_limit_inventory_coverage() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("class/net/eth0");
        interface(&path, "driver1");
        let mut context = Context {
            max_cached_interfaces: 0,
            ..Context::default()
        };
        for _ in 0..2 {
            let result = context.collect_links(root.path(), links()).unwrap();
            assert_eq!(result, super::super::collect_inventory(root.path()));
            assert!(context.directories.is_empty());
            fs::create_dir_all(path.join("queues/tx-0")).unwrap();
        }
    }

    #[test]
    fn cache_budget_and_removed_interface_release_cached_directories() {
        let root = tempfile::tempdir().unwrap();
        let net = root.path().join("class/net");
        interface(&net.join("eth0"), "driver1");
        interface(&net.join("eth1"), "driver2");
        fs::write(net.join("eth1/ifindex"), "3\n").unwrap();
        let mut current = links();
        current.push(netlink::Link {
            ifindex: 3,
            name: "eth1".to_owned(),
            operstate: Some(6),
            tx_queue_len: Some(1000),
            mtu: Some(1500),
        });
        let mut context = Context {
            max_cached_interfaces: 1,
            ..Context::default()
        };
        let result = context.collect_links(root.path(), current).unwrap();
        assert_eq!(result, super::super::collect_inventory(root.path()));
        assert_eq!(context.directories.len(), 1);
        fs::remove_dir_all(net.join("eth0")).unwrap();
        fs::remove_dir_all(net.join("eth1")).unwrap();
        assert_eq!(
            context.collect_links(root.path(), Vec::new()).unwrap(),
            NicCollection::default()
        );
        assert!(context.directories.is_empty());
    }

    #[test]
    fn cached_interface_tracks_retargeted_name_driver_and_discovery_errors() {
        let root = tempfile::tempdir().unwrap();
        let net = root.path().join("class/net");
        fs::create_dir_all(&net).unwrap();
        let old = root.path().join("old");
        let new = root.path().join("new");
        interface(&old, "driver1");
        interface(&new, "driver2");
        fs::create_dir(new.join("queues/tx-0")).unwrap();
        fs::write(net.join("bonding_masters"), "").unwrap();
        std::os::unix::fs::symlink(&old, net.join("eth0")).unwrap();
        let mut context = Context::default();
        for target in [&old, &new] {
            fs::remove_file(net.join("eth0")).unwrap();
            std::os::unix::fs::symlink(target, net.join("eth0")).unwrap();
            let result = context.collect_links(root.path(), links()).unwrap();
            assert_eq!(result, super::super::collect_inventory(root.path()));
            assert_eq!(result.errors.len(), 1);
        }
        fs::remove_file(new.join("device/driver")).unwrap();
        std::os::unix::fs::symlink("../driver3", new.join("device/driver")).unwrap();
        assert_eq!(
            context.collect_links(root.path(), links()).unwrap(),
            super::super::collect_inventory(root.path())
        );
        fs::remove_dir_all(new.join("device")).unwrap();
        assert_eq!(
            context.collect_links(root.path(), links()).unwrap(),
            super::super::collect_inventory(root.path())
        );
        fs::write(new.join("ifindex"), "3\n").unwrap();
        assert!(context.collect_links(root.path(), links()).is_err());
    }

    #[test]
    fn detached_directory_and_open_races_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("eth0");
        interface(&path, "driver1");
        let parent = File::open(root.path()).unwrap();
        let directory = directory(&path);
        let queues = identity_at(&directory.file, c"queues").unwrap();
        fs::rename(path.join("queues"), path.join("old-queues")).unwrap();
        fs::create_dir(path.join("queues")).unwrap();
        assert!(QueueDirectory::open(&directory.file, queues).is_err());
        fs::rename(&path, root.path().join("old-eth0")).unwrap();
        interface(&path, "driver2");
        assert!(directory.verify_identity(&parent, c"eth0").is_err());
        assert!(InterfaceDirectory::open(&parent, c"eth0", directory.identity).is_err());
        fs::remove_dir_all(&path).unwrap();
        assert!(directory.verify_identity(&parent, c"eth0").is_err());
    }
}
