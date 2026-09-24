use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{EthtoolFailure, NicCollection};

const RETRY_AFTER: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) index: u32,
    pub(crate) hardware: bool,
    pub(crate) driver: Option<String>,
    pub(crate) directory: Option<(u64, u64)>,
    pub(crate) device: Option<(u64, u64)>,
}

pub(crate) fn inventory(root: &Path, collection: &NicCollection) -> BTreeMap<String, Identity> {
    collection
        .interfaces
        .iter()
        .map(|interface| {
            let path = root.join("class/net").join(&interface.interface);
            let stat = |path: &Path| path.metadata().ok().map(|stat| (stat.dev(), stat.ino()));
            (
                interface.interface.clone(),
                Identity {
                    index: interface.ifindex,
                    hardware: interface.hardware_backed,
                    driver: std::fs::read_link(path.join("device/driver"))
                        .ok()
                        .map(|path| path.to_string_lossy().into_owned())
                        .or_else(|| interface.sysfs.driver.clone()),
                    directory: stat(&path),
                    device: stat(&path.join("device")),
                },
            )
        })
        .collect()
}

#[derive(Debug, Default)]
pub(super) struct Cache {
    identities: Arc<BTreeMap<String, Identity>>,
    failures: BTreeMap<String, BTreeMap<String, (Instant, EthtoolFailure)>>,
}

impl Cache {
    pub(super) fn reconcile(&mut self, identities: BTreeMap<String, Identity>) {
        self.failures.retain(|name, _| {
            identities.get(name).is_some_and(|identity| {
                identity.directory.is_some() && self.identities.get(name) == Some(identity)
            })
        });
        if *self.identities != identities {
            self.identities = Arc::new(identities);
        }
    }

    pub(super) fn snapshot(&self) -> Arc<BTreeMap<String, Identity>> {
        Arc::clone(&self.identities)
    }

    pub(super) fn get(&self, name: &str, operation: &str, now: Instant) -> Option<EthtoolFailure> {
        self.failures
            .get(name)?
            .get(operation)
            .filter(|(at, _)| now.saturating_duration_since(*at) < RETRY_AFTER)
            .map(|(_, failure)| failure.clone())
    }

    pub(super) fn record(
        &mut self,
        name: &str,
        operation: &str,
        now: Instant,
        failure: &EthtoolFailure,
    ) {
        // Ambiguous legacy messages such as "cannot get stats" are not capabilities.
        if let EthtoolFailure::Unsupported { detail } = failure {
            if detail.to_ascii_lowercase().contains("not supported")
                && self
                    .identities
                    .get(name)
                    .is_some_and(|identity| identity.directory.is_some())
            {
                self.failures
                    .entry(name.to_owned())
                    .or_default()
                    .insert(operation.to_owned(), (now, failure.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_expires_and_identity_changes_invalidate_it() {
        let now = Instant::now();
        let identity = Identity {
            index: 2,
            hardware: true,
            driver: Some("driver".into()),
            directory: Some((1, 10)),
            device: Some((1, 20)),
        };
        let mut cache = Cache::default();
        cache.reconcile(BTreeMap::from([("eth0".into(), identity.clone())]));
        let unsupported = EthtoolFailure::Unsupported {
            detail: "Operation not supported".into(),
        };
        cache.record("eth0", "-g", now, &unsupported);
        assert_eq!(
            cache.get("eth0", "-g", now + Duration::from_secs(299)),
            Some(unsupported.clone())
        );
        assert_eq!(cache.get("eth0", "-g", now + RETRY_AFTER), None);
        assert_eq!(cache.get("eth0", "-k", now), None);
        for failure in [
            EthtoolFailure::TimedOut,
            EthtoolFailure::InvalidOutput,
            EthtoolFailure::PermissionDenied {
                detail: "denied".into(),
            },
            EthtoolFailure::Unsupported {
                detail: "cannot get stats".into(),
            },
        ] {
            cache.record("eth0", "-a", now, &failure);
            assert_eq!(cache.get("eth0", "-a", now), None);
        }
        for changed in [
            Identity {
                index: 3,
                ..identity.clone()
            },
            Identity {
                directory: Some((1, 11)),
                ..identity.clone()
            },
            Identity {
                driver: Some("new".into()),
                ..identity.clone()
            },
        ] {
            cache.reconcile(BTreeMap::from([("eth0".into(), identity.clone())]));
            cache.record("eth0", "-g", now, &unsupported);
            cache.reconcile(BTreeMap::from([("eth0".into(), changed)]));
            assert_eq!(cache.get("eth0", "-g", now), None);
        }
        cache.reconcile(BTreeMap::new());
        assert!(cache.failures.is_empty());
    }
}
