pub(crate) mod conntrack_flow;
pub(crate) mod irq;
#[allow(dead_code)]
pub(crate) mod netfilter;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod network_route;
pub(crate) mod nic;
pub(crate) mod procfs;
pub(crate) mod rtnetlink;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod sock_diag;
pub(crate) mod socket_process;
pub(crate) mod sysfs;
pub(crate) mod tc;
mod topology;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::model::{
    CollectionError, MetricSample, PROVIDER_LINK, PROVIDER_PROC_PROTOCOL, PROVIDER_SOCK_DIAG,
    PROVIDER_SOFTNET,
};
use crate::provider as provider_registry;

pub use topology::{resolve_interface_path, ResolvedInterfacePath};

pub use sock_diag::SockDiagProbe;
pub(crate) use sock_diag::{SockDiagDeltaReport, SocketDropDelta};

#[derive(Clone, Debug)]
pub struct SystemPaths {
    pub proc_root: PathBuf,
    pub sys_root: PathBuf,
}

impl Default for SystemPaths {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            sys_root: PathBuf::from("/sys"),
        }
    }
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub metrics: Vec<MetricSample>,
    pub errors: Vec<CollectionError>,
    pub netlink_loss_events: u64,
    pub netlink_dump_interruptions: u64,
    pub parse_errors: u64,
    pub(crate) socket_diag: Option<sock_diag::SockDiagSnapshot>,
}

pub fn collect_snapshot(
    paths: &SystemPaths,
    interface: Option<&str>,
    providers: &BTreeSet<&str>,
) -> Snapshot {
    let mut snapshot = Snapshot::default();

    if providers.contains(PROVIDER_PROC_PROTOCOL) {
        collect_into(
            &mut snapshot,
            PROVIDER_PROC_PROTOCOL,
            procfs::collect_named_tables(&paths.proc_root.join("net/snmp"), "proc_net_snmp"),
        );
        collect_into(
            &mut snapshot,
            PROVIDER_PROC_PROTOCOL,
            procfs::collect_named_tables(&paths.proc_root.join("net/netstat"), "proc_net_netstat"),
        );
    }
    if providers.contains(PROVIDER_SOFTNET) {
        collect_into(
            &mut snapshot,
            PROVIDER_SOFTNET,
            procfs::collect_softnet(
                &paths.proc_root.join("net/softnet_stat"),
                &paths.sys_root.join("devices/system/cpu/online"),
            ),
        );
    }

    if providers.contains(PROVIDER_SOCK_DIAG) {
        snapshot.socket_diag = Some(sock_diag::collect_current_namespace());
    }

    if providers.contains(PROVIDER_LINK) {
        match rtnetlink::collect_link_stats(interface) {
            Ok(metrics) => snapshot.metrics.extend(metrics),
            Err(error) => {
                snapshot.netlink_loss_events = snapshot
                    .netlink_loss_events
                    .saturating_add(error.loss_events());
                snapshot.netlink_dump_interruptions = snapshot
                    .netlink_dump_interruptions
                    .saturating_add(error.dumps_interrupted());
                snapshot.parse_errors = snapshot.parse_errors.saturating_add(error.parse_errors());
                snapshot.errors.push(CollectionError {
                    provider: PROVIDER_LINK.to_owned(),
                    message: error.to_string(),
                });
                collect_link_stats_fallback(&mut snapshot, paths, interface);
            }
        }
    }

    snapshot
        .metrics
        .sort_by(|left, right| left.key.cmp(&right.key));
    snapshot
}

#[allow(dead_code)]
pub(crate) fn calculate_sock_diag_deltas(
    start: &mut Snapshot,
    end: &mut Snapshot,
) -> Option<SockDiagDeltaReport> {
    let start = start.socket_diag.take()?;
    let end = end.socket_diag.take()?;
    Some(sock_diag::calculate_deltas(start, end))
}

pub fn retain_interface_path(snapshot: &mut Snapshot, path: &ResolvedInterfacePath) {
    if !path.path.is_complete() {
        return;
    }
    snapshot.metrics.retain(|sample| {
        if provider_registry::descriptor_for_metric_source(&sample.key.source)
            .is_none_or(|provider| provider.name != PROVIDER_LINK)
        {
            return true;
        }
        let ifindex_matches = sample
            .key
            .labels
            .get("ifindex")
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|ifindex| {
                path.path
                    .visible_ifindices
                    .iter()
                    .any(|visible| visible.get() == ifindex)
            });
        let name_matches = sample
            .key
            .labels
            .get("interface")
            .is_some_and(|name| path.interface_names.contains(name));
        ifindex_matches || name_matches
    });
}

pub fn probe_rtnetlink_link_stats() -> Result<(), String> {
    rtnetlink::probe().map_err(|error| error.to_string())
}

pub fn probe_sock_diag() -> Result<SockDiagProbe, String> {
    sock_diag::probe()
}

pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/')
}

pub fn network_namespace(paths: &SystemPaths) -> Option<String> {
    std::fs::read_link(paths.proc_root.join("self/ns/net"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn collect_proc_net_dev_fallback(
    snapshot: &mut Snapshot,
    paths: &SystemPaths,
    interface: Option<&str>,
) {
    match procfs::collect_net_dev(&paths.proc_root.join("net/dev"), interface) {
        Ok(mut metrics) => match sysfs::attach_interface_ifindices(&paths.sys_root, &mut metrics) {
            Ok(()) => snapshot.metrics.extend(metrics),
            Err(error) => {
                snapshot.parse_errors = snapshot.parse_errors.saturating_add(error.parse_errors());
                snapshot.errors.push(CollectionError {
                    provider: PROVIDER_LINK.to_owned(),
                    message: error.to_string(),
                });
            }
        },
        Err(error) => {
            snapshot.parse_errors = snapshot.parse_errors.saturating_add(error.parse_errors());
            snapshot.errors.push(CollectionError {
                provider: PROVIDER_LINK.to_owned(),
                message: error.to_string(),
            });
        }
    }
}

fn collect_link_stats_fallback(
    snapshot: &mut Snapshot,
    paths: &SystemPaths,
    interface: Option<&str>,
) {
    match sysfs::collect_link_stats(&paths.sys_root, interface) {
        Ok(metrics) if !metrics.is_empty() => snapshot.metrics.extend(metrics),
        Ok(_) => collect_proc_net_dev_fallback(snapshot, paths, interface),
        Err(error) => {
            snapshot.parse_errors = snapshot.parse_errors.saturating_add(error.parse_errors());
            snapshot.errors.push(CollectionError {
                provider: PROVIDER_LINK.to_owned(),
                message: error.to_string(),
            });
            collect_proc_net_dev_fallback(snapshot, paths, interface);
        }
    }
}

fn collect_into(
    snapshot: &mut Snapshot,
    provider: &str,
    result: anyhow::Result<Vec<MetricSample>>,
) {
    match result {
        Ok(metrics) => snapshot.metrics.extend(metrics),
        Err(error) => snapshot.errors.push(CollectionError {
            provider: provider.to_owned(),
            message: error.to_string(),
        }),
    }
}

pub(crate) fn read_to_string(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|error| anyhow::anyhow!("{}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn validates_interface_names_before_path_construction() {
        assert!(valid_interface_name("eth0"));
        assert!(valid_interface_name("veth.100-1"));
        assert!(!valid_interface_name("../eth0"));
        assert!(!valid_interface_name("eth 0"));
        assert!(!valid_interface_name("eth\u{00a0}0"));
        assert!(!valid_interface_name("eth\u{1b}[2J"));
        assert!(!valid_interface_name("eth\u{7}0"));
        assert!(!valid_interface_name("eth\u{7f}0"));
        assert!(!valid_interface_name(""));
        assert!(!valid_interface_name("1234567890123456"));
    }

    #[test]
    fn fallback_parse_failures_are_counted() {
        let root = tempdir().unwrap();
        let sys_root = root.path().join("sys");
        let proc_root = root.path().join("proc");
        let stats = sys_root.join("class/net/eth0/statistics");
        fs::create_dir_all(&stats).unwrap();
        fs::create_dir_all(proc_root.join("net")).unwrap();
        fs::write(sys_root.join("class/net/eth0/ifindex"), "2\n").unwrap();
        fs::write(stats.join("rx_dropped"), "invalid\n").unwrap();
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 1 2 3\n",
        )
        .unwrap();
        let paths = SystemPaths {
            proc_root,
            sys_root,
        };
        let mut snapshot = Snapshot::default();

        collect_link_stats_fallback(&mut snapshot, &paths, Some("eth0"));

        assert_eq!(snapshot.parse_errors, 2);
        assert_eq!(snapshot.errors.len(), 2);
    }

    #[test]
    fn interface_path_filter_does_not_copy_anchor_identity_into_other_metrics() {
        use crate::capture::{InterfaceAnchor, InterfacePath};
        use crate::model::IfIndex;

        let path = ResolvedInterfacePath {
            path: InterfacePath::new(
                InterfaceAnchor::named("eth0").unwrap(),
                Some(IfIndex::new(2).unwrap()),
                [IfIndex::new(2).unwrap()],
                [],
            )
            .unwrap(),
            interface_names: ["eth0".to_owned()].into_iter().collect(),
        };
        let mut snapshot = Snapshot {
            metrics: vec![
                MetricSample {
                    key: crate::model::MetricKey::new("rtnetlink_link_stats", "link", "rx_dropped")
                        .with_label("ifindex", "2")
                        .with_label("interface", "eth0"),
                    value: 1,
                },
                MetricSample {
                    key: crate::model::MetricKey::new("rtnetlink_link_stats", "link", "rx_dropped")
                        .with_label("ifindex", "3")
                        .with_label("interface", "eth1"),
                    value: 2,
                },
                MetricSample {
                    key: crate::model::MetricKey::new("proc_net_snmp", "Udp", "RcvbufErrors"),
                    value: 3,
                },
            ],
            ..Snapshot::default()
        };

        retain_interface_path(&mut snapshot, &path);

        assert_eq!(snapshot.metrics.len(), 2);
        assert!(snapshot
            .metrics
            .iter()
            .any(|sample| sample.key.source == "proc_net_snmp"));
        assert!(!snapshot.metrics.iter().any(|sample| {
            sample
                .key
                .labels
                .get("interface")
                .is_some_and(|name| name == "eth1")
        }));
    }
}
