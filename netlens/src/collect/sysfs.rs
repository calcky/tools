use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use crate::model::{IfIndex, MetricKey, MetricSample};

use super::valid_interface_name;

pub fn collect_link_stats(
    sys_root: &Path,
    interface: Option<&str>,
) -> Result<Vec<MetricSample>, CollectError> {
    if let Some(interface) = interface {
        if !valid_interface_name(interface) {
            return Err(CollectError::request(format!(
                "invalid interface name {interface:?}"
            )));
        }
        let path = sys_root.join("class/net").join(interface);
        if !path.exists() {
            return Err(CollectError::io(format!(
                "interface {interface} not found in sysfs"
            )));
        }
        return collect_interface(&path, interface);
    }

    let net_root = sys_root.join("class/net");
    let entries = std::fs::read_dir(&net_root).map_err(|error| {
        CollectError::io(format!(
            "{}: cannot list interfaces: {error}",
            net_root.display()
        ))
    })?;
    let mut metrics = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CollectError::io(format!(
                "{}: invalid directory entry: {error}",
                net_root.display()
            ))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !valid_interface_name(&name) {
            continue;
        }
        metrics.extend(collect_interface(&entry.path(), &name)?);
    }
    Ok(metrics)
}

fn collect_interface(path: &Path, interface: &str) -> Result<Vec<MetricSample>, CollectError> {
    let ifindex = read_ifindex(path)?;
    let statistics = path.join("statistics");
    let entries = std::fs::read_dir(&statistics).map_err(|error| {
        CollectError::io(format!(
            "{}: cannot list statistics: {error}",
            statistics.display()
        ))
    })?;
    let mut metrics = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| {
            CollectError::io(format!(
                "{}: invalid directory entry: {error}",
                statistics.display()
            ))
        })?;
        let file_type = entry.file_type().map_err(|error| {
            CollectError::io(format!(
                "{}: cannot read statistic file type: {error}",
                entry.path().display()
            ))
        })?;
        if !file_type.is_file() {
            continue;
        }
        let metric = entry.file_name().to_string_lossy().into_owned();
        let raw = std::fs::read_to_string(entry.path()).map_err(|error| {
            CollectError::io(format!(
                "{}: cannot read statistic: {error}",
                entry.path().display()
            ))
        })?;
        let value = raw.trim().parse::<u64>().map_err(|error| {
            CollectError::parse(format!(
                "{}.{} is not an unsigned counter: {error}",
                interface, metric
            ))
        })?;
        metrics.push(MetricSample {
            key: MetricKey::new("sys_class_net", "link", metric)
                .with_label("interface", interface)
                .with_label("ifindex", ifindex.as_str()),
            value,
        });
    }

    let carrier_changes_path = path.join("carrier_changes");
    match std::fs::read_to_string(&carrier_changes_path) {
        Ok(raw) => {
            let value = raw.trim().parse::<u64>().map_err(|error| {
                CollectError::parse(format!(
                    "{}.carrier_changes is not an unsigned counter: {error}",
                    interface
                ))
            })?;
            metrics.push(MetricSample {
                key: MetricKey::new("sys_class_net", "link", "carrier_changes")
                    .with_label("counter_bits", "32")
                    .with_label("interface", interface)
                    .with_label("ifindex", ifindex.as_str()),
                value,
            });
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CollectError::io(format!(
                "{}: cannot read statistic: {error}",
                carrier_changes_path.display()
            )));
        }
    }

    metrics.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(metrics)
}

pub(crate) fn attach_interface_ifindices(
    sys_root: &Path,
    metrics: &mut [MetricSample],
) -> Result<(), CollectError> {
    let interfaces = metrics
        .iter()
        .filter_map(|sample| sample.key.labels.get("interface").cloned())
        .collect::<BTreeSet<_>>();
    let mut ifindices = BTreeMap::new();
    for interface in interfaces {
        if !valid_interface_name(&interface) {
            return Err(CollectError::parse(format!(
                "invalid interface identity {interface:?}"
            )));
        }
        let path = sys_root.join("class/net").join(&interface);
        ifindices.insert(interface, read_ifindex(&path)?);
    }
    for sample in metrics {
        let Some(interface) = sample.key.labels.get("interface") else {
            continue;
        };
        let ifindex = ifindices
            .get(interface)
            .expect("all interface labels were resolved before mutation")
            .clone();
        sample.key.labels.insert("ifindex".to_owned(), ifindex);
    }
    Ok(())
}

fn read_ifindex(interface_path: &Path) -> Result<String, CollectError> {
    let path = interface_path.join("ifindex");
    let raw = std::fs::read_to_string(&path).map_err(|error| {
        CollectError::io(format!(
            "{}: cannot read interface index: {error}",
            path.display()
        ))
    })?;
    let value = raw.trim().parse::<u32>().map_err(|error| {
        CollectError::parse(format!(
            "{} is not an interface index: {error}",
            path.display()
        ))
    })?;
    let ifindex = IfIndex::new(value).map_err(|error| {
        CollectError::parse(format!(
            "{} is not an interface index: {error}",
            path.display()
        ))
    })?;
    Ok(ifindex.get().to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorKind {
    Io,
    Parse,
    Request,
}

#[derive(Debug)]
pub struct CollectError {
    kind: ErrorKind,
    message: String,
}

impl CollectError {
    fn io(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Io,
            message: message.into(),
        }
    }

    fn parse(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Parse,
            message: message.into(),
        }
    }

    fn request(message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind::Request,
            message: message.into(),
        }
    }

    pub const fn parse_errors(&self) -> u64 {
        if matches!(self.kind, ErrorKind::Parse) {
            1
        } else {
            0
        }
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reads_interface_statistics() {
        let root = tempdir().unwrap();
        let stats = root.path().join("class/net/eth0/statistics");
        fs::create_dir_all(&stats).unwrap();
        fs::write(root.path().join("class/net/eth0/ifindex"), "2\n").unwrap();
        fs::write(stats.join("rx_dropped"), "12\n").unwrap();
        fs::write(stats.join("tx_errors"), "3\n").unwrap();

        let metrics = collect_link_stats(root.path(), Some("eth0")).unwrap();

        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].key.labels["interface"], "eth0");
        assert_eq!(metrics[0].key.labels["ifindex"], "2");
        assert!(metrics.iter().any(|sample| sample.value == 12));
    }

    #[test]
    fn reads_carrier_changes_from_the_interface_root() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(interface.join("statistics")).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();
        fs::write(interface.join("carrier_changes"), "7\n").unwrap();

        let metrics = collect_link_stats(root.path(), Some("eth0")).unwrap();
        let carrier_changes = metrics
            .iter()
            .find(|sample| sample.key.metric == "carrier_changes")
            .unwrap();

        assert_eq!(metrics.len(), 1);
        assert_eq!(carrier_changes.value, 7);
        assert_eq!(carrier_changes.key.labels["counter_bits"], "32");
        assert_eq!(carrier_changes.key.labels["interface"], "eth0");
        assert_eq!(carrier_changes.key.labels["ifindex"], "2");
    }

    #[test]
    fn rejects_path_traversal_interface() {
        let error = collect_link_stats(Path::new("/sys"), Some("../proc")).unwrap_err();
        assert!(error.to_string().contains("invalid interface"));
        assert_eq!(error.parse_errors(), 0);
    }

    #[test]
    fn counts_invalid_counter_as_a_parse_error() {
        let root = tempdir().unwrap();
        let stats = root.path().join("class/net/eth0/statistics");
        fs::create_dir_all(&stats).unwrap();
        fs::write(root.path().join("class/net/eth0/ifindex"), "2\n").unwrap();
        fs::write(stats.join("rx_dropped"), "not-a-counter\n").unwrap();

        let error = collect_link_stats(root.path(), Some("eth0")).unwrap_err();

        assert_eq!(error.parse_errors(), 1);
    }

    #[test]
    fn attaches_validated_ifindex_to_proc_fallback_rows() {
        let root = tempdir().unwrap();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "7\n").unwrap();
        let mut metrics = vec![MetricSample {
            key: MetricKey::new("proc_net_dev", "link", "rx_packets")
                .with_label("interface", "eth0"),
            value: 1,
        }];

        attach_interface_ifindices(root.path(), &mut metrics).unwrap();

        assert_eq!(metrics[0].key.labels["ifindex"], "7");
    }
}
