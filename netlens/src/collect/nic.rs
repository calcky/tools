use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

mod basic;
pub(crate) mod capabilities;
mod inventory;
mod ioctl;
mod netlink;

pub const ETHTOOL_TIMEOUT: Duration = Duration::from_secs(2);
pub const ETHTOOL_STDOUT_LIMIT: usize = 1024 * 1024;
pub const ETHTOOL_STDERR_LIMIT: usize = 64 * 1024;
pub const MAX_STATISTIC_NAME_LEN: usize = 128;

const IFNAMSIZ: usize = 16;
const SYSFS_VALUE_LIMIT: usize = 64;
const ERROR_DETAIL_LIMIT: usize = 256;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READER_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);
// Bounds simultaneous child processes and their fixed-size output captures.
const MAX_ETHTOOL_CONCURRENCY: usize = 4;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NicCollection {
    pub interfaces: Vec<NicInterface>,
    pub errors: Vec<NicCollectionError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NicInterface {
    pub interface: String,
    pub ifindex: u32,
    pub hardware_backed: bool,
    pub operstate: OperState,
    pub sysfs: NicSysfsInfo,
    pub channels: Vec<EthtoolSetting>,
    pub fallback_settings: Vec<EthtoolSetting>,
    pub settings: EthtoolSettingsOutcome,
    pub ethtool: EthtoolOutcome,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NicSysfsInfo {
    pub driver: Option<String>,
    pub rx_queue_count: Option<u32>,
    pub tx_queue_count: Option<u32>,
    pub tx_queue_len: Option<u32>,
    pub mtu: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EthtoolSettingsOutcome {
    NotHardwareInterface,
    RefreshPending,
    Collected(EthtoolSettings),
    Partial {
        settings: EthtoolSettings,
        rejected_lines: usize,
    },
    Failed(EthtoolFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperState {
    Up,
    Down,
    Unknown,
    Dormant,
    LowerLayerDown,
    NotPresent,
    Testing,
    Other(String),
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EthtoolOutcome {
    NotHardwareInterface,
    Collected(NicStatistics),
    Partial {
        statistics: NicStatistics,
        rejected_lines: usize,
        omitted_private: usize,
    },
    Failed(EthtoolFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EthtoolFailure {
    CommandNotFound,
    PermissionDenied { detail: String },
    Unsupported { detail: String },
    InterfaceUnavailable { detail: String },
    TimedOut,
    OutputTooLarge { stream: OutputStream },
    ExitFailure { code: Option<i32>, detail: String },
    InvalidOutput,
    Io { detail: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputStream {
    Stdout,
    Stderr,
    Both,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NicStatistics {
    pub standard: Vec<StandardNicStatistic>,
    pub private: Vec<PrivateNicStatistic>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EthtoolSettings {
    pub fields: Vec<EthtoolSetting>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthtoolSetting {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StandardNicStatistic {
    pub statistic: StandardStatistic,
    pub value: u64,
    pub semantics: NicStatisticSemantics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateNicStatistic {
    pub name: String,
    pub value: u64,
    pub semantics: NicStatisticSemantics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NicStatisticSemantics {
    OpaqueCurrentOnly,
}

// These are exact Linux rtnl_link_stats64 names used only as a display allowlist.
// ethtool -S exposes driver-defined fields, so allowlisted and private values both
// remain opaque current observations rather than inferred packet/drop counters.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StandardStatistic {
    RxPackets,
    TxPackets,
    RxBytes,
    TxBytes,
    RxErrors,
    TxErrors,
    RxDropped,
    TxDropped,
    Multicast,
    Collisions,
    RxLengthErrors,
    RxOverErrors,
    RxCrcErrors,
    RxFrameErrors,
    RxFifoErrors,
    RxMissedErrors,
    TxAbortedErrors,
    TxCarrierErrors,
    TxFifoErrors,
    TxHeartbeatErrors,
    TxWindowErrors,
    RxCompressed,
    TxCompressed,
    RxNohandler,
    RxOtherhostDropped,
}

impl StandardStatistic {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RxPackets => "rx_packets",
            Self::TxPackets => "tx_packets",
            Self::RxBytes => "rx_bytes",
            Self::TxBytes => "tx_bytes",
            Self::RxErrors => "rx_errors",
            Self::TxErrors => "tx_errors",
            Self::RxDropped => "rx_dropped",
            Self::TxDropped => "tx_dropped",
            Self::Multicast => "multicast",
            Self::Collisions => "collisions",
            Self::RxLengthErrors => "rx_length_errors",
            Self::RxOverErrors => "rx_over_errors",
            Self::RxCrcErrors => "rx_crc_errors",
            Self::RxFrameErrors => "rx_frame_errors",
            Self::RxFifoErrors => "rx_fifo_errors",
            Self::RxMissedErrors => "rx_missed_errors",
            Self::TxAbortedErrors => "tx_aborted_errors",
            Self::TxCarrierErrors => "tx_carrier_errors",
            Self::TxFifoErrors => "tx_fifo_errors",
            Self::TxHeartbeatErrors => "tx_heartbeat_errors",
            Self::TxWindowErrors => "tx_window_errors",
            Self::RxCompressed => "rx_compressed",
            Self::TxCompressed => "tx_compressed",
            Self::RxNohandler => "rx_nohandler",
            Self::RxOtherhostDropped => "rx_otherhost_dropped",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "rx_packets" => Self::RxPackets,
            "tx_packets" => Self::TxPackets,
            "rx_bytes" => Self::RxBytes,
            "tx_bytes" => Self::TxBytes,
            "rx_errors" => Self::RxErrors,
            "tx_errors" => Self::TxErrors,
            "rx_dropped" => Self::RxDropped,
            "tx_dropped" => Self::TxDropped,
            "multicast" => Self::Multicast,
            "collisions" => Self::Collisions,
            "rx_length_errors" => Self::RxLengthErrors,
            "rx_over_errors" => Self::RxOverErrors,
            "rx_crc_errors" => Self::RxCrcErrors,
            "rx_frame_errors" => Self::RxFrameErrors,
            "rx_fifo_errors" => Self::RxFifoErrors,
            "rx_missed_errors" => Self::RxMissedErrors,
            "tx_aborted_errors" => Self::TxAbortedErrors,
            "tx_carrier_errors" => Self::TxCarrierErrors,
            "tx_fifo_errors" => Self::TxFifoErrors,
            "tx_heartbeat_errors" => Self::TxHeartbeatErrors,
            "tx_window_errors" => Self::TxWindowErrors,
            "rx_compressed" => Self::RxCompressed,
            "tx_compressed" => Self::TxCompressed,
            "rx_nohandler" => Self::RxNohandler,
            "rx_otherhost_dropped" => Self::RxOtherhostDropped,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedEthtoolStats {
    pub statistics: NicStatistics,
    pub rejected_lines: usize,
    pub omitted_private: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedEthtoolSettings {
    pub settings: EthtoolSettings,
    pub rejected_lines: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NicCollectionErrorKind {
    DiscoverInterfaces,
    InvalidInterfaceName,
    ReadIfindex,
    ReadOperstate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NicCollectionError {
    pub interface: Option<String>,
    pub kind: NicCollectionErrorKind,
    pub detail: String,
}

#[derive(Debug, Default)]
pub(crate) struct NicCollector {
    sys_root: Option<std::path::PathBuf>,
    inventory: inventory::Context,
    statistics: ioctl::Context,
    settings: Mutex<Option<netlink::Context>>,
    basic_contexts: basic::ContextPool,
    basic_frontend: basic::Frontend,
    capabilities: Mutex<capabilities::Cache>,
}

impl NicCollector {
    pub(crate) fn collect_with_metadata(
        &mut self,
        sys_root: &Path,
        include_settings: bool,
        metadata: Option<super::rtnetlink::FreshLinkMetadata>,
    ) -> (NicCollection, Option<Instant>) {
        if self.sys_root.as_deref() != Some(sys_root) {
            *self = Self::default();
            self.sys_root = Some(sys_root.to_owned());
        }
        let (mut collection, metadata_started) = if sys_root == Path::new("/sys") {
            self.inventory
                .collect_with_metadata(sys_root, metadata)
                .unwrap_or_else(|_| (collect_inventory(sys_root), None))
        } else {
            (collect_inventory(sys_root), None)
        };
        self.statistics.retain(&collection.interfaces);
        self.capabilities
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .reconcile(capabilities::inventory(sys_root, &collection));
        for interface in &mut collection.interfaces {
            if !interface.hardware_backed {
                continue;
            }
            interface.settings = EthtoolSettingsOutcome::RefreshPending;
            if let Some(failure) = self
                .capabilities
                .get_mut()
                .unwrap_or_else(|error| error.into_inner())
                .get(&interface.interface, "-S", Instant::now())
            {
                interface.ethtool = EthtoolOutcome::Failed(failure);
                continue;
            }
            interface.ethtool = match self
                .statistics
                .statistics(&interface.interface, interface.ifindex)
            {
                Ok(statistics) => EthtoolOutcome::Collected(statistics),
                Err(_) => EthtoolOutcome::Failed(EthtoolFailure::InvalidOutput),
            };
        }
        probe_inventory(
            &mut collection,
            MAX_ETHTOOL_CONCURRENCY,
            |_| EthtoolSettingsOutcome::RefreshPending,
            |interface| {
                if let Some(failure) = self
                    .capabilities
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .get(interface, "-S", Instant::now())
                {
                    return EthtoolOutcome::Failed(failure);
                }
                let result = run_ethtool(
                    OsStr::new("ethtool"),
                    interface,
                    ETHTOOL_TIMEOUT,
                    ETHTOOL_STDOUT_LIMIT,
                    ETHTOOL_STDERR_LIMIT,
                );
                if let EthtoolOutcome::Failed(failure) = &result {
                    self.capabilities
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .record(interface, "-S", Instant::now(), failure);
                }
                result
            },
            true,
            |interface| {
                matches!(interface.ethtool, EthtoolOutcome::Failed(_))
                    && self
                        .cached_unsupported(&interface.interface, "-S")
                        .is_none()
            },
        );
        if include_settings {
            self.collect_configuration(sys_root, &mut collection);
        }
        (collection, metadata_started)
    }

    pub(crate) fn prepare_configuration(&mut self, sys_root: &Path, collection: &NicCollection) {
        self.capabilities
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .reconcile(capabilities::inventory(sys_root, collection));
    }

    pub(crate) fn configuration_inventory(
        &self,
    ) -> std::sync::Arc<std::collections::BTreeMap<String, capabilities::Identity>> {
        self.capabilities
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .snapshot()
    }

    pub(crate) fn cached_unsupported(
        &self,
        interface: &str,
        operation: &str,
    ) -> Option<EthtoolFailure> {
        self.capabilities
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(interface, operation, Instant::now())
    }

    pub(crate) fn collect_configuration(
        &mut self,
        sys_root: &Path,
        collection: &mut NicCollection,
    ) {
        if sys_root == Path::new("/sys") {
            for interface in &mut collection.interfaces {
                let cached = self
                    .cached_unsupported(&interface.interface, "channels")
                    .is_some();
                let result = if cached {
                    Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                } else {
                    self.statistics.channels(&interface.interface)
                };
                if !cached
                    && result
                        .as_ref()
                        .is_err_and(|error| error.raw_os_error() == Some(libc::EOPNOTSUPP))
                {
                    self.capabilities
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .record(
                            &interface.interface,
                            "channels",
                            Instant::now(),
                            &EthtoolFailure::Unsupported {
                                detail: "Operation not supported".into(),
                            },
                        );
                }
                interface.channels = channel_settings(result);
            }
        }
        let settings = self
            .settings
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        if settings.is_none() && sys_root == Path::new("/sys") {
            *settings = netlink::Context::new().ok();
        }
        let basic_program = if settings.is_some() {
            collection
                .interfaces
                .iter()
                .find(|interface| interface.hardware_backed)
                .and_then(|interface| self.basic_frontend.prepare(&interface.interface))
        } else {
            None
        };
        let identities: std::collections::BTreeMap<_, _> = if basic_program.is_some() {
            collection
                .interfaces
                .iter()
                .map(|interface| (interface.interface.clone(), interface.ifindex))
                .collect()
        } else {
            Default::default()
        };
        probe_inventory(
            collection,
            MAX_ETHTOOL_CONCURRENCY,
            |interface| {
                run_ethtool_settings_cached(
                    OsStr::new("ethtool"),
                    interface,
                    ETHTOOL_TIMEOUT,
                    ETHTOOL_STDOUT_LIMIT,
                    ETHTOOL_STDERR_LIMIT,
                    (
                        || {
                            let deadline = Instant::now() + basic::ATTEMPT_TIMEOUT;
                            let executable = basic_program.as_ref()?;
                            if !executable.current() {
                                return None;
                            }
                            let parsed = self
                                .basic_contexts
                                .settings_until(interface, identities[interface], deadline)
                                .ok()?;
                            (executable.current() && Instant::now() < deadline).then_some(parsed)
                        },
                        |operation| {
                            let result = self
                                .settings
                                .lock()
                                .unwrap_or_else(|error| error.into_inner())
                                .as_mut()?
                                .settings(interface, operation);
                            match result {
                                Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                                    self.capabilities
                                        .lock()
                                        .unwrap_or_else(|error| error.into_inner())
                                        .record(
                                            interface,
                                            operation,
                                            Instant::now(),
                                            &EthtoolFailure::Unsupported {
                                                detail: "Operation not supported".into(),
                                            },
                                        );
                                    Some(Vec::new())
                                }
                                result => result.ok(),
                            }
                        },
                    ),
                    Some(&self.capabilities),
                )
            },
            |_| EthtoolOutcome::NotHardwareInterface,
            false,
            |_| true,
        );
        for interface in &mut collection.interfaces {
            let path = sys_root.join("class/net").join(&interface.interface);
            interface.fallback_settings = collect_fallback_settings(&path);
            if sys_root == Path::new("/sys")
                && self
                    .cached_unsupported(&interface.interface, "ring-fallback")
                    .is_none()
                && (!has_setting(&interface.settings, "Ring RX")
                    || !has_setting(&interface.settings, "Ring TX"))
            {
                match self.statistics.settings(&interface.interface, "-g") {
                    Ok(fields) => {
                        interface
                            .fallback_settings
                            .extend(fields.into_iter().map(|field| EthtoolSetting {
                                name: format!("Fallback {}", field.name),
                                value: field.value,
                            }))
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                        self.capabilities
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .record(
                                &interface.interface,
                                "ring-fallback",
                                Instant::now(),
                                &EthtoolFailure::Unsupported {
                                    detail: "Operation not supported".into(),
                                },
                            );
                    }
                    Err(_) => (),
                }
            }
        }
    }
}

fn channel_settings(result: io::Result<(u32, u32)>) -> Vec<EthtoolSetting> {
    let mut fields = Vec::new();
    let source = match result {
        Ok((rx, tx)) => {
            for (name, value) in [("Channel RX", rx), ("Channel TX", tx)] {
                fields.push(EthtoolSetting {
                    name: name.to_owned(),
                    value: value.to_string(),
                });
            }
            "ethtool"
        }
        Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => "fixed",
        Err(_) => "sysfs",
    };
    fields.push(EthtoolSetting {
        name: "Queue source".to_owned(),
        value: source.to_owned(),
    });
    fields
}

pub fn parse_ethtool_stats(input: &[u8]) -> ParsedEthtoolStats {
    let mut parsed = ParsedEthtoolStats::default();
    let mut seen_names = BTreeSet::new();
    let mut saw_header = false;

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = trim_spaces(raw_line);
        if line.is_empty() {
            continue;
        }
        if !line.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }
        if line == b"NIC statistics:" {
            if saw_header || !seen_names.is_empty() {
                parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            } else {
                saw_header = true;
            }
            continue;
        }
        if line.iter().filter(|byte| **byte == b':').count() != 1 {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }
        let delimiter = line
            .iter()
            .position(|byte| *byte == b':')
            .expect("the delimiter count was checked");
        let name = trim_spaces(&line[..delimiter]);
        let value = trim_spaces(&line[delimiter + 1..]);
        if !valid_statistic_name(name) || value.is_empty() || !value.iter().all(u8::is_ascii_digit)
        {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }
        let name = String::from_utf8(name.to_vec()).expect("validated ASCII statistic name");
        let value = match std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
        {
            Some(value) => value,
            None => {
                parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
                continue;
            }
        };
        if seen_names.contains(&name) {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }

        if let Some(statistic) = StandardStatistic::from_name(&name) {
            seen_names.insert(name);
            parsed.statistics.standard.push(StandardNicStatistic {
                statistic,
                value,
                semantics: NicStatisticSemantics::OpaqueCurrentOnly,
            });
        } else {
            seen_names.insert(name.clone());
            parsed.statistics.private.push(PrivateNicStatistic {
                name,
                value,
                semantics: NicStatisticSemantics::OpaqueCurrentOnly,
            });
        }
    }

    parsed
        .statistics
        .standard
        .sort_by_key(|statistic| statistic.statistic);
    parsed
        .statistics
        .private
        .sort_by(|left, right| left.name.cmp(&right.name));
    parsed
}

pub fn parse_ethtool_settings(input: &[u8]) -> ParsedEthtoolSettings {
    let mut parsed = ParsedEthtoolSettings::default();
    let mut saw_header = false;
    let mut previous_name: Option<String> = None;
    let mut name_counts = std::collections::BTreeMap::<String, usize>::new();

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(line) = normalize_ascii_whitespace(raw_line) else {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        };
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Settings for ") && line.ends_with(':') {
            if saw_header {
                parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            }
            saw_header = true;
            previous_name = None;
            continue;
        }
        if !saw_header {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }

        let (base_name, value) = match line.split_once(':') {
            Some((name, value))
                if valid_setting_text(name.trim()) && valid_setting_text(value.trim()) =>
            {
                let name = name.trim();
                let value = value.trim();
                previous_name = Some(name.to_owned());
                (name.to_owned(), value.to_owned())
            }
            None if previous_name.is_some() && valid_setting_text(&line) => (
                previous_name
                    .as_ref()
                    .expect("continuation has a preceding setting")
                    .clone(),
                line,
            ),
            _ => {
                parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
                continue;
            }
        };

        let count = name_counts.entry(base_name.clone()).or_default();
        *count = count.saturating_add(1);
        let name = if *count == 1 {
            base_name
        } else {
            format!("{base_name} [{}]", *count)
        };
        if name.len() > MAX_STATISTIC_NAME_LEN {
            parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
            continue;
        }
        parsed.settings.fields.push(EthtoolSetting { name, value });
    }

    if !saw_header {
        parsed.rejected_lines = parsed.rejected_lines.saturating_add(1);
    }
    parsed
}

fn parse_ethtool_ring_settings(input: &[u8]) -> Vec<EthtoolSetting> {
    let mut in_maximum_settings = false;
    let mut in_current_settings = false;
    let mut rx_max = None;
    let mut tx_max = None;
    let mut rx = None;
    let mut tx = None;

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(line) = normalize_ascii_whitespace(raw_line) else {
            continue;
        };
        if line == "Current hardware settings:" {
            in_maximum_settings = false;
            in_current_settings = true;
            continue;
        }
        if line == "Pre-set maximums:" {
            in_maximum_settings = true;
            in_current_settings = false;
            continue;
        }
        if in_current_settings {
            if rx.is_none() {
                rx = parse_exact_unsigned_field(&line, "RX");
            }
            if tx.is_none() {
                tx = parse_exact_unsigned_field(&line, "TX");
            }
        } else if in_maximum_settings {
            if rx_max.is_none() {
                rx_max = parse_exact_unsigned_field(&line, "RX");
            }
            if tx_max.is_none() {
                tx_max = parse_exact_unsigned_field(&line, "TX");
            }
        }
    }

    optional_settings([
        ("Ring RX", rx),
        ("Ring TX", tx),
        ("Ring RX Max", rx_max),
        ("Ring TX Max", tx_max),
    ])
}

fn parse_ethtool_pause_settings(input: &[u8]) -> Vec<EthtoolSetting> {
    let mut rx = None;
    let mut tx = None;

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(line) = normalize_ascii_whitespace(raw_line) else {
            continue;
        };
        if rx.is_none() {
            rx = parse_exact_switch_field(&line, "RX", false);
        }
        if tx.is_none() {
            tx = parse_exact_switch_field(&line, "TX", false);
        }
    }

    optional_settings([("Flow Control RX", rx), ("Flow Control TX", tx)])
}

fn parse_ethtool_feature_settings(input: &[u8]) -> Vec<EthtoolSetting> {
    const FEATURES: [(&str, &str); 4] = [
        ("TSO", "tcp-segmentation-offload"),
        ("LRO", "large-receive-offload"),
        ("GRO", "generic-receive-offload"),
        ("GSO", "generic-segmentation-offload"),
    ];
    let mut values: [Option<String>; FEATURES.len()] = std::array::from_fn(|_| None);

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(line) = normalize_ascii_whitespace(raw_line) else {
            continue;
        };
        for (index, (_, key)) in FEATURES.iter().enumerate() {
            if values[index].is_none() {
                values[index] = parse_exact_switch_field(&line, key, true).map(|value| {
                    if line.ends_with("[fixed]") {
                        format!("{value} [fixed]")
                    } else {
                        value
                    }
                });
            }
        }
    }

    FEATURES
        .into_iter()
        .zip(values)
        .filter_map(|((name, _), value)| {
            value.map(|value| EthtoolSetting {
                name: name.to_owned(),
                value,
            })
        })
        .collect()
}

fn parse_ethtool_coalesce_settings(input: &[u8]) -> Vec<EthtoolSetting> {
    let mut adaptive_rx = None;
    let mut adaptive_tx = None;
    let mut rx_usecs = None;
    let mut rx_frames = None;
    let mut tx_usecs = None;
    let mut tx_frames = None;

    for raw_line in input.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(line) = normalize_ascii_whitespace(raw_line) else {
            continue;
        };
        if adaptive_rx.is_none() || adaptive_tx.is_none() {
            if let Some((rx, tx)) = parse_adaptive_coalesce_fields(&line) {
                adaptive_rx = adaptive_rx.or(rx);
                adaptive_tx = adaptive_tx.or(tx);
            }
        }
        if adaptive_rx.is_none() {
            adaptive_rx = parse_exact_switch_field(&line, "Adaptive RX", false);
        }
        if adaptive_tx.is_none() {
            adaptive_tx = parse_exact_switch_field(&line, "Adaptive TX", false);
        }
        if rx_usecs.is_none() {
            rx_usecs = parse_exact_unsigned_field(&line, "rx-usecs");
        }
        if rx_frames.is_none() {
            rx_frames = parse_exact_unsigned_field(&line, "rx-frames");
        }
        if tx_usecs.is_none() {
            tx_usecs = parse_exact_unsigned_field(&line, "tx-usecs");
        }
        if tx_frames.is_none() {
            tx_frames = parse_exact_unsigned_field(&line, "tx-frames");
        }
    }

    optional_settings([
        ("Adaptive RX", adaptive_rx),
        ("Adaptive TX", adaptive_tx),
        ("RX Usecs", rx_usecs),
        ("RX Frames", rx_frames),
        ("TX Usecs", tx_usecs),
        ("TX Frames", tx_frames),
    ])
}

fn parse_adaptive_coalesce_fields(line: &str) -> Option<(Option<String>, Option<String>)> {
    let values = line.strip_prefix("Adaptive RX:")?.trim();
    let (rx, tx) = values.split_once(" TX:")?;
    Some((parse_switch_value(rx), parse_switch_value(tx)))
}

fn parse_exact_unsigned_field(line: &str, expected_name: &str) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    let value = value.trim();
    if name.trim() != expected_name
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().is_err()
    {
        return None;
    }
    Some(value.to_owned())
}

fn parse_exact_switch_field(line: &str, expected_name: &str, allow_fixed: bool) -> Option<String> {
    let (name, value) = line.split_once(':')?;
    if name.trim() != expected_name {
        return None;
    }
    match (value.trim(), allow_fixed) {
        ("on", _) | ("on [fixed]", true) => Some("on".to_owned()),
        ("off", _) | ("off [fixed]", true) => Some("off".to_owned()),
        _ => None,
    }
}

fn parse_switch_value(value: &str) -> Option<String> {
    match value.trim() {
        "on" => Some("on".to_owned()),
        "off" => Some("off".to_owned()),
        _ => None,
    }
}

fn optional_settings<const N: usize>(settings: [(&str, Option<String>); N]) -> Vec<EthtoolSetting> {
    settings
        .into_iter()
        .filter_map(|(name, value)| {
            value.map(|value| EthtoolSetting {
                name: name.to_owned(),
                value,
            })
        })
        .collect()
}

fn normalize_ascii_whitespace(input: &[u8]) -> Option<String> {
    if !input.is_ascii()
        || input
            .iter()
            .any(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(
        input
            .split(u8::is_ascii_whitespace)
            .filter(|part| !part.is_empty())
            .map(|part| std::str::from_utf8(part).expect("ASCII chunks are UTF-8"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn valid_setting_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STATISTIC_NAME_LEN
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

#[cfg(test)]
fn collect_with<F>(sys_root: &Path, mut ethtool: F) -> NicCollection
where
    F: FnMut(&str) -> EthtoolOutcome,
{
    let mut collection = collect_inventory(sys_root);
    for interface in &mut collection.interfaces {
        if interface.hardware_backed {
            interface.ethtool = ethtool(&interface.interface);
        }
    }
    collection
}

#[cfg(test)]
fn collect_parallel_with<F>(sys_root: &Path, max_concurrency: usize, ethtool: F) -> NicCollection
where
    F: Fn(&str) -> EthtoolOutcome + Sync,
{
    collect_parallel_with_probes(
        sys_root,
        max_concurrency,
        |_| EthtoolSettingsOutcome::Collected(EthtoolSettings::default()),
        ethtool,
    )
}

#[cfg(test)]
fn collect_parallel_with_probes<S, F>(
    sys_root: &Path,
    max_concurrency: usize,
    settings_probe: S,
    statistics_probe: F,
) -> NicCollection
where
    S: Fn(&str) -> EthtoolSettingsOutcome + Sync,
    F: Fn(&str) -> EthtoolOutcome + Sync,
{
    let mut collection = collect_inventory(sys_root);
    probe_inventory(
        &mut collection,
        max_concurrency,
        settings_probe,
        statistics_probe,
        true,
        |_| true,
    );
    collection
}

fn probe_inventory<S, F>(
    collection: &mut NicCollection,
    max_concurrency: usize,
    settings_probe: S,
    statistics_probe: F,
    include_statistics: bool,
    selected: impl Fn(&NicInterface) -> bool,
) where
    S: Fn(&str) -> EthtoolSettingsOutcome + Sync,
    F: Fn(&str) -> EthtoolOutcome + Sync,
{
    let jobs = collection
        .interfaces
        .iter()
        .enumerate()
        .filter(|(_, interface)| interface.hardware_backed && selected(interface))
        .map(|(index, interface)| (index, interface.interface.clone()))
        .collect::<Vec<_>>();
    if jobs.is_empty() {
        return;
    }

    let worker_count = max_concurrency.max(1).min(jobs.len());
    let next_job = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(jobs.len()));
    thread::scope(|scope| {
        for _ in 0..worker_count {
            let jobs = &jobs;
            let next_job = &next_job;
            let results = &results;
            let settings_probe = &settings_probe;
            let statistics_probe = &statistics_probe;
            scope.spawn(move || loop {
                let job = next_job.fetch_add(1, Ordering::Relaxed);
                let Some((interface_index, interface)) = jobs.get(job) else {
                    break;
                };
                let outcome = (settings_probe(interface), statistics_probe(interface));
                results
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((*interface_index, outcome));
            });
        }
    });

    for (interface_index, (settings, statistics)) in results
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    {
        collection.interfaces[interface_index].settings = settings;
        if include_statistics {
            collection.interfaces[interface_index].ethtool = statistics;
        }
    }
}

fn collect_inventory(sys_root: &Path) -> NicCollection {
    let mut collection = NicCollection::default();
    let net_root = sys_root.join("class/net");
    let entries = match std::fs::read_dir(&net_root) {
        Ok(entries) => entries,
        Err(error) => {
            collection.errors.push(NicCollectionError {
                interface: None,
                kind: NicCollectionErrorKind::DiscoverInterfaces,
                detail: format!("{}: cannot list interfaces: {error}", net_root.display()),
            });
            return collection;
        }
    };

    for entry in entries {
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
        let interface = match entry.file_name().into_string() {
            Ok(interface) if valid_interface_name(&interface) => interface,
            _ => {
                collection.errors.push(NicCollectionError {
                    interface: None,
                    kind: NicCollectionErrorKind::InvalidInterfaceName,
                    detail: "ignored a sysfs interface entry with an invalid name".to_owned(),
                });
                continue;
            }
        };
        let hardware_backed = entry.path().join("device").exists();
        let ifindex = match read_ifindex(&entry.path()) {
            Ok(ifindex) => ifindex,
            Err(detail) => {
                collection.errors.push(NicCollectionError {
                    interface: Some(interface),
                    kind: NicCollectionErrorKind::ReadIfindex,
                    detail,
                });
                continue;
            }
        };
        let operstate = match read_operstate(&entry.path()) {
            Ok(operstate) => operstate,
            Err(detail) => {
                collection.errors.push(NicCollectionError {
                    interface: Some(interface.clone()),
                    kind: NicCollectionErrorKind::ReadOperstate,
                    detail,
                });
                OperState::Unavailable
            }
        };
        let sysfs = collect_sysfs_info(&entry.path());
        collection.interfaces.push(NicInterface {
            interface,
            ifindex,
            hardware_backed,
            operstate,
            sysfs,
            channels: Vec::new(),
            fallback_settings: Vec::new(),
            settings: EthtoolSettingsOutcome::NotHardwareInterface,
            ethtool: EthtoolOutcome::NotHardwareInterface,
        });
    }

    collection.interfaces.sort_by(|left, right| {
        left.ifindex
            .cmp(&right.ifindex)
            .then_with(|| left.interface.cmp(&right.interface))
    });
    collection
}

fn collect_sysfs_info(interface_path: &Path) -> NicSysfsInfo {
    let queues = count_queues(interface_path);
    NicSysfsInfo {
        driver: read_driver_name(interface_path),
        rx_queue_count: queues.map(|(rx, _)| rx),
        tx_queue_count: queues.map(|(_, tx)| tx),
        tx_queue_len: read_optional_u32(&interface_path.join("tx_queue_len")),
        mtu: read_optional_u32(&interface_path.join("mtu")),
    }
}

fn read_driver_name(interface_path: &Path) -> Option<String> {
    if let Ok(target) = std::fs::read_link(interface_path.join("device/driver")) {
        let driver = target.file_name()?.to_str()?;
        return valid_setting_text(driver).then(|| driver.to_owned());
    }
    let bytes = read_bounded(&interface_path.join("device/uevent"), 4096).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let driver = text.lines().find_map(|line| line.strip_prefix("DRIVER="))?;
    valid_setting_text(driver).then(|| driver.to_owned())
}

fn has_setting(outcome: &EthtoolSettingsOutcome, name: &str) -> bool {
    match outcome {
        EthtoolSettingsOutcome::Collected(settings)
        | EthtoolSettingsOutcome::Partial { settings, .. } => {
            settings.fields.iter().any(|field| field.name == name)
        }
        _ => false,
    }
}

fn collect_fallback_settings(path: &Path) -> Vec<EthtoolSetting> {
    let mut fields = Vec::new();
    if let Some(driver) = read_driver_name(path) {
        fields.push(EthtoolSetting {
            name: "Sysfs Driver".to_owned(),
            value: driver,
        });
    }
    if let Some(speed) =
        read_optional_u32(&path.join("speed")).filter(|&speed| speed > 0 && speed != u32::MAX)
    {
        fields.push(EthtoolSetting {
            name: "Sysfs Speed".to_owned(),
            value: format!("{speed}Mb/s"),
        });
    }
    if let Ok(bytes) = read_bounded(&path.join("duplex"), SYSFS_VALUE_LIMIT) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let duplex = match text.trim() {
                "full" => Some("Full"),
                "half" => Some("Half"),
                _ => None,
            };
            if let Some(duplex) = duplex {
                fields.push(EthtoolSetting {
                    name: "Sysfs Duplex".to_owned(),
                    value: duplex.to_owned(),
                });
            }
        }
    }
    if let Some(carrier) = read_optional_u32(&path.join("carrier")).filter(|&value| value <= 1) {
        fields.push(EthtoolSetting {
            name: "Sysfs Link detected".to_owned(),
            value: if carrier == 1 { "yes" } else { "no" }.to_owned(),
        });
    }
    fields
}

fn count_queues(interface_path: &Path) -> Option<(u32, u32)> {
    let entries = std::fs::read_dir(interface_path.join("queues")).ok()?;
    let mut rx = 0_u32;
    let mut tx = 0_u32;
    for entry in entries {
        let entry = entry.ok()?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let (index, count) = match name.strip_prefix("rx-") {
            Some(index) => (index, &mut rx),
            None => match name.strip_prefix("tx-") {
                Some(index) => (index, &mut tx),
                None => continue,
            },
        };
        if index.is_empty()
            || !index.bytes().all(|byte| byte.is_ascii_digit())
            || index.parse::<u32>().is_err()
        {
            continue;
        }
        *count = count.checked_add(1)?;
    }
    Some((rx, tx))
}

fn read_optional_u32(path: &Path) -> Option<u32> {
    let raw = read_bounded(path, SYSFS_VALUE_LIMIT).ok()?;
    std::str::from_utf8(&raw).ok()?.trim().parse::<u32>().ok()
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < IFNAMSIZ
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'/')
}

fn read_ifindex(interface_path: &Path) -> Result<u32, String> {
    let path = interface_path.join("ifindex");
    let raw = read_bounded(&path, SYSFS_VALUE_LIMIT)
        .map_err(|error| format!("{}: cannot read interface index: {error}", path.display()))?;
    let value = std::str::from_utf8(&raw)
        .ok()
        .map(str::trim)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{} is not a non-zero interface index", path.display()))?;
    Ok(value)
}

fn read_operstate(interface_path: &Path) -> Result<OperState, String> {
    let path = interface_path.join("operstate");
    let raw = read_bounded(&path, SYSFS_VALUE_LIMIT)
        .map_err(|error| format!("{}: cannot read operstate: {error}", path.display()))?;
    let value = std::str::from_utf8(&raw)
        .map(str::trim)
        .map_err(|_| format!("{} contains a non-ASCII operstate", path.display()))?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("{} contains an invalid operstate", path.display()));
    }
    Ok(match value {
        "up" => OperState::Up,
        "down" => OperState::Down,
        "unknown" => OperState::Unknown,
        "dormant" => OperState::Dormant,
        "lowerlayerdown" => OperState::LowerLayerDown,
        "notpresent" => OperState::NotPresent,
        "testing" => OperState::Testing,
        other => OperState::Other(other.to_owned()),
    })
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(64));
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("value exceeds {limit} bytes"),
        ));
    }
    Ok(bytes)
}

fn run_ethtool(
    program: &OsStr,
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> EthtoolOutcome {
    run_ethtool_with_prefix(program, &[], interface, timeout, stdout_limit, stderr_limit)
}

#[cfg(test)]
fn run_ethtool_settings(
    program: &OsStr,
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> EthtoolSettingsOutcome {
    run_ethtool_settings_with(
        program,
        interface,
        timeout,
        stdout_limit,
        stderr_limit,
        |_| None,
    )
}

#[cfg(test)]
fn run_ethtool_settings_with(
    program: &OsStr,
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    native: impl FnMut(&str) -> Option<Vec<EthtoolSetting>>,
) -> EthtoolSettingsOutcome {
    run_ethtool_settings_with_base(
        program,
        interface,
        timeout,
        stdout_limit,
        stderr_limit,
        || None,
        native,
    )
}

#[cfg(test)]
fn run_ethtool_settings_with_base(
    program: &OsStr,
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    native_base: impl FnOnce() -> Option<ParsedEthtoolSettings>,
    native: impl FnMut(&str) -> Option<Vec<EthtoolSetting>>,
) -> EthtoolSettingsOutcome {
    run_ethtool_settings_cached(
        program,
        interface,
        timeout,
        stdout_limit,
        stderr_limit,
        (native_base, native),
        None,
    )
}

fn run_ethtool_settings_cached(
    program: &OsStr,
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
    native: (
        impl FnOnce() -> Option<ParsedEthtoolSettings>,
        impl FnMut(&str) -> Option<Vec<EthtoolSetting>>,
    ),
    cache: Option<&Mutex<capabilities::Cache>>,
) -> EthtoolSettingsOutcome {
    let (native_base, mut native) = native;
    let cached = |operation| {
        cache.and_then(|cache| {
            cache.lock().unwrap_or_else(|error| error.into_inner()).get(
                interface,
                operation,
                Instant::now(),
            )
        })
    };
    let record = |operation, failure: &EthtoolFailure| {
        if let Some(cache) = cache {
            cache
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .record(interface, operation, Instant::now(), failure);
        }
    };
    if let Some(failure) = cached("basic") {
        return EthtoolSettingsOutcome::Failed(failure);
    }
    let started = Instant::now();
    let native_result = native_base();
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return EthtoolSettingsOutcome::Failed(EthtoolFailure::TimedOut);
    }
    let parsed = match native_result {
        Some(parsed) => parsed,
        None => {
            let output = match capture_ethtool(
                program,
                &[],
                &[],
                interface,
                remaining,
                stdout_limit,
                stderr_limit,
            ) {
                Ok(output) => output,
                Err(error) => {
                    record("basic", &error);
                    return EthtoolSettingsOutcome::Failed(error);
                }
            };
            parse_ethtool_settings(&output)
        }
    };
    if parsed.settings.fields.is_empty() {
        return EthtoolSettingsOutcome::Failed(EthtoolFailure::InvalidOutput);
    }
    let mut settings = parsed.settings;
    for (arguments, parser) in [
        (
            [OsStr::new("-g")],
            parse_ethtool_ring_settings as fn(&[u8]) -> Vec<EthtoolSetting>,
        ),
        ([OsStr::new("-a")], parse_ethtool_pause_settings),
        ([OsStr::new("-k")], parse_ethtool_feature_settings),
        ([OsStr::new("-c")], parse_ethtool_coalesce_settings),
    ] {
        let operation = arguments[0].to_str().expect("static argument");
        if cached(operation).is_some() {
            continue;
        }
        if let Some(fields) = native(arguments[0].to_str().expect("static argument")) {
            settings.fields.extend(fields);
            continue;
        }
        match capture_ethtool(
            program,
            &[],
            &arguments,
            interface,
            timeout,
            stdout_limit,
            stderr_limit,
        ) {
            Ok(output) => settings.fields.extend(parser(&output)),
            Err(error) => record(operation, &error),
        }
    }
    if parsed.rejected_lines == 0 {
        EthtoolSettingsOutcome::Collected(settings)
    } else {
        EthtoolSettingsOutcome::Partial {
            settings,
            rejected_lines: parsed.rejected_lines,
        }
    }
}

fn run_ethtool_with_prefix(
    program: &OsStr,
    prefix_arguments: &[&OsStr],
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> EthtoolOutcome {
    let output = match capture_ethtool(
        program,
        prefix_arguments,
        &[OsStr::new("-S")],
        interface,
        timeout,
        stdout_limit,
        stderr_limit,
    ) {
        Ok(output) => output,
        Err(error) => return EthtoolOutcome::Failed(error),
    };
    let parsed = parse_ethtool_stats(&output);
    if parsed.statistics.standard.is_empty() && parsed.statistics.private.is_empty() {
        return EthtoolOutcome::Failed(EthtoolFailure::InvalidOutput);
    }
    if parsed.rejected_lines != 0 || parsed.omitted_private != 0 {
        EthtoolOutcome::Partial {
            statistics: parsed.statistics,
            rejected_lines: parsed.rejected_lines,
            omitted_private: parsed.omitted_private,
        }
    } else {
        EthtoolOutcome::Collected(parsed.statistics)
    }
}

fn capture_ethtool(
    program: &OsStr,
    prefix_arguments: &[&OsStr],
    operation_arguments: &[&OsStr],
    interface: &str,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Vec<u8>, EthtoolFailure> {
    let mut command = Command::new(program);
    command
        .args(prefix_arguments)
        .args(operation_arguments)
        .arg(interface);
    capture_command(command, timeout, stdout_limit, stderr_limit)
}

fn capture_command(
    mut command: Command,
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<Vec<u8>, EthtoolFailure> {
    let mut child = match command
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(EthtoolFailure::CommandNotFound)
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Err(EthtoolFailure::PermissionDenied {
                detail: sanitize_detail(error.to_string().as_bytes()),
            })
        }
        Err(error) => {
            return Err(EthtoolFailure::Io {
                detail: sanitize_detail(error.to_string().as_bytes()),
            })
        }
    };

    let mut stdout_pipe = child.stdout.take().expect("stdout was configured as piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr was configured as piped");
    let result = capture_pipes(
        &mut child,
        &mut stdout_pipe,
        &mut stderr_pipe,
        timeout,
        stdout_limit,
        stderr_limit,
    );
    // Also terminate descendants after normal exit, including pipe holders.
    terminate(&mut child);
    let (status, stdout, stderr) = result?;
    if stdout.truncated || stderr.truncated {
        let stream = match (stdout.truncated, stderr.truncated) {
            (true, true) => OutputStream::Both,
            (true, false) => OutputStream::Stdout,
            (false, true) => OutputStream::Stderr,
            (false, false) => unreachable!("checked at least one truncated stream"),
        };
        return Err(EthtoolFailure::OutputTooLarge { stream });
    }

    let status = status.expect("non-truncated capture has an exit status");
    if !status.success() {
        return Err(classify_exit_failure(status, &stderr.bytes));
    }
    Ok(stdout.bytes)
}

fn classify_exit_failure(status: ExitStatus, stderr: &[u8]) -> EthtoolFailure {
    let detail = sanitize_detail(stderr);
    let lowercase = detail.to_ascii_lowercase();
    if ["operation not permitted", "permission denied"]
        .iter()
        .any(|phrase| lowercase.contains(phrase))
    {
        EthtoolFailure::PermissionDenied { detail }
    } else if [
        "operation not supported",
        "not supported",
        "no stats available",
        "no statistics available",
        "cannot get stats",
        "cannot get device statistics",
    ]
    .iter()
    .any(|phrase| lowercase.contains(phrase))
    {
        EthtoolFailure::Unsupported { detail }
    } else if ["no such device", "device not found", "cannot find device"]
        .iter()
        .any(|phrase| lowercase.contains(phrase))
    {
        EthtoolFailure::InterfaceUnavailable { detail }
    } else {
        EthtoolFailure::ExitFailure {
            code: status.code(),
            detail,
        }
    }
}

struct LimitedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

fn capture_pipes(
    child: &mut Child,
    stdout: &mut (impl Read + AsRawFd),
    stderr: &mut (impl Read + AsRawFd),
    timeout: Duration,
    stdout_limit: usize,
    stderr_limit: usize,
) -> Result<(Option<ExitStatus>, LimitedBytes, LimitedBytes), EthtoolFailure> {
    let io_failure = |error: io::Error| EthtoolFailure::Io {
        detail: sanitize_detail(error.to_string().as_bytes()),
    };
    set_nonblocking(stdout).map_err(io_failure)?;
    set_nonblocking(stderr).map_err(io_failure)?;
    let mut output = LimitedBytes {
        bytes: Vec::with_capacity(stdout_limit.min(8192)),
        truncated: false,
    };
    let mut errors = LimitedBytes {
        bytes: Vec::with_capacity(stderr_limit.min(8192)),
        truncated: false,
    };
    let mut pipes = [
        libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let started = Instant::now();
    let mut status = None;
    let mut exited_at = None;
    loop {
        let previous_size = output.bytes.len() + errors.bytes.len();
        // Bound each drain so a continuously writable child cannot starve the
        // other stream or postpone timeout/exit checks.
        if drain_pipe(stdout, &mut output, stdout_limit).map_err(io_failure)? {
            pipes[0].fd = -1;
        }
        if drain_pipe(stderr, &mut errors, stderr_limit).map_err(io_failure)? {
            pipes[1].fd = -1;
        }
        if output.truncated || errors.truncated {
            return Ok((status, output, errors));
        }
        if status.is_none() {
            status = child.try_wait().map_err(io_failure)?;
            if status.is_some() {
                exited_at = Some(Instant::now());
                terminate(child);
                continue;
            }
        }
        if let Some(exited_at) = exited_at {
            // After exit, drain buffered bytes without waiting for detached
            // descendants to close their inherited pipes.
            if pipes[0].fd == -1 && pipes[1].fd == -1 {
                return Ok((status, output, errors));
            }
            if exited_at.elapsed() >= READER_DRAIN_TIMEOUT {
                return Err(io_failure(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ethtool output did not drain after process exit",
                )));
            }
            if output.bytes.len() + errors.bytes.len() == previous_size {
                return Ok((status, output, errors));
            }
            continue;
        } else if started.elapsed() >= timeout {
            return Err(EthtoolFailure::TimedOut);
        }
        let remaining = timeout.saturating_sub(started.elapsed()).min(POLL_INTERVAL);
        // SAFETY: the poll array contains two borrowed pipe descriptors.
        let ready = unsafe {
            libc::poll(
                pipes.as_mut_ptr(),
                pipes.len() as libc::nfds_t,
                remaining.as_millis().max(1) as i32,
            )
        };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(io_failure(error));
            }
        }
    }
}

fn drain_pipe(
    reader: &mut impl Read,
    capture: &mut LimitedBytes,
    limit: usize,
) -> io::Result<bool> {
    let mut buffer = [0; 8192];
    for _ in 0..8 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                let retained = count.min(limit.saturating_sub(capture.bytes.len()));
                capture.bytes.extend_from_slice(&buffer[..retained]);
                if retained != count {
                    capture.truncated = true;
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn terminate(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // SAFETY: kill does not dereference pointers; process_group(0) made the
        // validated child PID the process-group ID targeted by the negative value.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn set_nonblocking(reader: &impl AsRawFd) -> io::Result<()> {
    let file_descriptor = reader.as_raw_fd();
    // SAFETY: fcntl operates on the borrowed valid pipe descriptor and does not
    // retain pointers or ownership beyond either call.
    let flags = unsafe { libc::fcntl(file_descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0 {
        let result =
            unsafe { libc::fcntl(file_descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn trim_spaces(mut value: &[u8]) -> &[u8] {
    while value.first() == Some(&b' ') {
        value = &value[1..];
    }
    while value.last() == Some(&b' ') {
        value = &value[..value.len() - 1];
    }
    value
}

fn valid_statistic_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_STATISTIC_NAME_LEN
        && name
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte) && *byte != b':')
}

fn sanitize_detail(input: &[u8]) -> String {
    let mut output = String::new();
    let mut previous_space = false;
    for byte in input.iter().copied() {
        let character = if (0x20..=0x7e).contains(&byte) {
            byte as char
        } else {
            ' '
        };
        if character == ' ' {
            if previous_space || output.is_empty() {
                continue;
            }
            previous_space = true;
        } else {
            previous_space = false;
        }
        output.push(character);
        if output.len() >= ERROR_DETAIL_LIMIT {
            break;
        }
    }
    output.trim_end().to_owned()
}

impl fmt::Display for EthtoolFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandNotFound => formatter.write_str("ethtool command not found"),
            Self::PermissionDenied { detail } => {
                write!(formatter, "cannot execute ethtool: {detail}")
            }
            Self::Unsupported { detail } => {
                write!(formatter, "ethtool statistics unsupported: {detail}")
            }
            Self::InterfaceUnavailable { detail } => {
                write!(formatter, "interface unavailable to ethtool: {detail}")
            }
            Self::TimedOut => formatter.write_str("ethtool statistics command timed out"),
            Self::OutputTooLarge { stream } => {
                write!(formatter, "ethtool {stream:?} exceeded its output limit")
            }
            Self::ExitFailure { code, detail } => {
                write!(formatter, "ethtool exited with status {code:?}: {detail}")
            }
            Self::InvalidOutput => formatter.write_str("ethtool returned no valid statistics"),
            Self::Io { detail } => write!(formatter, "ethtool I/O failure: {detail}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn channel_fallback_marks_only_explicit_unsupported_as_fixed() {
        let supported = channel_settings(Ok((6, 7)));
        assert_eq!(
            supported
                .iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect::<Vec<_>>(),
            [
                ("Channel RX", "6"),
                ("Channel TX", "7"),
                ("Queue source", "ethtool")
            ]
        );
        for (errno, expected) in [
            (libc::EOPNOTSUPP, "fixed"),
            (libc::EPERM, "sysfs"),
            (libc::EACCES, "sysfs"),
            (libc::ENODEV, "sysfs"),
        ] {
            let fields = channel_settings(Err(io::Error::from_raw_os_error(errno)));
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].value, expected);
        }
    }

    #[test]
    fn sysfs_configuration_fallback_validates_values_without_inventing_ring_or_fixed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path();
        std::fs::create_dir(path.join("device")).unwrap();
        std::fs::write(
            path.join("device/uevent"),
            "PCI_CLASS=20000\nDRIVER=ixgbe\n",
        )
        .unwrap();
        std::fs::write(path.join("speed"), "10000\n").unwrap();
        std::fs::write(path.join("duplex"), "full\n").unwrap();
        std::fs::write(path.join("carrier"), "1\n").unwrap();
        std::fs::write(path.join("tx_queue_len"), "1000\n").unwrap();
        let fields = collect_fallback_settings(path);
        assert_eq!(
            fields
                .iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect::<Vec<_>>(),
            [
                ("Sysfs Driver", "ixgbe"),
                ("Sysfs Speed", "10000Mb/s"),
                ("Sysfs Duplex", "Full"),
                ("Sysfs Link detected", "yes")
            ]
        );
        for speed in [
            "-1",
            "4294967295",
            "0",
            "garbage",
            "999999999999999999999999999999",
        ] {
            std::fs::write(path.join("speed"), speed).unwrap();
            assert!(!collect_fallback_settings(path)
                .iter()
                .any(|field| field.name == "Sysfs Speed"));
        }
        std::fs::write(path.join("duplex"), "unknown").unwrap();
        std::fs::write(path.join("carrier"), "2").unwrap();
        assert_eq!(collect_fallback_settings(path).len(), 1);
    }

    #[test]
    fn inventory_and_shared_rtnetlink_interface_name_validation_match() {
        for byte in 0..=127_u8 {
            for name in [
                char::from(byte).to_string(),
                format!("eth{}0", char::from(byte)),
            ] {
                assert_eq!(
                    valid_interface_name(&name),
                    crate::collect::valid_interface_name(&name),
                    "{name:?}"
                );
            }
        }
        for name in [
            "",
            ".",
            "..",
            "eth\u{e9}",
            "\u{4e00}",
            "abcdefghijklmno",
            "abcdefghijklmnop",
        ] {
            assert_eq!(
                valid_interface_name(name),
                crate::collect::valid_interface_name(name),
                "{name:?}"
            );
        }
    }

    #[test]
    fn parser_classifies_names_without_assigning_counter_semantics() {
        let parsed = parse_ethtool_stats(
            b"NIC statistics:\n rx_packets: 42\n rx_queue_7_drops: 9\n packet_errors: 3\n",
        );

        assert_eq!(parsed.rejected_lines, 0);
        assert_eq!(parsed.omitted_private, 0);
        assert_eq!(
            parsed.statistics.standard,
            vec![StandardNicStatistic {
                statistic: StandardStatistic::RxPackets,
                value: 42,
                semantics: NicStatisticSemantics::OpaqueCurrentOnly,
            }]
        );
        assert!(parsed
            .statistics
            .standard
            .iter()
            .all(|statistic| { statistic.semantics == NicStatisticSemantics::OpaqueCurrentOnly }));
        assert_eq!(parsed.statistics.private.len(), 2);
        assert!(parsed
            .statistics
            .private
            .iter()
            .all(|statistic| { statistic.semantics == NicStatisticSemantics::OpaqueCurrentOnly }));
    }

    #[test]
    fn parser_retains_valid_rows_while_rejecting_malformed_rows() {
        let parsed = parse_ethtool_stats(
            b"rx_bytes: 100\nrx_bytes: 101\nbad: -1\ncolon:twice: 2\nescape\x1b: 4\ntx_bytes: 200\n",
        );

        assert_eq!(parsed.rejected_lines, 4);
        assert_eq!(parsed.statistics.standard.len(), 2);
        assert_eq!(parsed.statistics.standard[0].value, 100);
        assert_eq!(parsed.statistics.standard[1].value, 200);
    }

    #[test]
    fn parser_keeps_more_than_256_statistics_and_bounds_name_length() {
        let mut fixture = Vec::new();
        fixture.extend_from_slice(
            format!("{}: 1\n", "x".repeat(MAX_STATISTIC_NAME_LEN + 1)).as_bytes(),
        );
        for index in 0..300 {
            fixture.extend_from_slice(format!("private_{index}: {index}\n").as_bytes());
        }

        let parsed = parse_ethtool_stats(&fixture);

        assert_eq!(parsed.rejected_lines, 1);
        assert_eq!(parsed.statistics.private.len(), 300);
        assert_eq!(parsed.omitted_private, 0);
    }

    #[test]
    fn settings_parser_keeps_scalar_and_multiline_fields() {
        let parsed = parse_ethtool_settings(
            b"Settings for eth0:\n\
              Supported link modes: 1000baseT/Full\n\
                                    10000baseT/Full\n\
              Speed: 10000Mb/s\n\
              Duplex: Full\n\
              Auto-negotiation: off\n\
              Link detected: yes\n",
        );

        assert_eq!(parsed.rejected_lines, 0);
        assert_eq!(parsed.settings.fields.len(), 6);
        assert_eq!(parsed.settings.fields[0].name, "Supported link modes");
        assert_eq!(parsed.settings.fields[1].name, "Supported link modes [2]");
        assert_eq!(parsed.settings.fields[1].value, "10000baseT/Full");
        assert!(
            parsed
                .settings
                .fields
                .iter()
                .any(|field| field.name == "Link detected" && field.value == "yes"),
            "{parsed:?}"
        );
    }

    #[test]
    fn optional_ethtool_parsers_keep_only_exact_standard_fields() {
        let ring = parse_ethtool_ring_settings(
            b"Ring parameters for eth0:\n\
              Pre-set maximums:\n\
              RX: 4096\n\
              TX: 4096\n\
              Current hardware settings:\n\
              RX Mini: 0\n\
              RX: 512\n\
              TX: 256\n",
        );
        let pause = parse_ethtool_pause_settings(
            b"Pause parameters for eth0:\nAutonegotiate: on\nRX negotiated: on\nRX: on\nTX: off\n",
        );
        let features = parse_ethtool_feature_settings(
            b"Features for eth0:\n\
              tx-tcp-segmentation-offload: off\n\
              tcp-segmentation-offload: on [fixed]\n\
              large-receive-offload: off [fixed]\n\
              generic-receive-offload-extra: off\n\
              generic-receive-offload: on\n\
              generic-segmentation-offload: off\n",
        );
        let coalesce = parse_ethtool_coalesce_settings(
            b"Coalesce parameters for eth0:\n\
              Adaptive RX: on  TX: off\n\
              rx-usecs: 8\n\
              rx-frames: 16\n\
              rx-usecs-irq: 99\n\
              tx-usecs: 12\n\
              tx-frames: 24\n",
        );
        let ring_section_boundary = parse_ethtool_ring_settings(
            b"Current hardware settings:\nRX: 64\nPre-set maximums:\nTX: 4096\n",
        );

        assert_eq!(
            ring,
            vec![
                EthtoolSetting {
                    name: "Ring RX".to_owned(),
                    value: "512".to_owned(),
                },
                EthtoolSetting {
                    name: "Ring TX".to_owned(),
                    value: "256".to_owned(),
                },
                EthtoolSetting {
                    name: "Ring RX Max".to_owned(),
                    value: "4096".to_owned(),
                },
                EthtoolSetting {
                    name: "Ring TX Max".to_owned(),
                    value: "4096".to_owned(),
                },
            ]
        );
        assert_eq!(
            ring_section_boundary,
            vec![
                EthtoolSetting {
                    name: "Ring RX".to_owned(),
                    value: "64".to_owned(),
                },
                EthtoolSetting {
                    name: "Ring TX Max".to_owned(),
                    value: "4096".to_owned(),
                },
            ]
        );
        assert_eq!(
            pause,
            vec![
                EthtoolSetting {
                    name: "Flow Control RX".to_owned(),
                    value: "on".to_owned(),
                },
                EthtoolSetting {
                    name: "Flow Control TX".to_owned(),
                    value: "off".to_owned(),
                },
            ]
        );
        assert_eq!(
            features,
            vec![
                EthtoolSetting {
                    name: "TSO".to_owned(),
                    value: "on [fixed]".to_owned(),
                },
                EthtoolSetting {
                    name: "LRO".to_owned(),
                    value: "off [fixed]".to_owned(),
                },
                EthtoolSetting {
                    name: "GRO".to_owned(),
                    value: "on".to_owned(),
                },
                EthtoolSetting {
                    name: "GSO".to_owned(),
                    value: "off".to_owned(),
                },
            ]
        );
        assert_eq!(
            coalesce,
            vec![
                EthtoolSetting {
                    name: "Adaptive RX".to_owned(),
                    value: "on".to_owned(),
                },
                EthtoolSetting {
                    name: "Adaptive TX".to_owned(),
                    value: "off".to_owned(),
                },
                EthtoolSetting {
                    name: "RX Usecs".to_owned(),
                    value: "8".to_owned(),
                },
                EthtoolSetting {
                    name: "RX Frames".to_owned(),
                    value: "16".to_owned(),
                },
                EthtoolSetting {
                    name: "TX Usecs".to_owned(),
                    value: "12".to_owned(),
                },
                EthtoolSetting {
                    name: "TX Frames".to_owned(),
                    value: "24".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn optional_ethtool_parsers_keep_first_values_across_repeated_sections() {
        let ring = parse_ethtool_ring_settings(
            b"Pre-set maximums:\n\
              RX Mini: 1\n\
              RX: 4096\n\
              RX: 8192\n\
              Current hardware settings:\n\
              TX: 256\n\
              Pre-set maximums:\n\
              TX: 8192\n\
              Current hardware settings:\n\
              RX: 512\n",
        );
        let coalesce = parse_ethtool_coalesce_settings(
            b"Adaptive RX: off TX: on\n\
              Adaptive RX: on TX: off\n\
              rx-usecs-high: 80\n\
              rx-usecs: 4\n\
              rx-usecs: 8\n\
              tx-frames: 32\n",
        );

        assert_eq!(
            ring.iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Ring RX", "512"),
                ("Ring TX", "256"),
                ("Ring RX Max", "4096"),
                ("Ring TX Max", "8192"),
            ]
        );
        assert_eq!(
            coalesce
                .iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Adaptive RX", "off"),
                ("Adaptive TX", "on"),
                ("RX Usecs", "4"),
                ("TX Frames", "32"),
            ]
        );
    }

    #[test]
    fn collection_reads_optional_sysfs_nic_details_without_following_driver_symlink() {
        let root = TestDir::new();
        write_hardware_interface(root.path(), "eth0", 2, "up");
        let interface = root.path().join("class/net/eth0");
        symlink(
            "../../../../bus/pci/drivers/igc",
            interface.join("device/driver"),
        )
        .unwrap();
        for queue in ["rx-0", "rx-7", "tx-0", "rx-other", "tx-1-extra"] {
            fs::create_dir_all(interface.join("queues").join(queue)).unwrap();
        }
        fs::write(interface.join("tx_queue_len"), "1000\n").unwrap();
        fs::write(interface.join("mtu"), "9000\n").unwrap();

        let collection = collect_with(root.path(), |_| {
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert!(collection.errors.is_empty());
        assert_eq!(
            collection.interfaces[0].sysfs,
            NicSysfsInfo {
                driver: Some("igc".to_owned()),
                rx_queue_count: Some(2),
                tx_queue_count: Some(1),
                tx_queue_len: Some(1000),
                mtu: Some(9000),
            }
        );
    }

    #[test]
    fn missing_or_malformed_optional_sysfs_nic_details_do_not_add_errors() {
        let root = TestDir::new();
        write_hardware_interface(root.path(), "eth0", 2, "up");
        fs::write(root.path().join("class/net/eth0/tx_queue_len"), "-1\n").unwrap();
        fs::write(root.path().join("class/net/eth0/mtu"), "not-a-number\n").unwrap();

        let collection = collect_with(root.path(), |_| {
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert!(collection.errors.is_empty());
        assert_eq!(collection.interfaces[0].sysfs, NicSysfsInfo::default());
    }

    #[test]
    fn collection_classifies_and_probes_only_by_the_sysfs_device_relationship() {
        let root = TestDir::new();
        write_hardware_interface(root.path(), "veth0", 2, "up");
        write_interface(root.path(), "eth0", 1, "unknown");
        let mut calls = Vec::new();

        let collection = collect_with(root.path(), |interface| {
            calls.push(interface.to_owned());
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert_eq!(calls, vec!["veth0"]);
        assert!(collection.errors.is_empty());
        assert_eq!(collection.interfaces.len(), 2);
        assert_eq!(collection.interfaces[0].interface, "eth0");
        assert_eq!(collection.interfaces[1].interface, "veth0");
        assert!(!collection.interfaces[0].hardware_backed);
        assert!(collection.interfaces[1].hardware_backed);
        assert!(matches!(
            collection.interfaces[0].ethtool,
            EthtoolOutcome::NotHardwareInterface
        ));
        assert!(matches!(
            collection.interfaces[1].ethtool,
            EthtoolOutcome::Collected(_)
        ));
    }

    #[test]
    fn parallel_collection_overlaps_slow_interfaces_within_the_worker_limit() {
        let root = TestDir::new();
        for ifindex in 1..=6 {
            write_hardware_interface(root.path(), &format!("eth{ifindex}"), ifindex, "up");
        }
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);

        let collection = collect_parallel_with(root.path(), 2, |_| {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(current, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(75));
            active.fetch_sub(1, Ordering::SeqCst);
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert_eq!(collection.interfaces.len(), 6);
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        assert!(collection
            .interfaces
            .iter()
            .all(|interface| matches!(&interface.ethtool, EthtoolOutcome::Collected(_))));
    }

    #[test]
    fn invalid_interface_identity_does_not_hide_valid_interfaces() {
        let root = TestDir::new();
        write_interface(root.path(), "eth0", 2, "up");
        write_interface(root.path(), "bad0", 0, "down");

        let collection = collect_with(root.path(), |_| {
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert_eq!(collection.interfaces.len(), 1);
        assert_eq!(collection.interfaces[0].interface, "eth0");
        assert_eq!(collection.errors.len(), 1);
        assert_eq!(collection.errors[0].interface.as_deref(), Some("bad0"));
        assert_eq!(
            collection.errors[0].kind,
            NicCollectionErrorKind::ReadIfindex
        );
    }

    #[test]
    fn missing_operstate_is_explicitly_unavailable() {
        let root = TestDir::new();
        let interface = root.path().join("class/net/eth0");
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), "2\n").unwrap();

        let collection = collect_with(root.path(), |_| {
            EthtoolOutcome::Collected(NicStatistics::default())
        });

        assert_eq!(collection.interfaces[0].operstate, OperState::Unavailable);
        assert_eq!(
            collection.errors[0].kind,
            NicCollectionErrorKind::ReadOperstate
        );
    }

    #[test]
    fn command_not_found_has_a_distinct_outcome() {
        let outcome = run_ethtool(
            OsStr::new("/definitely/not/a/real/ethtool"),
            "eth0",
            Duration::from_millis(50),
            1024,
            1024,
        );

        assert_eq!(
            outcome,
            EthtoolOutcome::Failed(EthtoolFailure::CommandNotFound)
        );
    }

    #[test]
    fn native_basic_preserves_partial_counts_and_supplementary_order() {
        let parsed = parse_ethtool_settings(b"Settings for eth0:\nSpeed: 1000Mb/s\n:\n");
        let mut expected = parsed.settings.clone();
        let mut operations = Vec::new();
        for operation in ["-g", "-a", "-k", "-c"] {
            expected.fields.push(EthtoolSetting {
                name: operation.to_owned(),
                value: "known".to_owned(),
            });
        }
        let outcome = run_ethtool_settings_with_base(
            OsStr::new("/definitely/not/a/real/ethtool"),
            "eth0",
            ETHTOOL_TIMEOUT,
            1024,
            1024,
            || Some(parsed),
            |operation| {
                operations.push(operation.to_owned());
                Some(vec![EthtoolSetting {
                    name: operation.to_owned(),
                    value: "known".to_owned(),
                }])
            },
        );
        assert_eq!(
            outcome,
            EthtoolSettingsOutcome::Partial {
                settings: expected,
                rejected_lines: 1
            }
        );
        assert_eq!(operations, ["-g", "-a", "-k", "-c"]);
        let fallback = run_ethtool_settings_with_base(
            OsStr::new("/definitely/not/a/real/ethtool"),
            "eth0",
            ETHTOOL_TIMEOUT,
            1024,
            1024,
            || None,
            |_| panic!("supplements cannot hide failed base command"),
        );
        assert_eq!(
            fallback,
            EthtoolSettingsOutcome::Failed(EthtoolFailure::CommandNotFound)
        );
    }

    #[test]
    fn unsupported_optional_commands_are_cached_without_skipping_supported_fields() {
        let root = TestDir::new();
        let command = root.executable("ethtool", "echo 'Operation not supported' >&2\nexit 1\n");
        let cache = Mutex::new(capabilities::Cache::default());
        cache
            .lock()
            .unwrap()
            .reconcile(std::collections::BTreeMap::from([(
                "eth0".into(),
                capabilities::Identity {
                    index: 2,
                    hardware: true,
                    driver: None,
                    directory: Some((1, 2)),
                    device: None,
                },
            )]));
        let invoke = |native: fn(&str) -> Option<Vec<EthtoolSetting>>| {
            run_ethtool_settings_cached(
                command.as_os_str(),
                "eth0",
                ETHTOOL_TIMEOUT,
                1024,
                1024,
                (
                    || {
                        Some(parse_ethtool_settings(
                            b"Settings for eth0:\nSpeed: 1000Mb/s\n",
                        ))
                    },
                    native,
                ),
                Some(&cache),
            )
        };
        assert!(matches!(
            invoke(|_| None),
            EthtoolSettingsOutcome::Collected(_)
        ));
        for operation in ["-g", "-a", "-k", "-c"] {
            assert!(cache
                .lock()
                .unwrap()
                .get("eth0", operation, Instant::now())
                .is_some());
        }
        let second = run_ethtool_settings_cached(
            command.as_os_str(),
            "eth0",
            ETHTOOL_TIMEOUT,
            1024,
            1024,
            (
                || {
                    Some(parse_ethtool_settings(
                        b"Settings for eth0:\nSpeed: 25000Mb/s\n",
                    ))
                },
                |_| panic!("unsupported supplements must not be queried again"),
            ),
            Some(&cache),
        );
        let EthtoolSettingsOutcome::Collected(settings) = second else {
            panic!("base settings must remain available")
        };
        assert!(settings
            .fields
            .iter()
            .any(|field| field.name == "Speed" && field.value == "25000Mb/s"));
    }

    #[test]
    fn exhausted_basic_budget_rejects_native_result_and_command_fallback() {
        for native_result in [
            None,
            Some(parse_ethtool_settings(
                b"Settings for eth0:\nSpeed: 1000Mb/s\n",
            )),
        ] {
            let outcome = run_ethtool_settings_with_base(
                OsStr::new("/definitely/not/a/real/ethtool"),
                "eth0",
                Duration::ZERO,
                1024,
                1024,
                || native_result,
                |_| panic!("no supplements after timeout"),
            );
            assert_eq!(
                outcome,
                EthtoolSettingsOutcome::Failed(EthtoolFailure::TimedOut)
            );
        }
    }

    #[test]
    fn link_settings_command_uses_plain_interface_argv_and_keeps_stdout_with_a_warning() {
        let root = TestDir::new();
        let command = root.executable(
            "ethtool",
            "[ \"$#\" -eq 1 ] || exit 7\n\
             [ \"$1\" = eth0 ] || exit 8\n\
             echo 'netlink warning' >&2\n\
             printf 'Settings for eth0:\\nSpeed: 10000Mb/s\\nLink detected: yes\\n'\n",
        );

        let outcome = run_ethtool_settings(
            command.as_os_str(),
            "eth0",
            Duration::from_secs(1),
            1024,
            1024,
        );

        assert!(
            matches!(
                &outcome,
                EthtoolSettingsOutcome::Collected(EthtoolSettings { fields })
                    if fields.len() == 2
                        && fields[0].name == "Speed"
                        && fields[0].value == "10000Mb/s"
                        && fields[1].name == "Link detected"
                        && fields[1].value == "yes"
            ),
            "unexpected settings outcome: {outcome:?}"
        );
    }

    #[test]
    fn link_settings_append_optional_queries_in_stable_order() {
        let root = TestDir::new();
        let calls = root.path().join("calls");
        let command = root.executable(
            "ethtool",
            &format!(
                "printf '%s|%s\\n' \"$1\" \"$2\" >> '{}'\n\
                 case \"$1\" in\n\
                   eth0) printf 'Settings for eth0:\\nSpeed: 10000Mb/s\\n' ;;\n\
                   -g) printf 'Pre-set maximums:\\nRX: 4096\\nTX: 4096\\nCurrent hardware settings:\\nRX: 512\\nTX: 256\\n' ;;\n\
                   -a) printf 'Pause parameters for eth0:\\nRX: on\\nTX: off\\n' ;;\n\
                   -k) printf 'Features for eth0:\\ntcp-segmentation-offload: on [fixed]\\nlarge-receive-offload: off\\ngeneric-receive-offload: on\\ngeneric-segmentation-offload: off [fixed]\\n' ;;\n\
                   -c) printf 'Coalesce parameters for eth0:\\nAdaptive RX: off TX: on\\nrx-usecs: 4\\nrx-frames: 8\\ntx-usecs: 12\\ntx-frames: 16\\n' ;;\n\
                   *) exit 9 ;;\n\
                 esac\n",
                calls.display()
            ),
        );

        let outcome = run_ethtool_settings(
            command.as_os_str(),
            "eth0",
            Duration::from_secs(1),
            4096,
            1024,
        );

        let EthtoolSettingsOutcome::Collected(settings) = outcome else {
            panic!("unexpected settings outcome: {outcome:?}");
        };
        assert_eq!(
            settings
                .fields
                .iter()
                .map(|field| (field.name.as_str(), field.value.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("Speed", "10000Mb/s"),
                ("Ring RX", "512"),
                ("Ring TX", "256"),
                ("Ring RX Max", "4096"),
                ("Ring TX Max", "4096"),
                ("Flow Control RX", "on"),
                ("Flow Control TX", "off"),
                ("TSO", "on [fixed]"),
                ("LRO", "off"),
                ("GRO", "on"),
                ("GSO", "off [fixed]"),
                ("Adaptive RX", "off"),
                ("Adaptive TX", "on"),
                ("RX Usecs", "4"),
                ("RX Frames", "8"),
                ("TX Usecs", "12"),
                ("TX Frames", "16"),
            ]
        );
        assert_eq!(
            fs::read_to_string(calls).unwrap(),
            "eth0|\n-g|eth0\n-a|eth0\n-k|eth0\n-c|eth0\n"
        );
    }

    #[test]
    fn optional_ethtool_failures_do_not_downgrade_base_settings() {
        let root = TestDir::new();
        let command = root.executable(
            "ethtool",
            "if [ \"$#\" -eq 1 ]; then\n\
               printf 'unexpected prefix\\nSettings for eth0:\\nSpeed: 1000Mb/s\\n'\n\
             else\n\
               echo 'Operation not supported' >&2\n\
               exit 95\n\
             fi\n",
        );

        let outcome = run_ethtool_settings(
            command.as_os_str(),
            "eth0",
            Duration::from_secs(1),
            1024,
            1024,
        );

        assert_eq!(
            outcome,
            EthtoolSettingsOutcome::Partial {
                settings: EthtoolSettings {
                    fields: vec![EthtoolSetting {
                        name: "Speed".to_owned(),
                        value: "1000Mb/s".to_owned(),
                    }],
                },
                rejected_lines: 1,
            }
        );
    }

    #[test]
    fn command_permission_denied_has_a_distinct_outcome() {
        let root = TestDir::new();
        let command = root.executable("ethtool", "printf 'private_counter: 1\\n'\n");
        let mut permissions = fs::metadata(&command).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&command, permissions).unwrap();

        let outcome = run_ethtool(
            command.as_os_str(),
            "eth0",
            Duration::from_millis(50),
            1024,
            1024,
        );

        assert!(matches!(
            outcome,
            EthtoolOutcome::Failed(EthtoolFailure::PermissionDenied { .. })
        ));
    }

    #[test]
    fn nonzero_permission_errors_have_a_distinct_outcome() {
        for message in ["Operation not permitted", "Permission denied"] {
            let root = TestDir::new();
            let command = root.executable("ethtool", &format!("echo '{message}' >&2\nexit 1\n"));

            let outcome = run_ethtool_script(&command, "eth0", Duration::from_secs(1), 1024, 1024);

            assert!(
                matches!(
                    outcome,
                    EthtoolOutcome::Failed(EthtoolFailure::PermissionDenied { .. })
                ),
                "unexpected outcome for {message:?}: {outcome:?}"
            );
        }
    }

    #[test]
    fn unsupported_interface_has_a_distinct_outcome() {
        let root = TestDir::new();
        let command = root.executable("ethtool", "echo 'Operation not supported' >&2\nexit 95\n");

        let outcome = run_ethtool_script(&command, "eth0", Duration::from_secs(1), 1024, 1024);

        assert!(matches!(
            outcome,
            EthtoolOutcome::Failed(EthtoolFailure::Unsupported { .. })
        ));
    }

    #[test]
    fn command_timeout_is_enforced() {
        let root = TestDir::new();
        let command = root.executable("ethtool", "sleep 5 &\nwait\n");
        let started = Instant::now();

        let outcome = run_ethtool_script(&command, "eth0", Duration::from_millis(30), 1024, 1024);

        assert_eq!(outcome, EthtoolOutcome::Failed(EthtoolFailure::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn parent_exit_kills_a_descendant_holding_output_pipes() {
        let root = TestDir::new();
        let command = root.executable(
            "ethtool",
            "sleep 5 &\nprintf 'private_counter: 1\\n'\nexit 0\n",
        );
        let started = Instant::now();

        let outcome = run_ethtool_script(&command, "eth0", Duration::from_secs(1), 1024, 1024);

        assert!(
            matches!(&outcome, EthtoolOutcome::Collected(_)),
            "unexpected command outcome: {outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn detached_descendant_cannot_hold_output_readers_open() {
        let root = TestDir::new();
        let detached_pid = root.path().join("detached.pid");
        let command = root.executable(
            "ethtool",
            &format!(
                "/usr/bin/setsid sleep 5 &\nprintf '%s' \"$!\" > '{}'\n\
                 printf 'private_counter: 1\\n'\nexit 0\n",
                detached_pid.display()
            ),
        );
        let started = Instant::now();

        let outcome = run_ethtool_script(&command, "eth0", Duration::from_secs(1), 1024, 1024);
        let elapsed = started.elapsed();
        if let Ok(process_id) = fs::read_to_string(&detached_pid) {
            if let Ok(process_id) = process_id.parse::<i32>() {
                // SAFETY: the test just spawned this positive PID and only requests SIGKILL.
                unsafe {
                    libc::kill(process_id, libc::SIGKILL);
                }
            }
        }

        assert!(
            matches!(&outcome, EthtoolOutcome::Collected(_)),
            "unexpected command outcome: {outcome:?}"
        );
        assert!(elapsed < Duration::from_millis(500), "elapsed: {elapsed:?}");
    }

    #[test]
    fn continuously_readable_output_cannot_starve_process_checks() {
        struct AlwaysReadable;

        impl std::io::Read for AlwaysReadable {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer[0] = b'x';
                Ok(1)
            }
        }

        let mut capture = LimitedBytes {
            bytes: Vec::new(),
            truncated: false,
        };
        assert!(!drain_pipe(&mut AlwaysReadable, &mut capture, usize::MAX).unwrap());
        assert!(!capture.bytes.is_empty());
        assert!(!capture.truncated);
    }

    #[test]
    fn continuously_readable_descendant_output_cannot_be_reported_as_complete() {
        struct AlwaysReadable(File);
        impl Read for AlwaysReadable {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                buffer[0] = b'x';
                Ok(1)
            }
        }
        impl AsRawFd for AlwaysReadable {
            fn as_raw_fd(&self) -> std::os::fd::RawFd {
                self.0.as_raw_fd()
            }
        }
        let mut child = Command::new("/bin/true").process_group(0).spawn().unwrap();
        let mut output = AlwaysReadable(File::open("/dev/null").unwrap());
        let mut errors = File::open("/dev/null").unwrap();
        let result = capture_pipes(
            &mut child,
            &mut output,
            &mut errors,
            Duration::from_secs(1),
            usize::MAX,
            1024,
        );
        terminate(&mut child);
        assert!(matches!(result, Err(EthtoolFailure::Io { .. })));
    }

    #[test]
    fn capture_drains_both_pipes_without_losing_large_successful_output() {
        let root = TestDir::new();
        let command = root.executable("ethtool", "i=0\nwhile [ \"$i\" -lt 5000 ]; do printf 'vendor_counter: 1\\n'; printf 'warning\\n' >&2; i=$((i + 1)); done\n");
        let output = capture_ethtool(
            OsStr::new("/bin/sh"),
            &[command.as_os_str()],
            &[],
            "eth0",
            Duration::from_secs(5),
            128 * 1024,
            64 * 1024,
        )
        .unwrap();
        assert_eq!(output, b"vendor_counter: 1\n".repeat(5000));
    }

    #[test]
    fn oversized_output_is_rejected_without_unbounded_capture() {
        let root = TestDir::new();
        let command = root.executable(
            "ethtool",
            "i=0\nwhile [ \"$i\" -lt 100 ]; do echo 'private_counter: 1'; i=$((i + 1)); done\n",
        );

        let outcome = run_ethtool_script(&command, "eth0", Duration::from_secs(1), 64, 1024);

        assert_eq!(
            outcome,
            EthtoolOutcome::Failed(EthtoolFailure::OutputTooLarge {
                stream: OutputStream::Stdout,
            })
        );
    }

    #[test]
    fn interface_name_is_passed_as_one_argument_without_shell_interpretation() {
        let root = TestDir::new();
        let marker = root.path().join("marker");
        let command = root.executable(
            "ethtool",
            "[ \"$#\" -eq 2 ] || exit 7\nprintf 'private_counter: 1\\n'\n",
        );
        let interface = format!("e;touch{}", marker.display());
        let interface = &interface[..15.min(interface.len())];

        let outcome = run_ethtool_script(&command, interface, Duration::from_secs(5), 1024, 1024);

        assert!(
            matches!(&outcome, EthtoolOutcome::Collected(_)),
            "unexpected command outcome: {outcome:?}"
        );
        assert!(!marker.exists());
    }

    #[test]
    #[ignore = "read-only live hardware equivalence; run explicitly on the benchmark host"]
    fn live_native_settings_match_all_hardware_commands() {
        let inventory = collect_inventory(Path::new("/sys"));
        eprintln!("baseline inventory errors: {:?}", inventory.errors);
        let mut native = netlink::Context::new().expect("live ethtool netlink family");
        let mut native_queries = std::collections::BTreeMap::<String, usize>::new();
        let mut fallbacks = std::collections::BTreeMap::<String, usize>::new();
        let mut interfaces = 0;
        for interface in inventory
            .interfaces
            .iter()
            .filter(|interface| interface.hardware_backed)
        {
            let expected = run_ethtool_settings(
                OsStr::new("ethtool"),
                &interface.interface,
                ETHTOOL_TIMEOUT,
                ETHTOOL_STDOUT_LIMIT,
                ETHTOOL_STDERR_LIMIT,
            );
            let actual = run_ethtool_settings_with(
                OsStr::new("ethtool"),
                &interface.interface,
                ETHTOOL_TIMEOUT,
                ETHTOOL_STDOUT_LIMIT,
                ETHTOOL_STDERR_LIMIT,
                |operation| match native.settings(&interface.interface, operation) {
                    Ok(fields) => {
                        *native_queries.entry(operation.to_owned()).or_default() += 1;
                        Some(fields)
                    }
                    Err(error) => {
                        *fallbacks
                            .entry(format!("{operation}: {error}"))
                            .or_default() += 1;
                        None
                    }
                },
            );
            assert_eq!(
                actual, expected,
                "settings differ for {}",
                interface.interface
            );
            interfaces += 1;
        }
        assert!(interfaces > 0, "no hardware interfaces tested");
        eprintln!("live settings: interfaces={interfaces}, native={native_queries:?}, command_fallbacks={fallbacks:?}");
    }

    #[test]
    #[ignore = "read-only live inventory equivalence; run explicitly on the benchmark host"]
    fn live_native_inventory_matches_sysfs_on_repeated_polls() {
        let mut native = inventory::Context::default();
        for _ in 0..2 {
            let expected = collect_inventory(Path::new("/sys"));
            let actual = native
                .collect(Path::new("/sys"))
                .expect("live route netlink dump");
            assert_eq!(actual.errors, expected.errors);
            assert_eq!(actual.interfaces.len(), expected.interfaces.len());
            for (actual, expected) in actual.interfaces.iter().zip(&expected.interfaces) {
                assert_eq!(
                    actual, expected,
                    "inventory mismatch for {}",
                    actual.interface
                );
            }
            eprintln!(
                "live inventory: {} interfaces match",
                actual.interfaces.len()
            );
        }
    }

    #[test]
    #[ignore = "manual read-only shared/independent inventory parity over 120 polls; requires stable metadata"]
    fn live_shared_inventory_matches_independent_over_120_polls() {
        let sys_root = Path::new("/sys");
        let mut independent = inventory::Context::default();
        let mut shared = inventory::Context::default();
        let mut interfaces = 0;
        for poll in 0..120 {
            let (_, metadata) = super::super::rtnetlink::collect_link_counters_with_metadata(true)
                .expect("completed bracketing link dumps");
            let metadata = metadata.expect("validated metadata available for handoff");
            let started_at = metadata.started_at;
            let (actual, shared_started) = shared
                .collect_with_metadata(sys_root, Some(metadata))
                .expect("shared inventory scan");
            assert_eq!(
                shared_started,
                Some(started_at),
                "poll {poll} independently recollected"
            );
            let expected = independent
                .collect(sys_root)
                .expect("independent inventory dump");
            assert_eq!(
                actual.errors, expected.errors,
                "inventory errors at poll {poll}"
            );
            // These inventory-only collections contain all identity, hardware,
            // operstate, driver, queue-count and queue-length fields, no probes.
            assert_eq!(
                actual.interfaces, expected.interfaces,
                "inventory fields at poll {poll}"
            );
            assert!(
                !actual.interfaces.is_empty(),
                "empty inventory at poll {poll}"
            );
            interfaces += actual.interfaces.len();
        }
        eprintln!("shared inventory: 120 polls, {interfaces} interface comparisons; all metadata fields and errors match (statistics excluded)");
    }

    #[test]
    #[ignore = "coordinated read-only native BASIC full-Outcome parity on all hardware interfaces"]
    fn live_native_basic_settings_match_all_hardware_commands() {
        let inventory = collect_inventory(Path::new("/sys"));
        let hardware: Vec<_> = inventory
            .interfaces
            .iter()
            .filter(|interface| interface.hardware_backed)
            .collect();
        assert!(!hardware.is_empty(), "no hardware interfaces");
        let mut frontend = basic::Frontend::default();
        let executable = frontend
            .prepare(&hardware[0].interface)
            .expect("verified CLI version and netlink frontend");
        let basic = basic::ContextPool::default();
        let mut native = netlink::Context::new().expect("ethtool netlink family");
        let mut eligible = 0;
        let mut fallbacks = std::collections::BTreeMap::<String, usize>::new();
        let mut statuses = std::collections::BTreeMap::<String, usize>::new();
        let mut fields = 0;
        for interface in &hardware {
            assert!(executable.current(), "CLI executable changed");
            let reference = capture_ethtool(
                OsStr::new("ethtool"),
                &[],
                &[],
                &interface.interface,
                ETHTOOL_TIMEOUT,
                ETHTOOL_STDOUT_LIMIT,
                ETHTOOL_STDERR_LIMIT,
            );
            let expected_base = reference
                .as_ref()
                .ok()
                .map(|output| parse_ethtool_settings(output));
            let native_base = match basic.settings_until(
                &interface.interface,
                interface.ifindex,
                Instant::now() + basic::ATTEMPT_TIMEOUT,
            ) {
                Ok(parsed) => {
                    assert_eq!(
                        Some(&parsed),
                        expected_base.as_ref(),
                        "basic parsed output differs for {}",
                        interface.interface
                    );
                    eligible += 1;
                    Some(parsed)
                }
                Err(error) => {
                    *fallbacks.entry(error.to_string()).or_default() += 1;
                    None
                }
            };
            let expected = match reference {
                Err(error) => EthtoolSettingsOutcome::Failed(error),
                Ok(_) => run_ethtool_settings_with_base(
                    OsStr::new("ethtool"),
                    &interface.interface,
                    ETHTOOL_TIMEOUT,
                    ETHTOOL_STDOUT_LIMIT,
                    ETHTOOL_STDERR_LIMIT,
                    || expected_base,
                    |_| None,
                ),
            };
            let actual = run_ethtool_settings_with_base(
                OsStr::new("ethtool"),
                &interface.interface,
                ETHTOOL_TIMEOUT,
                ETHTOOL_STDOUT_LIMIT,
                ETHTOOL_STDERR_LIMIT,
                || native_base,
                |operation| native.settings(&interface.interface, operation).ok(),
            );
            assert_eq!(
                actual, expected,
                "full Outcome differs for {}",
                interface.interface
            );
            let (status, count) = match &actual {
                EthtoolSettingsOutcome::Collected(settings) => ("Collected", settings.fields.len()),
                EthtoolSettingsOutcome::Partial { settings, .. } => {
                    ("Partial", settings.fields.len())
                }
                EthtoolSettingsOutcome::Failed(_) => ("Failed", 0),
                _ => panic!("unexpected hardware settings outcome"),
            };
            fields += count;
            *statuses.entry(status.to_owned()).or_default() += 1;
            eprintln!(
                "basic parity {}: {status}, fields={count}",
                interface.interface
            );
        }
        eprintln!("BASIC full parity: interfaces={}, eligible={eligible}, fields={fields}, statuses={statuses:?}, fallbacks={fallbacks:?}", hardware.len());
        assert!(eligible > 0, "no interface qualified for native BASIC");
    }

    fn run_ethtool_script(
        script: &Path,
        interface: &str,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> EthtoolOutcome {
        run_ethtool_with_prefix(
            OsStr::new("/bin/sh"),
            &[script.as_os_str()],
            interface,
            timeout,
            stdout_limit,
            stderr_limit,
        )
    }

    fn write_interface(root: &Path, name: &str, ifindex: u32, operstate: &str) {
        let interface = root.join("class/net").join(name);
        fs::create_dir_all(&interface).unwrap();
        fs::write(interface.join("ifindex"), format!("{ifindex}\n")).unwrap();
        fs::write(interface.join("operstate"), format!("{operstate}\n")).unwrap();
    }

    fn write_hardware_interface(root: &Path, name: &str, ifindex: u32, operstate: &str) {
        write_interface(root, name, ifindex, operstate);
        fs::create_dir(root.join("class/net").join(name).join("device")).unwrap();
    }

    struct TestDir(tempfile::TempDir);

    impl TestDir {
        fn new() -> Self {
            Self(tempfile::tempdir().unwrap())
        }

        fn path(&self) -> &Path {
            self.0.path()
        }

        fn executable(&self, name: &str, body: &str) -> PathBuf {
            let path = self.0.path().join(name);
            fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).unwrap();
            path
        }
    }
}
