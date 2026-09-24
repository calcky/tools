use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::collect::valid_interface_name;
use crate::model::IfIndex;

pub const MAX_ID_BYTES: usize = 128;
pub const MAX_LABELS_PER_READING: usize = 8;
pub const MAX_LABEL_VALUE_BYTES: usize = 128;
pub const MAX_DIAGNOSTIC_BYTES: usize = 256;
pub const MAX_PROVIDERS: usize = 64;
pub const MAX_READINGS_PER_PROVIDER: usize = 4_096;
pub const MAX_ADMITTED_SERIES: usize = 16_384;
pub const MAX_HISTORY_BUCKETS: u64 = 262_144;
pub const MAX_HISTORY_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_HISTORY_BUCKETS_PER_SERIES: usize = 16;

const MIN_INTERVAL: Duration = Duration::from_millis(250);
const MAX_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorSection {
    Overview,
    Socket,
    Netfilter,
    Tc,
    Netdevice,
    Nic,
    Softirq,
    Hardirq,
    Providers,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialPage {
    Overview,
    Interface,
    Qdisc,
    Softirq,
    Hardirq,
    Socket,
    Transport,
    Network,
    Conntrack,
    Route,
    Providers,
}

impl InitialPage {
    pub const fn monitor_section(self) -> MonitorSection {
        match self {
            Self::Overview | Self::Transport | Self::Network | Self::Route => {
                MonitorSection::Overview
            }
            Self::Interface => MonitorSection::Nic,
            Self::Qdisc => MonitorSection::Tc,
            Self::Softirq => MonitorSection::Softirq,
            Self::Hardirq => MonitorSection::Hardirq,
            Self::Socket => MonitorSection::Socket,
            Self::Conntrack => MonitorSection::Netfilter,
            Self::Providers => MonitorSection::Providers,
        }
    }
}

impl MonitorSection {
    pub const ALL: [Self; 9] = [
        Self::Overview,
        Self::Socket,
        Self::Netfilter,
        Self::Tc,
        Self::Netdevice,
        Self::Nic,
        Self::Softirq,
        Self::Hardirq,
        Self::Providers,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Socket => "socket",
            Self::Netfilter => "netfilter",
            Self::Tc => "tc",
            Self::Netdevice => "netdevice",
            Self::Nic => "nic",
            Self::Softirq => "softirq",
            Self::Hardirq => "hardirq",
            Self::Providers => "providers",
        }
    }

    pub const fn collection_section(self) -> Option<CollectionSection> {
        match self {
            Self::Socket => Some(CollectionSection::Socket),
            Self::Netfilter => Some(CollectionSection::Netfilter),
            Self::Tc => Some(CollectionSection::Tc),
            Self::Netdevice => Some(CollectionSection::Netdevice),
            Self::Nic => Some(CollectionSection::Nic),
            Self::Softirq => Some(CollectionSection::Softirq),
            Self::Hardirq => Some(CollectionSection::Hardirq),
            Self::Overview | Self::Providers => None,
        }
    }
}

impl fmt::Display for MonitorSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for MonitorSection {
    type Err = MonitorValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|section| section.as_str().eq_ignore_ascii_case(value))
            .ok_or(MonitorValidationError::InvalidSection)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionSection {
    Socket,
    Netfilter,
    Tc,
    Netdevice,
    Nic,
    Softirq,
    Hardirq,
}

impl CollectionSection {
    pub const ALL: [Self; 7] = [
        Self::Socket,
        Self::Netfilter,
        Self::Tc,
        Self::Netdevice,
        Self::Nic,
        Self::Softirq,
        Self::Hardirq,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Netfilter => "netfilter",
            Self::Tc => "tc",
            Self::Netdevice => "netdevice",
            Self::Nic => "nic",
            Self::Softirq => "softirq",
            Self::Hardirq => "hardirq",
        }
    }

    pub const fn monitor_section(self) -> MonitorSection {
        match self {
            Self::Socket => MonitorSection::Socket,
            Self::Netfilter => MonitorSection::Netfilter,
            Self::Tc => MonitorSection::Tc,
            Self::Netdevice => MonitorSection::Netdevice,
            Self::Nic => MonitorSection::Nic,
            Self::Softirq => MonitorSection::Softirq,
            Self::Hardirq => MonitorSection::Hardirq,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SamplingInterval(Duration);

impl SamplingInterval {
    pub fn new(value: Duration) -> Result<Self, MonitorValidationError> {
        if !(MIN_INTERVAL..=MAX_INTERVAL).contains(&value) {
            return Err(MonitorValidationError::IntervalOutOfRange);
        }
        if value.subsec_nanos() % 1_000_000 != 0 {
            return Err(MonitorValidationError::IntervalPrecision);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> Duration {
        self.0
    }

    pub fn as_millis(self) -> u64 {
        self.0
            .as_millis()
            .try_into()
            .expect("monitor interval is bounded to sixty seconds")
    }
}

impl Default for SamplingInterval {
    fn default() -> Self {
        Self(Duration::from_secs(1))
    }
}

impl FromStr for SamplingInterval {
    type Err = MonitorValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = humantime::parse_duration(value)
            .map_err(|_| MonitorValidationError::InvalidInterval)?;
        Self::new(value)
    }
}

impl Serialize for SamplingInterval {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.as_millis())
    }
}

impl<'de> Deserialize<'de> for SamplingInterval {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Duration::from_millis(u64::deserialize(deserializer)?))
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum InterfaceViewAnchor {
    Name { name: String },
    Ifindex { ifindex: IfIndex },
}

impl InterfaceViewAnchor {
    pub fn named(name: impl Into<String>) -> Result<Self, MonitorValidationError> {
        let anchor = Self::Name { name: name.into() };
        anchor.validate()?;
        Ok(anchor)
    }

    pub fn indexed(ifindex: u32) -> Result<Self, MonitorValidationError> {
        let ifindex =
            IfIndex::new(ifindex).map_err(|_| MonitorValidationError::InvalidInterfaceAnchor)?;
        Ok(Self::Ifindex { ifindex })
    }

    fn validate(&self) -> Result<(), MonitorValidationError> {
        match self {
            Self::Name { name }
                if name.is_ascii()
                    && name.len() <= MAX_LABEL_VALUE_BYTES
                    && valid_interface_name(name) =>
            {
                Ok(())
            }
            Self::Ifindex { .. } => Ok(()),
            Self::Name { .. } => Err(MonitorValidationError::InvalidInterfaceAnchor),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorPlan {
    #[serde(rename = "intervalMs")]
    interval: SamplingInterval,
    initial_section: MonitorSection,
    enabled_sections: BTreeSet<CollectionSection>,
    interface_anchor: Option<InterfaceViewAnchor>,
    #[serde(skip)]
    initial_page: Option<InitialPage>,
}

impl MonitorPlan {
    pub fn new(interval: SamplingInterval) -> Self {
        Self {
            interval,
            initial_section: MonitorSection::Overview,
            enabled_sections: CollectionSection::ALL.into_iter().collect(),
            interface_anchor: None,
            initial_page: None,
        }
    }

    pub fn from_parts(
        interval: SamplingInterval,
        initial_section: MonitorSection,
        enabled_sections: impl IntoIterator<Item = CollectionSection>,
        interface_anchor: Option<InterfaceViewAnchor>,
    ) -> Result<Self, MonitorValidationError> {
        let plan = Self {
            interval,
            initial_section,
            enabled_sections: enabled_sections.into_iter().collect(),
            interface_anchor,
            initial_page: None,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), MonitorValidationError> {
        SamplingInterval::new(self.interval.get())?;
        if self.enabled_sections.is_empty() {
            return Err(MonitorValidationError::EmptyEnabledSections);
        }
        if self.enabled_sections.len() > CollectionSection::ALL.len() {
            return Err(MonitorValidationError::TooManyEnabledSections);
        }
        if self
            .initial_section
            .collection_section()
            .is_some_and(|section| !self.enabled_sections.contains(&section))
        {
            return Err(MonitorValidationError::InitialSectionDisabled);
        }
        if let Some(anchor) = &self.interface_anchor {
            anchor.validate()?;
        }
        Ok(())
    }

    pub const fn interval(&self) -> SamplingInterval {
        self.interval
    }

    pub const fn initial_section(&self) -> MonitorSection {
        self.initial_section
    }

    pub fn enabled_sections(&self) -> &BTreeSet<CollectionSection> {
        &self.enabled_sections
    }

    pub fn interface_anchor(&self) -> Option<&InterfaceViewAnchor> {
        self.interface_anchor.as_ref()
    }

    pub fn with_initial_page(mut self, page: InitialPage) -> Self {
        self.initial_page = Some(page);
        self
    }

    pub const fn initial_page(&self) -> Option<InitialPage> {
        self.initial_page
    }
}

impl Default for MonitorPlan {
    fn default() -> Self {
        Self::new(SamplingInterval::default())
    }
}

impl<'de> Deserialize<'de> for MonitorPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WirePlan {
            #[serde(rename = "intervalMs")]
            interval: SamplingInterval,
            initial_section: MonitorSection,
            enabled_sections: Vec<CollectionSection>,
            interface_anchor: Option<InterfaceViewAnchor>,
        }

        let wire = WirePlan::deserialize(deserializer)?;
        let count = wire.enabled_sections.len();
        let enabled_sections: BTreeSet<_> = wire.enabled_sections.into_iter().collect();
        if enabled_sections.len() != count {
            return Err(serde::de::Error::custom(
                MonitorValidationError::DuplicateEnabledSection,
            ));
        }
        Self::from_parts(
            wire.interval,
            wire.initial_section,
            enabled_sections,
            wire.interface_anchor,
        )
        .map_err(serde::de::Error::custom)
    }
}

macro_rules! namespaced_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Ord, PartialOrd)]
        pub struct $name(Arc<str>, u64);

        impl PartialEq for $name {
            // Unsized Arc equality can compare contents even for shared allocations.
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.1 == other.1 && (Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0)
            }
        }

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                state.write_u64(self.1);
            }
        }

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, MonitorValidationError> {
                let value = value.into();
                if valid_namespaced_id(&value) {
                    let mut hasher = DefaultHasher::new();
                    value.hash(&mut hasher);
                    Ok(Self(value.into(), hasher.finish()))
                } else {
                    Err(MonitorValidationError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

namespaced_id!(ProviderId);

#[derive(Clone)]
pub struct MetricId {
    name: ProviderId,
    descriptor: Option<&'static super::catalog::MetricDescriptor>,
}

impl MetricId {
    pub fn new(value: impl Into<String>) -> Result<Self, MonitorValidationError> {
        let name = ProviderId::new(value)?;
        let descriptor = super::catalog::descriptor(name.as_str());
        Ok(Self { name, descriptor })
    }

    pub fn as_str(&self) -> &str {
        self.name.as_str()
    }

    pub fn descriptor(&self) -> Option<&'static super::catalog::MetricDescriptor> {
        self.descriptor
    }
}

impl fmt::Debug for MetricId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("MetricId")
            .field(&self.name.0)
            .field(&self.name.1)
            .finish()
    }
}

impl PartialEq for MetricId {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for MetricId {}

impl Ord for MetricId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for MetricId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for MetricId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

fn valid_namespaced_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ID_BYTES || !value.is_ascii() {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if !valid_id_segment(first, true) {
        return false;
    }
    let mut saw_namespace = false;
    for segment in segments {
        saw_namespace = true;
        if !valid_id_segment(segment, false) {
            return false;
        }
    }
    saw_namespace
}

fn valid_id_segment(value: &str, require_lowercase_start: bool) -> bool {
    !value.is_empty()
        && (!require_lowercase_start || value.as_bytes()[0].is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricLabel {
    Interface,
    Ifindex,
    Cpu,
    Protocol,
    IpVersion,
    Direction,
    Backend,
    Family,
    Table,
    Chain,
    Hook,
    Priority,
    Handle,
    Verdict,
    ObjectKind,
    QdiscKind,
    QdiscAttachment,
    RowId,
    Execution,
    Action,
    Statistic,
    InterruptClass,
}

impl MetricLabel {
    pub const ALL: [Self; 22] = [
        Self::Interface,
        Self::Ifindex,
        Self::Cpu,
        Self::Protocol,
        Self::IpVersion,
        Self::Direction,
        Self::Backend,
        Self::Family,
        Self::Table,
        Self::Chain,
        Self::Hook,
        Self::Priority,
        Self::Handle,
        Self::Verdict,
        Self::ObjectKind,
        Self::QdiscKind,
        Self::QdiscAttachment,
        Self::RowId,
        Self::Execution,
        Self::Action,
        Self::Statistic,
        Self::InterruptClass,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interface => "interface",
            Self::Ifindex => "ifindex",
            Self::Cpu => "cpu",
            Self::Protocol => "protocol",
            Self::IpVersion => "ip_version",
            Self::Direction => "direction",
            Self::Backend => "backend",
            Self::Family => "family",
            Self::Table => "table",
            Self::Chain => "chain",
            Self::Hook => "hook",
            Self::Priority => "priority",
            Self::Handle => "handle",
            Self::Verdict => "verdict",
            Self::ObjectKind => "object_kind",
            Self::QdiscKind => "qdisc_kind",
            Self::QdiscAttachment => "qdisc_attachment",
            Self::RowId => "row_id",
            Self::Execution => "execution",
            Self::Action => "action",
            Self::Statistic => "statistic",
            Self::InterruptClass => "interrupt_class",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialOrd)]
pub struct MetricLabels(Arc<[(MetricLabel, String)]>, u64);

impl PartialEq for MetricLabels {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.1 == other.1 && (Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0)
    }
}

impl Default for MetricLabels {
    fn default() -> Self {
        Self::new([]).expect("empty labels are valid")
    }
}

impl Hash for MetricLabels {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Labels are immutable and are looked up in several indices every sample.
        state.write_u64(self.1);
    }
}

impl MetricLabels {
    pub fn new(
        labels: impl IntoIterator<Item = (MetricLabel, String)>,
    ) -> Result<Self, MonitorValidationError> {
        let mut values = Vec::new();
        for (label, value) in labels {
            if values.len() == MAX_LABELS_PER_READING {
                return Err(MonitorValidationError::TooManyLabels);
            }
            validate_label_value(label, &value)?;
            match values.binary_search_by_key(&label, |(key, _)| *key) {
                Ok(_) => return Err(MonitorValidationError::DuplicateLabel),
                Err(index) => values.insert(index, (label, value)),
            }
        }
        let mut hasher = DefaultHasher::new();
        values.hash(&mut hasher);
        Ok(Self(values.into(), hasher.finish()))
    }

    pub fn get(&self, label: MetricLabel) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| *key == label)
            .map(|(_, value)| value.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (MetricLabel, &str)> {
        self.0.iter().map(|(label, value)| (*label, value.as_str()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn validate_label_value(label: MetricLabel, value: &str) -> Result<(), MonitorValidationError> {
    let bounded = valid_printable_ascii(value, MAX_LABEL_VALUE_BYTES);
    let valid = match label {
        MetricLabel::Interface => {
            value.is_ascii() && value.len() < libc::IFNAMSIZ && valid_interface_name(value)
        }
        MetricLabel::Ifindex => value
            .parse::<u32>()
            .ok()
            .and_then(|value| IfIndex::new(value).ok())
            .is_some(),
        MetricLabel::Cpu => value.parse::<u32>().is_ok(),
        MetricLabel::Protocol => matches!(
            value,
            "ip" | "ipv6" | "tcp" | "tcp6" | "udp" | "udp6" | "icmp" | "icmp6"
        ),
        MetricLabel::IpVersion => matches!(value, "4" | "6"),
        MetricLabel::Direction => matches!(value, "ingress" | "egress" | "rx" | "tx"),
        MetricLabel::Backend => matches!(
            value,
            "nftables" | "iptables_nft" | "iptables_legacy" | "iptables_unknown"
        ),
        MetricLabel::Family => matches!(value, "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev"),
        MetricLabel::Hook => matches!(
            value,
            "prerouting" | "input" | "forward" | "output" | "postrouting" | "ingress" | "egress"
        ),
        MetricLabel::Priority => value.parse::<i32>().is_ok(),
        MetricLabel::Handle => value.parse::<u64>().is_ok(),
        MetricLabel::Verdict => matches!(
            value,
            "accept"
                | "continue"
                | "drop"
                | "goto"
                | "jump"
                | "queue"
                | "reject"
                | "return"
                | "unknown"
        ),
        MetricLabel::ObjectKind => matches!(
            value,
            "action"
                | "chain"
                | "class"
                | "conntrack"
                | "device"
                | "filter"
                | "interrupt"
                | "qdisc"
                | "rule"
        ),
        MetricLabel::RowId => value.parse::<u64>().is_ok_and(|value| value > 0),
        MetricLabel::Execution => matches!(value, "software" | "hardware" | "unknown"),
        // One bounded tuple preserves root/handle/parent within the eight-label budget.
        // Two 128-byte identity parts can each double in size under JSON escaping.
        MetricLabel::QdiscAttachment => {
            valid_printable_ascii(value, 544)
                && serde_json::from_str::<(bool, Option<String>, Option<String>)>(value).is_ok_and(
                    |(_, handle, parent)| {
                        [handle, parent].iter().flatten().all(|part| {
                            !part.is_empty()
                                && part.len() <= MAX_LABEL_VALUE_BYTES
                                && part.bytes().all(|byte| byte.is_ascii_graphic())
                        })
                    },
                )
        }
        MetricLabel::Action => matches!(
            value,
            "drop"
                | "goto"
                | "mirror"
                | "pass"
                | "pipe"
                | "police"
                | "redirect"
                | "trap"
                | "unknown"
        ),
        MetricLabel::Table
        | MetricLabel::Chain
        | MetricLabel::QdiscKind
        | MetricLabel::Statistic
        | MetricLabel::InterruptClass => bounded,
    };
    if valid {
        Ok(())
    } else {
        Err(MonitorValidationError::InvalidLabelValue { label })
    }
}

#[cfg(test)]
mod tc_label_tests {
    use super::*;

    #[test]
    fn attachment_preserves_bounded_handle_parent_and_root_without_relaxing_other_labels() {
        for attachment in [
            (true, None, None),
            (false, Some("0:".to_owned()), Some(":1".to_owned())),
            (false, Some("\\".repeat(128)), Some("\"".repeat(128))),
        ] {
            let value = serde_json::to_string(&attachment).unwrap();
            assert!(MetricLabels::new([(MetricLabel::QdiscAttachment, value)]).is_ok());
        }
        for value in [
            "[]",
            "true",
            "[true,0,null]",
            "[true,\"\",null]",
            "[true,\"bad name\",null]",
        ] {
            assert!(MetricLabels::new([(MetricLabel::QdiscAttachment, value.to_owned())]).is_err());
        }
        let too_long = serde_json::to_string(&(false, "x".repeat(129), "1:1")).unwrap();
        assert!(MetricLabels::new([(MetricLabel::QdiscAttachment, too_long)]).is_err());
        assert!(MetricLabels::new([(MetricLabel::Handle, "1:".to_owned())]).is_err());
        assert!(MetricLabels::new([(MetricLabel::QdiscKind, "x".repeat(129))]).is_err());
    }
}

fn valid_printable_ascii(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricKind {
    Counter,
    Gauge,
    State,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricUnit {
    Occurrences,
    Bytes,
    Pages,
    BasisPoints,
    State,
    SourceUnits,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MetricScope {
    NetworkNamespace,
    Host,
    Cpu,
    Interface,
    Chain,
    Rule,
    TrafficControlObject,
    Source,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AggregationDomain {
    Connection,
    Socket,
    IpPacket,
    TcpSegment,
    Datagram,
    InterfacePacket,
    WireFrame,
    QueueEntry,
    PolicyHit,
    ConntrackEntry,
    Interrupt,
    PollCycle,
    FecCodeword,
    Memory,
    SourceStatistic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregationPolicy {
    None,
    Sum {
        target_scope: MetricScope,
        reducible_labels: &'static [MetricLabel],
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DisplayMeaning {
    Activity,
    Drop,
    Error,
    Pressure,
    Capacity,
    Correction,
    State,
    InformationOnly,
}

impl DisplayMeaning {
    pub const fn higher_is_worse(self) -> bool {
        matches!(self, Self::Drop | Self::Error | Self::Pressure)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateValue(String);

impl StateValue {
    pub fn new(value: impl Into<String>) -> Result<Self, MonitorValidationError> {
        let value = value.into();
        if valid_printable_ascii(&value, MAX_LABEL_VALUE_BYTES) {
            Ok(Self(value))
        } else {
            Err(MonitorValidationError::InvalidStateValue)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricReading {
    Counter {
        value: u64,
        bits: Option<CounterBits>,
    },
    Gauge(u64),
    State(StateValue),
}

impl MetricReading {
    pub const fn kind(&self) -> MetricKind {
        match self {
            Self::Counter { .. } => MetricKind::Counter,
            Self::Gauge(_) => MetricKind::Gauge,
            Self::State(_) => MetricKind::State,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CounterBits {
    Bits32,
    Bits64,
}

impl CounterBits {
    pub const fn get(self) -> u8 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UnavailableReason {
    Missing,
    NegativeSentinel,
    InvalidValue,
    Overflow,
    NotApplicable,
    CardinalityLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadingOutcome {
    Observed(MetricReading),
    Unavailable(UnavailableReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleReading {
    metric: MetricId,
    labels: MetricLabels,
    outcome: ReadingOutcome,
}

impl SampleReading {
    pub fn observed(metric: MetricId, labels: MetricLabels, reading: MetricReading) -> Self {
        Self {
            metric,
            labels,
            outcome: ReadingOutcome::Observed(reading),
        }
    }

    pub fn unavailable(metric: MetricId, labels: MetricLabels, reason: UnavailableReason) -> Self {
        Self {
            metric,
            labels,
            outcome: ReadingOutcome::Unavailable(reason),
        }
    }

    pub fn metric(&self) -> &MetricId {
        &self.metric
    }

    pub fn labels(&self) -> &MetricLabels {
        &self.labels
    }

    pub fn outcome(&self) -> &ReadingOutcome {
        &self.outcome
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MonitorErrorCode {
    Unsupported,
    PermissionDenied,
    NotFound,
    Parse,
    Io,
    Timeout,
    OutputLimit,
    SchemaMismatch,
    CardinalityLimit,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorError {
    code: MonitorErrorCode,
    diagnostic: String,
}

impl MonitorError {
    pub fn new(
        code: MonitorErrorCode,
        diagnostic: impl Into<String>,
    ) -> Result<Self, MonitorValidationError> {
        let diagnostic = diagnostic.into();
        if !valid_printable_ascii(&diagnostic, MAX_DIAGNOSTIC_BYTES) {
            return Err(MonitorValidationError::InvalidDiagnostic);
        }
        Ok(Self { code, diagnostic })
    }

    pub const fn code(&self) -> MonitorErrorCode {
        self.code
    }

    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderHealth {
    Fresh,
    Partial {
        warning: MonitorError,
    },
    Stale {
        last_success_at: Duration,
        age: Duration,
        cause: MonitorError,
    },
    Unsupported {
        reason: MonitorError,
    },
    PermissionDenied {
        reason: MonitorError,
    },
    Error {
        error: MonitorError,
    },
}

impl ProviderHealth {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Partial { .. } => "partial",
            Self::Stale { .. } => "stale",
            Self::Unsupported { .. } => "unsupported",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::Error { .. } => "error",
        }
    }

    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }

    pub const fn allows_readings(&self) -> bool {
        matches!(self, Self::Fresh | Self::Partial { .. })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSample {
    provider: ProviderId,
    finished_at: Duration,
    collection_duration: Duration,
    health: ProviderHealth,
    readings: Arc<Vec<SampleReading>>,
}

impl ProviderSample {
    pub fn new(
        provider: ProviderId,
        finished_at: Duration,
        collection_duration: Duration,
        health: ProviderHealth,
        mut readings: Vec<SampleReading>,
    ) -> Result<Self, MonitorValidationError> {
        validate_sample_metadata(finished_at, collection_duration, &health, readings.len())?;

        for reading in &readings {
            crate::monitor::catalog::validate_sample_reading(&provider, reading)?;
        }
        readings.sort_unstable_by(|left, right| {
            (&left.metric, &left.labels).cmp(&(&right.metric, &right.labels))
        });
        if readings
            .windows(2)
            .any(|pair| pair[0].metric == pair[1].metric && pair[0].labels == pair[1].labels)
        {
            return Err(MonitorValidationError::DuplicateReading);
        }

        Ok(Self::from_validated(
            provider,
            finished_at,
            collection_duration,
            health,
            readings,
        ))
    }

    // The prior immutable sample proves identity validity, order and uniqueness.
    // Only provider caches opting into this path may reuse that proof.
    pub(super) fn refresh(
        &self,
        provider: ProviderId,
        finished_at: Duration,
        collection_duration: Duration,
        health: ProviderHealth,
        readings: Vec<SampleReading>,
    ) -> Result<Self, MonitorValidationError> {
        validate_sample_metadata(finished_at, collection_duration, &health, readings.len())?;
        let same_layout = self.provider == provider
            && self.readings.len() == readings.len()
            && self
                .readings
                .iter()
                .zip(&readings)
                .all(|(previous, current)| {
                    previous.metric == current.metric && previous.labels == current.labels
                });
        if !same_layout {
            return Self::new(provider, finished_at, collection_duration, health, readings);
        }
        for reading in &readings {
            crate::monitor::catalog::validate_sample_outcome(reading)?;
        }
        Ok(Self::from_validated(
            provider,
            finished_at,
            collection_duration,
            health,
            readings,
        ))
    }

    fn from_validated(
        provider: ProviderId,
        finished_at: Duration,
        collection_duration: Duration,
        health: ProviderHealth,
        mut readings: Vec<SampleReading>,
    ) -> Self {
        // Share the owned allocation instead of copying every reading into an
        // Arc slice. Do not retain oversized caller-provided spare capacity.
        if readings.capacity() > MAX_READINGS_PER_PROVIDER {
            readings.shrink_to_fit();
        }

        Self {
            provider,
            finished_at,
            collection_duration,
            health,
            readings: Arc::new(readings),
        }
    }

    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub const fn finished_at(&self) -> Duration {
        self.finished_at
    }

    pub const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub fn health(&self) -> &ProviderHealth {
        &self.health
    }

    pub fn readings(&self) -> &[SampleReading] {
        &self.readings
    }
}

fn validate_sample_metadata(
    finished_at: Duration,
    collection_duration: Duration,
    health: &ProviderHealth,
    reading_count: usize,
) -> Result<(), MonitorValidationError> {
    validate_monotonic(finished_at)?;
    validate_monotonic(collection_duration)?;
    if collection_duration > finished_at {
        return Err(MonitorValidationError::InvalidTimestamp);
    }
    validate_health(health, finished_at)?;
    if !health.allows_readings() && reading_count != 0 {
        return Err(MonitorValidationError::NonFreshProviderHasReadings);
    }
    if reading_count > MAX_READINGS_PER_PROVIDER {
        return Err(MonitorValidationError::TooManyProviderReadings);
    }
    Ok(())
}

fn validate_health(
    health: &ProviderHealth,
    finished_at: Duration,
) -> Result<(), MonitorValidationError> {
    match health {
        ProviderHealth::Fresh | ProviderHealth::Partial { .. } => Ok(()),
        ProviderHealth::Stale {
            last_success_at,
            age,
            ..
        } if *last_success_at <= finished_at
            && finished_at.checked_sub(*last_success_at) == Some(*age) =>
        {
            Ok(())
        }
        ProviderHealth::Unsupported { reason }
            if reason.code() == MonitorErrorCode::Unsupported =>
        {
            Ok(())
        }
        ProviderHealth::PermissionDenied { reason }
            if reason.code() == MonitorErrorCode::PermissionDenied =>
        {
            Ok(())
        }
        ProviderHealth::Error { error }
            if !matches!(
                error.code(),
                MonitorErrorCode::Unsupported | MonitorErrorCode::PermissionDenied
            ) =>
        {
            Ok(())
        }
        _ => Err(MonitorValidationError::InvalidProviderHealth),
    }
}

fn validate_monotonic(value: Duration) -> Result<(), MonitorValidationError> {
    if value.as_nanos() <= u128::from(u64::MAX) {
        Ok(())
    } else {
        Err(MonitorValidationError::InvalidTimestamp)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectedValue<T> {
    Fresh {
        value: T,
        observed_at: Duration,
    },
    Stale {
        last: T,
        observed_at: Duration,
        age: Duration,
        cause: MonitorErrorCode,
    },
    Unavailable {
        reason: UnavailableReason,
    },
}

impl<T> ProjectedValue<T> {
    fn validate_at(&self, elapsed: Duration) -> Result<(), MonitorValidationError> {
        match self {
            Self::Fresh { observed_at, .. } if *observed_at <= elapsed => Ok(()),
            Self::Stale {
                observed_at, age, ..
            } if *observed_at <= elapsed && elapsed.checked_sub(*observed_at) == Some(*age) => {
                Ok(())
            }
            Self::Unavailable { .. } => Ok(()),
            _ => Err(MonitorValidationError::InvalidProjectedValue),
        }
    }

    fn observed_at(&self) -> Option<Duration> {
        match self {
            Self::Fresh { observed_at, .. } | Self::Stale { observed_at, .. } => Some(*observed_at),
            Self::Unavailable { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaselineOrigin {
    SessionStart,
    FirstObserved,
    Reset,
    RecoveredAfterGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterContinuity {
    FirstSample,
    Continuous {
        delta: u64,
        elapsed: Duration,
    },
    Wrapped {
        delta: u64,
        elapsed: Duration,
        bits: CounterBits,
    },
    Reset,
    RecoveredAfterGap,
}

impl CounterContinuity {
    pub fn rate_per_second(self) -> Option<f64> {
        let (delta, elapsed) = match self {
            Self::Continuous { delta, elapsed } | Self::Wrapped { delta, elapsed, .. } => {
                (delta, elapsed)
            }
            Self::FirstSample | Self::Reset | Self::RecoveredAfterGap => return None,
        };
        (elapsed > Duration::ZERO).then(|| delta as f64 / elapsed.as_secs_f64())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CounterSpan {
    delta: u64,
    elapsed: Duration,
}

impl CounterSpan {
    pub fn new(delta: u64, elapsed: Duration) -> Result<Self, MonitorValidationError> {
        if elapsed == Duration::ZERO {
            return Err(MonitorValidationError::InvalidSeriesProjection);
        }
        Ok(Self { delta, elapsed })
    }

    pub const fn delta(self) -> u64 {
        self.delta
    }

    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    pub fn rate_per_second(self) -> f64 {
        self.delta as f64 / self.elapsed.as_secs_f64()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GaugeChange {
    delta: i128,
    elapsed: Duration,
}

impl GaugeChange {
    pub fn new(delta: i128, elapsed: Duration) -> Result<Self, MonitorValidationError> {
        if elapsed == Duration::ZERO {
            return Err(MonitorValidationError::InvalidSeriesProjection);
        }
        Ok(Self { delta, elapsed })
    }

    pub const fn delta(self) -> i128 {
        self.delta
    }

    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    pub fn rate_per_second(self) -> f64 {
        self.delta as f64 / self.elapsed.as_secs_f64()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GaugeSummary {
    min: u64,
    max: u64,
    sum: u128,
    count: u64,
    elapsed: Duration,
}

impl GaugeSummary {
    pub fn new(
        min: u64,
        max: u64,
        sum: u128,
        count: u64,
        elapsed: Duration,
    ) -> Result<Self, MonitorValidationError> {
        if min > max
            || count == 0
            || sum < u128::from(min) * u128::from(count)
            || sum > u128::from(max) * u128::from(count)
        {
            return Err(MonitorValidationError::InvalidSeriesProjection);
        }
        Ok(Self {
            min,
            max,
            sum,
            count,
            elapsed,
        })
    }

    pub const fn min(self) -> u64 {
        self.min
    }

    pub const fn max(self) -> u64 {
        self.max
    }

    pub const fn count(self) -> u64 {
        self.count
    }

    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    pub fn average(self) -> f64 {
        self.sum as f64 / self.count as f64
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SeriesValue {
    Counter {
        current: ProjectedValue<u64>,
        interval: Option<CounterContinuity>,
        since_baseline: Option<CounterSpan>,
    },
    Gauge {
        current: ProjectedValue<u64>,
        interval: Option<GaugeChange>,
        since_baseline: Option<GaugeSummary>,
    },
    State {
        current: ProjectedValue<StateValue>,
        changed_at: Option<Duration>,
        continuous_for: Option<Duration>,
    },
}

impl SeriesValue {
    pub const fn kind(&self) -> MetricKind {
        match self {
            Self::Counter { .. } => MetricKind::Counter,
            Self::Gauge { .. } => MetricKind::Gauge,
            Self::State { .. } => MetricKind::State,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SeriesId(u64);

impl SeriesId {
    pub fn new(value: u64) -> Result<Self, MonitorValidationError> {
        if value == 0 {
            Err(MonitorValidationError::InvalidSeriesId)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryCoverage {
    start: Option<Duration>,
    end: Option<Duration>,
    resolution: Duration,
    bucket_count: u64,
    gaps: u64,
    compacted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryBucket {
    pub(crate) start: Duration,
    pub(crate) end: Duration,
    pub(crate) min: u64,
    pub(crate) max: u64,
    pub(crate) first: u64,
    pub(crate) last: u64,
    pub(crate) sum: u128,
    pub(crate) count: u64,
    pub(crate) delta: u64,
    pub(crate) trend_delta: u64,
    pub(crate) trend_elapsed: Duration,
    pub(crate) resets: u64,
    pub(crate) gaps: u64,
}

impl HistoryBucket {
    pub const fn start(self) -> Duration {
        self.start
    }

    pub const fn end(self) -> Duration {
        self.end
    }

    pub const fn min(self) -> u64 {
        self.min
    }

    pub const fn max(self) -> u64 {
        self.max
    }

    pub const fn first(self) -> u64 {
        self.first
    }

    pub const fn last(self) -> u64 {
        self.last
    }

    pub const fn count(self) -> u64 {
        self.count
    }

    pub const fn delta(self) -> u64 {
        self.delta
    }

    pub fn trend_rate_per_second(self) -> Option<f64> {
        (self.trend_elapsed > Duration::ZERO)
            .then(|| self.trend_delta as f64 / self.trend_elapsed.as_secs_f64())
    }

    pub const fn resets(self) -> u64 {
        self.resets
    }

    pub const fn gaps(self) -> u64 {
        self.gaps
    }

    pub(super) fn validate(self) -> Result<(), MonitorValidationError> {
        let observed_shape = self.count > 0
            && self.min <= self.first
            && self.first <= self.max
            && self.min <= self.last
            && self.last <= self.max
            && self.sum >= u128::from(self.min) * u128::from(self.count)
            && self.sum <= u128::from(self.max) * u128::from(self.count)
            && self.trend_elapsed <= self.end.saturating_sub(self.start)
            && self.resets <= self.count;
        let gap_only_shape = self.count == 0
            && self.min == 0
            && self.max == 0
            && self.first == 0
            && self.last == 0
            && self.sum == 0
            && self.delta == 0
            && self.trend_delta == 0
            && self.trend_elapsed == Duration::ZERO
            && self.resets == 0
            && self.gaps > 0;
        if self.start <= self.end && (observed_shape || gap_only_shape) {
            Ok(())
        } else {
            Err(MonitorValidationError::InvalidHistoryBucket)
        }
    }
}

impl HistoryCoverage {
    pub const fn empty() -> Self {
        Self {
            start: None,
            end: None,
            resolution: Duration::ZERO,
            bucket_count: 0,
            gaps: 0,
            compacted: false,
        }
    }

    pub fn new(
        start: Duration,
        end: Duration,
        resolution: Duration,
        bucket_count: u64,
        gaps: u64,
        compacted: bool,
    ) -> Result<Self, MonitorValidationError> {
        if start > end || resolution == Duration::ZERO || bucket_count == 0 {
            return Err(MonitorValidationError::InvalidHistoryCoverage);
        }
        Ok(Self {
            start: Some(start),
            end: Some(end),
            resolution,
            bucket_count,
            gaps,
            compacted,
        })
    }

    pub const fn start(self) -> Option<Duration> {
        self.start
    }

    pub const fn end(self) -> Option<Duration> {
        self.end
    }

    pub const fn resolution(self) -> Duration {
        self.resolution
    }

    pub const fn bucket_count(self) -> u64 {
        self.bucket_count
    }

    pub const fn gaps(self) -> u64 {
        self.gaps
    }

    pub const fn compacted(self) -> bool {
        self.compacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeriesSnapshot(Arc<SeriesSnapshotData>);

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeriesSnapshotData {
    id: SeriesId,
    provider: ProviderId,
    source: ProviderId,
    metric: MetricId,
    labels: MetricLabels,
    first_seen: Duration,
    baseline_origin: BaselineOrigin,
    baseline_at: Duration,
    value: SeriesValue,
    history: HistoryCoverage,
    history_buckets: Vec<HistoryBucket>,
}

impl SeriesSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: SeriesId,
        provider: ProviderId,
        source: ProviderId,
        metric: MetricId,
        labels: MetricLabels,
        first_seen: Duration,
        baseline_origin: BaselineOrigin,
        baseline_at: Duration,
        value: SeriesValue,
        history: HistoryCoverage,
    ) -> Result<Self, MonitorValidationError> {
        crate::monitor::catalog::validate_series(&provider, &source, &metric, &labels, &value)?;
        validate_baseline(first_seen, baseline_origin, baseline_at)?;
        Ok(Self(Arc::new(SeriesSnapshotData {
            id,
            provider,
            source,
            metric,
            labels,
            first_seen,
            baseline_origin,
            baseline_at,
            value,
            history,
            history_buckets: Vec::new(),
        })))
    }

    pub(super) fn with_history(
        mut self,
        history: super::history::HistoryProjection<'_>,
    ) -> Result<Self, MonitorValidationError> {
        replace_history(Arc::make_mut(&mut self.0), history)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn reproject(
        mut self,
        source: &ProviderId,
        baseline_origin: BaselineOrigin,
        baseline_at: Duration,
        value: SeriesValue,
        history: super::history::HistoryProjection<'_>,
    ) -> Result<Self, MonitorValidationError> {
        let source_changed = self.0.source != *source;
        if !source_changed {
            // Identity fields are immutable and were validated at construction.
            // Current values still need kind, state and raw-metric checks.
            crate::monitor::catalog::validate_series_projection(&self.0.metric, &value)?;
        } else {
            crate::monitor::catalog::validate_series(
                &self.0.provider,
                source,
                &self.0.metric,
                &self.0.labels,
                &value,
            )?;
        }
        validate_baseline(self.0.first_seen, baseline_origin, baseline_at)?;
        // A retained snapshot must stay immutable. Build its replacement without
        // cloning the old value/history, which this projection will overwrite.
        let Some(data) = Arc::get_mut(&mut self.0) else {
            let previous = &self.0;
            let mut data = SeriesSnapshotData {
                id: previous.id,
                provider: previous.provider.clone(),
                source: if source_changed {
                    source.clone()
                } else {
                    previous.source.clone()
                },
                metric: previous.metric.clone(),
                labels: previous.labels.clone(),
                first_seen: previous.first_seen,
                baseline_origin,
                baseline_at,
                value,
                history: HistoryCoverage::empty(),
                history_buckets: Vec::new(),
            };
            replace_history(&mut data, history)?;
            return Ok(Self(Arc::new(data)));
        };
        if source_changed {
            data.source = source.clone();
        }
        data.baseline_origin = baseline_origin;
        data.baseline_at = baseline_at;
        data.value = value;
        replace_history(data, history)?;
        Ok(self)
    }

    fn validate_at(&self, elapsed: Duration) -> Result<(), MonitorValidationError> {
        let data = &self.0;
        if data.first_seen > data.baseline_at || data.baseline_at > elapsed {
            return Err(MonitorValidationError::InvalidSeriesProjection);
        }
        if data
            .history
            .start()
            .is_some_and(|start| start < data.first_seen)
            || data.history.end().is_some_and(|end| end > elapsed)
        {
            return Err(MonitorValidationError::InvalidHistoryCoverage);
        }
        // HistoryProjection preserves validation across every history mutation.
        if data
            .history_buckets
            .first()
            .is_some_and(|bucket| bucket.start() < data.first_seen)
            || data
                .history_buckets
                .last()
                .is_some_and(|bucket| bucket.end() > elapsed)
        {
            return Err(MonitorValidationError::InvalidHistoryBucket);
        }
        validate_series_value(&data.value, data.baseline_origin, data.baseline_at, elapsed)
    }

    pub fn id(&self) -> SeriesId {
        self.0.id
    }

    pub fn provider(&self) -> &ProviderId {
        &self.0.provider
    }

    pub fn source(&self) -> &ProviderId {
        &self.0.source
    }

    pub fn metric(&self) -> &MetricId {
        &self.0.metric
    }

    pub fn labels(&self) -> &MetricLabels {
        &self.0.labels
    }

    pub fn first_seen(&self) -> Duration {
        self.0.first_seen
    }

    pub fn baseline_origin(&self) -> BaselineOrigin {
        self.0.baseline_origin
    }

    pub fn baseline_at(&self) -> Duration {
        self.0.baseline_at
    }

    pub fn value(&self) -> &SeriesValue {
        &self.0.value
    }

    pub fn history(&self) -> HistoryCoverage {
        self.0.history
    }

    pub fn history_buckets(&self) -> &[HistoryBucket] {
        &self.0.history_buckets
    }
}

fn replace_history(
    data: &mut SeriesSnapshotData,
    history: super::history::HistoryProjection<'_>,
) -> Result<(), MonitorValidationError> {
    let (coverage, buckets) = history.validated_parts()?;
    if buckets.0.len().saturating_add(buckets.1.len()) > MAX_HISTORY_BUCKETS_PER_SERIES {
        return Err(MonitorValidationError::InvalidHistoryBucket);
    }
    data.history = coverage;
    data.history_buckets.clear();
    if !buckets.0.is_empty() || !buckets.1.is_empty() {
        data.history_buckets
            .reserve_exact(MAX_HISTORY_BUCKETS_PER_SERIES);
    }
    data.history_buckets.extend_from_slice(buckets.0);
    data.history_buckets.extend_from_slice(buckets.1);
    Ok(())
}

#[cfg(test)]
pub(super) fn validate_history_buckets(
    history: HistoryCoverage,
    buckets: &[HistoryBucket],
) -> Result<(), MonitorValidationError> {
    if buckets.len() > MAX_HISTORY_BUCKETS_PER_SERIES
        || history.bucket_count() != buckets.len() as u64
        || buckets
            .windows(2)
            .any(|pair| pair[0].end() > pair[1].start())
        || buckets
            .iter()
            .copied()
            .any(|bucket| bucket.validate().is_err())
        || buckets
            .first()
            .is_some_and(|bucket| Some(bucket.start()) != history.start())
        || buckets
            .last()
            .is_some_and(|bucket| Some(bucket.end()) != history.end())
    {
        return Err(MonitorValidationError::InvalidHistoryBucket);
    }
    Ok(())
}

fn validate_baseline(
    first_seen: Duration,
    origin: BaselineOrigin,
    baseline_at: Duration,
) -> Result<(), MonitorValidationError> {
    let valid = match origin {
        BaselineOrigin::SessionStart => {
            first_seen == Duration::ZERO && baseline_at == Duration::ZERO
        }
        BaselineOrigin::FirstObserved => first_seen > Duration::ZERO && baseline_at == first_seen,
        BaselineOrigin::Reset | BaselineOrigin::RecoveredAfterGap => baseline_at > first_seen,
    };
    if valid {
        Ok(())
    } else {
        Err(MonitorValidationError::InvalidBaseline)
    }
}

fn validate_series_value(
    value: &SeriesValue,
    baseline_origin: BaselineOrigin,
    baseline_at: Duration,
    elapsed: Duration,
) -> Result<(), MonitorValidationError> {
    match value {
        SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        } => {
            current.validate_at(elapsed)?;
            if !matches!(current, ProjectedValue::Fresh { .. }) && interval.is_some() {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if let Some(interval) = interval {
                match interval {
                    CounterContinuity::Continuous {
                        elapsed: interval, ..
                    }
                    | CounterContinuity::Wrapped {
                        elapsed: interval, ..
                    } if *interval == Duration::ZERO || *interval > elapsed => {
                        return Err(MonitorValidationError::InvalidSeriesProjection)
                    }
                    CounterContinuity::Reset if baseline_origin != BaselineOrigin::Reset => {
                        return Err(MonitorValidationError::InvalidSeriesProjection)
                    }
                    CounterContinuity::RecoveredAfterGap
                        if baseline_origin != BaselineOrigin::RecoveredAfterGap =>
                    {
                        return Err(MonitorValidationError::InvalidSeriesProjection)
                    }
                    CounterContinuity::FirstSample
                        if !matches!(
                            baseline_origin,
                            BaselineOrigin::SessionStart | BaselineOrigin::FirstObserved
                        ) =>
                    {
                        return Err(MonitorValidationError::InvalidSeriesProjection)
                    }
                    _ => {}
                }
            }
            if matches!(interval, Some(CounterContinuity::FirstSample)) && since_baseline.is_some()
            {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if matches!(
                interval,
                Some(CounterContinuity::Reset | CounterContinuity::RecoveredAfterGap)
            ) && since_baseline.is_some()
            {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if let Some(span) = since_baseline {
                let Some(observed_at) = current.observed_at() else {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                };
                if observed_at.checked_sub(baseline_at) != Some(span.elapsed()) {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                }
            }
        }
        SeriesValue::Gauge {
            current,
            interval,
            since_baseline,
        } => {
            current.validate_at(elapsed)?;
            if !matches!(current, ProjectedValue::Fresh { .. }) && interval.is_some() {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if interval.is_some_and(|change| change.elapsed() > elapsed) {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if let Some(summary) = since_baseline {
                let Some(observed_at) = current.observed_at() else {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                };
                if observed_at.checked_sub(baseline_at) != Some(summary.elapsed()) {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                }
            }
        }
        SeriesValue::State {
            current,
            changed_at,
            continuous_for,
        } => {
            current.validate_at(elapsed)?;
            if changed_at.is_some_and(|changed| changed > elapsed)
                || continuous_for.is_some_and(|duration| duration > elapsed)
                || (!matches!(current, ProjectedValue::Fresh { .. }) && continuous_for.is_some())
            {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
            if let Some(continuous_for) = continuous_for {
                let Some(observed_at) = current.observed_at() else {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                };
                let continuity_start = changed_at.unwrap_or(baseline_at);
                if continuity_start < baseline_at
                    || observed_at.checked_sub(continuity_start) != Some(*continuous_for)
                {
                    return Err(MonitorValidationError::InvalidSeriesProjection);
                }
            }
        }
    }
    if let Some(observed_at) = match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            current.observed_at()
        }
        SeriesValue::State { current, .. } => current.observed_at(),
    } {
        validate_monotonic(observed_at)?;
    }
    Ok(())
}

fn series_matches_provider_health(value: &SeriesValue, health: &ProviderHealth) -> bool {
    let current_is_fresh = match value {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            matches!(current, ProjectedValue::Fresh { .. })
        }
        SeriesValue::State { current, .. } => matches!(current, ProjectedValue::Fresh { .. }),
    };
    match health {
        ProviderHealth::Fresh | ProviderHealth::Partial { .. } => true,
        ProviderHealth::Stale { .. } => !current_is_fresh,
        ProviderHealth::Unsupported { .. }
        | ProviderHealth::PermissionDenied { .. }
        | ProviderHealth::Error { .. } => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSnapshot {
    provider: ProviderId,
    health: ProviderHealth,
    last_attempt_at: Duration,
    collection_duration: Duration,
    unavailable_readings: u32,
}

impl ProviderSnapshot {
    pub fn new(
        provider: ProviderId,
        health: ProviderHealth,
        last_attempt_at: Duration,
        collection_duration: Duration,
        unavailable_readings: u32,
    ) -> Result<Self, MonitorValidationError> {
        validate_monotonic(last_attempt_at)?;
        if collection_duration > last_attempt_at {
            return Err(MonitorValidationError::InvalidTimestamp);
        }
        validate_health(&health, last_attempt_at)?;
        Ok(Self {
            provider,
            health,
            last_attempt_at,
            collection_duration,
            unavailable_readings,
        })
    }

    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub fn health(&self) -> &ProviderHealth {
        &self.health
    }

    pub const fn last_attempt_at(&self) -> Duration {
        self.last_attempt_at
    }

    pub const fn collection_duration(&self) -> Duration {
        self.collection_duration
    }

    pub const fn unavailable_readings(&self) -> u32 {
        self.unavailable_readings
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineTelemetry {
    pub samples_scheduled: u64,
    pub samples_completed: u64,
    pub provider_missed_samples: u64,
    pub skipped_snapshots: u64,
    pub rejected_series: u64,
    pub evicted_series: u64,
    pub history_buckets: u64,
    pub history_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorSnapshot {
    generation: u64,
    sequence: u64,
    started_at_unix_ms: u64,
    elapsed: Duration,
    network_namespace: Option<String>,
    providers: Arc<[ProviderSnapshot]>,
    series: Arc<[SeriesSnapshot]>,
    telemetry: EngineTelemetry,
    pub(crate) hardirq: Option<Arc<super::hardirq::HardirqSnapshot>>,
}

// The proof owns exactly the immutable projection it validated. Keeping it outside
// SeriesSnapshotData avoids changing published snapshots or retaining spare Arcs.
#[derive(Clone)]
pub(super) struct EngineSeriesProjection {
    row: SeriesSnapshot,
    elapsed: Duration,
}

impl EngineSeriesProjection {
    pub(super) fn new(
        row: SeriesSnapshot,
        elapsed: Duration,
    ) -> Result<Self, MonitorValidationError> {
        row.validate_at(elapsed)?;
        Ok(Self { row, elapsed })
    }

    pub(super) fn at(mut self, elapsed: Duration) -> Result<Self, MonitorValidationError> {
        let fresh = match self.row.value() {
            SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
                matches!(current, ProjectedValue::Fresh { .. })
            }
            SeriesValue::State { current, .. } => matches!(current, ProjectedValue::Fresh { .. }),
        };
        // Fresh projections have only upper time bounds. Stale age is tied to
        // one snapshot time, and a regressed elapsed value needs all checks again.
        if elapsed != self.elapsed && (!fresh || elapsed < self.elapsed) {
            self.row.validate_at(elapsed)?;
        }
        self.elapsed = elapsed;
        Ok(self)
    }

    pub(super) fn snapshot(&self) -> &SeriesSnapshot {
        &self.row
    }

    pub(super) fn into_snapshot(self) -> SeriesSnapshot {
        self.row
    }
}

pub(super) struct ValidatedEngineRows {
    elapsed: Duration,
    providers: Vec<ProviderSnapshot>,
    rows: Vec<SeriesSnapshot>,
    history_buckets: u64,
    #[cfg(debug_assertions)]
    identities: HashSet<(ProviderId, MetricId, MetricLabels)>,
}

impl ValidatedEngineRows {
    pub(super) fn new(
        elapsed: Duration,
        providers: Vec<ProviderSnapshot>,
        capacity: usize,
    ) -> Result<Self, MonitorValidationError> {
        validate_monotonic(elapsed)?;
        if providers.len() > MAX_PROVIDERS {
            return Err(MonitorValidationError::TooManyProviders);
        }
        if capacity > MAX_ADMITTED_SERIES {
            return Err(MonitorValidationError::TooManySeries);
        }
        let mut ids = BTreeSet::new();
        for provider in &providers {
            if provider.last_attempt_at > elapsed {
                return Err(MonitorValidationError::InvalidTimestamp);
            }
            if !ids.insert(provider.provider()) {
                return Err(MonitorValidationError::DuplicateProvider);
            }
        }
        Ok(Self {
            elapsed,
            providers,
            rows: Vec::with_capacity(capacity),
            history_buckets: 0,
            #[cfg(debug_assertions)]
            identities: HashSet::with_capacity(capacity),
        })
    }

    pub(super) fn push(
        &mut self,
        projection: EngineSeriesProjection,
        provider_index: Option<usize>,
    ) -> Result<(), MonitorValidationError> {
        if self.rows.len() == MAX_ADMITTED_SERIES {
            return Err(MonitorValidationError::TooManySeries);
        }
        if projection.elapsed != self.elapsed {
            return Err(MonitorValidationError::InvalidSeriesProjection);
        }
        let row = projection.row;
        let provider = provider_index
            .and_then(|index| self.providers.get(index))
            .filter(|provider| provider.provider() == row.source())
            .ok_or(MonitorValidationError::SeriesProviderMissing)?;
        if !series_matches_provider_health(row.value(), provider.health()) {
            return Err(MonitorValidationError::SeriesHealthMismatch);
        }
        if let Some(previous) = self.rows.last() {
            if previous.id() == row.id() {
                return Err(MonitorValidationError::DuplicateSeriesId);
            }
            if previous.id() > row.id() {
                return Err(MonitorValidationError::InvalidSeriesProjection);
            }
        }
        // As in the prior engine constructor, the engine's keyed store proves
        // identity uniqueness; retain the independent debug check.
        #[cfg(debug_assertions)]
        if !self.identities.insert((
            row.provider().clone(),
            row.metric().clone(),
            row.labels().clone(),
        )) {
            return Err(MonitorValidationError::DuplicateSeries);
        }
        let history_buckets = self
            .history_buckets
            .checked_add(row.history().bucket_count())
            .ok_or(MonitorValidationError::HistoryBudgetExceeded)?;
        self.rows.push(row);
        self.history_buckets = history_buckets;
        Ok(())
    }

    pub(super) fn history_buckets(&self) -> u64 {
        self.history_buckets
    }
}

impl MonitorSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: u64,
        sequence: u64,
        started_at_unix_ms: u64,
        elapsed: Duration,
        network_namespace: Option<String>,
        providers: Vec<ProviderSnapshot>,
        series: Vec<SeriesSnapshot>,
        telemetry: EngineTelemetry,
    ) -> Result<Self, MonitorValidationError> {
        Self::build(
            generation,
            sequence,
            started_at_unix_ms,
            elapsed,
            network_namespace,
            providers,
            series,
            telemetry,
            true,
        )
    }

    // Rows arrive in ID order with time and current-source health checks complete.
    pub(super) fn from_engine(
        generation: u64,
        sequence: u64,
        started_at_unix_ms: u64,
        network_namespace: Option<String>,
        mut validated: ValidatedEngineRows,
        telemetry: EngineTelemetry,
    ) -> Result<Self, MonitorValidationError> {
        if generation == 0 || sequence == 0 {
            return Err(MonitorValidationError::InvalidSnapshotIdentity);
        }
        if network_namespace
            .as_deref()
            .is_some_and(|value| !valid_printable_ascii(value, MAX_ID_BYTES))
        {
            return Err(MonitorValidationError::InvalidNetworkNamespace);
        }
        if telemetry.history_buckets > MAX_HISTORY_BUCKETS
            || telemetry.history_bytes > MAX_HISTORY_BYTES
        {
            return Err(MonitorValidationError::HistoryBudgetExceeded);
        }
        if validated.history_buckets != telemetry.history_buckets {
            return Err(MonitorValidationError::HistoryTelemetryMismatch);
        }
        validated
            .providers
            .sort_by(|left, right| left.provider.cmp(&right.provider));
        Ok(Self {
            generation,
            sequence,
            started_at_unix_ms,
            elapsed: validated.elapsed,
            network_namespace,
            providers: validated.providers.into(),
            series: validated.rows.into(),
            telemetry,
            hardirq: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        generation: u64,
        sequence: u64,
        started_at_unix_ms: u64,
        elapsed: Duration,
        network_namespace: Option<String>,
        mut providers: Vec<ProviderSnapshot>,
        mut series: Vec<SeriesSnapshot>,
        telemetry: EngineTelemetry,
        check_unique: bool,
    ) -> Result<Self, MonitorValidationError> {
        if generation == 0 || sequence == 0 {
            return Err(MonitorValidationError::InvalidSnapshotIdentity);
        }
        validate_monotonic(elapsed)?;
        if network_namespace
            .as_deref()
            .is_some_and(|value| !valid_printable_ascii(value, MAX_ID_BYTES))
        {
            return Err(MonitorValidationError::InvalidNetworkNamespace);
        }
        if providers.len() > MAX_PROVIDERS {
            return Err(MonitorValidationError::TooManyProviders);
        }
        if series.len() > MAX_ADMITTED_SERIES {
            return Err(MonitorValidationError::TooManySeries);
        }
        if telemetry.history_buckets > MAX_HISTORY_BUCKETS
            || telemetry.history_bytes > MAX_HISTORY_BYTES
        {
            return Err(MonitorValidationError::HistoryBudgetExceeded);
        }

        let mut provider_health = BTreeMap::new();
        for provider in &providers {
            if provider.last_attempt_at > elapsed {
                return Err(MonitorValidationError::InvalidTimestamp);
            }
            if provider_health
                .insert(provider.provider.clone(), provider.health.clone())
                .is_some()
            {
                return Err(MonitorValidationError::DuplicateProvider);
            }
        }

        let check_unique = check_unique || cfg!(debug_assertions);
        let mut series_ids = HashSet::with_capacity(if check_unique { series.len() } else { 0 });
        let mut series_keys = HashSet::with_capacity(if check_unique { series.len() } else { 0 });
        let mut history_buckets = 0_u64;
        for row in &series {
            row.validate_at(elapsed)?;
            let Some(health) = provider_health.get(row.source()) else {
                return Err(MonitorValidationError::SeriesProviderMissing);
            };
            if !series_matches_provider_health(row.value(), health) {
                return Err(MonitorValidationError::SeriesHealthMismatch);
            }
            if check_unique && !series_ids.insert(row.id().get()) {
                return Err(MonitorValidationError::DuplicateSeriesId);
            }
            if check_unique && !series_keys.insert((row.provider(), row.metric(), row.labels())) {
                return Err(MonitorValidationError::DuplicateSeries);
            }
            history_buckets = history_buckets
                .checked_add(row.history().bucket_count())
                .ok_or(MonitorValidationError::HistoryBudgetExceeded)?;
        }
        if history_buckets != telemetry.history_buckets {
            return Err(MonitorValidationError::HistoryTelemetryMismatch);
        }

        providers.sort_by(|left, right| left.provider.cmp(&right.provider));
        series.sort_by_key(SeriesSnapshot::id);
        Ok(Self {
            generation,
            sequence,
            started_at_unix_ms,
            elapsed,
            network_namespace,
            providers: providers.into(),
            series: series.into(),
            telemetry,
            hardirq: None,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn started_at_unix_ms(&self) -> u64 {
        self.started_at_unix_ms
    }

    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    pub fn network_namespace(&self) -> Option<&str> {
        self.network_namespace.as_deref()
    }

    pub fn providers(&self) -> &[ProviderSnapshot] {
        &self.providers
    }

    pub fn series(&self) -> &[SeriesSnapshot] {
        &self.series
    }

    pub const fn telemetry(&self) -> EngineTelemetry {
        self.telemetry
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorValidationError {
    InvalidSection,
    InvalidInterval,
    IntervalOutOfRange,
    IntervalPrecision,
    EmptyEnabledSections,
    TooManyEnabledSections,
    DuplicateEnabledSection,
    InitialSectionDisabled,
    InvalidInterfaceAnchor,
    InvalidIdentifier,
    TooManyLabels,
    DuplicateLabel,
    InvalidLabelValue { label: MetricLabel },
    InvalidStateValue,
    InvalidDiagnostic,
    InvalidTimestamp,
    InvalidProviderHealth,
    NonFreshProviderHasReadings,
    TooManyProviderReadings,
    DuplicateReading,
    UnknownMetric,
    MetricSourceMismatch,
    MetricOwnerMismatch,
    MetricKindMismatch,
    MetricLabelsMismatch,
    InvalidSeriesId,
    InvalidBaseline,
    InvalidProjectedValue,
    InvalidSeriesProjection,
    InvalidHistoryCoverage,
    InvalidHistoryBucket,
    InvalidSnapshotIdentity,
    InvalidNetworkNamespace,
    TooManyProviders,
    DuplicateProvider,
    TooManySeries,
    DuplicateSeriesId,
    DuplicateSeries,
    SeriesProviderMissing,
    HistoryBudgetExceeded,
    HistoryTelemetryMismatch,
    SeriesHealthMismatch,
    InvalidCatalog,
    DuplicateCatalogMetric,
    DuplicateCatalogSource,
    MissingCatalogSection,
    InvalidAggregation,
}

impl fmt::Display for MonitorValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSection => formatter.write_str("invalid monitor section"),
            Self::InvalidInterval => formatter.write_str("invalid monitor sampling interval"),
            Self::IntervalOutOfRange => {
                formatter.write_str("monitor interval must be between 250ms and 60s")
            }
            Self::IntervalPrecision => {
                formatter.write_str("monitor interval must use whole milliseconds")
            }
            Self::EmptyEnabledSections => {
                formatter.write_str("at least one collection section must be enabled")
            }
            Self::TooManyEnabledSections => {
                formatter.write_str("too many enabled monitor sections")
            }
            Self::DuplicateEnabledSection => {
                formatter.write_str("enabled monitor sections must be unique")
            }
            Self::InitialSectionDisabled => {
                formatter.write_str("initial monitor section is disabled")
            }
            Self::InvalidInterfaceAnchor => formatter.write_str("invalid interface view anchor"),
            Self::InvalidIdentifier => formatter.write_str("invalid monitor identifier"),
            Self::TooManyLabels => formatter.write_str("metric has too many labels"),
            Self::DuplicateLabel => formatter.write_str("metric labels must be unique"),
            Self::InvalidLabelValue { label } => {
                write!(formatter, "invalid {} metric label", label.as_str())
            }
            Self::InvalidStateValue => formatter.write_str("invalid metric state value"),
            Self::InvalidDiagnostic => formatter.write_str("invalid provider diagnostic"),
            Self::InvalidTimestamp => formatter.write_str("invalid monotonic timestamp"),
            Self::InvalidProviderHealth => formatter.write_str("invalid provider health"),
            Self::NonFreshProviderHasReadings => {
                formatter.write_str("non-fresh provider sample cannot contain readings")
            }
            Self::TooManyProviderReadings => {
                formatter.write_str("provider sample exceeds the reading limit")
            }
            Self::DuplicateReading => formatter.write_str("provider sample has duplicate readings"),
            Self::UnknownMetric => formatter.write_str("metric is outside the closed catalog"),
            Self::MetricSourceMismatch => {
                formatter.write_str("metric is not owned by this provider source")
            }
            Self::MetricOwnerMismatch => {
                formatter.write_str("metric is outside the canonical provider owner")
            }
            Self::MetricKindMismatch => {
                formatter.write_str("metric reading kind does not match the catalog")
            }
            Self::MetricLabelsMismatch => {
                formatter.write_str("metric labels do not match the catalog allowlist")
            }
            Self::InvalidSeriesId => formatter.write_str("invalid session-local series ID"),
            Self::InvalidBaseline => formatter.write_str("invalid series baseline origin"),
            Self::InvalidProjectedValue => formatter.write_str("invalid projected metric value"),
            Self::InvalidSeriesProjection => {
                formatter.write_str("invalid metric series projection")
            }
            Self::InvalidHistoryCoverage => formatter.write_str("invalid history coverage"),
            Self::InvalidHistoryBucket => formatter.write_str("invalid history bucket"),
            Self::InvalidSnapshotIdentity => {
                formatter.write_str("invalid monitor snapshot identity")
            }
            Self::InvalidNetworkNamespace => {
                formatter.write_str("invalid network namespace identity")
            }
            Self::TooManyProviders => formatter.write_str("monitor provider limit exceeded"),
            Self::DuplicateProvider => formatter.write_str("duplicate monitor provider"),
            Self::TooManySeries => formatter.write_str("monitor series limit exceeded"),
            Self::DuplicateSeriesId => formatter.write_str("duplicate session-local series ID"),
            Self::DuplicateSeries => formatter.write_str("duplicate monitor series"),
            Self::SeriesProviderMissing => {
                formatter.write_str("metric series references a missing provider")
            }
            Self::HistoryBudgetExceeded => formatter.write_str("monitor history budget exceeded"),
            Self::HistoryTelemetryMismatch => {
                formatter.write_str("history telemetry does not match series coverage")
            }
            Self::SeriesHealthMismatch => {
                formatter.write_str("metric freshness conflicts with provider health")
            }
            Self::InvalidCatalog => formatter.write_str("invalid monitor metric catalog"),
            Self::DuplicateCatalogMetric => formatter.write_str("duplicate catalog metric ID"),
            Self::DuplicateCatalogSource => {
                formatter.write_str("a source metric has more than one primary owner")
            }
            Self::MissingCatalogSection => {
                formatter.write_str("catalog section has no minimum metric")
            }
            Self::InvalidAggregation => formatter.write_str("invalid metric aggregation policy"),
        }
    }
}

impl std::error::Error for MonitorValidationError {}

#[cfg(test)]
mod identity_equality_tests {
    use super::*;

    fn assert_eq_ord_hash_coherence<T: Eq + Ord + Hash + fmt::Debug>(values: &[T]) {
        for left in values {
            for right in values {
                assert_eq!(left == right, left.cmp(right).is_eq());
                assert_eq!(left.partial_cmp(right), Some(left.cmp(right)));
                if left == right {
                    let mut left_hash = DefaultHasher::new();
                    let mut right_hash = DefaultHasher::new();
                    left.hash(&mut left_hash);
                    right.hash(&mut right_hash);
                    assert_eq!(left_hash.finish(), right_hash.finish());
                }
            }
        }
    }

    #[test]
    fn provider_id_equality_preserves_contents_and_cached_hash() {
        let original = ProviderId::new("linux.proc.net.dev").unwrap();
        let shared = original.clone();
        let distinct = ProviderId::new("linux.proc.net.dev").unwrap();
        assert!(Arc::ptr_eq(&original.0, &shared.0));
        assert!(!Arc::ptr_eq(&original.0, &distinct.0));
        assert_eq!(original, shared);
        assert_eq!(original, distinct);

        let mut collision = ProviderId::new("linux.rtnetlink.link_stats").unwrap();
        collision.1 = original.1;
        assert_ne!(original, collision);
        let mut shared_hash_mismatch = original.clone();
        shared_hash_mismatch.1 ^= 1;
        assert!(Arc::ptr_eq(&original.0, &shared_hash_mismatch.0));
        assert_ne!(original, shared_hash_mismatch);
        let mut distinct_hash_mismatch = distinct.clone();
        distinct_hash_mismatch.1 ^= 1;
        assert_ne!(original, distinct_hash_mismatch);

        assert_eq_ord_hash_coherence(&[
            original,
            shared,
            distinct,
            collision,
            shared_hash_mismatch,
            distinct_hash_mismatch,
        ]);
    }

    #[test]
    fn metric_labels_equality_preserves_contents_and_cached_hash() {
        let original = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let shared = original.clone();
        let distinct = MetricLabels::new([
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Interface, "eth0".to_owned()),
        ])
        .unwrap();
        assert!(Arc::ptr_eq(&original.0, &shared.0));
        assert!(!Arc::ptr_eq(&original.0, &distinct.0));
        assert_eq!(original, shared);
        assert_eq!(original, distinct);

        let mut collision = MetricLabels::new([
            (MetricLabel::Interface, "eth1".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        collision.1 = original.1;
        assert_ne!(original, collision);
        let mut different_key = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Cpu, "2".to_owned()),
        ])
        .unwrap();
        different_key.1 = original.1;
        assert_ne!(original, different_key);
        let empty = MetricLabels(Vec::new().into(), original.1);
        assert_ne!(original, empty);
        let mut shared_hash_mismatch = original.clone();
        shared_hash_mismatch.1 ^= 1;
        assert!(Arc::ptr_eq(&original.0, &shared_hash_mismatch.0));
        assert_ne!(original, shared_hash_mismatch);
        let mut distinct_hash_mismatch = distinct.clone();
        distinct_hash_mismatch.1 ^= 1;
        assert_ne!(original, distinct_hash_mismatch);

        assert_eq_ord_hash_coherence(&[
            original,
            shared,
            distinct,
            collision,
            different_key,
            empty,
            shared_hash_mismatch,
            distinct_hash_mismatch,
        ]);
    }
}

#[cfg(test)]
mod sample_refresh_tests {
    use super::*;

    fn prior_sample() -> ProviderSample {
        let metric = MetricId::new("linux.netdevice.rx_packets").unwrap();
        let readings = [2, 3].map(|ifindex| {
            SampleReading::observed(
                metric.clone(),
                MetricLabels::new([
                    (MetricLabel::Interface, format!("eth{ifindex}")),
                    (MetricLabel::Ifindex, ifindex.to_string()),
                ])
                .unwrap(),
                MetricReading::Counter {
                    value: 10,
                    bits: Some(CounterBits::Bits64),
                },
            )
        });
        ProviderSample::new(
            ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
            Duration::from_secs(3),
            Duration::ZERO,
            ProviderHealth::Fresh,
            readings.to_vec(),
        )
        .unwrap()
    }

    fn compare_refresh(
        prior: &ProviderSample,
        provider: ProviderId,
        at: Duration,
        duration: Duration,
        health: ProviderHealth,
        readings: Vec<SampleReading>,
    ) -> Result<ProviderSample, MonitorValidationError> {
        let expected = ProviderSample::new(
            provider.clone(),
            at,
            duration,
            health.clone(),
            readings.clone(),
        );
        let actual = prior.refresh(provider, at, duration, health, readings);
        assert_eq!(actual, expected);
        actual
    }

    #[test]
    fn refresh_matches_constructor_for_identity_outcome_and_source_changes() {
        let prior = prior_sample();
        let original = prior.clone();
        let base = prior.readings().to_vec();
        let mut cases = vec![base.clone(); 9];
        cases[0][0].outcome = ReadingOutcome::Observed(MetricReading::Counter {
            value: 99,
            bits: Some(CounterBits::Bits32),
        });
        cases[1][0].outcome = ReadingOutcome::Unavailable(UnavailableReason::Overflow);
        cases[2].reverse();
        cases[3][0].labels = MetricLabels::new([
            (MetricLabel::Interface, "renamed0".to_owned()),
            (MetricLabel::Ifindex, "9".to_owned()),
        ])
        .unwrap();
        cases[4][1] = cases[4][0].clone();
        cases[5][0].outcome = ReadingOutcome::Observed(MetricReading::Gauge(99));
        cases[6][0].metric = MetricId::new("linux.unknown.metric").unwrap();
        cases[7][0].labels = MetricLabels::default();
        cases[8].pop();
        // A later layout mismatch must not hide the first outcome error.
        let mut multiple_errors = cases[5].clone();
        multiple_errors[1].metric = MetricId::new("linux.unknown.metric").unwrap();
        cases.push(multiple_errors);
        cases.push(Vec::new());
        for provider in [
            prior.provider().clone(),
            ProviderId::new(prior.provider().as_str()).unwrap(),
            ProviderId::new("linux.sysfs.net.statistics").unwrap(),
            ProviderId::new("linux.proc.net.snmp").unwrap(),
        ] {
            for readings in &cases {
                let _ = compare_refresh(
                    &prior,
                    provider.clone(),
                    Duration::from_secs(4),
                    Duration::ZERO,
                    ProviderHealth::Fresh,
                    readings.clone(),
                );
            }
        }
        // Equal identities from separate allocations are valid too.
        let independent = prior_sample();
        assert!(!Arc::ptr_eq(
            &prior.readings()[0].labels.0,
            &independent.readings()[0].labels.0
        ));
        let refreshed = compare_refresh(
            &prior,
            independent.provider().clone(),
            Duration::from_secs(4),
            Duration::ZERO,
            ProviderHealth::Fresh,
            independent.readings().to_vec(),
        )
        .unwrap();
        assert!(!Arc::ptr_eq(&prior.readings, &refreshed.readings));
        assert_eq!(refreshed.finished_at(), Duration::from_secs(4));
        assert_eq!(prior, original);
    }

    #[test]
    fn refresh_matches_constructor_metadata_limits_and_error_precedence() {
        let prior = prior_sample();
        let error = MonitorError::new(MonitorErrorCode::Io, "failed").unwrap();
        let healths = [
            ProviderHealth::Fresh,
            ProviderHealth::Partial {
                warning: error.clone(),
            },
            ProviderHealth::Error {
                error: error.clone(),
            },
            ProviderHealth::Stale {
                last_success_at: Duration::from_secs(1),
                age: Duration::from_secs(1),
                cause: error.clone(),
            },
            ProviderHealth::Unsupported {
                reason: MonitorError::new(MonitorErrorCode::Unsupported, "unsupported").unwrap(),
            },
            ProviderHealth::PermissionDenied {
                reason: MonitorError::new(MonitorErrorCode::PermissionDenied, "denied").unwrap(),
            },
            ProviderHealth::Unsupported { reason: error },
        ];
        let oversized = vec![prior.readings()[0].clone(); MAX_READINGS_PER_PROVIDER + 1];
        for at in [
            Duration::ZERO,
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::MAX,
        ] {
            for duration in [Duration::ZERO, Duration::from_secs(3), Duration::MAX] {
                for health in &healths {
                    for readings in [prior.readings().to_vec(), Vec::new(), oversized.clone()] {
                        let _ = compare_refresh(
                            &prior,
                            prior.provider().clone(),
                            at,
                            duration,
                            health.clone(),
                            readings,
                        );
                    }
                }
            }
        }
        // Sample refresh has no engine elapsed proof or cross-sample time rule.
        compare_refresh(
            &prior,
            prior.provider().clone(),
            Duration::from_secs(2),
            Duration::ZERO,
            ProviderHealth::Fresh,
            prior.readings().to_vec(),
        )
        .unwrap();
    }

    #[test]
    fn refresh_validates_state_outcomes_and_bounds_retained_capacity() {
        let metric = MetricId::new("linux.nic.link_state").unwrap();
        let provider = ProviderId::new(metric.descriptor().unwrap().sources[0].provider).unwrap();
        let labels = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let prior = ProviderSample::new(
            provider.clone(),
            Duration::from_secs(1),
            Duration::ZERO,
            ProviderHealth::Fresh,
            vec![SampleReading::observed(
                metric.clone(),
                labels.clone(),
                MetricReading::State(StateValue::new("up").unwrap()),
            )],
        )
        .unwrap();
        let original = prior.clone();
        for outcome in [
            ReadingOutcome::Observed(MetricReading::State(StateValue::new("down").unwrap())),
            ReadingOutcome::Observed(MetricReading::State(
                StateValue::new("not-a-link-state").unwrap(),
            )),
            ReadingOutcome::Observed(MetricReading::Gauge(1)),
            ReadingOutcome::Unavailable(UnavailableReason::Missing),
        ] {
            let reading = SampleReading {
                metric: metric.clone(),
                labels: labels.clone(),
                outcome,
            };
            let _ = compare_refresh(
                &prior,
                provider.clone(),
                Duration::from_secs(2),
                Duration::ZERO,
                ProviderHealth::Fresh,
                vec![reading],
            );
        }
        for changed_layout in [false, true] {
            let mut readings = Vec::with_capacity(MAX_READINGS_PER_PROVIDER * 2);
            readings.extend_from_slice(prior.readings());
            if changed_layout {
                readings[0].labels = MetricLabels::new([
                    (MetricLabel::Interface, "renamed0".to_owned()),
                    (MetricLabel::Ifindex, "3".to_owned()),
                ])
                .unwrap();
            }
            let refreshed = compare_refresh(
                &prior,
                provider.clone(),
                Duration::from_secs(2),
                Duration::ZERO,
                ProviderHealth::Fresh,
                readings,
            )
            .unwrap();
            assert!(refreshed.readings.capacity() <= MAX_READINGS_PER_PROVIDER);
        }
        assert_eq!(prior, original);
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    fn counter_row(current: ProjectedValue<u64>) -> SeriesSnapshot {
        let metric = MetricId::new("linux.socket.tcp.segments_in").unwrap();
        let descriptor = metric.descriptor().unwrap();
        SeriesSnapshot::new(
            SeriesId::new(1).unwrap(),
            ProviderId::new(descriptor.owner).unwrap(),
            ProviderId::new(descriptor.sources[0].provider).unwrap(),
            metric,
            MetricLabels::default(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            SeriesValue::Counter {
                current,
                interval: None,
                since_baseline: None,
            },
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn assert_engine_build_matches_full(
        elapsed: Duration,
        providers: Vec<ProviderSnapshot>,
        rows: Vec<SeriesSnapshot>,
        telemetry: EngineTelemetry,
    ) {
        let expected = MonitorSnapshot::new(
            1,
            1,
            0,
            elapsed,
            None,
            providers.clone(),
            rows.clone(),
            telemetry,
        );
        let actual = (|| {
            let mut validated = ValidatedEngineRows::new(elapsed, providers.clone(), rows.len())?;
            for row in rows {
                let index = providers.iter().position(|p| p.provider() == row.source());
                validated.push(EngineSeriesProjection::new(row, elapsed)?, index)?;
            }
            MonitorSnapshot::from_engine(1, 1, 0, None, validated, telemetry)
        })();
        assert_eq!(actual, expected);
    }

    #[test]
    fn engine_builder_matches_full_source_health_time_and_telemetry_checks() {
        let at = Duration::from_secs(2);
        let error = MonitorError::new(MonitorErrorCode::Io, "failed").unwrap();
        let healths = [
            ProviderHealth::Fresh,
            ProviderHealth::Partial {
                warning: error.clone(),
            },
            ProviderHealth::Stale {
                last_success_at: Duration::from_secs(1),
                age: Duration::from_secs(1),
                cause: error.clone(),
            },
            ProviderHealth::Error {
                error: error.clone(),
            },
            ProviderHealth::Unsupported {
                reason: MonitorError::new(MonitorErrorCode::Unsupported, "unsupported").unwrap(),
            },
            ProviderHealth::PermissionDenied {
                reason: MonitorError::new(MonitorErrorCode::PermissionDenied, "denied").unwrap(),
            },
        ];
        let currents = [
            ProjectedValue::Fresh {
                value: 10,
                observed_at: at,
            },
            ProjectedValue::Stale {
                last: 10,
                observed_at: Duration::from_secs(1),
                age: Duration::from_secs(1),
                cause: MonitorErrorCode::Io,
            },
            ProjectedValue::Unavailable {
                reason: UnavailableReason::Missing,
            },
        ];
        for current in currents {
            let row = counter_row(current);
            for health in &healths {
                let provider = ProviderSnapshot::new(
                    row.source().clone(),
                    health.clone(),
                    at,
                    Duration::ZERO,
                    0,
                )
                .unwrap();
                for elapsed in [
                    Duration::from_secs(1),
                    at,
                    Duration::from_secs(3),
                    Duration::MAX,
                ] {
                    assert_engine_build_matches_full(
                        elapsed,
                        vec![provider.clone()],
                        vec![row.clone()],
                        EngineTelemetry::default(),
                    );
                }
            }
            assert_engine_build_matches_full(at, vec![], vec![row], EngineTelemetry::default());
        }
        let row = counter_row(ProjectedValue::Fresh {
            value: 10,
            observed_at: at,
        });
        let provider = ProviderSnapshot::new(
            row.source().clone(),
            ProviderHealth::Fresh,
            at,
            Duration::ZERO,
            0,
        )
        .unwrap();
        for telemetry in [
            EngineTelemetry::default(),
            EngineTelemetry {
                history_buckets: 1,
                ..EngineTelemetry::default()
            },
            EngineTelemetry {
                history_buckets: MAX_HISTORY_BUCKETS + 1,
                ..EngineTelemetry::default()
            },
            EngineTelemetry {
                history_bytes: MAX_HISTORY_BYTES + 1,
                ..EngineTelemetry::default()
            },
        ] {
            assert_engine_build_matches_full(
                at,
                vec![provider.clone()],
                vec![row.clone()],
                telemetry,
            );
        }
        assert_engine_build_matches_full(
            at,
            vec![provider.clone(), provider],
            vec![row],
            EngineTelemetry::default(),
        );
        for (generation, sequence, namespace) in
            [(0, 1, None), (1, 0, None), (1, 1, Some("\n".to_owned()))]
        {
            assert_eq!(
                MonitorSnapshot::from_engine(
                    generation,
                    sequence,
                    0,
                    namespace.clone(),
                    ValidatedEngineRows::new(at, vec![], 0).unwrap(),
                    EngineTelemetry::default()
                ),
                MonitorSnapshot::new(
                    generation,
                    sequence,
                    0,
                    at,
                    namespace,
                    vec![],
                    vec![],
                    EngineTelemetry::default()
                ),
            );
        }
    }

    #[test]
    fn engine_builder_matches_full_history_and_projection_time_boundaries() {
        let at = Duration::from_secs(2);
        let base = counter_row(ProjectedValue::Fresh {
            value: 10,
            observed_at: at,
        });
        let provider = ProviderSnapshot::new(
            base.source().clone(),
            ProviderHealth::Fresh,
            Duration::ZERO,
            Duration::ZERO,
            0,
        )
        .unwrap();
        for observed_at in [Duration::from_secs(3), Duration::MAX] {
            assert_engine_build_matches_full(
                at,
                vec![provider.clone()],
                vec![counter_row(ProjectedValue::Fresh {
                    value: 10,
                    observed_at,
                })],
                EngineTelemetry::default(),
            );
        }
        for interval in [Duration::ZERO, Duration::from_secs(3)] {
            let mut row = base.clone();
            if let SeriesValue::Counter {
                interval: target, ..
            } = &mut Arc::make_mut(&mut row.0).value
            {
                *target = Some(CounterContinuity::Continuous {
                    delta: 0,
                    elapsed: interval,
                });
            }
            assert_engine_build_matches_full(
                at,
                vec![provider.clone()],
                vec![row],
                EngineTelemetry::default(),
            );
        }
        let mut history = super::super::history::HistoryStore::new(Duration::from_secs(1));
        history.record(
            base.id(),
            super::super::history::HistoryObservation::new(
                Duration::ZERO,
                Duration::from_secs(3),
                10,
                0,
                Duration::ZERO,
                false,
            ),
        );
        let row = base
            .with_history(history.projection(SeriesId::new(1).unwrap()).unwrap())
            .unwrap();
        let telemetry = EngineTelemetry {
            history_buckets: 1,
            history_bytes: 128,
            ..EngineTelemetry::default()
        };
        assert_engine_build_matches_full(at, vec![provider.clone()], vec![row.clone()], telemetry);
        assert_engine_build_matches_full(
            Duration::from_secs(3),
            vec![provider],
            vec![row.clone()],
            telemetry,
        );
        let proof = EngineSeriesProjection::new(row.clone(), Duration::from_secs(3)).unwrap();
        assert_eq!(proof.at(at).err(), row.validate_at(at).err());
    }

    #[test]
    fn cached_temporal_proof_preserves_full_checks_and_current_source_health() {
        let at = Duration::from_secs(2);
        for current in [
            ProjectedValue::Fresh {
                value: 10,
                observed_at: at,
            },
            ProjectedValue::Stale {
                last: 10,
                observed_at: Duration::from_secs(1),
                age: Duration::from_secs(1),
                cause: MonitorErrorCode::Io,
            },
            ProjectedValue::Unavailable {
                reason: UnavailableReason::Missing,
            },
        ] {
            let row = counter_row(current);
            let proof = EngineSeriesProjection::new(row.clone(), at).unwrap();
            for elapsed in [Duration::from_secs(1), at, Duration::from_secs(3)] {
                assert_eq!(
                    proof.clone().at(elapsed).map(|p| p.into_snapshot()),
                    row.validate_at(elapsed).map(|()| row.clone())
                );
            }
        }
        let row = counter_row(ProjectedValue::Fresh {
            value: 10,
            observed_at: at,
        });
        let proof = EngineSeriesProjection::new(row.clone(), at)
            .unwrap()
            .at(Duration::from_secs(4))
            .unwrap();
        assert_eq!(
            proof.clone().at(Duration::from_secs(3)).unwrap().snapshot(),
            &row
        );
        assert_eq!(
            proof.clone().at(Duration::from_secs(1)).err(),
            Some(MonitorValidationError::InvalidProjectedValue)
        );
        for health in [
            ProviderHealth::Fresh,
            ProviderHealth::Stale {
                last_success_at: at,
                age: Duration::from_secs(2),
                cause: MonitorError::new(MonitorErrorCode::Io, "failed").unwrap(),
            },
        ] {
            let elapsed = Duration::from_secs(4);
            let provider =
                ProviderSnapshot::new(row.source().clone(), health, elapsed, Duration::ZERO, 0)
                    .unwrap();
            let mut validated =
                ValidatedEngineRows::new(elapsed, vec![provider.clone()], 1).unwrap();
            let actual = validated.push(proof.clone(), Some(0)).and_then(|()| {
                MonitorSnapshot::from_engine(1, 1, 0, None, validated, EngineTelemetry::default())
            });
            let expected = MonitorSnapshot::new(
                1,
                1,
                0,
                elapsed,
                None,
                vec![provider],
                vec![row.clone()],
                EngineTelemetry::default(),
            );
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn engine_builder_rejects_wrong_indices_proof_time_and_nonascending_ids() {
        let at = Duration::from_secs(2);
        let row = counter_row(ProjectedValue::Fresh {
            value: 10,
            observed_at: at,
        });
        let provider = ProviderSnapshot::new(
            row.source().clone(),
            ProviderHealth::Fresh,
            at,
            Duration::ZERO,
            0,
        )
        .unwrap();
        let other = ProviderSnapshot::new(
            ProviderId::new("linux.proc.net.sockstat").unwrap(),
            ProviderHealth::Fresh,
            at,
            Duration::ZERO,
            0,
        )
        .unwrap();
        let proof = EngineSeriesProjection::new(row.clone(), at).unwrap();
        for index in [None, Some(1), Some(2)] {
            let mut validated =
                ValidatedEngineRows::new(at, vec![provider.clone(), other.clone()], 1).unwrap();
            assert_eq!(
                validated.push(proof.clone(), index),
                Err(MonitorValidationError::SeriesProviderMissing)
            );
        }
        let mut validated =
            ValidatedEngineRows::new(Duration::from_secs(3), vec![provider.clone()], 1).unwrap();
        assert_eq!(
            validated.push(proof.clone(), Some(0)),
            Err(MonitorValidationError::InvalidSeriesProjection)
        );
        for first_id in [1, 2] {
            let mut first = row.clone();
            Arc::make_mut(&mut first.0).id = SeriesId::new(first_id).unwrap();
            let mut validated = ValidatedEngineRows::new(at, vec![provider.clone()], 2).unwrap();
            validated
                .push(EngineSeriesProjection::new(first, at).unwrap(), Some(0))
                .unwrap();
            assert_eq!(
                validated.push(proof.clone(), Some(0)),
                Err(if first_id == 1 {
                    MonitorValidationError::DuplicateSeriesId
                } else {
                    MonitorValidationError::InvalidSeriesProjection
                })
            );
        }
    }

    #[test]
    fn borrowed_reprojection_sources_preserve_equal_ids_and_retained_snapshots() {
        let metric = MetricId::new("linux.netdevice.rx_packets").unwrap();
        let owner = ProviderId::new(metric.descriptor().unwrap().owner).unwrap();
        let primary = ProviderId::new("linux.rtnetlink.link_stats").unwrap();
        let fallback = ProviderId::new("linux.sysfs.net.statistics").unwrap();
        let labels = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let value = |at| SeriesValue::Counter {
            current: ProjectedValue::Fresh {
                value: at,
                observed_at: Duration::from_secs(at),
            },
            interval: None,
            since_baseline: None,
        };
        let id = SeriesId::new(1).unwrap();
        let history = super::super::history::HistoryStore::new(Duration::from_secs(1));
        let mut row = SeriesSnapshot::new(
            id,
            owner.clone(),
            primary.clone(),
            metric.clone(),
            labels.clone(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            value(1),
            HistoryCoverage::empty(),
        )
        .unwrap();
        let mut retained = vec![row.clone()];
        for (index, source) in [&primary, &fallback, &fallback, &primary]
            .into_iter()
            .enumerate()
        {
            let at = index as u64 + 2;
            let independent = ProviderId::new(source.as_str()).unwrap();
            assert!(!Arc::ptr_eq(&independent.0, &source.0));
            let previous_source = row.source().clone();
            let changed = previous_source != independent;
            let (origin, baseline_at) = if changed {
                (BaselineOrigin::RecoveredAfterGap, Duration::from_secs(at))
            } else {
                (row.baseline_origin(), row.baseline_at())
            };
            let expected = SeriesSnapshot::new(
                id,
                owner.clone(),
                independent.clone(),
                metric.clone(),
                labels.clone(),
                Duration::ZERO,
                origin,
                baseline_at,
                value(at),
                HistoryCoverage::empty(),
            )
            .unwrap();
            row = row
                .reproject(
                    &independent,
                    origin,
                    baseline_at,
                    value(at),
                    history.projection(id).unwrap(),
                )
                .unwrap();
            assert_eq!(row, expected);
            if changed {
                assert!(Arc::ptr_eq(&row.source().0, &independent.0));
            } else {
                assert!(Arc::ptr_eq(&row.source().0, &previous_source.0));
            }
            retained.push(row.clone());
        }
        for (index, snapshot) in retained.into_iter().enumerate() {
            assert_eq!(snapshot.value(), &value(index as u64 + 1));
            assert_eq!(
                snapshot.source(),
                if index == 2 || index == 3 {
                    &fallback
                } else {
                    &primary
                }
            );
        }
    }

    #[test]
    fn reprojection_preserves_retained_history_and_reuses_exclusive_storage() {
        use super::super::history::{HistoryObservation, HistoryStore};

        let mut history = HistoryStore::new(Duration::from_secs(1));
        let mut row = counter_row(ProjectedValue::Fresh {
            value: 10,
            observed_at: Duration::ZERO,
        });
        let source = row.source().clone();
        let mut retained = Vec::new();
        let mut reused = 0;
        let mut detached = 0;
        for tick in 1..=MAX_HISTORY_BUCKETS_PER_SERIES * 3 {
            let at = Duration::from_secs(tick as u64);
            // Equal numeric values at new times must still append observations.
            history.record(
                row.id(),
                HistoryObservation::new(
                    at - Duration::from_secs(1),
                    at,
                    10,
                    0,
                    Duration::from_secs(1),
                    false,
                ),
            );
            let current = ProjectedValue::Fresh {
                value: 10,
                observed_at: at,
            };
            let expected = counter_row(current)
                .with_history(history.projection(row.id()).unwrap())
                .unwrap();
            let prior_data = Arc::as_ptr(&row.0);
            let prior_buckets = row.history_buckets().as_ptr();
            let had_history = !row.history_buckets().is_empty();
            let keep_reader = tick % 3 == 0;
            if keep_reader {
                retained.push((row.clone(), row.0.as_ref().clone()));
            }
            let projection = history.projection(row.id()).unwrap();
            row = row
                .reproject(
                    &source,
                    BaselineOrigin::SessionStart,
                    Duration::ZERO,
                    expected.value().clone(),
                    projection,
                )
                .unwrap();
            assert_eq!(row, expected);
            assert!(row.validate_at(at).is_ok());
            assert!(validate_history_buckets(row.history(), row.history_buckets()).is_ok());
            assert_eq!(
                row.history_buckets().iter().map(|p| p.count()).sum::<u64>(),
                tick as u64
            );
            assert_eq!(
                row.0.history_buckets.capacity(),
                MAX_HISTORY_BUCKETS_PER_SERIES
            );
            if keep_reader {
                assert_ne!(Arc::as_ptr(&row.0), prior_data);
                assert_ne!(row.history_buckets().as_ptr(), prior_buckets);
                detached += 1;
            } else {
                assert_eq!(Arc::as_ptr(&row.0), prior_data);
                if had_history {
                    assert_eq!(row.history_buckets().as_ptr(), prior_buckets);
                }
                reused += 1;
            }
        }
        assert!(reused > 0 && detached > 0);
        assert!(row.history().compacted());
        for (snapshot, original) in retained {
            assert_eq!(snapshot.0.as_ref(), &original);
        }
    }

    #[test]
    fn reprojection_history_errors_match_fresh_construction_with_retained_readers() {
        use super::super::history::HistoryStore;

        let id = SeriesId::new(1).unwrap();
        let mut invalid = HistoryStore::new(Duration::from_secs(1));
        for at in [1, 3, 2, 4] {
            invalid.record_gap(id, Duration::from_secs(at));
        }
        let mut oversized = HistoryStore::with_bucket_limit(
            Duration::from_secs(1),
            MAX_HISTORY_BUCKETS_PER_SERIES + 1,
        );
        for at in 1..=MAX_HISTORY_BUCKETS_PER_SERIES + 1 {
            oversized.record_gap(id, Duration::from_secs(at as u64));
        }
        for history in [&invalid, &oversized] {
            for keep_reader in [false, true] {
                let row = counter_row(ProjectedValue::Fresh {
                    value: 10,
                    observed_at: Duration::from_secs(1),
                });
                let original = row.0.as_ref().clone();
                let reader = keep_reader.then(|| row.clone());
                let source = row.source().clone();
                let value = row.value().clone();
                let expected = row.clone().with_history(history.projection(id).unwrap());
                let actual = row.reproject(
                    &source,
                    BaselineOrigin::SessionStart,
                    Duration::ZERO,
                    value,
                    history.projection(id).unwrap(),
                );
                assert_eq!(expected, Err(MonitorValidationError::InvalidHistoryBucket));
                assert_eq!(actual, expected, "keep_reader={keep_reader}");
                if let Some(reader) = reader {
                    assert_eq!(reader.0.as_ref(), &original);
                }
            }
        }
    }

    #[test]
    fn reused_projection_checks_match_fresh_construction() {
        let history = super::super::history::HistoryStore::new(Duration::from_secs(1));
        let id = SeriesId::new(1).unwrap();
        let values = [
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: 5,
                    observed_at: Duration::from_secs(2),
                },
                interval: None,
                since_baseline: None,
            },
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value: 5,
                    observed_at: Duration::from_secs(2),
                },
                interval: None,
                since_baseline: None,
            },
            SeriesValue::Gauge {
                current: ProjectedValue::Fresh {
                    value: 5,
                    observed_at: Duration::from_secs(2),
                },
                interval: Some(GaugeChange::new(1, Duration::from_secs(1)).unwrap()),
                since_baseline: None,
            },
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: StateValue::new("up").unwrap(),
                    observed_at: Duration::from_secs(2),
                },
                changed_at: None,
                continuous_for: None,
            },
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: StateValue::new("invalid-link-state").unwrap(),
                    observed_at: Duration::from_secs(2),
                },
                changed_at: None,
                continuous_for: None,
            },
        ];
        for name in [
            "linux.socket.tcp.segments_in",
            "linux.nic.link_state",
            "linux.nic.raw_private",
        ] {
            let metric = MetricId::new(name).unwrap();
            let descriptor = metric.descriptor().unwrap();
            let owner = ProviderId::new(descriptor.owner).unwrap();
            let source = ProviderId::new(descriptor.sources[0].provider).unwrap();
            let labels = MetricLabels::new(descriptor.required_labels.iter().map(|label| {
                (
                    *label,
                    match label {
                        MetricLabel::Interface => "eth0",
                        MetricLabel::Ifindex => "2",
                        MetricLabel::Statistic => "driver_counter",
                        _ => panic!("unexpected fixture label: {label:?}"),
                    }
                    .to_owned(),
                )
            }))
            .unwrap();
            let initial = match descriptor.kind {
                MetricKind::Counter => SeriesValue::Counter {
                    current: ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                    interval: None,
                    since_baseline: None,
                },
                MetricKind::Gauge => SeriesValue::Gauge {
                    current: ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                    interval: None,
                    since_baseline: None,
                },
                MetricKind::State => SeriesValue::State {
                    current: ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                    changed_at: None,
                    continuous_for: None,
                },
            };
            let original = SeriesSnapshot::new(
                id,
                owner.clone(),
                source,
                metric.clone(),
                labels.clone(),
                Duration::ZERO,
                BaselineOrigin::SessionStart,
                Duration::ZERO,
                initial,
                HistoryCoverage::empty(),
            )
            .unwrap();
            let sources = descriptor
                .sources
                .iter()
                .map(|source| source.provider)
                .chain(std::iter::once("linux.invalid.source"));
            for source in sources {
                for (origin, at) in [
                    (BaselineOrigin::SessionStart, 0),
                    (BaselineOrigin::FirstObserved, 1),
                    (BaselineOrigin::Reset, 0),
                    (BaselineOrigin::RecoveredAfterGap, 2),
                ] {
                    for value in &values {
                        let source = ProviderId::new(source).unwrap();
                        let expected = SeriesSnapshot::new(
                            id,
                            owner.clone(),
                            source.clone(),
                            metric.clone(),
                            labels.clone(),
                            Duration::ZERO,
                            origin,
                            Duration::from_secs(at),
                            value.clone(),
                            HistoryCoverage::empty(),
                        );
                        let actual = original.clone().reproject(
                            &source,
                            origin,
                            Duration::from_secs(at),
                            value.clone(),
                            history.projection(id).unwrap(),
                        );
                        assert_eq!(actual, expected, "metric={name}, baseline={origin:?}");
                    }
                }
            }
        }
    }
}
