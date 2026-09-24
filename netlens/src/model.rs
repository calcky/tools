use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capture::{ProviderScope, RequestedScope};
use crate::provider::{
    self as provider_registry, MetricSemantics, ObservationSemantics, TelemetryCounterRule,
};

pub const SCHEMA_VERSION: u16 = 5;
const REPORT_V4_SCHEMA_VERSION: u16 = 4;
pub const EVENT_STREAM_SCHEMA_VERSION: u16 = 1;
pub const PROVIDER_PROC_PROTOCOL: &str = "linux.proc.protocol_counters";
pub const PROVIDER_SOFTNET: &str = "linux.proc.softnet_counters";
pub const PROVIDER_LINK: &str = "linux.link.counters";
pub const PROVIDER_SOCK_DIAG: &str = "linux.sock_diag.skmeminfo";
pub const PROVIDER_KFREE_SKB: &str = "linux.tracepoint.kfree_skb";
pub const PROVIDER_UDP_RECEIVE_ADMISSION: &str = "linux.tracepoint.udp_fail_queue_rcv_skb";
pub const PROVIDER_SOCKET_RECEIVE_QUEUE_FULL: &str = "linux.tracepoint.sock_rcvqueue_full";
pub const PROVIDER_NWDIAG_CORE: &str = "nwdiag.core";

pub const ATTR_INTERFACE_NAME: &str = "linux.interface.name";
pub const ATTR_IFINDEX: &str = "linux.interface.ifindex";
pub const ATTR_QUEUE_ID: &str = "linux.queue.id";
pub const ATTR_NETWORK_NAMESPACE: &str = "linux.network_namespace.id";
pub const ATTR_HOP_ORDINAL: &str = "nwdiag.path.hop_ordinal";
pub const ATTR_COUNTER_BITS: &str = "linux.counter.bits";
pub const ATTR_CPU_ROW: &str = "linux.cpu.row";
pub const ATTR_SKB_REASON_CODE: &str = "linux.skb_free.reason_code";
pub const ATTR_SKB_REASON_NAME: &str = "linux.skb_free.reason_name";
pub const ATTR_BPF_MODE: &str = "linux.skb_free.source_mode";
pub const ATTR_UDP_RECEIVE_ADMISSION_CAUSE: &str = "linux.udp.receive_admission_failure.cause";
pub const ATTR_SOCKET_RECEIVE_MEMORY_ALLOCATED_BYTES: &str =
    "linux.socket.receive_memory_allocated_bytes";
pub const ATTR_SKB_TRUE_SIZE_BYTES: &str = "linux.skb.true_size_bytes";
pub const ATTR_SOCKET_RECEIVE_BUFFER_LIMIT_BYTES: &str = "linux.socket.receive_buffer_limit_bytes";
pub const EVENT_SKB_FREE: &str = "linux.skb.free";
pub const EVENT_UDP_RECEIVE_ADMISSION_FAILURE: &str = "linux.udp.receive_admission_failure";
pub const EVENT_SOCKET_RECEIVE_QUEUE_FULL: &str = "linux.socket.receive_queue_full";
pub const METRIC_SOCK_DIAG_DROPS: &str = "linux.sock_diag.skmeminfo_drops";
pub const MAX_SAMPLING_COMPONENTS: usize = 64;

pub(crate) const FINDING_SOCKET_RECEIVE_QUEUE_REJECTION: &str = "socket.receive_queue_rejection";
pub(crate) const FINDING_SOCKET_PROTOCOL_MEMORY_REJECTION: &str =
    "socket.protocol_memory_rejection";

#[derive(Clone, Copy)]
pub(crate) struct SocketCausalFindingContract {
    pub id: &'static str,
    pub title: &'static str,
    pub summary: &'static str,
}

pub(crate) fn socket_causal_finding_contract(
    provider: &str,
    event_type: &str,
    stage: Option<&str>,
) -> Option<SocketCausalFindingContract> {
    match (provider, event_type, stage) {
        (
            PROVIDER_UDP_RECEIVE_ADMISSION,
            EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
            Some("socket.receive_queue"),
        ) => Some(SocketCausalFindingContract {
            id: FINDING_SOCKET_RECEIVE_QUEUE_REJECTION,
            title: "UDP receive queue rejection",
            summary: "The UDP receive path reported skb admission rejection because the socket receive buffer was full.",
        }),
        (
            PROVIDER_UDP_RECEIVE_ADMISSION,
            EVENT_UDP_RECEIVE_ADMISSION_FAILURE,
            Some("socket.protocol_memory"),
        ) => Some(SocketCausalFindingContract {
            id: FINDING_SOCKET_PROTOCOL_MEMORY_REJECTION,
            title: "UDP protocol memory rejection",
            summary: "The UDP receive path reported skb admission rejection because protocol memory scheduling failed.",
        }),
        (
            PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
            EVENT_SOCKET_RECEIVE_QUEUE_FULL,
            Some("socket.receive_queue"),
        ) => Some(SocketCausalFindingContract {
            id: FINDING_SOCKET_RECEIVE_QUEUE_REJECTION,
            title: "Generic socket receive queue rejection",
            summary: "The generic socket receive helper reported skb admission rejection at its receive-buffer occupancy check.",
        }),
        _ => None,
    }
}

fn reserved_socket_causal_finding_id(id: &str) -> bool {
    matches!(
        id,
        FINDING_SOCKET_RECEIVE_QUEUE_REJECTION | FINDING_SOCKET_PROTOCOL_MEMORY_REJECTION
    )
}

pub(crate) fn metric_measurement_identity(metric_type: &str) -> &str {
    match metric_type {
        "linux.mib.tcp_ext.listen_drops" | "linux.mib.tcp_ext.listen_overflows" => {
            "linux.measurement.tcp.listen_queue_drop"
        }
        "linux.mib.tcp.retrans_segs" | "linux.mib.tcp_ext.tcp_syn_retrans" => {
            "linux.measurement.tcp.retransmission"
        }
        _ => metric_type,
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Socket,
    Transport,
    Network,
    Netfilter,
    Route,
    Xfrm,
    VirtualDevice,
    Tc,
    Netdevice,
    Xdp,
    Driver,
    Nic,
    KernelBypass,
}

impl Layer {
    pub const ALL: [Self; 13] = [
        Self::Socket,
        Self::Transport,
        Self::Network,
        Self::Netfilter,
        Self::Route,
        Self::Xfrm,
        Self::VirtualDevice,
        Self::Tc,
        Self::Netdevice,
        Self::Xdp,
        Self::Driver,
        Self::Nic,
        Self::KernelBypass,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Transport => "transport",
            Self::Network => "network",
            Self::Netfilter => "netfilter",
            Self::Route => "route",
            Self::Xfrm => "xfrm",
            Self::VirtualDevice => "virtual_device",
            Self::Tc => "tc",
            Self::Netdevice => "netdevice",
            Self::Xdp => "xdp",
            Self::Driver => "driver",
            Self::Nic => "nic",
            Self::KernelBypass => "kernel_bypass",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageAvailability {
    Active,
    Degraded,
    Error,
    Unsupported,
}

impl CoverageAvailability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Error => "error",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageVisibility {
    FullForDeclaredScope,
    Partial,
    Unknown,
}

impl CoverageVisibility {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullForDeclaredScope => "full_for_declared_scope",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterSupport {
    KernelExact,
    UserspaceExact,
    BroaderOnly,
    Unsupported,
}

impl FilterSupport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelExact => "kernel_exact",
            Self::UserspaceExact => "userspace_exact",
            Self::BroaderOnly => "broader_only",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageIntegrity {
    Complete,
    Sampled,
    LossDetected,
    Unknown,
}

impl CoverageIntegrity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Sampled => "sampled",
            Self::LossDetected => "loss_detected",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LayerCoverage {
    pub layer: Layer,
    pub availability: CoverageAvailability,
    pub visibility: CoverageVisibility,
    #[serde(deserialize_with = "deserialize_unique_forms")]
    pub forms: BTreeSet<EvidenceForm>,
    pub filter_support: FilterSupport,
    pub integrity: CoverageIntegrity,
    pub sources: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderStageCoverage {
    pub provider: NamespacedName,
    pub layer: Layer,
    pub stage: StageId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub execution_domain: Option<NamespacedName>,
    pub availability: CoverageAvailability,
    pub visibility: CoverageVisibility,
    #[serde(deserialize_with = "deserialize_unique_forms")]
    pub forms: BTreeSet<EvidenceForm>,
    pub filter_support: FilterSupport,
    pub integrity: CoverageIntegrity,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Available,
    Degraded,
    Unavailable,
}

impl ProviderState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderStatus {
    pub name: String,
    pub state: ProviderState,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TracepointCapability {
    pub available: bool,
    pub has_drop_reason: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub layout: Option<KfreeSkbLayout>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub format_path: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KfreeSkbLayout {
    Legacy,
    Reason,
    ReasonWithRxSk,
    Unsupported,
}

impl KfreeSkbLayout {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Reason => "reason",
            Self::ReasonWithRxSk => "reason_with_rx_sk",
            Self::Unsupported => "unsupported",
        }
    }

    pub const fn is_supported(self) -> bool {
        !matches!(self, Self::Unsupported)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BpfMode {
    CounterOnly,
    LegacyPerf,
    ReasonRing,
}

impl BpfMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CounterOnly => "counter_only",
            Self::LegacyPerf => "legacy_perf",
            Self::ReasonRing => "reason_ring",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityReport {
    pub schema_version: u16,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub kernel_release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_uid: Option<u32>,
    pub has_kernel_btf: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub tracefs_path: Option<String>,
    pub kfree_skb: TracepointCapability,
    pub selected_bpf_mode: BpfMode,
    pub providers: Vec<ProviderStatus>,
    pub coverage: Vec<LayerCoverage>,
    pub stage_coverage: Vec<ProviderStageCoverage>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricKey {
    pub source: String,
    pub group: String,
    pub metric: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl MetricKey {
    pub fn new(
        source: impl Into<String>,
        group: impl Into<String>,
        metric: impl Into<String>,
    ) -> Self {
        Self {
            source: source.into(),
            group: group.into(),
            metric: metric.into(),
            labels: BTreeMap::new(),
        }
    }

    pub fn with_label(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(name.into(), value.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricSample {
    pub key: MetricKey,
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMetricDelta {
    pub key: MetricKey,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub delta: Option<u64>,
    pub reset: bool,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NamespacedName(String);

impl NamespacedName {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidNamespacedName> {
        let value = value.into();
        if valid_namespaced_name(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidNamespacedName(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NamespacedName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidNamespacedName(String);

impl fmt::Display for InvalidNamespacedName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid namespaced name {:?}", self.0)
    }
}

impl std::error::Error for InvalidNamespacedName {}

fn valid_namespaced_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.is_empty()
        || !first.as_bytes()[0].is_ascii_lowercase()
        || !first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return false;
    }

    let mut saw_namespace = false;
    for segment in segments {
        saw_namespace = true;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return false;
        }
    }
    saw_namespace
}

macro_rules! report_local_id {
    ($name:ident, $error:ident, $prefix:literal, $description:literal) => {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, $error> {
                let value = value.into();
                if valid_report_local_id(&value, $prefix) {
                    Ok(Self(value))
                } else {
                    Err($error(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $error(String);

        impl fmt::Display for $error {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "invalid {} {:?}", $description, self.0)
            }
        }

        impl std::error::Error for $error {}
    };
}

report_local_id!(EvidenceId, InvalidEvidenceId, 'e', "evidence ID");
report_local_id!(SubjectId, InvalidSubjectId, 's', "subject ID");

fn valid_report_local_id(value: &str, prefix: char) -> bool {
    let Some(rest) = value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_prefix('_'))
    else {
        return false;
    };
    let Some((nonce, counter)) = rest.split_once('_') else {
        return false;
    };
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !counter.is_empty()
        && counter.as_bytes()[0].is_ascii_digit()
        && counter.as_bytes()[0] != b'0'
        && counter.bytes().all(|byte| byte.is_ascii_digit())
}

pub const MAX_ATTRIBUTES: usize = 16;
pub const MAX_ATTRIBUTE_STRING_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AttributeValue {
    String(String),
    Unsigned(u64),
    Boolean(bool),
}

impl AttributeValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            Self::Unsigned(_) | Self::Boolean(_) => None,
        }
    }

    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            Self::String(_) | Self::Boolean(_) => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Attributes(BTreeMap<NamespacedName, AttributeValue>);

impl Attributes {
    pub fn new(
        values: BTreeMap<NamespacedName, AttributeValue>,
    ) -> Result<Self, InvalidAttributes> {
        if values.len() > MAX_ATTRIBUTES {
            return Err(InvalidAttributes(format!(
                "attribute count {} exceeds limit {MAX_ATTRIBUTES}",
                values.len()
            )));
        }
        if let Some((name, value)) = values.iter().find(|(_, value)| {
            matches!(value, AttributeValue::String(value) if value.len() > MAX_ATTRIBUTE_STRING_BYTES)
        }) {
            return Err(InvalidAttributes(format!(
                "attribute {} string exceeds {MAX_ATTRIBUTE_STRING_BYTES} bytes: {value:?}",
                name.as_str()
            )));
        }
        Ok(Self(values))
    }

    pub fn insert(
        &mut self,
        name: NamespacedName,
        value: AttributeValue,
    ) -> Result<Option<AttributeValue>, InvalidAttributes> {
        if matches!(&value, AttributeValue::String(value) if value.len() > MAX_ATTRIBUTE_STRING_BYTES)
        {
            return Err(InvalidAttributes(format!(
                "attribute {} string exceeds {MAX_ATTRIBUTE_STRING_BYTES} bytes",
                name.as_str()
            )));
        }
        if !self.0.contains_key(&name) && self.0.len() == MAX_ATTRIBUTES {
            return Err(InvalidAttributes(format!(
                "attribute count exceeds limit {MAX_ATTRIBUTES}"
            )));
        }
        Ok(self.0.insert(name, value))
    }

    pub fn get(&self, name: &str) -> Option<&AttributeValue> {
        self.0
            .iter()
            .find_map(|(candidate, value)| (candidate.as_str() == name).then_some(value))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NamespacedName, &AttributeValue)> {
        self.0.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for Attributes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = BTreeMap::<NamespacedName, AttributeValue>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidAttributes(String);

impl fmt::Display for InvalidAttributes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InvalidAttributes {}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct StageId(String);

impl StageId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidStageId> {
        let value = value.into();
        if valid_stage_id(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidStageId(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn layer(&self) -> Option<Layer> {
        match self.0.split_once('.')?.0 {
            "socket" => Some(Layer::Socket),
            "transport" => Some(Layer::Transport),
            "network" => Some(Layer::Network),
            "netfilter" => Some(Layer::Netfilter),
            "route" => Some(Layer::Route),
            "xfrm" => Some(Layer::Xfrm),
            "virtual" => Some(Layer::VirtualDevice),
            "tc" | "qdisc" => Some(Layer::Tc),
            "netdevice" => Some(Layer::Netdevice),
            "xdp" => Some(Layer::Xdp),
            "driver" => Some(Layer::Driver),
            "nic" => Some(Layer::Nic),
            "kernel_bypass" => Some(Layer::KernelBypass),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for StageId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidStageId(String);

impl fmt::Display for InvalidStageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid namespaced stage identifier {:?}",
            self.0
        )
    }
}

impl std::error::Error for InvalidStageId {}

fn valid_stage_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    if first.is_empty()
        || !first.as_bytes()[0].is_ascii_lowercase()
        || !first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return false;
    }
    let mut saw_namespace = false;
    for segment in segments {
        saw_namespace = true;
        if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return false;
        }
    }
    saw_namespace
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathRole {
    LocalInput,
    LocalOutput,
    L2LocalInput,
    L2LocalOutput,
    L3Forward,
    L2Forward,
}

impl PathRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalInput => "local_input",
            Self::LocalOutput => "local_output",
            Self::L2LocalInput => "l2_local_input",
            Self::L2LocalOutput => "l2_local_output",
            Self::L3Forward => "l3_forward",
            Self::L2Forward => "l2_forward",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookRef {
    family: String,
    name: String,
}

impl HookRef {
    pub fn new(family: impl Into<String>, name: impl Into<String>) -> Result<Self, InvalidHookRef> {
        let family = family.into();
        let name = name.into();
        if !valid_hook_part(&family) {
            return Err(InvalidHookRef {
                field: "family",
                value: family,
            });
        }
        if !valid_hook_part(&name) {
            return Err(InvalidHookRef {
                field: "name",
                value: name,
            });
        }
        Ok(Self { family, name })
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl<'de> Deserialize<'de> for HookRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WireHookRef {
            family: String,
            name: String,
        }

        let value = WireHookRef::deserialize(deserializer)?;
        Self::new(value.family, value.name).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHookRef {
    field: &'static str,
    value: String,
}

impl fmt::Display for InvalidHookRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid hook {} identifier {:?}",
            self.field, self.value
        )
    }
}

impl std::error::Error for InvalidHookRef {}

fn valid_hook_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IfIndex(u32);

impl IfIndex {
    pub const MAX: u32 = i32::MAX as u32;

    pub fn new(value: u32) -> Result<Self, InvalidIfIndex> {
        if (1..=Self::MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidIfIndex(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for IfIndex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIfIndex(u32);

impl fmt::Display for InvalidIfIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Linux interface index {}", self.0)
    }
}

impl std::error::Error for InvalidIfIndex {}

#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceContext {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub network_namespace: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub ingress_ifindex: Option<IfIndex>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub egress_ifindex: Option<IfIndex>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub queue_id: Option<u32>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cpu: Option<u32>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub protocol: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeValueProvenance {
    Observed,
    Requested,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvidenceScopeProvenance {
    pub network_namespace: Option<ScopeValueProvenance>,
    pub ingress_ifindex: Option<ScopeValueProvenance>,
    pub egress_ifindex: Option<ScopeValueProvenance>,
    pub queue_id: Option<ScopeValueProvenance>,
    pub cpu: Option<ScopeValueProvenance>,
    pub protocol: Option<ScopeValueProvenance>,
}

impl EvidenceScopeProvenance {
    pub fn observed(context: &EvidenceContext) -> Self {
        let observed = |present: bool| present.then_some(ScopeValueProvenance::Observed);
        Self {
            network_namespace: observed(context.network_namespace.is_some()),
            ingress_ifindex: observed(context.ingress_ifindex.is_some()),
            egress_ifindex: observed(context.egress_ifindex.is_some()),
            queue_id: observed(context.queue_id.is_some()),
            cpu: observed(context.cpu.is_some()),
            protocol: observed(context.protocol.is_some()),
        }
    }

    pub fn validate(self, context: &EvidenceContext) -> Result<(), String> {
        let dimensions = [
            (
                "network namespace",
                context.network_namespace.is_some(),
                self.network_namespace,
            ),
            (
                "ingress ifindex",
                context.ingress_ifindex.is_some(),
                self.ingress_ifindex,
            ),
            (
                "egress ifindex",
                context.egress_ifindex.is_some(),
                self.egress_ifindex,
            ),
            ("queue", context.queue_id.is_some(), self.queue_id),
            ("CPU", context.cpu.is_some(), self.cpu),
            ("protocol", context.protocol.is_some(), self.protocol),
        ];
        for (dimension, present, provenance) in dimensions {
            match (present, provenance) {
                (true, Some(ScopeValueProvenance::Observed)) | (false, None) => {}
                (true, Some(ScopeValueProvenance::Requested)) => {
                    return Err(format!(
                        "evidence {dimension} context came from requested scope"
                    ))
                }
                (true, None) => {
                    return Err(format!(
                        "evidence {dimension} context has no declared provenance"
                    ))
                }
                (false, Some(_)) => {
                    return Err(format!(
                        "evidence {dimension} provenance has no context value"
                    ))
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Dropped,
    Rejected,
    Consumed,
    Passed,
    Redirected,
    Queued,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    Aborted,
    RedirectFailed,
    Backpressure,
    Congestion,
    Pressure,
    Timeout,
    Retransmission,
    Reset,
    Error,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Outcome {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub disposition: Option<Disposition>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub signal: Option<Signal>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceForm {
    Event,
    CounterDelta,
    Gauge,
    Inventory,
}

impl EvidenceForm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::CounterDelta => "counter_delta",
            Self::Gauge => "gauge",
            Self::Inventory => "inventory",
        }
    }
}

fn deserialize_unique_forms<'de, D>(deserializer: D) -> Result<BTreeSet<EvidenceForm>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let forms = Vec::<EvidenceForm>::deserialize(deserializer)?;
    let count = forms.len();
    let forms: BTreeSet<_> = forms.into_iter().collect();
    if forms.len() != count {
        return Err(serde::de::Error::custom("duplicate evidence form"));
    }
    Ok(forms)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    Causal,
    Symptom,
    Context,
    Telemetry,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementUnit {
    Occurrences,
    Bytes,
    Nanoseconds,
    SourceUnits,
}

impl MeasurementUnit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Occurrences => "occurrences",
            Self::Bytes => "bytes",
            Self::Nanoseconds => "nanoseconds",
            Self::SourceUnits => "source_units",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementDomain {
    WireFrame,
    InterfacePacket,
    XdpFrame,
    Skb,
    GroAggregate,
    GsoSuperPacket,
    L3Packet,
    Datagram,
    TcpSegment,
    SocketMessage,
    PolicyHit,
    QueueEntry,
    Connection,
    Interrupt,
    PollCycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementScope {
    Event,
    Flow,
    Socket,
    Cpu,
    Queue,
    Interface,
    NetworkNamespace,
    Host,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementBound {
    Exact,
    LowerBound,
    Estimate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Measurement {
    pub unit: MeasurementUnit,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub domain: Option<MeasurementDomain>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub scope: Option<MeasurementScope>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub bound: Option<MeasurementBound>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDescriptor {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub stage: Option<StageId>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub hook: Option<HookRef>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub direction: Option<Direction>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub path_role: Option<PathRole>,
    pub context: EvidenceContext,
    pub outcome: Outcome,
    pub form: EvidenceForm,
    pub role: EvidenceRole,
    pub measurement: Measurement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Direct,
    Correlated,
    Suspected,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Correlated => "correlated",
            Self::Suspected => "suspected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub layer: Option<Layer>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub execution_domain: Option<NamespacedName>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub transition: Option<NamespacedName>,
    pub descriptor: EvidenceDescriptor,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub summary: String,
    pub count: u64,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Metric,
    Observation,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: EvidenceKind,
    pub id: EvidenceId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Socket,
    Rule,
    Program,
    Queue,
    Interface,
    Hop,
    FlowDomain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRole {
    Primary,
    Ingress,
    Egress,
    Owner,
    Peer,
    Before,
    After,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRef {
    pub role: SubjectRole,
    pub id: SubjectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Subject {
    pub id: SubjectId,
    pub provider: NamespacedName,
    pub kind: SubjectKind,
    pub attributes: Attributes,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceMeta {
    pub id: EvidenceId,
    pub provider: NamespacedName,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub layer: Option<Layer>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub execution_domain: Option<NamespacedName>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub transition: Option<NamespacedName>,
    pub descriptor: EvidenceDescriptor,
    pub subjects: Vec<SubjectRef>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricValues {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub start: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub end: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub delta: Option<u64>,
    pub reset: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricDelta {
    pub meta: EvidenceMeta,
    pub metric_type: NamespacedName,
    pub values: MetricValues,
    pub attributes: Attributes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawObservation {
    pub monotonic_ns: u64,
    pub reason: Option<u32>,
    pub reason_name: Option<String>,
    pub layer: Option<Layer>,
    pub descriptor: EvidenceDescriptor,
    pub scope_provenance: EvidenceScopeProvenance,
    pub source_mode: BpfMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub meta: EvidenceMeta,
    pub event_type: NamespacedName,
    pub monotonic_ns: u64,
    pub attributes: Attributes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceRecordType {
    Observation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceRecord {
    pub schema_version: u16,
    pub record_type: TraceRecordType,
    pub sequence: u64,
    pub provider: NamespacedName,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub layer: Option<Layer>,
    pub descriptor: EvidenceDescriptor,
    pub event_type: NamespacedName,
    pub monotonic_ns: u64,
    pub attributes: Attributes,
}

impl TraceRecord {
    pub fn from_observation(
        sequence: u64,
        observation: Observation,
    ) -> Result<Self, ReportValidationError> {
        if !observation.meta.subjects.is_empty() {
            return invalid("trace observations cannot carry report-local subject references");
        }
        if observation.meta.transition.is_some() {
            return invalid("event stream v1 cannot carry path transition metadata");
        }
        if observation
            .meta
            .execution_domain
            .as_ref()
            .map(|domain| domain.as_str())
            != Some("linux.kernel")
        {
            return invalid("event stream v1 requires the linux.kernel execution domain");
        }
        let layer = match (
            observation.meta.layer,
            observation.meta.descriptor.stage.as_ref(),
        ) {
            (Some(Layer::Xfrm), Some(stage))
                if stage
                    .as_str()
                    .split_once('.')
                    .map(|(namespace, _)| namespace)
                    == Some("xfrm") =>
            {
                Some(Layer::Route)
            }
            (layer, _) => layer,
        };
        let record = Self {
            schema_version: EVENT_STREAM_SCHEMA_VERSION,
            record_type: TraceRecordType::Observation,
            sequence,
            provider: observation.meta.provider,
            layer,
            descriptor: observation.meta.descriptor,
            event_type: observation.event_type,
            monotonic_ns: observation.monotonic_ns,
            attributes: observation.attributes,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ReportValidationError> {
        if self.schema_version != EVENT_STREAM_SCHEMA_VERSION {
            return invalid(format!(
                "schemaVersion {} does not match event stream v{EVENT_STREAM_SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        if self.sequence == 0 {
            return invalid("trace record sequence must be greater than zero");
        }
        let reason_code = self.attributes.get(ATTR_SKB_REASON_CODE).is_some();
        let reason_name = self.attributes.get(ATTR_SKB_REASON_NAME).is_some();
        let source_mode = self
            .attributes
            .get(ATTR_BPF_MODE)
            .and_then(AttributeValue::as_str);
        match source_mode {
            Some("legacy_perf") if !reason_code && !reason_name => {}
            Some("reason_ring") if reason_code => {}
            Some("legacy_perf") => {
                return invalid("legacy event stream records cannot carry a drop reason")
            }
            Some("reason_ring") => {
                return invalid("reason-aware event stream records require a raw reason code")
            }
            Some(_) => return invalid("event stream records use an unsupported source mode"),
            None => return invalid("event stream record is missing its source mode"),
        }

        if self.provider.as_str() != PROVIDER_KFREE_SKB
            || self.event_type.as_str() != EVENT_SKB_FREE
        {
            return invalid(format!(
                "event type {} is not registered for provider {}",
                self.event_type.as_str(),
                self.provider.as_str()
            ));
        }
        if self.descriptor.form != EvidenceForm::Event {
            return invalid("event stream records require event-form descriptors");
        }
        match self.descriptor.stage.as_ref() {
            Some(stage) => match trace_stage_layer_v1(stage) {
                Some(layer) if self.layer == Some(layer) => {}
                Some(_) => return invalid("event stream record layer conflicts with its stage"),
                None => return invalid("event stream record uses an unregistered v1 stage"),
            },
            None if self.layer.is_some() => {
                return invalid("event stream record asserts a layer without a registered stage")
            }
            None => {}
        }
        if matches!(
            self.descriptor.path_role,
            Some(PathRole::L2LocalInput | PathRole::L2LocalOutput)
        ) {
            return invalid("event stream v1 does not support L2 local path roles");
        }
        validate_attributes(
            &self.provider,
            AttributeOwner::Observation,
            &self.attributes,
        )?;
        if reason_name && !reason_code {
            return invalid("skb-free reason name requires a raw reason code");
        }
        Ok(())
    }
}

fn trace_stage_layer_v1(stage: &StageId) -> Option<Layer> {
    match stage.as_str().split_once('.')?.0 {
        "socket" => Some(Layer::Socket),
        "transport" => Some(Layer::Transport),
        "netfilter" => Some(Layer::Netfilter),
        "route" | "xfrm" => Some(Layer::Route),
        "virtual" => Some(Layer::VirtualDevice),
        "tc" | "qdisc" => Some(Layer::Tc),
        "netdevice" => Some(Layer::Netdevice),
        "xdp" => Some(Layer::Xdp),
        "driver" => Some(Layer::Driver),
        "nic" => Some(Layer::Nic),
        "kernel_bypass" => Some(Layer::KernelBypass),
        _ => None,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundaryCounters<T> {
    pub bpf_events_seen: T,
    pub bpf_output_lost: T,
    pub transport_events_received: T,
    pub transport_events_lost: T,
    pub user_events_dropped: T,
    pub netlink_loss_events: T,
    pub netlink_dump_interruptions: T,
    pub parse_errors: T,
}

impl<T> BoundaryCounters<T> {
    pub fn as_refs(&self) -> BoundaryCounters<&T> {
        BoundaryCounters {
            bpf_events_seen: &self.bpf_events_seen,
            bpf_output_lost: &self.bpf_output_lost,
            transport_events_received: &self.transport_events_received,
            transport_events_lost: &self.transport_events_lost,
            user_events_dropped: &self.user_events_dropped,
            netlink_loss_events: &self.netlink_loss_events,
            netlink_dump_interruptions: &self.netlink_dump_interruptions,
            parse_errors: &self.parse_errors,
        }
    }
}

impl<T: Clone> BoundaryCounters<T> {
    pub fn filled(value: T) -> Self {
        Self {
            bpf_events_seen: value.clone(),
            bpf_output_lost: value.clone(),
            transport_events_received: value.clone(),
            transport_events_lost: value.clone(),
            user_events_dropped: value.clone(),
            netlink_loss_events: value.clone(),
            netlink_dump_interruptions: value.clone(),
            parse_errors: value,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CounterStatus {
    Measured { value: u64 },
    NotApplicable,
    Unknown,
}

impl CounterStatus {
    pub const fn measured(value: u64) -> Self {
        Self::Measured { value }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TotalBound {
    Exact,
    LowerBound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedTotal {
    pub value: u64,
    pub bound: TotalBound,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SamplingComponent {
    None {
        scope: NamespacedName,
    },
    Sampled {
        method: NamespacedName,
        scope: NamespacedName,
        effective_numerator: u32,
        effective_denominator: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SamplingTelemetry {
    None,
    Sampled {
        method: NamespacedName,
        scope: NamespacedName,
        effective_numerator: u32,
        effective_denominator: u32,
    },
    Mixed {
        components: Vec<SamplingComponent>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollectionError {
    pub provider: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderTelemetry {
    pub provider: NamespacedName,
    pub counters: BoundaryCounters<CounterStatus>,
    pub sampling: SamplingTelemetry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telemetry {
    pub totals: BoundaryCounters<BoundedTotal>,
    pub providers: Vec<ProviderTelemetry>,
    pub collection_errors: Vec<CollectionError>,
    pub sampling: SamplingTelemetry,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureScope {
    pub requested: RequestedScope,
    pub providers: Vec<ProviderScope>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureWindow {
    pub started_at_unix_ms: u64,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub schema_version: u16,
    pub window: CaptureWindow,
    pub scope: CaptureScope,
    pub capabilities: CapabilityReport,
    pub subjects: Vec<Subject>,
    pub metrics: Vec<MetricDelta>,
    pub observations: Vec<Observation>,
    pub findings: Vec<Finding>,
    pub telemetry: Telemetry,
}

impl Telemetry {
    pub fn from_providers(
        mut providers: Vec<ProviderTelemetry>,
        collection_errors: Vec<CollectionError>,
    ) -> Result<Self, ReportValidationError> {
        providers.sort_by(|left, right| left.provider.cmp(&right.provider));
        let totals = totals_from_providers(&providers);
        let sampling = aggregate_sampling(&providers);
        let telemetry = Self {
            totals,
            providers,
            collection_errors,
            sampling,
        };
        telemetry.validate()?;
        Ok(telemetry)
    }

    pub fn validate(&self) -> Result<(), ReportValidationError> {
        let mut provider_ids = BTreeSet::new();
        for provider in &self.providers {
            validate_provider_name(&provider.provider)?;
            if !provider_ids.insert(provider.provider.clone()) {
                return invalid(format!(
                    "duplicate telemetry provider {}",
                    provider.provider.as_str()
                ));
            }
            validate_sampling(&provider.sampling)?;
            validate_provider_counter_applicability(provider)?;
        }
        for error in &self.collection_errors {
            if !known_provider(&error.provider) {
                return invalid(format!(
                    "collection error uses unregistered provider {:?}",
                    error.provider
                ));
            }
            if error.message.is_empty() || error.message.len() > 1_024 {
                return invalid("collection error message must contain 1..=1024 bytes");
            }
            if !provider_ids
                .iter()
                .any(|provider| provider.as_str() == error.provider)
            {
                return invalid(format!(
                    "collection error provider {} has no telemetry row",
                    error.provider
                ));
            }
        }

        let expected_totals = totals_from_providers(&self.providers);
        if self.totals != expected_totals {
            return invalid("telemetry totals do not match provider boundary counters");
        }
        let expected_sampling = aggregate_sampling(&self.providers);
        if self.sampling != expected_sampling {
            return invalid("session sampling does not match provider sampling");
        }
        validate_sampling(&self.sampling)
    }
}

fn validate_provider_counter_applicability(
    provider: &ProviderTelemetry,
) -> Result<(), ReportValidationError> {
    if !provider_has_applicable_boundary(provider) {
        return Ok(());
    }
    let Some(descriptor) = provider_registry::descriptor(provider.provider.as_str()) else {
        return invalid(format!(
            "unregistered telemetry provider {}",
            provider.provider.as_str()
        ));
    };
    let rules = descriptor.telemetry.as_array();
    let counters = provider.counters.as_refs();
    let statuses = [
        counters.bpf_events_seen,
        counters.bpf_output_lost,
        counters.transport_events_received,
        counters.transport_events_lost,
        counters.user_events_dropped,
        counters.netlink_loss_events,
        counters.netlink_dump_interruptions,
        counters.parse_errors,
    ];

    if rules.iter().zip(statuses).any(|(rule, status)| {
        *rule == TelemetryCounterRule::NotApplicable
            && !matches!(status, CounterStatus::NotApplicable)
    }) {
        return invalid(format!(
            "provider {} marks an unsupported boundary applicable",
            provider.provider.as_str()
        ));
    }
    if rules.iter().zip(statuses).any(|(rule, status)| {
        *rule == TelemetryCounterRule::Required && matches!(status, CounterStatus::NotApplicable)
    }) {
        return invalid(format!(
            "provider {} marks a required boundary not applicable",
            provider.provider.as_str()
        ));
    }

    let groups: BTreeSet<_> = rules
        .iter()
        .filter_map(|rule| match rule {
            TelemetryCounterRule::AllOrNone(group) => Some(*group),
            _ => None,
        })
        .collect();
    for group in groups {
        let mut expected = None;
        for applicable in rules
            .iter()
            .zip(statuses)
            .filter_map(|(rule, status)| match rule {
                TelemetryCounterRule::AllOrNone(candidate) if *candidate == group => {
                    Some(!matches!(status, CounterStatus::NotApplicable))
                }
                _ => None,
            })
        {
            if expected.is_some_and(|expected| expected != applicable) {
                return invalid(format!(
                    "provider {} must mark its complete {group} applicable or not applicable",
                    provider.provider.as_str()
                ));
            }
            expected = Some(applicable);
        }
    }
    Ok(())
}

fn totals_from_providers(providers: &[ProviderTelemetry]) -> BoundaryCounters<BoundedTotal> {
    BoundaryCounters {
        bpf_events_seen: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.bpf_events_seen),
        ),
        bpf_output_lost: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.bpf_output_lost),
        ),
        transport_events_received: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.transport_events_received),
        ),
        transport_events_lost: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.transport_events_lost),
        ),
        user_events_dropped: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.user_events_dropped),
        ),
        netlink_loss_events: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.netlink_loss_events),
        ),
        netlink_dump_interruptions: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.netlink_dump_interruptions),
        ),
        parse_errors: bounded_total(
            providers
                .iter()
                .map(|provider| &provider.counters.parse_errors),
        ),
    }
}

fn bounded_total<'a>(values: impl Iterator<Item = &'a CounterStatus>) -> BoundedTotal {
    let mut value = 0_u64;
    let mut lower_bound = false;
    for status in values {
        match status {
            CounterStatus::Measured { value: measured } => {
                let (sum, overflowed) = value.overflowing_add(*measured);
                if overflowed {
                    value = u64::MAX;
                    lower_bound = true;
                } else {
                    value = sum;
                }
            }
            CounterStatus::NotApplicable => {}
            CounterStatus::Unknown => lower_bound = true,
        }
    }
    BoundedTotal {
        value,
        bound: if lower_bound {
            TotalBound::LowerBound
        } else {
            TotalBound::Exact
        },
    }
}

fn aggregate_sampling(providers: &[ProviderTelemetry]) -> SamplingTelemetry {
    let Some(first) = providers.first().map(|provider| &provider.sampling) else {
        return SamplingTelemetry::None;
    };
    if providers.iter().all(|provider| provider.sampling == *first) {
        return first.clone();
    }

    let mut components = BTreeSet::new();
    for provider in providers {
        match &provider.sampling {
            SamplingTelemetry::None => {
                components.insert(SamplingComponent::None {
                    scope: provider.provider.clone(),
                });
            }
            SamplingTelemetry::Sampled {
                method,
                scope,
                effective_numerator,
                effective_denominator,
            } => {
                components.insert(SamplingComponent::Sampled {
                    method: method.clone(),
                    scope: scope.clone(),
                    effective_numerator: *effective_numerator,
                    effective_denominator: *effective_denominator,
                });
            }
            SamplingTelemetry::Mixed { components: nested } => {
                components.extend(nested.iter().cloned())
            }
        }
    }
    SamplingTelemetry::Mixed {
        components: components.into_iter().collect(),
    }
}

fn validate_sampling(sampling: &SamplingTelemetry) -> Result<(), ReportValidationError> {
    match sampling {
        SamplingTelemetry::None => Ok(()),
        SamplingTelemetry::Sampled {
            method,
            scope,
            effective_numerator,
            effective_denominator,
        } => validate_sampling_ratio(method, scope, *effective_numerator, *effective_denominator),
        SamplingTelemetry::Mixed { components } => {
            if !(2..=MAX_SAMPLING_COMPONENTS).contains(&components.len()) {
                return invalid(format!(
                    "mixed sampling must contain 2..={MAX_SAMPLING_COMPONENTS} components"
                ));
            }
            let unique: BTreeSet<_> = components.iter().collect();
            if unique.len() != components.len() {
                return invalid("mixed sampling contains duplicate components");
            }
            for component in components {
                match component {
                    SamplingComponent::None { scope } => {
                        if !valid_namespaced_name(scope.as_str()) {
                            return invalid("sampling scope is not namespaced");
                        }
                    }
                    SamplingComponent::Sampled {
                        method,
                        scope,
                        effective_numerator,
                        effective_denominator,
                    } => validate_sampling_ratio(
                        method,
                        scope,
                        *effective_numerator,
                        *effective_denominator,
                    )?,
                }
            }
            Ok(())
        }
    }
}

fn validate_sampling_ratio(
    method: &NamespacedName,
    scope: &NamespacedName,
    numerator: u32,
    denominator: u32,
) -> Result<(), ReportValidationError> {
    if !valid_namespaced_name(method.as_str()) || !valid_namespaced_name(scope.as_str()) {
        return invalid("sampling method and scope must be namespaced");
    }
    if numerator == 0 || denominator == 0 || numerator > denominator {
        return invalid("sampled ratio must satisfy 0 < numerator <= denominator");
    }
    Ok(())
}

impl Report {
    pub fn validate(&self) -> Result<(), ReportValidationError> {
        if !matches!(
            self.schema_version,
            REPORT_V4_SCHEMA_VERSION | SCHEMA_VERSION
        ) {
            return invalid(format!(
                "unsupported report schemaVersion {}",
                self.schema_version
            ));
        }
        if self.capabilities.schema_version != self.schema_version {
            return invalid(format!(
                "capability schemaVersion {} does not match report schemaVersion {}",
                self.capabilities.schema_version, self.schema_version
            ));
        }
        self.capabilities.validate_for_schema(self.schema_version)?;
        self.scope.validate(&self.telemetry)?;
        validate_evidence_for_schema(
            self.schema_version,
            &self.subjects,
            &self.metrics,
            &self.observations,
        )?;
        validate_evidence_provider_scopes(&self.scope, &self.metrics, &self.observations)?;
        validate_evidence_stage_coverage(&self.capabilities, &self.metrics, &self.observations)?;
        validate_findings(
            self.schema_version,
            &self.subjects,
            &self.metrics,
            &self.observations,
            &self.findings,
        )?;
        self.telemetry.validate()?;
        validate_evidence_provider_telemetry(&self.metrics, &self.observations, &self.telemetry)?;
        validate_evidence_bounds(&self.metrics, &self.observations, &self.telemetry)
    }
}

impl CapabilityReport {
    pub fn validate(&self) -> Result<(), ReportValidationError> {
        self.validate_for_schema(SCHEMA_VERSION)
    }

    fn validate_for_schema(&self, schema_version: u16) -> Result<(), ReportValidationError> {
        if self.schema_version != schema_version {
            return invalid(format!(
                "capability schemaVersion {} does not match report schemaVersion {schema_version}",
                self.schema_version,
            ));
        }
        match (schema_version, self.effective_uid) {
            (REPORT_V4_SCHEMA_VERSION, None) => {
                return invalid("report v4 capability is missing effectiveUid")
            }
            (SCHEMA_VERSION, Some(_)) => {
                return invalid("report v5 capability cannot expose effectiveUid")
            }
            _ => {}
        }

        let mut provider_states = BTreeMap::new();
        for provider in &self.providers {
            if provider_states
                .insert(provider.name.as_str(), provider.state)
                .is_some()
            {
                return invalid(format!("duplicate capability provider {}", provider.name));
            }
        }
        let mut coverage_layers = BTreeMap::new();
        for coverage in &self.coverage {
            if coverage_layers.insert(coverage.layer, coverage).is_some() {
                return invalid(format!(
                    "duplicate layer coverage for {}",
                    coverage.layer.as_str()
                ));
            }
            match coverage.availability {
                CoverageAvailability::Active | CoverageAvailability::Degraded
                    if coverage.forms.is_empty() =>
                {
                    return invalid(format!(
                        "available layer coverage {} declares no evidence forms",
                        coverage.layer.as_str()
                    ));
                }
                CoverageAvailability::Error | CoverageAvailability::Unsupported
                    if !coverage.forms.is_empty() =>
                {
                    return invalid(format!(
                        "unavailable layer coverage {} declares evidence forms",
                        coverage.layer.as_str()
                    ));
                }
                _ => {}
            }
            let mut sources = BTreeSet::new();
            for source in &coverage.sources {
                if !sources.insert(source) {
                    return invalid(format!(
                        "duplicate source {source} for layer {}",
                        coverage.layer.as_str()
                    ));
                }
                let Some(provider) = provider_registry::descriptor_for_capability_source(source)
                else {
                    return invalid(format!(
                        "layer coverage {} uses unregistered source {source}",
                        coverage.layer.as_str()
                    ));
                };
                if !provider.owns_layer(coverage.layer) {
                    return invalid(format!(
                        "layer coverage {} is outside source {source} ownership",
                        coverage.layer.as_str()
                    ));
                }
            }
        }
        let mut rows = BTreeSet::new();
        for coverage in &self.stage_coverage {
            validate_provider_name(&coverage.provider)?;
            let Some(provider_state) = provider_states.get(coverage.provider.as_str()) else {
                return invalid(format!(
                    "stage coverage provider {} has no capability provider row",
                    coverage.provider.as_str()
                ));
            };
            if coverage.stage.layer() != Some(coverage.layer) {
                return invalid(format!(
                    "stage coverage {} conflicts with layer {}",
                    coverage.stage.as_str(),
                    coverage.layer.as_str()
                ));
            }
            let descriptor = provider_registry::descriptor(coverage.provider.as_str())
                .expect("validated providers have descriptors");
            if !descriptor.owns_layer(coverage.layer) {
                return invalid(format!(
                    "stage coverage {} is outside provider {} ownership",
                    coverage.stage.as_str(),
                    coverage.provider.as_str()
                ));
            }
            let Some(layer_coverage) = coverage_layers.get(&coverage.layer) else {
                return invalid(format!(
                    "stage coverage {} has no aggregate layer coverage",
                    coverage.stage.as_str()
                ));
            };
            if !rows.insert((
                coverage.provider.clone(),
                coverage.stage.clone(),
                coverage.execution_domain.clone(),
            )) {
                return invalid(format!(
                    "duplicate stage coverage for provider {} stage {}",
                    coverage.provider.as_str(),
                    coverage.stage.as_str()
                ));
            }
            match coverage.availability {
                CoverageAvailability::Active | CoverageAvailability::Degraded
                    if coverage.forms.is_empty() =>
                {
                    return invalid(format!(
                        "available stage coverage {} declares no evidence forms",
                        coverage.stage.as_str()
                    ));
                }
                CoverageAvailability::Error | CoverageAvailability::Unsupported
                    if !coverage.forms.is_empty() =>
                {
                    return invalid(format!(
                        "unavailable stage coverage {} declares evidence forms",
                        coverage.stage.as_str()
                    ));
                }
                _ => {}
            }
            if matches!(
                coverage.availability,
                CoverageAvailability::Active | CoverageAvailability::Degraded
            ) {
                if *provider_state == ProviderState::Unavailable {
                    return invalid(format!(
                        "active stage coverage {} belongs to unavailable provider {}",
                        coverage.stage.as_str(),
                        coverage.provider.as_str()
                    ));
                }
                if !matches!(
                    layer_coverage.availability,
                    CoverageAvailability::Active | CoverageAvailability::Degraded
                ) {
                    return invalid(format!(
                        "active stage coverage {} has unavailable aggregate layer {}",
                        coverage.stage.as_str(),
                        coverage.layer.as_str()
                    ));
                }
                if !coverage.forms.is_subset(&layer_coverage.forms) {
                    return invalid(format!(
                        "stage coverage {} forms are absent from aggregate layer {}",
                        coverage.stage.as_str(),
                        coverage.layer.as_str()
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_evidence_provider_scopes(
    scope: &CaptureScope,
    metrics: &[MetricDelta],
    observations: &[Observation],
) -> Result<(), ReportValidationError> {
    let providers: BTreeMap<_, _> = scope
        .providers
        .iter()
        .map(|provider| (provider.provider.as_str(), provider))
        .collect();
    for meta in metrics
        .iter()
        .map(|metric| &metric.meta)
        .chain(observations.iter().map(|observation| &observation.meta))
    {
        let provider = providers.get(meta.provider.as_str()).ok_or_else(|| {
            ReportValidationError(format!(
                "evidence {} belongs to provider {} with no provider scope",
                meta.id.as_str(),
                meta.provider.as_str()
            ))
        })?;
        let effective = provider.effective.as_ref().ok_or_else(|| {
            ReportValidationError(format!(
                "evidence {} belongs to provider {} with no effective scope",
                meta.id.as_str(),
                meta.provider.as_str()
            ))
        })?;
        if meta
            .layer
            .is_some_and(|layer| !effective.layers.contains(&layer))
        {
            return invalid(format!(
                "evidence {} layer is outside provider {} effective scope",
                meta.id.as_str(),
                meta.provider.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_evidence_stage_coverage(
    capabilities: &CapabilityReport,
    metrics: &[MetricDelta],
    observations: &[Observation],
) -> Result<(), ReportValidationError> {
    for meta in metrics
        .iter()
        .map(|metric| &metric.meta)
        .chain(observations.iter().map(|observation| &observation.meta))
    {
        let Some(stage) = meta.descriptor.stage.as_ref() else {
            continue;
        };
        let coverage = capabilities.stage_coverage.iter().find(|coverage| {
            coverage.provider == meta.provider
                && Some(coverage.layer) == meta.layer
                && coverage.stage == *stage
                && coverage.execution_domain == meta.execution_domain
        });
        let Some(coverage) = coverage else {
            return invalid(format!(
                "evidence {} has no matching provider-stage execution-domain coverage",
                meta.id.as_str()
            ));
        };
        if !matches!(
            coverage.availability,
            CoverageAvailability::Active | CoverageAvailability::Degraded
        ) {
            return invalid(format!(
                "evidence {} belongs to unavailable stage coverage",
                meta.id.as_str()
            ));
        }
        if !coverage.forms.contains(&meta.descriptor.form) {
            return invalid(format!(
                "evidence {} form is absent from its stage coverage",
                meta.id.as_str()
            ));
        }
    }
    Ok(())
}

impl CaptureScope {
    pub fn validate(&self, telemetry: &Telemetry) -> Result<(), ReportValidationError> {
        self.requested
            .validate()
            .map_err(|error| ReportValidationError(format!("invalid requested scope: {error}")))?;
        let mut providers = BTreeSet::new();
        for provider_scope in &self.providers {
            provider_scope.validate().map_err(|error| {
                ReportValidationError(format!(
                    "invalid scope for provider {}: {error}",
                    provider_scope.provider.as_str()
                ))
            })?;
            if provider_scope.requested != self.requested {
                return invalid(format!(
                    "provider {} requested scope does not match report scope",
                    provider_scope.provider.as_str()
                ));
            }
            validate_provider_name(&provider_scope.provider)?;
            let descriptor = provider_registry::descriptor(provider_scope.provider.as_str())
                .expect("validated providers have descriptors");
            if provider_scope.effective.as_ref().is_some_and(|effective| {
                effective
                    .layers
                    .iter()
                    .any(|layer| !descriptor.owns_layer(*layer))
            }) {
                return invalid(format!(
                    "provider scope {} includes a layer outside its ownership",
                    provider_scope.provider.as_str()
                ));
            }
            if !providers.insert(provider_scope.provider.clone()) {
                return invalid(format!(
                    "duplicate provider scope {}",
                    provider_scope.provider.as_str()
                ));
            }
        }
        let telemetry_providers: BTreeSet<_> = telemetry
            .providers
            .iter()
            .map(|provider| provider.provider.clone())
            .collect();
        if providers != telemetry_providers {
            return invalid("provider scopes do not match telemetry providers");
        }
        Ok(())
    }
}

fn validate_evidence_provider_telemetry(
    metrics: &[MetricDelta],
    observations: &[Observation],
    telemetry: &Telemetry,
) -> Result<(), ReportValidationError> {
    let providers: BTreeMap<_, _> = telemetry
        .providers
        .iter()
        .map(|provider| (provider.provider.as_str(), provider))
        .collect();

    for (provider, evidence_id) in metrics
        .iter()
        .map(|metric| (&metric.meta.provider, &metric.meta.id))
        .chain(
            observations
                .iter()
                .map(|observation| (&observation.meta.provider, &observation.meta.id)),
        )
    {
        let telemetry = providers.get(provider.as_str()).ok_or_else(|| {
            ReportValidationError(format!(
                "evidence {} provider {} has no telemetry row",
                evidence_id.as_str(),
                provider.as_str()
            ))
        })?;
        if !provider_has_applicable_boundary(telemetry) {
            return invalid(format!(
                "evidence {} provider {} has no applicable telemetry boundary",
                evidence_id.as_str(),
                provider.as_str()
            ));
        }
    }
    Ok(())
}

fn provider_has_applicable_boundary(provider: &ProviderTelemetry) -> bool {
    let counters = provider.counters.as_refs();
    [
        counters.bpf_events_seen,
        counters.bpf_output_lost,
        counters.transport_events_received,
        counters.transport_events_lost,
        counters.user_events_dropped,
        counters.netlink_loss_events,
        counters.netlink_dump_interruptions,
        counters.parse_errors,
    ]
    .into_iter()
    .any(|status| !matches!(status, CounterStatus::NotApplicable))
}

pub fn validate_evidence(
    subjects: &[Subject],
    metrics: &[MetricDelta],
    observations: &[Observation],
) -> Result<(), ReportValidationError> {
    validate_evidence_for_schema(SCHEMA_VERSION, subjects, metrics, observations)
}

fn validate_evidence_for_schema(
    schema_version: u16,
    subjects: &[Subject],
    metrics: &[MetricDelta],
    observations: &[Observation],
) -> Result<(), ReportValidationError> {
    let subject_index = validate_subjects(subjects)?;
    let mut evidence_ids = BTreeSet::new();
    let mut socket_drop_subjects = BTreeSet::new();

    for metric in metrics {
        if !evidence_ids.insert(metric.meta.id.clone()) {
            return invalid(format!("duplicate evidence ID {}", metric.meta.id.as_str()));
        }
        validate_provider_name(&metric.meta.provider)?;
        validate_evidence_meta(&metric.meta, EvidenceForm::CounterDelta, &subject_index)?;
        validate_metric(schema_version, metric, &subject_index)?;
        if schema_version == SCHEMA_VERSION && metric.meta.provider.as_str() == PROVIDER_SOCK_DIAG {
            let subject_id = &metric
                .meta
                .subjects
                .first()
                .expect("validated sock_diag metric has one subject")
                .id;
            if !socket_drop_subjects.insert(subject_id.clone()) {
                return invalid(format!(
                    "sock_diag subject {} is reused by more than one metric",
                    subject_id.as_str()
                ));
            }
        }
    }
    for observation in observations {
        if !evidence_ids.insert(observation.meta.id.clone()) {
            return invalid(format!(
                "duplicate evidence ID {}",
                observation.meta.id.as_str()
            ));
        }
        validate_provider_name(&observation.meta.provider)?;
        validate_evidence_meta(&observation.meta, EvidenceForm::Event, &subject_index)?;
        validate_observation(schema_version, observation)?;
    }
    Ok(())
}

fn validate_subjects(
    subjects: &[Subject],
) -> Result<BTreeMap<SubjectId, &Subject>, ReportValidationError> {
    let mut index = BTreeMap::new();
    for subject in subjects {
        validate_provider_name(&subject.provider)?;
        if !valid_subject_provider_kind(subject.provider.as_str(), subject.kind) {
            return invalid(format!(
                "provider {} cannot own a {:?} subject",
                subject.provider.as_str(),
                subject.kind
            ));
        }
        validate_attributes(
            &subject.provider,
            AttributeOwner::Subject(subject.kind),
            &subject.attributes,
        )?;
        if subject.kind == SubjectKind::Hop && subject.attributes.get(ATTR_HOP_ORDINAL).is_none() {
            return invalid(format!(
                "hop subject {} is missing {ATTR_HOP_ORDINAL}",
                subject.id.as_str()
            ));
        }
        if index.insert(subject.id.clone(), subject).is_some() {
            return invalid(format!("duplicate subject ID {}", subject.id.as_str()));
        }
    }
    Ok(index)
}

fn validate_evidence_meta(
    meta: &EvidenceMeta,
    expected_form: EvidenceForm,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<(), ReportValidationError> {
    if meta.descriptor.form != expected_form {
        return invalid(format!(
            "evidence {} has form {:?}, expected {:?}",
            meta.id.as_str(),
            meta.descriptor.form,
            expected_form
        ));
    }
    match meta.descriptor.stage.as_ref() {
        Some(stage) => match stage.layer() {
            Some(stage_layer) if meta.layer == Some(stage_layer) => {}
            Some(_) => {
                return invalid(format!(
                    "evidence {} layer conflicts with its stage",
                    meta.id.as_str()
                ));
            }
            None => {
                return invalid(format!(
                    "evidence {} uses an unregistered stage namespace",
                    meta.id.as_str()
                ));
            }
        },
        None if meta.layer.is_some() => {
            return invalid(format!(
                "evidence {} asserts a layer without a registered stage",
                meta.id.as_str()
            ));
        }
        None => {}
    }
    let mut refs = BTreeSet::new();
    for subject_ref in &meta.subjects {
        if !refs.insert(subject_ref.clone()) {
            return invalid(format!(
                "evidence {} contains a duplicate subject reference",
                meta.id.as_str()
            ));
        }
        let subject = subjects.get(&subject_ref.id).ok_or_else(|| {
            ReportValidationError(format!(
                "evidence {} references dangling subject {}",
                meta.id.as_str(),
                subject_ref.id.as_str()
            ))
        })?;
        if !valid_subject_role(subject.kind, subject_ref.role) {
            return invalid(format!(
                "subject role {:?} is invalid for {:?}",
                subject_ref.role, subject.kind
            ));
        }
        validate_subject_context(meta, subject_ref, subject, subjects)?;
    }
    validate_transition_metadata(meta, subjects)
}

fn validate_transition_metadata(
    meta: &EvidenceMeta,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<(), ReportValidationError> {
    if meta.transition.is_none() {
        return Ok(());
    }

    if meta.execution_domain.is_none() {
        return invalid(format!(
            "evidence {} transition has no execution domain",
            meta.id.as_str()
        ));
    }

    let mut before = BTreeSet::new();
    let mut after = BTreeSet::new();
    for subject_ref in &meta.subjects {
        let target = match subject_ref.role {
            SubjectRole::Before => &mut before,
            SubjectRole::After => &mut after,
            _ => continue,
        };
        let subject = subjects
            .get(&subject_ref.id)
            .expect("evidence subjects were checked before transition metadata");
        if !matches!(subject.kind, SubjectKind::Hop | SubjectKind::FlowDomain) {
            return invalid(format!(
                "evidence {} transition endpoint {} is not a hop or flow domain",
                meta.id.as_str(),
                subject.id.as_str()
            ));
        }
        target.insert(subject.id.clone());
    }
    if before.is_empty() || after.is_empty() {
        return invalid(format!(
            "evidence {} transition requires before and after endpoints",
            meta.id.as_str()
        ));
    }
    if before.iter().any(|id| after.contains(id)) {
        return invalid(format!(
            "evidence {} transition reuses one endpoint as both before and after",
            meta.id.as_str()
        ));
    }
    Ok(())
}

fn validate_metric(
    schema_version: u16,
    metric: &MetricDelta,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<(), ReportValidationError> {
    let metric_type = metric.metric_type.as_str();
    let Some(provider) = provider_registry::descriptor(metric.meta.provider.as_str()) else {
        return invalid(format!(
            "metric {} uses an unregistered provider",
            metric.meta.id.as_str()
        ));
    };
    if !provider.supports_metric_type(metric_type) {
        return invalid(format!(
            "metric type {metric_type} is not registered for provider {}",
            metric.meta.provider.as_str()
        ));
    }
    if provider.metric_semantics != MetricSemantics::SocketDrops
        && (metric.meta.layer.is_none() || metric.meta.descriptor.stage.is_none())
    {
        return invalid(format!(
            "registered metric {} must identify its layer and stage",
            metric.meta.id.as_str()
        ));
    }
    validate_metric_values(metric)?;
    if provider.metric_semantics == MetricSemantics::SocketDrops {
        validate_socket_drop_metric(schema_version, metric, subjects)?;
    } else if metric.meta.descriptor.measurement.unit == MeasurementUnit::SourceUnits {
        return invalid(format!(
            "metric {} cannot use source_units",
            metric.meta.id.as_str()
        ));
    }
    validate_attributes(
        &metric.meta.provider,
        AttributeOwner::Metric,
        &metric.attributes,
    )
}

fn validate_socket_drop_metric(
    schema_version: u16,
    metric: &MetricDelta,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<(), ReportValidationError> {
    let descriptor = &metric.meta.descriptor;
    let common_descriptor = metric.metric_type.as_str() == METRIC_SOCK_DIAG_DROPS
        && metric
            .meta
            .execution_domain
            .as_ref()
            .is_some_and(|domain| domain.as_str() == "linux.kernel")
        && metric.meta.transition.is_none()
        && descriptor.hook.is_none()
        && descriptor.context == EvidenceContext::default()
        && descriptor.measurement.scope == Some(MeasurementScope::Socket)
        && matches!(
            descriptor.measurement.bound,
            None | Some(MeasurementBound::LowerBound)
        )
        && metric.meta.subjects.len() == 1
        && metric.meta.subjects[0].role == SubjectRole::Primary
        && subjects
            .get(&metric.meta.subjects[0].id)
            .is_some_and(|subject| {
                subject.provider.as_str() == PROVIDER_SOCK_DIAG
                    && subject.kind == SubjectKind::Socket
                    && subject.attributes.is_empty()
            });
    let valid_descriptor = common_descriptor
        && match schema_version {
            REPORT_V4_SCHEMA_VERSION => {
                metric.meta.layer == Some(Layer::Socket)
                    && descriptor
                        .stage
                        .as_ref()
                        .is_some_and(|stage| stage.as_str() == "socket.receive_queue")
                    && descriptor.direction == Some(Direction::Ingress)
                    && descriptor.path_role == Some(PathRole::LocalInput)
                    && descriptor.outcome
                        == (Outcome {
                            disposition: Some(Disposition::Dropped),
                            signal: None,
                        })
                    && descriptor.role == EvidenceRole::Causal
                    && descriptor.measurement.unit == MeasurementUnit::Occurrences
                    && descriptor.measurement.domain == Some(MeasurementDomain::Skb)
            }
            SCHEMA_VERSION => {
                metric.meta.layer.is_none()
                    && descriptor.stage.is_none()
                    && descriptor.direction.is_none()
                    && descriptor.path_role.is_none()
                    && descriptor.outcome == Outcome::default()
                    && descriptor.role == EvidenceRole::Context
                    && descriptor.measurement.unit == MeasurementUnit::SourceUnits
                    && descriptor.measurement.domain.is_none()
            }
            _ => false,
        };
    if !valid_descriptor {
        return invalid(format!(
            "sock_diag metric {} does not use the report-v{schema_version} descriptor",
            metric.meta.id.as_str(),
        ));
    }
    if [metric.values.start, metric.values.end, metric.values.delta]
        .into_iter()
        .flatten()
        .any(|value| value > u64::from(u32::MAX))
    {
        return invalid(format!(
            "sock_diag metric {} exceeds its 32-bit counter width",
            metric.meta.id.as_str()
        ));
    }
    let valid_values = match (
        metric.values.start,
        metric.values.end,
        metric.values.delta,
        metric.values.reset,
        descriptor.measurement.bound,
    ) {
        (Some(start), Some(end), Some(delta), false, Some(MeasurementBound::LowerBound)) => {
            end > start && delta > 0
        }
        (Some(start), Some(end), None, true, None) => end < start,
        _ => false,
    };
    if !valid_values {
        return invalid(format!(
            "sock_diag metric {} must be a positive lower-bound delta or a two-endpoint reset",
            metric.meta.id.as_str()
        ));
    }
    Ok(())
}

fn validate_metric_values(metric: &MetricDelta) -> Result<(), ReportValidationError> {
    let values = metric.values;
    let valid_values = match (values.start, values.end) {
        (Some(start), Some(end)) if end >= start => {
            !values.reset && values.delta == Some(end - start)
        }
        (Some(_), Some(_)) => values.reset && values.delta.is_none(),
        (Some(_), None) | (None, Some(_)) => !values.reset && values.delta.is_none(),
        (None, None) => false,
    };
    if !valid_values {
        return invalid(format!(
            "metric {} has inconsistent start/end/delta/reset values",
            metric.meta.id.as_str()
        ));
    }

    if values.delta.is_some() != metric.meta.descriptor.measurement.bound.is_some() {
        return invalid(format!(
            "metric {} measurement bound does not match delta availability",
            metric.meta.id.as_str()
        ));
    }
    Ok(())
}

fn validate_observation(
    schema_version: u16,
    observation: &Observation,
) -> Result<(), ReportValidationError> {
    if schema_version == REPORT_V4_SCHEMA_VERSION
        && matches!(
            observation.meta.provider.as_str(),
            PROVIDER_UDP_RECEIVE_ADMISSION | PROVIDER_SOCKET_RECEIVE_QUEUE_FULL
        )
    {
        return invalid(format!(
            "provider {} is unavailable in report v4",
            observation.meta.provider.as_str()
        ));
    }
    if observation.meta.descriptor.measurement.unit == MeasurementUnit::SourceUnits {
        return invalid(format!(
            "observation {} cannot use source_units",
            observation.meta.id.as_str()
        ));
    }
    let descriptor = provider_registry::descriptor(observation.meta.provider.as_str());
    if !descriptor
        .is_some_and(|provider| provider.supports_observation_type(observation.event_type.as_str()))
    {
        return invalid(format!(
            "event type {} is not registered for provider {}",
            observation.event_type.as_str(),
            observation.meta.provider.as_str()
        ));
    }
    validate_attributes(
        &observation.meta.provider,
        AttributeOwner::Observation,
        &observation.attributes,
    )?;
    match descriptor
        .expect("registered observation provider")
        .observation_semantics
    {
        ObservationSemantics::SkbFree => {
            if observation.attributes.get(ATTR_BPF_MODE).is_none() {
                return invalid(format!(
                    "observation {} is missing {ATTR_BPF_MODE}",
                    observation.meta.id.as_str()
                ));
            }
            if observation.attributes.get(ATTR_SKB_REASON_NAME).is_some()
                && observation.attributes.get(ATTR_SKB_REASON_CODE).is_none()
            {
                return invalid("skb-free reason name requires a raw reason code");
            }
        }
        ObservationSemantics::UdpReceiveAdmission => {
            validate_udp_receive_admission_observation(observation)?
        }
        ObservationSemantics::SocketReceiveQueueFull => {
            validate_socket_receive_queue_full_observation(observation)?
        }
        ObservationSemantics::Generic => {}
    }
    Ok(())
}

fn validate_udp_receive_admission_observation(
    observation: &Observation,
) -> Result<(), ReportValidationError> {
    let cause = observation
        .attributes
        .get(ATTR_UDP_RECEIVE_ADMISSION_CAUSE)
        .and_then(AttributeValue::as_str);
    let stage = match cause {
        Some("receive_buffer") => "socket.receive_queue",
        Some("protocol_memory") => "socket.protocol_memory",
        _ => {
            return invalid(format!(
                "observation {} has no valid UDP receive-admission cause",
                observation.meta.id.as_str()
            ))
        }
    };
    if observation.attributes.iter().count() != 1
        || !valid_socket_causal_event_descriptor(observation, stage)
    {
        return invalid(format!(
            "observation {} does not use the registered UDP receive-admission descriptor",
            observation.meta.id.as_str()
        ));
    }
    Ok(())
}

fn validate_socket_receive_queue_full_observation(
    observation: &Observation,
) -> Result<(), ReportValidationError> {
    let required_attributes = [
        ATTR_SOCKET_RECEIVE_MEMORY_ALLOCATED_BYTES,
        ATTR_SKB_TRUE_SIZE_BYTES,
        ATTR_SOCKET_RECEIVE_BUFFER_LIMIT_BYTES,
    ];
    if observation.attributes.iter().count() != required_attributes.len()
        || required_attributes
            .iter()
            .any(|name| observation.attributes.get(name).is_none())
        || !valid_socket_causal_event_descriptor(observation, "socket.receive_queue")
    {
        return invalid(format!(
            "observation {} does not use the registered socket receive-queue-full descriptor",
            observation.meta.id.as_str()
        ));
    }
    Ok(())
}

fn valid_socket_causal_event_descriptor(observation: &Observation, stage: &str) -> bool {
    let descriptor = &observation.meta.descriptor;
    observation.meta.layer == Some(Layer::Socket)
        && observation
            .meta
            .execution_domain
            .as_ref()
            .is_some_and(|domain| domain.as_str() == "linux.kernel")
        && observation.meta.transition.is_none()
        && observation.meta.subjects.is_empty()
        && descriptor
            .stage
            .as_ref()
            .is_some_and(|actual| actual.as_str() == stage)
        && descriptor.hook.is_none()
        && descriptor.direction == Some(Direction::Ingress)
        && descriptor.path_role == Some(PathRole::LocalInput)
        && descriptor.context == EvidenceContext::default()
        && descriptor.outcome
            == (Outcome {
                disposition: Some(Disposition::Rejected),
                signal: None,
            })
        && descriptor.role == EvidenceRole::Causal
        && descriptor.measurement.unit == MeasurementUnit::Occurrences
        && descriptor.measurement.domain == Some(MeasurementDomain::Skb)
        && descriptor.measurement.scope == Some(MeasurementScope::Host)
        && matches!(
            descriptor.measurement.bound,
            Some(MeasurementBound::Exact | MeasurementBound::LowerBound)
        )
}

fn validate_findings(
    schema_version: u16,
    subjects: &[Subject],
    metrics: &[MetricDelta],
    observations: &[Observation],
    findings: &[Finding],
) -> Result<(), ReportValidationError> {
    let subject_index: BTreeMap<_, _> = subjects
        .iter()
        .map(|subject| (subject.id.clone(), subject))
        .collect();
    let mut evidence = BTreeMap::new();
    for metric in metrics {
        evidence.insert(
            metric.meta.id.clone(),
            (
                EvidenceKind::Metric,
                &metric.meta,
                FindingMeasurementIdentity::Metric {
                    provider: metric.meta.provider.as_str(),
                    identity: metric_measurement_identity(metric.metric_type.as_str()),
                },
                metric.values.delta,
            ),
        );
    }
    for observation in observations {
        evidence.insert(
            observation.meta.id.clone(),
            (
                EvidenceKind::Observation,
                &observation.meta,
                FindingMeasurementIdentity::Observation {
                    provider: observation.meta.provider.as_str(),
                    event_type: observation.event_type.as_str(),
                },
                None,
            ),
        );
    }

    let mut causal_socket_evidence = BTreeSet::new();
    for finding in findings {
        if !valid_namespaced_name(&finding.id) {
            return invalid(format!("invalid finding type {:?}", finding.id));
        }
        if finding.evidence.is_empty() {
            return invalid(format!("finding {} has no evidence", finding.id));
        }
        let expected_identity = evidence
            .get(&finding.evidence[0].id)
            .map(|(_, _, identity, _)| *identity)
            .ok_or_else(|| {
                ReportValidationError(format!(
                    "finding {} references dangling evidence {}",
                    finding.id,
                    finding.evidence[0].id.as_str()
                ))
            })?;
        let socket_drop_finding = matches!(
            expected_identity,
            FindingMeasurementIdentity::Metric { provider, identity }
                if provider == PROVIDER_SOCK_DIAG && identity == METRIC_SOCK_DIAG_DROPS
        );
        if finding.descriptor.measurement.unit == MeasurementUnit::SourceUnits {
            return invalid(format!("finding {} cannot use source_units", finding.id));
        }
        if schema_version == SCHEMA_VERSION && socket_drop_finding {
            return invalid(format!(
                "finding {} cannot reference generic sock_diag context",
                finding.id
            ));
        }
        let mut expected_socket_drop_count = None;
        let mut refs = BTreeSet::new();
        let expected_subjects = finding_subjects(&finding.evidence, &evidence, &subject_index)?;
        for evidence_ref in &finding.evidence {
            if !refs.insert(evidence_ref.clone()) {
                return invalid(format!(
                    "finding {} contains a duplicate evidence reference",
                    finding.id
                ));
            }
            let (actual_kind, meta, identity, metric_delta) =
                evidence.get(&evidence_ref.id).ok_or_else(|| {
                    ReportValidationError(format!(
                        "finding {} references dangling evidence {}",
                        finding.id,
                        evidence_ref.id.as_str()
                    ))
                })?;
            if *actual_kind != evidence_ref.kind {
                return invalid(format!(
                    "finding {} uses the wrong kind for evidence {}",
                    finding.id,
                    evidence_ref.id.as_str()
                ));
            }
            if *identity != expected_identity
                || meta.layer != finding.layer
                || meta.execution_domain != finding.execution_domain
                || meta.transition != finding.transition
                || meta.descriptor != finding.descriptor
                || meta.subjects.iter().cloned().collect::<BTreeSet<_>>() != expected_subjects
            {
                return invalid(format!(
                    "finding {} combines incompatible evidence",
                    finding.id
                ));
            }
            if socket_drop_finding {
                let Some(delta) = *metric_delta else {
                    return invalid(format!(
                        "finding {} references sock_diag evidence without a positive delta",
                        finding.id
                    ));
                };
                expected_socket_drop_count =
                    Some(expected_socket_drop_count.map_or(delta, |count: u64| count.max(delta)));
            }
        }
        if expected_socket_drop_count.is_some_and(|count| finding.count != count) {
            return invalid(format!(
                "finding {} count does not match its sock_diag evidence",
                finding.id
            ));
        }
        if schema_version == SCHEMA_VERSION
            && validate_socket_causal_finding(expected_identity, finding)?
        {
            for evidence_ref in &finding.evidence {
                if !causal_socket_evidence.insert(evidence_ref.id.clone()) {
                    return invalid(format!(
                        "causal socket evidence {} is referenced by more than one finding",
                        evidence_ref.id.as_str()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_socket_causal_finding(
    identity: FindingMeasurementIdentity<'_>,
    finding: &Finding,
) -> Result<bool, ReportValidationError> {
    let stage = finding.descriptor.stage.as_ref().map(StageId::as_str);
    let contract = match identity {
        FindingMeasurementIdentity::Observation {
            provider,
            event_type,
        } => socket_causal_finding_contract(provider, event_type, stage),
        FindingMeasurementIdentity::Metric { .. } => None,
    };

    let Some(contract) = contract else {
        if reserved_socket_causal_finding_id(&finding.id) {
            return invalid(format!(
                "finding {} is reserved for registered causal socket events",
                finding.id
            ));
        }
        return Ok(false);
    };

    let expected_count = u64::try_from(finding.evidence.len())
        .map_err(|_| ReportValidationError("causal finding evidence count exceeds u64".into()))?;
    if finding.id != contract.id
        || finding.severity != Severity::Warning
        || finding.confidence != Confidence::Direct
        || finding.title != contract.title
        || finding.summary != contract.summary
        || finding.count != expected_count
    {
        return invalid(format!(
            "finding {} does not match its registered causal socket event",
            finding.id
        ));
    }
    Ok(true)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FindingMeasurementIdentity<'a> {
    Metric {
        provider: &'a str,
        identity: &'a str,
    },
    Observation {
        provider: &'a str,
        event_type: &'a str,
    },
}

fn finding_subjects(
    evidence_refs: &[EvidenceRef],
    evidence: &BTreeMap<
        EvidenceId,
        (
            EvidenceKind,
            &EvidenceMeta,
            FindingMeasurementIdentity<'_>,
            Option<u64>,
        ),
    >,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<BTreeSet<SubjectRef>, ReportValidationError> {
    let Some(first) = evidence_refs.first() else {
        return Ok(BTreeSet::new());
    };
    let (_, meta, _, _) = evidence
        .get(&first.id)
        .ok_or_else(|| ReportValidationError(format!("dangling evidence {}", first.id.as_str())))?;
    for subject_ref in &meta.subjects {
        if !subjects.contains_key(&subject_ref.id) {
            return invalid(format!("dangling subject {}", subject_ref.id.as_str()));
        }
    }
    Ok(meta.subjects.iter().cloned().collect())
}

#[derive(Clone, Copy)]
enum AttributeOwner {
    Metric,
    Observation,
    Subject(SubjectKind),
}

fn validate_attributes(
    provider: &NamespacedName,
    owner: AttributeOwner,
    attributes: &Attributes,
) -> Result<(), ReportValidationError> {
    for (name, value) in attributes.iter() {
        let valid = match (provider.as_str(), owner, name.as_str()) {
            (PROVIDER_SOFTNET, AttributeOwner::Metric, ATTR_CPU_ROW) => {
                unsigned_at_most(value, u32::MAX as u64)
            }
            (PROVIDER_LINK, AttributeOwner::Metric, ATTR_INTERFACE_NAME) => {
                value.as_str().is_some_and(valid_interface_name)
            }
            (PROVIDER_LINK, AttributeOwner::Metric, ATTR_COUNTER_BITS) => {
                matches!(value.as_u64(), Some(32 | 64))
            }
            (PROVIDER_KFREE_SKB, AttributeOwner::Observation, ATTR_SKB_REASON_CODE) => {
                unsigned_at_most(value, u32::MAX as u64)
            }
            (PROVIDER_KFREE_SKB, AttributeOwner::Observation, ATTR_SKB_REASON_NAME) => {
                value.as_str().is_some_and(valid_reason_name)
            }
            (PROVIDER_KFREE_SKB, AttributeOwner::Observation, ATTR_BPF_MODE) => {
                value.as_str().is_some_and(|value| {
                    matches!(value, "counter_only" | "legacy_perf" | "reason_ring")
                })
            }
            (
                PROVIDER_UDP_RECEIVE_ADMISSION,
                AttributeOwner::Observation,
                ATTR_UDP_RECEIVE_ADMISSION_CAUSE,
            ) => value
                .as_str()
                .is_some_and(|value| matches!(value, "receive_buffer" | "protocol_memory")),
            (
                PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
                AttributeOwner::Observation,
                ATTR_SOCKET_RECEIVE_MEMORY_ALLOCATED_BYTES | ATTR_SOCKET_RECEIVE_BUFFER_LIMIT_BYTES,
            ) => unsigned_at_most(value, i32::MAX as u64),
            (
                PROVIDER_SOCKET_RECEIVE_QUEUE_FULL,
                AttributeOwner::Observation,
                ATTR_SKB_TRUE_SIZE_BYTES,
            ) => unsigned_at_most(value, u32::MAX as u64),
            (
                PROVIDER_LINK | PROVIDER_NWDIAG_CORE,
                AttributeOwner::Subject(SubjectKind::Interface | SubjectKind::Hop),
                ATTR_INTERFACE_NAME,
            ) => value.as_str().is_some_and(valid_interface_name),
            (
                PROVIDER_LINK | PROVIDER_NWDIAG_CORE,
                AttributeOwner::Subject(
                    SubjectKind::Interface | SubjectKind::Hop | SubjectKind::Queue,
                ),
                ATTR_IFINDEX,
            ) => unsigned_between(value, 1, IfIndex::MAX as u64),
            (PROVIDER_NWDIAG_CORE, AttributeOwner::Subject(SubjectKind::Queue), ATTR_QUEUE_ID) => {
                unsigned_at_most(value, u32::MAX as u64)
            }
            (
                PROVIDER_LINK | PROVIDER_NWDIAG_CORE,
                AttributeOwner::Subject(SubjectKind::Hop),
                ATTR_HOP_ORDINAL,
            ) => unsigned_between(value, 1, u32::MAX as u64),
            (
                PROVIDER_LINK | PROVIDER_NWDIAG_CORE,
                AttributeOwner::Subject(
                    SubjectKind::Socket
                    | SubjectKind::Queue
                    | SubjectKind::Interface
                    | SubjectKind::Hop
                    | SubjectKind::FlowDomain,
                ),
                ATTR_NETWORK_NAMESPACE,
            ) => value.as_str().is_some_and(valid_namespace_identity),
            _ => false,
        };
        if !valid {
            return invalid(format!(
                "attribute {} is not allowed for provider {} or has the wrong value type",
                name.as_str(),
                provider.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_subject_context(
    meta: &EvidenceMeta,
    subject_ref: &SubjectRef,
    subject: &Subject,
    subjects: &BTreeMap<SubjectId, &Subject>,
) -> Result<(), ReportValidationError> {
    if let Some(namespace) = subject
        .attributes
        .get(ATTR_NETWORK_NAMESPACE)
        .and_then(AttributeValue::as_str)
    {
        if meta
            .descriptor
            .context
            .network_namespace
            .as_deref()
            .is_some_and(|context| context != namespace)
        {
            return invalid(format!(
                "subject {} network namespace conflicts with evidence context",
                subject.id.as_str()
            ));
        }
    }

    let ifindex = subject
        .attributes
        .get(ATTR_IFINDEX)
        .and_then(AttributeValue::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    if let Some(ifindex) = ifindex {
        let context = &meta.descriptor.context;
        let (first, second) = match subject_ref.role {
            SubjectRole::Ingress => (context.ingress_ifindex.map(IfIndex::get), None),
            SubjectRole::Egress => (context.egress_ifindex.map(IfIndex::get), None),
            SubjectRole::Primary => match meta.descriptor.direction {
                Some(Direction::Ingress) => (context.ingress_ifindex.map(IfIndex::get), None),
                Some(Direction::Egress) => (context.egress_ifindex.map(IfIndex::get), None),
                None => (
                    context.ingress_ifindex.map(IfIndex::get),
                    context.egress_ifindex.map(IfIndex::get),
                ),
            },
            SubjectRole::Owner | SubjectRole::Peer | SubjectRole::Before | SubjectRole::After => (
                context.ingress_ifindex.map(IfIndex::get),
                context.egress_ifindex.map(IfIndex::get),
            ),
        };
        let has_context = first.is_some() || second.is_some();
        if has_context && first != Some(ifindex) && second != Some(ifindex) {
            return invalid(format!(
                "subject {} ifindex conflicts with evidence context",
                subject.id.as_str()
            ));
        }
    }

    if subject.kind == SubjectKind::Queue {
        if let Some(queue_id) = subject
            .attributes
            .get(ATTR_QUEUE_ID)
            .and_then(AttributeValue::as_u64)
        {
            if meta
                .descriptor
                .context
                .queue_id
                .is_some_and(|context| u64::from(context) != queue_id)
            {
                return invalid(format!(
                    "queue subject {} conflicts with evidence queue context",
                    subject.id.as_str()
                ));
            }
        }
        if let Some(queue_ifindex) = ifindex {
            let has_owner = meta.subjects.iter().any(|candidate| {
                candidate.role == SubjectRole::Owner
                    && subjects.get(&candidate.id).is_some_and(|owner| {
                        matches!(owner.kind, SubjectKind::Interface | SubjectKind::Hop)
                            && owner
                                .attributes
                                .get(ATTR_IFINDEX)
                                .and_then(AttributeValue::as_u64)
                                == Some(u64::from(queue_ifindex))
                    })
            });
            if !has_owner {
                return invalid(format!(
                    "queue subject {} has an ifindex but no matching owner reference",
                    subject.id.as_str()
                ));
            }
        }
    }
    Ok(())
}

fn valid_subject_provider_kind(provider: &str, kind: SubjectKind) -> bool {
    provider_registry::descriptor(provider)
        .is_some_and(|provider| provider.supports_subject_kind(kind))
}

fn valid_subject_role(kind: SubjectKind, role: SubjectRole) -> bool {
    match role {
        SubjectRole::Primary => true,
        SubjectRole::Ingress | SubjectRole::Egress => {
            matches!(kind, SubjectKind::Interface | SubjectKind::Hop)
        }
        SubjectRole::Owner => matches!(
            kind,
            SubjectKind::Interface | SubjectKind::Hop | SubjectKind::Program
        ),
        SubjectRole::Peer => matches!(
            kind,
            SubjectKind::Socket | SubjectKind::Interface | SubjectKind::Hop
        ),
        SubjectRole::Before | SubjectRole::After => matches!(
            kind,
            SubjectKind::Rule | SubjectKind::Program | SubjectKind::Hop | SubjectKind::FlowDomain
        ),
    }
}

fn validate_evidence_bounds(
    metrics: &[MetricDelta],
    observations: &[Observation],
    telemetry: &Telemetry,
) -> Result<(), ReportValidationError> {
    let lossy_providers: BTreeSet<_> = telemetry
        .providers
        .iter()
        .filter(|provider| provider_has_loss_or_unknown(provider))
        .map(|provider| provider.provider.as_str())
        .collect();
    for (provider, descriptor, id) in metrics
        .iter()
        .map(|metric| {
            (
                &metric.meta.provider,
                &metric.meta.descriptor,
                &metric.meta.id,
            )
        })
        .chain(observations.iter().map(|observation| {
            (
                &observation.meta.provider,
                &observation.meta.descriptor,
                &observation.meta.id,
            )
        }))
    {
        if lossy_providers.contains(provider.as_str())
            && descriptor.measurement.bound == Some(MeasurementBound::Exact)
        {
            return invalid(format!(
                "evidence {} is exact despite provider loss or unknown telemetry",
                id.as_str()
            ));
        }
    }
    Ok(())
}

fn provider_has_loss_or_unknown(provider: &ProviderTelemetry) -> bool {
    let counters = provider.counters.as_refs();
    let any_unknown = [
        counters.bpf_events_seen,
        counters.bpf_output_lost,
        counters.transport_events_received,
        counters.transport_events_lost,
        counters.user_events_dropped,
        counters.netlink_loss_events,
        counters.netlink_dump_interruptions,
        counters.parse_errors,
    ]
    .into_iter()
    .any(|status| matches!(status, CounterStatus::Unknown));
    let observed_loss = [
        &provider.counters.bpf_output_lost,
        &provider.counters.transport_events_lost,
        &provider.counters.user_events_dropped,
        &provider.counters.netlink_loss_events,
        &provider.counters.netlink_dump_interruptions,
        &provider.counters.parse_errors,
    ]
    .into_iter()
    .any(|status| matches!(status, CounterStatus::Measured { value } if *value > 0));
    any_unknown || observed_loss
}

fn validate_provider_name(provider: &NamespacedName) -> Result<(), ReportValidationError> {
    if known_provider(provider.as_str()) {
        Ok(())
    } else {
        invalid(format!("unregistered provider {}", provider.as_str()))
    }
}

fn known_provider(provider: &str) -> bool {
    provider_registry::descriptor(provider).is_some()
}

fn unsigned_at_most(value: &AttributeValue, maximum: u64) -> bool {
    value.as_u64().is_some_and(|value| value <= maximum)
}

fn unsigned_between(value: &AttributeValue, minimum: u64, maximum: u64) -> bool {
    value
        .as_u64()
        .is_some_and(|value| (minimum..=maximum).contains(&value))
}

fn valid_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < libc::IFNAMSIZ
        && value != "."
        && value != ".."
        && !value
            .bytes()
            .any(|byte| byte == b'/' || byte == 0 || byte.is_ascii_whitespace())
}

fn valid_namespace_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ATTRIBUTE_STRING_BYTES
        && value.is_ascii()
        && !value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

fn valid_reason_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportValidationError(String);

impl fmt::Display for ReportValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReportValidationError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, ReportValidationError> {
    Err(ReportValidationError(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stage_ids_are_namespaced_and_map_only_known_layer_namespaces() {
        let stage = StageId::new("netfilter.forward").unwrap();

        assert_eq!(stage.layer(), Some(Layer::Netfilter));
        assert_eq!(
            StageId::new("network.receive_validation").unwrap().layer(),
            Some(Layer::Network)
        );
        assert_eq!(
            StageId::new("route.lookup").unwrap().layer(),
            Some(Layer::Route)
        );
        assert_eq!(
            StageId::new("xfrm.policy").unwrap().layer(),
            Some(Layer::Xfrm)
        );
        assert!(StageId::new("netfilter").is_err());
        assert!(StageId::new("Netfilter.forward").is_err());
        assert_eq!(StageId::new("vendor.custom").unwrap().layer(), None);
    }

    #[test]
    fn event_stream_v1_downcasts_xfrm_and_rejects_v3_only_metadata() {
        let report: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/report-evidence-v4.json"))
                .unwrap();
        let base: Observation = serde_json::from_value(report["observations"][0].clone()).unwrap();
        let mut observation = base.clone();
        observation.meta.layer = Some(Layer::Xfrm);
        observation.meta.descriptor.stage = Some(StageId::new("xfrm.policy").unwrap());

        let record = TraceRecord::from_observation(1, observation.clone()).unwrap();
        assert_eq!(record.layer, Some(Layer::Route));
        assert_eq!(record.descriptor.stage.unwrap().as_str(), "xfrm.policy");

        observation.meta.layer = Some(Layer::Network);
        observation.meta.descriptor.stage =
            Some(StageId::new("network.receive_validation").unwrap());
        assert!(TraceRecord::from_observation(1, observation).is_err());

        let mut with_subject = base.clone();
        with_subject.meta.subjects.push(SubjectRef {
            role: SubjectRole::Primary,
            id: SubjectId::new("s_00000000000000000000000000000000_1").unwrap(),
        });
        assert!(TraceRecord::from_observation(1, with_subject).is_err());

        let mut with_transition = base.clone();
        with_transition.meta.transition = Some(NamespacedName::new("nwdiag.path.fixture").unwrap());
        assert!(TraceRecord::from_observation(1, with_transition).is_err());

        let mut unknown_domain = base.clone();
        unknown_domain.meta.execution_domain = None;
        assert!(TraceRecord::from_observation(1, unknown_domain).is_err());

        let mut hardware_domain = base.clone();
        hardware_domain.meta.execution_domain =
            Some(NamespacedName::new("linux.hardware").unwrap());
        assert!(TraceRecord::from_observation(1, hardware_domain).is_err());

        for path_role in [PathRole::L2LocalInput, PathRole::L2LocalOutput] {
            let mut l2_local = base.clone();
            l2_local.meta.descriptor.path_role = Some(path_role);
            assert!(TraceRecord::from_observation(1, l2_local).is_err());
        }
    }

    #[test]
    fn hook_references_reject_values_outside_the_schema_vocabulary() {
        assert!(HookRef::new("tc", "ingress").is_ok());
        assert!(HookRef::new("TC", "ingress").is_err());
        assert!(HookRef::new("tc", "bad-name").is_err());
        assert!(serde_json::from_value::<HookRef>(json!({
            "family": "tc",
            "name": "ingress",
            "extra": true
        }))
        .is_err());
    }

    #[test]
    fn ifindex_rejects_zero_and_values_outside_linux_signed_range() {
        assert_eq!(IfIndex::new(1).unwrap().get(), 1);
        assert!(IfIndex::new(0).is_err());
        assert!(IfIndex::new(IfIndex::MAX + 1).is_err());
        assert!(serde_json::from_value::<IfIndex>(json!(0)).is_err());
    }

    #[test]
    fn coverage_rejects_duplicate_forms() {
        let coverage = json!({
            "layer": "socket",
            "availability": "active",
            "visibility": "partial",
            "forms": ["event", "event"],
            "filterSupport": "broader_only",
            "integrity": "complete",
            "sources": [],
            "limitations": []
        });

        assert!(serde_json::from_value::<LayerCoverage>(coverage).is_err());
    }

    #[test]
    fn required_nullable_fields_cannot_be_omitted() {
        let report: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/report-evidence-v4.json"))
                .unwrap();
        let scope = report["scope"].clone();
        assert!(serde_json::from_value::<CaptureScope>(scope.clone()).is_ok());

        let mut missing = scope;
        missing["requested"]
            .as_object_mut()
            .unwrap()
            .remove("interfacePath");
        assert!(serde_json::from_value::<CaptureScope>(missing).is_err());
    }

    #[test]
    fn report_local_ids_require_a_random_nonce_shape() {
        assert!(EvidenceId::new("e_0123456789abcdef0123456789abcdef_1").is_ok());
        assert!(SubjectId::new("s_0123456789abcdef0123456789abcdef_1").is_ok());
        assert!(EvidenceId::new("e1").is_err());
        assert!(EvidenceId::new("e_0123456789ABCDEF0123456789ABCDEF_1").is_err());
        assert!(SubjectId::new("e_0123456789abcdef0123456789abcdef_1").is_err());
    }

    #[test]
    fn unknown_provider_counter_makes_the_session_total_a_lower_bound() {
        let telemetry = Telemetry::from_providers(
            vec![ProviderTelemetry {
                provider: NamespacedName::new(PROVIDER_SOFTNET).unwrap(),
                counters: BoundaryCounters {
                    parse_errors: CounterStatus::Unknown,
                    ..BoundaryCounters::filled(CounterStatus::NotApplicable)
                },
                sampling: SamplingTelemetry::None,
            }],
            Vec::new(),
        )
        .unwrap();

        assert_eq!(telemetry.totals.parse_errors.value, 0);
        assert_eq!(telemetry.totals.parse_errors.bound, TotalBound::LowerBound);
    }

    fn telemetry_row(
        provider: &str,
        counters: BoundaryCounters<CounterStatus>,
    ) -> ProviderTelemetry {
        ProviderTelemetry {
            provider: NamespacedName::new(provider).unwrap(),
            counters,
            sampling: SamplingTelemetry::None,
        }
    }

    fn active_counter_profile(provider: &str) -> BoundaryCounters<CounterStatus> {
        match provider {
            PROVIDER_PROC_PROTOCOL | PROVIDER_SOFTNET => BoundaryCounters {
                parse_errors: CounterStatus::measured(0),
                ..BoundaryCounters::filled(CounterStatus::NotApplicable)
            },
            PROVIDER_LINK | PROVIDER_SOCK_DIAG => BoundaryCounters {
                netlink_loss_events: CounterStatus::measured(0),
                netlink_dump_interruptions: CounterStatus::measured(0),
                parse_errors: CounterStatus::measured(0),
                ..BoundaryCounters::filled(CounterStatus::NotApplicable)
            },
            PROVIDER_KFREE_SKB
            | PROVIDER_UDP_RECEIVE_ADMISSION
            | PROVIDER_SOCKET_RECEIVE_QUEUE_FULL => BoundaryCounters {
                netlink_loss_events: CounterStatus::NotApplicable,
                netlink_dump_interruptions: CounterStatus::NotApplicable,
                ..BoundaryCounters::filled(CounterStatus::measured(0))
            },
            PROVIDER_NWDIAG_CORE => BoundaryCounters::filled(CounterStatus::measured(0)),
            _ => panic!("test profile requested for unknown provider"),
        }
    }

    fn set_counter(
        counters: &mut BoundaryCounters<CounterStatus>,
        index: usize,
        status: CounterStatus,
    ) {
        let target = match index {
            0 => &mut counters.bpf_events_seen,
            1 => &mut counters.bpf_output_lost,
            2 => &mut counters.transport_events_received,
            3 => &mut counters.transport_events_lost,
            4 => &mut counters.user_events_dropped,
            5 => &mut counters.netlink_loss_events,
            6 => &mut counters.netlink_dump_interruptions,
            7 => &mut counters.parse_errors,
            _ => panic!("counter index is outside the registry shape"),
        };
        *target = status;
    }

    #[test]
    fn registry_telemetry_rules_preserve_active_and_inactive_profiles() {
        for descriptor in provider_registry::PROVIDERS {
            let active = telemetry_row(descriptor.name, active_counter_profile(descriptor.name));
            assert!(Telemetry::from_providers(vec![active], Vec::new()).is_ok());

            let inactive = telemetry_row(
                descriptor.name,
                BoundaryCounters::filled(CounterStatus::NotApplicable),
            );
            assert!(Telemetry::from_providers(vec![inactive], Vec::new()).is_ok());

            for (index, rule) in descriptor.telemetry.as_array().into_iter().enumerate() {
                let mut counters = active_counter_profile(descriptor.name);
                match rule {
                    TelemetryCounterRule::NotApplicable => {
                        set_counter(&mut counters, index, CounterStatus::measured(0));
                        assert!(Telemetry::from_providers(
                            vec![telemetry_row(descriptor.name, counters)],
                            Vec::new(),
                        )
                        .is_err());
                    }
                    TelemetryCounterRule::Required => {
                        set_counter(&mut counters, index, CounterStatus::NotApplicable);
                        let result = Telemetry::from_providers(
                            vec![telemetry_row(descriptor.name, counters)],
                            Vec::new(),
                        );
                        if matches!(descriptor.name, PROVIDER_PROC_PROTOCOL | PROVIDER_SOFTNET) {
                            assert!(result.is_ok(), "all-not-applicable is the inactive row");
                        } else {
                            assert!(result.is_err());
                        }
                    }
                    TelemetryCounterRule::AllOrNone(_) => {
                        set_counter(&mut counters, index, CounterStatus::NotApplicable);
                        assert!(Telemetry::from_providers(
                            vec![telemetry_row(descriptor.name, counters)],
                            Vec::new(),
                        )
                        .is_err());
                    }
                    TelemetryCounterRule::Optional => {
                        set_counter(&mut counters, index, CounterStatus::NotApplicable);
                        assert!(Telemetry::from_providers(
                            vec![telemetry_row(descriptor.name, counters)],
                            Vec::new(),
                        )
                        .is_ok());
                    }
                }
            }
        }
    }

    #[test]
    fn unknown_telemetry_provider_remains_fail_closed() {
        let unknown = telemetry_row(
            "linux.unknown",
            BoundaryCounters::filled(CounterStatus::NotApplicable),
        );
        assert!(Telemetry::from_providers(vec![unknown], Vec::new()).is_err());
    }

    #[test]
    fn session_sampling_is_derived_from_provider_sampling() {
        let none = ProviderTelemetry {
            provider: NamespacedName::new(PROVIDER_PROC_PROTOCOL).unwrap(),
            counters: BoundaryCounters {
                parse_errors: CounterStatus::measured(0),
                ..BoundaryCounters::filled(CounterStatus::NotApplicable)
            },
            sampling: SamplingTelemetry::None,
        };
        let sampled = ProviderTelemetry {
            provider: NamespacedName::new(PROVIDER_SOFTNET).unwrap(),
            counters: BoundaryCounters {
                parse_errors: CounterStatus::measured(0),
                ..BoundaryCounters::filled(CounterStatus::NotApplicable)
            },
            sampling: SamplingTelemetry::Sampled {
                method: NamespacedName::new("nwdiag.every_n").unwrap(),
                scope: NamespacedName::new("linux.softnet.events").unwrap(),
                effective_numerator: 1,
                effective_denominator: 8,
            },
        };

        let telemetry = Telemetry::from_providers(vec![none, sampled], Vec::new()).unwrap();
        assert!(matches!(
            telemetry.sampling,
            SamplingTelemetry::Mixed { ref components } if components.len() == 2
        ));
    }

    #[test]
    fn sampled_ratios_are_validated() {
        let provider = ProviderTelemetry {
            provider: NamespacedName::new(PROVIDER_SOFTNET).unwrap(),
            counters: BoundaryCounters {
                parse_errors: CounterStatus::measured(0),
                ..BoundaryCounters::filled(CounterStatus::NotApplicable)
            },
            sampling: SamplingTelemetry::Sampled {
                method: NamespacedName::new("nwdiag.every_n").unwrap(),
                scope: NamespacedName::new("linux.softnet.events").unwrap(),
                effective_numerator: 0,
                effective_denominator: 8,
            },
        };

        assert!(Telemetry::from_providers(vec![provider], Vec::new()).is_err());
    }

    #[test]
    fn report_dto_rejects_unknown_fields() {
        let mut report: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/report-evidence-v4.json"))
                .unwrap();
        report
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_owned(), json!(true));

        assert!(serde_json::from_value::<Report>(report).is_err());
    }

    #[test]
    fn checked_in_report_deserializes_through_the_rust_contract() {
        let report = serde_json::from_str::<Report>(include_str!(
            "../tests/fixtures/report-evidence-v4.json"
        ))
        .and_then(|report| {
            report
                .validate()
                .map_err(|error| serde_json::Error::io(std::io::Error::other(error)))?;
            Ok(report)
        });

        assert!(report.is_ok(), "{report:?}");
    }
}
