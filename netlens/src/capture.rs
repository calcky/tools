use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::collect::valid_interface_name;
use crate::model::{Direction, FilterSupport, IfIndex, Layer, NamespacedName, Severity};

const MAX_CAPTURE_DURATION: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CaptureDuration(Duration);

impl CaptureDuration {
    pub fn new(duration: Duration) -> Result<Self, String> {
        if duration > MAX_CAPTURE_DURATION {
            Err("duration must not exceed 1h".to_owned())
        } else {
            Ok(Self(duration))
        }
    }

    pub const fn get(self) -> Duration {
        self.0
    }

    pub fn as_millis(self) -> u64 {
        self.0
            .as_millis()
            .try_into()
            .expect("capture duration is bounded to one hour")
    }
}

impl FromStr for CaptureDuration {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let duration = humantime::parse_duration(value).map_err(|error| error.to_string())?;
        Self::new(duration)
    }
}

impl Serialize for CaptureDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.as_millis())
    }
}

impl<'de> Deserialize<'de> for CaptureDuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(Duration::from_millis(u64::deserialize(deserializer)?))
            .map_err(serde::de::Error::custom)
    }
}

pub fn parse_layer(value: &str) -> Result<Layer, String> {
    Layer::ALL
        .into_iter()
        .find(|layer| layer.as_str() == value)
        .ok_or_else(|| format!("unknown capture layer {value:?}"))
}

pub fn parse_direction(value: &str) -> Result<Direction, String> {
    match value {
        "ingress" => Ok(Direction::Ingress),
        "egress" => Ok(Direction::Egress),
        _ => Err(format!("direction must be ingress or egress: {value:?}")),
    }
}

pub fn parse_failure_threshold(value: &str) -> Result<Severity, String> {
    match value {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!(
            "fail-on must be info, warning, or critical: {value:?}"
        )),
    }
}

pub const fn severity_meets_threshold(threshold: Severity, severity: Severity) -> bool {
    severity_rank(severity) >= severity_rank(threshold)
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Critical => 2,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum InterfaceAnchor {
    Name { name: String },
    Ifindex { ifindex: IfIndex },
}

impl InterfaceAnchor {
    pub fn named(name: impl Into<String>) -> Result<Self, String> {
        let name = name.into();
        if valid_interface_name(&name) {
            Ok(Self::Name { name })
        } else {
            Err(format!("invalid Linux interface name {name:?}"))
        }
    }

    pub fn indexed(ifindex: u32) -> Result<Self, String> {
        Ok(Self::Ifindex {
            ifindex: IfIndex::new(ifindex).map_err(|error| error.to_string())?,
        })
    }

    fn validate(&self) -> Result<(), InterfacePathValidationError> {
        if let Self::Name { name } = self {
            if !valid_interface_name(name) {
                return Err(InterfacePathValidationError::InvalidAnchorName { name: name.clone() });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyGap {
    AnchorUnresolved,
    DynamicRedirect,
    CrossNamespace,
    HardwareOffload,
    LowerDeviceUnresolved,
    TunnelUnresolved,
}

impl TopologyGap {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AnchorUnresolved => "anchor_unresolved",
            Self::DynamicRedirect => "dynamic_redirect",
            Self::CrossNamespace => "cross_namespace",
            Self::HardwareOffload => "hardware_offload",
            Self::LowerDeviceUnresolved => "lower_device_unresolved",
            Self::TunnelUnresolved => "tunnel_unresolved",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfacePath {
    pub anchor: InterfaceAnchor,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub resolved_anchor_ifindex: Option<IfIndex>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub visible_ifindices: BTreeSet<IfIndex>,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub topology_gaps: BTreeSet<TopologyGap>,
}

impl InterfacePath {
    pub fn unresolved(anchor: InterfaceAnchor) -> Self {
        Self {
            anchor,
            resolved_anchor_ifindex: None,
            visible_ifindices: BTreeSet::new(),
            topology_gaps: [TopologyGap::AnchorUnresolved].into_iter().collect(),
        }
    }

    pub fn new(
        anchor: InterfaceAnchor,
        resolved_anchor_ifindex: Option<IfIndex>,
        visible_ifindices: impl IntoIterator<Item = IfIndex>,
        topology_gaps: impl IntoIterator<Item = TopologyGap>,
    ) -> Result<Self, InterfacePathValidationError> {
        let path = Self {
            anchor,
            resolved_anchor_ifindex,
            visible_ifindices: visible_ifindices.into_iter().collect(),
            topology_gaps: topology_gaps.into_iter().collect(),
        };
        path.validate()?;
        Ok(path)
    }

    pub fn is_complete(&self) -> bool {
        self.topology_gaps.is_empty()
    }

    pub fn validate(&self) -> Result<(), InterfacePathValidationError> {
        self.anchor.validate()?;
        if self.topology_gaps.contains(&TopologyGap::AnchorUnresolved) {
            if self.resolved_anchor_ifindex.is_some() || !self.visible_ifindices.is_empty() {
                return Err(InterfacePathValidationError::UnresolvedAnchorHasResolvedContext);
            }
            if self.topology_gaps.len() != 1 {
                return Err(InterfacePathValidationError::UnresolvedAnchorHasTopologyGaps);
            }
            return Ok(());
        }
        if let InterfaceAnchor::Ifindex { ifindex } = self.anchor {
            if self.resolved_anchor_ifindex != Some(ifindex) {
                return Err(InterfacePathValidationError::AnchorIfindexMismatch {
                    expected: ifindex.get(),
                    resolved: self.resolved_anchor_ifindex.map(IfIndex::get),
                });
            }
        }
        if self.resolved_anchor_ifindex.is_none() {
            return Err(InterfacePathValidationError::UnresolvedCompleteAnchor);
        }
        if let Some(ifindex) = self.resolved_anchor_ifindex {
            if !self.visible_ifindices.contains(&ifindex) {
                return Err(InterfacePathValidationError::MissingAnchorIfindex {
                    ifindex: ifindex.get(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpProtocol(u8);

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const DCCP: Self = Self(33);
    pub const ICMPV6: Self = Self(58);
    pub const SCTP: Self = Self(132);
    pub const UDP_LITE: Self = Self(136);

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn carries_ports(self) -> bool {
        matches!(
            self,
            Self::TCP | Self::UDP | Self::DCCP | Self::SCTP | Self::UDP_LITE
        )
    }
}

impl FromStr for IpProtocol {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "icmp" => Ok(Self::ICMP),
            "tcp" => Ok(Self::TCP),
            "udp" => Ok(Self::UDP),
            "dccp" => Ok(Self::DCCP),
            "icmpv6" | "ipv6-icmp" => Ok(Self::ICMPV6),
            "sctp" => Ok(Self::SCTP),
            "udplite" | "udp-lite" => Ok(Self::UDP_LITE),
            _ => value.parse::<u8>().map(Self).map_err(|_| {
                format!("protocol must be a known name or an integer from 0 through 255: {value:?}")
            }),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FlowFilter {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub protocol: Option<IpProtocol>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_address: Option<IpAddr>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub destination_address: Option<IpAddr>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub source_port: Option<u16>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub destination_port: Option<u16>,
}

impl FlowFilter {
    pub fn validate(&self) -> Result<(), FlowFilterValidationError> {
        if self
            .source_address
            .zip(self.destination_address)
            .is_some_and(|(source, destination)| source.is_ipv4() != destination.is_ipv4())
        {
            return Err(FlowFilterValidationError::MixedAddressFamilies);
        }

        if let Some(protocol) = self.protocol {
            if (self.source_port.is_some() || self.destination_port.is_some())
                && !protocol.carries_ports()
            {
                return Err(FlowFilterValidationError::ProtocolHasNoPorts { protocol });
            }
            let addresses = self
                .source_address
                .into_iter()
                .chain(self.destination_address);
            let (mut has_ipv4, mut has_ipv6) = (false, false);
            for address in addresses {
                has_ipv4 |= address.is_ipv4();
                has_ipv6 |= address.is_ipv6();
            }
            if (protocol == IpProtocol::ICMP && has_ipv6)
                || (protocol == IpProtocol::ICMPV6 && has_ipv4)
            {
                return Err(FlowFilterValidationError::ProtocolAddressFamily { protocol });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessFilter {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub pid: Option<u32>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub cgroup: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SamplingRequest {
    #[default]
    None,
    Ratio {
        numerator: u32,
        denominator: u32,
    },
}

impl SamplingRequest {
    fn validate(self) -> Result<(), CapturePlanValidationError> {
        match self {
            Self::None => Ok(()),
            Self::Ratio {
                numerator,
                denominator,
            } if numerator > 0 && denominator > 0 && numerator <= denominator => Ok(()),
            Self::Ratio { .. } => Err(CapturePlanValidationError::InvalidSamplingRatio),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetailLevel {
    #[default]
    Summary,
    Full,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CurrentNetworkNamespace {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub identity: Option<String>,
}

impl CurrentNetworkNamespace {
    pub const fn unknown() -> Self {
        Self { identity: None }
    }

    pub fn identified(identity: impl Into<String>) -> Result<Self, String> {
        let identity = identity.into();
        validate_network_namespace_identity(&identity)?;
        Ok(Self {
            identity: Some(identity),
        })
    }

    fn validate(&self) -> Result<(), CapturePlanValidationError> {
        if let Some(identity) = &self.identity {
            validate_network_namespace_identity(identity)
                .map_err(|_| CapturePlanValidationError::InvalidNetworkNamespaceIdentity)?;
        }
        Ok(())
    }
}

fn validate_network_namespace_identity(identity: &str) -> Result<(), String> {
    if !identity.is_empty()
        && identity.len() <= 128
        && identity.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        Ok(())
    } else {
        Err("network namespace identity must be 1..=128 printable ASCII bytes".to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePlan {
    #[serde(rename = "durationMs")]
    pub duration: CaptureDuration,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub layers: BTreeSet<Layer>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub direction: Option<Direction>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub interface_path: Option<InterfacePath>,
    pub network_namespace: CurrentNetworkNamespace,
    pub flow: FlowFilter,
    pub process: ProcessFilter,
    pub sampling: SamplingRequest,
    pub detail_level: DetailLevel,
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub required_layers: BTreeSet<Layer>,
    pub strict_coverage: bool,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub fail_on: Option<Severity>,
}

impl CapturePlan {
    pub fn new(duration: CaptureDuration, network_namespace: CurrentNetworkNamespace) -> Self {
        Self {
            duration,
            layers: all_layers(),
            direction: None,
            interface_path: None,
            network_namespace,
            flow: FlowFilter::default(),
            process: ProcessFilter::default(),
            sampling: SamplingRequest::None,
            detail_level: DetailLevel::Summary,
            required_layers: BTreeSet::new(),
            strict_coverage: false,
            fail_on: None,
        }
    }

    pub fn validate(&self) -> Result<(), CapturePlanValidationError> {
        validate_requested_scope(
            &self.layers,
            &self.network_namespace,
            self.interface_path.as_ref(),
            &self.flow,
        )?;
        for layer in &self.required_layers {
            if !self.layers.contains(layer) {
                return Err(CapturePlanValidationError::RequiredLayerNotSelected { layer: *layer });
            }
        }
        self.sampling.validate()?;
        if self.process.pid.is_some() {
            return Err(CapturePlanValidationError::UnsupportedProcessFilter {
                filter: ProcessFilterKind::Pid,
            });
        }
        if self.process.cgroup.is_some() {
            return Err(CapturePlanValidationError::UnsupportedProcessFilter {
                filter: ProcessFilterKind::Cgroup,
            });
        }
        Ok(())
    }

    pub fn requested_scope(&self) -> Result<RequestedScope, CapturePlanValidationError> {
        self.validate()?;
        validate_resolved_interface_path(self.interface_path.as_ref())?;
        Ok(RequestedScope {
            layers: self.layers.clone(),
            network_namespace: self.network_namespace.clone(),
            interface_path: self.interface_path.clone(),
            direction: self.direction,
            flow: self.flow.clone(),
        })
    }
}

/// Requested scope is a filter request, not observed packet context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedScope {
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub layers: BTreeSet<Layer>,
    pub network_namespace: CurrentNetworkNamespace,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub interface_path: Option<InterfacePath>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub direction: Option<Direction>,
    pub flow: FlowFilter,
}

impl RequestedScope {
    pub fn validate(&self) -> Result<(), CapturePlanValidationError> {
        validate_requested_scope(
            &self.layers,
            &self.network_namespace,
            self.interface_path.as_ref(),
            &self.flow,
        )?;
        validate_resolved_interface_path(self.interface_path.as_ref())
    }
}

fn validate_resolved_interface_path(
    interface_path: Option<&InterfacePath>,
) -> Result<(), CapturePlanValidationError> {
    if interface_path.is_some_and(|path| {
        path.resolved_anchor_ifindex.is_none()
            || path.topology_gaps.contains(&TopologyGap::AnchorUnresolved)
    }) {
        Err(CapturePlanValidationError::UnresolvedInterfaceAnchor)
    } else {
        Ok(())
    }
}

fn validate_requested_scope(
    layers: &BTreeSet<Layer>,
    network_namespace: &CurrentNetworkNamespace,
    interface_path: Option<&InterfacePath>,
    flow: &FlowFilter,
) -> Result<(), CapturePlanValidationError> {
    if layers.is_empty() {
        return Err(CapturePlanValidationError::EmptyLayerSelection);
    }
    network_namespace.validate()?;
    if let Some(path) = interface_path {
        path.validate()
            .map_err(CapturePlanValidationError::InvalidInterfacePath)?;
    }
    flow.validate()
        .map_err(CapturePlanValidationError::InvalidFlowFilter)
}

fn all_layers() -> BTreeSet<Layer> {
    Layer::ALL.into_iter().collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "extent",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EffectiveNetworkNamespace {
    Current {
        #[serde(deserialize_with = "deserialize_required_option")]
        identity: Option<String>,
    },
    HostWide,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "extent",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EffectiveInterfaceScope {
    AllVisible,
    Path { path: InterfacePath },
    Unknown,
}

/// Effective scope describes collection breadth. It must never be copied into
/// `EvidenceContext`; evidence context contains only values a provider observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectiveScope {
    #[serde(deserialize_with = "deserialize_unique_set")]
    pub layers: BTreeSet<Layer>,
    pub network_namespace: EffectiveNetworkNamespace,
    pub interface_scope: EffectiveInterfaceScope,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub direction: Option<Direction>,
    pub flow: FlowFilter,
}

impl EffectiveScope {
    pub fn exact(requested: &RequestedScope) -> Self {
        Self {
            layers: requested.layers.clone(),
            network_namespace: EffectiveNetworkNamespace::Current {
                identity: requested.network_namespace.identity.clone(),
            },
            interface_scope: requested
                .interface_path
                .clone()
                .map_or(EffectiveInterfaceScope::AllVisible, |path| {
                    EffectiveInterfaceScope::Path { path }
                }),
            direction: requested.direction,
            flow: requested.flow.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFilterSupport {
    pub layers: FilterSupport,
    pub network_namespace: FilterSupport,
    pub interface_path: FilterSupport,
    pub direction: FilterSupport,
    pub protocol: FilterSupport,
    pub source_address: FilterSupport,
    pub destination_address: FilterSupport,
    pub source_port: FilterSupport,
    pub destination_port: FilterSupport,
}

impl ProviderFilterSupport {
    pub const fn uniform(support: FilterSupport) -> Self {
        Self {
            layers: support,
            network_namespace: support,
            interface_path: support,
            direction: support,
            protocol: support,
            source_address: support,
            destination_address: support,
            source_port: support,
            destination_port: support,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeDimension {
    Layers,
    NetworkNamespace,
    InterfacePath,
    Direction,
    Protocol,
    SourceAddress,
    DestinationAddress,
    SourcePort,
    DestinationPort,
}

impl fmt::Display for ScopeDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Layers => "layers",
            Self::NetworkNamespace => "network namespace",
            Self::InterfacePath => "interface path",
            Self::Direction => "direction",
            Self::Protocol => "protocol",
            Self::SourceAddress => "source address",
            Self::DestinationAddress => "destination address",
            Self::SourcePort => "source port",
            Self::DestinationPort => "destination port",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderScope {
    pub provider: NamespacedName,
    pub requested: RequestedScope,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub effective: Option<EffectiveScope>,
    pub filter_support: ProviderFilterSupport,
}

impl ProviderScope {
    pub fn active(
        provider: NamespacedName,
        requested: RequestedScope,
        effective: EffectiveScope,
        filter_support: ProviderFilterSupport,
    ) -> Result<Self, ProviderScopeValidationError> {
        let scope = Self {
            provider,
            requested,
            effective: Some(effective),
            filter_support,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn unavailable(
        provider: NamespacedName,
        requested: RequestedScope,
        filter_support: ProviderFilterSupport,
    ) -> Result<Self, ProviderScopeValidationError> {
        let scope = Self {
            provider,
            requested,
            effective: None,
            filter_support,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ProviderScopeValidationError> {
        self.requested
            .validate()
            .map_err(ProviderScopeValidationError::InvalidRequestedScope)?;
        let Some(effective) = &self.effective else {
            return Ok(());
        };
        validate_effective_scope(effective)?;

        validate_layers(
            &self.requested.layers,
            &effective.layers,
            self.filter_support.layers,
        )?;
        validate_network_namespace(
            &self.requested.network_namespace,
            &effective.network_namespace,
            self.filter_support.network_namespace,
        )?;
        if self.requested.interface_path.is_some()
            && matches!(
                effective.network_namespace,
                EffectiveNetworkNamespace::HostWide | EffectiveNetworkNamespace::Unknown
            )
            && matches!(
                effective.interface_scope,
                EffectiveInterfaceScope::Path { .. }
            )
        {
            return Err(ProviderScopeValidationError::EffectiveScopeMismatch {
                dimension: ScopeDimension::InterfacePath,
                support: self.filter_support.interface_path,
            });
        }
        validate_interface_scope(
            self.requested.interface_path.as_ref(),
            &effective.interface_scope,
            self.filter_support.interface_path,
        )?;
        validate_optional_dimension(
            ScopeDimension::Direction,
            self.requested.direction,
            effective.direction,
            self.filter_support.direction,
        )?;
        validate_optional_dimension(
            ScopeDimension::Protocol,
            self.requested.flow.protocol,
            effective.flow.protocol,
            self.filter_support.protocol,
        )?;
        validate_optional_dimension(
            ScopeDimension::SourceAddress,
            self.requested.flow.source_address,
            effective.flow.source_address,
            self.filter_support.source_address,
        )?;
        validate_optional_dimension(
            ScopeDimension::DestinationAddress,
            self.requested.flow.destination_address,
            effective.flow.destination_address,
            self.filter_support.destination_address,
        )?;
        validate_optional_dimension(
            ScopeDimension::SourcePort,
            self.requested.flow.source_port,
            effective.flow.source_port,
            self.filter_support.source_port,
        )?;
        validate_optional_dimension(
            ScopeDimension::DestinationPort,
            self.requested.flow.destination_port,
            effective.flow.destination_port,
            self.filter_support.destination_port,
        )
    }
}

fn validate_effective_scope(
    effective: &EffectiveScope,
) -> Result<(), ProviderScopeValidationError> {
    if effective.layers.is_empty() {
        return Err(ProviderScopeValidationError::InvalidEffectiveScope(
            "effective scope must contain at least one layer".to_owned(),
        ));
    }
    if let EffectiveNetworkNamespace::Current {
        identity: Some(identity),
    } = &effective.network_namespace
    {
        validate_network_namespace_identity(identity)
            .map_err(ProviderScopeValidationError::InvalidEffectiveScope)?;
    }
    if let EffectiveInterfaceScope::Path { path } = &effective.interface_scope {
        path.validate().map_err(|error| {
            ProviderScopeValidationError::InvalidEffectiveScope(error.to_string())
        })?;
    }
    effective
        .flow
        .validate()
        .map_err(|error| ProviderScopeValidationError::InvalidEffectiveScope(error.to_string()))
}

fn validate_layers(
    requested: &BTreeSet<Layer>,
    effective: &BTreeSet<Layer>,
    support: FilterSupport,
) -> Result<(), ProviderScopeValidationError> {
    let unconstrained = requested == &all_layers();
    let includes_requested_layer = effective.iter().any(|layer| requested.contains(layer));
    let valid = match support {
        FilterSupport::KernelExact | FilterSupport::UserspaceExact => {
            includes_requested_layer && effective.is_subset(requested)
        }
        FilterSupport::BroaderOnly => {
            includes_requested_layer
                && (unconstrained || effective.iter().any(|layer| !requested.contains(layer)))
        }
        FilterSupport::Unsupported => unconstrained && includes_requested_layer,
    };
    scope_result(ScopeDimension::Layers, support, valid)
}

fn validate_network_namespace(
    requested: &CurrentNetworkNamespace,
    effective: &EffectiveNetworkNamespace,
    support: FilterSupport,
) -> Result<(), ProviderScopeValidationError> {
    let exact_current = match effective {
        EffectiveNetworkNamespace::Current { identity } => requested
            .identity
            .as_ref()
            .is_none_or(|requested| identity.as_ref() == Some(requested)),
        EffectiveNetworkNamespace::HostWide | EffectiveNetworkNamespace::Unknown => false,
    };
    let valid = match support {
        FilterSupport::KernelExact | FilterSupport::UserspaceExact => exact_current,
        FilterSupport::BroaderOnly => matches!(
            effective,
            EffectiveNetworkNamespace::HostWide | EffectiveNetworkNamespace::Unknown
        ),
        FilterSupport::Unsupported => false,
    };
    scope_result(ScopeDimension::NetworkNamespace, support, valid)
}

fn validate_interface_scope(
    requested: Option<&InterfacePath>,
    effective: &EffectiveInterfaceScope,
    support: FilterSupport,
) -> Result<(), ProviderScopeValidationError> {
    let valid = match requested {
        None => matches!(
            effective,
            EffectiveInterfaceScope::AllVisible | EffectiveInterfaceScope::Unknown
        ),
        Some(requested) => match support {
            FilterSupport::KernelExact | FilterSupport::UserspaceExact => {
                requested.is_complete()
                    && matches!(effective, EffectiveInterfaceScope::Path { path } if path == requested)
            }
            FilterSupport::BroaderOnly => matches!(
                effective,
                EffectiveInterfaceScope::AllVisible | EffectiveInterfaceScope::Unknown
            ),
            FilterSupport::Unsupported => false,
        },
    };
    scope_result(ScopeDimension::InterfacePath, support, valid)
}

fn validate_optional_dimension<T: Copy + Eq>(
    dimension: ScopeDimension,
    requested: Option<T>,
    effective: Option<T>,
    support: FilterSupport,
) -> Result<(), ProviderScopeValidationError> {
    let valid = match requested {
        None => effective.is_none(),
        Some(requested) => match support {
            FilterSupport::KernelExact | FilterSupport::UserspaceExact => {
                effective == Some(requested)
            }
            FilterSupport::BroaderOnly => effective.is_none(),
            FilterSupport::Unsupported => false,
        },
    };
    scope_result(dimension, support, valid)
}

fn scope_result(
    dimension: ScopeDimension,
    support: FilterSupport,
    valid: bool,
) -> Result<(), ProviderScopeValidationError> {
    if valid {
        Ok(())
    } else if support == FilterSupport::Unsupported {
        Err(ProviderScopeValidationError::UnsupportedRequestedFilter { dimension })
    } else {
        Err(ProviderScopeValidationError::EffectiveScopeMismatch { dimension, support })
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn deserialize_unique_set<'de, D, T>(deserializer: D) -> Result<BTreeSet<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    let values = Vec::<T>::deserialize(deserializer)?;
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(value) {
            return Err(serde::de::Error::custom("array values must be unique"));
        }
    }
    Ok(unique)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessFilterKind {
    Pid,
    Cgroup,
}

impl fmt::Display for ProcessFilterKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pid => "PID",
            Self::Cgroup => "cgroup",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InterfacePathValidationError {
    InvalidAnchorName {
        name: String,
    },
    UnresolvedAnchorHasResolvedContext,
    UnresolvedAnchorHasTopologyGaps,
    AnchorIfindexMismatch {
        expected: u32,
        resolved: Option<u32>,
    },
    UnresolvedCompleteAnchor,
    MissingAnchorIfindex {
        ifindex: u32,
    },
}

impl fmt::Display for InterfacePathValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAnchorName { name } => {
                write!(formatter, "invalid Linux interface name {name:?}")
            }
            Self::UnresolvedAnchorHasResolvedContext => formatter.write_str(
                "an unresolved interface anchor cannot contain resolved or visible ifindices",
            ),
            Self::UnresolvedAnchorHasTopologyGaps => formatter
                .write_str("an unresolved interface anchor cannot contain other topology gaps"),
            Self::AnchorIfindexMismatch { expected, resolved } => write!(
                formatter,
                "resolved anchor ifindex {resolved:?} does not match requested ifindex {expected}"
            ),
            Self::UnresolvedCompleteAnchor => {
                formatter.write_str("a resolved interface path must contain the anchor ifindex")
            }
            Self::MissingAnchorIfindex { ifindex } => write!(
                formatter,
                "interface topology closure does not contain anchor ifindex {ifindex}"
            ),
        }
    }
}

impl std::error::Error for InterfacePathValidationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowFilterValidationError {
    MixedAddressFamilies,
    ProtocolHasNoPorts { protocol: IpProtocol },
    ProtocolAddressFamily { protocol: IpProtocol },
}

impl fmt::Display for FlowFilterValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedAddressFamilies => {
                formatter.write_str("source and destination addresses must use the same IP family")
            }
            Self::ProtocolHasNoPorts { protocol } => write!(
                formatter,
                "IP protocol {} does not have source or destination ports",
                protocol.get()
            ),
            Self::ProtocolAddressFamily { protocol } => write!(
                formatter,
                "IP protocol {} conflicts with the requested address family",
                protocol.get()
            ),
        }
    }
}

impl std::error::Error for FlowFilterValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapturePlanValidationError {
    EmptyLayerSelection,
    RequiredLayerNotSelected { layer: Layer },
    UnsupportedProcessFilter { filter: ProcessFilterKind },
    InvalidSamplingRatio,
    InvalidNetworkNamespaceIdentity,
    UnresolvedInterfaceAnchor,
    InvalidInterfacePath(InterfacePathValidationError),
    InvalidFlowFilter(FlowFilterValidationError),
}

impl fmt::Display for CapturePlanValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLayerSelection => formatter.write_str("at least one layer must be selected"),
            Self::RequiredLayerNotSelected { layer } => write!(
                formatter,
                "required layer {} is outside the selected layer set",
                layer.as_str()
            ),
            Self::UnsupportedProcessFilter { filter } => {
                write!(
                    formatter,
                    "{filter} filtering is unsupported in this release"
                )
            }
            Self::InvalidSamplingRatio => {
                formatter.write_str("sampling ratio requires 0 < numerator <= denominator")
            }
            Self::InvalidNetworkNamespaceIdentity => formatter
                .write_str("network namespace identity must be 1..=128 printable ASCII bytes"),
            Self::UnresolvedInterfaceAnchor => {
                formatter.write_str("interface anchor is not resolved in the current namespace")
            }
            Self::InvalidInterfacePath(error) => error.fmt(formatter),
            Self::InvalidFlowFilter(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CapturePlanValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderScopeValidationError {
    InvalidRequestedScope(CapturePlanValidationError),
    InvalidEffectiveScope(String),
    UnsupportedRequestedFilter {
        dimension: ScopeDimension,
    },
    EffectiveScopeMismatch {
        dimension: ScopeDimension,
        support: FilterSupport,
    },
}

impl fmt::Display for ProviderScopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequestedScope(error) => {
                write!(formatter, "invalid requested scope: {error}")
            }
            Self::InvalidEffectiveScope(error) => {
                write!(formatter, "invalid effective scope: {error}")
            }
            Self::UnsupportedRequestedFilter { dimension } => write!(
                formatter,
                "provider does not support requested {dimension} filter"
            ),
            Self::EffectiveScopeMismatch { dimension, support } => write!(
                formatter,
                "effective {dimension} scope is inconsistent with {} filter support",
                support.as_str()
            ),
        }
    }
}

impl std::error::Error for ProviderScopeValidationError {}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use serde_json::json;

    use super::*;

    fn plan() -> CapturePlan {
        CapturePlan::new(
            CaptureDuration::new(Duration::from_secs(1)).unwrap(),
            CurrentNetworkNamespace::identified("net:[4026531840]").unwrap(),
        )
    }

    fn provider() -> NamespacedName {
        NamespacedName::new(crate::model::PROVIDER_LINK).unwrap()
    }

    fn resolved_path() -> InterfacePath {
        InterfacePath::new(
            InterfaceAnchor::indexed(2).unwrap(),
            Some(IfIndex::new(2).unwrap()),
            [IfIndex::new(2).unwrap()],
            [],
        )
        .unwrap()
    }

    #[test]
    fn duration_keeps_zero_valid_and_rejects_more_than_one_hour() {
        assert_eq!("0ms".parse::<CaptureDuration>().unwrap().as_millis(), 0);
        assert_eq!(
            "1h".parse::<CaptureDuration>().unwrap().as_millis(),
            3_600_000
        );
        assert!("3600001ms".parse::<CaptureDuration>().is_err());
        assert_eq!(
            serde_json::from_value::<CaptureDuration>(json!(1000))
                .unwrap()
                .get(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn path_and_namespace_inputs_are_validated() {
        assert!(InterfaceAnchor::named("eth0").is_ok());
        assert!(InterfaceAnchor::named("../eth0").is_err());
        assert!(CurrentNetworkNamespace::identified("bad\nidentity").is_err());

        let anchor = InterfaceAnchor::indexed(2).unwrap();
        assert!(matches!(
            InterfacePath::new(anchor.clone(), Some(IfIndex::new(2).unwrap()), [], []),
            Err(InterfacePathValidationError::MissingAnchorIfindex { ifindex: 2 })
        ));
        assert!(matches!(
            InterfacePath::new(
                InterfaceAnchor::named("eth0").unwrap(),
                None,
                [IfIndex::new(2).unwrap()],
                []
            ),
            Err(InterfacePathValidationError::UnresolvedCompleteAnchor)
        ));
        let unresolved = InterfacePath::unresolved(anchor);
        assert_eq!(unresolved.validate(), Ok(()));
        assert!(!unresolved.is_complete());
        assert_eq!(unresolved.resolved_anchor_ifindex, None);
        assert!(unresolved.visible_ifindices.is_empty());

        let mut contradictory = unresolved;
        contradictory.resolved_anchor_ifindex = Some(IfIndex::new(2).unwrap());
        assert_eq!(
            contradictory.validate(),
            Err(InterfacePathValidationError::UnresolvedAnchorHasResolvedContext)
        );
    }

    #[test]
    fn flow_filter_allows_unspecified_transport_protocol_but_rejects_conflicts() {
        assert_eq!(
            FlowFilter {
                destination_port: Some(443),
                ..FlowFilter::default()
            }
            .validate(),
            Ok(())
        );
        assert!(matches!(
            FlowFilter {
                protocol: Some(IpProtocol::ICMP),
                destination_port: Some(7),
                ..FlowFilter::default()
            }
            .validate(),
            Err(FlowFilterValidationError::ProtocolHasNoPorts { .. })
        ));
        assert!(FlowFilter {
            protocol: Some(IpProtocol::new(99)),
            source_port: Some(1),
            ..FlowFilter::default()
        }
        .validate()
        .is_err());
        assert_eq!(
            FlowFilter {
                source_address: Some(Ipv4Addr::LOCALHOST.into()),
                destination_address: Some(Ipv6Addr::LOCALHOST.into()),
                ..FlowFilter::default()
            }
            .validate(),
            Err(FlowFilterValidationError::MixedAddressFamilies)
        );
        assert!(matches!(
            FlowFilter {
                protocol: Some(IpProtocol::ICMPV6),
                destination_address: Some(Ipv4Addr::LOCALHOST.into()),
                ..FlowFilter::default()
            }
            .validate(),
            Err(FlowFilterValidationError::ProtocolAddressFamily { .. })
        ));
    }

    #[test]
    fn pid_and_cgroup_are_explicitly_unsupported() {
        let mut capture = plan();
        capture.process.pid = Some(42);
        assert_eq!(
            capture.validate(),
            Err(CapturePlanValidationError::UnsupportedProcessFilter {
                filter: ProcessFilterKind::Pid
            })
        );
        assert!(matches!(
            capture.requested_scope(),
            Err(CapturePlanValidationError::UnsupportedProcessFilter {
                filter: ProcessFilterKind::Pid
            })
        ));
        capture.process.pid = None;
        capture.process.cgroup = Some("/sys/fs/cgroup/workload".to_owned());
        assert_eq!(
            capture.validate(),
            Err(CapturePlanValidationError::UnsupportedProcessFilter {
                filter: ProcessFilterKind::Cgroup
            })
        );
    }

    #[test]
    fn required_layers_must_be_selected() {
        let mut capture = plan();
        capture.layers = [Layer::Socket].into_iter().collect();
        capture.required_layers = [Layer::Nic].into_iter().collect();
        assert_eq!(
            capture.validate(),
            Err(CapturePlanValidationError::RequiredLayerNotSelected { layer: Layer::Nic })
        );
    }

    #[test]
    fn invalid_sampling_ratio_is_rejected() {
        let mut capture = plan();
        capture.sampling = SamplingRequest::Ratio {
            numerator: 2,
            denominator: 1,
        };
        assert_eq!(
            capture.validate(),
            Err(CapturePlanValidationError::InvalidSamplingRatio)
        );
    }

    #[test]
    fn plan_round_trips_and_requires_nullable_fields() {
        let mut capture = plan();
        capture.interface_path = Some(resolved_path());
        capture.direction = Some(Direction::Ingress);
        capture.flow.protocol = Some(IpProtocol::TCP);
        capture.flow.destination_port = Some(443);
        capture.fail_on = Some(Severity::Warning);
        capture.validate().unwrap();

        let value = serde_json::to_value(&capture).unwrap();
        let decoded: CapturePlan = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded, capture);
        assert_eq!(decoded.validate(), Ok(()));
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("direction");
        assert!(serde_json::from_value::<CapturePlan>(missing).is_err());
    }

    #[test]
    fn fail_on_uses_report_severity_as_a_minimum_threshold() {
        let threshold = parse_failure_threshold("warning").unwrap();
        assert!(!severity_meets_threshold(threshold, Severity::Info));
        assert!(severity_meets_threshold(threshold, Severity::Warning));
        assert!(severity_meets_threshold(threshold, Severity::Critical));
    }

    #[test]
    fn exact_provider_scope_requires_a_complete_matching_path() {
        let mut capture = plan();
        capture.interface_path = Some(resolved_path());
        let requested = capture.requested_scope().unwrap();
        assert!(ProviderScope::active(
            provider(),
            requested.clone(),
            EffectiveScope::exact(&requested),
            ProviderFilterSupport::uniform(FilterSupport::KernelExact),
        )
        .is_ok());

        capture.interface_path = Some(InterfacePath::unresolved(
            InterfaceAnchor::named("eth0").unwrap(),
        ));
        assert!(capture.validate().is_ok());
        assert!(capture.requested_scope().is_err());
    }

    #[test]
    fn exact_provider_scope_reports_only_its_owned_requested_layers() {
        let requested = plan().requested_scope().unwrap();
        let mut effective = EffectiveScope::exact(&requested);
        effective.layers = [Layer::Driver, Layer::Nic].into_iter().collect();
        let scope = ProviderScope::active(
            provider(),
            requested,
            effective,
            ProviderFilterSupport::uniform(FilterSupport::KernelExact),
        )
        .unwrap();
        let effective = scope.effective.unwrap();
        assert_eq!(
            effective.layers,
            [Layer::Driver, Layer::Nic].into_iter().collect()
        );
        assert!(!effective.layers.contains(&Layer::Socket));
    }

    #[test]
    fn broader_only_scope_cannot_copy_the_requested_anchor_or_flow() {
        let mut capture = plan();
        capture.interface_path = Some(resolved_path());
        capture.flow.destination_port = Some(443);
        let requested = capture.requested_scope().unwrap();
        let support = ProviderFilterSupport {
            interface_path: FilterSupport::BroaderOnly,
            destination_port: FilterSupport::BroaderOnly,
            ..ProviderFilterSupport::uniform(FilterSupport::KernelExact)
        };
        assert!(matches!(
            ProviderScope::active(
                provider(),
                requested.clone(),
                EffectiveScope::exact(&requested),
                support,
            ),
            Err(ProviderScopeValidationError::EffectiveScopeMismatch {
                dimension: ScopeDimension::InterfacePath,
                ..
            })
        ));

        let mut broad = EffectiveScope::exact(&requested);
        broad.interface_scope = EffectiveInterfaceScope::AllVisible;
        broad.flow.destination_port = None;
        let scope = ProviderScope::active(provider(), requested, broad, support).unwrap();
        let effective = serde_json::to_value(scope.effective.unwrap()).unwrap();
        assert_eq!(effective["interfaceScope"]["extent"], "all_visible");
        assert!(effective["interfaceScope"].get("path").is_none());
        assert!(effective["flow"]["destinationPort"].is_null());
    }

    #[test]
    fn unsupported_requested_filter_requires_unavailable_provider_scope() {
        let mut capture = plan();
        capture.direction = Some(Direction::Ingress);
        let requested = capture.requested_scope().unwrap();
        let support = ProviderFilterSupport {
            direction: FilterSupport::Unsupported,
            ..ProviderFilterSupport::uniform(FilterSupport::KernelExact)
        };
        assert!(matches!(
            ProviderScope::active(
                provider(),
                requested.clone(),
                EffectiveScope::exact(&requested),
                support,
            ),
            Err(ProviderScopeValidationError::UnsupportedRequestedFilter {
                dimension: ScopeDimension::Direction
            })
        ));
        assert!(ProviderScope::unavailable(provider(), requested, support).is_ok());
    }

    #[test]
    fn host_wide_namespace_is_valid_only_as_broader_scope() {
        let requested = plan().requested_scope().unwrap();
        let mut effective = EffectiveScope::exact(&requested);
        effective.network_namespace = EffectiveNetworkNamespace::HostWide;
        let support = ProviderFilterSupport {
            network_namespace: FilterSupport::BroaderOnly,
            ..ProviderFilterSupport::uniform(FilterSupport::KernelExact)
        };
        assert!(ProviderScope::active(provider(), requested, effective, support).is_ok());
    }

    #[test]
    fn host_wide_scope_cannot_reuse_a_namespace_relative_interface_path() {
        let mut capture = plan();
        capture.interface_path = Some(resolved_path());
        let requested = capture.requested_scope().unwrap();
        let mut effective = EffectiveScope::exact(&requested);
        effective.network_namespace = EffectiveNetworkNamespace::HostWide;
        let support = ProviderFilterSupport {
            network_namespace: FilterSupport::BroaderOnly,
            ..ProviderFilterSupport::uniform(FilterSupport::KernelExact)
        };
        assert!(matches!(
            ProviderScope::active(provider(), requested, effective, support),
            Err(ProviderScopeValidationError::EffectiveScopeMismatch {
                dimension: ScopeDimension::InterfacePath,
                ..
            })
        ));
    }
}
