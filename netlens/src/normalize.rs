use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;

use anyhow::{bail, Context};

use crate::analyze;
use crate::collect::SocketDropDelta;
use crate::model::{
    validate_evidence, AttributeValue, Attributes, CounterStatus, Direction, EvidenceId,
    EvidenceMeta, MeasurementBound, MetricDelta, MetricKey, MetricValues, NamespacedName,
    Observation, ProviderTelemetry, RawMetricDelta, RawObservation, Subject, SubjectId,
    SubjectKind, SubjectRef, SubjectRole, Telemetry, ATTR_BPF_MODE, ATTR_COUNTER_BITS,
    ATTR_CPU_ROW, ATTR_IFINDEX, ATTR_INTERFACE_NAME, ATTR_SKB_REASON_CODE, ATTR_SKB_REASON_NAME,
    EVENT_SKB_FREE, PROVIDER_KFREE_SKB, PROVIDER_LINK, PROVIDER_SOCK_DIAG,
};
use crate::provider as provider_registry;

#[derive(Debug)]
pub struct EvidenceBundle {
    pub subjects: Vec<Subject>,
    pub metrics: Vec<MetricDelta>,
    pub observations: Vec<Observation>,
}

pub fn normalize(
    raw_metrics: Vec<RawMetricDelta>,
    raw_observations: Vec<RawObservation>,
) -> anyhow::Result<EvidenceBundle> {
    normalize_with_socket_drops(raw_metrics, raw_observations, Vec::new())
}

pub(crate) fn normalize_with_socket_drops(
    raw_metrics: Vec<RawMetricDelta>,
    raw_observations: Vec<RawObservation>,
    socket_drops: Vec<SocketDropDelta>,
) -> anyhow::Result<EvidenceBundle> {
    let mut allocator = ReportIdAllocator::random()?;
    let mut subjects = Vec::new();
    let mut subject_index = BTreeMap::new();
    let mut metrics = Vec::new();

    for raw in raw_metrics {
        let Some((metric_type, layer, mut descriptor)) = analyze::metric_contract(&raw.key) else {
            continue;
        };
        let provider = provider_for_metric(&raw.key)?;
        let attributes = metric_attributes(&raw.key)?;
        let subject_refs = metric_subjects(
            &raw.key,
            &provider,
            &descriptor.direction,
            &mut allocator,
            &mut subject_index,
            &mut subjects,
        )?;
        if raw.delta.is_none() {
            descriptor.measurement.bound = None;
        }
        metrics.push(MetricDelta {
            meta: EvidenceMeta {
                id: allocator.next_evidence(),
                provider,
                layer: Some(layer),
                execution_domain: Some(execution_domain_for_layer(layer)),
                transition: None,
                descriptor,
                subjects: subject_refs,
            },
            metric_type,
            values: MetricValues {
                start: raw.start,
                end: raw.end,
                delta: raw.delta,
                reset: raw.reset,
            },
            attributes,
        });
    }

    for raw in socket_drops {
        let (metric_type, mut descriptor) = analyze::sock_diag_metric_contract();
        if raw.delta.is_none() {
            descriptor.measurement.bound = None;
        }
        let provider = namespaced(PROVIDER_SOCK_DIAG);
        let subject_id = allocator.next_subject();
        subjects.push(Subject {
            id: subject_id.clone(),
            provider: provider.clone(),
            kind: SubjectKind::Socket,
            attributes: Attributes::default(),
        });
        metrics.push(MetricDelta {
            meta: EvidenceMeta {
                id: allocator.next_evidence(),
                provider,
                layer: None,
                execution_domain: Some(namespaced("linux.kernel")),
                transition: None,
                descriptor,
                subjects: vec![SubjectRef {
                    role: SubjectRole::Primary,
                    id: subject_id,
                }],
            },
            metric_type,
            values: MetricValues {
                start: Some(raw.start),
                end: Some(raw.end),
                delta: raw.delta,
                reset: raw.reset,
            },
            attributes: Attributes::default(),
        });
    }

    let provider = namespaced(PROVIDER_KFREE_SKB);
    let event_type = namespaced(EVENT_SKB_FREE);
    let observations = raw_observations
        .into_iter()
        .map(|raw| {
            raw.scope_provenance
                .validate(&raw.descriptor.context)
                .map_err(anyhow::Error::msg)
                .context("validate raw evidence scope provenance")?;
            let mut attributes = Attributes::default();
            if let Some(reason) = raw.reason {
                insert_attribute(
                    &mut attributes,
                    ATTR_SKB_REASON_CODE,
                    AttributeValue::Unsigned(u64::from(reason)),
                )?;
            }
            if let Some(reason_name) = raw.reason_name {
                insert_attribute(
                    &mut attributes,
                    ATTR_SKB_REASON_NAME,
                    AttributeValue::String(reason_name),
                )?;
            }
            insert_attribute(
                &mut attributes,
                ATTR_BPF_MODE,
                AttributeValue::String(raw.source_mode.as_str().to_owned()),
            )?;
            Ok(Observation {
                meta: EvidenceMeta {
                    id: allocator.next_evidence(),
                    provider: provider.clone(),
                    layer: raw.layer,
                    execution_domain: Some(namespaced("linux.kernel")),
                    transition: None,
                    descriptor: raw.descriptor,
                    subjects: Vec::new(),
                },
                event_type: event_type.clone(),
                monotonic_ns: raw.monotonic_ns,
                attributes,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    validate_evidence(&subjects, &metrics, &observations)
        .context("validate normalized report evidence")?;
    Ok(EvidenceBundle {
        subjects,
        metrics,
        observations,
    })
}

pub fn apply_telemetry_bounds(bundle: &mut EvidenceBundle, telemetry: &Telemetry) {
    for provider in telemetry
        .providers
        .iter()
        .filter(|provider| has_loss_or_unknown(provider))
        .map(|provider| provider.provider.as_str())
    {
        for descriptor in bundle
            .metrics
            .iter_mut()
            .filter(|metric| metric.meta.provider.as_str() == provider)
            .map(|metric| &mut metric.meta.descriptor)
            .chain(
                bundle
                    .observations
                    .iter_mut()
                    .filter(|observation| observation.meta.provider.as_str() == provider)
                    .map(|observation| &mut observation.meta.descriptor),
            )
        {
            if descriptor.measurement.bound.is_some() {
                descriptor.measurement.bound = Some(MeasurementBound::LowerBound);
            }
        }
    }
}

fn has_loss_or_unknown(provider: &ProviderTelemetry) -> bool {
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

fn provider_for_metric(key: &MetricKey) -> anyhow::Result<NamespacedName> {
    let Some(provider) = provider_registry::descriptor_for_metric_source(&key.source) else {
        bail!("unregistered metric source {:?}", key.source);
    };
    Ok(namespaced(provider.name))
}

fn metric_attributes(key: &MetricKey) -> anyhow::Result<Attributes> {
    let mut attributes = Attributes::default();
    for (name, value) in &key.labels {
        match name.as_str() {
            "cpu" | "ifindex" => {}
            "interface" => insert_attribute(
                &mut attributes,
                ATTR_INTERFACE_NAME,
                AttributeValue::String(value.clone()),
            )?,
            "counter_bits" => insert_attribute(
                &mut attributes,
                ATTR_COUNTER_BITS,
                AttributeValue::Unsigned(
                    value
                        .parse()
                        .with_context(|| format!("invalid counter_bits label {value:?}"))?,
                ),
            )?,
            "cpu_row" => insert_attribute(
                &mut attributes,
                ATTR_CPU_ROW,
                AttributeValue::Unsigned(
                    value
                        .parse()
                        .with_context(|| format!("invalid cpu_row label {value:?}"))?,
                ),
            )?,
            name => bail!("unregistered metric label {name:?}"),
        }
    }
    Ok(attributes)
}

#[allow(clippy::too_many_arguments)]
fn metric_subjects(
    key: &MetricKey,
    provider: &NamespacedName,
    direction: &Option<Direction>,
    allocator: &mut ReportIdAllocator,
    subject_index: &mut BTreeMap<SubjectKey, SubjectId>,
    subjects: &mut Vec<Subject>,
) -> anyhow::Result<Vec<SubjectRef>> {
    if provider.as_str() != PROVIDER_LINK {
        return Ok(Vec::new());
    }
    let interface_name = key.labels.get("interface");
    let ifindex = key
        .labels
        .get("ifindex")
        .map(|value| {
            value
                .parse::<u32>()
                .with_context(|| format!("invalid ifindex label {value:?}"))
        })
        .transpose()?;
    if interface_name.is_none() && ifindex.is_none() {
        return Ok(Vec::new());
    }

    let mut attributes = Attributes::default();
    if let Some(interface_name) = interface_name {
        insert_attribute(
            &mut attributes,
            ATTR_INTERFACE_NAME,
            AttributeValue::String(interface_name.clone()),
        )?;
    }
    if let Some(ifindex) = ifindex {
        insert_attribute(
            &mut attributes,
            ATTR_IFINDEX,
            AttributeValue::Unsigned(u64::from(ifindex)),
        )?;
    }
    let key = SubjectKey {
        provider: provider.clone(),
        kind: SubjectKind::Interface,
        attributes: attributes.clone(),
    };
    let id = if let Some(id) = subject_index.get(&key) {
        id.clone()
    } else {
        let id = allocator.next_subject();
        subject_index.insert(key, id.clone());
        subjects.push(Subject {
            id: id.clone(),
            provider: provider.clone(),
            kind: SubjectKind::Interface,
            attributes,
        });
        id
    };
    let role = match direction {
        Some(Direction::Ingress) => SubjectRole::Ingress,
        Some(Direction::Egress) => SubjectRole::Egress,
        None => SubjectRole::Primary,
    };
    Ok(vec![SubjectRef { role, id }])
}

fn insert_attribute(
    attributes: &mut Attributes,
    name: &str,
    value: AttributeValue,
) -> anyhow::Result<()> {
    let name = NamespacedName::new(name).expect("registered attribute names are namespaced");
    if attributes.insert(name, value)?.is_some() {
        bail!("duplicate normalized attribute")
    }
    Ok(())
}

fn namespaced(value: &str) -> NamespacedName {
    NamespacedName::new(value).expect("registered names are namespaced")
}

fn execution_domain_for_layer(layer: crate::model::Layer) -> NamespacedName {
    if layer == crate::model::Layer::Nic {
        namespaced("linux.hardware")
    } else {
        namespaced("linux.kernel")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SubjectKey {
    provider: NamespacedName,
    kind: SubjectKind,
    attributes: Attributes,
}

struct ReportIdAllocator {
    nonce: String,
    evidence_counter: u64,
    subject_counter: u64,
}

impl ReportIdAllocator {
    fn random() -> anyhow::Result<Self> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")
            .context("open /dev/urandom for report-local IDs")?
            .read_exact(&mut bytes)
            .context("read report-local ID nonce")?;
        let mut nonce = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut nonce, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Ok(Self {
            nonce,
            evidence_counter: 0,
            subject_counter: 0,
        })
    }

    fn next_evidence(&mut self) -> EvidenceId {
        self.evidence_counter = self
            .evidence_counter
            .checked_add(1)
            .expect("one report cannot contain u64::MAX evidence rows");
        EvidenceId::new(format!("e_{}_{}", self.nonce, self.evidence_counter))
            .expect("allocator creates valid evidence IDs")
    }

    fn next_subject(&mut self) -> SubjectId {
        self.subject_counter = self
            .subject_counter
            .checked_add(1)
            .expect("one report cannot contain u64::MAX subjects");
        SubjectId::new(format!("s_{}_{}", self.nonce, self.subject_counter))
            .expect("allocator creates valid subject IDs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BpfMode, MetricSample, RawMetricDelta};

    #[test]
    fn report_ids_use_distinct_random_nonces() {
        let mut first = ReportIdAllocator::random().unwrap();
        let mut second = ReportIdAllocator::random().unwrap();

        assert_ne!(first.next_evidence(), second.next_evidence());
        assert_ne!(
            first.next_subject().as_str(),
            first.next_evidence().as_str()
        );
    }

    #[test]
    fn raw_collector_labels_do_not_escape_the_attribute_registry() {
        let raw = RawMetricDelta {
            key: MetricKey::new("proc_softnet", "softnet", "dropped")
                .with_label("kernel_pointer", "0xffff000000000000"),
            start: Some(1),
            end: Some(2),
            delta: Some(1),
            reset: false,
        };

        assert!(normalize(vec![raw], Vec::new()).is_err());
    }

    #[test]
    fn unknown_metrics_remain_internal() {
        let sample = MetricSample {
            key: MetricKey::new("proc_net_snmp", "Ip", "DefaultTTL"),
            value: 64,
        };
        let raw = RawMetricDelta {
            key: sample.key,
            start: Some(64),
            end: Some(64),
            delta: Some(0),
            reset: false,
        };

        let bundle = normalize(vec![raw], Vec::new()).unwrap();
        assert!(bundle.metrics.is_empty());
    }

    #[test]
    fn interface_subject_ids_do_not_encode_ifindex() {
        let raw = RawMetricDelta {
            key: MetricKey::new("rtnetlink_link_stats", "link", "rx_dropped")
                .with_label("interface", "eth0")
                .with_label("ifindex", "7")
                .with_label("counter_bits", "64"),
            start: Some(1),
            end: Some(2),
            delta: Some(1),
            reset: false,
        };

        let bundle = normalize(vec![raw], Vec::new()).unwrap();
        assert_eq!(bundle.subjects.len(), 1);
        assert!(!bundle.subjects[0].id.as_str().contains("eth0"));
        assert!(!bundle.subjects[0].id.as_str().contains("_7_"));
    }

    #[test]
    fn per_socket_deltas_get_distinct_opaque_subjects_without_findings() {
        let bundle = normalize_with_socket_drops(
            Vec::new(),
            Vec::new(),
            vec![
                SocketDropDelta {
                    start: 2,
                    end: 5,
                    delta: Some(3),
                    reset: false,
                },
                SocketDropDelta {
                    start: 10,
                    end: 17,
                    delta: Some(7),
                    reset: false,
                },
            ],
        )
        .unwrap();

        assert_eq!(bundle.subjects.len(), 2);
        assert_eq!(bundle.metrics.len(), 2);
        assert_ne!(bundle.subjects[0].id, bundle.subjects[1].id);
        assert!(bundle.subjects.iter().all(|subject| {
            subject.provider.as_str() == PROVIDER_SOCK_DIAG
                && subject.kind == SubjectKind::Socket
                && subject.attributes.is_empty()
        }));
        assert!(bundle.metrics.iter().all(|metric| {
            metric.meta.provider.as_str() == PROVIDER_SOCK_DIAG
                && metric.metric_type.as_str() == crate::model::METRIC_SOCK_DIAG_DROPS
                && metric.meta.layer.is_none()
                && metric.meta.descriptor.stage.is_none()
                && metric.meta.descriptor.direction.is_none()
                && metric.meta.descriptor.path_role.is_none()
                && metric.meta.descriptor.outcome == crate::model::Outcome::default()
                && metric.meta.descriptor.role == crate::model::EvidenceRole::Context
                && metric.meta.descriptor.measurement.unit
                    == crate::model::MeasurementUnit::SourceUnits
                && metric.meta.descriptor.measurement.domain.is_none()
                && metric.meta.descriptor.measurement.scope
                    == Some(crate::model::MeasurementScope::Socket)
                && metric.meta.descriptor.measurement.bound
                    == Some(crate::model::MeasurementBound::LowerBound)
                && metric.meta.subjects.len() == 1
                && metric.meta.subjects[0].role == SubjectRole::Primary
        }));

        let findings = analyze::findings(&bundle.metrics, &bundle.observations);
        assert!(findings.is_empty());

        let rendered = serde_json::to_string(&(bundle.subjects, bundle.metrics)).unwrap();
        for private_name in [
            "cookie",
            "inode",
            "pointer",
            "source_port",
            "destination_port",
        ] {
            assert!(!rendered.contains(private_name));
        }
    }

    #[test]
    fn per_socket_reset_keeps_endpoints_without_a_delta_bound_or_finding() {
        let bundle = normalize_with_socket_drops(
            Vec::new(),
            Vec::new(),
            vec![SocketDropDelta {
                start: 17,
                end: 3,
                delta: None,
                reset: true,
            }],
        )
        .unwrap();

        assert_eq!(bundle.subjects.len(), 1);
        assert_eq!(bundle.metrics.len(), 1);
        let metric = &bundle.metrics[0];
        assert_eq!(metric.values.start, Some(17));
        assert_eq!(metric.values.end, Some(3));
        assert_eq!(metric.values.delta, None);
        assert!(metric.values.reset);
        assert_eq!(metric.meta.descriptor.measurement.bound, None);
        assert_eq!(
            metric.meta.descriptor.measurement.unit,
            crate::model::MeasurementUnit::SourceUnits
        );
        assert!(analyze::findings(&bundle.metrics, &bundle.observations).is_empty());
    }

    #[test]
    fn socket_delta_and_proc_aggregate_coexist_without_summing() {
        let proc = RawMetricDelta {
            key: MetricKey::new("proc_net_snmp", "Udp", "RcvbufErrors"),
            start: Some(20),
            end: Some(30),
            delta: Some(10),
            reset: false,
        };
        let bundle = normalize_with_socket_drops(
            vec![proc],
            Vec::new(),
            vec![SocketDropDelta {
                start: 4,
                end: 7,
                delta: Some(3),
                reset: false,
            }],
        )
        .unwrap();

        let findings = analyze::findings(&bundle.metrics, &bundle.observations);
        assert_eq!(bundle.metrics.len(), 2);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 10);
        assert!(!findings.iter().any(|finding| finding.count == 13));
    }

    #[test]
    fn bpf_mode_is_preserved_as_a_typed_observation_attribute() {
        let descriptor = analyze::skb_free_descriptor(None, None, 0, 0);
        let raw = RawObservation {
            monotonic_ns: 1,
            reason: None,
            reason_name: None,
            layer: None,
            scope_provenance: crate::model::EvidenceScopeProvenance::observed(&descriptor.context),
            descriptor,
            source_mode: BpfMode::LegacyPerf,
        };

        let bundle = normalize(Vec::new(), vec![raw]).unwrap();
        assert_eq!(
            bundle.observations[0]
                .attributes
                .get(ATTR_BPF_MODE)
                .and_then(AttributeValue::as_str),
            Some("legacy_perf")
        );
    }

    #[test]
    fn requested_scope_values_cannot_enter_observation_context() {
        let descriptor = analyze::skb_free_descriptor(None, None, 0, 17);
        let mut scope_provenance =
            crate::model::EvidenceScopeProvenance::observed(&descriptor.context);
        scope_provenance.protocol = Some(crate::model::ScopeValueProvenance::Requested);
        let raw = RawObservation {
            monotonic_ns: 1,
            reason: None,
            reason_name: None,
            layer: None,
            descriptor,
            scope_provenance,
            source_mode: BpfMode::LegacyPerf,
        };

        let error = normalize(Vec::new(), vec![raw]).unwrap_err();

        assert!(format!("{error:#}").contains("requested scope"));
    }
}
