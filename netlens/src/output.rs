use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use anyhow::Context;

use crate::capture::{
    EffectiveInterfaceScope, EffectiveNetworkNamespace, FlowFilter, InterfaceAnchor,
    ProviderFilterSupport, RequestedScope,
};
use crate::model::{
    BoundedTotal, CapabilityReport, CounterStatus, Direction, Disposition, EvidenceForm,
    EvidenceMeta, EvidenceRole, Layer, MeasurementBound, MeasurementUnit, PathRole, Report,
    SamplingComponent, SamplingTelemetry, Signal, SubjectKind, SubjectRole, TotalBound,
    TraceRecord, ATTR_HOP_ORDINAL, ATTR_SKB_REASON_CODE, ATTR_SKB_REASON_NAME,
};

pub fn doctor_json(mut writer: impl Write, report: &CapabilityReport) -> anyhow::Result<()> {
    report
        .validate()
        .context("validate capability report before JSON output")?;
    serde_json::to_writer_pretty(&mut writer, report).context("serialize doctor report")?;
    writeln!(writer).context("write doctor report")
}

pub fn report_json(mut writer: impl Write, report: &Report) -> anyhow::Result<()> {
    report
        .validate()
        .context("validate report before JSON output")?;
    serde_json::to_writer_pretty(&mut writer, report).context("serialize report")?;
    writeln!(writer).context("write report")
}

pub fn trace_jsonl(mut writer: impl Write, records: &[TraceRecord]) -> anyhow::Result<()> {
    for record in records {
        record
            .validate()
            .context("validate trace record before JSONL output")?;
        serde_json::to_writer(&mut writer, record).context("serialize trace record")?;
        writeln!(writer).context("write trace record")?;
    }
    Ok(())
}

pub fn trace_table(mut writer: impl Write, records: &[TraceRecord]) -> anyhow::Result<()> {
    for record in records {
        record
            .validate()
            .context("validate trace record before table output")?;
    }
    writeln!(writer, "Events")?;
    writeln!(
        writer,
        "  {:<4} {:<4} {:<24} {:<16} {:<24} {:<13} REASON",
        "SEQ", "DIR", "STAGE", "LAYER", "EVENT", "OUTCOME"
    )?;
    for record in records {
        writeln!(
            writer,
            "  {:<4} {:<4} {:<24} {:<16} {:<24} {:<13} {}",
            record.sequence,
            table_direction(record.descriptor.direction),
            record
                .descriptor
                .stage
                .as_ref()
                .map_or("unclassified", |stage| stage.as_str()),
            record.layer.map_or("unclassified", Layer::as_str),
            record.event_type.as_str(),
            trace_outcome(record),
            trace_reason(record),
        )?;
    }
    Ok(())
}

pub fn doctor_table(mut writer: impl Write, report: &CapabilityReport) -> anyhow::Result<()> {
    report
        .validate()
        .context("validate capability report before table output")?;
    writeln!(
        writer,
        "Kernel: {}  BTF: {}",
        report.kernel_release.as_deref().unwrap_or("unknown"),
        yes_no(report.has_kernel_btf)
    )?;
    writeln!(
        writer,
        "kfree_skb: {}  layout: {}  reason: {}  selected mode: {}",
        yes_no(report.kfree_skb.available),
        report
            .kfree_skb
            .layout
            .map(|layout| layout.as_str())
            .unwrap_or("unavailable"),
        yes_no(report.kfree_skb.has_drop_reason),
        report.selected_bpf_mode.as_str()
    )?;
    writeln!(writer, "\nProviders")?;
    for provider in &report.providers {
        writeln!(
            writer,
            "  {:28} {:11} {}",
            provider.name,
            provider.state.as_str(),
            provider.detail
        )?;
    }
    write_coverage(&mut writer, report)
}

pub fn report_table(mut writer: impl Write, report: &Report) -> anyhow::Result<()> {
    report
        .validate()
        .context("validate report before table output")?;
    writeln!(
        writer,
        "Window: {} ms  Interface anchor: {}  Namespace: {}  Direction: {}",
        report.window.duration_ms,
        requested_interface(&report.scope.requested),
        report
            .scope
            .requested
            .network_namespace
            .identity
            .as_deref()
            .unwrap_or("current (identity unknown)"),
        report
            .scope
            .requested
            .direction
            .map_or("any", |direction| direction.as_str())
    )?;
    writeln!(
        writer,
        "Layers: {}  Flow: {}",
        report
            .scope
            .requested
            .layers
            .iter()
            .map(|layer| layer.as_str())
            .collect::<Vec<_>>()
            .join(","),
        requested_flow(&report.scope.requested)
    )?;
    writeln!(writer, "\nProvider scopes")?;
    for provider in &report.scope.providers {
        let effective = provider.effective.as_ref().map_or_else(
            || "unavailable".to_owned(),
            |scope| {
                format!(
                    "layers={} namespace={} interface={} direction={} flow={}",
                    scope
                        .layers
                        .iter()
                        .map(|layer| layer.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    effective_namespace(&scope.network_namespace),
                    effective_interface(&scope.interface_scope),
                    scope
                        .direction
                        .map_or("any", |direction| direction.as_str()),
                    flow_filter(&scope.flow)
                )
            },
        );
        writeln!(
            writer,
            "  {}  effective: {}  support: {}",
            provider.provider.as_str(),
            effective,
            filter_support(&provider.filter_support)
        )?;
    }

    write_report_stages(&mut writer, report)?;

    writeln!(writer, "\nFindings")?;
    if report.findings.is_empty() {
        writeln!(
            writer,
            "  No anomaly counters increased in the covered sources."
        )?;
    } else {
        for finding in &report.findings {
            let count = measurement_value(finding.count, finding.descriptor.measurement.bound);
            writeln!(
                writer,
                "  [{:7}] {:12} {:10} {}  {}",
                finding.severity.as_str(),
                finding.layer.map_or("unclassified", |layer| layer.as_str()),
                finding.confidence.as_str(),
                count,
                finding.title
            )?;
            writeln!(writer, "            {}", finding.summary)?;
        }
    }

    writeln!(
        writer,
        "\nObservations: {} stored",
        report.observations.len()
    )?;

    write_coverage(&mut writer, &report.capabilities)?;
    writeln!(writer, "\nTelemetry")?;
    writeln!(
        writer,
        "  bpf seen/output-lost: {}/{}  transport received/lost: {}/{}  user dropped: {}  netlink loss events: {}  interrupted dumps: {}  parse errors: {}  sampling: {}",
        bounded_total(&report.telemetry.totals.bpf_events_seen),
        bounded_total(&report.telemetry.totals.bpf_output_lost),
        bounded_total(&report.telemetry.totals.transport_events_received),
        bounded_total(&report.telemetry.totals.transport_events_lost),
        bounded_total(&report.telemetry.totals.user_events_dropped),
        bounded_total(&report.telemetry.totals.netlink_loss_events),
        bounded_total(&report.telemetry.totals.netlink_dump_interruptions),
        bounded_total(&report.telemetry.totals.parse_errors),
        sampling(&report.telemetry.sampling),
    )?;
    for provider in &report.telemetry.providers {
        writeln!(writer, "  provider {}", provider.provider.as_str())?;
        writeln!(
            writer,
            "    bpf seen/output-lost: {}/{}  transport received/lost: {}/{}  user dropped: {}",
            counter_status(&provider.counters.bpf_events_seen),
            counter_status(&provider.counters.bpf_output_lost),
            counter_status(&provider.counters.transport_events_received),
            counter_status(&provider.counters.transport_events_lost),
            counter_status(&provider.counters.user_events_dropped),
        )?;
        writeln!(
            writer,
            "    netlink loss/dumps: {}/{}  parse errors: {}  sampling: {}",
            counter_status(&provider.counters.netlink_loss_events),
            counter_status(&provider.counters.netlink_dump_interruptions),
            counter_status(&provider.counters.parse_errors),
            sampling(&provider.sampling),
        )?;
    }
    for error in &report.telemetry.collection_errors {
        writeln!(writer, "  collector {}: {}", error.provider, error.message)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum StageDirection {
    Rx,
    Tx,
    Unresolved,
}

impl StageDirection {
    const ALL: [Self; 3] = [Self::Rx, Self::Tx, Self::Unresolved];

    const fn evidence_title(self) -> &'static str {
        match self {
            Self::Rx => "RX evidence by layer",
            Self::Tx => "TX evidence by layer",
            Self::Unresolved => "Unresolved-direction evidence by layer",
        }
    }

    const fn path_title(self) -> &'static str {
        match self {
            Self::Rx => "RX path evidence",
            Self::Tx => "TX path evidence",
            Self::Unresolved => "Unresolved-direction path evidence",
        }
    }
}

struct StageRow {
    direction: StageDirection,
    layer: Option<Layer>,
    stage: String,
    evidence: String,
    value: String,
    unit: MeasurementUnit,
    form: EvidenceForm,
    role: EvidenceRole,
    path_role: Option<PathRole>,
    execution_domain: String,
    transition: String,
    endpoints: String,
    graph_sort_key: Vec<(u64, SubjectRole, String)>,
}

impl StageRow {
    fn has_graph_metadata(&self) -> bool {
        self.transition != "-"
    }
}

fn write_report_stages(mut writer: impl Write, report: &Report) -> anyhow::Result<()> {
    let subjects: BTreeMap<_, _> = report
        .subjects
        .iter()
        .map(|subject| (subject.id.as_str(), subject))
        .collect();
    let mut rows = Vec::new();
    for metric in &report.metrics {
        let value = match metric.values.delta {
            Some(0) => continue,
            Some(delta) => measurement_value(delta, metric.meta.descriptor.measurement.bound),
            None if metric.values.reset => "reset".to_owned(),
            None => "unknown".to_owned(),
        };
        rows.push(stage_row(
            &subjects,
            &metric.meta,
            format!(
                "{}{}",
                metric.metric_type.as_str(),
                evidence_context(&metric.meta.descriptor.context)
            ),
            value,
        ));
    }

    let mut observations = BTreeMap::new();
    for observation in &report.observations {
        let reason = observation
            .attributes
            .get(ATTR_SKB_REASON_NAME)
            .and_then(crate::model::AttributeValue::as_str)
            .map(str::to_owned)
            .or_else(|| {
                observation
                    .attributes
                    .get(ATTR_SKB_REASON_CODE)
                    .and_then(crate::model::AttributeValue::as_u64)
                    .map(|reason| format!("raw:{reason}"))
            });
        let evidence = format!(
            "{}{}{}",
            observation.event_type.as_str(),
            reason.map_or_else(String::new, |reason| format!(" reason={reason}")),
            evidence_context(&observation.meta.descriptor.context)
        );
        let key = (
            observation.meta.provider.clone(),
            observation.meta.layer,
            observation.meta.execution_domain.clone(),
            observation.meta.transition.clone(),
            observation.meta.descriptor.clone(),
            observation
                .meta
                .subjects
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            evidence,
        );
        let (count, _) = observations
            .entry(key)
            .or_insert((0_u64, &observation.meta));
        *count = count.saturating_add(1);
    }
    for (
        (_provider, _layer, _execution_domain, _transition, _descriptor, _subject_refs, evidence),
        (count, meta),
    ) in observations
    {
        rows.push(stage_row(
            &subjects,
            meta,
            evidence,
            if count == 1 {
                "1 event".to_owned()
            } else {
                format!("{count} events")
            },
        ));
    }

    rows.sort_by(|left, right| {
        left.direction.cmp(&right.direction).then_with(|| {
            if left.has_graph_metadata() != right.has_graph_metadata() {
                return left.has_graph_metadata().cmp(&right.has_graph_metadata());
            }
            if left.has_graph_metadata() {
                left.path_role
                    .is_none()
                    .cmp(&right.path_role.is_none())
                    .then_with(|| left.path_role.cmp(&right.path_role))
                    .then_with(|| {
                        left.graph_sort_key
                            .is_empty()
                            .cmp(&right.graph_sort_key.is_empty())
                    })
                    .then_with(|| left.graph_sort_key.cmp(&right.graph_sort_key))
                    .then_with(|| left.transition.cmp(&right.transition))
                    .then_with(|| left.execution_domain.cmp(&right.execution_domain))
                    .then_with(|| left.stage.cmp(&right.stage))
                    .then_with(|| left.evidence.cmp(&right.evidence))
            } else {
                layer_name(left.layer)
                    .cmp(layer_name(right.layer))
                    .then_with(|| left.stage.cmp(&right.stage))
                    .then_with(|| left.execution_domain.cmp(&right.execution_domain))
                    .then_with(|| left.evidence.cmp(&right.evidence))
            }
        })
    });

    for direction in StageDirection::ALL {
        writeln!(writer, "\n{}", direction.evidence_title())?;
        let layer_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.direction == direction && !row.has_graph_metadata())
            .collect();
        if layer_rows.is_empty() {
            writeln!(writer, "  No stored layer-scoped evidence in this window.")?;
        } else {
            write_layer_rows(&mut writer, &layer_rows)?;
        }

        let graph_rows: Vec<_> = rows
            .iter()
            .filter(|row| row.direction == direction && row.has_graph_metadata())
            .collect();
        if !graph_rows.is_empty() {
            writeln!(writer, "\n{}", direction.path_title())?;
            write_graph_rows(&mut writer, &graph_rows)?;
        }
    }
    Ok(())
}

fn stage_row(
    subjects: &BTreeMap<&str, &crate::model::Subject>,
    meta: &EvidenceMeta,
    evidence: String,
    value: String,
) -> StageRow {
    let mut endpoints = Vec::new();
    for subject_ref in &meta.subjects {
        let Some(subject) = subjects.get(subject_ref.id.as_str()) else {
            continue;
        };
        let (sort_ordinal, label) = match subject.kind {
            SubjectKind::Hop => {
                let Some(ordinal) = subject
                    .attributes
                    .get(ATTR_HOP_ORDINAL)
                    .and_then(crate::model::AttributeValue::as_u64)
                else {
                    continue;
                };
                (ordinal, format!("hop#{ordinal}"))
            }
            SubjectKind::FlowDomain
                if matches!(subject_ref.role, SubjectRole::Before | SubjectRole::After) =>
            {
                (u64::MAX, "flow".to_owned())
            }
            _ => continue,
        };
        endpoints.push((
            sort_ordinal,
            subject_ref.role,
            subject.id.as_str().to_owned(),
            label,
        ));
    }
    endpoints.sort();
    let endpoints_display = if endpoints.is_empty() {
        "-".to_owned()
    } else {
        endpoints
            .iter()
            .map(|(_, role, id, label)| format!("{}:{label}@{id}", subject_role(*role)))
            .collect::<Vec<_>>()
            .join(",")
    };
    let graph_sort_key = endpoints
        .into_iter()
        .map(|(ordinal, role, id, _)| (ordinal, role, id))
        .collect();
    StageRow {
        direction: stage_direction(meta.descriptor.direction),
        layer: meta.layer,
        stage: meta.descriptor.stage.as_ref().map_or_else(
            || "unclassified".to_owned(),
            |stage| stage.as_str().to_owned(),
        ),
        evidence,
        value,
        unit: meta.descriptor.measurement.unit,
        form: meta.descriptor.form,
        role: meta.descriptor.role,
        path_role: meta.descriptor.path_role,
        execution_domain: meta
            .execution_domain
            .as_ref()
            .map_or("-", |domain| domain.as_str())
            .to_owned(),
        transition: meta
            .transition
            .as_ref()
            .map_or("-", |transition| transition.as_str())
            .to_owned(),
        endpoints: endpoints_display,
        graph_sort_key,
    }
}

fn write_layer_rows(mut writer: impl Write, rows: &[&StageRow]) -> anyhow::Result<()> {
    writeln!(
        writer,
        "  {:16} {:28} {:16} {:20} {:42} {:10} {:14} {:14} ROLE",
        "LAYER", "STAGE", "PATH ROLE", "DOMAIN", "EVIDENCE", "VALUE", "UNIT", "FORM"
    )?;
    for row in rows {
        writeln!(
            writer,
            "  {:16} {:28} {:16} {:20} {:42} {:10} {:14} {:14} {}",
            layer_name(row.layer),
            row.stage,
            row.path_role.map_or("-", PathRole::as_str),
            row.execution_domain,
            row.evidence,
            row.value,
            row.unit.as_str(),
            row.form.as_str(),
            evidence_role(row.role),
        )?;
    }
    Ok(())
}

fn write_graph_rows(mut writer: impl Write, rows: &[&StageRow]) -> anyhow::Result<()> {
    writeln!(
        writer,
        "  {:16} {:32} {:20} {:28} {:28} {:16} {:38} {:10} {:14} {:14} ROLE",
        "PATH ROLE",
        "ENDPOINTS",
        "DOMAIN",
        "TRANSITION",
        "STAGE",
        "LAYER",
        "EVIDENCE",
        "VALUE",
        "UNIT",
        "FORM"
    )?;
    for row in rows {
        writeln!(
            writer,
            "  {:16} {:32} {:20} {:28} {:28} {:16} {:38} {:10} {:14} {:14} {}",
            row.path_role.map_or("-", PathRole::as_str),
            row.endpoints,
            row.execution_domain,
            row.transition,
            row.stage,
            layer_name(row.layer),
            row.evidence,
            row.value,
            row.unit.as_str(),
            row.form.as_str(),
            evidence_role(row.role),
        )?;
    }
    Ok(())
}

fn stage_direction(direction: Option<Direction>) -> StageDirection {
    match direction {
        Some(Direction::Ingress) => StageDirection::Rx,
        Some(Direction::Egress) => StageDirection::Tx,
        None => StageDirection::Unresolved,
    }
}

fn layer_name(layer: Option<Layer>) -> &'static str {
    layer.map_or("unclassified", Layer::as_str)
}

fn evidence_context(context: &crate::model::EvidenceContext) -> String {
    let mut values = Vec::new();
    if let Some(ifindex) = context.ingress_ifindex {
        values.push(format!("ifindex={}", ifindex.get()));
    }
    if let Some(ifindex) = context.egress_ifindex {
        values.push(format!("ifindex={}", ifindex.get()));
    }
    if let Some(queue) = context.queue_id {
        values.push(format!("queue={queue}"));
    }
    if let Some(cpu) = context.cpu {
        values.push(format!("cpu={cpu}"));
    }
    if let Some(protocol) = context.protocol {
        values.push(format!("protocol={protocol}"));
    }
    if values.is_empty() {
        String::new()
    } else {
        format!(" [{}]", values.join(","))
    }
}

fn table_direction(direction: Option<Direction>) -> &'static str {
    match direction {
        Some(Direction::Ingress) => "RX",
        Some(Direction::Egress) => "TX",
        None => "--",
    }
}

fn evidence_role(role: EvidenceRole) -> &'static str {
    match role {
        EvidenceRole::Causal => "causal",
        EvidenceRole::Symptom => "symptom",
        EvidenceRole::Context => "context",
        EvidenceRole::Telemetry => "telemetry",
    }
}

fn subject_role(role: SubjectRole) -> &'static str {
    match role {
        SubjectRole::Primary => "primary",
        SubjectRole::Ingress => "ingress",
        SubjectRole::Egress => "egress",
        SubjectRole::Owner => "owner",
        SubjectRole::Peer => "peer",
        SubjectRole::Before => "before",
        SubjectRole::After => "after",
    }
}

fn trace_outcome(record: &TraceRecord) -> &'static str {
    if let Some(disposition) = record.descriptor.outcome.disposition {
        return match disposition {
            Disposition::Dropped => "dropped",
            Disposition::Rejected => "rejected",
            Disposition::Consumed => "consumed",
            Disposition::Passed => "passed",
            Disposition::Redirected => "redirected",
            Disposition::Queued => "queued",
        };
    }
    match record.descriptor.outcome.signal {
        Some(Signal::Aborted) => "aborted",
        Some(Signal::RedirectFailed) => "redirect_failed",
        Some(Signal::Backpressure) => "backpressure",
        Some(Signal::Congestion) => "congestion",
        Some(Signal::Pressure) => "pressure",
        Some(Signal::Timeout) => "timeout",
        Some(Signal::Retransmission) => "retransmission",
        Some(Signal::Reset) => "reset",
        Some(Signal::Error) => "error",
        None => "unknown",
    }
}

fn trace_reason(record: &TraceRecord) -> String {
    record
        .attributes
        .get(ATTR_SKB_REASON_NAME)
        .and_then(crate::model::AttributeValue::as_str)
        .map(str::to_owned)
        .or_else(|| {
            record
                .attributes
                .get(ATTR_SKB_REASON_CODE)
                .and_then(crate::model::AttributeValue::as_u64)
                .map(|reason| format!("raw:{reason}"))
        })
        .unwrap_or_else(|| "-".to_owned())
}

fn requested_interface(scope: &RequestedScope) -> String {
    scope.interface_path.as_ref().map_or_else(
        || "all visible".to_owned(),
        |path| {
            let anchor = match &path.anchor {
                InterfaceAnchor::Name { name } => format!("name:{name}"),
                InterfaceAnchor::Ifindex { ifindex } => format!("ifindex:{}", ifindex.get()),
            };
            format!(
                "{} closure=[{}] gaps=[{}]",
                anchor,
                path.visible_ifindices
                    .iter()
                    .map(|ifindex| ifindex.get().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                path.topology_gaps
                    .iter()
                    .map(|gap| gap.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        },
    )
}

fn requested_flow(scope: &RequestedScope) -> String {
    flow_filter(&scope.flow)
}

fn flow_filter(flow: &FlowFilter) -> String {
    format!(
        "protocol={} src={}:{} dst={}:{}",
        flow.protocol
            .map_or_else(|| "any".to_owned(), |protocol| protocol.get().to_string()),
        flow.source_address
            .map_or_else(|| "any".to_owned(), |address| address.to_string()),
        flow.source_port
            .map_or_else(|| "any".to_owned(), |port| port.to_string()),
        flow.destination_address
            .map_or_else(|| "any".to_owned(), |address| address.to_string()),
        flow.destination_port
            .map_or_else(|| "any".to_owned(), |port| port.to_string())
    )
}

fn effective_namespace(scope: &EffectiveNetworkNamespace) -> String {
    match scope {
        EffectiveNetworkNamespace::Current { identity } => identity.as_deref().map_or_else(
            || "current".to_owned(),
            |identity| format!("current:{identity}"),
        ),
        EffectiveNetworkNamespace::HostWide => "host_wide".to_owned(),
        EffectiveNetworkNamespace::Unknown => "unknown".to_owned(),
    }
}

fn effective_interface(scope: &EffectiveInterfaceScope) -> String {
    match scope {
        EffectiveInterfaceScope::AllVisible => "all_visible".to_owned(),
        EffectiveInterfaceScope::Path { path } => format!(
            "path:[{}]",
            path.visible_ifindices
                .iter()
                .map(|ifindex| ifindex.get().to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        EffectiveInterfaceScope::Unknown => "unknown".to_owned(),
    }
}

fn filter_support(support: &ProviderFilterSupport) -> String {
    format!(
        "layers={} namespace={} interface={} direction={} protocol={} src_addr={} dst_addr={} src_port={} dst_port={}",
        support.layers.as_str(),
        support.network_namespace.as_str(),
        support.interface_path.as_str(),
        support.direction.as_str(),
        support.protocol.as_str(),
        support.source_address.as_str(),
        support.destination_address.as_str(),
        support.source_port.as_str(),
        support.destination_port.as_str(),
    )
}

fn counter_status(status: &CounterStatus) -> String {
    match status {
        CounterStatus::Measured { value } => value.to_string(),
        CounterStatus::NotApplicable => "n/a".to_owned(),
        CounterStatus::Unknown => "unknown".to_owned(),
    }
}

fn bounded_total(total: &BoundedTotal) -> String {
    match total.bound {
        TotalBound::Exact => format!("{} (exact)", total.value),
        TotalBound::LowerBound => format!(">={} (lower_bound)", total.value),
    }
}

fn measurement_value(value: u64, bound: Option<MeasurementBound>) -> String {
    match bound {
        Some(MeasurementBound::Exact) => format!("+{value} (exact)"),
        Some(MeasurementBound::LowerBound) => format!(">={value} (lower_bound)"),
        Some(MeasurementBound::Estimate) => format!("~{value} (estimate)"),
        None => format!("+{value}"),
    }
}

fn sampling(value: &SamplingTelemetry) -> String {
    match value {
        SamplingTelemetry::None => "none".to_owned(),
        SamplingTelemetry::Sampled {
            method,
            scope,
            effective_numerator,
            effective_denominator,
        } => format!(
            "sampled {effective_numerator}/{effective_denominator} via {} over {}",
            method.as_str(),
            scope.as_str()
        ),
        SamplingTelemetry::Mixed { components } => format!(
            "mixed [{}]",
            components
                .iter()
                .map(sampling_component)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn sampling_component(component: &SamplingComponent) -> String {
    match component {
        SamplingComponent::None { scope } => format!("none over {}", scope.as_str()),
        SamplingComponent::Sampled {
            method,
            scope,
            effective_numerator,
            effective_denominator,
        } => format!(
            "{effective_numerator}/{effective_denominator} via {} over {}",
            method.as_str(),
            scope.as_str()
        ),
    }
}

fn write_coverage(mut writer: impl Write, report: &CapabilityReport) -> anyhow::Result<()> {
    writeln!(writer, "\nCoverage")?;
    for coverage in &report.coverage {
        let sources = if coverage.sources.is_empty() {
            "-".to_owned()
        } else {
            coverage.sources.join(",")
        };
        let forms = if coverage.forms.is_empty() {
            "-".to_owned()
        } else {
            coverage
                .forms
                .iter()
                .map(|form| form.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        writeln!(
            writer,
            "  {:16} {:11} {:11} {:14} {:13} {:18} {}",
            coverage.layer.as_str(),
            coverage.availability.as_str(),
            coverage.visibility.as_str(),
            coverage.filter_support.as_str(),
            coverage.integrity.as_str(),
            forms,
            sources
        )?;
        for limitation in &coverage.limitations {
            writeln!(writer, "  {:16}             note: {}", "", limitation)?;
        }
    }
    writeln!(writer, "\nProvider-stage coverage")?;
    if report.stage_coverage.is_empty() {
        writeln!(writer, "  No provider-stage coverage declared.")?;
        return Ok(());
    }
    writeln!(
        writer,
        "  {:32} {:28} {:16} {:20} {:11} {:11} {:18} {:14} INTEGRITY",
        "PROVIDER", "STAGE", "LAYER", "DOMAIN", "STATE", "VISIBILITY", "FORMS", "FILTER"
    )?;
    for coverage in &report.stage_coverage {
        let forms = coverage
            .forms
            .iter()
            .map(|form| form.as_str())
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            writer,
            "  {:32} {:28} {:16} {:20} {:11} {:11} {:18} {:14} {}",
            coverage.provider.as_str(),
            coverage.stage.as_str(),
            coverage.layer.as_str(),
            coverage
                .execution_domain
                .as_ref()
                .map_or("-", |domain| domain.as_str()),
            coverage.availability.as_str(),
            coverage.visibility.as_str(),
            if forms.is_empty() { "-" } else { &forms },
            coverage.filter_support.as_str(),
            coverage.integrity.as_str(),
        )?;
        for limitation in &coverage.limitations {
            writeln!(writer, "  {:32} note: {}", "", limitation)?;
        }
    }
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
