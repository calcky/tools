use ratatui::style::Color;

use super::*;

fn inner_width(width: u16) -> usize {
    if width >= 5 {
        usize::from(width) - 4
    } else {
        usize::from(width).max(1)
    }
}

fn wrapped(value: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    crate::tui::socket::wrap_text(value, width)
        .into_iter()
        .map(|text| {
            if crate::tui::socket::text_width(&text) > width {
                Line::styled("?", style)
            } else {
                Line::styled(text, style)
            }
        })
        .collect()
}

pub(super) fn identity_lines(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    width: u16,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let inner = inner_width(width);
    let body = table_lines(
        &["NETDEV", "IFINDEX", "TYPE", "DRIVER"],
        &[TableRow::new(
            vec![
                identity.name().to_owned(),
                identity.ifindex().get().to_string(),
                interface_kind(snapshot, identity).label().to_owned(),
                interface_setting_display_value(snapshot, identity, "Driver")
                    .unwrap_or_else(|| "-".to_owned()),
            ],
            Style::default().fg(theme::TEXT_STRONG),
        )],
        &[30, 12, 14, 44],
        inner,
        &[],
    );
    detail_block::framed_lines("INTERFACE", theme::NETWORK, body, usize::from(width))
}

pub(super) fn unavailable_lines(identity: &InterfaceIdentity, width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let mut body = wrapped(
        &format!(
            "INTERFACE {}  ifindex {}  NO LONGER OBSERVED",
            identity.name(),
            identity.ifindex().get()
        ),
        inner_width(width),
        Style::default().fg(theme::WARN),
    );
    body.extend(wrapped(
        "The displayed snapshot no longer reports this interface as present.",
        inner_width(width),
        Style::default().fg(theme::MUTED),
    ));
    detail_block::framed_lines("INTERFACE", theme::WARN, body, usize::from(width))
}

pub(super) fn stage_lines(
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
    kind: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
    selected: bool,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let inner = inner_width(width);
    let assessment = assess_dashboard_block(snapshot, block);
    let mut body = stage_metric_tables(block, kind, display, inner);
    if body.is_empty() {
        body = wrapped(
            "No metrics with data",
            inner,
            Style::default().fg(theme::MUTED),
        );
    }
    if kind == BlockKind::ExecutionContext(ExecutionContext::Hardirq) {
        body.extend(coalescing_table(
            snapshot,
            block,
            display.metrics_mode,
            inner,
        ));
    }
    body.extend(wrapped(
        &format!(
            "Health: {} | Coverage: {}",
            assessment.health().as_str(),
            assessment.coverage().as_str()
        ),
        inner,
        network_health_style(assessment.health()),
    ));
    if let Some(cause) = assessment.causes().first() {
        let metric = cause.metric().descriptor();
        let title = metric.map_or_else(
            || fallback_health_metric_title(cause.metric().as_str()),
            |metric| metric.title.to_owned(),
        );
        let observed = format_health_value(cause.observed(), metric);
        body.extend(wrapped(
            &format!("NOTE: {title} | {observed}"),
            inner,
            network_health_style(cause.condition()),
        ));
    }
    let color = match kind {
        BlockKind::PacketStage(PacketStage::TrafficControl) => theme::QDISC,
        BlockKind::PacketStage(PacketStage::DriverNapi) => theme::TX,
        BlockKind::PacketStage(PacketStage::NicPhy) => theme::GOOD,
        BlockKind::ExecutionContext(ExecutionContext::Hardirq) => theme::WARN,
        _ => theme::NETWORK,
    };
    let title = if kind == BlockKind::PacketStage(PacketStage::TrafficControl) {
        "QDISC"
    } else {
        interface_stage_title(kind)
    };
    let mut lines = detail_block::framed_lines(title, color, body, usize::from(width));
    if selected {
        if let Some(title) = lines.first_mut() {
            title.style = title.style.bg(theme::SELECTED_BG);
            for span in &mut title.spans {
                span.style = span.style.bg(theme::SELECTED_BG);
            }
        }
    }
    lines
}

struct TableRow {
    cells: Vec<String>,
    style: Style,
}

impl TableRow {
    fn new(cells: Vec<String>, style: Style) -> Self {
        Self { cells, style }
    }
}

fn table_lines(
    headers: &[&str],
    rows: &[TableRow],
    weights: &[usize],
    width: usize,
    numeric: &[usize],
) -> Vec<Line<'static>> {
    let heading = Style::default()
        .fg(theme::TEXT_STRONG)
        .bg(theme::CHROME_BG)
        .add_modifier(Modifier::BOLD);
    let minimums: Vec<_> = headers
        .iter()
        .map(|header| match *header {
            "METRIC" => 10,
            "RATE" | "AVG RATE" => 9,
            _ => header.len(),
        })
        .collect();
    let minimum: usize = minimums.iter().sum();
    if width < minimum + 3 * (headers.len() - 1) {
        return rows
            .iter()
            .flat_map(|row| {
                headers.iter().zip(&row.cells).flat_map(|(header, value)| {
                    wrapped(&format!("{header}: {value}"), width, row.style)
                })
            })
            .collect();
    }
    let available = width.saturating_sub(3 * (headers.len() - 1));
    let mut widths: Vec<_> = weights
        .iter()
        .zip(minimums)
        .map(|(weight, min_width)| min_width + (available - minimum) * weight / 100)
        .collect();
    let used: usize = widths.iter().sum();
    *widths.last_mut().unwrap() += available.saturating_sub(used);
    let render = |values: &[String], style: Style, is_header: bool| {
        let cells: Vec<_> = values
            .iter()
            .zip(&widths)
            .map(|(value, width)| crate::tui::socket::wrap_text(value, *width))
            .collect();
        (0..cells.iter().map(Vec::len).max().unwrap_or(1))
            .map(|row| {
                let mut spans = Vec::new();
                for (column, cell) in cells.iter().enumerate() {
                    if column > 0 {
                        spans.push(Span::styled(" │ ", Style::default().fg(theme::DIVIDER)));
                    }
                    let value = cell.get(row).map_or("", String::as_str);
                    let value = if crate::tui::socket::text_width(value) > widths[column] {
                        "?"
                    } else {
                        value
                    };
                    let padding = " ".repeat(
                        widths[column].saturating_sub(crate::tui::socket::text_width(value)),
                    );
                    let value = if numeric.contains(&column) {
                        format!("{padding}{value}")
                    } else {
                        format!("{value}{padding}")
                    };
                    let cell_style = match (is_header, values[column].as_str()) {
                        (false, "stale") => Style::default().fg(theme::WARN),
                        (false, "n/a" | "-") => Style::default().fg(theme::MUTED),
                        _ => style,
                    };
                    spans.push(Span::styled(value, cell_style));
                }
                Line::from(spans)
            })
            .collect::<Vec<_>>()
    };
    let mut lines = render(
        &headers.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>(),
        heading,
        true,
    );
    lines.push(Line::styled(
        widths
            .iter()
            .map(|size| "─".repeat(*size))
            .collect::<Vec<_>>()
            .join("─┼─"),
        Style::default().fg(theme::DIVIDER),
    ));
    for row in rows {
        lines.extend(render(&row.cells, row.style, false));
    }
    lines
}

struct MetricValues {
    current: String,
    change: String,
    rate: String,
    state: &'static str,
}

fn metric_values(
    slot: InterfaceMetricSlot,
    group: &[&SeriesSnapshot],
    time_view: TimeView,
) -> MetricValues {
    let metric = descriptor(slot.metric).expect("catalogued interface metric");
    let mut current = "-".to_owned();
    let mut change = "-".to_owned();
    let mut rate = "-".to_owned();
    let mut state = "unavailable";
    if !group.is_empty() {
        state = if group
            .iter()
            .any(|series| series_status(series) == "unavailable")
        {
            "unavailable"
        } else if group.iter().any(|series| series_status(series) == "stale") {
            "stale"
        } else {
            "fresh"
        };
        if state == "fresh" {
            match group[0].value() {
                SeriesValue::Counter { .. } | SeriesValue::Gauge { .. } => {
                    let total = group
                        .iter()
                        .fold(0_u64, |sum, series| match series.value() {
                            SeriesValue::Counter {
                                current: ProjectedValue::Fresh { value, .. },
                                ..
                            }
                            | SeriesValue::Gauge {
                                current: ProjectedValue::Fresh { value, .. },
                                ..
                            } => sum.saturating_add(*value),
                            _ => sum,
                        });
                    current = format_value(total, metric.unit);
                    if matches!(group[0].value(), SeriesValue::Counter { .. }) {
                        if let Some((delta, value, wrap)) =
                            aggregate_counter_values(group, time_view)
                        {
                            change = format!("+{}", format_value(delta, metric.unit));
                            rate = format_rate(Some(value), metric);
                            if wrap {
                                state = "wrap";
                            }
                        }
                    } else if time_view == TimeView::Interval {
                        let values =
                            group
                                .iter()
                                .try_fold((0_i128, 0.0), |(delta, rate), series| {
                                    match series.value() {
                                        SeriesValue::Gauge {
                                            interval: Some(value),
                                            ..
                                        } => Some((
                                            delta.saturating_add(value.delta()),
                                            rate + value.rate_per_second(),
                                        )),
                                        _ => None,
                                    }
                                });
                        if let Some((delta, value)) = values {
                            change = format_signed_value(delta, metric.unit);
                            rate = if metric.unit == MetricUnit::BasisPoints {
                                format!("{:.2} pp/s", value / 100.0)
                            } else {
                                format_rate(Some(value), metric)
                            };
                        }
                    } else {
                        change = aggregate_gauge_projection(group, metric, time_view)
                            .unwrap_or_else(|| "-".to_owned());
                    }
                }
                SeriesValue::State {
                    current: ProjectedValue::Fresh { value, .. },
                    ..
                } => {
                    current = value.as_str().to_owned();
                    if group
                        .iter()
                        .skip(1)
                        .any(|series| !matches!(series.value(), SeriesValue::State { current: ProjectedValue::Fresh { value, .. }, .. } if value.as_str() == current))
                    {
                        current = "mixed".to_owned();
                    }
                }
                SeriesValue::State { .. } => {}
            }
        }
    }
    MetricValues {
        current,
        change,
        rate,
        state,
    }
}

#[derive(Clone, Copy)]
enum MetricProjection {
    Current,
    Change,
    Rate,
}

type MetricColumn = (&'static str, &'static str, MetricProjection);

fn stage_metric_tables(
    block: &DashboardBlock<'_>,
    kind: BlockKind,
    display: DetailDisplayOptions,
    width: usize,
) -> Vec<Line<'static>> {
    use MetricProjection::{Change, Current, Rate};
    let range = display.time_view == TimeView::SinceBaseline;
    let (directional, shared): (&[MetricColumn], &[MetricColumn]) = match kind {
        BlockKind::PacketStage(PacketStage::NetdeviceCore) => (
            &[
                ("PACKETS", "packets", Current),
                ("TRAFFIC", "bytes", Current),
                ("PPS", "packets", Rate),
                ("BANDWIDTH", "bytes", Rate),
                ("DROPS", "drop", Current),
                ("DROP/S", "drop", Rate),
                ("ERRORS", "err", Current),
                ("ERROR/S", "err", Rate),
            ],
            &[],
        ),
        BlockKind::PacketStage(PacketStage::TrafficControl) => (
            &[
                ("PACKETS", "packets", Current),
                ("PPS", "packets", Rate),
                ("DROPS", "drop", Current),
                ("DROP/S", "drop", Rate),
                ("REQUEUES", "requeue", Current),
                ("REQUEUE/S", "requeue", Rate),
                ("OVERLIMITS", "over", Current),
                ("OVERLIMIT/S", "over", Rate),
                ("BACKLOG", "backlog", Current),
                (
                    if range {
                        "BACKLOG RANGE"
                    } else {
                        "BACKLOG CHANGE"
                    },
                    "backlog",
                    Change,
                ),
            ],
            &[],
        ),
        BlockKind::PacketStage(PacketStage::DriverNapi) => (
            &[
                ("MISSED", "missed", Current),
                ("MISSED/S", "missed", Rate),
                ("FIFO ERR", "fifo", Current),
                ("FIFO ERR/S", "fifo", Rate),
                ("ABORTED", "abort", Current),
                ("ABORTED/S", "abort", Rate),
            ],
            &[
                ("RING DROPS", "ring_drop", Current),
                ("RING DROP/S", "ring_drop", Rate),
            ],
        ),
        BlockKind::PacketStage(PacketStage::NicPhy) => (
            &[
                ("CRC ERR", "crc", Current),
                ("CRC ERR/S", "crc", Rate),
                ("PAUSE", "pause", Current),
                ("PAUSE/S", "pause", Rate),
                ("CARRIER ERR", "carrier_err", Current),
                ("CARRIER ERR/S", "carrier_err", Rate),
            ],
            &[
                ("LINK", "link", Current),
                ("CARRIER CHG", "carrier_chg", Current),
                ("CARRIER CHG/S", "carrier_chg", Rate),
                ("FEC CORRECTED", "fec_ok", Current),
                ("FEC UNCORR", "fec_bad", Current),
            ],
        ),
        BlockKind::ExecutionContext(ExecutionContext::Hardirq) => (
            &[],
            &[
                ("INTERRUPTS", "irq", Current),
                ("INTR/S", "irq", Rate),
                ("IMBALANCE", "imbalance", Current),
                (
                    if range {
                        "IMBALANCE RANGE"
                    } else {
                        "IMBALANCE CHANGE"
                    },
                    "imbalance",
                    Change,
                ),
                ("CPU AFFINITY", "affinity", Current),
            ],
        ),
        _ => (&[], &[]),
    };
    let slots = interface_stage_slots(kind);
    let mut lines = metric_matrix(
        block,
        "DIR",
        &[("RX", slots.rx), ("TX", slots.tx)],
        directional,
        display,
        width,
    );
    let name = match block.key().scope() {
        BlockScope::Interface(identity) => identity.name(),
        _ => "-",
    };
    lines.extend(metric_matrix(
        block,
        "NETDEV",
        &[(name, slots.key)],
        shared,
        display,
        width,
    ));
    lines
}

fn metric_matrix(
    block: &DashboardBlock<'_>,
    row_header: &str,
    lanes: &[(&str, &[InterfaceMetricSlot])],
    columns: &[MetricColumn],
    display: DetailDisplayOptions,
    width: usize,
) -> Vec<Line<'static>> {
    let values: Vec<_> = lanes
        .iter()
        .map(|(name, slots)| {
            let values: BTreeMap<_, _> = slots
                .iter()
                .map(|slot| {
                    let group = interface_metric_group(block, *slot);
                    (
                        slot.label,
                        (
                            metric_values(*slot, &group, display.time_view),
                            series_group_has_fresh_data(&group),
                        ),
                    )
                })
                .collect();
            (*name, values)
        })
        .collect();
    let columns: Vec<_> = columns
        .iter()
        .filter(|(_, label, _)| {
            display.metrics_mode == DetailMetricsMode::All
                || values
                    .iter()
                    .any(|(_, values)| values.get(label).is_some_and(|(_, visible)| *visible))
        })
        .collect();
    if columns.is_empty() {
        return Vec::new();
    }
    let mut headers = vec![row_header.to_owned()];
    headers.extend(columns.iter().map(|(header, _, projection)| {
        if matches!(projection, MetricProjection::Rate)
            && display.time_view == TimeView::SinceBaseline
        {
            format!("AVG {header}")
        } else {
            (*header).to_owned()
        }
    }));
    let rows: Vec<_> = values
        .iter()
        .filter(|(_, values)| {
            display.metrics_mode == DetailMetricsMode::All
                || values.values().any(|(_, visible)| *visible)
        })
        .map(|(name, values)| {
            let mut cells = vec![(*name).to_owned()];
            cells.extend(columns.iter().map(|(_, label, projection)| {
                let Some((value, _)) = values.get(label) else {
                    return "-".to_owned();
                };
                match value.state {
                    "unavailable" => "n/a".to_owned(),
                    "stale" => "stale".to_owned(),
                    _ => match projection {
                        MetricProjection::Current => value.current.clone(),
                        MetricProjection::Change => value.change.clone(),
                        MetricProjection::Rate if value.state == "wrap" => {
                            format!("{} wrap", value.rate)
                        }
                        MetricProjection::Rate => value.rate.clone(),
                    },
                }
            }));
            TableRow::new(
                cells,
                Style::default().fg(match *name {
                    "RX" => theme::RX,
                    "TX" => theme::TX,
                    _ => theme::TEXT,
                }),
            )
        })
        .collect();
    // Keep metric headings horizontal on narrow terminals by repeating the row key.
    let mut lines = Vec::new();
    let mut start = 1;
    while start < headers.len() {
        let key_width = if row_header == "DIR" { 3 } else { 12 };
        let mut used = key_width;
        let mut end = start;
        while end < headers.len() {
            let size = headers[end].len().max(12) + 3;
            if end > start && used + size > width {
                break;
            }
            used += size;
            end += 1;
        }
        let chunk_headers: Vec<_> = std::iter::once(headers[0].as_str())
            .chain(headers[start..end].iter().map(String::as_str))
            .collect();
        let chunk_rows: Vec<_> = rows
            .iter()
            .map(|row| {
                TableRow::new(
                    std::iter::once(row.cells[0].clone())
                        .chain(row.cells[start..end].iter().cloned())
                        .collect(),
                    row.style,
                )
            })
            .collect();
        let count = chunk_headers.len();
        let key_weight = if row_header == "DIR" { 0 } else { 10 };
        let mut weights = vec![(100 - key_weight) / (count - 1); count];
        weights[0] = key_weight;
        let numeric: Vec<_> = (1..count).collect();
        lines.extend(table_lines(
            &chunk_headers,
            &chunk_rows,
            &weights,
            width,
            &numeric,
        ));
        start = end;
    }
    lines
}

fn series_status(series: &SeriesSnapshot) -> &'static str {
    fn status<T>(value: &ProjectedValue<T>) -> &'static str {
        match value {
            ProjectedValue::Fresh { .. } => "fresh",
            ProjectedValue::Stale { .. } => "stale",
            ProjectedValue::Unavailable { .. } => "unavailable",
        }
    }
    match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            status(current)
        }
        SeriesValue::State { current, .. } => status(current),
    }
}

fn coalescing_table(
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
    mode: DetailMetricsMode,
    width: usize,
) -> Vec<Line<'static>> {
    let BlockScope::Interface(identity) = block.key().scope() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for lane in ["RX", "TX"] {
        let settings = [
            format!("Adaptive {lane}"),
            format!("{lane} Usecs"),
            format!("{lane} Frames"),
        ];
        let values: Vec<_> = settings
            .iter()
            .map(|setting| interface_setting_display_value(snapshot, identity, setting))
            .collect();
        if mode == DetailMetricsMode::WithData && values.iter().all(Option::is_none) {
            continue;
        }
        let mut cells = vec![lane.to_owned()];
        cells.extend(
            values
                .into_iter()
                .map(|value| value.unwrap_or_else(|| "-".to_owned())),
        );
        rows.push(TableRow::new(
            cells,
            Style::default().fg(if lane == "RX" { theme::RX } else { theme::TX }),
        ));
    }
    if rows.is_empty() {
        return Vec::new();
    }
    let mut lines = wrapped(
        "COALESCE",
        width,
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    );
    lines.extend(table_lines(
        &["DIR", "ADAPTIVE", "USECS", "FRAMES"],
        &rows,
        &[10, 30, 30, 30],
        width,
        &[2, 3],
    ));
    lines
}

const GROUPS: [(&str, Color); 7] = [
    ("LINK / DRIVER", theme::NETWORK),
    ("QUEUES / RINGS", theme::GOOD),
    ("OFFLOADS / COALESCE", theme::TX),
    ("RX STATISTICS", theme::RX),
    ("TX STATISTICS", theme::TX),
    ("ERRORS / DROPS", theme::WARN),
    ("STATUS / OTHER", theme::ACCENT),
];

fn group_index(lane: &str, series: &SeriesSnapshot) -> usize {
    let metric = series
        .metric()
        .descriptor()
        .expect("catalogued interface metric");
    let setting = series
        .labels()
        .get(MetricLabel::Statistic)
        .unwrap_or("")
        .to_ascii_lowercase();
    if series.metric().as_str() == crate::monitor::RAW_NIC_SETTING_METRIC_ID {
        if ["queue", "ring", "channel"]
            .iter()
            .any(|part| setting.contains(part))
        {
            return 1;
        }
        if [
            "offload",
            "coales",
            "adaptive",
            "usecs",
            "frames",
            "checksum",
            "segmentation",
            "scatter",
            "flow control",
        ]
        .iter()
        .any(|part| setting.contains(part))
            || matches!(
                setting.as_str(),
                "tso" | "lro" | "gro" | "gso" | "ufo" | "sg"
            )
        {
            return 2;
        }
        return 0;
    }
    if matches!(
        metric.display,
        crate::monitor::DisplayMeaning::Error | crate::monitor::DisplayMeaning::Drop
    ) || ["error", "drop", "discard", "missed", "crc"]
        .iter()
        .any(|part| setting.contains(part))
    {
        return 5;
    }
    if matches!(series.value(), SeriesValue::State { .. }) {
        return 6;
    }
    match lane {
        "RX" => 3,
        "TX" => 4,
        _ => 6,
    }
}

pub(super) fn series_lines(
    block: &DashboardBlock<'_>,
    display: DetailDisplayOptions,
    width: u16,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let columns = if width >= 120 { 2 } else { 1 };
    let column_width = (usize::from(width) - (columns - 1)) / columns;
    let inner = inner_width(column_width as u16);
    let mut groups: [Vec<Line<'static>>; GROUPS.len()] = std::array::from_fn(|_| Vec::new());
    let mut sources: [Vec<&str>; GROUPS.len()] = std::array::from_fn(|_| Vec::new());
    let mut label_widths = [0; GROUPS.len()];
    for (lane, placed) in [
        ("RX", block.rx()),
        ("TX", block.tx()),
        ("KEY", block.shared()),
    ] {
        for series in placed.iter().map(PlacedSeries::series).filter(|series| {
            display.metrics_mode == DetailMetricsMode::All || series_has_detail_data(series)
        }) {
            let group = group_index(lane, series);
            let group_sources = &mut sources[group];
            if !group_sources.contains(&series.source().as_str()) {
                group_sources.push(series.source().as_str());
            }
            if series.metric().as_str() == crate::monitor::RAW_NIC_SETTING_METRIC_ID {
                if let Some(setting) = series.labels().get(MetricLabel::Statistic) {
                    label_widths[group] = label_widths[group]
                        .max(crate::tui::socket::text_width(setting).min(inner / 2));
                }
            }
        }
    }
    let mut count = 0;
    for (lane, placed) in [
        ("RX", block.rx()),
        ("TX", block.tx()),
        ("KEY", block.shared()),
    ] {
        for series in placed.iter().map(PlacedSeries::series).filter(|series| {
            display.metrics_mode == DetailMetricsMode::All || series_has_detail_data(series)
        }) {
            count += 1;
            let group = group_index(lane, series);
            let body = &mut groups[group];
            let metric = series
                .metric()
                .descriptor()
                .expect("catalogued interface metric");
            let title = format_series_title(series, metric);
            let (current, interval, since, state) = format_series(series, metric);
            if series.metric().as_str() == crate::monitor::RAW_NIC_SETTING_METRIC_ID {
                let setting = series
                    .labels()
                    .get(MetricLabel::Statistic)
                    .unwrap_or(&title);
                let label_width = label_widths[group];
                let mut text = format!("{setting:<label_width$} | {current}");
                if state != "fresh" {
                    text.push_str(&format!(" | {state}"));
                }
                if display.time_view == TimeView::SinceBaseline && since != "-" {
                    text.push_str(&format!(
                        " | baseline({}) {since}",
                        baseline_origin_label(series.baseline_origin())
                    ));
                }
                if sources[group].len() > 1 {
                    let index = sources[group]
                        .iter()
                        .position(|source| *source == series.source().as_str())
                        .unwrap();
                    text.push_str(&format!(" [{}]", index + 1));
                }
                body.extend(wrapped(&text, inner, detail_series_style(series, metric)));
                continue;
            }
            let (projection, value) = match display.time_view {
                TimeView::Interval => ("interval".to_owned(), interval),
                TimeView::SinceBaseline => (
                    format!(
                        "baseline({})",
                        baseline_origin_label(series.baseline_origin())
                    ),
                    since,
                ),
            };
            body.extend(wrapped(
                &format!("{lane} {title}"),
                inner,
                detail_lane_style(lane),
            ));
            body.extend(wrapped(
                &format!("current {current} | {projection} {value}"),
                inner,
                detail_series_style(series, metric),
            ));
            body.extend(wrapped(
                &format!("{state} | source {}", series.source().as_str()),
                inner,
                detail_state_style(state),
            ));
        }
    }
    if count == 0 && display.metrics_mode == DetailMetricsMode::WithData {
        return Vec::new();
    }
    let title = match display.metrics_mode {
        DetailMetricsMode::WithData => format!(
            "STATISTICS WITH DATA  {count}/{} series",
            block.series_count()
        ),
        DetailMetricsMode::All => format!("ALL STATISTICS  {} series", block.series_count()),
    };
    let mut output = wrapped(
        &title,
        usize::from(width),
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    );
    if count == 0 {
        output.extend(detail_block::framed_lines(
            "STATISTICS",
            theme::MUTED,
            wrapped(
                "- no collected series",
                inner_width(width),
                Style::default().fg(theme::MUTED),
            ),
            usize::from(width),
        ));
        return output;
    }
    let mut stacks: Vec<(usize, Vec<Line<'static>>)> =
        (0..columns).map(|_| (column_width, Vec::new())).collect();
    // Fixed thematic columns avoid moving groups when a value wraps or a counter changes.
    const COLUMN: [usize; GROUPS.len()] = [0, 0, 1, 0, 1, 1, 1];
    for (index, ((title, color), mut body)) in GROUPS.into_iter().zip(groups).enumerate() {
        if body.is_empty() {
            continue;
        }
        if index < 3 {
            for (source_index, source) in sources[index].iter().enumerate() {
                let label = if sources[index].len() > 1 {
                    format!("source [{}] {source}", source_index + 1)
                } else {
                    format!("source {source}")
                };
                body.extend(wrapped(&label, inner, Style::default().fg(theme::MUTED)));
            }
        }
        stacks[if columns == 1 { 0 } else { COLUMN[index] }]
            .1
            .extend(detail_block::framed_lines(title, color, body, column_width));
    }
    output.extend(detail_block::side_by_side(stacks));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{MetricLabels, ProviderId, SeriesId, StateValue};
    use std::time::Duration;

    fn settings_snapshot() -> MonitorSnapshot {
        let settings = [
            (
                "Driver",
                "vendor-driver-with-a-long-device-name-0000:08:00.1",
                "fresh",
            ),
            (
                "Address",
                "2001:0db8:1234:5678:abcd:0123:4567:89ab/128",
                "fresh",
            ),
            ("RX Queues", "64 fixed", "stale"),
            ("Ring TX", "", "unavailable"),
            ("TSO", "off fixed", "fresh"),
        ];
        let series = settings
            .into_iter()
            .enumerate()
            .map(|(index, (setting, value, state))| {
                let metric = descriptor(crate::monitor::RAW_NIC_SETTING_METRIC_ID).unwrap();
                let current = match state {
                    "unavailable" => ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                    "stale" => ProjectedValue::Stale {
                        last: StateValue::new(value).unwrap(),
                        observed_at: Duration::from_secs(1),
                        age: Duration::from_secs(1),
                        cause: crate::monitor::MonitorErrorCode::Timeout,
                    },
                    _ => ProjectedValue::Fresh {
                        value: StateValue::new(value).unwrap(),
                        observed_at: Duration::from_secs(2),
                    },
                };
                SeriesSnapshot::new(
                    SeriesId::new(index as u64 + 1).unwrap(),
                    ProviderId::new(metric.owner).unwrap(),
                    ProviderId::new("linux.ethtool.link_text").unwrap(),
                    crate::monitor::MetricId::new(metric.id).unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, "eth0".to_owned()),
                        (MetricLabel::Ifindex, "2".to_owned()),
                        (MetricLabel::Statistic, setting.to_owned()),
                    ])
                    .unwrap(),
                    Duration::ZERO,
                    crate::monitor::BaselineOrigin::SessionStart,
                    Duration::ZERO,
                    SeriesValue::State {
                        current,
                        changed_at: None,
                        continuous_for: (state == "fresh").then_some(Duration::from_secs(2)),
                    },
                    crate::monitor::HistoryCoverage::empty(),
                )
                .unwrap()
            })
            .collect();
        MonitorSnapshot::new(
            1,
            1,
            0,
            Duration::from_secs(2),
            None,
            vec![crate::monitor::ProviderSnapshot::new(
                ProviderId::new("linux.ethtool.link_text").unwrap(),
                crate::monitor::ProviderHealth::Fresh,
                Duration::from_secs(2),
                Duration::ZERO,
                0,
            )
            .unwrap()],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap()
    }

    fn plain(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn traffic_cells_keep_units_and_do_not_fabricate_rates_after_reset() {
        let metric = descriptor("linux.netdevice.rx_bytes").unwrap();
        let series = |interval, current| {
            SeriesSnapshot::new(
                SeriesId::new(1).unwrap(),
                ProviderId::new(metric.owner).unwrap(),
                ProviderId::new("linux.proc.net.dev").unwrap(),
                crate::monitor::MetricId::new(metric.id).unwrap(),
                MetricLabels::new([
                    (MetricLabel::Interface, "eth0".to_owned()),
                    (MetricLabel::Ifindex, "2".to_owned()),
                ])
                .unwrap(),
                Duration::ZERO,
                crate::monitor::BaselineOrigin::SessionStart,
                Duration::ZERO,
                SeriesValue::Counter {
                    current,
                    interval: Some(interval),
                    since_baseline: None,
                },
                crate::monitor::HistoryCoverage::empty(),
            )
            .unwrap()
        };
        let slot = *NETDEVICE_RX_SLOTS
            .iter()
            .find(|slot| slot.metric == metric.id)
            .unwrap();
        let fresh = || ProjectedValue::Fresh {
            value: 2048,
            observed_at: Duration::from_secs(2),
        };
        let continuous = series(
            CounterContinuity::Continuous {
                delta: 512,
                elapsed: Duration::from_secs(2),
            },
            fresh(),
        );
        let row = metric_values(slot, &[&continuous], TimeView::Interval);
        assert_eq!(
            [row.current, row.change, row.rate, row.state.to_owned()],
            ["2.0 KiB", "+512 B", "2.0 kbit/s", "fresh"]
        );
        let reset = series(CounterContinuity::Reset, fresh());
        let row = metric_values(slot, &[&reset], TimeView::Interval);
        assert_eq!([row.current, row.change, row.rate], ["2.0 KiB", "-", "-"]);
        let missing = series(
            CounterContinuity::FirstSample,
            ProjectedValue::Unavailable {
                reason: UnavailableReason::Missing,
            },
        );
        let row = metric_values(slot, &[&continuous, &missing], TimeView::Interval);
        assert_eq!(
            [row.current, row.change, row.rate, row.state.to_owned()],
            ["-", "-", "-", "unavailable"]
        );
    }

    #[test]
    fn netdevice_metrics_are_columns_with_rx_tx_rows_and_repeated_keys_on_narrow_screens() {
        let snapshot = crate::tui::view::tests::full_dashboard_snapshot();
        let dashboard = build_dashboard(&snapshot);
        let identity = ordered_interface_identities(&snapshot, None, None).remove(0);
        let kind = BlockKind::PacketStage(PacketStage::NetdeviceCore);
        let block = interface_block(&dashboard, &identity, kind).unwrap();
        for width in [60, 80, 160] {
            let lines = stage_metric_tables(
                block,
                kind,
                DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
                width,
            );
            let text = plain(&lines);
            for header in ["PACKETS", "TRAFFIC", "PPS", "BANDWIDTH", "DROPS", "ERRORS"] {
                assert!(text.contains(header), "{width}: {text}");
            }
            assert!(!text.contains("METRIC"), "{text}");
            assert!(!text.contains("CURRENT"), "{text}");
            assert!(lines.iter().all(|line| line.width() <= width));
            let count = |lane: &str| {
                lines
                    .iter()
                    .filter(|line| line.to_string().split('│').next().unwrap().trim() == lane)
                    .count()
            };
            assert_eq!(count("RX"), count("TX"));
            if width == 160 {
                assert_eq!(count("RX"), 1);
            } else {
                assert!(count("RX") > 1);
            }
        }
    }

    #[test]
    fn interface_identity_has_headers_without_path_or_link_banner() {
        let snapshot = settings_snapshot();
        let identity = ordered_interface_identities(&snapshot, None, None).remove(0);
        for width in [60, 80, 120, 160] {
            let lines = identity_lines(&snapshot, &identity, width);
            let text = plain(&lines);
            for header in ["NETDEV", "IFINDEX", "TYPE", "DRIVER"] {
                assert!(text.contains(header), "{width}: {text}");
            }
            for removed in ["LINK ", "NIC/PHY ->", "TX STACK", "UNKNOWN", "partial"] {
                assert!(!text.contains(removed), "{width}: {text}");
            }
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
        }
    }

    #[test]
    fn compact_settings_preserve_values_status_sources_and_baselines() {
        let snapshot = settings_snapshot();
        let dashboard = build_dashboard(&snapshot);
        let block = dashboard
            .blocks()
            .iter()
            .find(|block| block.series_count() == 5)
            .unwrap();
        for width in [60, 80, 120, 160] {
            let rows = series_lines(
                block,
                DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
                width,
            );
            assert!(
                rows.iter().all(|line| line.width() <= usize::from(width)),
                "{width}: {}",
                plain(&rows)
            );
            let text = plain(&rows);
            assert!(text.contains("RX Queues | 64 fixed | stale"), "{text}");
            assert!(text.contains("Ring TX   | - | unavailable"), "{text}");
            assert!(text.contains("TSO | off fixed"), "{text}");
            assert!(!text.contains("interval -"), "{text}");
            assert!(!text.contains("Driver  eth0"), "{text}");
            assert_eq!(text.matches("source linux.ethtool.link_text").count(), 3);
            let separator = |label: &str| {
                rows.iter()
                    .map(ToString::to_string)
                    .find(|row| row.contains(label))
                    .unwrap()
                    .find('|')
                    .unwrap()
            };
            assert_eq!(separator("Driver "), separator("Address "));
            assert_eq!(separator("RX Queues "), separator("Ring TX "));
            // Read only the fixed left column, then join wrapped payload without frame padding.
            let left_width = if width >= 120 {
                (usize::from(width) - 1) / 2
            } else {
                usize::from(width)
            };
            let payload: String = rows
                .iter()
                .map(|line| {
                    line.to_string()
                        .chars()
                        .take(left_width)
                        .collect::<String>()
                })
                .filter(|line| line.starts_with('│'))
                .map(|line| line.trim_matches(['│', ' ']).to_owned())
                .collect();
            assert!(
                payload.contains("vendor-driver-with-a-long-device-name-0000:08:00.1"),
                "{payload}"
            );
            assert!(
                payload.contains("2001:0db8:1234:5678:abcd:0123:4567:89ab/128"),
                "{payload}"
            );
            assert!(rows
                .iter()
                .flat_map(|line| &line.spans)
                .any(|span| span.content.contains("stale") && span.style.fg == Some(theme::WARN)));
            let baseline = plain(&series_lines(
                block,
                DetailDisplayOptions::new(TimeView::SinceBaseline, DetailMetricsMode::All),
                width,
            ));
            assert!(baseline.contains("baseline(start) 2s"), "{baseline}");
        }
        let filtered = plain(&series_lines(
            block,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            80,
        ));
        assert!(!filtered.contains("Ring TX"), "{filtered}");
        assert!(filtered.contains("64 fixed | stale"), "{filtered}");
    }

    #[test]
    fn interface_frames_match_scroll_geometry_at_normal_and_tiny_widths() {
        let snapshot = crate::tui::view::tests::full_dashboard_snapshot();
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .find(|identity| identity.name() == "eth0")
            .unwrap();
        for width in [0, 1, 2, 4, 5, 20, 60, 80, 120, 160] {
            for mode in [DetailMetricsMode::All, DetailMetricsMode::WithData] {
                let display = DetailDisplayOptions::new(TimeView::Interval, mode);
                for kind in INTERFACE_BLOCK_KINDS {
                    let rows = interface_detail_lines(&snapshot, &identity, kind, display, width);
                    assert_eq!(
                        rows.len(),
                        interface_detail_row_count(&snapshot, &identity, display, width)
                    );
                    assert!(
                        rows.iter().all(|line| line.width() <= usize::from(width)),
                        "width {width}: {}",
                        plain(&rows)
                    );
                    let span = interface_layer_row_span(&snapshot, &identity, kind, display, width)
                        .unwrap();
                    assert!(span.end <= rows.len());
                    if width > 0 {
                        assert!(span.start < span.end);
                        assert_eq!(rows[span.start].style.bg, Some(theme::SELECTED_BG));
                        assert_eq!(
                            rows.iter()
                                .filter(|line| line.style.bg == Some(theme::SELECTED_BG))
                                .count(),
                            1
                        );
                    }
                    let detail =
                        interface_layer_detail_lines(&snapshot, &identity, kind, display, width);
                    assert_eq!(
                        detail.len(),
                        interface_layer_detail_row_count(
                            &snapshot, &identity, kind, display, width
                        )
                    );
                    assert!(
                        detail.iter().all(|line| line.width() <= usize::from(width)),
                        "width {width}: {}",
                        plain(&detail)
                    );
                }
            }
        }
    }

    #[test]
    fn stage_frames_keep_rx_tx_and_cause_colors() {
        let snapshot = crate::tui::view::tests::full_dashboard_snapshot();
        let dashboard = build_dashboard(&snapshot);
        let display = DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All);
        let mut checked_cause = false;
        for block in dashboard
            .blocks()
            .iter()
            .filter(|block| matches!(block.key().scope(), BlockScope::Interface(_)))
        {
            for width in [60, 80, 120, 160] {
                let rows = stage_lines(&snapshot, block, block.key().kind(), display, width, false);
                for (lane, color) in [("RX ", theme::RX), ("TX ", theme::TX)] {
                    for span in rows
                        .iter()
                        .flat_map(|line| &line.spans)
                        .filter(|span| span.content.starts_with(lane))
                    {
                        assert_eq!(span.style.fg, Some(color), "{}", span.content);
                    }
                }
                let health = assess_dashboard_block(&snapshot, block);
                if block.series_count() > 0 && !health.causes().is_empty() {
                    let expected = network_health_style(health.causes()[0].condition());
                    let why = rows
                        .iter()
                        .flat_map(|line| &line.spans)
                        .find(|span| span.content.starts_with("NOTE:"))
                        .unwrap();
                    assert_eq!(why.style.fg, expected.fg);
                    checked_cause = true;
                }
            }
        }
        assert!(checked_cause);
    }
}
