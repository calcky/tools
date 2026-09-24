use std::collections::BTreeMap;

use crate::monitor::dashboard::{
    build_dashboard, build_dashboard_for_interfaces, interface_identity, placement_for,
    resolve_lane, BlockKind, BlockScope, Dashboard, DashboardBlock, DisplaySlot, ExecutionContext,
    InterfaceIdentity, Lane, PacketStage, PlacedSeries, PlacementScope, ResolvedLane,
};
use crate::monitor::health::{
    assess_dashboard_block, compare_health_causes, Assessment, EvidenceCoverage, HealthCause,
    HealthValue, NetworkHealth,
};
use crate::monitor::{
    descriptor, CounterContinuity, InterfaceViewAnchor, MetricDescriptor, MetricLabel, MetricScope,
    MetricUnit, MonitorSnapshot, ProjectedValue, SeriesSnapshot, SeriesValue, UnavailableReason,
};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::app::{DetailMetricsMode, TimeView};
use super::presentation::{
    is_fresh_down_link_state, GLOBAL_DASHBOARD_BLOCK_COUNT, GLOBAL_DASHBOARD_BLOCK_ROWS,
    GLOBAL_DASHBOARD_ROW_COUNT, NETFILTER_DASHBOARD_BLOCK_ROWS,
};
use super::view::{
    baseline_origin_label, format_rate, format_series, format_series_title, format_value,
    metric_style,
};
use super::{detail_block, sort_table, theme};

mod interface_detail;
mod softirq_order;
use softirq_order::softirq_sort_value;

pub(super) const WIDE_DASHBOARD_WIDTH: u16 = 100;
const WIDE_DETAIL_COLUMNS_WIDTH: u16 = 160;
const MEDIUM_DETAIL_COLUMNS_WIDTH: u16 = 100;
const DETAIL_ROW_INDENT: usize = 4;
const DETAIL_COLUMN_SEPARATOR: &str = " | ";
const INTERFACE_SUMMARY_ROWS: usize = 6;
const INTERFACE_KIND_METRIC: &str = "linux.nic.interface_kind";
const INTERFACE_SUMMARY_SETTINGS: [&str; 13] = [
    "Driver",
    "RX Queues",
    "TX Queues",
    "Ring RX",
    "Ring TX",
    "TX Queue Length",
    "Duplex",
    "Flow Control RX",
    "Flow Control TX",
    "TSO",
    "LRO",
    "GRO",
    "GSO",
];
const SOFTIRQ_SOURCE: &str = "linux.proc.softirqs";
const SOFTNET_SOURCE: &str = "linux.proc.net.softnet_stat";
const SOFTIRQ_CONFIG_SOURCE: &str = "linux.proc.sys.net.core";

#[derive(Clone, Copy, Debug)]
enum SoftirqProjection {
    Rate,
    Delta,
    Current,
}

#[derive(Clone, Copy, Debug)]
struct SoftirqColumn {
    metric: &'static str,
    label: &'static str,
    compact_label: &'static str,
    narrow_label: &'static str,
    projection: SoftirqProjection,
}

const SOFTIRQ_COLUMNS: [SoftirqColumn; 10] = [
    SoftirqColumn {
        metric: "linux.softirq.net_rx",
        label: "NET_RX",
        compact_label: "RX",
        narrow_label: "RX",
        projection: SoftirqProjection::Rate,
    },
    SoftirqColumn {
        metric: "linux.softirq.net_tx",
        label: "NET_TX",
        compact_label: "TX",
        narrow_label: "TX",
        projection: SoftirqProjection::Rate,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.processed",
        label: "PROCESSED",
        compact_label: "PROC",
        narrow_label: "P",
        projection: SoftirqProjection::Rate,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.dropped",
        label: "DROPPED",
        compact_label: "DROP",
        narrow_label: "D",
        projection: SoftirqProjection::Delta,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.time_squeeze",
        label: "SQUEEZE",
        compact_label: "SQZ",
        narrow_label: "S",
        projection: SoftirqProjection::Delta,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.received_rps",
        label: "RECEIVED_RPS",
        compact_label: "RECEIVED_RPS",
        narrow_label: "RP",
        projection: SoftirqProjection::Rate,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.flow_limit",
        label: "FLOW_LIMIT_COUNT",
        compact_label: "FLOW_LIMIT_COUNT",
        narrow_label: "FL",
        projection: SoftirqProjection::Delta,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.backlog_len",
        label: "BACKLOG_LEN",
        compact_label: "BACKLOG_LEN",
        narrow_label: "BL",
        projection: SoftirqProjection::Current,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.input_qlen",
        label: "INPUT_QLEN",
        compact_label: "INPUT_QLEN",
        narrow_label: "IQ",
        projection: SoftirqProjection::Current,
    },
    SoftirqColumn {
        metric: "linux.softirq.softnet.process_qlen",
        label: "PROCESS_QLEN",
        compact_label: "PROCESS_QLEN",
        narrow_label: "PQ",
        projection: SoftirqProjection::Current,
    },
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum SoftirqSort {
    #[default]
    Cpu,
    Metric(usize),
}

impl SoftirqSort {
    pub(super) const fn default_descending(self) -> bool {
        matches!(self, Self::Metric(_))
    }
}

#[derive(Debug)]
pub(super) struct SoftirqSection {
    header: Vec<Line<'static>>,
    rows: Vec<(u32, [Option<usize>; SOFTIRQ_COLUMNS.len()])>,
    columns: Vec<(usize, &'static SoftirqColumn)>,
    widths: Vec<usize>,
    width: u16,
    sort: SoftirqSort,
    descending: bool,
    display: DetailDisplayOptions,
}

impl SoftirqSection {
    pub(super) fn new_with_options(
        snapshot: &MonitorSnapshot,
        width: u16,
        display: DetailDisplayOptions,
        sort: SoftirqSort,
        descending: bool,
    ) -> Self {
        let dashboard = build_dashboard_for_interfaces(snapshot, &[]);
        let block = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().kind() == BlockKind::ExecutionContext(ExecutionContext::Softirq)
            })
            .expect("dashboard seeds the SoftIRQ block");
        let (mut header, rows, columns, widths) =
            softirq_matrix_parts(snapshot, block, display, width);
        let (sort, descending) = match sort {
            SoftirqSort::Metric(index) if !columns.iter().any(|(visible, _)| *visible == index) => {
                (SoftirqSort::Cpu, false)
            }
            sort => (sort, descending),
        };
        if !columns.is_empty() {
            *header.last_mut().expect("matrix heading") =
                softirq_sorted_header(&columns, &widths, width, sort, descending);
        }
        let mut rows: Vec<_> = if columns.is_empty() {
            Vec::new()
        } else {
            rows.into_iter()
                .map(|(cpu, row)| {
                    (
                        cpu,
                        row.map(|series| {
                            series.map(|series| {
                                snapshot
                                    .series()
                                    .binary_search_by_key(&series.id(), SeriesSnapshot::id)
                                    .expect("snapshot series")
                            })
                        }),
                    )
                })
                .collect()
        };
        rows.sort_by(|(left_cpu, left), (right_cpu, right)| {
            let order = match sort {
                SoftirqSort::Cpu => {
                    let order = left_cpu.cmp(right_cpu);
                    if descending {
                        order.reverse()
                    } else {
                        order
                    }
                }
                SoftirqSort::Metric(index) => {
                    let key = |row: &[Option<usize>; SOFTIRQ_COLUMNS.len()]| {
                        row[index].and_then(|i| {
                            softirq_sort_value(
                                &snapshot.series()[i],
                                SOFTIRQ_COLUMNS[index].projection,
                                display.time_view,
                            )
                        })
                    };
                    match (key(left), key(right)) {
                        (Some(left), Some(right)) => {
                            let order = left.compare(right);
                            if descending {
                                order.reverse()
                            } else {
                                order
                            }
                        }
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                }
            };
            order.then_with(|| left_cpu.cmp(right_cpu))
        });
        Self {
            header,
            rows,
            columns,
            widths,
            width,
            sort,
            descending,
            display,
        }
    }

    pub(super) fn row_count(&self) -> usize {
        self.header.len() + self.rows.len()
    }

    pub(super) fn effective_sort(&self) -> SoftirqSort {
        self.sort
    }

    pub(super) fn effective_descending(&self) -> bool {
        self.descending
    }

    pub(super) fn viewport(&self, height: usize, offset: usize) -> sort_table::TableViewport {
        let headings = usize::from(!self.columns.is_empty());
        sort_table::TableViewport::new(
            self.header.len().saturating_sub(headings),
            headings,
            self.rows.len(),
            height,
            offset,
        )
    }

    pub(super) fn header_sort_at(
        &self,
        x: usize,
        row: usize,
        height: usize,
        offset: usize,
    ) -> Option<SoftirqSort> {
        let view = self.viewport(height, offset);
        if view.headings == 0 || row != view.context || x >= usize::from(self.width) {
            return None;
        }
        let mut start = softirq_matrix_indent(self.width);
        for (position, width) in self.widths.iter().copied().enumerate() {
            if (start..start + width).contains(&x) {
                return Some(if position == 0 {
                    SoftirqSort::Cpu
                } else {
                    SoftirqSort::Metric(self.columns[position - 1].0)
                });
            }
            start += width + 1;
        }
        None
    }

    pub(super) fn next_sort(&self, current: SoftirqSort) -> SoftirqSort {
        match current {
            SoftirqSort::Cpu => self
                .columns
                .first()
                .map_or(SoftirqSort::Cpu, |(index, _)| SoftirqSort::Metric(*index)),
            SoftirqSort::Metric(index) => self
                .columns
                .iter()
                .position(|(visible, _)| *visible == index)
                .and_then(|position| self.columns.get(position + 1))
                .map_or(SoftirqSort::Cpu, |(index, _)| SoftirqSort::Metric(*index)),
        }
    }

    fn visible_lines(
        &self,
        snapshot: &MonitorSnapshot,
        _time_view: TimeView,
        offset: usize,
        limit: usize,
    ) -> Vec<Line<'static>> {
        let view = self.viewport(limit, offset);
        let count = view.data_start()
            + view
                .capacity
                .min(self.rows.len().saturating_sub(view.offset));
        (0..count)
            .filter_map(|row| {
                let logical = view.logical_row(row)?;
                if logical < self.header.len() {
                    return Some(self.header[logical].clone());
                }
                let (cpu, row) = &self.rows[logical - self.header.len()];
                let row = row.map(|index| index.map(|index| &snapshot.series()[index]));
                let mut line = softirq_matrix_row(
                    *cpu,
                    &row,
                    &self.columns,
                    &self.widths,
                    self.display.time_view,
                    self.width,
                );
                let position = match self.sort {
                    SoftirqSort::Cpu => Some(0),
                    SoftirqSort::Metric(index) => self
                        .columns
                        .iter()
                        .position(|(visible, _)| *visible == index)
                        .map(|position| position + 1),
                };
                if let Some(span) =
                    position.and_then(|position| line.spans.get_mut(1 + 2 * position))
                {
                    span.style = span.style.bg(theme::SORT_BG);
                }
                Some(line)
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DetailDisplayOptions {
    time_view: TimeView,
    metrics_mode: DetailMetricsMode,
}

impl DetailDisplayOptions {
    pub(super) const fn new(time_view: TimeView, metrics_mode: DetailMetricsMode) -> Self {
        Self {
            time_view,
            metrics_mode,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum InterfaceKind {
    Physical,
    Virtual,
    Unknown,
}

impl InterfaceKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Physical => "PHYS",
            Self::Virtual => "VIRT",
            Self::Unknown => "KIND?",
        }
    }

    const fn compact_label(self) -> &'static str {
        match self {
            Self::Physical => "P",
            Self::Virtual => "V",
            Self::Unknown => "?",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct InterfaceFilter<'a> {
    inventory: &'a [InterfaceIdentity],
    anchor: Option<&'a InterfaceViewAnchor>,
    name_alias: Option<&'a str>,
    selected_layer: Option<BlockKind>,
    selected: Option<&'a InterfaceIdentity>,
}

impl<'a> InterfaceFilter<'a> {
    pub(super) const fn new(
        inventory: &'a [InterfaceIdentity],
        anchor: Option<&'a InterfaceViewAnchor>,
        name_alias: Option<&'a str>,
        selected_layer: Option<BlockKind>,
        selected: Option<&'a InterfaceIdentity>,
    ) -> Self {
        Self {
            inventory,
            anchor,
            name_alias,
            selected_layer,
            selected,
        }
    }
}

struct InterfaceOverview<'dashboard, 'snapshot> {
    identity: &'dashboard InterfaceIdentity,
    blocks: [Option<&'dashboard DashboardBlock<'snapshot>>; INTERFACE_BLOCK_KINDS.len()],
    kind: InterfaceKind,
    inventory_observed: Option<bool>,
    any_observed: bool,
    link: Option<&'snapshot SeriesSnapshot>,
    speed: Option<&'snapshot SeriesSnapshot>,
    settings: BTreeMap<&'snapshot str, &'snapshot SeriesSnapshot>,
}

impl<'dashboard, 'snapshot> InterfaceOverview<'dashboard, 'snapshot> {
    fn new(identity: &'dashboard InterfaceIdentity) -> Self {
        Self {
            identity,
            blocks: [None; INTERFACE_BLOCK_KINDS.len()],
            kind: InterfaceKind::Unknown,
            inventory_observed: None,
            any_observed: false,
            link: None,
            speed: None,
            settings: BTreeMap::new(),
        }
    }

    fn record_block(&mut self, block: &'dashboard DashboardBlock<'snapshot>) {
        if let Some(index) = INTERFACE_BLOCK_KINDS
            .iter()
            .position(|kind| *kind == block.key().kind())
        {
            self.blocks[index] = Some(block);
        }
        for series in block
            .rx()
            .iter()
            .chain(block.tx())
            .chain(block.shared())
            .map(PlacedSeries::series)
        {
            self.record_series(series);
        }
    }

    fn record_series(&mut self, series: &'snapshot SeriesSnapshot) {
        let observed = series_has_observed_value(series);
        self.any_observed |= observed;
        match series.metric().as_str() {
            INTERFACE_KIND_METRIC => {
                self.inventory_observed = Some(observed);
                self.kind = match series_state_value(series) {
                    Some("physical") => InterfaceKind::Physical,
                    Some("virtual") => InterfaceKind::Virtual,
                    _ => InterfaceKind::Unknown,
                };
            }
            "linux.nic.link_state" => self.link = Some(series),
            crate::monitor::RAW_NIC_SETTING_METRIC_ID => {
                if let Some(statistic) = series.labels().get(MetricLabel::Statistic) {
                    if statistic == "Speed" {
                        self.speed.get_or_insert(series);
                    } else if INTERFACE_SUMMARY_SETTINGS.contains(&statistic) {
                        self.settings.entry(statistic).or_insert(series);
                    }
                }
            }
            _ => {}
        }
    }

    fn is_observed(&self) -> bool {
        self.inventory_observed.unwrap_or(self.any_observed)
    }

    fn is_visible(&self, anchor: Option<&InterfaceViewAnchor>) -> bool {
        self.is_observed()
            && (anchor.is_some()
                || self
                    .link
                    .is_none_or(|series| !is_fresh_down_link_state(series)))
    }

    fn block(&self, kind: BlockKind) -> Option<&'dashboard DashboardBlock<'snapshot>> {
        INTERFACE_BLOCK_KINDS
            .iter()
            .position(|candidate| *candidate == kind)
            .and_then(|index| self.blocks[index])
    }

    fn setting_display_value(&self, statistic: &str) -> String {
        self.settings
            .get(statistic)
            .and_then(|series| series_state_display_value(series))
            .unwrap_or_else(|| "-".to_owned())
    }
}

pub(super) fn render_starting_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    row_offset: usize,
    selected_layer: Option<BlockKind>,
) {
    let mut lines = Vec::with_capacity(dashboard_row_count(None, None, None, area.width));
    for kind in OVERVIEW_LAYER_KINDS {
        let title = global_block_title(kind).expect("global dashboard kinds have titles");
        lines.extend(starting_global_block_lines(
            kind,
            title,
            area.width,
            selected_layer == Some(kind),
        ));
    }
    lines.push(interface_section_line(0, area.width));
    lines.push(pending_interface_line(area.width));
    render_dashboard_lines(frame, area, lines, row_offset);
}

pub(super) fn render_overview(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &MonitorSnapshot,
    time_view: TimeView,
    row_offset: usize,
    interface_filter: InterfaceFilter<'_>,
) {
    let total_rows = overview_row_count(interface_filter.inventory.len());
    let offset = row_offset.min(total_rows.saturating_sub(1));
    let viewport = offset..offset.saturating_add(usize::from(area.height));
    let visible_range = visible_interface_range(&viewport, interface_filter.inventory.len());
    let dashboard = build_dashboard_for_interfaces(
        snapshot,
        &interface_filter.inventory[visible_range.clone()],
    );
    let interfaces = visible_interfaces(
        &dashboard,
        interface_filter.anchor,
        interface_filter.name_alias,
    );
    let mut visible_lines = Vec::with_capacity(usize::from(area.height));
    let mut block_start = 0;
    for block in dashboard.blocks().iter().take(GLOBAL_DASHBOARD_BLOCK_COUNT) {
        let block_end = block_start + global_block_row_count(block.key().kind());
        if viewport.start < block_end && viewport.end > block_start {
            let title = global_block_title(block.key().kind())
                .expect("dashboard starts with the global overview blocks");
            append_visible_lines(
                &mut visible_lines,
                &viewport,
                block_start,
                global_block_lines(
                    snapshot,
                    block,
                    title,
                    DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                    area.width,
                    interface_filter.selected_layer == Some(block.key().kind()),
                ),
            );
        }
        block_start = block_end;
    }
    debug_assert_eq!(block_start, GLOBAL_DASHBOARD_ROW_COUNT);
    if viewport.contains(&block_start) {
        visible_lines.push(interface_section_line(
            interface_filter.inventory.len(),
            area.width,
        ));
    }

    if interface_filter.inventory.is_empty() {
        append_visible_lines(
            &mut visible_lines,
            &viewport,
            GLOBAL_DASHBOARD_ROW_COUNT.saturating_add(1),
            vec![empty_interface_line(area.width)],
        );
    } else {
        for (index, interface) in visible_range.zip(&interfaces) {
            let lines = interface_summary_lines(
                snapshot,
                interface,
                time_view,
                area.width,
                interface_filter.selected == Some(interface.identity),
            );
            append_visible_lines(
                &mut visible_lines,
                &viewport,
                interface_row_span_at(index).start,
                lines,
            );
        }
    }
    frame.render_widget(Paragraph::new(visible_lines), area);
}

pub(super) fn render_interface_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    selected_layer: BlockKind,
    display: DetailDisplayOptions,
    row_offset: usize,
) {
    let lines = interface_detail_lines(snapshot, identity, selected_layer, display, area.width);
    render_dashboard_lines(frame, area, lines, row_offset);
}

pub(super) fn render_interface_layer_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    layer: BlockKind,
    display: DetailDisplayOptions,
    row_offset: usize,
) {
    let lines = interface_layer_detail_lines(snapshot, identity, layer, display, area.width);
    render_dashboard_lines(frame, area, lines, row_offset);
}

pub(super) fn render_global_layer_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &MonitorSnapshot,
    kind: BlockKind,
    display: DetailDisplayOptions,
    row_offset: usize,
) {
    let lines = global_layer_detail_lines(snapshot, kind, display, area.width);
    render_dashboard_lines(frame, area, lines, row_offset);
}

pub(super) fn render_softirq_section(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &MonitorSnapshot,
    model: &SoftirqSection,
    time_view: TimeView,
    row_offset: usize,
) {
    let lines = model.visible_lines(snapshot, time_view, row_offset, usize::from(area.height));
    frame.render_widget(Paragraph::new(lines), area);
}

pub(super) fn dashboard_row_count(
    snapshot: Option<&MonitorSnapshot>,
    interface_anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
    _width: u16,
) -> usize {
    let interface_count = snapshot.map_or(0, |snapshot| {
        let dashboard = build_dashboard(snapshot);
        visible_interfaces(&dashboard, interface_anchor, interface_name_alias).len()
    });
    overview_row_count(interface_count)
}

pub(super) fn overview_row_count(interface_count: usize) -> usize {
    GLOBAL_DASHBOARD_ROW_COUNT
        .saturating_add(1)
        .saturating_add(if interface_count == 0 {
            1
        } else {
            interface_count.saturating_mul(INTERFACE_SUMMARY_ROWS)
        })
}

#[cfg(test)]
pub(super) fn ordered_interface_identities(
    snapshot: &MonitorSnapshot,
    interface_anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> Vec<InterfaceIdentity> {
    ordered_interface_identities_with_down(snapshot, interface_anchor, interface_name_alias, false)
}

pub(super) fn ordered_interface_identities_with_down(
    snapshot: &MonitorSnapshot,
    interface_anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
    include_down: bool,
) -> Vec<InterfaceIdentity> {
    struct InventoryEntry<'a> {
        representative: &'a SeriesSnapshot,
        kind: Option<&'a SeriesSnapshot>,
        link: Option<&'a SeriesSnapshot>,
        any_observed: bool,
    }
    let mut grouped = BTreeMap::<(u32, &str), InventoryEntry<'_>>::new();
    for series in snapshot.series() {
        let Some(placement) = series.metric().descriptor().and_then(placement_for) else {
            continue;
        };
        if placement.scope() != PlacementScope::Interface
            || resolve_lane(series, placement.lane()).is_err()
        {
            continue;
        }
        let Some(name) = series.labels().get(MetricLabel::Interface) else {
            continue;
        };
        let Some(index) = series
            .labels()
            .get(MetricLabel::Ifindex)
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|index| *index > 0)
        else {
            continue;
        };
        let entry = grouped.entry((index, name)).or_insert(InventoryEntry {
            representative: series,
            kind: None,
            link: None,
            any_observed: false,
        });
        entry.any_observed |= series_has_observed_value(series);
        match series.metric().as_str() {
            INTERFACE_KIND_METRIC => entry.kind = Some(series),
            "linux.nic.link_state" => entry.link = Some(series),
            _ => {}
        }
    }
    let mut interfaces = Vec::new();
    for entry in grouped.values() {
        let identity =
            interface_identity(entry.representative).expect("validated interface identity");
        if !interface_matches_anchor(&identity, interface_anchor, interface_name_alias) {
            continue;
        }
        let mut interface = InterfaceOverview::new(&identity);
        for series in entry.kind.into_iter().chain(entry.link) {
            interface.record_series(series);
        }
        interface.any_observed = entry.any_observed;
        if (include_down && interface.is_observed()) || interface.is_visible(interface_anchor) {
            interfaces.push((interface.kind, identity));
        }
    }
    interfaces.sort();
    interfaces
        .into_iter()
        .map(|(_, identity)| identity)
        .collect()
}

pub(super) fn interface_row_span_at(index: usize) -> std::ops::Range<usize> {
    let start = GLOBAL_DASHBOARD_ROW_COUNT
        .saturating_add(1)
        .saturating_add(index.saturating_mul(INTERFACE_SUMMARY_ROWS));
    start..start.saturating_add(INTERFACE_SUMMARY_ROWS)
}

fn visible_interface_range(
    viewport: &std::ops::Range<usize>,
    interface_count: usize,
) -> std::ops::Range<usize> {
    let interface_start = GLOBAL_DASHBOARD_ROW_COUNT.saturating_add(1);
    if interface_count == 0 || viewport.is_empty() || viewport.end <= interface_start {
        return 0..0;
    }

    let first = viewport
        .start
        .saturating_sub(interface_start)
        .checked_div(INTERFACE_SUMMARY_ROWS)
        .unwrap_or(0)
        .min(interface_count);
    let end = viewport
        .end
        .saturating_sub(interface_start)
        .saturating_add(INTERFACE_SUMMARY_ROWS.saturating_sub(1))
        .checked_div(INTERFACE_SUMMARY_ROWS)
        .unwrap_or(0)
        .min(interface_count);
    first..end.max(first)
}

fn append_visible_lines(
    output: &mut Vec<Line<'static>>,
    viewport: &std::ops::Range<usize>,
    chunk_start: usize,
    lines: impl IntoIterator<Item = Line<'static>>,
) {
    let skip = viewport.start.saturating_sub(chunk_start);
    let take = viewport
        .end
        .saturating_sub(chunk_start)
        .saturating_sub(skip);
    output.extend(lines.into_iter().skip(skip).take(take));
}

#[cfg(test)]
fn overview_layer_row_span(kind: BlockKind) -> Option<std::ops::Range<usize>> {
    let index = OVERVIEW_LAYER_KINDS
        .iter()
        .position(|candidate| *candidate == kind)?;
    let start = OVERVIEW_LAYER_KINDS[..index]
        .iter()
        .map(|kind| global_block_row_count(*kind))
        .sum();
    Some(start..start.saturating_add(global_block_row_count(kind)))
}

pub(super) fn overview_layer_title(kind: BlockKind) -> &'static str {
    global_block_title(kind).expect("overview layer kinds have titles")
}

pub(super) fn global_layer_detail_row_count(
    snapshot: &MonitorSnapshot,
    kind: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> usize {
    global_layer_detail_lines(snapshot, kind, display, width).len()
}

pub(super) fn interface_detail_row_count(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    display: DetailDisplayOptions,
    width: u16,
) -> usize {
    interface_detail_lines(snapshot, identity, INTERFACE_BLOCK_KINDS[0], display, width).len()
}

pub(super) fn interface_layer_detail_row_count(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    layer: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> usize {
    interface_layer_detail_lines(snapshot, identity, layer, display, width).len()
}

pub(super) fn interface_layer_row_span(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    layer: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> Option<std::ops::Range<usize>> {
    if !interface_is_observed(snapshot, identity) {
        return None;
    }
    let dashboard = build_dashboard_for_interfaces(snapshot, std::slice::from_ref(identity));
    let mut start = interface_detail::identity_lines(snapshot, identity, width).len();
    for candidate in INTERFACE_BLOCK_KINDS {
        let block = interface_block(&dashboard, identity, candidate)
            .expect("dashboard seeds every stage for a discovered interface");
        let rows =
            interface_detail::stage_lines(snapshot, block, candidate, display, width, false).len();
        if candidate == layer {
            return Some(start..start.saturating_add(rows));
        }
        start = start.saturating_add(rows);
    }
    None
}

pub(super) const OVERVIEW_LAYER_KINDS: [BlockKind; GLOBAL_DASHBOARD_BLOCK_COUNT] = [
    BlockKind::PacketStage(PacketStage::SocketApplication),
    BlockKind::PacketStage(PacketStage::Transport),
    BlockKind::PacketStage(PacketStage::NetworkRoute),
    BlockKind::PacketStage(PacketStage::NetfilterConntrack),
    BlockKind::ExecutionContext(ExecutionContext::Softirq),
];

pub(super) const INTERFACE_BLOCK_KINDS: [BlockKind; 5] = [
    BlockKind::PacketStage(PacketStage::TrafficControl),
    BlockKind::PacketStage(PacketStage::NetdeviceCore),
    BlockKind::PacketStage(PacketStage::DriverNapi),
    BlockKind::PacketStage(PacketStage::NicPhy),
    BlockKind::ExecutionContext(ExecutionContext::Hardirq),
];

fn visible_interfaces<'dashboard, 'snapshot>(
    dashboard: &'dashboard Dashboard<'snapshot>,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> Vec<InterfaceOverview<'dashboard, 'snapshot>> {
    let mut interfaces = BTreeMap::new();
    for block in dashboard.blocks() {
        let BlockScope::Interface(identity) = block.key().scope() else {
            continue;
        };
        if !interface_matches_anchor(identity, anchor, interface_name_alias) {
            continue;
        }
        interfaces
            .entry(identity)
            .or_insert_with(|| InterfaceOverview::new(identity))
            .record_block(block);
    }
    let mut interfaces = interfaces
        .into_values()
        .filter(|interface| interface.is_visible(anchor))
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.identity.ifindex().cmp(&right.identity.ifindex()))
            .then_with(|| left.identity.name().cmp(right.identity.name()))
    });
    interfaces
}

fn interface_matches_anchor(
    identity: &InterfaceIdentity,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> bool {
    match anchor {
        None => true,
        Some(InterfaceViewAnchor::Name { name }) => identity.name() == name,
        Some(InterfaceViewAnchor::Names { names }) => names.contains(identity.name()),
        Some(InterfaceViewAnchor::Ifindex { ifindex }) => {
            identity.ifindex() == *ifindex
                || interface_name_alias.is_some_and(|name| identity.name() == name)
        }
    }
}

fn interface_block<'a, 'snapshot>(
    dashboard: &'a Dashboard<'snapshot>,
    identity: &InterfaceIdentity,
    kind: BlockKind,
) -> Option<&'a DashboardBlock<'snapshot>> {
    dashboard.blocks().iter().find(|block| {
        block.key().kind() == kind
            && matches!(
                block.key().scope(),
                BlockScope::Interface(candidate) if candidate == identity
            )
    })
}

fn interface_kind(snapshot: &MonitorSnapshot, identity: &InterfaceIdentity) -> InterfaceKind {
    match interface_state_value(snapshot, identity, INTERFACE_KIND_METRIC) {
        Some("physical") => InterfaceKind::Physical,
        Some("virtual") => InterfaceKind::Virtual,
        _ => InterfaceKind::Unknown,
    }
}

fn interface_is_observed(snapshot: &MonitorSnapshot, identity: &InterfaceIdentity) -> bool {
    let inventory = snapshot.series().iter().find(|series| {
        series.metric().as_str() == INTERFACE_KIND_METRIC
            && series_matches_interface(series, identity)
    });
    match inventory {
        Some(series) => series_has_observed_value(series),
        None => snapshot.series().iter().any(|series| {
            series_matches_interface(series, identity) && series_has_observed_value(series)
        }),
    }
}

fn series_has_observed_value(series: &SeriesSnapshot) -> bool {
    match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            matches!(
                current,
                ProjectedValue::Fresh { .. } | ProjectedValue::Stale { .. }
            )
        }
        SeriesValue::State { current, .. } => {
            matches!(
                current,
                ProjectedValue::Fresh { .. } | ProjectedValue::Stale { .. }
            )
        }
    }
}

fn interface_state_value<'a>(
    snapshot: &'a MonitorSnapshot,
    identity: &InterfaceIdentity,
    metric: &str,
) -> Option<&'a str> {
    snapshot
        .series()
        .iter()
        .find(|series| {
            series.metric().as_str() == metric && series_matches_interface(series, identity)
        })
        .and_then(series_state_value)
}

fn interface_setting_display_value(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    statistic: &str,
) -> Option<String> {
    snapshot
        .series()
        .iter()
        .find(|series| {
            series.metric().as_str() == crate::monitor::RAW_NIC_SETTING_METRIC_ID
                && series_matches_interface(series, identity)
                && series.labels().get(MetricLabel::Statistic) == Some(statistic)
        })
        .and_then(series_state_display_value)
}

fn series_state_value(series: &SeriesSnapshot) -> Option<&str> {
    let SeriesValue::State { current, .. } = series.value() else {
        return None;
    };
    match current {
        ProjectedValue::Fresh { value, .. } => Some(value.as_str()),
        ProjectedValue::Stale { last, .. } => Some(last.as_str()),
        ProjectedValue::Unavailable { .. } => None,
    }
}

fn series_state_display_value(series: &SeriesSnapshot) -> Option<String> {
    let SeriesValue::State { current, .. } = series.value() else {
        return None;
    };
    match current {
        ProjectedValue::Fresh { value, .. } => Some(value.as_str().to_owned()),
        ProjectedValue::Stale { last, .. } => Some(format!("~{}", last.as_str())),
        ProjectedValue::Unavailable { .. } => None,
    }
}

fn series_matches_interface(series: &SeriesSnapshot, identity: &InterfaceIdentity) -> bool {
    series.labels().get(MetricLabel::Interface) == Some(identity.name())
        && series
            .labels()
            .get(MetricLabel::Ifindex)
            .and_then(|value| value.parse::<u32>().ok())
            == Some(identity.ifindex().get())
}

fn interface_section_line(interface_count: usize, width: u16) -> Line<'static> {
    let prefix = " INTERFACES";
    let value = fit_cell(
        &format!("{prefix}  {interface_count} visible  physical first, then virtual"),
        usize::from(width),
    );
    let rest = value
        .chars()
        .skip(prefix.chars().count())
        .collect::<String>();
    Line::from(vec![
        Span::styled(
            prefix,
            Style::default()
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(rest, Style::default().fg(theme::MUTED)),
    ])
}

fn pending_interface_line(width: u16) -> Line<'static> {
    Line::from(fit_cell(
        "   waiting for interface-scoped kernel counters",
        usize::from(width),
    ))
    .style(Style::default().fg(theme::MUTED))
}

fn empty_interface_line(width: u16) -> Line<'static> {
    Line::from(fit_cell(
        "   no interface rows visible in the current view",
        usize::from(width),
    ))
    .style(Style::default().fg(theme::MUTED))
}

fn interface_summary_lines<'dashboard, 'snapshot>(
    snapshot: &MonitorSnapshot,
    interface: &InterfaceOverview<'dashboard, 'snapshot>,
    time_view: TimeView,
    width: u16,
    selected: bool,
) -> [Line<'static>; INTERFACE_SUMMARY_ROWS] {
    let assessments = interface
        .blocks
        .iter()
        .flatten()
        .map(|block| assess_dashboard_block(snapshot, block))
        .collect::<Vec<_>>();
    let health = combined_network_health(assessments.iter().map(Assessment::health));
    let coverage = EvidenceCoverage::combine(assessments.iter().map(Assessment::coverage));
    let link = interface
        .link
        .and_then(series_state_display_value)
        .unwrap_or_else(|| "-".to_owned())
        .to_ascii_uppercase();
    let speed = interface
        .speed
        .and_then(series_state_display_value)
        .unwrap_or_else(|| "-".to_owned());
    let netdevice = interface.block(BlockKind::PacketStage(PacketStage::NetdeviceCore));
    let cause = primary_interface_cause(&assessments);
    let mut lines = [
        interface_summary_title_line(
            interface.identity,
            interface.kind,
            &link,
            &speed,
            health,
            coverage,
            width,
            selected,
        ),
        interface_configuration_summary_line(interface, width),
        interface_feature_summary_line(interface, width),
        interface_direction_summary_line(netdevice, ResolvedLane::Rx, time_view, width),
        interface_direction_summary_line(netdevice, ResolvedLane::Tx, time_view, width),
        dashboard_cause_line(cause, width),
    ];
    if selected {
        lines[0] = lines[0]
            .clone()
            .style(Style::default().bg(theme::SELECTED_BG));
    }
    lines
}

fn interface_configuration_summary_line(
    interface: &InterfaceOverview<'_, '_>,
    width: u16,
) -> Line<'static> {
    let values = [
        interface.setting_display_value("Driver"),
        interface.setting_display_value("Duplex"),
        interface.setting_display_value("RX Queues"),
        interface.setting_display_value("TX Queues"),
        interface.setting_display_value("Ring RX"),
        interface.setting_display_value("Ring TX"),
        interface.setting_display_value("TX Queue Length"),
    ];
    let compact = width < WIDE_DASHBOARD_WIDTH;
    let fixed_width = if compact {
        "   CFG drv: dup: q:/ r:/ t:".len()
    } else {
        "   CFG  driver   duplex   queues RX/TX /  ring RX/TX /  txqlen ".len()
    };
    let [driver, duplex, rx_queues, tx_queues, ring_rx, ring_tx, tx_queue_len] =
        fit_interface_summary_values(
            values,
            usize::from(width).saturating_sub(fixed_width),
            [24, 12, 10, 10, 12, 12, 12],
            [2, 3, 4, 5, 6, 1, 0],
        );
    let value = if compact {
        format!(
            "   CFG drv:{driver} dup:{duplex} q:{rx_queues}/{tx_queues} r:{ring_rx}/{ring_tx} t:{tx_queue_len}"
        )
    } else {
        format!(
            "   CFG  driver {driver}  duplex {duplex}  queues RX/TX {rx_queues}/{tx_queues}  ring RX/TX {ring_rx}/{ring_tx}  txqlen {tx_queue_len}"
        )
    };
    dashboard_data_line(&value, width)
}

fn interface_feature_summary_line(
    interface: &InterfaceOverview<'_, '_>,
    width: u16,
) -> Line<'static> {
    let values = [
        compact_switch_value(interface.setting_display_value("Flow Control RX")),
        compact_switch_value(interface.setting_display_value("Flow Control TX")),
        compact_switch_value(interface.setting_display_value("TSO")),
        compact_switch_value(interface.setting_display_value("LRO")),
        compact_switch_value(interface.setting_display_value("GRO")),
        compact_switch_value(interface.setting_display_value("GSO")),
    ];
    let compact = width < WIDE_DASHBOARD_WIDTH;
    let fixed_width = if compact {
        "   FEAT fc:/ tso: lro: gro: gso:".len()
    } else {
        "   FEAT  flow control RX/TX /  TSO   LRO   GRO   GSO ".len()
    };
    let [flow_rx, flow_tx, tso, lro, gro, gso] = fit_interface_summary_values(
        values,
        usize::from(width).saturating_sub(fixed_width),
        [12; 6],
        [0, 1, 2, 3, 4, 5],
    );
    let value = if compact {
        format!("   FEAT fc:{flow_rx}/{flow_tx} tso:{tso} lro:{lro} gro:{gro} gso:{gso}")
    } else {
        format!(
            "   FEAT  flow control RX/TX {flow_rx}/{flow_tx}  TSO {tso}  LRO {lro}  GRO {gro}  GSO {gso}"
        )
    };
    dashboard_data_line(&value, width)
}

fn compact_switch_value(value: String) -> String {
    let (stale, raw) = value
        .strip_prefix('~')
        .map_or((false, value.as_str()), |raw| (true, raw));
    let state = raw.split_ascii_whitespace().next().unwrap_or("-");
    if stale {
        format!("~{state}")
    } else {
        state.to_owned()
    }
}

fn fit_interface_summary_values<const N: usize>(
    values: [String; N],
    available: usize,
    maximum_widths: [usize; N],
    priority: [usize; N],
) -> [String; N] {
    let mut widths = [0; N];
    let mut remaining = available;
    for index in priority {
        if remaining == 0 {
            break;
        }
        let width = values[index]
            .chars()
            .count()
            .min(maximum_widths[index])
            .min(remaining);
        widths[index] = width;
        remaining = remaining.saturating_sub(width);
    }
    std::array::from_fn(|index| truncate_component(&values[index], widths[index]))
}

#[cfg(test)]
fn interface_assessments(
    snapshot: &MonitorSnapshot,
    dashboard: &Dashboard<'_>,
    identity: &InterfaceIdentity,
) -> Vec<Assessment> {
    INTERFACE_BLOCK_KINDS
        .iter()
        .filter_map(|kind| interface_block(dashboard, identity, *kind))
        .map(|block| assess_dashboard_block(snapshot, block))
        .collect()
}

fn primary_interface_cause(assessments: &[Assessment]) -> Option<&HealthCause> {
    assessments
        .iter()
        .flat_map(Assessment::causes)
        .min_by(|left, right| compare_health_causes(left, right))
}

#[allow(clippy::too_many_arguments)]
fn interface_summary_title_line(
    identity: &InterfaceIdentity,
    kind: InterfaceKind,
    link: &str,
    speed: &str,
    health: NetworkHealth,
    coverage: EvidenceCoverage,
    width: u16,
    selected: bool,
) -> Line<'static> {
    let marker = if selected { ">" } else { " " };
    let compact = width < 70;
    let marker_style = Style::default().fg(if selected {
        theme::ACCENT
    } else {
        theme::MUTED
    });
    let link = if compact {
        compact_link_state(link)
    } else {
        link
    };
    let mut left = vec![
        (" ".to_owned(), Style::default()),
        (marker.to_owned(), marker_style),
        (" ".to_owned(), Style::default()),
        (
            identity.name().to_owned(),
            Style::default()
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if compact {
        left.push((
            format!(
                " ifindex {} {} ",
                identity.ifindex().get(),
                kind.compact_label()
            ),
            Style::default().fg(theme::MUTED),
        ));
        left.push((link.to_owned(), link_state_style(link)));
        left.push((format!(" {speed}"), Style::default().fg(theme::TEXT)));
    } else {
        left.push((
            format!("  {}  ", kind.label()),
            Style::default().fg(theme::MUTED),
        ));
        left.push((link.to_owned(), link_state_style(link)));
        left.push((format!("  {speed}"), Style::default().fg(theme::TEXT)));
        left.push((
            format!("  ifindex {}", identity.ifindex().get()),
            Style::default().fg(theme::MUTED),
        ));
    }
    let health_label = if compact && health == NetworkHealth::Unknown {
        "UNK"
    } else {
        health.as_str()
    };
    let coverage_label = if compact {
        match coverage {
            EvidenceCoverage::Fresh => "fresh",
            EvidenceCoverage::Partial => "part",
            EvidenceCoverage::Stale => "stale",
            EvidenceCoverage::Unsupported => "unsup",
        }
    } else {
        coverage.as_str()
    };
    let status = format!("[{health_label}|{coverage_label}]");
    let available = usize::from(width);
    if available <= status.chars().count().saturating_add(1) {
        left.push((format!(" {status}"), Style::default().fg(theme::MUTED)));
        return Line::from(fit_styled_parts(left, available));
    }
    let left_width = available
        .saturating_sub(status.chars().count())
        .saturating_sub(1);
    let mut spans = fit_styled_parts(left, left_width);
    spans.extend([
        Span::raw(" "),
        Span::styled("[", Style::default().fg(theme::MUTED)),
        Span::styled(health_label, network_health_style(health)),
        Span::styled("|", Style::default().fg(theme::MUTED)),
        Span::styled(coverage_label, coverage_style(coverage)),
        Span::styled("]", Style::default().fg(theme::MUTED)),
    ]);
    Line::from(spans)
}

fn fit_styled_parts(parts: Vec<(String, Style)>, width: usize) -> Vec<Span<'static>> {
    let mut remaining = width;
    let mut spans = Vec::with_capacity(parts.len().saturating_add(1));
    for (value, style) in parts {
        if remaining == 0 {
            break;
        }
        let fitted = value.chars().take(remaining).collect::<String>();
        remaining = remaining.saturating_sub(fitted.chars().count());
        spans.push(Span::styled(fitted, style));
    }
    if remaining > 0 {
        spans.push(Span::raw(" ".repeat(remaining)));
    }
    spans
}

fn link_state_style(link: &str) -> Style {
    match link {
        "UP" => Style::default()
            .fg(theme::GOOD)
            .add_modifier(Modifier::BOLD),
        "DOWN" | "LOWER_LAYER_DOWN" | "LOWER_DOWN" | "DORMANT" => Style::default().fg(theme::WARN),
        "NOT_PRESENT" => Style::default().fg(theme::BAD),
        _ => Style::default().fg(theme::MUTED),
    }
}

fn compact_link_state(value: &str) -> &str {
    match value {
        "LOWER_LAYER_DOWN" => "LOWER_DOWN",
        "NOT_PRESENT" => "NOT_PRESENT",
        value => value,
    }
}

fn interface_direction_summary_line(
    block: Option<&DashboardBlock<'_>>,
    lane: ResolvedLane,
    time_view: TimeView,
    width: u16,
) -> Line<'static> {
    let direction = match lane {
        ResolvedLane::Rx => "RX",
        ResolvedLane::Tx => "TX",
        ResolvedLane::Shared => unreachable!("direction summaries are RX or TX"),
    };
    let (packets, bytes, drops, errors) = match lane {
        ResolvedLane::Rx => (
            "linux.netdevice.rx_packets",
            "linux.netdevice.rx_bytes",
            "linux.netdevice.rx_dropped",
            "linux.netdevice.rx_errors",
        ),
        ResolvedLane::Tx => (
            "linux.netdevice.tx_packets",
            "linux.netdevice.tx_bytes",
            "linux.netdevice.tx_dropped",
            "linux.netdevice.tx_errors",
        ),
        ResolvedLane::Shared => unreachable!("direction summaries are RX or TX"),
    };
    let value = |metric| {
        block.map_or_else(
            || "-".to_owned(),
            |block| compact_counter_projection(block, lane, metric, time_view),
        )
    };
    let data_label = match time_view {
        TimeView::Interval => "bw",
        TimeView::SinceBaseline => "data",
    };
    let text = if width < 70 {
        format!(
            "   {direction} pkt {}  {data_label} {}  drp {}  err {}",
            value(packets),
            value(bytes),
            value(drops),
            value(errors)
        )
    } else {
        format!(
            "   {direction} packets {}  {data_label} {}  drop {}  err {}",
            value(packets),
            value(bytes),
            value(drops),
            value(errors)
        )
    };
    dashboard_data_line(&text, width)
}

fn compact_counter_projection(
    block: &DashboardBlock<'_>,
    lane: ResolvedLane,
    metric_id: &str,
    time_view: TimeView,
) -> String {
    let series = block
        .lane(lane)
        .iter()
        .filter(|placed| placed.series().metric().as_str() == metric_id)
        .map(PlacedSeries::series)
        .collect::<Vec<_>>();
    let Some(first) = series.first() else {
        return "-".to_owned();
    };
    let metric = descriptor(metric_id).expect("summary metric is catalogued");
    match time_view {
        TimeView::Interval => {
            let rate = series.iter().try_fold(0.0_f64, |total, series| {
                let SeriesValue::Counter {
                    interval: Some(continuity),
                    ..
                } = series.value()
                else {
                    return None;
                };
                continuity.rate_per_second().map(|rate| total + rate)
            });
            rate.map_or_else(
                || counter_continuity_label(first),
                |rate| compact_counter_rate(rate, metric.unit),
            )
        }
        TimeView::SinceBaseline => series
            .iter()
            .try_fold(0_u64, |total, series| {
                let SeriesValue::Counter {
                    since_baseline: Some(span),
                    ..
                } = series.value()
                else {
                    return None;
                };
                Some(total.saturating_add(span.delta()))
            })
            .map(|delta| format!("+{}", compact_counter_total(delta, metric.unit)))
            .unwrap_or_else(|| "-".to_owned()),
    }
}

fn counter_continuity_label(series: &SeriesSnapshot) -> String {
    let SeriesValue::Counter { interval, .. } = series.value() else {
        return "-".to_owned();
    };
    match interval {
        Some(CounterContinuity::Reset) => "reset".to_owned(),
        Some(CounterContinuity::RecoveredAfterGap) => "gap".to_owned(),
        Some(CounterContinuity::FirstSample) | None => "-".to_owned(),
        Some(CounterContinuity::Continuous { .. } | CounterContinuity::Wrapped { .. }) => {
            "-".to_owned()
        }
    }
}

fn compact_counter_rate(rate: f64, unit: MetricUnit) -> String {
    if unit == MetricUnit::Bytes {
        compact_scaled(
            rate * 8.0,
            &["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"],
        )
    } else {
        compact_scaled(rate, &["/s", "k/s", "M/s", "G/s", "T/s"])
    }
}

fn compact_counter_total(value: u64, unit: MetricUnit) -> String {
    let suffixes: &[&str] = if unit == MetricUnit::Bytes {
        &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
    } else {
        &["", "k", "M", "G", "T", "P", "E"]
    };
    let base = if unit == MetricUnit::Bytes {
        1024.0
    } else {
        1000.0
    };
    compact_scaled_with_base(value as f64, suffixes, base)
}

fn compact_scaled(value: f64, suffixes: &[&str]) -> String {
    compact_scaled_with_base(value, suffixes, 1000.0)
}

fn compact_scaled_with_base(mut value: f64, suffixes: &[&str], base: f64) -> String {
    let mut index = 0;
    while value.abs() >= base && index + 1 < suffixes.len() {
        value /= base;
        index += 1;
    }
    let number = if value.abs() >= 100.0 || value.fract().abs() < 0.05 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    };
    format!("{number}{}", suffixes[index])
}

fn global_layer_detail_lines(
    snapshot: &MonitorSnapshot,
    kind: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> Vec<Line<'static>> {
    let dashboard = build_dashboard_for_interfaces(snapshot, &[]);
    let block = dashboard
        .blocks()
        .iter()
        .find(|block| block.key().kind() == kind)
        .expect("dashboard seeds every overview layer");
    let mut lines = global_block_lines(
        snapshot,
        block,
        overview_layer_title(kind),
        display,
        width,
        false,
    );
    if kind == BlockKind::ExecutionContext(ExecutionContext::Softirq) {
        append_softirq_cpu_matrix(&mut lines, snapshot, block, display, width);
    } else {
        append_block_detail_series(&mut lines, block, display, width);
    }
    lines
}

#[cfg(test)]
fn softirq_section_lines(
    snapshot: &MonitorSnapshot,
    time_view: TimeView,
    width: u16,
) -> Vec<Line<'static>> {
    SoftirqSection::new_with_options(
        snapshot,
        width,
        DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
        SoftirqSort::Cpu,
        false,
    )
    .visible_lines(snapshot, time_view, 0, usize::MAX)
}

fn append_softirq_cpu_matrix(
    lines: &mut Vec<Line<'static>>,
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
    display: DetailDisplayOptions,
    width: u16,
) {
    let (header, rows, columns, widths) = softirq_matrix_parts(snapshot, block, display, width);
    lines.extend(header);
    if !columns.is_empty() {
        lines.extend(rows.into_iter().map(|(cpu, row)| {
            softirq_matrix_row(cpu, &row, &columns, &widths, display.time_view, width)
        }));
    }
}

type SoftirqRows<'a> = BTreeMap<u32, [Option<&'a SeriesSnapshot>; SOFTIRQ_COLUMNS.len()]>;
type SoftirqMatrixParts<'a> = (
    Vec<Line<'static>>,
    SoftirqRows<'a>,
    Vec<(usize, &'static SoftirqColumn)>,
    Vec<usize>,
);

fn softirq_matrix_parts<'a>(
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'a>,
    display: DetailDisplayOptions,
    width: u16,
) -> SoftirqMatrixParts<'a> {
    let mut lines = Vec::new();
    append_softirq_notes(&mut lines, snapshot, block, display.metrics_mode, width);
    let rows = softirq_cpu_rows(block);
    let mut columns = SOFTIRQ_COLUMNS
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            display.metrics_mode == DetailMetricsMode::All
                || rows
                    .values()
                    .filter_map(|row| row[*index])
                    .any(series_has_detail_data)
        })
        .collect::<Vec<_>>();
    let indent = softirq_matrix_indent(width);
    while !columns.is_empty()
        && usize::from(width) < indent.saturating_add(3 + columns.len().saturating_mul(2))
    {
        columns.pop();
    }

    let heading = match display.metrics_mode {
        DetailMetricsMode::WithData => format!(
            "   PER-CPU STATISTICS WITH DATA  {}/{} metrics  {} CPUs",
            columns.len(),
            SOFTIRQ_COLUMNS.len(),
            rows.len()
        ),
        DetailMetricsMode::All => format!(
            "   ALL STATISTICS  PER-CPU  {} metrics  {} CPUs",
            columns.len(),
            rows.len()
        ),
    };
    lines.push(
        Line::from(fit_cell(&heading, usize::from(width))).style(
            Style::default()
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
    );

    if rows.is_empty() {
        lines.push(
            Line::from(fit_cell("   NO PER-CPU SOFTIRQ DATA", usize::from(width)))
                .style(Style::default().fg(theme::MUTED)),
        );
        return (lines, rows, Vec::new(), Vec::new());
    }
    if columns.is_empty() {
        lines.push(
            Line::from(fit_cell(
                "   NO NON-ZERO PER-CPU STATISTICS",
                usize::from(width),
            ))
            .style(Style::default().fg(theme::MUTED)),
        );
        return (lines, rows, columns, Vec::new());
    }

    let widths = softirq_matrix_widths(width, &columns);
    lines.push(softirq_matrix_header(&columns, &widths, width));
    (lines, rows, columns, widths)
}

fn append_softirq_notes(
    lines: &mut Vec<Line<'static>>,
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
    metrics_mode: DetailMetricsMode,
    width: u16,
) {
    if width < 30 {
        return;
    }
    let width = usize::from(width);
    let split = width >= 120;
    let config_width = if split { (width - 1) / 2 } else { width };
    let meaning_width = if split {
        width - config_width - 1
    } else {
        width
    };
    let mut config = Vec::new();
    append_softirq_coalescing_config(&mut config, block, metrics_mode, (config_width - 4) as u16);
    let health = |source: &str| {
        snapshot
            .providers()
            .iter()
            .find(|provider| provider.provider().as_str() == source)
            .map_or("missing", |provider| provider.health().as_str())
    };
    let notes = [
        "RX/TX calls; P packets processed; RP RPS triggers.",
        "D: drops; S: budget/time exhausted; FL: flow-limit.",
        "/s: rate; +: span delta; BL/IQ/PQ: current queues.",
    ];
    let sources = format!(
        "Sources: softirqs {}; softnet {}; sysctl {}",
        health(SOFTIRQ_SOURCE),
        health(SOFTNET_SOURCE),
        health(SOFTIRQ_CONFIG_SOURCE)
    );
    let meanings = notes
        .into_iter()
        .chain(std::iter::once(sources.as_str()))
        .flat_map(|text| super::socket::wrap_text(text, meaning_width - 4))
        .map(|text| Line::styled(text, Style::default().fg(theme::TEXT)))
        .collect::<Vec<_>>();
    if split && !config.is_empty() {
        lines.extend(detail_block::side_by_side(vec![
            (
                config_width,
                detail_block::framed_lines("CONFIGURATION", theme::SOFTIRQ, config, config_width),
            ),
            (
                meaning_width,
                detail_block::framed_lines(
                    "MEANING / SOURCES",
                    theme::SOFTIRQ,
                    meanings,
                    meaning_width,
                ),
            ),
        ]));
    } else {
        let title = if config.is_empty() {
            "MEANING / SOURCES"
        } else {
            "CONFIG / MEANING"
        };
        config.extend(meanings);
        lines.extend(detail_block::framed_lines(
            title,
            theme::SOFTIRQ,
            config,
            width,
        ));
    }
}

fn append_softirq_coalescing_config(
    lines: &mut Vec<Line<'static>>,
    block: &DashboardBlock<'_>,
    metrics_mode: DetailMetricsMode,
    width: u16,
) {
    let item = |label: &str, metric: &str, suffix: &str| {
        softirq_config_value(block, metric)
            .map(|value| format!("{label} {value}{suffix}"))
            .or_else(|| (metrics_mode == DetailMetricsMode::All).then(|| format!("{label} -")))
    };
    let coalescing = [
        item("packet budget", "linux.softirq.config.netdev_budget", ""),
        item(
            "time budget",
            "linux.softirq.config.netdev_budget_usecs",
            " us",
        ),
        item("device weight", "linux.softirq.config.dev_weight", ""),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let backlog = item(
        "per-CPU maximum",
        "linux.softirq.config.netdev_max_backlog",
        "",
    )
    .into_iter()
    .collect::<Vec<_>>();

    lines.extend(dashboard_group_lines("BUDGET", &coalescing, width));
    lines.extend(dashboard_group_lines("BACKLOG", &backlog, width));
}

fn softirq_config_value(block: &DashboardBlock<'_>, metric: &str) -> Option<String> {
    let series = block
        .shared()
        .iter()
        .map(PlacedSeries::series)
        .find(|series| series.metric().as_str() == metric)?;
    let SeriesValue::Gauge { current, .. } = series.value() else {
        return None;
    };
    match current {
        ProjectedValue::Fresh { value, .. } => Some(value.to_string()),
        ProjectedValue::Stale { last, .. } => Some(format!("~{last}")),
        ProjectedValue::Unavailable { .. } => None,
    }
}

fn dashboard_group_lines(label: &str, values: &[String], width: u16) -> Vec<Line<'static>> {
    if values.is_empty() {
        return Vec::new();
    }
    let prefix = format!("   {label} ");
    let continuation = " ".repeat(prefix.chars().count());
    let maximum = usize::from(width);
    let mut current = prefix.clone();
    let mut lines = Vec::new();
    for value in values {
        let separator = if current == prefix { "" } else { " | " };
        if current != prefix
            && current
                .chars()
                .count()
                .saturating_add(separator.len())
                .saturating_add(value.chars().count())
                > maximum
        {
            lines.push(dashboard_data_line(&current, width));
            current = continuation.clone();
            current.push_str(value);
        } else {
            current.push_str(separator);
            current.push_str(value);
        }
    }
    lines.push(dashboard_data_line(&current, width));
    lines
}

fn softirq_cpu_rows<'a>(
    block: &DashboardBlock<'a>,
) -> BTreeMap<u32, [Option<&'a SeriesSnapshot>; SOFTIRQ_COLUMNS.len()]> {
    let mut rows = BTreeMap::new();
    for series in block
        .rx()
        .iter()
        .chain(block.tx())
        .chain(block.shared())
        .map(PlacedSeries::series)
    {
        let Some(column) = SOFTIRQ_COLUMNS
            .iter()
            .position(|column| column.metric == series.metric().as_str())
        else {
            continue;
        };
        let Some(cpu) = series
            .labels()
            .get(MetricLabel::Cpu)
            .and_then(|cpu| cpu.parse::<u32>().ok())
        else {
            continue;
        };
        rows.entry(cpu).or_insert([None; SOFTIRQ_COLUMNS.len()])[column] = Some(series);
    }
    rows
}

fn softirq_matrix_indent(width: u16) -> usize {
    if width >= 20 {
        3
    } else {
        0
    }
}

fn softirq_matrix_widths(width: u16, columns: &[(usize, &SoftirqColumn)]) -> Vec<usize> {
    let indent = softirq_matrix_indent(width);
    let metric_columns = columns.len();
    let available = usize::from(width).saturating_sub(indent.saturating_add(metric_columns));
    let cpu_width = 5.min(available.saturating_sub(metric_columns));
    let mut widths = vec![cpu_width];
    let metric_width = available.saturating_sub(cpu_width);
    let mut metric_widths = columns
        .iter()
        .map(|(_, column)| softirq_column_label(column, width).chars().count() + 1)
        .collect::<Vec<_>>();
    let minimum = metric_widths.iter().sum::<usize>();
    if minimum <= metric_width {
        let extra = metric_width - minimum;
        for (index, column_width) in metric_widths.iter_mut().enumerate() {
            *column_width += extra / metric_columns + usize::from(index < extra % metric_columns);
        }
    } else {
        let base = metric_width.checked_div(metric_columns).unwrap_or(0);
        let remainder = metric_width.saturating_sub(base.saturating_mul(metric_columns));
        metric_widths = (0..metric_columns)
            .map(|index| base + usize::from(index < remainder))
            .collect();
    }
    widths.extend(metric_widths);
    widths
}

fn softirq_column_label(column: &SoftirqColumn, width: u16) -> String {
    let label = if width < 100 {
        column.narrow_label
    } else if width < 140 {
        column.compact_label
    } else {
        column.label
    };
    match column.projection {
        SoftirqProjection::Rate => format!("{label}/s"),
        SoftirqProjection::Delta => format!("{label}+"),
        SoftirqProjection::Current => label.to_owned(),
    }
}

fn softirq_matrix_header(
    columns: &[(usize, &SoftirqColumn)],
    widths: &[usize],
    width: u16,
) -> Line<'static> {
    softirq_sorted_header(columns, widths, width, SoftirqSort::Cpu, false)
}

fn softirq_sorted_header(
    columns: &[(usize, &SoftirqColumn)],
    widths: &[usize],
    width: u16,
    sort: SoftirqSort,
    descending: bool,
) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(softirq_matrix_indent(width)))];
    spans.push(Span::styled(
        sort_table::pad(
            &sort_table::label(
                "CPU",
                widths[0],
                (sort == SoftirqSort::Cpu).then_some(descending),
            ),
            widths[0],
            false,
        ),
        sort_table::header_style(sort == SoftirqSort::Cpu, theme::TEXT_STRONG),
    ));
    for (position, (index, column)) in columns.iter().enumerate() {
        spans.push(sort_table::divider());
        let label = softirq_column_label(column, width);
        spans.push(Span::styled(
            sort_table::pad(
                &sort_table::label(
                    &label,
                    widths[position + 1],
                    (sort == SoftirqSort::Metric(*index)).then_some(descending),
                ),
                widths[position + 1],
                true,
            ),
            sort_table::header_style(
                sort == SoftirqSort::Metric(*index),
                softirq_header_style(column).fg.unwrap_or(theme::TEXT),
            ),
        ));
    }
    Line::from(spans)
}

fn softirq_matrix_row(
    cpu: u32,
    row: &[Option<&SeriesSnapshot>; SOFTIRQ_COLUMNS.len()],
    columns: &[(usize, &SoftirqColumn)],
    widths: &[usize],
    time_view: TimeView,
    width: u16,
) -> Line<'static> {
    let mut spans = vec![Span::raw(" ".repeat(softirq_matrix_indent(width)))];
    spans.push(Span::styled(
        fit_cell(&cpu.to_string(), widths[0]),
        Style::default().fg(theme::TEXT_STRONG),
    ));
    for (position, (index, column)) in columns.iter().enumerate() {
        spans.push(sort_table::divider());
        let value = row[*index].map_or_else(
            || "-".to_owned(),
            |series| softirq_matrix_value(series, column.projection, time_view),
        );
        let style = row[*index].map_or_else(
            || Style::default().fg(theme::MUTED),
            |series| softirq_cell_style(series, column, &value),
        );
        spans.push(Span::styled(
            fit_right_cell(&value, widths[position + 1]),
            style,
        ));
    }
    Line::from(spans)
}

fn softirq_matrix_value(
    series: &SeriesSnapshot,
    projection: SoftirqProjection,
    time_view: TimeView,
) -> String {
    if matches!(projection, SoftirqProjection::Current) {
        let SeriesValue::Gauge { current, .. } = series.value() else {
            return "-".to_owned();
        };
        let metric = series
            .metric()
            .descriptor()
            .expect("SoftIRQ metric is catalogued");
        return match current {
            ProjectedValue::Fresh { value, .. } => compact_counter_total(*value, metric.unit),
            ProjectedValue::Stale { .. } => "stale".to_owned(),
            ProjectedValue::Unavailable { .. } => "-".to_owned(),
        };
    }
    let SeriesValue::Counter {
        current,
        interval,
        since_baseline,
    } = series.value()
    else {
        return "-".to_owned();
    };
    match current {
        ProjectedValue::Stale { .. } => return "stale".to_owned(),
        ProjectedValue::Unavailable { .. } => return "-".to_owned(),
        ProjectedValue::Fresh { .. } => {}
    }
    let metric = series
        .metric()
        .descriptor()
        .expect("SoftIRQ metric is catalogued");
    match (time_view, projection) {
        (TimeView::Interval, SoftirqProjection::Rate) => interval
            .as_ref()
            .and_then(|continuity| continuity.rate_per_second())
            .map_or_else(
                || counter_continuity_label(series),
                |rate| compact_counter_rate(rate, metric.unit),
            ),
        (TimeView::Interval, SoftirqProjection::Delta) => interval
            .as_ref()
            .and_then(softirq_continuity_delta)
            .map_or_else(
                || counter_continuity_label(series),
                |delta| format!("+{}", compact_counter_total(delta, metric.unit)),
            ),
        (TimeView::SinceBaseline, SoftirqProjection::Rate) => since_baseline
            .as_ref()
            .map(|span| compact_counter_rate(span.rate_per_second(), metric.unit))
            .unwrap_or_else(|| counter_continuity_label(series)),
        (TimeView::SinceBaseline, SoftirqProjection::Delta) => since_baseline
            .as_ref()
            .map(|span| format!("+{}", compact_counter_total(span.delta(), metric.unit)))
            .unwrap_or_else(|| counter_continuity_label(series)),
        (_, SoftirqProjection::Current) => unreachable!("current gauges return above"),
    }
}

fn softirq_continuity_delta(continuity: &CounterContinuity) -> Option<u64> {
    match continuity {
        CounterContinuity::Continuous { delta, .. } | CounterContinuity::Wrapped { delta, .. } => {
            Some(*delta)
        }
        CounterContinuity::FirstSample
        | CounterContinuity::Reset
        | CounterContinuity::RecoveredAfterGap => None,
    }
}

fn softirq_header_style(column: &SoftirqColumn) -> Style {
    match column.metric {
        "linux.softirq.net_tx" => Style::default().fg(theme::TX),
        "linux.softirq.net_rx"
        | "linux.softirq.softnet.processed"
        | "linux.softirq.softnet.received_rps" => Style::default().fg(theme::RX),
        _ => Style::default().fg(theme::TEXT),
    }
}

fn softirq_cell_style(series: &SeriesSnapshot, column: &SoftirqColumn, value: &str) -> Style {
    let current = match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => current,
        SeriesValue::State { .. } => return Style::default().fg(theme::MUTED),
    };
    match current {
        ProjectedValue::Stale { .. } => return Style::default().fg(theme::WARN),
        ProjectedValue::Unavailable { .. } => return Style::default().fg(theme::MUTED),
        ProjectedValue::Fresh { .. } => {}
    }
    if matches!(value, "reset" | "gap") {
        return Style::default().fg(theme::WARN);
    }
    if matches!(column.projection, SoftirqProjection::Delta)
        && value.starts_with('+')
        && value != "+0"
    {
        let metric = series
            .metric()
            .descriptor()
            .expect("SoftIRQ metric is catalogued");
        return metric_style(metric.display);
    }
    softirq_header_style(column)
}

fn fit_right_cell(value: &str, width: usize) -> String {
    let value = truncate_component(value, width);
    format!(
        "{}{}",
        " ".repeat(width.saturating_sub(value.chars().count())),
        value
    )
}

fn interface_detail_lines(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    selected_layer: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> Vec<Line<'static>> {
    if !interface_is_observed(snapshot, identity) {
        return unavailable_interface_lines(identity, width);
    }

    let dashboard = build_dashboard_for_interfaces(snapshot, std::slice::from_ref(identity));
    let mut lines = Vec::new();
    lines.extend(interface_detail::identity_lines(snapshot, identity, width));
    for kind in INTERFACE_BLOCK_KINDS {
        let block = interface_block(&dashboard, identity, kind)
            .expect("dashboard seeds every stage for a discovered interface");
        lines.extend(interface_detail::stage_lines(
            snapshot,
            block,
            kind,
            display,
            width,
            kind == selected_layer,
        ));
    }
    lines
}

fn interface_layer_detail_lines(
    snapshot: &MonitorSnapshot,
    identity: &InterfaceIdentity,
    layer: BlockKind,
    display: DetailDisplayOptions,
    width: u16,
) -> Vec<Line<'static>> {
    if !interface_is_observed(snapshot, identity) {
        return unavailable_interface_lines(identity, width);
    }

    let dashboard = build_dashboard_for_interfaces(snapshot, std::slice::from_ref(identity));
    let block = interface_block(&dashboard, identity, layer)
        .expect("dashboard seeds every stage for a discovered interface");
    let mut lines = Vec::new();
    lines.extend(interface_detail::identity_lines(snapshot, identity, width));
    lines.extend(interface_detail::stage_lines(
        snapshot, block, layer, display, width, false,
    ));
    lines.extend(interface_detail::series_lines(block, display, width));
    lines
}

fn unavailable_interface_lines(identity: &InterfaceIdentity, width: u16) -> Vec<Line<'static>> {
    interface_detail::unavailable_lines(identity, width)
}

fn append_block_detail_series(
    lines: &mut Vec<Line<'static>>,
    block: &DashboardBlock<'_>,
    display: DetailDisplayOptions,
    width: u16,
) {
    let visible_series_count = block
        .rx()
        .iter()
        .chain(block.tx())
        .chain(block.shared())
        .map(PlacedSeries::series)
        .filter(|series| {
            display.metrics_mode == DetailMetricsMode::All || series_has_detail_data(series)
        })
        .count();
    if visible_series_count == 0 && display.metrics_mode == DetailMetricsMode::WithData {
        return;
    }

    let heading = match display.metrics_mode {
        DetailMetricsMode::WithData => format!(
            "   STATISTICS WITH DATA  {visible_series_count}/{} series",
            block.series_count()
        ),
        DetailMetricsMode::All => format!("   ALL STATISTICS  {} series", block.series_count()),
    };
    lines.push(
        Line::from(fit_cell(&heading, usize::from(width))).style(
            Style::default()
                .fg(theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
    );
    if block.series_count() == 0 {
        lines.push(
            Line::from(fit_cell("    - no collected series", usize::from(width)))
                .style(Style::default().fg(theme::MUTED)),
        );
        return;
    }
    for (lane, placed) in [
        ("RX", block.rx()),
        ("TX", block.tx()),
        ("KEY", block.shared()),
    ] {
        for series in placed.iter().map(PlacedSeries::series).filter(|series| {
            display.metrics_mode == DetailMetricsMode::All || series_has_detail_data(series)
        }) {
            lines.extend(interface_detail_series_lines(
                lane,
                series,
                display.time_view,
                width,
            ));
        }
    }
}

fn interface_detail_series_lines(
    lane: &str,
    series: &SeriesSnapshot,
    time_view: TimeView,
    width: u16,
) -> Vec<Line<'static>> {
    let metric = series
        .metric()
        .descriptor()
        .expect("dashboard series is catalogued");
    let title = format_series_title(series, metric);
    let (current, interval, since, state) = format_series(series, metric);
    let (projection_label, projection) = match time_view {
        TimeView::Interval => ("interval".to_owned(), interval),
        TimeView::SinceBaseline => (
            format!(
                "baseline({})",
                baseline_origin_label(series.baseline_origin())
            ),
            since,
        ),
    };
    let style = detail_series_style(series, metric);
    let columns = [
        format!("{lane} {title}"),
        format!("current {current}"),
        format!("{projection_label} {projection}"),
        state.to_owned(),
        format!("source {}", series.source().as_str()),
    ];
    let styles = [
        style,
        style,
        style,
        detail_state_style(state),
        Style::default().fg(theme::MUTED),
    ];
    if width >= WIDE_DETAIL_COLUMNS_WIDTH {
        return aligned_detail_cells(
            &columns.iter().map(String::as_str).collect::<Vec<_>>(),
            &styles,
            &wide_detail_column_widths(width),
            DETAIL_ROW_INDENT,
            Some(lane),
        );
    }
    if width >= MEDIUM_DETAIL_COLUMNS_WIDTH {
        return medium_detail_series_lines(&columns, &styles, width, lane);
    }
    compact_detail_series_lines(&columns, &styles, width, lane)
}

fn detail_lane_style(lane: &str) -> Style {
    match lane {
        "RX" => Style::default().fg(theme::RX).add_modifier(Modifier::BOLD),
        "TX" => Style::default().fg(theme::TX).add_modifier(Modifier::BOLD),
        _ => Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    }
}

fn detail_state_style(state: &str) -> Style {
    match state {
        "fresh" => Style::default().fg(theme::GOOD),
        "stale" => Style::default().fg(theme::WARN),
        _ => Style::default().fg(theme::MUTED),
    }
}

fn detail_series_style(series: &SeriesSnapshot, metric: &MetricDescriptor) -> Style {
    let fresh = metric_style(metric.display);
    match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            projected_detail_style(current, fresh)
        }
        SeriesValue::State { current, .. } => projected_detail_style(current, fresh),
    }
}

fn projected_detail_style<T>(current: &ProjectedValue<T>, fresh: Style) -> Style {
    match current {
        ProjectedValue::Fresh { .. } => fresh,
        ProjectedValue::Stale { .. } => Style::default().fg(theme::WARN),
        ProjectedValue::Unavailable { .. } => Style::default().fg(theme::MUTED),
    }
}

fn wide_detail_column_widths(width: u16) -> [usize; 5] {
    let separators = DETAIL_COLUMN_SEPARATOR.len().saturating_mul(4);
    let available = usize::from(width)
        .saturating_sub(DETAIL_ROW_INDENT)
        .saturating_sub(separators);
    let extra = available.saturating_sub(144);
    let metric = 33_usize.saturating_add(extra.saturating_mul(2) / 5);
    let current = 17;
    let projection = 24_usize.saturating_add(extra / 5);
    let state = 11;
    let source = available.saturating_sub(
        metric
            .saturating_add(current)
            .saturating_add(projection)
            .saturating_add(state),
    );
    [metric, current, projection, state, source]
}

fn medium_detail_series_lines(
    columns: &[String; 5],
    styles: &[Style; 5],
    width: u16,
    lane: &str,
) -> Vec<Line<'static>> {
    let separators = DETAIL_COLUMN_SEPARATOR.len().saturating_mul(2);
    let available = usize::from(width)
        .saturating_sub(DETAIL_ROW_INDENT)
        .saturating_sub(separators);
    let first = available.saturating_mul(34) / 100;
    let second = available.saturating_mul(22) / 100;
    let widths = [
        first,
        second,
        available.saturating_sub(first.saturating_add(second)),
    ];
    let mut lines = aligned_detail_cells(
        &[
            columns[0].as_str(),
            columns[1].as_str(),
            columns[2].as_str(),
        ],
        &[styles[0], styles[1], styles[2]],
        &widths,
        DETAIL_ROW_INDENT,
        Some(lane),
    );
    lines.extend(aligned_detail_cells(
        &[columns[3].as_str(), columns[4].as_str()],
        &[styles[3], styles[4]],
        &[first, widths[1] + DETAIL_COLUMN_SEPARATOR.len() + widths[2]],
        DETAIL_ROW_INDENT,
        None,
    ));
    lines
}

fn compact_detail_series_lines(
    columns: &[String; 5],
    styles: &[Style; 5],
    width: u16,
    lane: &str,
) -> Vec<Line<'static>> {
    let available = usize::from(width);
    if available
        <= DETAIL_ROW_INDENT
            .saturating_add(DETAIL_COLUMN_SEPARATOR.len())
            .saturating_add(2)
    {
        return wrap_detail_cell(&columns.join(DETAIL_COLUMN_SEPARATOR), available.max(1))
            .into_iter()
            .map(|value| Line::from(value).style(styles[0]))
            .collect();
    }

    let title_width = available.saturating_sub(DETAIL_ROW_INDENT);
    let mut lines = aligned_detail_cells(
        &[columns[0].as_str()],
        &[styles[0]],
        &[title_width],
        DETAIL_ROW_INDENT,
        Some(lane),
    );
    let pair_width = available
        .saturating_sub(DETAIL_ROW_INDENT)
        .saturating_sub(DETAIL_COLUMN_SEPARATOR.len());
    let left_width = pair_width / 2;
    let widths = [left_width, pair_width.saturating_sub(left_width)];
    for (left, right) in [(1, 2), (3, 4)] {
        lines.extend(aligned_detail_cells(
            &[columns[left].as_str(), columns[right].as_str()],
            &[styles[left], styles[right]],
            &widths,
            DETAIL_ROW_INDENT,
            None,
        ));
    }
    lines
}

fn aligned_detail_cells(
    values: &[&str],
    styles: &[Style],
    widths: &[usize],
    indent: usize,
    lane: Option<&str>,
) -> Vec<Line<'static>> {
    debug_assert_eq!(values.len(), styles.len());
    debug_assert_eq!(values.len(), widths.len());
    let wrapped = values
        .iter()
        .zip(widths)
        .map(|(value, width)| wrap_detail_cell(value, *width))
        .collect::<Vec<_>>();
    let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
    (0..height)
        .map(|row| {
            let mut spans = vec![Span::raw(" ".repeat(indent))];
            for column in 0..values.len() {
                let value = wrapped[column].get(row).map_or("", String::as_str);
                append_detail_cell_spans(
                    &mut spans,
                    value,
                    widths[column],
                    styles[column],
                    (column == 0 && row == 0).then_some(lane).flatten(),
                );
                if column + 1 < values.len() {
                    spans.push(Span::styled(
                        DETAIL_COLUMN_SEPARATOR,
                        Style::default().fg(theme::DIVIDER),
                    ));
                }
            }
            Line::from(spans)
        })
        .collect()
}

fn append_detail_cell_spans(
    spans: &mut Vec<Span<'static>>,
    value: &str,
    width: usize,
    style: Style,
    lane: Option<&str>,
) {
    let fitted = fit_cell(value, width);
    if let Some(lane) = lane.filter(|lane| fitted.starts_with(*lane)) {
        spans.push(Span::styled(lane.to_owned(), detail_lane_style(lane)));
        spans.push(Span::styled(
            fitted
                .chars()
                .skip(lane.chars().count())
                .collect::<String>(),
            style,
        ));
    } else {
        spans.push(Span::styled(fitted, style));
    }
}

fn wrap_detail_cell(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut remaining = value.trim_end();
    let mut lines = Vec::new();
    while !remaining.is_empty() {
        if remaining.chars().count() <= width {
            lines.push(remaining.to_owned());
            break;
        }
        let hard_end = remaining
            .char_indices()
            .nth(width)
            .map_or(remaining.len(), |(index, _)| index);
        let candidate = &remaining[..hard_end];
        let split = candidate
            .rfind(' ')
            .filter(|index| *index >= width / 2)
            .unwrap_or(hard_end);
        let chunk = remaining[..split].trim_end();
        lines.push(chunk.to_owned());
        remaining = remaining[split..].trim_start();
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn combined_network_health(values: impl IntoIterator<Item = NetworkHealth>) -> NetworkHealth {
    let mut saw_ok = false;
    let mut saw_unknown = false;
    let mut saw_warn = false;
    for value in values {
        match value {
            NetworkHealth::Crit => return NetworkHealth::Crit,
            NetworkHealth::Warn => saw_warn = true,
            NetworkHealth::Unknown => saw_unknown = true,
            NetworkHealth::Ok => saw_ok = true,
        }
    }
    if saw_warn {
        NetworkHealth::Warn
    } else if saw_unknown || !saw_ok {
        NetworkHealth::Unknown
    } else {
        NetworkHealth::Ok
    }
}

pub(super) fn interface_stage_title(kind: BlockKind) -> &'static str {
    match kind {
        BlockKind::PacketStage(PacketStage::TrafficControl) => "TC / QDISC",
        BlockKind::PacketStage(PacketStage::NetdeviceCore) => "NETDEVICE CORE",
        BlockKind::PacketStage(PacketStage::DriverNapi) => "DRIVER / NAPI",
        BlockKind::PacketStage(PacketStage::NicPhy) => "NIC / PHY",
        BlockKind::ExecutionContext(ExecutionContext::Hardirq) => "EXECUTION CONTEXT: HARDIRQ",
        BlockKind::PacketStage(
            PacketStage::SocketApplication
            | PacketStage::Transport
            | PacketStage::NetworkRoute
            | PacketStage::NetfilterConntrack,
        )
        | BlockKind::ExecutionContext(ExecutionContext::Softirq) => {
            unreachable!("global block cannot be an interface stage")
        }
    }
}

fn render_dashboard_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    lines: Vec<Line<'static>>,
    row_offset: usize,
) {
    let offset = row_offset.min(lines.len().saturating_sub(1));
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(usize::from(area.height))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), area);
}

fn starting_global_block_lines(
    kind: BlockKind,
    title: &'static str,
    width: u16,
    selected: bool,
) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(global_block_row_count(kind));
    lines.push(dashboard_title_line(
        title,
        NetworkHealth::Unknown,
        EvidenceCoverage::Partial,
        width,
        selected,
    ));
    if kind != BlockKind::PacketStage(PacketStage::NetfilterConntrack) {
        if width >= WIDE_DASHBOARD_WIDTH {
            lines.push(paired_dashboard_line(
                "  RX -".to_owned(),
                "TX -".to_owned(),
                width,
            ));
            lines.push(paired_dashboard_line(
                "  RX -".to_owned(),
                "TX -".to_owned(),
                width,
            ));
        } else {
            lines.push(dashboard_data_line("  RX -", width));
            lines.push(dashboard_data_line("  TX -", width));
        }
    }
    lines.push(dashboard_data_line("  KEY -", width));
    lines.push(
        Line::from(fit_cell("   WHY -", usize::from(width)))
            .style(Style::default().fg(theme::MUTED)),
    );
    debug_assert_eq!(lines.len(), global_block_row_count(kind));
    highlight_selected_lines(&mut lines, selected);
    lines
}

const fn global_block_row_count(kind: BlockKind) -> usize {
    if matches!(
        kind,
        BlockKind::PacketStage(PacketStage::NetfilterConntrack)
    ) {
        NETFILTER_DASHBOARD_BLOCK_ROWS
    } else {
        GLOBAL_DASHBOARD_BLOCK_ROWS
    }
}

const fn global_block_title(kind: BlockKind) -> Option<&'static str> {
    match kind {
        BlockKind::PacketStage(PacketStage::SocketApplication) => Some("SOCKET / APPLICATION"),
        BlockKind::PacketStage(PacketStage::Transport) => Some("TRANSPORT TCP / UDP"),
        BlockKind::PacketStage(PacketStage::NetworkRoute) => Some("NETWORK / ROUTE"),
        BlockKind::PacketStage(PacketStage::NetfilterConntrack) => Some("NETFILTER / CONNTRACK"),
        BlockKind::ExecutionContext(ExecutionContext::Softirq) => {
            Some("EXECUTION CONTEXT: SOFTIRQ")
        }
        BlockKind::PacketStage(
            PacketStage::TrafficControl
            | PacketStage::NetdeviceCore
            | PacketStage::DriverNapi
            | PacketStage::NicPhy,
        )
        | BlockKind::ExecutionContext(ExecutionContext::Hardirq) => None,
    }
}

fn global_block_lines(
    snapshot: &MonitorSnapshot,
    block: &DashboardBlock<'_>,
    title: &'static str,
    display: DetailDisplayOptions,
    width: u16,
    selected: bool,
) -> Vec<Line<'static>> {
    let assessment = assess_dashboard_block(snapshot, block);
    let kind = block.key().kind();
    let slots = global_metric_slots(block.key().kind());
    let mut lines = Vec::with_capacity(global_block_row_count(kind));
    lines.push(dashboard_title_line(
        title,
        assessment.health(),
        assessment.coverage(),
        width,
        selected,
    ));

    if kind != BlockKind::PacketStage(PacketStage::NetfilterConntrack) {
        if width >= WIDE_DASHBOARD_WIDTH {
            for index in 0..2 {
                let rx_slot = visible_global_slot(block, slots.rx[index], display.metrics_mode);
                let tx_slot = visible_global_slot(block, slots.tx[index], display.metrics_mode);
                let rx_value = rx_slot.map(|slot| {
                    format!(
                        "  RX {}",
                        format_metric_slot(block, Some(slot), display.time_view,)
                    )
                });
                let tx_value = tx_slot.map(|slot| {
                    format!(
                        "TX {}",
                        format_metric_slot(block, Some(slot), display.time_view,)
                    )
                });
                match (rx_value, tx_value, display.metrics_mode) {
                    (Some(rx), Some(tx), _) => lines.push(paired_dashboard_line(rx, tx, width)),
                    (Some(value), None, DetailMetricsMode::WithData)
                    | (None, Some(value), DetailMetricsMode::WithData) => {
                        lines.push(dashboard_data_line(&value, width));
                    }
                    (None, None, DetailMetricsMode::WithData) => {}
                    (rx, tx, DetailMetricsMode::All) => lines.push(paired_dashboard_line(
                        rx.unwrap_or_else(|| "  RX -".to_owned()),
                        tx.unwrap_or_else(|| "TX -".to_owned()),
                        width,
                    )),
                }
            }
        } else {
            if let Some(line) = format_lane_slots("RX", block, &slots.rx, display, 1, width) {
                lines.push(dashboard_data_line(&line, width));
            }
            if let Some(line) = format_lane_slots("TX", block, &slots.tx, display, 1, width) {
                lines.push(dashboard_data_line(&line, width));
            }
        }
    }

    if let Some(line) = format_key_slots(block, &slots.key, display, width) {
        lines.push(dashboard_data_line(&line, width));
    }
    if display.metrics_mode == DetailMetricsMode::All || !assessment.causes().is_empty() {
        lines.push(dashboard_cause_line(assessment.causes().first(), width));
    }
    if display.metrics_mode == DetailMetricsMode::All {
        debug_assert_eq!(lines.len(), global_block_row_count(kind));
    }
    highlight_selected_lines(&mut lines, selected);
    lines
}

fn visible_global_slot(
    block: &DashboardBlock<'_>,
    slot: Option<MetricSlot>,
    detail_metrics_mode: DetailMetricsMode,
) -> Option<MetricSlot> {
    slot.filter(|slot| {
        detail_metrics_mode == DetailMetricsMode::All
            || series_group_has_fresh_data(&metric_group(block, *slot))
    })
}

fn series_group_has_fresh_data(group: &[&SeriesSnapshot]) -> bool {
    !group.is_empty()
        && group.iter().all(|series| series_has_fresh_value(series))
        && group.iter().any(|series| series_has_detail_data(series))
}

fn series_has_fresh_value(series: &SeriesSnapshot) -> bool {
    match series.value() {
        SeriesValue::Counter { current, .. } | SeriesValue::Gauge { current, .. } => {
            matches!(current, ProjectedValue::Fresh { .. })
        }
        SeriesValue::State { current, .. } => {
            matches!(current, ProjectedValue::Fresh { .. })
        }
    }
}

fn series_has_detail_data(series: &SeriesSnapshot) -> bool {
    let history_has_data = || {
        series
            .history_buckets()
            .iter()
            .any(|bucket| bucket.max() != 0 || bucket.delta() != 0)
    };
    match series.value() {
        SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        } => {
            let current_has_data = match current {
                ProjectedValue::Fresh { value, .. } => *value != 0,
                ProjectedValue::Stale { last, .. } => *last != 0,
                ProjectedValue::Unavailable { .. } => return false,
            };
            current_has_data
                || matches!(
                    interval,
                    Some(
                        CounterContinuity::Continuous { delta, .. }
                            | CounterContinuity::Wrapped { delta, .. }
                    ) if *delta != 0
                )
                || since_baseline
                    .as_ref()
                    .is_some_and(|span| span.delta() != 0)
                || history_has_data()
        }
        SeriesValue::Gauge {
            current,
            interval,
            since_baseline,
        } => {
            let current_has_data = match current {
                ProjectedValue::Fresh { value, .. } => *value != 0,
                ProjectedValue::Stale { last, .. } => *last != 0,
                ProjectedValue::Unavailable { .. } => return false,
            };
            current_has_data
                || interval.as_ref().is_some_and(|change| change.delta() != 0)
                || since_baseline
                    .as_ref()
                    .is_some_and(|summary| summary.max() != 0)
                || history_has_data()
        }
        SeriesValue::State { current, .. } => matches!(
            current,
            ProjectedValue::Fresh { .. } | ProjectedValue::Stale { .. }
        ),
    }
}

fn highlight_selected_lines(lines: &mut [Line<'static>], selected: bool) {
    if selected {
        if let Some(line) = lines.first_mut() {
            *line = line.clone().style(Style::default().bg(theme::SELECTED_BG));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MetricSlot {
    lane: Lane,
    metric: &'static str,
    rank: u16,
}

const fn slot(lane: Lane, metric: &'static str, rank: u16) -> Option<MetricSlot> {
    Some(MetricSlot { lane, metric, rank })
}

#[derive(Clone, Copy)]
struct GlobalMetricSlots {
    rx: [Option<MetricSlot>; 2],
    tx: [Option<MetricSlot>; 2],
    key: [Option<MetricSlot>; 2],
}

const fn global_metric_slots(kind: BlockKind) -> GlobalMetricSlots {
    match kind {
        BlockKind::PacketStage(PacketStage::SocketApplication) => GlobalMetricSlots {
            rx: [
                slot(Lane::Rx, "linux.socket.tcp.listen_drops", 10),
                slot(Lane::Rx, "linux.socket.tcp.listen_overflows", 20),
            ],
            tx: [
                slot(Lane::Tx, "linux.socket.udp.send_buffer_errors", 30),
                None,
            ],
            key: [
                slot(Lane::Shared, "linux.socket.used", 10),
                slot(Lane::Shared, "linux.socket.tcp.current_established", 20),
            ],
        },
        BlockKind::PacketStage(PacketStage::Transport) => GlobalMetricSlots {
            rx: [
                slot(Lane::Rx, "linux.socket.tcp.segments_in", 10),
                slot(Lane::Rx, "linux.socket.udp.datagrams_in", 40),
            ],
            tx: [
                slot(Lane::Tx, "linux.socket.tcp.segments_out", 10),
                slot(Lane::Tx, "linux.socket.udp.datagrams_out", 40),
            ],
            key: [
                slot(Lane::Tx, "linux.socket.tcp.retransmitted_segments", 20),
                slot(Lane::Rx, "linux.socket.udp.input_errors", 60),
            ],
        },
        BlockKind::PacketStage(PacketStage::NetworkRoute) => GlobalMetricSlots {
            rx: [
                slot(Lane::Rx, "linux.socket.ip.delivers", 20),
                slot(Lane::Rx, "linux.socket.ipv6.delivers", 21),
            ],
            tx: [
                slot(Lane::Tx, "linux.socket.ip.output_discards", 20),
                slot(Lane::Tx, "linux.socket.ipv6.output_discards", 21),
            ],
            key: [
                slot(Lane::Rx, "linux.socket.ip.input_errors", 30),
                slot(Lane::Tx, "linux.socket.ip.output_requests", 10),
            ],
        },
        BlockKind::PacketStage(PacketStage::NetfilterConntrack) => GlobalMetricSlots {
            rx: [None, None],
            tx: [None, None],
            key: [None, None],
        },
        BlockKind::ExecutionContext(ExecutionContext::Softirq) => GlobalMetricSlots {
            rx: [
                slot(Lane::Rx, "linux.softirq.net_rx", 10),
                slot(Lane::Rx, "linux.softirq.softnet.processed", 20),
            ],
            tx: [slot(Lane::Tx, "linux.softirq.net_tx", 10), None],
            key: [
                slot(Lane::Rx, "linux.softirq.softnet.dropped", 30),
                slot(Lane::Rx, "linux.softirq.softnet.time_squeeze", 40),
            ],
        },
        BlockKind::PacketStage(
            PacketStage::TrafficControl
            | PacketStage::NetdeviceCore
            | PacketStage::DriverNapi
            | PacketStage::NicPhy,
        )
        | BlockKind::ExecutionContext(ExecutionContext::Hardirq) => GlobalMetricSlots {
            rx: [None, None],
            tx: [None, None],
            key: [None, None],
        },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceMetricSlot {
    label: &'static str,
    placement_lane: Lane,
    resolved_lane: ResolvedLane,
    metric: &'static str,
    display: DisplaySlot,
}

const fn interface_summary_slot(
    label: &'static str,
    placement_lane: Lane,
    resolved_lane: ResolvedLane,
    metric: &'static str,
    rank: u16,
) -> InterfaceMetricSlot {
    InterfaceMetricSlot {
        label,
        placement_lane,
        resolved_lane,
        metric,
        display: DisplaySlot::Summary { rank },
    }
}

const fn interface_detail_slot(
    label: &'static str,
    placement_lane: Lane,
    resolved_lane: ResolvedLane,
    metric: &'static str,
) -> InterfaceMetricSlot {
    InterfaceMetricSlot {
        label,
        placement_lane,
        resolved_lane,
        metric,
        display: DisplaySlot::Detail,
    }
}

#[derive(Clone, Copy)]
struct InterfaceStageSlots {
    rx: &'static [InterfaceMetricSlot],
    tx: &'static [InterfaceMetricSlot],
    key: &'static [InterfaceMetricSlot],
}

const EMPTY_INTERFACE_SLOTS: [InterfaceMetricSlot; 0] = [];
const TC_RX_SLOTS: [InterfaceMetricSlot; 5] = [
    interface_summary_slot(
        "drop",
        Lane::FromLabel,
        ResolvedLane::Rx,
        "linux.tc.drops",
        30,
    ),
    interface_summary_slot(
        "backlog",
        Lane::FromLabel,
        ResolvedLane::Rx,
        "linux.tc.backlog_bytes",
        70,
    ),
    interface_summary_slot(
        "over",
        Lane::FromLabel,
        ResolvedLane::Rx,
        "linux.tc.overlimits",
        40,
    ),
    interface_summary_slot(
        "requeue",
        Lane::FromLabel,
        ResolvedLane::Rx,
        "linux.tc.requeues",
        50,
    ),
    interface_summary_slot(
        "packets",
        Lane::FromLabel,
        ResolvedLane::Rx,
        "linux.tc.packets",
        10,
    ),
];
const TC_TX_SLOTS: [InterfaceMetricSlot; 5] = [
    interface_summary_slot(
        "drop",
        Lane::FromLabel,
        ResolvedLane::Tx,
        "linux.tc.drops",
        30,
    ),
    interface_summary_slot(
        "backlog",
        Lane::FromLabel,
        ResolvedLane::Tx,
        "linux.tc.backlog_bytes",
        70,
    ),
    interface_summary_slot(
        "over",
        Lane::FromLabel,
        ResolvedLane::Tx,
        "linux.tc.overlimits",
        40,
    ),
    interface_summary_slot(
        "requeue",
        Lane::FromLabel,
        ResolvedLane::Tx,
        "linux.tc.requeues",
        50,
    ),
    interface_summary_slot(
        "packets",
        Lane::FromLabel,
        ResolvedLane::Tx,
        "linux.tc.packets",
        10,
    ),
];
const NETDEVICE_RX_SLOTS: [InterfaceMetricSlot; 4] = [
    interface_summary_slot(
        "drop",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.netdevice.rx_dropped",
        40,
    ),
    interface_summary_slot(
        "err",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.netdevice.rx_errors",
        30,
    ),
    interface_summary_slot(
        "packets",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.netdevice.rx_packets",
        10,
    ),
    interface_summary_slot(
        "bytes",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.netdevice.rx_bytes",
        20,
    ),
];
const NETDEVICE_TX_SLOTS: [InterfaceMetricSlot; 4] = [
    interface_summary_slot(
        "drop",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.netdevice.tx_dropped",
        40,
    ),
    interface_summary_slot(
        "err",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.netdevice.tx_errors",
        30,
    ),
    interface_summary_slot(
        "packets",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.netdevice.tx_packets",
        10,
    ),
    interface_summary_slot(
        "bytes",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.netdevice.tx_bytes",
        20,
    ),
];
const DRIVER_RX_SLOTS: [InterfaceMetricSlot; 2] = [
    interface_summary_slot(
        "missed",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.nic.rx_missed_errors",
        30,
    ),
    interface_summary_slot(
        "fifo",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.nic.rx_fifo_errors",
        20,
    ),
];
const DRIVER_TX_SLOTS: [InterfaceMetricSlot; 2] = [
    interface_detail_slot(
        "fifo",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.nic.tx_fifo_errors",
    ),
    interface_detail_slot(
        "abort",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.nic.tx_aborted_errors",
    ),
];
const DRIVER_KEY_SLOTS: [InterfaceMetricSlot; 1] = [interface_summary_slot(
    "ring_drop",
    Lane::Shared,
    ResolvedLane::Shared,
    "linux.nic.ring_drops",
    10,
)];
const NIC_RX_SLOTS: [InterfaceMetricSlot; 2] = [
    interface_summary_slot(
        "crc",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.nic.rx_crc_errors",
        20,
    ),
    interface_summary_slot(
        "pause",
        Lane::Rx,
        ResolvedLane::Rx,
        "linux.nic.pause.rx_frames",
        10,
    ),
];
const NIC_TX_SLOTS: [InterfaceMetricSlot; 2] = [
    interface_summary_slot(
        "carrier_err",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.nic.tx_carrier_errors",
        20,
    ),
    interface_summary_slot(
        "pause",
        Lane::Tx,
        ResolvedLane::Tx,
        "linux.nic.pause.tx_frames",
        10,
    ),
];
const NIC_KEY_SLOTS: [InterfaceMetricSlot; 4] = [
    interface_summary_slot(
        "link",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.nic.link_state",
        10,
    ),
    interface_summary_slot(
        "fec_bad",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.nic.fec.uncorrectable",
        40,
    ),
    interface_summary_slot(
        "fec_ok",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.nic.fec.corrected",
        30,
    ),
    interface_summary_slot(
        "carrier_chg",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.nic.carrier_changes",
        20,
    ),
];
const HARDIRQ_KEY_SLOTS: [InterfaceMetricSlot; 3] = [
    interface_summary_slot(
        "irq",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.hardirq.network_interrupts",
        10,
    ),
    interface_summary_slot(
        "imbalance",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.hardirq.imbalance",
        20,
    ),
    interface_summary_slot(
        "affinity",
        Lane::Shared,
        ResolvedLane::Shared,
        "linux.hardirq.affinity",
        30,
    ),
];

const fn interface_stage_slots(kind: BlockKind) -> InterfaceStageSlots {
    match kind {
        BlockKind::PacketStage(PacketStage::TrafficControl) => InterfaceStageSlots {
            rx: &TC_RX_SLOTS,
            tx: &TC_TX_SLOTS,
            key: &EMPTY_INTERFACE_SLOTS,
        },
        BlockKind::PacketStage(PacketStage::NetdeviceCore) => InterfaceStageSlots {
            rx: &NETDEVICE_RX_SLOTS,
            tx: &NETDEVICE_TX_SLOTS,
            key: &EMPTY_INTERFACE_SLOTS,
        },
        BlockKind::PacketStage(PacketStage::DriverNapi) => InterfaceStageSlots {
            rx: &DRIVER_RX_SLOTS,
            tx: &DRIVER_TX_SLOTS,
            key: &DRIVER_KEY_SLOTS,
        },
        BlockKind::PacketStage(PacketStage::NicPhy) => InterfaceStageSlots {
            rx: &NIC_RX_SLOTS,
            tx: &NIC_TX_SLOTS,
            key: &NIC_KEY_SLOTS,
        },
        BlockKind::ExecutionContext(ExecutionContext::Hardirq) => InterfaceStageSlots {
            rx: &EMPTY_INTERFACE_SLOTS,
            tx: &EMPTY_INTERFACE_SLOTS,
            key: &HARDIRQ_KEY_SLOTS,
        },
        BlockKind::PacketStage(
            PacketStage::SocketApplication
            | PacketStage::Transport
            | PacketStage::NetworkRoute
            | PacketStage::NetfilterConntrack,
        )
        | BlockKind::ExecutionContext(ExecutionContext::Softirq) => InterfaceStageSlots {
            rx: &EMPTY_INTERFACE_SLOTS,
            tx: &EMPTY_INTERFACE_SLOTS,
            key: &EMPTY_INTERFACE_SLOTS,
        },
    }
}

fn interface_metric_group<'a>(
    block: &DashboardBlock<'a>,
    slot: InterfaceMetricSlot,
) -> Vec<&'a SeriesSnapshot> {
    if slot.metric == "linux.hardirq.network_interrupts" {
        let compact: Vec<_> = block
            .lane(slot.resolved_lane)
            .iter()
            .map(PlacedSeries::series)
            .filter(|series| {
                series.metric().as_str() == "linux.hardirq.interface_interrupts"
                    && matches!(
                        series.value(),
                        SeriesValue::Counter {
                            current: ProjectedValue::Fresh { .. },
                            ..
                        }
                    )
            })
            .collect();
        if !compact.is_empty() {
            return compact;
        }
    }
    debug_assert!(descriptor(slot.metric)
        .and_then(placement_for)
        .is_some_and(|placement| {
            placement.block_kind() == block.key().kind()
                && placement.lane() == slot.placement_lane
                && placement.display() == slot.display
        }));
    block
        .lane(slot.resolved_lane)
        .iter()
        .filter(|placed| placed.series().metric().as_str() == slot.metric)
        .map(PlacedSeries::series)
        .collect()
}

const NETFILTER_KEY_SLOTS: [MetricSlot; 5] = [
    MetricSlot {
        lane: Lane::Shared,
        metric: "linux.netfilter.conntrack.count",
        rank: 10,
    },
    MetricSlot {
        lane: Lane::Shared,
        metric: "linux.netfilter.conntrack.maximum",
        rank: 20,
    },
    MetricSlot {
        lane: Lane::Shared,
        metric: "linux.netfilter.conntrack.utilization",
        rank: 30,
    },
    MetricSlot {
        lane: Lane::Shared,
        metric: "linux.netfilter.conntrack.invalid",
        rank: 40,
    },
    MetricSlot {
        lane: Lane::Shared,
        metric: "linux.netfilter.conntrack.drop",
        rank: 60,
    },
];

fn dashboard_title_line(
    title: &str,
    health: NetworkHealth,
    coverage: EvidenceCoverage,
    width: u16,
    selected: bool,
) -> Line<'static> {
    let marker = if selected { ">" } else { " " };
    let prefix_width = 3_usize
        .saturating_add(title.chars().count())
        .saturating_add(1);
    let status_width = health
        .as_str()
        .len()
        .saturating_add(coverage.as_str().len())
        .saturating_add(5);
    let divider_width =
        usize::from(width).saturating_sub(prefix_width.saturating_add(status_width));
    let divider = if divider_width == 0 {
        String::new()
    } else {
        format!("{} ", "─".repeat(divider_width.saturating_sub(1)))
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(
            marker,
            Style::default().fg(if selected {
                theme::ACCENT
            } else {
                theme::MUTED
            }),
        ),
        Span::raw(" "),
        Span::styled(
            format!("{title} "),
            Style::default()
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(divider, Style::default().fg(theme::DIVIDER)),
        Span::styled("[", Style::default().fg(theme::MUTED)),
        Span::styled(health.as_str(), network_health_style(health)),
        Span::styled(" | ", Style::default().fg(theme::MUTED)),
        Span::styled(coverage.as_str(), coverage_style(coverage)),
        Span::styled("]", Style::default().fg(theme::MUTED)),
    ])
}

fn paired_dashboard_line(left: String, right: String, width: u16) -> Line<'static> {
    let available = usize::from(width);
    let delimiter = " | ";
    let left_width = available.saturating_sub(delimiter.len()) / 2;
    let right_width = available.saturating_sub(delimiter.len() + left_width);
    dashboard_data_line(
        &format!(
            "{}{}{}",
            fit_cell(&left, left_width),
            delimiter,
            fit_cell(&right, right_width)
        ),
        width,
    )
}

fn dashboard_data_line(value: &str, width: u16) -> Line<'static> {
    let value = fit_cell(value, usize::from(width));
    let mut spans = Vec::new();
    let mut start = 0;
    let mut in_whitespace = value.chars().next().is_none_or(char::is_whitespace);
    for (index, character) in value.char_indices() {
        if character.is_whitespace() == in_whitespace {
            continue;
        }
        spans.push(dashboard_data_span(&value[start..index], in_whitespace));
        start = index;
        in_whitespace = !in_whitespace;
    }
    spans.push(dashboard_data_span(&value[start..], in_whitespace));
    Line::from(spans)
}

fn dashboard_data_span(value: &str, whitespace: bool) -> Span<'static> {
    if whitespace {
        return Span::raw(value.to_owned());
    }
    let style = match value {
        "RX" => Style::default().fg(theme::RX).add_modifier(Modifier::BOLD),
        "TX" => Style::default().fg(theme::TX).add_modifier(Modifier::BOLD),
        "KEY" | "CFG" | "FEAT" | "COALESCE" | "BACKLOG" => Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
        "|" => Style::default().fg(theme::DIVIDER),
        _ => Style::default().fg(theme::TEXT),
    };
    Span::styled(value.to_owned(), style)
}

fn fit_cell(value: &str, width: usize) -> String {
    let mut fitted = value.chars().take(width).collect::<String>();
    fitted.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(fitted.chars().count()),
    ));
    fitted
}

fn format_lane_slots(
    label: &str,
    block: &DashboardBlock<'_>,
    slots: &[Option<MetricSlot>],
    display: DetailDisplayOptions,
    maximum_groups: usize,
    width: u16,
) -> Option<String> {
    let values = slots
        .iter()
        .filter_map(|slot| *slot)
        .filter(|slot| {
            display.metrics_mode == DetailMetricsMode::All
                || series_group_has_fresh_data(&metric_group(block, *slot))
        })
        .take(maximum_groups)
        .map(|slot| format_metric_slot(block, Some(slot), display.time_view))
        .collect::<Vec<_>>();
    if values.is_empty() && display.metrics_mode == DetailMetricsMode::WithData {
        return None;
    }
    let value = format!(
        "  {label} {}",
        if values.is_empty() {
            "-".to_owned()
        } else {
            values.join(" | ")
        }
    );
    Some(fit_cell(&value, usize::from(width)))
}

fn format_key_slots(
    block: &DashboardBlock<'_>,
    slots: &[Option<MetricSlot>; 2],
    display: DetailDisplayOptions,
    width: u16,
) -> Option<String> {
    if block.key().kind() == BlockKind::PacketStage(PacketStage::NetfilterConntrack) {
        return format_netfilter_key(block, display.metrics_mode, width);
    }
    if width >= WIDE_DASHBOARD_WIDTH {
        return format_lane_slots("KEY", block, slots, display, slots.len(), width);
    }
    let values = slots
        .iter()
        .flatten()
        .filter(|slot| {
            display.metrics_mode == DetailMetricsMode::All
                || series_group_has_fresh_data(&metric_group(block, **slot))
        })
        .map(|slot| {
            format!(
                "{} {}",
                compact_slot_label(slot.metric),
                compact_metric_value(block, *slot)
            )
        })
        .collect::<Vec<_>>();
    if values.is_empty() && display.metrics_mode == DetailMetricsMode::WithData {
        return None;
    }
    Some(fit_cell(
        &format!(
            "  KEY {}",
            if values.is_empty() {
                "-".to_owned()
            } else {
                values.join(" | ")
            }
        ),
        usize::from(width),
    ))
}

fn format_netfilter_key(
    block: &DashboardBlock<'_>,
    detail_metrics_mode: DetailMetricsMode,
    width: u16,
) -> Option<String> {
    let [count, maximum, utilization, invalid, drop] = NETFILTER_KEY_SLOTS;
    if detail_metrics_mode == DetailMetricsMode::All {
        return Some(fit_cell(
            &format!(
                "  KEY ct {}/{} util {} | inv {} drop {}",
                compact_metric_value(block, count),
                compact_metric_value(block, maximum),
                compact_metric_value(block, utilization),
                compact_metric_value(block, invalid),
                compact_metric_value(block, drop),
            ),
            usize::from(width),
        ));
    }
    let values = [
        ("ct", count),
        ("max", maximum),
        ("util", utilization),
        ("inv", invalid),
        ("drop", drop),
    ]
    .into_iter()
    .filter(|(_, slot)| series_group_has_fresh_data(&metric_group(block, *slot)))
    .map(|(label, slot)| format!("{label} {}", compact_metric_value(block, slot)))
    .collect::<Vec<_>>();
    (!values.is_empty())
        .then(|| fit_cell(&format!("  KEY {}", values.join(" | ")), usize::from(width)))
}

fn format_metric_slot(
    block: &DashboardBlock<'_>,
    slot: Option<MetricSlot>,
    time_view: TimeView,
) -> String {
    let Some(slot) = slot else {
        return "-".to_owned();
    };
    let group = metric_group(block, slot);
    format_summary_group(Some(&group), time_view)
}

fn metric_group<'a>(block: &DashboardBlock<'a>, slot: MetricSlot) -> Vec<&'a SeriesSnapshot> {
    debug_assert!(descriptor(slot.metric)
        .and_then(placement_for)
        .is_some_and(|placement| {
            placement.block_kind() == block.key().kind()
                && placement.lane() == slot.lane
                && matches!(
                    placement.display(),
                    DisplaySlot::Summary { rank } if rank == slot.rank
                )
        }));
    let placed = match slot.lane {
        Lane::Rx => block.rx(),
        Lane::Tx => block.tx(),
        Lane::Shared => block.shared(),
        Lane::FromLabel => unreachable!("global dashboard slots have resolved lanes"),
    };
    placed
        .iter()
        .filter(|placed| placed.series().metric().as_str() == slot.metric)
        .map(PlacedSeries::series)
        .collect()
}

fn compact_metric_value(block: &DashboardBlock<'_>, slot: MetricSlot) -> String {
    let group = metric_group(block, slot);
    let Some(first) = group.first() else {
        return "-".to_owned();
    };
    let metric = first
        .metric()
        .descriptor()
        .expect("dashboard metric is catalogued");
    match first.value() {
        SeriesValue::Counter { .. } => group
            .iter()
            .try_fold(0.0_f64, |total, series| match series.value() {
                SeriesValue::Counter {
                    current: ProjectedValue::Fresh { .. },
                    interval: Some(continuity),
                    ..
                } => continuity.rate_per_second().map(|rate| total + rate),
                _ => None,
            })
            .map(|rate| format!("{rate:.1}/s"))
            .or_else(|| {
                group
                    .iter()
                    .try_fold(0_u64, |total, series| match series.value() {
                        SeriesValue::Counter {
                            current: ProjectedValue::Fresh { value, .. },
                            ..
                        } => Some(total.saturating_add(*value)),
                        _ => None,
                    })
                    .map(|value| format_value(value, metric.unit))
            })
            .unwrap_or_else(|| "-".to_owned()),
        SeriesValue::Gauge { .. } => group
            .iter()
            .try_fold(0_u64, |total, series| match series.value() {
                SeriesValue::Gauge {
                    current: ProjectedValue::Fresh { value, .. },
                    ..
                } => Some(total.saturating_add(*value)),
                _ => None,
            })
            .map(|value| format_value(value, metric.unit))
            .unwrap_or_else(|| "-".to_owned()),
        SeriesValue::State { current, .. } => match current {
            ProjectedValue::Fresh { value, .. } => value.as_str().to_owned(),
            ProjectedValue::Stale { .. } | ProjectedValue::Unavailable { .. } => "-".to_owned(),
        },
    }
}

fn compact_slot_label(metric: &str) -> &'static str {
    match metric {
        "linux.socket.used" => "sockets",
        "linux.socket.tcp.current_established" => "estab",
        "linux.socket.tcp.retransmitted_segments" => "retrans",
        "linux.socket.udp.input_errors" => "udp_err",
        "linux.socket.ip.input_errors" => "ip_err",
        "linux.socket.ip.output_requests" => "ip_out",
        "linux.softirq.softnet.dropped" => "drop",
        "linux.softirq.softnet.time_squeeze" => "squeeze",
        _ => "metric",
    }
}

fn format_summary_group(group: Option<&[&SeriesSnapshot]>, time_view: TimeView) -> String {
    let Some(group) = group.filter(|group| !group.is_empty()) else {
        return "-".to_owned();
    };
    let metric = group[0]
        .metric()
        .descriptor()
        .expect("dashboard metric is catalogued");
    if metric.scope == MetricScope::Cpu {
        return format_aggregate_summary(group, metric, time_view);
    }
    let series = group[0];
    let (current, interval, since, _) = format_series(series, metric);
    let selected = match time_view {
        TimeView::Interval => interval,
        TimeView::SinceBaseline => since,
    };
    format!("{} {current}  {selected}", metric.title)
}

fn format_aggregate_summary(
    group: &[&SeriesSnapshot],
    metric: &MetricDescriptor,
    time_view: TimeView,
) -> String {
    let current = group
        .iter()
        .try_fold(0_u64, |total, series| match series.value() {
            SeriesValue::Counter {
                current: ProjectedValue::Fresh { value, .. },
                ..
            } => Some(total.saturating_add(*value)),
            _ => None,
        })
        .map(|value| format_value(value, metric.unit))
        .unwrap_or_else(|| "-".to_owned());
    let selected =
        aggregate_counter_projection(group, metric, time_view).unwrap_or_else(|| "-".to_owned());
    format!(
        "{} total/{}CPU {current}  {selected}",
        metric.title,
        group.len()
    )
}

fn aggregate_counter_projection(
    group: &[&SeriesSnapshot],
    metric: &MetricDescriptor,
    time_view: TimeView,
) -> Option<String> {
    let (total_delta, total_rate, wrapped) = aggregate_counter_values(group, time_view)?;
    Some(format!(
        "+{}  {}{}",
        format_value(total_delta, metric.unit),
        format_rate(Some(total_rate), metric),
        if wrapped { " wrap" } else { "" }
    ))
}

fn aggregate_counter_values(
    group: &[&SeriesSnapshot],
    time_view: TimeView,
) -> Option<(u64, f64, bool)> {
    let mut total_delta = 0_u64;
    let mut total_rate = 0.0_f64;
    let mut wrapped = false;
    for series in group {
        let SeriesValue::Counter {
            interval,
            since_baseline,
            ..
        } = series.value()
        else {
            return None;
        };
        let (delta, rate, did_wrap) = match time_view {
            TimeView::Interval => match interval {
                Some(CounterContinuity::Continuous { delta, elapsed }) => {
                    (*delta, *delta as f64 / elapsed.as_secs_f64(), false)
                }
                Some(CounterContinuity::Wrapped { delta, elapsed, .. }) => {
                    (*delta, *delta as f64 / elapsed.as_secs_f64(), true)
                }
                Some(
                    CounterContinuity::FirstSample
                    | CounterContinuity::Reset
                    | CounterContinuity::RecoveredAfterGap,
                )
                | None => return None,
            },
            TimeView::SinceBaseline => {
                let span = since_baseline.as_ref()?;
                (span.delta(), span.rate_per_second(), false)
            }
        };
        total_delta = total_delta.saturating_add(delta);
        total_rate += rate;
        wrapped |= did_wrap;
    }
    Some((total_delta, total_rate, wrapped))
}

fn aggregate_gauge_projection(
    group: &[&SeriesSnapshot],
    metric: &MetricDescriptor,
    time_view: TimeView,
) -> Option<String> {
    match time_view {
        TimeView::Interval => {
            let mut delta = 0_i128;
            let mut rate = 0.0_f64;
            for series in group {
                let SeriesValue::Gauge {
                    interval: Some(change),
                    ..
                } = series.value()
                else {
                    return None;
                };
                delta = delta.saturating_add(change.delta());
                rate += change.rate_per_second();
            }
            Some(format!(
                "{}  {}",
                format_signed_value(delta, metric.unit),
                format_rate(Some(rate), metric)
            ))
        }
        TimeView::SinceBaseline => {
            let mut minimum = 0_u64;
            let mut maximum = 0_u64;
            for series in group {
                let SeriesValue::Gauge {
                    since_baseline: Some(summary),
                    ..
                } = series.value()
                else {
                    return None;
                };
                minimum = minimum.saturating_add(summary.min());
                maximum = maximum.saturating_add(summary.max());
            }
            Some(format!(
                "min {} max {}",
                format_value(minimum, metric.unit),
                format_value(maximum, metric.unit)
            ))
        }
    }
}

fn format_signed_value(value: i128, unit: MetricUnit) -> String {
    let sign = if value < 0 { '-' } else { '+' };
    let magnitude = u64::try_from(value.unsigned_abs()).unwrap_or(u64::MAX);
    format!("{sign}{}", format_value(magnitude, unit))
}

fn dashboard_cause_line(cause: Option<&HealthCause>, width: u16) -> Line<'static> {
    let Some(cause) = cause else {
        return Line::from(fit_cell("   WHY -", usize::from(width)))
            .style(Style::default().fg(theme::MUTED));
    };
    let metric = cause.metric().descriptor();
    let title = metric.map_or_else(
        || fallback_health_metric_title(cause.metric().as_str()),
        |metric| metric.title.to_owned(),
    );
    let observed = format_health_value(cause.observed(), metric);
    let value = dashboard_cause_text(&title, &observed, usize::from(width));
    Line::from(value).style(network_health_style(cause.condition()))
}

fn dashboard_cause_text(title: &str, observed: &str, width: usize) -> String {
    const PREFIX: &str = "   WHY  ";
    const MIN_TITLE_WIDTH: usize = 3;
    let available = width.saturating_sub(PREFIX.len());
    if available < 3 {
        return fit_cell(PREFIX, width);
    }

    let minimum_title_width = MIN_TITLE_WIDTH.min(available.saturating_sub(1));
    let observed = if available.saturating_sub(observed.chars().count() + 1) < minimum_title_width {
        compact_dashboard_observed(observed)
    } else {
        observed
    };
    let observed_width = observed
        .chars()
        .count()
        .min(available.saturating_sub(minimum_title_width + 1));
    let title_width = available.saturating_sub(observed_width + 1);
    let title = truncate_component(title, title_width);
    let observed = truncate_component(observed, observed_width);
    fit_cell(&format!("{PREFIX}{title} {observed}"), width)
}

fn compact_dashboard_observed(observed: &str) -> &str {
    match observed {
        "collection complete" => "complete",
        "settings refresh pending" => "refresh",
        "collection schema mismatch" => "schema",
        "collection limit reached" => "limit",
        "collection not supported" => "not supp",
        "collector command not found" => "no cmd",
        "collection permission denied" => "no perm",
        "interface unavailable" => "if n/a",
        "collection timed out" => "timeout",
        "collector output limit reached" => "out cap",
        "invalid collector output" => "bad out",
        "collector command failed" => "cmd fail",
        "collection I/O error" => "I/O err",
        "interval data missing" => "no int",
        "interval data stale" => "stale",
        "waiting for next sample" => "waiting",
        "recovered after data gap" => "post-gap",
        "data missing" => "missing",
        "value unavailable" | "not applicable" => "n/a",
        "invalid value" => "invalid",
        "value overflow" => "overflow",
        _ => observed,
    }
}

fn truncate_component(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_owned();
    }
    match width {
        0 => String::new(),
        1 => "~".to_owned(),
        _ => format!("{}~", value.chars().take(width - 1).collect::<String>()),
    }
}

fn format_health_value(value: &HealthValue, metric: Option<&MetricDescriptor>) -> String {
    match value {
        HealthValue::RatePerSecond(value) => format!("{value:.1}/s"),
        HealthValue::Gauge(value) => metric.map_or_else(
            || value.to_string(),
            |metric| format_value(*value, metric.unit),
        ),
        HealthValue::BasisPoints(value) => format_value(*value, MetricUnit::BasisPoints),
        HealthValue::State(value) => humanize_health_state(value),
        HealthValue::Continuity("missing") => "interval data missing".to_owned(),
        HealthValue::Continuity("stale") => "interval data stale".to_owned(),
        HealthValue::Continuity("first_sample") => "waiting for next sample".to_owned(),
        HealthValue::Continuity("recovered_after_gap") => "recovered after data gap".to_owned(),
        HealthValue::Continuity(value) => value.replace('_', " "),
        HealthValue::Unavailable(reason) => humanize_unavailable_reason(*reason).to_owned(),
    }
}

fn fallback_health_metric_title(metric: &str) -> String {
    metric
        .rsplit('.')
        .next()
        .unwrap_or("metric")
        .replace('_', " ")
}

fn humanize_health_state(value: &str) -> String {
    match value {
        "complete" => "collection complete".to_owned(),
        "refresh_pending" => "settings refresh pending".to_owned(),
        "partial_schema_mismatch" => "collection schema mismatch".to_owned(),
        "partial_cardinality_limit" => "collection limit reached".to_owned(),
        "unsupported" => "collection not supported".to_owned(),
        "command_not_found" => "collector command not found".to_owned(),
        "permission_denied" => "collection permission denied".to_owned(),
        "interface_unavailable" => "interface unavailable".to_owned(),
        "timed_out" => "collection timed out".to_owned(),
        "output_limit" => "collector output limit reached".to_owned(),
        "invalid_output" => "invalid collector output".to_owned(),
        "command_failed" => "collector command failed".to_owned(),
        "io_error" => "collection I/O error".to_owned(),
        _ => value.replace('_', " "),
    }
}

const fn humanize_unavailable_reason(reason: UnavailableReason) -> &'static str {
    match reason {
        UnavailableReason::Missing => "data missing",
        UnavailableReason::NegativeSentinel => "value unavailable",
        UnavailableReason::InvalidValue => "invalid value",
        UnavailableReason::Overflow => "value overflow",
        UnavailableReason::NotApplicable => "not applicable",
        UnavailableReason::CardinalityLimit => "collection limit reached",
    }
}

const fn network_health_style(health: NetworkHealth) -> Style {
    match health {
        NetworkHealth::Ok => Style::new().fg(theme::GOOD).add_modifier(Modifier::BOLD),
        NetworkHealth::Warn => Style::new().fg(theme::WARN).add_modifier(Modifier::BOLD),
        NetworkHealth::Crit => Style::new().fg(theme::BAD).add_modifier(Modifier::BOLD),
        NetworkHealth::Unknown => Style::new().fg(theme::MUTED),
    }
}

const fn coverage_style(coverage: EvidenceCoverage) -> Style {
    match coverage {
        EvidenceCoverage::Fresh => Style::new().fg(theme::GOOD),
        EvidenceCoverage::Partial | EvidenceCoverage::Stale => Style::new().fg(theme::WARN),
        EvidenceCoverage::Unsupported => Style::new().fg(theme::MUTED),
    }
}

#[cfg(test)]
pub(in crate::tui) mod tests {
    use super::*;

    fn ethtool_timeout_snapshot() -> MonitorSnapshot {
        let metric = crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID;
        let descriptor = descriptor(metric).unwrap();
        let source = crate::monitor::ProviderId::new("linux.ethtool.text").unwrap();
        let labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let series = SeriesSnapshot::new(
            crate::monitor::SeriesId::new(1).unwrap(),
            crate::monitor::ProviderId::new(descriptor.owner).unwrap(),
            source.clone(),
            crate::monitor::MetricId::new(metric).unwrap(),
            labels,
            std::time::Duration::ZERO,
            crate::monitor::BaselineOrigin::SessionStart,
            std::time::Duration::ZERO,
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: crate::monitor::StateValue::new("timed_out").unwrap(),
                    observed_at: std::time::Duration::from_secs(1),
                },
                changed_at: None,
                continuous_for: Some(std::time::Duration::from_secs(1)),
            },
            crate::monitor::HistoryCoverage::empty(),
        )
        .unwrap();
        MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(1),
            None,
            vec![crate::monitor::ProviderSnapshot::new(
                source,
                crate::monitor::ProviderHealth::Partial {
                    warning: crate::monitor::MonitorError::new(
                        crate::monitor::MonitorErrorCode::Timeout,
                        "statistics timed out",
                    )
                    .unwrap(),
                },
                std::time::Duration::from_secs(1),
                std::time::Duration::ZERO,
                0,
            )
            .unwrap()],
            vec![series],
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap()
    }

    fn projected_counter(origin: crate::monitor::BaselineOrigin) -> SeriesSnapshot {
        let interval = std::time::Duration::from_secs(1);
        let values = match origin {
            crate::monitor::BaselineOrigin::SessionStart => vec![Some(10), Some(20)],
            crate::monitor::BaselineOrigin::Reset => vec![Some(100), Some(10), Some(20)],
            crate::monitor::BaselineOrigin::RecoveredAfterGap => {
                vec![Some(10), None, Some(20), Some(30)]
            }
            crate::monitor::BaselineOrigin::FirstObserved => unreachable!(),
        };
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let mut snapshot = None;
        for (index, value) in values.into_iter().enumerate() {
            let at = std::time::Duration::from_secs(index as u64 + 1);
            let readings = value
                .map(|value| {
                    crate::monitor::SampleReading::observed(
                        crate::monitor::MetricId::new("linux.netdevice.rx_packets").unwrap(),
                        crate::monitor::MetricLabels::new([
                            (crate::monitor::MetricLabel::Interface, "eth0".to_owned()),
                            (crate::monitor::MetricLabel::Ifindex, "2".to_owned()),
                        ])
                        .unwrap(),
                        crate::monitor::MetricReading::Counter { value, bits: None },
                    )
                })
                .into_iter()
                .collect();
            let sample = crate::monitor::ProviderSample::new(
                crate::monitor::ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
                at,
                std::time::Duration::from_millis(1),
                crate::monitor::ProviderHealth::Fresh,
                readings,
            )
            .unwrap();
            snapshot = Some(engine.ingest(at, vec![sample], None).unwrap());
        }
        snapshot
            .unwrap()
            .series()
            .iter()
            .find(|series| series.metric().as_str() == "linux.netdevice.rx_packets")
            .unwrap()
            .clone()
    }

    fn line_text(lines: Vec<Line<'static>>) -> String {
        lines
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn counter_series(
        id: u64,
        metric_id: &str,
        labels: crate::monitor::MetricLabels,
        current: ProjectedValue<u64>,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        counter_series_from(id, metric_id, metric.sources[0].provider, labels, current)
    }

    fn counter_series_from(
        id: u64,
        metric_id: &str,
        source: &str,
        labels: crate::monitor::MetricLabels,
        current: ProjectedValue<u64>,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        SeriesSnapshot::new(
            crate::monitor::SeriesId::new(id).unwrap(),
            crate::monitor::ProviderId::new(metric.owner).unwrap(),
            crate::monitor::ProviderId::new(source).unwrap(),
            crate::monitor::MetricId::new(metric_id).unwrap(),
            labels,
            std::time::Duration::ZERO,
            crate::monitor::BaselineOrigin::SessionStart,
            std::time::Duration::ZERO,
            SeriesValue::Counter {
                current,
                interval: None,
                since_baseline: None,
            },
            crate::monitor::HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn gauge_series(
        id: u64,
        metric_id: &str,
        labels: crate::monitor::MetricLabels,
        current: ProjectedValue<u64>,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        gauge_series_from(id, metric_id, metric.sources[0].provider, labels, current)
    }

    fn gauge_series_from(
        id: u64,
        metric_id: &str,
        source: &str,
        labels: crate::monitor::MetricLabels,
        current: ProjectedValue<u64>,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        SeriesSnapshot::new(
            crate::monitor::SeriesId::new(id).unwrap(),
            crate::monitor::ProviderId::new(metric.owner).unwrap(),
            crate::monitor::ProviderId::new(source).unwrap(),
            crate::monitor::MetricId::new(metric_id).unwrap(),
            labels,
            std::time::Duration::ZERO,
            crate::monitor::BaselineOrigin::SessionStart,
            std::time::Duration::ZERO,
            SeriesValue::Gauge {
                current,
                interval: None,
                since_baseline: None,
            },
            crate::monitor::HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn state_series(
        id: u64,
        metric_id: &str,
        labels: crate::monitor::MetricLabels,
        value: &str,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        SeriesSnapshot::new(
            crate::monitor::SeriesId::new(id).unwrap(),
            crate::monitor::ProviderId::new(metric.owner).unwrap(),
            crate::monitor::ProviderId::new(metric.sources[0].provider).unwrap(),
            crate::monitor::MetricId::new(metric_id).unwrap(),
            labels,
            std::time::Duration::ZERO,
            crate::monitor::BaselineOrigin::SessionStart,
            std::time::Duration::ZERO,
            SeriesValue::State {
                current: ProjectedValue::Fresh {
                    value: crate::monitor::StateValue::new(value).unwrap(),
                    observed_at: std::time::Duration::from_secs(2),
                },
                changed_at: None,
                continuous_for: Some(std::time::Duration::from_secs(2)),
            },
            crate::monitor::HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn provider_snapshot(provider: &str) -> crate::monitor::ProviderSnapshot {
        crate::monitor::ProviderSnapshot::new(
            crate::monitor::ProviderId::new(provider).unwrap(),
            crate::monitor::ProviderHealth::Fresh,
            std::time::Duration::from_secs(2),
            std::time::Duration::ZERO,
            0,
        )
        .unwrap()
    }

    #[test]
    fn detail_filter_hides_zero_only_numeric_values_but_keeps_state_and_history() {
        let zero = counter_series(
            1,
            "linux.socket.tcp.listen_drops",
            crate::monitor::MetricLabels::default(),
            ProjectedValue::Fresh {
                value: 0,
                observed_at: std::time::Duration::from_secs(2),
            },
        );
        let stale = counter_series(
            2,
            "linux.socket.tcp.listen_overflows",
            crate::monitor::MetricLabels::default(),
            ProjectedValue::Stale {
                last: 3,
                observed_at: std::time::Duration::from_secs(1),
                age: std::time::Duration::from_secs(1),
                cause: crate::monitor::MonitorErrorCode::Timeout,
            },
        );
        let unavailable = counter_series(
            3,
            "linux.socket.tcp.listen_overflows",
            crate::monitor::MetricLabels::default(),
            ProjectedValue::Unavailable {
                reason: UnavailableReason::Missing,
            },
        );
        let nonzero = counter_series(
            4,
            "linux.socket.tcp.listen_drops",
            crate::monitor::MetricLabels::default(),
            ProjectedValue::Fresh {
                value: 1,
                observed_at: std::time::Duration::from_secs(2),
            },
        );
        let state = state_series(
            5,
            "linux.nic.interface_kind",
            crate::monitor::MetricLabels::new([
                (MetricLabel::Interface, "eth0".to_owned()),
                (MetricLabel::Ifindex, "2".to_owned()),
            ])
            .unwrap(),
            "physical",
        );
        let raw_private_labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Statistic, "vendor_counter".to_owned()),
        ])
        .unwrap();
        let raw_private_zero = gauge_series(
            6,
            crate::monitor::RAW_PRIVATE_NIC_METRIC_ID,
            raw_private_labels.clone(),
            ProjectedValue::Fresh {
                value: 0,
                observed_at: std::time::Duration::from_secs(2),
            },
        );
        let raw_private_nonzero = gauge_series(
            7,
            crate::monitor::RAW_PRIVATE_NIC_METRIC_ID,
            raw_private_labels,
            ProjectedValue::Fresh {
                value: 1,
                observed_at: std::time::Duration::from_secs(2),
            },
        );

        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, std::time::Duration::from_secs(1))
                .unwrap();
        let mut reset_to_zero = None;
        for (second, value) in [(1, 5), (2, 0)] {
            let sample = crate::monitor::ProviderSample::new(
                crate::monitor::ProviderId::new("linux.proc.net.netstat").unwrap(),
                std::time::Duration::from_secs(second),
                std::time::Duration::ZERO,
                crate::monitor::ProviderHealth::Fresh,
                vec![crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.socket.tcp.listen_drops").unwrap(),
                    crate::monitor::MetricLabels::default(),
                    crate::monitor::MetricReading::Counter { value, bits: None },
                )],
            )
            .unwrap();
            reset_to_zero = Some(
                engine
                    .ingest(std::time::Duration::from_secs(second), vec![sample], None)
                    .unwrap(),
            );
        }
        let reset_snapshot = reset_to_zero.unwrap();
        let reset_to_zero = reset_snapshot
            .series()
            .iter()
            .find(|series| series.metric().as_str() == "linux.socket.tcp.listen_drops")
            .unwrap();

        assert!(series_has_observed_value(&zero));
        assert!(series_has_observed_value(&stale));
        assert!(!series_has_observed_value(&unavailable));
        assert!(!series_has_detail_data(&zero));
        assert!(series_has_detail_data(&stale));
        assert!(!series_has_detail_data(&unavailable));
        assert!(series_has_detail_data(&nonzero));
        assert!(series_has_detail_data(&state));
        assert!(!series_has_detail_data(&raw_private_zero));
        assert!(series_has_detail_data(&raw_private_nonzero));
        assert!(series_has_detail_data(reset_to_zero));
        assert!(!series_group_has_fresh_data(&[&zero]));
        assert!(series_group_has_fresh_data(&[&nonzero]));
        assert!(!series_group_has_fresh_data(&[&stale]));
        assert!(!series_group_has_fresh_data(&[&zero, &stale]));
    }

    #[test]
    fn global_detail_hides_zero_only_series_and_can_show_all() {
        let source = "linux.proc.net.netstat";
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![provider_snapshot(source)],
            vec![
                counter_series(
                    1,
                    "linux.socket.tcp.listen_drops",
                    crate::monitor::MetricLabels::default(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series(
                    2,
                    "linux.socket.tcp.listen_overflows",
                    crate::monitor::MetricLabels::default(),
                    ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                ),
            ],
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let kind = BlockKind::PacketStage(PacketStage::SocketApplication);

        let with_data = line_text(global_layer_detail_lines(
            &snapshot,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            160,
        ));
        assert!(!with_data.contains("current 0"), "{with_data}");
        assert!(!with_data.contains("STATISTICS WITH DATA"), "{with_data}");

        let all = line_text(global_layer_detail_lines(
            &snapshot,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
            160,
        ));
        assert!(all.contains("ALL STATISTICS  2"), "{all}");
        assert!(all.contains("Listen drops"), "{all}");
        assert!(all.contains("current 0"), "{all}");
        assert!(all.contains("Listen overflows"), "{all}");
        assert!(all.contains("unavailable"), "{all}");
    }

    fn projected_softirq_series(
        id: u64,
        metric_id: &str,
        cpu: u32,
        current: u64,
        interval_delta: u64,
        baseline_delta: u64,
    ) -> SeriesSnapshot {
        softirq_series_with_value(
            id,
            metric_id,
            cpu,
            SeriesValue::Counter {
                current: ProjectedValue::Fresh {
                    value: current,
                    observed_at: std::time::Duration::from_secs(2),
                },
                interval: Some(CounterContinuity::Continuous {
                    delta: interval_delta,
                    elapsed: std::time::Duration::from_secs(1),
                }),
                since_baseline: Some(
                    crate::monitor::CounterSpan::new(
                        baseline_delta,
                        std::time::Duration::from_secs(2),
                    )
                    .unwrap(),
                ),
            },
        )
    }

    fn softirq_series_with_value(
        id: u64,
        metric_id: &str,
        cpu: u32,
        value: SeriesValue,
    ) -> SeriesSnapshot {
        let metric = descriptor(metric_id).unwrap();
        let baseline_origin = match &value {
            SeriesValue::Counter {
                interval: Some(CounterContinuity::Reset),
                ..
            } => crate::monitor::BaselineOrigin::Reset,
            SeriesValue::Counter {
                interval: Some(CounterContinuity::RecoveredAfterGap),
                ..
            } => crate::monitor::BaselineOrigin::RecoveredAfterGap,
            _ => crate::monitor::BaselineOrigin::SessionStart,
        };
        SeriesSnapshot::new(
            crate::monitor::SeriesId::new(id).unwrap(),
            crate::monitor::ProviderId::new(metric.owner).unwrap(),
            crate::monitor::ProviderId::new(metric.sources[0].provider).unwrap(),
            crate::monitor::MetricId::new(metric_id).unwrap(),
            crate::monitor::MetricLabels::new([(MetricLabel::Cpu, cpu.to_string())]).unwrap(),
            std::time::Duration::ZERO,
            baseline_origin,
            if baseline_origin == crate::monitor::BaselineOrigin::SessionStart {
                std::time::Duration::ZERO
            } else {
                std::time::Duration::from_secs(2)
            },
            value,
            crate::monitor::HistoryCoverage::empty(),
        )
        .unwrap()
    }

    pub(in crate::tui) fn softirq_matrix_snapshot(pressure: bool) -> MonitorSnapshot {
        let mut id = 1_u64;
        let mut series = Vec::new();
        for cpu in [10_u32, 2] {
            for (index, column) in SOFTIRQ_COLUMNS.iter().enumerate() {
                let projected = match column.projection {
                    SoftirqProjection::Rate => {
                        let scale = u64::from(cpu);
                        projected_softirq_series(
                            id,
                            column.metric,
                            cpu,
                            1_000 + scale,
                            10 + scale,
                            20 + scale,
                        )
                    }
                    SoftirqProjection::Delta => {
                        let (current, interval, baseline) = if pressure {
                            let value = index as u64 - 2;
                            (value + 3, value + 1, value + 2)
                        } else {
                            (0, 0, 0)
                        };
                        projected_softirq_series(
                            id,
                            column.metric,
                            cpu,
                            current,
                            interval,
                            baseline,
                        )
                    }
                    SoftirqProjection::Current => softirq_series_with_value(
                        id,
                        column.metric,
                        cpu,
                        SeriesValue::Gauge {
                            current: ProjectedValue::Fresh {
                                value: if pressure {
                                    index as u64 + u64::from(cpu)
                                } else {
                                    0
                                },
                                observed_at: std::time::Duration::from_secs(2),
                            },
                            interval: None,
                            since_baseline: None,
                        },
                    ),
                };
                series.push(projected);
                id += 1;
            }
        }
        for (metric, value) in [
            ("linux.softirq.config.netdev_budget", 300),
            ("linux.softirq.config.netdev_budget_usecs", 2_000),
            ("linux.softirq.config.dev_weight", 64),
            ("linux.softirq.config.netdev_max_backlog", 0),
        ] {
            series.push(gauge_series(
                id,
                metric,
                crate::monitor::MetricLabels::default(),
                ProjectedValue::Fresh {
                    value,
                    observed_at: std::time::Duration::from_secs(2),
                },
            ));
            id += 1;
        }
        MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![
                provider_snapshot(SOFTIRQ_SOURCE),
                provider_snapshot(SOFTNET_SOURCE),
                provider_snapshot(SOFTIRQ_CONFIG_SOURCE),
            ],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap()
    }

    #[test]
    #[ignore = "manual TUI refresh benchmark; run with --release --ignored --nocapture"]
    fn benchmark_large_snapshot_refresh() {
        use crate::monitor::{MetricKind, MetricLabels, MonitorSection};
        use ratatui::{backend::TestBackend, Terminal};
        use std::{
            sync::Arc,
            time::{Duration, Instant},
        };
        let mut series = Vec::new();
        for ifindex in 1..=121 {
            let labels = || {
                MetricLabels::new([
                    (MetricLabel::Interface, format!("eth{ifindex}")),
                    (MetricLabel::Ifindex, ifindex.to_string()),
                ])
                .unwrap()
            };
            series.push(state_series(
                series.len() as u64 + 1,
                INTERFACE_KIND_METRIC,
                labels(),
                "physical",
            ));
            for metric in [
                "rx_packets",
                "rx_bytes",
                "rx_errors",
                "rx_dropped",
                "tx_packets",
                "tx_bytes",
                "tx_errors",
                "tx_dropped",
            ] {
                series.push(counter_series(
                    series.len() as u64 + 1,
                    &format!("linux.netdevice.{metric}"),
                    labels(),
                    ProjectedValue::Fresh {
                        value: 100,
                        observed_at: Duration::from_secs(2),
                    },
                ));
            }
            for statistic in 0..74 {
                let labels = MetricLabels::new([
                    (MetricLabel::Interface, format!("eth{ifindex}")),
                    (MetricLabel::Ifindex, ifindex.to_string()),
                    (MetricLabel::Statistic, format!("counter_{statistic}")),
                ])
                .unwrap();
                series.push(gauge_series(
                    series.len() as u64 + 1,
                    crate::monitor::RAW_PRIVATE_NIC_METRIC_ID,
                    labels,
                    ProjectedValue::Fresh {
                        value: 100,
                        observed_at: Duration::from_secs(2),
                    },
                ));
            }
        }
        for cpu in 0..64 {
            for column in SOFTIRQ_COLUMNS {
                let current = ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(2),
                };
                let value = match descriptor(column.metric).unwrap().kind {
                    MetricKind::Counter => SeriesValue::Counter {
                        current,
                        interval: None,
                        since_baseline: None,
                    },
                    _ => SeriesValue::Gauge {
                        current,
                        interval: None,
                        since_baseline: None,
                    },
                };
                series.push(softirq_series_with_value(
                    series.len() as u64 + 1,
                    column.metric,
                    cpu,
                    value,
                ));
            }
        }
        for metric in [
            "linux.softirq.config.netdev_budget",
            "linux.softirq.config.netdev_budget_usecs",
            "linux.softirq.config.dev_weight",
            "linux.softirq.config.netdev_max_backlog",
        ] {
            series.push(gauge_series(
                series.len() as u64 + 1,
                metric,
                MetricLabels::default(),
                ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(2),
                },
            ));
        }
        for metric in ["linux.nic.link_state", "linux.nic.ethtool_settings_status"] {
            series.push(state_series(
                series.len() as u64 + 1,
                metric,
                MetricLabels::new([
                    (MetricLabel::Interface, "eth1".to_owned()),
                    (MetricLabel::Ifindex, "1".to_owned()),
                ])
                .unwrap(),
                if metric.ends_with("link_state") {
                    "up"
                } else {
                    "complete"
                },
            ));
        }
        assert_eq!(series.len(), 10_689);
        let providers: Vec<_> = series
            .iter()
            .map(|series| series.source().as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(provider_snapshot)
            .collect();
        let snapshots: Vec<_> = (1..=100)
            .map(|sequence| {
                Arc::new(
                    MonitorSnapshot::new(
                        1,
                        sequence,
                        0,
                        Duration::from_secs(2),
                        None,
                        providers.clone(),
                        series.clone(),
                        crate::monitor::EngineTelemetry::default(),
                    )
                    .unwrap(),
                )
            })
            .collect();
        for section in [
            MonitorSection::Overview,
            MonitorSection::Nic,
            MonitorSection::Softirq,
        ] {
            let mut app = super::super::app::App::new(section, Duration::from_secs(1));
            let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
            let started = Instant::now();
            for snapshot in &snapshots {
                app.apply_snapshot(Arc::clone(snapshot));
                terminal
                    .draw(|frame| {
                        app.set_viewport_size(
                            160,
                            super::super::view::body_rows(frame.area(), &app),
                        );
                        super::super::view::render(frame, &app);
                    })
                    .unwrap();
            }
            eprintln!(
                "{section:?}: {:.1} us/refresh (121 interfaces, 10689 series, 160x40)",
                started.elapsed().as_secs_f64() * 1e6 / snapshots.len() as f64
            );
        }
    }

    #[test]
    fn softirq_sort_uses_raw_rates_selected_time_view_and_cpu_ties() {
        let series = [(10, 1200, 2), (2, 9, 10000), (7, 9, 10000)]
            .into_iter()
            .enumerate()
            .map(|(i, (cpu, delta, baseline))| {
                projected_softirq_series(
                    i as u64 + 1,
                    SOFTIRQ_COLUMNS[0].metric,
                    cpu,
                    20000,
                    delta,
                    baseline,
                )
            })
            .collect();
        let snapshot = softirq_sort_snapshot(series);
        for (time_view, descending, expected) in [
            (TimeView::Interval, true, [10, 2, 7]),
            (TimeView::Interval, false, [2, 7, 10]),
            (TimeView::SinceBaseline, true, [2, 7, 10]),
            (TimeView::SinceBaseline, false, [10, 2, 7]),
        ] {
            let model = SoftirqSection::new_with_options(
                &snapshot,
                80,
                DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                SoftirqSort::Metric(0),
                descending,
            );
            assert_eq!(
                model.rows.iter().map(|(cpu, _)| *cpu).collect::<Vec<_>>(),
                expected
            );
            let visible = model.visible_lines(&snapshot, TimeView::Interval, 0, usize::MAX);
            let rendered = &visible[model.header.len()];
            let series = &snapshot.series()[model.rows[0].1[0].unwrap()];
            assert!(line_content(rendered).contains(&softirq_matrix_value(
                series,
                SoftirqProjection::Rate,
                time_view
            )));
        }
        assert!(!SoftirqSort::Cpu.default_descending());
        assert!(SoftirqSort::Metric(0).default_descending());
    }

    fn softirq_sort_snapshot(series: Vec<SeriesSnapshot>) -> MonitorSnapshot {
        MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            softirq_matrix_snapshot(true).providers().to_vec(),
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap()
    }

    #[test]
    fn softirq_sort_keeps_full_u64_precision_for_deltas_and_gauges() {
        for index in [3, 7] {
            let series = [(10, u64::MAX - 1), (2, u64::MAX), (7, 0)]
                .into_iter()
                .enumerate()
                .map(|(i, (cpu, value))| {
                    if index == 3 {
                        projected_softirq_series(
                            i as u64 + 1,
                            SOFTIRQ_COLUMNS[index].metric,
                            cpu,
                            value,
                            value,
                            value,
                        )
                    } else {
                        softirq_series_with_value(
                            i as u64 + 1,
                            SOFTIRQ_COLUMNS[index].metric,
                            cpu,
                            SeriesValue::Gauge {
                                current: ProjectedValue::Fresh {
                                    value,
                                    observed_at: std::time::Duration::from_secs(2),
                                },
                                interval: None,
                                since_baseline: None,
                            },
                        )
                    }
                })
                .collect();
            let snapshot = softirq_sort_snapshot(series);
            for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                for (descending, expected) in [(true, [2, 10, 7]), (false, [7, 10, 2])] {
                    let model = SoftirqSection::new_with_options(
                        &snapshot,
                        160,
                        DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                        SoftirqSort::Metric(index),
                        descending,
                    );
                    assert_eq!(
                        model.rows.iter().map(|(cpu, _)| *cpu).collect::<Vec<_>>(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn softirq_sort_unusable_samples_stay_last_in_both_directions() {
        let fresh = |value| ProjectedValue::Fresh {
            value,
            observed_at: std::time::Duration::from_secs(2),
        };
        for index in [0, 3] {
            let mut series = vec![
                projected_softirq_series(1, SOFTIRQ_COLUMNS[index].metric, 1, 0, 0, 0),
                projected_softirq_series(2, SOFTIRQ_COLUMNS[index].metric, 2, 2, 2, 2),
                softirq_series_with_value(
                    3,
                    SOFTIRQ_COLUMNS[7].metric,
                    3,
                    SeriesValue::Gauge {
                        current: fresh(1),
                        interval: None,
                        since_baseline: None,
                    },
                ),
            ];
            for (cpu, current, interval) in [
                (
                    4,
                    ProjectedValue::Stale {
                        last: u64::MAX,
                        observed_at: std::time::Duration::from_secs(1),
                        age: std::time::Duration::from_secs(1),
                        cause: crate::monitor::MonitorErrorCode::Timeout,
                    },
                    None,
                ),
                (
                    5,
                    ProjectedValue::Unavailable {
                        reason: UnavailableReason::Missing,
                    },
                    None,
                ),
                (6, fresh(9000), Some(CounterContinuity::FirstSample)),
                (7, fresh(9000), Some(CounterContinuity::Reset)),
                (8, fresh(9000), Some(CounterContinuity::RecoveredAfterGap)),
            ] {
                series.push(softirq_series_with_value(
                    u64::from(cpu),
                    SOFTIRQ_COLUMNS[index].metric,
                    cpu,
                    SeriesValue::Counter {
                        current,
                        interval,
                        since_baseline: None,
                    },
                ));
            }
            let snapshot = softirq_sort_snapshot(series);
            for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                for (descending, expected) in [
                    (true, [2, 1, 3, 4, 5, 6, 7, 8]),
                    (false, [1, 2, 3, 4, 5, 6, 7, 8]),
                ] {
                    let model = SoftirqSection::new_with_options(
                        &snapshot,
                        80,
                        DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                        SoftirqSort::Metric(index),
                        descending,
                    );
                    assert_eq!(
                        model.rows.iter().map(|(cpu, _)| *cpu).collect::<Vec<_>>(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn softirq_headers_hit_the_visible_cells_and_skip_separators() {
        let snapshot = softirq_matrix_snapshot(true);
        for width in [0, 1, 12, 20, 60, 80, 120, 160] {
            let model = SoftirqSection::new_with_options(
                &snapshot,
                width,
                DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
                SoftirqSort::Metric(3),
                true,
            );
            for height in [0, 1, 3, 40] {
                for offset in [0, 1, usize::MAX] {
                    let view = model.viewport(height, offset);
                    let lines = model.visible_lines(&snapshot, TimeView::Interval, offset, height);
                    assert!(lines.len() <= height);
                    assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                    if view.headings == 0 {
                        continue;
                    }
                    assert_eq!(lines[view.context], *model.header.last().unwrap());
                    let mut start = softirq_matrix_indent(width);
                    for (position, cell_width) in model.widths.iter().copied().enumerate() {
                        let field = if position == 0 {
                            SoftirqSort::Cpu
                        } else {
                            SoftirqSort::Metric(model.columns[position - 1].0)
                        };
                        for x in start..start + cell_width {
                            assert_eq!(
                                model.header_sort_at(x, view.context, height, offset),
                                Some(field)
                            );
                            assert_eq!(
                                model.header_sort_at(x, view.data_start(), height, offset),
                                None
                            );
                        }
                        assert_eq!(
                            model.header_sort_at(start + cell_width, view.context, height, offset),
                            None
                        );
                        start += cell_width + 1;
                    }
                }
            }
            if width >= 60 {
                let header = model.header.last().unwrap();
                let active = &header.spans[1 + 2 * 4];
                assert!(active.content.contains('↓'));
                assert_eq!(active.style.bg, Some(theme::SORT_BG));
                for (position, (_, column)) in model.columns.iter().enumerate() {
                    let label = &header.spans[3 + 2 * position].content;
                    if matches!(column.projection, SoftirqProjection::Rate) {
                        assert!(label.contains("/s"), "{width}: {label}");
                    }
                    if matches!(column.projection, SoftirqProjection::Delta) {
                        assert!(label.contains('+'), "{width}: {label}");
                    }
                }
            }
        }
    }

    #[test]
    fn softirq_sort_cycles_visible_columns_and_falls_back_to_cpu_ascending() {
        let snapshot = softirq_matrix_snapshot(false);
        let model = SoftirqSection::new_with_options(
            &snapshot,
            80,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            SoftirqSort::Metric(3),
            true,
        );
        assert_eq!(model.effective_sort(), SoftirqSort::Cpu);
        assert!(!model.effective_descending());
        assert_eq!(
            model.rows.iter().map(|(cpu, _)| *cpu).collect::<Vec<_>>(),
            [2, 10]
        );
        let mut sort = SoftirqSort::Cpu;
        for expected in [0, 1, 2, 5] {
            sort = model.next_sort(sort);
            assert_eq!(sort, SoftirqSort::Metric(expected));
        }
        assert_eq!(model.next_sort(sort), SoftirqSort::Cpu);
        assert_eq!(model.next_sort(SoftirqSort::Metric(100)), SoftirqSort::Cpu);
    }

    #[test]
    fn softirq_matrix_sorts_cpu_ids_numerically_and_keeps_one_fixed_width_row_per_cpu() {
        let snapshot = softirq_matrix_snapshot(true);
        let dashboard = build_dashboard(&snapshot);
        let block = dashboard
            .blocks()
            .iter()
            .find(|block| {
                block.key().kind() == BlockKind::ExecutionContext(ExecutionContext::Softirq)
            })
            .unwrap();
        assert_eq!(
            softirq_cpu_rows(block).keys().copied().collect::<Vec<_>>(),
            [2, 10]
        );

        for width in [60_u16, 80, 120, 160] {
            let lines = softirq_section_lines(&snapshot, TimeView::Interval, width);
            let header = lines
                .iter()
                .position(|line| line_content(line).trim_start().starts_with("CPU "))
                .unwrap();
            let table = &lines[header..];
            assert_eq!(table.len(), 3);
            let cell_widths = table[0]
                .spans
                .iter()
                .map(|span| span.content.chars().count())
                .collect::<Vec<_>>();
            for line in table {
                assert_eq!(line_content(line).chars().count(), usize::from(width));
                assert_eq!(
                    line.spans
                        .iter()
                        .map(|span| span.content.chars().count())
                        .collect::<Vec<_>>(),
                    cell_widths
                );
            }
            assert!(line_content(&table[1]).trim_start().starts_with("2 "));
            assert!(line_content(&table[2]).trim_start().starts_with("10 "));
            if width == 60 {
                let header = line_content(&table[0]);
                for label in [
                    "RX/s", "TX/s", "P/s", "D+", "S+", "RP/s", "FL+", "BL", "IQ", "PQ",
                ] {
                    assert!(header.contains(label), "missing {label}: {header}");
                }
            }
        }
    }

    #[test]
    fn softirq_cached_viewports_match_the_complete_matrix_at_every_offset() {
        for pressure in [false, true] {
            let snapshot = softirq_matrix_snapshot(pressure);
            let dashboard = build_dashboard(&snapshot);
            let block = dashboard
                .blocks()
                .iter()
                .find(|block| {
                    block.key().kind() == BlockKind::ExecutionContext(ExecutionContext::Softirq)
                })
                .unwrap();
            for width in [1, 12, 20, 60, 80, 120, 160] {
                for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                    let model = SoftirqSection::new_with_options(
                        &snapshot,
                        width,
                        DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                        SoftirqSort::Cpu,
                        false,
                    );
                    let mut expected = Vec::new();
                    append_softirq_cpu_matrix(
                        &mut expected,
                        &snapshot,
                        block,
                        DetailDisplayOptions::new(time_view, DetailMetricsMode::All),
                        width,
                    );
                    assert_eq!(model.row_count(), expected.len());
                    let complete = model.visible_lines(&snapshot, time_view, 0, usize::MAX);
                    assert_eq!(
                        complete.iter().map(line_content).collect::<Vec<_>>(),
                        expected.iter().map(line_content).collect::<Vec<_>>()
                    );
                    for offset in 0..=expected.len() + 1 {
                        for height in [0, 1, 3, 40] {
                            let view = model.viewport(height, offset);
                            assert_eq!(
                                model.visible_lines(&snapshot, time_view, offset, height),
                                (0..height)
                                    .filter_map(|row| view.logical_row(row))
                                    .map(|row| complete[row].clone())
                                    .collect::<Vec<_>>(),
                                "width={width} offset={offset} height={height}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn softirq_cache_follows_snapshot_pause_resume_and_resize() {
        use super::super::app::{Action, App};
        use crate::monitor::MonitorSection;
        use std::{sync::Arc, time::Duration};
        let first = Arc::new(softirq_matrix_snapshot(false));
        let changed = softirq_matrix_snapshot(true);
        let next = Arc::new(
            MonitorSnapshot::new(
                1,
                2,
                0,
                changed.elapsed(),
                None,
                changed.providers().to_vec(),
                changed.series().to_vec(),
                changed.telemetry(),
            )
            .unwrap(),
        );
        let mut app = App::new(MonitorSection::Softirq, Duration::from_secs(1));
        app.set_viewport_size(160, 8);
        app.apply_snapshot(Arc::clone(&first));
        let first_lines = app.softirq_section().unwrap().visible_lines(
            app.snapshot().unwrap(),
            app.time_view(),
            0,
            usize::MAX,
        );
        app.update(Action::TogglePause);
        app.apply_snapshot(Arc::clone(&next));
        assert_eq!(
            app.softirq_section().unwrap().visible_lines(
                app.snapshot().unwrap(),
                app.time_view(),
                0,
                usize::MAX
            ),
            first_lines
        );
        app.update(Action::TogglePause);
        assert_ne!(
            app.softirq_section().unwrap().visible_lines(
                app.snapshot().unwrap(),
                app.time_view(),
                0,
                usize::MAX
            ),
            first_lines
        );
        app.update(Action::ToggleTimeView);
        app.set_viewport_size(60, 4);
        assert_eq!(
            app.softirq_section().unwrap().visible_lines(
                app.snapshot().unwrap(),
                app.time_view(),
                0,
                usize::MAX
            ),
            SoftirqSection::new_with_options(
                &next,
                60,
                DetailDisplayOptions::new(TimeView::SinceBaseline, app.detail_metrics_mode()),
                SoftirqSort::Cpu,
                false,
            )
            .visible_lines(&next, TimeView::SinceBaseline, 0, usize::MAX)
        );
    }

    #[test]
    fn softirq_matrix_hides_only_whole_zero_columns_and_all_mode_restores_them() {
        let snapshot = softirq_matrix_snapshot(false);
        let kind = BlockKind::ExecutionContext(ExecutionContext::Softirq);
        let with_data = global_layer_detail_lines(
            &snapshot,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            160,
        );
        let header = with_data
            .iter()
            .map(line_content)
            .find(|line| line.trim_start().starts_with("CPU "))
            .unwrap();
        assert!(header.contains("NET_RX/s"), "{header}");
        assert!(header.contains("NET_TX/s"), "{header}");
        assert!(header.contains("PROCESSED/s"), "{header}");
        assert!(header.contains("RECEIVED_RPS/s"), "{header}");
        for hidden in [
            "DROPPED+",
            "SQUEEZE+",
            "FLOW_LIMIT_COUNT+",
            "BACKLOG_LEN",
            "INPUT_QLEN",
            "PROCESS_QLEN",
        ] {
            assert!(!header.contains(hidden), "{header}");
        }

        let all = softirq_section_lines(&snapshot, TimeView::Interval, 160);
        let header = all
            .iter()
            .map(line_content)
            .find(|line| line.trim_start().starts_with("CPU "))
            .unwrap();
        for visible in [
            "DROPPED+",
            "SQUEEZE+",
            "FLOW_LIMIT_COUNT+",
            "BACKLOG_LEN",
            "INPUT_QLEN",
            "PROCESS_QLEN",
        ] {
            assert!(header.contains(visible), "{header}");
        }
        for gauge in ["BACKLOG_LEN", "INPUT_QLEN", "PROCESS_QLEN"] {
            assert!(!header.contains(&format!("{gauge}/")), "{header}");
            assert!(!header.contains(&format!("{gauge}+")), "{header}");
        }
    }

    #[test]
    fn softirq_coalescing_config_keeps_zero_values_and_wraps_to_terminal_width() {
        let snapshot = softirq_matrix_snapshot(false);
        let kind = BlockKind::ExecutionContext(ExecutionContext::Softirq);
        for width in [60_u16, 80, 120, 160] {
            let lines = global_layer_detail_lines(
                &snapshot,
                kind,
                DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
                width,
            );
            let text = line_text(lines.clone());
            for expected in [
                "packet budget 300",
                "time budget 2000 us",
                "device weight 64",
                "per-CPU maximum 0",
                "sysctl fresh",
            ] {
                assert!(
                    text.contains(expected),
                    "{width}: missing {expected}: {text}"
                );
            }
            assert!(!text.contains("trend"), "{width}: {text}");
            for line in lines.iter().filter(|line| {
                let line = line_content(line);
                line.contains("BUDGET")
                    || line.contains("packet budget")
                    || line.contains("device weight")
                    || line.contains("BACKLOG")
            }) {
                assert_eq!(line_content(line).chars().count(), usize::from(width));
            }
        }
    }

    #[test]
    fn softirq_coalescing_config_hides_only_when_unobserved() {
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(1),
            None,
            Vec::new(),
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let kind = BlockKind::ExecutionContext(ExecutionContext::Softirq);
        let with_data = line_text(global_layer_detail_lines(
            &snapshot,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            120,
        ));
        assert!(!with_data.contains("BUDGET"), "{with_data}");
        assert!(!with_data.contains("BACKLOG"), "{with_data}");

        let all = line_text(softirq_section_lines(&snapshot, TimeView::Interval, 120));
        assert!(all.contains("packet budget -"), "{all}");
        assert!(all.contains("time budget -"), "{all}");
        assert!(all.contains("device weight -"), "{all}");
        assert!(all.contains("per-CPU maximum -"), "{all}");
    }

    #[test]
    fn softirq_matrix_uses_rates_deltas_and_current_queue_lengths() {
        let snapshot = softirq_matrix_snapshot(true);
        let net_rx = snapshot
            .series()
            .iter()
            .find(|series| {
                series.metric().as_str() == "linux.softirq.net_rx"
                    && series.labels().get(MetricLabel::Cpu) == Some("2")
            })
            .unwrap();
        let dropped = snapshot
            .series()
            .iter()
            .find(|series| {
                series.metric().as_str() == "linux.softirq.softnet.dropped"
                    && series.labels().get(MetricLabel::Cpu) == Some("2")
            })
            .unwrap();
        assert_eq!(
            softirq_matrix_value(net_rx, SoftirqProjection::Rate, TimeView::Interval),
            "12/s"
        );
        assert_eq!(
            softirq_matrix_value(net_rx, SoftirqProjection::Rate, TimeView::SinceBaseline),
            "11/s"
        );
        assert_eq!(
            softirq_matrix_value(dropped, SoftirqProjection::Delta, TimeView::Interval),
            "+2"
        );
        assert_eq!(
            softirq_matrix_value(dropped, SoftirqProjection::Delta, TimeView::SinceBaseline),
            "+3"
        );
        for (metric_id, expected) in [
            ("linux.softirq.softnet.backlog_len", "9"),
            ("linux.softirq.softnet.input_qlen", "10"),
            ("linux.softirq.softnet.process_qlen", "11"),
        ] {
            let column = SOFTIRQ_COLUMNS
                .iter()
                .find(|column| column.metric == metric_id)
                .unwrap();
            assert!(matches!(column.projection, SoftirqProjection::Current));
            let series = snapshot
                .series()
                .iter()
                .find(|series| {
                    series.metric().as_str() == metric_id
                        && series.labels().get(MetricLabel::Cpu) == Some("2")
                })
                .unwrap();
            for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                assert_eq!(
                    softirq_matrix_value(series, column.projection, time_view),
                    expected
                );
            }
        }
    }

    #[test]
    fn softirq_matrix_keeps_discontinuity_states_aligned_without_fabricating_zero() {
        let fresh = |value| ProjectedValue::Fresh {
            value,
            observed_at: std::time::Duration::from_secs(2),
        };
        let reset = softirq_series_with_value(
            1,
            SOFTIRQ_COLUMNS[0].metric,
            7,
            SeriesValue::Counter {
                current: fresh(10),
                interval: Some(CounterContinuity::Reset),
                since_baseline: None,
            },
        );
        let gap = softirq_series_with_value(
            2,
            SOFTIRQ_COLUMNS[1].metric,
            7,
            SeriesValue::Counter {
                current: fresh(20),
                interval: Some(CounterContinuity::RecoveredAfterGap),
                since_baseline: None,
            },
        );
        let stale = softirq_series_with_value(
            3,
            SOFTIRQ_COLUMNS[2].metric,
            7,
            SeriesValue::Counter {
                current: ProjectedValue::Stale {
                    last: 30,
                    observed_at: std::time::Duration::from_secs(1),
                    age: std::time::Duration::from_secs(1),
                    cause: crate::monitor::MonitorErrorCode::Timeout,
                },
                interval: None,
                since_baseline: None,
            },
        );
        let unavailable = softirq_series_with_value(
            4,
            SOFTIRQ_COLUMNS[3].metric,
            7,
            SeriesValue::Counter {
                current: ProjectedValue::Unavailable {
                    reason: UnavailableReason::Missing,
                },
                interval: None,
                since_baseline: None,
            },
        );
        let mut row = [None; SOFTIRQ_COLUMNS.len()];
        row[0] = Some(&reset);
        row[1] = Some(&gap);
        row[2] = Some(&stale);
        row[3] = Some(&unavailable);
        let columns = SOFTIRQ_COLUMNS.iter().enumerate().collect::<Vec<_>>();

        for width in [60_u16, 80, 120, 160] {
            let widths = softirq_matrix_widths(width, &columns);
            let header = softirq_matrix_header(&columns, &widths, width);
            let rendered =
                softirq_matrix_row(7, &row, &columns, &widths, TimeView::Interval, width);
            let text = line_content(&rendered);
            assert!(text.contains("reset"), "{width}: {text}");
            assert!(text.contains("gap"), "{width}: {text}");
            if width >= 80 {
                assert!(text.contains("stale"), "{width}: {text}");
            }
            assert_eq!(text.chars().count(), usize::from(width));
            assert_eq!(
                rendered
                    .spans
                    .iter()
                    .map(|span| span.content.chars().count())
                    .collect::<Vec<_>>(),
                header
                    .spans
                    .iter()
                    .map(|span| span.content.chars().count())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn netfilter_block_omits_direction_placeholders() {
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(1),
            None,
            Vec::new(),
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let kind = BlockKind::PacketStage(PacketStage::NetfilterConntrack);
        let dashboard = build_dashboard(&snapshot);
        let block = dashboard
            .blocks()
            .iter()
            .find(|block| block.key().kind() == kind)
            .unwrap();
        let lines = global_block_lines(
            &snapshot,
            block,
            global_block_title(kind).unwrap(),
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
            160,
            false,
        );
        let row_count = lines.len();
        let text = line_text(lines);

        assert_eq!(row_count, 3, "{text}");
        assert!(!text.contains("RX -"), "{text}");
        assert!(!text.contains("TX -"), "{text}");
        assert!(text.contains("KEY ct -/- util - | inv - drop -"), "{text}");

        let netfilter_span = overview_layer_row_span(kind).unwrap();
        let softirq_span =
            overview_layer_row_span(BlockKind::ExecutionContext(ExecutionContext::Softirq))
                .unwrap();
        assert_eq!(netfilter_span.len(), NETFILTER_DASHBOARD_BLOCK_ROWS);
        assert_eq!(softirq_span.start, netfilter_span.end);
        assert_eq!(interface_row_span_at(0).start, softirq_span.end + 1);
    }

    #[test]
    fn interface_layer_detail_hides_zero_only_tc_rows_and_can_show_all() {
        let interface_labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let tc_labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Direction, "egress".to_owned()),
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::QdiscKind, "fq_codel".to_owned()),
            (MetricLabel::RowId, "10".to_owned()),
            (MetricLabel::Execution, "software".to_owned()),
        ])
        .unwrap();
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![
                provider_snapshot("linux.sysfs.net.nic"),
                provider_snapshot("linux.tc.json"),
            ],
            vec![
                state_series(1, "linux.nic.interface_kind", interface_labels, "physical"),
                counter_series_from(
                    2,
                    "linux.tc.drops",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series_from(
                    3,
                    "linux.tc.overlimits",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series_from(
                    4,
                    "linux.tc.requeues",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 1,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                gauge_series_from(
                    5,
                    "linux.tc.backlog_bytes",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                gauge_series_from(
                    6,
                    "linux.tc.backlog_packets",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                gauge_series_from(
                    7,
                    "linux.tc.max_packet_bytes",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series_from(
                    8,
                    "linux.tc.drop_overlimit",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series_from(
                    9,
                    "linux.tc.new_flow_count",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                counter_series_from(
                    10,
                    "linux.tc.ecn_marks",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                gauge_series_from(
                    11,
                    "linux.tc.new_flows_len",
                    "linux.tc.json",
                    tc_labels.clone(),
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
                gauge_series_from(
                    12,
                    "linux.tc.old_flows_len",
                    "linux.tc.json",
                    tc_labels,
                    ProjectedValue::Fresh {
                        value: 0,
                        observed_at: std::time::Duration::from_secs(2),
                    },
                ),
            ],
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();

        let menu = interface_detail_lines(
            &snapshot,
            &identity,
            BlockKind::PacketStage(PacketStage::NetdeviceCore),
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
            160,
        );
        let selected = menu
            .iter()
            .filter(|line| line.style.bg == Some(theme::SELECTED_BG))
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 1);
        assert!(selected[0]
            .spans
            .iter()
            .any(|span| span.content.contains("NETDEVICE CORE")));
        let menu = line_text(menu);
        assert!(!menu.contains("STATISTICS WITH DATA"), "{menu}");
        assert!(!menu.contains("ALL STATISTICS"), "{menu}");
        assert!(!menu.contains("source linux."), "{menu}");

        let with_data = line_text(interface_layer_detail_lines(
            &snapshot,
            &identity,
            BlockKind::PacketStage(PacketStage::TrafficControl),
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            160,
        ));
        assert!(
            !with_data.contains("r10 drops tx fq_codel eth0"),
            "{with_data}"
        );
        assert!(!with_data.contains("current 0"), "{with_data}");
        assert!(with_data.contains("eth0"), "{with_data}");
        assert!(!with_data.contains("r10 overlimits"), "{with_data}");
        assert!(with_data.contains("REQUEUES"), "{with_data}");
        assert!(
            with_data.contains("r10 requeues tx fq_codel"),
            "{with_data}"
        );
        assert!(with_data.contains("current 1"), "{with_data}");
        assert!(!with_data.contains("maximum packet"), "{with_data}");
        assert!(!with_data.contains("r10 overlimit drops"), "{with_data}");
        assert!(!with_data.contains("new-flow events"), "{with_data}");
        assert!(!with_data.contains("ECN marks"), "{with_data}");
        assert!(!with_data.contains("new-flow list length"), "{with_data}");
        assert!(!with_data.contains("old-flow list length"), "{with_data}");
        assert!(!with_data.contains("no collected series"), "{with_data}");

        let all = line_text(interface_layer_detail_lines(
            &snapshot,
            &identity,
            BlockKind::PacketStage(PacketStage::TrafficControl),
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
            160,
        ));
        assert!(all.contains("r10 drops tx fq_codel eth0"), "{all}");
        assert!(all.contains("current 0"), "{all}");
        assert!(all.contains("r10 overlimits tx"), "{all}");
        assert!(all.contains("fq_codel eth0"), "{all}");
        for title in [
            "maximum packet",
            "overlimit drops",
            "new-flow events",
            "ECN marks",
            "new-flow list length",
            "old-flow list length",
        ] {
            assert!(all.contains(title), "missing {title}: {all}");
        }
        assert!(all.contains("source linux.tc.json"), "{all}");
        assert!(all.len() > with_data.len());
    }

    #[test]
    fn hardirq_stage_shows_rx_and_tx_interrupt_coalescing_config() {
        let interface_labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let mut series = vec![state_series(
            1,
            "linux.nic.interface_kind",
            interface_labels,
            "physical",
        )];
        for (id, statistic, value) in [
            (2, "Adaptive RX", "on"),
            (3, "RX Usecs", "0"),
            (4, "RX Frames", "16"),
            (5, "Adaptive TX", "off"),
            (6, "TX Usecs", "12"),
            (7, "TX Frames", "24"),
        ] {
            let labels = crate::monitor::MetricLabels::new([
                (MetricLabel::Interface, "eth0".to_owned()),
                (MetricLabel::Ifindex, "2".to_owned()),
                (MetricLabel::Statistic, statistic.to_owned()),
            ])
            .unwrap();
            series.push(state_series(
                id,
                crate::monitor::RAW_NIC_SETTING_METRIC_ID,
                labels,
                value,
            ));
        }
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![
                provider_snapshot("linux.sysfs.net.nic"),
                provider_snapshot("linux.ethtool.link_text"),
            ],
            series,
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();
        let kind = BlockKind::ExecutionContext(ExecutionContext::Hardirq);
        let dashboard = build_dashboard(&snapshot);
        let block = interface_block(&dashboard, &identity, kind).unwrap();

        for width in [60_u16, 80, 120, 160] {
            let lines = interface_detail::stage_lines(
                &snapshot,
                block,
                kind,
                DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
                width,
                false,
            );
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
            let text = line_text(lines.clone());
            assert!(text.contains("COALESCE"));
            for expected in [["RX", "on", "0", "16"], ["TX", "off", "12", "24"]] {
                assert!(
                    lines.iter().any(|line| {
                        let text = line.to_string();
                        let cells: Vec<_> = text
                            .split('│')
                            .map(str::trim)
                            .filter(|cell| !cell.is_empty())
                            .collect();
                        cells == expected
                    }),
                    "{width}: {text}"
                );
            }
            assert!(!text.contains("direction unavailable"), "{width}: {text}");
        }
    }

    #[test]
    fn hardirq_stage_hides_unobserved_coalescing_until_all_mode() {
        let labels = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![provider_snapshot("linux.sysfs.net.nic")],
            vec![state_series(
                1,
                "linux.nic.interface_kind",
                labels,
                "physical",
            )],
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();
        let kind = BlockKind::ExecutionContext(ExecutionContext::Hardirq);
        let dashboard = build_dashboard(&snapshot);
        let block = interface_block(&dashboard, &identity, kind).unwrap();
        let with_data = line_text(interface_detail::stage_lines(
            &snapshot,
            block,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData),
            120,
            false,
        ));
        assert!(!with_data.contains("COALESCE"), "{with_data}");

        let all = interface_detail::stage_lines(
            &snapshot,
            block,
            kind,
            DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
            120,
            false,
        );
        for lane in ["RX", "TX"] {
            assert!(all.iter().any(|line| {
                let text = line.to_string();
                let cells: Vec<_> = text
                    .split('│')
                    .map(str::trim)
                    .filter(|cell| !cell.is_empty())
                    .collect();
                cells == [lane, "-", "-", "-"]
            }));
        }
    }

    #[test]
    fn fixed_metric_slots_match_catalog_block_lane_and_rank() {
        for kind in OVERVIEW_LAYER_KINDS {
            let slots = global_metric_slots(kind);
            for slot in slots
                .rx
                .into_iter()
                .chain(slots.tx)
                .chain(slots.key)
                .flatten()
            {
                assert_slot(kind, slot);
            }
        }
        let kind = BlockKind::PacketStage(PacketStage::NetfilterConntrack);
        for slot in NETFILTER_KEY_SLOTS {
            assert_slot(kind, slot);
        }
    }

    #[test]
    fn interface_metric_slots_match_catalog_block_lane_and_display() {
        for kind in INTERFACE_BLOCK_KINDS {
            let slots = interface_stage_slots(kind);
            for slot in slots.rx.iter().chain(slots.tx).chain(slots.key) {
                let metric =
                    descriptor(slot.metric).expect("interface slots reference catalog metrics");
                let placement =
                    placement_for(metric).expect("interface slots reference placed metrics");
                assert_eq!(placement.block_kind(), kind, "{}", slot.metric);
                assert_eq!(placement.lane(), slot.placement_lane, "{}", slot.metric);
                assert_eq!(placement.display(), slot.display, "{}", slot.metric);
            }
        }
    }

    #[test]
    fn interface_detail_names_every_baseline_origin() {
        for (origin, label) in [
            (crate::monitor::BaselineOrigin::SessionStart, "start"),
            (crate::monitor::BaselineOrigin::Reset, "reset-base"),
            (
                crate::monitor::BaselineOrigin::RecoveredAfterGap,
                "gap-base",
            ),
        ] {
            let series = projected_counter(origin);
            assert!(!series.history_buckets().is_empty());
            for width in [60, 80, 120, 160] {
                for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                    let lines = interface_detail_series_lines("RX", &series, time_view, width);
                    assert!(lines.iter().all(|line| line.width() == usize::from(width)));
                    let text = line_text(lines);
                    assert_no_trends(&text);
                    let compacted = text
                        .chars()
                        .filter(|character| !character.is_whitespace() && *character != '|')
                        .collect::<String>();
                    let expected_rate = if time_view == TimeView::SinceBaseline
                        && origin == crate::monitor::BaselineOrigin::SessionStart
                    {
                        "5.0pps"
                    } else {
                        "10.0pps"
                    };
                    for expected in [
                        "current",
                        "+10",
                        expected_rate,
                        "fresh",
                        "sourcelinux.rtnetlink.link_stats",
                    ] {
                        assert!(
                            compacted.contains(expected),
                            "{width}: missing {expected}: {text}"
                        );
                    }
                    let projection = match time_view {
                        TimeView::Interval => "interval".to_owned(),
                        TimeView::SinceBaseline => format!("baseline({label})"),
                    };
                    assert!(compacted.contains(&projection), "{width}: {text}");
                }
            }
        }
    }

    #[test]
    fn summary_and_interface_lanes_keep_statistics_without_trends() {
        let series = projected_counter(crate::monitor::BaselineOrigin::SessionStart);
        assert!(!series.history_buckets().is_empty());
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            std::time::Duration::from_secs(2),
            None,
            vec![provider_snapshot("linux.rtnetlink.link_stats")],
            vec![series.clone()],
            crate::monitor::EngineTelemetry {
                history_buckets: series.history().bucket_count(),
                ..crate::monitor::EngineTelemetry::default()
            },
        )
        .unwrap();
        let identity = ordered_interface_identities(&snapshot, None, None).remove(0);
        let dashboard = build_dashboard(&snapshot);
        let kind = BlockKind::PacketStage(PacketStage::NetdeviceCore);
        let block = interface_block(&dashboard, &identity, kind).unwrap();
        for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
            let expected_rate = match time_view {
                TimeView::Interval => "10.0 pps",
                TimeView::SinceBaseline => "5.0 pps",
            };
            let summary = format_summary_group(Some(&[&series]), time_view);
            assert_no_trends(&summary);
            assert!(summary.contains("20"), "{summary}");
            assert!(summary.contains("+10"), "{summary}");
            assert!(summary.contains(expected_rate), "{summary}");
            for width in [60, 80, 120, 160] {
                for mode in [DetailMetricsMode::All, DetailMetricsMode::WithData] {
                    let lines = interface_detail::stage_lines(
                        &snapshot,
                        block,
                        kind,
                        DetailDisplayOptions::new(time_view, mode),
                        width,
                        false,
                    );
                    assert!(lines.iter().all(|line| line.width() == usize::from(width)));
                    let text = line_text(lines);
                    assert_no_trends(&text);
                    assert!(text.contains(expected_rate), "{width}: {text}");
                }
            }
        }
    }

    #[test]
    fn aggregate_summary_keeps_current_interval_and_baseline_totals_without_trends() {
        use crate::monitor::{
            MetricId, MetricLabels, MetricReading, ProviderSample, SampleReading,
        };
        use std::time::Duration;

        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        let mut snapshot = None;
        for (second, values) in [(1, [970, 950]), (2, [990, 980]), (3, [1000, 1000])] {
            let at = Duration::from_secs(second);
            let readings = values
                .into_iter()
                .enumerate()
                .map(|(cpu, value)| {
                    SampleReading::observed(
                        MetricId::new("linux.softirq.net_rx").unwrap(),
                        MetricLabels::new([(MetricLabel::Cpu, cpu.to_string())]).unwrap(),
                        MetricReading::Counter { value, bits: None },
                    )
                })
                .collect();
            let sample = ProviderSample::new(
                crate::monitor::ProviderId::new(SOFTIRQ_SOURCE).unwrap(),
                at,
                Duration::ZERO,
                crate::monitor::ProviderHealth::Fresh,
                readings,
            )
            .unwrap();
            snapshot = Some(engine.ingest(at, vec![sample], None).unwrap());
        }
        let snapshot = snapshot.unwrap();
        let group = snapshot
            .series()
            .iter()
            .filter(|series| series.metric().as_str() == "linux.softirq.net_rx")
            .collect::<Vec<_>>();
        assert_eq!(group.len(), 2);
        assert!(group
            .iter()
            .all(|series| !series.history_buckets().is_empty()));
        for (time_view, delta, rate) in [
            (TimeView::Interval, "+30", "30.0"),
            (TimeView::SinceBaseline, "+80", "26.7"),
        ] {
            let text = format_summary_group(Some(&group), time_view);
            assert_no_trends(&text);
            for expected in ["total/2CPU", "2000", delta, rate] {
                assert!(text.contains(expected), "missing {expected}: {text}");
            }
        }
    }

    fn assert_no_trends(text: &str) {
        assert!(!text.to_ascii_lowercase().contains("trend"), "{text}");
        assert!(
            !text
                .chars()
                .any(|character| ('\u{2581}'..='\u{2588}').contains(&character)),
            "{text}"
        );
    }

    #[test]
    fn detail_series_columns_align_for_short_and_long_metric_titles() {
        let interface = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();
        let qdisc = crate::monitor::MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Direction, "egress".to_owned()),
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::QdiscKind, "pfifo_fast".to_owned()),
            (MetricLabel::RowId, "10".to_owned()),
            (MetricLabel::Execution, "software".to_owned()),
        ])
        .unwrap();
        let short = counter_series(
            1,
            "linux.netdevice.rx_packets",
            interface,
            ProjectedValue::Fresh {
                value: 10,
                observed_at: std::time::Duration::from_secs(1),
            },
        );
        let long = counter_series_from(
            2,
            "linux.tc.packets",
            "linux.rtnetlink.tc",
            qdisc,
            ProjectedValue::Fresh {
                value: 20,
                observed_at: std::time::Duration::from_secs(1),
            },
        );

        for (width, expected_positions) in [
            (60, vec![31]),
            (80, vec![41]),
            (120, vec![42, 69]),
            (160, vec![38, 58, 85, 99]),
        ] {
            let lines = [&short, &long]
                .into_iter()
                .flat_map(|series| {
                    [TimeView::Interval, TimeView::SinceBaseline]
                        .into_iter()
                        .flat_map(|time_view| {
                            interface_detail_series_lines("TX", series, time_view, width)
                        })
                })
                .collect::<Vec<_>>();
            assert!(
                lines
                    .iter()
                    .all(|line| line_content(line).chars().count() == usize::from(width)),
                "{width} column detail rows must fit the viewport"
            );
            let positions = lines
                .iter()
                .map(line_content)
                .filter(|line| line.contains('|'))
                .map(|line| {
                    line.chars()
                        .enumerate()
                        .filter_map(|(index, character)| (character == '|').then_some(index))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let expected = positions.first().expect("detail rows contain separators");
            assert_eq!(expected, &expected_positions, "{width} columns");
            assert!(
                positions
                    .iter()
                    .all(|value| value == expected || (width == 120 && value == &[42])),
                "{width} columns: {positions:?}"
            );

            let rendered = line_text(interface_detail_series_lines(
                "TX",
                &long,
                TimeView::SinceBaseline,
                width,
            ));
            let compacted = rendered
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            assert_no_trends(&rendered);
            for expected in [
                "TXr10packetstxpfifo_fasteth0",
                "current20",
                "baseline(start)-",
                "fresh",
                "sourcelinux.rtnetlink.tc",
            ] {
                assert!(
                    compacted.contains(expected),
                    "missing {expected}: {rendered}"
                );
            }
        }
    }

    fn line_content(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn cause_uses_catalog_title_and_observed_value_at_dashboard_widths() {
        let title = descriptor("linux.nic.rx_missed_errors").unwrap().title;
        let observed = format_health_value(&HealthValue::RatePerSecond(42.0), None);

        for width in [60, 80, 120, 160] {
            let text = dashboard_cause_text(title, &observed, width);
            assert_eq!(text.chars().count(), width);
            assert!(
                text.contains("WHY  RX missed errors 42.0/s"),
                "{width}: {text}"
            );
            for internal in ["linux.", "rule=", "threshold=", "origin="] {
                assert!(!text.contains(internal), "{width}: {text}");
            }
        }
    }

    #[test]
    fn narrow_cause_keeps_a_metric_hint_at_twenty_and_thirty_columns() {
        let title = descriptor("linux.nic.rx_missed_errors").unwrap().title;
        let observed = format_health_value(&HealthValue::RatePerSecond(42.0), None);

        assert_eq!(
            dashboard_cause_text(title, &observed, 20),
            "   WHY  RX m~ 42.0/s"
        );
        assert_eq!(
            dashboard_cause_text(title, &observed, 30),
            "   WHY  RX missed erro~ 42.0/s"
        );
    }

    #[test]
    fn narrow_collection_causes_use_readable_status_abbreviations() {
        assert_eq!(
            dashboard_cause_text("ethtool statistics status", "collection timed out", 20),
            "   WHY  eth~ timeout"
        );
        assert_eq!(
            dashboard_cause_text("ethtool statistics status", "collection timed out", 30),
            "   WHY  ethtool stati~ timeout"
        );
        assert_eq!(
            dashboard_cause_text("ethtool statistics status", "collection not supported", 20),
            "   WHY  et~ not supp"
        );
    }

    #[test]
    fn collection_outcomes_are_operationally_readable_at_dashboard_widths() {
        for (observed, expected) in [
            ("complete", "collection complete"),
            ("refresh_pending", "settings refresh pending"),
            ("partial_schema_mismatch", "collection schema mismatch"),
            ("partial_cardinality_limit", "collection limit reached"),
            ("unsupported", "collection not supported"),
            ("command_not_found", "collector command not found"),
            ("permission_denied", "collection permission denied"),
            ("interface_unavailable", "interface unavailable"),
            ("timed_out", "collection timed out"),
            ("output_limit", "collector output limit reached"),
            ("invalid_output", "invalid collector output"),
            ("command_failed", "collector command failed"),
            ("io_error", "collection I/O error"),
        ] {
            let observed = HealthValue::State(observed.to_owned());
            let observed = format_health_value(&observed, None);
            for width in [60, 80, 120, 160] {
                let text = dashboard_cause_text("ethtool statistics status", &observed, width);
                assert_eq!(text.chars().count(), width);
                assert!(text.contains(expected), "{width}: {text}");
                assert!(!text.contains('_'), "{width}: {text}");
            }
        }
    }

    #[test]
    fn rendered_interface_cause_hides_health_engine_internals() {
        let snapshot = ethtool_timeout_snapshot();
        let dashboard = build_dashboard(&snapshot);
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();
        let assessments = interface_assessments(&snapshot, &dashboard, &identity);
        let cause = primary_interface_cause(&assessments).unwrap();

        for width in [60, 80, 120, 160] {
            let text = line_content(&dashboard_cause_line(Some(cause), width as u16));
            assert_eq!(text.chars().count(), width);
            assert!(
                text.contains("WHY  ethtool statistics status collection timed out"),
                "{width}: {text}"
            );
            for internal in ["linux.", "rule=", "threshold=", "origin="] {
                assert!(!text.contains(internal), "{width}: {text}");
            }
        }
    }

    #[test]
    fn interface_why_prefers_timeout_over_missing_fec() {
        let snapshot = ethtool_timeout_snapshot();
        let dashboard = build_dashboard(&snapshot);
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();
        let assessments = interface_assessments(&snapshot, &dashboard, &identity);
        assert!(assessments
            .iter()
            .flat_map(Assessment::causes)
            .any(|cause| {
                cause.metric().as_str() == "linux.nic.fec.corrected"
                    && cause.observed()
                        == &HealthValue::Unavailable(UnavailableReason::NotApplicable)
            }));

        let cause = primary_interface_cause(&assessments).unwrap();
        assert_eq!(
            cause.metric().as_str(),
            crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID
        );
        assert_eq!(
            cause.observed(),
            &HealthValue::State("timed_out".to_owned())
        );
    }

    #[test]
    fn compact_interface_title_keeps_ifindex() {
        let snapshot = ethtool_timeout_snapshot();
        let identity = ordered_interface_identities(&snapshot, None, None)
            .into_iter()
            .next()
            .unwrap();
        let text = line_text(vec![interface_summary_title_line(
            &identity,
            InterfaceKind::Physical,
            "UP",
            "1Gb/s",
            NetworkHealth::Unknown,
            EvidenceCoverage::Partial,
            60,
            true,
        )]);

        assert!(text.contains("eth0 ifindex 2"), "{text}");
    }

    #[test]
    fn overview_row_count_accounts_for_empty_and_populated_interface_sections() {
        assert_eq!(
            overview_row_count(0),
            GLOBAL_DASHBOARD_ROW_COUNT.saturating_add(2)
        );
        assert_eq!(
            overview_row_count(3),
            GLOBAL_DASHBOARD_ROW_COUNT
                .saturating_add(1)
                .saturating_add(3 * INTERFACE_SUMMARY_ROWS)
        );
    }

    #[test]
    fn empty_snapshot_interface_section_is_not_presented_as_pending() {
        let text = line_text(vec![empty_interface_line(80)]);

        assert!(text.contains("no interface rows visible"), "{text}");
        assert!(!text.contains("waiting"), "{text}");
    }

    #[test]
    fn visible_interface_range_skips_viewports_above_interface_summaries() {
        assert_eq!(
            visible_interface_range(&(0..GLOBAL_DASHBOARD_ROW_COUNT), 20),
            0..0
        );
        assert_eq!(visible_interface_range(&(12..12), 20), 0..0);
    }

    #[test]
    fn visible_interface_range_includes_partial_and_adjacent_summaries() {
        let start = interface_row_span_at(0).start;

        assert_eq!(visible_interface_range(&(start + 2..start + 3), 20), 0..1);
        assert_eq!(visible_interface_range(&(start + 5..start + 7), 20), 0..2);
    }

    #[test]
    fn visible_interface_range_clamps_at_last_interface() {
        let last = interface_row_span_at(19);

        assert_eq!(
            visible_interface_range(&(last.start..usize::MAX), 20),
            19..20
        );
        assert_eq!(
            visible_interface_range(&(last.end..last.end.saturating_add(10)), 20),
            20..20
        );
    }

    #[test]
    fn append_visible_lines_keeps_only_the_viewport_intersection() {
        let mut output = Vec::new();
        append_visible_lines(
            &mut output,
            &(11..14),
            10,
            (0..5).map(|index| Line::from(format!("row-{index}"))),
        );

        assert_eq!(line_text(output), "row-1 row-2 row-3");
    }

    #[test]
    fn dashboard_scroll_reaches_lines_beyond_u16_max() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(24, 2);
        let mut terminal = Terminal::new(backend).unwrap();
        let lines = (0..=usize::from(u16::MAX) + 2)
            .map(|index| Line::from(format!("row-{index}")))
            .collect::<Vec<_>>();
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_dashboard_lines(frame, area, lines, usize::from(u16::MAX) + 1);
            })
            .unwrap();

        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("row-65536"), "{rendered}");
        assert!(rendered.contains("row-65537"), "{rendered}");
        assert!(!rendered.contains("row-65535"), "{rendered}");
    }

    fn assert_slot(kind: BlockKind, slot: MetricSlot) {
        let metric = descriptor(slot.metric).expect("fixed slots reference catalog metrics");
        let placement = placement_for(metric).expect("fixed slots reference placed metrics");
        assert_eq!(placement.block_kind(), kind, "{}", slot.metric);
        assert_eq!(placement.lane(), slot.lane, "{}", slot.metric);
        assert_eq!(
            placement.display(),
            DisplaySlot::Summary { rank: slot.rank },
            "{}",
            slot.metric
        );
    }
}
