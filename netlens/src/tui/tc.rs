use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::monitor::{
    CounterContinuity, InterfaceViewAnchor, MetricLabel, MonitorSnapshot, ProjectedValue,
    SeriesSnapshot, SeriesValue,
};

use super::{
    presentation::matches_anchor,
    socket::{format_scaled_value, wrap_text},
    theme,
};

const TABLE_HEADER_ROWS: usize = 3;
const METRICS: [(&str, &str, &str); 13] = [
    (
        "bytes",
        "Bandwidth (bit/s)",
        "Bytes sent; cumulative value is bytes.",
    ),
    (
        "packets",
        "Packets/s",
        "Accounting packets; may differ from NIC wire packets.",
    ),
    (
        "drops",
        "Drops/s",
        "Packets dropped at this qdisc accounting point.",
    ),
    (
        "requeues",
        "Requeues/s",
        "Packets returned to the queue for retry; not drops or TCP retransmissions.",
    ),
    (
        "overlimits",
        "Overlimits/s",
        "Limit events; not a packet-loss counter.",
    ),
    (
        "backlog_bytes",
        "Backlog (bytes)",
        "Current queued bytes; a gauge, not a cumulative total.",
    ),
    (
        "backlog_packets",
        "Queue length",
        "Current queued packets; a gauge, not a cumulative total.",
    ),
    (
        "ecn_marks",
        "ECN marks/s",
        "Packets marked with ECN instead of dropped, when exported.",
    ),
    (
        "drop_overlimit",
        "Limit drops/s",
        "Packets dropped at the qdisc-specific queue limit.",
    ),
    (
        "new_flow_count",
        "New flows/s",
        "Packets activating a new flow in this qdisc.",
    ),
    (
        "max_packet_bytes",
        "Max packet (bytes)",
        "Largest observed packet, when exported.",
    ),
    (
        "new_flows_len",
        "New flow list",
        "Current flows in the new-flow list.",
    ),
    (
        "old_flows_len",
        "Old flow list",
        "Current flows in the old-flow list.",
    ),
];

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct TcRowKey {
    generation: u64,
    provider: String,
    ifindex: u32,
    pub(super) row_id: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) enum TcValue<T> {
    Fresh(T),
    Stale(Option<T>),
    Reset,
    Warming,
    Gap,
    #[default]
    Unavailable,
}

impl<T: Copy> TcValue<T> {
    pub(super) fn fresh(self) -> Option<T> {
        match self {
            Self::Fresh(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct TcMetric {
    pub(super) current: TcValue<u64>,
    pub(super) rate: TcValue<f64>,
    pub(super) counter: bool,
}

impl TcMetric {
    fn from_series(series: &SeriesSnapshot) -> Self {
        let (current, interval, counter) = match series.value() {
            SeriesValue::Counter {
                current, interval, ..
            } => (current, *interval, true),
            SeriesValue::Gauge { current, .. } => (current, None, false),
            SeriesValue::State { .. } => return Self::default(),
        };
        let rate = match current {
            ProjectedValue::Fresh { .. } if counter => match interval {
                Some(CounterContinuity::Reset) => TcValue::Reset,
                Some(CounterContinuity::FirstSample) => TcValue::Warming,
                Some(CounterContinuity::RecoveredAfterGap) => TcValue::Gap,
                Some(continuity) => continuity
                    .rate_per_second()
                    .map_or(TcValue::Unavailable, TcValue::Fresh),
                None => TcValue::Unavailable,
            },
            ProjectedValue::Stale { .. } => TcValue::Stale(None),
            _ => TcValue::Unavailable,
        };
        let current = match current {
            ProjectedValue::Fresh { value, .. } => TcValue::Fresh(*value),
            ProjectedValue::Stale { last, .. } => TcValue::Stale(Some(*last)),
            ProjectedValue::Unavailable { .. } => TcValue::Unavailable,
        };
        Self {
            current,
            rate,
            counter,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct TcRow {
    pub(super) key: TcRowKey,
    pub(super) interface: String,
    pub(super) ifindex: u32,
    pub(super) kind: String,
    pub(super) direction: String,
    pub(super) root: Option<bool>,
    pub(super) handle: Option<String>,
    pub(super) parent: Option<String>,
    metrics: BTreeMap<String, TcMetric>,
}

impl TcRow {
    pub(super) fn metric(&self, name: &str) -> TcMetric {
        self.metrics.get(name).copied().unwrap_or_default()
    }

    pub(super) fn is_egress_root(&self) -> bool {
        self.root == Some(true) && self.direction == "egress"
    }

    pub(super) fn overview_matches(&self) -> bool {
        self.is_egress_root()
            && ["drops", "requeues"].iter().any(|name| {
                self.metric(name)
                    .rate
                    .fresh()
                    .is_some_and(|value| value.is_finite() && value > 0.0)
            })
    }

    fn object_label(&self, hierarchy: bool) -> String {
        let role = if !hierarchy {
            String::new()
        } else if self.root == Some(true) {
            " ROOT".to_owned()
        } else {
            format!(" <-{}", self.parent.as_deref().unwrap_or("n/a"))
        };
        format!(
            "{} {}{role}",
            self.kind,
            self.handle.as_deref().unwrap_or("n/a")
        )
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct TcCoverage {
    pub(super) roots: usize,
    pub(super) shown: usize,
    pub(super) missing: usize,
    pub(super) stale: usize,
    pub(super) reset: usize,
    pub(super) warming: usize,
    pub(super) unknown_attachment: usize,
    pub(super) not_applicable: usize,
    pub(super) provider: String,
}

impl TcCoverage {
    pub(super) fn summary(&self) -> String {
        let mut parts = vec![
            format!("{}/{} roots", self.shown, self.roots),
            "drop/s > 0 or requeue/s > 0".to_owned(),
        ];
        for (label, count) in [
            ("unavailable", self.missing),
            ("stale", self.stale),
            ("reset", self.reset),
            ("warming", self.warming),
            ("attachment n/a", self.unknown_attachment),
            ("noqueue", self.not_applicable),
        ] {
            if count > 0 {
                parts.push(format!("{count} {label}"));
            }
        }
        parts.join(" | ")
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct TcTable {
    pub(super) rows: Vec<TcRow>,
    provider: String,
}

impl TcTable {
    pub(super) fn from_snapshot(
        snapshot: Option<&MonitorSnapshot>,
        anchor: Option<&InterfaceViewAnchor>,
        alias: Option<&str>,
    ) -> Self {
        let Some(snapshot) = snapshot else {
            return Self {
                rows: Vec::new(),
                provider: "n/a: waiting for TC sample".to_owned(),
            };
        };
        let provider = snapshot
            .providers()
            .iter()
            .filter(|provider| {
                matches!(
                    provider.provider().as_str(),
                    "linux.tc.json" | "linux.rtnetlink.tc"
                )
            })
            .map(|provider| {
                format!(
                    "{} {} (sample {:.1}s, cost {:.1}ms)",
                    provider.provider().as_str(),
                    provider.health().as_str(),
                    provider.last_attempt_at().as_secs_f64(),
                    provider.collection_duration().as_secs_f64() * 1000.0
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let mut rows = BTreeMap::<TcRowKey, TcRow>::new();
        for series in snapshot.series() {
            let Some(metric) = series.metric().as_str().strip_prefix("linux.tc.") else {
                continue;
            };
            let labels = series.labels();
            if labels.get(MetricLabel::ObjectKind) != Some("qdisc")
                || !matches_anchor(series, anchor, alias)
            {
                continue;
            }
            let (Some(interface), Some(ifindex), Some(row_id)) = (
                labels.get(MetricLabel::Interface),
                labels
                    .get(MetricLabel::Ifindex)
                    .and_then(|value| value.parse::<u32>().ok()),
                labels
                    .get(MetricLabel::RowId)
                    .and_then(|value| value.parse::<u64>().ok()),
            ) else {
                continue;
            };
            let key = TcRowKey {
                generation: snapshot.generation(),
                provider: series.provider().as_str().to_owned(),
                ifindex,
                row_id,
            };
            let row = rows.entry(key.clone()).or_insert_with(|| {
                let attachment = labels.get(MetricLabel::QdiscAttachment).and_then(|value| {
                    serde_json::from_str::<(bool, Option<String>, Option<String>)>(value).ok()
                });
                let (root, handle, parent) = attachment
                    .map_or((None, None, None), |(root, handle, parent)| {
                        (Some(root), handle, parent)
                    });
                TcRow {
                    key,
                    interface: interface.to_owned(),
                    ifindex,
                    kind: labels
                        .get(MetricLabel::QdiscKind)
                        .unwrap_or("n/a")
                        .to_owned(),
                    direction: labels
                        .get(MetricLabel::Direction)
                        .unwrap_or("n/a")
                        .to_owned(),
                    root,
                    handle,
                    parent,
                    metrics: BTreeMap::new(),
                }
            });
            row.metrics
                .insert(metric.to_owned(), TcMetric::from_series(series));
        }
        Self {
            rows: rows.into_values().collect(),
            provider: if provider.is_empty() {
                "n/a: TC provider not sampled".to_owned()
            } else {
                provider
            },
        }
    }

    pub(super) fn row(&self, key: &TcRowKey) -> Option<&TcRow> {
        self.rows.iter().find(|row| &row.key == key)
    }

    pub(super) fn overview_rows(&self) -> Vec<&TcRow> {
        let mut rows = self
            .rows
            .iter()
            .filter(|row| row.overview_matches())
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.ifindex.cmp(&b.ifindex).then(a.key.cmp(&b.key)));
        rows
    }

    pub(super) fn overview_coverage(&self) -> TcCoverage {
        let mut coverage = TcCoverage {
            provider: self.provider.clone(),
            ..TcCoverage::default()
        };
        for row in &self.rows {
            if row.root.is_none() {
                coverage.unknown_attachment += 1;
            }
            if !row.is_egress_root() {
                continue;
            }
            coverage.roots += 1;
            coverage.shown += usize::from(row.overview_matches());
            if row.kind == "noqueue"
                && row
                    .metrics
                    .values()
                    .all(|metric| matches!(metric.current, TcValue::Unavailable))
            {
                coverage.not_applicable += 1;
                continue;
            }
            let rates = [row.metric("drops").rate, row.metric("requeues").rate];
            coverage.missing += usize::from(
                rates
                    .iter()
                    .any(|value| matches!(value, TcValue::Unavailable | TcValue::Gap))
                    || ["backlog_bytes", "backlog_packets"]
                        .iter()
                        .any(|name| matches!(row.metric(name).current, TcValue::Unavailable)),
            );
            coverage.stale += usize::from(
                rates.iter().any(|value| matches!(value, TcValue::Stale(_)))
                    || ["backlog_bytes", "backlog_packets"]
                        .iter()
                        .any(|name| matches!(row.metric(name).current, TcValue::Stale(_))),
            );
            coverage.reset += usize::from(rates.contains(&TcValue::Reset));
            coverage.warming += usize::from(rates.contains(&TcValue::Warming));
        }
        coverage
    }

    /// Sort siblings while retaining all roots, leaves, ingress and unknown attachments.
    pub(super) fn ordered_rows(&self, state: &TcViewState) -> Vec<&TcRow> {
        let mut sorted = self.rows.iter().collect::<Vec<_>>();
        sorted.sort_by(|a, b| compare_rows(a, b, state.sort, state.descending));
        let parents = self
            .rows
            .iter()
            .map(|row| {
                let parent = if row.root == Some(true) {
                    None
                } else {
                    row.parent.as_deref().and_then(|parent| {
                        let major = parent.split_once(':')?.0;
                        self.rows
                            .iter()
                            .filter(|candidate| {
                                candidate.key != row.key
                                    && candidate.ifindex == row.ifindex
                                    && candidate.direction == row.direction
                                    && candidate.handle.as_deref().is_some_and(|handle| {
                                        handle.strip_suffix(':').is_some_and(|handle_major| {
                                            handle_major.trim_start_matches('0')
                                                == major.trim_start_matches('0')
                                        })
                                    })
                            })
                            .min_by_key(|candidate| (candidate.root != Some(true), &candidate.key))
                    })
                };
                (row.key.clone(), parent.map(|parent| parent.key.clone()))
            })
            .collect::<BTreeMap<_, _>>();
        fn visit<'a>(
            row: &'a TcRow,
            sorted: &[&'a TcRow],
            parents: &BTreeMap<TcRowKey, Option<TcRowKey>>,
            seen: &mut BTreeSet<TcRowKey>,
            result: &mut Vec<&'a TcRow>,
        ) {
            if !seen.insert(row.key.clone()) {
                return;
            }
            result.push(row);
            for child in sorted {
                if parents.get(&child.key).and_then(Option::as_ref) == Some(&row.key) {
                    visit(child, sorted, parents, seen, result);
                }
            }
        }
        let mut result = Vec::with_capacity(sorted.len());
        let mut seen = BTreeSet::new();
        for row in &sorted {
            if parents.get(&row.key).and_then(Option::as_ref).is_none() {
                visit(row, &sorted, &parents, &mut seen, &mut result);
            }
        }
        // Malformed/cyclic parent metadata must not hide an observed object.
        for row in &sorted {
            visit(row, &sorted, &parents, &mut seen, &mut result);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum TcSort {
    Netdev,
    #[default]
    Drops,
    Requeues,
    Backlog,
    QueueLength,
    Bandwidth,
    Packets,
    Overlimits,
}

impl TcSort {
    const ALL: [Self; 8] = [
        Self::Netdev,
        Self::Drops,
        Self::Requeues,
        Self::Backlog,
        Self::QueueLength,
        Self::Bandwidth,
        Self::Packets,
        Self::Overlimits,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Netdev => "NETDEV",
            Self::Drops => "DROP/s",
            Self::Requeues => "REQUEUE/s",
            Self::Backlog => "BACKLOG",
            Self::QueueLength => "QLEN",
            Self::Bandwidth => "BW bit/s",
            Self::Packets => "PPS",
            Self::Overlimits => "OVER/s",
        }
    }

    fn value(self, row: &TcRow) -> Option<f64> {
        match self {
            Self::Netdev => Some(f64::from(row.ifindex)),
            Self::Backlog => row
                .metric("backlog_bytes")
                .current
                .fresh()
                .map(|value| value as f64),
            Self::QueueLength => row
                .metric("backlog_packets")
                .current
                .fresh()
                .map(|value| value as f64),
            _ => row
                .metric(match self {
                    Self::Drops => "drops",
                    Self::Requeues => "requeues",
                    Self::Bandwidth => "bytes",
                    Self::Packets => "packets",
                    _ => "overlimits",
                })
                .rate
                .fresh(),
        }
    }
}

fn compare_rows(a: &TcRow, b: &TcRow, sort: TcSort, descending: bool) -> Ordering {
    let order = match (sort.value(a), sort.value(b)) {
        (Some(a), Some(b)) => {
            if descending {
                b.total_cmp(&a)
            } else {
                a.total_cmp(&b)
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    order.then(a.key.cmp(&b.key))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum TcMetrics {
    #[default]
    Queue,
    Traffic,
}

#[derive(Clone, Debug)]
pub(super) struct TcViewState {
    pub(super) selected: Option<TcRowKey>,
    pub(super) sort: TcSort,
    pub(super) descending: bool,
    pub(super) metrics: TcMetrics,
    pub(super) row_offset: usize,
    detail: bool,
    list_offset: usize,
    viewport_rows: usize,
}

impl Default for TcViewState {
    fn default() -> Self {
        Self {
            selected: None,
            sort: TcSort::Drops,
            descending: true,
            metrics: TcMetrics::Queue,
            row_offset: 0,
            detail: false,
            list_offset: 0,
            viewport_rows: 1,
        }
    }
}

impl TcViewState {
    pub(super) fn is_detail(&self) -> bool {
        self.detail
    }

    pub(super) fn detail(&self) -> bool {
        self.is_detail()
    }

    pub(super) fn selected_key(&self) -> Option<&TcRowKey> {
        self.selected.as_ref()
    }

    pub(super) fn select_key(&mut self, table: &TcTable, key: &TcRowKey) -> bool {
        self.select(table, key)
    }

    pub(super) fn move_selection(&mut self, table: &TcTable, amount: isize) {
        self.move_by(table, amount);
    }

    pub(super) fn open(&mut self, table: &TcTable) {
        self.enter(table);
    }

    pub(super) fn reconcile(&mut self, table: &TcTable) {
        // Keep a vanished detail's identity until Back; never silently switch objects.
        if self.detail {
            return;
        }
        let rows = table.ordered_rows(self);
        if !rows
            .iter()
            .any(|row| Some(&row.key) == self.selected.as_ref())
        {
            self.selected = rows.first().map(|row| row.key.clone());
            self.row_offset = 0;
        }
        self.ensure_selection_visible(table);
    }

    pub(super) fn select(&mut self, table: &TcTable, key: &TcRowKey) -> bool {
        if table.row(key).is_none() {
            return false;
        }
        self.selected = Some(key.clone());
        if !self.detail {
            self.ensure_selection_visible(table);
        }
        true
    }

    pub(super) fn enter(&mut self, table: &TcTable) {
        self.reconcile(table);
        if !self.detail
            && self
                .selected
                .as_ref()
                .is_some_and(|key| table.row(key).is_some())
        {
            self.list_offset = self.row_offset;
            self.row_offset = 0;
            self.detail = true;
        }
    }

    pub(super) fn open_detail(&mut self, table: &TcTable, key: &TcRowKey) -> bool {
        if !self.select_key(table, key) {
            return false;
        }
        self.enter(table);
        true
    }

    /// True means the caller should leave TC. Detail return keeps the row identity.
    pub(super) fn back(&mut self) -> bool {
        if !self.detail {
            return true;
        }
        self.detail = false;
        self.row_offset = self.list_offset;
        false
    }

    pub(super) fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = rows.max(1);
    }

    pub(super) fn clamp_content_rows(&mut self, rows: usize) {
        self.row_offset = self.row_offset.min(rows.saturating_sub(self.viewport_rows));
    }

    pub(super) fn scroll_top(&mut self, table: &TcTable) {
        self.row_offset = 0;
        if !self.detail {
            self.selected = table.ordered_rows(self).first().map(|row| row.key.clone());
        }
    }

    fn move_by(&mut self, table: &TcTable, delta: isize) {
        if self.detail {
            self.row_offset = self.row_offset.saturating_add_signed(delta);
            return;
        }
        self.reconcile(table);
        let rows = table.ordered_rows(self);
        let current = rows
            .iter()
            .position(|row| Some(&row.key) == self.selected.as_ref())
            .unwrap_or(0);
        if let Some(row) = rows.get(
            current
                .saturating_add_signed(delta)
                .min(rows.len().saturating_sub(1)),
        ) {
            self.selected = Some(row.key.clone());
        }
        self.ensure_selection_visible(table);
    }

    pub(super) fn cycle_sort(&mut self, table: &TcTable) {
        let index = TcSort::ALL
            .iter()
            .position(|sort| sort == &self.sort)
            .unwrap_or(0);
        self.sort = (1..=TcSort::ALL.len())
            .map(|offset| TcSort::ALL[(index + offset) % TcSort::ALL.len()])
            .find(|sort| tc_column(*sort, self.metrics).is_some())
            .unwrap_or(TcSort::Drops);
        self.ensure_selection_visible(table);
    }

    pub(super) fn reverse_sort(&mut self, table: &TcTable) {
        self.descending = !self.descending;
        self.ensure_selection_visible(table);
    }

    pub(super) fn click_header(&mut self, table: &TcTable, width: u16, x: u16, row: usize) -> bool {
        if self.detail || row != TABLE_HEADER_ROWS - 1 || x >= width {
            return false;
        }
        let mut start = 0;
        for (index, size) in widths(width).into_iter().enumerate() {
            if (start..start + size).contains(&usize::from(x)) {
                if let Some(sort) = TcSort::ALL
                    .into_iter()
                    .find(|sort| tc_column(*sort, self.metrics) == Some(index))
                {
                    self.descending = if self.sort == sort {
                        !self.descending
                    } else {
                        sort != TcSort::Netdev
                    };
                    self.sort = sort;
                    self.ensure_selection_visible(table);
                    return true;
                }
            }
            start += size + 1;
        }
        false
    }

    pub(super) fn toggle_metrics(&mut self) {
        self.metrics = match self.metrics {
            TcMetrics::Queue => TcMetrics::Traffic,
            TcMetrics::Traffic => TcMetrics::Queue,
        };
        if tc_column(self.sort, self.metrics).is_none() {
            self.sort = TcSort::Drops;
            self.descending = true;
        }
    }

    fn ensure_selection_visible(&mut self, table: &TcTable) {
        if self.detail {
            return;
        }
        if let Some(index) = self
            .selected_key()
            .and_then(|key| table_row_index(table, self, key))
        {
            if index < self.row_offset {
                self.row_offset = index;
            }
            if index >= self.row_offset.saturating_add(self.viewport_rows) {
                self.row_offset = index.saturating_add(1).saturating_sub(self.viewport_rows);
            }
        }
        self.clamp_content_rows(TABLE_HEADER_ROWS + table.rows.len().max(1));
    }
}

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, table: &TcTable, state: &TcViewState) {
    let lines = lines(table, state, area.width);
    let offset = state
        .row_offset
        .min(lines.len().saturating_sub(usize::from(area.height)));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(usize::from(area.height))
                .collect::<Vec<_>>(),
        ),
        area,
    );
}

pub(super) fn row_count(table: &TcTable, state: &TcViewState, width: u16) -> usize {
    if state.detail() {
        lines(table, state, width).len()
    } else {
        TABLE_HEADER_ROWS + table.rows.len().max(1)
    }
}

/// content_row includes the scroll offset, relative to the content area's first line.
pub(super) fn table_row_key(
    table: &TcTable,
    state: &TcViewState,
    content_row: usize,
) -> Option<TcRowKey> {
    if state.detail() {
        return None;
    }
    table
        .ordered_rows(state)
        .get(content_row.checked_sub(TABLE_HEADER_ROWS)?)
        .map(|row| row.key.clone())
}

pub(super) fn table_row_index(
    table: &TcTable,
    state: &TcViewState,
    key: &TcRowKey,
) -> Option<usize> {
    if state.detail {
        return None;
    }
    table
        .ordered_rows(state)
        .iter()
        .position(|row| &row.key == key)
        .map(|index| TABLE_HEADER_ROWS + index)
}

pub(super) fn overview_lines(table: &TcTable, width: u16) -> Vec<Line<'static>> {
    let mut lines = overview_header(table, width);
    let rows = table.overview_rows();
    if rows.is_empty() {
        let coverage = table.overview_coverage();
        let text = if coverage.roots == 0 {
            "No observed egress ROOT qdiscs; statistics n/a."
        } else {
            "No fresh drops or requeues in this interval; see coverage."
        };
        lines.extend(wrapped(text, width, theme::MUTED));
    } else {
        lines.extend(
            rows.iter()
                .map(|row| data_line(row, width, TcMetrics::Queue, false, None)),
        );
    }
    lines
}

fn overview_header(table: &TcTable, width: u16) -> Vec<Line<'static>> {
    let mut lines = wrapped(
        &format!(
            "QDISC EGRESS ROOT | {}",
            table.overview_coverage().summary()
        ),
        width.saturating_sub(1),
        theme::TEXT,
    );
    if let Some(title) = lines.first_mut() {
        *title = super::summary::colored_heading(&title.to_string(), false, theme::QDISC);
    }
    if !table.overview_rows().is_empty() {
        lines.push(heading_line(width, TcMetrics::Queue, None));
    }
    lines
}

pub(super) fn overview_row_key(
    table: &TcTable,
    width: u16,
    content_row: usize,
) -> Option<TcRowKey> {
    table
        .overview_rows()
        .get(content_row.checked_sub(overview_header(table, width).len())?)
        .map(|row| row.key.clone())
}

pub(super) fn overview_row_index(table: &TcTable, width: u16, key: &TcRowKey) -> Option<usize> {
    table
        .overview_rows()
        .iter()
        .position(|row| &row.key == key)
        .map(|index| overview_header(table, width).len() + index)
}

fn lines(table: &TcTable, state: &TcViewState, width: u16) -> Vec<Line<'static>> {
    if state.detail {
        return detail_lines(table, state, width);
    }
    let mut lines = vec![
        clipped_line(
            &format!(
                "Qdisc | {} objects | sort {} {} | {}",
                table.rows.len(),
                state.sort.label(),
                if state.descending { "desc" } else { "asc" },
                table.provider
            ),
            width,
            theme::TEXT_STRONG,
        ),
        clipped_line(
            "Qdiscs: root / parent hierarchy | class and action statistics not collected",
            width,
            theme::MUTED,
        ),
        heading_line(width, state.metrics, Some((state.sort, state.descending))),
    ];
    if table.rows.is_empty() {
        lines.push(clipped_line(
            "No observed qdiscs; TC statistics n/a",
            width,
            theme::MUTED,
        ));
    }
    for row in table.ordered_rows(state) {
        let mut line = data_line(
            row,
            width,
            state.metrics,
            true,
            Some((state.sort, state.descending)),
        );
        if state.selected.as_ref() == Some(&row.key) {
            super::sort_table::select(&mut line);
        }
        lines.push(line);
    }
    lines
}

fn detail_lines(table: &TcTable, state: &TcViewState, width: u16) -> Vec<Line<'static>> {
    let Some(row) = state.selected.as_ref().and_then(|key| table.row(key)) else {
        return wrapped(
            "Selected qdisc is no longer present; statistics n/a. Back returns to the TC table.",
            width,
            theme::WARN,
        );
    };
    let mut lines = wrapped(
        &format!(
            "{} / {} | {} | ifindex {}",
            row.interface,
            row.object_label(true),
            row.direction,
            row.ifindex
        ),
        width,
        theme::TEXT_STRONG,
    );
    lines.extend(wrapped(
        &format!(
            "Parent: {} | root: {} | {}",
            row.parent.as_deref().unwrap_or(if row.root == Some(true) {
                "root"
            } else {
                "n/a"
            }),
            row.root
                .map_or("n/a", |root| if root { "yes" } else { "no" }),
            table.provider
        ),
        width,
        theme::MUTED,
    ));
    lines.extend(wrapped(
        "RATE / CURRENT | CUMULATIVE since object creation/reset",
        width,
        theme::ACCENT,
    ));
    if row.kind == "noqueue" {
        lines.extend(wrapped(
            "No software queue (noqueue); absent statistics are not applicable.",
            width,
            theme::MUTED,
        ));
    }
    for (name, title, meaning) in METRICS {
        let metric = row.metric(name);
        let counter = !matches!(
            name,
            "backlog_bytes"
                | "backlog_packets"
                | "max_packet_bytes"
                | "new_flows_len"
                | "old_flows_len"
        );
        let value = if counter {
            rate_text(metric.rate, if name == "bytes" { 8.0 } else { 1.0 })
        } else {
            current_text(metric.current)
        };
        let total = if counter {
            current_text(metric.current)
        } else {
            "n/a (gauge)".to_owned()
        };
        lines.extend(wrapped(
            &format!("{title}: {value} | {total}"),
            width,
            theme::TEXT,
        ));
        lines.extend(wrapped(&format!("  {meaning}"), width, theme::MUTED));
    }
    lines.extend(wrapped("Root, class and leaf accounting may overlap. Compare each object separately; no totals are summed.", width, theme::MUTED));
    lines.extend(wrapped("n/a: not exported or unavailable; warmup: first sample; reset/gap: no valid interval rate; stale: last sample, not a current rate.", width, theme::MUTED));
    lines.extend(wrapped(
        "Class/action statistics and qdisc options are not collected.",
        width,
        theme::MUTED,
    ));
    lines
}

fn widths(width: u16) -> [usize; 6] {
    let available = usize::from(width).saturating_sub(5);
    if available < 55 {
        let base = available / 6;
        return [base, base + available % 6, base, base, base, base];
    }
    let netdev = (available / 7).clamp(8, 16);
    let number = (available / 8).clamp(7, 12);
    [
        netdev,
        available - netdev - number * 3 - 9,
        number,
        9,
        number,
        number,
    ]
}

fn cells(
    values: &[String; 6],
    width: u16,
    heading: bool,
    metrics: TcMetrics,
    active_sort: Option<(TcSort, bool)>,
) -> Line<'static> {
    let widths = widths(width);
    let active_column = active_sort.and_then(|(sort, _)| tc_column(sort, metrics));
    let descending = active_sort.is_some_and(|(_, descending)| descending);
    let mut spans = Vec::with_capacity(values.len() * 2);
    for (index, (value, column_width)) in values.iter().zip(widths).enumerate() {
        if index > 0 {
            spans.push(Span::styled("|", Style::default().fg(theme::DIVIDER)));
        }
        let active = active_column == Some(index);
        let sortable = TcSort::ALL
            .into_iter()
            .any(|sort| tc_column(sort, metrics) == Some(index));
        let value = if heading && sortable && active_sort.is_some() {
            super::sort_table::label(value, column_width, active.then_some(descending))
        } else {
            value.clone()
        };
        let text = if index >= 2 && value.len() > column_width {
            value.parse::<f64>().ok().map_or_else(
                || fit(&value, column_width),
                |value| format_scaled_value(value, column_width),
            )
        } else {
            fit(&value, column_width)
        };
        let text = if index < 2 {
            format!("{text:<column_width$}")
        } else {
            format!("{text:>column_width$}")
        };
        let mut style = Style::default()
            .fg(if heading { theme::ACCENT } else { theme::TEXT })
            .add_modifier(if heading {
                Modifier::BOLD
            } else {
                Modifier::empty()
            });
        if active {
            style = style
                .bg(theme::SORT_BG)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        }
        if heading {
            style = super::sort_table::header_style(active, theme::TEXT);
        }
        spans.push(Span::styled(text, style));
    }
    Line::from(spans)
}

fn heading_line(
    width: u16,
    metrics: TcMetrics,
    active_sort: Option<(TcSort, bool)>,
) -> Line<'static> {
    cells(
        &match metrics {
            TcMetrics::Queue => [
                "NETDEV",
                "QDISC/ID",
                "DROP/s",
                "REQUEUE/s",
                "BACKLOG",
                "QLEN",
            ],
            TcMetrics::Traffic => ["NETDEV", "QDISC/ID", "BW bit/s", "PPS", "DROP/s", "OVER/s"],
        }
        .map(str::to_owned),
        width,
        true,
        metrics,
        active_sort,
    )
}

fn data_line(
    row: &TcRow,
    width: u16,
    metrics: TcMetrics,
    hierarchy: bool,
    active_sort: Option<(TcSort, bool)>,
) -> Line<'static> {
    let values = match metrics {
        TcMetrics::Queue => [
            row.interface.clone(),
            row.object_label(hierarchy),
            rate_text(row.metric("drops").rate, 1.0),
            rate_text(row.metric("requeues").rate, 1.0),
            current_text(row.metric("backlog_bytes").current),
            current_text(row.metric("backlog_packets").current),
        ],
        TcMetrics::Traffic => [
            row.interface.clone(),
            row.object_label(hierarchy),
            rate_text(row.metric("bytes").rate, 8.0),
            rate_text(row.metric("packets").rate, 1.0),
            rate_text(row.metric("drops").rate, 1.0),
            rate_text(row.metric("overlimits").rate, 1.0),
        ],
    };
    cells(&values, width, false, metrics, active_sort)
}

fn tc_column(sort: TcSort, metrics: TcMetrics) -> Option<usize> {
    match (metrics, sort) {
        (_, TcSort::Netdev) => Some(0),
        (TcMetrics::Queue, TcSort::Drops) => Some(2),
        (TcMetrics::Queue, TcSort::Requeues) => Some(3),
        (TcMetrics::Queue, TcSort::Backlog) => Some(4),
        (TcMetrics::Queue, TcSort::QueueLength) => Some(5),
        (TcMetrics::Traffic, TcSort::Bandwidth) => Some(2),
        (TcMetrics::Traffic, TcSort::Packets) => Some(3),
        (TcMetrics::Traffic, TcSort::Drops) => Some(4),
        (TcMetrics::Traffic, TcSort::Overlimits) => Some(5),
        _ => None,
    }
}

fn rate_text(value: TcValue<f64>, scale: f64) -> String {
    match value {
        TcValue::Fresh(value) if value > 0.0 && value * scale < 0.1 => "<0.1".to_owned(),
        TcValue::Fresh(value) if value.is_finite() => format!("{:.1}", value * scale),
        TcValue::Stale(_) => "stale".to_owned(),
        TcValue::Reset => "reset".to_owned(),
        TcValue::Warming => "warmup".to_owned(),
        TcValue::Gap => "gap".to_owned(),
        _ => "n/a".to_owned(),
    }
}

fn current_text(value: TcValue<u64>) -> String {
    match value {
        TcValue::Fresh(value) => value.to_string(),
        TcValue::Stale(Some(value)) => format!("stale {value}"),
        TcValue::Stale(None) => "stale".to_owned(),
        _ => "n/a".to_owned(),
    }
}

fn fit(text: &str, width: usize) -> String {
    if text.len() <= width {
        text.to_owned()
    } else if width == 0 {
        String::new()
    } else {
        format!("{}~", text.chars().take(width - 1).collect::<String>())
    }
}

fn clipped_line(text: &str, width: u16, color: ratatui::style::Color) -> Line<'static> {
    Line::styled(fit(text, usize::from(width)), Style::default().fg(color))
}

fn wrapped(text: &str, width: u16, color: ratatui::style::Color) -> Vec<Line<'static>> {
    wrap_text(text, usize::from(width).max(1))
        .into_iter()
        .map(|line| Line::styled(line, Style::default().fg(color)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{
        BaselineOrigin, CounterSpan, EngineTelemetry, HistoryCoverage, MetricId, MetricLabels,
        MonitorErrorCode, ProviderHealth, ProviderId, ProviderSnapshot, SeriesId,
        UnavailableReason,
    };
    use ratatui::{backend::TestBackend, Terminal};
    use std::time::Duration;

    fn series(
        id: u64,
        row_id: u64,
        metric: &str,
        attachment: Option<(bool, &str, Option<&str>)>,
        current: ProjectedValue<u64>,
        interval: Option<CounterContinuity>,
    ) -> SeriesSnapshot {
        let mut labels = vec![
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::Direction, "egress".to_owned()),
            (MetricLabel::QdiscKind, "fq_codel".to_owned()),
            (MetricLabel::RowId, row_id.to_string()),
            (MetricLabel::Execution, "software".to_owned()),
        ];
        if let Some(attachment) = attachment {
            labels.push((
                MetricLabel::QdiscAttachment,
                serde_json::to_string(&attachment).unwrap(),
            ));
        }
        let value = if matches!(metric, "backlog_bytes" | "backlog_packets") {
            SeriesValue::Gauge {
                current,
                interval: None,
                since_baseline: None,
            }
        } else {
            SeriesValue::Counter {
                current,
                interval,
                since_baseline: interval.and_then(|interval| match interval {
                    CounterContinuity::Continuous { delta, elapsed } => {
                        Some(CounterSpan::new(delta, elapsed).unwrap())
                    }
                    _ => None,
                }),
            }
        };
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new("linux.monitor.tc").unwrap(),
            ProviderId::new("linux.tc.json").unwrap(),
            MetricId::new(format!("linux.tc.{metric}")).unwrap(),
            MetricLabels::new(labels).unwrap(),
            Duration::ZERO,
            BaselineOrigin::SessionStart,
            Duration::ZERO,
            value,
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn fresh(value: u64) -> ProjectedValue<u64> {
        ProjectedValue::Fresh {
            value,
            observed_at: Duration::from_secs(1),
        }
    }

    fn continuous(delta: u64) -> Option<CounterContinuity> {
        Some(CounterContinuity::Continuous {
            delta,
            elapsed: Duration::from_secs(1),
        })
    }

    fn snapshot(rows: Vec<SeriesSnapshot>) -> MonitorSnapshot {
        MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(1),
            None,
            vec![ProviderSnapshot::new(
                ProviderId::new("linux.tc.json").unwrap(),
                ProviderHealth::Fresh,
                Duration::from_secs(1),
                Duration::ZERO,
                0,
            )
            .unwrap()],
            rows,
            EngineTelemetry::default(),
        )
        .unwrap()
    }

    fn root_rows(row_id: u64, drops: u64, requeues: u64) -> Vec<SeriesSnapshot> {
        ["drops", "requeues", "backlog_bytes", "backlog_packets"]
            .iter()
            .enumerate()
            .map(|(index, metric)| {
                let delta = if *metric == "drops" { drops } else { requeues };
                series(
                    row_id * 10 + index as u64,
                    row_id,
                    metric,
                    Some((true, "1:", None)),
                    fresh(10_000 + delta),
                    continuous(delta),
                )
            })
            .collect()
    }

    fn fixture() -> TcTable {
        let mut rows = root_rows(1, 0, 3);
        rows.extend(root_rows(2, 0, 0));
        rows.push(series(
            30,
            3,
            "drops",
            Some((false, "2:", Some("1:1"))),
            fresh(100),
            continuous(90),
        ));
        rows.push(series(
            40,
            4,
            "drops",
            Some((true, "3:", None)),
            ProjectedValue::Unavailable {
                reason: UnavailableReason::Missing,
            },
            None,
        ));
        TcTable::from_snapshot(Some(&snapshot(rows)), None, None)
    }

    #[test]
    fn visible_qdisc_headers_toggle_sort_without_opening_detail() {
        let table = fixture();
        for width in [80, 120, 160] {
            let mut state = TcViewState::default();
            state.set_viewport_rows(30);
            state.reconcile(&table);
            let selected = state.selected.clone();
            for metrics in [TcMetrics::Queue, TcMetrics::Traffic] {
                state.metrics = metrics;
                for sort in TcSort::ALL {
                    let Some(column) = tc_column(sort, metrics) else {
                        continue;
                    };
                    let x = widths(width)[..column].iter().sum::<usize>() + column;
                    let old_sort = state.sort;
                    let old_direction = state.descending;
                    assert!(state.click_header(&table, width, x as u16, TABLE_HEADER_ROWS - 1));
                    assert_eq!(state.sort, sort);
                    assert_eq!(
                        state.descending,
                        if old_sort == sort {
                            !old_direction
                        } else {
                            sort != TcSort::Netdev
                        }
                    );
                    assert_eq!(state.selected, selected);
                    assert!(!state.detail);
                    assert!(!state.click_header(&table, width, x as u16, TABLE_HEADER_ROWS));
                }
                for _ in 0..TcSort::ALL.len() {
                    state.cycle_sort(&table);
                    assert!(tc_column(state.sort, metrics).is_some());
                }
            }
        }
    }

    #[test]
    fn overview_is_fresh_root_or_with_no_backlog_or_total_filter_and_no_leaf_sum() {
        let table = fixture();
        let rows = table.overview_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key.row_id, 1);
        assert_eq!(rows[0].metric("drops").rate, TcValue::Fresh(0.0));
        assert_eq!(rows[0].metric("requeues").rate, TcValue::Fresh(3.0));
        assert_eq!(table.rows.len(), 4);
        let coverage = table.overview_coverage();
        assert_eq!(
            (coverage.shown, coverage.roots, coverage.missing),
            (1, 3, 1)
        );
        let mut table = table;
        table.rows[0].metrics.insert(
            "drops".into(),
            TcMetric {
                current: TcValue::Fresh(0),
                rate: TcValue::Unavailable,
                counter: true,
            },
        );
        assert!(
            table.rows[0].overview_matches(),
            "fresh requeues suffice when drops are missing"
        );
        table.rows[0].direction = "ingress".into();
        assert!(!table.rows[0].overview_matches());
    }

    #[test]
    fn missing_attachment_is_not_guessed_to_be_root_and_anchor_is_respected() {
        let snap = snapshot(vec![series(1, 1, "drops", None, fresh(7), continuous(7))]);
        let table = TcTable::from_snapshot(Some(&snap), None, None);
        assert!(table.overview_rows().is_empty());
        assert_eq!(table.overview_coverage().unknown_attachment, 1);
        assert_eq!(table.rows.len(), 1);
        let anchor = InterfaceViewAnchor::named("eth1").unwrap();
        assert!(TcTable::from_snapshot(Some(&snap), Some(&anchor), None)
            .rows
            .is_empty());
    }

    #[test]
    fn projected_missing_stale_reset_and_warmup_never_become_zero_rates() {
        let cases = [
            (fresh(0), Some(CounterContinuity::Reset), "reset"),
            (fresh(500), Some(CounterContinuity::FirstSample), "warmup"),
            (
                fresh(500),
                Some(CounterContinuity::RecoveredAfterGap),
                "gap",
            ),
            (
                ProjectedValue::Unavailable {
                    reason: UnavailableReason::Missing,
                },
                None,
                "n/a",
            ),
            (
                ProjectedValue::Stale {
                    last: 900,
                    observed_at: Duration::ZERO,
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                None,
                "stale",
            ),
        ];
        for (current, interval, text) in cases {
            let metric = TcMetric::from_series(&series(
                1,
                1,
                "drops",
                Some((true, "1:", None)),
                current,
                interval,
            ));
            assert_eq!(rate_text(metric.rate, 1.0), text);
            assert_eq!(metric.rate.fresh(), None);
            let mut table = fixture();
            table.rows[0].metrics.insert("drops".into(), metric);
            table.rows[0].metrics.insert("requeues".into(), metric);
            assert!(!table.rows[0].overview_matches());
        }
    }

    #[test]
    fn selection_survives_rate_sort_refresh_and_disappearing_detail() {
        let mut table = fixture();
        let mut state = TcViewState::default();
        state.set_viewport_rows(5);
        state.reconcile(&table);
        let key = table.rows[1].key.clone();
        assert!(state.select_key(&table, &key));
        for _ in 0..8 {
            state.cycle_sort(&table);
            state.reverse_sort(&table);
            assert_eq!(state.selected_key(), Some(&key));
        }
        state.open(&table);
        assert!(state.detail());
        assert!(!state.back());
        assert_eq!(state.selected_key(), Some(&key));
        state.open(&table);
        table.rows.retain(|row| row.key != key);
        state.reconcile(&table);
        assert_eq!(state.selected_key(), Some(&key));
        assert!(detail_lines(&table, &state, 80)[0]
            .to_string()
            .contains("no longer present"));
        assert!(!state.back());
        state.reconcile(&table);
        assert_ne!(state.selected_key(), Some(&key));
        assert!(state.back());
    }

    #[test]
    fn hierarchy_remains_visible_and_missing_sorts_last_in_both_directions() {
        let table = fixture();
        for descending in [false, true] {
            let state = TcViewState {
                descending,
                sort: TcSort::Drops,
                ..TcViewState::default()
            };
            let rows = table.ordered_rows(&state);
            assert_eq!(rows.len(), 4);
            assert_eq!(rows.last().unwrap().key.row_id, 4);
            let root = rows.iter().position(|row| row.key.row_id == 1).unwrap();
            assert_eq!(rows[root + 1].key.row_id, 3);
        }
    }

    #[test]
    fn mouse_identity_helpers_follow_wrapped_headers_and_sort_order() {
        let table = fixture();
        let state = TcViewState::default();
        for width in [40, 80, 120, 160, 240] {
            assert_eq!(overview_row_key(&table, width, 0), None);
            let key = &table.overview_rows()[0].key;
            let index = overview_row_index(&table, width, key).unwrap();
            assert_eq!(overview_row_key(&table, width, index).as_ref(), Some(key));
            for row in &table.rows {
                let index = table_row_index(&table, &state, &row.key).unwrap();
                assert_eq!(
                    table_row_key(&table, &state, index).as_ref(),
                    Some(&row.key)
                );
            }
            assert_eq!(table_row_key(&table, &state, 0), None);
        }
    }

    #[test]
    fn table_detail_and_overview_render_within_narrow_and_wide_terminals() {
        let table = fixture();
        let mut state = TcViewState::default();
        state.set_viewport_rows(20);
        state.reconcile(&table);
        for width in [40, 80, 120, 160, 240] {
            for metrics in [TcMetrics::Queue, TcMetrics::Traffic] {
                state.metrics = metrics;
                let lines = lines(&table, &state, width);
                assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                assert_eq!(row_count(&table, &state, width), lines.len());
                let mut terminal = Terminal::new(TestBackend::new(width, 20)).unwrap();
                terminal
                    .draw(|frame| render(frame, frame.area(), &table, &state))
                    .unwrap();
                assert!(terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .any(|cell| cell.symbol() == "Q"));
            }
            assert!(overview_lines(&table, width)
                .iter()
                .all(|line| line.width() <= usize::from(width)));
            state.open(&table);
            let detail = detail_lines(&table, &state, width);
            assert!(detail.iter().all(|line| line.width() <= usize::from(width)));
            let text = detail
                .iter()
                .map(Line::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains("not drops or TCP retransmissions"));
            assert!(text.contains("no totals are summed"));
            assert!(!state.back());
        }
    }

    #[test]
    fn unavailable_and_empty_provider_states_are_explicit() {
        let waiting = TcTable::from_snapshot(None, None, None);
        let text = overview_lines(&waiting, 100)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        assert!(text.contains("statistics n/a"));
        assert!(!text.contains("sample"));
        assert!(text.contains("No observed egress ROOT"));
        let table = fixture();
        let mut state = TcViewState::default();
        assert!(state.open_detail(&table, &table.rows[3].key));
        assert!(detail_lines(&table, &state, 100)
            .iter()
            .any(|line| line.to_string().contains("Drops/s: n/a | n/a")));
    }

    #[test]
    fn overview_coverage_is_compact_and_noqueue_is_not_missing_coverage() {
        let mut table = fixture();
        table.rows[3].kind = "noqueue".to_owned();
        let coverage = table.overview_coverage();
        assert_eq!(coverage.missing, 0);
        assert_eq!(coverage.not_applicable, 1);
        let summary = coverage.summary();
        assert!(summary.contains("1/3 roots"));
        assert!(summary.contains("drop/s > 0 or requeue/s > 0"));
        assert!(summary.contains("1 noqueue"));
        for hidden in [
            "0 stale",
            "0 reset",
            "0 warming",
            "0 unavailable",
            "sample",
            "cost",
            "fresh",
        ] {
            assert!(!summary.contains(hidden));
        }
        let mut state = TcViewState::default();
        assert!(state.open_detail(&table, &table.rows[3].key));
        assert!(detail_lines(&table, &state, 100)
            .iter()
            .any(|line| line.to_string().contains("No software queue")));
    }
}
