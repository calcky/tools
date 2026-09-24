use std::net::IpAddr;
#[cfg(test)]
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::monitor::conntrack_flow::{
    ConntrackEndpoint, ConntrackFlowFilter, ConntrackFlowKey, ConntrackFlowSnapshot, ConntrackSort,
    ConntrackTableSnapshot, ConntrackTraffic,
};
use crate::monitor::ProviderHealth;

use super::theme;

mod detail;
use detail::flow_detail_lines;

const FLOW_ROWS: usize = 1;
const FLOW_HEADER_ROWS: usize = 2;

#[derive(Debug)]
pub(super) struct ConntrackViewState {
    snapshot: Option<Arc<ConntrackTableSnapshot>>,
    filter: Option<ConntrackFlowFilter>,
    order: Vec<usize>,
    selected: Option<ConntrackFlowKey>,
    position: Option<usize>,
    detail: bool,
    diagnostics: bool,
    sort: ConntrackSort,
    descending: bool,
}

impl Default for ConntrackViewState {
    fn default() -> Self {
        Self {
            snapshot: None,
            filter: None,
            order: Vec::new(),
            selected: None,
            position: None,
            detail: false,
            diagnostics: false,
            sort: ConntrackSort::default(),
            descending: true,
        }
    }
}

impl ConntrackViewState {
    pub(super) fn clear(&mut self) {
        *self = Self {
            sort: self.sort,
            descending: self.descending,
            ..Self::default()
        };
    }

    // Reconcile only when the displayed immutable snapshot or filter changes.
    pub(super) fn update(
        &mut self,
        snapshot: Arc<ConntrackTableSnapshot>,
        filter: Option<&ConntrackFlowFilter>,
    ) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, &snapshot))
            && self.filter.as_ref() == filter
        {
            return;
        }
        self.snapshot = Some(snapshot);
        self.filter = filter.cloned();
        self.rebuild();
    }

    fn rebuild(&mut self) {
        self.order.clear();
        if let Some(snapshot) = &self.snapshot {
            self.order.extend(
                snapshot
                    .flows()
                    .iter()
                    .enumerate()
                    .filter(|(_, flow)| {
                        self.filter
                            .as_ref()
                            .is_none_or(|filter| flow.matches_filter(filter))
                    })
                    .map(|(index, _)| index),
            );
        }
        self.sort_rows();
    }

    fn sort_rows(&mut self) {
        if let Some(snapshot) = &self.snapshot {
            self.order.sort_unstable_by(|left, right| {
                self.sort.compare(
                    &snapshot.flows()[*left],
                    &snapshot.flows()[*right],
                    self.descending,
                )
            });
        }
        self.reconcile_selection();
    }

    fn reconcile_selection(&mut self) {
        let previous_position = self.position.unwrap_or(0);
        self.position = self.snapshot.as_ref().and_then(|snapshot| {
            self.selected.as_ref().and_then(|key| {
                self.order
                    .iter()
                    .position(|index| key.matches(&snapshot.flows()[*index]))
            })
        });
        if self.position.is_none() && !self.detail {
            if self.order.is_empty() {
                self.selected = None;
            } else {
                self.select(previous_position.min(self.order.len() - 1));
            }
        }
    }

    pub(super) const fn is_detail(&self) -> bool {
        self.detail || self.diagnostics
    }
    #[cfg(test)]
    pub(super) const fn sort(&self) -> ConntrackSort {
        self.sort
    }
    #[cfg(test)]
    pub(super) const fn descending(&self) -> bool {
        self.descending
    }
    pub(super) fn shown_count(&self) -> usize {
        self.order.len()
    }
    pub(super) const fn selected_position(&self) -> Option<usize> {
        self.position
    }
    pub(super) fn selected_key(&self) -> Option<&ConntrackFlowKey> {
        self.selected.as_ref()
    }

    pub(super) fn selected_flow(&self) -> Option<&ConntrackFlowSnapshot> {
        let index = *self.order.get(self.position?)?;
        self.snapshot.as_ref()?.flows().get(index)
    }

    pub(super) fn select(&mut self, position: usize) -> bool {
        if self.is_detail() {
            return false;
        }
        let Some(flow) = self
            .order
            .get(position)
            .and_then(|index| self.snapshot.as_ref()?.flows().get(*index))
        else {
            return false;
        };
        self.selected = Some(flow.key());
        self.position = Some(position);
        true
    }

    pub(super) fn move_up(&mut self) -> bool {
        self.select(self.position.unwrap_or(0).saturating_sub(1))
    }

    pub(super) fn move_down(&mut self) -> bool {
        self.select(
            self.position
                .map_or(0, |position| position.saturating_add(1))
                .min(self.order.len().saturating_sub(1)),
        )
    }

    pub(super) fn open(&mut self) -> bool {
        if self.selected_flow().is_none() {
            return false;
        }
        self.diagnostics = false;
        self.detail = true;
        true
    }

    pub(super) fn back(&mut self) -> bool {
        if !self.is_detail() {
            return false;
        }
        self.detail = false;
        self.diagnostics = false;
        self.reconcile_selection();
        true
    }

    pub(super) fn set_sort(&mut self, sort: ConntrackSort, descending: bool) {
        if self.sort != sort || self.descending != descending {
            self.sort = sort;
            self.descending = descending;
            self.sort_rows();
        }
    }

    pub(super) fn cycle_sort(&mut self) {
        self.set_sort(self.sort.next(), self.descending);
    }
    pub(super) fn click_header(&mut self, x: u16, row: usize, width: u16) -> bool {
        let heading = self.header(width).len();
        if self.is_detail() || self.snapshot.is_none() || !(heading..heading + 2).contains(&row) {
            return false;
        }
        let layout = flow_layout(usize::from(width));
        let sort = if let Some(field) = layout.prefix_hit(usize::from(x)) {
            [
                ConntrackSort::Protocol,
                ConntrackSort::State,
                ConntrackSort::Original,
                ConntrackSort::Mark,
            ][field]
        } else if row == heading + 1 {
            let Some(field) = layout.hit(usize::from(x)) else {
                return false;
            };
            flow_field_sort(field)
        } else {
            return false;
        };
        self.set_sort(
            sort,
            if self.sort == sort {
                !self.descending
            } else {
                true
            },
        );
        true
    }
    pub(super) fn reverse_sort(&mut self) {
        self.set_sort(self.sort, !self.descending);
    }

    pub(super) fn open_diagnostics(&mut self) {
        self.diagnostics = true;
    }

    fn header(&self, width: u16) -> Vec<Line<'static>> {
        self.snapshot.as_ref().map_or_else(
            || {
                vec![Line::from(fit_cell(
                    " Collecting conntrack flows",
                    usize::from(width),
                ))]
            },
            |snapshot| {
                table_header_lines(
                    snapshot,
                    self.filter.as_ref(),
                    self.order.len(),
                    self.sort,
                    self.descending,
                    usize::from(width),
                )
            },
        )
    }

    pub(super) fn row_count(&self, width: u16) -> usize {
        if self.is_detail() {
            return self.detail_lines(width).len();
        }
        if self.snapshot.is_none() {
            return self.header(width).len();
        }
        self.header(width).len()
            + FLOW_HEADER_ROWS
            + self.order.len().saturating_mul(FLOW_ROWS).max(1)
    }

    /// Content row coordinates, before applying the viewport scroll offset.
    #[cfg(test)]
    pub(super) fn row_span(&self, position: usize, width: u16) -> Option<Range<usize>> {
        if self.is_detail() || position >= self.order.len() {
            return None;
        }
        let start = self.header(width).len() + FLOW_HEADER_ROWS + position * FLOW_ROWS;
        Some(start..start + FLOW_ROWS)
    }

    #[cfg(test)]
    pub(super) fn selected_row_span(&self, width: u16) -> Option<Range<usize>> {
        self.row_span(self.position?, width)
    }

    pub(super) fn row_index(&self, row: usize, width: u16) -> Option<usize> {
        if self.is_detail() {
            return None;
        }
        let index = row.checked_sub(self.header(width).len() + FLOW_HEADER_ROWS)? / FLOW_ROWS;
        (index < self.order.len()).then_some(index)
    }

    pub(super) fn select_row(&mut self, row: usize, width: u16) -> bool {
        self.row_index(row, width)
            .is_some_and(|index| self.select(index))
    }

    pub(super) fn viewport(
        &self,
        width: u16,
        height: usize,
        row_offset: usize,
    ) -> super::sort_table::TableViewport {
        super::sort_table::TableViewport::new(
            self.header(width).len(),
            FLOW_HEADER_ROWS,
            self.order.len().max(1),
            height,
            row_offset,
        )
    }

    pub(super) fn select_viewport_row(
        &mut self,
        row: u16,
        width: u16,
        height: u16,
        row_offset: usize,
    ) -> bool {
        if row >= height || self.is_detail() {
            return false;
        }
        self.viewport(width, usize::from(height), row_offset)
            .logical_row(usize::from(row))
            .is_some_and(|logical| self.select_row(logical, width))
    }

    pub(super) fn render(&self, frame: &mut Frame<'_>, area: Rect, row_offset: usize) {
        if area.is_empty() {
            return;
        }
        let lines = if self.is_detail() {
            visible_lines(
                self.detail_lines(area.width),
                row_offset,
                usize::from(area.height),
            )
        } else if let Some(snapshot) = &self.snapshot {
            table_viewport(
                snapshot,
                &self.order,
                self.header(area.width),
                self.position,
                self.sort,
                self.descending,
                area.width,
                row_offset,
                usize::from(area.height),
            )
        } else {
            self.header(area.width)
        };
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn detail_lines(&self, width: u16) -> Vec<Line<'static>> {
        if self.diagnostics {
            return self.snapshot.as_ref().map_or_else(
                || self.header(width),
                |snapshot| diagnostic_lines(snapshot, usize::from(width).max(1)),
            );
        }
        match (&self.snapshot, self.selected_flow()) {
            (Some(snapshot), Some(flow)) => {
                flow_detail_lines(snapshot, flow, usize::from(width).max(1))
            }
            _ => {
                let mut lines = self.header(width);
                lines.extend(
                    wrap_text(
                        " Selected flow is no longer in the current filtered sample",
                        usize::from(width),
                    )
                    .into_iter()
                    .map(|text| Line::styled(text, Style::default().fg(theme::WARN))),
                );
                lines
            }
        }
    }
}

#[cfg(test)]
pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &ConntrackTableSnapshot,
    filter: Option<&ConntrackFlowFilter>,
    row_offset: usize,
) {
    if area.is_empty() {
        return;
    }
    let order = ordered_flows(snapshot, filter);
    let header = table_header_lines(
        snapshot,
        filter,
        order.len(),
        ConntrackSort::default(),
        true,
        usize::from(area.width),
    );
    let visible = table_viewport(
        snapshot,
        &order,
        header,
        None,
        ConntrackSort::default(),
        true,
        area.width,
        row_offset,
        usize::from(area.height),
    );
    frame.render_widget(Paragraph::new(visible), area);
}

#[cfg(test)]
pub(super) fn row_count(
    snapshot: &ConntrackTableSnapshot,
    filter: Option<&ConntrackFlowFilter>,
    width: u16,
) -> usize {
    let shown = snapshot
        .flows()
        .iter()
        .filter(|flow| filter.is_none_or(|filter| flow.matches_filter(filter)))
        .count();
    table_header_lines(
        snapshot,
        filter,
        shown,
        ConntrackSort::default(),
        true,
        usize::from(width),
    )
    .len()
        + FLOW_HEADER_ROWS
        + shown.saturating_mul(FLOW_ROWS).max(1)
}

#[cfg(test)]
fn ordered_flows(
    snapshot: &ConntrackTableSnapshot,
    filter: Option<&ConntrackFlowFilter>,
) -> Vec<usize> {
    let mut order = snapshot
        .flows()
        .iter()
        .enumerate()
        .filter(|(_, flow)| filter.is_none_or(|filter| flow.matches_filter(filter)))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    order.sort_unstable_by(|left, right| {
        ConntrackSort::default().compare(&snapshot.flows()[*left], &snapshot.flows()[*right], true)
    });
    order
}

#[cfg(test)]
fn flow_table_lines(
    snapshot: &ConntrackTableSnapshot,
    filter: Option<&ConntrackFlowFilter>,
    width: u16,
) -> Vec<Line<'static>> {
    let order = ordered_flows(snapshot, filter);
    let header = table_header_lines(
        snapshot,
        filter,
        order.len(),
        ConntrackSort::default(),
        true,
        usize::from(width),
    );
    table_viewport(
        snapshot,
        &order,
        header,
        None,
        ConntrackSort::default(),
        true,
        width,
        0,
        usize::MAX,
    )
}

fn visible_lines(lines: Vec<Line<'static>>, offset: usize, height: usize) -> Vec<Line<'static>> {
    let offset = offset.min(lines.len().saturating_sub(height));
    lines.into_iter().skip(offset).take(height).collect()
}

#[allow(clippy::too_many_arguments)]
fn table_viewport(
    snapshot: &ConntrackTableSnapshot,
    order: &[usize],
    mut header: Vec<Line<'static>>,
    selected: Option<usize>,
    sort: ConntrackSort,
    descending: bool,
    width: u16,
    offset: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let viewport = super::sort_table::TableViewport::new(
        header.len(),
        FLOW_HEADER_ROWS,
        order.len().max(1),
        height,
        offset,
    );
    header.truncate(viewport.context);
    header.extend(
        flow_heading_lines(usize::from(width), sort, descending)
            .into_iter()
            .take(viewport.headings),
    );
    let mut visible = header;
    if order.is_empty() {
        if viewport.capacity > 0 {
            let message = if snapshot.truncated() {
                " No matches in retained flows; capture truncated"
            } else if !matches!(snapshot.health(), ProviderHealth::Fresh) {
                " No matches in retained flows; collection incomplete or unavailable"
            } else if snapshot.flows().is_empty() {
                " No active conntrack flows"
            } else {
                " No flows match the active filter"
            };
            visible.push(Line::styled(
                fit_cell(message, usize::from(width)),
                Style::default().fg(theme::MUTED),
            ));
        }
    } else {
        for (position, index) in order
            .iter()
            .enumerate()
            .skip(viewport.offset)
            .take(viewport.capacity)
        {
            let mut line = flow_line(
                &snapshot.flows()[*index],
                usize::from(width),
                sort,
                descending,
            );
            if selected == Some(position) {
                super::sort_table::select(&mut line);
            }
            visible.push(line);
        }
    }
    visible
}

fn table_header_lines(
    snapshot: &ConntrackTableSnapshot,
    filter: Option<&ConntrackFlowFilter>,
    shown: usize,
    sort: ConntrackSort,
    descending: bool,
    width: usize,
) -> Vec<Line<'static>> {
    let (health, health_style) = health_label(snapshot.health());
    let mut lines = vec![Line::styled(
        fit_cell(
            &format!(
                " CONNTRACK [{}] {shown}/{} retained {} sort {} {}",
                if snapshot.truncated() {
                    "TRUNCATED"
                } else {
                    health
                },
                snapshot.flows().len(),
                if snapshot.truncated() {
                    "| matches may be omitted |"
                } else {
                    ""
                },
                sort.label(),
                if descending { "desc" } else { "asc" }
            ),
            width,
        ),
        (if snapshot.truncated() {
            Style::default().fg(theme::WARN)
        } else {
            health_style
        })
        .add_modifier(Modifier::BOLD),
    )];

    let total = snapshot
        .total_entries()
        .map_or_else(|| "?".to_owned(), |value| value.to_string());
    let accounting = match snapshot.accounting_enabled() {
        Some(true) => "on",
        Some(false) => "off",
        None => "unknown",
    };
    lines.push(Line::styled(
        fit_cell(
            &format!(
                " kernel {total} acct {accounting} truncated {} rejected {}",
                if snapshot.truncated() { "yes" } else { "no" },
                snapshot.rejected_lines()
            ),
            width,
        ),
        Style::default().fg(theme::TEXT),
    ));
    lines.push(Line::styled(
        fit_cell(
            " TX original / RX reply; traffic/packets: cumulative; BW bit/s; AVG byte/pkt",
            width,
        ),
        Style::default().fg(theme::MUTED),
    ));

    if let Some(filter) = filter {
        lines.push(Line::styled(
            fit_cell(&format!(" filter {}", filter.query()), width),
            Style::default().fg(theme::ACCENT),
        ));
    }
    if let Some(diagnostic) = health_diagnostic(snapshot.health()) {
        lines.push(Line::styled(
            fit_cell(&format!(" {diagnostic}"), width),
            health_style,
        ));
    }
    lines
}

fn health_label(health: &ProviderHealth) -> (&'static str, Style) {
    match health {
        ProviderHealth::Fresh => ("FRESH", Style::default().fg(theme::GOOD)),
        ProviderHealth::Partial { .. } => ("PARTIAL", Style::default().fg(theme::WARN)),
        ProviderHealth::Stale { .. } => ("STALE", Style::default().fg(theme::WARN)),
        ProviderHealth::Unsupported { .. } => ("UNSUPPORTED", Style::default().fg(theme::MUTED)),
        ProviderHealth::PermissionDenied { .. } => {
            ("PERMISSION DENIED", Style::default().fg(theme::WARN))
        }
        ProviderHealth::Error { .. } => ("ERROR", Style::default().fg(theme::BAD)),
    }
}

fn health_diagnostic(health: &ProviderHealth) -> Option<&str> {
    match health {
        ProviderHealth::Fresh => None,
        ProviderHealth::Partial { warning } => Some(warning.diagnostic()),
        ProviderHealth::Stale { cause, .. } => Some(cause.diagnostic()),
        ProviderHealth::Unsupported { reason } | ProviderHealth::PermissionDenied { reason } => {
            Some(reason.diagnostic())
        }
        ProviderHealth::Error { error } => Some(error.diagnostic()),
    }
}

fn flow_layout(width: usize) -> super::sort_table::TrafficLayout {
    super::sort_table::TrafficLayout::new(width, true)
}

fn flow_fields(sort: ConntrackSort) -> Vec<usize> {
    match sort {
        ConntrackSort::Bytes => vec![0, 1],
        ConntrackSort::TxBytes => vec![0],
        ConntrackSort::RxBytes => vec![1],
        ConntrackSort::Packets => vec![2, 3],
        ConntrackSort::TxPackets => vec![2],
        ConntrackSort::RxPackets => vec![3],
        ConntrackSort::TxPps => vec![4],
        ConntrackSort::RxPps => vec![5],
        ConntrackSort::Bandwidth => vec![6, 7],
        ConntrackSort::TxBandwidth => vec![6],
        ConntrackSort::RxBandwidth => vec![7],
        ConntrackSort::TxAverage => vec![8],
        ConntrackSort::RxAverage => vec![9],
        ConntrackSort::Protocol => vec![10],
        ConntrackSort::State => vec![11],
        ConntrackSort::Original => vec![12],
        ConntrackSort::Mark => vec![13],
    }
}

fn flow_field_sort(field: usize) -> ConntrackSort {
    [
        ConntrackSort::TxBytes,
        ConntrackSort::RxBytes,
        ConntrackSort::TxPackets,
        ConntrackSort::RxPackets,
        ConntrackSort::TxPps,
        ConntrackSort::RxPps,
        ConntrackSort::TxBandwidth,
        ConntrackSort::RxBandwidth,
        ConntrackSort::TxAverage,
        ConntrackSort::RxAverage,
    ][field]
}

fn flow_heading_lines(width: usize, sort: ConntrackSort, descending: bool) -> Vec<Line<'static>> {
    flow_layout(width).headings(
        &["PROTO", "STATE", "ORIGINAL ENDPOINTS", "CT MARK"],
        [
            "traffic byte",
            "PACKETS",
            "PPS",
            "BANDWIDTH b/s",
            "avg pkt byte",
        ],
        &flow_fields(sort),
        descending,
    )
}

fn flow_line(
    flow: &ConntrackFlowSnapshot,
    width: usize,
    sort: ConntrackSort,
    _descending: bool,
) -> Line<'static> {
    let layout = flow_layout(width);
    let path = format!(
        "{} -> {}",
        format_endpoint(flow.original().source()),
        format_endpoint(flow.original().destination())
    );
    let directions = [flow.original_traffic(), flow.reply_traffic()];
    let values = std::array::from_fn(|index| {
        let traffic = directions[index % 2];
        match index / 2 {
            0 => format_optional_total(traffic.bytes(), layout.cell),
            1 => format_optional_total(traffic.packets(), layout.cell),
            2 => {
                format_accounted_value(traffic.packets(), traffic.packets_per_second(), layout.cell)
            }
            3 => format_accounted_value(traffic.bytes(), traffic.bits_per_second(), layout.cell),
            _ => crate::monitor::conntrack_flow::average_packet(traffic).map_or_else(
                || compact_unavailable(layout.cell),
                |value| format_scaled_value(value, layout.cell),
            ),
        }
    });
    layout.row(
        &[
            flow.protocol_name().to_owned(),
            flow.state().unwrap_or("-").to_owned(),
            path,
            format_ct_mark(flow.ct_mark(), layout.prefix[3]),
        ],
        values,
        &flow_fields(sort),
    )
}

fn format_accounted_value(counter: Option<u64>, rate: Option<f64>, width: usize) -> String {
    if counter.is_none() {
        compact_unavailable(width)
    } else {
        rate.map_or_else(|| "-".to_owned(), |value| format_scaled_value(value, width))
    }
}

fn format_optional_total(value: Option<u64>, width: usize) -> String {
    value.map_or_else(
        || compact_unavailable(width),
        |value| format_scaled_value(value as f64, width),
    )
}

fn compact_unavailable(width: usize) -> String {
    if width >= 3 {
        "n/a".to_owned()
    } else {
        "-".to_owned()
    }
}

fn format_ct_mark(mark: Option<u32>, width: usize) -> String {
    let Some(mark) = mark else {
        return compact_unavailable(width);
    };
    if width >= 10 {
        format!("0x{mark:08x}")
    } else {
        format!("{mark:08x}")
    }
}

fn diagnostic_lines(snapshot: &ConntrackTableSnapshot, width: usize) -> Vec<Line<'static>> {
    let (health, style) = health_label(snapshot.health());
    let segments = [
        format!("Health {health}"),
        format!("sample #{}", snapshot.sequence()),
        format!("at {}", format_duration(snapshot.attempted_at())),
        format!("cost {}", format_duration(snapshot.collection_duration())),
        format!("retained {}", snapshot.flows().len()),
        format!(
            "kernel {}",
            snapshot
                .total_entries()
                .map_or_else(|| "n/a".to_owned(), |value| value.to_string())
        ),
        format!(
            "accounting {}",
            snapshot
                .accounting_enabled()
                .map_or("unknown", |value| if value { "on" } else { "off" })
        ),
        format!("truncated {}", yes_no(snapshot.truncated())),
        format!("rejected {}", snapshot.rejected_lines()),
    ];
    let mut lines = wrap_segments(&segments, width, 1)
        .into_iter()
        .map(|text| Line::styled(text, style))
        .collect::<Vec<_>>();
    if let Some(reason) = health_diagnostic(snapshot.health()) {
        lines.extend(
            wrap_text(&format!(" Reason: {reason}"), width)
                .into_iter()
                .map(|text| Line::styled(text, style)),
        );
    }
    lines
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn format_endpoint(endpoint: &ConntrackEndpoint) -> String {
    match (endpoint.address(), endpoint.port()) {
        (IpAddr::V4(address), Some(port)) => format!("{address}:{port}"),
        (IpAddr::V6(address), Some(port)) => format!("[{address}]:{port}"),
        (address, None) => address.to_string(),
    }
}

#[cfg(test)]
fn format_scaled_rate(rate: Option<f64>) -> String {
    rate.map_or_else(|| "-".to_owned(), |value| format_scaled_value(value, 8))
}

fn format_scaled_value(value: f64, width: usize) -> String {
    const PREFIXES: [&str; 7] = ["", "k", "M", "G", "T", "P", "E"];

    if width == 0 {
        return String::new();
    }
    if !value.is_finite() || value < 0.0 {
        return "-".chars().take(width).collect();
    }
    let mut value = value;
    let mut prefix = 0_usize;
    let mut lower_bound = None;
    while value >= 1_000.0 && prefix + 1 < PREFIXES.len() {
        value /= 1_000.0;
        prefix += 1;
    }
    loop {
        let whole = format!("{value:.0}{}", PREFIXES[prefix]);
        if value > 0.0 && value < 10.0 {
            let rounded = format!("{value:.1}");
            if rounded != "0.0" {
                let scaled = rounded.strip_suffix(".0").unwrap_or(&rounded);
                let scaled = scaled.strip_prefix('0').unwrap_or(scaled);
                let decimal = format!("{scaled}{}", PREFIXES[prefix]);
                if text_width(&decimal) <= width {
                    return decimal;
                }
            }
        }
        if (value == 0.0 || !whole.starts_with('0')) && text_width(&whole) <= width {
            return whole;
        }
        if value > 0.0 && value < 1.0 && lower_bound.is_none() {
            let candidate = if prefix == 0 {
                "<1".to_owned()
            } else {
                format!("<{}", PREFIXES[prefix])
            };
            if text_width(&candidate) <= width {
                lower_bound = Some(candidate);
            }
        }
        if prefix + 1 == PREFIXES.len() {
            return lower_bound.unwrap_or_else(|| "+".chars().take(width).collect());
        }
        value /= 1_000.0;
        prefix += 1;
    }
}

fn wrap_segments(segments: &[String], width: usize, indent: usize) -> Vec<String> {
    let indent = " ".repeat(indent.min(width));
    let mut lines = Vec::new();
    let mut current = indent.clone();
    for segment in segments {
        let separator = if current.trim().is_empty() { "" } else { "  " };
        if text_width(&current) + separator.len() + text_width(segment) <= width {
            current.push_str(separator);
            current.push_str(segment);
        } else {
            if !current.trim().is_empty() {
                lines.push(current);
            }
            current = format!("{indent}{segment}");
        }
    }
    if !current.trim().is_empty() {
        lines.push(current);
    }
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}

fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut rest = value.trim_end();
    while text_width(rest) > width {
        let hard_end = char_boundary_at(rest, width);
        let split = rest[..hard_end]
            .rfind(char::is_whitespace)
            .filter(|index| *index > 0)
            .unwrap_or(hard_end);
        lines.push(rest[..split].trim_end().to_owned());
        rest = rest[split..].trim_start();
    }
    if !rest.is_empty() || lines.is_empty() {
        lines.push(rest.to_owned());
    }
    lines
}

fn char_boundary_at(value: &str, maximum_chars: usize) -> usize {
    value
        .char_indices()
        .nth(maximum_chars)
        .map_or(value.len(), |(index, _)| index)
}

fn fit_cell(value: &str, width: usize) -> String {
    let mut output = value.chars().take(width).collect::<String>();
    output.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(text_width(&output)),
    ));
    output
}

fn text_width(value: &str) -> usize {
    value.chars().count()
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::fs;
    use std::sync::Arc;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use tempfile::TempDir;

    use super::*;
    use crate::collect::SystemPaths;
    use crate::monitor::conntrack_flow::ConntrackFlowSession;

    const IPV6_SOURCE: &str = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535";
    const IPV6_DESTINATION: &str = "[eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee]:5353";

    fn fixture_dump(step: u64) -> String {
        format!(
            "ipv4 2 tcp 6 \
             src=192.0.2.10 dst=198.51.100.20 sport=54321 dport=443 packets={} bytes={} \
             src=10.0.0.2 dst=192.0.2.10 sport=8443 dport=54321 packets={} bytes={} \
             [ASSURED] [OFFLOAD] mark=0 zone=7 use=2\n\
             ipv6 10 udp 17 29 \
             src=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
             dst=eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee sport=65535 dport=5353 \
             src=eeee:eeee:eeee:eeee:eeee:eeee:eeee:eeee \
             dst=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff sport=5353 dport=65535 \
             [HW_OFFLOAD] zone=9 use=2\n\
             ipv4 2 icmp 1 29 \
             src=192.0.2.1 dst=198.51.100.1 type=8 code=0 id=3 packets={} bytes={} \
             src=198.51.100.1 dst=192.0.2.1 type=0 code=0 id=3 packets={} bytes={} \
             mark=0 zone=3 use=1\n\
             malformed conntrack row\n",
            10 + step,
            1_000 + step * 1_000,
            20 + step * 2,
            2_000 + step * 2_000,
            30 + step,
            3_000 + step * 3_000,
            40 + step,
            4_000 + step * 4_000,
        )
    }

    fn is_flow_row(line: &str) -> bool {
        ["tcp", "udp", "icmp"]
            .into_iter()
            .any(|protocol| line.contains(protocol))
    }

    fn row_cells(line: &str) -> Vec<&str> {
        line.trim_matches('"').split('|').map(str::trim).collect()
    }

    pub(in crate::tui) fn fixture_snapshots(
    ) -> (Arc<ConntrackTableSnapshot>, Arc<ConntrackTableSnapshot>) {
        let root = TempDir::new().unwrap();
        let proc_root = root.path().join("proc");
        let net = proc_root.join("net");
        let sysctl = proc_root.join("sys/net/netfilter");
        fs::create_dir_all(&net).unwrap();
        fs::create_dir_all(&sysctl).unwrap();
        fs::write(net.join("nf_conntrack"), fixture_dump(0)).unwrap();
        fs::write(sysctl.join("nf_conntrack_count"), "9\n").unwrap();
        fs::write(sysctl.join("nf_conntrack_acct"), "0\n").unwrap();

        let session = ConntrackFlowSession::start(
            Duration::from_millis(100),
            SystemPaths {
                proc_root: proc_root.clone(),
                sys_root: root.path().join("sys"),
            },
        )
        .unwrap();
        let first = session
            .wait_after(0, Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let replacement = net.join("nf_conntrack.next");
        fs::write(&replacement, fixture_dump(1)).unwrap();
        fs::rename(replacement, net.join("nf_conntrack")).unwrap();
        let snapshot = session
            .wait_after(first.sequence(), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        session.shutdown().unwrap();
        (first, snapshot)
    }

    fn fixture_snapshot() -> Arc<ConntrackTableSnapshot> {
        fixture_snapshots().1
    }

    fn render_snapshot(
        snapshot: &ConntrackTableSnapshot,
        filter: Option<&ConntrackFlowFilter>,
        width: u16,
    ) -> String {
        let height = row_count(snapshot, filter, width).try_into().unwrap();
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), snapshot, filter, 0))
            .unwrap();
        terminal.backend().to_string()
    }

    #[test]
    fn truncated_zero_matches_are_not_reported_as_no_connections() {
        let snapshot = fixture_snapshot();
        assert!(snapshot.truncated());
        let filter = ConntrackFlowFilter::parse("host=203.0.113.0/24").unwrap();
        let mut view = ConntrackViewState::default();
        view.update(snapshot, filter.as_ref());
        assert_eq!(view.shown_count(), 0);
        let lines = view.header(100);
        assert!(lines[0].to_string().contains("TRUNCATED"));
        let rendered = render_snapshot(view.snapshot.as_ref().unwrap(), filter.as_ref(), 100);
        assert!(
            rendered.contains("No matches in retained flows; capture truncated"),
            "{rendered}"
        );
    }

    #[test]
    fn supported_widths_render_one_row_per_flow_without_overlap() {
        let snapshot = fixture_snapshot();
        for width in [1, 6, 20, 60, 80, 100, 120, 160, 240] {
            let lines = flow_table_lines(&snapshot, None, width);
            assert!(
                lines.iter().all(|line| line.width() <= usize::from(width)),
                "{width}"
            );
            assert_eq!(row_count(&snapshot, None, width), lines.len());
            let header = table_header_lines(
                &snapshot,
                None,
                3,
                ConntrackSort::default(),
                true,
                usize::from(width),
            );
            assert!(header.len() <= 5);
            assert_eq!(
                lines.len(),
                header.len() + FLOW_HEADER_ROWS + snapshot.flows().len()
            );
            if width < 60 {
                continue;
            }
            let rendered = render_snapshot(&snapshot, None, width);
            for expected in [
                "TX",
                "RX",
                "3/3",
                "kernel 9",
                "acct off",
                "truncated yes",
                "rejected 1",
            ] {
                assert!(
                    rendered.contains(expected),
                    "{width}: missing {expected}: {rendered}"
                );
            }
            if width >= 80 {
                for expected in ["traffic", "PACKETS", "PPS", "CT MARK"] {
                    assert!(
                        rendered.contains(expected),
                        "{width}: missing {expected}: {rendered}"
                    );
                }
            }
            let rows = &lines[header.len() + FLOW_HEADER_ROWS..];
            let positions = rows
                .iter()
                .map(|line| {
                    line.to_string()
                        .chars()
                        .enumerate()
                        .filter_map(|(index, ch)| (ch == '|').then_some(index))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            assert_eq!(positions[0].len(), 13);
            assert!(positions.iter().all(|position| *position == positions[0]));
        }
    }

    #[test]
    fn one_row_preserves_directional_values_missing_counters_and_first_sample_rates() {
        let (first, snapshot) = fixture_snapshots();
        let tcp = snapshot
            .flows()
            .iter()
            .find(|flow| flow.protocol() == 6)
            .unwrap();
        let tcp_line = flow_line(tcp, 160, ConntrackSort::default(), true).to_string();
        let cells = row_cells(&tcp_line);
        assert_eq!(cells.len(), 14);
        assert_eq!(cells[0], "tcp");
        assert_eq!(cells[1], tcp.state().unwrap_or("-"));
        assert_eq!(cells[3], "0x00000000");
        assert_eq!(&cells[4..6], ["2k", "4k"]);
        assert_eq!(&cells[6..8], ["11", "22"]);
        assert_eq!(&cells[12..14], ["182", "182"]);
        let first_tcp = first
            .flows()
            .iter()
            .find(|flow| flow.protocol() == 6)
            .unwrap();
        let first_line = flow_line(first_tcp, 160, ConntrackSort::default(), true).to_string();
        let first_cells = row_cells(&first_line);
        assert_eq!(&first_cells[8..10], ["-", "-"]);
        assert_eq!(&first_cells[10..12], ["-", "-"]);
        let udp = snapshot
            .flows()
            .iter()
            .find(|flow| flow.protocol() == 17)
            .unwrap();
        let udp_line = flow_line(udp, 160, ConntrackSort::default(), true).to_string();
        let udp_cells = row_cells(&udp_line);
        assert_eq!(udp_cells[3], "n/a");
        assert!(udp_cells[4..].iter().all(|cell| *cell == "n/a"));
        assert_eq!(format_optional_total(Some(0), 8), "0");
        assert_eq!(format_accounted_value(Some(0), Some(0.0), 8), "0");
    }

    #[test]
    fn identity_headings_sort_independently_and_match_split_columns() {
        let snapshot = fixture_snapshot();
        let mut view = ConntrackViewState::default();
        view.update(snapshot, None);
        let selected = view.selected_key().cloned();
        for width in [80, 120, 160, 240] {
            let row = view.header(width).len();
            let layout = flow_layout(usize::from(width));
            let mut x = 0;
            for (field, sort) in [
                ConntrackSort::Protocol,
                ConntrackSort::State,
                ConntrackSort::Original,
                ConntrackSort::Mark,
            ]
            .into_iter()
            .enumerate()
            {
                assert!(view.click_header(x, row, width));
                assert_eq!(view.sort(), sort);
                assert!(view.descending());
                assert!(!view.is_detail());
                assert_eq!(view.selected_key(), selected.as_ref());
                assert!(view.click_header(x, row + 1, width));
                assert!(!view.descending());
                let headers =
                    flow_heading_lines(usize::from(width), view.sort(), view.descending());
                assert!(headers[0].spans.iter().any(
                    |span| span.style.bg == Some(theme::SORT_BG) && span.content.contains('↑')
                ));
                x += layout.prefix[field] as u16;
                assert!(!view.click_header(x, row, width));
                x += 1;
            }
        }
        let heading = flow_heading_lines(160, ConntrackSort::State, true)[0].to_string();
        for title in ["PROTO", "STATE", "traffic byte", "avg pkt byte"] {
            assert!(heading.contains(title), "{heading}");
        }
        assert!(!heading.contains("PROTO/STATE"));
        assert!(!heading.contains("LIFETIME"));
    }

    #[test]
    fn directional_headers_sort_only_the_clicked_metric_and_keep_identity() {
        let snapshot = fixture_snapshot();
        let mut view = ConntrackViewState::default();
        view.update(snapshot, None);
        let selected = view.selected_key().cloned();
        for width in [80, 120, 160, 240] {
            let row = view.header(width).len() + 1;
            let layout = flow_layout(usize::from(width));
            let first = layout.prefix.iter().sum::<usize>() + layout.prefix.len();
            for field in 0..10 {
                let x = (first + field * (layout.cell + 1)) as u16;
                assert!(view.click_header(x, row, width));
                assert_eq!(view.sort(), flow_field_sort(field));
                assert!(view.descending());
                assert_eq!(view.selected_key(), selected.as_ref());
                let headers =
                    flow_heading_lines(usize::from(width), view.sort(), view.descending());
                let active = headers[1]
                    .spans
                    .iter()
                    .filter(|span| span.style.bg == Some(theme::SORT_BG))
                    .collect::<Vec<_>>();
                assert_eq!(active.len(), 1);
                assert!(active[0].content.contains('↓'));
                assert!(view.click_header(x, row, width));
                assert!(!view.descending());
                assert!(!view.click_header(x + layout.cell as u16, row, width));
            }
            assert!(!view.click_header(first as u16, row - 1, width));
            assert!(!view.click_header(first as u16, row + 1, width));
        }
        view.open();
        assert!(!view.click_header(100, view.header(160).len() + 1, 160));
    }

    #[test]
    fn details_retain_full_nat_ipv6_icmp_metadata_and_diagnostics() {
        let snapshot = fixture_snapshot();
        for width in [1, 4, 20, 60, 80, 120, 160] {
            for flow in snapshot.flows() {
                let lines = flow_detail_lines(&snapshot, flow, width);
                assert!(lines.iter().all(|line| line.width() <= width));
                let text = lines
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                let columns = if width >= 110 { 2 } else { 1 };
                let column_width = (width - (columns - 1)) / columns;
                let compact: String = (0..columns)
                    .flat_map(|column| {
                        lines.iter().flat_map(move |line| {
                            line.to_string()
                                .chars()
                                .skip(column * (column_width + 1))
                                .take(column_width)
                                .collect::<Vec<_>>()
                        })
                    })
                    .filter(|c| !c.is_whitespace() && !"│┌┐└┘─|".contains(*c))
                    .collect();
                for tuple in [flow.original(), flow.reply()] {
                    for endpoint in [tuple.source(), tuple.destination()] {
                        assert!(compact.contains(&format_endpoint(endpoint)));
                    }
                }
                for expected in [
                    "Protocol/state",
                    "Family/zone",
                    "Timeout",
                    "Flowoffload",
                    "Hardwareoffload",
                    "Trafficbyte",
                    "Packetstotal",
                    "Bandwidthbit/s",
                    "PPS",
                    "Sample#",
                    "Accountingoff",
                    "Rejectedlines1",
                    "Reason",
                ] {
                    assert!(compact.contains(expected), "missing {expected}: {text}");
                }
                assert!(compact.contains("CTmark"), "{text}");
                if flow.ct_mark().is_some() {
                    assert!(compact.contains("CTmark0x00000000"), "{text}");
                } else {
                    assert!(compact.contains("CTmarkn/a"), "{text}");
                }
                match flow.protocol() {
                    6 => {
                        assert!(
                            compact.contains(
                                "TXAFTERNATSource192.0.2.10:54321Destination10.0.0.2:8443"
                            ),
                            "{compact}"
                        );
                        assert!(compact.contains("FlowoffloadyesHardwareoffloadno"));
                        assert!(compact.contains("Timeoutn/a"));
                    }
                    17 => {
                        assert!(compact.contains(IPV6_SOURCE));
                        assert!(compact.contains(IPV6_DESTINATION));
                        assert!(compact.contains("FlowoffloadnoHardwareoffloadyes"));
                    }
                    1 => {
                        assert!(compact.contains("ICMPtype/code/id8/0/3"));
                        assert!(compact.contains("ICMPtype/code/id0/0/3"));
                        assert!(!compact.contains("AFTERNAT"));
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn framed_details_scroll_using_the_same_row_geometry() {
        let snapshot = fixture_snapshot();
        let mut view = ConntrackViewState::default();
        view.update(snapshot, None);
        view.open();
        for width in [1, 20, 60, 80, 120, 160] {
            let full = view.detail_lines(width);
            assert_eq!(view.row_count(width), full.len());
            let mut complete = Terminal::new(TestBackend::new(width, full.len() as u16)).unwrap();
            complete.draw(|f| view.render(f, f.area(), 0)).unwrap();
            for height in [1, 12, 35] {
                for requested in [0, 5, usize::MAX] {
                    let offset = requested.min(full.len().saturating_sub(height as usize));
                    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                    terminal
                        .draw(|f| view.render(f, f.area(), requested))
                        .unwrap();
                    for y in 0..height.min(full.len() as u16) {
                        for x in 0..width {
                            assert_eq!(
                                terminal.backend().buffer()[(x, y)],
                                complete.backend().buffer()[(x, y + offset as u16)],
                                "{width}x{height}, offset {offset}"
                            );
                        }
                    }
                }
            }
        }
        let full = view.detail_lines(160);
        for title in [
            "CONNECTION",
            "TUPLES / NAT",
            "TRAFFIC",
            "TOTALS",
            "SAMPLE / COVERAGE",
        ] {
            assert!(
                full.iter()
                    .flat_map(|line| &line.spans)
                    .any(|s| s.content.contains(title)
                        && s.style.add_modifier.contains(Modifier::BOLD)),
                "{title}"
            );
        }
    }

    #[test]
    fn selection_survives_updates_sorts_filters_and_detail_disappearance() {
        let (first, second) = fixture_snapshots();
        let mut view = ConntrackViewState::default();
        view.update(Arc::clone(&first), None);
        let tcp = view
            .order
            .iter()
            .position(|index| first.flows()[*index].protocol() == 6)
            .unwrap();
        assert!(view.select(tcp));
        let selected = view.selected_key().unwrap().clone();
        assert!(view.open());
        view.update(Arc::clone(&second), None);
        assert_eq!(view.selected_key(), Some(&selected));
        assert_eq!(
            view.selected_flow().unwrap().original_traffic().bytes(),
            Some(2000)
        );
        assert!(!view.move_down());
        assert!(view.back());
        for sort in ConntrackSort::ALL {
            view.set_sort(sort, false);
            assert_eq!(view.selected_key(), Some(&selected));
            view.reverse_sort();
            assert_eq!(view.selected_key(), Some(&selected));
        }
        view.set_sort(ConntrackSort::default(), true);
        for _ in 0..ConntrackSort::ALL.len() {
            view.cycle_sort();
        }
        assert_eq!(view.sort(), ConntrackSort::default());
        assert!(view.descending());
        assert!(view.open());
        let filter = ConntrackFlowFilter::from_fields("", "", "UDP")
            .unwrap()
            .unwrap();
        view.update(Arc::clone(&second), Some(&filter));
        assert!(view.selected_flow().is_none());
        assert_eq!(view.selected_key(), Some(&selected));
        assert!(view
            .detail_lines(80)
            .iter()
            .any(|line| line.to_string().contains("no longer")));
        view.update(Arc::clone(&second), None);
        assert_eq!(view.selected_flow().unwrap().key(), selected);
        view.update(Arc::clone(&second), Some(&filter));
        assert!(view.back());
        assert_eq!(view.selected_flow().unwrap().protocol(), 17);
        assert_eq!(view.shown_count(), 1);
        let no_matches = ConntrackFlowFilter::from_fields("203.0.113.199", "", "")
            .unwrap()
            .unwrap();
        view.update(second, Some(&no_matches));
        assert_eq!(view.selected_position(), None);
        assert!(!view.open());
        view.open_diagnostics();
        assert!(view.is_detail());
        assert!(view
            .detail_lines(60)
            .iter()
            .any(|line| line.to_string().contains("rejected 1")));
        assert!(view.back());
        assert!(!view.back());
    }

    #[test]
    fn viewport_and_mouse_rows_match_full_table_with_stable_selection() {
        let snapshot = fixture_snapshot();
        let mut view = ConntrackViewState::default();
        view.update(Arc::clone(&snapshot), None);
        assert!(view.move_down());
        assert!(view.move_up());
        let index_buffer = view.order.as_ptr();
        view.update(Arc::clone(&snapshot), None);
        assert_eq!(view.order.as_ptr(), index_buffer);
        for width in [20, 60, 80, 120, 160] {
            for position in 0..view.shown_count() {
                let span = view.row_span(position, width).unwrap();
                for row in span.clone() {
                    assert_eq!(view.row_index(row, width), Some(position));
                    assert!(view.select_row(row, width));
                    assert_eq!(view.selected_position(), Some(position));
                    assert_eq!(view.selected_row_span(width), Some(span.clone()));
                }
            }
            let all = table_viewport(
                &snapshot,
                &view.order,
                view.header(width),
                view.position,
                view.sort,
                view.descending,
                width,
                0,
                usize::MAX,
            );
            assert_eq!(all.len(), view.row_count(width));
            assert_eq!(view.row_index(0, width), None);
            assert_eq!(view.row_index(all.len(), width), None);
            for offset in 0..all.len() + 2 {
                for height in [0, 1, 2, 3, 8] {
                    let viewport = view.viewport(width, height, offset);
                    let expected = (0..height)
                        .filter_map(|row| viewport.logical_row(row))
                        .map(|row| all[row].clone())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        table_viewport(
                            &snapshot,
                            &view.order,
                            view.header(width),
                            view.position,
                            view.sort,
                            view.descending,
                            width,
                            offset,
                            height
                        ),
                        expected
                    );
                }
            }
            let mut terminal = Terminal::new(TestBackend::new(width, 8)).unwrap();
            terminal
                .draw(|frame| view.render(frame, frame.area(), usize::MAX))
                .unwrap();
            let viewport = view.viewport(width, 3, usize::MAX);
            for row in 0..3 {
                let expected = viewport
                    .logical_row(usize::from(row))
                    .and_then(|logical| view.row_index(logical, width));
                assert_eq!(
                    view.select_viewport_row(row, width, 3, usize::MAX),
                    expected.is_some()
                );
                if let Some(position) = expected {
                    assert_eq!(view.selected_position(), Some(position));
                }
            }
            assert!(!view.select_viewport_row(3, width, 3, usize::MAX));
        }
    }

    #[test]
    fn pending_view_has_no_selectable_rows() {
        let mut view = ConntrackViewState::default();
        assert_eq!(view.row_count(80), 1);
        assert!(!view.move_up());
        assert!(!view.move_down());
        assert!(!view.open());
        assert_eq!(view.row_index(0, 80), None);
        assert_eq!(view.selected_row_span(80), None);
    }

    #[test]
    fn filter_changes_shown_count_and_row_count_without_debugging_tuples() {
        let snapshot = fixture_snapshot();
        let filter = ConntrackFlowFilter::parse("443").unwrap().unwrap();
        let all_rows = row_count(&snapshot, None, 80);
        let filtered_rows = row_count(&snapshot, Some(&filter), 80);
        let rendered = render_snapshot(&snapshot, Some(&filter), 80);

        assert!(filtered_rows <= all_rows);
        assert!(rendered.contains("1/3"));
        assert!(rendered.contains("filter 443"));
        assert!(!rendered.contains(IPV6_SOURCE));
        assert!(!format!("{filter:?}").contains("443"));

        let filtered_flow_rows = rendered.lines().filter(|line| is_flow_row(line)).count();
        assert_eq!(filtered_flow_rows, 1);
    }

    #[test]
    fn scroll_offset_is_clamped_to_the_last_full_viewport() {
        let snapshot = fixture_snapshot();
        let width = 80;
        let backend = TestBackend::new(width, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &snapshot, None, usize::MAX))
            .unwrap();
        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("udp"));
    }

    #[test]
    fn duration_formatter_stays_compact() {
        assert_eq!(format_duration(Duration::from_millis(12)), "12ms");
        assert_eq!(format_duration(Duration::from_millis(1_250)), "1.2s");
    }

    #[test]
    fn rate_formatter_uses_units_from_the_column_heading() {
        assert_eq!(format_scaled_rate(None), "-");
        assert_eq!(format_scaled_rate(Some(10.0)), "10");
        assert_eq!(format_scaled_rate(Some(1_250.0)), "1.2k");
        assert_eq!(format_scaled_rate(Some(8_400_000.0)), "8.4M");
        assert_eq!(format_scaled_value(10_000.0, 3), "10k");
        assert_eq!(format_scaled_value(100_000.0, 3), ".1M");
        assert_eq!(format_scaled_value(100_000.0, 2), "<M");
        assert_ne!(format_scaled_value(100_000.0, 3), "0M");
        assert!(flow_layout(80).cell >= 3);

        for width in 1..=8 {
            for value in [0.01, 1.0, 10.0, 100.0, 1_000.0, 100_000.0, 1.0e12] {
                let formatted = format_scaled_value(value, width);
                assert!(text_width(&formatted) <= width);
                assert!(!["0", "0k", "0M", "0G", "0T", "0P", "0E"].contains(&formatted.as_str()));
                assert!(!["k", "M", "G", "T", "P", "E"].contains(&formatted.as_str()));
            }
        }
    }
}
