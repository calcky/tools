use std::net::IpAddr;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use unicode_segmentation::UnicodeSegmentation;

use crate::monitor::socket_table::{
    InetSocketSnapshot, SocketEndpoint, SocketProcessCoverage, SocketRowKey, SocketTableSnapshot,
};
use crate::monitor::ProviderHealth;

use super::sort_table::{divider, header_style, pad};
use super::theme;

const HEADER_ROWS: usize = 2;

mod order;
pub(super) use order::SocketOrder;

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    selected: Option<&SocketRowKey>,
    row_offset: usize,
) {
    if area.is_empty() {
        return;
    }
    let visible = socket_table_viewport(
        snapshot,
        order,
        selected,
        area.width,
        usize::from(area.height),
        row_offset,
    );
    frame.render_widget(Paragraph::new(visible), area);
}

#[cfg(test)]
pub(super) fn row_count(snapshot: &SocketTableSnapshot, width: u16) -> usize {
    table_header_lines(
        snapshot,
        usize::from(width).max(1),
        snapshot.sockets().len(),
    )
    .len()
        + HEADER_ROWS
        + snapshot.sockets().len().max(1)
}

pub(super) fn viewport(
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    width: u16,
    height: usize,
    offset: usize,
) -> super::sort_table::TableViewport {
    super::sort_table::TableViewport::new(
        table_header_lines(snapshot, usize::from(width).max(1), order.shown_count()).len()
            + if order.filter().is_some() { 1 } else { 0 },
        HEADER_ROWS,
        order.shown_count().max(1),
        height,
        offset,
    )
}

pub(super) fn socket_row_index(
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    width: u16,
    position: usize,
) -> Option<usize> {
    let header_rows = table_header_lines(snapshot, usize::from(width).max(1), order.shown_count())
        .len()
        + if order.filter().is_some() { 1 } else { 0 };
    (position < order.shown_count()).then_some(header_rows + HEADER_ROWS + position)
}

#[cfg(test)]
fn socket_table_lines(
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    selected: Option<&SocketRowKey>,
    width: u16,
) -> Vec<Line<'static>> {
    socket_table_viewport(snapshot, order, selected, width, usize::MAX, 0)
}

fn socket_table_viewport(
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    selected: Option<&SocketRowKey>,
    width: u16,
    height: usize,
    offset: usize,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = table_header_lines(snapshot, width, order.shown_count());
    let remaining_width = width.saturating_sub(lines[0].width());
    lines[0].spans.push(Span::styled(
        fit_cell(&format!("  {}", order.status()), remaining_width),
        Style::default().fg(theme::TEXT),
    ));
    if let Some(filter) = order.filter() {
        lines.push(Line::styled(
            fit_cell(&format!(" filter {}", filter.query()), width),
            Style::default().fg(theme::ACCENT),
        ));
    }
    let viewport = super::sort_table::TableViewport::new(
        lines.len(),
        HEADER_ROWS,
        order.shown_count().max(1),
        height,
        offset,
    );
    lines.truncate(viewport.context);
    lines.extend(
        socket_heading_lines(width, order)
            .into_iter()
            .take(viewport.headings),
    );
    if viewport.capacity == 0 {
        return lines;
    }
    if order.shown_count() == 0 {
        lines.push(Line::styled(
            fit_cell(
                if snapshot.truncated() {
                    " No matches in retained sockets; capture truncated"
                } else if !matches!(snapshot.health(), ProviderHealth::Fresh) {
                    " No matches in retained sockets; collection incomplete or unavailable"
                } else if snapshot.sockets().is_empty() {
                    " No INET TCP/UDP sockets were retained"
                } else {
                    " No sockets match the active filter"
                },
                width,
            ),
            Style::default().fg(theme::MUTED),
        ));
        return lines;
    }
    lines.extend(
        order
            .indices()
            .iter()
            .skip(viewport.offset)
            .take(viewport.capacity)
            .map(|&index| {
                let socket = &snapshot.sockets()[index];
                socket_line(
                    socket,
                    snapshot.process_coverage(),
                    width,
                    order,
                    selected.is_some_and(|key| key == socket.row_key()),
                )
            }),
    );
    lines
}

fn table_header_lines(
    snapshot: &SocketTableSnapshot,
    width: usize,
    shown: usize,
) -> Vec<Line<'static>> {
    let (health, health_style) = health_label(snapshot.health());
    let mut lines = vec![Line::from(vec![
        Span::styled(
            " INET SOCKETS ",
            Style::default()
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("[{health}]"),
            health_style.add_modifier(Modifier::BOLD),
        ),
    ])];
    if snapshot.truncated() {
        lines[0].spans.push(Span::styled(
            " TRUNCATED: matches may be omitted",
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let segments = [
        format!(
            "shown {shown}/{} retained; {} observed",
            snapshot.sockets().len(),
            snapshot.observed_sockets()
        ),
        format!(
            "queries {}/{}",
            snapshot.completed_queries(),
            snapshot.completed_queries() + snapshot.failed_queries()
        ),
        format!("process-map {}", snapshot.process_map_summary()),
        "Q: bytes; LISTEN: pending/max connections".to_owned(),
    ];
    lines.extend(
        wrap_segments(&segments, width, 1)
            .into_iter()
            .map(|line| Line::styled(line, Style::default().fg(theme::TEXT))),
    );
    if let Some(diagnostic) = health_diagnostic(snapshot.health()) {
        lines.extend(
            wrap_text(&format!(" reason {diagnostic}"), width)
                .into_iter()
                .map(|line| {
                    Line::styled(
                        line,
                        Style::default().fg(health_style.fg.unwrap_or(theme::WARN)),
                    )
                }),
        );
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

struct SocketLayout {
    widths: [usize; 10],
    width: usize,
}

impl SocketLayout {
    fn new(width: usize) -> Self {
        const MIN: [usize; 10] = [6, 6, 6, 7, 8, 9, 9, 9, 6, 5];
        const PREFERRED: [usize; 10] = [6, 11, 22, 22, 18, 9, 9, 10, 8, 7];
        let available = width.saturating_sub(9);
        let minimum = MIN.iter().sum::<usize>();
        let extra = available.saturating_sub(minimum);
        let preferred_extra = PREFERRED
            .iter()
            .zip(MIN)
            .map(|(preferred, minimum)| preferred.saturating_sub(minimum))
            .sum::<usize>();
        let mut widths = MIN;
        for index in 0..widths.len() {
            widths[index] = widths[index].saturating_add(
                extra
                    .saturating_mul(PREFERRED[index].saturating_sub(MIN[index]))
                    .checked_div(preferred_extra)
                    .unwrap_or(0),
            );
        }
        let used = widths.iter().sum::<usize>();
        let mut remainder = available.saturating_sub(used);
        for index in [2, 3, 4, 9, 1, 5, 6, 7, 8] {
            if remainder == 0 {
                break;
            }
            widths[index] += 1;
            remainder -= 1;
        }
        for index in [2, 3] {
            let excess = widths[index].saturating_sub(22);
            widths[index] -= excess;
            widths[4] += excess;
        }
        Self { widths, width }
    }

    fn hit(&self, x: usize) -> Option<usize> {
        if x >= self.width {
            return None;
        }
        let mut start = 0;
        for (index, width) in self.widths.into_iter().enumerate() {
            if (start..start + width).contains(&x) {
                return Some(index);
            }
            start += width + 1;
        }
        None
    }

    fn headings(&self, sort: order::SocketSort, descending: bool) -> Vec<Line<'static>> {
        let groups = [
            ("SOCKET", 0, 2),
            ("ENDPOINTS", 2, 2),
            ("PROCESS", 4, 1),
            ("QUEUES", 5, 2),
            ("TCP", 7, 3),
        ];
        let mut top = Vec::new();
        for (group_index, (label, start, count)) in groups.into_iter().enumerate() {
            if group_index > 0 {
                top.push(divider());
            }
            let width = self.widths[start..start + count].iter().sum::<usize>() + count - 1;
            top.push(Span::styled(
                pad(label, width, false),
                header_style(false, group_color(group_index)),
            ));
        }
        let labels = [
            "PROTO", "STATE", "LOCAL", "REMOTE", "PROCESS", "RECV-Q", "SEND-Q", "RTT", "MSS", "CC",
        ];
        let mut bottom = Vec::new();
        for (index, label) in labels.into_iter().enumerate() {
            if index > 0 {
                bottom.push(divider());
            }
            let active = column_sort(index) == sort;
            bottom.push(Span::styled(
                pad(
                    &super::sort_table::label(
                        label,
                        self.widths[index],
                        active.then_some(descending),
                    ),
                    self.widths[index],
                    false,
                ),
                header_style(active, column_color(index)),
            ));
        }
        vec![self.bounded(top), self.bounded(bottom)]
    }

    fn row(&self, values: [String; 10], sort: order::SocketSort, selected: bool) -> Line<'static> {
        let mut spans = Vec::new();
        for (index, (value, width)) in values.into_iter().zip(self.widths).enumerate() {
            if index > 0 {
                spans.push(divider());
            }
            let right = matches!(index, 5..=8);
            let active = column_sort(index) == sort;
            let mut style = Style::default().fg(if active {
                theme::TEXT_STRONG
            } else {
                column_color(index)
            });
            if active {
                style = style.bg(theme::SORT_BG).add_modifier(Modifier::BOLD);
            }
            spans.push(Span::styled(pad(&value, width, right), style));
        }
        let mut line = self.bounded(spans);
        if selected {
            super::sort_table::select(&mut line);
        }
        line
    }

    fn bounded(&self, spans: Vec<Span<'static>>) -> Line<'static> {
        let mut remaining = self.width;
        Line::from(
            spans
                .into_iter()
                .filter_map(|span| {
                    if remaining == 0 {
                        return None;
                    }
                    let width = span.width().min(remaining);
                    remaining -= width;
                    Some(Span::styled(pad(&span.content, width, false), span.style))
                })
                .collect::<Vec<_>>(),
        )
    }
}

fn column_sort(index: usize) -> order::SocketSort {
    use order::SocketSort::*;
    [
        Protocol,
        State,
        Local,
        Remote,
        Process,
        RxQueue,
        TxQueue,
        Rtt,
        Mss,
        CongestionControl,
    ][index]
}

fn group_color(index: usize) -> ratatui::style::Color {
    [
        theme::TEXT_STRONG,
        theme::ACCENT,
        theme::GOOD,
        theme::WARN,
        theme::TX,
    ][index]
}

fn column_color(index: usize) -> ratatui::style::Color {
    match index {
        5 => theme::RX,
        6 => theme::TX,
        7..=9 => theme::ACCENT,
        _ => theme::TEXT,
    }
}

pub(super) fn header_sort_at(
    snapshot: &SocketTableSnapshot,
    order: &SocketOrder,
    width: u16,
    x: u16,
    row: usize,
) -> Option<order::SocketSort> {
    if row
        != table_header_lines(snapshot, usize::from(width).max(1), order.shown_count()).len()
            + if order.filter().is_some() { 1 } else { 0 }
            + 1
    {
        return None;
    }
    Some(column_sort(
        SocketLayout::new(usize::from(width)).hit(usize::from(x))?,
    ))
}

fn socket_heading_lines(width: usize, order: &SocketOrder) -> Vec<Line<'static>> {
    SocketLayout::new(width).headings(order.sort(), order.descending())
}

fn socket_line(
    socket: &InetSocketSnapshot,
    process_coverage: SocketProcessCoverage,
    width: usize,
    order: &SocketOrder,
    selected: bool,
) -> Line<'static> {
    let layout = SocketLayout::new(width);
    let values = [
        socket.protocol().label().to_ascii_uppercase(),
        compact_state(socket.state()).to_owned(),
        truncate_middle(&format_endpoint(socket.local()), layout.widths[2]),
        truncate_middle(&format_endpoint(socket.remote()), layout.widths[3]),
        format_owner(socket, process_coverage, layout.widths[4]),
        format_queue(socket, socket.receive_queue()),
        format_queue(socket, socket.send_queue()),
        socket
            .tcp()
            .map_or_else(|| "n/a".to_owned(), |tcp| format_rtt(tcp.rtt_micros)),
        socket.tcp().map_or_else(
            || "n/a".to_owned(),
            |tcp| format!("{} B", tcp.send_mss_bytes),
        ),
        socket.congestion_algorithm().unwrap_or("n/a").to_owned(),
    ];
    layout.row(values, order.sort(), selected)
}

fn format_owner(
    socket: &InetSocketSnapshot,
    process_coverage: SocketProcessCoverage,
    width: usize,
) -> String {
    let Some(owner) = socket.owners().first() else {
        if !socket.owner_lookup_applicable() {
            return "-".to_owned();
        }
        if !socket.row_key().is_stable() {
            return "owner?".to_owned();
        }
        return if process_coverage.is_complete() {
            format!("u{}", socket.uid())
        } else {
            "owner?".to_owned()
        };
    };
    let additional = socket.owners().len().saturating_sub(1);
    let suffix = if additional > 0 {
        format!("+{additional}")
    } else {
        String::new()
    };
    let value = owner.command().map_or_else(
        || owner.pid().to_string(),
        |command| format!("{}/{command}", owner.pid()),
    );
    let owner_width = width.saturating_sub(suffix.len()).max(1);
    format!("{}{suffix}", truncate_middle(&value, owner_width))
}

fn compact_state(state: &str) -> &str {
    match state {
        "ESTABLISHED" => "ESTAB",
        "CONNECTED" => "CONN",
        "CLOSE_WAIT" => "CLOSE_W",
        "NEW_SYN_RECV" => "NEW_SYN",
        value => value,
    }
}

pub(super) fn format_endpoint(endpoint: &SocketEndpoint) -> String {
    match endpoint.address() {
        IpAddr::V4(address) => format!("{address}:{}", endpoint.port()),
        IpAddr::V6(address) => format!("[{address}]:{}", endpoint.port()),
    }
}

fn format_bytes_value(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 || value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_queue(socket: &InetSocketSnapshot, value: u32) -> String {
    if socket.is_tcp_listener() {
        value.to_string()
    } else {
        format_bytes_value(u64::from(value))
    }
}

fn format_rtt(micros: u32) -> String {
    if micros >= 1_000_000 {
        format!("{:.2} s", f64::from(micros) / 1_000_000.0)
    } else if micros >= 100_000 {
        format!("{:.1} ms", f64::from(micros) / 1_000.0)
    } else if micros >= 1_000 {
        format!("{:.2} ms", f64::from(micros) / 1_000.0)
    } else {
        format!("{micros} us")
    }
}

pub(super) fn format_scaled_value(value: f64, width: usize) -> String {
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

pub(super) fn wrap_text(value: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut rest = value.trim_end();
    while text_width(rest) > width {
        let hard_end = display_width_boundary_at(rest, width);
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

fn display_width_boundary_at(value: &str, maximum_width: usize) -> usize {
    let mut width = 0_usize;
    for (index, grapheme) in value.grapheme_indices(true) {
        let next = width.saturating_add(text_width(grapheme));
        if next > maximum_width {
            return if index == 0 { grapheme.len() } else { index };
        }
        width = next;
    }
    value.len()
}

fn fit_cell(value: &str, width: usize) -> String {
    let mut output = take_prefix_width(value, width);
    output.extend(std::iter::repeat_n(
        ' ',
        width.saturating_sub(text_width(&output)),
    ));
    output
}

pub(super) fn truncate_middle(value: &str, width: usize) -> String {
    const MARKER: &str = "...";
    if text_width(value) <= width {
        return value.to_owned();
    }
    let marker_width = text_width(MARKER);
    if width <= marker_width {
        return take_prefix_width(value, width);
    }
    let remaining = width - marker_width;
    let prefix_width = remaining.div_ceil(2);
    let suffix_width = remaining / 2;
    let prefix = take_prefix_width(value, prefix_width);
    let suffix = take_suffix_width(value, suffix_width);
    format!("{prefix}{MARKER}{suffix}")
}

pub(super) fn text_width(value: &str) -> usize {
    Span::raw(value).width()
}

fn take_prefix_width(value: &str, maximum_width: usize) -> String {
    let mut width = 0_usize;
    value
        .graphemes(true)
        .take_while(|grapheme| {
            let next = width.saturating_add(text_width(grapheme));
            if next > maximum_width {
                return false;
            }
            width = next;
            true
        })
        .collect()
}

fn take_suffix_width(value: &str, maximum_width: usize) -> String {
    let mut width = 0_usize;
    let mut graphemes = value
        .graphemes(true)
        .rev()
        .take_while(|grapheme| {
            let next = width.saturating_add(text_width(grapheme));
            if next > maximum_width {
                return false;
            }
            width = next;
            true
        })
        .collect::<Vec<_>>();
    graphemes.reverse();
    graphemes.concat()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    fn order(snapshot: &Arc<SocketTableSnapshot>) -> SocketOrder {
        let mut order = SocketOrder::default();
        order.update(Arc::clone(snapshot), None);
        order
    }

    fn render_snapshot(width: u16) -> (Arc<SocketTableSnapshot>, String) {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let height = row_count(&snapshot, width).try_into().unwrap();
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, frame.area(), &snapshot, &order(&snapshot), None, 0))
            .unwrap();
        let rendered = terminal.backend().to_string();
        (snapshot, rendered)
    }

    fn socket_rows(rendered: &str) -> Vec<&str> {
        rendered
            .lines()
            .filter(|line| line.contains("ESTAB") || line.contains("UNCONN"))
            .collect()
    }

    #[test]
    fn supported_widths_keep_one_aligned_row_per_socket() {
        for width in [60, 80, 120, 160] {
            let (snapshot, rendered) = render_snapshot(width);
            let rows = socket_rows(&rendered);
            assert_eq!(rows.len(), snapshot.sockets().len(), "{width}\n{rendered}");
            let boundaries = |line: &str| {
                line.char_indices()
                    .filter_map(|(index, value)| {
                        (value == '|').then_some(text_width(&line[..index]))
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(boundaries(rows[0]), boundaries(rows[1]));
            assert!(
                socket_table_lines(&snapshot, &order(&snapshot), None, width)
                    .iter()
                    .all(|line| line.width() <= usize::from(width))
            );
            assert_eq!(row_count(&snapshot, width), rendered.lines().count());
        }
    }

    #[test]
    fn wide_rows_show_ss_fields_and_udp_has_no_tcp_values() {
        let (_, rendered) = render_snapshot(240);
        let rows = socket_rows(&rendered);
        let tcp = rows.iter().find(|line| line.contains("ESTAB")).unwrap();
        let udp = rows.iter().find(|line| line.contains("UNCONN")).unwrap();
        assert_eq!(
            tcp.split('|')
                .next()
                .unwrap()
                .trim()
                .trim_start_matches('"'),
            "TCP"
        );
        assert_eq!(
            udp.split('|')
                .next()
                .unwrap()
                .trim()
                .trim_start_matches('"'),
            "UDP"
        );
        for expected in [
            "1234/client-worker",
            "192.0.2.10:42000",
            "198.51.100.20:443",
            "128 B",
            "256 B",
            "12.50 ms",
            "1448 B",
            "cubic",
        ] {
            assert!(tcp.contains(expected), "{expected}: {tcp}");
        }
        for expected in [
            "PROTO", "STATE", "LOCAL", "REMOTE", "PROCESS", "RECV-Q", "SEND-Q", "RTT", "MSS", "CC",
        ] {
            assert!(rendered.contains(expected), "{expected}: {rendered}");
        }
        assert_eq!(udp.matches("n/a").count(), 3, "{udp}");
        for removed in ["BANDWIDTH", "SEGMENTS", "PPS", "LIMIT", "cwnd"] {
            assert!(!rendered.contains(removed), "{rendered}");
        }
    }

    #[test]
    fn compact_rows_preserve_numeric_units_and_sort_labels() {
        let (_, rendered) = render_snapshot(80);
        let rows = socket_rows(&rendered);
        let tcp = rows.iter().find(|line| line.contains("ESTAB")).unwrap();
        for expected in ["128 B", "256 B", "12.50 ms", "1448 B", "cubic"] {
            assert!(tcp.contains(expected), "{expected}: {tcp}");
        }
        for expected in ["RECV-Q", "SEND-Q", "PROCESS"] {
            assert!(rendered.contains(expected), "{expected}: {rendered}");
        }
        for micros in [0, 999, 999_999, 1_000_000, u32::MAX] {
            assert!(format_rtt(micros).len() <= 9);
        }
        for bytes in [0, 1023, 1024, 1_048_575, u64::from(u32::MAX)] {
            assert!(format_bytes_value(bytes).len() <= 9);
        }
    }

    #[test]
    fn wide_address_columns_stay_compact_without_changing_row_hit_geometry() {
        for width in [120, 160, 240, 500] {
            let layout = SocketLayout::new(width);
            assert_eq!(layout.widths[0], 6);
            assert!(layout.widths[2] <= 22 && layout.widths[3] <= 22);
            assert_eq!(layout.widths.iter().sum::<usize>() + 9, width);
            let mut start = 0;
            for (field, size) in layout.widths.iter().copied().enumerate() {
                assert_eq!(layout.hit(start), Some(field));
                assert_eq!(layout.hit(start + size - 1), Some(field));
                assert_eq!(layout.hit(start + size), None);
                start += size + 1;
            }
        }
    }

    #[test]
    fn listener_queues_are_connection_counts() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_listener_snapshot_at(2);
        let row = socket_line(
            &snapshot.sockets()[0],
            snapshot.process_coverage(),
            160,
            &order(&snapshot),
            false,
        )
        .to_string();
        let fields: Vec<_> = row.split('|').map(str::trim).collect();
        assert_eq!(fields[0], "TCP");
        assert_eq!(fields[5], "11");
        assert_eq!(fields[6], "128");
        assert_eq!(fields[7], "n/a");
    }

    #[test]
    fn selected_socket_highlight_does_not_move_column_boundaries() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let selected = snapshot.sockets()[0].row_key();
        let order = order(&snapshot);
        let width = 120;
        let height = row_count(&snapshot, width).try_into().unwrap();
        let selected_row = socket_row_index(&snapshot, &order, width, 0).unwrap() as u16;
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| render(frame, frame.area(), &snapshot, &order, Some(selected), 0))
            .unwrap();

        let buffer = terminal.backend().buffer();
        for x in 0..width {
            assert_eq!(buffer[(x, selected_row)].bg, theme::SELECTED_BG);
        }
        let rendered = terminal.backend().to_string();
        let positions = rendered
            .lines()
            .filter(|line| line.matches('|').count() == 9)
            .map(|line| {
                line.char_indices()
                    .filter_map(|(index, value)| {
                        (value == '|').then_some(text_width(&line[..index]))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert!(positions.iter().all(|value| value == &positions[0]));
    }

    #[test]
    fn scrolling_preserves_grouped_headers_and_renders_only_visible_entries() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let order = order(&snapshot);
        for width in [20, 60, 120, 160] {
            let full = socket_table_lines(&snapshot, &order, None, width);
            for height in [0, 1, 2, 3, 8, 30] {
                for offset in [0, 1, usize::MAX] {
                    let view = viewport(&snapshot, &order, width, height, offset);
                    let visible =
                        socket_table_viewport(&snapshot, &order, None, width, height, offset);
                    let expected = (0..height)
                        .filter_map(|row| view.logical_row(row))
                        .map(|row| full[row].clone())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        visible, expected,
                        "width={width} height={height} offset={offset}"
                    );
                    if height >= 3 {
                        let headings = socket_heading_lines(usize::from(width), &order);
                        assert_eq!(&visible[view.context..view.data_start()], &headings);
                    }
                }
            }
        }
    }

    #[test]
    fn truncated_zero_matches_warn_and_filtered_headers_keep_their_positions() {
        use crate::monitor::socket_table::SocketFilter;
        let snapshot = crate::monitor::socket_table::synthetic_truncated_socket_snapshot();
        let filter = SocketFilter::parse("src=203.0.113.0/24").unwrap();
        let mut order = SocketOrder::default();
        order.update(Arc::clone(&snapshot), filter.as_ref());
        let lines = socket_table_viewport(&snapshot, &order, None, 100, 30, 0);
        assert!(lines[0].to_string().contains("TRUNCATED"));
        assert!(lines.iter().any(|line| line
            .to_string()
            .contains("No matches in retained sockets; capture truncated")));
        assert!(socket_row_index(&snapshot, &order, 100, 0).is_none());

        let filter = SocketFilter::parse("src=192.0.2.0/24 dst=198.51.100.20 dport=443").unwrap();
        order.update(Arc::clone(&snapshot), filter.as_ref());
        assert_eq!(order.shown_count(), 1);
        for width in [60, 100, 160] {
            let full = socket_table_lines(&snapshot, &order, None, width);
            for height in [3, 4, 8, 30] {
                let view = viewport(&snapshot, &order, width, height, 10);
                let visible = socket_table_viewport(&snapshot, &order, None, width, height, 10);
                let expected = (0..height)
                    .filter_map(|row| view.logical_row(row))
                    .map(|row| full[row].clone())
                    .collect::<Vec<_>>();
                assert_eq!(visible, expected);
                assert_eq!(
                    &visible[view.context..view.data_start()],
                    &socket_heading_lines(usize::from(width), &order)
                );
            }
        }
    }

    #[test]
    fn oversized_scroll_still_shows_the_last_socket() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let backend = TestBackend::new(80, 3);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    frame.area(),
                    &snapshot,
                    &order(&snapshot),
                    None,
                    usize::MAX,
                )
            })
            .unwrap();
        assert!(terminal.backend().to_string().contains("UNCONN"));
        assert!(terminal.backend().to_string().contains("STATE"));
        assert!(terminal.backend().to_string().contains("LOCAL"));
    }

    #[test]
    fn wide_process_names_cannot_shift_column_boundaries() {
        let fitted = fit_cell("network-\u{7f51}\u{7edc}", 10);
        let middle = fit_cell(&truncate_middle("process-\u{7f51}\u{7edc}-worker", 12), 12);

        assert_eq!(text_width(&fitted), 10);
        assert_eq!(text_width(&middle), 12);
    }

    #[test]
    fn subcolumn_clicks_and_highlights_match_the_exact_socket_metric() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let mut order = order(&snapshot);
        for width in [80, 120, 160, 240] {
            let layout = SocketLayout::new(usize::from(width));
            let header =
                table_header_lines(&snapshot, usize::from(width), snapshot.sockets().len()).len()
                    + 1;
            for field in 0..10 {
                let x = (layout.widths[..field].iter().sum::<usize>() + field) as u16;
                let sort = header_sort_at(&snapshot, &order, width, x, header).unwrap();
                if order.sort() == sort && order.descending() {
                    order.reverse();
                }
                order.select_sort(sort);
                assert_eq!(order.sort(), column_sort(field));
                let headings = socket_heading_lines(usize::from(width), &order);
                let active = headings[1]
                    .spans
                    .iter()
                    .filter(|span| span.style.bg == Some(theme::SORT_BG))
                    .collect::<Vec<_>>();
                assert_eq!(active.len(), 1);
                assert!(active[0].content.contains('↓'));
                order.select_sort(sort);
                assert!(!order.descending());
                assert!(header_sort_at(
                    &snapshot,
                    &order,
                    width,
                    x + layout.widths[field] as u16,
                    header
                )
                .is_none());
                assert!(header_sort_at(&snapshot, &order, width, x, header + 1).is_none());
            }
        }
    }

    #[test]
    fn socket_detail_owner_wraps_by_terminal_display_width() {
        let owner = format!(
            "  STATE / OWNER: 1234/{}",
            "\u{7f51}\u{7edc}\u{8bca}\u{65ad}".repeat(16)
        );
        let lines = wrap_text(&owner, 60);

        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| text_width(line) <= 60), "{lines:?}");
    }
}
