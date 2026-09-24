use ratatui::style::Color;
use ratatui::text::Span;

use super::*;
use crate::tui::detail_block::{framed_lines, side_by_side};

const LABEL: Color = Color::Rgb(164, 173, 179);

pub(super) fn flow_detail_lines(
    snapshot: &ConntrackTableSnapshot,
    flow: &ConntrackFlowSnapshot,
    width: usize,
) -> Vec<Line<'static>> {
    let count = if width >= 110 { 2 } else { 1 };
    let outer = width.saturating_sub(count - 1) / count;
    let inner = if outer >= 5 { outer - 4 } else { outer.max(1) };
    let mut left = section(
        "CONNECTION",
        theme::CONNTRACK,
        vec![
            (
                "Protocol / state",
                format!(
                    "{}/{} / {}",
                    flow.protocol_name(),
                    flow.protocol(),
                    flow.state().unwrap_or("n/a")
                ),
            ),
            (
                "Family / zone",
                format!("{:?} / {}", flow.family(), flow.zone()),
            ),
            (
                "CT mark",
                flow.ct_mark()
                    .map_or_else(|| "n/a".to_owned(), |mark| format!("0x{mark:08x}")),
            ),
            (
                "Timeout",
                flow.timeout_seconds()
                    .map_or_else(|| "n/a".to_owned(), |value| format!("{value} s remaining")),
            ),
            ("Flow offload", yes_no(flow.offloaded()).to_owned()),
            (
                "Hardware offload",
                yes_no(flow.hardware_offloaded()).to_owned(),
            ),
        ],
        inner,
        outer,
    );

    let mut tuples = Vec::new();
    for (label, tuple) in [
        ("TX / ORIGINAL", flow.original()),
        ("RX / REPLY", flow.reply()),
    ] {
        tuples.push(Line::styled(
            label,
            Style::default()
                .fg(if label.starts_with("TX") {
                    theme::TX
                } else {
                    theme::RX
                })
                .add_modifier(Modifier::BOLD),
        ));
        field(
            &mut tuples,
            "Source",
            &format_endpoint(tuple.source()),
            inner,
        );
        field(
            &mut tuples,
            "Destination",
            &format_endpoint(tuple.destination()),
            inner,
        );
        if let Some(icmp) = tuple.icmp() {
            field(
                &mut tuples,
                "ICMP type/code/id",
                &format!("{}/{}/{}", icmp.icmp_type(), icmp.code(), icmp.id()),
                inner,
            );
        }
    }
    // Reply endpoints reversed describe the translated original direction.
    if flow.original().source() != flow.reply().destination()
        || flow.original().destination() != flow.reply().source()
    {
        tuples.push(Line::styled(
            "TX AFTER NAT",
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
        field(
            &mut tuples,
            "Source",
            &format_endpoint(flow.reply().destination()),
            inner,
        );
        field(
            &mut tuples,
            "Destination",
            &format_endpoint(flow.reply().source()),
            inner,
        );
        tuples.push(Line::styled(
            "RX AFTER REVERSE NAT",
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
        field(
            &mut tuples,
            "Source",
            &format_endpoint(flow.original().destination()),
            inner,
        );
        field(
            &mut tuples,
            "Destination",
            &format_endpoint(flow.original().source()),
            inner,
        );
    }
    // These subsection labels also wrap on very narrow terminals.
    let tuples = tuples
        .into_iter()
        .flat_map(|line| {
            if line.width() > inner {
                wrap_text(&line.to_string(), inner)
                    .into_iter()
                    .map(|text| Line::styled(text, line.style))
                    .collect()
            } else {
                vec![line]
            }
        })
        .collect();
    left.extend(framed_lines("TUPLES / NAT", theme::NETWORK, tuples, outer));

    let mut right = framed_lines("TRAFFIC", theme::ACCENT, traffic(flow, inner), outer);
    right.extend(section(
        "TOTALS",
        theme::GOOD,
        vec![
            (
                "Traffic byte",
                optional(flow.total_bytes().map(|v| v.to_string())),
            ),
            (
                "Packets",
                optional(flow.total_packets().map(|v| v.to_string())),
            ),
            (
                "Bandwidth bit/s",
                optional(flow.total_bits_per_second().map(|v| format!("{v:.2}"))),
            ),
            (
                "PPS",
                optional(flow.total_packets_per_second().map(|v| format!("{v:.2}"))),
            ),
        ],
        inner,
        outer,
    ));

    let (health, style) = health_label(snapshot.health());
    let mut coverage = Vec::new();
    for (label, value) in [
        ("Health", health.to_owned()),
        ("Sample", format!("#{}", snapshot.sequence())),
        ("Sample at", format_duration(snapshot.attempted_at())),
        (
            "Collection cost",
            format_duration(snapshot.collection_duration()),
        ),
        (
            "Retained / kernel",
            format!(
                "{} / {}",
                snapshot.flows().len(),
                optional(snapshot.total_entries().map(|v| v.to_string()))
            ),
        ),
        (
            "Accounting",
            snapshot
                .accounting_enabled()
                .map_or("unknown", |v| if v { "on" } else { "off" })
                .to_owned(),
        ),
        ("Truncated", yes_no(snapshot.truncated()).to_owned()),
        ("Rejected lines", snapshot.rejected_lines().to_string()),
    ] {
        field(&mut coverage, label, &value, inner);
    }
    if let Some(reason) = health_diagnostic(snapshot.health()) {
        field(&mut coverage, "Reason", reason, inner);
    }
    right.extend(framed_lines(
        "SAMPLE / COVERAGE",
        style.fg.unwrap_or(theme::WARN),
        coverage,
        outer,
    ));

    let mut lines = vec![Line::styled(
        fit_cell(" CONNTRACK / CONNECTION", width),
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    )];
    if count == 2 {
        lines.extend(side_by_side(vec![(outer, left), (outer, right)]));
    } else {
        // Keep per-flow fields ahead of the table-wide coverage when stacked.
        // Traffic remains intact; every field is reachable by normal scrolling.
        lines.extend(left);
        lines.extend(right);
    }
    lines.extend(wrap_text("TX = original initiator; RX = reply (not NIC direction). Offloaded traffic may be partial.", width).into_iter().map(|s| Line::styled(s, Style::default().fg(LABEL))));
    lines
}

fn optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "n/a".to_owned())
}

fn section(
    title: &str,
    color: Color,
    rows: Vec<(&str, String)>,
    inner: usize,
    outer: usize,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (label, value) in rows {
        field(&mut lines, label, &value, inner);
    }
    framed_lines(title, color, lines, outer)
}

fn field(lines: &mut Vec<Line<'static>>, label: &str, value: &str, width: usize) {
    if width < 24 {
        lines.extend(
            wrap_text(label, width)
                .into_iter()
                .map(|s| Line::styled(s, Style::default().fg(LABEL))),
        );
        lines.extend(wrap_text(value, width).into_iter().map(Line::raw));
        return;
    }
    let label_width = (width / 3).min(18);
    let labels = wrap_text(label, label_width);
    let values = wrap_text(value, width - label_width - 3);
    for i in 0..labels.len().max(values.len()) {
        let label = labels.get(i).map_or("", String::as_str);
        lines.push(Line::from(vec![
            Span::styled(
                super::super::sort_table::pad(label, label_width, false),
                Style::default().fg(LABEL),
            ),
            Span::styled(" | ", Style::default().fg(theme::DIVIDER)),
            Span::styled(
                values.get(i).cloned().unwrap_or_default(),
                Style::default().fg(theme::TEXT),
            ),
        ]));
    }
}

fn traffic(flow: &ConntrackFlowSnapshot, width: usize) -> Vec<Line<'static>> {
    let values = |t: ConntrackTraffic| {
        [
            t.bytes().map(|v| v.to_string()),
            t.packets().map(|v| v.to_string()),
            t.bits_per_second().map(|v| format!("{v:.2}")),
            t.packets_per_second().map(|v| format!("{v:.2}")),
            crate::monitor::conntrack_flow::average_packet(t).map(|v| format!("{v:.2}")),
            t.byte_interval().map(|s| s.delta().to_string()),
            t.packet_interval().map(|s| s.delta().to_string()),
            t.byte_interval().map(|s| format_duration(s.elapsed())),
            t.packet_interval().map(|s| format_duration(s.elapsed())),
        ]
    };
    let tx = values(flow.original_traffic());
    let rx = values(flow.reply_traffic());
    let mut lines = Vec::new();
    if width >= 40 {
        matrix_row(&mut lines, "COUNTER", "TX", "RX", width, true);
    }
    for (i, label) in [
        "Traffic byte",
        "Packets total",
        "Bandwidth bit/s",
        "PPS",
        "Avg pkt byte",
        "Byte delta",
        "Packet delta",
        "Byte interval",
        "Packet interval",
    ]
    .into_iter()
    .enumerate()
    {
        let tx = tx[i].as_deref().unwrap_or("n/a");
        let rx = rx[i].as_deref().unwrap_or("n/a");
        if width >= 40 {
            matrix_row(&mut lines, label, tx, rx, width, false);
        } else {
            field(&mut lines, &format!("TX {label}"), tx, width);
            field(&mut lines, &format!("RX {label}"), rx, width);
        }
    }
    lines
}

fn matrix_row(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    tx: &str,
    rx: &str,
    width: usize,
    header: bool,
) {
    let label_width = 16;
    let tx_width = (width - label_width - 6) / 2;
    let rx_width = width - label_width - 6 - tx_width;
    let labels = wrap_text(label, label_width);
    let tx = wrap_text(tx, tx_width);
    let rx = wrap_text(rx, rx_width);
    let emphasis = if header {
        Modifier::BOLD
    } else {
        Modifier::empty()
    };
    for i in 0..labels.len().max(tx.len()).max(rx.len()) {
        let mut spans = Vec::new();
        for (col, (text, size, color)) in [
            (labels.get(i), label_width, LABEL),
            (tx.get(i), tx_width, theme::TX),
            (rx.get(i), rx_width, theme::RX),
        ]
        .into_iter()
        .enumerate()
        {
            if col > 0 {
                spans.push(Span::styled(" | ", Style::default().fg(theme::DIVIDER)));
            }
            spans.push(Span::styled(
                super::super::sort_table::pad(text.map_or("", String::as_str), size, col > 0),
                Style::default().fg(color).add_modifier(emphasis),
            ));
        }
        lines.push(Line::from(spans));
    }
}
