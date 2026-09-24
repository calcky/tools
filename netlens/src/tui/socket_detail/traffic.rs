use super::{
    diagnostic_value, format_bit_rate, format_bytes, push_metric, socket, theme, DetailMetricsMode,
    InetSocketSnapshot, Line, Modifier, Span, Style, LABEL_COLOR,
};

pub(super) fn push_traffic_matrix(
    lines: &mut Vec<Line<'static>>,
    socket: &InetSocketSnapshot,
    width: usize,
    mode: DetailMetricsMode,
) {
    let rx = socket.receive_traffic();
    let tx = socket.send_traffic();
    let tcp = socket.tcp();
    let queue_present = socket.receive_queue() > 0 || socket.send_queue() > 0;
    let rows = [
        (
            "APP BYTES",
            rx.bytes().map(format_bytes),
            tx.bytes().map(format_bytes),
        ),
        (
            "APP BANDWIDTH",
            rx.bits_per_second()
                .map(|v| format_bit_rate(v.round() as u64)),
            tx.bits_per_second()
                .map(|v| format_bit_rate(v.round() as u64)),
        ),
        (
            "ALL SEG TOTAL",
            rx.segments().map(|v| v.to_string()),
            tx.segments().map(|v| v.to_string()),
        ),
        (
            "ALL SEG/S",
            rx.segments_per_second().map(|v| format!("{v:.1}")),
            tx.segments_per_second().map(|v| format!("{v:.1}")),
        ),
        (
            "DATA SEG TOTAL",
            tcp.and_then(|v| v.data_segments_in).map(|v| v.to_string()),
            tcp.and_then(|v| v.data_segments_out).map(|v| v.to_string()),
        ),
        (
            "QUEUE",
            diagnostic_value(mode, queue_present, || {
                format_bytes(u64::from(socket.receive_queue()))
            }),
            diagnostic_value(mode, queue_present, || {
                format_bytes(u64::from(socket.send_queue()))
            }),
        ),
    ];
    let mut header = false;
    for (label, rx, tx) in rows {
        if mode == DetailMetricsMode::WithData && rx.is_none() && tx.is_none() {
            continue;
        }
        if width < 40 {
            push_metric(lines, &format!("{label} RX"), rx, width, mode);
            push_metric(lines, &format!("{label} TX"), tx, width, mode);
            continue;
        }
        if !header {
            row(lines, "COUNTER", "RX", "TX", width, true);
            header = true;
        }
        row(
            lines,
            label,
            rx.as_deref().unwrap_or("n/a"),
            tx.as_deref().unwrap_or("n/a"),
            width,
            false,
        );
    }
    if tcp.is_some() {
        push_metric(
            lines,
            "TX APP",
            Some("acknowledged bytes".to_owned()),
            width,
            mode,
        );
    }
}

fn row(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    rx: &str,
    tx: &str,
    width: usize,
    header: bool,
) {
    let label_width = 15;
    let rx_width = (width - label_width - 6) / 2;
    let tx_width = width - label_width - 6 - rx_width;
    let labels = socket::wrap_text(label, label_width);
    let rx = socket::wrap_text(rx, rx_width);
    let tx = socket::wrap_text(tx, tx_width);
    let emphasis = if header {
        Modifier::BOLD
    } else {
        Modifier::empty()
    };
    for index in 0..labels.len().max(rx.len()).max(tx.len()) {
        let label = labels.get(index).map_or("", String::as_str);
        let rx = rx.get(index).map_or("", String::as_str);
        let tx = tx.get(index).map_or("", String::as_str);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{label:<label_width$}"),
                Style::default().fg(LABEL_COLOR).add_modifier(emphasis),
            ),
            Span::styled(" | ", Style::default().fg(theme::DIVIDER)),
            Span::styled(
                format!("{rx:>rx_width$}"),
                Style::default().fg(theme::RX).add_modifier(emphasis),
            ),
            Span::styled(" | ", Style::default().fg(theme::DIVIDER)),
            Span::styled(
                format!("{tx:>tx_width$}"),
                Style::default().fg(theme::TX).add_modifier(emphasis),
            ),
        ]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_columns_and_headers_share_right_edges() {
        for width in [49, 55] {
            let mut lines = Vec::new();
            row(&mut lines, "COUNTER", "RX", "TX", width, true);
            row(&mut lines, "QUEUE", "128 B", "2.00 KiB", width, false);
            let rx_end = 18 + (width - 21) / 2;
            for line in lines {
                let text = line.to_string();
                assert_eq!(text.len(), width);
                assert_ne!(text.as_bytes()[rx_end - 1], b' ');
                assert_ne!(text.as_bytes()[width - 1], b' ');
                assert_eq!(&text[rx_end..rx_end + 3], " | ");
            }
        }
    }
}
