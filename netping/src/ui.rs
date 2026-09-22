use std::{net::IpAddr, time::Duration};

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

pub struct Row {
    pub name: String,
    pub sent: u64,
    pub received: u64,
    pub loss: f64,
    pub last: String,
    pub min: Option<f64>,
    pub avg: Option<f64>,
    pub max: Option<f64>,
    pub mdev: Option<f64>,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
    pub pending: usize,
    pub timeout: u64,
    pub failed: u64,
    pub reordered: u64,
    pub duplicate: u64,
    pub late: u64,
    pub invalid: u64,
    pub limited: u64,
    pub skipped: u64,
    pub connect_failed: u64,
    pub retrans: Option<crate::tcp::View>,
    pub alert: Option<Alert>,
    pub state: String,
    pub error: Option<String>,
    pub bad: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alert {
    Retrans,
    Timeout,
    Disconnected,
    Failed,
}

impl Alert {
    fn label(self) -> &'static str {
        match self {
            Self::Retrans => "RETRANS",
            Self::Timeout => "TIMEOUT",
            Self::Disconnected => "DISCONNECTED",
            Self::Failed => "FAILED",
        }
    }

    fn style(self) -> Style {
        bold().fg(if self == Self::Retrans {
            Color::Yellow
        } else {
            Color::Red
        })
    }
}

pub struct View {
    pub host: String,
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub interval: Duration,
    pub timeout: Duration,
    pub elapsed: Duration,
    pub paused: bool,
    pub draining: bool,
    pub rows: Vec<Row>,
}

#[derive(Default)]
pub struct State {
    pub selected: usize,
}

fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

fn error_style() -> Style {
    bold().fg(Color::Red)
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn fit(value: &str, width: u16) -> String {
    let value = clean(value);
    let width = usize::from(width);
    if Line::raw(value.as_str()).width() <= width {
        return value;
    }
    if width == 0 {
        return String::new();
    }
    let mut result = String::new();
    for c in value.chars() {
        let end = result.len();
        result.push(c);
        if Line::raw(result.as_str()).width() > width - 1 {
            result.truncate(end);
            break;
        }
    }
    result.push('~');
    result
}

fn text(f: &mut Frame, area: Rect, value: &str, style: Style, right: bool) {
    f.render_widget(
        Paragraph::new(fit(value, area.width))
            .style(style)
            .alignment(if right {
                Alignment::Right
            } else {
                Alignment::Left
            }),
        area,
    );
}

fn number(value: Option<f64>, precision: usize, width: u16) -> String {
    let Some(value) = value.filter(|v| v.is_finite() && *v >= 0.0) else {
        return "-".into();
    };
    let value_text = format!("{value:.precision$}");
    if value_text.len() <= usize::from(width) {
        return value_text;
    }
    for precision in (0..=2).rev() {
        let scientific = format!("{value:.precision$e}");
        if scientific.len() <= usize::from(width) {
            return scientific;
        }
    }
    ">".into()
}

fn count(value: u64, width: u16) -> String {
    let exact = value.to_string();
    if exact.len() <= usize::from(width) {
        return exact;
    }
    for (divisor, suffix) in [
        (1_000_u64, "k"),
        (1_000_000, "M"),
        (1_000_000_000, "G"),
        (1_000_000_000_000, "T"),
        (1_000_000_000_000_000, "P"),
        (1_000_000_000_000_000_000, "E"),
    ] {
        if value < divisor {
            break;
        }
        for precision in [1, 0] {
            let compact = format!("{:.*}{suffix}", precision, value as f64 / divisor as f64);
            if compact.len() <= usize::from(width) {
                return compact;
            }
        }
    }
    ">".into()
}

#[derive(Clone, Copy)]
enum Value {
    Count(u64),
    Number(Option<f64>, usize),
}

#[derive(Clone, Copy)]
struct Field {
    label: &'static str,
    value: Value,
}

impl Field {
    fn display(&self, width: u16) -> String {
        match self.value {
            Value::Count(value) => count(value, width),
            Value::Number(value, precision) => number(value, precision, width),
        }
    }

    fn width(&self) -> u16 {
        self.label.len() as u16
            + 1
            + match self.value {
                Value::Count(_) => 6,
                Value::Number(_, _) => 7,
            }
    }

    fn style(&self) -> Style {
        match self.value {
            Value::Number(None, _) | Value::Count(0) => Style::default().fg(Color::DarkGray),
            Value::Number(Some(_), _) => bold().fg(Color::White),
            Value::Count(_) => bold().fg(match self.label {
                "Pending" => Color::Cyan,
                "Timeout" | "Failed" | "ConnFail" => Color::Red,
                _ => Color::Yellow,
            }),
        }
    }
}

fn fields(f: &mut Frame, area: Rect, fields: &[Field]) {
    let columns = Layout::horizontal(vec![
        Constraint::Ratio(1, fields.len() as u32);
        fields.len()
    ])
    .spacing(2)
    .split(area);
    for (index, field) in fields.iter().enumerate() {
        let column = columns[index];
        let label_width = field.label.len() as u16 + 1;
        text(
            f,
            Rect {
                width: label_width,
                ..column
            },
            &format!("{}:", field.label),
            Style::default().fg(Color::Gray),
            false,
        );
        let value = Rect::new(
            column.x + label_width + 1,
            column.y,
            column.width.saturating_sub(label_width + 1),
            1,
        );
        text(f, value, &field.display(value.width), field.style(), true);
    }
}

fn detail_groups(row: &Row) -> Vec<Vec<Field>> {
    use Value::{Count, Number};
    vec![
        vec![
            Field {
                label: "Min",
                value: Number(row.min, 3),
            },
            Field {
                label: "Max",
                value: Number(row.max, 3),
            },
            Field {
                label: "Mdev",
                value: Number(row.mdev, 3),
            },
            Field {
                label: "P50",
                value: Number(row.p50, 3),
            },
            Field {
                label: "P95",
                value: Number(row.p95, 3),
            },
            Field {
                label: "P99",
                value: Number(row.p99, 3),
            },
        ],
        vec![
            Field {
                label: "Pending",
                value: Count(row.pending as u64),
            },
            Field {
                label: "Timeout",
                value: Count(row.timeout),
            },
            Field {
                label: "Failed",
                value: Count(row.failed),
            },
            Field {
                label: "Reordered",
                value: Count(row.reordered),
            },
            Field {
                label: "Duplicate",
                value: Count(row.duplicate),
            },
        ],
        vec![
            Field {
                label: "Late",
                value: Count(row.late),
            },
            Field {
                label: "Invalid",
                value: Count(row.invalid),
            },
            Field {
                label: "Limited",
                value: Count(row.limited),
            },
            Field {
                label: "Skipped",
                value: Count(row.skipped),
            },
            Field {
                label: "ConnFail",
                value: Count(row.connect_failed),
            },
        ],
    ]
}

fn field_lines(groups: &[Vec<Field>], width: u16) -> Vec<&[Field]> {
    let mut lines = Vec::new();
    // Fixed value budgets keep fields in the same row as counters change.
    for group in groups {
        let mut start = 0;
        let mut used = 0;
        for (index, field) in group.iter().enumerate() {
            let next = field.width();
            if index > start && used + 1 + next > width {
                lines.push(&group[start..index]);
                start = index;
                used = 0;
            }
            used += u16::from(used > 0) + next;
        }
        lines.push(&group[start..]);
    }
    lines
}

fn retrans_style(value: Option<f64>) -> Style {
    if value.is_some_and(|n| n > 0.0) {
        bold().fg(Color::Red)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

fn retrans(f: &mut Frame, area: Rect, value: crate::tcp::View, columns: bool) {
    let total = |v: Option<u64>, width| v.map_or_else(|| "-".into(), |v| count(v, width));
    if columns {
        let [label, count_area, rate_area] = Layout::horizontal([
            Constraint::Length(13),
            Constraint::Min(1),
            Constraint::Length(9),
        ])
        .areas(Rect { height: 1, ..area });
        text(f, label, "TCP RETRANS", bold().fg(Color::Gray), false);
        text(f, count_area, "TOTAL", bold().fg(Color::Gray), true);
        text(f, rate_area, "/s", bold().fg(Color::Gray), true);
        for (index, (name, counter)) in [("Tx", value.tx), ("Rx", value.rx)].iter().enumerate() {
            let y = area.y + 1 + index as u16;
            text(
                f,
                Rect { y, ..label },
                name,
                Style::default().fg(Color::Gray),
                false,
            );
            text(
                f,
                Rect { y, ..count_area },
                &total(counter.total, count_area.width),
                retrans_style(counter.total.map(|n| n as f64)),
                true,
            );
            text(
                f,
                Rect { y, ..rate_area },
                &number(counter.rate, 2, rate_area.width),
                retrans_style(counter.rate),
                true,
            );
        }
    } else {
        let [label, tx, rx] = Layout::horizontal([
            Constraint::Length(8),
            Constraint::Ratio(1, 2),
            Constraint::Ratio(1, 2),
        ])
        .areas(area);
        text(f, label, "Retrans", bold().fg(Color::Gray), false);
        for (area, name, counter) in [(tx, "Tx", value.tx), (rx, "Rx", value.rx)] {
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(format!("{name}:"), Style::default().fg(Color::Gray)),
                    Span::styled(
                        total(counter.total, 6),
                        retrans_style(counter.total.map(|n| n as f64)),
                    ),
                    Span::raw(" ("),
                    Span::styled(number(counter.rate, 2, 6), retrans_style(counter.rate)),
                    Span::raw("/s)"),
                ])),
                area,
            );
        }
    }
}

fn details(f: &mut Frame, area: Rect, row: &Row, focused: bool, joined: bool, columns: bool) {
    let title = format!(
        " {}{} | ms ",
        if focused { "> " } else { "" },
        clean(&row.name)
    );
    let title = fit(&title, area.width.saturating_sub(4).min(22));
    let state = if let Some(alert) = row.alert {
        alert.label().into()
    } else if row.bad {
        format!("ERROR {}", clean(&row.state))
    } else {
        clean(&row.state)
    };
    let status_style = if let Some(alert) = row.alert {
        alert.style()
    } else if row.bad {
        error_style()
    } else if row.state.eq_ignore_ascii_case("ready") {
        bold().fg(Color::Green)
    } else {
        bold().fg(Color::Yellow)
    };
    let state = format!(
        " {} ",
        fit(
            &state,
            area.width
                .saturating_sub(Line::raw(&title).width() as u16 + 5)
        ),
    );
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_set(if joined {
            border::Set {
                top_left: "\u{251c}",
                top_right: "\u{2524}",
                ..border::PLAIN
            }
        } else {
            border::PLAIN
        })
        .border_style(if let Some(alert) = row.alert {
            alert.style()
        } else if row.bad {
            Style::default().fg(Color::Red)
        } else if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        })
        .title(Line::styled(title, bold().fg(Color::White)))
        .title(Line::styled(state, status_style).alignment(Alignment::Right));
    if row.retrans.is_some() {
        if let Some(error) = &row.error {
            block = block.title_bottom(Line::styled(
                fit(
                    &format!(" Last error: {error} "),
                    area.width.saturating_sub(2),
                ),
                if row.bad {
                    error_style()
                } else {
                    Style::default().fg(Color::DarkGray)
                },
            ));
        }
    }
    let inner = block.inner(area);
    f.render_widget(block, area);
    let groups = detail_groups(row);
    let mut y = inner.y;
    if columns {
        let [latency, percentiles] =
            Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
                .spacing(2)
                .areas(Rect::new(inner.x, y, inner.width, 1));
        text(f, latency, "LATENCY", bold().fg(Color::Gray), false);
        text(f, percentiles, "PERCENTILES", bold().fg(Color::Gray), false);
        y += 1;
        for index in 0..3 {
            fields(
                f,
                Rect::new(inner.x, y, inner.width, 1),
                &[groups[0][index], groups[0][index + 3]],
            );
            y += 1;
        }
        y += 1;
        text(
            f,
            Rect::new(inner.x, y, inner.width, 1),
            "COUNTERS",
            bold().fg(Color::Gray),
            false,
        );
        y += 1;
        for pair in [
            [groups[1][0], groups[1][1]],
            [groups[1][2], groups[2][4]],
            [groups[1][3], groups[1][4]],
            [groups[2][0], groups[2][1]],
            [groups[2][2], groups[2][3]],
        ] {
            fields(f, Rect::new(inner.x, y, inner.width, 1), &pair);
            y += 1;
        }
    } else {
        let rows = field_lines(&groups, inner.width);
        let spaced = usize::from(inner.height) >= rows.len() + 3;
        for fields_in_row in rows {
            if spaced && matches!(fields_in_row[0].label, "Pending" | "Late") {
                y += 1;
            }
            fields(f, Rect::new(inner.x, y, inner.width, 1), fields_in_row);
            y += 1;
        }
    }
    if let Some(value) = row.retrans {
        retrans(
            f,
            Rect::new(inner.x, y, inner.width, if columns { 3 } else { 1 }),
            value,
            columns,
        );
        return;
    }
    let Some(error) = row.error.as_deref() else {
        return;
    };
    if inner.bottom().saturating_sub(y) > 1 {
        y += 1;
    }
    let last_error_style = if row.bad {
        error_style()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let error_area = Rect::new(inner.x, y, inner.width, inner.bottom().saturating_sub(y));
    if error_area.height == 1 {
        text(
            f,
            error_area,
            &format!("Last error: {error}"),
            last_error_style,
            false,
        );
    } else {
        let message = clean(&format!("Last error: {error}"));
        f.render_widget(
            Paragraph::new(message)
                .style(last_error_style)
                .wrap(Wrap { trim: false }),
            error_area,
        );
    }
}

fn detail_layout(area: Rect, view: &View) -> Option<Vec<Rect>> {
    if view.rows.is_empty() {
        return Some(Vec::new());
    }
    let count = view.rows.len() as u16;
    let columns = area.width >= 120;
    let width = if columns {
        area.width / count
    } else {
        area.width
    };
    let metrics = field_lines(&detail_groups(&view.rows[0]), width.saturating_sub(2)).len();
    // Stacked panels share their horizontal borders, fitting all details at 80x24.
    let minimum = if columns { 16 } else { metrics as u16 + 3 };
    if columns {
        if area.height < minimum {
            return None;
        }
        let areas = Layout::horizontal(vec![Constraint::Ratio(1, count as u32); count as usize])
            .split(area);
        Some(areas.to_vec())
    } else {
        if area.height < (minimum - 1) * count + 1 {
            return None;
        }
        let heights = Layout::vertical(vec![Constraint::Ratio(1, count as u32); count as usize])
            .split(Rect {
                height: area.height - 1,
                ..area
            });
        Some(
            heights
                .iter()
                .map(|r| Rect {
                    height: r.height + 1,
                    ..*r
                })
                .collect(),
        )
    }
}

fn table(f: &mut Frame, area: Rect, view: &View, state: &State) {
    let wide = area.width >= 100;
    let headers: &[&str] = if wide {
        &[
            "Protocol",
            "Sent",
            "Recv",
            "Loss-Fail%",
            "Last",
            "Avg",
            "Min",
            "Max",
            "Mdev",
        ]
    } else {
        &["Protocol", "Sent", "Recv", "Loss-Fail%", "Last", "Avg"]
    };
    let base: &[u16] = if wide {
        &[11, 9, 9, 10, 10, 9, 9, 9, 9]
    } else {
        &[9, 7, 7, 10, 10, 10]
    };
    let spare = area
        .width
        .saturating_sub(2 + base.iter().sum::<u16>() + headers.len() as u16 - 1);
    let mut x = area.x + 2;
    let columns: Vec<_> = base
        .iter()
        .enumerate()
        .map(|(index, width)| {
            let width = *width
                + spare / headers.len() as u16
                + u16::from(index < usize::from(spare) % headers.len());
            let column = Rect::new(x, area.y, width, 1);
            x += width + 1;
            column
        })
        .collect();
    for (index, header) in headers.iter().enumerate() {
        text(f, columns[index], header, bold(), index > 0);
    }
    let start = state.selected.saturating_sub(2);
    for (offset, row) in view.rows.iter().enumerate().skip(start).take(3) {
        let y = area.y + 1 + (offset - start) as u16;
        let style = if let Some(alert) = row.alert {
            alert.style()
        } else if row.bad {
            error_style()
        } else {
            Style::default()
        };
        let style = if offset == state.selected {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        };
        if offset == state.selected {
            text(f, Rect::new(area.x, y, 2, 1), ">", style, false);
        }
        for (index, header) in headers.iter().enumerate() {
            let column = Rect {
                y,
                ..columns[index]
            };
            let value = match *header {
                "Protocol" => {
                    if row.bad && row.alert.is_none() {
                        format!("{} ERR", fit(&row.name, column.width.saturating_sub(4)))
                    } else {
                        row.name.clone()
                    }
                }
                "Sent" => count(row.sent, column.width),
                "Recv" => count(row.received, column.width),
                "Loss-Fail%" => number(Some(row.loss), 2, column.width),
                "Last" => row.last.clone(),
                "Min" => number(row.min, 3, column.width),
                "Avg" => number(row.avg, 3, column.width),
                "Max" => number(row.max, 3, column.width),
                "Mdev" => number(row.mdev, 3, column.width),
                _ => unreachable!(),
            };
            text(f, column, &value, style, index > 0);
        }
    }
}

pub fn draw(f: &mut Frame, view: &View, state: &mut State) {
    state.selected = state.selected.min(view.rows.len().saturating_sub(1));
    let area = f.area();
    if area.width < 60 || area.height < 16 {
        f.render_widget(
            Paragraph::new(
                "Terminal too small\nUse 80x24 or a wider/taller terminal\nResize or press q",
            )
            .style(bold()),
            area,
        );
        return;
    }
    let [title, address, settings, table_area, detail_area, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(area);
    let Some(panels) = detail_layout(detail_area, view) else {
        f.render_widget(
            Paragraph::new(
                "Terminal too small for all three details\nUse 80x24 or a wider/taller terminal\nResize or press q",
            )
            .style(bold()),
            area,
        );
        return;
    };
    let [host, status] =
        Layout::horizontal([Constraint::Min(1), Constraint::Length(12)]).areas(title);
    text(f, host, &format!("netping | {}", view.host), bold(), false);
    text(
        f,
        status,
        if view.draining {
            "DRAINING"
        } else if view.paused {
            "PAUSED"
        } else {
            "RUNNING"
        },
        bold(),
        true,
    );
    text(
        f,
        address,
        &format!("{} UDP:{} TCP:{}", view.ip, view.udp_port, view.tcp_port),
        Style::default(),
        false,
    );
    text(
        f,
        settings,
        &format!(
            "Interval:{:.3}s Timeout:{:.3}s Elapsed:{:.1}s",
            view.interval.as_secs_f64(),
            view.timeout.as_secs_f64(),
            view.elapsed.as_secs_f64()
        ),
        Style::default(),
        false,
    );
    table(f, table_area, view, state);
    if panels.is_empty() {
        text(f, detail_area, "No protocol rows", Style::default(), false);
    }
    for (index, (row, panel)) in view.rows.iter().zip(panels).enumerate() {
        details(
            f,
            panel,
            row,
            index == state.selected,
            index > 0 && panel.x == detail_area.x,
            detail_area.width >= 120,
        );
    }
    text(
        f,
        footer,
        "j/k Up/Down focus | Space pause | r reset | q quit",
        Style::default(),
        false,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

    fn row(name: &str) -> Row {
        Row {
            name: name.into(),
            sent: 100,
            received: 98,
            loss: 2.0,
            last: "4.250".into(),
            min: Some(1.125),
            avg: Some(3.250),
            max: Some(5.875),
            mdev: Some(0.500),
            p50: Some(3.0),
            p95: Some(4.5),
            p99: Some(5.0),
            pending: 1,
            timeout: 1,
            failed: 0,
            reordered: 2,
            duplicate: 3,
            late: 4,
            invalid: 5,
            limited: 6,
            skipped: 7,
            connect_failed: 8,
            retrans: name
                .starts_with("TCP")
                .then_some(crate::tcp::View::default()),
            alert: None,
            state: "ready".into(),
            error: None,
            bad: false,
        }
    }

    fn view() -> View {
        View {
            host: "example.test".into(),
            ip: "192.0.2.1".parse().unwrap(),
            udp_port: 11111,
            tcp_port: 443,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            elapsed: Duration::from_secs(65),
            paused: false,
            draining: false,
            rows: vec![row("ICMP"), row("UDP"), row("TCP")],
        }
    }

    fn screen(view: &View, state: &mut State, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, view, state)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn lines(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect()
            })
            .collect()
    }

    fn panel_contents(buffer: &Buffer, panel: Rect) -> String {
        (panel.y..panel.bottom())
            .map(|y| {
                (panel.x..panel.right())
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn field_value<'a>(content: &'a str, label: &str) -> &'a str {
        content
            .split_once(&format!("{label}:"))
            .unwrap()
            .1
            .split_whitespace()
            .next()
            .unwrap()
            .trim_end_matches('\u{2502}')
    }

    #[test]
    fn supported_sizes_show_every_protocols_details_without_switching() {
        for (width, height) in [(60, 33), (80, 24), (100, 24), (120, 24), (160, 40)] {
            let mut report = view();
            for (index, row) in report.rows.iter_mut().enumerate() {
                row.pending = 11 + index;
                row.p99 = Some(21.0 + index as f64);
                row.error = Some(format!("previous error {index}"));
            }
            let buffer = screen(&report, &mut State { selected: 1 }, width, height);
            let display = lines(&buffer);
            assert!(display[0].contains("netping") && display[0].contains("RUNNING"));
            assert!(display[4].contains("ICMP"));
            assert!(display[5].starts_with("> UDP"));
            assert!(display[6].contains("TCP"));
            assert!(display[usize::from(height - 1)].contains("q quit"));
            let panels = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap();
            for (index, panel) in panels.iter().enumerate() {
                let content = panel_contents(&buffer, *panel);
                assert!(content.contains(&format!("{} | ms", report.rows[index].name)));
                assert_eq!(field_value(&content, "Pending"), (11 + index).to_string());
                assert_eq!(field_value(&content, "P99"), format!("{}.000", 21 + index));
                for label in [
                    "Min:",
                    "Max:",
                    "Mdev:",
                    "P50:",
                    "P95:",
                    "P99:",
                    "Pending:",
                    "Timeout:",
                    "Failed:",
                    "Reordered:",
                    "Duplicate:",
                    "Late:",
                    "Invalid:",
                    "Limited:",
                    "Skipped:",
                    "ConnFail:",
                    "Last error:",
                ] {
                    assert!(
                        content.contains(label),
                        "missing {label} for protocol {index} at {width}x{height}\n{content}"
                    );
                }
                let joined = width < 120 && index > 0;
                assert_eq!(
                    buffer[(panel.x, panel.y)].symbol(),
                    if joined { "\u{251c}" } else { "\u{250c}" }
                );
                assert_eq!(
                    buffer[(panel.right() - 1, panel.y)].symbol(),
                    if joined { "\u{2524}" } else { "\u{2510}" }
                );
                for y in panel.y + 1..panel.bottom() - 1 {
                    assert_eq!(buffer[(panel.x, y)].symbol(), "\u{2502}");
                    assert_eq!(buffer[(panel.right() - 1, y)].symbol(), "\u{2502}");
                }
            }
            assert!(buffer[(2, 3)].modifier.contains(Modifier::BOLD));
            assert!(buffer[(2, 5)].modifier.contains(Modifier::BOLD));
            assert!(!buffer[(2, 4)].modifier.contains(Modifier::BOLD));
        }
    }

    #[test]
    fn panels_stack_on_normal_terminals_and_align_on_wide_ones() {
        let stacked = lines(&screen(&view(), &mut State::default(), 80, 24));
        assert!(stacked[7].contains("> ICMP | ms"));
        assert!(stacked[12].contains("UDP | ms"));
        assert!(stacked[17].contains("TCP | ms"));
        let wide = lines(&screen(&view(), &mut State { selected: 2 }, 120, 24));
        assert!(wide[7].contains("ICMP | ms"));
        assert!(wide[7].contains("UDP | ms"));
        assert!(wide[7].contains("> TCP | ms"));
        assert!(wide[7].find("ICMP").unwrap() < wide[7].find("UDP").unwrap());
        assert!(wide[7].find("UDP").unwrap() < wide[7].find("TCP").unwrap());
    }

    #[test]
    fn wide_panels_align_values_and_keep_unfocused_titles_bright() {
        let buffer = screen(&view(), &mut State::default(), 120, 24);
        let display = lines(&buffer);
        for x in [0, 40, 80] {
            let panel = Rect::new(x, 7, 40, 16);
            let content = panel_contents(&buffer, panel);
            assert!(content.contains("LATENCY") && content.contains("PERCENTILES"));
            assert!(content.contains("COUNTERS"));
            assert!(!content.contains("Last error:"));
            assert_eq!(buffer[(x + 2, 7)].fg, Color::White);
            assert_eq!(buffer[(x + 18, 9)].fg, Color::White);
            assert!(buffer[(x + 18, 9)].modifier.contains(Modifier::BOLD));
            assert_eq!(buffer[(x + 18, 14)].fg, Color::Cyan);
            assert_eq!(buffer[(x + 38, 14)].fg, Color::Red);
            assert_eq!(buffer[(x + 18, 15)].fg, Color::DarkGray);
            assert_eq!(buffer[(x + 18, 16)].fg, Color::Yellow);
        }
        let positions: Vec<_> = [(9, "1.125"), (10, "5.875"), (11, "0.500")]
            .iter()
            .map(|(y, value)| display[*y].find(value).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn long_tcp_status_keeps_its_protocol_title_and_error_visible() {
        let mut report = view();
        report.rows[2].name = "TCP connect".into();
        report.rows[2].state = "Unavailable".into();
        report.rows[2].bad = true;
        report.rows[2].error = Some("connection refused".into());
        for (width, height) in [(80, 24), (120, 24)] {
            let buffer = screen(&report, &mut State { selected: 2 }, width, height);
            let panel = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap()[2];
            let content = panel_contents(&buffer, panel);
            let title = content.lines().next().unwrap();
            assert!(title.contains("TCP connect | ms") && title.contains("ERROR"));
            assert!(content.contains("Last error: connection refused"));
            assert_eq!(field_value(&content, "Timeout"), "1");
        }
    }

    #[test]
    fn tcp_retransmissions_show_both_directions_and_rates_alongside_errors() {
        let mut report = view();
        report.rows[2].retrans = Some(crate::tcp::View {
            tx: crate::tcp::CounterView {
                total: Some(3),
                rate: Some(0.5),
            },
            rx: crate::tcp::CounterView {
                total: Some(7),
                rate: Some(1.25),
            },
        });
        report.rows[2].bad = true;
        report.rows[2].error = Some("connection reset".into());
        for (width, height) in [(60, 33), (80, 24), (120, 24), (160, 40)] {
            let buffer = screen(&report, &mut State::default(), width, height);
            let panel = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap()[2];
            let content = panel_contents(&buffer, panel);
            assert!(content.contains("Last error: connection reset"));
            if width < 120 {
                assert!(content.contains("Tx:3 (0.50/s)"));
                assert!(content.contains("Rx:7 (1.25/s)"));
            } else {
                assert!(content.contains("TCP RETRANS"));
                for (name, value) in [("Tx", "0.50"), ("Rx", "1.25")] {
                    assert!(content
                        .lines()
                        .any(|line| line.contains(name) && line.contains(value)));
                }
            }
            assert_eq!(field_value(&content, "Pending"), "1");
            assert_eq!(field_value(&content, "P99"), "5.000");
        }
    }

    #[test]
    fn tcp_alerts_are_explicit_without_hiding_successful_measurements() {
        let mut report = view();
        report.rows[2].name = "TCP echo".into();
        report.rows[2].received = report.rows[2].sent;
        report.rows[2].loss = 0.0;
        for (width, height) in [(60, 33), (80, 24), (120, 24), (160, 40)] {
            for name in ["TCP echo", "TCP connect"] {
                report.rows[2].name = name.into();
                for alert in [
                    Alert::Retrans,
                    Alert::Timeout,
                    Alert::Disconnected,
                    Alert::Failed,
                ] {
                    report.rows[2].alert = Some(alert);
                    report.rows[2].bad = alert != Alert::Retrans;
                    let buffer = screen(&report, &mut State { selected: 2 }, width, height);
                    let panels =
                        detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap();
                    let panel = panels[2];
                    let content = panel_contents(&buffer, panel);
                    let title = content.lines().next().unwrap();
                    assert!(title.contains(&format!("{name} | ms")), "{title}");
                    assert!(title.contains(alert.label()), "{title}");
                    assert!(!title.contains("ERROR") && !title.contains("Ready"));
                    let expected = if alert == Alert::Retrans {
                        Color::Yellow
                    } else {
                        Color::Red
                    };
                    assert_eq!(buffer[(2, 6)].fg, expected);
                    assert!(buffer[(2, 6)].modifier.contains(Modifier::BOLD));
                    assert_eq!(buffer[(panel.x, panel.y + 1)].fg, expected);
                    for other in &panels[..2] {
                        assert_eq!(buffer[(other.x, other.y + 1)].fg, Color::DarkGray);
                    }
                    assert!(lines(&buffer)[6].contains("0.00"));
                    assert!(lines(&buffer)[6].contains("4.250"));
                    assert_eq!(field_value(&content, "P99"), "5.000");
                }
            }
        }
    }

    #[test]
    fn narrow_prioritizes_core_columns_and_wide_includes_spread() {
        for width in [60, 80, 99, 100, 120] {
            let display = lines(&screen(&view(), &mut State::default(), width, 36));
            for label in ["Protocol", "Sent", "Recv", "Loss-Fail%", "Last", "Avg"] {
                assert!(display[3].contains(label), "{label} missing at {width}");
            }
            for label in ["Min", "Max", "Mdev"] {
                assert_eq!(display[3].contains(label), width >= 100);
            }
            if width >= 100 {
                assert_eq!(
                    display[3].split_whitespace().collect::<Vec<_>>(),
                    [
                        "Protocol",
                        "Sent",
                        "Recv",
                        "Loss-Fail%",
                        "Last",
                        "Avg",
                        "Min",
                        "Max",
                        "Mdev"
                    ]
                );
            }
            assert!(display[4].contains("4.250"));
            assert!(display[4].contains("3.250"));
        }
    }

    #[test]
    fn missing_measurements_are_dashes_and_errors_use_words_and_red() {
        let mut report = view();
        let row = &mut report.rows[2];
        row.last = "-".into();
        row.min = None;
        row.avg = None;
        row.max = None;
        row.mdev = None;
        row.p50 = None;
        row.p95 = None;
        row.p99 = None;
        row.bad = true;
        row.state = "unavailable".into();
        row.error = Some("connection refused".into());
        for (width, height) in [(60, 33), (80, 24), (120, 24)] {
            let buffer = screen(&report, &mut State { selected: 2 }, width, height);
            let display = lines(&buffer);
            assert!(display[6].contains("TCP ERR"));
            assert_eq!(buffer[(2, 6)].fg, Color::Red);
            assert!(display
                .iter()
                .any(|line| line.contains("ERROR unavailable")));
            assert!(display
                .iter()
                .any(|line| line.contains("Last error: connection refused")));
            let panel = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap()[2];
            let details = panel_contents(&buffer, panel);
            for label in ["Min", "Max", "Mdev", "P50", "P95", "P99"] {
                assert_eq!(field_value(&details, label), "-");
            }
            assert!(!details.contains("0.000"));
        }
    }

    #[test]
    fn recovered_row_keeps_last_error_without_current_error_styling() {
        let mut report = view();
        report.rows[2].error = Some("connection refused".into());
        for (width, height) in [(60, 33), (80, 24), (120, 24)] {
            let buffer = screen(&report, &mut State { selected: 2 }, width, height);
            let display = lines(&buffer);
            assert!(display[6].starts_with("> TCP"));
            assert!(!display[6].contains("ERR"));
            assert!(buffer[(2, 6)].modifier.contains(Modifier::BOLD));
            assert!(display.iter().any(|line| line.contains(" ready ")));
            assert!(!display.iter().any(|line| line.contains("ERROR")));
            let panel = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap()[2];
            assert!((panel.x..panel.right()).all(|x| buffer[(x, panel.y)].fg != Color::Red));
            let y = display
                .iter()
                .position(|line| line.contains("Last error: connection refused"))
                .unwrap();
            let x = display[y].find("Last error:").unwrap();
            // The frame border is Unicode; count terminal cells, not UTF-8 bytes.
            let x = Line::raw(&display[y][..x]).width();
            assert_eq!(buffer[(x as u16, y as u16)].fg, Color::DarkGray);
        }
    }

    #[test]
    fn large_counters_and_untrusted_text_stay_inside_their_areas() {
        let mut report = view();
        report.host = "long-host\x1b[2J\n\r\t\u{4e2d}".repeat(100);
        report.ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        report.paused = true;
        let row = &mut report.rows[0];
        row.sent = u64::MAX;
        row.received = u64::MAX;
        row.pending = usize::MAX;
        row.timeout = u64::MAX;
        row.failed = u64::MAX;
        row.reordered = u64::MAX;
        row.duplicate = u64::MAX;
        row.late = u64::MAX;
        row.invalid = u64::MAX;
        row.limited = u64::MAX;
        row.skipped = u64::MAX;
        row.connect_failed = u64::MAX;
        row.state = "failed\x1b[0m\r\n".repeat(30);
        row.error = Some("permission denied\x1b[2J\n".repeat(100));
        for (width, height) in [(60, 33), (80, 24), (120, 30)] {
            let buffer = screen(&report, &mut State::default(), width, height);
            let display = lines(&buffer);
            assert!(display[0].ends_with("PAUSED"));
            assert!(display.iter().all(|line| !line.contains('\x1b')
                && !line.contains('\r')
                && !line.contains('\n')));
            let sent = display[4].split_whitespace().nth(2).unwrap();
            assert!(sent.starts_with(|c: char| c.is_ascii_digit()));
            assert!(sent.ends_with(['k', 'M', 'G', 'T', 'P', 'E']));
            assert!(display.iter().any(|line| line.contains("ConnFail:")));
            let panels = detail_layout(Rect::new(0, 7, width, height - 8), &report).unwrap();
            for panel in panels {
                for y in panel.y + 1..panel.bottom() - 1 {
                    assert_eq!(buffer[(panel.x, y)].symbol(), "\u{2502}");
                    assert_eq!(buffer[(panel.right() - 1, y)].symbol(), "\u{2502}");
                }
            }
            assert!(display[usize::from(height - 1)].contains("q quit"));
            assert_eq!(display.join("\n").matches("P99:").count(), 3);
        }
    }

    #[test]
    fn resize_empty_rows_and_selection_are_safe() {
        let mut report = view();
        let mut state = State {
            selected: usize::MAX,
        };
        for (width, height) in [(0, 0), (1, 1), (59, 16), (80, 15), (60, 16), (120, 40)] {
            let display = lines(&screen(&report, &mut state, width, height));
            assert_eq!(state.selected, 2);
            if width >= 30 && height <= 16 {
                assert!(display[0].contains("Terminal too small"));
            }
        }
        report.rows.clear();
        let display = lines(&screen(&report, &mut state, 80, 24));
        assert_eq!(state.selected, 0);
        assert!(display.iter().any(|line| line.contains("No protocol rows")));
        report.draining = true;
        report.paused = true;
        assert!(lines(&screen(&report, &mut state, 80, 24))[0].contains("DRAINING"));
    }

    #[test]
    fn invalid_numbers_are_not_presented_as_successful_samples() {
        assert_eq!(number(None, 3, 10), "-");
        assert_eq!(number(Some(f64::NAN), 3, 10), "-");
        assert_eq!(number(Some(f64::INFINITY), 3, 10), "-");
        assert_eq!(number(Some(-1.0), 3, 10), "-");
        assert_eq!(number(Some(0.0), 3, 10), "0.000");
    }
}
