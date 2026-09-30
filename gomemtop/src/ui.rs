use crate::{App, StackRow};
use crossterm::{
    cursor::{Hide, Show},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table, TableState},
    Frame, Terminal,
};
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Screen {
    pub terminal: Terminal<CrosstermBackend<io::Stdout>>,
}
fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
}
impl Screen {
    pub fn open() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            restore();
            return Err(error);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(t) => t,
            Err(error) => {
                restore();
                return Err(error);
            }
        };
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
        Ok(Self { terminal })
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        restore();
    }
}

fn bytes(value: i64) -> String {
    let sign = if value < 0 { "-" } else { "" };
    let n = value.unsigned_abs() as f64;
    for (scale, unit) in [
        (1024.0_f64.powi(3), "GiB"),
        (1024.0_f64.powi(2), "MiB"),
        (1024.0, "KiB"),
    ] {
        if n >= scale {
            return format!("{sign}{:.1}{unit}", n / scale);
        }
    }
    format!("{sign}{}B", value.unsigned_abs())
}
fn signed_bytes(value: i64) -> String {
    format!("{}{}", if value > 0 { "+" } else { "" }, bytes(value))
}
fn time(value: Option<SystemTime>) -> String {
    let Some(value) = value else {
        return "waiting".into();
    };
    let seconds = value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}
fn line(text: impl Into<String>) -> Line<'static> {
    Line::raw(text.into())
}

pub fn draw(frame: &mut Frame, app: &App, rows: &[StackRow]) {
    let area = frame.area();
    if area.width < 60 || area.height < 16 {
        frame.render_widget(Paragraph::new("Resize terminal to at least 60x16"), area);
        return;
    }
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(6),
            Constraint::Length(7),
            Constraint::Length(2),
        ])
        .split(area);
    let total = app.current.as_ref().map(|s| s.total).unwrap_or_default();
    let base = app.baseline.as_ref().map(|s| s.total).unwrap_or_default();
    let prev = app.previous.as_ref().map(|s| s.total).unwrap_or_default();
    let mode = if app.gc { "GC on" } else { "GC off" };
    let title = format!(
        " gomemtop | {} | {} | {} ",
        app.metric.label(),
        mode,
        if app.paused {
            "PAUSED"
        } else if app.pending {
            "FETCHING"
        } else {
            "LIVE"
        }
    );
    let summary = vec![
        line(format!("Target  {}", app.url)),
        Line::from(vec![
            Span::raw(format!(
                "Sample  {}  |  OK {}  ERR {}  |  every {:.1}s  ",
                time(app.last_success),
                app.successes,
                app.failures,
                app.interval.as_secs_f64()
            )),
            Span::styled(
                "sampled heap estimate, not RSS",
                Style::default().fg(Color::Yellow),
            ),
        ]),
        line(format!(
            "Total   {}  {} objects  |  vs last {}  |  vs baseline {}",
            bytes(app.metric.bytes(total)),
            app.metric.objects(total),
            signed_bytes(
                app.metric
                    .bytes(total)
                    .saturating_sub(app.metric.bytes(prev))
            ),
            signed_bytes(
                app.metric
                    .bytes(total)
                    .saturating_sub(app.metric.bytes(base))
            )
        )),
    ];
    frame.render_widget(
        Paragraph::new(summary).block(Block::default().title(title).borders(Borders::ALL)),
        layout[0],
    );
    let floor = app.history.iter().min().copied().unwrap_or(0);
    let trend: Vec<u64> = app
        .history
        .iter()
        .map(|n| n.saturating_sub(floor) as u64)
        .collect();
    frame.render_widget(
        Sparkline::default()
            .data(&trend)
            .style(Style::default().fg(Color::Cyan)),
        Rect {
            x: layout[0].x + 2,
            y: layout[0].y + 4,
            width: layout[0].width.saturating_sub(4),
            height: 1,
        },
    );
    let wide = area.width >= 95;
    let header = if wide {
        Row::new(["STACK (LEAF)", "CURRENT", "OBJECTS", "VS LAST", "VS BASE"])
    } else {
        Row::new(["STACK (LEAF)", "CURRENT", "VS BASE"])
    };
    let table_rows = rows.iter().map(|row| {
        let leaf = row.stack.lines().next().unwrap_or("[unknown]");
        let function = leaf.split_once(" (").map_or(leaf, |(name, _)| name);
        let values = if wide {
            vec![
                Cell::from(function.to_owned()),
                Cell::from(bytes(app.metric.bytes(row.current))),
                Cell::from(app.metric.objects(row.current).to_string()),
                Cell::from(signed_bytes(
                    app.metric
                        .bytes(row.current)
                        .saturating_sub(app.metric.bytes(row.previous)),
                )),
                Cell::from(signed_bytes(
                    app.metric
                        .bytes(row.current)
                        .saturating_sub(app.metric.bytes(row.baseline)),
                )),
            ]
        } else {
            vec![
                Cell::from(function.to_owned()),
                Cell::from(bytes(app.metric.bytes(row.current))),
                Cell::from(signed_bytes(
                    app.metric
                        .bytes(row.current)
                        .saturating_sub(app.metric.bytes(row.baseline)),
                )),
            ]
        };
        Row::new(values)
    });
    let widths = if wide {
        vec![
            Constraint::Min(25),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(12),
        ]
    } else {
        vec![
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(12),
        ]
    };
    let table = Table::new(table_rows, widths)
        .header(
            header.style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .title(format!(" Growth by stack | {} stacks ", rows.len()))
                .borders(Borders::ALL),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = TableState::default().with_selected((!rows.is_empty()).then_some(app.selected));
    frame.render_stateful_widget(table, layout[1], &mut state);
    detail(frame, layout[2], app, rows);
    let error = app.error.as_deref().unwrap_or("No errors");
    let help = if area.width < 95 {
        "j/k move  PgUp/Dn frames  m metric  b base  g GC  Space pause  r retry  q quit"
    } else {
        "j/k select  PgUp/PgDn stack  m metric  b baseline  g GC  Space pause  r sample  q quit"
    };
    frame.render_widget(
        Paragraph::new(vec![
            line(help),
            Line::from(Span::styled(
                error.to_owned(),
                Style::default().fg(if app.error.is_some() {
                    Color::Red
                } else {
                    Color::Gray
                }),
            )),
        ]),
        layout[3],
    );
}

fn detail(frame: &mut Frame, area: Rect, app: &App, rows: &[StackRow]) {
    let Some(row) = rows.get(app.selected) else {
        frame.render_widget(
            Paragraph::new("Waiting for the first heap profile").block(
                Block::default()
                    .title(" Stack detail ")
                    .borders(Borders::ALL),
            ),
            area,
        );
        return;
    };
    let summary = format!(
        "Current {} / {} objects  |  last {}  |  baseline {}",
        bytes(app.metric.bytes(row.current)),
        app.metric.objects(row.current),
        signed_bytes(
            app.metric
                .bytes(row.current)
                .saturating_sub(app.metric.bytes(row.previous))
        ),
        signed_bytes(
            app.metric
                .bytes(row.current)
                .saturating_sub(app.metric.bytes(row.baseline))
        )
    );
    let lines: Vec<_> = std::iter::once(line(summary))
        .chain(
            row.stack
                .lines()
                .enumerate()
                .map(|(i, frame)| line(format!("{:>2} {frame}", i + 1))),
        )
        .collect();
    frame.render_widget(
        Paragraph::new(lines).scroll((app.detail_scroll, 0)).block(
            Block::default()
                .title(" Stack detail (leaf first) ")
                .borders(Borders::ALL),
        ),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    #[test]
    fn render_at_common_sizes() {
        let app = App::new(
            "http://localhost:6060/debug/pprof/heap".into(),
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(10),
        );
        for (w, h) in [(80, 24), (120, 32), (55, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|frame| draw(frame, &app, &[])).unwrap();
        }
    }
    #[test]
    fn units_and_signs() {
        assert_eq!(bytes(2048), "2.0KiB");
        assert_eq!(signed_bytes(2048), "+2.0KiB");
    }
}
