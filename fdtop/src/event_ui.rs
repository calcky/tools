use crate::{events::Collector, model::clean, ui::App};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App, collector: &Collector) {
    if f.area().width < 80 || f.area().height < 18 {
        f.render_widget(
            Paragraph::new("fdtop: terminal needs at least 80 x 18"),
            f.area(),
        );
        return;
    }
    let areas = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(4),
        Constraint::Length(1),
    ])
    .split(f.area());
    let store = collector.store.borrow();
    let color = |c| {
        if app.no_color {
            Style::default()
        } else {
            Style::default().fg(c)
        }
    };
    let bad = collector.losses.iter().any(|v| *v != 0)
        || store.decode_errors != 0
        || store.output_dropped != 0;
    let scope = collector
        .pid
        .map_or_else(|| "all processes".into(), |pid| format!("PID {pid}"));
    let header=format!("fdtop | FD events | {scope} | {} retained / {} received\nLost ring/read/map/scan {:?} | evicted {} | output dropped {}",
        store.history.len(),store.received,collector.losses,store.evicted,store.output_dropped);
    f.render_widget(
        Paragraph::new(header)
            .style(color(if bad { Color::Red } else { Color::Cyan }))
            .block(Block::default().borders(Borders::BOTTOM)),
        areas[0],
    );
    app.selected = app.selected.min(store.history.len().saturating_sub(1));
    let rows = store.history.iter().rev().map(|item| {
        let e = item.event;
        Row::new(vec![
            collector.time(e.ns),
            e.id.key.pid.to_string(),
            e.id.key.fd.to_string(),
            e.action().into(),
            e.id.kind_name().into(),
            item.label.clone(),
        ])
        .style(color(match e.kind {
            1 | 2 => Color::Green,
            3 => Color::Yellow,
            5 => Color::Cyan,
            _ => Color::Reset,
        }))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(12),
        ],
    )
    .header(
        Row::new(
            ["TIME", "PID", "FD", "EVENT", "TYPE", "OBJECT"]
                .into_iter()
                .map(Cell::from),
        )
        .style(color(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Latest first | e I/O view "),
    )
    .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD));
    app.table.select(Some(app.selected));
    f.render_stateful_widget(table, areas[1], &mut app.table);
    let detail = if app.help {
        vec![
            Line::from("e switch view | j/k select | q/Ctrl+C quit | h help"),
            Line::from("EXISTING is a baseline observation; OPEN/DUP/CLOSE are FD events."),
        ]
    } else if let Some(item) = store.history.iter().rev().nth(app.selected) {
        let e = item.event;
        vec![
            Line::from(format!(
                "{} PID {} TID {} | {} {} | event object #{} | inode {}",
                clean(&e.id.comm),
                e.id.key.pid,
                e.tid,
                e.action(),
                e.reason(),
                e.id.key.object,
                e.id.ino
            )),
            Line::from(format!(
                "{}{}",
                item.label,
                if e.source >= 0 {
                    format!(" | source FD {}", e.source)
                } else {
                    String::new()
                }
            )),
        ]
    } else {
        vec![Line::from(
            "Waiting for FD lifecycle events. Capture starts when enabled.",
        )]
    };
    f.render_widget(
        Paragraph::new(detail).block(Block::default().borders(Borders::ALL).title(" Detail ")),
        areas[2],
    );
    f.render_widget(
        Paragraph::new("e I/O  j/k move  h help  q quit | close != final object release"),
        areas[3],
    );
}
