use crate::{
    collect::Metrics,
    model::{Frame as Data, Process, Row as IoRow},
};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
    Frame,
};
use serde_json::{json, Value};
use std::io::{self, Write};

#[derive(Default)]
pub struct App {
    pub events: bool,
    pub focus: Option<(u32, u64)>,
    pub selected: usize,
    pub sort: u8,
    pub help: bool,
    pub no_color: bool,
    pub table: TableState,
}

pub fn bytes(n: f64) -> String {
    for (scale, label) in [(1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "K")] {
        if n >= scale {
            return format!("{:.1}{label}", n / scale);
        }
    }
    format!("{n:.0}")
}
fn number(n: Option<f64>) -> String {
    n.map(|n| format!("{n:.3}")).unwrap_or_else(|| "-".into())
}
fn latency_number(enabled: bool, n: Option<f64>) -> String {
    number(n.filter(|_| enabled))
}
fn mode(data: &Data) -> &'static str {
    if data.latency {
        "latency"
    } else {
        "light"
    }
}

fn rate_bytes(row: &IoRow, value: u64, seconds: f64) -> String {
    if row.total.id.family == 44 {
        "-".into()
    } else {
        bytes(value as f64 / seconds)
    }
}

fn object_label(row: &IoRow) -> String {
    if matches!(row.state, "closed" | "reused" | "unconfirmed") {
        format!("[{}] {}", row.state, row.object)
    } else {
        row.object.clone()
    }
}

impl App {
    pub fn processes<'a>(&self, data: &'a Data) -> Vec<&'a Process> {
        let mut rows: Vec<_> = data.processes.iter().collect();
        rows.sort_by(|a, b| {
            let score = |p: &Process| match self.sort {
                1 => p.pending as f64,
                2 => (p.rd.ops + p.wr.ops) as f64,
                _ => (p.rd.bytes + p.wr.bytes) as f64,
            };
            score(b)
                .total_cmp(&score(a))
                .then_with(|| (a.pid, a.start).cmp(&(b.pid, b.start)))
        });
        rows
    }
    pub fn rows<'a>(&self, data: &'a Data) -> Vec<&'a IoRow> {
        let mut rows: Vec<_> = data
            .rows
            .iter()
            .filter(|r| {
                self.focus
                    .is_none_or(|p| p == (r.total.id.key.pid, r.total.id.key.start))
            })
            .collect();
        rows.sort_by(|a, b| {
            let score = |r: &IoRow| match self.sort {
                1 => r.pending as f64,
                2 => r.ops() as f64,
                _ => (r.rd.bytes + r.wr.bytes) as f64,
            };
            score(b).total_cmp(&score(a)).then_with(|| {
                (a.total.id.key.fd, a.total.id.key).cmp(&(b.total.id.key.fd, b.total.id.key))
            })
        });
        rows
    }
    pub fn enter(&mut self, data: &Data) {
        if self.focus.is_none() {
            if let Some(p) = self.processes(data).get(self.selected) {
                self.focus = Some((p.pid, p.start));
                self.selected = 0;
                self.table = TableState::default();
            }
        }
    }
    pub fn back(&mut self) {
        self.focus = None;
        self.selected = 0;
        self.table = TableState::default();
    }
    fn color(&self, c: Color) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(c)
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut App, data: &Data) {
    if f.area().width < 80 || f.area().height < 18 {
        f.render_widget(
            Paragraph::new("fdtop: terminal needs at least 80 x 18"),
            f.area(),
        );
        return;
    }
    let parts = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(if app.focus.is_some() { 8 } else { 7 }),
        Constraint::Length(1),
    ])
    .split(f.area());
    let total_read: u64 = data.rows.iter().map(|r| r.rd.bytes).sum();
    let total_write: u64 = data.rows.iter().map(|r| r.wr.bytes).sum();
    let mut header=format!("fdtop | {} | {:.3}s | {} tracked FD objects\nRead {}/s   Write {}/s   gaps cap/read/batch: {}/{}/{}   compat: {}",
        mode(data),data.seconds,data.tracked,bytes(total_read as f64/data.seconds),bytes(total_write as f64/data.seconds),data.gaps[0],data.gaps[1],data.gaps[2],data.gaps[3]);
    if let Some(error) = &data.inventory_error {
        header = format!("fdtop | {} | inventory incomplete\n{error}", mode(data));
    }
    f.render_widget(
        Paragraph::new(header)
            .style(app.color(Color::Cyan))
            .block(Block::default().borders(Borders::BOTTOM)),
        parts[0],
    );
    let mut details = vec![Line::from(
        "No completed or outstanding I/O in this interval.",
    )];
    let (rows, widths, labels, title) = if let Some((pid, _)) = app.focus {
        let entries = app.rows(data);
        app.selected = app.selected.min(entries.len().saturating_sub(1));
        if let Some(r) = entries.get(app.selected) {
            let id = &r.total.id;
            let aliases: Vec<_> = data
                .rows
                .iter()
                .filter(|other| {
                    other.total.id.key.pid == pid
                        && id.key.object != 0
                        && other.total.id.key.start == id.key.start
                        && other.total.id.key.object == id.key.object
                        && other.total.id.key.fd != id.key.fd
                })
                .map(|r| r.total.id.key.fd.to_string())
                .collect();
            details = vec![
                Line::from(format!(
                    "FD {} {} {} | {} | inode {} | {}",
                    id.key.fd,
                    r.access,
                    id.kind_name(),
                    r.state,
                    id.ino,
                    r.object
                )),
                Line::from(format!(
                    "Metadata {} | age {} ms | {}",
                    r.metadata_source,
                    r.metadata_age_ms
                        .map_or_else(|| "-".into(), |v| v.to_string()),
                    r.metadata_error.as_deref().unwrap_or("no query error")
                )),
                Line::from(format!(
                    "Read  total {} B  {} ops | avg {}  P95~ {}  P99~ {} ms",
                    bytes(r.total.rd.bytes as f64),
                    r.total.rd.ops,
                    latency_number(data.latency, r.rd.avg_ms()),
                    latency_number(data.latency, r.rd.percentile_ms(95)),
                    latency_number(data.latency, r.rd.percentile_ms(99))
                )),
                Line::from(format!(
                    "Write total {} B  {} ops | avg {}  P95~ {}  P99~ {} ms",
                    bytes(r.total.wr.bytes as f64),
                    r.total.wr.ops,
                    latency_number(data.latency, r.wr.avg_ms()),
                    latency_number(data.latency, r.wr.percentile_ms(95)),
                    latency_number(data.latency, r.wr.percentile_ms(99))
                )),
                Line::from(format!(
                    "Errors {}  EAGAIN {}  Restart {} | pending {}  oldest {} ms",
                    r.rd.errors + r.wr.errors,
                    r.rd.again + r.wr.again,
                    r.rd.restarts + r.wr.restarts,
                    r.pending,
                    latency_number(data.latency, Some(r.wait_ms))
                )),
                Line::from(format!(
                    "Capture max R/W: {}/{} ms | active aliases: {}",
                    latency_number(
                        data.latency,
                        (r.total.rd.ops > 0).then_some(r.total.rd.max_ns as f64 / 1e6)
                    ),
                    latency_number(
                        data.latency,
                        (r.total.wr.ops > 0).then_some(r.total.wr.max_ns as f64 / 1e6)
                    ),
                    if aliases.is_empty() {
                        "-".into()
                    } else {
                        aliases.join(",")
                    }
                )),
            ];
        }
        let rows = entries
            .iter()
            .map(|r| {
                let style = if r.rd.errors + r.wr.errors > 0 {
                    app.color(Color::Red)
                } else if r.pending > 0 {
                    app.color(Color::Yellow)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    r.total.id.key.fd.to_string(),
                    r.access.into(),
                    r.total.id.kind_name().into(),
                    object_label(r),
                    rate_bytes(r, r.rd.bytes, data.seconds),
                    rate_bytes(r, r.wr.bytes, data.seconds),
                    format!("{:.0}", r.rd.ops as f64 / data.seconds),
                    format!("{:.0}", r.wr.ops as f64 / data.seconds),
                    format!("{:.0}", (r.rd.errors + r.wr.errors) as f64 / data.seconds),
                    r.pending.to_string(),
                ])
                .style(style)
            })
            .collect::<Vec<_>>();
        (
            rows,
            vec![
                Constraint::Length(4),
                Constraint::Length(4),
                Constraint::Length(7),
                Constraint::Min(10),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(7),
            ],
            vec![
                "FD",
                "MODE",
                "TYPE",
                "OBJECT",
                "READ B/s",
                "WRITE B/s",
                "ROPS/s",
                "WOPS/s",
                "ERR/s",
                "PENDING",
            ],
            format!(
                " PID {pid}: {} open / {} interval objects ",
                entries.iter().filter(|r| r.state == "open").count(),
                entries.len()
            ),
        )
    } else {
        let entries = app.processes(data);
        app.selected = app.selected.min(entries.len().saturating_sub(1));
        if let Some(p) = entries.get(app.selected) {
            details = vec![
                Line::from(format!(
                    "{} [{}]  {} active FD objects",
                    p.comm, p.pid, p.fds
                )),
                Line::from(format!(
                    "Read  avg {}  P95~ {}  P99~ {} ms",
                    latency_number(data.latency, p.rd.avg_ms()),
                    latency_number(data.latency, p.rd.percentile_ms(95)),
                    latency_number(data.latency, p.rd.percentile_ms(99))
                )),
                Line::from(format!(
                    "Write avg {}  P95~ {}  P99~ {} ms",
                    latency_number(data.latency, p.wr.avg_ms()),
                    latency_number(data.latency, p.wr.percentile_ms(95)),
                    latency_number(data.latency, p.wr.percentile_ms(99))
                )),
                Line::from(format!(
                    "Errors {}  EAGAIN {}  Restart {}",
                    p.rd.errors + p.wr.errors,
                    p.rd.again + p.wr.again,
                    p.rd.restarts + p.wr.restarts
                )),
                Line::from(format!(
                    "Pending endpoints {}  oldest {} ms",
                    p.pending,
                    latency_number(data.latency, Some(p.wait_ms))
                )),
            ];
        }
        let rows = entries
            .iter()
            .map(|p| {
                Row::new(vec![
                    p.pid.to_string(),
                    p.comm.clone(),
                    p.fds.to_string(),
                    bytes(p.rd.bytes as f64 / data.seconds),
                    bytes(p.wr.bytes as f64 / data.seconds),
                    format!("{:.0}", (p.rd.ops + p.wr.ops) as f64 / data.seconds),
                    format!("{:.0}", (p.rd.errors + p.wr.errors) as f64 / data.seconds),
                    p.pending.to_string(),
                ])
                .style(if p.rd.errors + p.wr.errors > 0 {
                    app.color(Color::Red)
                } else if p.pending > 0 {
                    app.color(Color::Yellow)
                } else {
                    Style::default()
                })
            })
            .collect::<Vec<_>>();
        (
            rows,
            vec![
                Constraint::Length(7),
                Constraint::Min(10),
                Constraint::Length(4),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Length(6),
                Constraint::Length(7),
            ],
            vec![
                "PID",
                "COMM",
                "FDs",
                "READ B/s",
                "WRITE B/s",
                "OPS/s",
                "ERR/s",
                "PENDING",
            ],
            " Processes ".into(),
        )
    };
    let heading = Row::new(labels.into_iter().map(Cell::from))
        .style(app.color(Color::Cyan).add_modifier(Modifier::BOLD));
    let table = Table::new(rows, widths)
        .header(heading)
        .column_spacing(1)
        .block(Block::default().title(title).borders(Borders::ALL))
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD));
    app.table.select(Some(app.selected));
    f.render_stateful_widget(table, parts[1], &mut app.table);
    f.render_widget(
        Paragraph::new(details).block(Block::default().borders(Borders::ALL).title(
            if data.latency {
                " Detail | syscall elapsed time "
            } else {
                " Detail | latency off "
            },
        )),
        parts[2],
    );
    let sort = ["bytes", "pending", "ops"][app.sort as usize];
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Enter", app.color(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" FDs  e events  Esc back  j/k move  s sort  h help  q quit  "),
            Span::raw(format!("sort:{sort}")),
        ])),
        parts[3],
    );
    if app.help {
        let area = Rect {
            x: f.area().x + 4,
            y: f.area().y + 2,
            width: f.area().width - 8,
            height: 14.min(f.area().height - 4),
        };
        f.render_widget(Clear, area);
        f.render_widget(Paragraph::new("Enter: full process FD inventory    Esc: back\nj/k or arrows: select    s: bytes / pending / ops\nh or ?: help            q or Ctrl+C: quit\nMODE: r/w/rw/path is access, not current activity.\nROPS/s, WOPS/s: completed attempts, including EAGAIN/errors.\nB/s: syscall payload; XSK '-' excludes mmap ring traffic.\nClosed/reused objects retain this interval's I/O.\nLatency includes blocking/scheduling; requires -l.\nP95~/P99~: interval log2 histogram upper bounds.\nTwo-FD transfers count bytes at both endpoints.\nGaps or inventory errors mean incomplete coverage.")
            .block(Block::default().title(" Help ").borders(Borders::ALL)),area);
    }
}

fn metrics_json(m: &Metrics, latency: bool) -> Value {
    json!({"bytes":m.bytes,"ops":m.ops,"errors":m.errors,"again":m.again,"restarts":m.restarts,
        "elapsed_ns":latency.then_some(m.ns),"avg_ms":m.avg_ms().filter(|_|latency),
        "p95_upper_ms":m.percentile_ms(95).filter(|_|latency),"p99_upper_ms":m.percentile_ms(99).filter(|_|latency),
        "capture_max_ms":(latency && m.ops > 0).then_some(m.max_ns as f64/1e6)})
}

fn json_frame(data: &Data) -> Value {
    let rows:Vec<_>=data.rows.iter().map(|r| {
            let id=&r.total.id;
            json!({"pid":id.key.pid,"process_start":id.key.start,"comm":crate::model::clean(&id.comm),"fd":id.key.fd,"object_id":id.key.object,
                "type":id.kind_name(),"object":r.object,"inode":id.ino,"device":id.dev,"access":r.access,"state":r.state,
                "read_ops_s":r.rd.ops as f64/data.seconds,"write_ops_s":r.wr.ops as f64/data.seconds,
                "read_bytes_s":(id.family != 44).then_some(r.rd.bytes as f64/data.seconds),
                "write_bytes_s":(id.family != 44).then_some(r.wr.bytes as f64/data.seconds),
                "byte_scope":if id.family == 44 {"syscalls_only_no_mmap"} else {"syscalls"},
                "metadata_source":r.metadata_source,"metadata_age_ms":r.metadata_age_ms,"metadata_error":r.metadata_error,
                "read":metrics_json(&r.rd, data.latency),"write":metrics_json(&r.wr, data.latency),
                "total_read":metrics_json(&r.total.rd, data.latency),"total_write":metrics_json(&r.total.wr, data.latency),"calls":r.calls,"pending":r.pending,"oldest_ms":data.latency.then_some(r.wait_ms)})
        }).collect();
    json!({"mode":mode(data),"latency":data.latency,"interval_s":data.seconds,"tracked":data.tracked,"gaps":data.gaps,"inventory_error":data.inventory_error,"rows":rows})
}

pub fn print(data: &Data, json_output: bool, fd_view: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    if json_output {
        writeln!(out, "{}", json_frame(data))?;
    } else {
        writeln!(
            out,
            "\nfdtop | {} | {:.3}s | {} tracked | gaps {:?}",
            mode(data),
            data.seconds,
            data.tracked,
            data.gaps
        )?;
        let app = App::default();
        if let Some(error) = &data.inventory_error {
            writeln!(out, "Inventory incomplete: {error}")?;
        }
        if fd_view {
            writeln!(
                out,
                "{:>7} {:>5} {:<4} {:<8} {:<11} {:>10} {:>10} {:>8} {:>8} {:>7} {:>7} {:>7} {:>10}  OBJECT",
                "PID", "FD", "MODE", "TYPE", "STATE", "READ B/s", "WRITE B/s", "ROPS/s", "WOPS/s", "AGAIN/s", "ERR/s", "PENDING", "WAIT ms"
            )?;
            for r in app.rows(data) {
                writeln!(
                    out,
                    "{:>7} {:>5} {:<4} {:<8} {:<11} {:>10} {:>10} {:>8.0} {:>8.0} {:>7.0} {:>7.0} {:>7} {:>10}  {} [{}]",
                    r.total.id.key.pid,
                    r.total.id.key.fd,
                    r.access,
                    r.total.id.kind_name(),
                    r.state,
                    rate_bytes(r,r.rd.bytes,data.seconds),
                    rate_bytes(r,r.wr.bytes,data.seconds),
                    r.rd.ops as f64 / data.seconds,
                    r.wr.ops as f64 / data.seconds,
                    (r.rd.again+r.wr.again) as f64/data.seconds,
                    (r.rd.errors+r.wr.errors) as f64/data.seconds,
                    r.pending,
                    latency_number(data.latency, Some(r.wait_ms)),
                    r.object,
                    r.metadata_source
                )?;
            }
        } else {
            writeln!(
                out,
                "{:>7} {:<16} {:>5} {:>10} {:>10} {:>8} {:>7} {:>10}",
                "PID", "COMM", "FDs", "READ B/s", "WRITE B/s", "OPS/s", "PENDING", "WAIT ms"
            )?;
            for p in app.processes(data) {
                writeln!(
                    out,
                    "{:>7} {:<16} {:>5} {:>10} {:>10} {:>8.0} {:>7} {:>10}",
                    p.pid,
                    p.comm,
                    p.fds,
                    bytes(p.rd.bytes as f64 / data.seconds),
                    bytes(p.wr.bytes as f64 / data.seconds),
                    (p.rd.ops + p.wr.ops) as f64 / data.seconds,
                    p.pending,
                    latency_number(data.latency, Some(p.wait_ms))
                )?;
            }
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};
    #[test]
    fn light_mode_preserves_counters_and_marks_latency_unavailable() {
        let mut m = Metrics {
            bytes: 123,
            ops: 2,
            errors: 1,
            ns: 1000,
            max_ns: 1000,
            ..Default::default()
        };
        m.hist[0] = 2;
        let light = metrics_json(&m, false);
        assert_eq!(light["bytes"], 123);
        assert_eq!(light["ops"], 2);
        assert_eq!(light["errors"], 1);
        for name in [
            "elapsed_ns",
            "avg_ms",
            "p95_upper_ms",
            "p99_upper_ms",
            "capture_max_ms",
        ] {
            assert!(light[name].is_null());
            assert!(metrics_json(&m, true)[name].is_number());
        }
    }
    #[test]
    fn layouts_render_at_small_standard_and_wide_sizes() {
        let data = Data {
            inventory_error: None,
            latency: false,
            seconds: 1.0,
            rows: vec![],
            processes: vec![],
            gaps: [0; 5],
            tracked: 0,
        };
        for (w, h) in [(50, 12), (80, 24), (120, 30)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            let mut app = App::default();
            terminal.draw(|f| draw(f, &mut app, &data)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(text.contains("fdtop"));
            if w >= 80 {
                assert!(text.contains("READ B/s"));
                assert!(text.contains("q quit"));
            }
        }
    }

    #[test]
    fn populated_views_keep_pending_and_errors_visible_in_both_modes() {
        use crate::collect::{Pending, Record, Snapshot};
        use crate::model::{frame, Filter};
        use std::collections::HashMap;
        let mut record = Record::default();
        record.id.key.pid = 42;
        record.id.key.start = 1;
        record.id.key.fd = 7;
        record.id.comm[..6].copy_from_slice(b"writer");
        record.wr.bytes = 4096;
        record.wr.ops = 1;
        record.wr.errors = 1;
        for latency in [false, true] {
            let snapshot = Snapshot {
                latency,
                at: 2_000_000_000,
                records: HashMap::from([(record.id.key, record)]),
                pending: vec![Pending {
                    first: record.id.key,
                    since: if latency { 1_000_000_000 } else { 0 },
                    ..Default::default()
                }],
                ..Default::default()
            };
            let data = frame(&Snapshot::default(), &snapshot, &Filter::default());
            let json = json_frame(&data);
            assert_eq!(json["latency"], latency);
            assert_eq!(json["rows"][0]["pending"], 1);
            assert_eq!(json["rows"][0]["oldest_ms"].is_null(), !latency);
            for width in [80, 120] {
                for focus in [None, Some((42, 1))] {
                    let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
                    let mut app = App {
                        focus,
                        no_color: true,
                        ..Default::default()
                    };
                    terminal.draw(|f| draw(f, &mut app, &data)).unwrap();
                    let buffer = terminal.backend().buffer();
                    let text: String = buffer.content.iter().map(|c| c.symbol()).collect();
                    for label in ["READ B/s", "WRITE B/s", "OPS/s", "ERR/s", "PENDING"] {
                        assert!(text.contains(label), "{width} {focus:?}: missing {label}");
                    }
                    if focus.is_some() {
                        for label in ["MODE", "ROPS/s", "WOPS/s"] {
                            assert!(text.contains(label), "{width}: missing {label}");
                        }
                    }
                    assert!(!text.contains("WAIT ms"));
                    assert!(buffer.content.iter().all(|c| c.fg == Color::Reset));
                    if !latency {
                        assert!(text.contains("latency off"));
                    }
                }
            }
        }
    }
}
