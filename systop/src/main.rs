mod collect;
mod model;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use collect::Probe;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::{ProcessFilter, ThreadFilter, View};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::{
    io::{self, IsTerminal, Write},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Sort {
    Calls,
    Time,
}

#[derive(Parser)]
#[command(version, about = "Live eBPF syscall and process call-rate top")]
struct Args {
    #[arg(short = 'd', default_value_t = 1.0, value_parser = delay, help = "Refresh interval in seconds (0.1..60)")]
    delay: f64,
    #[arg(short = 'c', value_parser = clap::value_parser!(u32).range(1..), help = "Print N text snapshots")]
    count: Option<u32>,
    #[arg(short = 'p', value_parser = clap::value_parser!(u32).range(1..), help = "Show syscall and thread rankings for this PID")]
    pid: Option<u32>,
    #[arg(short = 'n', default_value_t = 12, value_parser = clap::value_parser!(u32).range(1..=100), help = "Rows per table in text mode")]
    rows: u32,
    #[arg(
        short = 'L',
        help = "Measure enter-to-exit wall-clock latency (higher overhead)"
    )]
    latency: bool,
    #[arg(
        short = 'o',
        value_enum,
        requires = "latency",
        help = "Sort by calls or total wall time (default with -L: time)"
    )]
    sort: Option<Sort>,
}

fn delay(value: &str) -> std::result::Result<f64, String> {
    let value = value.parse::<f64>().map_err(|_| "invalid interval")?;
    if !value.is_finite() || !(0.1..=60.0).contains(&value) {
        return Err("interval must be 0.1..60 seconds".into());
    }
    Ok(value)
}

fn rate(rate: f64) -> String {
    if rate >= 1000.0 {
        format!("{rate:.0}")
    } else {
        format!("{rate:.1}")
    }
}

fn millis(value: Option<f64>) -> String {
    value.map_or_else(|| "-".into(), |value| format!("{value:.3}"))
}

fn print_snapshot(out: &mut impl Write, view: &View, rows: usize) -> Result<()> {
    let scope = view
        .thread_filter
        .map(|filter| format!("TID {}", filter.tid))
        .or_else(|| view.pid_filter.map(|filter| format!("PID {}", filter.pid)))
        .unwrap_or_else(|| "host".into());
    writeln!(
        out,
        "systop | {scope} | interval {:.3}s | host {} calls/s | process keys {}/{}{}{}",
        view.seconds,
        rate(view.total_rate),
        view.process_keys,
        collect::PROC_CAPACITY,
        if view.thread_target.is_some() {
            format!(
                " | thread keys {}/{}",
                view.thread_keys,
                collect::PROC_CAPACITY
            )
        } else {
            String::new()
        },
        if view.latency_enabled {
            if view.sort_time {
                " | sort time"
            } else {
                " | sort calls"
            }
        } else {
            ""
        }
    )?;
    if view.invalid_rate > 0.0
        || view.attribution_fail_rate > 0.0
        || view.latency_fail_rate > 0.0
        || view.thread_fail_rate > 0.0
    {
        writeln!(
            out,
            "out-of-range {:.1}/s | process-map errors {:.1}/s | thread-map errors {:.1}/s | latency-map errors {:.1}/s",
            view.invalid_rate, view.attribution_fail_rate, view.thread_fail_rate, view.latency_fail_rate
        )?;
    }
    if view.latency_enabled {
        writeln!(
            out,
            "paired {:.1}/s | unmatched exits {:.1}/s | start failures {:.1}/s | process misses {:.1}/s | abandoned {:.1}/s | inflight {}/{}",
            view.completed_rate,
            view.unmatched_rate,
            view.start_fail_rate,
            view.process_miss_rate,
            view.abandoned_rate,
            view.inflight,
            collect::PROC_CAPACITY,
        )?;
        writeln!(out, "latency: completed enter-to-exit wall time; TIME ms/s sums across threads; P95 approximate")?;
    }
    writeln!(
        out,
        "SYSCALLS ({scope}, {} calls/s)",
        rate(view.selected_rate)
    )?;
    if view.latency_enabled {
        writeln!(
            out,
            "{:>5}  {:<20} {:>12} {:>11} {:>10} {:>10}",
            "ID", "NAME", "CALLS/s", "TIME ms/s", "AVG ms", "P95~ms"
        )?;
    } else {
        writeln!(
            out,
            "{:>5}  {:<20} {:>12} {:>7}",
            "ID", "NAME", "CALLS/s", "SHARE"
        )?;
    }
    for row in view.syscalls.iter().take(rows) {
        if view.latency_enabled {
            write!(
                out,
                "{:>5}  {:<20} {:>12} {:>11} {:>10} {:>10}",
                row.id,
                row.name,
                rate(row.rate),
                rate(row.time_ms_s),
                millis(row.avg_ms),
                millis(row.p95_ms)
            )?;
        } else {
            write!(
                out,
                "{:>5}  {:<20} {:>12} {:>6.1}%",
                row.id,
                row.name,
                rate(row.rate),
                row.share * 100.0
            )?;
        }
        writeln!(out)?;
    }
    let process_scope = view
        .syscall_filter
        .map(model::syscall_name)
        .unwrap_or_else(|| "all syscalls".into());
    let thread_mode = view.thread_target.is_some();
    writeln!(
        out,
        "{} ({process_scope})",
        if thread_mode { "THREADS" } else { "PROCESSES" }
    )?;
    if view.latency_enabled {
        writeln!(
            out,
            "{:>7}  {:<20} {:>12} {:>11} {:>10}",
            if thread_mode { "TID" } else { "PID" },
            "COMM",
            "CALLS/s",
            "TIME ms/s",
            "AVG ms"
        )?;
    } else {
        writeln!(
            out,
            "{:>7}  {:<20} {:>12} {:>7}",
            if thread_mode { "TID" } else { "PID" },
            "COMM",
            "CALLS/s",
            "SHARE"
        )?;
    }
    let entries = if thread_mode {
        &view.threads
    } else {
        &view.processes
    };
    for row in entries.iter().take(rows) {
        if view.latency_enabled {
            write!(
                out,
                "{:>7}  {:<20} {:>12} {:>11} {:>10}",
                row.pid,
                row.comm,
                rate(row.rate),
                rate(row.time_ms_s),
                millis(row.avg_ms)
            )?;
        } else {
            write!(
                out,
                "{:>7}  {:<20} {:>12} {:>6.1}%",
                row.pid,
                row.comm,
                rate(row.rate),
                row.share * 100.0
            )?;
        }
        writeln!(out)?;
    }
    writeln!(out)?;
    Ok(())
}

struct TerminalGuard;
impl TerminalGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            let _ = terminal::disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self)
    }
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

#[derive(Default)]
struct Ui {
    pane: usize,
    syscall_index: usize,
    process_index: usize,
    selected_syscall: Option<u32>,
    selected_process: Option<(u32, u64)>,
    pid_filter: Option<ProcessFilter>,
    thread_filter: Option<ThreadFilter>,
    syscall_filter: Option<u32>,
    sort_time: bool,
}

impl Ui {
    fn sync(&mut self, view: &View) {
        let entries = if view.thread_target.is_some() {
            &view.threads
        } else {
            &view.processes
        };
        if let Some(id) = self.selected_syscall {
            if let Some(index) = view.syscalls.iter().position(|row| row.id == id) {
                self.syscall_index = index;
            }
        }
        if let Some(key) = self.selected_process {
            if let Some(index) = entries.iter().position(|row| (row.pid, row.start) == key) {
                self.process_index = index;
            }
        }
        self.syscall_index = self
            .syscall_index
            .min(view.syscalls.len().saturating_sub(1));
        self.process_index = self.process_index.min(entries.len().saturating_sub(1));
        self.selected_syscall = view.syscalls.get(self.syscall_index).map(|row| row.id);
        self.selected_process = entries
            .get(self.process_index)
            .map(|row| (row.pid, row.start));
    }

    fn key(&mut self, key: KeyCode, view: &View) -> bool {
        let entries = if view.thread_target.is_some() {
            &view.threads
        } else {
            &view.processes
        };
        match key {
            KeyCode::Char('q') => return true,
            KeyCode::Tab | KeyCode::BackTab => self.pane = 1 - self.pane,
            KeyCode::Down | KeyCode::Char('j') => {
                if self.pane == 0 {
                    self.syscall_index =
                        (self.syscall_index + 1).min(view.syscalls.len().saturating_sub(1));
                } else {
                    self.process_index =
                        (self.process_index + 1).min(entries.len().saturating_sub(1));
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.pane == 0 {
                    self.syscall_index = self.syscall_index.saturating_sub(1);
                } else {
                    self.process_index = self.process_index.saturating_sub(1);
                }
            }
            KeyCode::Enter => {
                if self.pane == 0 {
                    self.syscall_filter = view.syscalls.get(self.syscall_index).map(|row| row.id);
                } else if view.thread_target.is_some() {
                    self.thread_filter = entries.get(self.process_index).map(|row| ThreadFilter {
                        tid: row.pid,
                        start: row.start,
                    });
                } else {
                    self.pid_filter =
                        view.processes
                            .get(self.process_index)
                            .map(|row| ProcessFilter {
                                pid: row.pid,
                                start: Some(row.start),
                            });
                }
            }
            KeyCode::Esc => {
                if view.thread_target.is_some() {
                    self.thread_filter = None;
                } else {
                    self.pid_filter = None;
                }
                self.syscall_filter = None;
            }
            KeyCode::Char('s') if view.latency_enabled => self.sort_time = !self.sort_time,
            _ => {}
        }
        self.selected_syscall = view.syscalls.get(self.syscall_index).map(|row| row.id);
        self.selected_process = entries
            .get(self.process_index)
            .map(|row| (row.pid, row.start));
        false
    }
}

fn draw_table(frame: &mut Frame, area: Rect, view: &View, ui: &Ui, process: bool) {
    let selected = if process {
        ui.process_index
    } else {
        ui.syscall_index
    };
    let active = (ui.pane == 1) == process;
    let visible = area.height.saturating_sub(3) as usize;
    let start = selected.saturating_sub(visible.saturating_sub(1));
    let (title, rows, widths) = if process {
        let scope = view
            .syscall_filter
            .map(model::syscall_name)
            .unwrap_or_else(|| "all syscalls".into());
        let entries = if view.thread_target.is_some() {
            &view.threads
        } else {
            &view.processes
        };
        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, item)| {
                let mut cells = vec![
                    Cell::from(item.pid.to_string()),
                    Cell::from(item.comm.clone()),
                    Cell::from(rate(item.rate)),
                ];
                if view.latency_enabled {
                    cells.push(Cell::from(rate(item.time_ms_s)));
                    cells.push(Cell::from(millis(item.avg_ms)));
                } else {
                    cells.push(Cell::from(format!("{:.1}%", item.share * 100.0)));
                }
                Row::new(cells).style(if active && index == selected {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default()
                })
            })
            .collect();
        (
            format!(
                "{} / {scope}",
                view.thread_target.map_or("PROCESSES", |_| "THREADS")
            ),
            rows,
            vec![
                Constraint::Length(8),
                Constraint::Min(12),
                Constraint::Length(11),
                Constraint::Length(if view.latency_enabled { 11 } else { 7 }),
                Constraint::Length(9),
            ],
        )
    } else {
        let scope = view
            .thread_filter
            .map(|filter| format!("TID {}", filter.tid))
            .or_else(|| view.pid_filter.map(|filter| format!("PID {}", filter.pid)))
            .unwrap_or_else(|| "host".into());
        let rows: Vec<Row> = view
            .syscalls
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, item)| {
                let mut cells = vec![
                    Cell::from(item.id.to_string()),
                    Cell::from(item.name.clone()),
                    Cell::from(rate(item.rate)),
                ];
                if view.latency_enabled {
                    cells.push(Cell::from(rate(item.time_ms_s)));
                    cells.push(Cell::from(millis(item.avg_ms)));
                    cells.push(Cell::from(millis(item.p95_ms)));
                } else {
                    cells.push(Cell::from(format!("{:.1}%", item.share * 100.0)));
                }
                Row::new(cells).style(if active && index == selected {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default()
                })
            })
            .collect();
        (
            format!("SYSCALLS / {scope}"),
            rows,
            vec![
                Constraint::Length(6),
                Constraint::Min(12),
                Constraint::Length(11),
                Constraint::Length(if view.latency_enabled { 11 } else { 7 }),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
    };
    let header = if process {
        let id = if view.thread_target.is_some() {
            "TID"
        } else {
            "PID"
        };
        if view.latency_enabled {
            Row::new([id, "COMM", "CALLS/s", "TIME ms/s", "AVG ms"])
        } else {
            Row::new([id, "COMM", "CALLS/s", "SHARE"])
        }
    } else {
        if view.latency_enabled {
            Row::new(["ID", "NAME", "CALLS/s", "TIME ms/s", "AVG ms", "P95~ms"])
        } else {
            Row::new(["ID", "NAME", "CALLS/s", "SHARE"])
        }
    }
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        });
    let widths = if view.latency_enabled {
        widths
    } else {
        widths[..4].to_vec()
    };
    frame.render_widget(Table::new(rows, widths).header(header).block(block), area);
}

fn draw(frame: &mut Frame, view: &View, ui: &Ui) {
    let area = frame.area();
    if area.width < 60 || area.height < 16 {
        frame.render_widget(
            Paragraph::new("systop: resize terminal to at least 60x16"),
            area,
        );
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if view.latency_enabled { 3 } else { 2 }),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);
    let summary = if view.seconds < 0.01 {
        if view.latency_enabled {
            Text::from(vec![
                Line::raw("systop  collecting first interval..."),
                Line::raw("latency: completed enter-to-exit wall time"),
                Line::raw("s sort time/calls"),
            ])
        } else {
            Text::from("systop  collecting first interval...\ncounts at sys_enter")
        }
    } else if view.latency_enabled {
        let unhealthy = view.start_fail_rate > 0.0
            || view.unmatched_rate > 0.0
            || view.process_miss_rate > 0.0
            || view.thread_fail_rate > 0.0
            || view.latency_fail_rate > 0.0;
        Text::from(vec![
            Line::raw(format!(
                "systop  {:.2}s  host {} calls/s  sort {}{}",
                view.seconds,
                rate(view.total_rate),
                if view.sort_time {
                    "TIME ms/s"
                } else {
                    "CALLS/s"
                },
                view.thread_target
                    .map_or_else(String::new, |pid| format!("  PID {pid}"))
            )),
            Line::styled(
                format!(
                    "paired {}/s | unmatched {}/s | start-fail {}/s | proc-miss {}/s",
                    rate(view.completed_rate),
                    rate(view.unmatched_rate),
                    rate(view.start_fail_rate),
                    rate(view.process_miss_rate)
                ),
                Style::default().fg(if unhealthy {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
            ),
            Line::raw(if view.thread_target.is_some() {
                format!(
                    "thread keys {}/{} | thread-miss {}/s | inflight {} | abandoned {}/s",
                    view.thread_keys,
                    collect::PROC_CAPACITY,
                    rate(view.thread_fail_rate),
                    view.inflight,
                    rate(view.abandoned_rate)
                )
            } else {
                format!(
                    "abandoned {}/s | map-fail {}/s | inflight {}/{} | proc keys {}/{}",
                    rate(view.abandoned_rate),
                    rate(view.latency_fail_rate),
                    view.inflight,
                    collect::PROC_CAPACITY,
                    view.process_keys,
                    collect::PROC_CAPACITY
                )
            }),
        ])
    } else {
        Text::from(format!(
            "systop  interval {:.2}s  host {} calls/s  process keys {}/{}{}\nout-of-range {:.1}/s  proc-map {:.1}/s  thread-map {:.1}/s  [sys_enter]",
            view.seconds,
            rate(view.total_rate),
            view.process_keys,
            collect::PROC_CAPACITY,
            view.thread_target.map_or_else(String::new, |pid| format!("  PID {pid} thread keys {}/{}", view.thread_keys, collect::PROC_CAPACITY)),
            view.invalid_rate,
            view.attribution_fail_rate,
            view.thread_fail_rate,
        ))
    };
    frame.render_widget(
        Paragraph::new(summary).style(Style::default().fg(Color::White)),
        chunks[0],
    );
    if chunks[1].width >= if view.latency_enabled { 124 } else { 100 } {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);
        draw_table(frame, cols[0], view, ui, false);
        draw_table(frame, cols[1], view, ui, true);
    } else {
        draw_table(frame, chunks[1], view, ui, ui.pane == 1);
    }
    frame.render_widget(
        Paragraph::new(if view.latency_enabled {
            "Tab pane  j/k move  Enter filter  Esc clear  s sort  q quit"
        } else {
            "Tab pane  j/k move  Enter filter  Esc clear  q quit"
        })
        .style(Style::default().fg(Color::Gray)),
        chunks[2],
    );
}

fn run() -> Result<()> {
    let args = Args::parse();
    if let Some(pid) = args.pid {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            bail!("PID {pid} does not exist")
        }
    }
    if args.count.is_none()
        && (!io::stdout().is_terminal() || std::env::var("TERM").as_deref() == Ok("dumb"))
    {
        bail!("interactive mode requires a terminal; use -c N for text snapshots")
    }
    let sort_time = args.sort.unwrap_or(if args.latency {
        Sort::Time
    } else {
        Sort::Calls
    }) == Sort::Time;
    let probe = Probe::attach(args.latency, args.pid)?;
    let interval = Duration::from_secs_f64(args.delay);
    let mut old = probe.read()?;
    if let Some(count) = args.count {
        let mut stdout = io::BufWriter::new(io::stdout().lock());
        for _ in 0..count {
            std::thread::sleep(interval);
            let new = probe.read()?;
            let mut view = model::build(
                &old,
                &new,
                args.pid.map(|pid| ProcessFilter { pid, start: None }),
                None,
                None,
            );
            view.sort(sort_time);
            print_snapshot(&mut stdout, &view, args.rows as usize)?;
            stdout.flush()?;
            old = new;
        }
        return Ok(());
    }
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut ui = Ui {
        pid_filter: args.pid.map(|pid| ProcessFilter { pid, start: None }),
        pane: usize::from(args.pid.is_some()),
        sort_time,
        ..Ui::default()
    };
    let mut next = Instant::now() + interval;
    let mut new = old.clone();
    let mut view = model::build(
        &old,
        &new,
        ui.pid_filter,
        ui.syscall_filter,
        ui.thread_filter,
    );
    view.sort(ui.sort_time);
    loop {
        ui.sync(&view);
        terminal.draw(|frame| draw(frame, &view, &ui))?;
        let wait = next.saturating_duration_since(Instant::now());
        if event::poll(wait)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                        || ui.key(key.code, &view)
                    {
                        break;
                    }
                    view = model::build(
                        &old,
                        &new,
                        ui.pid_filter,
                        ui.syscall_filter,
                        ui.thread_filter,
                    );
                    view.sort(ui.sort_time);
                }
            }
        }
        if Instant::now() >= next {
            old = new;
            new = probe.read().context("read syscall counters")?;
            view = model::build(
                &old,
                &new,
                ui.pid_filter,
                ui.syscall_filter,
                ui.thread_filter,
            );
            view.sort(ui.sort_time);
            next = Instant::now() + interval;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("systop: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::{ProcessRow, SyscallRow};
    use ratatui::{backend::TestBackend, Terminal};

    fn view() -> View {
        View {
            seconds: 1.0,
            total_rate: 300.0,
            process_keys: 2,
            inflight: 0,
            selected_rate: 300.0,
            syscalls: vec![SyscallRow {
                id: 0,
                name: "read".into(),
                rate: 200.0,
                share: 2.0 / 3.0,
                time_ms_s: 0.0,
                avg_ms: None,
                p95_ms: None,
            }],
            processes: vec![ProcessRow {
                pid: 123,
                start: 1,
                comm: "worker".into(),
                rate: 250.0,
                share: 5.0 / 6.0,
                time_ms_s: 0.0,
                avg_ms: None,
            }],
            threads: vec![],
            thread_target: None,
            thread_filter: None,
            thread_keys: 0,
            thread_fail_rate: 0.0,
            invalid_rate: 0.0,
            attribution_fail_rate: 0.0,
            latency_fail_rate: 0.0,
            completed_rate: 0.0,
            start_fail_rate: 0.0,
            unmatched_rate: 0.0,
            process_miss_rate: 0.0,
            abandoned_rate: 0.0,
            latency_enabled: false,
            sort_time: false,
            pid_filter: None,
            syscall_filter: None,
        }
    }

    #[test]
    fn filters_and_selection() {
        let view = view();
        let mut ui = Ui::default();
        ui.sync(&view);
        ui.key(KeyCode::Enter, &view);
        assert_eq!(ui.syscall_filter, Some(0));
        ui.key(KeyCode::Tab, &view);
        ui.key(KeyCode::Enter, &view);
        assert_eq!(
            ui.pid_filter,
            Some(ProcessFilter {
                pid: 123,
                start: Some(1)
            })
        );
        ui.key(KeyCode::Esc, &view);
        assert!(ui.pid_filter.is_none() && ui.syscall_filter.is_none());
    }

    #[test]
    fn text_snapshot_and_terminal_layouts() {
        let view = view();
        let mut text = Vec::new();
        print_snapshot(&mut text, &view, 12).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("read"));
        assert!(text.contains("worker"));
        assert!(text.contains("process keys 2/65536"));
        for (width, height) in [(80, 24), (120, 35), (50, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw(frame, &view, &Ui::default()))
                .unwrap();
            let contents = terminal.backend().buffer().content();
            assert!(contents.iter().any(|cell| cell.symbol() == "s"));
        }
    }

    #[test]
    fn latency_text_and_terminal_layouts() {
        let mut view = view();
        view.latency_enabled = true;
        view.syscalls[0].time_ms_s = 250.0;
        view.processes[0].time_ms_s = 100.0;
        view.sort(true);
        view.syscalls[0].avg_ms = Some(1.25);
        view.syscalls[0].p95_ms = Some(2.048);
        view.processes[0].avg_ms = Some(1.5);
        let mut text = Vec::new();
        print_snapshot(&mut text, &view, 12).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("P95~ms"));
        assert!(text.contains("TIME ms/s"));
        assert!(text.contains("sort time"));
        assert!(text.contains("1.250"));
        assert!(text.contains("2.048"));
        let mut ui = Ui {
            sort_time: true,
            ..Ui::default()
        };
        ui.key(KeyCode::Char('s'), &view);
        assert!(!ui.sort_time);
        for (width, height) in [(80, 24), (140, 30)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw(frame, &view, &Ui::default()))
                .unwrap();
            let buffer = terminal.backend().buffer();
            assert!(buffer.content().iter().any(|cell| cell.symbol() == "P"));
        }
    }

    #[test]
    fn sort_option_requires_latency() {
        assert!(Args::try_parse_from(["systop", "-o", "time", "-c", "1"]).is_err());
        let args = Args::try_parse_from(["systop", "-L", "-o", "calls", "-c", "1"]).unwrap();
        assert_eq!(args.sort, Some(Sort::Calls));
    }

    #[test]
    fn pid_mode_shows_threads_and_preserves_pid_on_escape() {
        let mut view = view();
        view.thread_target = Some(123);
        view.pid_filter = Some(ProcessFilter {
            pid: 123,
            start: None,
        });
        view.thread_keys = 2;
        view.threads = vec![
            ProcessRow {
                pid: 124,
                start: 4,
                comm: "rx".into(),
                rate: 90.0,
                ..view.processes[0].clone()
            },
            ProcessRow {
                pid: 125,
                start: 5,
                comm: "tx".into(),
                rate: 80.0,
                ..view.processes[0].clone()
            },
        ];
        let mut text = Vec::new();
        print_snapshot(&mut text, &view, 12).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("THREADS (all syscalls)"));
        assert!(text.contains("TID"));
        assert!(text.contains("rx"));
        assert!(!text.contains("worker"));
        let mut ui = Ui {
            pane: 1,
            pid_filter: view.pid_filter,
            ..Ui::default()
        };
        ui.sync(&view);
        ui.key(KeyCode::Down, &view);
        ui.key(KeyCode::Enter, &view);
        assert_eq!(ui.thread_filter, Some(ThreadFilter { tid: 125, start: 5 }));
        ui.key(KeyCode::Esc, &view);
        assert!(ui.thread_filter.is_none());
        assert_eq!(ui.pid_filter, view.pid_filter);
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &view, &ui)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("THREADS"));
        let mut narrow = Terminal::new(TestBackend::new(80, 24)).unwrap();
        narrow.draw(|frame| draw(frame, &view, &ui)).unwrap();
        let rendered = narrow
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("THREADS"));
        assert!(rendered.contains("TID"));
    }
}
