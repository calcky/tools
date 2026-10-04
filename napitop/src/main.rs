mod collect;
mod model;

use anyhow::{bail, Result};
use clap::Parser;
use collect::{interface_index, interface_name, Collector, Snapshot};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::{sample, Counters, NapiRow, Sample};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::{
    cmp::Ordering,
    io::{self, IsTerminal, Write},
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "Show per-NAPI poll work, budget pressure and latency"
)]
struct Args {
    #[arg(
        short = 'i',
        value_name = "IFACE",
        help = "Only show this interface in the current network namespace"
    )]
    interface: Option<String>,
    #[arg(short = 'd', default_value_t = 1.0, value_parser = interval, help = "Sample interval in seconds (0.1..60)")]
    delay: f64,
    #[arg(short = 'c', value_parser = clap::value_parser!(u32).range(1..), help = "Print N samples in text mode, then exit")]
    count: Option<u32>,
}

fn interval(value: &str) -> std::result::Result<f64, String> {
    let value: f64 = value.parse().map_err(|_| "invalid interval")?;
    if !(0.1..=60.0).contains(&value) {
        Err("interval must be 0.1..60 seconds".into())
    } else {
        Ok(value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Work,
    Budget,
    Latency,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Self::Work => Self::Budget,
            Self::Budget => Self::Latency,
            Self::Latency => Self::Work,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Work => "work/s",
            Self::Budget => "budget%",
            Self::Latency => "avg us",
        }
    }
}

fn sort_rows(rows: &mut [NapiRow], sort: Sort) {
    rows.sort_by(|a, b| {
        let compare = match sort {
            Sort::Work => b.stats.work.cmp(&a.stats.work),
            Sort::Budget => b.stats.hit_percent().total_cmp(&a.stats.hit_percent()),
            Sort::Latency => match (a.stats.avg_us(), b.stats.avg_us()) {
                (Some(a), Some(b)) => b.total_cmp(&a),
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (None, None) => Ordering::Equal,
            },
        };
        compare
            .then_with(|| b.stats.work.cmp(&a.stats.work))
            .then_with(|| a.ifindex.cmp(&b.ifindex))
            .then_with(|| a.napi_id.cmp(&b.napi_id))
    });
}

fn rate(value: u64, elapsed: f64) -> String {
    if elapsed <= 0.0 {
        return "-".into();
    }
    let value = value as f64 / elapsed;
    if value >= 1_000_000.0 {
        format!("{:.2}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}k", value / 1_000.0)
    } else {
        format!("{value:.1}")
    }
}

fn avg_us(stats: &Counters) -> String {
    stats
        .avg_us()
        .map_or_else(|| "-".into(), |value| format!("{value:.1}"))
}

fn percentile_us(stats: &Counters, percentile: u64) -> String {
    stats.percentile_us(percentile).map_or_else(
        || "-".into(),
        |(value, open)| {
            if open {
                format!(">{value}")
            } else {
                format!("<={value}")
            }
        },
    )
}

fn print_sample(out: &mut impl Write, sample: &Sample, scope: &str) -> Result<()> {
    writeln!(out, "napitop | {scope} | interval {:.3}s | {} active NAPI | work {} /s | poll {} /s | budget-hit {:.1}% | map-miss {} timing-miss {}",
        sample.elapsed, sample.rows.len(), rate(sample.total.work, sample.elapsed), rate(sample.total.polls, sample.elapsed), sample.total.hit_percent(), sample.errors[0], sample.errors[1])?;
    writeln!(
        out,
        "{:<12} {:>7} {:>10} {:>11} {:>10} {:>9} {:>9} {:>10} {:>10} {:>7}",
        "IFACE",
        "NAPI",
        "poll/s",
        "work/s",
        "work/poll",
        "budget%",
        "avg us",
        "p50 us*",
        "p99 us*",
        "CPU"
    )?;
    for row in &sample.rows {
        let hot = row
            .cpus
            .first()
            .map_or_else(|| "-".into(), |cpu| cpu.cpu.to_string());
        writeln!(
            out,
            "{:<12.12} {:>7} {:>10} {:>11} {:>10.1} {:>8.1}% {:>9} {:>10} {:>10} {:>7}",
            interface_name(row.ifindex),
            row.napi_id,
            rate(row.stats.polls, sample.elapsed),
            rate(row.stats.work, sample.elapsed),
            row.stats.work_per_poll(),
            row.stats.hit_percent(),
            avg_us(&row.stats),
            percentile_us(&row.stats, 50),
            percentile_us(&row.stats, 99),
            hot
        )?;
    }
    writeln!(
        out,
        "* P50/P99 are histogram bounds in us; budget-hit is not proof of loss.\n"
    )?;
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

struct Ui {
    sort: Sort,
    selected: usize,
    cpu_page: usize,
    table: TableState,
    no_color: bool,
}

impl Ui {
    fn new() -> Self {
        Self {
            sort: Sort::Work,
            selected: 0,
            cpu_page: 0,
            table: TableState::default(),
            no_color: std::env::var_os("NO_COLOR").is_some(),
        }
    }

    fn key(&mut self, key: KeyCode, len: usize) -> bool {
        match key {
            KeyCode::Char('q') => return true,
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected = (self.selected + 1).min(len.saturating_sub(1));
                self.cpu_page = 0;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                self.cpu_page = 0;
            }
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.cpu_page = 0;
            }
            KeyCode::Char('[') => self.cpu_page = self.cpu_page.saturating_sub(1),
            KeyCode::Char(']') => self.cpu_page = self.cpu_page.saturating_add(1),
            _ => {}
        }
        false
    }
}

fn draw(frame: &mut Frame, sample: &Sample, scope: &str, ui: &mut Ui) {
    let area = frame.area();
    if area.width < 76 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("napitop needs at least 76x20; resize the terminal"),
            area,
        );
        return;
    }
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(7),
            Constraint::Length(7),
            Constraint::Length(1),
        ])
        .split(area);
    let accent = if ui.no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    let header = format!("{scope} | {:.3}s | NAPI {} | sort {}\nwork/s {}  poll/s {}  budget {:.1}%  |  gaps map {} timing {}",
        sample.elapsed, sample.rows.len(), ui.sort.name(), rate(sample.total.work, sample.elapsed),
        rate(sample.total.polls, sample.elapsed), sample.total.hit_percent(), sample.errors[0], sample.errors[1]);
    frame.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" napitop ")
                .title_style(accent),
        ),
        parts[0],
    );

    let wide = area.width >= 112;
    let mut headings = vec!["IFACE", "NAPI", "poll/s", "work/s"];
    let mut widths = vec![
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(11),
    ];
    if wide {
        headings.push("work/poll");
        widths.push(Constraint::Length(10));
    }
    headings.extend(["budget%", "avg us"]);
    widths.extend([Constraint::Length(9), Constraint::Length(9)]);
    if wide {
        headings.push("p50 us*");
        widths.push(Constraint::Length(10));
    }
    headings.push("p99 us*");
    widths.push(Constraint::Length(10));
    if wide {
        headings.push("hot CPU");
        widths.push(Constraint::Length(8));
    }
    let rows: Vec<_> = sample
        .rows
        .iter()
        .map(|row| {
            let mut cells = vec![
                Cell::from(interface_name(row.ifindex)),
                Cell::from(row.napi_id.to_string()),
                Cell::from(rate(row.stats.polls, sample.elapsed)),
                Cell::from(rate(row.stats.work, sample.elapsed)),
            ];
            if wide {
                cells.push(Cell::from(format!("{:.1}", row.stats.work_per_poll())));
            }
            let hit_style = if !ui.no_color && row.stats.hit_percent() >= 20.0 {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            cells.extend([
                Cell::from(format!("{:.1}%", row.stats.hit_percent())).style(hit_style),
                Cell::from(avg_us(&row.stats)),
            ]);
            if wide {
                cells.push(Cell::from(percentile_us(&row.stats, 50)));
            }
            cells.push(Cell::from(percentile_us(&row.stats, 99)));
            if wide {
                cells.push(Cell::from(
                    row.cpus
                        .first()
                        .map_or_else(|| "-".into(), |cpu| cpu.cpu.to_string()),
                ));
            }
            Row::new(cells)
        })
        .collect();
    let selected_style = if ui.no_color {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    let table = Table::new(rows, widths)
        .header(Row::new(headings).style(accent))
        .block(Block::default().borders(Borders::ALL).title(" NAPI polls "))
        .row_highlight_style(selected_style)
        .highlight_symbol(" > ");
    ui.selected = ui.selected.min(sample.rows.len().saturating_sub(1));
    ui.table
        .select((!sample.rows.is_empty()).then_some(ui.selected));
    frame.render_stateful_widget(table, parts[1], &mut ui.table);

    let detail = sample.rows.get(ui.selected).map_or_else(
        || "No NAPI polls in this interval".into(),
        |row| {
            ui.cpu_page = ui.cpu_page.min(row.cpus.len().saturating_sub(1) / 3);
            let start = ui.cpu_page * 3;
            let end = (start + 3).min(row.cpus.len());
            let mut lines = vec![
                format!(
                    "{} NAPI {} | {} CPUs | work/poll {:.1} | budget {:.1}%",
                    interface_name(row.ifindex),
                    row.napi_id,
                    row.cpus.len(),
                    row.stats.work_per_poll(),
                    row.stats.hit_percent()
                ),
                format!(
                    "avg {} us | p50 {} us | p99 {} us | CPUs {}-{}/{} by work",
                    avg_us(&row.stats),
                    percentile_us(&row.stats, 50),
                    percentile_us(&row.stats, 99),
                    start + 1,
                    end,
                    row.cpus.len()
                ),
            ];
            for cpu in row.cpus.iter().skip(start).take(3) {
                lines.push(format!(
                    "CPU {:>3}  poll/s {:>9}  work/s {:>10}  budget {:>5.1}%  avg {:>8} us",
                    cpu.cpu,
                    rate(cpu.stats.polls, sample.elapsed),
                    rate(cpu.stats.work, sample.elapsed),
                    cpu.stats.hit_percent(),
                    avg_us(&cpu.stats)
                ));
            }
            lines.join("\n")
        },
    );
    frame.render_widget(
        Paragraph::new(detail).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Selected NAPI / hottest CPUs "),
        ),
        parts[2],
    );
    frame.render_widget(
        Paragraph::new(
            "j/k NAPI  [/] CPU page  s sort  q quit  |  * P50/P99 bucket bound; budget != loss",
        ),
        parts[3],
    );
}

fn next_sample(
    collector: &Collector,
    previous: &mut Snapshot,
    last: &mut Instant,
) -> Result<Sample> {
    let current = collector.snapshot()?;
    let now = Instant::now();
    let result = sample(
        &previous.rows,
        &current.rows,
        previous.errors,
        current.errors,
        now.duration_since(*last).as_secs_f64().max(0.000_001),
    );
    *previous = current;
    *last = now;
    Ok(result)
}

fn run_text(
    collector: &Collector,
    mut previous: Snapshot,
    args: &Args,
    scope: &str,
    delay: Duration,
) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    ctrlc::set_handler(move || flag.store(true, AtomicOrdering::Relaxed))?;
    let mut last = Instant::now();
    let mut out = io::stdout().lock();
    for _ in 0..args.count.unwrap_or(u32::MAX) {
        let deadline = last + delay;
        while Instant::now() < deadline && !stop.load(AtomicOrdering::Relaxed) {
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
        if stop.load(AtomicOrdering::Relaxed) {
            break;
        }
        let mut sample = next_sample(collector, &mut previous, &mut last)?;
        sort_rows(&mut sample.rows, Sort::Work);
        print_sample(&mut out, &sample, scope)?;
        out.flush()?;
    }
    Ok(())
}

fn run_tui(
    collector: &Collector,
    mut previous: Snapshot,
    scope: &str,
    delay: Duration,
) -> Result<()> {
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut ui = Ui::new();
    let mut last = Instant::now();
    let mut next = last + delay;
    let mut current = Sample {
        rows: Vec::new(),
        total: Counters::default(),
        errors: [0; 2],
        elapsed: 0.0,
    };
    loop {
        terminal.draw(|frame| draw(frame, &current, scope, &mut ui))?;
        if event::poll(
            next.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(200)),
        )? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break;
                    }
                    let previous_sort = ui.sort;
                    if ui.key(key.code, current.rows.len()) {
                        break;
                    }
                    if ui.sort != previous_sort {
                        sort_rows(&mut current.rows, ui.sort);
                    }
                }
            }
        }
        if Instant::now() >= next {
            current = next_sample(collector, &mut previous, &mut last)?;
            sort_rows(&mut current.rows, ui.sort);
            next = last + delay;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let ifindex = args
        .interface
        .as_deref()
        .map(interface_index)
        .transpose()?
        .unwrap_or(0);
    let scope = args.interface.as_deref().unwrap_or("all interfaces");
    let delay = Duration::from_secs_f64(args.delay);
    let collector = Collector::attach(ifindex)?;
    let previous = collector.snapshot()?;
    if args.count.is_some() || !io::stdout().is_terminal() {
        run_text(&collector, previous, &args, scope, delay)
    } else if std::env::var("TERM").as_deref() == Ok("dumb") {
        bail!("interactive display requires a terminal; use -c for text samples");
    } else {
        run_tui(&collector, previous, scope, delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::CpuRow;
    use ratatui::backend::TestBackend;

    #[test]
    fn zero_interval_does_not_print_nan() {
        assert_eq!(rate(0, 0.0), "-");
        assert_eq!(rate(1000, 1.0), "1.0k");
    }

    #[test]
    fn tui_renders_narrow_and_wide_without_losing_summary() {
        let stats = Counters {
            polls: 10,
            work: 20,
            timed_polls: 10,
            duration_ns: 100_000,
            latency_us: [10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        let sample = Sample {
            rows: vec![NapiRow {
                ifindex: 1,
                napi_id: 42,
                stats: stats.clone(),
                cpus: vec![CpuRow { cpu: 3, stats }],
            }],
            total: Counters::default(),
            errors: [0; 2],
            elapsed: 1.0,
        };
        for width in [80, 120] {
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            let mut ui = Ui::new();
            terminal
                .draw(|frame| draw(frame, &sample, "all interfaces", &mut ui))
                .unwrap();
            let rendered: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            assert!(rendered.contains("gaps map 0 timing 0"), "width {width}");
            assert!(rendered.contains("avg 10.0 us"), "width {width}");
            assert!(!rendered.contains("NaN"), "width {width}");
        }
    }
}
