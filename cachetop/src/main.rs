mod collect;
mod model;
mod perf;

use anyhow::{bail, Result};
use clap::Parser;
use collect::{Collector, Sample};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::Row;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table, TableState},
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
    about = "Inspect LLC reads/misses, MPKI, IPC and CPU migrations via perf PMU"
)]
struct Args {
    #[arg(short = 'p', value_parser = clap::value_parser!(u32).range(1..), help = "Show per-thread counters for this PID")]
    pid: Option<u32>,
    #[arg(short = 'd', default_value_t = 1.0, value_parser = interval, help = "Sample interval in seconds (0.1..60)")]
    delay: f64,
    #[arg(short = 'c', value_parser = clap::value_parser!(u32).range(1..), help = "Print N plain-text snapshots")]
    count: Option<u32>,
}

fn interval(input: &str) -> std::result::Result<f64, String> {
    let value: f64 = input.parse().map_err(|_| "invalid interval")?;
    if !value.is_finite() || !(0.1..=60.0).contains(&value) {
        Err("interval must be 0.1..60 seconds".into())
    } else {
        Ok(value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Miss,
    Mpki,
    Ipc,
    Id,
}

impl Sort {
    fn label(self) -> &'static str {
        match self {
            Self::Miss => "LLC miss/s",
            Self::Mpki => "MPKI",
            Self::Ipc => "IPC",
            Self::Id => "ID",
        }
    }
}

fn sort_rows(rows: &mut [Row], sort: Sort) {
    rows.sort_by(|a, b| {
        let metric = |row: &Row| match sort {
            Sort::Miss => row.rates.llc_misses,
            Sort::Mpki => row.rates.mpki(),
            Sort::Ipc => row.rates.ipc(),
            Sort::Id => Some(row.id as f64),
        };
        if sort == Sort::Id {
            return a.id.cmp(&b.id);
        }
        match (metric(a), metric(b)) {
            (Some(left), Some(right)) => right
                .partial_cmp(&left)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.id.cmp(&b.id),
        }
    });
}

fn number(value: Option<f64>, decimals: usize) -> String {
    value.map_or_else(|| "-".into(), |value| format!("{value:.decimals$}"))
}

fn rate(value: Option<f64>) -> String {
    value.map_or_else(
        || "-".into(),
        |value| {
            if value >= 1_000_000.0 {
                format!("{:.2}M", value / 1_000_000.0)
            } else if value >= 1_000.0 {
                format!("{:.1}k", value / 1_000.0)
            } else {
                format!("{value:.1}")
            }
        },
    )
}

fn percentage(value: Option<f64>) -> String {
    value.map_or_else(|| "-".into(), |value| format!("{value:.1}%"))
}

fn print_sample(out: &mut impl Write, sample: &Sample, pid: Option<u32>, sort: Sort) -> Result<()> {
    let scope = pid.map_or_else(
        || "host CPUs".to_owned(),
        |pid| format!("PID {pid} threads"),
    );
    writeln!(
        out,
        "cachetop | {scope} | interval {:.3}s | rows {}/{} | sort {}",
        sample.elapsed,
        sample.observed,
        sample.live,
        sort.label()
    )?;
    writeln!(
        out,
        "LLC read hit {} | MPKI {} | IPC {} | PMU min run {} | LLC available {}/{}",
        percentage(sample.total.llc_hit_pct()),
        number(sample.total.mpki(), 2),
        number(sample.total.ipc(), 2),
        percentage(sample.total.running_pct),
        sample
            .rows
            .iter()
            .filter(|row| row.rates.llc_reads.is_some())
            .count(),
        sample.rows.len(),
    )?;
    if pid.is_some() {
        write!(out, "{:>6} {:<18} {:>5} ", "TID", "THREAD", "CPU")?;
    } else {
        write!(out, "{:>6} ", "CPU")?;
    }
    writeln!(
        out,
        "{:>11} {:>11} {:>9} {:>8} {:>7} {:>9} {:>8}",
        "LLC rd/s", "LLC miss/s", "rd hit%", "MPKI", "IPC", "migrate/s", "PMU run%"
    )?;
    for row in &sample.rows {
        if pid.is_some() {
            write!(
                out,
                "{:>6} {:<18.18} {:>5} ",
                row.id,
                row.name,
                row.last_cpu
                    .map_or_else(|| "-".into(), |value| value.to_string()),
            )?;
        } else {
            write!(out, "{:>6} ", row.id)?;
        }
        writeln!(
            out,
            "{:>11} {:>11} {:>9} {:>8} {:>7} {:>9} {:>8}",
            rate(row.rates.llc_reads),
            rate(row.rates.llc_misses),
            percentage(row.rates.llc_hit_pct()),
            number(row.rates.mpki(), 2),
            number(row.rates.ipc(), 2),
            rate(row.rates.migrations),
            percentage(row.rates.running_pct),
        )?;
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

struct Ui {
    sort: Sort,
    selected: usize,
    table: TableState,
    no_color: bool,
}

impl Ui {
    fn new() -> Self {
        Self {
            sort: Sort::Miss,
            selected: 0,
            table: TableState::default(),
            no_color: std::env::var_os("NO_COLOR").is_some(),
        }
    }

    fn key(&mut self, code: KeyCode, len: usize) -> bool {
        match code {
            KeyCode::Char('q') => return true,
            KeyCode::Char('j') | KeyCode::Down => {
                self.selected = (self.selected + 1).min(len.saturating_sub(1))
            }
            KeyCode::Char('k') | KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Char('m') => self.sort = Sort::Miss,
            KeyCode::Char('p') => self.sort = Sort::Mpki,
            KeyCode::Char('i') => self.sort = Sort::Ipc,
            KeyCode::Char('c') => self.sort = Sort::Id,
            _ => {}
        }
        false
    }
}

fn draw(frame: &mut Frame, sample: &Sample, pid: Option<u32>, ui: &mut Ui) {
    let area = frame.area();
    if area.width < 80 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("cachetop needs at least 80x20; resize the terminal"),
            area,
        );
        return;
    }
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(7),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area);
    let scope = pid.map_or_else(
        || "HOST / per CPU".to_owned(),
        |pid| format!("PID {pid} / per TID"),
    );
    let coverage = sample
        .rows
        .iter()
        .filter(|row| row.rates.llc_reads.is_some())
        .count();
    let header = format!(
        "{scope}  |  interval {:.3}s  |  counters {}/{}  |  sort {}\nLLC read hit {}  MPKI {}  IPC {}  PMU min run {}  |  LLC available {}/{}",
        sample.elapsed,
        sample.observed,
        sample.live,
        ui.sort.label(),
        percentage(sample.total.llc_hit_pct()),
        number(sample.total.mpki(), 2),
        number(sample.total.ipc(), 2),
        percentage(sample.total.running_pct),
        coverage,
        sample.rows.len(),
    );
    let title_style = if ui.no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" cachetop ")
                .title_style(title_style),
        ),
        sections[0],
    );

    let wide = area.width >= 120;
    let mut headings = vec![if pid.is_some() { "TID" } else { "CPU" }];
    let mut widths = vec![Constraint::Length(7)];
    if pid.is_some() {
        headings.extend(["THREAD", "CPU"]);
        widths.extend([Constraint::Min(12), Constraint::Length(5)]);
    }
    if wide {
        headings.push("LLC rd/s");
        widths.push(Constraint::Length(11));
    }
    headings.extend(["LLC miss/s", "rd hit%", "MPKI", "IPC"]);
    widths.extend([
        Constraint::Length(11),
        Constraint::Length(9),
        Constraint::Length(8),
        Constraint::Length(7),
    ]);
    if wide {
        headings.push("mig/s");
        widths.push(Constraint::Length(9));
    }
    headings.push("PMU%");
    widths.push(Constraint::Length(7));
    let max_miss = sample
        .rows
        .iter()
        .filter_map(|row| row.rates.llc_misses)
        .fold(0.0_f64, f64::max);
    let rows: Vec<_> = sample
        .rows
        .iter()
        .map(|row| {
            let mut cells = vec![Cell::from(row.id.to_string())];
            if pid.is_some() {
                cells.push(Cell::from(row.name.clone()));
                cells.push(Cell::from(
                    row.last_cpu
                        .map_or_else(|| "-".into(), |value| value.to_string()),
                ));
            }
            if wide {
                cells.push(Cell::from(rate(row.rates.llc_reads)));
            }
            let highest_miss = row
                .rates
                .llc_misses
                .is_some_and(|value| value > 0.0 && value == max_miss);
            let miss_style = if highest_miss && !ui.no_color {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            cells.extend([
                Cell::from(rate(row.rates.llc_misses)).style(miss_style),
                Cell::from(percentage(row.rates.llc_hit_pct())),
                Cell::from(number(row.rates.mpki(), 2)),
                Cell::from(number(row.rates.ipc(), 2)),
            ]);
            if wide {
                cells.push(Cell::from(rate(row.rates.migrations)));
            }
            let coverage_style =
                if row.rates.running_pct.is_some_and(|value| value < 75.0) && !ui.no_color {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default()
                };
            cells.push(Cell::from(percentage(row.rates.running_pct)).style(coverage_style));
            TableRow::new(cells)
        })
        .collect();
    let heading = TableRow::new(headings).style(title_style);
    let selected_style = if ui.no_color {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    let table = Table::new(rows, widths)
        .header(heading)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(if pid.is_some() { " Threads " } else { " CPUs " }),
        )
        .row_highlight_style(selected_style)
        .highlight_symbol(" > ");
    ui.selected = ui.selected.min(sample.rows.len().saturating_sub(1));
    ui.table
        .select((!sample.rows.is_empty()).then_some(ui.selected));
    frame.render_stateful_widget(table, sections[1], &mut ui.table);

    let detail = sample.rows.get(ui.selected).map_or_else(
        || "No sampled counters yet".to_owned(),
        |row| format!(
            "{} {}  {}  {}\nLLC reads/s {}  misses/s {}  LLC read hit {}  MPKI {}\nInstructions/s {}  cycles/s {}  IPC {}  migrations/s {}",
            if pid.is_some() { "TID" } else { "CPU" },
            row.id,
            row.name,
            if pid.is_some() { format!("last CPU {}", row.last_cpu.map_or_else(|| "-".into(), |value| value.to_string())) } else { String::new() },
            rate(row.rates.llc_reads),
            rate(row.rates.llc_misses),
            percentage(row.rates.llc_hit_pct()),
            number(row.rates.mpki(), 2),
            rate(row.rates.instructions),
            rate(row.rates.cycles),
            number(row.rates.ipc(), 2),
            rate(row.rates.migrations),
        ),
    );
    frame.render_widget(
        Paragraph::new(detail).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Selected counter "),
        ),
        sections[2],
    );
    frame.render_widget(
        Paragraph::new("j/k move  m miss/s  p MPKI  i IPC  c ID  q quit  |  - unavailable"),
        sections[3],
    );
}

fn run_text(mut collector: Collector, args: &Args, delay: Duration) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    ctrlc::set_handler(move || flag.store(true, AtomicOrdering::Relaxed))?;
    let mut stdout = io::stdout().lock();
    for _ in 0..args.count.unwrap_or(0) {
        let deadline = Instant::now() + delay;
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
        let mut sample = collector.sample()?;
        sort_rows(&mut sample.rows, Sort::Miss);
        print_sample(&mut stdout, &sample, args.pid, Sort::Miss)?;
        stdout.flush()?;
    }
    Ok(())
}

fn run_ui(mut collector: Collector, args: &Args, delay: Duration) -> Result<()> {
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
    {
        bail!("interactive mode requires a terminal; use -c N for plain-text output");
    }
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut ui = Ui::new();
    let mut sample = Sample {
        rows: Vec::new(),
        total: Default::default(),
        elapsed: 0.0,
        observed: 0,
        live: 0,
    };
    let mut next = Instant::now() + delay;
    loop {
        terminal.draw(|frame| draw(frame, &sample, args.pid, &mut ui))?;
        let timeout = next.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        break;
                    }
                    if ui.key(key.code, sample.rows.len()) {
                        break;
                    }
                    sort_rows(&mut sample.rows, ui.sort);
                }
            }
        }
        if Instant::now() >= next {
            sample = collector.sample()?;
            sort_rows(&mut sample.rows, ui.sort);
            next = Instant::now() + delay;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let delay = Duration::from_secs_f64(args.delay);
    let collector = Collector::new(args.pid)?;
    if args.count.is_some() {
        run_text(collector, &args, delay)
    } else {
        run_ui(collector, &args, delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use model::Rates;
    use ratatui::backend::TestBackend;

    #[test]
    fn parameter_and_sort_behavior() {
        assert!(Args::try_parse_from(["cachetop", "-p", "42", "-c", "2", "-d", "0.5"]).is_ok());
        assert!(Args::try_parse_from(["cachetop", "-d", "0"]).is_err());
        let mut rows = vec![
            Row {
                id: 2,
                name: "b".into(),
                last_cpu: None,
                rates: Rates {
                    llc_misses: Some(5.0),
                    ..Rates::default()
                },
            },
            Row {
                id: 1,
                name: "a".into(),
                last_cpu: None,
                rates: Rates {
                    llc_misses: Some(10.0),
                    ..Rates::default()
                },
            },
        ];
        sort_rows(&mut rows, Sort::Miss);
        assert_eq!(rows[0].id, 1);
        sort_rows(&mut rows, Sort::Id);
        assert_eq!(rows[0].id, 1);
    }

    #[test]
    fn text_and_terminal_layouts() {
        let sample = Sample {
            rows: vec![Row {
                id: 0,
                name: "CPU0".into(),
                last_cpu: None,
                rates: Rates::default(),
            }],
            total: Rates::default(),
            elapsed: 1.0,
            observed: 1,
            live: 1,
        };
        let mut output = Vec::new();
        print_sample(&mut output, &sample, None, Sort::Miss).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("LLC read hit -"));
        for (width, height) in [(80, 24), (140, 30), (60, 15)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut ui = Ui::new();
            terminal
                .draw(|frame| draw(frame, &sample, None, &mut ui))
                .unwrap();
            let screen: String = terminal
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|cell| cell.symbol())
                .collect();
            if width < 80 {
                assert!(screen.contains("resize the terminal"));
            } else {
                assert!(screen.contains("LLC miss/s"));
                assert!(screen.contains("PMU%"));
            }
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut ui = Ui::new();
        ui.no_color = true;
        terminal
            .draw(|frame| draw(frame, &sample, Some(1234), &mut ui))
            .unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(screen.contains("TID"));
        assert!(screen.contains("THREAD"));
        assert!(screen.contains("PMU%"));
    }
}
