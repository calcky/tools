mod collect;
mod interfaces;
mod model;
mod report;
mod ui;

use anyhow::{bail, Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Live skb path traffic and elapsed latency for Linux 6.6+",
    disable_version_flag = true
)]
struct Args {
    #[arg(short = 'i', value_delimiter = ',', action = clap::ArgAction::Append, value_name = "IFACE")]
    interfaces: Vec<String>,
    #[arg(short = 'd', default_value = "1", value_name = "SEC")]
    interval: f64,
    #[arg(short = 'c', value_name = "N")]
    count: Option<u64>,
    #[arg(short = 'T', value_name = "SEC")]
    duration: Option<f64>,
    #[arg(
        short = 'm',
        default_value = "262144",
        value_name = "N",
        help = "Maximum combined origin/transmit associations"
    )]
    inflight: u32,
    #[arg(
        short = 'g',
        default_value = "4096",
        value_name = "N",
        help = "Maximum directed paths"
    )]
    paths: u32,
    #[arg(
        short = 'o',
        value_name = "DIR",
        help = "Write snapshots.jsonl, summary.json and report.html"
    )]
    output: Option<PathBuf>,
    #[arg(short = 'v', action = clap::ArgAction::Version)]
    version: (),
}

impl Args {
    fn validate(&self) -> Result<()> {
        if !self.interval.is_finite() || self.interval < 0.05 || self.interval > 3600.0 {
            bail!("-d must be between 0.05 and 3600 seconds");
        }
        if self.count == Some(0) {
            bail!("-c must be positive");
        }
        if self.duration.is_some_and(|n| !n.is_finite() || n <= 0.0) {
            bail!("-T must be finite and positive");
        }
        if self.inflight == 0 || self.paths == 0 || self.paths > u32::MAX / 4 {
            bail!(
                "-m and -g must be positive; -g must not exceed {}",
                u32::MAX / 4
            );
        }
        if self
            .interfaces
            .iter()
            .any(|i| i.is_empty() || i.len() >= libc::IF_NAMESIZE || i.contains('\0'))
        {
            bail!("-i requires nonempty Linux interface names");
        }
        Ok(())
    }
}

struct TerminalGuard;
impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        let guard = Self;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            crossterm::cursor::Hide,
            EnableMouseCapture
        )?;
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal();
            previous(info);
        }));
        Ok(guard)
    }
}
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        DisableMouseCapture,
        crossterm::cursor::Show,
        LeaveAlternateScreen
    );
}
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn run(args: Args) -> Result<()> {
    args.validate()?;
    let text = args.count.is_some();
    if !text
        && (!io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || std::env::var("TERM").as_deref() == Ok("dumb"))
    {
        bail!("interactive mode requires a terminal; use -c N for plain text snapshots");
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let signal = stopped.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))
        .context("install signal handler")?;
    let mut recorder = args
        .output
        .as_deref()
        .map(report::Recorder::create)
        .transpose()?;
    let mut collector =
        collect::Collector::attach(&args.interfaces, args.interval, args.inflight, args.paths)?;
    let mut view = ui::Ui::new();
    let guard = if text {
        None
    } else {
        Some(TerminalGuard::enter()?)
    };
    let mut terminal = if text {
        None
    } else {
        Some(Terminal::new(CrosstermBackend::new(io::stdout()))?)
    };
    let interval_ns = (args.interval * 1e9) as u64;
    let stop_ns = args
        .duration
        .map(|t| collector.started_ns.saturating_add((t * 1e9) as u64));
    let mut next = collector
        .started_ns
        .saturating_add(interval_ns)
        .saturating_add(2_000_000);
    let mut last: Option<model::Snapshot> = None;
    let initial = model::Snapshot {
        sequence: 0,
        elapsed_secs: 0.0,
        interval_secs: args.interval,
        unix_ms: 0,
        rows: Vec::new(),
        interfaces: Vec::new(),
        health: model::Health {
            inflight_capacity: args.inflight as u64,
            path_capacity: args.paths as u64,
            ..Default::default()
        },
    };
    let mut redraw = true;
    let mut snapshots = 0;
    let mut result = Ok(());
    loop {
        let now = collect::monotonic_ns();
        let finish = stopped.load(Ordering::Relaxed)
            || stop_ns.is_some_and(|s| now >= s)
            || (now >= next && args.count.is_some_and(|c| snapshots + 1 >= c));
        if finish {
            collector.stop()?;
        }
        if now >= next || finish {
            match collector.snapshot(finish) {
                Ok(snapshot) => {
                    snapshots += 1;
                    if text {
                        print!("{}", ui::text(&snapshot));
                        io::stdout().flush()?;
                    }
                    if let Some(r) = recorder.as_mut() {
                        r.write(&snapshot)?;
                    }
                    last = Some(snapshot);
                    redraw = true;
                }
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
            // Missed deadlines produce one wider interval, never a burst of catch-up reads.
            next = collector.started_ns
                + ((now - collector.started_ns) / interval_ns + 1) * interval_ns
                + 2_000_000;
            if finish {
                break;
            }
        }
        if redraw {
            if let Some(t) = terminal.as_mut() {
                t.draw(|frame| view.draw(frame, last.as_ref().unwrap_or(&initial)))?;
            }
            redraw = false;
        }
        if let Err(e) = collector.refresh_interfaces() {
            result = Err(e);
            break;
        }
        let now = collect::monotonic_ns();
        let due = stop_ns.map_or(next, |s| s.min(next));
        let wait = Duration::from_nanos(due.saturating_sub(now).min(200_000_000));
        if text {
            std::thread::sleep(wait);
        } else if event::poll(wait)? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    redraw = true;
                    stopped.fetch_or(view.key(key), Ordering::Relaxed);
                }
                Event::Resize(_, _) => redraw = true,
                Event::Mouse(mouse) => redraw |= view.mouse(mouse),
                _ => {}
            }
        }
    }
    collector.stop()?;
    drop(terminal);
    drop(guard);
    if let Some(r) = recorder.as_mut() {
        println!("Report: {}", r.finish()?.display());
    }
    result
}

fn main() {
    if let Err(e) = run(Args::parse()) {
        eprintln!("skbtop: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_comma_interfaces_and_validation() {
        let args = Args::try_parse_from(["skbtop", "-i", "a,b", "-i", "c", "-c", "2"]).unwrap();
        assert_eq!(args.interfaces, vec!["a", "b", "c"]);
        assert!(args.validate().is_ok());
        for options in [
            ["-d", "NaN"],
            ["-d", "0"],
            ["-T", "0"],
            ["-m", "0"],
            ["-g", "0"],
            ["-c", "0"],
            ["-i", ""],
        ] {
            assert!(Args::try_parse_from(["skbtop", options[0], options[1]])
                .unwrap()
                .validate()
                .is_err());
        }
    }
}
