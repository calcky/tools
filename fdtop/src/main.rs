mod collect;
mod event_ui;
mod events;
mod inventory;
mod metadata;
mod model;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, IsTerminal},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "eBPF process and file-descriptor I/O monitor",
    disable_version_flag = true
)]
struct Args {
    #[arg(short='p',value_name="PID",value_parser=clap::value_parser!(u32).range(1..),help="Trace this process and list all its open FDs")]
    pid: Option<u32>,
    #[arg(short='f',value_name="FD",requires="pid",value_parser=clap::value_parser!(i32).range(0..),help="Trace one descriptor (requires -p)")]
    fd: Option<i32>,
    #[arg(
        short = 'n',
        value_name = "COMM",
        help = "Filter process name (substring)"
    )]
    name: Option<String>,
    #[arg(short='t',value_name="TYPE",ignore_case=true,value_parser=["file","socket","tcp","udp","unix","xsk","netlink","pipe","char","block","mq","eventfd","timerfd","signalfd","epoll","bpfmap","bpfprog","btf","other"])]
    kind: Option<String>,
    #[arg(short='d',default_value="1",value_name="SECONDS",value_parser=interval,help="Refresh interval, 0.1-60 seconds")]
    interval: f64,
    #[arg(short='c',value_name="COUNT",value_parser=clap::value_parser!(u32).range(1..),help="Print COUNT text snapshots then exit")]
    count: Option<u32>,
    #[arg(
        short = 'b',
        help = "Text output (automatic when stdout is not a terminal)"
    )]
    batch: bool,
    #[arg(short = 'j', help = "One JSON object per sample, including FD details")]
    json: bool,
    #[arg(
        short = 'l',
        help = "Collect syscall latency and pending age (higher overhead)"
    )]
    latency: bool,
    #[arg(
        short = 'e',
        help = "Start in FD lifecycle event view (capture enabled on demand)"
    )]
    events: bool,
    #[arg(short='v',action=clap::ArgAction::Version,help="Print version")]
    version: Option<bool>,
}
fn interval(s: &str) -> std::result::Result<f64, String> {
    let value: f64 = s.parse().map_err(|_| "expected seconds")?;
    if !value.is_finite() || !(0.1..=60.0).contains(&value) {
        return Err("interval must be 0.1-60 seconds".into());
    }
    Ok(value)
}

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}
struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore();
    }
}

fn run(args: Args) -> Result<()> {
    let batch = args.batch
        || args.json
        || args.count.is_some()
        || !io::stdout().is_terminal()
        || !io::stdin().is_terminal()
        || std::env::var("TERM").is_ok_and(|t| t == "dumb");
    let collector = collect::Collector::new(args.pid, args.fd, args.latency)?;
    let filter = model::Filter {
        name: args.name,
        kind: args.kind.map(|v| v.to_ascii_uppercase()),
        fd: args.fd,
    };
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))?;
    let _guard;
    let mut terminal = if batch {
        None
    } else {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            previous(info);
        }));
        _guard = TerminalGuard;
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Some(ratatui::Terminal::new(
            ratatui::backend::CrosstermBackend::new(io::stdout()),
        )?)
    };
    let mut previous = collector.snapshot()?;
    let mut data = model::frame(&previous, &previous, &filter);
    let mut metadata = metadata::Resolver::default();
    metadata.enrich(&mut data, &previous);
    if let Some(pid) = args.pid {
        inventory::enrich(&mut data, &previous, pid, &filter, &mut metadata);
    }
    let duration = Duration::from_secs_f64(args.interval);
    let mut next = Instant::now() + duration;
    let mut samples = 0;
    let mut app = ui::App {
        events: args.events,
        no_color: std::env::var_os("NO_COLOR").is_some(),
        ..Default::default()
    };
    let mut event_collector = if args.events {
        Some(events::Collector::new(args.pid, &filter, &data)?)
    } else {
        None
    };
    if let Some(pid) = args.pid {
        app.focus = data
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| (p.pid, p.start));
    }
    if let Some(t) = terminal.as_mut() {
        t.draw(|f| {
            if app.events {
                event_ui::draw(f, &mut app, event_collector.as_ref().unwrap());
            } else {
                ui::draw(f, &mut app, &data);
            }
        })?;
    }
    while !stop.load(Ordering::Relaxed) {
        if let Some(events) = event_collector.as_mut() {
            events.poll()?;
        }
        if Instant::now() >= next {
            let current = collector.snapshot()?;
            data = model::frame(&previous, &current, &filter);
            metadata.enrich(&mut data, &current);
            if let Some(pid) = args.pid.or(app.focus.map(|p| p.0)) {
                inventory::enrich(&mut data, &current, pid, &filter, &mut metadata);
                if app.focus.is_some() || samples == 0 {
                    let selected = data
                        .rows
                        .iter()
                        .find(|r| r.total.id.key.pid == pid && r.state == "open")
                        .map(|r| (pid, r.total.id.key.start));
                    app.focus = selected.or(app.focus);
                }
            }
            previous = current;
            if let Some(t) = terminal.as_mut() {
                t.draw(|f| {
                    if app.events {
                        event_ui::draw(f, &mut app, event_collector.as_ref().unwrap());
                    } else {
                        ui::draw(f, &mut app, &data);
                    }
                })?;
                if let Some(events) = &event_collector {
                    events.discard_output();
                }
            } else {
                if args.events {
                    event_collector.as_ref().unwrap().print(args.json)?;
                } else {
                    ui::print(&data, args.json, args.pid.is_some())?;
                }
            }
            samples += 1;
            if args.count.is_some_and(|n| samples >= n) {
                break;
            }
            next = Instant::now() + duration;
        }
        let wait = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        if batch {
            std::thread::sleep(wait);
            continue;
        }
        if event::poll(wait)? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if key.code == KeyCode::Char('q')
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL))
                    {
                        break;
                    }
                    match key.code {
                        KeyCode::Char('e') => {
                            if event_collector.is_none() {
                                event_collector = Some(events::Collector::new(
                                    args.pid.or(app.focus.map(|p| p.0)),
                                    &filter,
                                    &data,
                                )?);
                            }
                            app.events = !app.events;
                            app.selected = 0;
                            app.table = Default::default();
                        }
                        KeyCode::Char('h' | '?') => app.help = !app.help,
                        KeyCode::Esc if app.help => app.help = false,
                        KeyCode::Esc if !app.events => app.back(),
                        KeyCode::Char('j') | KeyCode::Down => {
                            app.selected = app.selected.saturating_add(1)
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            app.selected = app.selected.saturating_sub(1)
                        }
                        KeyCode::Enter if !app.events => app.enter(&data),
                        KeyCode::Char('s') => app.sort = (app.sort + 1) % 3,
                        _ => {}
                    }
                }
                _ => {}
            }
            if let Some(t) = terminal.as_mut() {
                t.draw(|f| {
                    if app.events {
                        event_ui::draw(f, &mut app, event_collector.as_ref().unwrap());
                    } else {
                        ui::draw(f, &mut app, &data);
                    }
                })?;
            }
        }
    }
    if let Some(events) = event_collector.as_mut() {
        events.finish(batch && args.events, args.json)?;
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(Args::parse()).context("fdtop") {
        if error
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
        {
            return;
        }
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_filters_and_intervals() {
        for kind in ["eventfd", "timerfd", "signalfd", "SIGNALFD"] {
            Args::try_parse_from(["fdtop", "-t", kind]).unwrap();
        }
        assert!(!Args::try_parse_from(["fdtop"]).unwrap().latency);
        assert!(
            Args::try_parse_from(["fdtop", "-l", "-p", "12"])
                .unwrap()
                .latency
        );
        assert!(Args::try_parse_from(["fdtop", "-f", "3"]).is_err());
        Args::try_parse_from(["fdtop", "-p", "12", "-f", "3", "-t", "TCP"]).unwrap();
        assert!(interval("NaN").is_err());
        assert!(interval("0").is_err());
    }
}
