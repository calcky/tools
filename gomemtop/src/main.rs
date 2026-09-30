mod diagnosis;
mod process;
mod profile;
mod ui;

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use profile::{Snapshot, Values};
use std::{
    io::{self, IsTerminal, Read},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant, SystemTime},
};

#[derive(Parser)]
#[command(version, about = "Analyze Go heap pprof growth in a terminal window")]
struct Args {
    #[arg(value_name = "PPROF_URL")]
    url: String,
    #[arg(short = 'i', default_value_t = 30.0, value_parser = positive_seconds, value_name = "SECONDS")]
    interval: f64,
    #[arg(short = 'T', default_value_t = 10.0, value_parser = positive_seconds, value_name = "SECONDS")]
    timeout: f64,
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
}

fn positive_seconds(value: &str) -> Result<f64, String> {
    let n: f64 = value.parse().map_err(|_| "expected seconds".to_string())?;
    if !n.is_finite() || !(0.2..=3600.0).contains(&n) {
        Err("seconds must be between 0.2 and 3600".into())
    } else {
        Ok(n)
    }
}

fn heap_url(input: &str) -> Result<String, String> {
    let url = input.trim_end_matches('/');
    if !(url.starts_with("http://") || url.starts_with("https://")) || url.contains('#') {
        return Err("provide an http(s) pprof server URL".into());
    }
    if url.ends_with("/debug/pprof/heap") {
        Ok(url.into())
    } else if !url.contains('?') {
        Ok(format!("{url}/debug/pprof/heap"))
    } else {
        Err("query parameters are not supported; use the server root or heap endpoint".into())
    }
}

fn fetch(url: &str, timeout: Duration, gc: bool) -> Result<Snapshot, String> {
    let request_url = if gc {
        format!("{url}?gc=1")
    } else {
        url.into()
    };
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .redirects(0)
        .build();
    let response = agent.get(&request_url).call().map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take((profile::MAX_BODY + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    profile::decode(&body)
}

fn fetch_runtime(url: &str, timeout: Duration) -> Result<process::RuntimeMemory, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build();
    let response = agent
        .get(&format!("{url}?debug=1"))
        .call()
        .map_err(|e| e.to_string())?;
    let mut text = String::new();
    response
        .into_reader()
        .take(2 * 1024 * 1024)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    process::parse_runtime(&text).map_err(|e| e.to_string())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Metric {
    Inuse,
    Alloc,
}
impl Metric {
    fn label(self) -> &'static str {
        match self {
            Self::Inuse => "inuse_space",
            Self::Alloc => "alloc_space",
        }
    }
    fn bytes(self, value: Values) -> i64 {
        match self {
            Self::Inuse => value.inuse_bytes,
            Self::Alloc => value.alloc_bytes,
        }
    }
    fn objects(self, value: Values) -> i64 {
        match self {
            Self::Inuse => value.inuse_objects,
            Self::Alloc => value.alloc_objects,
        }
    }
}

#[derive(Clone)]
struct StackRow {
    stack: String,
    current: Values,
    previous: Values,
    baseline: Values,
}

struct SampleResult {
    heap: Result<Snapshot, String>,
    memory: Option<Result<process::Memory, String>>,
    runtime: Option<Result<process::RuntimeMemory, String>>,
}

struct App {
    url: String,
    pid: Option<u32>,
    memory: Option<process::Memory>,
    memory_error: Option<String>,
    runtime: Option<process::RuntimeMemory>,
    runtime_error: Option<String>,
    interval: Duration,
    timeout: Duration,
    metric: Metric,
    gc: bool,
    paused: bool,
    pending: bool,
    gc_queued: bool,
    next: Instant,
    selected: usize,
    detail_scroll: u16,
    current: Option<Snapshot>,
    previous: Option<Snapshot>,
    baseline: Option<Snapshot>,
    history: Vec<i64>,
    diagnosis_history: Vec<diagnosis::Point>,
    successes: u64,
    failures: u64,
    last_success: Option<SystemTime>,
    error: Option<String>,
    sender: Sender<SampleResult>,
    receiver: Receiver<SampleResult>,
}
impl App {
    fn new(url: String, interval: Duration, timeout: Duration) -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            url,
            pid: None,
            memory: None,
            memory_error: None,
            runtime: None,
            runtime_error: None,
            interval,
            timeout,
            metric: Metric::Inuse,
            gc: false,
            paused: false,
            pending: false,
            gc_queued: false,
            next: Instant::now(),
            selected: 0,
            detail_scroll: 0,
            current: None,
            previous: None,
            baseline: None,
            history: Vec::new(),
            diagnosis_history: Vec::new(),
            successes: 0,
            failures: 0,
            last_success: None,
            error: None,
            sender,
            receiver,
        }
    }
    fn tick(&mut self) {
        if !self.paused && !self.pending && Instant::now() >= self.next {
            let url = self.url.clone();
            let timeout = self.timeout;
            let gc = self.gc;
            let sender = self.sender.clone();
            let pid = self.pid;
            self.pending = true;
            thread::spawn(move || {
                let heap = fetch(&url, timeout, gc);
                let memory = pid.map(|pid| process::read(pid).map_err(|e| e.to_string()));
                let runtime = pid.map(|_| fetch_runtime(&url, timeout));
                let _ = sender.send(SampleResult {
                    heap,
                    memory,
                    runtime,
                });
            });
        }
        while let Ok(result) = self.receiver.try_recv() {
            self.pending = false;
            self.next = Instant::now() + self.interval;
            if self.gc_queued {
                self.gc_queued = false;
                self.apply_gc_toggle();
                continue;
            }
            let mut fresh_memory = None;
            let mut fresh_runtime = None;
            if let Some(memory) = result.memory {
                match memory {
                    Ok(memory) => {
                        self.memory = Some(memory);
                        fresh_memory = Some(memory);
                        self.memory_error = None;
                    }
                    Err(error) => self.memory_error = Some(error),
                }
            }
            if let Some(runtime) = result.runtime {
                match runtime {
                    Ok(runtime) => {
                        self.runtime = Some(runtime);
                        fresh_runtime = Some(runtime);
                        self.runtime_error = None;
                    }
                    Err(error) => self.runtime_error = Some(error),
                }
            }
            match result.heap {
                Ok(snapshot) => {
                    if let Some(memory) = fresh_memory {
                        self.diagnosis_history.push(diagnosis::Point::new(
                            memory,
                            snapshot.total.inuse_bytes,
                            fresh_runtime,
                        ));
                        if self.diagnosis_history.len() > 60 {
                            self.diagnosis_history.remove(0);
                        }
                    }
                    self.previous = self.current.take();
                    if self.baseline.is_none() {
                        self.baseline = Some(snapshot.clone());
                    }
                    self.history.push(self.metric.bytes(snapshot.total));
                    if self.history.len() > 60 {
                        self.history.remove(0);
                    }
                    self.current = Some(snapshot);
                    self.successes += 1;
                    self.last_success = Some(SystemTime::now());
                    self.error = None;
                }
                Err(error) => {
                    self.failures += 1;
                    self.error = Some(error);
                }
            }
        }
    }
    fn rows(&self) -> Vec<StackRow> {
        let Some(current) = &self.current else {
            return Vec::new();
        };
        let mut rows: Vec<_> = current
            .stacks
            .iter()
            .map(|(stack, values)| StackRow {
                stack: stack.clone(),
                current: *values,
                previous: self
                    .previous
                    .as_ref()
                    .and_then(|s| s.stacks.get(stack))
                    .copied()
                    .unwrap_or_default(),
                baseline: self
                    .baseline
                    .as_ref()
                    .and_then(|s| s.stacks.get(stack))
                    .copied()
                    .unwrap_or_default(),
            })
            .collect();
        rows.sort_unstable_by(|a, b| {
            let delta = |row: &StackRow| {
                self.metric
                    .bytes(row.current)
                    .saturating_sub(self.metric.bytes(row.baseline))
            };
            delta(b)
                .cmp(&delta(a))
                .then_with(|| {
                    self.metric
                        .bytes(b.current)
                        .cmp(&self.metric.bytes(a.current))
                })
                .then_with(|| a.stack.cmp(&b.stack))
        });
        rows
    }
    fn reset_baseline(&mut self) {
        self.baseline = self.current.clone();
        self.previous = None;
        self.history.clear();
        if let Some(last) = self.diagnosis_history.last().copied() {
            self.diagnosis_history.clear();
            self.diagnosis_history.push(last);
        }
        if let Some(snapshot) = &self.current {
            self.history.push(self.metric.bytes(snapshot.total));
        }
        self.selected = 0;
        self.detail_scroll = 0;
    }
    fn toggle_gc(&mut self) {
        if self.pending {
            self.gc_queued = !self.gc_queued;
            return;
        }
        self.apply_gc_toggle();
    }
    fn apply_gc_toggle(&mut self) {
        self.gc = !self.gc;
        self.current = None;
        self.previous = None;
        self.baseline = None;
        self.history.clear();
        self.diagnosis_history.clear();
        self.selected = 0;
        self.detail_scroll = 0;
        self.next = Instant::now();
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    if !io::stdout().is_terminal()
        || !io::stdin().is_terminal()
        || std::env::var("TERM").as_deref() == Ok("dumb")
    {
        return Err("gomemtop needs an interactive terminal".into());
    }
    let mut app = App::new(
        heap_url(&args.url)?,
        Duration::from_secs_f64(args.interval),
        Duration::from_secs_f64(args.timeout),
    );
    app.pid = args.pid;
    let mut screen = ui::Screen::open().map_err(|e| e.to_string())?;
    loop {
        app.tick();
        let rows = app.rows();
        app.selected = app.selected.min(rows.len().saturating_sub(1));
        screen
            .terminal
            .draw(|frame| ui::draw(frame, &app, &rows))
            .map_err(|e| e.to_string())?;
        if event::poll(Duration::from_millis(150)).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => {
                        app.selected = (app.selected + 1).min(rows.len().saturating_sub(1));
                        app.detail_scroll = 0;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        app.selected = app.selected.saturating_sub(1);
                        app.detail_scroll = 0;
                    }
                    KeyCode::PageDown => app.detail_scroll = app.detail_scroll.saturating_add(4),
                    KeyCode::PageUp => app.detail_scroll = app.detail_scroll.saturating_sub(4),
                    KeyCode::Char('m') => {
                        app.metric = if app.metric == Metric::Inuse {
                            Metric::Alloc
                        } else {
                            Metric::Inuse
                        };
                        app.history.clear();
                        if let Some(current) = &app.current {
                            app.history.push(app.metric.bytes(current.total));
                        }
                        app.selected = 0;
                        app.detail_scroll = 0;
                    }
                    KeyCode::Char('g') => app.toggle_gc(),
                    KeyCode::Char('b') => app.reset_baseline(),
                    KeyCode::Char(' ') => {
                        app.paused = !app.paused;
                        if !app.paused {
                            app.next = Instant::now();
                        }
                    }
                    KeyCode::Char('r') if !app.pending => app.next = Instant::now(),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("gomemtop: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_and_interval_validation() {
        assert_eq!(
            heap_url("http://localhost:6060/").unwrap(),
            "http://localhost:6060/debug/pprof/heap"
        );
        assert_eq!(
            heap_url("https://example.com/debug/pprof/heap").unwrap(),
            "https://example.com/debug/pprof/heap"
        );
        assert!(heap_url("file:///tmp/profile").is_err());
        assert!(positive_seconds("NaN").is_err());
    }
    #[test]
    fn growth_sort_and_reset() {
        let mut app = App::new(
            "http://localhost/debug/pprof/heap".into(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let snapshot = |a, b| Snapshot {
            stacks: [
                (
                    "a".into(),
                    Values {
                        inuse_bytes: a,
                        ..Values::default()
                    },
                ),
                (
                    "b".into(),
                    Values {
                        inuse_bytes: b,
                        ..Values::default()
                    },
                ),
            ]
            .into(),
            total: Values {
                inuse_bytes: a + b,
                ..Values::default()
            },
        };
        app.baseline = Some(snapshot(10, 10));
        app.previous = Some(snapshot(15, 10));
        app.current = Some(snapshot(20, 100));
        assert_eq!(app.rows()[0].stack, "b");
        app.reset_baseline();
        assert_eq!(
            app.rows()[0].current.inuse_bytes - app.rows()[0].baseline.inuse_bytes,
            0
        );
        app.toggle_gc();
        assert!(app.current.is_none() && app.gc);
    }

    #[test]
    fn gc_toggle_waits_for_inflight_sample() {
        let mut app = App::new(
            "http://localhost/debug/pprof/heap".into(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        app.pending = true;
        app.toggle_gc();
        assert!(!app.gc);
        assert!(app.gc_queued);
        app.sender
            .send(SampleResult {
                heap: Err("old request".into()),
                memory: None,
                runtime: None,
            })
            .unwrap();
        app.tick();
        assert!(app.gc);
        assert!(!app.gc_queued);
        assert!(app.baseline.is_none());
    }
}
