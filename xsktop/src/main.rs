mod diag;

use anyhow::{bail, Context, Result};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use diag::{Errors, Socket};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, IsTerminal, Write},
    num::NonZeroU32,
    os::unix::fs::MetadataExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/observe.bpf.o"));

#[derive(Parser)]
#[command(version, about = "Live AF_XDP socket traffic and error monitor")]
struct Args {
    /// Show one interface
    #[arg(short = 'i', long = "interface")]
    interface: Option<String>,
    /// Refresh interval in seconds
    #[arg(short = 'd', long = "delay", default_value_t = 1.0, value_parser = positive_interval)]
    delay: f64,
    /// Print N measured samples instead of opening the live window
    #[arg(short = 'c', long = "count")]
    count: Option<NonZeroU32>,
}

fn positive_interval(text: &str) -> std::result::Result<f64, String> {
    let number = text
        .parse::<f64>()
        .map_err(|_| "expected a positive number".to_string())?;
    if !number.is_finite() || number < 0.1 {
        return Err("delay must be at least 0.1 seconds".into());
    }
    Ok(number)
}

struct Bpf {
    object: Object,
    _links: Vec<Link>,
}

impl Bpf {
    fn attach() -> Result<Self> {
        let object = ObjectBuilder::default()
            .open_memory(BPF_OBJECT)
            .context("open xsktop BPF object")?
            .load()
            .context("load XSK probes (check BPF/tracing permissions, CONFIG_BPF_SYSCALL, CONFIG_BPF_JIT, CONFIG_BPF_EVENTS and kernel BTF)")?;
        let netns = std::fs::metadata("/proc/self/ns/net")
            .context("read current network namespace")?
            .ino() as u32;
        object
            .maps()
            .find(|map| map.name() == "target_netns")
            .context("BPF network namespace map missing")?
            .update(&0_u32.to_ne_bytes(), &netns.to_ne_bytes(), MapFlags::ANY)?;
        let mut links = Vec::new();
        for program in object.progs_mut() {
            let name = program.name().to_string_lossy().into_owned();
            let section = program.section().to_string_lossy().into_owned();
            links.push(
                program
                    .attach_trace()
                    .with_context(|| format!("attach {name} ({section}); check that the kernel function is present and supports fentry/fexit"))?,
            );
        }
        Ok(Self {
            object,
            _links: links,
        })
    }

    fn counters(&self, ifindex: u32, queue: u32) -> Result<Counter> {
        let mut key = [0_u8; 8];
        key[..4].copy_from_slice(&ifindex.to_ne_bytes());
        key[4..].copy_from_slice(&queue.to_ne_bytes());
        let map = self
            .object
            .maps()
            .find(|map| map.name() == "traffic")
            .context("BPF traffic map missing")?;
        let Some(per_cpu) = map.lookup_percpu(&key, MapFlags::ANY)? else {
            return Ok(Counter::default());
        };
        let mut total = Counter::default();
        for bytes in per_cpu {
            total.add(Counter::parse(&bytes)?);
        }
        Ok(total)
    }
}

fn diagnose_diag_error(error: anyhow::Error) -> anyhow::Error {
    match error
        .root_cause()
        .downcast_ref::<io::Error>()
        .and_then(io::Error::raw_os_error)
    {
        Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) => error.context(
            "AF_XDP socket diagnostics unavailable; enable CONFIG_XDP_SOCKETS_DIAG=y or install/load xsk_diag when configured as a module",
        ),
        _ => error.context("query AF_XDP sockets through NETLINK_SOCK_DIAG"),
    }
}

fn preflight() -> Result<()> {
    diag::snapshot().map_err(diagnose_diag_error)?;
    File::open("/sys/kernel/btf/vmlinux").context(
        "kernel BTF unavailable; enable CONFIG_DEBUG_INFO_BTF and expose /sys/kernel/btf/vmlinux",
    )?;
    Ok(())
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Counter {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    rx_frag_packets: u64,
    tx_unmeasured_packets: u64,
}

impl Counter {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 48 {
            bail!("short BPF counter value");
        }
        let at = |offset| u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        Ok(Self {
            rx_packets: at(0),
            rx_bytes: at(8),
            tx_packets: at(16),
            tx_bytes: at(24),
            rx_frag_packets: at(32),
            tx_unmeasured_packets: at(40),
        })
    }

    fn delta(self, old: Self) -> Self {
        Self {
            rx_packets: self.rx_packets.saturating_sub(old.rx_packets),
            rx_bytes: self.rx_bytes.saturating_sub(old.rx_bytes),
            tx_packets: self.tx_packets.saturating_sub(old.tx_packets),
            tx_bytes: self.tx_bytes.saturating_sub(old.tx_bytes),
            rx_frag_packets: self.rx_frag_packets.saturating_sub(old.rx_frag_packets),
            tx_unmeasured_packets: self
                .tx_unmeasured_packets
                .saturating_sub(old.tx_unmeasured_packets),
        }
    }

    fn add(&mut self, other: Self) {
        self.rx_packets = self.rx_packets.saturating_add(other.rx_packets);
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
        self.tx_packets = self.tx_packets.saturating_add(other.tx_packets);
        self.tx_bytes = self.tx_bytes.saturating_add(other.tx_bytes);
        self.rx_frag_packets = self.rx_frag_packets.saturating_add(other.rx_frag_packets);
        self.tx_unmeasured_packets = self
            .tx_unmeasured_packets
            .saturating_add(other.tx_unmeasured_packets);
    }
}

#[derive(Clone)]
struct Item {
    socket: Socket,
    delta: Counter,
    errors: Errors,
    elapsed: f64,
    ambiguous: bool,
    ready: bool,
}

#[derive(Clone, Copy)]
enum Sort {
    Queue,
    Activity,
    Rx,
    Tx,
    Errors,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Self::Queue => Self::Activity,
            Self::Activity => Self::Rx,
            Self::Rx => Self::Tx,
            Self::Tx => Self::Errors,
            Self::Errors => Self::Queue,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::Activity => "activity",
            Self::Rx => "RX",
            Self::Tx => "TX",
            Self::Errors => "errors",
        }
    }
    fn value(self, item: &Item) -> u64 {
        match self {
            Self::Queue => 0,
            Self::Activity => item.delta.rx_packets + item.delta.tx_packets,
            Self::Rx => item.delta.rx_packets,
            Self::Tx => item.delta.tx_packets,
            Self::Errors => item.errors.total(),
        }
    }
}

struct Screen {
    items: Vec<Item>,
    selected: usize,
    scroll: usize,
    sort: Sort,
    filter: Option<String>,
    interval: f64,
    started: Instant,
    owner_cache: HashMap<u32, String>,
    owner_refreshed: Option<Instant>,
    previous: HashMap<u32, (Counter, Errors)>,
    sampled: Option<Instant>,
    sample_interval: f64,
    sample_error: Option<String>,
}

impl Screen {
    fn new(args: Args) -> Self {
        Self {
            items: Vec::new(),
            selected: 0,
            scroll: 0,
            sort: Sort::Queue,
            filter: args.interface,
            interval: args.delay,
            started: Instant::now(),
            owner_cache: HashMap::new(),
            owner_refreshed: None,
            previous: HashMap::new(),
            sampled: None,
            sample_interval: 0.0,
            sample_error: None,
        }
    }

    fn sample(&mut self, bpf: &Bpf) -> Result<()> {
        let scan_started = Instant::now();
        let selected_inode = self.items.get(self.selected).map(|item| item.socket.inode);
        let mut sockets = diag::snapshot()?;
        let mut counts = HashMap::<(u32, u32), usize>::new();
        for socket in &mut sockets {
            socket.iface = diag::iface_name(socket.ifindex);
            *counts.entry((socket.ifindex, socket.queue)).or_default() += 1;
        }
        let inodes: HashSet<u32> = sockets
            .iter()
            .filter_map(|socket| {
                if self
                    .filter
                    .as_ref()
                    .is_none_or(|filter| filter == &socket.iface)
                {
                    Some(socket.inode)
                } else {
                    None
                }
            })
            .collect();
        if self
            .owner_refreshed
            .is_none_or(|last| scan_started.duration_since(last) >= Duration::from_secs(5))
            || inodes
                .iter()
                .any(|inode| !self.owner_cache.contains_key(inode))
        {
            self.owner_cache = diag::owners(&inodes);
            for inode in &inodes {
                self.owner_cache.entry(*inode).or_insert_with(|| "-".into());
            }
            self.owner_refreshed = Some(scan_started);
        }
        let now = Instant::now();
        let elapsed = self
            .sampled
            .map_or(0.0, |last| now.duration_since(last).as_secs_f64());
        let mut previous = HashMap::new();
        let mut items = Vec::new();
        for mut socket in sockets.drain(..) {
            if self
                .filter
                .as_ref()
                .is_some_and(|name| name != &socket.iface)
            {
                continue;
            }
            socket.owner = self
                .owner_cache
                .get(&socket.inode)
                .cloned()
                .unwrap_or_else(|| "-".into());
            let counter = bpf.counters(socket.ifindex, socket.queue)?;
            let old = self.previous.get(&socket.inode).copied();
            let delta = old.map_or(Counter::default(), |(value, _)| counter.delta(value));
            let errors = old.map_or(Errors::default(), |(_, value)| socket.errors.delta(value));
            let ambiguous = counts
                .get(&(socket.ifindex, socket.queue))
                .copied()
                .unwrap_or(0)
                > 1;
            previous.insert(socket.inode, (counter, socket.errors));
            let ready = old.is_some() && elapsed > 0.0 && socket.ifindex != 0;
            items.push(Item {
                socket,
                delta,
                errors,
                elapsed,
                ambiguous,
                ready,
            });
        }
        sort_items(&mut items, self.sort);
        self.items = items;
        self.previous = previous;
        self.sampled = Some(now);
        self.sample_interval = elapsed;
        self.selected = selected_inode
            .and_then(|inode| {
                self.items
                    .iter()
                    .position(|item| item.socket.inode == inode)
            })
            .unwrap_or_else(|| self.selected.min(self.items.len().saturating_sub(1)));
        Ok(())
    }

    fn move_selection(&mut self, down: bool) {
        if down {
            self.selected = (self.selected + 1).min(self.items.len().saturating_sub(1));
        } else {
            self.selected = self.selected.saturating_sub(1);
        }
    }
}

fn sort_items(items: &mut [Item], sort: Sort) {
    items.sort_by(|a, b| {
        a.socket
            .iface
            .cmp(&b.socket.iface)
            .then_with(|| sort.value(b).cmp(&sort.value(a)))
            .then_with(|| a.socket.queue.cmp(&b.socket.queue))
            .then_with(|| a.socket.inode.cmp(&b.socket.inode))
    });
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, crossterm::cursor::Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
        let _ = terminal::disable_raw_mode();
    }
}

fn rate(value: u64, elapsed: f64) -> String {
    let rate = value as f64 / elapsed.max(0.001);
    if value > 0 && rate < 0.01 {
        "<0.01".into()
    } else if rate < 1.0 && value > 0 {
        format!("{rate:.2}")
    } else if rate >= 1_000_000.0 {
        format!("{:.1}M", rate / 1_000_000.0)
    } else if rate >= 10_000.0 {
        format!("{:.1}k", rate / 1000.0)
    } else {
        format!("{rate:.0}")
    }
}

fn throughput(bytes: u64, elapsed: f64, partial: bool) -> String {
    let number = bytes as f64 * 8.0 / elapsed.max(0.001) / 1_000_000.0;
    format!("{}{number:.3}", if partial { ">=" } else { "" })
}

fn text_sample(screen: &Screen, index: u32, count: u32) -> String {
    let mut output = format!(
        "# sample {index}/{count}  interval {:.3}s  sockets {}\n",
        screen.sample_interval,
        screen.items.len()
    );
    output.push_str(&format!(
        "{:<14} {:>2} {:<4} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8} {:>12} {:>10}  {}\n",
        "IFACE",
        "Q",
        "MODE",
        "RXpps",
        "TXpps",
        "RXMb/s",
        "TXMb/s",
        "RXERR/s",
        "TXERR/s",
        "FILL_EMPTY/s",
        "TX_EMPTY/s",
        "PROCESS"
    ));
    for item in &screen.items {
        let traffic = item.ready && !item.ambiguous;
        let rx_pps = if traffic {
            rate(item.delta.rx_packets, item.elapsed)
        } else {
            "-".into()
        };
        let tx_pps = if traffic {
            format!(
                "{}{}",
                if item.delta.tx_unmeasured_packets > 0 {
                    ">="
                } else {
                    ""
                },
                rate(item.delta.tx_packets, item.elapsed)
            )
        } else {
            "-".into()
        };
        let rx_bw = if traffic {
            throughput(
                item.delta.rx_bytes,
                item.elapsed,
                item.delta.rx_frag_packets > 0,
            )
        } else {
            "-".into()
        };
        let tx_bw = if traffic {
            throughput(
                item.delta.tx_bytes,
                item.elapsed,
                item.delta.tx_unmeasured_packets > 0,
            )
        } else {
            "-".into()
        };
        let event_rate = |value| {
            if item.ready {
                rate(value, item.elapsed)
            } else {
                "-".into()
            }
        };
        let status = if item.ambiguous { " [ambiguous]" } else { "" };
        output.push_str(&format!(
            "{:<14} {:>2} {:<4} {:>7} {:>7} {:>8} {:>8} {:>8} {:>8} {:>12} {:>10}  {}{}\n",
            item.socket.iface,
            item.socket.queue,
            if item.socket.zero_copy { "zc" } else { "copy" },
            rx_pps,
            tx_pps,
            rx_bw,
            tx_bw,
            event_rate(item.errors.rx_total()),
            event_rate(item.errors.tx_total()),
            event_rate(item.errors.fill_empty),
            event_rate(item.errors.tx_empty),
            item.socket.owner,
            status
        ));
    }
    if screen.items.is_empty() {
        output.push_str("(no AF_XDP sockets in this network namespace)\n");
    }
    output
}

fn run_text(bpf: &Bpf, screen: &mut Screen, count: u32, stop: &AtomicBool) -> Result<()> {
    let delay = Duration::from_secs_f64(screen.interval);
    let mut next = Instant::now() + delay;
    let mut stdout = io::stdout().lock();
    for index in 1..=count {
        while !stop.load(Ordering::Relaxed) && Instant::now() < next {
            std::thread::sleep(
                next.saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        screen
            .sample(bpf)
            .with_context(|| format!("sample {index}"))?;
        stdout.write_all(text_sample(screen, index, count).as_bytes())?;
        stdout.flush()?;
        next = Instant::now() + delay;
    }
    Ok(())
}

fn draw(frame: &mut ratatui::Frame<'_>, screen: &mut Screen) {
    let area = frame.area();
    if area.width < 74 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("xsktop needs at least 74 x 20 columns"),
            area,
        );
        return;
    }
    let wide = area.width >= 104;
    let detail_height = if wide { 10 } else { 11 };
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(detail_height),
            Constraint::Length(1),
        ])
        .split(area);
    let total_rx: u64 = screen
        .items
        .iter()
        .filter(|item| !item.ambiguous)
        .map(|item| item.delta.rx_packets)
        .sum();
    let total_tx: u64 = screen
        .items
        .iter()
        .filter(|item| !item.ambiguous)
        .map(|item| item.delta.tx_packets)
        .sum();
    let partial_rx = screen.items.iter().any(|item| item.ambiguous);
    let partial_tx = partial_rx
        || screen
            .items
            .iter()
            .any(|item| item.ready && item.delta.tx_unmeasured_packets > 0);
    let elapsed = screen.sample_interval.max(0.001);
    let header = format!(
        "{} XSK  |  RX {}{} pps  TX {}{} pps  |  up {:.0}s  |  sort {}{}",
        screen.items.len(),
        if partial_rx { ">=" } else { "" },
        rate(total_rx, elapsed),
        if partial_tx { ">=" } else { "" },
        rate(total_tx, elapsed),
        screen.started.elapsed().as_secs_f64(),
        screen.sort.label(),
        screen
            .sample_error
            .as_ref()
            .map_or(String::new(), |error| format!("  |  SAMPLE ERROR: {error}"))
    );
    frame.render_widget(
        Paragraph::new(header).block(Block::default().title(" xsktop ").borders(Borders::ALL)),
        panes[0],
    );
    let header = Row::new([
        "IFACE",
        "Q",
        "MODE",
        "RX pps",
        "TX pps",
        "RX Mb/s",
        "TX Mb/s",
        if area.width >= 100 {
            "RX err/s"
        } else {
            "RXe/s"
        },
        if area.width >= 100 {
            "TX err/s"
        } else {
            "TXe/s"
        },
        "PROCESS",
    ])
    .style(
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    );
    let capacity = panes[1].height.saturating_sub(3) as usize;
    if screen.selected < screen.scroll {
        screen.scroll = screen.selected;
    }
    if capacity > 0 && screen.selected >= screen.scroll + capacity {
        screen.scroll = screen.selected + 1 - capacity;
    }
    let rows = screen
        .items
        .iter()
        .enumerate()
        .skip(screen.scroll)
        .take(capacity)
        .map(|(idx, item)| {
            let hidden = item.ambiguous || !item.ready;
            let show = |number| {
                if hidden {
                    "-".into()
                } else {
                    rate(number, item.elapsed)
                }
            };
            let rx_bw = if hidden {
                "-".into()
            } else {
                throughput(
                    item.delta.rx_bytes,
                    item.elapsed,
                    item.delta.rx_frag_packets > 0,
                )
            };
            let tx_bw = if hidden {
                "-".into()
            } else {
                throughput(
                    item.delta.tx_bytes,
                    item.elapsed,
                    item.delta.tx_unmeasured_packets > 0,
                )
            };
            let mode = if item.socket.zero_copy { "zc" } else { "copy" };
            let first_in_group =
                idx == screen.scroll || screen.items[idx - 1].socket.iface != item.socket.iface;
            let mut cells = vec![
                if first_in_group {
                    item.socket.iface.clone()
                } else {
                    String::new()
                },
                item.socket.queue.to_string(),
                mode.into(),
                show(item.delta.rx_packets),
            ];
            cells.push(if !hidden && item.delta.tx_unmeasured_packets > 0 {
                format!(">={}", show(item.delta.tx_packets))
            } else {
                show(item.delta.tx_packets)
            });
            cells.push(rx_bw);
            cells.push(tx_bw);
            cells.push(if item.ready {
                rate(item.errors.rx_total(), item.elapsed)
            } else {
                "-".into()
            });
            cells.push(if item.ready {
                rate(item.errors.tx_total(), item.elapsed)
            } else {
                "-".into()
            });
            cells.push(item.socket.owner.clone());
            let style = if idx == screen.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if item.ambiguous {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            let cells = cells.into_iter().enumerate().map(|(column, value)| {
                let cell = Cell::from(value);
                if column == 0 && first_in_group && idx != screen.selected {
                    cell.style(
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                } else if idx != screen.selected
                    && ((column == 7 && item.errors.rx_total() > 0)
                        || (column == 8 && item.errors.tx_total() > 0))
                {
                    cell.style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )
                } else {
                    cell
                }
            });
            Row::new(cells).style(style)
        });
    let widths = if area.width >= 100 {
        vec![
            Constraint::Length(15),
            Constraint::Length(4),
            Constraint::Length(5),
            Constraint::Length(9),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(10),
        ]
    } else if area.width >= 80 {
        vec![
            Constraint::Length(11),
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Min(9),
        ]
    } else {
        vec![
            Constraint::Length(11),
            Constraint::Length(2),
            Constraint::Length(4),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(7),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(10),
        ]
    };
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(" AF_XDP sockets ")
                .borders(Borders::ALL),
        );
    frame.render_widget(table, panes[1]);
    let detail = if let Some(item) = screen.items.get(screen.selected) {
        let s = &item.socket;
        let note = if item.ambiguous {
            "AMBIGUOUS: multiple XSKs on this interface/queue"
        } else if item.delta.rx_frag_packets > 0 || item.delta.tx_unmeasured_packets > 0 {
            ">= bandwidth: multi-buffer or batch bytes partly unavailable"
        } else {
            "RX = enqueued to XSK; TX = dequeued from XSK (not wire TX)"
        };
        let bw = if item.ambiguous || !item.ready {
            "RX/TX: - / - Mb/s".into()
        } else {
            format!(
                "RX/TX: {} / {} Mb/s",
                throughput(
                    item.delta.rx_bytes,
                    item.elapsed,
                    item.delta.rx_frag_packets > 0
                ),
                throughput(
                    item.delta.tx_bytes,
                    item.elapsed,
                    item.delta.tx_unmeasured_packets > 0
                )
            )
        };
        let show_error_rate = |value| {
            if item.ready {
                rate(value, item.elapsed)
            } else {
                "-".into()
            }
        };
        let err_rate = format!(
            "ERR/s: RX drop {} invalid {} full {} | TX invalid {}",
            show_error_rate(item.errors.rx_dropped),
            show_error_rate(item.errors.rx_invalid),
            show_error_rate(item.errors.rx_full),
            show_error_rate(item.errors.tx_invalid)
        );
        let event_rate = format!(
            "Events/s: UMEM fill empty {} | TX empty {}",
            show_error_rate(item.errors.fill_empty),
            show_error_rate(item.errors.tx_empty)
        );
        format!("{} / q{}  {}  inode {}\n{}{}UMEM {} KiB; chunk {} B\nRing capacity RX/TX/FILL/CQ: {}/{}/{}/{}\n{}\nErrors total: RX drop {} invalid {} full {} | TX invalid {}\n{}\nEvents total: UMEM fill empty {} | TX empty {}\n{}",
            s.iface, s.queue, s.owner, s.inode, bw, if wide { " | " } else { "\n" }, s.umem_bytes / 1024, s.chunk_bytes,
            s.rings[0], s.rings[1], s.rings[2], s.rings[3], err_rate, s.errors.rx_dropped,
            s.errors.rx_invalid, s.errors.rx_full, s.errors.tx_invalid,
            event_rate, s.errors.fill_empty, s.errors.tx_empty, note)
    } else {
        "No AF_XDP sockets in this network namespace".into()
    };
    frame.render_widget(
        Paragraph::new(detail).block(Block::default().title(" Details ").borders(Borders::ALL)),
        panes[2],
    );
    frame.render_widget(
        Paragraph::new(
            "j/k or arrows select  |  s sort  |  q quit  |  Mb/s = packet bytes, not wire rate",
        ),
        panes[3],
    );
}

fn run(args: Args) -> Result<()> {
    if args.count.is_none()
        && (!io::stdout().is_terminal() || std::env::var("TERM").is_ok_and(|term| term == "dumb"))
    {
        bail!("xsktop requires an interactive terminal");
    }
    let count = args.count;
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || handler_stop.store(true, Ordering::Relaxed))?;
    preflight()?;
    let bpf = Bpf::attach()?;
    let mut screen = Screen::new(args);
    screen.sample(&bpf)?;
    if let Some(count) = count {
        return run_text(&bpf, &mut screen, count.get(), &stop);
    }
    let _guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let delay = Duration::from_secs_f64(screen.interval);
    let mut next = Instant::now() + delay;
    while !stop.load(Ordering::Relaxed) {
        terminal.draw(|frame| draw(frame, &mut screen))?;
        let wait = next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        if event::poll(wait)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => screen.move_selection(true),
                    KeyCode::Up | KeyCode::Char('k') => screen.move_selection(false),
                    KeyCode::Char('s') => screen.sort = screen.sort.next(),
                    _ => {}
                }
            }
        }
        if Instant::now() >= next {
            match screen.sample(&bpf) {
                Ok(()) => screen.sample_error = None,
                Err(error) => screen.sample_error = Some(format!("{error:#}")),
            }
            next = Instant::now() + delay;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("xsktop: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn counter_delta_does_not_underflow_on_reset() {
        let old = Counter {
            rx_packets: 100,
            tx_bytes: 20,
            ..Default::default()
        };
        let new = Counter {
            rx_packets: 5,
            tx_bytes: 30,
            ..Default::default()
        };
        assert_eq!(new.delta(old).rx_packets, 0);
        assert_eq!(new.delta(old).tx_bytes, 10);
    }

    #[test]
    fn sums_per_cpu_counters() {
        let mut total = Counter {
            rx_packets: 10,
            tx_bytes: 100,
            ..Default::default()
        };
        total.add(Counter {
            rx_packets: 3,
            tx_bytes: 50,
            ..Default::default()
        });
        assert_eq!(total.rx_packets, 13);
        assert_eq!(total.tx_bytes, 150);
    }

    #[test]
    fn delay_rejects_non_finite_and_too_short_values() {
        for text in ["0", "0.01", "NaN", "inf", "wrong"] {
            assert!(positive_interval(text).is_err());
        }
        assert_eq!(positive_interval("0.2").unwrap(), 0.2);
    }

    #[test]
    fn missing_diag_handler_has_actionable_error() {
        let error = diagnose_diag_error(io::Error::from_raw_os_error(libc::ENOENT).into());
        let message = format!("{error:#}");
        assert!(message.contains("CONFIG_XDP_SOCKETS_DIAG"));
        assert!(message.contains("No such file or directory"));
    }

    #[test]
    fn count_accepts_positive_samples_only() {
        let args = Args::try_parse_from(["xsktop", "-c", "2", "-d", "0.2"]).unwrap();
        assert_eq!(args.count.map(NonZeroU32::get), Some(2));
        assert!(Args::try_parse_from(["xsktop", "-c", "0"]).is_err());
    }

    #[test]
    fn nonzero_rates_do_not_round_to_zero() {
        assert_eq!(rate(0, 5.0), "0");
        assert_eq!(rate(1, 5.0), "0.20");
        assert_eq!(rate(1, 1_000.0), "<0.01");
        assert_eq!(rate(5, 1.0), "5");
    }

    #[test]
    fn header_marks_unmeasured_tx_as_a_lower_bound() {
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: None,
        });
        screen.sample_interval = 1.0;
        screen.items.push(Item {
            socket: Socket {
                iface: "eth0".into(),
                ..Default::default()
            },
            delta: Counter {
                rx_packets: 7,
                tx_packets: 10,
                tx_unmeasured_packets: 3,
                ..Default::default()
            },
            errors: Errors::default(),
            elapsed: 1.0,
            ambiguous: false,
            ready: true,
        });
        terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
        let buffer = terminal.backend().buffer();
        let header = (0..120)
            .map(|column| buffer[(column, 1)].symbol())
            .collect::<String>();
        assert!(header.contains("RX 7 pps  TX >=10 pps"));
    }

    #[test]
    fn text_sample_keeps_events_separate_from_errors() {
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: NonZeroU32::new(1),
        });
        screen.sample_interval = 2.0;
        let empty = text_sample(&screen, 1, 1);
        assert!(empty.contains("no AF_XDP sockets"));
        assert!(empty.contains("interval 2.000s"));
        screen.items.push(Item {
            socket: Socket {
                iface: "eth0".into(),
                owner: "worker(42)".into(),
                ..Default::default()
            },
            delta: Counter {
                rx_packets: 20,
                tx_packets: 10,
                rx_bytes: 2000,
                tx_bytes: 1000,
                ..Default::default()
            },
            errors: Errors {
                rx_dropped: 4,
                tx_invalid: 6,
                fill_empty: 20,
                tx_empty: 8,
                ..Default::default()
            },
            elapsed: 2.0,
            ambiguous: false,
            ready: true,
        });
        let output = text_sample(&screen, 1, 1);
        assert!(output.contains("sample 1/1  interval 2.000s"));
        assert!(output.contains("RXERR/s"));
        assert!(output.contains("TXERR/s"));
        assert!(output.contains("FILL_EMPTY/s"));
        assert!(output.contains("TX_EMPTY/s"));
        assert!(output.contains("eth0"));
        assert!(output.contains("10"));
        assert!(output.contains("worker(42)"));
        let fields = output
            .lines()
            .nth(2)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        assert_eq!(&fields[7..11], &["2", "3", "10", "4"]);
    }

    #[test]
    fn renders_empty_and_populated_screens_at_supported_widths() {
        for (width, height) in [(74, 20), (80, 24), (100, 30), (120, 40)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut screen = Screen::new(Args {
                interface: None,
                delay: 1.0,
                count: None,
            });
            terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
            screen.items.push(Item {
                socket: Socket {
                    iface: "eth0".into(),
                    queue: 3,
                    owner: "worker(42)".into(),
                    ..Default::default()
                },
                delta: Counter {
                    rx_packets: 100,
                    tx_packets: 200,
                    ..Default::default()
                },
                errors: Errors::default(),
                elapsed: 1.0,
                ambiguous: false,
                ready: true,
            });
            terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
        }
    }

    #[test]
    fn groups_interfaces_and_sorts_queues_by_default() {
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: None,
        });
        for (iface, queue, rx_packets) in [("eth1", 0, 1000), ("eth0", 1, 500), ("eth0", 0, 100)] {
            screen.items.push(Item {
                socket: Socket {
                    iface: iface.into(),
                    queue,
                    ..Default::default()
                },
                delta: Counter {
                    rx_packets,
                    ..Default::default()
                },
                errors: Errors::default(),
                elapsed: 1.0,
                ambiguous: false,
                ready: true,
            });
        }
        sort_items(&mut screen.items, screen.sort);
        let keys = screen
            .items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(keys, [("eth0", 0), ("eth0", 1), ("eth1", 0)]);

        sort_items(&mut screen.items, Sort::Activity);
        let keys = screen
            .items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(keys, [("eth0", 1), ("eth0", 0), ("eth1", 0)]);
    }

    #[test]
    fn compact_table_shows_bandwidth_and_groups_interface_rows() {
        for width in [74, 80, 100, 120] {
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            let mut screen = Screen::new(Args {
                interface: None,
                delay: 1.0,
                count: None,
            });
            for queue in [0, 1] {
                screen.items.push(Item {
                    socket: Socket {
                        iface: "eth0".into(),
                        queue,
                        ..Default::default()
                    },
                    delta: Counter {
                        rx_bytes: 2000,
                        tx_bytes: 1000,
                        ..Default::default()
                    },
                    errors: if queue == 0 {
                        Errors {
                            rx_dropped: 1,
                            rx_invalid: 2,
                            rx_full: 3,
                            tx_invalid: 8,
                            fill_empty: 100,
                            tx_empty: 200,
                        }
                    } else {
                        Errors::default()
                    },
                    elapsed: 2.0,
                    ambiguous: false,
                    ready: true,
                });
            }
            terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
            let buffer = terminal.backend().buffer();
            let line = |row| {
                (0..width)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            };
            let header = line(4);
            assert!(header.contains("RX pps"), "width {width}");
            assert!(header.contains("TX pps"), "width {width}");
            assert!(header.contains("RX Mb/s"), "width {width}");
            assert!(
                header.find("TX pps") < header.find("RX Mb/s"),
                "width {width}"
            );
            assert!(line(4).contains("TX Mb/s"), "width {width}");
            assert!(header.contains(if width >= 100 { "RX err/s" } else { "RXe/s" }));
            assert!(header.contains(if width >= 100 { "TX err/s" } else { "TXe/s" }));
            assert!(line(5).contains("eth0"), "width {width}");
            assert!(line(5).contains("0.008"), "width {width}");
            assert!(line(5).contains("0.004"), "width {width}");
            let data_row = line(5).chars().skip(1).collect::<String>();
            assert_eq!(
                &data_row.split_whitespace().collect::<Vec<_>>()[..9],
                &["eth0", "0", "copy", "0", "0", "0.008", "0.004", "3", "4"],
                "width {width}"
            );
            assert_eq!(
                line(6).chars().skip(1).take(11).collect::<String>(),
                "           "
            );
            assert!(line(6).contains("0.008"), "width {width}");
        }
    }

    #[test]
    fn ambiguous_queue_hides_traffic_but_keeps_socket_errors() {
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: None,
        });
        screen.items.push(Item {
            socket: Socket {
                iface: "eth0".into(),
                owner: "worker(42)".into(),
                ..Default::default()
            },
            delta: Counter {
                rx_packets: 100,
                tx_packets: 200,
                ..Default::default()
            },
            errors: Errors {
                rx_dropped: 7,
                ..Default::default()
            },
            elapsed: 1.0,
            ambiguous: true,
            ready: true,
        });
        terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
        let buffer = terminal.backend().buffer();
        let line = |row| {
            (0..120)
                .map(|column| buffer[(column, row)].symbol())
                .collect::<String>()
        };
        assert!(line(1).contains("RX >=0 pps  TX >=0 pps"));
        let data_row = line(5).chars().skip(1).collect::<String>();
        assert_eq!(
            data_row.split_whitespace().take(8).collect::<Vec<_>>(),
            ["eth0", "0", "copy", "-", "-", "-", "-", "7"]
        );
    }

    #[test]
    fn detail_separates_error_and_empty_ring_rates_from_totals() {
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: None,
        });
        screen.items.push(Item {
            socket: Socket {
                iface: "eth0".into(),
                errors: Errors {
                    rx_dropped: 100,
                    fill_empty: 500,
                    ..Default::default()
                },
                ..Default::default()
            },
            errors: Errors {
                rx_dropped: 4,
                fill_empty: 20,
                ..Default::default()
            },
            elapsed: 2.0,
            ambiguous: false,
            ready: true,
            delta: Counter::default(),
        });
        terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
        let buffer = terminal.backend().buffer();
        let lines = (0..24)
            .map(|row| {
                (0..120)
                    .map(|column| buffer[(column, row)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        assert!(lines.iter().any(|line| line.contains("ERR/s: RX drop 2")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Errors total: RX drop 100")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Events/s: UMEM fill empty 10")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Events total: UMEM fill empty 500")));
    }
}
