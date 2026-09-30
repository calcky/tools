mod diag;

use anyhow::{bail, Context, Result};
use clap::Parser;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use diag::{Errors, Socket};
use libbpf_rs::{Link, MapCore, MapFlags, Object, ObjectBuilder};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Queue,
    RxPps,
    TxPps,
    RxMbps,
    TxMbps,
    RxErrors,
    TxErrors,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Self::Queue => Self::RxPps,
            Self::RxPps => Self::TxPps,
            Self::TxPps => Self::RxMbps,
            Self::RxMbps => Self::TxMbps,
            Self::TxMbps => Self::RxErrors,
            Self::RxErrors => Self::TxErrors,
            Self::TxErrors => Self::Queue,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Queue => "queue",
            Self::RxPps => "RX pps",
            Self::TxPps => "TX pps",
            Self::RxMbps => "RX Mb/s",
            Self::TxMbps => "TX Mb/s",
            Self::RxErrors => "RX err/s",
            Self::TxErrors => "TX err/s",
        }
    }
    fn column(self) -> usize {
        match self {
            Self::Queue => 1,
            Self::RxPps => 3,
            Self::TxPps => 4,
            Self::RxMbps => 5,
            Self::TxMbps => 6,
            Self::RxErrors => 7,
            Self::TxErrors => 8,
        }
    }
    fn value(self, item: &Item) -> Option<f64> {
        if self == Self::Queue {
            return Some(item.socket.queue as f64);
        }
        if !item.ready
            || (item.ambiguous
                && matches!(
                    self,
                    Self::RxPps | Self::TxPps | Self::RxMbps | Self::TxMbps
                ))
        {
            return None;
        }
        let count = match self {
            Self::Queue => unreachable!(),
            Self::RxPps => item.delta.rx_packets,
            Self::TxPps => item.delta.tx_packets,
            Self::RxMbps => item.delta.rx_bytes,
            Self::TxMbps => item.delta.tx_bytes,
            Self::RxErrors => item.errors.rx_total(),
            Self::TxErrors => item.errors.tx_total(),
        };
        Some(count as f64 / item.elapsed.max(0.001))
    }
}

struct Screen {
    items: Vec<Item>,
    selected: usize,
    scroll: usize,
    sort: Sort,
    sort_descending: bool,
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
            sort_descending: false,
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
        sort_items(&mut items, self.sort, self.sort_descending);
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

    fn set_sort(&mut self, sort: Sort) {
        let selected_inode = self.items.get(self.selected).map(|item| item.socket.inode);
        if self.sort == sort {
            self.sort_descending = !self.sort_descending;
        } else {
            self.sort = sort;
            self.sort_descending = sort != Sort::Queue;
        }
        sort_items(&mut self.items, self.sort, self.sort_descending);
        if let Some(inode) = selected_inode {
            if let Some(index) = self
                .items
                .iter()
                .position(|item| item.socket.inode == inode)
            {
                self.selected = index;
            }
        }
    }
}

fn sort_items(items: &mut [Item], sort: Sort, descending: bool) {
    let mut iface_rates = HashMap::<String, (f64, bool)>::new();
    if sort != Sort::Queue {
        for item in items.iter() {
            let entry = iface_rates.entry(item.socket.iface.clone()).or_default();
            if let Some(value) = sort.value(item) {
                entry.0 += value;
                entry.1 = true;
            }
        }
    }
    let compare = |left: Option<f64>, right: Option<f64>| match (left, right) {
        (Some(left), Some(right)) => {
            if descending {
                right.total_cmp(&left)
            } else {
                left.total_cmp(&right)
            }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    };
    let iface_rate = |iface: &str| {
        iface_rates
            .get(iface)
            .and_then(|(rate, valid)| valid.then_some(*rate))
    };
    items.sort_by(|a, b| {
        let by_iface = if sort == Sort::Queue {
            std::cmp::Ordering::Equal
        } else {
            compare(iface_rate(&a.socket.iface), iface_rate(&b.socket.iface))
        };
        by_iface
            .then_with(|| a.socket.iface.cmp(&b.socket.iface))
            .then_with(|| compare(sort.value(a), sort.value(b)))
            .then_with(|| a.socket.queue.cmp(&b.socket.queue))
            .then_with(|| a.socket.inode.cmp(&b.socket.inode))
    });
}

fn screen_panes(area: Rect) -> [Rect; 4] {
    Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(4),
        Constraint::Length(12),
        Constraint::Length(1),
    ])
    .areas(area)
}

fn table_widths(width: u16) -> [Constraint; 10] {
    let lengths = if width >= 100 {
        [15, 4, 5, 9, 9, 10, 10, 8, 8, 10]
    } else if width >= 80 {
        [11, 3, 4, 7, 7, 8, 8, 6, 6, 9]
    } else {
        [11, 2, 4, 6, 6, 7, 7, 5, 5, 10]
    };
    std::array::from_fn(|index| {
        if index == 9 {
            Constraint::Min(lengths[index])
        } else {
            Constraint::Length(lengths[index])
        }
    })
}

fn header_sort(area: Rect, column: u16, row: u16) -> Option<Sort> {
    if area.width < 74 || area.height < 20 {
        return None;
    }
    let table = screen_panes(area)[1];
    if row != table.y + 1 {
        return None;
    }
    let inner = Rect::new(
        table.x + 1,
        table.y + 1,
        table.width.saturating_sub(2),
        table.height.saturating_sub(2),
    );
    let columns = Layout::horizontal(table_widths(area.width))
        .spacing(1)
        .split(inner);
    let index = columns
        .iter()
        .position(|rect| rect.x <= column && column < rect.right())?;
    match index {
        1 => Some(Sort::Queue),
        3 => Some(Sort::RxPps),
        4 => Some(Sort::TxPps),
        5 => Some(Sort::RxMbps),
        6 => Some(Sort::TxMbps),
        7 => Some(Sort::RxErrors),
        8 => Some(Sort::TxErrors),
        _ => None,
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            crossterm::cursor::Hide
        ) {
            let _ = execute!(
                io::stdout(),
                DisableMouseCapture,
                LeaveAlternateScreen,
                crossterm::cursor::Show
            );
            let _ = terminal::disable_raw_mode();
            return Err(error.into());
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            DisableMouseCapture,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
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

fn detail_metric(
    label: &str,
    delta: u64,
    total: u64,
    item: &Item,
    is_error: bool,
) -> Line<'static> {
    let current = if item.ready {
        rate(delta, item.elapsed)
    } else {
        "-".into()
    };
    let color = if is_error && delta > 0 {
        Color::Yellow
    } else {
        Color::Reset
    };
    Line::from(vec![
        Span::raw(format!("{label:<15} ")),
        Span::styled(
            format!("{current:>7}"),
            Style::default()
                .fg(color)
                .add_modifier(if is_error && delta > 0 {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
        Span::styled(
            format!(" {total:>10}"),
            Style::default().fg(Color::DarkGray),
        ),
    ])
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
    let panes = screen_panes(area);
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
        "{} XSK  |  RX {}{} pps  TX {}{} pps  |  up {:.0}s  |  sort {} {}{}",
        screen.items.len(),
        if partial_rx { ">=" } else { "" },
        rate(total_rx, elapsed),
        if partial_tx { ">=" } else { "" },
        rate(total_tx, elapsed),
        screen.started.elapsed().as_secs_f64(),
        screen.sort.label(),
        if screen.sort_descending {
            "desc"
        } else {
            "asc"
        },
        screen
            .sample_error
            .as_ref()
            .map_or(String::new(), |error| format!("  |  SAMPLE ERROR: {error}"))
    );
    frame.render_widget(
        Paragraph::new(header).block(Block::default().title(" xsktop ").borders(Borders::ALL)),
        panes[0],
    );
    let header_labels = [
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
    ];
    let header = Row::new(header_labels.into_iter().enumerate().map(|(index, label)| {
        let cell = Cell::from(label);
        if index == screen.sort.column() {
            cell.style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::UNDERLINED | Modifier::BOLD),
            )
        } else {
            cell
        }
    }))
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
    let table = Table::new(rows, table_widths(area.width))
        .header(header)
        .column_spacing(1)
        .block(
            Block::default()
                .title(" AF_XDP sockets ")
                .borders(Borders::ALL),
        );
    frame.render_widget(table, panes[1]);
    if let Some(item) = screen.items.get(screen.selected) {
        let socket = &item.socket;
        let detail_panes = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(7),
                Constraint::Length(4),
            ])
            .split(panes[2]);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!("{} / q{}", socket.iface, socket.queue),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("  {}  inode {}", socket.owner, socket.inode)),
            ])),
            detail_panes[0],
        );
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(detail_panes[1]);
        let metric_header = Line::styled(
            format!("{:<15} {:>7} {:>10}", "", "rate/s", "total"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
        let errors = vec![
            metric_header.clone(),
            detail_metric(
                "RX dropped",
                item.errors.rx_dropped,
                socket.errors.rx_dropped,
                item,
                true,
            ),
            detail_metric(
                "RX invalid",
                item.errors.rx_invalid,
                socket.errors.rx_invalid,
                item,
                true,
            ),
            detail_metric(
                "RX ring full",
                item.errors.rx_full,
                socket.errors.rx_full,
                item,
                true,
            ),
            detail_metric(
                "TX invalid",
                item.errors.tx_invalid,
                socket.errors.tx_invalid,
                item,
                true,
            ),
        ];
        frame.render_widget(
            Paragraph::new(errors).block(Block::default().title(" Errors ").borders(Borders::ALL)),
            columns[0],
        );
        let note = if item.ambiguous {
            "Shared queue: traffic hidden"
        } else if item.delta.rx_frag_packets > 0 || item.delta.tx_unmeasured_packets > 0 {
            ">= rates: incomplete byte count"
        } else {
            "RX/TX are XSK-side, not wire"
        };
        let events = vec![
            metric_header,
            detail_metric(
                "UMEM fill empty",
                item.errors.fill_empty,
                socket.errors.fill_empty,
                item,
                false,
            ),
            detail_metric(
                "TX empty",
                item.errors.tx_empty,
                socket.errors.tx_empty,
                item,
                false,
            ),
            Line::raw(""),
            Line::styled(
                note,
                Style::default().fg(
                    if item.ambiguous
                        || item.delta.rx_frag_packets > 0
                        || item.delta.tx_unmeasured_packets > 0
                    {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    },
                ),
            ),
        ];
        frame.render_widget(
            Paragraph::new(events).block(
                Block::default()
                    .title(" Events (not errors) ")
                    .borders(Borders::ALL),
            ),
            columns[1],
        );
        let config = format!(
            "UMEM {} KiB  |  chunk {} B  |  {}\nRings  RX {}  TX {}  FILL {}  CQ {}",
            socket.umem_bytes / 1024,
            socket.chunk_bytes,
            if socket.zero_copy {
                "zero-copy"
            } else {
                "copy"
            },
            socket.rings[0],
            socket.rings[1],
            socket.rings[2],
            socket.rings[3]
        );
        frame.render_widget(
            Paragraph::new(config).block(
                Block::default()
                    .title(" Config (capacities) ")
                    .borders(Borders::ALL),
            ),
            detail_panes[2],
        );
    } else {
        frame.render_widget(
            Paragraph::new("No AF_XDP sockets in this network namespace")
                .block(Block::default().title(" Details ").borders(Borders::ALL)),
            panes[2],
        );
    }
    frame.render_widget(
        Paragraph::new("click Q/rate/error header  |  s next sort  |  j/k select  |  q quit"),
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
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => screen.move_selection(true),
                    KeyCode::Up | KeyCode::Char('k') => screen.move_selection(false),
                    KeyCode::Char('s') => screen.set_sort(screen.sort.next()),
                    _ => {}
                },
                Event::Mouse(mouse) if mouse.kind == MouseEventKind::Down(MouseButton::Left) => {
                    let size = terminal.size()?;
                    let area = Rect::new(0, 0, size.width, size.height);
                    if let Some(sort) = header_sort(area, mouse.column, mouse.row) {
                        screen.set_sort(sort);
                    }
                }
                _ => {}
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
        sort_items(&mut screen.items, screen.sort, screen.sort_descending);
        let keys = screen
            .items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(keys, [("eth0", 0), ("eth0", 1), ("eth1", 0)]);

        sort_items(&mut screen.items, Sort::RxPps, true);
        let keys = screen
            .items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(keys, [("eth1", 0), ("eth0", 1), ("eth0", 0)]);
    }

    #[test]
    fn metric_sort_ranks_interface_totals_before_queues() {
        let make = |iface: &str, queue, packets, ambiguous| Item {
            socket: Socket {
                iface: iface.into(),
                queue,
                inode: packets + queue + 1,
                ..Default::default()
            },
            delta: Counter {
                rx_packets: packets as u64,
                ..Default::default()
            },
            errors: Errors::default(),
            elapsed: 1.0,
            ambiguous,
            ready: true,
        };
        let mut items = vec![
            make("eth1", 0, 150, false),
            make("eth0", 0, 100, false),
            make("eth0", 1, 90, false),
            make("eth2", 0, 1000, true),
            make("eth3", 0, 0, false),
        ];
        sort_items(&mut items, Sort::RxPps, true);
        let keys = items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                ("eth0", 0),
                ("eth0", 1),
                ("eth1", 0),
                ("eth3", 0),
                ("eth2", 0)
            ]
        );

        sort_items(&mut items, Sort::RxPps, false);
        let keys = items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                ("eth3", 0),
                ("eth1", 0),
                ("eth0", 1),
                ("eth0", 0),
                ("eth2", 0)
            ]
        );

        sort_items(&mut items, Sort::Queue, false);
        let keys = items
            .iter()
            .map(|item| (item.socket.iface.as_str(), item.socket.queue))
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                ("eth0", 0),
                ("eth0", 1),
                ("eth1", 0),
                ("eth2", 0),
                ("eth3", 0)
            ]
        );
    }

    #[test]
    fn metric_sort_uses_displayed_rate_and_keeps_unavailable_rows_last() {
        let make = |queue, packets, elapsed, ambiguous, ready| Item {
            socket: Socket {
                iface: "eth0".into(),
                queue,
                inode: queue + 1,
                ..Default::default()
            },
            delta: Counter {
                rx_packets: packets,
                rx_bytes: if queue == 0 { 10_000 } else { 1_000 },
                ..Default::default()
            },
            errors: Errors {
                rx_dropped: if queue == 2 { 50 } else { 0 },
                ..Default::default()
            },
            elapsed,
            ambiguous,
            ready,
        };
        let mut items = vec![
            make(0, 100, 1.0, false, true),
            make(1, 80, 0.2, false, true),
            make(2, 1000, 1.0, true, true),
            make(3, 1000, 1.0, false, false),
        ];
        sort_items(&mut items, Sort::RxPps, true);
        assert_eq!(
            items
                .iter()
                .map(|item| item.socket.queue)
                .collect::<Vec<_>>(),
            [1, 0, 2, 3]
        );
        sort_items(&mut items, Sort::RxPps, false);
        assert_eq!(
            items
                .iter()
                .map(|item| item.socket.queue)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        sort_items(&mut items, Sort::RxMbps, true);
        assert_eq!(
            items
                .iter()
                .map(|item| item.socket.queue)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        sort_items(&mut items, Sort::RxErrors, true);
        assert_eq!(
            items
                .iter()
                .map(|item| item.socket.queue)
                .collect::<Vec<_>>(),
            [2, 0, 1, 3]
        );
    }

    #[test]
    fn selecting_a_sort_column_reorders_immediately_without_changing_socket() {
        let mut screen = Screen::new(Args {
            interface: None,
            delay: 1.0,
            count: None,
        });
        for (queue, packets) in [(0, 10), (1, 100)] {
            screen.items.push(Item {
                socket: Socket {
                    iface: "eth0".into(),
                    queue,
                    inode: queue + 10,
                    ..Default::default()
                },
                delta: Counter {
                    rx_packets: packets,
                    ..Default::default()
                },
                errors: Errors::default(),
                elapsed: 1.0,
                ambiguous: false,
                ready: true,
            });
        }
        screen.set_sort(Sort::RxPps);
        assert!(screen.sort_descending);
        assert_eq!(screen.items[0].socket.queue, 1);
        assert_eq!(screen.items[screen.selected].socket.queue, 0);
        screen.set_sort(Sort::RxPps);
        assert!(!screen.sort_descending);
        assert_eq!(screen.items[0].socket.queue, 0);
        assert_eq!(screen.items[screen.selected].socket.queue, 0);
    }

    #[test]
    fn sortable_header_hitboxes_match_rendered_columns() {
        for width in [74, 80, 100, 120] {
            let area = Rect::new(0, 0, width, 24);
            let table = screen_panes(area)[1];
            let inner = Rect::new(table.x + 1, table.y + 1, table.width - 2, table.height - 2);
            let columns = Layout::horizontal(table_widths(width))
                .spacing(1)
                .split(inner);
            for sort in [
                Sort::Queue,
                Sort::RxPps,
                Sort::TxPps,
                Sort::RxMbps,
                Sort::TxMbps,
                Sort::RxErrors,
                Sort::TxErrors,
            ] {
                let column = columns[sort.column()];
                assert_eq!(header_sort(area, column.x, column.y), Some(sort));
                assert_eq!(header_sort(area, column.right() - 1, column.y), Some(sort));
                assert_eq!(header_sort(area, column.x, column.y + 1), None);
            }
            assert_eq!(header_sort(area, columns[0].x, inner.y), None);
            assert_eq!(header_sort(area, columns[2].x, inner.y), None);
            assert_eq!(header_sort(area, columns[9].x, inner.y), None);
            assert_eq!(header_sort(area, columns[3].right(), inner.y), None);

            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            let mut screen = Screen::new(Args {
                interface: None,
                delay: 1.0,
                count: None,
            });
            screen.set_sort(Sort::RxPps);
            terminal.draw(|frame| draw(frame, &mut screen)).unwrap();
            assert_eq!(
                terminal.backend().buffer()[(columns[3].x, inner.y)].fg,
                Color::Yellow
            );
        }
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
        for (width, height) in [(74, 20), (120, 24)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
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
                    umem_bytes: 16 * 1024 * 1024,
                    chunk_bytes: 4096,
                    rings: [2048; 4],
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
            let lines = (0..height)
                .map(|row| {
                    (0..width)
                        .map(|column| buffer[(column, row)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>();
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("Errors") && line.contains("Events (not errors)")),
                "width {width}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("Config (capacities)")),
                "width {width}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("RX dropped") && line.contains("100")),
                "width {width}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("UMEM fill empty") && line.contains("500")),
                "width {width}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("UMEM 16384 KiB") && line.contains("chunk 4096 B")),
                "width {width}"
            );
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("Rings  RX 2048  TX 2048  FILL 2048  CQ 2048")),
                "width {width}"
            );
        }
    }
}
