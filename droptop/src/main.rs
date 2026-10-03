mod collect;
mod model;

use anyhow::{bail, Result};
use clap::Parser;
use collect::{DropEvent, Probe, Snapshot};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::{GroupBy, GroupKey, Row};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table},
    Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, IsTerminal, Stdout, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "Continuously aggregate kernel skb drop reasons and call stacks"
)]
struct Args {
    #[arg(
        short = 'i',
        value_name = "IFACE",
        help = "Only drops attributed to this interface in the current netns"
    )]
    interface: Option<String>,
    #[arg(short = 'd', default_value_t = 1.0, value_parser = interval, help = "Sampling interval in seconds (default: 1)")]
    delay: f64,
    #[arg(short = 'c', value_parser = clap::value_parser!(u32).range(1..), help = "Print N interval samples instead of the live window")]
    count: Option<u32>,
    #[arg(short = 'g', value_enum, default_value_t = GroupBy::Pair, help = "Initial aggregation: pair, reason, device, site")]
    group: GroupBy,
}

fn interval(input: &str) -> std::result::Result<f64, String> {
    let value: f64 = input.parse().map_err(|_| "expected seconds".to_string())?;
    if !value.is_finite() || !(0.1..=60.0).contains(&value) {
        return Err("interval must be 0.1..60 seconds".into());
    }
    Ok(value)
}

struct Labels {
    reasons: HashMap<u32, String>,
    interfaces: HashMap<(u32, u32), String>,
    symbols: Vec<(u64, String)>,
}

impl Labels {
    fn reason(&self, code: u32) -> String {
        self.reasons
            .get(&code)
            .cloned()
            .unwrap_or_else(|| format!("reason#{code}"))
    }

    fn device(&self, ifindex: u32, netns: u32) -> String {
        if ifindex == 0 {
            return "unknown".into();
        }
        self.interfaces
            .get(&(ifindex, netns))
            .cloned()
            .unwrap_or_else(|| format!("if#{ifindex}@net:{netns}"))
    }

    fn site(&self, address: u64) -> String {
        collect::symbol(address, &self.symbols)
    }

    fn fields(&self, key: GroupKey) -> [String; 3] {
        match key {
            GroupKey::Pair(reason, ifindex, netns) => {
                [self.reason(reason), self.device(ifindex, netns), "-".into()]
            }
            GroupKey::Reason(reason) => [self.reason(reason), "-".into(), "-".into()],
            GroupKey::Device(ifindex, netns) => {
                ["-".into(), self.device(ifindex, netns), "-".into()]
            }
            GroupKey::Site(location) => ["-".into(), "-".into(), self.site(location)],
        }
    }

    fn group(&self, key: GroupKey) -> String {
        let [reason, device, site] = self.fields(key);
        match key {
            GroupKey::Pair(..) => format!("{reason} / {device}"),
            GroupKey::Reason(..) => reason,
            GroupKey::Device(..) => device,
            GroupKey::Site(..) => site,
        }
    }
}

struct App {
    group: GroupBy,
    track_stacks: bool,
    current: Snapshot,
    previous: Snapshot,
    rows: Vec<Row>,
    selected: Option<GroupKey>,
    stack_rows: Vec<(u32, f64, u64)>,
    stack_paths: HashMap<u32, Vec<u64>>,
    selected_stack: Option<u32>,
    frames: Vec<u64>,
    frame_scroll: u16,
    samples: VecDeque<DropEvent>,
    sample_index: usize,
    user_lost: u64,
    started_ns: u64,
    elapsed: f64,
    total_rate: f64,
}

impl App {
    fn new(group: GroupBy, baseline: Snapshot, track_stacks: bool, started_ns: u64) -> Self {
        Self {
            group,
            track_stacks,
            current: baseline,
            previous: Snapshot::default(),
            rows: Vec::new(),
            selected: None,
            stack_rows: Vec::new(),
            stack_paths: HashMap::new(),
            selected_stack: None,
            frames: Vec::new(),
            frame_scroll: 0,
            samples: VecDeque::new(),
            sample_index: 0,
            user_lost: 0,
            started_ns,
            elapsed: 0.0,
            total_rate: 0.0,
        }
    }

    fn sample(&mut self, probe: &Probe, elapsed: f64) -> Result<()> {
        self.previous = std::mem::replace(&mut self.current, probe.snapshot()?);
        self.elapsed = elapsed;
        self.rebuild(probe)
    }

    fn rebuild(&mut self, probe: &Probe) -> Result<()> {
        self.rows = model::rows(&self.current, &self.previous, self.elapsed, self.group);
        self.total_rate = model::total_rate(&self.current, &self.previous, self.elapsed);
        if !self.rows.iter().any(|row| Some(row.key) == self.selected) {
            self.selected = self.rows.first().map(|row| row.key);
        }
        self.sync_focus(probe)
    }

    fn sync_focus(&mut self, probe: &Probe) -> Result<()> {
        let focus = if self.track_stacks {
            self.selected.map(GroupKey::focus).unwrap_or_default()
        } else {
            Default::default()
        };
        if !focus.same_selection(probe.current_focus()) {
            probe.focus(focus)?;
            self.previous.stacks.clear();
            self.current.stacks.clear();
            self.stack_rows.clear();
            self.stack_paths.clear();
            self.selected_stack = None;
            self.frames.clear();
            self.frame_scroll = 0;
            self.samples.clear();
            self.sample_index = 0;
            return Ok(());
        }
        if !self.track_stacks {
            return Ok(());
        }
        self.stack_rows = model::stack_rates(&self.current, &self.previous, self.elapsed);
        self.stack_rows.truncate(16);
        self.stack_paths.clear();
        for &(id, _, _) in &self.stack_rows {
            self.stack_paths.insert(id, probe.stack(id)?);
        }
        if !self
            .stack_rows
            .iter()
            .any(|(id, _, _)| Some(*id) == self.selected_stack)
        {
            self.selected_stack = self.stack_rows.first().map(|(id, _, _)| *id);
            self.frame_scroll = 0;
        }
        self.frames = self
            .selected_stack
            .and_then(|id| self.stack_paths.get(&id).cloned())
            .unwrap_or_default();
        Ok(())
    }

    fn move_row(&mut self, probe: &Probe, offset: isize) -> Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let index = self
            .rows
            .iter()
            .position(|row| Some(row.key) == self.selected)
            .unwrap_or(0);
        let next = index.saturating_add_signed(offset).min(self.rows.len() - 1);
        self.selected = Some(self.rows[next].key);
        self.sync_focus(probe)
    }

    fn move_stack(&mut self, offset: isize) {
        if self.stack_rows.is_empty() {
            return;
        }
        let index = self
            .stack_rows
            .iter()
            .position(|(id, _, _)| Some(*id) == self.selected_stack)
            .unwrap_or(0);
        let next = index
            .saturating_add_signed(offset)
            .min(self.stack_rows.len() - 1);
        let id = self.stack_rows[next].0;
        self.selected_stack = Some(id);
        self.frames = self.stack_paths.get(&id).cloned().unwrap_or_default();
        self.frame_scroll = 0;
    }

    fn scroll_frames(&mut self, offset: i16) {
        self.frame_scroll = self
            .frame_scroll
            .saturating_add_signed(offset)
            .min(self.frames.len().saturating_sub(1) as u16);
    }

    fn receive_sample(&mut self, event: DropEvent, generation: u32) {
        if self.selected.is_none() || event.generation != generation {
            return;
        }
        self.samples.push_front(event);
        self.samples.truncate(16);
        if self.sample_index > 0 {
            self.sample_index = (self.sample_index + 1).min(self.samples.len() - 1);
        }
    }

    fn move_sample(&mut self, offset: isize) {
        if !self.samples.is_empty() {
            self.sample_index = self
                .sample_index
                .saturating_add_signed(offset)
                .min(self.samples.len() - 1);
        }
    }
}

fn protocol_name(protocol: u8) -> &'static str {
    match protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        _ => "IP",
    }
}

fn packet_protocol(event: &DropEvent) -> &'static str {
    if event.family == 0 {
        "non-IP"
    } else {
        protocol_name(event.l4_protocol)
    }
}

fn ip_address(family: u8, bytes: &[u8; 16]) -> Option<IpAddr> {
    match family {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
    }
}

fn endpoint(event: &DropEvent, source: bool) -> String {
    let (address, port) = if source {
        (&event.source, event.source_port)
    } else {
        (&event.dest, event.dest_port)
    };
    let Some(ip) = ip_address(event.family, address) else {
        return "N/A".into();
    };
    if event.status != 0 {
        return ip.to_string();
    }
    if event.family == 6 {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn parse_status(code: u8) -> &'static str {
    match code {
        0 => "complete",
        1 => "network header unavailable",
        2 => "header unreadable/truncated",
        3 => "non-initial IPv4 fragment",
        4 => "IPv6 extension header",
        5 => "non-IP payload",
        6 => "protocol has no TCP/UDP ports",
        _ => "unknown parse status",
    }
}

struct Screen {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Screen {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            terminal::disable_raw_mode()?;
            return Err(error.into());
        }
        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => terminal,
            Err(error) => {
                let _ = terminal::disable_raw_mode();
                let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
                return Err(error.into());
            }
        };
        Ok(Self { terminal })
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    }
}

fn render(frame: &mut ratatui::Frame, app: &App, labels: &Labels) {
    let area = frame.area();
    if area.width < 78 || area.height < 20 {
        frame.render_widget(
            Paragraph::new("droptop needs at least 78x20; enlarge the terminal"),
            area,
        );
        return;
    }
    let available = area.height - 3;
    let list_height = if area.height < 24 {
        5
    } else {
        (available * 30 / 100).clamp(6, 12)
    };
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(list_height),
            Constraint::Length(list_height),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);
    let heading = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(20)])
        .split(Rect::new(area.x, area.y, area.width, 1));
    frame.render_widget(
        Paragraph::new(format!(
            "droptop | {} | {:.3}s",
            app.group.name(),
            app.elapsed
        ))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        heading[0],
    );
    frame.render_widget(
        Paragraph::new(format!("{:.1} drop/s", app.total_rate))
            .alignment(Alignment::Right)
            .style(
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
        heading[1],
    );
    let missed = app.current.errors[0].saturating_sub(app.previous.errors[0]);
    let stack_failures = app.current.errors[1].saturating_sub(app.previous.errors[1])
        + app.current.errors[2].saturating_sub(app.previous.errors[2]);
    let limited = app.current.errors[3].saturating_sub(app.previous.errors[3]);
    let ring_full = app.current.errors[4].saturating_sub(app.previous.errors[4]);
    let active = app.rows.iter().filter(|row| row.rate > 0.0).count();
    let notice = format!(
        "groups {active}/{} keys {} | map+{missed} stack+{stack_failures} | skb {} limit+{limited} ring+{ring_full} user{}",
        app.rows.len(),
        app.current.drops.len(),
        app.samples.len(),
        app.user_lost,
    );
    frame.render_widget(
        Paragraph::new(notice).style(Style::default().fg(Color::Gray)),
        Rect::new(area.x, area.y + 1, area.width, 1),
    );

    render_groups(frame, layout[1], app, labels);
    render_timeline(frame, layout[2], app, labels);
    if area.width >= 105 {
        let detail = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
            .split(layout[3]);
        render_packet(frame, detail[0], app, labels);
        render_stack(frame, detail[1], app, labels);
    } else {
        let packet_height = if layout[3].height >= 9 {
            6
        } else {
            layout[3].height.saturating_sub(2)
        };
        let detail = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(packet_height), Constraint::Min(0)])
            .split(layout[3]);
        render_packet(frame, detail[0], app, labels);
        render_stack(frame, detail[1], app, labels);
    }
    frame.render_widget(
        Paragraph::new(
            "j/k group | [/] skb | Left/Right path | PgUp/PgDn stack | g group | q quit",
        )
        .style(Style::default().fg(Color::Gray)),
        layout[4],
    );
}

fn render_groups(frame: &mut ratatui::Frame, area: Rect, app: &App, labels: &Labels) {
    let (headers, widths): (Vec<&str>, Vec<Constraint>) = match app.group {
        GroupBy::Pair => (
            vec!["REASON", "NETDEV", "DROP/s", "TOTAL"],
            vec![
                Constraint::Min(28),
                Constraint::Length(18),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        ),
        GroupBy::Reason => (
            vec!["REASON", "DROP/s", "TOTAL"],
            vec![
                Constraint::Min(28),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        ),
        GroupBy::Device => (
            vec!["NETDEV", "DROP/s", "TOTAL"],
            vec![
                Constraint::Min(28),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        ),
        GroupBy::Site => (
            vec!["CALL SITE", "DROP/s", "TOTAL"],
            vec![
                Constraint::Min(28),
                Constraint::Length(10),
                Constraint::Length(10),
            ],
        ),
    };
    let header = TableRow::new(headers).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    let selected = app.selected;
    let visible = area.height.saturating_sub(3) as usize;
    let selected_index = app
        .rows
        .iter()
        .position(|row| Some(row.key) == selected)
        .unwrap_or(0);
    let start = selected_index
        .saturating_sub(visible / 2)
        .min(app.rows.len().saturating_sub(visible));
    let rows = app.rows.iter().skip(start).take(visible).map(|row| {
        let style = if Some(row.key) == selected {
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let fields = labels.fields(row.key);
        let mut cells = match app.group {
            GroupBy::Pair => vec![Cell::from(fields[0].clone()), Cell::from(fields[1].clone())],
            GroupBy::Reason => vec![Cell::from(fields[0].clone())],
            GroupBy::Device => vec![Cell::from(fields[1].clone())],
            GroupBy::Site => vec![Cell::from(fields[2].clone())],
        };
        let rate_color = if row.rate > 0.0 {
            Color::LightRed
        } else {
            Color::Gray
        };
        cells.push(Cell::from(format!("{:.1}", row.rate)).style(Style::default().fg(rate_color)));
        cells.push(Cell::from(row.count.to_string()));
        TableRow::new(cells).style(style)
    });
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(format!(
                    " Drops | {}/{} shown ",
                    visible.min(app.rows.len()),
                    app.rows.len()
                ))
                .borders(Borders::ALL),
        )
        .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_timeline(frame: &mut ratatui::Frame, area: Rect, app: &App, labels: &Labels) {
    let selection = app
        .selected
        .map(|key| labels.group(key))
        .unwrap_or_else(|| "none".into());
    let visible = area.height.saturating_sub(3) as usize;
    let selected = app.sample_index.min(app.samples.len().saturating_sub(1));
    let start = selected
        .saturating_sub(visible / 2)
        .min(app.samples.len().saturating_sub(visible));
    let wide = area.width >= 105;
    let widths = if wide {
        vec![
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(25),
            Constraint::Length(18),
            Constraint::Length(21),
        ]
    } else {
        vec![
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Min(20),
        ]
    };
    let headers = if wide {
        vec!["TIME", "PROTO / LEN", "FLOW", "REASON", "SITE"]
    } else {
        vec!["TIME", "PROTO / LEN", "FLOW"]
    };
    let rows = app
        .samples
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, event)| {
            let time = event.timestamp_ns.saturating_sub(app.started_ns) as f64 / 1e9;
            let mut cells = vec![
                Cell::from(format!("+{time:.3}s")),
                Cell::from(format!("{} {}B", packet_protocol(event), event.length)),
                Cell::from(format!(
                    "{} -> {}",
                    endpoint(event, true),
                    endpoint(event, false)
                )),
            ];
            if wide {
                cells.push(Cell::from(labels.reason(event.reason)));
                cells.push(Cell::from(labels.site(event.location)));
            }
            let style = if index == selected {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            TableRow::new(cells).style(style)
        });
    frame.render_widget(
        Table::new(rows, widths)
            .header(
                TableRow::new(headers).style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            )
            .block(
                Block::default()
                    .title(format!(
                        " Recent skb | {selection} | {}/{} sampled ",
                        if app.samples.is_empty() {
                            0
                        } else {
                            selected + 1
                        },
                        app.samples.len()
                    ))
                    .borders(Borders::ALL),
            )
            .column_spacing(1),
        area,
    );
    if app.samples.is_empty() && area.height >= 4 {
        frame.render_widget(
            Paragraph::new("Waiting for a drop in the selected group")
                .style(Style::default().fg(Color::Gray)),
            Rect::new(area.x + 1, area.y + 2, area.width.saturating_sub(2), 1),
        );
    }
}

fn render_packet(frame: &mut ratatui::Frame, area: Rect, app: &App, labels: &Labels) {
    let title = format!(
        " Selected skb {}/{} ",
        if app.samples.is_empty() {
            0
        } else {
            app.sample_index + 1
        },
        app.samples.len(),
    );
    let Some(event) = app.samples.get(app.sample_index) else {
        frame.render_widget(
            Paragraph::new("Waiting for a sample")
                .block(Block::default().title(title).borders(Borders::ALL)),
            area,
        );
        return;
    };
    let source = endpoint(event, true);
    let dest = endpoint(event, false);
    let ingress = labels.device(event.ingress_ifindex, event.netns);
    let device = labels.device(event.ifindex, event.netns);
    let time = event.timestamp_ns.saturating_sub(app.started_ns) as f64 / 1e9;
    let lines = vec![
        Line::from(vec![
            Span::styled("SRC ", Style::default().fg(Color::Yellow)),
            Span::raw(source),
        ]),
        Line::from(vec![
            Span::styled("DST ", Style::default().fg(Color::Yellow)),
            Span::raw(dest),
        ]),
        Line::from(format!("rx iif {ingress} | drop dev {device}")),
        Line::from(format!(
            "+{time:.3}s | site {} | tuple {}",
            labels.site(event.location),
            parse_status(event.status)
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .title(format!(
                    "{title}| {} {}B | {} ",
                    packet_protocol(event),
                    event.length,
                    labels.reason(event.reason)
                ))
                .borders(Borders::ALL),
        ),
        area,
    );
}

fn render_stack(frame: &mut ratatui::Frame, area: Rect, app: &App, labels: &Labels) {
    let selected = app
        .stack_rows
        .iter()
        .position(|(id, _, _)| Some(*id) == app.selected_stack);
    let title = selected
        .map(|index| {
            format!(
                " Group hot path {}/{} | {:.1} drop/s ",
                index + 1,
                app.stack_rows.len(),
                app.stack_rows[index].1
            )
        })
        .unwrap_or_else(|| " Group hot path | waiting ".into());
    let frames: Vec<_> = useful_frames(&app.frames, labels)
        .into_iter()
        .enumerate()
        .map(|(index, symbol)| {
            Line::from(vec![
                Span::styled(
                    format!("{:2} ", index + 1),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(symbol),
            ])
        })
        .collect();
    let scroll = app.frame_scroll.min(frames.len().saturating_sub(1) as u16);
    frame.render_widget(
        Paragraph::new(if frames.is_empty() {
            vec![Line::from("No stack yet for the selected group")]
        } else {
            frames
        })
        .scroll((scroll, 0))
        .block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn useful_frames(addresses: &[u64], labels: &Labels) -> Vec<String> {
    let mut frames: Vec<_> = addresses
        .iter()
        .map(|address| labels.site(*address))
        .collect();
    if let Some(index) = frames
        .iter()
        .position(|frame| frame.starts_with("__bpf_trace_kfree_skb"))
    {
        frames.drain(..=index);
    }
    while frames
        .first()
        .is_some_and(|frame| frame.starts_with("sk_skb_reason_drop"))
    {
        frames.remove(0);
    }
    frames
}

fn text_sample(app: &App, labels: &Labels) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "droptop | {} | interval {:.3}s | {:.1} drop/s | {}/{} active groups | map misses +{}",
        app.group.name(),
        app.elapsed,
        app.total_rate,
        app.rows.iter().filter(|row| row.rate > 0.0).count(),
        app.rows.len(),
        app.current.errors[0].saturating_sub(app.previous.errors[0])
    )?;
    writeln!(out, "{:<65} {:>10} {:>10}", "GROUP", "DROP/s", "TOTAL")?;
    for row in app.rows.iter().take(30) {
        let name = labels.group(row.key);
        writeln!(out, "{name:<65.65} {:>10.1} {:>10}", row.rate, row.count)?;
    }
    if app.rows.len() > 30 {
        writeln!(out, "... {} more groups", app.rows.len() - 30)?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn run(args: Args) -> Result<()> {
    if args.count.is_none()
        && (!io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || std::env::var("TERM").as_deref() == Ok("dumb"))
    {
        bail!("live view needs a terminal; use -c N for text samples");
    }
    let netns = collect::current_netns()?;
    let interface = args
        .interface
        .as_deref()
        .map(|name| collect::interface(name, netns))
        .transpose()?;
    let labels = Labels {
        reasons: collect::reason_names(),
        interfaces: collect::interfaces(netns),
        symbols: collect::kernel_symbols(),
    };
    let probe = Probe::attach(interface)?;
    let baseline = probe.snapshot()?;
    let mut app = App::new(
        args.group,
        baseline,
        args.count.is_none(),
        collect::monotonic_ns()?,
    );
    let interval = Duration::from_secs_f64(args.delay);
    let stop = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stop);
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;

    if let Some(count) = args.count {
        let mut last = Instant::now();
        for _ in 0..count {
            while !stop.load(Ordering::Relaxed) && last.elapsed() < interval {
                std::thread::sleep((interval - last.elapsed()).min(Duration::from_millis(100)));
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            app.sample(&probe, now.duration_since(last).as_secs_f64())?;
            last = now;
            text_sample(&app, &labels)?;
        }
        return Ok(());
    }

    let (sender, receiver) = mpsc::sync_channel(256);
    let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ring = probe.samples(sender, Arc::clone(&dropped))?;
    let mut screen = Screen::enter()?;
    let mut last = Instant::now();
    screen.terminal.draw(|frame| render(frame, &app, &labels))?;
    while !stop.load(Ordering::Relaxed) {
        ring.consume()?;
        let generation = probe.current_focus().generation;
        for event in receiver.try_iter() {
            app.receive_sample(event, generation);
        }
        app.user_lost = dropped.load(Ordering::Relaxed);
        let wait = interval
            .saturating_sub(last.elapsed())
            .min(Duration::from_millis(200));
        if event::poll(wait)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Down | KeyCode::Char('j') => app.move_row(&probe, 1)?,
                    KeyCode::Up | KeyCode::Char('k') => app.move_row(&probe, -1)?,
                    KeyCode::Right => app.move_stack(1),
                    KeyCode::Left => app.move_stack(-1),
                    KeyCode::Char('[') => app.move_sample(1),
                    KeyCode::Char(']') => app.move_sample(-1),
                    KeyCode::PageDown => app.scroll_frames(5),
                    KeyCode::PageUp => app.scroll_frames(-5),
                    KeyCode::Char('g') => {
                        app.group = app.group.next();
                        app.selected = None;
                        app.rebuild(&probe)?;
                    }
                    _ => {}
                }
                screen.terminal.draw(|frame| render(frame, &app, &labels))?;
            }
        }
        if last.elapsed() >= interval {
            let now = Instant::now();
            app.sample(&probe, now.duration_since(last).as_secs_f64())?;
            last = now;
            screen.terminal.draw(|frame| render(frame, &app, &labels))?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("droptop: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn buffer_text(terminal: &Terminal<TestBackend>, width: u16, height: u16) -> String {
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn rejects_invalid_intervals() {
        assert!(interval("0.05").is_err());
        assert!(interval("inf").is_err());
        assert!(interval("0.5").is_ok());
    }

    #[test]
    fn labels_unknown_interface_and_reason() {
        let labels = Labels {
            reasons: HashMap::new(),
            interfaces: HashMap::new(),
            symbols: Vec::new(),
        };
        assert_eq!(labels.reason(500), "reason#500");
        assert_eq!(labels.device(0, 0), "unknown");
        assert_eq!(labels.device(3, 12), "if#3@net:12");
    }

    #[test]
    fn live_view_shows_group_and_useful_stack_at_80_columns() {
        let labels = Labels {
            reasons: HashMap::from([(1, "NOT_SPECIFIED".into())]),
            interfaces: HashMap::from([((2, 10), "vmbr0".into())]),
            symbols: vec![
                (0x1000, "__bpf_trace_kfree_skb".into()),
                (0x2000, "sk_skb_reason_drop".into()),
                (0x3000, "br_stp_rcv".into()),
            ],
        };
        let key = GroupKey::Pair(1, 2, 10);
        let mut app = App::new(GroupBy::Pair, Snapshot::default(), true, 0);
        app.rows.push(Row {
            key,
            rate: 3.0,
            count: 9,
        });
        app.selected = Some(key);
        app.stack_rows.push((7, 2.0, 5));
        app.selected_stack = Some(7);
        app.frames = vec![0x1000, 0x2000, 0x3000];
        app.stack_paths.insert(7, app.frames.clone());
        app.samples.push_front(sample(4, 0));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app, &labels)).unwrap();
        let text = buffer_text(&terminal, 80, 24);
        assert!(text.contains("NOT_SPECIFIED"));
        assert!(text.contains("vmbr0"));
        assert!(text.contains("Recent skb"));
        assert!(text.contains("Selected skb 1/1"));
        assert!(text.contains("192.0.2.1:1234 -> 198.51.100.2:443"));
        assert!(text.contains("Group hot path"));
        assert!(text.contains("br_stp_rcv"));
        assert!(!text.contains("__bpf_trace_kfree_skb"));
    }

    #[test]
    fn small_terminal_has_resize_message() {
        let labels = Labels {
            reasons: HashMap::new(),
            interfaces: HashMap::new(),
            symbols: Vec::new(),
        };
        let app = App::new(GroupBy::Reason, Snapshot::default(), true, 0);
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal.draw(|frame| render(frame, &app, &labels)).unwrap();
        assert!(buffer_text(&terminal, 60, 16).contains("enlarge the terminal"));
    }

    fn sample(family: u8, status: u8) -> DropEvent {
        let mut source = [0; 16];
        let mut dest = [0; 16];
        if family == 4 {
            source[..4].copy_from_slice(&[192, 0, 2, 1]);
            dest[..4].copy_from_slice(&[198, 51, 100, 2]);
        } else if family == 6 {
            source[15] = 1;
            dest[15] = 2;
        }
        DropEvent {
            timestamp_ns: 2_000_000_000,
            location: 0x3000,
            reason: 1,
            ifindex: 2,
            ingress_ifindex: 3,
            netns: 10,
            length: 128,
            generation: 4,
            family,
            l4_protocol: 17,
            status,
            source_port: 1234,
            dest_port: 443,
            source,
            dest,
        }
    }

    #[test]
    fn formats_ipv4_ipv6_and_missing_ports() {
        let ipv4 = sample(4, 0);
        assert_eq!(endpoint(&ipv4, true), "192.0.2.1:1234");
        assert_eq!(endpoint(&ipv4, false), "198.51.100.2:443");
        let ipv6 = sample(6, 0);
        assert_eq!(endpoint(&ipv6, true), "[::1]:1234");
        assert_eq!(endpoint(&ipv6, false), "[::2]:443");
        assert_eq!(endpoint(&sample(6, 4), true), "::1");
        assert_eq!(endpoint(&sample(0, 5), true), "N/A");
        assert_eq!(packet_protocol(&sample(0, 5)), "non-IP");
    }

    #[test]
    fn ignores_old_focus_generation_and_browses_samples() {
        let mut app = App::new(GroupBy::Pair, Snapshot::default(), true, 0);
        app.selected = Some(GroupKey::Pair(1, 2, 10));
        app.receive_sample(sample(4, 0), 5);
        assert!(app.samples.is_empty());
        app.receive_sample(sample(4, 0), 4);
        app.receive_sample(sample(6, 0), 4);
        assert_eq!(app.samples.len(), 2);
        assert_eq!(app.samples[0].family, 6);
        app.move_sample(1);
        assert_eq!(app.samples[app.sample_index].family, 4);
    }

    #[test]
    fn packet_view_shows_full_tuple_and_interface_roles() {
        let labels = Labels {
            reasons: HashMap::from([(1, "NOT_SPECIFIED".into())]),
            interfaces: HashMap::from([((2, 10), "vmbr0".into()), ((3, 10), "nic0".into())]),
            symbols: vec![(0x3000, "ip_forward".into())],
        };
        let mut app = App::new(GroupBy::Pair, Snapshot::default(), true, 0);
        app.selected = Some(GroupKey::Pair(1, 2, 10));
        app.samples.push_front(sample(6, 0));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app, &labels)).unwrap();
        let text = buffer_text(&terminal, 80, 24);
        assert!(text.contains("[::1]:1234"));
        assert!(text.contains("[::2]:443"));
        assert!(text.contains("rx iif nic0 | drop dev vmbr0"));
        assert!(text.contains("site ip_forward+0x0"));
    }

    #[test]
    fn timeline_keeps_selected_older_sample_visible() {
        let labels = Labels {
            reasons: HashMap::from([(1, "NOT_SPECIFIED".into())]),
            interfaces: HashMap::from([((2, 10), "vmbr0".into())]),
            symbols: vec![(0x3000, "ip_forward".into())],
        };
        let mut app = App::new(GroupBy::Pair, Snapshot::default(), true, 0);
        app.selected = Some(GroupKey::Pair(1, 2, 10));
        for index in 0..6 {
            let mut event = sample(4, 0);
            event.timestamp_ns = (index + 1) * 1_000_000_000;
            event.source[3] = index as u8 + 1;
            app.samples.push_front(event);
        }
        app.sample_index = 5;
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app, &labels)).unwrap();
        let text = buffer_text(&terminal, 80, 24);
        assert!(text.contains("Selected skb 6/6"));
        assert!(text.contains("+1.000s"));
        assert_eq!(terminal.backend().buffer()[(2, 12)].bg, Color::DarkGray);
    }

    #[test]
    fn wide_view_shows_sample_reason_site_and_group_stack() {
        let labels = Labels {
            reasons: HashMap::from([(1, "NOT_SPECIFIED".into())]),
            interfaces: HashMap::from([((2, 10), "vmbr0".into())]),
            symbols: vec![(0x3000, "ip_forward".into())],
        };
        let mut app = App::new(GroupBy::Pair, Snapshot::default(), true, 0);
        app.selected = Some(GroupKey::Pair(1, 2, 10));
        app.samples.push_front(sample(4, 0));
        app.stack_rows.push((7, 3.0, 3));
        app.selected_stack = Some(7);
        app.frames = vec![0x3000];
        let mut terminal = Terminal::new(TestBackend::new(120, 32)).unwrap();
        terminal.draw(|frame| render(frame, &app, &labels)).unwrap();
        let text = buffer_text(&terminal, 120, 32);
        assert!(text.contains("PROTO / LEN"));
        assert!(text.contains("NOT_SPECIFIED"));
        assert!(text.contains("ip_forward+0x0"));
        assert!(text.contains("Group hot path 1/1"));
    }
}
