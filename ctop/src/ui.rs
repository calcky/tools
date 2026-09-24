mod group_columns;
mod panels;

use crate::{
    engine::Engine,
    model::{self, Entry, Field, Group},
    options::Options,
};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::{
    io::{self, Write},
    time::{Duration, Instant},
};

fn restore() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
}
pub struct Screen {
    pub terminal: Terminal<CrosstermBackend<io::Stdout>>,
}
impl Screen {
    pub fn open() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            restore();
            return Err(error);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(t) => t,
            Err(e) => {
                restore();
                return Err(e);
            }
        };
        let old = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore();
            old(info)
        }));
        Ok(Self { terminal })
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        restore();
    }
}

struct Scope {
    fields: Vec<Field>,
    nat: bool,
    key: String,
    search: String,
    sort: usize,
}
impl Scope {
    fn matches(&self, entry: &Entry) -> bool {
        model::group_key(entry, &self.fields, self.nat) == self.key
    }
}

pub struct View {
    pub groups: Vec<Group>,
    pub fields: Vec<Field>,
    pub nat: bool,
    pub selected: usize,
    pub search: String,
    pub input: Option<(char, String)>,
    pub note: String,
    pub drill: Option<String>,
    scopes: Vec<Scope>,
    restore_selection: Option<String>,
    pub sessions: Vec<Entry>,
    pub session_total: usize,
    session_offset: usize,
    pub sort: usize,
    pub elapsed: f64,
    pub rates_valid: bool,
    bandwidth_valid: bool,
    offline_at: Option<Instant>,
    events: Vec<(bool, Entry)>,
    pub mono: bool,
    pub detail_scroll: u16,
    help: bool,
    help_scroll: u16,
}
impl View {
    pub fn new(o: &Options) -> Self {
        Self {
            groups: Vec::new(),
            fields: if o.fields.is_empty() {
                vec![Field::Src]
            } else {
                o.fields.clone()
            },
            nat: o.nat,
            selected: 0,
            search: String::new(),
            input: None,
            note: String::new(),
            drill: o.fields.is_empty().then(|| "All connections".into()),
            scopes: Vec::new(),
            restore_selection: None,
            sessions: Vec::new(),
            session_total: 0,
            session_offset: 0,
            sort: 0,
            elapsed: 1.0,
            rates_valid: false,
            bandwidth_valid: false,
            offline_at: None,
            events: Vec::new(),
            mono: std::env::var_os("NO_COLOR").is_some(),
            detail_scroll: 0,
            help: false,
            help_scroll: 0,
        }
    }
    pub fn update(&mut self, e: &mut Engine, o: &Options, elapsed: f64) {
        (self.events, self.rates_valid) = e.take_window();
        self.elapsed = elapsed.max(0.001);
        self.rebuild(e, o);
    }
    pub fn rebuild(&mut self, e: &Engine, o: &Options) {
        self.offline_at = e.offline_at;
        self.bandwidth_valid = e.ready && !e.stale && e.offline_at.is_none();
        if self.drill.is_some() {
            let previous = self
                .selected_session()
                .map(|entry| (entry.key.clone(), entry.id));
            let entries = self.matching_sessions(e, o);
            self.session_total = entries.len();
            if let Some((key, id)) = previous {
                if let Some(index) = entries
                    .iter()
                    .position(|entry| entry.key == key && entry.id == id)
                {
                    self.selected = index;
                }
            }
            self.selected = self.selected.min(self.session_total.saturating_sub(1));
            self.session_offset = self.selected / 5000 * 5000;
            self.sessions = entries
                .into_iter()
                .skip(self.session_offset)
                .take(5000)
                .cloned()
                .collect();
            self.groups.clear();
            return;
        }
        let selected_key = self
            .restore_selection
            .take()
            .or_else(|| self.groups.get(self.selected).map(|g| g.key.clone()));
        self.groups = model::aggregate(
            e.entries.values().filter(|entry| self.in_scope(entry)),
            self.events.iter().filter(|(_, entry)| self.in_scope(entry)),
            &self.fields,
            self.nat,
            &o.filter,
            e.offline_at.unwrap_or_else(Instant::now),
            o.warning,
        );
        self.groups.retain(|g| {
            g.sessions >= o.minimum && g.key.to_lowercase().contains(&self.search.to_lowercase())
        });
        self.groups.sort_by(|a, b| {
            let value = |g: &Group| match self.sort {
                1 => g.new,
                2 => g.unreplied,
                3 => g.old_syn + g.old_unreplied + g.old_closing,
                _ => g.sessions,
            };
            value(b).cmp(&value(a)).then_with(|| a.key.cmp(&b.key))
        });
        self.sessions.clear();
        self.session_total = 0;
        self.session_offset = 0;
        if let Some(key) = selected_key {
            if let Some(index) = self.groups.iter().position(|g| g.key == key) {
                self.selected = index;
            }
        }
        self.selected = self.selected.min(self.len().saturating_sub(1));
    }
    fn len(&self) -> usize {
        if self.drill.is_some() {
            self.session_total
        } else {
            self.groups.len()
        }
    }
    fn selected_session(&self) -> Option<&Entry> {
        self.selected
            .checked_sub(self.session_offset)
            .and_then(|i| self.sessions.get(i))
    }
    fn matching_sessions<'a>(&self, e: &'a Engine, o: &Options) -> Vec<&'a Entry> {
        let search = self.search.to_lowercase();
        let mut entries = e
            .entries
            .values()
            .filter(|entry| {
                o.filter.matches(entry)
                    && self.in_scope(entry)
                    && (search.is_empty()
                        || format!(
                            "{} {} {}",
                            entry.tuple(self.nat).label(),
                            entry.state_label(),
                            entry.mark_label()
                        )
                        .to_lowercase()
                        .contains(&search))
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|a, b| {
            a.key
                .original
                .cmp(&b.key.original)
                .then_with(|| a.key.zone.cmp(&b.key.zone))
                .then_with(|| a.key.reply_zone.cmp(&b.key.reply_zone))
                .then_with(|| a.id.cmp(&b.id))
        });
        entries
    }
    fn show_connections(&mut self) {
        self.drill = Some(
            self.scopes
                .last()
                .map(|s| s.key.clone())
                .unwrap_or_else(|| "All connections".into()),
        );
        self.search.clear();
        self.selected = 0;
        self.session_offset = 0;
        self.sessions.clear();
        self.detail_scroll = 0;
        self.note.clear();
    }
    fn in_scope(&self, entry: &Entry) -> bool {
        self.scopes.iter().all(|scope| scope.matches(entry))
    }
    fn enter(&mut self) {
        let Some(group) = self.groups.get(self.selected) else {
            return;
        };
        if self.scopes.len() >= 16 {
            self.note = "Maximum depth 16; Esc returns one level".into();
            return;
        }
        self.scopes.push(Scope {
            fields: self.fields.clone(),
            nat: self.nat,
            key: group.key.clone(),
            search: self.search.clone(),
            sort: self.sort,
        });
        self.drill = Some(group.key.clone());
        self.search.clear();
        self.selected = 0;
        self.groups.clear();
        self.detail_scroll = 0;
    }
    fn back(&mut self) {
        if let Some(parent) = self.scopes.pop() {
            self.fields = parent.fields;
            self.nat = parent.nat;
            self.search = parent.search;
            self.sort = parent.sort;
            self.restore_selection = Some(parent.key);
            self.selected = 0;
        } else {
            self.search.clear();
            self.selected = 0;
        }
        self.drill = None;
        self.detail_scroll = 0;
        self.note.clear();
    }
    fn regroup(&mut self, fields: Vec<Field>) {
        self.fields = fields;
        self.drill = None;
        self.search.clear();
        self.selected = 0;
        self.groups.clear();
        self.detail_scroll = 0;
        self.note.clear();
    }
    fn path(&self) -> String {
        let mut parts = vec!["All".to_owned()];
        for scope in &self.scopes {
            let fields = scope
                .fields
                .iter()
                .map(|f| f.name())
                .collect::<Vec<_>>()
                .join(",");
            parts.push(format!(
                "{}{fields}={}",
                if scope.nat { "NAT:" } else { "" },
                scope.key
            ));
        }
        parts.join(" > ")
    }
    pub fn keys(&mut self, e: &Engine, o: &Options) -> io::Result<bool> {
        while event::poll(Duration::ZERO)? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if self.key(key, e, o) {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn key(&mut self, key: KeyEvent, e: &Engine, o: &Options) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        let mut changed = false;
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if self.help {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Char('h') | KeyCode::Esc => self.help = false,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = (self.help_scroll + 1).min(20)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => self.help_scroll = (self.help_scroll + 8).min(20),
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(8),
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = 20,
                _ => (),
            }
            return false;
        }
        if let Some((mode, buffer)) = &mut self.input {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
                buffer.clear();
                return false;
            }
            match key.code {
                KeyCode::Esc => self.input = None,
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Char(c) if c.is_ascii() && !c.is_control() && buffer.len() < 160 => {
                    buffer.push(c)
                }
                KeyCode::Enter => {
                    let mode = *mode;
                    let text = buffer.clone();
                    self.input = None;
                    if mode == 'g' {
                        if text.trim() == "none" {
                            self.show_connections();
                        } else {
                            match Field::parse(&text) {
                                Ok(fields) => {
                                    self.regroup(fields);
                                }
                                Err(err) => self.note = err,
                            }
                        }
                    } else {
                        self.search = text;
                        self.selected = 0;
                        self.sessions.clear();
                        self.session_offset = 0;
                    }
                    changed = true;
                }
                _ => (),
            }
        } else {
            match key.code {
                KeyCode::Char('0') => {
                    if self.drill.is_some() {
                        self.regroup(self.fields.clone());
                    } else {
                        self.show_connections();
                    }
                    changed = true;
                }
                KeyCode::Char('h') => {
                    self.help = true;
                    self.help_scroll = 0;
                }
                KeyCode::Char('[') => self.detail_scroll = self.detail_scroll.saturating_sub(1),
                KeyCode::Char(']') => self.detail_scroll = self.detail_scroll.saturating_add(1),
                KeyCode::Char('q') => return true,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.selected = (self.selected + 1).min(self.len().saturating_sub(1))
                }
                KeyCode::Up | KeyCode::Char('k') => self.selected = self.selected.saturating_sub(1),
                KeyCode::PageDown => {
                    self.selected = (self.selected + 10).min(self.len().saturating_sub(1))
                }
                KeyCode::PageUp => self.selected = self.selected.saturating_sub(10),
                KeyCode::Home => self.selected = 0,
                KeyCode::End => self.selected = self.len().saturating_sub(1),
                KeyCode::Enter if self.drill.is_none() => {
                    self.enter();
                    changed = true;
                }
                KeyCode::Esc => {
                    self.back();
                    changed = true;
                }
                KeyCode::Char('n') => {
                    self.nat = !self.nat;
                    self.search.clear();
                    self.groups.clear();
                    self.selected = 0;
                    changed = true;
                }
                KeyCode::Char('s') => {
                    if self.drill.is_some() {
                        self.note = "Connections sorted by original tuple, zone and ID".into();
                    } else {
                        self.sort = (self.sort + 1) % 4;
                        changed = true;
                    }
                }
                KeyCode::Char('g') => self.input = Some(('g', self.field_names())),
                KeyCode::Char('/') => self.input = Some(('/', self.search.clone())),
                KeyCode::Char(c @ '1'..='7') => {
                    let fields = match c {
                        '1' => vec![Field::Src],
                        '2' => vec![Field::Dst, Field::Dport, Field::Proto],
                        '3' => vec![Field::Src, Field::Dst],
                        '4' => vec![Field::Proto],
                        '5' => vec![Field::Sport],
                        '6' => vec![Field::Dport],
                        _ => vec![Field::Mark],
                    };
                    self.regroup(fields);
                    changed = true;
                }
                _ => (),
            }
        }
        if self.drill.is_some() && self.session_total > 0 && self.selected_session().is_none() {
            changed = true;
        }
        if changed {
            self.rebuild(e, o);
        }
        false
    }
    pub fn field_names(&self) -> String {
        self.fields
            .iter()
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join(",")
    }
    fn color(&self, color: Color) -> Style {
        if self.mono {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }
    fn rate(&self, n: u64) -> String {
        if self.rates_valid {
            format!("{:.1}", n as f64 / self.elapsed)
        } else {
            "N/A".into()
        }
    }
    fn bandwidth(&self, g: &Group, i: usize) -> String {
        covered(
            bandwidth(Some(g.bandwidth[i])),
            if self.bandwidth_valid {
                g.bandwidth_accounted[i]
            } else {
                0
            },
            g.sessions,
        )
    }
    fn entry_bandwidth(&self, e: &Entry, i: usize) -> String {
        bandwidth(
            e.traffic
                .as_ref()
                .filter(|_| self.bandwidth_valid)
                .and_then(|sample| sample.bytes_per_second[i]),
        )
    }
    pub fn draw(&self, f: &mut Frame, e: &Engine, o: &Options) {
        let area = f.area();
        if area.width < 70 || area.height < 20 {
            f.render_widget(
                Paragraph::new("ctop: terminal needs at least 70 x 20 (q quits)"),
                area,
            );
            return;
        }
        if self.help {
            self.help_panel(f, e);
            return;
        }
        let detail_height = if area.height >= 32 { 12 } else { 5 };
        let status_height = 6;
        let areas = Layout::vertical([
            Constraint::Length(status_height),
            Constraint::Length(u16::from(!self.scopes.is_empty())),
            Constraint::Min(4),
            Constraint::Length(detail_height),
            Constraint::Length(2),
        ])
        .split(area);
        self.status_panel(f, areas[0], e, o);
        if !self.scopes.is_empty() {
            let path = self.path();
            let width = area.width as usize;
            let path = if path.len() > width {
                format!("...{}", &path[path.len() - width + 3..])
            } else {
                path
            };
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    path,
                    self.color(Color::Cyan).add_modifier(Modifier::BOLD),
                ))),
                areas[1],
            );
        }
        let bold = self.color(Color::Cyan).add_modifier(Modifier::BOLD);
        let (header, rows, widths, title) = if let Some(group) = &self.drill {
            let wide = area.width >= 100;
            let mut labels = vec!["Session", "Mark", "Orig bit/s", "Reply bit/s", "Packets"];
            let mut widths = vec![
                Constraint::Min(20),
                Constraint::Length(10),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(12),
            ];
            if wide {
                labels.push("State");
                widths.push(Constraint::Length(13));
            }
            let rows = self
                .sessions
                .iter()
                .map(|e| {
                    let mut cells = vec![
                        Cell::from(e.tuple(self.nat).label()),
                        Cell::from(e.mark_label()),
                        Cell::from(self.entry_bandwidth(e, 0)),
                        Cell::from(self.entry_bandwidth(e, 1)),
                        Cell::from(covered(
                            e.packets
                                .iter()
                                .flatten()
                                .map(|n| *n as u128)
                                .sum::<u128>()
                                .to_string(),
                            e.packets.iter().flatten().count() as u64,
                            2,
                        )),
                    ];
                    if wide {
                        cells.push(Cell::from(e.state_label()));
                    }
                    Row::new(cells)
                })
                .collect::<Vec<_>>();
            (
                Row::new(labels).style(bold),
                rows,
                widths,
                format!(
                    " {group} | CT {}-{} / {} ",
                    if self.session_total == 0 {
                        0
                    } else {
                        self.session_offset + 1
                    },
                    self.session_offset + self.sessions.len(),
                    self.session_total
                ),
            )
        } else {
            let wide = area.width >= 120;
            let extra = if wide { 39 } else { 0 } + if area.width >= 160 { 31 } else { 0 };
            let group_columns =
                group_columns::GroupColumns::new(self, area.width.saturating_sub(49 + extra));
            let mut labels = vec![
                group_columns.header(),
                Cell::from("Sessions"),
                Cell::from("Orig bit/s"),
                Cell::from("Reply bit/s"),
                Cell::from("Packets"),
            ];
            let mut widths = vec![
                Constraint::Min(18),
                Constraint::Length(9),
                Constraint::Length(11),
                Constraint::Length(11),
                Constraint::Length(12),
            ];
            if wide {
                labels.extend(["New/s", "End/s", "Unreplied", "SYN"].map(Cell::from));
                widths.extend([
                    Constraint::Length(9),
                    Constraint::Length(9),
                    Constraint::Length(10),
                    Constraint::Length(7),
                ]);
            }
            if area.width >= 160 {
                labels.push(Cell::from("Flags"));
                widths.push(Constraint::Length(30));
            }
            let rows = self
                .groups
                .iter()
                .map(|g| {
                    let (identity, height) = group_columns.cell(g);
                    let mut cells = vec![
                        identity,
                        Cell::from(g.sessions.to_string())
                            .style(Style::default().add_modifier(Modifier::BOLD)),
                        Cell::from(self.bandwidth(g, 0)),
                        Cell::from(self.bandwidth(g, 1)),
                        Cell::from(covered(
                            (g.packets[0] + g.packets[1]).to_string(),
                            g.packets_accounted[0] + g.packets_accounted[1],
                            g.sessions * 2,
                        )),
                    ];
                    if wide {
                        cells.extend([
                            Cell::from(self.rate(g.new)),
                            Cell::from(self.rate(g.end)),
                            Cell::from(g.unreplied.to_string()),
                            Cell::from(g.syn.to_string()).style(if g.old_syn > 0 {
                                self.color(Color::Yellow)
                            } else {
                                Style::default()
                            }),
                        ]);
                    }
                    if area.width >= 160 {
                        let highlight = g.old_syn > 0
                            || g.old_unreplied > 0
                            || (g.source_group
                                && (g.destinations.len() >= 128
                                    || g.destination_ports.len() >= 128));
                        cells.push(Cell::from(g.flags()).style(self.color(if highlight {
                            Color::Yellow
                        } else {
                            Color::Gray
                        })));
                    }
                    Row::new(cells).height(height)
                })
                .collect();
            (
                Row::new(labels).style(bold),
                rows,
                widths,
                format!(
                    " {} | {} groups | sort {} | {} ",
                    self.field_names(),
                    self.groups.len(),
                    ["sessions", "new", "unreplied", "aged"][self.sort],
                    if self.offline_at.is_some() {
                        "static snapshot".into()
                    } else {
                        format!("aged >= {}s", o.warning.as_secs_f64())
                    }
                ),
            )
        };
        let table = Table::new(rows, widths)
            .header(header)
            .column_spacing(1)
            .block(Block::default().borders(Borders::ALL).title(title))
            .row_highlight_style(if self.mono {
                Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            });
        let mut state = TableState::default().with_selected(if self.len() > 0 {
            Some(if self.drill.is_some() {
                self.selected - self.session_offset
            } else {
                self.selected
            })
        } else {
            None
        });
        f.render_stateful_widget(table, areas[2], &mut state);
        self.details_panel(f, areas[3], o);
        self.footer(f, areas[4]);
    }
    pub fn batch(&self, e: &Engine, o: &Options, out: &mut impl Write) -> io::Result<()> {
        writeln!(
            out,
            "ctop | {} | {} | group {} | entries {}/{} | gaps {} | {}",
            e.health.namespace,
            if self.nat { "NAT" } else { "original" },
            if self.drill.is_some() {
                "none (individual CT)".into()
            } else {
                self.field_names()
            },
            opt(e.health.count),
            opt(e.health.max),
            e.lost,
            if e.offline_at.is_some() {
                "STATIC"
            } else if e.stale {
                "STALE"
            } else {
                "LIVE"
            }
        )?;
        writeln!(out, "{}", e.message)?;
        if e.offline_at.is_some() {
            writeln!(out, "Counters = saved snapshot totals; rates and observed age = N/A; * = partial; orig/reply directions")?;
        } else {
            writeln!(out, "BW = latest live-connection snapshot average; packets = current live totals; * = partial; orig/reply directions")?;
        }
        writeln!(
            out,
            "Kernel delta: insert_failed={} drop={} early_drop={} | acct={} events={}",
            opt(e.health.delta[0]),
            opt(e.health.delta[1]),
            opt(e.health.delta[2]),
            opt(e.health.acct),
            opt(e.health.events)
        )?;
        if self.drill.is_some() {
            let entries = self.matching_sessions(e, o);
            writeln!(out,"Session | Mark | State | Orig bit/s | Reply bit/s | Pkts orig | Pkts reply | Bytes orig | Bytes reply")?;
            for entry in &entries {
                writeln!(
                    out,
                    "{} | {} | {} | {} | {} | {} | {} | {} | {}",
                    entry.tuple(self.nat).label(),
                    entry.mark_label(),
                    entry.state_label(),
                    self.entry_bandwidth(entry, 0),
                    self.entry_bandwidth(entry, 1),
                    opt(entry.packets[0]),
                    opt(entry.packets[1]),
                    opt(entry.bytes[0]),
                    opt(entry.bytes[1])
                )?;
            }
            writeln!(out, "{} connections\n", entries.len())?;
            return Ok(());
        }
        let width = self
            .groups
            .iter()
            .map(|g| g.key.len())
            .max()
            .unwrap_or(5)
            .max(20);
        writeln!(
            out,
            "{:<width$} | Sessions |    New/s |    End/s | Unreplied |     SYN | NAT | Orig bit/s | Reply bit/s | Pkts orig | Pkts reply | Flags",
            "Group"
        )?;
        for g in &self.groups {
            writeln!(
                out,
                "{:<width$} | {:>8} | {:>8} | {:>8} | {:>9} | {:>7} | {:>3} | {:>10} | {:>11} | {:>9} | {:>10} | {}",
                g.key,
                g.sessions,
                self.rate(g.new),
                self.rate(g.end),
                g.unreplied,
                g.syn,
                g.nat,
                self.bandwidth(g, 0),
                self.bandwidth(g, 1),
                covered(g.packets[0].to_string(), g.packets_accounted[0], g.sessions),
                covered(g.packets[1].to_string(), g.packets_accounted[1], g.sessions),
                g.flags()
            )?;
        }
        if self.groups.is_empty() {
            writeln!(out, "No matching sessions")?;
        }
        writeln!(out)
    }
}
fn opt<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "N/A".into(), |v| v.to_string())
}
fn covered(value: String, count: u64, total: u64) -> String {
    if count == 0 {
        "N/A".into()
    } else if count < total {
        format!("{value}*")
    } else {
        value
    }
}
fn bandwidth(bytes_per_second: Option<f64>) -> String {
    let Some(bytes) = bytes_per_second else {
        return "N/A".into();
    };
    let bits = bytes * 8.0;
    for (scale, unit) in [(1e12, "Tb/s"), (1e9, "Gb/s"), (1e6, "Mb/s"), (1e3, "kb/s")] {
        if bits >= scale {
            return format!("{:.2}{unit}", bits / scale);
        }
    }
    format!("{bits:.1}b/s")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    #[test]
    fn static_snapshot_does_not_age_or_claim_live_metrics() {
        let at = Instant::now() - Duration::from_secs(60);
        let mut item = model::fixture();
        item.seen = at;
        item.state_since = at;
        item.state = Some(1);
        item.status = Some(0);
        let mut engine = Engine::offline([(item.key.clone(), item)].into(), "dump.txt".into(), at);
        let options = Options::default();
        let mut view = View::new(&options);
        view.update(&mut engine, &options, 1.0);
        assert!(!view.rates_valid);
        assert_eq!(view.groups[0].old_syn, 0);
        assert_eq!(view.groups[0].old_unreplied, 0);
        assert!(view.detail().contains(&("SYN-aged".into(), "N/A".into())));
        for width in [80, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 36)).unwrap();
            terminal.draw(|f| view.draw(f, &engine, &options)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(text.contains("STATIC") && text.contains("SNAPSHOT"));
            assert!(!text.contains("LIVE") && !text.contains("BW sample"));
        }
        press(&mut view, &engine, &options, KeyCode::Enter);
        assert!(view
            .detail()
            .contains(&("State observed".into(), "N/A".into())));
        assert!(view.detail().contains(&("Age".into(), "N/A".into())));
    }
    #[test]
    fn mark_drilldown_and_regroup_follow_current_connection_marks() {
        let mut engine = crate::engine::fixture();
        for (source, port, mark) in [
            ("192.0.2.1", 1, 16),
            ("192.0.2.2", 2, 16),
            ("192.0.2.3", 3, 32),
        ] {
            let mut item = entry(source, 443, port);
            item.mark = Some(mark);
            engine.entries.insert(item.key.clone(), item);
        }
        let o = Options::default();
        let mut view = View::new(&o);
        press(&mut view, &engine, &o, KeyCode::Char('7'));
        assert_eq!(view.groups.len(), 2);
        assert_eq!(view.groups[0].key, "0x10");
        press(&mut view, &engine, &o, KeyCode::Enter);
        assert_eq!(view.session_total, 2);
        press(&mut view, &engine, &o, KeyCode::Char('1'));
        assert_eq!(view.groups.len(), 2);
        engine
            .entries
            .get_mut(&entry("192.0.2.1", 443, 1).key)
            .unwrap()
            .mark = Some(32);
        view.rebuild(&engine, &o);
        assert_eq!(view.groups.len(), 1);
        assert_eq!(view.groups[0].key, "192.0.2.2");
        press(&mut view, &engine, &o, KeyCode::Char('0'));
        assert_eq!(view.session_total, 1);
        let mut report = Vec::new();
        view.batch(&engine, &o, &mut report).unwrap();
        assert!(String::from_utf8(report).unwrap().contains(" | 0x10 | "));
        view.search = "0x20".into();
        view.rebuild(&engine, &o);
        assert_eq!(view.session_total, 0);
        view.search = "0X10".into();
        view.rebuild(&engine, &o);
        assert_eq!(view.session_total, 1);
        press(&mut view, &engine, &o, KeyCode::Esc);
        assert_eq!(view.fields, vec![Field::Mark]);
        assert_eq!(view.groups.iter().map(|g| g.sessions).sum::<u64>(), 3);
    }
    #[test]
    fn individual_view_keeps_entries_separate_filters_search_and_stable_selection() {
        let mut engine = crate::engine::fixture();
        let a = entry("192.0.2.1", 443, 1);
        let mut zone = a.clone();
        zone.key.zone = 5;
        let outside = entry("192.0.2.1", 80, 2);
        for item in [&a, &zone, &outside] {
            engine.entries.insert(item.key.clone(), item.clone());
        }
        let mut o = Options {
            fields: Vec::new(),
            ..Options::default()
        };
        o.filter.dport = Some(443);
        let mut v = View::new(&o);
        v.rebuild(&engine, &o);
        assert!(v.groups.is_empty());
        assert_eq!(v.session_total, 2);
        press(&mut v, &engine, &o, KeyCode::End);
        assert_eq!(v.selected_session().unwrap().key.zone, 5);
        let fresh = entry("192.0.2.0", 443, 1);
        engine.entries.insert(fresh.key.clone(), fresh);
        v.rebuild(&engine, &o);
        assert_eq!(v.selected, 2);
        assert_eq!(v.selected_session().unwrap().key.zone, 5);
        v.input = Some(('/', "192.0.2.0".into()));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert!(v.drill.is_some());
        assert_eq!(v.session_total, 1);
        assert_eq!(
            v.selected_session().unwrap().key.original.src.to_string(),
            "192.0.2.0"
        );
        press(&mut v, &engine, &o, KeyCode::Char('0'));
        assert!(v.drill.is_none());
        assert_eq!(v.groups.iter().map(|g| g.sessions).sum::<u64>(), 3);
        v.input = Some(('g', "none".into()));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.session_total, 3);
        let mut output = Vec::new();
        v.batch(&engine, &o, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().filter(|l| l.starts_with("tcp ")).count(), 3);
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("tcp 192.0.2.1:1 ->"))
                .count(),
            2
        );
        assert!(!text.contains(":80 |"));
    }
    #[test]
    fn individual_toggle_preserves_parent_scope() {
        let mut engine = crate::engine::fixture();
        for item in [
            entry("192.0.2.1", 443, 1),
            entry("192.0.2.2", 443, 2),
            entry("192.0.2.1", 80, 3),
        ] {
            engine.entries.insert(item.key.clone(), item);
        }
        let o = Options::default();
        let mut v = View::new(&o);
        press(&mut v, &engine, &o, KeyCode::Char('6'));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.session_total, 2);
        let path = v.path();
        press(&mut v, &engine, &o, KeyCode::Char('0'));
        press(&mut v, &engine, &o, KeyCode::Char('0'));
        assert_eq!(v.path(), path);
        assert_eq!(v.session_total, 2);
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert_eq!(v.groups.iter().map(|g| g.sessions).sum::<u64>(), 3);
    }
    #[test]
    fn layout_a_sections_and_narrow_scrolling_keep_details_accessible() {
        let mut engine = crate::engine::fixture();
        let mut entry = model::fixture();
        entry.state = Some(7);
        engine.entries.insert(entry.key.clone(), entry);
        let o = Options::default();
        let mut view = View::new(&o);
        view.rebuild(&engine, &o);
        for width in [120, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 40)).unwrap();
            terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
            let text = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            for title in [
                "CAPACITY",
                "KERNEL / CAPTURE",
                "ACCOUNTING",
                "TRAFFIC",
                "STATES",
                "SIGNALS",
                "TIME_WAIT",
            ] {
                assert!(text.contains(title), "{title}: {text}");
            }
        }
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        let mut seen = String::new();
        for _ in 0..70 {
            terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
            seen.extend(
                terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|c| c.symbol()),
            );
            press(&mut view, &engine, &o, KeyCode::Char(']'));
        }
        for value in [
            "Byte cover",
            "STATES",
            "SIGNALS",
            "Proto-port pairs",
            "NAT sessions",
            "TIME_WAIT is not a fault",
        ] {
            assert!(seen.contains(value), "missing {value}");
        }
        press(&mut view, &engine, &o, KeyCode::Enter);
        assert_eq!(view.detail_scroll, 0);
        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        for title in ["TRAFFIC", "ENDPOINTS", "STATE", "Original", "Reply"] {
            assert!(text.contains(title));
        }
    }
    #[test]
    fn help_preserves_scope_and_selection_and_footer_respects_no_color() {
        let mut engine = crate::engine::fixture();
        let entry = model::fixture();
        engine.entries.insert(entry.key.clone(), entry);
        let o = Options::default();
        let mut view = View::new(&o);
        view.rebuild(&engine, &o);
        press(&mut view, &engine, &o, KeyCode::Enter);
        let path = view.path();
        press(&mut view, &engine, &o, KeyCode::Char('h'));
        press(&mut view, &engine, &o, KeyCode::Char('n'));
        assert!(!view.nat);
        assert_eq!(view.path(), path);
        for mono in [false, true] {
            view.mono = mono;
            for (width, height) in [(70, 20), (80, 24), (160, 40)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
                let buffer = terminal.backend().buffer();
                let text = buffer
                    .content
                    .iter()
                    .map(|c| c.symbol())
                    .collect::<String>();
                assert!(text.contains("Help | h/Esc close"));
                assert!(text.contains("Enter selected group"));
                if mono {
                    assert!(buffer
                        .content
                        .iter()
                        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
                }
            }
        }
        press(&mut view, &engine, &o, KeyCode::End);
        assert_eq!(view.help_scroll, 20);
        press(&mut view, &engine, &o, KeyCode::Esc);
        assert!(!view.help);
        assert_eq!(view.path(), path);
        for mono in [false, true] {
            view.mono = mono;
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
            let buffer = terminal.backend().buffer();
            let key = &buffer[(0, 22)];
            assert_eq!(key.symbol(), "h");
            assert!(key.modifier.contains(Modifier::BOLD));
            assert_eq!(key.fg, if mono { Color::Reset } else { Color::Yellow });
            let text = buffer
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            for metric in ["CAPACITY", "ACCOUNTING", "BW sample", "Packets"] {
                assert!(text.contains(metric), "{metric}: {text}");
            }
        }
        press(&mut view, &engine, &o, KeyCode::Char('h'));
        assert!(view.key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            &engine,
            &o
        ));
    }
    #[test]
    fn bandwidth_and_packets_are_visible_in_group_and_connection_tables_at_all_sizes() {
        let mut engine = crate::engine::fixture();
        let mut entry = model::fixture();
        let at = Instant::now();
        entry.sample_traffic(None, at);
        let previous = entry.clone();
        entry.bytes = [Some(600), Some(1100)];
        entry.packets = [Some(123), Some(456)];
        entry.mark = Some(u32::MAX);
        entry.sample_traffic(Some(&previous), at + Duration::from_secs(1));
        engine.entries.insert(entry.key.clone(), entry);
        let o = Options::default();
        let mut view = View::new(&o);
        view.rebuild(&engine, &o);
        for drill in [false, true] {
            if drill {
                view.enter();
                view.rebuild(&engine, &o);
            }
            for (width, height) in [(70, 20), (80, 24), (100, 24), (120, 32), (160, 40)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal.draw(|f| view.draw(f, &engine, &o)).unwrap();
                let lines = terminal
                    .backend()
                    .buffer()
                    .content
                    .chunks(width as usize)
                    .map(|line| line.iter().map(|c| c.symbol()).collect::<String>())
                    .collect::<Vec<_>>();
                let header = lines
                    .iter()
                    .find(|line| line.contains("Orig bit/s"))
                    .unwrap();
                if drill {
                    assert!(header.contains("Mark"));
                }
                assert!(
                    header.contains("Reply bit/s") && header.contains("Packets"),
                    "{width}: {header}"
                );
                let row = lines.iter().find(|line| {
                    line.contains("4.00kb/s") && line.contains("8.00kb/s") && line.contains("579")
                });
                assert!(
                    row.is_some(),
                    "{width}x{height}, drill={drill}: {}",
                    lines.join("\n")
                );
                if drill {
                    assert!(row.unwrap().contains("0xffffffff"));
                }
            }
        }
    }
    fn press(v: &mut View, e: &Engine, o: &Options, key: KeyCode) {
        assert!(!v.key(KeyEvent::new(key, KeyModifiers::NONE), e, o));
    }
    fn entry(src: &str, port: u16, sport: u16) -> Entry {
        let mut e = model::fixture();
        e.key.original.src = src.parse().unwrap();
        e.key.original.dport = Some(port);
        e.key.original.sport = Some(sport);
        e.reply = Some(e.key.original.reverse());
        e
    }
    #[test]
    fn nested_groups_filter_live_entries_and_lifecycle_events_and_restore_parent() {
        let mut engine = crate::engine::fixture();
        let a = entry("192.0.2.1", 443, 1);
        let b = entry("192.0.2.2", 443, 2);
        let outside = entry("192.0.2.1", 80, 3);
        for e in [&a, &b, &outside] {
            engine.entries.insert(e.key.clone(), e.clone());
        }
        let o = Options::default();
        let mut v = View::new(&o);
        v.events = vec![
            (true, a.clone()),
            (false, a.clone()),
            (true, b),
            (true, outside),
        ];
        press(&mut v, &engine, &o, KeyCode::Char('6'));
        v.search = "443".into();
        v.sort = 2;
        v.rebuild(&engine, &o);
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.session_total, 2);
        press(&mut v, &engine, &o, KeyCode::Char('1'));
        assert_eq!(v.groups.len(), 2);
        assert_eq!(v.groups.iter().map(|g| g.new).sum::<u64>(), 2);
        press(&mut v, &engine, &o, KeyCode::Enter);
        press(&mut v, &engine, &o, KeyCode::Char('2'));
        assert_eq!(v.groups.len(), 1);
        assert_eq!(
            (v.groups[0].sessions, v.groups[0].new, v.groups[0].end),
            (1, 1, 1)
        );
        assert_eq!(v.path(), "All > dport=443 > src=192.0.2.1");
        let fresh = entry("192.0.2.1", 443, 4);
        engine.entries.insert(fresh.key.clone(), fresh);
        v.rebuild(&engine, &o);
        assert_eq!(v.groups[0].sessions, 2);
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert_eq!(v.fields, vec![Field::Src]);
        assert_eq!(v.groups[v.selected].key, "192.0.2.1");
        assert_eq!(v.scopes.len(), 1);
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert_eq!(v.fields, vec![Field::Dport]);
        assert_eq!(v.search, "443");
        assert_eq!(v.sort, 2);
        assert!(v.scopes.is_empty());
        assert_eq!(v.groups[v.selected].key, "443");
    }
    #[test]
    fn ancestor_direction_and_zone_survive_nat_and_custom_regrouping() {
        let mut engine = crate::engine::fixture();
        let mut a = entry("192.0.2.1", 443, 1);
        a.reply.as_mut().unwrap().sport = Some(8443);
        let mut other_zone = a.clone();
        other_zone.key.zone = 5;
        for e in [a, other_zone, entry("192.0.2.1", 8443, 2)] {
            engine.entries.insert(e.key.clone(), e);
        }
        let o = Options::default();
        let mut v = View::new(&o);
        press(&mut v, &engine, &o, KeyCode::Char('6'));
        v.selected = v.groups.iter().position(|g| g.key == "443").unwrap();
        press(&mut v, &engine, &o, KeyCode::Enter);
        press(&mut v, &engine, &o, KeyCode::Char('n'));
        assert_eq!(v.session_total, 1);
        v.input = Some(('g', "dst,dport,proto".into()));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.groups.len(), 1);
        assert_eq!(v.groups[0].sessions, 1);
        assert!(v.groups[0].key.contains("8443"));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert!(v.path().contains("NAT:dst,dport,proto="));
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert!(v.nat);
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert!(!v.nat);
        assert_eq!(v.groups[v.selected].key, "443");
    }
    #[test]
    fn empty_scope_stays_scoped_and_regrouping_uses_more_than_display_limit() {
        let mut engine = crate::engine::fixture();
        for port in 1..=5001 {
            let e = entry("192.0.2.1", 443, port);
            engine.entries.insert(e.key.clone(), e);
        }
        let o = Options::default();
        let mut v = View::new(&o);
        press(&mut v, &engine, &o, KeyCode::Char('6'));
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.sessions.len(), 5000);
        assert_eq!(v.session_total, 5001);
        press(&mut v, &engine, &o, KeyCode::End);
        assert_eq!(v.selected, 5000);
        assert_eq!(v.sessions.len(), 1);
        assert_eq!(v.selected_session().unwrap().key.original.sport, Some(5001));
        let mut terminal = Terminal::new(TestBackend::new(160, 40)).unwrap();
        terminal.draw(|f| v.draw(f, &engine, &o)).unwrap();
        let mut output = Vec::new();
        v.batch(&engine, &o, &mut output).unwrap();
        assert_eq!(
            String::from_utf8(output)
                .unwrap()
                .lines()
                .filter(|l| l.starts_with("tcp "))
                .count(),
            5001
        );
        press(&mut v, &engine, &o, KeyCode::Home);
        assert_eq!(v.sessions.len(), 5000);
        assert_eq!(v.selected_session().unwrap().key.original.sport, Some(1));
        press(&mut v, &engine, &o, KeyCode::Char('1'));
        assert_eq!(v.groups[0].sessions, 5001);
        engine.entries.clear();
        let outside = entry("192.0.2.1", 80, 1);
        engine.entries.insert(outside.key.clone(), outside);
        v.rebuild(&engine, &o);
        assert!(v.groups.is_empty());
        press(&mut v, &engine, &o, KeyCode::Enter);
        assert_eq!(v.scopes.len(), 1);
        press(&mut v, &engine, &o, KeyCode::Esc);
        assert_eq!(v.groups[0].sessions, 1);
    }
    #[test]
    fn layouts_remain_drawable_and_monochrome_across_sizes() {
        let mut engine = crate::engine::fixture();
        let entry = crate::model::fixture();
        engine.entries.insert(entry.key.clone(), entry);
        let o = Options::default();
        let mut v = View::new(&o);
        v.mono = true;
        v.rebuild(&engine, &o);
        for (width, height) in [(160, 40), (80, 24), (70, 20), (40, 12)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|f| v.draw(f, &engine, &o)).unwrap();
            let buffer = terminal.backend().buffer();
            let text = buffer
                .content
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            if width >= 70 {
                assert!(text.contains("Sessions"));
                assert!(text.contains("192.0.2.1"));
            } else {
                assert!(text.contains("terminal needs"));
            }
            for cell in &buffer.content {
                assert_eq!(cell.fg, Color::Reset);
                assert_eq!(cell.bg, Color::Reset);
            }
        }
    }
    #[test]
    fn drilldown_shows_both_tuples_and_unknown_accounting() {
        let mut engine = crate::engine::fixture();
        let mut entry = crate::model::fixture();
        entry.bytes = [None; 2];
        entry.packets = [None; 2];
        engine.entries.insert(entry.key.clone(), entry);
        let o = Options::default();
        let mut v = View::new(&o);
        v.rebuild(&engine, &o);
        assert!(v
            .detail()
            .contains(&("Bytes original".into(), "N/A".into())));
        v.enter();
        v.rebuild(&engine, &o);
        let text = format!("{:?}", v.detail());
        for word in ["Original", "NAT", "Reply", "N/A", "observed", "443"] {
            assert!(text.contains(word), "{word}: {text}");
        }
    }
    #[test]
    fn search_and_original_filter_survive_nat_switch() {
        let mut engine = crate::engine::fixture();
        let mut entry = crate::model::fixture();
        entry.reply.as_mut().unwrap().src = "203.0.113.9".parse().unwrap();
        let mut o = Options::default();
        o.filter.dst = Some(entry.key.original.dst);
        o.fields = vec![Field::Dst];
        engine.entries.insert(entry.key.clone(), entry);
        let mut v = View::new(&o);
        v.nat = true;
        v.search = "203.0.113".into();
        v.rebuild(&engine, &o);
        assert_eq!(v.groups.len(), 1);
        assert_eq!(v.groups[0].key, "203.0.113.9");
    }
}
