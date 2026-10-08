mod browse;
mod counts;
mod detail;
mod kernel;
mod percpu;
mod refs;
mod xsk;

use anyhow::{bail, Result};
use clap::Parser;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use kernel::{Btf, Inventory, MapRow, Preview};
use libbpf_rs::{MapHandle, MapType};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
    Terminal,
};
use std::{
    collections::HashMap,
    io::{self, IsTerminal},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "Read-only live viewer for BPF map metadata and entries"
)]
struct Args {
    #[arg(short = 'm', value_name = "ID", help = "Open this map ID directly")]
    map: Option<u32>,
    #[arg(short = 'n', default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..=256), help = "Maximum matching entries per data page (1..256)")]
    entries: u16,
    #[arg(short = 'd', default_value_t = 1.0, value_parser = parse_delay, help = "Refresh interval in seconds (0.2..60)")]
    delay: f64,
}

fn parse_delay(value: &str) -> std::result::Result<f64, String> {
    let value: f64 = value.parse().map_err(|_| "expected seconds".to_string())?;
    if !(0.2..=60.0).contains(&value) || !value.is_finite() {
        return Err("interval must be 0.2..60 seconds".into());
    }
    Ok(value)
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        terminal::enable_raw_mode()?;
        if let Err(err) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = terminal::disable_raw_mode();
            return Err(err.into());
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

struct Detail {
    id: u32,
    map: MapHandle,
    btf: Option<Btf>,
    preview: Option<Preview>,
    selected: usize,
    error: Option<String>,
    state: detail::State,
    browse: browse::State,
}

struct DetailView<'a> {
    row: &'a MapRow,
    btf_decoded: bool,
    preview: Option<&'a Preview>,
    selected: usize,
    error: Option<&'a str>,
}

struct App {
    inventory: Inventory,
    direct_id: Option<u32>,
    selected: usize,
    detail: Option<Detail>,
    history: Vec<Detail>,
    detail_serial: u64,
    help: bool,
    message: Option<String>,
    last_refresh: Instant,
    last_inventory: Instant,
    interval: Duration,
    entry_limit: usize,
    no_color: bool,
    counts: HashMap<u32, counts::MapCount>,
    scans: HashMap<u32, counts::MapCount>,
    count_error: Option<String>,
    count_duration: Duration,
    count_worker: Option<counts::Worker>,
    internal_maps: Vec<u32>,
}

impl App {
    fn new(args: &Args) -> Result<Self> {
        let inventory = match args.map {
            Some(id) => kernel::inventory_id(id)?,
            None => kernel::inventory()?,
        };
        let mut app = Self {
            inventory,
            direct_id: args.map,
            selected: 0,
            detail: None,
            history: Vec::new(),
            detail_serial: 0,
            help: false,
            message: None,
            last_refresh: Instant::now(),
            last_inventory: Instant::now(),
            interval: Duration::from_secs_f64(args.delay),
            entry_limit: usize::from(args.entries),
            no_color: std::env::var_os("NO_COLOR").is_some(),
            counts: HashMap::new(),
            scans: HashMap::new(),
            count_error: None,
            count_duration: Duration::ZERO,
            count_worker: Some(counts::Worker::new()),
            internal_maps: Vec::new(),
        };
        app.count_worker.as_mut().unwrap().request(false);
        if args.map.is_some() {
            app.open_selected();
        }
        Ok(app)
    }

    fn count(&self, info: &kernel::MapMeta) -> counts::MapCount {
        match self.counts.get(&info.id) {
            Some(count) if count.value.is_some() => count.clone(),
            Some(count) => self
                .scans
                .get(&info.id)
                .cloned()
                .unwrap_or_else(|| count.clone()),
            _ => self
                .scans
                .get(&info.id)
                .cloned()
                .unwrap_or_else(|| counts::MapCount::fallback(info)),
        }
    }

    fn collect_counts(&mut self) {
        let Some(update) = self.count_worker.as_mut().and_then(counts::Worker::poll) else {
            self.request_references();
            return;
        };
        self.apply_update(update);
        self.request_references();
    }

    fn apply_update(&mut self, update: counts::Update) {
        match update {
            counts::Update::Snapshot(snapshot) => {
                self.counts = snapshot.counts;
                self.count_error = snapshot.error;
                self.count_duration = snapshot.duration;
                self.internal_maps = snapshot.internal;
                self.inventory
                    .maps
                    .retain(|row| !self.internal_maps.contains(&row.info.id));
                self.selected = self
                    .selected
                    .min(self.inventory.maps.len().saturating_sub(1));
            }
            counts::Update::Scan(id, result) => match result {
                Ok(count) => {
                    self.message = Some(format!(
                        "map {id}: {} | {} key scan | {} reads | {:.1} ms",
                        count.label(),
                        if count.source == counts::Source::PartialScan {
                            "incomplete"
                        } else {
                            "completed"
                        },
                        count.scanned,
                        count.duration.as_secs_f64() * 1000.0
                    ));
                    self.scans.insert(id, count);
                }
                Err(error) => self.message = Some(format!("count scan: {error}")),
            },
            counts::Update::References(id, references) => {
                if let Some(detail) = self.detail.as_mut().filter(|detail| detail.id == id) {
                    detail.state.references = Some(references);
                }
            }
            counts::Update::Xsk(id, result) => {
                if let Some(detail) = self.detail.as_mut().filter(|detail| detail.id == id) {
                    match result {
                        Ok(snapshot) => {
                            let key = detail
                                .state
                                .xsk
                                .as_ref()
                                .and_then(|snapshot| snapshot.entries.get(detail.selected))
                                .map(|entry| entry.key);
                            detail.selected = key
                                .and_then(|key| {
                                    snapshot.entries.iter().position(|entry| entry.key == key)
                                })
                                .unwrap_or(
                                    detail
                                        .selected
                                        .min(snapshot.entries.len().saturating_sub(1)),
                                );
                            detail.state.xsk = Some(snapshot);
                            detail.state.xsk_error = None;
                        }
                        Err(error) => {
                            detail.state.xsk = None;
                            detail.state.xsk_error = Some(error.to_string());
                        }
                    }
                }
            }
            counts::Update::Preview(id, generation, result) => {
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| detail.id == id && detail.browse.generation == generation)
                {
                    match result {
                        Ok(preview) => {
                            detail.browse.loading = false;
                            let key = detail
                                .preview
                                .as_ref()
                                .and_then(|p| p.entries.get(detail.selected))
                                .map(|entry| &entry.raw_key);
                            detail.selected = key
                                .and_then(|key| {
                                    preview
                                        .entries
                                        .iter()
                                        .position(|entry| &entry.raw_key == key)
                                })
                                .unwrap_or(
                                    detail.selected.min(preview.entries.len().saturating_sub(1)),
                                );
                            detail.browse.continue_search(&preview);
                            detail.preview = Some(preview);
                            detail.error = None;
                        }
                        Err(error) => {
                            detail.browse.loading = false;
                            detail.preview = None;
                            detail.error = Some(error.to_string());
                        }
                    }
                }
            }
            counts::Update::Targets(id, generation, result) => {
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| detail.id == id && detail.browse.generation == generation)
                {
                    match result {
                        Ok(snapshot) => {
                            let key = detail
                                .state
                                .targets
                                .as_ref()
                                .and_then(|p| p.entries.get(detail.selected))
                                .map(|entry| &entry.raw_key);
                            detail.selected = key
                                .and_then(|key| {
                                    snapshot
                                        .entries
                                        .iter()
                                        .position(|entry| &entry.raw_key == key)
                                })
                                .unwrap_or(
                                    detail
                                        .selected
                                        .min(snapshot.entries.len().saturating_sub(1)),
                                );
                            detail.state.targets = Some(snapshot);
                            detail.browse.loading = false;
                            detail.error = None;
                        }
                        Err(error) => {
                            detail.state.targets = None;
                            detail.browse.loading = false;
                            detail.error = Some(error.to_string());
                        }
                    }
                }
            }
            counts::Update::Program(map, id, result) => {
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| detail.id == map && detail.state.program_id == Some(id))
                {
                    detail.state.program_lines = Some(result.unwrap_or_else(|error| {
                        vec![Line::raw(format!("Program ID {id}: {error}"))]
                    }));
                }
            }
        }
    }

    fn request_references(&mut self) {
        if self.count_worker.as_ref().is_none_or(counts::Worker::busy) {
            return;
        }
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        if detail.browse.pending {
            if let Some(row) = self
                .inventory
                .maps
                .iter()
                .find(|row| row.info.id == detail.id)
            {
                let request = counts::PreviewRequest {
                    info: row.info.clone(),
                    limit: self.entry_limit,
                    previous: detail
                        .preview
                        .as_ref()
                        .map(|p| p.baseline.clone())
                        .unwrap_or_default(),
                    previous_time: detail.preview.as_ref().map(|p| p.measured),
                    query: detail.browse.query.clone(),
                    anchor: detail.browse.anchor.clone(),
                    generation: detail.browse.generation,
                };
                if self
                    .count_worker
                    .as_mut()
                    .is_some_and(|worker| worker.preview(request))
                {
                    detail.browse.pending = false;
                    detail.browse.loading = true;
                }
            }
        }
        if detail.state.targets_pending {
            if let Some(row) = self
                .inventory
                .maps
                .iter()
                .find(|row| row.info.id == detail.id)
            {
                if self.count_worker.as_mut().is_some_and(|worker| {
                    worker.targets(
                        row.info.clone(),
                        self.entry_limit,
                        detail.browse.anchor.clone(),
                        detail.browse.generation,
                    )
                }) {
                    detail.state.targets_pending = false;
                    detail.browse.loading = true;
                }
            }
        }
        if detail.state.program_pending {
            if let Some(id) = detail.state.program_id {
                if self
                    .count_worker
                    .as_mut()
                    .is_some_and(|worker| worker.program(detail.id, id))
                {
                    detail.state.program_pending = false;
                }
            }
        }
        if detail.state.references_pending
            && self
                .count_worker
                .as_mut()
                .is_some_and(|worker| worker.references(detail.id))
        {
            detail.state.references_pending = false;
        }
        if detail.state.xsk_pending
            && self.count_worker.as_mut().is_some_and(|worker| {
                worker.xsk(detail.id, self.entry_limit, detail.state.xsk_retry)
            })
        {
            detail.state.xsk_pending = false;
            detail.state.xsk_retry = false;
        }
    }

    fn scan_selected(&mut self) {
        let row = if let Some(detail) = &self.detail {
            self.inventory
                .maps
                .iter()
                .find(|row| row.info.id == detail.id)
        } else {
            self.inventory.maps.get(self.selected)
        };
        let Some(row) = row else { return };
        if !counts::scannable(row.info.ty) {
            self.message =
                Some("No non-destructive key scan for this type; see COUNT source".into());
        } else if self
            .count_worker
            .as_mut()
            .is_some_and(|worker| worker.scan(row.info.clone()))
        {
            self.message = Some("Counting distinct keys in background...".into());
        } else {
            self.message = Some("Count collection already running; try c again".into());
        }
    }

    fn open_selected(&mut self) {
        let Some(row) = self.inventory.maps.get(self.selected) else {
            return;
        };
        let id = row.info.id;
        self.open_map(id, false);
    }

    fn open_map(&mut self, id: u32, nested: bool) {
        if nested && self.history.len() >= 16 {
            self.message = Some("Maximum inner-map depth reached (16)".into());
            return;
        }
        if !self.inventory.maps.iter().any(|row| row.info.id == id) {
            match kernel::inventory_id(id) {
                Ok(mut inventory) => self.inventory.maps.append(&mut inventory.maps),
                Err(error) => {
                    self.message = Some(format!("map {id}: {error}"));
                    return;
                }
            }
        }
        let Some(row) = self.inventory.maps.iter().find(|row| row.info.id == id) else {
            return;
        };
        match MapHandle::from_map_id(id) {
            Ok(map) => {
                let btf = Btf::open(&row.info);
                let state = detail::State::new(&map, &row.info, btf.as_ref());
                if nested {
                    if let Some(current) = self.detail.take() {
                        self.history.push(current);
                    }
                } else {
                    self.history.clear();
                }
                self.detail_serial = self.detail_serial.wrapping_add(1);
                self.detail = Some(Detail {
                    id,
                    map,
                    btf,
                    preview: None,
                    selected: 0,
                    error: None,
                    state,
                    browse: browse::State {
                        generation: self.detail_serial << 32,
                        ..Default::default()
                    },
                });
                self.refresh_detail();
            }
            Err(err) => self.message = Some(format!("map {id}: {err}")),
        }
    }

    fn refresh_detail(&mut self) {
        let Some(detail) = self.detail.as_mut() else {
            return;
        };
        let Some(row) = self
            .inventory
            .maps
            .iter()
            .find(|row| row.info.id == detail.id)
        else {
            detail.error = Some("map disappeared from inventory; press Esc".into());
            return;
        };
        if row.info.ty == MapType::Xskmap {
            detail.state.xsk_pending = true;
            return;
        }
        if refs::supported(row.info.ty) {
            detail.state.targets_pending = true;
        } else if kernel::previewable(row.info.ty) {
            detail.browse.pending = true;
        }
    }

    fn refresh(&mut self, force: bool) {
        if self.detail.is_some() {
            if let Some(detail) = self.detail.as_mut() {
                detail.state.xsk_retry |= force;
                if force || detail.state.last_configuration.elapsed() >= Duration::from_secs(5) {
                    detail
                        .state
                        .refresh_configuration(&detail.map, detail.btf.as_ref());
                    if force || detail.state.page == detail::Page::Info {
                        detail.state.references_pending = true;
                    }
                }
            }
            self.refresh_detail();
        } else if force || self.last_inventory.elapsed() >= Duration::from_secs(5) {
            let selected_id = self
                .inventory
                .maps
                .get(self.selected)
                .map(|row| row.info.id);
            let result = match self.direct_id {
                Some(id) => kernel::inventory_id(id),
                None => kernel::inventory(),
            };
            match result {
                Ok(mut inventory) => {
                    inventory
                        .maps
                        .retain(|row| !self.internal_maps.contains(&row.info.id));
                    self.selected = selected_id
                        .and_then(|id| inventory.maps.iter().position(|row| row.info.id == id))
                        .unwrap_or(0);
                    self.inventory = inventory;
                    self.message = None;
                }
                Err(err) => self.message = Some(err.to_string()),
            }
            self.last_inventory = Instant::now();
        }
        if let Some(worker) = self.count_worker.as_mut() {
            worker.request(force);
        }
        self.last_refresh = Instant::now();
    }

    fn move_selection(&mut self, down: bool) {
        let (selected, len) = if let Some(detail) = self.detail.as_mut() {
            (
                &mut detail.selected,
                detail.state.xsk.as_ref().map_or_else(
                    || {
                        detail.state.targets.as_ref().map_or_else(
                            || detail.preview.as_ref().map_or(0, |p| p.entries.len()),
                            |p| p.entries.len(),
                        )
                    },
                    |snapshot| snapshot.entries.len(),
                ),
            )
        } else {
            (&mut self.selected, self.inventory.maps.len())
        };
        if len == 0 {
            return;
        }
        *selected = if down {
            (*selected + 1).min(len - 1)
        } else {
            selected.saturating_sub(1)
        };
    }

    fn handle_key(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        if modifiers.contains(KeyModifiers::CONTROL) && key == KeyCode::Char('c') {
            return true;
        }
        if self.help {
            self.help = false;
            return false;
        }
        if self
            .detail
            .as_ref()
            .is_some_and(|detail| detail.browse.input.is_some())
        {
            let detail = self.detail.as_mut().unwrap();
            let input = detail.browse.input.as_mut().unwrap();
            match key {
                KeyCode::Esc => detail.browse.input = None,
                KeyCode::Enter => {
                    let size = self
                        .inventory
                        .maps
                        .iter()
                        .find(|row| row.info.id == detail.id)
                        .map_or(0, |row| row.info.key_size as usize);
                    match input.query(size) {
                        Ok(query) => {
                            detail.browse.set_query(query);
                            detail.browse.input = None;
                            detail.preview = None;
                            detail.selected = 0;
                            detail.state.page = detail::Page::Entries;
                        }
                        Err(error) => input.error = Some(error.to_string()),
                    }
                }
                KeyCode::Backspace => {
                    input.text.pop();
                    input.error = None;
                }
                KeyCode::Char(character) if input.text.len() < 8192 => {
                    input.text.push(character);
                    input.error = None;
                }
                _ => {}
            }
            return false;
        }
        match key {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => {
                if let Some(detail) = self.detail.as_mut().filter(|detail| {
                    matches!(
                        detail.state.page,
                        detail::Page::Entry | detail::Page::Program
                    )
                }) {
                    detail.state.page = detail::Page::Entries;
                    detail.state.scroll = 0;
                } else {
                    self.detail = self.history.pop();
                    self.refresh_detail();
                    self.message = None;
                }
            }
            KeyCode::Char('/') | KeyCode::Char('f') => {
                if let Some(detail) = self.detail.as_mut() {
                    if self
                        .inventory
                        .maps
                        .iter()
                        .find(|row| row.info.id == detail.id)
                        .is_some_and(|row| kernel::previewable(row.info.ty))
                    {
                        detail.browse.input = Some(browse::Input {
                            kind: if key == KeyCode::Char('/') {
                                browse::InputKind::Search
                            } else {
                                browse::InputKind::Key
                            },
                            text: String::new(),
                            error: None,
                        });
                    }
                }
            }
            KeyCode::Char('x') => {
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| !matches!(detail.browse.query, browse::Query::All))
                {
                    detail.browse.set_query(browse::Query::All);
                    detail.preview = None;
                    detail.selected = 0;
                    detail.state.page = detail::Page::Entries;
                }
            }
            KeyCode::Char('[') | KeyCode::Char(']') => {
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| detail.state.page == detail::Page::Entries)
                {
                    let changed = if key == KeyCode::Char('[') {
                        detail.browse.previous()
                    } else {
                        detail.browse.next(
                            detail
                                .state
                                .targets
                                .as_ref()
                                .and_then(|p| p.next_key.as_deref())
                                .or_else(|| {
                                    detail.preview.as_ref().and_then(|p| p.next_key.as_deref())
                                }),
                        )
                    };
                    if changed {
                        detail.preview = None;
                        detail.selected = 0;
                        if self
                            .inventory
                            .maps
                            .iter()
                            .find(|row| row.info.id == detail.id)
                            .is_some_and(|row| refs::supported(row.info.ty))
                        {
                            detail.state.targets = None;
                            detail.state.targets_pending = true;
                            detail.browse.pending = false;
                        }
                    }
                }
            }
            KeyCode::Char('v') => {
                if let Some(detail) = self.detail.as_mut() {
                    detail.browse.counter_mode = !detail.browse.counter_mode;
                }
            }
            KeyCode::Tab if self.detail.is_some() => {
                let detail = self.detail.as_mut().unwrap();
                detail.state.page = if detail.state.page == detail::Page::Info {
                    detail::Page::Entries
                } else {
                    detail::Page::Info
                };
                detail.state.scroll = 0;
            }
            KeyCode::Char('h') | KeyCode::Char('?') => self.help = true,
            KeyCode::Char('r') => self.refresh(true),
            KeyCode::Char('c') => self.scan_selected(),
            KeyCode::Down | KeyCode::Char('j') => self.move_or_scroll(true, 1),
            KeyCode::Up | KeyCode::Char('k') => self.move_or_scroll(false, 1),
            KeyCode::PageDown => self.move_or_scroll(true, 10),
            KeyCode::PageUp => self.move_or_scroll(false, 10),
            KeyCode::Enter if self.detail.is_none() => self.open_selected(),
            KeyCode::Enter => {
                let target = self
                    .detail
                    .as_ref()
                    .filter(|detail| detail.state.page == detail::Page::Entries)
                    .and_then(|detail| detail.state.targets.as_ref()?.entries.get(detail.selected))
                    .cloned();
                if let Some(entry) = target {
                    match entry.kind {
                        refs::Kind::Map => self.open_map(entry.target_id, true),
                        refs::Kind::Program => {
                            let detail = self.detail.as_mut().unwrap();
                            detail.state.program_id = Some(entry.target_id);
                            detail.state.program_pending = true;
                            detail.state.program_lines = None;
                            detail.state.page = detail::Page::Program;
                            detail.state.scroll = 0;
                        }
                    }
                    return false;
                }
                if let Some(detail) = self
                    .detail
                    .as_mut()
                    .filter(|detail| detail.state.page == detail::Page::Entries)
                {
                    if let Some(entry) = detail
                        .preview
                        .as_ref()
                        .and_then(|preview| preview.entries.get(detail.selected))
                    {
                        detail.state.entry_key = Some(entry.raw_key.clone());
                        detail.state.page = detail::Page::Entry;
                        detail.state.scroll = 0;
                    } else if let Some(entry) = detail
                        .state
                        .xsk
                        .as_ref()
                        .and_then(|snapshot| snapshot.entries.get(detail.selected))
                    {
                        detail.state.entry_key = Some(entry.key.to_ne_bytes().to_vec());
                        detail.state.page = detail::Page::Entry;
                        detail.state.scroll = 0;
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn move_or_scroll(&mut self, down: bool, amount: usize) {
        if let Some(detail) = self
            .detail
            .as_mut()
            .filter(|detail| detail.state.page != detail::Page::Entries)
        {
            let scroll = detail.state.scroll.min(detail.state.max_scroll.get());
            detail.state.scroll = if down {
                scroll
                    .saturating_add(amount)
                    .min(detail.state.max_scroll.get())
            } else {
                scroll.saturating_sub(amount)
            };
        } else {
            for _ in 0..amount {
                self.move_selection(down);
            }
        }
    }
}

fn style(app: &App, highlighted: bool) -> Style {
    if highlighted {
        let style = Style::default().add_modifier(Modifier::BOLD);
        if app.no_color {
            style
        } else {
            style.fg(Color::Cyan)
        }
    } else {
        Style::default()
    }
}

fn selected_style(app: &App) -> Style {
    let selected = Style::default().add_modifier(Modifier::BOLD);
    if app.no_color {
        selected
    } else {
        selected.bg(Color::Rgb(31, 64, 52)).fg(Color::White)
    }
}

fn delta_style(app: &App, delta: &str) -> Style {
    if app.no_color {
        return Style::default();
    }
    match delta {
        value if value.starts_with('+') || value.contains(" +") => {
            Style::default().fg(Color::Green)
        }
        value if value.contains("reset") => Style::default().fg(Color::Red),
        "changed" | "new" => Style::default().fg(Color::Yellow),
        _ => Style::default(),
    }
}

fn visible_range(selected: usize, len: usize, height: usize) -> std::ops::Range<usize> {
    if height == 0 || len == 0 {
        return 0..0;
    }
    let start = selected
        .saturating_sub(height / 2)
        .min(len.saturating_sub(height));
    start..(start + height).min(len)
}

fn wrap_cell(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut used = 0;
    for word in text.split_whitespace() {
        let word_width = Span::raw(word).width();
        if used > 0 && used + 1 + word_width > width {
            lines.push(std::mem::take(&mut line));
            used = 0;
        }
        if used > 0 {
            line.push(' ');
            used += 1;
        }
        for ch in word.chars() {
            let ch_width = if ch.is_ascii() {
                1
            } else {
                Span::raw(ch.to_string()).width()
            };
            if used > 0 && used + ch_width > width {
                lines.push(std::mem::take(&mut line));
                used = 0;
            }
            line.push(ch);
            used += ch_width;
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    if lines.len() > 3 {
        lines.truncate(3);
        lines[2] = format!("{}...", clipped(&lines[2], width.saturating_sub(3)));
    }
    lines
}

fn clipped(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    format!(
        "{}...",
        text.chars()
            .take(width.saturating_sub(3))
            .collect::<String>()
    )
}

fn capacity(info: &kernel::MapMeta) -> String {
    if matches!(info.ty, MapType::RingBuf | MapType::UserRingBuf) {
        format!("{} B", info.max_entries)
    } else {
        info.max_entries.to_string()
    }
}

fn draw_header(frame: &mut ratatui::Frame, area: Rect, app: &App, view: &str) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(area);
    let brand = if app.no_color {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("bpfmap", brand),
            Span::raw(format!("  /  {view}")),
        ])),
        columns[0],
    );
    frame.render_widget(
        Paragraph::new("READ ONLY")
            .alignment(Alignment::Right)
            .style(if app.no_color {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            }),
        columns[1],
    );
}

fn draw_footer(frame: &mut ratatui::Frame, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::TOP)),
        area,
    );
}

fn draw_frame(frame: &mut ratatui::Frame, app: &App) {
    let area = frame.area();
    if area.width < 60 || area.height < 16 {
        frame.render_widget(
            Paragraph::new("bpfmap: resize terminal to at least 60x16"),
            area,
        );
        return;
    }
    if app.help {
        let text = concat!(
            "bpfmap  read-only BPF map viewer\n\n",
            "  j/k or arrows  select / scroll; PgUp/PgDn viewport page\n",
            "  Enter          open map / expand entry / follow reference\n",
            "  Tab / Esc      Entries-Info / back one level\n",
            "  /              search displayed key/value text\n",
            "  f              exact key lookup (hex in memory order)\n",
            "  x              clear search / key query\n",
            "  [ / ]          previous / next data page\n",
            "  v              per-CPU counter RATE/s interpretation\n",
            "  r / c          refresh-retry / bounded key count scan\n",
            "  h or ?         help; q / Ctrl+C quit\n\n",
            "Info: config, BTF, pins and loaded-program references.\n",
            "Entry: expanded BTF, raw bytes, per-CPU delta and share.\n",
            "Reference entries: inner maps / program metadata (IDs, not FDs).\n",
            "XSKMAP: real interface/queue; map key need not equal queue.\n",
            "part = incomplete coverage; - = unknown, never assumed empty.\n",
            "COUNT is type-specific; page count is not whole-map count.\n",
            "Live reads are not atomic; NO_COLOR disables colors."
        );
        frame.render_widget(
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Help")),
            area,
        );
        return;
    }
    if let Some(detail) = &app.detail {
        draw_detail(frame, area, app, detail);
        if let Some(input) = &detail.browse.input {
            let popup = Rect {
                x: area.x + 1,
                y: area.y + 1,
                width: area.width.saturating_sub(2),
                height: 5,
            };
            frame.render_widget(ratatui::widgets::Clear, popup);
            let text = vec![
                Line::raw(input.text.clone()),
                Line::raw(input.error.as_deref().unwrap_or("Enter apply | Esc cancel")),
            ];
            frame.render_widget(
                Paragraph::new(text)
                    .block(Block::default().borders(Borders::ALL).title(input.label())),
                popup,
            );
        }
    } else {
        draw_list(frame, area, app);
    }
}

fn draw_list(frame: &mut ratatui::Frame, area: Rect, app: &App) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(5),
            Constraint::Length(2),
        ])
        .split(area);
    draw_header(frame, parts[0], app, "MAPS");
    let status = format!(
        "{} maps{} | {} inaccessible | pins {} | counts {}",
        app.inventory.maps.len(),
        if app.inventory.maps_truncated {
            " (partial)"
        } else {
            ""
        },
        app.inventory.inaccessible,
        if app.inventory.pins_truncated {
            "partial"
        } else {
            "complete"
        },
        if app.count_error.is_some() {
            "unavailable (c scan / r retry)".to_owned()
        } else {
            format!("{:.2} ms", app.count_duration.as_secs_f64() * 1000.0)
        },
    );
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("Inventory")),
        parts[1],
    );
    let sizes = area.width >= 110;
    let pins = area.width >= 150;
    let height = usize::from(parts[2].height.saturating_sub(3));
    let rows = visible_range(app.selected, app.inventory.maps.len(), height)
        .map(|index| {
            let map = &app.inventory.maps[index];
            let info = &map.info;
            let mut cells = vec![
                Cell::from(info.id.to_string()),
                Cell::from(clipped(&info.name, name_width(area.width))),
                Cell::from(format!("{:?}", info.ty)),
                Cell::from(app.count(info).label()),
                Cell::from(capacity(info)),
            ];
            if sizes {
                cells.push(Cell::from(info.key_size.to_string()));
                cells.push(Cell::from(info.value_size.to_string()));
            }
            if pins {
                let pin = if map.pins.is_empty() {
                    "-".into()
                } else {
                    map.pins.join(", ")
                };
                cells.push(Cell::from(pin));
            }
            Row::new(cells).style(if index == app.selected {
                selected_style(app)
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    let mut widths = vec![
        Constraint::Length(7),
        Constraint::Length(name_width(area.width) as u16),
        Constraint::Length(14),
        Constraint::Length(12),
        Constraint::Length(10),
    ];
    let mut headers = vec!["ID", "NAME", "TYPE", "COUNT", "CAPACITY"];
    if sizes {
        widths.extend([Constraint::Length(5), Constraint::Length(5)]);
        headers.extend(["KEY", "VALUE"]);
    }
    if pins {
        widths.push(Constraint::Min(10));
        headers.push("PIN PATH");
    }
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(style(app, true)))
        .block(Block::default().borders(Borders::ALL).title("Maps"));
    frame.render_widget(table, parts[2]);
    if let Some(row) = app.inventory.maps.get(app.selected) {
        let count = app.count(&row.info);
        let text = vec![
            Line::styled(row.info.name.clone(), style(app, true)),
            Line::raw(format!("COUNT {}", count.description())),
            Line::raw(format!(
                "KEY {} B | VALUE {} B | name {}",
                row.info.key_size,
                row.info.value_size,
                if row.info.name != row.info.kernel_name {
                    "BTF"
                } else {
                    "kernel"
                }
            )),
        ];
        frame.render_widget(
            Paragraph::new(text)
                .block(Block::default().borders(Borders::ALL).title("Selected map")),
            parts[3],
        );
    }
    let footer = app
        .message
        .as_deref()
        .or(app.count_error.as_deref())
        .unwrap_or("Enter detail | j/k move | c count | r refresh | h help | q quit");
    draw_footer(frame, parts[4], footer);
}

fn name_width(width: u16) -> usize {
    usize::from(if width >= 150 {
        36
    } else if width >= 110 {
        30
    } else {
        width.saturating_sub(51).max(8)
    })
}

fn draw_detail(frame: &mut ratatui::Frame, area: Rect, app: &App, detail: &Detail) {
    let Some(row) = app
        .inventory
        .maps
        .iter()
        .find(|row| row.info.id == detail.id)
    else {
        return;
    };
    if detail.state.page == detail::Page::Info {
        detail::draw_info(frame, area, app, row, &detail.state);
        return;
    }
    if detail.state.page == detail::Page::Program {
        detail::draw_page(
            frame,
            area,
            app,
            row,
            &detail.state,
            "Referenced program",
            detail
                .state
                .program_lines
                .clone()
                .unwrap_or_else(|| vec![Line::raw("Loading program metadata...")]),
        );
        return;
    }
    if refs::supported(row.info.ty) {
        draw_targets(frame, area, app, row, detail);
        return;
    }
    if row.info.ty == MapType::Xskmap {
        if detail.state.page == detail::Page::Entry {
            xsk::draw_entry(frame, area, app, row, &detail.state);
        } else {
            xsk::draw_entries(frame, area, app, row, &detail.state, detail.selected);
        }
        return;
    }
    if detail.state.page == detail::Page::Entry {
        detail::draw_entry(frame, area, app, row, detail);
        return;
    }
    draw_detail_view(
        frame,
        area,
        app,
        DetailView {
            row,
            btf_decoded: detail.btf.is_some(),
            preview: detail.preview.as_ref(),
            selected: detail.selected,
            error: detail.error.as_deref(),
        },
    );
}

fn draw_targets(frame: &mut ratatui::Frame, area: Rect, app: &App, row: &MapRow, detail: &Detail) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(5),
            Constraint::Length(2),
        ])
        .split(area);
    draw_header(
        frame,
        parts[0],
        app,
        &format!("MAP #{} / REFERENCES", row.info.id),
    );
    frame.render_widget(
        Paragraph::new(format!(
            "{} | {:?} | COUNT {}",
            row.info.name,
            row.info.ty,
            app.count(&row.info).label()
        ))
        .block(Block::default().borders(Borders::ALL).title("Source map")),
        parts[1],
    );
    if let Some(snapshot) = &detail.state.targets {
        let height = usize::from(parts[2].height.saturating_sub(3));
        let rows = visible_range(detail.selected, snapshot.entries.len(), height).map(|index| {
            let entry = &snapshot.entries[index];
            Row::new([
                entry.key.clone(),
                format!("{:?}", entry.kind),
                entry.target_id.to_string(),
                entry.target_name.clone(),
            ])
            .style(if index == detail.selected {
                selected_style(app)
            } else {
                Style::default()
            })
        });
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Percentage(20),
                    Constraint::Length(9),
                    Constraint::Length(9),
                    Constraint::Min(12),
                ],
            )
            .header(Row::new(["KEY", "TARGET", "ID", "NAME"]).style(style(app, true)))
            .block(Block::default().borders(Borders::ALL).title(format!(
                "page {} | {} references | {} scanned | {} | {} errors",
                detail.browse.page(),
                snapshot.entries.len(),
                snapshot.scanned,
                if snapshot.partial || snapshot.truncated {
                    "partial"
                } else {
                    "completed"
                },
                snapshot.read_errors
            ))),
            parts[2],
        );
        let text = snapshot
            .entries
            .get(detail.selected)
            .map(|entry| {
                format!(
                    "{}\nRaw key {}\nReturned object ID; no inferred attachment or owner.",
                    entry.description,
                    kernel::hex(&entry.raw_key)
                )
            })
            .unwrap_or_else(|| "No occupied references in available coverage.".into());
        frame.render_widget(
            Paragraph::new(text)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Selected reference"),
                ),
            parts[3],
        );
    } else {
        frame.render_widget(
            Paragraph::new(
                detail
                    .error
                    .as_deref()
                    .unwrap_or("Loading references in background..."),
            )
            .block(Block::default().borders(Borders::ALL).title("References")),
            parts[2],
        );
    }
    draw_footer(
        frame,
        parts[4],
        app.message
            .as_deref()
            .unwrap_or("Enter target | [ ] data pages | Tab info | Esc back | h help"),
    );
}

fn draw_detail_view(frame: &mut ratatui::Frame, area: Rect, app: &App, view: DetailView<'_>) {
    let DetailView {
        row,
        btf_decoded,
        preview,
        selected,
        error,
    } = view;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(if area.height < 22 { 1 } else { 2 }),
            Constraint::Length(7),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);
    let info = &row.info;
    let count = app.count(info);
    draw_header(frame, parts[0], app, &format!("MAP #{}", info.id));
    let pin = if row.pins.is_empty() {
        "-".to_owned()
    } else {
        format!(
            "{}{}",
            row.pins[0],
            if row.pins.len() > 1 {
                format!(" (+{} pins)", row.pins.len() - 1)
            } else {
                String::new()
            }
        )
    };
    let pin = clipped(&pin, usize::from(area.width.saturating_sub(8)));
    let title = format!("MAP #{}  {:?}", info.id, info.ty);
    let btf_status = if !kernel::previewable(info.ty) {
        "n/a"
    } else if btf_decoded {
        "decoded"
    } else {
        "hex"
    };
    let metrics = if area.width < 90 {
        format!(
            "capacity {} | key {} B | value {} B | BTF {}",
            capacity(info),
            info.key_size,
            info.value_size,
            btf_status,
        )
    } else {
        format!(
            "capacity {} | key {} B | value {} B | BTF {} | interval {:.1}s",
            capacity(info),
            info.key_size,
            info.value_size,
            btf_status,
            app.interval.as_secs_f64(),
        )
    };
    let browse_status = app
        .detail
        .as_ref()
        .filter(|detail| detail.id == info.id)
        .map(|detail| {
            format!(
                "{} | page {} | {}",
                detail.browse.query.label(),
                detail.browse.page(),
                if detail.browse.pending || detail.browse.loading {
                    "loading"
                } else if preview.is_some_and(|p| p.partial) {
                    "partial scan; ] continue"
                } else if preview.is_some_and(|p| p.truncated) {
                    "more entries; ] next"
                } else {
                    "end reached"
                }
            )
        });
    let metadata = format!(
        "name: {}\n{}\nCOUNT {}\npin: {}\n{}",
        info.name,
        clipped(&metrics, usize::from(area.width.saturating_sub(2))),
        clipped(
            &count.description(),
            usize::from(area.width.saturating_sub(8))
        ),
        pin,
        clipped(
            browse_status.as_deref().unwrap_or_else(|| app
                .count_error
                .as_deref()
                .filter(|_| count.value.is_none())
                .unwrap_or(&count.note)),
            usize::from(area.width.saturating_sub(2))
        ),
    );
    frame.render_widget(
        Paragraph::new(metadata).block(Block::default().borders(Borders::ALL).title(title)),
        parts[1],
    );
    let Some(preview) = preview else {
        let message_area = Rect {
            height: parts[2].height.min(4),
            ..parts[2]
        };
        frame.render_widget(
            Paragraph::new(error.unwrap_or("Loading entries in background...")).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if kernel::previewable(info.ty) {
                        "Preview unavailable"
                    } else {
                        "Metadata only"
                    }),
            ),
            message_area,
        );
        draw_footer(
            frame,
            parts[3],
            app.message
                .as_deref()
                .unwrap_or("Tab info | Esc maps | c count | r refresh | h help | q quit"),
        );
        return;
    };
    let (table_area, selected_area) = if parts[2].height >= 12 {
        let content = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(5)])
            .split(parts[2]);
        (content[0], Some(content[1]))
    } else {
        (parts[2], None)
    };
    let max_width = |field: fn(&kernel::Entry) -> &str| {
        preview
            .entries
            .iter()
            .map(|entry| Span::raw(field(entry)).width())
            .max()
            .unwrap_or(0)
    };
    let delta_width = max_width(|entry| &entry.delta).clamp(5, 16);
    let available = usize::from(table_area.width)
        .saturating_sub(8 + delta_width)
        .max(2);
    let key_wanted = max_width(|entry| &entry.key).max(3);
    let value_wanted = max_width(|entry| &entry.value).max(5);
    let key_width = if key_wanted + value_wanted <= available {
        key_wanted
    } else {
        (available * key_wanted / (key_wanted + value_wanted))
            .clamp((available * 35 / 100).max(1), (available * 65 / 100).max(1))
    }
    .min(available - 1);
    let value_width = available - key_width;
    let cells = preview
        .entries
        .iter()
        .map(|entry| {
            (
                wrap_cell(&entry.key, key_width),
                wrap_cell(&entry.value, value_width),
            )
        })
        .collect::<Vec<_>>();
    let height = usize::from(table_area.height.saturating_sub(3));
    let row_height = cells
        .iter()
        .map(|(key, value)| key.len().max(value.len()))
        .max()
        .unwrap_or(1)
        .min(height.max(1));
    let rows = visible_range(selected, preview.entries.len(), height / row_height)
        .map(|index| {
            let entry = &preview.entries[index];
            let (key, value) = &cells[index];
            let separator = "|\n".repeat(row_height);
            Row::new(vec![
                Cell::from(key.join("\n")),
                Cell::from(separator.clone()),
                Cell::from(value.join("\n")),
                Cell::from(separator),
                Cell::from(clipped(&entry.delta, delta_width))
                    .style(delta_style(app, &entry.delta)),
            ])
            .height(row_height as u16)
            .style(if index == selected {
                selected_style(app)
            } else {
                Style::default()
            })
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(key_width as u16),
            Constraint::Length(1),
            Constraint::Length(value_width as u16),
            Constraint::Length(1),
            Constraint::Length(delta_width as u16),
        ],
    )
    .header(Row::new(["KEY", "|", "VALUE", "|", "DELTA"]).style(style(app, true)))
    .block(Block::default().borders(Borders::ALL).title(format!(
            "Preview | {} entries{} | scanned {} | errors {}",
            preview.entries.len(),
            if preview.truncated {
                " (more exist)"
            } else {
                ""
            },
            app.detail
                .as_ref()
                .filter(|detail| detail.id == info.id)
                .map_or(preview.scanned, |detail| detail.browse.scanned),
            preview.read_errors
        )));
    frame.render_widget(table, table_area);
    if let Some(selected_area) = selected_area {
        let selected = preview.entries.get(selected);
        let width = usize::from(selected_area.width.saturating_sub(10));
        let text = selected.map_or_else(
            || "No entries in preview".to_owned(),
            |entry| {
                format!(
                    "Key   {}\nValue {}\nDelta {}",
                    clipped(&entry.key, width),
                    clipped(&entry.value, width),
                    clipped(&entry.delta, width)
                )
            },
        );
        frame.render_widget(
            Paragraph::new(text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Selected entry"),
            ),
            selected_area,
        );
    }
    draw_footer(
        frame,
        parts[3],
        app.message
            .as_deref()
            .unwrap_or("/ search | f key | x clear | [ ] data pages | Enter expand | Tab info | Esc back | h help"),
    );
}

fn run(args: Args) -> Result<()> {
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || std::env::var("TERM").is_ok_and(|term| term == "dumb")
    {
        bail!("bpfmap needs an interactive terminal (TERM must not be dumb)");
    }
    let mut app = App::new(&args)?;
    let guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    loop {
        app.collect_counts();
        terminal.draw(|frame| draw_frame(frame, &app))?;
        let mut wait = app.interval.saturating_sub(app.last_refresh.elapsed());
        if app.count_worker.as_ref().is_some_and(counts::Worker::busy) {
            wait = wait.min(Duration::from_millis(50));
        }
        if event::poll(wait)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && app.handle_key(key.code, key.modifiers) {
                    break;
                }
            }
        }
        if app.last_refresh.elapsed() >= app.interval {
            app.refresh(false);
        }
    }
    drop(terminal);
    drop(guard);
    Ok(())
}

fn main() -> Result<()> {
    run(Args::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::{Entry, MapMeta};
    use libbpf_rs::MapType;
    use ratatui::backend::TestBackend;

    pub(crate) fn test_app() -> App {
        App {
            inventory: Inventory {
                maps: Vec::new(),
                pins_truncated: false,
                maps_truncated: false,
                inaccessible: 0,
            },
            direct_id: None,
            selected: 0,
            detail: None,
            history: Vec::new(),
            detail_serial: 0,
            help: false,
            message: None,
            last_refresh: Instant::now(),
            last_inventory: Instant::now(),
            interval: Duration::from_secs(1),
            entry_limit: 64,
            no_color: true,
            counts: HashMap::new(),
            scans: HashMap::new(),
            count_error: None,
            count_duration: Duration::ZERO,
            count_worker: None,
            internal_maps: Vec::new(),
        }
    }

    pub(crate) fn test_map(ty: MapType) -> MapRow {
        MapRow {
            info: MapMeta {
                id: 42,
                name: "test_map".into(),
                kernel_name: "test_map".into(),
                ty,
                key_size: 4,
                value_size: 8,
                max_entries: 16,
                btf_id: 0,
                btf_key_type_id: 0,
                btf_value_type_id: 0,
            },
            pins: vec!["/sys/fs/bpf/test_map".into()],
        }
    }

    #[test]
    fn bounded_viewport() {
        assert_eq!(visible_range(90, 100, 10), 85..95);
        assert_eq!(visible_range(2, 5, 10), 0..5);
        assert_eq!(visible_range(0, 0, 10), 0..0);
    }

    #[test]
    fn list_renders_at_80_columns() {
        let mut app = test_app();
        app.inventory.maps.push(test_map(MapType::Hash));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw_frame(frame, &app)).unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Inventory"));
        assert!(text.contains("READ ONLY"));
        assert!(text.contains("test_map"));
        assert!(text.contains("Enter detail"));
    }

    #[test]
    fn long_map_names_are_visible_with_counts_at_common_widths() {
        for width in [60, 80, 160] {
            let mut app = test_app();
            let mut map = test_map(MapType::PercpuArray);
            map.info.name = "aiwan_xdp_counters".into();
            map.info.kernel_name = "aiwan_xdp_count".into();
            app.inventory.maps.push(map);
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            terminal.draw(|frame| draw_frame(frame, &app)).unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(text.contains("aiwan_xdp_counters"), "width {width}: {text}");
            assert!(text.contains("COUNT"));
            assert!(text.contains("16 slots"));
        }
    }

    #[test]
    fn unknown_map_count_is_not_presented_as_zero() {
        let mut app = test_app();
        app.inventory.maps.push(test_map(MapType::BloomFilter));
        assert_eq!(app.count(&app.inventory.maps[0].info).value, None);
        app.handle_key(KeyCode::Char('c'), KeyModifiers::NONE);
        assert!(app
            .message
            .as_deref()
            .unwrap()
            .contains("No non-destructive"));
    }

    #[test]
    fn unavailable_counts_preserve_metadata_and_entry_previews() {
        let mut app = test_app();
        app.count_error = Some("count iterator unavailable: missing kernel BTF".into());
        let map = test_map(MapType::Hash);
        let preview = Preview {
            cpu_ids: None,
            entries: vec![Entry {
                raw_key: vec![1, 0, 0, 0],
                key: "known-key".into(),
                value: "known-value".into(),
                delta: "new".into(),
            }],
            truncated: false,
            read_errors: 0,
            baseline: HashMap::new(),
            ..Preview::default()
        };
        assert_eq!(app.count(&map.info).label(), "-");
        assert_eq!(
            app.count(&test_map(MapType::Array).info).label(),
            "16 slots"
        );
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw_detail_view(
                    frame,
                    frame.area(),
                    &app,
                    DetailView {
                        row: &map,
                        btf_decoded: false,
                        preview: Some(&preview),
                        selected: 0,
                        error: None,
                    },
                );
            })
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("missing kernel BTF"));
        assert!(text.contains("test_map"));
        assert!(text.contains("known-key"));
        assert!(text.contains("known-value"));
    }

    #[test]
    fn narrow_list_keeps_key_and_value_sizes() {
        let mut app = test_app();
        app.inventory.maps.push(test_map(MapType::Hash));
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal.draw(|frame| draw_frame(frame, &app)).unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("test_map"));
        assert!(text.contains("CAPACITY"));
        assert!(text.contains("VALUE"));
        assert!(!text.contains("PIN PATH"));
    }

    #[test]
    fn detail_renders_entries_at_80_columns() {
        let mut app = test_app();
        app.message = Some("map 42: 1 | completed key scan | 1 reads".into());
        let map = test_map(MapType::Hash);
        let preview = Preview {
            cpu_ids: None,
            entries: vec![Entry {
                raw_key: vec![1, 0, 0, 0],
                key: "0x00000001".into(),
                value: "0x0000000000000002".into(),
                delta: "new".into(),
            }],
            truncated: false,
            read_errors: 0,
            baseline: HashMap::new(),
            ..Preview::default()
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                draw_detail_view(
                    frame,
                    frame.area(),
                    &app,
                    DetailView {
                        row: &map,
                        btf_decoded: false,
                        preview: Some(&preview),
                        selected: 0,
                        error: None,
                    },
                );
            })
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Preview | 1 entries"));
        assert!(text.contains("Selected entry"));
        assert!(text.contains("new"));
        assert!(text.contains("BTF hex"));
        assert!(text.contains("completed key scan"));
    }

    #[test]
    fn long_flow_preview_keeps_both_endpoints_values_and_separation_visible() {
        for width in [80, 120, 180] {
            let app = test_app();
            let map = test_map(MapType::Hash);
            let preview = Preview {
                entries: (0..20)
                    .map(|index| Entry {
                        raw_key: vec![index],
                        key: format!("192.168.200.117:{index} -> 192.168.201.118:11111 TCP"),
                        value: "generation=104 max_inner_mtu=1500".into(),
                        delta: "=".into(),
                    })
                    .collect(),
                ..Preview::default()
            };
            let mut terminal = Terminal::new(TestBackend::new(width, 24)).unwrap();
            for selected in [0, 19, 0] {
                terminal
                    .draw(|frame| {
                        draw_detail_view(
                            frame,
                            frame.area(),
                            &app,
                            DetailView {
                                row: &map,
                                btf_decoded: true,
                                preview: Some(&preview),
                                selected,
                                error: None,
                            },
                        )
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let text = (10..18)
                    .map(|y| {
                        (0..width)
                            .map(|x| buffer[(x, y)].symbol())
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                assert!(text.contains("192.168.200.117"), "{width}: {text}");
                assert!(text.contains("192.168.201.118"), "{width}: {text}");
                assert!(text.contains("generation=104"), "{width}: {text}");
                assert!(text.contains("max_inner_mtu=1500"), "{width}: {text}");
                assert!(
                    text.contains("|"),
                    "{width}: columns have no separator: {text}"
                );
                assert!(
                    text.contains(&format!("192.168.200.117:{selected}")),
                    "selected row off screen: {text}"
                );
            }
        }
    }

    #[test]
    fn metadata_only_has_no_empty_entries_table() {
        let app = test_app();
        let map = test_map(MapType::RingBuf);
        let mut terminal = Terminal::new(TestBackend::new(60, 16)).unwrap();
        terminal
            .draw(|frame| {
                draw_detail_view(
                    frame,
                    frame.area(),
                    &app,
                    DetailView {
                        row: &map,
                        btf_decoded: false,
                        preview: None,
                        selected: 0,
                        error: Some("this map type is metadata-only"),
                    },
                );
            })
            .unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("Metadata only"));
        assert!(text.contains("capacity 16 B"));
        assert!(!text.contains("Selected entry"));
        assert!(!text.contains("KEY"));
    }

    #[test]
    fn ring_buffer_capacity_is_bytes() {
        assert_eq!(capacity(&test_map(MapType::RingBuf).info), "16 B");
        assert_eq!(capacity(&test_map(MapType::Hash).info), "16");
    }

    #[test]
    fn clipping_preserves_short_values() {
        assert_eq!(clipped("/sys/fs/bpf/a", 20), "/sys/fs/bpf/a");
        assert_eq!(clipped("123456789", 6), "123...");
        assert_eq!(clipped("123456789", 2), "..");
    }

    #[test]
    #[ignore = "requires held browse/reference fixtures and BPFMAP_TEST_HASH/AOM/PROG_ARRAY"]
    fn live_navigation_query_generation_and_layouts() {
        let env_id = |name: &str| std::env::var(name).unwrap().parse::<u32>().unwrap();
        let mut app = test_app();
        let hash = env_id("BPFMAP_TEST_HASH");
        app.open_map(hash, false);
        let generation = app.detail.as_ref().unwrap().browse.generation;
        app.apply_update(counts::Update::Preview(
            hash,
            generation - 1,
            Ok(Preview::default()),
        ));
        assert!(app.detail.as_ref().unwrap().preview.is_none());
        app.handle_key(KeyCode::Char('f'), KeyModifiers::NONE);
        for ch in "c7 00 00 00".chars() {
            app.handle_key(KeyCode::Char(ch), KeyModifiers::NONE);
        }
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(
            app.detail.as_ref().unwrap().browse.query,
            browse::Query::Key(199_u32.to_ne_bytes().to_vec())
        );
        app.apply_update(counts::Update::Preview(
            hash,
            generation,
            Ok(Preview::default()),
        ));
        assert!(app.detail.as_ref().unwrap().preview.is_none());
        app.handle_key(KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(
            app.detail.as_ref().unwrap().browse.query,
            browse::Query::All
        );

        let aom = env_id("BPFMAP_TEST_AOM");
        app.open_map(aom, false);
        let info = app
            .inventory
            .maps
            .iter()
            .find(|row| row.info.id == aom)
            .unwrap()
            .info
            .clone();
        app.apply_update(counts::Update::Targets(
            aom,
            app.detail.as_ref().unwrap().browse.generation,
            refs::load(&info, 64),
        ));
        let target = app
            .detail
            .as_ref()
            .unwrap()
            .state
            .targets
            .as_ref()
            .unwrap()
            .entries[0]
            .target_id;
        for (width, height) in [(60, 16), (80, 24), (160, 40)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal.draw(|frame| draw_frame(frame, &app)).unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(
                text.contains("TARGET") && text.contains("refs_inner"),
                "{text}"
            );
        }
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(app.detail.as_ref().unwrap().id, target);
        assert_eq!(app.history.len(), 1);
        app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
        assert_eq!(app.detail.as_ref().unwrap().id, aom);
        assert!(app.history.is_empty());

        let pa = env_id("BPFMAP_TEST_PROG_ARRAY");
        app.open_map(pa, false);
        let info = app
            .inventory
            .maps
            .iter()
            .find(|row| row.info.id == pa)
            .unwrap()
            .info
            .clone();
        app.apply_update(counts::Update::Targets(
            pa,
            app.detail.as_ref().unwrap().browse.generation,
            refs::load(&info, 64),
        ));
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.detail.as_ref().unwrap().state.page == detail::Page::Program);
        let id = app.detail.as_ref().unwrap().state.program_id.unwrap();
        app.apply_update(counts::Update::Program(pa, id, refs::program_lines(id)));
        let text = app
            .detail
            .as_ref()
            .unwrap()
            .state
            .program_lines
            .as_ref()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("64 of 64; complete"), "{text}");
        app.handle_key(KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.detail.as_ref().unwrap().state.page == detail::Page::Entries);
    }
}
