mod kernel;

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
    #[arg(short = 'n', default_value_t = 64, value_parser = clap::value_parser!(u16).range(1..=256), help = "Maximum entries read per interval (1..256)")]
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
    help: bool,
    message: Option<String>,
    last_refresh: Instant,
    last_inventory: Instant,
    interval: Duration,
    entry_limit: usize,
    no_color: bool,
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
            help: false,
            message: None,
            last_refresh: Instant::now(),
            last_inventory: Instant::now(),
            interval: Duration::from_secs_f64(args.delay),
            entry_limit: usize::from(args.entries),
            no_color: std::env::var_os("NO_COLOR").is_some(),
        };
        if args.map.is_some() {
            app.open_selected();
        }
        Ok(app)
    }

    fn open_selected(&mut self) {
        let Some(row) = self.inventory.maps.get(self.selected) else {
            return;
        };
        let id = row.info.id;
        match MapHandle::from_map_id(id) {
            Ok(map) => {
                let btf = Btf::open(&row.info);
                self.detail = Some(Detail {
                    id,
                    map,
                    btf,
                    preview: None,
                    selected: 0,
                    error: None,
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
        let baseline = detail
            .preview
            .as_ref()
            .map(|preview| &preview.baseline)
            .cloned()
            .unwrap_or_else(HashMap::new);
        match kernel::preview(
            &detail.map,
            &row.info,
            detail.btf.as_ref(),
            self.entry_limit,
            &baseline,
        ) {
            Ok(preview) => {
                detail.selected = detail.selected.min(preview.entries.len().saturating_sub(1));
                detail.preview = Some(preview);
                detail.error = None;
            }
            Err(err) => {
                detail.preview = None;
                detail.error = Some(err.to_string());
            }
        }
    }

    fn refresh(&mut self, force: bool) {
        if self.detail.is_some() {
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
                Ok(inventory) => {
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
        self.last_refresh = Instant::now();
    }

    fn move_selection(&mut self, down: bool) {
        let (selected, len) = if let Some(detail) = self.detail.as_mut() {
            (
                &mut detail.selected,
                detail.preview.as_ref().map_or(0, |p| p.entries.len()),
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
        match key {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => self.detail = None,
            KeyCode::Char('h') | KeyCode::Char('?') => self.help = true,
            KeyCode::Char('r') => self.refresh(true),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(true),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(false),
            KeyCode::Enter if self.detail.is_none() => self.open_selected(),
            _ => {}
        }
        false
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
        let text = "bpfmap  read-only BPF map viewer\n\n  j/k or arrows   move selection\n  Enter           open map\n  Esc             return to maps\n  r               refresh now\n  h or ?          toggle this help\n  q / Ctrl+C      quit\n\nPreview reads at most -n entries from the beginning each interval.\nHash iteration under concurrent writes is not a consistent snapshot.\nDelta is per observed key; reset/- means a numeric value decreased.\nNo-color mode: set NO_COLOR=1.";
        frame.render_widget(
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Help")),
            area,
        );
        return;
    }
    if let Some(detail) = &app.detail {
        draw_detail(frame, area, app, detail);
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
            Constraint::Length(2),
        ])
        .split(area);
    draw_header(frame, parts[0], app, "MAPS");
    let status = format!(
        "{} maps | {} inaccessible | pins {} | list {}",
        app.inventory.maps.len(),
        app.inventory.inaccessible,
        if app.inventory.pins_truncated {
            "partial"
        } else {
            "complete"
        },
        if app.inventory.maps_truncated {
            "partial"
        } else {
            "complete"
        }
    );
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("Inventory")),
        parts[1],
    );
    let compact = area.width < 80;
    let height = usize::from(parts[2].height.saturating_sub(3));
    let rows = visible_range(app.selected, app.inventory.maps.len(), height)
        .map(|index| {
            let map = &app.inventory.maps[index];
            let info = &map.info;
            let mut cells = vec![
                Cell::from(info.id.to_string()),
                Cell::from(info.name.clone()),
                Cell::from(format!("{:?}", info.ty)),
                Cell::from(capacity(info)),
                Cell::from(info.key_size.to_string()),
                Cell::from(info.value_size.to_string()),
            ];
            if !compact {
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
    let widths = if compact {
        vec![
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(4),
            Constraint::Length(5),
        ]
    } else {
        vec![
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(10),
        ]
    };
    let headers = if compact {
        vec!["ID", "NAME", "TYPE", "CAPACITY", "KEY", "VALUE"]
    } else {
        vec!["ID", "NAME", "TYPE", "CAPACITY", "KEY", "VALUE", "PIN PATH"]
    };
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(style(app, true)))
        .block(Block::default().borders(Borders::ALL).title("Maps"));
    frame.render_widget(table, parts[2]);
    let footer = app
        .message
        .as_deref()
        .unwrap_or("Enter detail   j/k move   r refresh   h help   q quit");
    draw_footer(frame, parts[3], footer);
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
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);
    let info = &row.info;
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
    let title = format!("MAP #{}  {}  {:?}", info.id, info.name, info.ty);
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
    let metadata = format!(
        "{}\npin: {}\n{}",
        clipped(&metrics, usize::from(area.width.saturating_sub(2))),
        pin,
        if preview.is_none() {
            "no key/value preview"
        } else if preview.is_some_and(|p| p.truncated) {
            "first entries only; more exist"
        } else {
            "preview within limit"
        },
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
            Paragraph::new(error.unwrap_or("No entries available")).block(
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
        draw_footer(frame, parts[3], "Esc maps | r refresh | h help | q quit");
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
    let height = usize::from(table_area.height.saturating_sub(3));
    let rows = visible_range(selected, preview.entries.len(), height)
        .map(|index| {
            let entry = &preview.entries[index];
            Row::new(vec![
                Cell::from(entry.key.clone()),
                Cell::from(entry.value.clone()),
                Cell::from(entry.delta.clone()).style(delta_style(app, &entry.delta)),
            ])
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
            Constraint::Percentage(25),
            Constraint::Percentage(45),
            Constraint::Percentage(30),
        ],
    )
    .header(Row::new(["KEY", "VALUE", "DELTA"]).style(style(app, true)))
    .block(Block::default().borders(Borders::ALL).title(format!(
        "Entries {}/{}{} | read errors {}",
        preview.entries.len(),
        app.entry_limit,
        if preview.truncated { "+" } else { "" },
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
        "Esc maps | j/k move | r refresh | h help | q quit",
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
        terminal.draw(|frame| draw_frame(frame, &app))?;
        let wait = app.interval.saturating_sub(app.last_refresh.elapsed());
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

    fn test_app() -> App {
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
            help: false,
            message: None,
            last_refresh: Instant::now(),
            last_inventory: Instant::now(),
            interval: Duration::from_secs(1),
            entry_limit: 64,
            no_color: true,
        }
    }

    fn test_map(ty: MapType) -> MapRow {
        MapRow {
            info: MapMeta {
                id: 42,
                name: "test_map".into(),
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
        let app = test_app();
        let map = test_map(MapType::Hash);
        let preview = Preview {
            entries: vec![Entry {
                key: "0x00000001".into(),
                value: "0x0000000000000002".into(),
                delta: "new".into(),
            }],
            truncated: false,
            read_errors: 0,
            baseline: HashMap::new(),
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
        assert!(text.contains("Entries 1/64"));
        assert!(text.contains("Selected entry"));
        assert!(text.contains("new"));
        assert!(text.contains("BTF hex"));
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
}
