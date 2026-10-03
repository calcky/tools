mod kernel;

use anyhow::{bail, Result};
use clap::Parser;
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use kernel::{Btf, Inventory, Preview};
use libbpf_rs::MapHandle;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
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

fn delta_style(app: &App, delta: &str) -> Style {
    if app.no_color {
        return Style::default();
    }
    match delta {
        value if value.starts_with('+') || value.contains(" +") => {
            Style::default().fg(Color::Green)
        }
        value if value.contains("reset") => Style::default().fg(Color::Red),
        "changed" => Style::default().fg(Color::Yellow),
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
    format!(
        "{}...",
        text.chars()
            .take(width.saturating_sub(3))
            .collect::<String>()
    )
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
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);
    let status = format!(
        "{} maps | {} inaccessible | pin scan {}{}",
        app.inventory.maps.len(),
        app.inventory.inaccessible,
        if app.inventory.pins_truncated {
            "partial"
        } else {
            "complete"
        },
        if app.inventory.maps_truncated {
            " | map list truncated"
        } else {
            ""
        }
    );
    frame.render_widget(
        Paragraph::new(status).block(Block::default().borders(Borders::ALL).title("BPF MAPS")),
        parts[0],
    );
    let height = usize::from(parts[1].height.saturating_sub(3));
    let rows = visible_range(app.selected, app.inventory.maps.len(), height)
        .map(|index| {
            let map = &app.inventory.maps[index];
            let info = &map.info;
            let pin = if map.pins.is_empty() {
                "-".into()
            } else {
                map.pins.join(", ")
            };
            Row::new(vec![
                Cell::from(info.id.to_string()),
                Cell::from(info.name.clone()),
                Cell::from(format!("{:?}", info.ty)),
                Cell::from(info.max_entries.to_string()),
                Cell::from(info.key_size.to_string()),
                Cell::from(info.value_size.to_string()),
                Cell::from(pin),
            ])
            .style(style(app, index == app.selected))
        })
        .collect::<Vec<_>>();
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(16),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(["ID", "NAME", "TYPE", "CAPACITY", "KEY", "VALUE", "PIN PATH"])
            .style(style(app, true)),
    )
    .block(Block::default().borders(Borders::ALL).title("Maps"));
    frame.render_widget(table, parts[1]);
    let footer = app
        .message
        .as_deref()
        .unwrap_or("Enter detail   j/k move   r refresh   h help   q quit");
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL)),
        parts[2],
    );
}

fn draw_detail(frame: &mut ratatui::Frame, area: Rect, app: &App, detail: &Detail) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);
    let Some(row) = app
        .inventory
        .maps
        .iter()
        .find(|row| row.info.id == detail.id)
    else {
        return;
    };
    let info = &row.info;
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
    let title = format!("MAP {}  {}  {:?}", info.id, info.name, info.ty);
    let metadata = format!(
        "capacity {} | key {} B | value {} B | BTF {} | interval {:.1}s\npin: {}\n{}",
        info.max_entries,
        info.key_size,
        info.value_size,
        if detail.btf.is_some() {
            "decoded"
        } else {
            "unavailable (hex)"
        },
        app.interval.as_secs_f64(),
        pin,
        detail.error.as_deref().unwrap_or_else(|| {
            if detail.preview.as_ref().is_some_and(|p| p.truncated) {
                "first entries only; more exist"
            } else {
                "preview within limit"
            }
        }),
    );
    frame.render_widget(
        Paragraph::new(metadata).block(Block::default().borders(Borders::ALL).title(title)),
        parts[0],
    );
    let empty = Preview {
        entries: Vec::new(),
        truncated: false,
        read_errors: 0,
        baseline: HashMap::new(),
    };
    let preview = detail.preview.as_ref().unwrap_or(&empty);
    let (table_area, selected_area) = if parts[1].height >= 12 {
        let content = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(5)])
            .split(parts[1]);
        (content[0], Some(content[1]))
    } else {
        (parts[1], None)
    };
    let height = usize::from(table_area.height.saturating_sub(3));
    let rows = visible_range(detail.selected, preview.entries.len(), height)
        .map(|index| {
            let entry = &preview.entries[index];
            Row::new(vec![
                Cell::from(entry.key.clone()),
                Cell::from(entry.value.clone()),
                Cell::from(entry.delta.clone()).style(delta_style(app, &entry.delta)),
            ])
            .style(style(app, index == detail.selected))
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
        let selected = preview.entries.get(detail.selected);
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
    frame.render_widget(
        Paragraph::new("Esc maps | j/k move | r refresh | h help | q quit")
            .block(Block::default().borders(Borders::ALL)),
        parts[2],
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
    use ratatui::backend::TestBackend;

    #[test]
    fn bounded_viewport() {
        assert_eq!(visible_range(90, 100, 10), 85..95);
        assert_eq!(visible_range(2, 5, 10), 0..5);
        assert_eq!(visible_range(0, 0, 10), 0..0);
    }

    #[test]
    fn list_renders_at_80_columns() {
        let app = App {
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
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| draw_frame(frame, &app)).unwrap();
        let text = format!("{:?}", terminal.backend().buffer());
        assert!(text.contains("BPF MAPS"));
        assert!(text.contains("Enter detail"));
    }

    #[test]
    fn clipping_preserves_short_values() {
        assert_eq!(clipped("/sys/fs/bpf/a", 20), "/sys/fs/bpf/a");
        assert_eq!(clipped("123456789", 6), "123...");
    }
}
