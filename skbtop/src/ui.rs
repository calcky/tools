use crate::model::{Counters, Kind, Latency, PathKey, Row, Snapshot};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::{
    layout::{Alignment, Constraint, Flex, Layout, Position, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, HighlightSpacing, Paragraph, Row as TableRow, Table, TableState, Wrap,
    },
    Frame,
};
use std::collections::BTreeMap;

const KINDS: [Kind; 3] = [Kind::Input, Kind::Output, Kind::Forward];
const STAGES: [&str; 3] = ["STACK", "QUEUE", "TOTAL"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Stack,
    Queue,
    Total,
}

const LATENCY_STAGES: [Stage; 3] = [Stage::Stack, Stage::Queue, Stage::Total];

impl Stage {
    fn initial(self) -> &'static str {
        match self {
            Self::Stack => "S",
            Self::Queue => "Q",
            Self::Total => "T",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Metric {
    Avg,
    Min,
    Max,
    Newest,
}

const METRICS: [Metric; 4] = [Metric::Avg, Metric::Min, Metric::Max, Metric::Newest];

impl Metric {
    fn label(self) -> &'static str {
        match self {
            Self::Avg => "Avg",
            Self::Min => "Min",
            Self::Max => "Max",
            Self::Newest => "Newest",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Sort {
    Path,
    InBandwidth,
    #[default]
    Bandwidth,
    InPps,
    Pps,
    Latency(Metric, Stage),
    Pending,
}

impl Sort {
    fn for_kind(self, kind: Kind) -> Self {
        match self {
            Self::Latency(metric, _) if kind == Kind::Input => Self::Latency(metric, Stage::Stack),
            _ => self,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Path => "PATH",
            Self::InBandwidth => "IN bit/s",
            Self::Bandwidth => "OUT bit/s",
            Self::InPps => "IN PPS",
            Self::Pps => "OUT PPS",
            Self::Latency(metric, stage) => {
                const LABELS: [[&str; 3]; 4] = [
                    ["Stack avg", "Queue avg", "Total avg"],
                    ["Stack min", "Queue min", "Total min"],
                    ["Stack max", "Queue max", "Total max"],
                    ["Stack newest", "Queue newest", "Total newest"],
                ];
                LABELS[metric as usize][stage as usize]
            }
            Self::Pending => "PEND",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Bandwidth => Self::Pps,
            Self::Pps => Self::Latency(Metric::Avg, Stage::Total),
            _ => Self::Bandwidth,
        }
    }

    fn latency(self, row: &Row) -> Option<f64> {
        let Self::Latency(metric, stage) = self.for_kind(row.key.kind) else {
            return None;
        };
        let latency = &row.latency[stage as usize];
        match metric {
            Metric::Avg => latency.avg_us,
            Metric::Min => latency.min_us,
            Metric::Max => latency.max_us,
            Metric::Newest => {
                // Never combine stages from different completed samples.
                let total = &row.latency[row.key.kind.primary_stage()];
                if total.newest_us.is_some()
                    && total.newest_at_ns.is_some()
                    && latency.newest_at_ns == total.newest_at_ns
                {
                    latency.newest_us
                } else {
                    None
                }
            }
        }
    }

    fn is_min(self) -> bool {
        matches!(self, Self::Latency(Metric::Min, _))
    }

    fn score(self, rows: &[&Row]) -> Option<f64> {
        if matches!(self, Self::Latency(..)) {
            let values = rows
                .iter()
                .filter_map(|row| self.latency(row))
                .filter(|value| value.is_finite() && *value >= 0.0);
            return if self.is_min() {
                values.min_by(f64::total_cmp)
            } else {
                values.max_by(f64::total_cmp)
            };
        }
        match self {
            Self::InBandwidth => Some(rows.iter().map(|row| nonnegative(row.in_bps)).sum()),
            Self::Bandwidth => Some(rows.iter().map(|row| nonnegative(row.bps)).sum()),
            Self::InPps => Some(rows.iter().map(|row| nonnegative(row.in_pps)).sum()),
            Self::Pps => Some(rows.iter().map(|row| nonnegative(row.pps)).sum()),
            Self::Pending => Some(rows.iter().map(|row| row.pending as f64).sum()),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Panel {
    state: TableState,
    keys: Vec<PathKey>,
    page: usize,
}

impl Panel {
    fn update(&mut self, rows: &[&Row], page: usize) {
        let old_index = self.state.selected().unwrap_or(0);
        let selected = self.keys.get(old_index).copied();
        self.keys = rows.iter().map(|row| row.key).collect();
        self.page = page.max(1);
        let index = selected
            .and_then(|key| self.keys.iter().position(|candidate| *candidate == key))
            .unwrap_or(old_index)
            .min(self.keys.len().saturating_sub(1));
        self.select(index);
    }

    fn select(&mut self, index: usize) {
        if self.keys.is_empty() {
            self.state.select(None);
            *self.state.offset_mut() = 0;
            return;
        }
        let index = index.min(self.keys.len() - 1);
        self.state.select(Some(index));
        let offset = self.state.offset_mut();
        *offset = (*offset).min(self.keys.len().saturating_sub(self.page));
        if index < *offset {
            *offset = index;
        } else if index >= offset.saturating_add(self.page) {
            *offset = index + 1 - self.page;
        }
    }

    fn move_by(&mut self, amount: usize, down: bool) {
        let index = self.state.selected().unwrap_or(0);
        self.select(if down {
            index.saturating_add(amount)
        } else {
            index.saturating_sub(amount)
        });
    }
}

pub struct Ui {
    panels: [Panel; 3],
    focus: usize,
    sort: Sort,
    descending: bool,
    headers: Vec<(Rect, usize, Sort)>,
    search: String,
    editing: Option<String>,
    detail: Option<PathKey>,
    detail_scroll: u16,
    detail_page: u16,
    detail_max_scroll: u16,
    no_color: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self::new()
    }
}

impl Ui {
    pub fn new() -> Self {
        Self {
            panels: std::array::from_fn(|_| Panel::default()),
            focus: 0,
            sort: Sort::default(),
            descending: true,
            headers: Vec::new(),
            search: String::new(),
            editing: None,
            detail: None,
            detail_scroll: 0,
            detail_page: 1,
            detail_max_scroll: 0,
            no_color: std::env::var_os("NO_COLOR").is_some(),
        }
    }

    fn accent(&self, color: Color) -> Style {
        if self.no_color {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }

    fn set_sort(&mut self, sort: Sort) {
        self.descending = if self.sort == sort {
            !self.descending
        } else {
            sort != Sort::Path
        };
        self.sort = sort;
        for panel in &mut self.panels {
            panel.state = TableState::default();
            panel.keys.clear();
        }
    }

    pub fn mouse(&mut self, event: MouseEvent) -> bool {
        if self.editing.is_some()
            || self.detail.is_some()
            || event.kind != MouseEventKind::Down(MouseButton::Left)
        {
            return false;
        }
        let position = Position::new(event.column, event.row);
        if let Some((_, panel, sort)) = self
            .headers
            .iter()
            .find(|(area, _, _)| area.contains(position))
            .copied()
        {
            self.focus = panel;
            self.sort = self.sort.for_kind(KINDS[panel]);
            self.set_sort(sort);
            return true;
        }
        false
    }

    pub fn key(&mut self, event: KeyEvent) -> bool {
        if event.kind == KeyEventKind::Release {
            return false;
        }
        if event.modifiers.contains(KeyModifiers::CONTROL) && event.code == KeyCode::Char('c') {
            return true;
        }
        if self.editing.is_some() {
            match event.code {
                KeyCode::Esc => self.search = self.editing.take().unwrap_or_default(),
                KeyCode::Enter => self.editing = None,
                KeyCode::Backspace => {
                    self.search.pop();
                }
                KeyCode::Char('u') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.search.clear()
                }
                KeyCode::Char(ch)
                    if !event
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !ch.is_control() =>
                {
                    self.search.push(ch)
                }
                _ => {}
            }
            return false;
        }
        if event.code == KeyCode::Char('q') {
            return true;
        }
        if self.detail.is_some() {
            match event.code {
                KeyCode::Esc => self.detail = None,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.detail_scroll = self.detail_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => {
                    self.detail_scroll = self.detail_scroll.saturating_add(self.detail_page)
                }
                KeyCode::PageUp => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(self.detail_page)
                }
                KeyCode::Home => self.detail_scroll = 0,
                KeyCode::End => self.detail_scroll = self.detail_max_scroll,
                _ => {}
            }
            self.detail_scroll = self.detail_scroll.min(self.detail_max_scroll);
            return false;
        }
        let panel = &mut self.panels[self.focus];
        match event.code {
            KeyCode::Tab => self.focus = (self.focus + 1) % KINDS.len(),
            KeyCode::BackTab => self.focus = (self.focus + KINDS.len() - 1) % KINDS.len(),
            KeyCode::Down | KeyCode::Char('j') => panel.move_by(1, true),
            KeyCode::Up | KeyCode::Char('k') => panel.move_by(1, false),
            KeyCode::PageDown => panel.move_by(panel.page, true),
            KeyCode::PageUp => panel.move_by(panel.page, false),
            KeyCode::Home => panel.select(0),
            KeyCode::End => panel.select(panel.keys.len().saturating_sub(1)),
            KeyCode::Char('s') => self.set_sort(self.sort.next()),
            KeyCode::Char('S') => self.set_sort(self.sort),
            KeyCode::Char('/') => self.editing = Some(self.search.clone()),
            KeyCode::Esc => self.search.clear(),
            KeyCode::Enter => {
                self.detail = panel
                    .state
                    .selected()
                    .and_then(|index| panel.keys.get(index).copied());
                self.detail_scroll = 0;
            }
            _ => {}
        }
        false
    }

    pub fn draw(&mut self, frame: &mut Frame, snapshot: &Snapshot) {
        self.headers.clear();
        let area = frame.area();
        if area.width == 0 || area.height == 0 {
            return;
        }
        if area.width < 80 || area.height < 24 {
            let message = format!(
                "skbtop\nTerminal too small (minimum 80x24).\nINPUT {}  OUTPUT {}  FORWARD {}",
                snapshot
                    .rows
                    .iter()
                    .filter(|row| row.key.kind == Kind::Input)
                    .count(),
                snapshot
                    .rows
                    .iter()
                    .filter(|row| row.key.kind == Kind::Output)
                    .count(),
                snapshot
                    .rows
                    .iter()
                    .filter(|row| row.key.kind == Kind::Forward)
                    .count(),
            );
            frame.render_widget(Paragraph::new(message).wrap(Wrap { trim: false }), area);
            return;
        }
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .areas(area);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("skbtop", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!(
                        "  #{}  {:.1}s  interval {:.2}s  latency us",
                        snapshot.sequence, snapshot.elapsed_secs, snapshot.interval_secs
                    )),
                ]),
                Line::raw(health_line(snapshot)),
            ]),
            header,
        );

        if let Some(key) = self.detail {
            self.draw_detail(frame, body, snapshot, key);
        } else {
            let areas: [Rect; 3] = Layout::vertical([Constraint::Ratio(1, 3); 3]).areas(body);
            for (index, area) in areas.into_iter().enumerate() {
                let rows = ordered_rows(
                    snapshot,
                    KINDS[index],
                    self.sort,
                    self.descending,
                    &self.search,
                );
                let recorded = snapshot
                    .rows
                    .iter()
                    .filter(|row| row.key.kind == KINDS[index])
                    .count();
                self.draw_panel(frame, area, index, &rows, recorded);
            }
        }
        let status = if self.editing.is_some() {
            format!("/{}_", clean(&self.search))
        } else if self.detail.is_some() {
            "Esc back  j/k scroll  PgUp/PgDn  q quit".into()
        } else {
            format!(
                "sort: {} {}  filter: {}  focus: {}",
                self.sort.label(),
                if self.descending { "desc" } else { "asc" },
                if self.search.is_empty() {
                    "all".into()
                } else {
                    clean(&self.search)
                },
                KINDS[self.focus].label()
            )
        };
        let hints = if self.detail.is_some() || self.editing.is_some() {
            ""
        } else {
            "Click header sort | s/S sort/reverse | Tab focus | j/k | / | Enter | q"
        };
        frame.render_widget(
            Paragraph::new(vec![Line::raw(status), Line::raw(hints)]),
            footer,
        );
    }

    fn draw_panel(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        index: usize,
        rows: &[&Row],
        recorded: usize,
    ) {
        let focused = index == self.focus;
        let border = if focused {
            self.accent(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let block = Block::default().borders(Borders::ALL).border_style(border);
        let inner = block.inner(area);
        self.panels[index].update(rows, inner.height.saturating_sub(2) as usize);
        let selected = self.panels[index]
            .state
            .selected()
            .unwrap_or(0)
            .min(rows.len().saturating_sub(1));
        let first = if rows.is_empty() {
            0
        } else {
            self.panels[index].state.offset() + 1
        };
        let last = (self.panels[index].state.offset() + self.panels[index].page).min(rows.len());
        let title = format!(
            " {}{}  visible {}-{}  matched {}  recorded {}  selected {} ",
            if focused { "> " } else { "" },
            KINDS[index].label(),
            first,
            last,
            rows.len(),
            recorded,
            if rows.is_empty() { 0 } else { selected + 1 },
        );
        frame.render_widget(block.title(title), area);
        let kind = KINDS[index];
        let panel_sort = self.sort.for_kind(kind);
        let columns = main_columns(inner.width, kind);
        let fixed: u16 = columns.iter().map(|(_, width)| width).sum();
        let path_width = inner
            .width
            .saturating_sub(fixed + columns.len() as u16 - 1 + 2);
        let constraints: Vec<Constraint> = columns
            .iter()
            .enumerate()
            .map(|(i, (_, width))| Constraint::Length(if i == 0 { path_width } else { *width }))
            .collect();
        let [_selection, column_area] =
            Layout::horizontal([Constraint::Length(2), Constraint::Fill(0)]).areas(inner);
        let column_rects = Layout::horizontal(constraints.clone())
            .flex(Flex::Start)
            .spacing(1)
            .split(column_area);
        for ((sort, _), area) in columns.iter().zip(column_rects.iter()) {
            let latency = matches!(sort, Sort::Latency(..));
            self.headers.push((
                Rect::new(
                    area.x,
                    inner.y + u16::from(latency),
                    area.width,
                    if latency { 1 } else { 2 },
                ),
                index,
                *sort,
            ));
        }
        let max_bps = rows
            .iter()
            .map(|row| nonnegative(row.bps))
            .fold(0.0, f64::max);
        let max_pps = rows
            .iter()
            .map(|row| nonnegative(row.pps))
            .fold(0.0, f64::max);
        let max_in_bps = rows
            .iter()
            .map(|row| nonnegative(row.in_bps))
            .fold(0.0, f64::max);
        let max_in_pps = rows
            .iter()
            .map(|row| nonnegative(row.in_pps))
            .fold(0.0, f64::max);
        let latency_extrema: Vec<_> = columns
            .iter()
            .map(|(sort, _)| {
                rows.iter()
                    .filter_map(|row| sort.latency(row))
                    .filter(|value| value.is_finite() && *value >= 0.0)
                    .reduce(|a, b| if sort.is_min() { a.min(b) } else { a.max(b) })
            })
            .collect();
        let emphatic = self.accent(Color::Cyan).add_modifier(Modifier::BOLD);
        let latency_style = self.accent(Color::Yellow).add_modifier(Modifier::BOLD);
        let items: Vec<TableRow> = rows
            .iter()
            .map(|row| {
                let metric = |value: f64, maximum: f64, label: String| {
                    (
                        label,
                        if nonnegative(value) > 0.0 && value == maximum {
                            emphatic
                        } else {
                            Style::default()
                        },
                    )
                };
                let cells = columns
                    .iter()
                    .enumerate()
                    .map(|(i, (sort, width))| {
                        let width = if i == 0 { path_width } else { *width } as usize;
                        let (content, style) = match sort {
                            Sort::Path => (path_label(row, width), Style::default()),
                            Sort::InBandwidth => metric(row.in_bps, max_in_bps, rate(row.in_bps)),
                            Sort::Bandwidth => metric(row.bps, max_bps, rate(row.bps)),
                            Sort::InPps => metric(row.in_pps, max_in_pps, rate(row.in_pps)),
                            Sort::Pps => metric(row.pps, max_pps, rate(row.pps)),
                            Sort::Pending => (row.pending.to_string(), Style::default()),
                            Sort::Latency(..) => {
                                let value = sort.latency(row);
                                (
                                    latency_number(value, width),
                                    if value.is_some() && value == latency_extrema[i] {
                                        if sort.is_min() {
                                            emphatic
                                        } else {
                                            latency_style
                                        }
                                    } else {
                                        Style::default()
                                    },
                                )
                            }
                        };
                        Cell::from(Line::raw(clamp(&content, width)).alignment(if i == 0 {
                            Alignment::Left
                        } else {
                            Alignment::Right
                        }))
                        .style(style)
                    })
                    .collect::<Vec<_>>();
                TableRow::new(cells)
            })
            .collect();
        let table = Table::new(items, constraints)
            .header(
                TableRow::new(columns.iter().map(|(sort, _)| {
                    let label = if let Sort::Latency(_, stage) = sort {
                        stage.initial()
                    } else {
                        sort.label()
                    };
                    let label = if *sort == panel_sort {
                        format!(
                            "{label}{}",
                            if self.descending {
                                "\u{2193}"
                            } else {
                                "\u{2191}"
                            }
                        )
                    } else {
                        label.into()
                    };
                    let label = Line::raw(label).alignment(if *sort == Sort::Path {
                        Alignment::Left
                    } else {
                        Alignment::Right
                    });
                    let lines = if matches!(sort, Sort::Latency(..)) {
                        vec![Line::raw(""), label]
                    } else {
                        vec![label, Line::raw("")]
                    };
                    Cell::from(lines).style(if *sort == panel_sort {
                        emphatic
                    } else {
                        Style::default()
                    })
                }))
                .height(2)
                .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .column_spacing(1)
            .flex(Flex::Start)
            .highlight_symbol(if focused { "> " } else { "  " })
            .highlight_spacing(HighlightSpacing::Always)
            .row_highlight_style(if focused {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            });
        frame.render_stateful_widget(table, inner, &mut self.panels[index].state);
        if rows.is_empty() && inner.height > 2 {
            let first = column_rects[0];
            frame.render_widget(
                Paragraph::new(clamp(
                    if self.search.is_empty() {
                        "No paths"
                    } else {
                        "No matches"
                    },
                    first.width as usize,
                )),
                Rect::new(first.x, inner.y + 2, first.width, 1),
            );
        }
        let separator = self.accent(Color::DarkGray);
        for (i, column) in column_rects
            .iter()
            .enumerate()
            .take(columns.len().saturating_sub(1))
        {
            let x = column.right();
            if x >= inner.right() {
                continue;
            }
            let inside_group = matches!((columns[i].0, columns[i + 1].0), (Sort::Latency(a, _), Sort::Latency(b, _)) if a == b);
            for y in inner.y + u16::from(inside_group)..inner.bottom() {
                frame.buffer_mut()[(x, y)]
                    .set_symbol("\u{2502}")
                    .set_style(separator);
            }
            frame.buffer_mut()[(x, area.bottom() - 1)]
                .set_symbol("\u{2534}")
                .set_style(border);
        }
        for metric in METRICS {
            let group: Vec<_> = columns
                .iter()
                .zip(column_rects.iter())
                .filter(|((sort, _), _)| matches!(sort, Sort::Latency(m, _) if *m == metric))
                .collect();
            if let (Some((_, first)), Some((_, last))) = (group.first(), group.last()) {
                frame.render_widget(
                    Paragraph::new(metric.label())
                        .alignment(Alignment::Center)
                        .style(Style::default().add_modifier(Modifier::BOLD)),
                    Rect::new(first.x, inner.y, last.right() - first.x, 1),
                );
            }
        }
    }

    fn draw_detail(&mut self, frame: &mut Frame, area: Rect, snapshot: &Snapshot, key: PathKey) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Details ")
            .border_style(self.accent(Color::Cyan));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let mut lines = Vec::new();
        if let Some(row) = snapshot.rows.iter().find(|row| row.key == key) {
            lines.push(Line::styled(
                format!(
                    "{}  {}",
                    key.kind.label(),
                    path_label(row, inner.width as usize)
                ),
                Style::default().add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::raw(format!(
                "netns={}  ingress={}#{}  egress={}#{}",
                key.netns, key.ingress, key.ingress_generation, key.egress, key.egress_generation
            )));
            lines.push(Line::raw(format!(
                "IN bit/s={}  OUT bit/s={}",
                rate(row.in_bps),
                rate(row.bps),
            )));
            lines.push(Line::raw(format!(
                "IN PPS={}  OUT PPS={}  pending={}",
                rate(row.in_pps),
                rate(row.pps),
                row.pending,
            )));
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "LATENCY (us; percentiles approximate): min, avg, p50, p90, p95, p99, max, newest",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            for &stage in key.kind.latency_stages() {
                lines.push(Line::styled(
                    STAGES[stage],
                    Style::default().add_modifier(Modifier::BOLD),
                ));
                lines.push(Line::raw(latency_line("interval", &row.latency[stage])));
                lines.push(Line::raw(latency_line(
                    "lifetime",
                    &row.total_latency[stage],
                )));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                "COUNTERS",
                Style::default().add_modifier(Modifier::BOLD),
            ));
            lines.extend(counter_lines("interval", &row.interval));
            lines.extend(counter_lines("lifetime", &row.total));
        } else {
            lines.push(Line::raw("Path no longer present in this snapshot."));
            lines.push(Line::raw(format!(
                "{}  netns={}  ingress={}#{}  egress={}#{}",
                key.kind.label(),
                key.netns,
                key.ingress,
                key.ingress_generation,
                key.egress,
                key.egress_generation
            )));
        }
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "HEALTH",
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::raw(health_line(snapshot)));
        lines.extend(counter_lines("global", &snapshot.health.global));
        lines.push(Line::styled(
            "OBSERVATION HEALTH (lifetime)",
            Style::default().add_modifier(Modifier::BOLD),
        ));
        if snapshot.health.errors.is_empty() {
            lines.push(Line::raw("none"));
        } else {
            lines.extend(
                snapshot
                    .health
                    .errors
                    .iter()
                    .map(|(name, count)| Line::raw(format!("{}: {count}", clean(name)))),
            );
        }
        let lines = wrap_details(lines, inner.width as usize);
        self.detail_page = inner.height.max(1);
        self.detail_max_scroll = lines
            .len()
            .saturating_sub(inner.height as usize)
            .min(u16::MAX as usize) as u16;
        self.detail_scroll = self.detail_scroll.min(self.detail_max_scroll);
        frame.render_widget(Paragraph::new(lines).scroll((self.detail_scroll, 0)), inner);
    }
}

fn ordered_rows<'a>(
    snapshot: &'a Snapshot,
    kind: Kind,
    sort: Sort,
    descending: bool,
    search: &str,
) -> Vec<&'a Row> {
    let mut groups: BTreeMap<PathKey, Vec<&Row>> = BTreeMap::new();
    for row in snapshot.rows.iter().filter(|row| row.key.kind == kind) {
        groups.entry(row.key.group()).or_default().push(row);
    }
    let search = search.to_lowercase();
    let mut groups: Vec<_> = groups
        .into_iter()
        .filter(|(_, rows)| {
            search.is_empty()
                || rows.iter().any(|row| {
                    format!(
                        "{} {} {} {} {} {} {}",
                        row.ingress_name,
                        row.egress_name,
                        row.key.kind.label(),
                        row.key.ingress,
                        row.key.egress,
                        row.key.netns,
                        path_label(row, usize::MAX)
                    )
                    .to_lowercase()
                    .contains(&search)
                })
        })
        .collect();
    groups.sort_by(|(a_key, a), (b_key, b)| {
        let order = if sort == Sort::Path {
            let name = |rows: &[&Row]| {
                path_label(rows.iter().min_by_key(|row| row.key).unwrap(), usize::MAX)
                    .to_lowercase()
            };
            let order = name(a).cmp(&name(b));
            if descending {
                order.reverse()
            } else {
                order
            }
        } else {
            match (sort.score(a), sort.score(b)) {
                (Some(a), Some(b)) => {
                    if descending {
                        b.total_cmp(&a)
                    } else {
                        a.total_cmp(&b)
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        };
        order.then(a_key.cmp(b_key))
    });
    groups
        .into_iter()
        .flat_map(|(_, mut rows)| {
            rows.sort_by_key(|row| row.key);
            rows
        })
        .collect()
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

// Pre-wrap details so scrolling has exact bounds without Ratatui's unstable line-count API.
fn wrap_details(lines: Vec<Line<'static>>, width: usize) -> Vec<Line<'static>> {
    let mut result = Vec::new();
    for line in lines {
        let mut current = String::new();
        for word in line.to_string().split_whitespace() {
            let candidate = if current.is_empty() {
                word.into()
            } else {
                format!("{current} {word}")
            };
            if Span::raw(candidate.as_str()).width() <= width {
                current = candidate;
                continue;
            }
            if !current.is_empty() {
                result.push(Line::styled(std::mem::take(&mut current), line.style));
            }
            let span = Span::raw(word);
            for grapheme in span.styled_graphemes(Style::default()) {
                let candidate = format!("{current}{}", grapheme.symbol);
                if Span::raw(candidate.as_str()).width() > width && !current.is_empty() {
                    result.push(Line::styled(std::mem::take(&mut current), line.style));
                }
                current.push_str(grapheme.symbol);
            }
        }
        result.push(Line::styled(current, line.style));
    }
    result
}

fn clamp(value: &str, width: usize) -> String {
    let value = clean(value);
    if Span::raw(value.as_str()).width() <= width {
        return value;
    }
    if width == 0 {
        return String::new();
    }
    let mut result = String::new();
    let mut used = 0;
    let span = Span::raw(value.as_str());
    for grapheme in span.styled_graphemes(Style::default()) {
        let grapheme_width = Span::raw(grapheme.symbol).width();
        if used + grapheme_width > width - 1 {
            break;
        }
        result.push_str(grapheme.symbol);
        used += grapheme_width;
    }
    result.push('~');
    result
}

fn path_label(row: &Row, width: usize) -> String {
    let interface = |name: &str, index: u32| {
        if name.is_empty() {
            format!("if{index}")
        } else {
            clean(name)
        }
    };
    let ingress = interface(&row.ingress_name, row.key.ingress);
    let egress = interface(&row.egress_name, row.key.egress);
    match row.key.kind {
        Kind::Input => clamp(
            &format!("{} -> LOCAL", clamp(&ingress, width.saturating_sub(9))),
            width,
        ),
        Kind::Output => clamp(
            &format!("LOCAL -> {}", clamp(&egress, width.saturating_sub(9))),
            width,
        ),
        Kind::Forward => {
            let available = width.saturating_sub(4);
            let left_width = Span::raw(ingress.as_str()).width();
            let right_width = Span::raw(egress.as_str()).width();
            let left = left_width.min(available.saturating_sub(right_width.min(available / 2)));
            clamp(
                &format!(
                    "{} -> {}",
                    clamp(&ingress, left),
                    clamp(&egress, available.saturating_sub(left))
                ),
                width,
            )
        }
    }
}

fn nonnegative(value: f64) -> f64 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn number(value: f64) -> String {
    let value = nonnegative(value);
    if value > 0.0 && value < 1.0 {
        format!("{value:.3}")
    } else if value < 10.0 {
        format!("{value:.2}")
    } else if value < 100.0 {
        format!("{value:.1}")
    } else if value < 1_000_000.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1e}")
    }
}

fn rate(value: f64) -> String {
    let mut value = nonnegative(value);
    let mut unit = 0;
    let units = ["", "k", "M", "G", "T", "P", "E"];
    while value >= 1_000.0 && unit + 1 < units.len() {
        value /= 1_000.0;
        unit += 1;
    }
    format!("{}{}", number(value), units[unit])
}

fn latency_number(value: Option<f64>, width: usize) -> String {
    match value.filter(|value| value.is_finite() && *value >= 0.0) {
        None => "-".into(),
        Some(value) => {
            let label = number(value);
            if label.len() <= width {
                label
            } else {
                format!("{value:.0e}")
            }
        }
    }
}

fn main_columns(width: u16, kind: Kind) -> Vec<(Sort, u16)> {
    let stages: &[Stage] = if kind == Kind::Input {
        &[Stage::Stack]
    } else if width >= 118 {
        &LATENCY_STAGES
    } else {
        &[Stage::Total]
    };
    let wide = width >= 158;
    let cell_width = if stages.len() == 1 {
        7
    } else if width >= 138 {
        6
    } else {
        5
    };
    let mut columns = vec![(Sort::Path, 0)];
    if wide {
        columns.push((Sort::InBandwidth, 9));
    }
    columns.push((Sort::Bandwidth, 10));
    if wide {
        columns.push((Sort::InPps, 7));
    }
    columns.push((Sort::Pps, 8));
    for metric in METRICS {
        columns.extend(
            stages
                .iter()
                .map(|stage| (Sort::Latency(metric, *stage), cell_width)),
        );
    }
    if wide {
        columns.push((Sort::Pending, 6));
    }
    columns
}

fn latency_line(window: &str, latency: &Latency) -> String {
    let value = |value: Option<f64>| {
        value
            .filter(|value| value.is_finite() && *value >= 0.0)
            .map(number)
            .unwrap_or_else(|| "-".into())
    };
    format!(
        " {window}: n={} min={} avg={} p50={} p90={} p95={} p99={} max={} newest={}",
        latency.samples,
        value(latency.min_us),
        value(latency.avg_us),
        value(latency.p50_us),
        value(latency.p90_us),
        value(latency.p95_us),
        value(latency.p99_us),
        value(latency.max_us),
        value(latency.newest_us)
    )
}

fn counter_lines(window: &str, counters: &Counters) -> Vec<Line<'static>> {
    vec![
        Line::raw(format!(
            " {window}: in_packets={} in_bytes={} out_packets={} out_bytes={}",
            counters.in_packets, counters.in_bytes, counters.out_packets, counters.out_bytes
        )),
        Line::raw(format!(
            "           route={} bridge={} combo={} freed={}",
            counters.route, counters.bridge, counters.combo, counters.freed
        )),
    ]
}

fn health_line(snapshot: &Snapshot) -> String {
    let active = snapshot
        .health
        .errors
        .values()
        .filter(|count| **count > 0)
        .count();
    format!(
        "paths {}/{}  inflight {}/{}  health counters {}",
        snapshot.rows.len(),
        snapshot.health.path_capacity,
        snapshot.health.inflight,
        snapshot.health.inflight_capacity,
        active
    )
}

pub fn text(snapshot: &Snapshot) -> String {
    let mut lines = vec![
        format!(
            "skbtop #{} elapsed={:.1}s interval={:.2}s | latency us: S=Stack Q=Queue T=Total",
            snapshot.sequence, snapshot.elapsed_secs, snapshot.interval_secs
        ),
        health_line(snapshot),
    ];
    for kind in KINDS {
        let stages: Vec<_> = kind
            .latency_stages()
            .iter()
            .map(|&stage| LATENCY_STAGES[stage])
            .collect();
        let metric_width = stages.len() * 7 + (stages.len() - 1) * 3;
        lines.push(String::new());
        lines.push(kind.label().into());
        let mut header = vec![
            format!("{:<30}", "PATH"),
            format!("{:>10}", "IN bit/s"),
            format!("{:>10}", "OUT bit/s"),
            format!("{:>7}", "IN PPS"),
            format!("{:>7}", "OUT PPS"),
        ];
        header.extend(
            METRICS
                .iter()
                .map(|metric| format!("{:^metric_width$}", metric.label())),
        );
        header.push(format!("{:>6}", "PEND"));
        lines.push(header.join(" | "));
        let mut subheader = vec![
            " ".repeat(30),
            " ".repeat(10),
            " ".repeat(10),
            " ".repeat(7),
            " ".repeat(7),
        ];
        for _ in METRICS {
            subheader.extend(stages.iter().map(|stage| format!("{:>7}", stage.initial())));
        }
        subheader.push(" ".repeat(6));
        lines.push(subheader.join(" | "));
        let rows = ordered_rows(snapshot, kind, Sort::Bandwidth, true, "");
        if rows.is_empty() {
            lines.push("No paths observed".into());
        }
        for row in rows {
            let mut cells = vec![
                format!("{:<30}", path_label(row, 30)),
                format!("{:>10}", rate(row.in_bps)),
                format!("{:>10}", rate(row.bps)),
                format!("{:>7}", rate(row.in_pps)),
                format!("{:>7}", rate(row.pps)),
            ];
            for metric in METRICS {
                cells.extend(stages.iter().map(|stage| {
                    format!(
                        "{:>7}",
                        latency_number(Sort::Latency(metric, *stage).latency(row), 7)
                    )
                }));
            }
            cells.push(format!("{:>6}", row.pending));
            lines.push(cells.join(" | "));
        }
    }
    if snapshot.health.errors.values().any(|count| *count > 0) {
        lines.push(String::from("\nOBSERVATION HEALTH (lifetime)"));
        lines.extend(
            snapshot
                .health
                .errors
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(name, count)| format!("{}: {count}", clean(name))),
        );
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{bucket_index, Health, BUCKETS};
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

    fn row(kind: Kind, ingress: u32, egress: u32, bps: f64, pps: f64, p99: f64) -> Row {
        let latency = |us: f64| {
            let ns = (us * 1_000.0) as u64;
            let mut histogram = vec![0; BUCKETS];
            histogram[bucket_index(ns)] = 10;
            Latency::from_raw(10, ns * 10, ns, ns, histogram)
        };
        Row {
            key: PathKey {
                kind,
                ingress,
                egress,
                netns: 1,
                ingress_generation: u64::from(ingress),
                egress_generation: u64::from(egress),
            },
            ingress_name: format!("eth{ingress}"),
            egress_name: format!("eth{egress}"),
            interval: Counters {
                in_packets: 11,
                in_bytes: 1_100,
                out_packets: 10,
                out_bytes: 1_000,
                route: 7,
                bridge: 2,
                combo: 1,
                freed: 3,
            },
            total: Counters {
                in_packets: 111,
                in_bytes: 11_100,
                out_packets: 100,
                out_bytes: 10_000,
                route: 70,
                bridge: 20,
                combo: 10,
                freed: 30,
            },
            latency: if kind == Kind::Input {
                [latency(p99), Latency::default(), Latency::default()]
            } else {
                [latency(p99 / 2.0), latency(p99 / 2.0), latency(p99)]
            },
            total_latency: if kind == Kind::Input {
                [latency(p99 * 2.0), Latency::default(), Latency::default()]
            } else {
                [latency(p99), latency(p99), latency(p99 * 2.0)]
            },
            pending: 1,
            bps,
            pps,
            in_bps: bps * 1.1,
            in_pps: pps * 1.1,
        }
    }

    fn snapshot(rows: Vec<Row>) -> Snapshot {
        Snapshot {
            sequence: 7,
            elapsed_secs: 8.0,
            interval_secs: 0.5,
            unix_ms: 1_000,
            rows,
            interfaces: Vec::new(),
            health: Health {
                inflight: 1,
                inflight_capacity: 1_024,
                path_capacity: 100,
                global: Counters::default(),
                errors: BTreeMap::from([("inflight_full".into(), 3), ("missing_path".into(), 2)]),
            },
        }
    }

    fn fixture() -> Snapshot {
        snapshot(vec![
            row(Kind::Input, 1, 0, 8_000.0, 10.0, 5.0),
            row(Kind::Output, 0, 2, 16_000.0, 20.0, 8.0),
            row(Kind::Forward, 1, 2, 32_000.0, 30.0, 12.0),
            row(Kind::Forward, 2, 1, 40_000.0, 40.0, 16.0),
        ])
    }

    fn render(ui: &mut Ui, snapshot: &Snapshot, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| ui.draw(frame, snapshot)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn screen(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .map(|y| {
                let mut line = String::new();
                let mut x = 0;
                while x < buffer.area.width {
                    let symbol = buffer[(x, y)].symbol();
                    line.push_str(symbol);
                    x += Span::raw(symbol).width().max(1) as u16;
                }
                line
            })
            .collect()
    }

    fn press(ui: &mut Ui, code: KeyCode) -> bool {
        ui.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn click(ui: &mut Ui, x: u16, y: u16) -> bool {
        ui.mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        })
    }

    #[test]
    fn rendered_headers_and_dividers_match_mouse_targets_at_different_sizes() {
        for (width, height) in [(80, 24), (112, 24), (120, 32), (160, 40)] {
            let mut ui = Ui::new();
            let snapshot = fixture();
            let buffer = render(&mut ui, &snapshot, width, height);
            let headers = ui.headers.clone();
            let mut expected = vec![Sort::Path];
            if width >= 160 {
                expected.push(Sort::InBandwidth);
            }
            expected.push(Sort::Bandwidth);
            if width >= 160 {
                expected.push(Sort::InPps);
            }
            expected.push(Sort::Pps);
            for metric in METRICS {
                if width >= 120 {
                    expected.extend(LATENCY_STAGES.map(|stage| Sort::Latency(metric, stage)));
                } else {
                    expected.push(Sort::Latency(metric, Stage::Total));
                }
            }
            if width >= 160 {
                expected.push(Sort::Pending);
            }
            for (panel, kind) in KINDS.into_iter().enumerate() {
                let mut panel_expected: Vec<_> =
                    expected.iter().map(|sort| sort.for_kind(kind)).collect();
                panel_expected.dedup();
                let targets: Vec<_> = headers
                    .iter()
                    .filter(|(_, index, _)| *index == panel)
                    .collect();
                assert_eq!(
                    targets.iter().map(|(_, _, sort)| *sort).collect::<Vec<_>>(),
                    panel_expected
                );
                let bottom = headers
                    .iter()
                    .find(|(_, index, _)| *index == panel + 1)
                    .map(|(area, _, _)| area.y - 2)
                    .unwrap_or(height - 3);
                for (area, _, sort) in &targets {
                    let label: String = (area.x..area.right())
                        .map(|x| buffer[(x, area.y)].symbol())
                        .collect();
                    let expected_label = if let Sort::Latency(_, stage) = sort {
                        stage.initial()
                    } else {
                        sort.label()
                    };
                    assert!(label.trim().starts_with(expected_label), "{width}: {label}");
                    for x in [area.x, area.right() - 1] {
                        ui.sort = if *sort == Sort::Bandwidth {
                            Sort::Path
                        } else {
                            Sort::Bandwidth
                        };
                        assert!(click(&mut ui, x, area.y));
                        assert_eq!(ui.sort, *sort);
                        assert_eq!(ui.focus, panel);
                        assert_eq!(ui.descending, *sort != Sort::Path);
                        assert!(click(&mut ui, x, area.y));
                        assert_eq!(ui.descending, *sort == Sort::Path);
                        assert!(!click(&mut ui, x, area.bottom()));
                        if matches!(sort, Sort::Latency(..)) {
                            assert!(!click(&mut ui, x, area.y - 1));
                        }
                    }
                    if area.right() < targets.last().unwrap().0.right() {
                        for y in area.y..bottom {
                            assert_eq!(buffer[(area.right(), y)].symbol(), "\u{2502}");
                            assert!(!click(&mut ui, area.right(), y));
                        }
                        assert_eq!(buffer[(area.right(), bottom)].symbol(), "\u{2534}");
                    }
                }
            }
            assert!(!click(&mut ui, 0, 3));
            assert!(!click(&mut ui, width - 1, 3));
            let (area, _, _) = headers[0];
            assert!(!ui.mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Right),
                column: area.x,
                row: area.y,
                modifiers: KeyModifiers::NONE,
            }));
        }
    }

    #[test]
    fn sorting_resets_to_top_and_resize_or_modal_views_replace_click_targets() {
        let snapshot = snapshot(
            (1..=20)
                .map(|i| row(Kind::Input, i, 0, f64::from(i), 1.0, 1.0))
                .collect(),
        );
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 160, 40);
        press(&mut ui, KeyCode::End);
        assert!(ui.panels[0].state.offset() > 0);
        let (area, _, _) = *ui
            .headers
            .iter()
            .find(|(_, index, sort)| *index == 0 && *sort == Sort::Path)
            .unwrap();
        assert!(click(&mut ui, area.x, area.y));
        let buffer = render(&mut ui, &snapshot, 160, 40);
        assert_eq!(ui.panels[0].state.selected(), Some(0));
        assert_eq!(ui.panels[0].state.offset(), 0);
        assert!(screen(&buffer)
            .iter()
            .any(|line| line.contains("PATH\u{2191}")));
        press(&mut ui, KeyCode::Char('S'));
        let buffer = render(&mut ui, &snapshot, 80, 24);
        assert!(screen(&buffer)
            .iter()
            .any(|line| line.contains("PATH\u{2193}")));
        assert!(!ui
            .headers
            .iter()
            .any(|(_, _, sort)| *sort == Sort::InBandwidth || *sort == Sort::InPps));
        assert!(!click(&mut ui, 100, 3));
        let (area, _, _) = ui.headers[0];
        press(&mut ui, KeyCode::Char('/'));
        assert!(!click(&mut ui, area.x, area.y));
        press(&mut ui, KeyCode::Esc);
        press(&mut ui, KeyCode::Enter);
        assert!(!click(&mut ui, area.x, area.y));
        render(&mut ui, &snapshot, 80, 24);
        assert!(ui.headers.is_empty());
        press(&mut ui, KeyCode::Esc);
        render(&mut ui, &snapshot, 79, 24);
        assert!(ui.headers.is_empty());
        assert!(!click(&mut ui, area.x, area.y));
        render(&mut ui, &snapshot, 160, 40);
        assert_eq!(ui.headers.len(), 46);
    }

    #[test]
    fn every_metric_sorts_forward_pairs_as_units_in_both_directions() {
        let mut snapshot = snapshot(vec![
            row(Kind::Forward, 1, 2, 40.0, 60.0, 200.0),
            row(Kind::Forward, 3, 4, 70.0, 200.0, 50.0),
            row(Kind::Forward, 2, 1, 40.0, 60.0, 1.0),
            row(Kind::Forward, 4, 3, 0.0, 0.0, 60.0),
            row(Kind::Forward, 5, 5, 30.0, 10.0, 70.0),
        ]);
        for (i, row) in snapshot.rows.iter_mut().enumerate() {
            row.in_bps = [1.0, 0.0, 1.0, 0.0, 3.0][i];
            row.in_pps = [1.0, 20.0, 1.0, 0.0, 1.0][i];
            row.pending = [1, 0, 4, 3, 4][i];
            row.latency[0].avg_us = Some([1.0, 2.0, 10.0, 2.0, 4.0][i]);
            row.latency[1].avg_us = Some([1.0, 20.0, 1.0, 0.0, 4.0][i]);
            for stage in LATENCY_STAGES {
                row.latency[stage as usize].newest_us =
                    Some([5.0, 4.0, 2.0, 3.0, 1.0][i] * (stage as usize + 1) as f64);
                row.latency[stage as usize].newest_at_ns = Some(42);
            }
        }
        let mut cases = vec![
            (Sort::Path, vec![5, 3, 1]),
            (Sort::InBandwidth, vec![5, 1, 3]),
            (Sort::Bandwidth, vec![1, 3, 5]),
            (Sort::InPps, vec![3, 1, 5]),
            (Sort::Pps, vec![3, 1, 5]),
            (Sort::Latency(Metric::Avg, Stage::Stack), vec![1, 5, 3]),
            (Sort::Latency(Metric::Avg, Stage::Queue), vec![3, 5, 1]),
            (Sort::Latency(Metric::Avg, Stage::Total), vec![1, 5, 3]),
            (Sort::Pending, vec![1, 5, 3]),
        ];
        for stage in LATENCY_STAGES {
            cases.extend([
                (Sort::Latency(Metric::Min, stage), vec![5, 3, 1]),
                (Sort::Latency(Metric::Max, stage), vec![1, 5, 3]),
                (Sort::Latency(Metric::Newest, stage), vec![1, 3, 5]),
            ]);
        }
        for (sort, descending_groups) in cases {
            for descending in [true, false] {
                let rows = ordered_rows(&snapshot, Kind::Forward, sort, descending, "");
                let expected: Vec<_> = if descending {
                    descending_groups.clone()
                } else {
                    descending_groups.iter().rev().copied().collect()
                };
                let groups: Vec<_> = rows.iter().map(|row| row.key.group()).collect();
                let mut unique = groups.clone();
                unique.dedup();
                assert_eq!(
                    unique.iter().map(|key| key.ingress).collect::<Vec<_>>(),
                    expected,
                    "{sort:?} desc={descending}"
                );
                for key in unique {
                    let positions: Vec<_> = groups
                        .iter()
                        .enumerate()
                        .filter(|(_, group)| **group == key)
                        .map(|(i, _)| i)
                        .collect();
                    assert_eq!(
                        positions.last().unwrap() - positions[0] + 1,
                        positions.len()
                    );
                }
                let keys: Vec<_> = rows.iter().map(|row| row.key).collect();
                snapshot.rows.reverse();
                assert_eq!(
                    ordered_rows(&snapshot, Kind::Forward, sort, descending, "")
                        .iter()
                        .map(|row| row.key)
                        .collect::<Vec<_>>(),
                    keys
                );
            }
        }
        for row in &mut snapshot.rows {
            if row.key.ingress == 5 {
                row.latency = std::array::from_fn(|_| Latency::default());
            }
        }
        for sort in METRICS
            .into_iter()
            .flat_map(|metric| LATENCY_STAGES.map(|stage| Sort::Latency(metric, stage)))
        {
            for descending in [true, false] {
                assert_eq!(
                    ordered_rows(&snapshot, Kind::Forward, sort, descending, "")
                        .last()
                        .unwrap()
                        .key
                        .ingress,
                    5
                );
            }
        }
    }

    #[test]
    fn layout_80x24_keeps_all_three_partitions_and_metrics_visible() {
        let mut ui = Ui::new();
        let buffer = render(&mut ui, &fixture(), 80, 24);
        let lines = screen(&buffer);
        let titles: Vec<usize> = KINDS
            .iter()
            .map(|kind| {
                lines
                    .iter()
                    .position(|line| line.contains(&format!("{}  ", kind.label())))
                    .unwrap()
            })
            .collect();
        assert!(titles[0] < titles[1] && titles[1] < titles[2] && titles[2] < 22);
        let input = lines[titles[0]..titles[1]].join("\n");
        let output = lines[titles[1]..titles[2]].join("\n");
        let forward = lines[titles[2]..22].join("\n");
        assert!(input.contains("eth1 -> LOCAL"));
        assert!(output.contains("LOCAL -> eth2"));
        assert!(forward.contains("eth1 -> eth2"));
        assert!(forward.contains("eth2 -> eth1"));
        for band in [input, output, forward] {
            for name in ["OUT bit/s", "OUT PPS", "Avg", "Min", "Max", "Newest"] {
                assert!(band.contains(name), "missing {name}:\n{band}");
            }
        }
        assert!(lines[0].contains("skbtop"));
        assert!(lines[1].contains("health counters 2"));
        assert!(lines[22].contains("sort: OUT bit/s desc"));
    }

    #[test]
    fn wide_layout_shows_ingress_rates_and_full_detail_statistics() {
        let mut ui = Ui::new();
        let snapshot = fixture();
        let lines = screen(&render(&mut ui, &snapshot, 160, 40)).join("\n");
        assert_eq!(lines.matches("IN bit/s").count(), 3);
        assert_eq!(lines.matches("IN PPS").count(), 3);
        assert_eq!(
            lines
                .lines()
                .filter(|line| line.contains("OUT bit/s") && line.contains("PATH"))
                .count(),
            3
        );
        assert_eq!(lines.matches("OUT PPS").count(), 3);
        let header = lines
            .lines()
            .find(|line| line.contains("IN bit/s"))
            .unwrap();
        assert!(header.find("IN bit/s").unwrap() < header.find("OUT bit/s").unwrap());
        assert!(header.find("OUT bit/s").unwrap() < header.find("IN PPS").unwrap());
        assert!(header.find("IN PPS").unwrap() < header.find("OUT PPS").unwrap());
        press(&mut ui, KeyCode::Tab);
        press(&mut ui, KeyCode::Enter);
        let detail = screen(&render(&mut ui, &snapshot, 160, 40)).join("\n");
        for field in [
            "STACK",
            "QUEUE",
            "TOTAL",
            "min=",
            "avg=",
            "p50=",
            "p90=",
            "p95=",
            "p99=",
            "max=",
            "percentiles approximate",
            "interval: n=10",
            "lifetime: n=10",
            "in_packets=11",
            "out_bytes=1000",
            "route=7",
            "bridge=2",
            "combo=1",
            "freed=3",
            "pending=1",
            "IN bit/s=17.6k OUT bit/s=16.0k",
            "IN PPS=22.0 OUT PPS=20.0",
            "inflight_full: 3",
        ] {
            assert!(detail.contains(field), "missing {field}:\n{detail}");
        }
        assert!(!press(&mut ui, KeyCode::Esc));
        assert!(ui.detail.is_none());
    }

    #[test]
    fn partitions_scroll_independently_with_arrows_vim_and_page_keys() {
        let rows = (1..=20)
            .flat_map(|index| {
                [
                    row(Kind::Input, index, 0, f64::from(100 - index), 1.0, 1.0),
                    row(Kind::Output, 0, index, f64::from(100 - index), 1.0, 1.0),
                    row(
                        Kind::Forward,
                        index,
                        index,
                        f64::from(100 - index),
                        1.0,
                        1.0,
                    ),
                ]
            })
            .collect();
        let snapshot = snapshot(rows);
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 80, 24);
        let page = ui.panels[0].page;
        assert!(page > 0 && page < 20);
        press(&mut ui, KeyCode::PageDown);
        assert_eq!(ui.panels[0].state.selected(), Some(page));
        press(&mut ui, KeyCode::Down);
        assert_eq!(ui.panels[0].state.selected(), Some(page + 1));
        render(&mut ui, &snapshot, 80, 24);
        assert!(ui.panels[0].state.offset() > 0);
        let input_offset = ui.panels[0].state.offset();
        press(&mut ui, KeyCode::Tab);
        press(&mut ui, KeyCode::Char('j'));
        assert_eq!(ui.panels[1].state.selected(), Some(1));
        assert_eq!(ui.panels[0].state.selected(), Some(page + 1));
        assert_eq!(ui.panels[0].state.offset(), input_offset);
        press(&mut ui, KeyCode::Tab);
        press(&mut ui, KeyCode::End);
        assert_eq!(ui.panels[2].state.selected(), Some(19));
        press(&mut ui, KeyCode::BackTab);
        press(&mut ui, KeyCode::Char('k'));
        assert_eq!(ui.panels[1].state.selected(), Some(0));
        press(&mut ui, KeyCode::BackTab);
        press(&mut ui, KeyCode::PageUp);
        assert_eq!(ui.panels[0].state.selected(), Some(1));
        press(&mut ui, KeyCode::Up);
        press(&mut ui, KeyCode::Up);
        assert_eq!(ui.panels[0].state.selected(), Some(0));
    }

    #[test]
    fn forward_groups_sort_by_combined_rates_and_worst_total_stage_average() {
        let snapshot = snapshot(vec![
            row(Kind::Forward, 1, 2, 40.0, 60.0, 200.0),
            row(Kind::Forward, 3, 4, 70.0, 200.0, 50.0),
            row(Kind::Forward, 2, 1, 40.0, 60.0, 1.0),
            row(Kind::Forward, 4, 3, 0.0, 0.0, 60.0),
            row(Kind::Forward, 5, 5, 30.0, 10.0, 70.0),
        ]);
        let mut ui = Ui::new();
        ui.focus = 2;
        let buffer = render(&mut ui, &snapshot, 160, 40);
        let lines = screen(&buffer);
        let first = lines
            .iter()
            .position(|line| line.contains("eth1 -> eth2"))
            .unwrap();
        assert!(lines[first + 1].contains("eth2 -> eth1"));
        assert_eq!(
            ui.panels[2]
                .keys
                .iter()
                .filter(|key| key.ingress == 5)
                .count(),
            1
        );
        let pairs = |ui: &Ui| {
            ui.panels[2]
                .keys
                .iter()
                .map(|key| (key.ingress, key.egress))
                .collect::<Vec<_>>()
        };
        assert_eq!(pairs(&ui), [(1, 2), (2, 1), (3, 4), (4, 3), (5, 5)]);
        press(&mut ui, KeyCode::Char('s'));
        render(&mut ui, &snapshot, 80, 24);
        assert_eq!(pairs(&ui), [(3, 4), (4, 3), (1, 2), (2, 1), (5, 5)]);
        press(&mut ui, KeyCode::Char('s'));
        render(&mut ui, &snapshot, 80, 24);
        assert_eq!(pairs(&ui), [(1, 2), (2, 1), (5, 5), (3, 4), (4, 3)]);
        press(&mut ui, KeyCode::Char('s'));
        assert!(matches!(ui.sort, Sort::Bandwidth));
    }

    #[test]
    fn search_is_view_only_retains_partner_and_supports_unicode_cancel_and_clear() {
        let mut snapshot = fixture();
        snapshot.rows[2].ingress_name = "needle接口".into();
        snapshot.rows[3].ingress_name = "renamed".into();
        snapshot.rows[3].egress_name = "renamed-too".into();
        let before = serde_json::to_string(&snapshot).unwrap();
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 80, 24);
        press(&mut ui, KeyCode::Char('/'));
        for ch in "NEEDLE接口".chars() {
            press(&mut ui, KeyCode::Char(ch));
        }
        press(&mut ui, KeyCode::Backspace);
        assert_eq!(ui.search, "NEEDLE接");
        press(&mut ui, KeyCode::Char('口'));
        press(&mut ui, KeyCode::Enter);
        let output = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        assert!(ui.panels[0].keys.is_empty());
        assert!(ui.panels[1].keys.is_empty());
        assert_eq!(ui.panels[2].keys.len(), 2);
        assert!(output.contains("INPUT  visible 0-0  matched 0  recorded 1  selected 0"));
        assert!(output.contains("FORWARD  visible 1-2  matched 2  recorded 2"));
        assert_eq!(serde_json::to_string(&snapshot).unwrap(), before);
        press(&mut ui, KeyCode::Char('/'));
        press(&mut ui, KeyCode::Char('q'));
        press(&mut ui, KeyCode::Esc);
        assert_eq!(ui.search, "NEEDLE接口");
        press(&mut ui, KeyCode::Esc);
        render(&mut ui, &snapshot, 80, 24);
        assert_eq!(ui.panels[0].keys.len(), 1);
        assert_eq!(ui.panels[2].keys.len(), 2);
    }

    #[test]
    fn refresh_keeps_selection_by_generation_and_recovers_when_row_disappears() {
        let mut snapshot = snapshot(vec![
            row(Kind::Input, 1, 0, 100.0, 1.0, 1.0),
            row(Kind::Input, 2, 0, 50.0, 1.0, 1.0),
        ]);
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 80, 24);
        press(&mut ui, KeyCode::Down);
        let selected = ui.panels[0].keys[1];
        snapshot.rows[1].bps = 200.0;
        let output = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        assert_eq!(ui.panels[0].state.selected(), Some(0));
        assert_eq!(ui.panels[0].keys[0], selected);
        assert!(output.contains("INPUT  visible 1-2  matched 2  recorded 2  selected 1"));
        press(&mut ui, KeyCode::Enter);
        snapshot.rows.retain(|row| row.key != selected);
        let detail = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        assert!(detail.contains("Path no longer present"));
        press(&mut ui, KeyCode::Esc);
        render(&mut ui, &snapshot, 80, 24);
        assert_eq!(ui.panels[0].keys.len(), 1);
        assert_eq!(ui.panels[0].state.selected(), Some(0));
    }

    #[test]
    fn details_scroll_to_counters_and_health_on_80x24_and_after_resize() {
        let snapshot = fixture();
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 80, 24);
        press(&mut ui, KeyCode::Tab);
        press(&mut ui, KeyCode::Enter);
        let detail = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        assert!(detail.contains("STACK"));
        assert!(detail.contains("QUEUE"));
        assert!(detail.contains("TOTAL"));
        press(&mut ui, KeyCode::PageDown);
        assert!(ui.detail_scroll > 0);
        press(&mut ui, KeyCode::End);
        let detail = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        for field in [
            "in_packets=111",
            "freed=30",
            "HEALTH",
            "OBSERVATION HEALTH",
            "inflight_full: 3",
            "missing_path: 2",
        ] {
            assert!(detail.contains(field), "missing {field}:\n{detail}");
        }
        render(&mut ui, &snapshot, 160, 60);
        assert_eq!(ui.detail_scroll, 0);
        press(&mut ui, KeyCode::Home);
        assert_eq!(ui.detail_scroll, 0);
    }

    #[test]
    fn monochrome_removes_colors_and_maxima_remain_emphatic() {
        let mut ui = Ui::new();
        ui.no_color = true;
        let buffer = render(&mut ui, &fixture(), 80, 24);
        assert!(buffer
            .content
            .iter()
            .all(|cell| cell.fg == Color::Reset && cell.bg == Color::Reset));
        ui.focus = 1;
        let buffer = render(&mut ui, &fixture(), 80, 24);
        let lines = screen(&buffer);
        let y = lines
            .iter()
            .position(|line| line.contains("eth1 -> LOCAL"))
            .unwrap() as u16;
        let bold = (2..78)
            .filter(|x| buffer[(*x, y)].modifier.contains(Modifier::BOLD))
            .count();
        assert!(
            bold > 5,
            "maxima need emphasis in the inactive INPUT partition"
        );
        assert!(press(&mut ui, KeyCode::Char('q')));
        let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert!(!ui.key(release));
        assert!(ui.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    }

    #[test]
    fn no_data_small_terminals_and_long_utf8_names_render_without_overflow() {
        let mut ui = Ui::new();
        let empty = snapshot(Vec::new());
        let output = screen(&render(&mut ui, &empty, 80, 24)).join("\n");
        assert_eq!(output.matches("No paths").count(), 3);
        assert!(!press(&mut ui, KeyCode::Enter));
        assert!(ui.detail.is_none());
        for (width, height) in [(0, 0), (1, 1), (20, 5), (40, 16), (79, 24), (80, 23)] {
            let output = screen(&render(&mut ui, &empty, width, height)).join("\n");
            if width == 20 {
                assert!(output.contains("Terminal too small"));
            }
            if width >= 40 {
                assert!(output.contains("minimum 80x24"));
                assert!(!output.contains("Stack avg"));
            }
        }
        let mut snapshot = fixture();
        snapshot.rows[2].ingress_name = "接口".repeat(40);
        snapshot.rows[2].egress_name = "出口".repeat(40);
        let output = screen(&render(&mut ui, &snapshot, 80, 24)).join("\n");
        assert!(output.contains("接口"));
        assert!(output.contains("出口"));
        assert!(output.contains("~ -> "));
        for width in 0..40 {
            let label = path_label(&snapshot.rows[2], width);
            assert!(Span::raw(label.as_str()).width() <= width);
        }
        assert!(!clamp("bad\nname\u{1b}", 100).contains(['\n', '\u{1b}']));
        assert_eq!(clamp("a\u{301}bc", 2), "a\u{301}~");
        assert_eq!(
            clamp("\u{1f469}\u{200d}\u{1f4bb}abc", 3),
            "\u{1f469}\u{200d}\u{1f4bb}~"
        );
    }

    #[test]
    fn plain_text_has_all_partitions_adjacent_directions_and_no_ansi() {
        let snapshot = fixture();
        let output = text(&snapshot);
        for field in [
            "INPUT\n",
            "OUTPUT\n",
            "FORWARD\n",
            "IN bit/s",
            "OUT bit/s",
            "IN PPS",
            "OUT PPS",
            "S=Stack Q=Queue T=Total",
            "Avg",
            "Min",
            "Max",
            "Newest",
            "inflight_full: 3",
        ] {
            assert!(output.contains(field));
        }
        let lines: Vec<_> = output.lines().collect();
        let first = lines
            .iter()
            .position(|line| line.contains("eth1 -> eth2"))
            .unwrap();
        assert!(lines[first + 1].contains("eth2 -> eth1"));
        assert!(!output.contains('\u{1b}'));
        assert!(output.ends_with('\n'));
    }

    #[test]
    fn main_columns_use_stage_averages_and_highlight_the_same_values() {
        let mut snapshot = snapshot(vec![
            row(Kind::Input, 1, 0, 100.0, 1.0, 10.0),
            row(Kind::Input, 2, 0, 50.0, 1.0, 20.0),
        ]);
        snapshot.rows[0].latency[0].avg_us = Some(1.25);
        snapshot.rows[0].latency[0].p99_us = Some(90.0);
        snapshot.rows[1].latency[0].avg_us = Some(1.0);
        snapshot.rows[1].latency[0].p99_us = Some(100.0);
        snapshot.rows[0].latency[1].avg_us = Some(2.5);
        snapshot.rows[0].latency[1].p99_us = Some(80.0);
        snapshot.rows[1].latency[1].avg_us = Some(2.0);
        snapshot.rows[1].latency[1].p99_us = Some(200.0);
        snapshot.rows[0].latency[2].avg_us = Some(3.75);
        snapshot.rows[0].latency[0].min_us = Some(0.5);
        snapshot.rows[0].latency[0].max_us = Some(70.0);
        snapshot.rows[0].latency[0].newest_us = Some(6.0);
        snapshot.rows[0].latency[0].newest_at_ns = Some(42);
        snapshot.rows[0].latency[2].p99_us = Some(60.0);
        let output = text(&snapshot);
        let row = output
            .lines()
            .find(|line| line.contains("eth1 -> LOCAL"))
            .unwrap();
        let columns: Vec<_> = row.split('|').map(str::trim).collect();
        assert_eq!(&columns[1..5], ["110", "100", "1.10", "1.00"]);
        assert_eq!(&columns[5..9], ["1.25", "0.500", "70.0", "6.00"]);
        let compact = screen(&render(&mut Ui::new(), &snapshot, 80, 24)).join("\n");
        for value in [
            "Avg", "Min", "Max", "Newest", "1.25", "0.500", "70.0", "6.00",
        ] {
            assert!(compact.contains(value), "missing {value}: {compact}");
        }
        assert!(!compact.contains("TotalP99"));
        let wide = screen(&render(&mut Ui::new(), &fixture(), 120, 32)).join("\n");
        assert!(wide.contains("eth1 -> LOCAL"));
        assert!(wide.contains("LOCAL -> eth2"));
        let mut ui = Ui::new();
        ui.focus = 1;
        ui.no_color = false;
        let buffer = render(&mut ui, &snapshot, 160, 40);
        let lines = screen(&buffer);
        let first = lines
            .iter()
            .position(|line| line.contains("eth1 -> LOCAL"))
            .unwrap() as u16;
        let second = lines
            .iter()
            .position(|line| line.contains("eth2 -> LOCAL"))
            .unwrap() as u16;
        let (area, _, _) = ui
            .headers
            .iter()
            .find(|(_, panel, sort)| {
                *panel == 0 && *sort == Sort::Latency(Metric::Avg, Stage::Stack)
            })
            .unwrap();
        let x = area.right() - 1;
        assert_eq!(buffer[(x, first)].fg, Color::Yellow);
        assert_eq!(buffer[(x, second)].fg, Color::Reset);
    }

    #[test]
    fn grouped_metrics_match_each_stage_and_newest_never_mixes_samples() {
        let mut row = row(Kind::Forward, 1, 2, 1.0, 1.0, 1.0);
        for (index, latency) in row.latency.iter_mut().enumerate() {
            let base = (index + 1) as f64 * 10.0;
            latency.avg_us = Some(base + 1.0);
            latency.min_us = Some(base + 2.0);
            latency.max_us = Some(base + 3.0);
            latency.newest_us = Some(base + 4.0);
            latency.newest_at_ns = Some(100);
        }
        for (index, metric) in METRICS.into_iter().enumerate() {
            for stage in LATENCY_STAGES {
                assert_eq!(
                    Sort::Latency(metric, stage).latency(&row),
                    Some((stage as usize + 1) as f64 * 10.0 + index as f64 + 1.0)
                );
            }
        }
        row.latency[0].newest_at_ns = Some(99);
        assert_eq!(
            Sort::Latency(Metric::Newest, Stage::Stack).latency(&row),
            None
        );
        assert_eq!(
            Sort::Latency(Metric::Newest, Stage::Queue).latency(&row),
            Some(24.0)
        );
        row.latency[2].newest_us = None;
        for stage in LATENCY_STAGES {
            assert_eq!(Sort::Latency(Metric::Newest, stage).latency(&row), None);
        }
        row.latency[2].newest_us = Some(34.0);
        row.latency[2].newest_at_ns = None;
        assert_eq!(
            Sort::Latency(Metric::Newest, Stage::Total).latency(&row),
            None
        );
    }

    #[test]
    fn two_level_headers_show_only_stack_for_input() {
        let snapshot = fixture();
        let mut ui = Ui::new();
        for width in [80, 119, 120, 139, 140, 159, 160, 200] {
            let buffer = render(&mut ui, &snapshot, width, 32);
            let lines = screen(&buffer);
            let header = lines.iter().position(|line| line.contains("PATH")).unwrap() as u16;
            let input = lines
                .iter()
                .position(|line| line.contains("eth1 -> LOCAL"))
                .unwrap() as u16;
            assert_eq!(input, header + 2);
            for metric in METRICS {
                let targets: Vec<_> = ui
                    .headers
                    .iter()
                    .filter(|(_, panel, sort)| {
                        *panel == 0 && matches!(sort, Sort::Latency(m, _) if *m == metric)
                    })
                    .collect();
                assert_eq!(targets.len(), 1);
                assert_eq!(targets[0].2, Sort::Latency(metric, Stage::Stack));
                let first = targets.first().unwrap().0;
                let last = targets.last().unwrap().0;
                let caption: String = (first.x..last.right())
                    .map(|x| buffer[(x, header)].symbol())
                    .collect();
                assert_eq!(caption.trim(), metric.label());
                let output_stages = ui
                    .headers
                    .iter()
                    .filter(|(_, panel, sort)| {
                        *panel == 1 && matches!(sort, Sort::Latency(m, _) if *m == metric)
                    })
                    .count();
                assert_eq!(output_stages, if width >= 120 { 3 } else { 1 });
            }
        }
        let (area, _, sort) = *ui
            .headers
            .iter()
            .find(|(_, panel, sort)| {
                *panel == 1 && *sort == Sort::Latency(Metric::Max, Stage::Queue)
            })
            .unwrap();
        assert!(click(&mut ui, area.x, area.y));
        let buffer = render(&mut ui, &snapshot, 200, 32);
        let label: String = (area.x..area.right())
            .map(|x| buffer[(x, area.y)].symbol())
            .collect();
        assert_eq!(label.trim(), "Q\u{2193}");
        assert!(screen(&buffer)
            .iter()
            .any(|line| line.contains(&format!("sort: {} desc", sort.label()))));
    }

    #[test]
    fn input_newest_sort_and_details_use_stack_without_total() {
        let mut first = row(Kind::Input, 1, 0, 1.0, 1.0, 10.0);
        first.latency[0].newest_us = Some(11.0);
        first.latency[0].newest_at_ns = Some(100);
        let second = row(Kind::Input, 2, 0, 1.0, 1.0, 20.0);
        let snapshot = snapshot(vec![first, second]);
        assert_eq!(
            Sort::Latency(Metric::Newest, Stage::Stack).latency(&snapshot.rows[0]),
            Some(11.0)
        );
        let sorted = ordered_rows(
            &snapshot,
            Kind::Input,
            Sort::Latency(Metric::Avg, Stage::Total),
            true,
            "",
        );
        assert_eq!(sorted[0].key.ingress, 2);
        let mut ui = Ui::new();
        render(&mut ui, &snapshot, 120, 32);
        press(&mut ui, KeyCode::Enter);
        let detail = screen(&render(&mut ui, &snapshot, 120, 48)).join("\n");
        assert!(detail.contains("STACK"));
        assert!(!detail.contains("QUEUE"));
        assert!(!detail.contains("TOTAL"));
    }

    #[test]
    fn microsecond_cells_keep_large_values_numeric_and_text_headers_aligned() {
        for width in [5, 6, 7] {
            for value in [0.0001, 0.9999, 9.999, 99.999, 99999.9, 20_000_000.0] {
                let label = latency_number(Some(value), width);
                assert!(label.len() <= width, "{label}");
                assert!(label.parse::<f64>().is_ok());
            }
            assert_eq!(latency_number(Some(f64::NAN), width), "-");
        }
        let output = text(&fixture());
        let lines: Vec<_> = output.lines().collect();
        let header = lines.iter().position(|line| line.contains("PATH")).unwrap();
        assert_eq!(lines[header].len(), lines[header + 1].len());
        assert_eq!(lines[header].len(), lines[header + 2].len());
        assert_eq!(lines[header + 1].matches('S').count(), 4);
        assert_eq!(lines[header + 1].matches('Q').count(), 0);
        assert_eq!(lines[header + 1].matches('T').count(), 0);
        let header = lines
            .iter()
            .enumerate()
            .skip(header + 1)
            .find(|(_, line)| line.contains("PATH"))
            .unwrap()
            .0;
        assert_eq!(lines[header + 1].matches('S').count(), 4);
        assert_eq!(lines[header + 1].matches('Q').count(), 4);
        assert_eq!(lines[header + 1].matches('T').count(), 4);
    }

    #[test]
    fn text_health_reports_only_nonzero_counters_without_calling_busy_an_error() {
        let mut snapshot = snapshot(Vec::new());
        snapshot.health.errors = BTreeMap::from([
            ("driver_busy".into(), 8),
            ("interface_generation_mismatch".into(), 2),
            ("inflight_full".into(), 0),
            ("interface_event_gaps".into(), 0),
        ]);
        let output = text(&snapshot);
        assert!(output.contains("OBSERVATION HEALTH (lifetime)"));
        assert!(output.contains("driver_busy: 8"));
        assert!(output.contains("interface_generation_mismatch: 2"));
        assert!(!output.contains("inflight_full"));
        assert!(!output.contains("interface_event_gaps"));
        assert!(!output.to_lowercase().contains("error"));
        assert!(output.contains("health counters 2"));
        for count in snapshot.health.errors.values_mut() {
            *count = 0;
        }
        let output = text(&snapshot);
        assert!(!output.contains("OBSERVATION HEALTH"));
        assert!(!output.contains("driver_busy"));
    }
}
