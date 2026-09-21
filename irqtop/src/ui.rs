use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame as Canvas,
};

use crate::{fit, DisplayRow, Domain, Frame};

#[derive(Default)]
pub struct State {
    pub offset: usize,
    pub page_size: usize,
    pub softnet_offset: usize,
    pub softnet_page_size: usize,
    pub softnet_focus: bool,
}

fn accent(domain: Domain) -> Style {
    Style::default()
        .fg(match domain {
            Domain::Hard => Color::Cyan,
            Domain::Soft => Color::Yellow,
        })
        .add_modifier(Modifier::BOLD)
}

fn label(domain: Domain) -> &'static str {
    match domain {
        Domain::Hard => "HARD IRQ",
        Domain::Soft => "SOFTIRQ",
    }
}

fn text(canvas: &mut Canvas, area: Rect, value: impl Into<String>, style: Style) {
    canvas.render_widget(Paragraph::new(value.into()).style(style), area);
}

fn panel(canvas: &mut Canvas, area: Rect, title: &str, focused: bool) -> Rect {
    let style = if focused {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(style)
        .title(Line::styled(format!(" {title} "), style));
    let inner = block.inner(area);
    canvas.render_widget(block, area);
    inner
}

struct Grid {
    label_width: usize,
    value_width: usize,
    cell_width: usize,
    columns: usize,
}

impl Grid {
    fn new(report: &Frame, width: usize) -> Self {
        let cells = || report.entries.iter().flat_map(|row| &row.cpus);
        let label_width = 4 + cells()
            .map(|(cpu, _)| cpu.to_string().len())
            .max()
            .unwrap_or(0)
            .max(2);
        let value_width = cells()
            .map(|(_, value)| value.len())
            .max()
            .unwrap_or(0)
            .max(9);
        let cell_width = label_width + 1 + value_width;
        // Two characters of indentation; " | " separates complete CPU cells.
        let columns = ((width.saturating_sub(2) + 3) / (cell_width + 3)).max(1);
        Self {
            label_width,
            value_width,
            cell_width,
            columns,
        }
    }
}

enum BodyLine<'a> {
    Section(Domain),
    Main(&'a DisplayRow),
    Cpus(&'a DisplayRow, &'a [(u32, String)]),
    Idle,
}

fn body_lines<'a>(report: &'a Frame, grid: &Grid) -> Vec<BodyLine<'a>> {
    let mut result = Vec::new();
    let mut last = None;
    for row in &report.entries {
        if last != Some(row.domain) {
            result.push(BodyLine::Section(row.domain));
        }
        last = Some(row.domain);
        result.push(BodyLine::Main(row));
        if row.cpus.is_empty() {
            result.push(BodyLine::Idle);
        }
        for cells in row.cpus.chunks(grid.columns) {
            result.push(BodyLine::Cpus(row, cells));
        }
    }
    result
}

fn main_line(canvas: &mut Canvas, area: Rect, report: &Frame, row: Option<&DisplayRow>) {
    let rate_width = report
        .entries
        .iter()
        .map(|r| r.value.len())
        .max()
        .unwrap_or(0)
        .max(12) as u16;
    let [id, cpu, source, rate] = Layout::horizontal([
        Constraint::Length(13),
        Constraint::Length(5),
        Constraint::Min(4),
        Constraint::Length(rate_width),
    ])
    .areas(area);
    let (id_text, cpu_text, source_text, rate_text, style) = if let Some(row) = row {
        (
            row.id.as_str(),
            "all",
            row.source.as_str(),
            row.value.as_str(),
            accent(row.domain),
        )
    } else {
        (
            "IRQ / TYPE",
            "CPU",
            "NETDEV / SOURCE",
            report.unit,
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
    };
    text(
        canvas,
        id,
        fit(id_text, id.width.saturating_sub(1) as usize),
        style,
    );
    text(canvas, cpu, cpu_text, style);
    text(
        canvas,
        source,
        fit(source_text, source.width.saturating_sub(1) as usize),
        style,
    );
    canvas.render_widget(
        Paragraph::new(rate_text)
            .alignment(Alignment::Right)
            .style(style),
        rate,
    );
}

pub fn draw(canvas: &mut Canvas, report: &Frame, state: &mut State) {
    let area = canvas.area();
    let plain = Style::default();
    let bold = plain.add_modifier(Modifier::BOLD);
    let content_width = area.width.saturating_sub(2) as usize;
    let softnet_table = report
        .softnet
        .as_ref()
        .map(|r| crate::softnet_view::Table::new(r, content_width));
    let minimum_height = softnet_table.as_ref().map_or(11, |table| {
        13 + table.headers.len() + table.total.len() + table.headers.len().max(1)
    }) as u16;
    if area.width < 55 || area.height < minimum_height {
        text(
            canvas,
            area,
            format!(
                "Terminal too small\nNeed 55 columns x {minimum_height} rows\nResize or press q"
            ),
            plain,
        );
        return;
    }
    let [title, totals, summary, settings, panels, position, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let grid = Grid::new(report, content_width);
    let lines = body_lines(report, &grid);
    let mut softnet_count = 0;
    let irq_area = if let (Some(softnet), Some(table)) = (&report.softnet, &softnet_table) {
        let fixed = 2 + table.headers.len() + table.total.len();
        softnet_count = table.rows.iter().map(Vec::len).sum::<usize>();
        let needed = fixed + softnet_count.max(1);
        let softnet_height = (usize::from(panels.height) / 2)
            .max(fixed + table.headers.len().max(1))
            .min(needed)
            .min(usize::from(panels.height.saturating_sub(5))) as u16;
        let irq_height =
            (lines.len().max(2) + 3).min(usize::from(panels.height - softnet_height)) as u16;
        let irq = Rect::new(panels.x, panels.y, panels.width, irq_height);
        let softnet_area = Rect::new(
            panels.x,
            panels.y + irq_height,
            panels.width,
            usize::from(panels.height - irq_height).min(needed) as u16,
        );
        let inner = panel(canvas, softnet_area, "SOFTNET | host", state.softnet_focus);
        draw_softnet(canvas, inner, softnet, table, state);
        irq
    } else {
        panels
    };
    let irq_title = if report
        .totals
        .iter()
        .any(|(domain, _, _)| *domain == Domain::Soft)
    {
        "IRQ / SOFTIRQ"
    } else {
        "IRQ"
    };
    let inner = panel(
        canvas,
        irq_area,
        irq_title,
        report.softnet.is_none() || !state.softnet_focus,
    );
    let [header, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    let [name, time] = Layout::horizontal([Constraint::Min(0), Constraint::Length(9)]).areas(title);
    text(
        canvas,
        name,
        format!(
            "irqtop | {}",
            fit(&report.scope, name.width.saturating_sub(9) as usize)
        ),
        bold,
    );
    canvas.render_widget(
        Paragraph::new(report.clock.clone()).alignment(Alignment::Right),
        time,
    );
    let total_areas =
        Layout::horizontal(report.totals.iter().map(|_| Constraint::Fill(1))).split(totals);
    for ((domain, value, unit), rect) in report.totals.iter().zip(total_areas.iter()) {
        let name = match domain {
            Domain::Hard => "hard",
            Domain::Soft => "soft",
        };
        text(
            canvas,
            *rect,
            format!("{name} {value} {unit}"),
            accent(*domain),
        );
    }
    text(
        canvas,
        summary,
        format!(
            "{} shown / {} matched, {} active | {} CPUs",
            report.entries.len(),
            report.matched,
            report.active,
            report.cpu_count
        ),
        plain,
    );
    text(
        canvas,
        settings,
        format!("interval {:.3}s | {}", report.elapsed, report.rate_filter()),
        plain,
    );
    main_line(canvas, header, report, None);

    state.page_size = body.height as usize;
    state.offset = state
        .offset
        .min(lines.len().saturating_sub(state.page_size));
    let end = (state.offset + state.page_size).min(lines.len());
    for (i, line) in lines[state.offset..end].iter().enumerate() {
        let row_area = Rect::new(body.x, body.y + i as u16, body.width, 1);
        match line {
            BodyLine::Section(domain) => text(canvas, row_area, label(*domain), accent(*domain)),
            BodyLine::Main(row) => main_line(canvas, row_area, report, Some(row)),
            BodyLine::Idle => text(canvas, row_area, "  (no CPU activity)", plain),
            BodyLine::Cpus(row, cells) => {
                for (column, (cpu, value)) in cells.iter().enumerate() {
                    let cell = Rect::new(
                        row_area.x + 2 + (column * (grid.cell_width + 3)) as u16,
                        row_area.y,
                        grid.cell_width as u16,
                        1,
                    );
                    let muted = plain.fg(Color::DarkGray);
                    if column > 0 {
                        text(canvas, Rect::new(cell.x - 3, cell.y, 3, 1), " | ", muted);
                    }
                    let peak = row.peak_cpus.contains(cpu);
                    let peak_style = bold.fg(Color::Green);
                    let label = format!("CPU{cpu}:");
                    let content = Line::from(vec![
                        Span::styled(
                            format!("{label:<width$} ", width = grid.label_width),
                            if peak { peak_style } else { muted },
                        ),
                        Span::styled(
                            format!("{value:>width$}", width = grid.value_width),
                            if peak { peak_style } else { plain },
                        ),
                    ]);
                    canvas.render_widget(Paragraph::new(content), cell);
                }
            }
        }
    }
    if lines.is_empty() {
        text(
            canvas,
            body,
            if report.matched == 0 {
                "No matching sources".into()
            } else {
                format!("No sources with CPU rate > {}/s", report.min_rate)
            },
            plain,
        );
    }
    text(
        canvas,
        position,
        if state.softnet_focus && report.softnet.is_some() {
            format!(
                "Softnet rows {}-{}/{} | Tab IRQ | PgUp/PgDn",
                if softnet_count == 0 {
                    0
                } else {
                    state.softnet_offset + 1
                },
                (state.softnet_offset + state.softnet_page_size).min(softnet_count),
                softnet_count
            )
        } else if report.softnet.is_some() {
            format!(
                "Rows {}-{}/{} | Tab softnet | PgUp/PgDn",
                if lines.is_empty() {
                    0
                } else {
                    state.offset + 1
                },
                end,
                lines.len()
            )
        } else {
            format!(
                "Rows {}-{}/{} | j/k scroll | PgUp/PgDn page",
                if lines.is_empty() {
                    0
                } else {
                    state.offset + 1
                },
                end,
                lines.len()
            )
        },
        plain,
    );
    text(
        canvas,
        keys,
        "q quit | a all | n net | z >200 | s sort | b softnet",
        plain,
    );
}

fn draw_softnet(
    canvas: &mut Canvas,
    area: Rect,
    report: &crate::softnet::Report,
    table: &crate::softnet_view::Table,
    state: &mut State,
) {
    let mut y = area.y;
    state.softnet_page_size = 0;
    if let Some(status) = &report.status {
        state.softnet_offset = 0;
        text(canvas, area, status, Style::default());
        return;
    }
    for line in table.headers.iter().chain(&table.total) {
        canvas.render_widget(
            Paragraph::new(line.clone()),
            Rect::new(area.x, y, area.width, 1),
        );
        y += 1;
    }
    let lines: Vec<_> = table.rows.iter().flatten().collect();
    state.softnet_page_size = area.bottom().saturating_sub(y) as usize;
    state.softnet_offset = state
        .softnet_offset
        .min(lines.len().saturating_sub(state.softnet_page_size));
    if lines.is_empty() {
        text(
            canvas,
            Rect::new(area.x, y, area.width, 1),
            "(no CPU activity)",
            Style::default().fg(Color::DarkGray),
        );
    }
    for line in lines
        .iter()
        .skip(state.softnet_offset)
        .take(state.softnet_page_size)
    {
        canvas.render_widget(
            Paragraph::new((*line).clone()),
            Rect::new(area.x, y, area.width, 1),
        );
        y += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

    fn report() -> Frame {
        let cpus = (0..64)
            .map(|c| format!("CPU{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let counts = (0..64)
            .map(|c| (c + 300).to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let hard = crate::parse(&format!("{cpus}\nLOC: {counts} local\n")).unwrap();
        let soft =
            crate::parse_domain(&format!("{cpus}\nNET_RX: {counts}\n"), Domain::Soft).unwrap();
        let snapshot = crate::merge_snapshots(Some(hard), Some(soft)).unwrap();
        let mut o = crate::options(vec![]).unwrap();
        o.top = true;
        crate::frame(&o, None, &snapshot, 1.0, 80)
    }

    fn screen(report: &Frame, state: &mut State, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| draw(f, report, state)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn lines(buffer: &Buffer) -> Vec<String> {
        (0..buffer.area.height)
            .map(|y| {
                let framed = buffer[(0, y)].symbol() == "\u{2502}";
                let columns = if framed {
                    1..buffer.area.width - 1
                } else {
                    0..buffer.area.width
                };
                columns.map(|x| buffer[(x, y)].symbol()).collect()
            })
            .collect()
    }

    #[test]
    fn short_irq_list_keeps_softnet_close_without_a_large_gap() {
        let mut report = report();
        report.entries.truncate(1);
        report.entries[0].cpus.truncate(1);
        report.softnet = Some(crate::softnet::Report {
            total: crate::softnet::Values {
                events: [10, 0, 0, 0, 0],
                backlog: Some(0),
            },
            elapsed: 1.0,
            ..crate::softnet::Report::default()
        });
        let display = lines(&screen(&report, &mut State::default(), 120, 40));
        let last_irq = display
            .iter()
            .position(|s| s.starts_with("  CPU0:"))
            .unwrap();
        let softnet = display
            .iter()
            .position(|s| s.contains("SOFTNET | host"))
            .unwrap();
        assert_eq!(softnet - last_irq, 2);
    }

    #[test]
    fn softnet_totals_stay_pinned_and_all_cpu_rows_are_reachable() {
        let mut report = report();
        let softnet = crate::softnet::Report {
            rows: (0..64)
                .map(|id| crate::softnet::Cpu {
                    id,
                    values: crate::softnet::Values {
                        events: [100 + u64::from(id), 1, 1, 0, 0],
                        backlog: Some(u64::from(id)),
                    },
                })
                .collect(),
            total: crate::softnet::Values {
                events: [8416, 64, 64, 0, 0],
                backlog: Some(2016),
            },
            elapsed: 2.0,
            peak: 163,
            ..crate::softnet::Report::default()
        };
        report.softnet = Some(softnet);
        for (width, height) in [(55, 20), (60, 24), (80, 24), (120, 40)] {
            let mut state = State {
                softnet_focus: true,
                ..State::default()
            };
            let mut seen = Vec::new();
            loop {
                let buffer = screen(&report, &mut state, width, height);
                let display = lines(&buffer);
                assert!(display.iter().any(|s| s.contains("SOFTNET | host")));
                assert!(display
                    .iter()
                    .any(|s| s.starts_with("all") && s.contains("4208.00")));
                assert!(display.iter().any(|s| s.starts_with("LOC")));
                assert_eq!(state.offset, 0);
                seen.extend(display);
                let total = crate::softnet_view::Table::new(
                    report.softnet.as_ref().unwrap(),
                    width as usize - 2,
                )
                .rows
                .iter()
                .map(Vec::len)
                .sum::<usize>();
                if state.softnet_offset + state.softnet_page_size >= total {
                    break;
                }
                assert!(state.softnet_page_size > 0);
                state.softnet_offset += state.softnet_page_size;
            }
            for cpu in 0..64 {
                assert!(
                    seen.iter().any(
                        |s| s.split_whitespace().next() == Some(&format!("CPU{cpu}"))
                            && s.contains(&format!("{:.2}", (100 + cpu) as f64 / 2.0))
                    ),
                    "missing CPU{cpu} at {width}x{height}"
                );
            }
        }
        report.softnet.as_mut().unwrap().status = Some("unavailable: permission denied".into());
        let display = lines(&screen(&report, &mut State::default(), 80, 24));
        assert!(display.iter().any(|s| s.contains("permission denied")));
        assert!(display.iter().any(|s| s.starts_with("LOC")));
    }

    #[test]
    fn totals_align_and_styles_survive_scrolling_past_section() {
        let report = report();
        for width in [55, 60, 80, 100, 120, 160] {
            let mut state = State::default();
            let buffer = screen(&report, &mut state, width, 80);
            let display = lines(&buffer);
            assert!(display[5].ends_with("rate/s"));
            assert!(display[3].contains("CPU rate > 200/s"));
            assert!(!display
                .iter()
                .any(|line| line.contains("CPU columns") || line.contains("filter")));
            assert!(display[78].contains("PgUp/PgDn page"));
            assert!(display[79].contains("a all | n net | z >200"));
            assert!(buffer[(1, 5)].modifier.contains(Modifier::BOLD));
            for row in &report.entries {
                let y = display.iter().position(|s| s.starts_with(&row.id)).unwrap();
                assert!(display[y].ends_with(&row.value), "{}", display[y]);
                assert_eq!(buffer[(1, y as u16)].fg, accent(row.domain).fg.unwrap());
                assert_eq!(buffer[(width - 1, y as u16)].symbol(), "\u{2502}");
                assert!(buffer[(width - 2, y as u16)]
                    .modifier
                    .contains(Modifier::BOLD));
            }
        }
        let grid = Grid::new(&report, 78);
        let soft_row = body_lines(&report, &grid)
            .iter()
            .position(|l| matches!(l, BodyLine::Main(r) if r.domain == Domain::Soft))
            .unwrap();
        let mut state = State {
            offset: soft_row,
            ..State::default()
        };
        let buffer = screen(&report, &mut state, 80, 12);
        assert!(lines(&buffer)[6].starts_with("NET_RX"));
        assert_eq!(buffer[(1, 6)].fg, Color::Yellow);
        assert!(buffer[(1, 6)].modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn all_64_cpu_values_fit_across_pages_and_widths() {
        let report = report();
        for width in [55, 60, 79, 80, 100, 119, 120, 160] {
            let mut state = State::default();
            let mut seen = Vec::new();
            loop {
                let buffer = screen(&report, &mut state, width, 12);
                seen.extend(lines(&buffer));
                let end = state.offset + state.page_size;
                if end >= body_lines(&report, &Grid::new(&report, width as usize - 2)).len() {
                    break;
                }
                state.offset = end;
            }
            for (cpu, value) in &report.entries[0].cpus {
                let grid = Grid::new(&report, width as usize - 2);
                let expected = format!(
                    "{:<6} {value:>cell_width$}",
                    format!("CPU{cpu}:"),
                    cell_width = grid.value_width
                );
                assert!(
                    seen.iter().any(|s| s.contains(&expected)),
                    "width {width}: missing {expected}"
                );
            }
        }
    }

    #[test]
    fn resizing_long_counts_empty_and_tiny_windows() {
        let mut report = report();
        report.entries[0].value = "18446744073709551615".into();
        report.entries[0].cpus = vec![
            (10000, "18446744073709551615".into()),
            (10001, "12345678901234567890".into()),
        ];
        let mut state = State::default();
        let buffer = screen(&report, &mut state, 55, 16);
        assert!(lines(&buffer)
            .iter()
            .any(|s| s.ends_with("18446744073709551615")));
        assert!(lines(&buffer)
            .iter()
            .any(|s| s.contains("CPU10001: 12345678901234567890")));
        state.offset = usize::MAX;
        screen(&report, &mut state, 80, 12);
        screen(&report, &mut state, 120, 40);
        assert!(state.offset < 40);
        for (width, height) in [(1, 1), (40, 6), (54, 9), (80, 8)] {
            screen(&report, &mut state, width, height);
        }
        report.entries.clear();
        let buffer = screen(&report, &mut state, 80, 24);
        assert_eq!(state.offset, 0);
        assert!(lines(&buffer).iter().any(|s| s.contains("No sources")));
        assert!(lines(&buffer).iter().any(|s| s.contains("Rows 0-0/0")));
    }

    #[test]
    fn peak_styles_follow_the_irq_across_pages_and_resize() {
        let mut report = report();
        for row in &mut report.entries {
            row.peak_cpus.insert(62);
            row.cpus[62].1 = row.cpus[63].1.clone();
        }
        for width in [55, 80, 120, 200] {
            let mut state = State::default();
            let mut peaks = 0;
            loop {
                let buffer = screen(&report, &mut state, width, 12);
                for (y, line) in lines(&buffer)
                    .iter()
                    .enumerate()
                    .skip(6)
                    .take(state.page_size)
                {
                    for cpu in 0..64 {
                        let tag = format!("CPU{cpu}:");
                        if let Some(x) = line.find(&tag) {
                            let cell = &buffer[(x as u16 + 1, y as u16)];
                            let peak = cpu >= 62;
                            assert_eq!(cell.modifier.contains(Modifier::BOLD), peak);
                            assert_eq!(cell.fg, if peak { Color::Green } else { Color::DarkGray });
                            let value_start =
                                x + Grid::new(&report, width as usize - 2).label_width + 1;
                            let value_x = value_start
                                + line[value_start..]
                                    .find(|c: char| c.is_ascii_digit())
                                    .unwrap();
                            let cell = &buffer[(value_x as u16 + 1, y as u16)];
                            assert_eq!(cell.modifier.contains(Modifier::BOLD), peak);
                            assert_eq!(cell.fg, if peak { Color::Green } else { Color::Reset });
                            peaks += usize::from(peak);
                        }
                    }
                    for (x, _) in line.match_indices('|') {
                        assert_eq!(buffer[(x as u16 + 1, y as u16)].fg, Color::DarkGray);
                        assert!(!buffer[(x as u16 + 1, y as u16)]
                            .modifier
                            .contains(Modifier::BOLD));
                    }
                }
                let end = state.offset + state.page_size;
                if end >= body_lines(&report, &Grid::new(&report, width as usize - 2)).len() {
                    break;
                }
                state.offset = end;
            }
            assert!(peaks >= 4, "width {width}: peak CPU missing on later pages");
        }
    }

    #[test]
    fn frames_keep_their_edges_and_focus_is_independent_of_data_styles() {
        let mut report = report();
        report.softnet = Some(crate::softnet::Report {
            elapsed: 1.0,
            ..crate::softnet::Report::default()
        });
        for width in [55, 80, 120] {
            for focused in [false, true] {
                let mut state = State {
                    softnet_focus: focused,
                    ..State::default()
                };
                let buffer = screen(&report, &mut state, width, 24);
                let soft_y = lines(&buffer)
                    .iter()
                    .position(|s| s.contains("SOFTNET | host"))
                    .unwrap() as u16;
                for (top, bottom, active) in [(4, soft_y - 1, !focused), (soft_y, 21, focused)] {
                    // The softnet frame may end above the footer when its list is short.
                    let bottom = (top + 1..=bottom)
                        .find(|y| buffer[(0, *y)].symbol() == "\u{2514}")
                        .unwrap();
                    assert_eq!(buffer[(0, top)].symbol(), "\u{250c}");
                    assert_eq!(buffer[(width - 1, top)].symbol(), "\u{2510}");
                    assert_eq!(buffer[(width - 1, bottom)].symbol(), "\u{2518}");
                    for y in top..=bottom {
                        for x in [0, width - 1] {
                            let cell = &buffer[(x, y)];
                            assert_eq!(
                                cell.fg,
                                if active {
                                    Color::White
                                } else {
                                    Color::DarkGray
                                }
                            );
                            assert_eq!(cell.modifier.contains(Modifier::BOLD), active);
                            if y != top && y != bottom {
                                assert_eq!(cell.symbol(), "\u{2502}");
                            }
                        }
                    }
                }
                assert_eq!(buffer[(1, 7)].fg, Color::Cyan);
            }
        }
        assert_eq!(Grid::new(&report, 78).columns, 4);
        assert_eq!(Grid::new(&report, 118).columns, 6);
    }

    #[test]
    fn control_characters_in_labels_are_not_terminal_commands() {
        let mut report = report();
        report.entries[0].source = "eth0\x1b[2J\n\r".into();
        report.entries[0].id = "LOC\x1b[0m".into();
        let buffer = screen(&report, &mut State::default(), 80, 24);
        assert!(lines(&buffer).iter().all(|s| !s.contains('\x1b')));
        assert!(lines(&buffer).iter().any(|s| s.contains("eth0?[2J??")));
    }
}
