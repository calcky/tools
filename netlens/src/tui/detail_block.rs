use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use super::{socket, theme};

/// Body rows are already wrapped to width - 4 (or width for viewports below 5).
pub(super) fn framed_lines(
    title: &str,
    color: Color,
    body: Vec<Line<'static>>,
    width: usize,
) -> Vec<Line<'static>> {
    let title_style = Style::default().fg(color).add_modifier(Modifier::BOLD);
    if width < 5 {
        let mut rows: Vec<_> = socket::wrap_text(title, width)
            .into_iter()
            .map(|line| Line::styled(line, title_style))
            .collect();
        rows.extend(body.into_iter().map(|line| {
            if line.width() > width {
                // A two-cell grapheme cannot fit a one-cell viewport.
                Line::styled("?", line.style)
            } else {
                line
            }
        }));
        return rows;
    }

    let border = Style::default().fg(theme::DIVIDER);
    let mut rows = Vec::with_capacity(body.len() + 4);
    let heading = format!(" {title} ");
    if heading.len() <= width - 2 {
        rows.push(Line::from(vec![
            Span::styled("┌", border),
            Span::styled(heading.clone(), title_style),
            Span::styled(
                format!("{}┐", "─".repeat(width - 2 - heading.len())),
                border,
            ),
        ]));
    } else {
        rows.push(Line::styled(format!("┌{}┐", "─".repeat(width - 2)), border));
        for title in socket::wrap_text(title, width - 4) {
            rows.push(frame_row(Line::styled(title, title_style), width));
        }
    }
    rows.extend(body.into_iter().map(|line| frame_row(line, width)));
    rows.push(Line::styled(format!("└{}┘", "─".repeat(width - 2)), border));
    rows
}

fn frame_row(line: Line<'static>, width: usize) -> Line<'static> {
    let border = Style::default().fg(theme::DIVIDER);
    let remaining = (width - 4).saturating_sub(line.width());
    let mut spans = Vec::with_capacity(line.spans.len() + 2);
    spans.push(Span::styled("│ ", border));
    spans.extend(
        line.spans
            .into_iter()
            .map(|span| Span::styled(span.content, line.style.patch(span.style))),
    );
    spans.push(Span::styled(format!("{} │", " ".repeat(remaining)), border));
    Line::from(spans)
}

/// Join independently stacked columns with one cell between them, without a leading gap.
pub(super) fn side_by_side(columns: Vec<(usize, Vec<Line<'static>>)>) -> Vec<Line<'static>> {
    let height = columns
        .iter()
        .map(|(_, rows)| rows.len())
        .max()
        .unwrap_or(0);
    let widths: Vec<_> = columns.iter().map(|(width, _)| *width).collect();
    let mut columns: Vec<_> = columns
        .into_iter()
        .map(|(_, rows)| rows.into_iter())
        .collect();
    let mut output = Vec::with_capacity(height);
    for _ in 0..height {
        let mut spans = Vec::new();
        for (index, column) in columns.iter_mut().enumerate() {
            if index > 0 {
                spans.push(Span::raw(" "));
            }
            if let Some(line) = column.next() {
                spans.extend(
                    line.spans
                        .into_iter()
                        .map(|span| Span::styled(span.content, line.style.patch(span.style))),
                );
            } else {
                spans.push(Span::raw(" ".repeat(widths[index])));
            }
        }
        output.push(Line::from(spans));
    }
    output
}
