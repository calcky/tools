use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use super::theme;

pub(super) const fn inner_width(width: u16) -> u16 {
    width.saturating_sub(2)
}

// The first heading occupies the top border, so each module costs one extra row.
pub(super) fn lines(content: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let symbols = border::PLAIN;
    let border_style = Style::default()
        .fg(theme::DIVIDER)
        .bg(Color::Reset)
        .remove_modifier(Modifier::BOLD);
    let inside = usize::from(inner_width(width));
    let mut result = Vec::with_capacity(content.len() + 1);
    for (index, mut line) in content.into_iter().enumerate() {
        if index == 0 {
            while let Some(span) = line.spans.last_mut() {
                let trimmed = span.content.trim_end();
                if !trimmed.is_empty() {
                    if trimmed.len() != span.content.len() {
                        span.content = trimmed.to_owned().into();
                    }
                    break;
                }
                line.spans.pop();
            }
        }
        if width < 2 {
            line.spans = clipped(line.spans, usize::from(width));
            line.spans.push(Span::raw(
                " ".repeat(usize::from(width).saturating_sub(line.width())),
            ));
            result.push(line);
            continue;
        }
        line.spans = clipped(line.spans, inside);
        let padding = inside.saturating_sub(line.width());
        let mut spans = Vec::with_capacity(line.spans.len() + 3);
        spans.push(Span::styled(
            if index == 0 {
                symbols.top_left
            } else {
                symbols.vertical_left
            },
            border_style,
        ));
        spans.extend(line.spans);
        if index == 0 {
            if padding > 0 {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::styled(
                symbols.horizontal_top.repeat(padding.saturating_sub(1)),
                border_style,
            ));
        } else {
            spans.push(Span::raw(" ".repeat(padding)));
        }
        spans.push(Span::styled(
            if index == 0 {
                symbols.top_right
            } else {
                symbols.vertical_right
            },
            border_style,
        ));
        line.spans = spans;
        result.push(line);
    }
    if width >= 2 {
        result.push(Line::from(vec![
            Span::styled(symbols.bottom_left, border_style),
            Span::styled(symbols.horizontal_bottom.repeat(inside), border_style),
            Span::styled(symbols.bottom_right, border_style),
        ]));
    }
    result
}

pub(super) fn highlight(lines: &mut [Line<'_>]) {
    let last = lines.len().saturating_sub(1);
    for (index, line) in lines.iter_mut().enumerate() {
        let end = line.spans.len().saturating_sub(1);
        for (position, span) in line.spans.iter_mut().enumerate() {
            if position == 0
                || position == end
                || index == last
                || (index == 0 && position == end.saturating_sub(1))
            {
                span.style = span.style.fg(theme::ACCENT);
            }
        }
    }
}

fn clipped(spans: Vec<Span<'static>>, width: usize) -> Vec<Span<'static>> {
    let mut remaining = width;
    let mut result = Vec::with_capacity(spans.len());
    for span in spans {
        if remaining == 0 {
            break;
        }
        let size = span.width();
        if size <= remaining {
            remaining -= size;
            result.push(span);
        } else {
            let mut text = String::new();
            for grapheme in span.content.graphemes(true) {
                let size = Span::raw(grapheme).width();
                if size > remaining {
                    break;
                }
                text.push_str(grapheme);
                remaining -= size;
            }
            result.push(Span::styled(text, span.style));
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_preserves_wide_graphemes_styles_and_terminal_bounds() {
        let content = vec![
            Line::styled(" NETDEV   ", Style::default().add_modifier(Modifier::BOLD)),
            Line::from(vec![
                Span::styled("\u{754c}e\u{301}", Style::default().fg(theme::WARN)),
                Span::raw(" 12345"),
            ]),
        ];
        for width in [0, 1, 2, 3, 4, 5, 6, 8, 80, 120, 160] {
            let framed = lines(content.clone(), width);
            assert_eq!(framed.len(), content.len() + usize::from(width >= 2));
            assert!(framed.iter().all(|line| line.width() == usize::from(width)));
            if width >= 2 {
                assert!(framed[0].to_string().starts_with(border::PLAIN.top_left));
                assert!(framed[0].to_string().ends_with(border::PLAIN.top_right));
                assert!(framed[1]
                    .to_string()
                    .starts_with(border::PLAIN.vertical_left));
                assert!(framed[1]
                    .to_string()
                    .ends_with(border::PLAIN.vertical_right));
                assert!(framed[2].to_string().starts_with(border::PLAIN.bottom_left));
                assert!(framed[2].to_string().ends_with(border::PLAIN.bottom_right));
            }
            if width >= 5 {
                assert!(framed[1].to_string().contains("\u{754c}e\u{301}"));
                assert_eq!(framed[1].spans[1].style.fg, Some(theme::WARN));
            }
        }
    }
}
