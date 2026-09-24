use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use super::{socket::text_width, theme};

#[cfg(test)]
mod preview;

/// List offsets count data rows; context and column headings never scroll.
pub(super) struct TableViewport {
    pub(super) context: usize,
    pub(super) headings: usize,
    pub(super) capacity: usize,
    pub(super) offset: usize,
    pub(super) max_offset: usize,
    full_context: usize,
    full_headings: usize,
    data_rows: usize,
}

impl TableViewport {
    pub(super) fn new(
        context: usize,
        headings: usize,
        data_rows: usize,
        height: usize,
        offset: usize,
    ) -> Self {
        // On short terminals, keep column labels and one entry ahead of metadata.
        let visible_context = context.min(height.saturating_sub(headings + 1));
        let visible_headings = headings.min(height);
        let capacity = height.saturating_sub(visible_context + visible_headings);
        let max_offset = data_rows.saturating_sub(capacity.max(1));
        Self {
            context: visible_context,
            headings: visible_headings,
            capacity,
            offset: offset.min(max_offset),
            max_offset,
            full_context: context,
            full_headings: headings,
            data_rows,
        }
    }

    pub(super) fn data_start(&self) -> usize {
        self.context + self.headings
    }

    pub(super) fn logical_row(&self, row: usize) -> Option<usize> {
        if row < self.context {
            return Some(row);
        }
        if row < self.data_start() {
            return Some(self.full_context + row - self.context);
        }
        let relative = row - self.data_start();
        let position = self.offset.saturating_add(relative);
        (relative < self.capacity && position < self.data_rows)
            .then(|| self.full_context + self.full_headings + position)
    }

    pub(super) fn reveal(&self, position: Option<usize>) -> usize {
        let Some(position) = position else {
            return self.offset;
        };
        if position < self.offset {
            position.min(self.max_offset)
        } else if position >= self.offset.saturating_add(self.capacity) {
            position
                .saturating_add(1)
                .saturating_sub(self.capacity.max(1))
                .min(self.max_offset)
        } else {
            self.offset
        }
    }
}

pub(super) fn label(text: &str, width: usize, direction: Option<bool>) -> String {
    let marker = match direction {
        Some(true) => "↓",
        Some(false) => "↑",
        None => "↕",
    };
    if width == 0 {
        return String::new();
    }
    let spaced = text_width(text) + 2 <= width;
    let available = width.saturating_sub(if spaced { 2 } else { 1 });
    let mut value = String::new();
    for grapheme in text.graphemes(true) {
        if text_width(&value) + text_width(grapheme) > available {
            break;
        }
        value.push_str(grapheme);
    }
    if !value.is_empty() && spaced {
        value.push(' ');
    }
    value.push_str(marker);
    value
}

pub(super) fn header_style(active: bool, color: Color) -> Style {
    Style::default()
        .fg(if active { theme::TEXT_STRONG } else { color })
        .bg(if active {
            theme::SORT_BG
        } else {
            theme::HEADER_BG
        })
        .add_modifier(if active {
            Modifier::BOLD | Modifier::UNDERLINED
        } else {
            Modifier::BOLD
        })
}

pub(super) fn select(line: &mut Line<'_>) {
    line.style = line.style.bg(theme::SELECTED_BG);
    for span in &mut line.spans {
        span.style = span.style.bg(theme::SELECTED_BG);
    }
}

/// The same geometry drives grouped headers, data cells and mouse hit testing.
pub(super) struct TrafficLayout {
    pub(super) prefix: Vec<usize>,
    pub(super) cell: usize,
    width: usize,
}

impl TrafficLayout {
    pub(super) fn new(width: usize, conntrack: bool) -> Self {
        let count = if conntrack { 4 } else { 2 };
        let separators = count + 4 + 5;
        let available = width.saturating_sub(separators);
        let cell = (available * 3 / 5 / 10).clamp(if width >= 60 { 3 } else { 1 }, 12);
        let prefix_space = available.saturating_sub(cell * 10);
        let meta = if conntrack {
            (prefix_space / 5).min(6)
        } else {
            (prefix_space / 3).min(30)
        };
        let state = if conntrack {
            (prefix_space / 4).min(14)
        } else {
            0
        };
        let mark = if conntrack {
            (prefix_space / 3).min(10)
        } else {
            0
        };
        let prefix = if conntrack {
            vec![
                meta,
                state,
                prefix_space.saturating_sub(meta + state + mark),
                mark,
            ]
        } else {
            vec![meta, prefix_space.saturating_sub(meta)]
        };
        Self {
            prefix,
            cell,
            width,
        }
    }

    pub(super) fn hit(&self, x: usize) -> Option<usize> {
        if x >= self.width {
            return None;
        }
        let mut start = self.prefix.iter().sum::<usize>() + self.prefix.len();
        for field in 0..10 {
            if (start..start + self.cell).contains(&x) {
                return Some(field);
            }
            start += self.cell + 1;
        }
        None
    }

    pub(super) fn prefix_hit(&self, x: usize) -> Option<usize> {
        if x >= self.width {
            return None;
        }
        let mut start = 0;
        for (field, width) in self.prefix.iter().copied().enumerate() {
            if (start..start + width).contains(&x) {
                return Some(field);
            }
            start += width + 1;
        }
        None
    }

    pub(super) fn headings(
        &self,
        prefix: &[&str],
        groups: [&str; 5],
        active: &[usize],
        descending: bool,
    ) -> Vec<Line<'static>> {
        let mut top = Vec::new();
        let mut bottom = Vec::new();
        for (index, (&name, &width)) in prefix.iter().zip(&self.prefix).enumerate() {
            if index > 0 {
                top.push(divider());
                bottom.push(divider());
            }
            let selected = active.contains(&(10 + index));
            top.push(Span::styled(
                pad(
                    &label(name, width, selected.then_some(descending)),
                    width,
                    false,
                ),
                header_style(selected, theme::TEXT),
            ));
            bottom.push(Span::styled(
                " ".repeat(width),
                header_style(selected, theme::TEXT),
            ));
        }
        let colors = [
            theme::TEXT_STRONG,
            theme::GOOD,
            theme::ACCENT,
            theme::WARN,
            theme::TX,
        ];
        for (group, name) in groups.into_iter().enumerate() {
            top.push(divider());
            bottom.push(divider());
            top.push(Span::styled(
                pad(name, self.cell * 2 + 1, false),
                header_style(false, colors[group]),
            ));
            for (direction, name) in ["TX", "RX"].into_iter().enumerate() {
                if direction == 1 {
                    bottom.push(divider());
                }
                let selected = active.contains(&(group * 2 + direction));
                bottom.push(Span::styled(
                    pad(
                        &label(name, self.cell, selected.then_some(descending)),
                        self.cell,
                        true,
                    ),
                    header_style(selected, if direction == 0 { theme::TX } else { theme::RX }),
                ));
            }
        }
        vec![self.bounded(top), self.bounded(bottom)]
    }

    pub(super) fn row(
        &self,
        prefix: &[String],
        values: [String; 10],
        active: &[usize],
    ) -> Line<'static> {
        let mut spans = Vec::new();
        for (index, (value, &width)) in prefix.iter().zip(&self.prefix).enumerate() {
            if index > 0 {
                spans.push(divider());
            }
            // The full endpoints remain available in the connection detail.
            let value = if index == if self.prefix.len() == 4 { 2 } else { 1 } {
                super::socket::truncate_middle(value, width)
            } else {
                value.clone()
            };
            let mut style = Style::default().fg(theme::TEXT);
            if active.contains(&(10 + index)) {
                style = style
                    .fg(theme::TEXT_STRONG)
                    .bg(theme::SORT_BG)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
            }
            spans.push(Span::styled(pad(&value, width, false), style));
        }
        for (index, value) in values.into_iter().enumerate() {
            spans.push(divider());
            let mut style = Style::default().fg(if index % 2 == 0 { theme::TX } else { theme::RX });
            if active.contains(&index) {
                style = style
                    .fg(theme::TEXT_STRONG)
                    .bg(theme::SORT_BG)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
            }
            spans.push(Span::styled(pad(&value, self.cell, true), style));
        }
        self.bounded(spans)
    }

    fn bounded(&self, spans: Vec<Span<'static>>) -> Line<'static> {
        let mut remaining = self.width;
        Line::from(
            spans
                .into_iter()
                .filter_map(|span| {
                    if remaining == 0 {
                        return None;
                    }
                    let width = span.width().min(remaining);
                    remaining -= width;
                    Some(Span::styled(pad(&span.content, width, false), span.style))
                })
                .collect::<Vec<_>>(),
        )
    }
}

pub(super) fn divider() -> Span<'static> {
    Span::styled("|", Style::default().fg(theme::DIVIDER))
}

pub(super) fn pad(value: &str, width: usize, right: bool) -> String {
    let mut text = String::new();
    for grapheme in value.graphemes(true) {
        if text_width(&text) + text_width(grapheme) > width {
            break;
        }
        text.push_str(grapheme);
    }
    let padding = " ".repeat(width.saturating_sub(text_width(&text)));
    if right {
        format!("{padding}{text}")
    } else {
        format!("{text}{padding}")
    }
}

#[cfg(test)]
mod viewport_tests {
    use super::TableViewport;

    #[test]
    fn headers_stay_fixed_and_only_data_coordinates_scroll() {
        let view = TableViewport::new(4, 2, 100, 12, 30);
        assert_eq!(view.data_start(), 6);
        assert_eq!(view.capacity, 6);
        assert_eq!(view.logical_row(4), Some(4));
        assert_eq!(view.logical_row(5), Some(5));
        assert_eq!(view.logical_row(6), Some(36));
        assert_eq!(view.logical_row(11), Some(41));
        assert_eq!(view.logical_row(12), None);
        assert_eq!(view.reveal(Some(29)), 29);
        assert_eq!(view.reveal(Some(35)), 30);
        assert_eq!(view.reveal(Some(36)), 31);
        let end = TableViewport::new(4, 2, 100, 12, usize::MAX);
        assert_eq!(end.offset, 94);
        assert_eq!(end.logical_row(11), Some(105));
    }

    #[test]
    fn short_and_empty_viewports_keep_headings_without_phantom_rows() {
        for height in 0..=3 {
            let view = TableViewport::new(10, 2, 5, height, usize::MAX);
            assert_eq!(view.context, 0);
            assert_eq!(view.headings, height.min(2));
            assert_eq!(view.capacity, height.saturating_sub(2));
            for row in 0..height.min(2) {
                assert_eq!(view.logical_row(row), Some(10 + row));
            }
            assert_eq!(view.logical_row(height), None);
            if height == 3 {
                assert_eq!(view.logical_row(2), Some(16));
            }
        }
        let view = TableViewport::new(4, 2, 2, usize::MAX, usize::MAX);
        assert_eq!(view.offset, 0);
        assert_eq!(view.logical_row(7), Some(7));
        assert_eq!(view.logical_row(8), None);
        assert_eq!(view.logical_row(usize::MAX), None);
        let empty = TableViewport::new(4, 2, 0, 10, 0);
        assert_eq!(empty.logical_row(6), None);
    }
}
