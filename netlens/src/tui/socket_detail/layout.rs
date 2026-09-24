use ratatui::style::Color;
use ratatui::text::Line;

use super::{socket, theme};
use crate::tui::detail_block::{framed_lines, side_by_side};

pub(super) struct DetailGroup {
    title: &'static str,
    lines: Vec<Line<'static>>,
}

impl DetailGroup {
    pub(super) fn take(title: &'static str, lines: &mut Vec<Line<'static>>) -> Self {
        Self {
            title,
            lines: std::mem::take(lines),
        }
    }

    fn column(&self, columns: usize) -> usize {
        match (columns, self.title) {
            (3, "LIMIT BASIS" | "PATH / MEMORY") => 1,
            (3, "CONGESTION / RECOVERY" | "LATENCY / TIMERS") => 2,
            (2, "LIMIT BASIS" | "CONGESTION / RECOVERY" | "LATENCY / TIMERS") => 1,
            _ => 0,
        }
    }

    fn order(&self) -> usize {
        match self.title {
            "TRAFFIC / QUEUES" | "LISTENER BACKLOG" => 0,
            "WINDOWS / BUFFERS" => 1,
            "LIMIT BASIS" => 2,
            "PATH / MEMORY" => 3,
            "CONGESTION / RECOVERY" => 4,
            "LATENCY / TIMERS" => 5,
            _ => 6,
        }
    }

    fn color(&self) -> Color {
        match self.title {
            "IDENTITY" => theme::SOCKETS,
            "TRAFFIC / QUEUES" | "LISTENER BACKLOG" => theme::RX,
            "WINDOWS / BUFFERS" => theme::GOOD,
            "CONGESTION / RECOVERY" | "LIMIT BASIS" => theme::WARN,
            "LATENCY / TIMERS" => theme::TX,
            "PATH / MEMORY" => theme::NETWORK,
            _ => theme::ACCENT,
        }
    }
}

pub(super) struct DetailLayout {
    width: usize,
    columns: usize,
    column_width: usize,
}

impl DetailLayout {
    pub(super) fn new(width: u16) -> Self {
        let width = usize::from(width);
        // Leave room for complete metric labels and useful values in each module.
        let columns = ((width + 1) / 53).clamp(1, 3);
        let column_width = width.saturating_sub(columns - 1) / columns;
        Self {
            width,
            columns,
            column_width,
        }
    }

    pub(super) fn full_inner_width(&self) -> usize {
        self.width.max(1)
    }

    pub(super) fn column_inner_width(&self) -> usize {
        inner_width(self.column_width)
    }

    pub(super) fn row_count(&self, groups: &[DetailGroup]) -> usize {
        if self.width == 0 {
            return 0;
        }
        let mut identity_height = 0;
        let mut column_heights = [0; 3];
        for group in groups.iter().filter(|group| !group.lines.is_empty()) {
            if group.title == "IDENTITY" {
                identity_height += group.lines.len();
            } else {
                column_heights[group.column(self.columns)] +=
                    framed_height(group, self.column_width);
            }
        }
        let stack_height = column_heights.into_iter().max().unwrap_or(0);
        identity_height + usize::from(identity_height > 0 && stack_height > 0) + stack_height
    }

    // Build styled rows directly. A large off-screen terminal buffer is unnecessary,
    // and counting and scrolling use exactly the same wrapped module geometry.
    pub(super) fn compose(&self, groups: Vec<DetailGroup>) -> Vec<Line<'static>> {
        if self.width == 0 {
            return Vec::new();
        }
        let mut output = Vec::new();
        let mut stacks: [Vec<DetailGroup>; 3] = std::array::from_fn(|_| Vec::new());
        for group in groups.into_iter().filter(|group| !group.lines.is_empty()) {
            if group.title == "IDENTITY" {
                output.extend(group.lines);
            } else {
                stacks[group.column(self.columns)].push(group);
            }
        }
        let columns = stacks
            .into_iter()
            .take(self.columns)
            .map(|mut stack| {
                stack.sort_by_key(DetailGroup::order);
                (
                    self.column_width,
                    stack
                        .into_iter()
                        .flat_map(|group| {
                            framed_lines(group.title, group.color(), group.lines, self.column_width)
                        })
                        .collect(),
                )
            })
            .collect();
        let rows = side_by_side(columns);
        if !output.is_empty() && !rows.is_empty() {
            output.push(Line::default());
        }
        output.extend(rows);
        output
    }
}

fn inner_width(width: usize) -> usize {
    if width >= 5 {
        width - 4
    } else {
        width.max(1)
    }
}

fn framed_height(group: &DetailGroup, width: usize) -> usize {
    if width < 5 {
        group.lines.len() + socket::wrap_text(group.title, width).len()
    } else {
        group.lines.len()
            + 2
            + if group.title.len() + 2 > width - 2 {
                socket::wrap_text(group.title, inner_width(width)).len()
            } else {
                0
            }
    }
}

#[cfg(test)]
mod tests {
    use ratatui::style::Modifier;

    use super::*;

    fn group(title: &'static str, height: usize) -> DetailGroup {
        DetailGroup::take(
            title,
            &mut (0..height)
                .map(|index| Line::raw(format!("v{index}")))
                .collect(),
        )
    }

    fn fixtures() -> Vec<DetailGroup> {
        // Deliberately shuffled. Placement must not depend on collection order.
        vec![
            group("LATENCY / TIMERS", 2),
            group("IDENTITY", 3),
            group("WINDOWS / BUFFERS", 3),
            group("PATH / MEMORY", 2),
            group("CONGESTION / RECOVERY", 4),
            group("TRAFFIC / QUEUES", 1),
            group("LIMIT BASIS", 8),
        ]
    }

    fn cell_text(line: &Line<'_>, start: usize, width: usize) -> String {
        line.to_string().chars().skip(start).take(width).collect()
    }

    #[test]
    fn three_columns_stack_independently_in_the_approved_order() {
        let layout = DetailLayout::new(160);
        let groups = fixtures();
        let count = layout.row_count(&groups);
        let rows = layout.compose(groups);
        assert_eq!(count, rows.len());
        assert_eq!(count, 3 + 1 + (8 + 2) + (2 + 2));
        for (index, row) in rows.iter().take(3).enumerate() {
            assert_eq!(row.to_string(), format!("v{index}"));
        }
        assert!(rows[3].spans.is_empty());
        for (column, title, y) in [
            (0, "TRAFFIC / QUEUES", 4),
            (0, "WINDOWS / BUFFERS", 7),
            (1, "LIMIT BASIS", 4),
            (1, "PATH / MEMORY", 14),
            (2, "CONGESTION / RECOVERY", 4),
            (2, "LATENCY / TIMERS", 10),
        ] {
            let text = cell_text(
                &rows[y],
                column * (layout.column_width + 1),
                layout.column_width,
            );
            assert!(text.contains(title), "{title} at {column}/{y}: {text}");
        }
        assert!(rows.iter().all(|line| line.width() <= 160));
    }

    #[test]
    fn two_column_fallback_keeps_path_with_windows() {
        let layout = DetailLayout::new(120);
        let groups = fixtures();
        let count = layout.row_count(&groups);
        let rows = layout.compose(groups);
        assert_eq!(count, rows.len());
        assert_eq!(count, 3 + 1 + (8 + 2) + (4 + 2) + (2 + 2));
        for (column, title, y) in [
            (0, "TRAFFIC / QUEUES", 4),
            (0, "WINDOWS / BUFFERS", 7),
            (0, "PATH / MEMORY", 12),
            (1, "LIMIT BASIS", 4),
            (1, "CONGESTION / RECOVERY", 14),
            (1, "LATENCY / TIMERS", 20),
        ] {
            let text = cell_text(
                &rows[y],
                column * (layout.column_width + 1),
                layout.column_width,
            );
            assert!(text.contains(title), "{title} at {column}/{y}: {text}");
        }
        assert!(rows.iter().all(|line| line.width() <= 120));
    }

    #[test]
    fn narrow_layout_preserves_every_module_and_empty_identity_has_no_gap() {
        let layout = DetailLayout::new(60);
        let groups = fixtures();
        let count = layout.row_count(&groups);
        let rows = layout.compose(groups);
        let titles: Vec<_> = rows
            .iter()
            .map(Line::to_string)
            .filter(|line| line.starts_with('┌'))
            .collect();
        for (title, expected) in titles.iter().zip([
            "TRAFFIC / QUEUES",
            "WINDOWS / BUFFERS",
            "LIMIT BASIS",
            "PATH / MEMORY",
            "CONGESTION / RECOVERY",
            "LATENCY / TIMERS",
        ]) {
            assert!(title.contains(expected));
        }
        assert_eq!(titles.len(), 6);
        assert_eq!(count, rows.len());
        assert_eq!(count, 3 + 1 + 20 + 6 * 2);

        let groups = vec![group("IDENTITY", 0), group("LISTENER BACKLOG", 1)];
        assert_eq!(layout.row_count(&groups), 3);
        assert!(layout.compose(groups)[0]
            .to_string()
            .contains("LISTENER BACKLOG"));
    }

    #[test]
    fn counts_match_at_every_width_even_with_sparse_or_unknown_groups() {
        for width in 0..=180 {
            let layout = DetailLayout::new(width);
            let value = if width < 5 { "x" } else { "v" };
            let groups = ["IDENTITY", "LISTENER BACKLOG", "LIMIT BASIS", "EXTRA"]
                .into_iter()
                .map(|title| DetailGroup::take(title, &mut vec![Line::raw(value)]))
                .collect::<Vec<_>>();
            let count = layout.row_count(&groups);
            let rows = layout.compose(groups);
            assert_eq!(count, rows.len(), "width {width}");
            assert!(
                rows.iter().all(|line| line.width() <= usize::from(width)),
                "width {width}"
            );
            assert_eq!(layout.full_inner_width(), usize::from(width).max(1));
            if width > 0 {
                assert_eq!(rows[0].to_string(), value);
            }
        }
        let layout = DetailLayout::new(160);
        assert_eq!(layout.row_count(&[]), 0);
        assert!(layout.compose(vec![group("LIMIT BASIS", 0)]).is_empty());
        assert_eq!(layout.row_count(&[group("IDENTITY", 3)]), 3);
        assert_eq!(layout.compose(vec![group("IDENTITY", 3)]).len(), 3);
    }

    #[test]
    fn frame_titles_retain_theme_color_and_bold_style() {
        let layout = DetailLayout::new(160);
        let rows = layout.compose(fixtures());
        for (title, color) in [
            (" LIMIT BASIS ", theme::WARN),
            (" WINDOWS / BUFFERS ", theme::GOOD),
        ] {
            let span = rows
                .iter()
                .flat_map(|line| &line.spans)
                .find(|span| span.content == title)
                .unwrap();
            assert_eq!(span.style.fg, Some(color));
            assert!(span.style.add_modifier.contains(Modifier::BOLD));
        }
    }
}
