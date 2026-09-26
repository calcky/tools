use super::*;
use ratatui::text::Text;

pub(super) struct GroupColumns {
    labels: Vec<&'static str>,
    widths: Vec<u16>,
    styles: Vec<Style>,
    fields: usize,
    available: u16,
    expanded: bool,
}

impl GroupColumns {
    pub fn new(view: &View, available: u16) -> Self {
        let mut labels = Vec::new();
        let mut styles = Vec::new();
        for field in &view.fields {
            let (label, color) = match field {
                Field::Src => ("Source", Color::Reset),
                Field::Dst => ("Destination", Color::Reset),
                Field::Sport => ("Src port", Color::Cyan),
                Field::Dport => ("Dst port", Color::Cyan),
                Field::Proto => ("Proto", Color::Green),
                Field::Zone => ("Zone", Color::Reset),
                Field::Mark => ("Mark", Color::Yellow),
            };
            labels.push(label);
            styles.push(view.color(color));
        }
        if view
            .groups
            .iter()
            .any(|g| g.values.len() > view.fields.len())
        {
            labels.push("Context");
            styles.push(view.color(Color::Gray));
        }
        let mut result = Self {
            widths: labels.iter().map(|s| s.len() as u16).collect(),
            labels,
            styles,
            fields: view.fields.len(),
            available: available.max(1),
            expanded: false,
        };
        for group in &view.groups {
            for (i, value) in result.values(group).iter().enumerate() {
                result.widths[i] = result.widths[i].max(value.len() as u16);
            }
        }
        result.expanded = result.widths.iter().sum::<u16>()
            + result.widths.len().saturating_sub(1) as u16 * 2
            <= result.available;
        result
    }

    fn values(&self, group: &Group) -> Vec<String> {
        let mut values = group.values[..self.fields].to_vec();
        if self.labels.len() > self.fields {
            values.push(group.values[self.fields..].join(" "));
        }
        values
    }

    pub fn header(&self) -> Cell<'static> {
        if self.expanded {
            Cell::from(
                self.aligned(
                    &self
                        .labels
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>(),
                    true,
                ),
            )
        } else {
            Cell::from("Group")
        }
    }

    fn aligned(&self, values: &[String], header: bool) -> Line<'static> {
        let mut spans = Vec::new();
        for (i, value) in values.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw("  "));
            }
            spans.push(Span::styled(
                format!("{value:<width$}", width = self.widths[i] as usize),
                if header {
                    Style::default()
                } else {
                    self.styles[i]
                },
            ));
        }
        Line::from(spans)
    }

    pub fn cell(&self, group: &Group) -> (Cell<'static>, u16) {
        let values = self.values(group);
        if self.expanded {
            return (Cell::from(self.aligned(&values, false)), 1);
        }
        let mut lines = Vec::new();
        for (i, value) in values.iter().enumerate() {
            if value.is_empty() {
                continue;
            }
            // Group values and labels are ASCII; wrap rather than hiding IPv6 suffixes.
            let text = format!("{}: {}", self.labels[i], value);
            for chunk in text.as_bytes().chunks(self.available as usize) {
                lines.push(Line::from(Span::styled(
                    String::from_utf8_lossy(chunk).into_owned(),
                    self.styles[i],
                )));
            }
        }
        let height = lines.len().max(1) as u16;
        (Cell::from(Text::from(lines)), height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn composite_columns_align_and_compact_rows_keep_all_values() {
        for fields in [
            vec![Field::Dst, Field::Dport, Field::Proto],
            vec![Field::Src, Field::Dst],
            vec![Field::Mark, Field::Src],
        ] {
            let mut engine = crate::engine::fixture();
            let mut first = model::fixture();
            first.mark = Some(u32::MAX);
            let mut second = first.clone();
            second.key.original.src = "::1".parse().unwrap();
            second.key.original.dst = "::2".parse().unwrap();
            second.key.original.dport = Some(22);
            second.mark = Some(0);
            engine.entries.insert(first.key.clone(), first);
            engine.entries.insert(second.key.clone(), second);
            let options = Options {
                fields,
                ..Options::default()
            };
            let mut view = View::new(&options);
            view.mono = true;
            view.rebuild(&engine, &options);
            for width in [21, 100] {
                let columns = GroupColumns::new(&view, width);
                let rows = view
                    .groups
                    .iter()
                    .map(|g| {
                        let (cell, height) = columns.cell(g);
                        Row::new(vec![cell]).height(height)
                    })
                    .collect::<Vec<_>>();
                let mut terminal = Terminal::new(TestBackend::new(width, 30)).unwrap();
                terminal
                    .draw(|frame| {
                        frame.render_widget(
                            Table::new(rows, [Constraint::Length(width)])
                                .header(Row::new(vec![columns.header()])),
                            frame.area(),
                        )
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let lines = buffer
                    .content
                    .chunks(width as usize)
                    .map(|line| line.iter().map(|c| c.symbol()).collect::<String>())
                    .collect::<Vec<_>>();
                let text = lines.iter().map(|line| line.trim()).collect::<String>();
                for group in &view.groups {
                    for value in &group.values {
                        assert!(text.contains(value), "{width}: {value}: {text}");
                    }
                }
                assert!(buffer.content.iter().all(|c| c.fg == Color::Reset));
                if width == 100 {
                    assert!(columns.expanded);
                    let offset = columns.widths[0] as usize + 2;
                    for (i, group) in view.groups.iter().enumerate() {
                        assert!(lines[i + 1][offset..].starts_with(&group.values[1]));
                    }
                }
            }
        }
    }
}
