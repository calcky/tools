use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

use crate::softnet::{Report, Values};

#[derive(Default)]
pub struct Table {
    pub headers: Vec<Line<'static>>,
    pub total: Vec<Line<'static>>,
    pub rows: Vec<Vec<Line<'static>>>,
}

fn values(report: &Report, values: &Values) -> Vec<String> {
    values
        .events
        .iter()
        .map(|n| report.value(*n))
        .chain([values.backlog.map_or_else(|| "-".into(), |n| n.to_string())])
        .collect()
}

fn styles(values: &Values, peak: bool, total: bool) -> Vec<Style> {
    let plain = Style::default();
    let bold = plain.add_modifier(Modifier::BOLD);
    values
        .events
        .iter()
        .enumerate()
        .map(|(i, count)| {
            if *count == 0 {
                plain.fg(Color::DarkGray)
            } else {
                match i {
                    1 | 4 => bold.fg(Color::Red),
                    2 => bold.fg(Color::Yellow),
                    0 if peak => bold.fg(Color::Green),
                    _ if total => bold,
                    _ => plain,
                }
            }
        })
        .chain([if values.backlog == Some(0) {
            plain.fg(Color::DarkGray)
        } else if total {
            bold
        } else {
            plain
        }])
        .collect()
}

impl Table {
    pub fn new(report: &Report, width: usize) -> Self {
        if report.status.is_some() {
            return Self::default();
        }
        let names = if report.delta {
            ["processed", "dropped", "squeeze", "rps", "flow", "backlog"]
        } else {
            [
                "processed/s",
                "dropped/s",
                "squeeze/s",
                "rps/s",
                "flow/s",
                "backlog",
            ]
        };
        let total = values(report, &report.total);
        let rows: Vec<_> = report
            .rows
            .iter()
            .map(|r| values(report, &r.values))
            .collect();
        let label_width = report
            .rows
            .iter()
            .map(|r| 3 + r.id.to_string().len())
            .max()
            .unwrap_or(3)
            .max(3);
        let widths: Vec<_> = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                rows.iter()
                    .map(|r| r[i].len())
                    .chain([total[i].len(), name.len()])
                    .max()
                    .unwrap()
            })
            .collect();
        let mut groups = vec![Vec::new()];
        let mut used = label_width;
        for (i, cell_width) in widths.iter().enumerate() {
            if used + 2 + cell_width > width && !groups.last().unwrap().is_empty() {
                groups.push(Vec::new());
                used = label_width;
            }
            groups.last_mut().unwrap().push(i);
            used += 2 + cell_width;
        }
        let lines = |label: &str, cells: &[String], cell_styles: &[Style], label_style: Style| {
            groups
                .iter()
                .map(|group| {
                    let mut spans =
                        vec![Span::styled(format!("{label:<label_width$}"), label_style)];
                    for &i in group {
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled(
                            format!("{:>width$}", cells[i], width = widths[i]),
                            cell_styles[i],
                        ));
                    }
                    Line::from(spans)
                })
                .collect::<Vec<_>>()
        };
        let bold = Style::default().add_modifier(Modifier::BOLD);
        let headers = lines("CPU", &names.map(String::from), &[bold; 6], bold);
        let total = lines("all", &total, &styles(&report.total, false, true), bold);
        let rows = report
            .rows
            .iter()
            .zip(rows)
            .map(|(row, cells)| {
                let peak = report.peak > 0 && row.values.events[0] == report.peak;
                lines(
                    &format!("CPU{}", row.id),
                    &cells,
                    &styles(&row.values, peak, false),
                    if peak {
                        bold.fg(Color::Green)
                    } else {
                        Style::default()
                    },
                )
            })
            .collect();
        Self {
            headers,
            total,
            rows,
        }
    }
}

pub fn plain(line: &Line<'_>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::softnet::Cpu;

    pub fn report() -> Report {
        Report {
            rows: (0..64)
                .map(|id| Cpu {
                    id,
                    values: Values {
                        events: [100 + u64::from(id), 1, 1, 0, 1],
                        backlog: Some(0),
                    },
                })
                .collect(),
            total: Values {
                events: [8416, 64, 64, 0, 64],
                backlog: Some(0),
            },
            elapsed: 2.0,
            peak: 163,
            ..Report::default()
        }
    }

    #[test]
    fn table_preserves_values_at_narrow_widths_and_colors_anomalies() {
        let mut report = report();
        for width in [55, 60, 80, 100, 120, 160] {
            let table = Table::new(&report, width);
            for line in table
                .headers
                .iter()
                .chain(&table.total)
                .chain(table.rows.iter().flatten())
            {
                assert!(line.width() <= width, "width {width}: {}", plain(line));
            }
            let cells = table.rows[63]
                .iter()
                .flat_map(|l| &l.spans)
                .collect::<Vec<_>>();
            assert!(cells
                .iter()
                .any(|s| s.content.trim() == "81.50" && s.style.fg == Some(Color::Green)));
            assert!(cells
                .iter()
                .any(|s| s.content.trim() == "0.50" && s.style.fg == Some(Color::Red)));
            assert!(cells
                .iter()
                .any(|s| s.content.trim() == "0.50" && s.style.fg == Some(Color::Yellow)));
        }
        report.delta = true;
        report.total.events = [u64::MAX; 5];
        let table = Table::new(&report, 55);
        assert!(table.total.iter().all(|line| line.width() <= 55));
        assert_eq!(
            table
                .total
                .iter()
                .map(plain)
                .collect::<Vec<_>>()
                .join(" ")
                .matches(&u64::MAX.to_string())
                .count(),
            5
        );
        assert!(!table
            .headers
            .iter()
            .map(plain)
            .any(|line| line.contains("/s")));
    }
}
