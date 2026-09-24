use super::{module_frame, sort_table, theme};
use crate::monitor::hardirq::HardirqSnapshot;
use crate::monitor::InterfaceViewAnchor;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Sort {
    Irq,
    Netdev,
    Count,
    Rate,
}
impl Sort {
    pub(super) fn next(self) -> Self {
        match self {
            Self::Irq => Self::Netdev,
            Self::Netdev => Self::Count,
            Self::Count => Self::Rate,
            Self::Rate => Self::Irq,
        }
    }
    pub(super) fn descending(self) -> bool {
        matches!(self, Self::Count | Self::Rate)
    }
}
struct Row {
    irq: u32,
    netdev: String,
    count: u128,
    rate: Option<f64>,
    cpus: String,
}
#[derive(Debug)]
pub(super) struct HardirqTable {
    heading: Line<'static>,
    context: Line<'static>,
    header: Line<'static>,
    rows: Vec<Line<'static>>,
    widths: [usize; 5],
}
impl HardirqTable {
    pub(super) fn new(
        snapshot: &HardirqSnapshot,
        anchor: Option<&InterfaceViewAnchor>,
        width: u16,
        sort: Sort,
        descending: bool,
    ) -> Self {
        let inner = usize::from(module_frame::inner_width(width));
        let widths = columns(inner);
        let mut records = Vec::new();
        for row in &snapshot.data.rows {
            if !row.interfaces.iter().any(|(name, index)| match anchor {
                None => true,
                Some(InterfaceViewAnchor::Name { name: interface }) => {
                    name == interface.as_str()
                        || name.starts_with(&format!("{}/vf", interface.as_str()))
                }
                Some(InterfaceViewAnchor::Names { names }) => names.iter().any(|interface| {
                    name == interface.as_str() || name.starts_with(&format!("{interface}/vf"))
                }),
                Some(InterfaceViewAnchor::Ifindex { ifindex }) => *index == ifindex.get(),
            }) {
                continue;
            }
            let rates = snapshot.rates(row);
            let cpus = active_cpus(&snapshot.data.cpus, rates.as_deref(), widths[2]);
            records.push(Row {
                irq: row.irq,
                netdev: row
                    .interfaces
                    .iter()
                    .map(|(name, _)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                count: row.counts.iter().map(|value| u128::from(*value)).sum(),
                rate: rates.as_ref().map(|values| values.iter().sum()),
                cpus,
            });
        }
        records.sort_by(|left, right| {
            let order = match sort {
                Sort::Irq => left.irq.cmp(&right.irq),
                Sort::Netdev => left.netdev.cmp(&right.netdev),
                Sort::Count => left.count.cmp(&right.count),
                Sort::Rate => match (left.rate, right.rate) {
                    (Some(left), Some(right)) => left.total_cmp(&right),
                    (None, Some(_)) => return Ordering::Greater,
                    (Some(_), None) => return Ordering::Less,
                    _ => Ordering::Equal,
                },
            };
            (if descending { order.reverse() } else { order })
                .then_with(|| left.irq.cmp(&right.irq))
        });
        let heading = Line::styled(
            format!(
                " HARDIRQ / NETWORK  {} IRQs  {} CPUs",
                records.len(),
                snapshot.data.cpus.len()
            ),
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        );
        let context = Line::styled(match &snapshot.error {
            Some(error) => format!(" STALE / UNAVAILABLE: {error}"),
            None => match snapshot.previous.as_ref() {
                Some((before, _)) => format!(" /proc/interrupts | count since boot | interval {:.3}s | CPU: active this interval", snapshot.at.saturating_sub(*before).as_secs_f64()),
                None => " /proc/interrupts | count since boot | rates pending a second sample".to_owned(),
            },
        }, Style::default().fg(if snapshot.error.is_some() { theme::BAD } else { theme::MUTED }));
        let mut cells = Vec::new();
        for (index, (label, key)) in [
            ("IRQ", Some(Sort::Irq)),
            ("NETDEV", Some(Sort::Netdev)),
            ("CPU", None),
            ("COUNT", Some(Sort::Count)),
            ("intr/s", Some(Sort::Rate)),
        ]
        .into_iter()
        .enumerate()
        {
            let selected = key == Some(sort);
            let label = if key.is_some() {
                sort_table::label(label, widths[index], selected.then_some(descending))
            } else {
                super::summary::fit(label, widths[index])
            };
            if index > 0 {
                cells.push(Span::styled("│", Style::default().fg(theme::DIVIDER)));
            }
            cells.push(Span::styled(
                sort_table::pad(&label, widths[index], index >= 3),
                Style::default()
                    .fg(theme::TEXT_STRONG)
                    .bg(if selected {
                        theme::SELECTED_BG
                    } else {
                        theme::CHROME_BG
                    })
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let header = Line::from(cells);
        let mut rows = Vec::new();
        for row in records {
            let values = [
                row.irq.to_string(),
                row.netdev,
                row.cpus,
                row.count.to_string(),
                rate(row.rate),
            ];
            let mut spans = Vec::new();
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    spans.push(Span::styled("│", Style::default().fg(theme::DIVIDER)));
                }
                spans.push(Span::styled(
                    sort_table::pad(value, widths[index], index >= 3),
                    Style::default()
                        .fg(if index == 4 {
                            theme::ACCENT
                        } else {
                            theme::TEXT_STRONG
                        })
                        .add_modifier(Modifier::BOLD),
                ));
            }
            rows.push(Line::from(spans));
        }
        if rows.is_empty() {
            rows.push(Line::styled(
                " No mapped network IRQs in this snapshot",
                Style::default().fg(theme::MUTED),
            ));
        }
        Self {
            heading,
            context,
            header,
            rows,
            widths,
        }
    }
    pub(super) fn viewport(&self, height: usize, offset: usize) -> sort_table::TableViewport {
        sort_table::TableViewport::new(2, 1, self.rows.len(), height.saturating_sub(1), offset)
    }
    pub(super) fn sort_at(&self, x: u16, y: usize, height: usize, offset: usize) -> Option<Sort> {
        let view = self.viewport(height, offset);
        if y != view.context || x == 0 {
            return None;
        }
        let mut start = 1;
        for (width, key) in self.widths.iter().zip([
            Some(Sort::Irq),
            Some(Sort::Netdev),
            None,
            Some(Sort::Count),
            Some(Sort::Rate),
        ]) {
            if usize::from(x) >= start && usize::from(x) < start + width {
                return key;
            }
            start += width + 1;
        }
        None
    }
    pub(super) fn render(&self, frame: &mut Frame<'_>, area: Rect, offset: usize) {
        let view = self.viewport(usize::from(area.height), offset);
        let mut content = Vec::new();
        if view.context >= 1 {
            content.push(self.heading.clone());
        }
        if view.context >= 2 {
            content.push(self.context.clone());
        }
        if view.headings > 0 {
            content.push(self.header.clone());
        }
        content.extend(
            self.rows
                .iter()
                .skip(view.offset)
                .take(view.capacity)
                .cloned(),
        );
        // A hidden context must not turn the sortable header into a frame title.
        if view.context == 0 {
            let framed = module_frame::lines(
                std::iter::once(Line::default()).chain(content).collect(),
                area.width,
            );
            frame.render_widget(
                Paragraph::new(framed.into_iter().skip(1).collect::<Vec<_>>()),
                area,
            );
        } else {
            frame.render_widget(
                Paragraph::new(module_frame::lines(content, area.width)),
                area,
            );
        }
    }
}
fn rate(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}"))
}
fn active_cpus(cpus: &[u32], rates: Option<&[f64]>, width: usize) -> String {
    let Some(rates) = rates else {
        return "n/a".to_owned();
    };
    let active: Vec<_> = cpus
        .iter()
        .zip(rates)
        .filter_map(|(cpu, rate)| (*rate > 0.0).then_some(cpu))
        .collect();
    if active.is_empty() {
        return "-".to_owned();
    }
    let mut label = format!("+{}", active.len());
    let mut prefix = String::new();
    for (index, cpu) in active.iter().enumerate() {
        if index > 0 {
            prefix.push(',');
        }
        prefix.push_str(&cpu.to_string());
        let remaining = active.len() - index - 1;
        let candidate = if remaining == 0 {
            prefix.clone()
        } else {
            format!("{prefix},+{remaining}")
        };
        if candidate.len() <= width {
            label = candidate;
        }
        if prefix.len() > width {
            break;
        }
    }
    label
}
fn columns(width: usize) -> [usize; 5] {
    let available = width.saturating_sub(4);
    if available < 50 {
        let base = available / 5;
        return [base, base, base, base, available - base * 4];
    }
    let count = if available >= 90 { 20 } else { 16 };
    let cpu = if available >= 90 { 18 } else { 10 };
    [7, available - 7 - cpu - count - 13, cpu, count, 13]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::irq::{NetworkIrqData, NetworkIrqRow};
    use ratatui::{backend::TestBackend, Terminal};
    use std::time::Duration;

    fn snapshot() -> HardirqSnapshot {
        let data = |sequence: u64| NetworkIrqData {
            cpus: vec![0, 4, 9],
            rows: (0..40)
                .map(|index| NetworkIrqRow {
                    irq: index + 40,
                    interfaces: vec![(format!("eth{}", index % 2), index % 2 + 1)],
                    counts: vec![100 + sequence * u64::from(index), 200, 0],
                    action: format!("vector-{index}"),
                })
                .collect(),
        };
        let first = HardirqSnapshot::next(None, Duration::from_secs(1), Ok(data(0)));
        HardirqSnapshot::next(Some(&first), Duration::from_secs(3), Ok(data(1)))
    }

    #[test]
    fn irq_table_keeps_counts_rates_sort_geometry_and_sticky_headers() {
        let snapshot = snapshot();
        for width in [60, 80, 120, 160] {
            let model = HardirqTable::new(&snapshot, None, width, Sort::Rate, true);
            assert!(model.rows[0].to_string().starts_with("79"));
            assert!(model.rows[0].to_string().contains("339"));
            assert!(model.rows[0].to_string().ends_with("19.50"));
            assert_eq!(model.rows.len(), snapshot.data.rows.len());
            assert_eq!(
                model.rows[0].to_string().split('│').nth(2).unwrap().trim(),
                "0"
            );
            assert!(model.rows[1].to_string().starts_with("78"));
            let mut terminal = Terminal::new(TestBackend::new(width, 12)).unwrap();
            terminal
                .draw(|frame| model.render(frame, frame.area(), 0))
                .unwrap();
            let before = terminal.backend().buffer().clone();
            let mut separator_x = 1;
            for (index, column_width) in model.widths.iter().enumerate() {
                separator_x += *column_width as u16;
                if index < 4 {
                    assert_eq!(before[(separator_x, 2)].symbol(), "│");
                    assert_eq!(before[(separator_x, 3)].symbol(), "│");
                    assert!(model.sort_at(separator_x, 2, 12, 0).is_none());
                    separator_x += 1;
                }
            }
            assert_eq!(separator_x, width - 1);
            assert_eq!(before[(width - 2, 3)].symbol(), "0");
            terminal
                .draw(|frame| model.render(frame, frame.area(), 15))
                .unwrap();
            let after = terminal.backend().buffer();
            for y in 0..3 {
                for x in 0..width {
                    assert_eq!(before[(x, y)], after[(x, y)]);
                }
            }
            let sortable: Vec<_> = (0..width)
                .filter_map(|x| model.sort_at(x, 2, 12, 15))
                .collect();
            for key in [Sort::Irq, Sort::Netdev, Sort::Count, Sort::Rate] {
                assert!(sortable.contains(&key));
            }
            assert!(model.sort_at(0, 2, 12, 15).is_none());
            assert!(model.sort_at(width - 1, 2, 12, 15).is_none());
            assert!(model.sort_at(2, 3, 12, 15).is_none());
            let asc = HardirqTable::new(&snapshot, None, width, Sort::Irq, false);
            assert!(asc.rows[0].to_string().starts_with("40"));
            let filtered = HardirqTable::new(
                &snapshot,
                Some(&InterfaceViewAnchor::named("eth0").unwrap()),
                width,
                Sort::Irq,
                false,
            );
            assert!(filtered.heading.to_string().contains("20 IRQs"));
            assert!(!filtered
                .rows
                .iter()
                .any(|row| row.to_string().contains("eth1")));
        }
    }

    #[test]
    fn multiple_interfaces_include_vfs_and_shared_irqs_without_duplicate_rows() {
        let mut rows: Vec<_> = ["eth0", "eth0/vf1", "eth1", "eth2", "eth01/vf1"]
            .into_iter()
            .enumerate()
            .map(|(index, name)| NetworkIrqRow {
                irq: 40 + index as u32,
                interfaces: vec![(name.to_owned(), index as u32 + 1)],
                counts: vec![100],
                action: "vector".to_owned(),
            })
            .collect();
        rows[0].interfaces.push(("eth2".to_owned(), 4));
        let snapshot = HardirqSnapshot::next(
            None,
            Duration::from_secs(1),
            Ok(NetworkIrqData {
                cpus: vec![0],
                rows,
            }),
        );
        let anchor = InterfaceViewAnchor::named_many(["eth0".into(), "eth2".into()]).unwrap();
        let table = HardirqTable::new(&snapshot, Some(&anchor), 160, Sort::Irq, false);
        assert_eq!(table.rows.len(), 3);
        assert!(table.rows[0].to_string().contains("eth0,eth2"));
        assert!(table.rows[1].to_string().contains("eth0/vf1"));
        assert!(table.rows[2].to_string().contains("eth2"));
        assert!(!table
            .rows
            .iter()
            .any(|row| row.to_string().contains("eth1")));
        assert!(!table
            .rows
            .iter()
            .any(|row| row.to_string().contains("eth01")));
    }

    #[test]
    fn inline_cpu_list_distinguishes_idle_unknown_and_truncated_active_cpus() {
        assert_eq!(active_cpus(&[0, 4, 9], None, 10), "n/a");
        assert_eq!(active_cpus(&[0, 4, 9], Some(&[0.0, 0.0, 0.0]), 10), "-");
        assert_eq!(active_cpus(&[0, 4, 9], Some(&[1.0, 2.0, 3.0]), 10), "0,4,9");
        assert_eq!(active_cpus(&[0, 4, 9], Some(&[0.0, 2.0, 0.0]), 10), "4");
        assert_eq!(
            active_cpus(&[10, 40, 90], Some(&[1.0, 2.0, 3.0]), 5),
            "10,+2"
        );
    }

    #[test]
    fn tiny_viewports_and_error_frames_do_not_hide_zero_as_unavailable() {
        let snapshot = snapshot();
        let first = HardirqTable::new(&snapshot, None, 80, Sort::Irq, false);
        assert!(first.rows[0].to_string().ends_with("0.00"));
        let failed = HardirqSnapshot::next(
            Some(&snapshot),
            Duration::from_secs(4),
            Err("read failed".to_owned()),
        );
        for width in [12, 40, 80, 160] {
            let table = HardirqTable::new(&failed, None, width, Sort::Rate, true);
            assert!(table.context.to_string().contains("STALE"));
            if width >= 40 {
                assert!(table.rows[0].to_string().contains("n/a"));
            }
            for height in [2, 3, 4, 10] {
                let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                terminal
                    .draw(|frame| table.render(frame, frame.area(), 1000))
                    .unwrap();
                let view = table.viewport(usize::from(height), 1000);
                assert!(view.offset <= view.max_offset);
            }
        }
    }
}
