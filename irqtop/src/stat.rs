use std::io::{self, Write};

use crate::{fit, Frame};

pub struct Printer {
    started: bool,
    lines_since_header: usize,
    widths: [usize; 4],
    screen_width: usize,
}

impl Default for Printer {
    fn default() -> Self {
        Self {
            started: false,
            lines_since_header: 0,
            widths: [8, 6, 16, 12],
            screen_width: 0,
        }
    }
}

impl Printer {
    fn table_line(&self, time: &str, id: &str, cpu: &str, source: &str, value: &str) -> String {
        let [id_width, cpu_width, source_width, value_width] = self.widths;
        let id = fit(id, id_width);
        let source = fit(source, source_width);
        format!("{time:<8}  {id:<id_width$}  {cpu:<cpu_width$}  {source:<source_width$}  {value:>value_width$}")
    }

    pub fn print(&mut self, out: &mut impl Write, report: &Frame, height: usize) -> io::Result<()> {
        let old_widths = self.widths;
        for row in &report.entries {
            self.widths[0] = self.widths[0].max(row.id.chars().count());
            self.widths[1] = self.widths[1].max(
                row.cpus
                    .iter()
                    .map(|(c, _)| 3 + c.to_string().len())
                    .max()
                    .unwrap_or(0),
            );
            self.widths[2] = self.widths[2].max(row.source.chars().count());
            self.widths[3] = self.widths[3].max(row.value.len());
        }
        if !self.started {
            writeln!(
                out,
                "{} | {} | rate >= {}/s\n",
                report.program,
                fit(&report.scope, usize::MAX),
                report.min_rate
            )?;
        } else {
            writeln!(out)?;
            self.lines_since_header += 1;
        }
        if !self.started
            || report.softnet.is_some()
            || self.widths != old_widths
            || self.screen_width != report.width
            || self.lines_since_header >= height.saturating_sub(4).max(5)
        {
            writeln!(
                out,
                "{}",
                self.table_line("TIME", "IRQ/TYPE", "CPU", "NETDEV", report.unit)
            )?;
            self.lines_since_header = 0;
        }
        self.started = true;
        self.screen_width = report.width;

        for row in &report.entries {
            let cpu = match row.cpus.as_slice() {
                [(id, _)] => format!("CPU{id}"),
                [] => "-".into(),
                _ => "all".into(),
            };
            writeln!(
                out,
                "{}",
                self.table_line(&report.clock, &row.id, &cpu, &row.source, &row.value)
            )?;
            self.lines_since_header += 1;
            if row.cpus.len() <= 1 {
                continue;
            }

            let label_width = row
                .cpus
                .iter()
                .map(|(c, _)| 4 + c.to_string().len())
                .max()
                .unwrap_or(0);
            let value_width = row.cpus.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
            let columns = ((report.width.saturating_sub(10) + 3)
                / (label_width + 1 + value_width + 3))
                .max(1);
            for cells in row.cpus.chunks(columns) {
                let cells: Vec<_> = cells
                    .iter()
                    .map(|(cpu, value)| {
                        let label = format!("CPU{cpu}:");
                        format!("{label:<label_width$} {value:>value_width$}")
                    })
                    .collect();
                writeln!(out, "          {}", cells.join(" | "))?;
                self.lines_since_header += 1;
            }
        }
        if report.entries.is_empty() {
            let message = if report.matched == 0 {
                "No matching sources".to_string()
            } else {
                format!("No sources >= {}/s", report.min_rate)
            };
            writeln!(out, "{}  {message}", report.clock)?;
            self.lines_since_header += 1;
        }
        if let Some(softnet) = &report.softnet {
            writeln!(out, "\nSOFTNET | host | {}", report.clock)?;
            self.lines_since_header += 2;
            if let Some(status) = &softnet.status {
                writeln!(out, "{status}")?;
                self.lines_since_header += 1;
            } else {
                let table = crate::softnet_view::Table::new(softnet, report.width);
                for line in table
                    .headers
                    .iter()
                    .chain(&table.total)
                    .chain(table.rows.iter().flatten())
                {
                    writeln!(out, "{}", crate::softnet_view::plain(line))?;
                    self.lines_since_header += 1;
                }
            }
        }
        out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame, options, parse, parse_domain, Domain};

    fn sample(width: usize) -> Frame {
        let snapshot = parse("CPU28 CPU40 CPU42\n128: 1137762 0 0 vfio\n401: 0 863936 0 vfio\n403: 0 0 558988 vfio\n").unwrap();
        let mut report = frame(&options(vec![]).unwrap(), None, &snapshot, 100.0, width);
        for (row, source) in report
            .entries
            .iter_mut()
            .zip(["xnic0/vf1", "xnic0/vf9", "xnic0/vf9"])
        {
            row.source = source.into();
        }
        report
    }

    #[test]
    fn softnet_plain_output_keeps_units_totals_and_small_anomalies() {
        let mut report = sample(55);
        report.entries.clear();
        report.softnet = Some(crate::softnet::Report {
            total: crate::softnet::Values {
                events: [10, 1, 1, 0, 1],
                backlog: Some(5),
            },
            rows: vec![crate::softnet::Cpu {
                id: 28,
                values: crate::softnet::Values {
                    events: [10, 1, 1, 0, 1],
                    backlog: Some(5),
                },
            }],
            elapsed: 2.0,
            peak: 10,
            ..crate::softnet::Report::default()
        });
        let mut printer = Printer::default();
        let mut output = Vec::new();
        printer.print(&mut output, &report, 24).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("SOFTNET | host"));
        assert!(output.contains("processed/s") && output.contains("backlog"));
        assert!(output
            .lines()
            .any(|s| s.starts_with("CPU28") && s.contains("0.50")));
        assert!(output
            .lines()
            .any(|s| s.starts_with("all") && s.contains("5.00")));
        assert!(!output.contains('\x1b'));
        let table = output.split("SOFTNET").nth(1).unwrap();
        assert!(table.lines().all(|s| s.len() <= 55));
        let mut next = Vec::new();
        printer.print(&mut next, &report, 24).unwrap();
        assert!(String::from_utf8(next).unwrap().contains("IRQ/TYPE"));
    }

    #[test]
    fn single_cpu_sources_use_one_row_and_share_headers() {
        let mut report = sample(80);
        let mut printer = Printer::default();
        let mut out = Vec::new();
        for second in 53..56 {
            report.clock = format!("11:14:{second}");
            printer.print(&mut out, &report, 24).unwrap();
        }
        let output = std::str::from_utf8(&out).unwrap();
        assert_eq!(output.matches("irqstat |").count(), 1);
        assert_eq!(output.matches("IRQ/TYPE").count(), 1);
        assert!(!output.contains("CPU all ="));
        assert!(!output.contains("HARD IRQ"));
        assert!(!output.contains("CPU28:"));
        let rows: Vec<_> = output.lines().filter(|s| s.starts_with("11:")).collect();
        assert_eq!(rows.len(), 9);
        assert_eq!(
            rows[0].split_whitespace().collect::<Vec<_>>(),
            ["11:14:53", "128", "CPU28", "xnic0/vf1", "11377.62"]
        );
        assert_eq!(
            rows[1].split_whitespace().collect::<Vec<_>>(),
            ["11:14:53", "401", "CPU40", "xnic0/vf9", "8639.36"]
        );
        assert!(rows.iter().all(|row| row.len() < 80));
        for _ in 0..6 {
            printer.print(&mut out, &report, 24).unwrap();
        }
        let output = String::from_utf8(out).unwrap();
        assert_eq!(output.matches("irqstat |").count(), 1);
        assert!(output.matches("IRQ/TYPE").count() > 1);
    }

    #[test]
    fn all_cpu_details_and_totals_fit_without_losing_values() {
        let cpus = (0..64)
            .map(|c| format!("CPU{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        let values = (1..=64)
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let snapshot = parse_domain(&format!("{cpus}\nNET_RX: {values}\n"), Domain::Soft).unwrap();
        for width in [55, 80, 120, 160] {
            let report = frame(
                &options(vec!["-s".into()]).unwrap(),
                None,
                &snapshot,
                1.0,
                width,
            );
            let mut out = Vec::new();
            Printer::default().print(&mut out, &report, 24).unwrap();
            let output = String::from_utf8(out).unwrap();
            let row = output.lines().find(|s| s.contains("NET_RX")).unwrap();
            assert_eq!(
                row.split_whitespace().skip(1).collect::<Vec<_>>(),
                ["NET_RX", "all", "softirq", "2080.00"]
            );
            let cells: Vec<_> = output
                .lines()
                .filter(|s| s.starts_with("          CPU"))
                .flat_map(|s| s.split('|'))
                .collect();
            assert_eq!(cells.len(), 64);
            for (cpu, cell) in cells.iter().enumerate() {
                assert_eq!(
                    cell.split_whitespace().collect::<Vec<_>>(),
                    [format!("CPU{cpu}:"), format!("{:.2}", (cpu + 1) as f64)]
                );
            }
            assert!(output
                .lines()
                .filter(|s| s.starts_with("          CPU"))
                .all(|s| s.len() <= width));
        }
    }

    #[test]
    fn idle_filtered_and_large_counts_stay_unambiguous() {
        let mut report = sample(80);
        report.clock = "11:14:53".into();
        report.unit = "count";
        report.entries[0].cpus = vec![(10000, "18446744073709551615".into())];
        report.entries[0].value = "18446744073709551615".into();
        report.entries[0].source = "a-very-long-interface/vf12345".into();
        report.entries[1].cpus.clear();
        report.entries[1].value = "0".into();
        let mut out = Vec::new();
        let mut printer = Printer::default();
        printer.print(&mut out, &report, 24).unwrap();
        report.entries.clear();
        printer.print(&mut out, &report, 24).unwrap();
        report.matched = 0;
        printer.print(&mut out, &report, 24).unwrap();
        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("CPU10000"));
        assert!(output.contains("a-very-long-interface/vf12345"));
        assert_eq!(output.matches("18446744073709551615").count(), 1);
        assert!(output
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>()
                == ["11:14:53", "401", "-", "xnic0/vf9", "0"]));
        assert!(output.contains("11:14:53  No sources >= 200/s"));
        assert!(output.contains("11:14:53  No matching sources"));
        assert!(!output.contains('\x1b'));
    }
}
