use ratatui::{
    style::{Color, Modifier, Style},
    text::Line,
};
use std::time::Duration;

/// Render unpadded per-CPU values whose BTF type is an unsigned integer.
pub fn lines(
    current: &[u8],
    previous: Option<&[u8]>,
    value_size: usize,
    cpu_ids: Option<&[usize]>,
    elapsed: Option<Duration>,
    counter_mode: bool,
    no_color: bool,
) -> Vec<Line<'static>> {
    let mut output = vec![
        Line::raw("SHARE: positive observed deltas; reads are not atomic."),
        Line::raw("Observed deltas are not exact counter totals."),
    ];
    if counter_mode {
        output.push(Line::raw(
            "Counter interpretation is user selected; RATE/s uses actual elapsed time.",
        ));
    }
    if !matches!(value_size, 1 | 2 | 4 | 8) {
        output.push(Line::raw(
            "Per-CPU values unavailable: unsigned size must be 1, 2, 4 or 8.",
        ));
        return output;
    }
    if current.is_empty() || !current.len().is_multiple_of(value_size) {
        output.push(Line::raw(
            "Per-CPU values unavailable: empty or incomplete current sample.",
        ));
        return output;
    }

    let values: Vec<_> = current.chunks_exact(value_size).map(unsigned).collect();
    let before = previous
        .filter(|sample| sample.len() == current.len())
        .map(|sample| {
            sample
                .chunks_exact(value_size)
                .map(unsigned)
                .collect::<Vec<_>>()
        });
    let deltas: Vec<_> = values
        .iter()
        .enumerate()
        .map(|(index, &value)| {
            before
                .as_ref()
                .and_then(|old| value.checked_sub(old[index]))
        })
        .collect();
    let total: u128 = deltas.iter().flatten().copied().map(u128::from).sum();
    let greatest = deltas
        .iter()
        .flatten()
        .copied()
        .max()
        .filter(|&delta| delta > 0);
    let ids = cpu_ids.filter(|ids| ids.len() == values.len());
    let interval = elapsed.filter(|interval| !interval.is_zero());
    let value_total: u128 = values.iter().copied().map(u128::from).sum();
    let valid = deltas.iter().flatten().count();
    let missing = if before.is_none() { values.len() } else { 0 };
    let resets = values.len() - valid - missing;
    output.push(Line::raw(format!(
        "VALUE sum (non-atomic observation): {value_total}"
    )));
    output.push(Line::raw(format!(
        "Positive observed DELTA total: {}",
        if before.is_some() {
            total.to_string()
        } else {
            "-".into()
        },
    )));
    output.push(Line::raw(format!(
        "DELTA coverage: {valid}/{} copies; {resets} resets; {missing} missing.",
        values.len(),
    )));

    if before.is_none() {
        output.push(Line::raw(if previous.is_none() {
            "First sample: DELTA/SHARE unavailable."
        } else {
            "Missing/incompatible previous sample: DELTA/SHARE unavailable."
        }));
    } else if deltas.iter().any(Option::is_none) {
        output.push(Line::raw(
            "Resets excluded; shares are incomplete, not exact counter totals.",
        ));
    }
    if total == 0 {
        output.push(Line::raw("No positive observed deltas: SHARE is '-'."));
    }
    if ids.is_none() {
        output.push(Line::raw("CPU IDs unavailable; CopyN denotes copy order."));
    }
    if counter_mode && interval.is_none() {
        output.push(Line::raw(
            "RATE/s unavailable: missing or zero elapsed time.",
        ));
    }

    let rows: Vec<[String; 5]> = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let delta = deltas[index];
            [
                ids.map_or_else(|| format!("Copy{index}"), |ids| ids[index].to_string()),
                value.to_string(),
                match delta {
                    Some(0) => "0".into(),
                    Some(delta) => format!("+{delta}"),
                    None if before.is_some() => "reset/-".into(),
                    None => "-".into(),
                },
                match delta {
                    Some(delta) if total > 0 => {
                        format!("{:.1}%", delta as f64 * 100.0 / total as f64)
                    }
                    _ => "-".into(),
                },
                if counter_mode {
                    match (delta, interval) {
                        (Some(delta), Some(interval)) => rate(delta, interval),
                        _ => "-".into(),
                    }
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    let headers = ["CPU", "VALUE", "DELTA", "SHARE", "RATE/s"];
    let widths: Vec<_> = headers
        .iter()
        .enumerate()
        .map(|(column, header)| {
            rows.iter()
                .map(|row| row[column].len())
                .max()
                .unwrap_or(0)
                .max(header.len())
        })
        .collect();
    // Keep exact integer cells; move wide rates onto their own labelled line.
    let inline_rate = counter_mode && widths.iter().sum::<usize>() + 12 <= 78;
    let columns = if inline_rate { 5 } else { 4 };
    let format_row = |cells: &[&str]| {
        cells
            .iter()
            .enumerate()
            .map(|(column, cell)| {
                if column == 0 {
                    format!("{cell:<width$}", width = widths[column])
                } else {
                    format!("{cell:>width$}", width = widths[column])
                }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    output.push(Line::styled(
        format_row(&headers[..columns]),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    for (index, row) in rows.iter().enumerate() {
        let mut style = Style::default();
        if greatest.is_some() && deltas[index] == greatest {
            style = style.add_modifier(Modifier::BOLD);
            if !no_color {
                style = style.fg(Color::Green);
            }
        }
        let cells: Vec<_> = row[..columns].iter().map(String::as_str).collect();
        output.push(Line::styled(format_row(&cells), style));
        if counter_mode && !inline_rate {
            output.push(Line::styled(
                format!("{:width$} | RATE/s {}", "", row[4], width = widths[0]),
                style,
            ));
        }
    }
    output
}

fn unsigned(bytes: &[u8]) -> u64 {
    match bytes.len() {
        1 => u64::from(bytes[0]),
        2 => u64::from(u16::from_ne_bytes(bytes.try_into().unwrap())),
        4 => u64::from(u32::from_ne_bytes(bytes.try_into().unwrap())),
        8 => u64::from_ne_bytes(bytes.try_into().unwrap()),
        _ => unreachable!("value size validated before decoding"),
    }
}

fn rate(delta: u64, interval: Duration) -> String {
    // Integer arithmetic keeps u64 deltas exact even above f64's integer range.
    let nanos = interval.as_nanos();
    let hundredths = (u128::from(delta) * 100_000_000_000 + nanos / 2) / nanos;
    format!("{}.{:02}", hundredths / 100, hundredths % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        backend::TestBackend,
        widgets::{Paragraph, Wrap},
        Terminal,
    };

    fn sample(values: &[u64], size: usize) -> Vec<u8> {
        values
            .iter()
            .flat_map(|&value| match size {
                1 => vec![value as u8],
                2 => (value as u16).to_ne_bytes().to_vec(),
                4 => (value as u32).to_ne_bytes().to_vec(),
                8 => value.to_ne_bytes().to_vec(),
                _ => panic!("invalid test sample size"),
            })
            .collect()
    }

    fn text(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn cells(line: &Line<'_>) -> Vec<String> {
        line.to_string()
            .split('|')
            .map(|cell| cell.trim().to_owned())
            .collect()
    }

    fn rows<'a>(lines: &'a [Line<'static>]) -> Vec<&'a Line<'static>> {
        lines
            .iter()
            .filter(|line| cells(line).len() >= 4 && cells(line)[0] != "CPU")
            .collect()
    }

    #[test]
    fn sparse_ids_and_all_copies_including_zero_are_displayed() {
        let current = sample(&[11, 4, 0], 8);
        let previous = sample(&[1, 4, 0], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[0, 7, 42]),
            None,
            false,
            true,
        );
        let rows = rows(&output);
        assert_eq!(rows.len(), 3);
        assert_eq!(cells(rows[0]), ["0", "11", "+10", "100.0%"]);
        assert_eq!(cells(rows[1]), ["7", "4", "0", "0.0%"]);
        assert_eq!(cells(rows[2]), ["42", "0", "0", "0.0%"]);
    }

    #[test]
    fn mismatched_or_missing_ids_use_copy_labels() {
        let current = sample(&[1, 0], 1);
        for ids in [None, Some(&[9][..]), Some(&[0, 9, 15][..])] {
            let output = lines(&current, None, 1, ids, None, false, true);
            let rows = rows(&output);
            assert_eq!(cells(rows[0])[0], "Copy0");
            assert_eq!(cells(rows[1])[0], "Copy1");
        }
    }

    #[test]
    fn redistribution_with_unchanged_sum_still_shows_positive_delta() {
        let current = sample(&[90, 110], 8);
        let previous = sample(&[100, 100], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[2, 8]),
            None,
            false,
            false,
        );
        let rows = rows(&output);
        assert_eq!(cells(rows[0]), ["2", "90", "reset/-", "-"]);
        assert_eq!(cells(rows[1]), ["8", "110", "+10", "100.0%"]);
        assert_eq!(rows[0].style, Style::default());
        assert_eq!(rows[1].style.fg, Some(Color::Green));
        assert!(text(&output).contains("VALUE sum (non-atomic observation): 200"));
        assert!(text(&output).contains("Positive observed DELTA total: 10"));
        assert!(text(&output).contains("DELTA coverage: 1/2 copies; 1 resets; 0 missing."));
        assert!(text(&output).contains("Resets excluded; shares are incomplete"));
        assert!(text(&output).contains("not exact counter totals"));
    }

    #[test]
    fn first_sample_has_no_delta_share_rate_or_highlight() {
        let current = sample(&[u64::MAX, 0], 8);
        let output = lines(
            &current,
            None,
            8,
            Some(&[0, 1]),
            Some(Duration::from_secs(1)),
            true,
            false,
        );
        for row in rows(&output) {
            assert_eq!(&cells(row)[2..], ["-", "-", "-"]);
            assert_eq!(row.style, Style::default());
        }
        assert!(text(&output).contains("First sample"));
        assert!(text(&output).contains("Positive observed DELTA total: -"));
        assert!(text(&output).contains("DELTA coverage: 0/2 copies; 0 resets; 2 missing."));
        assert!(text(&output).contains("user selected"));
        assert!(text(&output).contains("reads are not atomic"));
    }

    #[test]
    fn incompatible_previous_lengths_make_every_delta_unavailable() {
        let current = sample(&[3, 5], 4);
        for previous in [vec![], sample(&[1], 4), vec![0; 9]] {
            let output = lines(
                &current,
                Some(&previous),
                4,
                Some(&[0, 1]),
                Some(Duration::from_secs(1)),
                true,
                true,
            );
            for row in rows(&output) {
                assert_eq!(&cells(row)[2..], ["-", "-", "-"]);
                assert_eq!(row.style, Style::default());
            }
            assert!(text(&output).contains("Missing/incompatible previous sample"));
        }
    }

    #[test]
    fn decreases_are_resets_without_unsigned_wrap_or_rate() {
        for size in [1, 2, 4, 8] {
            let current = sample(&[0, 6], size);
            let previous = sample(&[u64::MAX, 2], size);
            let output = lines(
                &current,
                Some(&previous),
                size,
                Some(&[1, 7]),
                Some(Duration::from_secs(2)),
                true,
                true,
            );
            let rows = rows(&output);
            assert_eq!(cells(rows[0]), ["1", "0", "reset/-", "-", "-"]);
            assert_eq!(cells(rows[1]), ["7", "6", "+4", "100.0%", "2.00"]);
        }
    }

    #[test]
    fn zero_deltas_have_no_share_or_highlight() {
        let current = sample(&[0, 300], 8);
        let output = lines(
            &current,
            Some(&current),
            8,
            Some(&[0, 6]),
            Some(Duration::from_secs(1)),
            true,
            false,
        );
        for row in rows(&output) {
            assert_eq!(&cells(row)[2..], ["0", "-", "0.00"]);
            assert_eq!(row.style, Style::default());
        }
        assert!(text(&output).contains("No positive observed deltas"));
    }

    #[test]
    fn all_resets_have_no_share_or_highlight() {
        let current = sample(&[0, 1], 2);
        let previous = sample(&[2, 3], 2);
        let output = lines(&current, Some(&previous), 2, None, None, false, false);
        for row in rows(&output) {
            assert_eq!(&cells(row)[2..], ["reset/-", "-"]);
            assert_eq!(row.style, Style::default());
        }
    }

    #[test]
    fn all_supported_widths_decode_native_unsigned_values() {
        for (size, value) in [(1, 255), (2, 65_535), (4, 4_294_967_295), (8, u64::MAX)] {
            let current = sample(&[value], size);
            let previous = sample(&[value - 2], size);
            let output = lines(
                &current,
                Some(&previous),
                size,
                Some(&[17]),
                None,
                false,
                true,
            );
            assert_eq!(
                cells(rows(&output)[0]),
                [
                    "17".to_owned(),
                    value.to_string(),
                    "+2".to_owned(),
                    "100.0%".to_owned()
                ]
            );
        }
    }

    #[test]
    fn malformed_sizes_and_current_samples_are_reported_without_rows() {
        for size in [0, 3, 5, 16, usize::MAX] {
            let output = lines(&[1; 8], None, size, None, None, false, true);
            assert!(rows(&output).is_empty());
            assert!(text(&output).contains("unsigned size must be"));
        }
        for (current, size) in [
            (&[][..], 1),
            (&[1][..], 2),
            (&[1; 7][..], 4),
            (&[1; 9][..], 8),
        ] {
            let output = lines(current, None, size, None, None, false, true);
            assert!(rows(&output).is_empty());
            assert!(text(&output).contains("empty or incomplete current sample"));
        }
    }

    #[test]
    fn rates_use_actual_fractional_elapsed_time_only_in_counter_mode() {
        let current = sample(&[10], 8);
        let previous = sample(&[1], 8);
        let interval = Some(Duration::from_millis(2250));
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[0]),
            interval,
            true,
            true,
        );
        assert_eq!(cells(rows(&output)[0]), ["0", "10", "+9", "100.0%", "4.00"]);
        let numeric = lines(
            &current,
            Some(&previous),
            8,
            Some(&[0]),
            interval,
            false,
            true,
        );
        assert_eq!(cells(rows(&numeric)[0]), ["0", "10", "+9", "100.0%"]);
        assert!(!text(&numeric).contains("RATE/s"));
        assert!(!text(&numeric).contains("user selected"));
    }

    #[test]
    fn missing_or_zero_intervals_have_no_rate() {
        let current = sample(&[5], 4);
        let previous = sample(&[1], 4);
        for interval in [None, Some(Duration::ZERO)] {
            let output = lines(
                &current,
                Some(&previous),
                4,
                Some(&[0]),
                interval,
                true,
                true,
            );
            assert_eq!(cells(rows(&output)[0])[4], "-");
            assert!(text(&output).contains("missing or zero elapsed time"));
        }
    }

    #[test]
    fn greatest_positive_delta_wins_over_lifetime_value_and_ties_highlight() {
        let current = sample(&[10_000, 20, 30, 0], 8);
        let previous = sample(&[9_999, 10, 20, 0], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[0, 4, 9, 22]),
            None,
            false,
            false,
        );
        let rows = rows(&output);
        assert_eq!(rows[0].style, Style::default());
        assert_eq!(rows[3].style, Style::default());
        for row in &rows[1..3] {
            assert_eq!(row.style.fg, Some(Color::Green));
            assert!(row.style.add_modifier.contains(Modifier::BOLD));
        }
    }

    #[test]
    fn no_color_keeps_delta_highlight_bold_without_any_colors() {
        let current = sample(&[1_000, 20], 4);
        let previous = sample(&[999, 10], 4);
        let output = lines(
            &current,
            Some(&previous),
            4,
            Some(&[0, 3]),
            None,
            false,
            true,
        );
        let rows = rows(&output);
        assert_eq!(rows[0].style, Style::default());
        assert!(rows[1].style.add_modifier.contains(Modifier::BOLD));
        for line in &output {
            assert_eq!(line.style.fg, None);
            assert_eq!(line.style.bg, None);
            for span in &line.spans {
                assert_eq!(span.style.fg, None);
                assert_eq!(span.style.bg, None);
            }
        }
    }

    #[test]
    fn large_positive_totals_do_not_overflow_u64() {
        let current = sample(&[u64::MAX, u64::MAX], 8);
        let previous = sample(&[0, 0], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[0, 1]),
            None,
            false,
            true,
        );
        for row in rows(&output) {
            assert_eq!(cells(row)[1], u64::MAX.to_string());
            assert_eq!(cells(row)[2], format!("+{}", u64::MAX));
            assert_eq!(cells(row)[3], "50.0%");
        }
        assert!(text(&output).contains("VALUE sum (non-atomic observation): 36893488147419103230"));
        assert!(text(&output).contains("Positive observed DELTA total: 36893488147419103230"));
        assert!(text(&output).contains("DELTA coverage: 2/2 copies; 0 resets; 0 missing."));
    }

    #[test]
    fn large_rates_keep_integer_precision_and_fit_eighty_columns() {
        let current = sample(&[u64::MAX], 8);
        let previous = sample(&[0], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[usize::MAX]),
            Some(Duration::from_nanos(1)),
            true,
            true,
        );
        assert!(text(&output).contains("18446744073709551615000000000.00"));
        assert_eq!(cells(rows(&output)[0])[1], u64::MAX.to_string());
        assert_eq!(cells(rows(&output)[0])[2], format!("+{}", u64::MAX));
        assert!(output.iter().all(|line| line.width() <= 78));
        assert_eq!(
            rate(u64::MAX, Duration::from_secs(1)),
            "18446744073709551615.00"
        );
        assert_eq!(rate(1, Duration::from_secs(3)), "0.33");
        assert_eq!(rate(2, Duration::from_secs(3)), "0.67");
    }

    #[test]
    fn exact_numeric_cells_survive_wrapping_at_sixty_columns() {
        let current = sample(&[u64::MAX], 8);
        let previous = sample(&[0], 8);
        let output = lines(
            &current,
            Some(&previous),
            8,
            Some(&[usize::MAX]),
            Some(Duration::from_nanos(1)),
            true,
            true,
        );
        for width in [60, 80] {
            let mut terminal = Terminal::new(TestBackend::new(width, 30)).unwrap();
            terminal
                .draw(|frame| {
                    frame.render_widget(
                        Paragraph::new(output.clone()).wrap(Wrap { trim: false }),
                        frame.area(),
                    );
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            let rendered = (0..30)
                .map(|y| {
                    (0..width)
                        .map(|x| buffer[(x, y)].symbol())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                rendered.contains("18446744073709551615"),
                "{width}: {rendered}"
            );
            assert!(
                rendered.contains("+18446744073709551615"),
                "{width}: {rendered}"
            );
            assert!(
                rendered.contains("18446744073709551615000000000.00"),
                "{width}: {rendered}"
            );
            assert!(
                rendered.contains(&usize::MAX.to_string()),
                "{width}: {rendered}"
            );
            assert!(rendered.contains("100.0%"), "{width}: {rendered}");
        }
    }
}
