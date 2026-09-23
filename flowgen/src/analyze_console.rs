use super::{Aggregate, Group, Kind, Report, Samples};
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
};

const HEADING: &str = "1;36";
const KEY: &str = "1";
const ERROR: &str = "1;31";
const WARNING: &str = "1;33";
const GOOD: &str = "32";
const MUTED: &str = "2";

#[derive(Clone, Copy)]
struct Palette(bool);

impl Palette {
    fn paint(self, text: impl AsRef<str>, style: &str) -> String {
        let text = text.as_ref();
        if self.0 && !style.is_empty() {
            format!("\x1b[{style}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

pub(super) fn color_enabled() -> bool {
    io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb")
}

fn counter_style(label: &str, value: u64) -> &'static str {
    if value == 0 {
        return MUTED;
    }
    match label {
        "Timeout records" | "Timed out" | "Failed sessions" | "Errors" | "Invalid"
        | "Dropped events" | "Unknown-drop files" | "Truncated files" | "Corrupt files"
        | "Seq conflicts" | "Orphan outcomes" | "Outcome conflicts" => ERROR,
        "Duplicate" | "Late" | "Late unique" | "Reordered" | "Limited" | "Send skipped"
        | "Session skipped" | "No RTT sessions" | "Canceled" | "Canceled sent"
        | "Unsent canceled" | "Unresolved" => WARNING,
        _ => "",
    }
}

fn number(value: f64, width: usize) -> String {
    for precision in (0..=6).rev() {
        let text = format!("{value:.precision$}");
        if text.len() <= width && (value == 0.0 || text.parse::<f64>().unwrap() != 0.0) {
            return text;
        }
    }
    for precision in (0..=3).rev() {
        let text = format!("{value:.precision$e}");
        if text.len() <= width {
            return text;
        }
    }
    unreachable!("report numeric columns hold an f64 exponent")
}

fn count(value: u128, _width: usize) -> String {
    value.to_string()
}

fn row(
    out: &mut impl Write,
    cells: &[String],
    widths: &[usize],
    palette: Palette,
    styles: &[&str],
) -> io::Result<()> {
    write!(out, "| ")?;
    for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if index != 0 {
            write!(out, " | ")?;
        }
        let padded = if index == 0 {
            format!("{cell:<width$}")
        } else {
            format!("{cell:>width$}")
        };
        write!(
            out,
            "{}",
            palette.paint(padded, styles.get(index).copied().unwrap_or(""))
        )?;
    }
    writeln!(out, " |")
}

fn separator(out: &mut impl Write, widths: &[usize]) -> io::Result<()> {
    writeln!(
        out,
        "+{}+",
        widths
            .iter()
            .map(|width| "-".repeat(*width + 2))
            .collect::<Vec<_>>()
            .join("+")
    )
}

fn header(
    out: &mut impl Write,
    cells: &[&str],
    widths: &[usize],
    palette: Palette,
) -> io::Result<()> {
    separator(out, widths)?;
    row(
        out,
        &cells
            .iter()
            .map(|cell| cell.to_string())
            .collect::<Vec<_>>(),
        widths,
        palette,
        &vec![HEADING; cells.len()],
    )?;
    separator(out, widths)
}

fn latency(
    out: &mut impl Write,
    name: &str,
    samples: &Samples,
    jitter: bool,
    widths: &[usize],
    palette: Palette,
) -> io::Result<()> {
    let mut cells = vec![name.into(), count(samples.count as u128, 6)];
    let values = if samples.count == 0 {
        [None; 7]
    } else {
        [
            (!jitter).then_some(samples.min as f64),
            Some(samples.mean),
            (!jitter).then_some(samples.max as f64),
            (!jitter).then(|| samples.mdev()),
            (!jitter).then(|| samples.quantile(0.50) as f64),
            Some(samples.quantile(0.95) as f64),
            Some(samples.quantile(0.99) as f64),
        ]
    };
    cells.extend(
        values.map(|value| value.map_or_else(|| "-".into(), |value| number(value / 1e6, 7))),
    );
    let mut styles = [""; 9];
    styles[0] = KEY;
    for index in 1..cells.len() {
        styles[index] = if cells[index] == "-" {
            MUTED
        } else if [3, 4, 8].contains(&index) {
            KEY
        } else {
            ""
        };
    }
    row(out, &cells, widths, palette, &styles)
}

fn group(index: usize) -> Group {
    Group {
        run: 0,
        tcp: index / 2 != 0,
        server: !index.is_multiple_of(2),
    }
}

fn rate_reason(status: &str) -> &str {
    match status {
        "incomplete_logs" => "incomplete logs",
        "inconsistent_outcomes" => "conflicting outcomes",
        "unresolved_requests" => "pending outcomes",
        "no_eligible_sent" => "no eligible sends",
        _ => status,
    }
}

fn terminal_width() -> usize {
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    // ioctl initializes winsize on success; stdout determines the report layout.
    if unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, size.as_mut_ptr()) } == 0 {
        let columns = unsafe { size.assume_init() }.ws_col;
        if columns != 0 {
            return usize::from(columns);
        }
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|width| *width > 0)
        .unwrap_or(120)
}

fn details(
    out: &mut impl Write,
    total: &Aggregate,
    server: bool,
    available_width: usize,
    palette: Palette,
) -> io::Result<()> {
    let c = |kind| total.counts[kind as usize];
    let t = &total.timeouts;
    let q = &total.quality;
    let events = vec![
        ("Sent", c(Kind::Sent)),
        ("Reply", c(Kind::Response)),
        ("Timeout records", c(Kind::Timeout)),
        ("Canceled", c(Kind::Canceled)),
        ("Duplicate", c(Kind::Duplicate)),
        ("Late", c(Kind::Late)),
        ("Reordered", c(Kind::Reordered)),
        ("Invalid", c(Kind::Invalid)),
        ("Server requests", c(Kind::ServerRequest)),
        ("Server responses", c(Kind::ServerResponse)),
    ];
    let scheduling = vec![
        ("Limited", c(Kind::Limited)),
        ("Send skipped", c(Kind::Skipped)),
        ("Session skipped", c(Kind::SessionSkipped)),
        ("Failed sessions", c(Kind::Failed)),
        ("Errors", c(Kind::Error)),
        ("No RTT sessions", total.no_response),
        ("Open", c(Kind::Open)),
        ("Ready", c(Kind::Ready)),
        ("Closed", c(Kind::Closed)),
    ];
    let outcomes = if server {
        Vec::new()
    } else {
        vec![
            ("Unique sent", t.sent),
            ("TO denominator", t.denominator()),
            ("Timed out", t.timed_out),
            ("Late unique", t.late),
            ("Canceled sent", t.canceled),
            ("Unsent canceled", t.unsent_canceled),
            ("Unresolved", t.unresolved),
            ("Orphan outcomes", t.orphaned),
            ("Outcome conflicts", t.conflicting),
        ]
    };
    let logs = vec![
        ("Files", q.files),
        ("Events", total.events),
        ("Dropped events", q.dropped),
        ("Unknown-drop files", q.unknown),
        ("Truncated files", q.truncated),
        ("Corrupt files", q.corrupt),
        ("Seq conflicts", total.conflicts),
    ];
    let counters = [events, scheduling, outcomes, logs];
    let styles = counters.each_ref().map(|column| {
        column
            .iter()
            .map(|(label, value)| counter_style(label, *value))
            .collect::<Vec<_>>()
    });
    let columns = counters.map(|column| {
        column
            .into_iter()
            .map(|(label, value)| format!("{label:<20} {value:>12}"))
            .collect::<Vec<_>>()
    });
    let titles = [
        "Event counts",
        "Sessions / scheduling",
        if server {
            "Outcomes: NA (server)"
        } else {
            "Timeout accounting"
        },
        "Recording quality",
    ];
    let widths: Vec<_> = columns
        .iter()
        .zip(titles)
        .map(|(column, title)| {
            column
                .iter()
                .map(String::len)
                .chain([title.len(), 36])
                .max()
                .unwrap()
        })
        .collect();
    let side_by_side = widths.iter().sum::<usize>() + 18 <= available_width;
    let mut blocks = [Vec::new(), Vec::new()];
    for (block, pair) in blocks.iter_mut().zip([0..2, 2..4]) {
        separator(block, &widths[pair.clone()])?;
        let rows = if side_by_side {
            &columns[..]
        } else {
            &columns[pair.clone()]
        };
        for index in 0..=rows.iter().map(Vec::len).max().unwrap_or(0) {
            write!(block, "| ")?;
            for col in pair.clone() {
                if col != pair.start {
                    write!(block, " | ")?;
                }
                let cell = if index == 0 {
                    titles[col]
                } else {
                    columns[col].get(index - 1).map_or("", String::as_str)
                };
                let style = if index == 0 {
                    HEADING
                } else {
                    styles[col].get(index - 1).copied().unwrap_or("")
                };
                write!(
                    block,
                    "{}",
                    palette.paint(format!("{cell:<width$}", width = widths[col]), style)
                )?;
            }
            writeln!(block, " |")?;
            if index == 0 {
                separator(block, &widths[pair.clone()])?;
            }
        }
        separator(block, &widths[pair])?;
    }
    if side_by_side {
        let [left, right] =
            blocks.map(|block| String::from_utf8(block).expect("UTF-8 report table"));
        writeln!(out)?;
        for (left, right) in left.lines().zip(right.lines()) {
            writeln!(out, "{left}    {right}")?;
        }
    } else {
        for block in blocks {
            writeln!(out)?;
            out.write_all(&block)?;
        }
    }
    Ok(())
}

// Keep every metric visible; large counts and mixed groups may exceed one screen.
pub(super) fn write(
    report: &Report,
    dir: &Path,
    out: &mut impl Write,
    color: bool,
) -> io::Result<()> {
    let palette = Palette(color);
    let available_width = terminal_width();
    writeln!(
        out,
        "{} | files={} bad-headers={} | latency ms | HDR ~0.1%",
        palette.paint("flowgen", HEADING),
        count(report.files as u128, 6),
        palette.paint(
            count(report.bad_headers as u128, 6),
            if report.bad_headers > 0 { ERROR } else { MUTED }
        )
    )?;
    writeln!(out)?;
    let mut summary_widths = [10, 8, 10, 10, 8, 7, 10];
    let mut latency_widths = [10, 6, 7, 7, 7, 7, 7, 7, 7];
    for (index, total) in report.totals.iter().enumerate() {
        if total.quality.files == 0 {
            continue;
        }
        let server = group(index).server;
        for (column, value) in [
            (1, total.sessions),
            (
                2,
                total.counts[if server {
                    Kind::ServerRequest
                } else {
                    Kind::Sent
                } as usize],
            ),
            (
                3,
                total.counts[if server {
                    Kind::ServerResponse
                } else {
                    Kind::Response
                } as usize],
            ),
            (4, if server { 0 } else { total.timeouts.timed_out }),
        ] {
            summary_widths[column] = summary_widths[column].max(value.to_string().len());
        }
        if !server {
            for samples in [
                &total.rtt,
                &total.session_means,
                &total.setup,
                &total.jitter,
            ] {
                latency_widths[1] = latency_widths[1].max(samples.count.to_string().len());
            }
        }
    }
    header(
        out,
        &["Group", "Sessions", "Req", "Resp", "Timeout", "TO%", "Logs"],
        &summary_widths,
        palette,
    )?;
    let mut reasons = Vec::new();
    let mut clients = false;
    for (index, total) in report.totals.iter().enumerate() {
        if total.quality.files == 0 {
            continue;
        }
        let key = group(index);
        let protocol = key.protocol().to_uppercase();
        let incomplete = total
            .quality
            .incomplete(report.bad_headers, total.conflicts);
        let t = &total.timeouts;
        let status = t.status(key.server, total.quality.incomplete(report.bad_headers, 0));
        let rate = if key.server {
            "-".into()
        } else if status == "available" {
            number(100.0 * t.timed_out as f64 / t.denominator() as f64, 7)
        } else {
            reasons.push(format!("{protocol}: {}", rate_reason(status)));
            "NA".into()
        };
        clients |= !key.server;
        row(
            out,
            &[
                format!("{protocol}/{}", key.role()),
                count(total.sessions as u128, 8),
                count(
                    total.counts[if key.server {
                        Kind::ServerRequest
                    } else {
                        Kind::Sent
                    } as usize] as u128,
                    10,
                ),
                count(
                    total.counts[if key.server {
                        Kind::ServerResponse
                    } else {
                        Kind::Response
                    } as usize] as u128,
                    10,
                ),
                if key.server {
                    "-".into()
                } else {
                    count(t.timed_out as u128, 8)
                },
                rate,
                if incomplete { "INCOMPLETE" } else { "COMPLETE" }.into(),
            ],
            &summary_widths,
            palette,
            &[
                KEY,
                KEY,
                "",
                "",
                if t.timed_out > 0 && !key.server {
                    ERROR
                } else {
                    ""
                },
                if status == "available" && t.timed_out > 0 {
                    ERROR
                } else if !key.server && status != "available" {
                    WARNING
                } else {
                    ""
                },
                if incomplete { ERROR } else { GOOD },
            ],
        )?;
    }
    separator(out, &summary_widths)?;
    if clients {
        writeln!(out)?;
        header(
            out,
            &[
                "Metric(ms)",
                "N",
                "Min",
                "Avg",
                "Max",
                "Mdev",
                "P50",
                "P95",
                "P99",
            ],
            &latency_widths,
            palette,
        )?;
        for index in [0, 2] {
            let total = &report.totals[index];
            if total.quality.files == 0 {
                continue;
            }
            let protocol = group(index).protocol().to_uppercase();
            for (label, samples, jitter) in [
                ("RTT", &total.rtt, false),
                ("Mean", &total.session_means, false),
                ("Setup", &total.setup, false),
                ("Jitter", &total.jitter, true),
            ] {
                latency(
                    out,
                    &format!("{protocol}/{label}"),
                    samples,
                    jitter,
                    &latency_widths,
                    palette,
                )?;
            }
        }
        separator(out, &latency_widths)?;
    } else {
        writeln!(out, "Latency: NA (no client recordings)")?;
    }
    for (index, total) in report.totals.iter().enumerate() {
        if total.quality.files == 0 {
            continue;
        }
        let key = group(index);
        writeln!(
            out,
            "\n{}",
            palette.paint(
                format!(
                    "--- {}/{} details ---",
                    key.protocol().to_uppercase(),
                    key.role()
                ),
                HEADING
            )
        )?;
        details(out, total, key.server, available_width, palette)?;
    }
    if !reasons.is_empty() {
        writeln!(
            out,
            "{}",
            palette.paint(format!("TO% NA: {}", reasons.join("; ")), WARNING)
        )?;
    }
    if !report.worst.is_empty() {
        writeln!(
            out,
            "\n{}",
            palette.paint(
                "Slowest sessions: group / run / flow / mean RTT(ms) / samples / logs",
                HEADING
            )
        )?;
    }
    for worst in &report.worst {
        writeln!(
            out,
            "{}/{} run={} flow={} avg={}ms N={} {}",
            worst.group.protocol().to_uppercase(),
            worst.group.role(),
            worst.group.run,
            worst.flow,
            palette.paint(number(worst.mean / 1e6, 9), KEY),
            worst.samples,
            palette.paint(
                if worst.incomplete {
                    "INCOMPLETE"
                } else {
                    "COMPLETE"
                },
                if worst.incomplete { ERROR } else { GOOD }
            )
        )?;
    }
    if report.totals[..2]
        .iter()
        .any(|total| total.quality.files != 0)
    {
        let f = &report.forward;
        let rate = if f.available_runs == 0 || f.counts.sent == 0 {
            "NA".to_string()
        } else {
            format!(
                "{}%",
                number(
                    100.0 * (f.counts.sent - f.counts.matched) as f64 / f.counts.sent as f64,
                    9
                )
            )
        };
        let rate = palette.paint(
            &rate,
            if rate == "NA" {
                WARNING
            } else if f.counts.sent > f.counts.matched {
                ERROR
            } else {
                GOOD
            },
        );
        writeln!(out, "\nUDP delivery: {rate} missing | sent={} delivered={} missing={} | runs={} unavailable={}",
            f.counts.sent, f.counts.matched, f.counts.sent - f.counts.matched,
            f.available_runs, f.unavailable_runs)?;
        writeln!(
            out,
            "Delivery uses reconciled runs only; requires complete paired logs and final counts."
        )?;
    }
    writeln!(
        out,
        "\nMean=session mean; TO%=request timeout, not path loss. Latency rounded; counts exact."
    )?;
    writeln!(out, "CSV: {}", dir.display().to_string().escape_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::Worst;

    fn report() -> Report {
        Report {
            files: 1,
            bad_headers: 0,
            totals: Default::default(),
            worst: Vec::new(),
            forward: Default::default(),
        }
    }

    #[test]
    fn mixed_groups_preserve_large_counts_and_full_paths() {
        let mut report = report();
        report.bad_headers = u64::MAX;
        for total in &mut report.totals {
            total.quality.files = 1;
            total.sessions = u64::MAX;
            total.counts.fill(u64::MAX);
            total.timeouts.sent = u64::MAX;
            for samples in [
                &mut total.rtt,
                &mut total.session_means,
                &mut total.setup,
                &mut total.jitter,
            ] {
                samples.add(u64::MAX).unwrap();
            }
        }
        report.worst.push(Worst {
            group: Group {
                run: u64::MAX,
                tcp: true,
                server: false,
            },
            flow: u64::MAX,
            mean: u64::MAX as f64,
            samples: u64::MAX,
            incomplete: true,
        });
        let mut out = Vec::new();
        write(
            &report,
            Path::new(&"directory/".repeat(30)),
            &mut out,
            false,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(&"directory/".repeat(30)));
        assert!(out.contains(&format!("N={}", u64::MAX)));
        let normalized = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized.contains(&format!("Invalid {}", u64::MAX)));
        assert!(!out.contains('\x1b'));
        assert!(out.contains("INCOMPLETE") && out.contains("Canceled"));
        for label in [
            "UDP/client",
            "UDP/server",
            "TCP/client",
            "TCP/server",
            "UDP/Jitter",
            "TCP/Jitter",
        ] {
            assert!(out.contains(label));
        }
    }

    #[test]
    fn details_keep_each_counter_and_all_three_worst_sessions() {
        let mut report = report();
        let total = &mut report.totals[0];
        total.quality.files = 1;
        for (index, count) in total.counts.iter_mut().enumerate() {
            *count = 100 + index as u64;
        }
        total.timeouts.sent = 1000;
        total.timeouts.canceled = 201;
        total.timeouts.unsent_canceled = 202;
        total.timeouts.timed_out = 203;
        total.timeouts.late = 204;
        total.timeouts.unresolved = 205;
        total.timeouts.orphaned = 206;
        total.timeouts.conflicting = 207;
        total.quality.dropped = 301;
        total.quality.unknown = 302;
        total.quality.truncated = 303;
        total.quality.corrupt = 304;
        total.conflicts = 305;
        total.events = 306;
        total.no_response = 307;
        for flow in 1..=3 {
            report.worst.push(Worst {
                group: group(0),
                flow,
                mean: 1e6,
                samples: 400 + flow,
                incomplete: flow == 3,
            });
        }
        report.forward.available_runs = 4;
        report.forward.unavailable_runs = 5;
        report.forward.counts.sent = 900;
        report.forward.counts.matched = 899;
        let mut out = Vec::new();
        write(&report, Path::new("results/test"), &mut out, false).unwrap();
        let out = String::from_utf8(out).unwrap();
        for expected in [
            "Sent=102",
            "Reply=103",
            "Timeout records=104",
            "Canceled=105",
            "Duplicate=110",
            "Late=111",
            "Reordered=115",
            "Invalid=112",
            "Limited=113",
            "Send skipped=114",
            "Session skipped=116",
            "Failed sessions=107",
            "Errors=117",
            "Server requests=108",
            "Server responses=109",
            "Unique sent=1000",
            "TO denominator=799",
            "Timed out=203",
            "Late unique=204",
            "Canceled sent=201",
            "Unsent canceled=202",
            "Unresolved=205",
            "Orphan outcomes=206",
            "Outcome conflicts=207",
            "Files=1",
            "Dropped events=301",
            "Unknown-drop files=302",
            "Truncated files=303",
            "Corrupt files=304",
            "Seq conflicts=305",
            "Events=306",
            "No RTT sessions=307",
            "Open=100",
            "Ready=101",
            "Closed=106",
            "sent=900 delivered=899 missing=1",
            "runs=4 unavailable=5",
        ] {
            let normalized = out
                .replace('=', " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            assert!(
                normalized.contains(&expected.replace('=', " ")),
                "missing {expected}: {out}"
            );
        }
        for flow in 1..=3 {
            let line = out
                .lines()
                .find(|line| line.contains(&format!("flow={flow} ")))
                .unwrap();
            assert!(line.contains(&format!("N={}", 400 + flow)));
            assert!(line.ends_with(if flow == 3 { "INCOMPLETE" } else { "COMPLETE" }));
        }
    }

    #[test]
    fn detail_tables_use_available_width_without_losing_cells() {
        let mut total = Aggregate::default();
        total.quality.files = 1;
        total.timeouts.sent = 91;
        for (index, value) in total.counts.iter_mut().enumerate() {
            *value = index as u64 + 10;
        }
        let render = |total: &Aggregate, width| {
            let mut out = Vec::new();
            details(&mut out, total, false, width, Palette(false)).unwrap();
            String::from_utf8(out).unwrap()
        };
        let narrow = render(&total, 161);
        let wide = render(&total, 162);
        assert!(!narrow.contains("|    |"));
        assert!(wide.contains("|    |"));
        assert!(wide
            .lines()
            .any(|line| line.contains("Event counts") && line.contains("Timeout accounting")));
        assert!(wide
            .lines()
            .all(|line| line.is_empty() || line.len() == 162));
        assert!(wide.lines().count() < narrow.lines().count());
        let cells = |text: &str| {
            let mut cells: Vec<_> = text
                .lines()
                .filter(|line| line.starts_with('|'))
                .flat_map(|line| line.split('|'))
                .map(str::trim)
                .filter(|cell| !cell.is_empty())
                .map(str::to_owned)
                .collect();
            cells.sort();
            cells
        };
        assert_eq!(cells(&narrow), cells(&wide));
        total.counts.fill(u64::MAX);
        let large = render(&total, 162);
        assert!(!large.contains("|    |"));
        assert!(large.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn color_preserves_report_content_and_table_alignment() {
        let mut report = report();
        let total = &mut report.totals[0];
        total.quality.files = 1;
        total.quality.corrupt = 1;
        total.timeouts.sent = 10;
        total.timeouts.timed_out = 2;
        total.counts[Kind::Timeout as usize] = 2;
        total.counts[Kind::Late as usize] = 1;
        total.rtt.add(1_000_000).unwrap();
        let strip = |text: &str| {
            text.split('\x1b')
                .map(|chunk| {
                    chunk
                        .strip_prefix('[')
                        .and_then(|value| value.split_once('m'))
                        .map_or(chunk, |(_, rest)| rest)
                })
                .collect::<String>()
        };
        for width in [120, 180] {
            let mut plain = Vec::new();
            let mut colored = Vec::new();
            details(&mut plain, total, false, width, Palette(false)).unwrap();
            details(&mut colored, total, false, width, Palette(true)).unwrap();
            let plain = String::from_utf8(plain).unwrap();
            let colored = String::from_utf8(colored).unwrap();
            assert_eq!(strip(&colored), plain);
            assert!(colored.contains("\x1b[1;36mEvent counts"));
            assert!(colored.contains("\x1b[1;31mTimeout records"));
            assert!(colored.contains("\x1b[1;33mLate"));
            assert!(colored.contains("\x1b[2mLimited"));
        }
        let mut plain = Vec::new();
        let mut colored = Vec::new();
        write(&report, Path::new("results/test"), &mut plain, false).unwrap();
        write(&report, Path::new("results/test"), &mut colored, true).unwrap();
        let plain = String::from_utf8(plain).unwrap();
        let colored = String::from_utf8(colored).unwrap();
        assert_eq!(strip(&colored), plain);
        assert!(!plain.contains('\x1b'));
        assert!(colored.contains("\x1b[1;31mINCOMPLETE"));
        let rtt = colored
            .lines()
            .find(|line| line.contains("UDP/RTT"))
            .unwrap();
        for column in [4, 5, 9] {
            assert!(rtt.split('|').nth(column).unwrap().contains("\x1b[1m"));
        }
    }

    #[test]
    fn incomplete_logs_never_display_zero_latency_or_a_valid_timeout_rate() {
        let mut report = report();
        let client = &mut report.totals[0];
        client.quality.files = 1;
        client.quality.truncated = 1;
        client.timeouts.sent = 10;
        client.timeouts.timed_out = 2;
        let mut out = Vec::new();
        write(&report, Path::new("results/test"), &mut out, false).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.lines().any(|line| line.starts_with("| UDP/client")
            && line.contains("INCOMPLETE")
            && line.contains("NA")));
        assert!(!out.contains("20.0000"));
        let rtt = out
            .lines()
            .find(|line| line.starts_with("| UDP/RTT"))
            .unwrap();
        assert_eq!(
            rtt.split_whitespace().filter(|cell| *cell == "-").count(),
            7
        );
        assert!(out.contains("TO% NA: UDP: incomplete logs"));
    }

    #[test]
    fn small_nonzero_values_and_large_counts_are_not_displayed_as_zero() {
        for width in 5..=10 {
            for value in [0.000000001, 0.000001, 0.1, 123.456789, u64::MAX as f64] {
                let text = number(value, width);
                assert!(text.len() <= width);
                assert!(text.parse::<f64>().unwrap() > 0.0);
            }
        }
        assert_eq!(count(12345, 5), "12345");
    }
}
