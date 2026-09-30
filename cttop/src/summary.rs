use crate::{
    engine::Engine,
    model::{protocol, Entry},
    options::Options,
};
use std::{
    collections::{BTreeMap, HashMap},
    io::{self, IsTerminal, Write},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Default)]
struct Totals {
    sessions: usize,
    nat: usize,
    unreplied: usize,
    syn: usize,
    closing: usize,
    packets: [u128; 2],
    packet_coverage: [usize; 2],
    bytes: [u128; 2],
    byte_coverage: [usize; 2],
    protocols: BTreeMap<String, usize>,
    tcp_states: BTreeMap<String, usize>,
}

impl Totals {
    fn add(&mut self, entry: &Entry) {
        self.sessions += 1;
        self.nat += usize::from(entry.is_nat());
        self.unreplied += usize::from(entry.unreplied());
        *self
            .protocols
            .entry(protocol(entry.key.original.proto))
            .or_default() += 1;
        if entry.key.original.proto == 6 {
            let state = entry.state_label();
            *self.tcp_states.entry(state.into()).or_default() += 1;
            self.syn += usize::from(matches!(entry.state, Some(1 | 2 | 9)));
            self.closing += usize::from(matches!(entry.state, Some(4..=8)));
        }
        for direction in 0..2 {
            if let Some(value) = entry.packets[direction] {
                self.packets[direction] += u128::from(value);
                self.packet_coverage[direction] += 1;
            }
            if let Some(value) = entry.bytes[direction] {
                self.bytes[direction] += u128::from(value);
                self.byte_coverage[direction] += 1;
            }
        }
    }
}

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

fn ranked(counts: impl IntoIterator<Item = (String, usize)>) -> Vec<(String, usize)> {
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

fn top(engine: &Engine, o: &Options, key: impl Fn(&Entry) -> String) -> Vec<(String, usize)> {
    let mut counts = HashMap::new();
    for entry in engine
        .entries
        .values()
        .filter(|entry| o.filter.matches(entry))
    {
        *counts.entry(key(entry)).or_insert(0) += 1;
    }
    let mut rows = ranked(counts);
    rows.truncate(5);
    rows
}

fn pad(text: &str, width: usize) -> String {
    format!(
        "{text}{}",
        " ".repeat(width.saturating_sub(UnicodeWidthStr::width(text)))
    )
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let indentation = text.chars().take_while(|ch| *ch == ' ').count().min(2);
    let mut remaining = text.to_string();
    while UnicodeWidthStr::width(remaining.as_str()) > width {
        let mut used = 0;
        let mut split = 0;
        let mut last_space = None;
        for (index, ch) in remaining.char_indices() {
            let size = ch.width().unwrap_or(0);
            if used + size > width {
                break;
            }
            used += size;
            split = index + ch.len_utf8();
            if ch == ' ' && index > 0 {
                last_space = Some(index);
            }
        }
        let split = last_space.unwrap_or(split);
        let (head, tail) = remaining.split_at(split);
        lines.push(head.trim_end().to_string());
        remaining = format!("{}{}", " ".repeat(indentation), tail.trim_start());
    }
    lines.push(remaining);
    lines
}

fn border(out: &mut impl Write, width: usize) -> io::Result<()> {
    writeln!(out, "+{}+", "-".repeat(width - 2))
}

fn full_line(out: &mut impl Write, text: &str, width: usize) -> io::Result<()> {
    for line in wrap(text, width - 2) {
        writeln!(out, "|{}|", pad(&line, width - 2))?;
    }
    Ok(())
}

fn split_line(out: &mut impl Write, left: &str, right: &str, width: usize) -> io::Result<()> {
    let left_width = (width - 3) / 2;
    let right_width = width - 3 - left_width;
    let left_lines = wrap(left, left_width);
    let right_lines = wrap(right, right_width);
    for index in 0..left_lines.len().max(right_lines.len()) {
        writeln!(
            out,
            "|{}|{}|",
            pad(left_lines.get(index).map_or("", String::as_str), left_width),
            pad(
                right_lines.get(index).map_or("", String::as_str),
                right_width
            )
        )?;
    }
    Ok(())
}

fn ranked_lines(title: &str, rows: &[(String, usize)], total: usize, width: usize) -> Vec<String> {
    let mut lines = vec![format!(" {title}")];
    if rows.is_empty() {
        lines.push(" -".into());
    }
    for (label, count) in rows {
        let end = format!("{count:>5} {:>6.1}%", percent(*count, total));
        let available = width.saturating_sub(3 + UnicodeWidthStr::width(end.as_str()));
        if UnicodeWidthStr::width(label.as_str()) <= available {
            lines.push(format!(
                " {label}{} {end} ",
                " ".repeat(available - UnicodeWidthStr::width(label.as_str()))
            ));
        } else {
            lines.push(format!(" {label}"));
            lines.push(format!(
                "{}{end}",
                " ".repeat(width.saturating_sub(UnicodeWidthStr::width(end.as_str())))
            ));
        }
    }
    lines
}

fn full_section(
    out: &mut impl Write,
    title: &str,
    rows: &[(String, usize)],
    total: usize,
    width: usize,
) -> io::Result<()> {
    for line in ranked_lines(title, rows, total, width - 2) {
        full_line(out, &line, width)?;
    }
    border(out, width)
}

fn metrics(
    out: &mut impl Write,
    width: usize,
    values: &[(&str, String, String); 4],
) -> io::Result<()> {
    let columns = if width >= 110 { 4 } else { 2 };
    let inside = width - 2;
    let cells = inside - (columns - 1);
    let base = cells / columns;
    for (group, chunk) in values.chunks(columns).enumerate() {
        if group > 0 {
            border(out, width)?;
        }
        for row in 0..3 {
            write!(out, "|")?;
            for (index, value) in chunk.iter().enumerate() {
                let cell_width = base + usize::from(index < cells % columns);
                let text = match row {
                    0 => value.0.to_string(),
                    1 => value.1.clone(),
                    _ => value.2.clone(),
                };
                write!(out, "{}|", pad(&format!(" {text}"), cell_width))?;
            }
            writeln!(out)?;
        }
    }
    Ok(())
}

fn counters(title: &str, values: [u128; 2], coverage: [usize; 2], total: usize) -> String {
    let display = |direction: usize| {
        if coverage[direction] == 0 {
            format!("N/A (0/{total})")
        } else {
            format!("{} ({}/{total})", values[direction], coverage[direction])
        }
    };
    format!("{title:<7} orig {} | reply {}", display(0), display(1))
}

pub fn write(engine: &Engine, o: &Options, out: &mut impl Write) -> io::Result<()> {
    let width = if io::stdout().is_terminal() {
        crossterm::terminal::size().map_or(80, |(columns, _)| usize::from(columns))
    } else {
        80
    };
    write_at_width(engine, o, width, out)
}

fn write_at_width(
    engine: &Engine,
    o: &Options,
    width: usize,
    out: &mut impl Write,
) -> io::Result<()> {
    let width = width.clamp(60, 160);
    let mut totals = Totals::default();
    for entry in engine
        .entries
        .values()
        .filter(|entry| o.filter.matches(entry))
    {
        totals.add(entry);
    }
    let protocols = ranked(totals.protocols);
    let states = ranked(totals.tcp_states);
    let sources = top(engine, o, |entry| entry.tuple(o.nat).src.to_string());
    let destinations = top(engine, o, |entry| entry.tuple(o.nat).dst.to_string());
    let services = top(engine, o, |entry| {
        let tuple = entry.tuple(o.nat);
        let destination = if tuple.dst.is_ipv6() {
            format!("[{}]", tuple.dst)
        } else {
            tuple.dst.to_string()
        };
        match tuple.dport {
            Some(port) => format!("{} {destination}:{port}", protocol(tuple.proto)),
            None => format!("{} {destination}", protocol(tuple.proto)),
        }
    });
    let marks = top(engine, o, Entry::mark_label);

    let mut attention = Vec::new();
    if let (Some(count), Some(max)) = (engine.health.count, engine.health.max) {
        if max > 0 && count.saturating_mul(100) >= max.saturating_mul(80) {
            attention.push("conntrack table occupancy >= 80%");
        }
    }
    if totals.sessions >= 100
        && sources
            .first()
            .is_some_and(|(_, count)| *count * 100 >= totals.sessions * 30)
    {
        attention.push("top source holds >= 30% of matched entries");
    }
    let tcp = states.iter().map(|(_, n)| *n).sum::<usize>();
    if tcp >= 100 && totals.syn * 100 >= tcp * 20 {
        attention.push("TCP SYN states >= 20% of TCP entries");
    }
    if totals.sessions >= 100 && totals.unreplied * 100 >= totals.sessions * 30 {
        attention.push("unreplied entries >= 30% (UDP can be normal)");
    }
    let attention: Vec<String> = if attention.is_empty() {
        vec!["No threshold flags".into()]
    } else {
        attention
            .into_iter()
            .map(|item| format!("Check: {item}"))
            .collect()
    };
    let scope = if engine.offline_at.is_some() {
        "STATIC"
    } else {
        "LIVE"
    };
    border(out, width)?;
    full_line(
        out,
        &format!(
            " cttop summary | {scope} | {} | {}",
            engine.health.namespace,
            if o.nat { "NAT" } else { "original" }
        ),
        width,
    )?;
    border(out, width)?;
    let tcp_count = protocols
        .iter()
        .find(|(name, _)| name == "tcp")
        .map_or(0, |(_, count)| *count);
    let udp_count = protocols
        .iter()
        .find(|(name, _)| name == "udp")
        .map_or(0, |(_, count)| *count);
    let capacity = match (engine.health.count, engine.health.max) {
        (Some(count), Some(max)) if max > 0 => {
            format!("{count}/{max} ({:.1}%)", count as f64 * 100.0 / max as f64)
        }
        _ => "capacity N/A".into(),
    };
    let closing_state = states
        .iter()
        .filter(|(state, _)| {
            matches!(
                state.as_str(),
                "FIN_WAIT" | "CLOSE_WAIT" | "LAST_ACK" | "TIME_WAIT" | "CLOSE"
            )
        })
        .max_by_key(|(_, count)| *count);
    let closing_detail = closing_state.map_or_else(
        || format!("no closing | SYN {}", totals.syn),
        |(state, count)| format!("{state} {count} | SYN {}", totals.syn),
    );
    let values = [
        (
            "ENTRIES",
            totals.sessions.to_string(),
            if engine.offline_at.is_some() {
                format!("{} in file", engine.entries.len())
            } else {
                capacity
            },
        ),
        (
            "TCP / UDP",
            format!("{tcp_count} / {udp_count}"),
            format!(
                "{:.1}% / {:.1}%",
                percent(tcp_count, totals.sessions),
                percent(udp_count, totals.sessions)
            ),
        ),
        ("TCP CLOSING", totals.closing.to_string(), closing_detail),
        (
            "UNREPLIED",
            totals.unreplied.to_string(),
            format!(
                "{:.1}% | NAT {}",
                percent(totals.unreplied, totals.sessions),
                totals.nat
            ),
        ),
    ];
    metrics(out, width, &values)?;
    border(out, width)?;
    if protocols.len() > 2 {
        let mix = protocols
            .iter()
            .map(|(name, count)| format!("{name} {count}"))
            .collect::<Vec<_>>()
            .join(" | ");
        full_line(out, &format!(" Protocols: {mix}"), width)?;
        border(out, width)?;
    }

    if width >= 110 {
        let left_width = (width - 3) / 2;
        let right_width = width - 3 - left_width;
        let mut left = ranked_lines("TOP SOURCES", &sources, totals.sessions, left_width);
        left.push("-".repeat(left_width));
        left.extend(ranked_lines(
            "TOP DESTINATIONS",
            &destinations,
            totals.sessions,
            left_width,
        ));
        let mut right = ranked_lines("TOP SERVICES", &services, totals.sessions, right_width);
        right.push("-".repeat(right_width));
        right.extend(ranked_lines("TCP STATES", &states, tcp, right_width));
        right.push("-".repeat(right_width));
        right.extend(ranked_lines(
            "TOP MARKS",
            &marks,
            totals.sessions,
            right_width,
        ));
        if engine.offline_at.is_none() {
            right.push("-".repeat(right_width));
            right.push(" KERNEL CUMULATIVE".into());
            let display = |n: Option<u64>| n.map_or_else(|| "N/A".into(), |n| n.to_string());
            right.push(format!(
                " insert_failed {} | drop {} | early_drop {}",
                display(engine.health.errors[0]),
                display(engine.health.errors[1]),
                display(engine.health.errors[2])
            ));
        }
        for index in 0..left.len().max(right.len()) {
            split_line(
                out,
                left.get(index).map_or("", String::as_str),
                right.get(index).map_or("", String::as_str),
                width,
            )?;
        }
        border(out, width)?;
        let accounting = [
            " ACCOUNTING / SAVED TOTALS".to_string(),
            format!(
                " {}",
                counters(
                    "packets",
                    totals.packets,
                    totals.packet_coverage,
                    totals.sessions
                )
            ),
            format!(
                " {}",
                counters("bytes", totals.bytes, totals.byte_coverage, totals.sessions)
            ),
        ];
        let mut notices = vec![" ATTENTION".to_string()];
        notices.extend(attention.iter().map(|item| format!(" {item}")));
        for index in 0..accounting.len().max(notices.len()) {
            split_line(
                out,
                accounting.get(index).map_or("", String::as_str),
                notices.get(index).map_or("", String::as_str),
                width,
            )?;
        }
        border(out, width)?;
    } else {
        full_section(out, "TOP SOURCES", &sources, totals.sessions, width)?;
        full_section(
            out,
            "TOP DESTINATIONS",
            &destinations,
            totals.sessions,
            width,
        )?;
        full_section(out, "TOP SERVICES", &services, totals.sessions, width)?;
        full_section(out, "TCP STATES", &states, tcp, width)?;
        full_section(out, "TOP MARKS", &marks, totals.sessions, width)?;
        if engine.offline_at.is_none() {
            let display = |n: Option<u64>| n.map_or_else(|| "N/A".into(), |n| n.to_string());
            full_line(out, " KERNEL CUMULATIVE", width)?;
            full_line(
                out,
                &format!(
                    " insert_failed {} | drop {} | early_drop {}",
                    display(engine.health.errors[0]),
                    display(engine.health.errors[1]),
                    display(engine.health.errors[2])
                ),
                width,
            )?;
            border(out, width)?;
        }
        full_line(out, " ACCOUNTING / SAVED TOTALS", width)?;
        full_line(
            out,
            &format!(
                " {}",
                counters(
                    "packets",
                    totals.packets,
                    totals.packet_coverage,
                    totals.sessions
                )
            ),
            width,
        )?;
        full_line(
            out,
            &format!(
                " {}",
                counters("bytes", totals.bytes, totals.byte_coverage, totals.sessions)
            ),
            width,
        )?;
        border(out, width)?;
        full_line(out, " ATTENTION", width)?;
        for item in &attention {
            full_line(out, &format!(" {item}"), width)?;
        }
        border(out, width)?;
    }
    full_line(
        out,
        " One snapshot is not a health verdict; bandwidth, lifecycle rate and observed state age are unavailable.",
        width,
    )?;
    border(out, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::fixture;
    use std::{collections::HashMap, time::Instant};

    #[test]
    fn reports_empty_snapshot_without_fake_counters() {
        let engine = Engine::offline(HashMap::new(), "empty.txt".into(), Instant::now());
        let mut output = Vec::new();
        write(&engine, &Options::default(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("0 in file"));
        assert!(text.contains("packets orig N/A (0/0) | reply N/A (0/0)"));
        assert!(!text.contains("KERNEL CUMULATIVE"));
    }

    #[test]
    fn filters_and_nat_view_change_top_dimensions_without_inventing_rates() {
        let mut first = fixture();
        first.mark = Some(16);
        first.reply.as_mut().unwrap().dst = "203.0.113.1".parse().unwrap();
        let mut second = fixture();
        second.key.original.src = "192.0.2.2".parse().unwrap();
        second.key.original.dport = Some(8443);
        second.packets = [None; 2];
        second.bytes = [None; 2];
        let entries = [first, second]
            .into_iter()
            .map(|e| (e.key.clone(), e))
            .collect();
        let engine = Engine::offline(entries, "sample.txt".into(), Instant::now());
        let mut o = Options::default();
        o.filter.src = Some("192.0.2.1".parse().unwrap());
        o.nat = true;
        let mut output = Vec::new();
        write(&engine, &o, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("2 in file"));
        assert!(text.contains("orig 10 (1/1) | reply 10 (1/1)"));
        assert!(text.contains("TOP SOURCES"));
        assert!(text.contains("203.0.113.1"));
        assert!(text.contains("TOP MARKS"));
        assert!(text.contains("0x10"));
        assert!(text.contains("is not a health verdict"));
        assert!(text.contains("observed"));
        assert!(text.contains("unavailable."));

        o.filter.src = None;
        o.nat = false;
        let mut output = Vec::new();
        write(&engine, &o, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.lines().all(|line| UnicodeWidthStr::width(line) == 80));
        assert!(text.contains("TOP DESTINATIONS"));
        assert!(text.contains("198.51.100.2"));
        assert!(text.contains("2  100.0%"));
        assert!(text.contains("tcp 198.51.100.2:443"));
        assert!(text.contains("tcp 198.51.100.2:8443"));

        let mut wide = Vec::new();
        write_at_width(&engine, &o, 120, &mut wide).unwrap();
        let wide = String::from_utf8(wide).unwrap();
        assert!(wide.lines().all(|line| UnicodeWidthStr::width(line) == 120));
        assert!(wide
            .lines()
            .any(|line| line.contains("TOP SOURCES") && line.contains("TOP SERVICES")));
    }

    #[test]
    fn threshold_flags_require_a_meaningful_population() {
        let entries = (0..100u16)
            .map(|index| {
                let mut entry = fixture();
                entry.key.original.sport = Some(index + 1000);
                entry.key.original.src = format!("192.0.2.{}", 1 + index.saturating_sub(39))
                    .parse()
                    .unwrap();
                entry.state = Some(if index < 25 { 1 } else { 3 });
                entry.status = Some(if index < 35 { 0 } else { 2 });
                (entry.key.clone(), entry)
            })
            .collect();
        let engine = Engine::offline(entries, "many.txt".into(), Instant::now());
        let mut output = Vec::new();
        write(&engine, &Options::default(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("top source holds >= 30%"));
        assert!(text.contains("TCP SYN states >= 20%"));
        assert!(text.contains("unreplied entries >= 30%"));
    }

    #[test]
    fn long_text_wraps_at_words_and_preserves_display_width() {
        let mut output = Vec::new();
        split_line(
            &mut output,
            " sources",
            " No threshold flags; a single snapshot is not a health verdict.",
            120,
        )
        .unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output
            .lines()
            .all(|line| UnicodeWidthStr::width(line) == 120));
        assert!(output.contains("health"));
        assert!(output.contains(" verdict."));
        assert!(!output.contains("verd|ict"));
    }

    #[test]
    fn unicode_snapshot_name_keeps_borders_aligned() {
        let engine = Engine::offline(
            HashMap::new(),
            "\u{4e2d}\u{6587}-snapshot.txt".into(),
            Instant::now(),
        );
        let mut output = Vec::new();
        write_at_width(&engine, &Options::default(), 80, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output
            .lines()
            .all(|line| UnicodeWidthStr::width(line) == 80));
    }
}
