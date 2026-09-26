use super::{covered, opt, View};
use crate::{engine::Engine, options::Options};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};
use std::time::{SystemTime, UNIX_EPOCH};

impl View {
    pub(super) fn detail(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        let mut add = |key: &str, value: String| rows.push((key.to_owned(), value));
        if self.drill.is_some() {
            let Some(e) = self.selected_session() else {
                add("Connections", "No matching sessions".into());
                return rows;
            };
            add("Original", e.key.original.label());
            add(
                "NAT",
                e.reply
                    .as_ref()
                    .map(|_| e.tuple(true).label())
                    .unwrap_or_else(|| "N/A".into()),
            );
            add(
                "Reply",
                e.reply
                    .as_ref()
                    .map(|r| r.label())
                    .unwrap_or_else(|| "N/A".into()),
            );
            add("BW original", self.entry_bandwidth(e, 0));
            add("BW reply", self.entry_bandwidth(e, 1));
            add("Packets original", opt(e.packets[0]));
            add("Packets reply", opt(e.packets[1]));
            add("Bytes original", opt(e.bytes[0]));
            add("Bytes reply", opt(e.bytes[1]));
            add("State", e.state_label().into());
            add(
                "State observed",
                if self.offline_at.is_some() {
                    "N/A".into()
                } else {
                    format!("{:.1}s", e.state_since.elapsed().as_secs_f64())
                },
            );
            let age = e
                .start_ns
                .and_then(|start| {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .and_then(|now| now.as_nanos().checked_sub(start as u128))
                })
                .map(|age| format!("{:.1}s (kernel timestamp)", age as f64 / 1e9))
                .unwrap_or_else(|| format!("{:.1}s observed", e.seen.elapsed().as_secs_f64()));
            add(
                "Age",
                if self.offline_at.is_some() {
                    "N/A".into()
                } else {
                    age
                },
            );
            add(
                "Zone orig/reply",
                format!("{}/{}", e.key.zone, e.key.reply_zone),
            );
            add("ID", opt(e.id));
            add("Mark", e.mark_label());
            add("Sampled TTL", format!("{}s", opt(e.timeout)));
        } else {
            let Some(g) = self.groups.get(self.selected) else {
                add("Groups", "No matching groups".into());
                return rows;
            };
            add("BW original", self.bandwidth(g, 0));
            add("BW reply", self.bandwidth(g, 1));
            for (i, direction) in ["original", "reply"].iter().enumerate() {
                add(
                    &format!("Packets {direction}"),
                    covered(g.packets[i].to_string(), g.packets_accounted[i], g.sessions),
                );
                add(
                    &format!("Bytes {direction}"),
                    covered(g.bytes[i].to_string(), g.accounted[i], g.sessions),
                );
            }
            add("Sessions", g.sessions.to_string());
            add("NAT sessions", g.nat.to_string());
            add("New/s", self.rate(g.new));
            add("End/s", self.rate(g.end));
            add("Destination IPs", g.destinations.len().to_string());
            add("Proto-port pairs", g.destination_ports.len().to_string());
            add("Unreplied", g.unreplied.to_string());
            add("SYN", g.syn.to_string());
            add("SYN-aged", self.observed_count(g.old_syn));
            add("Unreplied-aged", self.observed_count(g.old_unreplied));
            add("Closing-aged", self.observed_count(g.old_closing));
            for (key, count) in &g.protocols {
                add(key, count.to_string());
            }
            for (key, count) in &g.states {
                add(key, count.to_string());
            }
            add("Flags", g.flags());
            for (i, direction) in ["orig", "reply"].iter().enumerate() {
                add(
                    &format!("BW cover {direction}"),
                    format!(
                        "{}/{}",
                        if self.bandwidth_valid {
                            g.bandwidth_accounted[i]
                        } else {
                            0
                        },
                        g.sessions
                    ),
                );
                add(
                    &format!("Pkt cover {direction}"),
                    format!("{}/{}", g.packets_accounted[i], g.sessions),
                );
                add(
                    &format!("Byte cover {direction}"),
                    format!("{}/{}", g.accounted[i], g.sessions),
                );
            }
        }
        rows
    }

    pub(super) fn properties(
        &self,
        f: &mut Frame,
        area: Rect,
        title: String,
        items: &[(String, String)],
        columns: usize,
        scroll: usize,
    ) {
        let count = items.len().div_ceil(columns).max(1);
        let width = area.width.saturating_sub(2 + columns as u16 - 1) / columns as u16;
        let label_width = (width / 2).min(16);
        let value_width = width.saturating_sub(label_width + 1).max(1);
        let mut widths = Vec::new();
        for column in 0..columns {
            if column > 0 {
                widths.push(Constraint::Length(1));
            }
            widths.extend([
                Constraint::Length(label_width),
                Constraint::Length(1),
                Constraint::Min(value_width),
            ]);
        }
        let rows = (scroll.min(count.saturating_sub(1))..count).map(|row| {
            let mut cells = Vec::new();
            let mut height = 1;
            for column in 0..columns {
                if column > 0 {
                    cells.push(Cell::from("|"));
                }
                if let Some((key, value)) = items.get(column * count + row) {
                    let lines = wrap(value, value_width as usize);
                    height = height.max(lines.len() as u16);
                    let warning = value == "N/A"
                        || value.starts_with("OFF")
                        || (key == "Flags" && value != "-");
                    let error = value == "STALE"
                        || ((key.starts_with('+') || key == "Gaps")
                            && value != "0"
                            && value != "N/A");
                    let style = self.color(if error {
                        Color::Red
                    } else if warning
                        || (key == "Occupancy"
                            && value
                                .trim_end_matches('%')
                                .parse::<f64>()
                                .is_ok_and(|n| n >= 80.0))
                    {
                        Color::Yellow
                    } else if key == "State" && value == "LIVE" {
                        Color::Green
                    } else {
                        Color::Reset
                    });
                    cells.extend([
                        Cell::from(key.clone())
                            .style(self.color(Color::Cyan).add_modifier(Modifier::BOLD)),
                        Cell::from(" "),
                        Cell::from(lines.join("\n")).style(style),
                    ]);
                } else {
                    cells.extend([Cell::from(""), Cell::from(""), Cell::from("")]);
                }
            }
            // Extend dividers through wrapped values.
            for column in 1..columns {
                cells[column * 4 - 1] = Cell::from(vec![Line::from("|"); height as usize]);
            }
            Row::new(cells).height(height)
        });
        f.render_widget(
            Table::new(rows, widths)
                .column_spacing(0)
                .block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
    }

    pub(super) fn status_panel(&self, f: &mut Frame, area: Rect, e: &Engine, o: &Options) {
        let h = &e.health;
        let occupancy = h
            .count
            .zip(h.max)
            .filter(|(_, max)| *max > 0)
            .map(|(n, max)| 100.0 * n as f64 / max as f64);
        let status = if e.offline_at.is_some() {
            "STATIC"
        } else if e.stale {
            "STALE"
        } else if e.collecting() {
            "SYNCING"
        } else {
            "LIVE"
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(
                " cttop | {} | {} ",
                h.namespace,
                if self.nat { "NAT" } else { "original" }
            ))
            .title(
                Line::from(Span::styled(
                    format!(" {status} "),
                    self.color(if e.stale { Color::Red } else { Color::Green })
                        .add_modifier(Modifier::BOLD),
                ))
                .right_aligned(),
            );
        let inner = block.inner(area);
        f.render_widget(block, area);
        let cols = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(inner);
        let header = |s: &str| {
            Line::from(Span::styled(
                s.to_owned(),
                self.color(Color::Cyan).add_modifier(Modifier::BOLD),
            ))
        };
        if e.offline_at.is_some() {
            let panels = [
                vec![
                    header("SNAPSHOT"),
                    Line::from(format!("{} connections", e.entries.len())),
                    Line::from("Read only"),
                ],
                vec![
                    header("SOURCE"),
                    Line::from(h.namespace.clone()),
                    Line::from("conntrack text"),
                ],
                vec![
                    header("COUNTERS"),
                    Line::from("Saved packets / bytes"),
                    Line::from("Rates / age N/A"),
                ],
            ];
            for (i, lines) in panels.into_iter().enumerate() {
                let panel = if i == 0 {
                    Block::default()
                } else {
                    Block::default().borders(Borders::LEFT)
                };
                f.render_widget(Paragraph::new(lines).block(panel), cols[i]);
            }
            return;
        }
        let capacity = vec![
            header("CAPACITY"),
            Line::from(vec![
                Span::styled(
                    opt(h.count),
                    self.color(Color::White).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" / {}", opt(h.max))),
            ]),
            Line::from(Span::styled(
                format!(
                    "Used {}",
                    occupancy
                        .map(|v| format!("{v:.2}%"))
                        .unwrap_or_else(|| "N/A".into())
                ),
                self.color(if occupancy.is_some_and(|v| v >= 80.0) {
                    Color::Yellow
                } else {
                    Color::Gray
                }),
            )),
            Line::from(format!("Cached {}", e.entries.len())),
        ];
        let delta = |label: &str, n: Option<u64>| {
            Span::styled(
                format!("{label} {}", opt(n)),
                self.color(if n.is_some_and(|n| n > 0) {
                    Color::Red
                } else {
                    Color::Gray
                }),
            )
        };
        let health = vec![
            header("KERNEL / CAPTURE"),
            Line::from(vec![
                delta("Drop", h.delta[1]),
                Span::raw("  "),
                delta("Fail", h.delta[0]),
            ]),
            Line::from(vec![
                delta("Early", h.delta[2]),
                Span::raw("  "),
                delta("Gaps", Some(e.lost)),
            ]),
        ];
        let accounting = match h.acct {
            Some(0) => "OFF (N/A)",
            Some(_) => "ON",
            None => "N/A",
        };
        let events = match h.events {
            Some(0) => "OFF".into(),
            Some(1) => "ON".into(),
            Some(2) => "AUTO".into(),
            _ => opt(h.events),
        };
        let counters = vec![
            header("ACCOUNTING"),
            Line::from(Span::styled(
                accounting,
                self.color(if h.acct == Some(0) {
                    Color::Yellow
                } else {
                    Color::Green
                })
                .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Events {events}")),
            Line::from(format!("BW sample {}s", o.refresh.as_secs_f64())),
        ];
        for (i, lines) in [capacity, health, counters].into_iter().enumerate() {
            let panel = if i == 0 {
                Block::default()
            } else {
                Block::default().borders(Borders::LEFT)
            };
            f.render_widget(Paragraph::new(lines).block(panel), cols[i]);
        }
    }

    fn pair(&self, key: &str, value: String, width: usize, highlight: bool) -> Line<'static> {
        let gap = width.saturating_sub(key.len() + value.len()).max(1);
        Line::from(vec![
            Span::styled(key.to_owned(), self.color(Color::Gray)),
            Span::raw(" ".repeat(gap)),
            Span::styled(
                value,
                if highlight {
                    self.color(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    self.color(Color::White)
                },
            ),
        ])
    }

    fn traffic_lines(&self, width: usize) -> Vec<Line<'static>> {
        let data = self.detail();
        let get = |key: &str| {
            data.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| "N/A".into())
        };
        let w = width.saturating_sub(10) / 2;
        let mut lines = vec![Line::from(Span::styled(
            format!("{:<10}{:>w$}{:>w$}", "Metric", "Original", "Reply"),
            self.color(Color::Gray),
        ))];
        for (label, orig, reply) in [
            ("Bandwidth", "BW original", "BW reply"),
            ("Packets", "Packets original", "Packets reply"),
            ("Bytes", "Bytes original", "Bytes reply"),
        ] {
            lines.push(Line::from(Span::styled(
                format!("{label:<10}{:>w$}{:>w$}", get(orig), get(reply)),
                self.color(Color::White)
                    .add_modifier(if label == "Bandwidth" {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
            )));
        }
        if self.drill.is_none() {
            lines.push(Line::default());
            for (label, prefix) in [
                ("BW cover", "BW cover"),
                ("Pkt cover", "Pkt cover"),
                ("Byte cover", "Byte cover"),
            ] {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{label:<10}{:>w$}{:>w$}",
                        get(&format!("{prefix} orig")),
                        get(&format!("{prefix} reply"))
                    ),
                    self.color(Color::Gray),
                )));
            }
            lines.push(Line::from(Span::styled(
                "* partial; N/A unavailable",
                self.color(Color::Gray),
            )));
        }
        lines
    }

    fn state_lines(&self, width: usize) -> Vec<Line<'static>> {
        let Some(g) = self.groups.get(self.selected) else {
            return Vec::new();
        };
        let mut lines = Vec::new();
        for (state, n) in &g.states {
            let count = n.to_string();
            let bar_width = width.saturating_sub(state.len() + count.len() + 2).min(12);
            let filled = if g.sessions == 0 {
                0
            } else {
                ((*n as u128 * bar_width as u128) / g.sessions as u128) as usize
            };
            let warning = state.starts_with("SYN") && g.old_syn > 0;
            let bar = format!("{}{}", "#".repeat(filled), ".".repeat(bar_width - filled));
            let gap = width
                .saturating_sub(state.len() + bar.len() + count.len() + 1)
                .max(1);
            lines.push(Line::from(vec![
                Span::raw(state.to_string()),
                Span::raw(" ".repeat(gap)),
                Span::styled(
                    bar,
                    self.color(if warning {
                        Color::Yellow
                    } else if *state == "TIME_WAIT" {
                        Color::DarkGray
                    } else {
                        Color::Cyan
                    }),
                ),
                Span::raw(format!(" {count}")),
            ]));
        }
        lines.push(Line::default());
        for (protocol, n) in &g.protocols {
            lines.push(self.pair(protocol, n.to_string(), width, false));
        }
        lines.push(self.pair("Dest IPs", g.destinations.len().to_string(), width, false));
        lines.push(self.pair(
            "Proto-port pairs",
            g.destination_ports.len().to_string(),
            width,
            false,
        ));
        lines.push(self.pair("NAT sessions", g.nat.to_string(), width, false));
        lines
    }

    fn signal_lines(&self, width: usize, o: &Options) -> Vec<Line<'static>> {
        let Some(g) = self.groups.get(self.selected) else {
            return Vec::new();
        };
        vec![
            self.pair(
                "SYN-aged",
                self.observed_count(g.old_syn),
                width,
                g.old_syn > 0,
            ),
            self.pair(
                "Unreplied-aged",
                self.observed_count(g.old_unreplied),
                width,
                g.old_unreplied > 0,
            ),
            self.pair(
                "Closing-aged",
                self.observed_count(g.old_closing),
                width,
                false,
            ),
            self.pair("New/s", self.rate(g.new), width, false),
            self.pair("End/s", self.rate(g.end), width, false),
            self.pair("Unreplied", g.unreplied.to_string(), width, false),
            self.pair("SYN", g.syn.to_string(), width, false),
            Line::from(Span::styled(
                if self.offline_at.is_some() {
                    "Observed age unavailable".into()
                } else {
                    format!("Observed >= {}s; hints only", o.warning.as_secs_f64())
                },
                self.color(Color::Gray),
            )),
            Line::from(Span::styled(
                "TIME_WAIT is not a fault",
                self.color(Color::Gray),
            )),
            self.pair("Flags", g.flags(), width, false),
        ]
    }

    fn observed_count(&self, count: u64) -> String {
        if self.offline_at.is_some() {
            "N/A".into()
        } else {
            count.to_string()
        }
    }

    fn connection_lines(&self, endpoints: bool) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        for (key, value) in self.detail() {
            let endpoint = matches!(key.as_str(), "Original" | "NAT" | "Reply");
            if endpoint != endpoints
                || key.starts_with("BW ")
                || key.starts_with("Packets ")
                || key.starts_with("Bytes ")
            {
                continue;
            }
            if endpoints {
                lines.push(Line::from(Span::styled(key, self.color(Color::Gray))));
                lines.push(Line::from(value));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(format!("{key}: "), self.color(Color::Gray)),
                    Span::raw(value),
                ]));
            }
        }
        lines
    }

    pub(super) fn details_panel(&self, f: &mut Frame, area: Rect, o: &Options) {
        let key = self
            .drill
            .as_deref()
            .or_else(|| self.groups.get(self.selected).map(|g| g.key.as_str()))
            .unwrap_or("-");
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Details | {key} | [ ] scroll "));
        let inner = block.inner(area);
        f.render_widget(block, area);
        let available = if self.drill.is_some() {
            !self.sessions.is_empty()
        } else {
            !self.groups.is_empty()
        };
        if !available {
            f.render_widget(Paragraph::new("No matching connections"), inner);
            return;
        }
        let wide = area.width >= 120;
        let cols = if wide {
            Layout::horizontal([
                Constraint::Percentage(40),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
            ])
            .split(inner)
            .to_vec()
        } else {
            vec![inner; 3]
        };
        let widths = cols
            .iter()
            .enumerate()
            .map(|(i, r)| r.width.saturating_sub(u16::from(wide && i > 0) + 1) as usize)
            .collect::<Vec<_>>();
        let sections = if self.drill.is_some() {
            vec![
                ("TRAFFIC", self.traffic_lines(widths[0])),
                ("ENDPOINTS", self.connection_lines(true)),
                ("STATE", self.connection_lines(false)),
            ]
        } else {
            vec![
                ("TRAFFIC", self.traffic_lines(widths[0])),
                ("STATES", self.state_lines(widths[1])),
                ("SIGNALS", self.signal_lines(widths[2], o)),
            ]
        };
        let heading = |title: &str| {
            Line::from(Span::styled(
                title.to_owned(),
                self.color(Color::Cyan).add_modifier(Modifier::BOLD),
            ))
        };
        if wide {
            for (i, (title, body)) in sections.into_iter().enumerate() {
                let panel = if i == 0 {
                    Block::default()
                } else {
                    Block::default().borders(Borders::LEFT)
                };
                let content = panel.inner(cols[i]);
                f.render_widget(panel, cols[i]);
                f.render_widget(
                    Paragraph::new(heading(title)),
                    Rect::new(content.x, content.y, content.width, 1),
                );
                self.detail_body(
                    f,
                    Rect::new(
                        content.x,
                        content.y + 1,
                        content.width,
                        content.height.saturating_sub(1),
                    ),
                    body,
                );
            }
        } else {
            let mut all = Vec::new();
            for (title, body) in sections {
                all.push(heading(title));
                all.extend(body);
                all.push(Line::default());
            }
            self.detail_body(f, inner, all);
        }
    }

    fn detail_body(&self, f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        let rows = paragraph.line_count(area.width);
        let scroll = (self.detail_scroll as usize).min(rows.saturating_sub(area.height as usize));
        f.render_widget(paragraph.scroll((scroll as u16, 0)), area);
    }

    pub(super) fn footer(&self, f: &mut Frame, area: Rect) {
        let key = |k: &str, label: &str| {
            [
                Span::styled(
                    k.to_owned(),
                    self.color(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(" {label}  ")),
            ]
        };
        let mut lines = if let Some((mode, text)) = &self.input {
            vec![
                Line::from(format!(
                    "{}: {text}_",
                    if *mode == 'g' {
                        "Group fields"
                    } else {
                        "Search"
                    }
                )),
                Line::from([key("Enter", "apply"), key("Esc", "cancel")].concat()),
            ]
        } else {
            let first = if area.width >= 120 {
                [
                    key("h", "help"),
                    key("0", "CT"),
                    key("1", "src"),
                    key("2", "service"),
                    key("3", "pair"),
                    key("4", "proto"),
                    key("5", "sport"),
                    key("6", "dport"),
                    key("7", "mark"),
                    key("g", "fields"),
                    key("n", "NAT"),
                    key("/", "search"),
                ]
                .concat()
            } else {
                [
                    key("h", "help"),
                    key("0", "CT"),
                    key("1-7", "group"),
                    key("g", "fields"),
                    key("n", "NAT"),
                    key("/", "search"),
                ]
                .concat()
            };
            vec![
                Line::from(first),
                Line::from(
                    [
                        key("Enter", "drill"),
                        key("Esc", "up"),
                        key("s", "sort"),
                        key("j/k", "move"),
                        key("[]", "details"),
                        key("q", "quit"),
                    ]
                    .concat(),
                ),
            ]
        };
        if self.input.is_none() && !self.note.is_empty() {
            lines[0] = Line::from(Span::styled(
                self.note.clone(),
                self.color(Color::Red).add_modifier(Modifier::BOLD),
            ));
        }
        f.render_widget(Paragraph::new(lines), area);
    }

    pub(super) fn help_panel(&self, f: &mut Frame, e: &Engine) {
        let items = [
            ("0 / 1 / 2 / 3", "Toggle CT/group view / group by source IP / target service / address pair"),
            ("4 / 5 / 6 / 7", "Group by protocol / source port / destination port / conntrack mark"),
            ("g", "Enter none or combine src,sport,dst,dport,proto,zone,mark; Ctrl+U clears"),
            ("Enter", "Enter selected group; 1-7 or g regroups only inside that scope"),
            ("Esc", "Return one level; cancel input; at root clear search"),
            ("n", "Toggle original/NAT view; ancestor filters keep their direction"),
            ("/", "Search group labels, or CT tuples, states and hexadecimal marks in individual view"),
            ("s", "Group sort: sessions / new / unreplied / aged; CT order: tuple, zone, ID"),
            ("Arrows / j,k", "Select row; in help scroll"),
            ("PgUp / PgDn", "Page through rows or help"),
            ("Home / End", "First / last row"),
            ("[ / ]", "Scroll Details up / down"),
            ("h / Esc", "Close help; monitoring continues while help is open"),
            ("q / Ctrl+C", "Quit and restore terminal"),
            ("Bandwidth", "Original/reply bit/s, averaged over full snapshots (-r, default 5s)"),
            ("Packets / bytes", "Cumulative counters of current connections; deleted flows excluded"),
            ("N/A / *", "Missing data / partial coverage; bandwidth needs two valid samples"),
            ("Accounting OFF", "Counters unavailable for connections without accounting; cttop never changes sysctls"),
            ("New/s / End/s", "Observed creation/deletion rates; deletion does not mean successful close"),
            ("Aged / UNREPLIED", "Observed-age hints, not confirmed faults; one-way UDP can be legitimate"),
            ("Collector", e.message.as_str()),
        ].map(|(k,v)| (k.to_owned(), v.to_owned()));
        self.properties(
            f,
            f.area(),
            " Help | h/Esc close | j/k or PgUp/PgDn scroll ".into(),
            &items,
            1,
            self.help_scroll as usize,
        );
    }
}

fn wrap(value: &str, width: usize) -> Vec<String> {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.is_empty() {
        return vec![String::new()];
    }
    chars
        .chunks(width.max(1))
        .map(|chunk| chunk.iter().collect())
        .collect()
}
