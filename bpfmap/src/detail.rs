use crate::{
    counts::Source,
    kernel::{self, Btf, Configuration, MapMeta, MapRow, Preview, ProgramReferences},
    App, Detail,
};
use libbpf_rs::MapHandle;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::{cell::Cell, fmt::Write, time::Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Entries,
    Info,
    Entry,
    Program,
}

pub struct State {
    pub page: Page,
    pub scroll: usize,
    pub max_scroll: Cell<usize>,
    pub entry_key: Option<Vec<u8>>,
    pub configuration: Option<Configuration>,
    pub configuration_error: Option<String>,
    pub references: Option<ProgramReferences>,
    pub references_pending: bool,
    pub last_configuration: Instant,
    pub xsk: Option<crate::xsk::Snapshot>,
    pub xsk_error: Option<String>,
    pub xsk_pending: bool,
    pub xsk_retry: bool,
    pub targets: Option<crate::refs::Snapshot>,
    pub targets_pending: bool,
    pub program_id: Option<u32>,
    pub program_pending: bool,
    pub program_lines: Option<Vec<Line<'static>>>,
}

impl State {
    pub fn new(map: &MapHandle, info: &MapMeta, btf: Option<&Btf>) -> Self {
        let mut state = Self::empty(
            if kernel::previewable(info.ty)
                || info.ty == libbpf_rs::MapType::Xskmap
                || crate::refs::supported(info.ty)
            {
                Page::Entries
            } else {
                Page::Info
            },
        );
        state.refresh_configuration(map, btf);
        state.xsk_pending = info.ty == libbpf_rs::MapType::Xskmap;
        state.targets_pending = crate::refs::supported(info.ty);
        state
    }

    pub fn empty(page: Page) -> Self {
        Self {
            page,
            scroll: 0,
            max_scroll: Cell::new(0),
            entry_key: None,
            configuration: None,
            configuration_error: None,
            references: None,
            references_pending: true,
            last_configuration: Instant::now(),
            xsk: None,
            xsk_error: None,
            xsk_pending: false,
            xsk_retry: false,
            targets: None,
            targets_pending: false,
            program_id: None,
            program_pending: false,
            program_lines: None,
        }
    }

    pub fn refresh_configuration(&mut self, map: &MapHandle, btf: Option<&Btf>) {
        match kernel::configuration(map, btf) {
            Ok(configuration) => {
                self.configuration = Some(configuration);
                self.configuration_error = None;
            }
            Err(error) => {
                self.configuration = None;
                self.configuration_error = Some(error.to_string());
            }
        }
        self.last_configuration = Instant::now();
    }
}

pub fn flag_names(flags: u32) -> String {
    use libbpf_rs::libbpf_sys::*;
    let mut remaining = flags;
    let mut names = Vec::new();
    for (bit, name) in [
        (BPF_F_NO_PREALLOC, "NO_PREALLOC"),
        (BPF_F_NO_COMMON_LRU, "NO_COMMON_LRU"),
        (BPF_F_NUMA_NODE, "NUMA_NODE"),
        (BPF_F_RDONLY, "RDONLY"),
        (BPF_F_WRONLY, "WRONLY"),
        (BPF_F_STACK_BUILD_ID, "STACK_BUILD_ID"),
        (BPF_F_ZERO_SEED, "ZERO_SEED"),
        (BPF_F_RDONLY_PROG, "RDONLY_PROG"),
        (BPF_F_WRONLY_PROG, "WRONLY_PROG"),
        (BPF_F_CLONE, "CLONE"),
        (BPF_F_MMAPABLE, "MMAPABLE"),
        (BPF_F_PRESERVE_ELEMS, "PRESERVE_ELEMS"),
        (BPF_F_INNER_MAP, "INNER_MAP"),
        (BPF_F_LINK, "LINK"),
    ] {
        if remaining & bit != 0 {
            names.push(name.into());
            remaining &= !bit;
        }
    }
    if remaining != 0 {
        names.push(format!("unknown {remaining:#x}"));
    }
    if names.is_empty() {
        "none".into()
    } else {
        names.join(" | ")
    }
}

fn section(lines: &mut Vec<Line<'static>>, app: &App, title: &str) {
    if !lines.is_empty() {
        lines.push(Line::default());
    }
    lines.push(Line::styled(title.to_owned(), crate::style(app, true)));
}

fn field(lines: &mut Vec<Line<'static>>, label: &str, value: impl Into<String>) {
    let value = value.into();
    for (index, line) in value.lines().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<14} | ", if index == 0 { label } else { "" }),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(line.to_owned()),
        ]));
    }
    if value.is_empty() {
        lines.push(Line::raw(format!("{label:<14} | -")));
    }
}

fn type_label(id: u32, name: Option<&String>) -> String {
    if id == 0 {
        "-".into()
    } else {
        format!(
            "ID {id} ({})",
            name.map_or("name unavailable", String::as_str)
        )
    }
}

fn info_lines(app: &App, row: &MapRow, state: &State) -> Vec<Line<'static>> {
    let info = &row.info;
    let count = app.count(info);
    let mut lines = Vec::new();
    section(&mut lines, app, "CONFIGURATION");
    field(&mut lines, "Full name", info.name.clone());
    field(&mut lines, "Kernel name", info.kernel_name.clone());
    field(
        &mut lines,
        "Name source",
        if info.name == info.kernel_name {
            "kernel"
        } else {
            "unique BTF declaration"
        },
    );
    field(
        &mut lines,
        "Key / value",
        format!("{} B / {} B", info.key_size, info.value_size),
    );
    if let Some(config) = &state.configuration {
        field(
            &mut lines,
            "Flags",
            format!("{:#x} ({})", config.flags, flag_names(config.flags)),
        );
        field(
            &mut lines,
            "Frozen",
            match config.frozen {
                Some(true) => "yes",
                Some(false) => "no",
                None => "-",
            },
        );
        field(
            &mut lines,
            "Memlock",
            config.memlock.map_or_else(
                || "-".into(),
                |bytes| {
                    format!("{bytes} B (kernel-reported allocation, not used-entry bytes or RSS)")
                },
            ),
        );
        if let Some(cpus) = config.cpus {
            field(
                &mut lines,
                "CPU copies",
                format!("{cpus} possible CPUs; capacity counts keys, not copies"),
            );
        }
        field(&mut lines, "Map extra", format!("{:#x}", config.extra));
        if config.ifindex != 0 || config.netns_ino != 0 {
            field(
                &mut lines,
                "Offload",
                format!(
                    "ifindex {} | netns {}:{}",
                    config.ifindex, config.netns_dev, config.netns_ino
                ),
            );
        }
        if let Some(error) = &config.fdinfo_error {
            field(&mut lines, "FD info", error.clone());
        }
    } else {
        field(
            &mut lines,
            "Config status",
            state
                .configuration_error
                .clone()
                .unwrap_or_else(|| "unavailable".into()),
        );
    }

    section(&mut lines, app, "COUNT & CAPACITY");
    field(
        &mut lines,
        "Current / max",
        format!("{} / {}", count.label(), crate::capacity(info)),
    );
    if let Some(value) = count.value.filter(|_| {
        matches!(
            count.source,
            Source::Kernel | Source::Occupied | Source::Bytes | Source::Scan
        )
    }) {
        if info.max_entries > 0 {
            field(
                &mut lines,
                "Occupancy",
                format!(
                    "{:.2}% (observation, not an atomic snapshot)",
                    value as f64 * 100.0 / f64::from(info.max_entries)
                ),
            );
        }
    }
    field(&mut lines, "Measurement", count.description());
    if !matches!(count.source, Source::Slots | Source::Unknown) {
        field(
            &mut lines,
            "Read duration",
            format!(
                "{:.3} ms ({})",
                count.duration.as_secs_f64() * 1000.0,
                if matches!(count.source, Source::Scan | Source::PartialScan) {
                    "this key scan"
                } else {
                    "whole map inventory"
                }
            ),
        );
    }
    field(
        &mut lines,
        "Meaning",
        app.count_error
            .as_deref()
            .filter(|_| count.value.is_none())
            .unwrap_or(&count.note)
            .to_owned(),
    );

    section(&mut lines, app, "BTF & PINS");
    field(
        &mut lines,
        "BTF object",
        if info.btf_id == 0 {
            "-".into()
        } else {
            info.btf_id.to_string()
        },
    );
    field(
        &mut lines,
        "Key type",
        type_label(
            info.btf_key_type_id,
            state
                .configuration
                .as_ref()
                .and_then(|config| config.key_type.as_ref()),
        ),
    );
    field(
        &mut lines,
        "Value type",
        type_label(
            info.btf_value_type_id,
            state
                .configuration
                .as_ref()
                .and_then(|config| config.value_type.as_ref()),
        ),
    );
    if row.pins.is_empty() {
        field(
            &mut lines,
            "Pin paths",
            "none found in visible bpffs; not proof of being unpinned",
        );
    } else {
        for pin in &row.pins {
            field(&mut lines, "Pin path", pin.clone());
        }
    }
    if app.inventory.pins_truncated {
        field(
            &mut lines,
            "Pin coverage",
            "partial (scan limit or inaccessible nodes)",
        );
    }

    section(&mut lines, app, "REFERENCING PROGRAMS");
    if let Some(references) = &state.references {
        field(
            &mut lines,
            "Coverage",
            format!(
                "{} matched / {} inspected | {} inaccessible | {} | {:.1}s ago",
                references.programs.len(),
                references.inspected,
                references.inaccessible,
                if references.partial {
                    "partial"
                } else {
                    "completed"
                },
                references.measured.elapsed().as_secs_f64()
            ),
        );
        if let Some(error) = &references.error {
            field(&mut lines, "Query error", error.clone());
        }
        if references.programs.is_empty() {
            lines.push(Line::raw(if references.partial {
                "No references found within available coverage."
            } else {
                "No loaded program references observed at collection time."
            }));
        } else {
            lines.push(Line::styled(
                "ID      NAME             TYPE                 UID",
                crate::style(app, true),
            ));
            for program in &references.programs {
                lines.push(Line::raw(format!(
                    "{:<7} {:<16} {:<20} {}",
                    program.id,
                    program.name,
                    format!("{:?}", program.ty),
                    program.uid
                )));
            }
        }
        lines.push(Line::raw(
            "Loaded program references; this is not an attachment or process-owner list.",
        ));
    } else {
        lines.push(Line::raw("Loading program references in background..."));
    }
    if info.ty == libbpf_rs::MapType::Xskmap {
        section(&mut lines, app, "XSKMAP");
        lines.push(Line::raw("Entries shows map keys and actual socket interface/queue bindings via a read-only CO-RE iterator. Keys need not equal queue IDs; COUNT is occupied slots. Use xsktop for socket rings and activity."));
    }
    lines
}

fn dump_bytes(lines: &mut Vec<Line<'static>>, bytes: &[u8]) {
    if bytes.is_empty() {
        lines.push(Line::raw("(empty)"));
    }
    for (index, chunk) in bytes.chunks(16).enumerate() {
        let mut row = format!("{:04x}  ", index * 16);
        for byte in chunk {
            let _ = write!(row, "{byte:02x} ");
        }
        lines.push(Line::raw(row));
    }
}

fn entry_lines(
    app: &App,
    info: &MapMeta,
    btf: Option<&Btf>,
    preview: Option<&Preview>,
    key: Option<&[u8]>,
    counter_mode: bool,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let selected = preview.and_then(|preview| {
        preview
            .entries
            .iter()
            .find(|entry| Some(entry.raw_key.as_slice()) == key)
    });
    let Some(entry) = selected else {
        lines.push(Line::raw(
            "Selected key is not present in the current bounded preview.",
        ));
        lines.push(Line::raw(
            "It may have been deleted or moved outside the preview; no stale value is shown.",
        ));
        return lines;
    };
    section(&mut lines, app, "KEY");
    field(&mut lines, "Display", entry.key.clone());
    if let Some(addresses) = btf.and_then(|btf| btf.key_addresses(&entry.raw_key)) {
        field(&mut lines, "IP address", addresses);
    }
    if btf.is_some() {
        section(&mut lines, app, "BTF KEY (MEMORY VALUES)");
    }
    lines.extend(
        btf.and_then(|btf| btf.expanded(info.btf_key_type_id, &entry.raw_key))
            .unwrap_or_else(|| entry.key.clone())
            .lines()
            .map(|line| Line::raw(line.to_owned())),
    );
    section(&mut lines, app, "RAW KEY (HEX BYTES)");
    dump_bytes(&mut lines, &entry.raw_key);
    field(&mut lines, "Delta", entry.delta.clone());
    let Some(raw) = preview.and_then(|preview| preview.baseline.get(&entry.raw_key)) else {
        lines.push(Line::raw("No captured raw value is available."));
        return lines;
    };
    if info.ty.is_percpu() {
        let size = info.value_size as usize;
        if btf.and_then(Btf::unsigned_size) == Some(size) {
            section(&mut lines, app, "PER-CPU DISTRIBUTION");
            let sample = preview.unwrap();
            lines.extend(crate::percpu::lines(
                raw,
                sample.previous.get(&entry.raw_key).map(Vec::as_slice),
                size,
                sample.cpu_ids.as_deref(),
                sample.elapsed,
                counter_mode,
                app.no_color,
            ));
            lines.push(Line::raw("v toggle counter interpretation / RATE/s"));
        }
        section(
            &mut lines,
            app,
            "VALUES PER CPU (POSSIBLE CPUS, INCLUDING ZERO VALUES)",
        );
        if size == 0 || raw.len() % size != 0 {
            lines.push(Line::raw("Captured per-CPU value layout is unavailable."));
            return lines;
        }
        lines.push(Line::raw(
            "Individual values; reads across CPUs are not an atomic snapshot.",
        ));
        let cpu_ids = preview
            .and_then(|preview| preview.cpu_ids.as_ref())
            .filter(|ids| ids.len() == raw.len() / size);
        for (index, value) in raw.chunks_exact(size).enumerate() {
            let decoded = btf
                .and_then(|btf| btf.expanded(info.btf_value_type_id, value))
                .unwrap_or_else(|| kernel::hex(value));
            let label = cpu_ids.map_or_else(
                || format!("Copy{index}"),
                |ids| format!("CPU{}", ids[index]),
            );
            field(&mut lines, &label, decoded);
            if let Some(addresses) =
                btf.and_then(|btf| btf.addresses(info.btf_value_type_id, value))
            {
                field(&mut lines, "IP address", addresses);
            }
            if value.len() <= 16 {
                field(&mut lines, "Raw", kernel::hex(value));
            } else {
                dump_bytes(&mut lines, value);
            }
        }
    } else {
        section(&mut lines, app, "VALUE");
        if let Some(addresses) = btf.and_then(|btf| btf.addresses(info.btf_value_type_id, raw)) {
            field(&mut lines, "IP address", addresses);
        }
        lines.extend(
            btf.and_then(|btf| btf.expanded(info.btf_value_type_id, raw))
                .unwrap_or_else(|| entry.value.clone())
                .lines()
                .map(|line| Line::raw(line.to_owned())),
        );
        section(&mut lines, app, "RAW VALUE (HEX BYTES)");
        dump_bytes(&mut lines, raw);
    }
    lines
}

pub(crate) fn draw_page(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    row: &MapRow,
    state: &State,
    title: &str,
    lines: Vec<Line<'static>>,
) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);
    crate::draw_header(
        frame,
        parts[0],
        app,
        &format!("MAP #{} / {title}", row.info.id),
    );
    let count = app.count(&row.info);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(row.info.name.clone(), crate::style(app, true)),
            Line::raw(format!(
                "{:?} | {} / {} | interval {:.1}s",
                row.info.ty,
                count.label(),
                crate::capacity(&row.info),
                app.interval.as_secs_f64()
            )),
        ])
        .wrap(Wrap { trim: false }),
        parts[1],
    );
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    let width = parts[2].width.saturating_sub(2);
    let height = parts[2].height.saturating_sub(2);
    let total = paragraph.line_count(width);
    let max_scroll = total.saturating_sub(height as usize).min(u16::MAX as usize);
    state.max_scroll.set(max_scroll);
    let scroll = state.scroll.min(max_scroll);
    let block = Block::default().borders(Borders::ALL).title(format!(
        "{title}  {}-{}/{}",
        scroll + 1,
        (scroll + height as usize).min(total),
        total
    ));
    frame.render_widget(paragraph.scroll((scroll as u16, 0)).block(block), parts[2]);
    let footer = if title == "Entry" && row.info.ty.is_percpu() {
        "v counter rate | j/k scroll | Esc entries | Tab info | h help | q quit"
    } else if title == "Entry" {
        "j/k scroll | PgUp/PgDn page | Esc entries | Tab info | h help | q quit"
    } else {
        "j/k scroll | PgUp/PgDn page | Tab entries | Esc maps | r refresh | q quit"
    };
    crate::draw_footer(frame, parts[3], app.message.as_deref().unwrap_or(footer));
}

pub fn draw_info(frame: &mut ratatui::Frame, area: Rect, app: &App, row: &MapRow, state: &State) {
    draw_page(
        frame,
        area,
        app,
        row,
        state,
        "Info",
        info_lines(app, row, state),
    );
}

pub fn draw_entry(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    row: &MapRow,
    detail: &Detail,
) {
    let lines = entry_lines(
        app,
        &row.info,
        detail.btf.as_ref(),
        detail.preview.as_ref(),
        detail.state.entry_key.as_deref(),
        detail.browse.counter_mode,
    );
    draw_page(frame, area, app, row, &detail.state, "Entry", lines);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        kernel::{Entry, ProgramReference},
        tests::{test_app, test_map},
    };
    use libbpf_rs::{libbpf_sys, MapType, ProgramType};
    use ratatui::{backend::TestBackend, style::Color, Terminal};
    use std::collections::HashMap;

    #[test]
    fn flags_preserve_unknown_bits_and_distinguish_program_access() {
        let flags = libbpf_sys::BPF_F_RDONLY_PROG | libbpf_sys::BPF_F_MMAPABLE | (1 << 31);
        let text = flag_names(flags);
        assert!(text.contains("RDONLY_PROG"));
        assert!(text.contains("MMAPABLE"));
        assert!(text.contains("0x80000000"));
        assert_eq!(flag_names(0), "none");
    }

    #[test]
    fn info_scroll_reaches_programs_at_narrow_and_wide_sizes_without_colors() {
        for (width, height) in [(60, 16), (80, 24), (160, 40)] {
            let app = test_app();
            let map = test_map(MapType::Xskmap);
            let mut state = State::empty(Page::Info);
            state.configuration = Some(Configuration {
                flags: libbpf_sys::BPF_F_RDONLY_PROG,
                memlock: Some(8192),
                frozen: Some(true),
                ..Configuration::default()
            });
            state.references = Some(ProgramReferences {
                programs: vec![ProgramReference {
                    id: 7,
                    name: "xdp_test".into(),
                    ty: ProgramType::Xdp,
                    uid: 1000,
                }],
                inspected: 3,
                inaccessible: 1,
                partial: true,
                error: None,
                measured: Instant::now(),
            });
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw_info(frame, frame.area(), &app, &map, &state))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(text.contains("test_map"));
            assert!(text.contains("CONFIGURATION"));
            state.scroll = state.max_scroll.get();
            terminal
                .draw(|frame| draw_info(frame, frame.area(), &app, &map, &state))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(text.contains("xsktop"), "{width}x{height}: {text}");
            if height >= 24 {
                assert!(text.contains("xdp_test"), "{text}");
            }
            assert!(terminal
                .backend()
                .buffer()
                .content
                .iter()
                .all(|cell| cell.fg == Color::Reset));
        }
    }

    #[test]
    fn missing_config_and_failed_reference_queries_are_not_empty_or_zero() {
        let app = test_app();
        let map = test_map(MapType::Hash);
        let mut state = State::empty(Page::Info);
        state.configuration_error = Some("map info denied".into());
        state.references = Some(ProgramReferences {
            programs: Vec::new(),
            inspected: 0,
            inaccessible: 1,
            partial: true,
            error: Some("query denied".into()),
            measured: Instant::now(),
        });
        let text = info_lines(&app, &map, &state)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("map info denied"));
        assert!(text.contains("query denied"));
        assert!(text.contains("available coverage"));
        assert!(text.contains("partial"));
        assert!(!text.contains("0 B"));
    }

    #[test]
    fn expanded_percpu_values_keep_zero_copies_and_follow_the_key() {
        let app = test_app();
        let map = test_map(MapType::PercpuArray);
        let key = 1_u32.to_ne_bytes().to_vec();
        let raw = [0_u64, 23, 99]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect::<Vec<_>>();
        let preview = Preview {
            cpu_ids: Some(vec![0, 2, 5]),
            entries: vec![
                Entry {
                    raw_key: 2_u32.to_ne_bytes().to_vec(),
                    key: "other".into(),
                    value: "wrong-value".into(),
                    delta: "=".into(),
                },
                Entry {
                    raw_key: key.clone(),
                    key: "selected".into(),
                    value: "sum=122".into(),
                    delta: "+122".into(),
                },
            ],
            truncated: false,
            read_errors: 0,
            baseline: HashMap::from([(key.clone(), raw)]),
            ..Preview::default()
        };
        let text = entry_lines(&app, &map.info, None, Some(&preview), Some(&key), false)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("selected"));
        assert!(text.contains("CPU0") && text.contains("CPU2") && text.contains("CPU5"));
        assert!(!text.contains("CPU1"));
        assert!(text.contains(&kernel::hex(&0_u64.to_ne_bytes())));
        assert!(text.contains(&kernel::hex(&23_u64.to_ne_bytes())));
        assert!(!text.contains("wrong-value"));
        let text = entry_lines(
            &app,
            &map.info,
            None,
            Some(&preview),
            Some(&[3, 0, 0, 0]),
            false,
        )
        .iter()
        .map(Line::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        assert!(text.contains("no stale value"));
        assert!(!text.contains("sum=122"));
    }

    #[test]
    fn expanded_raw_dump_contains_bytes_beyond_the_preview_limit() {
        let mut lines = Vec::new();
        let mut bytes = vec![0; 80];
        bytes[79] = 0xab;
        dump_bytes(&mut lines, &bytes);
        let text = lines
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("0040"));
        assert!(text.ends_with("ab "));
    }
}
