use crate::{detail::State, kernel::MapRow, App};
use anyhow::{bail, Context, Result};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};
use std::{
    ffi::c_void,
    time::{Duration, Instant},
};

const SLOT_LIMIT: u32 = 16384;
const ENTRY_LIMIT: usize = 256;

unsafe extern "C" {
    fn bpfmap_xsk_open(data: *const u8, len: usize, id: u32, limit: u32) -> *mut c_void;
    fn bpfmap_xsk_read(reader: *mut c_void, out: *mut Record, capacity: usize) -> i32;
    fn bpfmap_count_close(reader: *mut c_void);
    fn bpfmap_count_map_ids(reader: *mut c_void, ids: *mut u32, capacity: usize) -> usize;
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Record {
    kind: u32,
    key: u32,
    ifindex: u32,
    netns: u32,
    queue: u32,
    state: u32,
    mode: u32,
    flags: u32,
    iface: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub key: u32,
    pub iface: String,
    pub ifindex: u32,
    pub netns: u32,
    pub queue: Option<u32>,
    pub state: u32,
    pub mode: u32,
    pub read_error: bool,
}

impl Entry {
    pub fn state_label(&self) -> String {
        match self.state {
            0 => "Ready".into(),
            1 => "Bound".into(),
            2 => "Unbound".into(),
            u32::MAX => "-".into(),
            other => format!("State{other}"),
        }
    }

    pub fn mode_label(&self) -> &'static str {
        match self.mode {
            1 => "Copy",
            2 => "Zero-copy",
            _ => "-",
        }
    }
}

pub struct Snapshot {
    pub entries: Vec<Entry>,
    pub scanned: u32,
    pub capacity: u32,
    pub read_errors: u32,
    pub more: bool,
    pub partial: bool,
    pub measured: Instant,
    pub duration: Duration,
}

fn decode(id: u32, records: &[Record], duration: Duration) -> Result<Snapshot> {
    let Some(summary) = records
        .last()
        .filter(|record| record.kind == 0 && record.state == id)
    else {
        bail!("Map disappeared or no XSKMAP coverage record was returned");
    };
    if summary.flags & 1 != 0 {
        bail!("XSKMAP socket fields unavailable for this map/kernel");
    }
    if summary.key > summary.ifindex
        || summary.key > SLOT_LIMIT
        || summary.queue as usize != records.len() - 1
    {
        bail!("Invalid XSKMAP coverage record");
    }
    let mut entries = Vec::new();
    for record in &records[..records.len() - 1] {
        if record.kind != 1
            || record.key >= summary.ifindex
            || entries
                .last()
                .is_some_and(|entry: &Entry| entry.key >= record.key)
        {
            bail!("Invalid XSKMAP socket record");
        }
        let end = record
            .iface
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(record.iface.len());
        let iface = String::from_utf8_lossy(&record.iface[..end])
            .chars()
            .map(|ch| if ch.is_control() { '?' } else { ch })
            .collect::<String>();
        entries.push(Entry {
            key: record.key,
            iface: if iface.is_empty() { "-".into() } else { iface },
            ifindex: record.ifindex,
            netns: record.netns,
            queue: (record.queue != u32::MAX).then_some(record.queue),
            state: record.state,
            mode: record.mode,
            read_error: record.flags != 0,
        });
    }
    Ok(Snapshot {
        entries,
        scanned: summary.key,
        capacity: summary.ifindex,
        read_errors: summary.netns,
        more: summary.flags & 4 != 0,
        partial: summary.flags & 2 != 0 || summary.netns != 0,
        measured: Instant::now(),
        duration,
    })
}

pub struct Reader {
    ptr: *mut c_void,
    pub id: u32,
    pub limit: usize,
}

impl Reader {
    pub fn open(id: u32, limit: usize) -> Result<Self> {
        if !(1..=ENTRY_LIMIT).contains(&limit) {
            bail!("XSKMAP entry limit must be 1..256");
        }
        let object = include_bytes!(concat!(env!("OUT_DIR"), "/count.bpf.o"));
        let ptr = unsafe { bpfmap_xsk_open(object.as_ptr(), object.len(), id, limit as u32) };
        if ptr.is_null() {
            bail!("XSKMAP iterator unavailable: requires kernel BTF, AF_XDP fields and BPF privileges (r retries)");
        }
        Ok(Self { ptr, id, limit })
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut records = vec![Record::default(); self.limit + 1];
        let start = Instant::now();
        let n = unsafe { bpfmap_xsk_read(self.ptr, records.as_mut_ptr(), records.len()) };
        if n < 0 {
            return Err(std::io::Error::from_raw_os_error(-n)).context("read XSKMAP sockets");
        }
        decode(self.id, &records[..n as usize], start.elapsed())
    }

    pub fn internal_maps(&self) -> Vec<u32> {
        let mut ids = [0; 16];
        let n = unsafe { bpfmap_count_map_ids(self.ptr, ids.as_mut_ptr(), ids.len()) };
        ids[..n].to_vec()
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        unsafe { bpfmap_count_close(self.ptr) };
    }
}

fn number(value: u32) -> String {
    if value == 0 {
        "-".into()
    } else {
        value.to_string()
    }
}

pub fn draw_entries(
    frame: &mut ratatui::Frame,
    area: Rect,
    app: &App,
    row: &MapRow,
    state: &State,
    selected: usize,
) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);
    crate::draw_header(
        frame,
        parts[0],
        app,
        &format!("MAP #{} / XSK sockets", row.info.id),
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(row.info.name.clone(), crate::style(app, true)),
            Line::raw(format!(
                "XSKMAP | COUNT {} / {} | interval {:.1}s",
                app.count(&row.info).label(),
                row.info.max_entries,
                app.interval.as_secs_f64()
            )),
        ]),
        parts[1],
    );
    let status = if let Some(snapshot) = &state.xsk {
        format!(
            "Scanned {}/{} | errors {} | {:.2} ms | age {:.1}s\n{}",
            snapshot.scanned,
            snapshot.capacity,
            snapshot.read_errors,
            snapshot.duration.as_secs_f64() * 1000.0,
            snapshot.measured.elapsed().as_secs_f64(),
            if snapshot.partial {
                "Partial coverage; unread fields/slots are unknown."
            } else {
                "Read-only observation; concurrent changes are not atomic."
            }
        )
    } else {
        state
            .xsk_error
            .clone()
            .unwrap_or_else(|| "Loading socket bindings in background...".into())
    };
    frame.render_widget(
        Paragraph::new(status)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title("Coverage")),
        parts[2],
    );
    let wide = area.width >= 100;
    let mut widths = vec![
        Constraint::Length(7),
        Constraint::Min(10),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(10),
    ];
    let mut headers = vec!["KEY", "IFACE", "QUEUE", "MODE", "STATE"];
    if wide {
        widths.extend([Constraint::Length(8), Constraint::Length(11)]);
        headers.extend(["IFINDEX", "NETNS"]);
    }
    let entries = state
        .xsk
        .as_ref()
        .map_or(&[][..], |snapshot| snapshot.entries.as_slice());
    let height = usize::from(parts[3].height.saturating_sub(3));
    let rows = crate::visible_range(selected, entries.len(), height)
        .map(|index| {
            let entry = &entries[index];
            let mut cells = vec![
                Cell::from(format!(
                    "{}{}",
                    entry.key,
                    if entry.read_error { " !" } else { "" }
                )),
                Cell::from(crate::clipped(
                    &entry.iface,
                    usize::from(area.width.saturating_sub(if wide { 68 } else { 47 })),
                )),
                Cell::from(
                    entry
                        .queue
                        .map_or_else(|| "-".into(), |queue| queue.to_string()),
                ),
                Cell::from(entry.mode_label()),
                Cell::from(entry.state_label()),
            ];
            if wide {
                cells.extend([
                    Cell::from(number(entry.ifindex)),
                    Cell::from(number(entry.netns)),
                ]);
            }
            let style = if index == selected {
                crate::selected_style(app)
            } else if entry.read_error {
                crate::style(app, true)
            } else {
                Default::default()
            };
            Row::new(cells).style(style)
        })
        .collect::<Vec<_>>();
    let title = state.xsk.as_ref().map_or_else(
        || "Sockets unavailable".into(),
        |snapshot| {
            format!(
                "Preview {} sockets{}{}",
                entries.len(),
                if snapshot.more { " (more exist)" } else { "" },
                if snapshot.partial { " (partial)" } else { "" }
            )
        },
    );
    frame.render_widget(
        Table::new(rows, widths)
            .header(Row::new(headers).style(crate::style(app, true)))
            .block(Block::default().borders(Borders::ALL).title(title)),
        parts[3],
    );
    let selected_text = entries.get(selected).map_or_else(
        || {
            if state.xsk.is_some() {
                "No occupied sockets observed within the scanned slots.".into()
            } else {
                "Socket bindings unavailable; Tab opens map information.".into()
            }
        },
        |entry| {
            format!(
                "Key {} | ifindex {} | netns {}{}",
                entry.key,
                number(entry.ifindex),
                number(entry.netns),
                if entry.read_error {
                    " | ! incomplete"
                } else {
                    ""
                }
            )
        },
    );
    frame.render_widget(
        Paragraph::new(selected_text)
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Selected socket"),
            ),
        parts[4],
    );
    crate::draw_footer(
        frame,
        parts[5],
        app.message
            .as_deref()
            .unwrap_or("Tab info | Enter expand | j/k move | Esc maps | r refresh | q quit"),
    );
}

pub fn draw_entry(frame: &mut ratatui::Frame, area: Rect, app: &App, row: &MapRow, state: &State) {
    let key = state
        .entry_key
        .as_deref()
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_ne_bytes);
    let entry = state
        .xsk
        .as_ref()
        .and_then(|snapshot| snapshot.entries.iter().find(|entry| Some(entry.key) == key));
    let lines = if let Some(entry) = entry {
        vec![
            Line::styled("SOCKET BINDING", crate::style(app, true)),
            Line::raw(format!(
                "Map key    | {} (slot index; not necessarily the queue ID)",
                entry.key
            )),
            Line::raw(format!(
                "Interface  | {} (ifindex {})",
                entry.iface,
                number(entry.ifindex)
            )),
            Line::raw(format!(
                "Netns      | {} (device namespace)",
                number(entry.netns)
            )),
            Line::raw(format!(
                "Queue      | {}",
                entry
                    .queue
                    .map_or_else(|| "-".into(), |queue| queue.to_string())
            )),
            Line::raw(format!("State      | {}", entry.state_label())),
            Line::raw(format!("Mode       | {}", entry.mode_label())),
            Line::default(),
            Line::raw(if entry.read_error {
                "Some socket fields could not be read; ! means incomplete."
            } else {
                "Read from this map's socket reference using CO-RE."
            }),
            Line::raw("Binding fields are an observation, not an atomic snapshot."),
            Line::raw("Use xsktop for socket ring configuration and activity."),
        ]
    } else {
        vec![Line::raw(state.xsk_error.clone().unwrap_or_else(|| "Selected key is not in the current socket preview; it may have been removed or lie beyond the preview limit. No stale binding is shown.".into()))]
    };
    crate::detail::draw_page(frame, area, app, row, state, "Entry", lines);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        detail::Page,
        tests::{test_app, test_map},
    };
    use libbpf_rs::MapType;
    use ratatui::{backend::TestBackend, style::Color, Terminal};

    fn fixture() -> Vec<Record> {
        let mut row = Record {
            kind: 1,
            key: 7,
            ifindex: 5,
            netns: 4026531840,
            queue: 0,
            state: 1,
            mode: 2,
            ..Default::default()
        };
        row.iface[..4].copy_from_slice(b"eth0");
        vec![
            row,
            Record {
                key: 128,
                ifindex: 128,
                queue: 1,
                state: 42,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn map_key_is_independent_of_queue_and_unknown_is_not_zero() {
        assert_eq!(std::mem::size_of::<Record>(), 48);
        let snapshot = decode(42, &fixture(), Duration::ZERO).unwrap();
        assert_eq!(
            (snapshot.entries[0].key, snapshot.entries[0].queue),
            (7, Some(0))
        );
        assert_eq!(snapshot.entries[0].mode_label(), "Zero-copy");
        let mut records = fixture();
        records[0] = Record {
            kind: 1,
            key: 7,
            queue: u32::MAX,
            state: 0,
            ..Default::default()
        };
        let snapshot = decode(42, &records, Duration::ZERO).unwrap();
        assert_eq!(snapshot.entries[0].queue, None);
        assert_eq!(snapshot.entries[0].iface, "-");
        assert_eq!(snapshot.entries[0].state_label(), "Ready");
        assert_eq!(snapshot.entries[0].mode_label(), "-");
    }

    #[test]
    fn unavailable_and_partial_are_not_empty_complete_maps() {
        assert!(decode(42, &[], Duration::ZERO).is_err());
        assert!(decode(43, &fixture(), Duration::ZERO).is_err());
        let mut records = fixture();
        records[1].flags = 1;
        assert!(decode(42, &records, Duration::ZERO).is_err());
        records[1].flags = 2;
        assert!(decode(42, &records, Duration::ZERO).unwrap().partial);
        records[1].flags = 4;
        assert!(decode(42, &records, Duration::ZERO).unwrap().more);
        records[1].flags = 0;
        records[1].netns = 1;
        assert!(decode(42, &records, Duration::ZERO).unwrap().partial);
    }

    #[test]
    fn layouts_show_real_bindings_without_color_and_missing_keys_drop_stale_values() {
        for (width, height) in [(60, 16), (80, 24), (160, 40)] {
            let app = test_app();
            let row = test_map(MapType::Xskmap);
            let mut state = State::empty(Page::Entries);
            state.xsk = Some(decode(42, &fixture(), Duration::ZERO).unwrap());
            state.entry_key = Some(7u32.to_ne_bytes().to_vec());
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| draw_entries(frame, frame.area(), &app, &row, &state, 0))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(text.contains("QUEUE"), "{text}");
            if height >= 24 {
                assert!(text.contains("eth0"));
                assert!(text.contains("Zero-copy"));
            }
            assert!(terminal
                .backend()
                .buffer()
                .content
                .iter()
                .all(|cell| cell.fg == Color::Reset));
            terminal
                .draw(|frame| draw_entry(frame, frame.area(), &app, &row, &state))
                .unwrap();
            assert!(format!("{:?}", terminal.backend().buffer()).contains("eth0"));
            state.xsk.as_mut().unwrap().entries.clear();
            terminal
                .draw(|frame| draw_entry(frame, frame.area(), &app, &row, &state))
                .unwrap();
            let text = format!("{:?}", terminal.backend().buffer());
            assert!(!text.contains("eth0"));
            assert!(text.contains("Selected key"));
        }
    }
}
