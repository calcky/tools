use std::time::Duration;

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::monitor::socket_table::{
    InetSocketSnapshot, SocketDetailState, SocketMemoryDiagnostics, SocketProtocol,
    SocketTcpDiagnostics,
};

use super::app::DetailMetricsMode;
use super::{socket, theme};

mod layout;
mod traffic;

use layout::{DetailGroup, DetailLayout};
use traffic::push_traffic_matrix;

const LABEL_COLOR: Color = Color::Rgb(164, 173, 179);

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    detail: &SocketDetailState,
    metrics_mode: DetailMetricsMode,
    row_offset: usize,
) {
    if area.is_empty() {
        return;
    }
    let lines = detail_lines(detail, metrics_mode, area.width);
    let offset = row_offset.min(lines.len().saturating_sub(usize::from(area.height)));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(usize::from(area.height))
                .collect::<Vec<_>>(),
        ),
        area,
    );
}

pub(super) fn row_count(
    detail: &SocketDetailState,
    metrics_mode: DetailMetricsMode,
    width: u16,
) -> usize {
    let layout = DetailLayout::new(width);
    layout.row_count(&detail_groups(detail, metrics_mode, &layout))
}

fn detail_lines(
    detail: &SocketDetailState,
    metrics_mode: DetailMetricsMode,
    width: u16,
) -> Vec<Line<'static>> {
    let layout = DetailLayout::new(width);
    layout.compose(detail_groups(detail, metrics_mode, &layout))
}

fn detail_groups(
    detail: &SocketDetailState,
    metrics_mode: DetailMetricsMode,
    layout: &DetailLayout,
) -> Vec<DetailGroup> {
    let width = layout.full_inner_width();
    let socket = detail.socket();
    let mut groups = Vec::new();
    let mut lines = Vec::new();
    let observed_latest = detail.observed_latest();
    let status = if observed_latest {
        "OBSERVED"
    } else {
        "NOT OBSERVED / LAST STATE"
    };
    push_wrapped(
        &mut lines,
        &format!(
            "{}{} SOCKET DETAIL [{status}]  {}  OWNER {}",
            socket.protocol().label().to_uppercase(),
            socket.family().label(),
            socket.state(),
            format_owner(socket),
        ),
        width,
        Style::default()
            .fg(if observed_latest {
                theme::SOCKETS
            } else {
                theme::WARN
            })
            .add_modifier(Modifier::BOLD),
    );
    if !observed_latest {
        push_wrapped(
            &mut lines,
            " latest query did not contain this identity; it may have closed or the query may be incomplete",
            width,
            Style::default().fg(theme::WARN),
        );
    }
    push_metric(
        &mut lines,
        if observed_latest {
            "LOCAL / REMOTE"
        } else {
            "LAST ENDPOINTS"
        },
        Some(format!(
            "{} -> {}",
            socket::format_endpoint(socket.local()),
            socket::format_endpoint(socket.remote())
        )),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        if observed_latest {
            "SCOPE / OWNER"
        } else {
            "LAST SCOPE"
        },
        Some(format!(
            "{}; owner map {}",
            format_scope(socket, detail.key().is_stable()),
            detail.process_map_summary()
        )),
        width,
        metrics_mode,
    );
    groups.push(DetailGroup::take("IDENTITY", &mut lines));
    if !observed_latest {
        return groups;
    }

    let width = layout.column_inner_width();
    if socket.protocol() == SocketProtocol::Tcp && !socket.is_tcp_listener() {
        push_limit_basis(&mut lines, socket.tcp(), width);
        groups.push(DetailGroup::take("LIMIT BASIS", &mut lines));
    }

    if socket.is_tcp_listener() {
        push_metric(
            &mut lines,
            "ACCEPT QUEUE",
            Some(format!(
                "pending {}  limit {}",
                socket.receive_queue(),
                socket.send_queue()
            )),
            width,
            metrics_mode,
        );
    } else {
        push_traffic_matrix(&mut lines, socket, width, metrics_mode);
    }
    push_metric(
        &mut lines,
        "SOCKET DROPS",
        socket.drops().and_then(|total| {
            diagnostic_value(
                metrics_mode,
                total > 0 || socket.drops_per_second().is_some_and(|rate| rate > 0.0),
                || format_total_rate(total, socket.drops_per_second(), "drops", metrics_mode),
            )
        }),
        width,
        metrics_mode,
    );
    groups.push(DetailGroup::take(
        if socket.is_tcp_listener() {
            "LISTENER BACKLOG"
        } else {
            "TRAFFIC / QUEUES"
        },
        &mut lines,
    ));

    let tcp = socket.tcp();
    push_metric(
        &mut lines,
        "CWND",
        tcp.map(|tcp| {
            format!(
                "{} seg / {}",
                tcp.send_cwnd_segments,
                format_bytes(tcp.congestion_window_bytes()),
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "PEER RWND",
        tcp.and_then(|tcp| tcp.send_window_bytes)
            .map(|value| format_bytes(u64::from(value))),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "LOCAL RWND",
        tcp.and_then(|tcp| tcp.receive_window_bytes)
            .map(|value| format_bytes(u64::from(value))),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RCV SPACE",
        tcp.map(|tcp| {
            format!(
                "{}; autotune, not advertised rwnd",
                format_bytes(u64::from(tcp.receive_space_bytes))
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RCV SSTHRESH",
        tcp.map(|tcp| format_bytes(u64::from(tcp.receive_ssthresh_bytes))),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "WSCALE TX/RX",
        tcp.and_then(
            |tcp| match (tcp.send_window_scale, tcp.receive_window_scale) {
                (Some(send), Some(receive)) => Some(format!("{send} / {receive}")),
                _ => None,
            },
        ),
        width,
        metrics_mode,
    );
    if let Some(memory) = socket.memory() {
        push_memory_windows(&mut lines, memory, width, metrics_mode);
    } else {
        push_metric(&mut lines, "SOCKET MEMORY", None, width, metrics_mode);
    }
    push_metric(
        &mut lines,
        "UNSENT",
        tcp.and_then(|tcp| tcp.notsent_bytes).and_then(|value| {
            diagnostic_value(metrics_mode, value > 0, || format_bytes(u64::from(value)))
        }),
        width,
        metrics_mode,
    );
    groups.push(DetailGroup::take("WINDOWS / BUFFERS", &mut lines));

    push_metric(
        &mut lines,
        "CC",
        socket.congestion_algorithm().map(str::to_owned),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "CA STATE",
        tcp.map(|tcp| congestion_state(tcp.congestion_state).to_owned()),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "SSTHRESH",
        tcp.map(|tcp| {
            if tcp.send_ssthresh_segments == i32::MAX as u32 {
                "infinite".to_owned()
            } else {
                format!("{} seg", tcp.send_ssthresh_segments)
            }
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RECOVERY SEG",
        tcp.and_then(|tcp| format_flight_recovery(tcp, metrics_mode)),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RETRANS",
        tcp.and_then(|tcp| {
            diagnostic_value(
                metrics_mode,
                tcp.total_retransmitted_segments > 0
                    || tcp
                        .total_retransmits_per_second()
                        .is_some_and(|rate| rate > 0.0),
                || {
                    format_total_rate(
                        u64::from(tcp.total_retransmitted_segments),
                        tcp.total_retransmits_per_second(),
                        "seg",
                        metrics_mode,
                    )
                },
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RETRANS RATIO",
        tcp.and_then(|tcp| tcp.total_retransmits_per_second())
            .zip(socket.send_traffic().segments_per_second())
            .filter(|(_, sent)| *sent > 0.0)
            .map(|(retrans, sent)| format!("{:.3}% of TX seg/s", retrans / sent * 100.0)),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "REORDER",
        tcp.and_then(|tcp| {
            diagnostic_value(metrics_mode, tcp.reordering_segments > 0, || {
                format!("{} seg", tcp.reordering_segments)
            })
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "PACING",
        tcp.and_then(|tcp| tcp.pacing_rate_bytes_per_second)
            .map(bytes_per_second_as_bits),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "MAX PACING",
        tcp.and_then(|tcp| tcp.max_pacing_rate_bytes_per_second)
            .map(bytes_per_second_as_bits),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "DELIVERY EST",
        tcp.and_then(|tcp| tcp.delivery_rate_bytes_per_second)
            .map(|rate| {
                format!(
                    "{}{}",
                    bytes_per_second_as_bits(rate),
                    if tcp.is_some_and(|tcp| tcp.delivery_rate_app_limited) {
                        "  app-limited"
                    } else {
                        ""
                    }
                )
            }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "TIME TOTALS",
        tcp.and_then(|tcp| format_limited_time(tcp, metrics_mode)),
        width,
        metrics_mode,
    );
    groups.push(DetailGroup::take("CONGESTION / RECOVERY", &mut lines));

    push_metric(
        &mut lines,
        "RTT / VAR",
        tcp.map(|tcp| {
            format!(
                "{} / {}",
                format_micros(u64::from(tcp.rtt_micros)),
                format_micros(u64::from(tcp.rtt_variance_micros))
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "MIN RTT",
        tcp.and_then(|tcp| tcp.min_rtt_micros)
            .map(|value| format_micros(u64::from(value))),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RECV RTT",
        tcp.and_then(|tcp| {
            (tcp.receive_rtt_micros > 0).then(|| format_micros(u64::from(tcp.receive_rtt_micros)))
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RTO / ATO",
        tcp.map(|tcp| {
            format!(
                "{} / {}",
                format_micros(u64::from(tcp.retransmission_timeout_micros)),
                if tcp.ack_timeout_micros == 0 {
                    "inactive".to_owned()
                } else {
                    format_micros(u64::from(tcp.ack_timeout_micros))
                }
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "DATA TX AGE",
        tcp.map(|tcp| format!("{}ms", tcp.last_data_sent_millis,)),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "RX DATA/ACK AGE",
        tcp.map(|tcp| {
            format!(
                "{} / {} ms",
                tcp.last_data_received_millis, tcp.last_ack_received_millis
            )
        }),
        width,
        metrics_mode,
    );
    push_metric(
        &mut lines,
        "TIMEOUT STATE",
        tcp.and_then(|tcp| {
            diagnostic_value(
                metrics_mode,
                tcp.retransmit_timeouts > 0 || tcp.probes > 0 || tcp.backoff > 0,
                || {
                    format!(
                        "retrans {} probes {} backoff {}",
                        tcp.retransmit_timeouts, tcp.probes, tcp.backoff
                    )
                },
            )
        }),
        width,
        metrics_mode,
    );
    groups.push(DetailGroup::take("LATENCY / TIMERS", &mut lines));

    let mut path_memory = Vec::new();
    push_metric(
        &mut path_memory,
        "MSS TX/RX",
        tcp.map(|tcp| format!("{} / {} byte", tcp.send_mss_bytes, tcp.receive_mss_bytes,)),
        width,
        metrics_mode,
    );
    push_metric(
        &mut path_memory,
        "ADVMSS / PMTU",
        tcp.map(|tcp| format!("{} / {} byte", tcp.advertised_mss_bytes, tcp.path_mtu_bytes)),
        width,
        metrics_mode,
    );
    push_metric(
        &mut path_memory,
        "TCP OPTIONS",
        tcp.and_then(|tcp| {
            diagnostic_value(metrics_mode, tcp.options > 0, || {
                format_tcp_options(tcp.options, metrics_mode)
            })
        }),
        width,
        metrics_mode,
    );
    if let Some(memory) = socket.memory() {
        push_metric(
            &mut path_memory,
            "AUX MEMORY",
            diagnostic_value(
                metrics_mode,
                memory.forward_allocated > 0 || memory.option_memory > 0 || memory.backlog > 0,
                || format_aux_memory(memory, metrics_mode),
            ),
            width,
            metrics_mode,
        );
    }
    if !path_memory.is_empty() {
        groups.push(DetailGroup::take("PATH / MEMORY", &mut path_memory));
    }

    groups
}

fn push_limit_basis(
    lines: &mut Vec<Line<'static>>,
    tcp: Option<SocketTcpDiagnostics>,
    width: usize,
) {
    let (reason, why) = tcp.map_or(
        ("UNKNOWN", "TCP_INFO unavailable for this socket"),
        SocketTcpDiagnostics::limit_reason,
    );
    let mode = DetailMetricsMode::All;
    push_metric(lines, "LIMIT", Some(reason.to_owned()), width, mode);
    push_metric(lines, "WHY", Some(why.to_owned()), width, mode);
    let Some(tcp) = tcp else { return };
    let timing = tcp.limit_interval;
    push_metric(
        lines,
        "INTERVAL",
        timing.map(|value| format!("{:.3}s; same socket/query", value.elapsed.as_secs_f64())),
        width,
        mode,
    );
    push_metric(
        lines,
        "BUSY DELTA",
        timing.map(|value| format_micros(value.busy_micros)),
        width,
        mode,
    );
    for (label, micros) in [
        ("RWND DELTA", timing.and_then(|value| value.rwnd_micros)),
        ("SNDBUF DELTA", timing.and_then(|value| value.sndbuf_micros)),
    ] {
        push_metric(
            lines,
            label,
            micros.map(|micros| {
                let share = timing.and_then(|value| value.share(Some(micros)));
                format!(
                    "{} / {}",
                    format_micros(micros),
                    share.map_or_else(
                        || "n/a (busy=0)".to_owned(),
                        |share| format!("{:.1}% busy", share * 100.0)
                    )
                )
            }),
            width,
            mode,
        );
    }
    push_metric(
        lines,
        "UNSENT NOW",
        tcp.notsent_bytes
            .map(|value| format_bytes(u64::from(value))),
        width,
        mode,
    );
    push_metric(
        lines,
        "FLIGHT/CWND?",
        tcp.estimated_flight_segments().map(|flight| {
            let percent = if tcp.send_cwnd_segments == 0 {
                "n/a".to_owned()
            } else {
                format!(
                    "{:.1}%",
                    f64::from(flight) / f64::from(tcp.send_cwnd_segments) * 100.0
                )
            };
            format!("{flight} / {} seg ({percent})", tcp.send_cwnd_segments)
        }),
        width,
        mode,
    );
    push_metric(
        lines,
        "FLIGHT MATH",
        Some(format!(
            "{} - {} - {} + {} = {} seg",
            tcp.unacked_segments,
            tcp.sacked_segments,
            tcp.lost_segments,
            tcp.retransmitted_segments,
            tcp.estimated_flight_segments()
                .map_or_else(|| "n/a".to_owned(), |v| v.to_string()),
        )),
        width,
        mode,
    );
    push_metric(
        lines,
        "FORMULA",
        Some("unacked - sacked - lost + retrans".to_owned()),
        width,
        mode,
    );
    push_metric(
        lines,
        "CA / APP SAMPLE",
        Some(format!(
            "{} / {} (app-limited; latest)",
            congestion_state(tcp.congestion_state),
            if tcp.delivery_rate_app_limited {
                "yes"
            } else {
                "no"
            },
        )),
        width,
        mode,
    );
    push_metric(
        lines,
        "PEER/CWND BYTE",
        tcp.send_window_bytes.map(|window| {
            format!(
                "{} / {}",
                format_bytes(u64::from(window)),
                format_bytes(tcp.congestion_window_bytes())
            )
        }),
        width,
        mode,
    );
    push_metric(lines, "RULES", Some(
        "RWND/SNDBUF >=50% busy. CWND?: unsent>0, flight>=90% cwnd, CA OPEN, peer>=cwnd. ?=inference, not proof.".to_owned()
    ), width, mode);
}

fn push_memory_windows(
    lines: &mut Vec<Line<'static>>,
    memory: SocketMemoryDiagnostics,
    width: usize,
    mode: DetailMetricsMode,
) {
    push_metric(
        lines,
        "RX ALLOC/LIMIT",
        Some(format!(
            "{} / {}",
            format_bytes(u64::from(memory.receive_allocated)),
            format_bytes(u64::from(memory.receive_limit))
        )),
        width,
        mode,
    );
    push_metric(
        lines,
        "TX ALLOC/LIMIT",
        Some(format!(
            "{} / {}",
            format_bytes(u64::from(memory.send_allocated)),
            format_bytes(u64::from(memory.send_limit)),
        )),
        width,
        mode,
    );
    push_metric(
        lines,
        "TX MEM QUEUED",
        Some(format_bytes(u64::from(memory.send_queued))),
        width,
        mode,
    );
}

fn push_metric(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: Option<String>,
    width: usize,
    mode: DetailMetricsMode,
) {
    let value = match value {
        Some(value) => value,
        None if mode == DetailMetricsMode::WithData => return,
        None => "n/a".to_owned(),
    };
    if width < 24 {
        push_wrapped(lines, label, width, Style::default().fg(LABEL_COLOR));
        push_wrapped(lines, &value, width, Style::default().fg(theme::TEXT));
        return;
    }
    let label_width = 15.min(width / 3);
    let labels = socket::wrap_text(label, label_width);
    let values = socket::wrap_text(&value, width - label_width - 3);
    for index in 0..labels.len().max(values.len()) {
        let label = labels.get(index).map_or("", String::as_str);
        let value = values.get(index).map_or("", String::as_str);
        lines.push(Line::from(vec![
            Span::styled(
                format!("{label:<label_width$}"),
                Style::default().fg(LABEL_COLOR),
            ),
            Span::styled(" | ", Style::default().fg(theme::DIVIDER)),
            Span::styled(value.to_owned(), Style::default().fg(theme::TEXT)),
        ]));
    }
}

fn push_wrapped(lines: &mut Vec<Line<'static>>, value: &str, width: usize, style: Style) {
    lines.extend(socket::wrap_text(value, width).into_iter().map(|line| {
        if socket::text_width(&line) > width {
            Line::styled("?", style)
        } else {
            Line::styled(line, style)
        }
    }));
}

fn format_scope(socket: &InetSocketSnapshot, stable_identity: bool) -> String {
    let device = if socket.bound_ifindex() == 0 {
        "device any".to_owned()
    } else {
        format!("device ifindex {}", socket.bound_ifindex())
    };
    let expires = if socket.expires_millis() > 0 {
        format!("  expires {}ms", socket.expires_millis())
    } else {
        String::new()
    };
    format!(
        "uid {}  {device}{expires}  identity {}",
        socket.uid(),
        if stable_identity {
            "stable"
        } else {
            "sample-only"
        }
    )
}

fn format_owner(socket: &InetSocketSnapshot) -> String {
    let Some(owner) = socket.owners().first() else {
        return format!("uid {}", socket.uid());
    };
    let owner = owner.command().map_or_else(
        || owner.pid().to_string(),
        |command| format!("{}/{}", owner.pid(), command),
    );
    let additional = socket.owners().len().saturating_sub(1);
    if additional == 0 {
        owner
    } else {
        format!("{owner} +{additional}")
    }
}

fn format_flight_recovery(tcp: SocketTcpDiagnostics, mode: DetailMetricsMode) -> Option<String> {
    let mut parts = Vec::new();
    for (label, value) in [
        ("unacked", tcp.unacked_segments),
        ("sacked", tcp.sacked_segments),
        ("lost", tcp.lost_segments),
        ("retrans", tcp.retransmitted_segments),
        ("fackets", tcp.fackets),
    ] {
        if value > 0 || mode == DetailMetricsMode::All {
            parts.push(format!("{label} {value}"));
        }
    }
    (!parts.is_empty()).then(|| parts.join("  "))
}

fn format_aux_memory(memory: SocketMemoryDiagnostics, mode: DetailMetricsMode) -> String {
    let mut parts = Vec::new();
    for (label, value) in [
        ("forward", memory.forward_allocated),
        ("options", memory.option_memory),
        ("backlog", memory.backlog),
    ] {
        if value > 0 || mode == DetailMetricsMode::All {
            parts.push(format!("{label} {}", format_bytes(u64::from(value))));
        }
    }
    parts.join("  ")
}

fn format_limited_time(tcp: SocketTcpDiagnostics, mode: DetailMetricsMode) -> Option<String> {
    if tcp.busy_time_micros.is_none()
        && tcp.receive_window_limited_micros.is_none()
        && tcp.send_buffer_limited_micros.is_none()
    {
        return None;
    }
    let mut parts = Vec::new();
    push_optional_duration(&mut parts, "busy", tcp.busy_time_micros, mode, true);
    push_optional_duration(
        &mut parts,
        "peer-window",
        tcp.receive_window_limited_micros,
        mode,
        false,
    );
    push_optional_duration(
        &mut parts,
        "send-buffer",
        tcp.send_buffer_limited_micros,
        mode,
        false,
    );
    (!parts.is_empty()).then(|| parts.join("  "))
}

fn push_optional_duration(
    parts: &mut Vec<String>,
    label: &str,
    value: Option<u64>,
    mode: DetailMetricsMode,
    keep_zero: bool,
) {
    match value {
        Some(value) if keep_zero || value > 0 || mode == DetailMetricsMode::All => {
            parts.push(format!("{label} {}", format_micros(value)));
        }
        None if mode == DetailMetricsMode::All => parts.push(format!("{label} n/a")),
        Some(_) | None => {}
    }
}

fn diagnostic_value(
    mode: DetailMetricsMode,
    has_signal: bool,
    format: impl FnOnce() -> String,
) -> Option<String> {
    (has_signal || mode == DetailMetricsMode::All).then(format)
}

fn format_total_rate(total: u64, rate: Option<f64>, unit: &str, mode: DetailMetricsMode) -> String {
    rate.map_or_else(
        || {
            if mode == DetailMetricsMode::All {
                format!("{total} {unit} total  rate n/a")
            } else {
                format!("{total} {unit} total")
            }
        },
        |rate| format!("{total} {unit} total  {rate:.2}/s"),
    )
}

fn format_tcp_options(options: u8, mode: DetailMetricsMode) -> String {
    const KNOWN_OPTIONS: u8 = 0x3f;
    let mut names = Vec::new();
    for (mask, name) in [
        (0x01, "timestamps"),
        (0x02, "sack"),
        (0x04, "wscale"),
        (0x08, "ecn"),
        (0x10, "ecn-seen"),
        (0x20, "syn-data"),
    ] {
        if options & mask != 0 {
            names.push(name);
        }
    }
    let unknown = options & !KNOWN_OPTIONS;
    if unknown != 0 {
        names.push("unknown");
    }
    if names.is_empty() {
        names.push("none");
    }
    let mut value = names.join("  ");
    if mode == DetailMetricsMode::All {
        value.push_str(&format!("  raw 0x{options:02x}"));
    }
    value
}

fn congestion_state(state: u8) -> &'static str {
    match state {
        0 => "OPEN",
        1 => "DISORDER",
        2 => "CWR",
        3 => "RECOVERY",
        4 => "LOSS",
        _ => "UNKNOWN",
    }
}

fn bytes_per_second_as_bits(value: u64) -> String {
    format_bit_rate(value.saturating_mul(8))
}

fn format_bit_rate(value: u64) -> String {
    const KILO: f64 = 1_000.0;
    const MEGA: f64 = 1_000_000.0;
    const GIGA: f64 = 1_000_000_000.0;
    let value = value as f64;
    if value >= GIGA {
        format!("{:.2} Gbit/s", value / GIGA)
    } else if value >= MEGA {
        format!("{:.2} Mbit/s", value / MEGA)
    } else if value >= KILO {
        format!("{:.2} kbit/s", value / KILO)
    } else {
        format!("{value:.0} bit/s")
    }
}

fn format_bytes(value: u64) -> String {
    const KIB: f64 = 1_024.0;
    const MIB: f64 = KIB * 1_024.0;
    const GIB: f64 = MIB * 1_024.0;
    let value = value as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.2} KiB", value / KIB)
    } else {
        format!("{value:.0} B")
    }
}

fn format_micros(value: u64) -> String {
    if value >= 1_000_000 {
        format!("{:.3}s", Duration::from_micros(value).as_secs_f64())
    } else if value >= 1_000 {
        format!("{:.3}ms", value as f64 / 1_000.0)
    } else {
        format!("{value}us")
    }
}

#[cfg(test)]
pub(super) fn preview_buffer(width: u16, mode: DetailMetricsMode) -> ratatui::buffer::Buffer {
    tests::render_buffer(&tests::tcp_detail(), width, mode)
}

#[cfg(test)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    pub(super) fn tcp_detail() -> SocketDetailState {
        let first = crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2);
        let key = first.sockets()[0].row_key().clone();
        let mut detail = SocketDetailState::start(&first, key).unwrap();
        detail.record(&crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3));
        detail
    }

    fn udp_detail() -> SocketDetailState {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2);
        SocketDetailState::start(&snapshot, snapshot.sockets()[1].row_key().clone()).unwrap()
    }

    fn listener_detail() -> SocketDetailState {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_listener_snapshot_at(2);
        SocketDetailState::start(&snapshot, snapshot.sockets()[0].row_key().clone()).unwrap()
    }

    pub(super) fn render_buffer(
        detail: &SocketDetailState,
        width: u16,
        mode: DetailMetricsMode,
    ) -> ratatui::buffer::Buffer {
        let height = row_count(detail, mode, width).try_into().unwrap();
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                render(frame, frame.area(), detail, mode, 0);
            })
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn render_text(detail: &SocketDetailState, width: u16, mode: DetailMetricsMode) -> String {
        buffer_text(&render_buffer(detail, width, mode))
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    // Read each visible frame independently: wrapping in adjacent columns must not
    // interleave unrelated values when checking that a complete metric survived.
    fn module_text(buffer: &ratatui::buffer::Buffer) -> Vec<String> {
        let mut modules = Vec::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                if buffer[(x, y)].symbol() != "┌" {
                    continue;
                }
                let right = ((x + 1)..buffer.area.width)
                    .find(|right| buffer[(*right, y)].symbol() == "┐")
                    .expect("complete top border");
                let mut text = String::new();
                let mut row = y;
                loop {
                    for col in (x + 1)..right {
                        let symbol = buffer[(col, row)].symbol();
                        if symbol != "─" && symbol != "|" {
                            text.push_str(symbol);
                        }
                    }
                    text.push(' ');
                    row += 1;
                    assert!(row < buffer.area.height, "missing bottom border");
                    if buffer[(x, row)].symbol() == "└" {
                        assert_eq!(buffer[(right, row)].symbol(), "┘");
                        break;
                    }
                    assert_eq!(buffer[(x, row)].symbol(), "│");
                    assert_eq!(buffer[(right, row)].symbol(), "│");
                }
                modules.push(text.split_whitespace().collect::<Vec<_>>().join(" "));
            }
        }
        modules
    }

    fn assert_no_trends(rendered: &str) {
        for removed in [
            "KEY TRENDS",
            "TREND COVERAGE",
            "max-bucket",
            "buckets",
            "compacted",
        ] {
            assert!(!rendered.contains(removed), "{rendered}");
        }
        assert!(
            !rendered.chars().any(|value| "▁▂▃▄▅▆▇█".contains(value)),
            "{rendered}"
        );
    }

    #[test]
    fn normal_tcp_detail_fits_one_page_at_approved_sizes() {
        let detail = tcp_detail();
        for (width, body_height) in [(160, 40), (180, 45)] {
            for mode in [DetailMetricsMode::WithData, DetailMetricsMode::All] {
                let lines = detail_lines(&detail, mode, width);
                let height = row_count(&detail, mode, width);
                assert_eq!(height, lines.len());
                assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                eprintln!("Socket detail {width} columns {mode:?}: {height} body rows");
                if mode == DetailMetricsMode::WithData {
                    assert!(
                        height <= body_height,
                        "{width} columns: {height} > {body_height}"
                    );
                }
            }
        }
    }

    #[test]
    fn metric_values_wrap_under_the_value_column_with_readable_labels() {
        for width in [49, 55] {
            let mut lines = Vec::new();
            let value = "unacked - sacked - lost + retrans; flight is an estimate, not proof";
            push_metric(
                &mut lines,
                "FORMULA",
                Some(value.to_owned()),
                width,
                DetailMetricsMode::All,
            );
            assert!(lines.len() > 1);
            assert_eq!(lines[0].spans[0].style.fg, Some(LABEL_COLOR));
            let separator = lines[0].to_string().find('|').unwrap();
            for line in &lines {
                assert_eq!(line.to_string().find('|'), Some(separator));
                assert!(line.width() <= width);
            }
            for line in &lines[1..] {
                assert!(line.spans[0].content.trim().is_empty());
            }
            let values = lines
                .iter()
                .map(|line| line.spans[2].content.as_ref())
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(values, value);
        }
    }

    #[test]
    fn framed_modules_preserve_all_data_across_responsive_widths() {
        for detail in [tcp_detail(), udp_detail(), listener_detail()] {
            for mode in [DetailMetricsMode::WithData, DetailMetricsMode::All] {
                let compact = |buffer: &ratatui::buffer::Buffer| {
                    let mut values = module_text(buffer)
                        .into_iter()
                        .map(|text| {
                            text.chars()
                                .filter(|ch| !ch.is_whitespace())
                                .collect::<String>()
                        })
                        .collect::<Vec<_>>();
                    values.sort();
                    values
                };
                let expected = compact(&render_buffer(&detail, 240, mode));
                for width in [60, 80, 120, 160] {
                    let buffer = render_buffer(&detail, width, mode);
                    assert_eq!(compact(&buffer), expected, "width {width}, mode {mode:?}");
                    let text: String = buffer_text(&buffer)
                        .chars()
                        .filter(|ch| !ch.is_whitespace() && *ch != '|')
                        .collect();
                    for endpoint in [detail.socket().local(), detail.socket().remote()] {
                        assert!(text.contains(&socket::format_endpoint(endpoint)), "{text}");
                    }
                    let max_columns = (0..buffer.area.height)
                        .map(|y| {
                            (0..width)
                                .filter(|x| buffer[(*x, y)].symbol() == "┌")
                                .count()
                        })
                        .max()
                        .unwrap();
                    if detail.socket().tcp().is_some() {
                        assert_eq!(
                            max_columns,
                            match width {
                                160 => 3,
                                120 => 2,
                                _ => 1,
                            }
                        );
                    }
                    let title = (0..buffer.area.height)
                        .find_map(|y| {
                            (0..width).find_map(|x| {
                                let cell = &buffer[(x, y)];
                                (cell.symbol() == "S" && cell.fg == theme::SOCKETS).then_some(cell)
                            })
                        })
                        .expect("colored identity title");
                    assert!(title.modifier.contains(Modifier::BOLD));
                }
            }
        }
    }

    #[test]
    fn scrolling_matches_full_render_at_small_and_regular_sizes() {
        let detail = tcp_detail();
        for width in [1, 2, 3, 4, 5, 12, 60, 80, 120, 160] {
            for mode in [DetailMetricsMode::WithData, DetailMetricsMode::All] {
                let lines = detail_lines(&detail, mode, width);
                assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                assert_eq!(row_count(&detail, mode, width), lines.len());
                let full = render_buffer(&detail, width, mode);
                for height in [1, 3, 17] {
                    for requested in [0, 1, 7, lines.len() / 2, usize::MAX] {
                        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
                        terminal
                            .draw(|frame| render(frame, frame.area(), &detail, mode, requested))
                            .unwrap();
                        let offset = requested.min(lines.len().saturating_sub(usize::from(height)));
                        for y in 0..height {
                            for x in 0..width {
                                assert_eq!(
                                    terminal.backend().buffer()[(x, y)],
                                    full[(x, y + offset as u16)],
                                    "width {width}, height {height}, offset {offset}, cell {x}/{y}"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(row_count(&detail, DetailMetricsMode::All, 0), 0);
        let mut terminal = Terminal::new(TestBackend::new(0, 0)).unwrap();
        terminal
            .draw(|frame| {
                render(
                    frame,
                    frame.area(),
                    &detail,
                    DetailMetricsMode::All,
                    usize::MAX,
                )
            })
            .unwrap();
    }

    #[test]
    fn wrapping_preserves_long_ipv6_endpoints_and_unicode_values() {
        for width in [1, 5, 12, 60, 80, 120, 160] {
            let layout = DetailLayout::new(width);
            let endpoint = "[2001:db8:abcd:1234:5678:9876:5432:1234]:65535";
            let mut lines = Vec::new();
            push_metric(
                &mut lines,
                "LOCAL -> REMOTE",
                Some(format!("{endpoint} -> {endpoint}")),
                layout.full_inner_width(),
                DetailMetricsMode::All,
            );
            push_metric(
                &mut lines,
                "PROCESS",
                Some("网管/服务端".to_owned()),
                layout.full_inner_width(),
                DetailMetricsMode::All,
            );
            let groups = vec![DetailGroup::take("IDENTITY", &mut lines)];
            let height = layout.row_count(&groups);
            let rows = layout.compose(groups);
            assert_eq!(height, rows.len());
            assert!(
                rows.iter().all(|line| line.width() <= usize::from(width)),
                "width {width}"
            );
            let text = rows.iter().map(Line::to_string).collect::<String>();
            let normalized: String = text
                .chars()
                .filter(|ch| !ch.is_whitespace() && !"|│┌┐└┘─".contains(*ch))
                .collect();
            assert!(normalized.contains(endpoint), "{text}");
            if width >= 12 {
                assert!(normalized.contains("网管/服务端"), "{text}");
            }
        }
    }

    #[test]
    #[ignore = "manual production renderer snapshot; set NETLENS_SOCKET_DETAIL_SNAPSHOT to a text path"]
    fn export_framed_detail_snapshot() {
        let path = std::env::var("NETLENS_SOCKET_DETAIL_SNAPSHOT").expect("snapshot path");
        let mut snapshot = String::new();
        for width in [60, 80, 120, 160] {
            snapshot.push_str(&format!("SOCKET DETAIL / {width} columns\n"));
            snapshot.push_str(&buffer_text(&preview_buffer(
                width,
                DetailMetricsMode::WithData,
            )));
            snapshot.push_str("\n\n");
        }
        std::fs::write(path, snapshot).unwrap();
    }

    #[test]
    fn limit_basis_shows_wall_interval_busy_denominator_and_missing_baseline() {
        let snapshot = crate::monitor::socket_table::synthetic_socket_table_snapshot();
        let mut tcp = snapshot.sockets()[0].tcp().unwrap();
        tcp.limit_interval = Some(crate::monitor::socket_table::SocketLimitInterval {
            elapsed: Duration::from_secs(1),
            busy_micros: 500_000,
            rwnd_micros: Some(360_000),
            sndbuf_micros: Some(60_000),
        });
        for width in [60, 80, 160] {
            let mut lines = Vec::new();
            push_limit_basis(&mut lines, Some(tcp), width);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines
                .iter()
                .map(Line::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            for expected in [
                "RWND",
                "72.0%",
                "12.0%",
                "500.000ms",
                "1.000s",
                "unacked",
                "sacked",
                "CA / APP SAMPLE",
                "OPEN / no (app-limited; latest)",
            ] {
                assert!(text.contains(expected), "{expected}: {text}");
            }
        }
        let text = render_text(&tcp_detail(), 120, DetailMetricsMode::WithData);
        assert!(text.contains("UNKNOWN"), "{text}");
        assert!(text.contains("baseline"), "{text}");
    }

    #[test]
    fn supported_widths_show_realtime_metrics_without_trends() {
        let detail = tcp_detail();
        for width in [60, 80, 120, 160] {
            for mode in [DetailMetricsMode::WithData, DetailMetricsMode::All] {
                let lines = detail_lines(&detail, mode, width);
                assert!(
                    lines.iter().all(|line| line.width() <= usize::from(width)),
                    "width {width}, mode {mode:?}"
                );
                assert_no_trends(&render_text(&detail, width, mode));
            }
            let rendered = render_text(&detail, width, DetailMetricsMode::WithData);
            let normalized =
                module_text(&render_buffer(&detail, width, DetailMetricsMode::WithData)).join(" ");
            for expected in [
                "APP BANDWIDTH",
                "ALL SEG TOTAL",
                "acknowledged bytes",
                "CWND",
                "PEER RWND",
                "LOCAL RWND",
                "RCV SPACE",
                "RCV SSTHRESH",
                "DATA SEG TOTAL",
                "not advertised rwnd",
                "RTT",
                "RETRANS",
                "RETRANS RATIO",
                "REORDER",
                "PACING",
                "DELIVERY EST",
                "QUEUE",
            ] {
                assert!(
                    normalized.contains(expected),
                    "missing {expected:?} at {width} columns:\n{rendered}"
                );
            }
        }
    }

    #[test]
    fn former_trend_metrics_remain_as_current_numeric_values() {
        let rendered = render_text(&tcp_detail(), 160, DetailMetricsMode::WithData);
        let normalized = module_text(&render_buffer(
            &tcp_detail(),
            160,
            DetailMetricsMode::WithData,
        ))
        .join(" ");
        for expected in [
            "APP BANDWIDTH 8.00 kbit/s 16.00 kbit/s",
            "RTT / VAR 12.500ms",
            "CWND 20 seg / 28.28 KiB",
            "QUEUE 128 B 256 B",
            "RETRANS 3 seg total 1.00/s",
            "DELIVERY EST 12.00 Mbit/s",
            "PEER RWND 256.00 KiB",
            "LOCAL RWND 128.00 KiB",
        ] {
            assert!(
                normalized.contains(expected),
                "missing {expected}:\n{rendered}"
            );
        }
        assert_no_trends(&rendered);
    }

    #[test]
    fn udp_hides_tcp_only_rows_by_default_and_all_mode_marks_them_unavailable() {
        let detail = udp_detail();
        let data = render_text(&detail, 120, DetailMetricsMode::WithData);
        let all = render_text(&detail, 120, DetailMetricsMode::All);

        assert!(!data.contains("PEER RWND"), "{data}");
        assert!(!data.contains("LIMIT BASIS"), "{data}");
        assert!(!all.contains("LIMIT BASIS"), "{all}");
        assert!(all.contains("PEER RWND"), "{all}");
        assert!(all.contains("n/a"), "{all}");
        assert!(data.contains("RX ALLOC/LIMIT"), "{data}");
        assert!(data.contains("QUEUE"), "{data}");
        assert!(!data.contains("APP BYTES"), "{data}");
        assert!(!data.contains("ALL SEG TOTAL"), "{data}");
        assert!(all.contains("APP BYTES"), "{all}");
        assert!(!data.contains("SOCKET DROPS"), "{data}");
        assert!(!data.contains("AUX MEMORY"), "{data}");
        assert!(!data.contains("n/a"), "{data}");
        assert!(all.contains("SOCKET DROPS"), "{all}");
        assert!(all.contains("AUX MEMORY"), "{all}");
        assert_no_trends(&data);
        assert_no_trends(&all);
    }

    #[test]
    fn missing_selected_identity_is_not_called_closed() {
        let mut detail = tcp_detail();
        detail.record(
            &crate::monitor::socket_table::synthetic_socket_table_snapshot_without_tcp_at(4),
        );
        let rendered = render_text(&detail, 80, DetailMetricsMode::WithData);

        assert!(rendered.contains("NOT OBSERVED"), "{rendered}");
        assert!(rendered.contains("LAST STATE"), "{rendered}");
        assert!(!rendered.contains("12.500ms"), "{rendered}");
        assert!(!rendered.contains("CONNECTION SUMMARY"), "{rendered}");
        assert!(!rendered.contains("TRAFFIC / QUEUES"), "{rendered}");
        assert!(!rendered.contains("WINDOWS / BUFFERS"), "{rendered}");
        assert!(!rendered.contains("CLOSED"), "{rendered}");
        assert_no_trends(&rendered);
    }

    #[test]
    fn listener_uses_connection_counts_without_connection_diagnostics() {
        let detail = listener_detail();
        let rendered = render_text(&detail, 120, DetailMetricsMode::WithData);

        assert!(rendered.contains("LISTENER BACKLOG"), "{rendered}");
        assert!(rendered.contains("pending 11  limit 128"), "{rendered}");
        assert!(!rendered.contains("TRAFFIC / QUEUES"), "{rendered}");
        assert!(!rendered.contains("CONNECTION SUMMARY"), "{rendered}");
        assert!(!rendered.contains("CWND"), "{rendered}");
        assert!(!rendered.contains("LIMIT BASIS"), "{rendered}");
        assert!(!rendered.contains("FLIGHT / RECOVERY"), "{rendered}");
        assert!(!rendered.contains("PATH / MEMORY"), "{rendered}");
        assert!(!rendered.contains("RX QUEUE"), "{rendered}");
        assert!(!rendered.contains("TX QUEUE"), "{rendered}");
        assert_no_trends(&rendered);
    }

    #[test]
    fn reappearing_socket_restores_current_values_without_old_trends() {
        let mut detail = tcp_detail();
        detail.record(
            &crate::monitor::socket_table::synthetic_socket_table_snapshot_without_tcp_at(4),
        );
        detail.record(
            &crate::monitor::socket_table::synthetic_socket_table_snapshot_with_rtt_at(5, 20_000),
        );
        let rendered = render_text(&detail, 160, DetailMetricsMode::WithData);
        assert!(rendered.contains("20.000ms"), "{rendered}");
        assert!(!rendered.contains("12.500ms"), "{rendered}");
        assert!(!rendered.contains("NOT OBSERVED"), "{rendered}");
        assert_no_trends(&rendered);
    }

    #[test]
    fn long_running_socket_shows_current_rtt_without_historical_peak() {
        let first =
            crate::monitor::socket_table::synthetic_socket_table_snapshot_with_rtt_at(1, 123_456);
        let key = first.sockets()[0].row_key().clone();
        let mut detail = SocketDetailState::start(&first, key).unwrap();
        for sequence in 2..=121 {
            detail.record(
                &crate::monitor::socket_table::synthetic_socket_table_snapshot_with_rtt_at(
                    sequence, 20_000,
                ),
            );
        }

        let rendered = render_text(&detail, 160, DetailMetricsMode::WithData);
        assert!(rendered.contains("20.000ms"), "{rendered}");
        assert!(!rendered.contains("123.456ms"), "{rendered}");
        assert_no_trends(&rendered);
    }

    #[test]
    fn tcp_options_are_named_and_raw_bits_are_reserved_for_all_mode() {
        assert_eq!(
            format_tcp_options(0x07, DetailMetricsMode::WithData),
            "timestamps  sack  wscale"
        );
        assert_eq!(
            format_tcp_options(0x47, DetailMetricsMode::All),
            "timestamps  sack  wscale  unknown  raw 0x47"
        );
    }

    #[test]
    fn missing_metrics_are_omitted_by_default_and_marked_in_all_mode() {
        let mut lines = Vec::new();
        push_metric(
            &mut lines,
            "APP BYTES",
            None,
            49,
            DetailMetricsMode::WithData,
        );
        assert!(lines.is_empty());
        push_metric(&mut lines, "APP BYTES", None, 49, DetailMetricsMode::All);
        assert!(lines[0].to_string().contains("n/a"));
    }

    #[test]
    fn limit_basis_does_not_guess_without_the_peer_window() {
        let detail = tcp_detail();
        let mut tcp = detail.socket().tcp().unwrap();
        tcp.send_window_bytes = None;
        let mut lines = Vec::new();
        push_limit_basis(&mut lines, Some(tcp), 49);
        let peer = lines
            .iter()
            .find(|line| line.to_string().contains("PEER/CWND BYTE"))
            .unwrap();
        assert!(peer.to_string().contains("n/a"));
        assert_eq!(tcp.limit_reason().0, "UNKNOWN");
    }

    #[test]
    fn zero_diagnostics_are_hidden_by_default_and_available_in_all_mode() {
        assert_eq!(
            diagnostic_value(DetailMetricsMode::WithData, false, || "0".to_owned()),
            None
        );
        assert_eq!(
            diagnostic_value(DetailMetricsMode::All, false, || "0".to_owned()),
            Some("0".to_owned())
        );

        let detail = tcp_detail();
        let tcp = detail.socket().tcp().unwrap();
        assert_eq!(
            format_flight_recovery(tcp, DetailMetricsMode::WithData).as_deref(),
            Some("unacked 2")
        );
        assert_eq!(
            format_aux_memory(
                detail.socket().memory().unwrap(),
                DetailMetricsMode::WithData
            ),
            "options 2.00 KiB"
        );

        let udp = udp_detail();
        let mut lines = Vec::new();
        push_traffic_matrix(&mut lines, udp.socket(), 49, DetailMetricsMode::WithData);
        assert!(!lines
            .iter()
            .any(|line| line.to_string().contains("APP BANDWIDTH")));
    }
}
