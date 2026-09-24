use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::monitor::{
    AggregationDomain, BaselineOrigin, CounterContinuity, DisplayMeaning, InterfaceViewAnchor,
    MetricDescriptor, MetricLabel, MetricLabels, MetricUnit, MonitorSection, ProjectedValue,
    ProviderHealth, SeriesSnapshot, SeriesValue,
};

use super::app::{series_matches_anchor, App, DetailMetricsMode, Page, SessionStatus, TimeView};
use super::presentation::{is_interface_grouped, DirectionSummary};
use super::theme;

pub fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width < 2 || area.height < 7 {
        frame.render_widget(Paragraph::new("netlens"), area);
        return;
    }

    let footer_height = footer_height(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(body_top(area.width) - 2),
            Constraint::Min(1),
            Constraint::Length(footer_height),
        ])
        .split(area);
    render_header(frame, chunks[0], app);
    render_context(frame, chunks[1], app);
    render_navigation(frame, chunks[2], app);
    render_body(frame, chunks[3], app);
    render_footer(frame, chunks[4], app);
}

pub(super) fn body_rows(area: Rect, app: &App) -> usize {
    if area.width < 2 || area.height < 7 {
        return 0;
    }
    usize::from(
        area.height
            .saturating_sub(body_top(area.width) + footer_height(app)),
    )
}

fn footer_height(app: &App) -> u16 {
    if app.command().is_some()
        || app.command_error().is_some()
        || app.flow_filter_input().is_some()
        || app.flow_filter_error().is_some()
        || app.socket_filter_input().is_some()
        || app.socket_filter_error().is_some()
        || app.route_lookup_input().is_some()
        || app.route_lookup_error().is_some()
    {
        2
    } else {
        1
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let status_style = match app.status() {
        SessionStatus::Starting => Style::default().fg(theme::ACCENT),
        SessionStatus::Live => Style::default().fg(theme::GOOD),
        SessionStatus::Degraded => Style::default().fg(theme::WARN),
        SessionStatus::NoData => Style::default().fg(theme::MUTED),
        SessionStatus::Error => Style::default().fg(theme::BAD),
    };
    let elapsed = app
        .snapshot()
        .map(|snapshot| format_duration(snapshot.elapsed()))
        .unwrap_or_else(|| "0s".to_owned());
    let details = if app.is_socket_detail() {
        if area.width < 70 {
            format!("  {elapsed}/{}", format_duration(app.interval()))
        } else if area.width < 100 {
            format!("  e:{elapsed} i:{}", format_duration(app.interval()))
        } else {
            format!(
                "  elapsed {elapsed}  sample {}",
                format_duration(app.interval())
            )
        }
    } else if area.width < 70 {
        if app.paused() {
            format!("  {}", app.time_view().as_str())
        } else {
            format!(
                "  {elapsed}/{}  {}",
                format_duration(app.interval()),
                app.time_view().as_str(),
            )
        }
    } else if area.width < 100 {
        format!(
            "  e:{elapsed} i:{}  {}",
            format_duration(app.interval()),
            app.time_view().as_str(),
        )
    } else {
        format!(
            "  elapsed {elapsed}  sample {}  view {}",
            format_duration(app.interval()),
            app.time_view().as_str(),
        )
    };
    let paused = app.paused().then(|| {
        Span::styled(
            "  PAUSED ",
            Style::default()
                .fg(Color::Black)
                .bg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        )
    });
    let mut spans = vec![
        Span::styled(
            " netlens ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            app.status().as_str(),
            status_style.add_modifier(Modifier::BOLD),
        ),
    ];
    spans.extend(paused);
    spans.push(Span::styled(details, Style::default().fg(theme::TEXT)));
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme::CHROME_BG)),
        area,
    );
}

fn render_context(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let network_namespace = app
        .snapshot()
        .and_then(crate::monitor::MonitorSnapshot::network_namespace)
        .unwrap_or("unknown")
        .to_owned();
    let anchor = match app.interface_anchor() {
        Some(InterfaceViewAnchor::Name { name }) => Some(name.to_owned()),
        Some(InterfaceViewAnchor::Names { names }) => Some(
            names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
        ),
        Some(InterfaceViewAnchor::Ifindex { ifindex }) => {
            Some(format!("ifindex={}", ifindex.get()))
        }
        None => None,
    };
    let detail = if app.is_netfilter_view() {
        Some(("detail", app.netfilter_view().breadcrumb()))
    } else if app.is_network_route() {
        Some(("detail", app.network_route_view().breadcrumb()))
    } else if app.is_socket_detail() {
        Some((
            "detail",
            "SOCKET / APPLICATION > SOCKETS > DETAIL".to_owned(),
        ))
    } else if app.is_socket_table() {
        Some(("detail", "SOCKET / APPLICATION > SOCKETS".to_owned()))
    } else if app.is_conntrack_flows() {
        Some((
            "detail",
            if app.is_conntrack_list() {
                "CONNTRACK > FLOWS"
            } else {
                "CONNTRACK > FLOW DETAIL / DIAGNOSTICS"
            }
            .to_owned(),
        ))
    } else if let Some(kind) = app.detail_layer() {
        Some((
            "detail",
            super::dashboard::overview_layer_title(kind).to_owned(),
        ))
    } else if let (Some(identity), Some(layer)) =
        (app.detail_interface(), app.detail_interface_layer())
    {
        Some((
            "detail",
            format!(
                "{} ifindex={} > {}",
                identity.name(),
                identity.ifindex().get(),
                super::dashboard::interface_stage_title(layer)
            ),
        ))
    } else {
        app.detail_interface().map(|identity| {
            (
                "detail",
                format!("{} ifindex={}", identity.name(), identity.ifindex().get()),
            )
        })
    };
    let filter = app
        .is_conntrack_flows()
        .then(|| app.conntrack_filter())
        .flatten()
        .map(|filter| filter.query().to_owned());
    let fields = if app.is_socket_session_active() {
        let detail = detail.expect("socket table has a detail breadcrumb");
        let mut full = vec![("netns", network_namespace.clone())];
        if let Some(anchor) = &anchor {
            full.push(("filter", anchor.clone()));
        }
        full.push(detail.clone());
        if context_fields_width(&full) <= usize::from(area.width) {
            full
        } else {
            let without_anchor = vec![("netns", network_namespace), detail.clone()];
            if context_fields_width(&without_anchor) <= usize::from(area.width) {
                without_anchor
            } else {
                vec![detail]
            }
        }
    } else {
        let mut fields = vec![("netns", network_namespace)];
        if let Some(anchor) = anchor {
            fields.push(("filter", anchor));
        }
        if let Some(detail) = detail {
            fields.push(detail);
        }
        if let Some(filter) = filter {
            fields.push(("filter", filter));
        }
        if app.is_netdev_table() || app.page() == Page::Overview {
            fields.push(("sort", app.netdev_sort_status()));
        }
        fields
    };
    let mut spans = Vec::with_capacity(fields.len() * 2);
    for (index, (label, value)) in fields.into_iter().enumerate() {
        spans.push(Span::styled(
            format!("{}{label} ", if index == 0 { " " } else { "  " }),
            Style::default().fg(theme::MUTED),
        ));
        spans.push(Span::styled(
            value,
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme::CHROME_BG)),
        area,
    );
}

fn context_fields_width(fields: &[(&str, String)]) -> usize {
    fields
        .iter()
        .enumerate()
        .map(|(index, (label, value))| {
            (if index == 0 { 1 } else { 2 }) + label.chars().count() + 1 + value.chars().count()
        })
        .sum()
}

fn navigation(width: u16) -> Vec<(Page, u16, u16)> {
    let mut result = Vec::new();
    let (mut x, mut y) = (0, 0);
    for page in Page::ALL {
        let length = page.label().len() as u16 + 2;
        if x > 0 && x + length > width {
            x = 0;
            y += 1;
        }
        result.push((page, x, y));
        x += length;
    }
    result
}

pub(super) fn body_top(width: u16) -> u16 {
    navigation(width).last().map_or(3, |(_, _, y)| y + 3)
}

pub(super) fn page_at(width: u16, column: u16, row: u16) -> Option<Page> {
    let row = row.checked_sub(2)?;
    navigation(width).into_iter().find_map(|(page, x, y)| {
        (row == y && column >= x && column < x + page.label().len() as u16 + 2).then_some(page)
    })
}

fn render_navigation(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    for (page, _, y) in navigation(area.width) {
        while lines.len() <= usize::from(y) {
            lines.push(Line::default());
        }
        let style = if page == app.page() {
            Style::default()
                .fg(theme::ACCENT)
                .bg(theme::SELECTED_BG)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme::MUTED)
        };
        lines[usize::from(y)]
            .spans
            .push(Span::styled(format!(" {} ", page.label()), style));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_body(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if app.section() == MonitorSection::Hardirq {
        if let Some(table) = app.hardirq_table() {
            table.render(frame, area, app.row_offset());
            return;
        }
    }
    if app.is_softirq_view() {
        match (app.snapshot(), app.softirq_section()) {
            (Some(snapshot), Some(model)) => super::dashboard::render_softirq_section(
                frame,
                area,
                snapshot,
                model,
                app.time_view(),
                app.row_offset(),
            ),
            _ => frame.render_widget(Paragraph::new("Collecting SoftIRQ counters..."), area),
        }
        return;
    }
    if app.is_tc_view() {
        super::tc::render(frame, area, app.tc_table(), app.tc_view());
        return;
    }
    if app.is_netdev_table()
        || (app.section() == MonitorSection::Overview
            && app.dashboard_mode() == super::app::DashboardMode::Summary)
    {
        app.render_workspace(frame, area, app.section() == MonitorSection::Overview);
        return;
    }
    if matches!(app.page(), Page::Transport | Page::Network) && !app.is_network_route() {
        if let Some(summary) = app.summary() {
            let layer = if app.page() == Page::Transport {
                super::summary::Layer::Transport
            } else {
                super::summary::Layer::Network
            };
            let lines: Vec<_> = summary
                .detail_lines(layer, area.width)
                .into_iter()
                .skip(app.row_offset())
                .take(usize::from(area.height))
                .collect();
            frame.render_widget(Paragraph::new(lines), area);
        }
        return;
    }
    if app.is_network_route() {
        super::network_route::render(
            frame,
            area,
            app.network_route_view(),
            app.network_route_snapshot(),
            app.snapshot(),
            app.time_view(),
            app.detail_metrics_mode(),
        );
        return;
    }
    if app.is_netfilter_view() {
        super::netfilter::render(
            frame,
            area,
            app.netfilter_view(),
            app.snapshot(),
            app.time_view(),
            super::dashboard::DetailDisplayOptions::new(app.time_view(), app.detail_metrics_mode()),
        );
        return;
    }
    if app.is_socket_detail() {
        match app.socket_detail() {
            Some(detail) => super::socket_detail::render(
                frame,
                area,
                detail,
                app.detail_metrics_mode(),
                app.row_offset(),
            ),
            None => frame.render_widget(Paragraph::new("Collecting socket diagnostics..."), area),
        }
        return;
    }
    if app.is_socket_table() {
        match app.socket_snapshot() {
            Some(snapshot) => super::socket::render(
                frame,
                area,
                snapshot,
                app.socket_order(),
                app.selected_socket_key(),
                app.row_offset(),
            ),
            None => frame.render_widget(
                Paragraph::new("Collecting the INET TCP/UDP socket table..."),
                area,
            ),
        }
        return;
    }
    if app.is_conntrack_flows() {
        app.conntrack_view().render(frame, area, app.row_offset());
        return;
    }
    if let Some(kind) = app.detail_layer() {
        match app.snapshot() {
            Some(snapshot) => super::dashboard::render_global_layer_detail(
                frame,
                area,
                snapshot,
                kind,
                super::dashboard::DetailDisplayOptions::new(
                    app.time_view(),
                    app.detail_metrics_mode(),
                ),
                app.row_offset(),
            ),
            None => frame.render_widget(
                Paragraph::new("Collecting the selected layer snapshot..."),
                area,
            ),
        }
        return;
    }
    if let (Some(identity), Some(layer)) = (app.detail_interface(), app.detail_interface_layer()) {
        match app.snapshot() {
            Some(snapshot) => super::dashboard::render_interface_layer_detail(
                frame,
                area,
                snapshot,
                identity,
                layer,
                super::dashboard::DetailDisplayOptions::new(
                    app.time_view(),
                    app.detail_metrics_mode(),
                ),
                app.row_offset(),
            ),
            None => frame.render_widget(
                Paragraph::new("Collecting the selected interface layer snapshot..."),
                area,
            ),
        }
        return;
    }
    if let Some(identity) = app.detail_interface() {
        match app.snapshot() {
            Some(snapshot) => super::dashboard::render_interface_detail(
                frame,
                area,
                snapshot,
                identity,
                app.selected_interface_layer()
                    .expect("interface detail has a selected layer"),
                super::dashboard::DetailDisplayOptions::new(
                    app.time_view(),
                    app.detail_metrics_mode(),
                ),
                app.row_offset(),
            ),
            None => frame.render_widget(
                Paragraph::new("Collecting the selected interface snapshot..."),
                area,
            ),
        }
        return;
    }
    if app.section() == MonitorSection::Overview {
        match app.snapshot() {
            Some(snapshot) => super::dashboard::render_overview(
                frame,
                area,
                snapshot,
                app.time_view(),
                app.row_offset(),
                super::dashboard::InterfaceFilter::new(
                    app.interface_inventory(),
                    app.interface_anchor(),
                    app.interface_name_alias(),
                    app.selected_layer(),
                    app.selected_interface(),
                ),
            ),
            None => super::dashboard::render_starting_overview(
                frame,
                area,
                app.row_offset(),
                app.selected_layer(),
            ),
        }
        return;
    }
    let Some(snapshot) = app.snapshot() else {
        frame.render_widget(
            Paragraph::new("Collecting the first kernel counter snapshot...")
                .block(Block::default().borders(Borders::TOP)),
            area,
        );
        return;
    };
    match app.section() {
        MonitorSection::Providers => render_providers(frame, area, snapshot, app.row_offset()),
        MonitorSection::Softirq => super::dashboard::render_softirq_section(
            frame,
            area,
            snapshot,
            app.softirq_section().expect("SoftIRQ snapshot"),
            app.time_view(),
            app.row_offset(),
        ),
        MonitorSection::Overview => unreachable!("overview returned above"),
        _ => render_metrics(frame, area, app, snapshot),
    }
}

fn render_metrics(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &App,
    snapshot: &crate::monitor::MonitorSnapshot,
) {
    let section = app.section();
    let Some(collection_section) = section.collection_section() else {
        return;
    };
    let rows = if is_interface_grouped(collection_section) {
        grouped_metric_rows(
            app,
            snapshot,
            app.row_offset(),
            usize::from(area.height.saturating_sub(2)),
        )
    } else {
        snapshot
            .series()
            .iter()
            .filter(|row| {
                series_matches_anchor(
                    row.labels(),
                    app.interface_anchor(),
                    app.interface_name_alias(),
                ) && row
                    .metric()
                    .descriptor()
                    .is_some_and(|metric| metric.primary_section == collection_section)
            })
            .skip(app.row_offset())
            .take(usize::from(area.height.saturating_sub(2)))
            .map(|series| metric_row(series, app))
            .collect::<Vec<_>>()
    };
    let time_heading = match app.time_view() {
        TimeView::Interval => "Interval rate/delta",
        TimeView::SinceBaseline => "Since baseline",
    };
    let grouped = is_interface_grouped(collection_section);
    let widths = if grouped {
        vec![
            Constraint::Percentage(40),
            Constraint::Percentage(12),
            Constraint::Percentage(18),
            Constraint::Percentage(12),
            Constraint::Percentage(18),
        ]
    } else {
        vec![
            Constraint::Percentage(40),
            Constraint::Percentage(14),
            Constraint::Percentage(22),
            Constraint::Percentage(24),
        ]
    };
    let mut headings = vec![
        if grouped {
            "Interface / metric"
        } else {
            "Metric"
        },
        if grouped { "Current / PPS" } else { "Current" },
        if grouped {
            "Value / bandwidth"
        } else {
            time_heading
        },
    ];
    if grouped {
        headings.push("Errors/s");
    }
    headings.push(if grouped {
        "State / drops"
    } else {
        "State / source"
    });
    let table = Table::new(rows, widths)
        .header(
            Row::new(headings).style(
                Style::default()
                    .fg(theme::TEXT_STRONG)
                    .bg(theme::CHROME_BG)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .column_spacing(1)
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(theme::DIVIDER))
                .title_style(
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                )
                .title(format!(" {} ", section.as_str())),
        );
    frame.render_widget(table, area);
}

fn grouped_metric_rows(
    app: &App,
    snapshot: &crate::monitor::MonitorSnapshot,
    offset: usize,
    limit: usize,
) -> Vec<Row<'static>> {
    let grouped = app.grouped_section().expect("grouped metric section");
    enum TableRow<'a> {
        Header(&'a super::presentation::InterfaceKey),
        Summary(&'static str, DirectionSummary),
        Metric(&'a SeriesSnapshot),
    }
    grouped
        .interfaces
        .iter()
        .flat_map(|block| {
            [
                TableRow::Header(&block.key),
                TableRow::Summary("RX", block.summary.rx),
                TableRow::Summary("TX", block.summary.tx),
            ]
            .into_iter()
            .chain(
                block
                    .rows
                    .iter()
                    .map(|index| TableRow::Metric(&snapshot.series()[*index])),
            )
        })
        .chain(
            grouped
                .unscoped
                .iter()
                .map(|index| TableRow::Metric(&snapshot.series()[*index])),
        )
        .skip(offset)
        .take(limit)
        .map(|row| match row {
            TableRow::Header(key) => Row::new(vec![
                Cell::from(format!("{}  ifindex {}", key.name(), key.ifindex())),
                Cell::from("RX/TX"),
                Cell::from("interface summary"),
                Cell::from(""),
                Cell::from(""),
            ])
            .style(
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            TableRow::Summary(direction, summary) => interface_summary_row(direction, summary),
            TableRow::Metric(series) => metric_row(series, app),
        })
        .collect()
}

fn interface_summary_row(direction: &str, summary: DirectionSummary) -> Row<'static> {
    Row::new(vec![
        Cell::from(format!("  {direction} summary")),
        Cell::from(format_rate_value(summary.packets_per_second, "pps")),
        Cell::from(
            summary
                .bits_per_second
                .map(format_bit_rate)
                .unwrap_or_else(|| "-".to_owned()),
        ),
        Cell::from(format_rate_value(summary.errors_per_second, "errors/s")),
        Cell::from(format_rate_value(summary.drops_per_second, "drops/s")),
    ])
    .style(Style::default().fg(theme::TEXT_STRONG))
}

fn format_rate_value(value: Option<f64>, suffix: &str) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.1} {suffix}"))
}

fn metric_row(series: &SeriesSnapshot, app: &App) -> Row<'static> {
    let metric = series
        .metric()
        .descriptor()
        .expect("snapshot metric is catalogued");
    let title = format_series_title(series, metric);
    let (current, interval, since, state) = format_series(series, metric);
    let selected_time = match app.time_view() {
        TimeView::Interval => interval,
        TimeView::SinceBaseline => since,
    };
    let mut cells = vec![
        Cell::from(title),
        Cell::from(current),
        Cell::from(selected_time),
    ];
    if app
        .section()
        .collection_section()
        .is_some_and(is_interface_grouped)
    {
        cells.push(Cell::from(""));
    }
    cells.push(Cell::from(format!(
        "{state} {} {}",
        baseline_origin_label(series.baseline_origin()),
        series.source().as_str()
    )));
    Row::new(cells).style(metric_style(metric.display))
}

fn render_providers(
    frame: &mut Frame<'_>,
    area: Rect,
    snapshot: &crate::monitor::MonitorSnapshot,
    row_offset: usize,
) {
    let divided_cells = |values: [String; 6]| {
        let mut cells = Vec::with_capacity(11);
        for (index, value) in values.into_iter().enumerate() {
            if index > 0 {
                cells.push(Cell::from("│").style(Style::default().fg(theme::DIVIDER)));
            }
            cells.push(Cell::from(value));
        }
        cells
    };
    let rows = snapshot
        .providers()
        .iter()
        .map(|provider| {
            let health = provider.health().as_str();
            Row::new(divided_cells([
                provider.provider().as_str().to_owned(),
                health.to_owned(),
                format_duration(provider.last_attempt_at()),
                format_duration(provider.collection_duration()),
                provider.unavailable_readings().to_string(),
                provider_diagnostic(provider.health()).to_owned(),
            ]))
            .style(health_style(health))
        })
        .collect::<Vec<_>>();
    let rows = visible_rows(rows, row_offset);
    frame.render_widget(
        Table::new(
            rows,
            [
                Constraint::Fill(30),
                Constraint::Length(1),
                Constraint::Fill(16),
                Constraint::Length(1),
                Constraint::Fill(10),
                Constraint::Length(1),
                Constraint::Fill(10),
                Constraint::Length(1),
                Constraint::Fill(8),
                Constraint::Length(1),
                Constraint::Fill(26),
            ],
        )
        .column_spacing(0)
        .header(
            Row::new(divided_cells(
                ["Provider", "Health", "Attempt", "Cost", "Missing", "Detail"].map(str::to_owned),
            ))
            .style(
                Style::default()
                    .fg(theme::TEXT_STRONG)
                    .bg(theme::CHROME_BG)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(theme::DIVIDER))
                .title_style(
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                )
                .title(" Collection providers "),
        ),
        area,
    );
}

fn provider_diagnostic(health: &ProviderHealth) -> &str {
    match health {
        ProviderHealth::Fresh => "-",
        ProviderHealth::Partial { warning } => warning.diagnostic(),
        ProviderHealth::Stale { cause, .. } => cause.diagnostic(),
        ProviderHealth::Unsupported { reason } | ProviderHealth::PermissionDenied { reason } => {
            reason.diagnostic()
        }
        ProviderHealth::Error { error } => error.diagnostic(),
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    if let Some(input) = app.route_lookup_input() {
        let mut lines = vec![Line::from(vec![
            Span::styled(
                ">",
                Style::default()
                    .fg(Color::Black)
                    .bg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(input.to_owned(), Style::default().fg(theme::TEXT_STRONG)),
        ])];
        if let Some(error) = app.route_lookup_error() {
            lines.push(Line::styled(
                error.to_owned(),
                Style::default().fg(theme::BAD),
            ));
        }
        frame.render_widget(
            Paragraph::new(lines).style(Style::default().bg(theme::FOOTER_BG)),
            area,
        );
    } else if let Some(filter) = app
        .flow_filter_input()
        .or_else(|| app.socket_filter_input())
    {
        let mut lines = vec![Line::from(vec![
            Span::styled(
                "/",
                Style::default()
                    .fg(Color::Black)
                    .bg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(filter.to_owned(), Style::default().fg(theme::TEXT_STRONG)),
        ])];
        if let Some(error) = app
            .flow_filter_error()
            .or_else(|| app.socket_filter_error())
        {
            lines.push(Line::styled(
                error.to_owned(),
                Style::default().fg(theme::BAD),
            ));
        } else {
            lines.push(Line::styled(
                if app.is_socket_table() {
                    " host IP | net CIDR | port N | and/or/not | src/dst: local/remote"
                } else {
                    " host IP | net CIDR | port N | and/or/not | src/dst: original"
                },
                Style::default().fg(theme::TEXT),
            ));
        }
        frame.render_widget(
            Paragraph::new(lines).style(Style::default().bg(theme::FOOTER_BG)),
            area,
        );
    } else if let Some(command) = app.command() {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    ":",
                    Style::default()
                        .fg(Color::Black)
                        .bg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(command.to_owned(), Style::default().fg(theme::TEXT_STRONG)),
            ]))
            .style(Style::default().bg(theme::FOOTER_BG)),
            area,
        );
    } else if let Some(error) = app.command_error() {
        frame.render_widget(
            Paragraph::new(error)
                .style(Style::default().fg(theme::BAD).bg(theme::FOOTER_BG))
                .wrap(Wrap { trim: true }),
            area,
        );
    } else {
        let help = if app.section() == MonitorSection::Hardirq {
            " j/k scroll  s sort  r reverse  Pg page  p pause  Esc back  q quit ".to_owned()
        } else if app.is_softirq_view() {
            let target = match app.detail_metrics_mode() {
                DetailMetricsMode::WithData => "all",
                DetailMetricsMode::All => "data",
            };
            if area.width < 100 {
                format!(" j/k scroll s sort r reverse a {target} t time Esc back q quit ")
            } else {
                format!(
                    " j/k scroll  s sort  r reverse  Pg page  a {target}  p pause  t time  Esc back  q quit "
                )
            }
        } else if app.is_tc_view() {
            if app.tc_view().detail() {
                " j/k scroll  Esc back  Pg page  v metrics  p pause  q quit ".to_owned()
            } else if area.width < 100 {
                " j/k select Enter detail s sort r reverse v metrics Esc back ".to_owned()
            } else {
                " j/k select  Enter detail  s sort  r reverse  v metrics  Pg page  Esc overview  p pause  q quit ".to_owned()
            }
        } else if app.is_netdev_table() {
            if area.width < 100 {
                " j/k select Enter detail s sort r reverse Pg page Esc back ".to_owned()
            } else {
                " j/k select  Enter detail  s sort  r reverse  Pg page  Esc overview  p pause  t time  q quit ".to_owned()
            }
        } else if app.is_netfilter_view() {
            if area.width < 100 {
                app.netfilter_view().compact_footer_help().to_owned()
            } else {
                format!(
                    "{} p pause  t time  q quit ",
                    app.netfilter_view().footer_help()
                )
            }
        } else if app.is_network_route() {
            format!(
                "{} p pause  t time  q quit ",
                app.network_route_view().footer_help()
            )
        } else if app.is_socket_detail() {
            let metric_target = match app.detail_metrics_mode() {
                DetailMetricsMode::WithData => "all",
                DetailMetricsMode::All => "data",
            };
            if area.width < 83 {
                format!(" j/k scroll Esc sockets Pg a {metric_target} p pause q quit ")
            } else {
                format!(
                    " j/k scroll  Esc sockets  PgUp/PgDn page  a {metric_target}  p pause  q quit "
                )
            }
        } else if app.is_socket_table() {
            if area.width >= 120 {
                " j/k select Enter detail / filter Ctrl+u clear s sort r reverse Esc back Pg page p pause q quit ".to_owned()
            } else if area.width < 70 {
                " j/k select Enter detail s sort r reverse Esc back q quit ".to_owned()
            } else if area.width < 83 {
                " j/k select Enter detail s sort r reverse Esc back p pause q quit ".to_owned()
            } else {
                " j/k select  Enter detail  s sort  r reverse  Esc socket  Pg page  p pause  q quit ".to_owned()
            }
        } else if app.is_conntrack_flows() {
            if !app.is_conntrack_list() {
                " j/k scroll  Esc flows  PgUp/PgDn page  / filter  p pause  q quit ".to_owned()
            } else if area.width >= 120 {
                " j/k select Enter detail / filter Ctrl+u clear s sort r reverse d diagnostics Esc back Pg page p pause q quit ".to_owned()
            } else if area.width < 100 {
                " j/k select Enter detail / filter s sort r reverse Esc back ".to_owned()
            } else {
                " j/k select Enter detail / filter s sort r reverse d diagnostics Esc back Pg page p pause q quit "
                    .to_owned()
            }
        } else if app.is_interface_detail() {
            let metric_target = match app.detail_metrics_mode() {
                DetailMetricsMode::WithData => "all",
                DetailMetricsMode::All => "data",
            };
            if area.width < 83 {
                format!(" j/k select Enter layer Esc overview Pg a {metric_target} p pause q quit ")
            } else {
                format!(
                    " j/k select layer  Enter details  Esc overview  PgUp/PgDn page  a {metric_target}  p pause  t time  q quit "
                )
            }
        } else if app.is_interface_layer_detail() {
            let metric_target = match app.detail_metrics_mode() {
                DetailMetricsMode::WithData => "all",
                DetailMetricsMode::All => "data",
            };
            if area.width < 83 {
                format!(" j/k scroll Esc layers Pg a {metric_target} p pause q quit ")
            } else {
                format!(
                    " j/k scroll  Esc layers  PgUp/PgDn page  a {metric_target}  p pause  t time  q quit "
                )
            }
        } else if app.can_open_socket_table() || app.can_open_conntrack_flows() {
            let target = if app.can_open_socket_table() {
                "sockets"
            } else {
                "flows"
            };
            if app.is_overview_detail() {
                let metric_target = match app.detail_metrics_mode() {
                    DetailMetricsMode::WithData => "all",
                    DetailMetricsMode::All => "data",
                };
                if area.width < 83 {
                    format!(
                        " j/k scroll Enter {target} Esc back Pg a {metric_target} p pause q quit "
                    )
                } else {
                    format!(
                        " j/k scroll Enter {target} Esc overview Pg page a {metric_target} p pause t time q quit "
                    )
                }
            } else if area.width < 83 {
                format!(" j/k scroll Enter {target} Esc back Pg page p pause q quit ")
            } else {
                format!(" j/k scroll Enter {target} Esc overview Pg page p pause t time q quit ")
            }
        } else if app.is_overview_detail() {
            let metric_target = match app.detail_metrics_mode() {
                DetailMetricsMode::WithData => "all",
                DetailMetricsMode::All => "data",
            };
            if area.width < 83 {
                format!(" j/k scroll Esc back Pg a {metric_target} p pause t time q quit ")
            } else {
                format!(
                    " j/k scroll Esc overview Pg page a {metric_target} : cmd p pause t time q quit "
                )
            }
        } else if app.is_detail() {
            if area.width < 83 {
                " j/k scroll Esc back Pg page p pause t time q quit ".to_owned()
            } else {
                " j/k scroll  Esc overview  PgUp/PgDn page  : cmd  p pause  t time  q quit "
                    .to_owned()
            }
        } else if app.section() == MonitorSection::Overview {
            if area.width < 100 {
                " j/k select Enter open Pg page p pause t time q quit ".to_owned()
            } else {
                " j/k select layer/interface  Enter details  PgUp/PgDn page  : cmd  p pause  t time  q quit ".to_owned()
            }
        } else if area.width < 70 {
            " j/k scroll Pg page : cmd p pause t time q quit ".to_owned()
        } else {
            " j/k scroll  PgUp/PgDn page  : cmd  p pause  t time  q quit ".to_owned()
        };
        frame.render_widget(
            Paragraph::new(footer_help_line(&help))
                .style(Style::default().fg(theme::TEXT).bg(theme::FOOTER_BG)),
            area,
        );
    }
}

fn footer_help_line(help: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let mut start = 0;
    let mut in_whitespace = help.chars().next().is_none_or(char::is_whitespace);
    for (index, character) in help.char_indices() {
        if character.is_whitespace() == in_whitespace {
            continue;
        }
        spans.push(footer_help_span(&help[start..index], in_whitespace));
        start = index;
        in_whitespace = !in_whitespace;
    }
    spans.push(footer_help_span(&help[start..], in_whitespace));
    Line::from(spans)
}

fn footer_help_span(value: &str, whitespace: bool) -> Span<'static> {
    if whitespace {
        return Span::raw(value.to_owned());
    }
    if matches!(
        value,
        "j/k" | "Esc" | "Enter" | "Pg" | "PgUp/PgDn" | ":" | "/" | "a" | "p" | "h" | "t" | "q"
    ) {
        Span::styled(
            value.to_owned(),
            Style::default()
                .fg(Color::Black)
                .bg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(value.to_owned(), Style::default().fg(theme::TEXT))
    }
}

pub(super) fn baseline_origin_label(origin: BaselineOrigin) -> &'static str {
    match origin {
        BaselineOrigin::SessionStart => "start",
        BaselineOrigin::FirstObserved => "first-seen",
        BaselineOrigin::Reset => "reset-base",
        BaselineOrigin::RecoveredAfterGap => "gap-base",
    }
}

pub(super) fn format_series_title(
    series: &SeriesSnapshot,
    metric: &crate::monitor::MetricDescriptor,
) -> String {
    format_metric_title(metric, series.labels())
}

fn format_metric_title(metric: &MetricDescriptor, labels: &MetricLabels) -> String {
    if matches!(
        metric.id,
        crate::monitor::RAW_PRIVATE_NIC_METRIC_ID | crate::monitor::RAW_NIC_SETTING_METRIC_ID
    ) {
        if let Some(statistic) = labels.get(MetricLabel::Statistic) {
            return match labels.get(MetricLabel::Interface) {
                Some(interface) => format!("{statistic}  {interface}"),
                None => statistic.to_owned(),
            };
        }
    }

    if let (Some(row_id), Some(qdisc_kind)) = (
        labels.get(MetricLabel::RowId),
        labels.get(MetricLabel::QdiscKind),
    ) {
        let title = metric.title.strip_prefix("TC ").unwrap_or(metric.title);
        let direction = labels
            .get(MetricLabel::Direction)
            .map(compact_direction)
            .unwrap_or("-");
        let interface = labels.get(MetricLabel::Interface).unwrap_or("-");
        return format!("r{row_id} {title} {direction} {qdisc_kind} {interface}");
    }

    let mut identity = Vec::new();
    if let Some(interface) = labels.get(MetricLabel::Interface) {
        identity.push(interface.to_owned());
    } else if let Some(ifindex) = labels.get(MetricLabel::Ifindex) {
        identity.push(format!("if{ifindex}"));
    }
    if let Some(cpu) = labels.get(MetricLabel::Cpu) {
        identity.push(format!("cpu{cpu}"));
    }
    if let Some(protocol) = labels.get(MetricLabel::Protocol) {
        identity.push(protocol.to_owned());
    }
    if let Some(direction) = labels.get(MetricLabel::Direction) {
        identity.push(compact_direction(direction).to_owned());
    }
    for label in [
        MetricLabel::Family,
        MetricLabel::Table,
        MetricLabel::Chain,
        MetricLabel::Verdict,
        MetricLabel::Action,
    ] {
        if let Some(value) = labels.get(label) {
            identity.push(value.to_owned());
        }
    }

    if identity.is_empty() {
        metric.title.to_owned()
    } else {
        format!("{}  {}", metric.title, identity.join(" "))
    }
}

fn compact_direction(direction: &str) -> &str {
    match direction {
        "ingress" => "rx",
        "egress" => "tx",
        value => value,
    }
}

fn visible_rows<T>(rows: Vec<T>, requested_offset: usize) -> impl Iterator<Item = T> {
    let offset = requested_offset.min(rows.len().saturating_sub(1));
    rows.into_iter().skip(offset)
}

pub(super) fn format_series(
    series: &SeriesSnapshot,
    metric: &MetricDescriptor,
) -> (String, String, String, &'static str) {
    let unit = metric.unit;
    match series.value() {
        SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        } => {
            let (current, state) = format_projected(current, unit);
            let interval = match interval {
                Some(CounterContinuity::Continuous { delta, .. }) => {
                    format!(
                        "+{delta}  {}",
                        format_rate(interval.and_then(|v| v.rate_per_second()), metric)
                    )
                }
                Some(CounterContinuity::Wrapped { delta, .. }) => {
                    format!("+{delta} wrap")
                }
                Some(CounterContinuity::Reset) => "reset".to_owned(),
                Some(CounterContinuity::RecoveredAfterGap) => "gap recovery".to_owned(),
                Some(CounterContinuity::FirstSample) | None => "-".to_owned(),
            };
            let since = since_baseline
                .map(|span| {
                    format!(
                        "+{}  {}",
                        span.delta(),
                        format_rate(Some(span.rate_per_second()), metric)
                    )
                })
                .unwrap_or_else(|| "-".to_owned());
            (current, interval, since, state)
        }
        SeriesValue::Gauge {
            current,
            interval,
            since_baseline,
        } => {
            let (current, state) = format_projected(current, unit);
            let interval = interval
                .map(|change| {
                    format!(
                        "{:+}  {}",
                        change.delta(),
                        format_rate(Some(change.rate_per_second()), metric)
                    )
                })
                .unwrap_or_else(|| "-".to_owned());
            let since = since_baseline
                .map(|summary| format!("min {} max {}", summary.min(), summary.max()))
                .unwrap_or_else(|| "-".to_owned());
            (current, interval, since, state)
        }
        SeriesValue::State {
            current,
            continuous_for,
            ..
        } => {
            let (current, state) = match current {
                ProjectedValue::Fresh { value, .. } => (value.as_str().to_owned(), "fresh"),
                ProjectedValue::Stale { last, .. } => (last.as_str().to_owned(), "stale"),
                ProjectedValue::Unavailable { .. } => ("-".to_owned(), "unavailable"),
            };
            let since = continuous_for
                .map(format_duration)
                .unwrap_or_else(|| "-".to_owned());
            (current, "-".to_owned(), since, state)
        }
    }
}

fn format_projected(value: &ProjectedValue<u64>, unit: MetricUnit) -> (String, &'static str) {
    match value {
        ProjectedValue::Fresh { value, .. } => (format_value(*value, unit), "fresh"),
        ProjectedValue::Stale { last, .. } => (format!("~{}", format_value(*last, unit)), "stale"),
        ProjectedValue::Unavailable { .. } => ("-".to_owned(), "unavailable"),
    }
}

pub(super) fn format_value(value: u64, unit: MetricUnit) -> String {
    match unit {
        MetricUnit::Bytes if value >= 1 << 30 => {
            format!("{:.1} GiB", value as f64 / (1_u64 << 30) as f64)
        }
        MetricUnit::Bytes if value >= 1 << 20 => {
            format!("{:.1} MiB", value as f64 / (1_u64 << 20) as f64)
        }
        MetricUnit::Bytes if value >= 1 << 10 => {
            format!("{:.1} KiB", value as f64 / (1_u64 << 10) as f64)
        }
        MetricUnit::Bytes => format!("{value} B"),
        MetricUnit::Pages => format!("{value} pages"),
        MetricUnit::BasisPoints => format!("{:.2}%", value as f64 / 100.0),
        MetricUnit::Occurrences | MetricUnit::SourceUnits | MetricUnit::State => value.to_string(),
    }
}

pub(super) fn format_rate(rate: Option<f64>, metric: &MetricDescriptor) -> String {
    let Some(value) = rate else {
        return "-".to_owned();
    };
    if metric.unit == MetricUnit::Bytes {
        return format_bit_rate(value * 8.0);
    }
    match metric.display {
        DisplayMeaning::Error => return format!("{value:.1} errors/s"),
        DisplayMeaning::Drop => return format!("{value:.1} drops/s"),
        _ => {}
    }
    match metric.domain {
        AggregationDomain::InterfacePacket | AggregationDomain::WireFrame => {
            format!("{value:.1} pps")
        }
        AggregationDomain::Interrupt => format!("{value:.1} irq/s"),
        _ => format!("{value:.1}/s"),
    }
}

fn format_bit_rate(bits_per_second: f64) -> String {
    const KILO: f64 = 1_000.0;
    const MEGA: f64 = 1_000_000.0;
    const GIGA: f64 = 1_000_000_000.0;
    if bits_per_second >= GIGA {
        format!("{:.1} Gbit/s", bits_per_second / GIGA)
    } else if bits_per_second >= MEGA {
        format!("{:.1} Mbit/s", bits_per_second / MEGA)
    } else if bits_per_second >= KILO {
        format!("{:.1} kbit/s", bits_per_second / KILO)
    } else {
        format!("{bits_per_second:.0} bit/s")
    }
}

fn format_duration(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 3_600 {
        format!("{}h{:02}m", seconds / 3_600, seconds / 60 % 60)
    } else if seconds >= 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else if seconds > 0 {
        format!("{seconds}s")
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub(super) fn metric_style(meaning: DisplayMeaning) -> Style {
    match meaning {
        DisplayMeaning::Drop => Style::default().fg(theme::BAD),
        DisplayMeaning::Error => Style::default().fg(theme::WARN),
        DisplayMeaning::Pressure => Style::default().fg(Color::LightMagenta),
        DisplayMeaning::Correction => Style::default().fg(theme::GOOD),
        DisplayMeaning::Activity
        | DisplayMeaning::Capacity
        | DisplayMeaning::State
        | DisplayMeaning::InformationOnly => Style::default().fg(theme::TEXT),
    }
}

fn health_style(health: &str) -> Style {
    match health {
        "ACTIVE" | "fresh" => Style::default().fg(theme::GOOD),
        "PARTIAL" | "DEGRADED" | "UNAVAILABLE" | "partial" | "stale" | "permission_denied" => {
            Style::default().fg(theme::WARN)
        }
        "ERROR" | "error" => Style::default().fg(theme::BAD),
        _ => Style::default().fg(theme::MUTED),
    }
}

#[cfg(test)]
pub(in crate::tui) mod tests {
    use crate::monitor::dashboard::PacketStage;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;
    use crate::monitor::{descriptor, MetricLabel, MetricLabels};
    use crate::tui::app::workspace::LAYERS as OVERVIEW_LAYER_KINDS;
    use crate::tui::app::Action;

    fn link_sample(at: u64, base: u64) -> crate::monitor::ProviderSample {
        let metrics = [
            ("linux.netdevice.rx_packets", 10_u64),
            ("linux.netdevice.rx_bytes", 100),
            ("linux.netdevice.rx_errors", 1),
            ("linux.netdevice.rx_dropped", 2),
            ("linux.netdevice.tx_packets", 20),
            ("linux.netdevice.tx_bytes", 200),
            ("linux.netdevice.tx_errors", 3),
            ("linux.netdevice.tx_dropped", 4),
            ("linux.nic.rx_crc_errors", 5),
        ];
        let mut readings = Vec::new();
        for (interface_index, (interface, ifindex, scale)) in
            [(0_u64, ("eth0", "2", 1_u64)), (1, ("eth1", "3", 10))]
        {
            for (metric_index, (metric, delta)) in metrics.iter().enumerate() {
                readings.push(crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new(*metric).unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, interface.to_owned()),
                        (MetricLabel::Ifindex, ifindex.to_owned()),
                    ])
                    .unwrap(),
                    crate::monitor::MetricReading::Counter {
                        value: base
                            .saturating_add(interface_index * 10_000)
                            .saturating_add(metric_index as u64 * 100)
                            .saturating_add(at.saturating_sub(1) * delta * scale),
                        bits: Some(crate::monitor::CounterBits::Bits64),
                    },
                ));
            }
        }
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.rtnetlink.link_stats").unwrap(),
            std::time::Duration::from_secs(at),
            std::time::Duration::from_millis(1),
            ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    fn nic_state_sample(at: u64) -> crate::monitor::ProviderSample {
        let readings = [
            ("eth0", "2", "physical", "up"),
            ("eth1", "3", "virtual", "up"),
        ]
        .into_iter()
        .flat_map(|(interface, ifindex, kind, state)| {
            let labels = MetricLabels::new([
                (MetricLabel::Interface, interface.to_owned()),
                (MetricLabel::Ifindex, ifindex.to_owned()),
            ])
            .unwrap();
            [
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.nic.interface_kind").unwrap(),
                    labels.clone(),
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(kind).unwrap(),
                    ),
                ),
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.nic.link_state").unwrap(),
                    labels,
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(state).unwrap(),
                    ),
                ),
            ]
        })
        .collect();
        provider_sample("linux.sysfs.net.nic", at, readings)
    }

    fn nic_speed_sample(at: u64) -> crate::monitor::ProviderSample {
        let readings = [
            ("Speed", "10000Mb/s"),
            ("Driver", "ixgbe"),
            ("RX Queues", "8"),
            ("TX Queues", "8"),
            ("Ring RX", "1024"),
            ("Ring TX", "512"),
            ("TX Queue Length", "1000"),
            ("Duplex", "Full"),
            ("Flow Control RX", "on"),
            ("Flow Control TX", "off"),
            ("TSO", "on"),
            ("LRO", "off"),
            ("GRO", "on"),
            ("GSO", "on"),
        ]
        .into_iter()
        .map(|(statistic, value)| {
            crate::monitor::SampleReading::observed(
                crate::monitor::MetricId::new(crate::monitor::RAW_NIC_SETTING_METRIC_ID).unwrap(),
                MetricLabels::new([
                    (MetricLabel::Interface, "eth0".to_owned()),
                    (MetricLabel::Ifindex, "2".to_owned()),
                    (MetricLabel::Statistic, statistic.to_owned()),
                ])
                .unwrap(),
                crate::monitor::MetricReading::State(
                    crate::monitor::StateValue::new(value).unwrap(),
                ),
            )
        })
        .collect();
        provider_sample("linux.ethtool.link_text", at, readings)
    }

    fn nic_statistics_status_sample(at: u64) -> crate::monitor::ProviderSample {
        let readings = [("eth0", "2", "timed_out"), ("eth1", "3", "complete")]
            .into_iter()
            .map(|(interface, ifindex, status)| {
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new(
                        crate::monitor::NIC_ETHTOOL_STATISTICS_STATUS_METRIC_ID,
                    )
                    .unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, interface.to_owned()),
                        (MetricLabel::Ifindex, ifindex.to_owned()),
                    ])
                    .unwrap(),
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(status).unwrap(),
                    ),
                )
            })
            .collect();
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.ethtool.text").unwrap(),
            std::time::Duration::from_secs(at),
            std::time::Duration::from_millis(1),
            ProviderHealth::Partial {
                warning: crate::monitor::MonitorError::new(
                    crate::monitor::MonitorErrorCode::Timeout,
                    "eth0 statistics timed out",
                )
                .unwrap(),
            },
            readings,
        )
        .unwrap()
    }

    fn counter_reading(
        metric: &str,
        labels: MetricLabels,
        value: u64,
    ) -> crate::monitor::SampleReading {
        crate::monitor::SampleReading::observed(
            crate::monitor::MetricId::new(metric).unwrap(),
            labels,
            crate::monitor::MetricReading::Counter { value, bits: None },
        )
    }

    fn gauge_reading(metric: &str, value: u64) -> crate::monitor::SampleReading {
        crate::monitor::SampleReading::observed(
            crate::monitor::MetricId::new(metric).unwrap(),
            MetricLabels::default(),
            crate::monitor::MetricReading::Gauge(value),
        )
    }

    fn provider_sample(
        provider: &str,
        at: u64,
        readings: Vec<crate::monitor::SampleReading>,
    ) -> crate::monitor::ProviderSample {
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new(provider).unwrap(),
            std::time::Duration::from_secs(at),
            std::time::Duration::from_millis(1),
            ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    fn open_first_interface_detail(app: &mut App) {
        app.update(Action::SelectPage(Page::Overview));
        app.update(Action::ScrollTop);
        for _ in 0..OVERVIEW_LAYER_KINDS.len() {
            app.update(Action::SelectNextOverviewItem);
        }
        assert!(app.selected_interface().is_some());
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.detail_interface().is_some());
    }

    fn open_interface_layer_detail(app: &mut App, layer: crate::monitor::dashboard::BlockKind) {
        for _ in 0..super::super::dashboard::INTERFACE_BLOCK_KINDS.len() {
            if app.selected_interface_layer() == Some(layer) {
                break;
            }
            app.update(Action::SelectNextInterfaceLayer);
        }
        assert_eq!(app.selected_interface_layer(), Some(layer));
        app.update(Action::OpenSelectedInterfaceLayer);
        assert_eq!(app.detail_interface_layer(), Some(layer));
    }

    fn render_all_workspace_rows(app: &mut App, width: u16, height: u16) -> String {
        app.set_viewport_size(width, body_rows(Rect::new(0, 0, width, height), app));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut rendered = String::new();
        for _ in 0..1_024 {
            terminal.draw(|frame| render(frame, app)).unwrap();
            rendered.push_str(&terminal.backend().to_string());
            let previous = app.row_offset();
            app.update(Action::PageDown);
            if app.row_offset() == previous {
                return rendered;
            }
        }
        panic!("page navigation did not reach the final row");
    }

    fn assert_metric_cell(rendered: &str, label: &str, expected: f64) {
        let row = rendered
            .lines()
            .find(|row| row.contains(label))
            .unwrap_or_else(|| panic!("missing {label}:\n{rendered}"));
        let value = row[row.find(label).unwrap() + label.len()..]
            .split_whitespace()
            .next()
            .unwrap()
            .trim_matches('"');
        assert_eq!(
            value.parse::<f64>().ok(),
            Some(expected),
            "{label}:\n{rendered}"
        );
    }

    fn failed_provider_sample(provider: &str, at: u64) -> crate::monitor::ProviderSample {
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new(provider).unwrap(),
            std::time::Duration::from_secs(at),
            std::time::Duration::from_millis(1),
            ProviderHealth::Error {
                error: crate::monitor::MonitorError::new(
                    crate::monitor::MonitorErrorCode::Timeout,
                    "fixture timeout",
                )
                .unwrap(),
            },
            Vec::new(),
        )
        .unwrap()
    }

    fn interface_gauge_samples(
        at: u64,
        backlog: u64,
        imbalance: u64,
    ) -> Vec<crate::monitor::ProviderSample> {
        let interface = "eth0";
        let ifindex = "2";
        let tc_labels = MetricLabels::new([
            (MetricLabel::Interface, interface.to_owned()),
            (MetricLabel::Ifindex, ifindex.to_owned()),
            (MetricLabel::Direction, "egress".to_owned()),
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::QdiscKind, "fq_codel".to_owned()),
            (MetricLabel::RowId, "1".to_owned()),
            (MetricLabel::Execution, "software".to_owned()),
        ])
        .unwrap();
        let hardirq_labels = MetricLabels::new([
            (MetricLabel::Interface, interface.to_owned()),
            (MetricLabel::Ifindex, ifindex.to_owned()),
        ])
        .unwrap();
        vec![
            provider_sample(
                "linux.tc.json",
                at,
                vec![crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.tc.backlog_bytes").unwrap(),
                    tc_labels,
                    crate::monitor::MetricReading::Gauge(backlog),
                )],
            ),
            provider_sample(
                "linux.proc.interrupts",
                at,
                vec![crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.hardirq.imbalance").unwrap(),
                    hardirq_labels,
                    crate::monitor::MetricReading::Gauge(imbalance),
                )],
            ),
        ]
    }

    fn global_dashboard_samples(at: u64) -> Vec<crate::monitor::ProviderSample> {
        let counter = |metric, base, delta| {
            counter_reading(
                metric,
                MetricLabels::default(),
                base + at.saturating_mul(delta),
            )
        };
        let cpu_counter = |metric, cpu: u64, base, delta| {
            counter_reading(
                metric,
                MetricLabels::new([(MetricLabel::Cpu, cpu.to_string())]).unwrap(),
                base + at.saturating_mul(delta),
            )
        };
        vec![
            provider_sample(
                "linux.proc.net.snmp",
                at,
                vec![
                    gauge_reading("linux.socket.tcp.current_established", 42),
                    counter("linux.socket.tcp.segments_in", 1_000, 100),
                    counter("linux.socket.tcp.segments_out", 900, 90),
                    counter("linux.socket.tcp.retransmitted_segments", 10, 2),
                    counter("linux.socket.udp.datagrams_in", 500, 30),
                    counter("linux.socket.udp.datagrams_out", 450, 25),
                    counter("linux.socket.ip.receives", 2_000, 120),
                    counter("linux.socket.ip.delivers", 1_900, 115),
                    counter("linux.socket.ip.output_requests", 1_800, 110),
                    counter("linux.socket.ip.input_errors", 0, 0),
                    counter("linux.socket.ip.output_discards", 0, 0),
                    counter("linux.socket.udp.send_buffer_errors", 0, 0),
                ],
            ),
            provider_sample(
                "linux.proc.net.netstat",
                at,
                vec![
                    counter("linux.socket.tcp.listen_drops", 0, 0),
                    counter("linux.socket.tcp.listen_overflows", 0, 0),
                ],
            ),
            provider_sample(
                "linux.proc.net.sockstat",
                at,
                vec![
                    gauge_reading("linux.socket.used", 184),
                    gauge_reading("linux.socket.tcp.in_use", 42),
                    gauge_reading("linux.socket.tcp.memory_pages", 4_608),
                ],
            ),
            provider_sample(
                "linux.proc.netfilter.conntrack",
                at,
                vec![
                    gauge_reading("linux.netfilter.conntrack.count", 18_420),
                    gauge_reading("linux.netfilter.conntrack.maximum", 262_144),
                    gauge_reading("linux.netfilter.conntrack.utilization", 8_500),
                    cpu_counter("linux.netfilter.conntrack.invalid", 0, 0, 0),
                    cpu_counter("linux.netfilter.conntrack.invalid", 1, 0, 0),
                ],
            ),
            provider_sample(
                "linux.proc.softirqs",
                at,
                vec![
                    cpu_counter("linux.softirq.net_rx", 0, 10_000, 40),
                    cpu_counter("linux.softirq.net_rx", 1, 11_000, 44),
                    cpu_counter("linux.softirq.net_tx", 0, 8_000, 30),
                    cpu_counter("linux.softirq.net_tx", 1, 9_000, 32),
                ],
            ),
            provider_sample(
                "linux.proc.net.softnet_stat",
                at,
                vec![
                    cpu_counter("linux.softirq.softnet.processed", 0, 20_000, 100),
                    cpu_counter("linux.softirq.softnet.processed", 1, 22_000, 110),
                    cpu_counter("linux.softirq.softnet.dropped", 0, 0, 0),
                    cpu_counter("linux.softirq.softnet.dropped", 1, 0, 0),
                    cpu_counter("linux.softirq.softnet.time_squeeze", 0, 0, 0),
                    cpu_counter("linux.softirq.softnet.time_squeeze", 1, 0, 0),
                ],
            ),
        ]
    }

    fn global_dashboard_snapshot() -> std::sync::Arc<crate::monitor::MonitorSnapshot> {
        let interval = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        engine
            .ingest(
                std::time::Duration::from_secs(1),
                global_dashboard_samples(1),
                Some("net:[42]".to_owned()),
            )
            .unwrap();
        engine
            .ingest(
                std::time::Duration::from_secs(2),
                global_dashboard_samples(2),
                Some("net:[42]".to_owned()),
            )
            .unwrap()
    }

    pub(in crate::tui) fn full_dashboard_snapshot(
    ) -> std::sync::Arc<crate::monitor::MonitorSnapshot> {
        full_dashboard_snapshot_with_samples(2)
    }

    fn full_dashboard_snapshot_with_samples(
        sample_count: u64,
    ) -> std::sync::Arc<crate::monitor::MonitorSnapshot> {
        let interval = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let samples = |at| {
            let mut samples = global_dashboard_samples(at);
            samples.extend([
                link_sample(at, 1_000),
                nic_state_sample(at),
                nic_speed_sample(at),
                tc_sample(at),
                hardirq_sample(at),
            ]);
            samples
        };
        (1..=sample_count)
            .map(|at| {
                engine
                    .ingest(
                        std::time::Duration::from_secs(at),
                        samples(at),
                        Some("net:[42]".to_owned()),
                    )
                    .unwrap()
            })
            .last()
            .expect("at least one dashboard sample")
    }

    fn downstream_sample(
        provider: &str,
        at: u64,
        metric: &str,
        labels_for: impl Fn(&str, &str, u64) -> MetricLabels,
    ) -> crate::monitor::ProviderSample {
        let readings = [("eth0", "2", 1_u64), ("eth1", "3", 2)]
            .into_iter()
            .map(|(interface, ifindex, identity)| {
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new(metric).unwrap(),
                    labels_for(interface, ifindex, identity),
                    crate::monitor::MetricReading::Counter {
                        value: 1_000 + identity * 100 + at * identity,
                        bits: None,
                    },
                )
            })
            .collect();
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new(provider).unwrap(),
            std::time::Duration::from_secs(at),
            std::time::Duration::from_millis(1),
            ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    fn tc_sample(at: u64) -> crate::monitor::ProviderSample {
        downstream_sample(
            "linux.tc.json",
            at,
            "linux.tc.packets",
            |interface, ifindex, identity| {
                MetricLabels::new([
                    (MetricLabel::Interface, interface.to_owned()),
                    (MetricLabel::Ifindex, ifindex.to_owned()),
                    (MetricLabel::Direction, "egress".to_owned()),
                    (MetricLabel::ObjectKind, "qdisc".to_owned()),
                    (MetricLabel::QdiscKind, "fq_codel".to_owned()),
                    (MetricLabel::RowId, identity.to_string()),
                    (MetricLabel::Execution, "software".to_owned()),
                ])
                .unwrap()
            },
        )
    }

    fn hardirq_sample(at: u64) -> crate::monitor::ProviderSample {
        downstream_sample(
            "linux.proc.interrupts",
            at,
            "linux.hardirq.network_interrupts",
            |interface, ifindex, identity| {
                MetricLabels::new([
                    (MetricLabel::Interface, interface.to_owned()),
                    (MetricLabel::Ifindex, ifindex.to_owned()),
                    (MetricLabel::Cpu, (identity - 1).to_string()),
                    (MetricLabel::InterruptClass, "msi".to_owned()),
                ])
                .unwrap()
            },
        )
    }

    fn nic_settings_sample(count: usize) -> crate::monitor::ProviderSample {
        let readings = (0..count)
            .map(|index| {
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new(crate::monitor::RAW_NIC_SETTING_METRIC_ID)
                        .unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, "eth0".to_owned()),
                        (MetricLabel::Ifindex, "2".to_owned()),
                        (MetricLabel::Statistic, format!("setting_{index:03}")),
                    ])
                    .unwrap(),
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(format!("value-{index}")).unwrap(),
                    ),
                )
            })
            .collect();
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.ethtool.link_text").unwrap(),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(1),
            ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    #[test]
    fn byte_counter_rates_are_rendered_as_network_bandwidth() {
        let metric = descriptor("linux.netdevice.rx_bytes").unwrap();
        assert_eq!(format_rate(Some(125_000.0), metric), "1.0 Mbit/s");
    }

    #[test]
    fn compact_titles_keep_dynamic_row_identity_visible() {
        let qdisc = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Direction, "egress".to_owned()),
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::QdiscKind, "pfifo_fast".to_owned()),
            (MetricLabel::RowId, "7".to_owned()),
            (MetricLabel::Execution, "software".to_owned()),
        ])
        .unwrap();
        assert_eq!(
            format_metric_title(descriptor("linux.tc.backlog_bytes").unwrap(), &qdisc),
            "r7 backlog bytes tx pfifo_fast eth0"
        );

        let raw_nic = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
            (MetricLabel::Statistic, "vendor_counter".to_owned()),
        ])
        .unwrap();
        assert_eq!(
            format_metric_title(
                descriptor(crate::monitor::RAW_PRIVATE_NIC_METRIC_ID).unwrap(),
                &raw_nic,
            ),
            "vendor_counter  eth0"
        );
    }

    #[test]
    fn starting_view_renders_at_supported_and_tiny_sizes() {
        for (width, height) in [(120, 30), (80, 24), (60, 20), (20, 5), (1, 1)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            terminal.draw(|frame| render(frame, &app)).unwrap();
        }
    }

    #[test]
    fn socket_table_keeps_its_breadcrumb_and_footer_complete_at_compact_widths() {
        let elapsed = std::time::Duration::from_secs(1);
        let snapshot = crate::monitor::MonitorSnapshot::new(
            1,
            1,
            1,
            elapsed,
            Some("net:[4026531993]".to_owned()),
            Vec::new(),
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed)
            .with_interface_anchor(Some(InterfaceViewAnchor::named("eth0").unwrap()));
        app.apply_snapshot(std::sync::Arc::new(snapshot));
        app.update(Action::OpenSelectedOverviewItem);
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_table_snapshot());

        for (width, footer) in [
            (
                60,
                "j/k select Enter detail s sort r reverse Esc back q quit",
            ),
            (
                80,
                "j/k select Enter detail s sort r reverse Esc back p pause q quit",
            ),
            (
                83,
                "j/k select  Enter detail  s sort  r reverse  Esc socket  Pg page  p pause  q quit",
            ),
        ] {
            let backend = TestBackend::new(width, 30);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            let lines = rendered.lines().collect::<Vec<_>>();
            let context = lines[1];

            assert!(
                context.contains("SOCKET / APPLICATION > SOCKETS"),
                "{width} columns:\n{rendered}"
            );
            if width == 60 {
                assert!(!context.contains("netns"), "{context}");
                assert!(!context.contains("filter"), "{context}");
            } else {
                assert!(context.contains("netns net:[4026531993]"), "{context}");
                assert!(context.contains("filter eth0"), "{context}");
            }
            assert!(
                lines.last().unwrap().contains(footer),
                "{width} columns:\n{rendered}"
            );
        }
    }

    #[test]
    fn socket_detail_keeps_breadcrumb_footer_without_history_controls() {
        let elapsed = std::time::Duration::from_secs(1);
        let mut app = App::new(MonitorSection::Socket, elapsed);
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_table_snapshot());
        app.update(Action::ToggleTimeView);
        app.update(Action::OpenSocketDetail);

        for (width, footer) in [
            (60, "j/k scroll Esc sockets Pg a all p pause q quit"),
            (80, "j/k scroll Esc sockets Pg a all p pause q quit"),
            (
                83,
                "j/k scroll  Esc sockets  PgUp/PgDn page  a all  p pause  q quit",
            ),
        ] {
            let backend = TestBackend::new(width, 30);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            let lines = rendered.lines().collect::<Vec<_>>();

            assert!(!lines[0].contains("ALL DETAIL"), "{rendered}");
            assert!(
                !rendered.to_ascii_lowercase().contains("trend"),
                "{rendered}"
            );
            assert_eq!(spark_glyph_count(&rendered), 0, "{rendered}");
            assert!(!lines[0].contains("SINCE BASELINE"), "{rendered}");
            assert!(!lines[0].contains("INTERVAL"), "{rendered}");
            assert!(
                lines[1].contains("SOCKET / APPLICATION > SOCKETS > DETAIL"),
                "{width} columns:\n{rendered}"
            );
            assert!(
                rendered.contains("TCP4 SOCKET DETAIL"),
                "{width} columns:\n{rendered}"
            );
            assert!(
                lines.last().unwrap().contains(footer),
                "{width} columns:\n{rendered}"
            );
        }
    }

    #[test]
    fn footer_help_variants_fit_supported_terminal_widths() {
        let compact_overview = "j/k select Enter open Pg page p pause t time q quit";
        let wide_overview = "j/k select layer/interface  Enter details  PgUp/PgDn page  : cmd  p pause  t time  q quit";
        for (width, expected) in [
            (60, compact_overview),
            (80, compact_overview),
            (100, wide_overview),
        ] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let compact_netfilter = "j/k select Enter open Esc back p pause q quit";
        let wide_netfilter = "j/k select  Enter open  Esc overview  p pause  t time  q quit";
        for (width, expected) in [
            (60, compact_netfilter),
            (80, compact_netfilter),
            (100, wide_netfilter),
        ] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let app = App::new(MonitorSection::Netfilter, std::time::Duration::from_secs(1));
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let compact_conntrack = "j/k scroll Enter flows Esc back Pg a all p pause q quit";
        let wide_conntrack = "j/k scroll  Enter flows  Esc back  PgUp/PgDn page  a all/data  p pause  t time  q quit";
        for (width, expected) in [
            (60, compact_conntrack),
            (80, compact_conntrack),
            (100, wide_conntrack),
        ] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = App::new(MonitorSection::Netfilter, std::time::Duration::from_secs(1));
            app.update(Action::OpenNetfilterItem);
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let compact_flows = "j/k select Enter detail / filter s sort r reverse Esc back";
        let wide_flows =
            "j/k select Enter detail / filter Ctrl+u clear s sort r reverse d diagnostics Esc back Pg page p pause q quit";
        for (width, expected) in [(60, compact_flows), (80, compact_flows), (120, wide_flows)] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = App::new(MonitorSection::Netfilter, std::time::Duration::from_secs(1));
            app.update(Action::SelectPage(Page::Conntrack));
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let compact_detail = "j/k scroll Esc back Pg a all p pause t time q quit";
        let wide_detail = "j/k scroll Esc overview Pg page a all : cmd p pause t time q quit";
        for (width, expected) in [
            (60, compact_detail),
            (80, compact_detail),
            (83, wide_detail),
        ] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            app.update(Action::SelectNextOverviewItem);
            app.update(Action::OpenSelectedOverviewItem);
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let compact_socket_detail = "j/k scroll Enter sockets Esc back Pg a all p pause q quit";
        let wide_socket_detail =
            "j/k scroll Enter sockets Esc overview Pg page a all p pause t time q quit";
        for (width, expected) in [
            (60, compact_socket_detail),
            (80, compact_socket_detail),
            (83, wide_socket_detail),
        ] {
            let backend = TestBackend::new(width, 20);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            app.update(Action::OpenSelectedOverviewItem);
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains(expected), "{width} columns:\n{rendered}");
        }

        let backend = TestBackend::new(60, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.update(Action::SelectNextOverviewItem);
        app.update(Action::OpenSelectedOverviewItem);
        app.update(Action::ToggleDetailMetrics);
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let rendered = terminal.backend().to_string();
        assert!(
            rendered.contains("j/k scroll Esc back Pg a data p pause t time q quit"),
            "{rendered}"
        );
    }

    #[test]
    fn netdevice_table_keeps_numeric_direction_columns_for_both_interfaces() {
        let mut app = App::new(MonitorSection::Netdevice, std::time::Duration::from_secs(1));
        app.apply_snapshot(full_dashboard_snapshot());
        app.set_viewport_size(160, 40);
        let mut terminal = Terminal::new(TestBackend::new(160, 45)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal.backend().to_string();
        for title in [
            "INTERFACE",
            "RX Mb/s",
            "TX Mb/s",
            "RX pps",
            "TX pps",
            "RX drop/s",
            "TX err/s",
            "CONFIGURATION",
        ] {
            assert!(text.contains(title), "{title}:\n{text}");
        }
        let rows: Vec<_> = text
            .lines()
            .filter(|line| line.contains("eth0") || line.contains("eth1"))
            .collect();
        assert_eq!(rows.len(), 4, "{text}");
        assert!(
            rows[0].contains("eth0") && rows[1].contains("eth1"),
            "{text}"
        );
        assert!(
            rows[0].contains("10.00") && rows[1].contains("100.00"),
            "{text}"
        );
        assert!(
            rows[2].contains("eth0") && rows[3].contains("eth1"),
            "{text}"
        );
    }

    #[test]
    fn tc_netdev_and_hardirq_pages_keep_both_interface_identities_reachable() {
        let snapshot = full_dashboard_snapshot();
        for section in [
            MonitorSection::Tc,
            MonitorSection::Nic,
            MonitorSection::Hardirq,
        ] {
            let mut app = App::new(section, std::time::Duration::from_secs(1));
            app.apply_snapshot(snapshot.clone());
            app.set_viewport_size(160, 46);
            let mut terminal = Terminal::new(TestBackend::new(160, 50)).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let text = terminal.backend().to_string();
            assert!(
                text.contains("eth0") && text.contains("eth1"),
                "{section}:\n{text}"
            );
            assert!(text.find("eth0") < text.find("eth1"), "{text}");
        }
    }

    #[test]
    fn overview_uses_repeated_netdev_tables_with_current_and_cumulative_columns() {
        for width in [120, 160] {
            let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            app.apply_snapshot(full_dashboard_snapshot());
            app.set_viewport_size(width, 80);
            let mut terminal = Terminal::new(TestBackend::new(width, 85)).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let text = terminal.backend().to_string();
            assert!(
                text.contains("INTERFACE") && text.contains("CONFIGURATION"),
                "{text}"
            );
            let rows: Vec<_> = text
                .lines()
                .filter(|line| line.contains("eth0") || line.contains("eth1"))
                .collect();
            let tables = if width >= 160 { 2 } else { 3 };
            assert_eq!(rows.len(), tables * 2, "{text}");
            for pair in rows.chunks_exact(2) {
                assert!(
                    pair[0].contains("eth0") && pair[1].contains("eth1"),
                    "{text}"
                );
            }
            assert!(text.contains("10.00") && text.contains("100.00"), "{text}");
            app.update(Action::ToggleTimeView);
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let total = terminal.backend().to_string();
            assert!(
                total.contains("RX bytes") && total.contains("RX pkts"),
                "{total}"
            );
            assert!(
                total.contains("ixgbe") && total.contains("1024/512"),
                "{total}"
            );
        }
    }

    #[test]
    fn compact_interface_configuration_has_link_queues_and_offload_tables() {
        let mut app = App::new(MonitorSection::Nic, std::time::Duration::from_secs(1));
        app.apply_snapshot(full_dashboard_snapshot());
        app.set_viewport_size(120, 30);
        let mut terminal = Terminal::new(TestBackend::new(120, 35)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal.backend().to_string();
        for value in [
            "LINK + QUEUES",
            "OFFLOAD",
            "DRIVER",
            "DUPLEX",
            "Q R/T",
            "RING R/T",
            "TXQLEN",
            "TSO",
            "LRO",
            "GRO",
            "GSO",
            "PAUSE R/T",
            "ixgbe",
            "1024/512",
            "on/off",
        ] {
            assert!(text.contains(value), "{value}:\n{text}");
        }
    }

    #[test]
    fn overview_highlights_selected_border_and_title_without_coloring_values() {
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(global_dashboard_snapshot());
        let (width, height) = (80, 30);
        app.set_viewport_size(width, body_rows(Rect::new(0, 0, width, height), &app));
        app.update(Action::SelectNextOverviewItem);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal.backend().to_string();
        let y = text
            .lines()
            .position(|line| line.contains("TRANSPORT") && !line.contains("detail"))
            .unwrap() as u16;
        let buffer = terminal.backend().buffer();
        for x in 1..=" TRANSPORT".len() as u16 {
            assert_eq!(buffer[(x, y)].bg, theme::SELECTED_BG);
        }
        for x in 0..width {
            assert_eq!(buffer[(x, y + 1)].bg, Color::Reset);
        }
        for x in [0, width - 1] {
            assert_eq!(buffer[(x, y)].fg, theme::ACCENT);
            assert_eq!(buffer[(x, y + 1)].fg, theme::ACCENT);
        }
    }

    #[test]
    fn chrome_highlights_the_active_page_and_footer_keycaps() {
        let (width, height) = (80, 20);
        let app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(width - 1, 0)].bg, theme::CHROME_BG);
        assert_eq!(buffer[(width - 1, 1)].bg, theme::CHROME_BG);
        assert_eq!(buffer[(1, 2)].fg, theme::ACCENT);
        assert_eq!(buffer[(1, 2)].bg, theme::SELECTED_BG);
        assert_eq!(buffer[(0, height - 1)].bg, theme::FOOTER_BG);
        assert_eq!(buffer[(1, height - 1)].fg, Color::Black);
        assert_eq!(buffer[(1, height - 1)].bg, theme::ACCENT);
    }

    #[test]
    fn providers_keep_header_and_row_separators_aligned_while_scrolling() {
        let snapshot = full_dashboard_snapshot();
        assert!(snapshot.providers().len() > 2);
        for width in [60, 80, 120, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 8)).unwrap();
            for offset in [0, 1, snapshot.providers().len() - 1] {
                terminal
                    .draw(|frame| {
                        render_providers(frame, frame.area(), &snapshot, offset);
                    })
                    .unwrap();
                let buffer = terminal.backend().buffer();
                let header: Vec<_> = (0..width)
                    .filter(|x| buffer[(*x, 1)].symbol() == "│")
                    .collect();
                let row: Vec<_> = (0..width)
                    .filter(|x| buffer[(*x, 2)].symbol() == "│")
                    .collect();
                assert_eq!(header.len(), 5, "width={width}");
                assert_eq!(row, header, "width={width} offset={offset}");
            }
        }
    }

    #[test]
    fn every_global_layer_opens_a_complete_scrollable_detail() {
        let snapshot = full_dashboard_snapshot();
        let dashboard = crate::monitor::dashboard::build_dashboard(&snapshot);
        for (index, (kind, page)) in OVERVIEW_LAYER_KINDS
            .into_iter()
            .zip([
                Page::Socket,
                Page::Transport,
                Page::Network,
                Page::Conntrack,
                Page::Tc,
                Page::Softirq,
            ])
            .enumerate()
        {
            for width in [80, 120, 160] {
                let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
                app.apply_snapshot(snapshot.clone());
                for _ in 0..index {
                    app.update(Action::SelectNextOverviewItem);
                }
                assert_eq!(app.selected_layer(), Some(kind));
                app.update(Action::OpenSelectedOverviewItem);
                assert_eq!(app.page(), page);
                if app.detail_metrics_mode() != DetailMetricsMode::All {
                    app.update(Action::ToggleDetailMetrics);
                }
                let text = render_all_workspace_rows(&mut app, width, 20);
                let fields: &[&str] = match page {
                    Page::Transport => &[
                        "TCP",
                        "UDP",
                        "InSegs/s",
                        "OutSegs/s",
                        "RetransSegs/s",
                        "TCPTimeouts/s",
                        "InCsumErrors/s",
                        "MEANING",
                    ],
                    Page::Network => &[
                        "IP",
                        "ICMP",
                        "IPv4 receive/s",
                        "IPv4 deliver/s",
                        "IPv4 headerErr/s",
                        "IPv6 reasmFail/s",
                        "InUnreach/s",
                        "Echo replies out/s",
                        "v6 OutTooBig/s",
                        "MEANING",
                    ],
                    Page::Conntrack => &["Conntrack", "Collecting conntrack flows"],
                    Page::Tc => &["eth0", "eth1", "fq_codel"],
                    Page::Softirq if width < 100 => &[
                        "CPU", "RX/s", "TX/s", "P/s", "D+", "S+", "RP/s", "FL+", "BL", "IQ", "PQ",
                    ],
                    Page::Softirq if width < 140 => &[
                        "CPU",
                        "RX/s",
                        "TX/s",
                        "PROC/s",
                        "DROP+",
                        "SQZ+",
                        "RECEIVED_RPS/s",
                        "FLOW_LIMIT_COUNT+",
                        "BACKLOG_LEN",
                        "INPUT_QLEN",
                        "PROCESS_QLEN",
                    ],
                    Page::Softirq => &[
                        "CPU",
                        "NET_RX/s",
                        "NET_TX/s",
                        "PROCESSED/s",
                        "DROPPED+",
                        "SQUEEZE+",
                        "RECEIVED_RPS/s",
                        "FLOW_LIMIT_COUNT+",
                        "BACKLOG_LEN",
                        "INPUT_QLEN",
                        "PROCESS_QLEN",
                    ],
                    Page::Socket => &["ALL STATISTICS"],
                    _ => unreachable!(),
                };
                for field in fields {
                    assert!(
                        text.contains(field),
                        "{page:?} {width}, missing {field}:\n{text}"
                    );
                }
                if page == Page::Transport {
                    for (label, value) in [
                        ("InSegs/s", 100.0),
                        ("OutSegs/s", 90.0),
                        ("RetransSegs/s", 2.0),
                    ] {
                        assert_metric_cell(&text, label, value);
                    }
                }
                if page == Page::Network {
                    for (label, value) in [
                        ("IPv4 receive/s", 120.0),
                        ("IPv4 deliver/s", 115.0),
                        ("IPv4 headerErr/s", 0.0),
                    ] {
                        assert_metric_cell(&text, label, value);
                    }
                }
                if page == Page::Socket {
                    let block = dashboard
                        .blocks()
                        .iter()
                        .find(|block| block.key().kind() == kind)
                        .unwrap();
                    for series in block
                        .rx()
                        .iter()
                        .chain(block.tx())
                        .chain(block.shared())
                        .map(crate::monitor::dashboard::PlacedSeries::series)
                    {
                        let metric = descriptor(series.metric().as_str()).unwrap();
                        let title = format_series_title(series, metric);
                        assert!(text.contains(&title), "{width}, missing {title}:\n{text}");
                    }
                }
                if page == Page::Softirq {
                    for (cpu, rates) in [
                        ("0", ["40/s", "30/s", "100/s"]),
                        ("1", ["44/s", "32/s", "110/s"]),
                    ] {
                        let row = text
                            .lines()
                            .find(|row| {
                                row.trim_matches('"')
                                    .split('|')
                                    .next()
                                    .is_some_and(|cell| cell.trim() == cpu)
                            })
                            .unwrap_or_else(|| panic!("{width}, CPU {cpu}:\n{text}"));
                        let cells: Vec<_> =
                            row.trim_matches('"').split('|').map(str::trim).collect();
                        assert_eq!(&cells[1..4], &rates, "{width}, CPU {cpu}:\n{text}");
                        assert_eq!(
                            &cells[4..],
                            ["+0", "+0", "-", "-", "-", "-", "-"],
                            "zero drops/squeezes and missing RPS/flow/backlog: {row}"
                        );
                    }
                }
                app.update(Action::Back);
                assert_eq!(app.page(), Page::Overview);
                assert_eq!(app.selected_layer(), Some(kind));
            }
        }
    }
    #[test]
    fn overview_scales_to_many_interfaces_without_changing_stable_order() {
        let elapsed = std::time::Duration::from_secs(1);
        let interfaces = (100_u32..104)
            .map(|ifindex| (format!("p{ifindex}"), ifindex, "physical"))
            .chain((1_u32..=16).map(|ifindex| (format!("v{ifindex:02}"), ifindex, "virtual")))
            .collect::<Vec<_>>();
        let readings = interfaces
            .iter()
            .map(|(name, ifindex, kind)| {
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.nic.interface_kind").unwrap(),
                    MetricLabels::new([
                        (MetricLabel::Interface, name.clone()),
                        (MetricLabel::Ifindex, ifindex.to_string()),
                    ])
                    .unwrap(),
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(*kind).unwrap(),
                    ),
                )
            })
            .collect();
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        let snapshot = engine
            .ingest(
                elapsed,
                vec![provider_sample("linux.sysfs.net.nic", 1, readings)],
                None,
            )
            .unwrap();
        for (width, height) in [(80, 24), (120, 35), (160, 45)] {
            let mut app = App::new(MonitorSection::Overview, elapsed);
            app.apply_snapshot(snapshot.clone());
            let ordered: Vec<_> = app
                .interface_inventory()
                .iter()
                .map(|identity| identity.name().to_owned())
                .collect();
            assert_eq!(&ordered[..4], ["v01", "v02", "v03", "v04"]);
            assert_eq!(&ordered[16..], ["p100", "p101", "p102", "p103"]);
            let rendered = render_all_workspace_rows(&mut app, width, height);
            for (name, _, _) in &interfaces {
                assert!(
                    rendered.contains(name),
                    "{width} missing {name}:\n{rendered}"
                );
            }
            assert_eq!(
                app.interface_inventory()
                    .iter()
                    .map(|identity| identity.name())
                    .collect::<Vec<_>>(),
                ordered.iter().map(String::as_str).collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn interface_details_keep_rates_without_trends_at_supported_widths() {
        let snapshot = full_dashboard_snapshot_with_samples(17);
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(snapshot);
        open_first_interface_detail(&mut app);
        open_interface_layer_detail(
            &mut app,
            crate::monitor::dashboard::BlockKind::PacketStage(PacketStage::NetdeviceCore),
        );
        for width in [60, 80, 160] {
            let mut terminal = Terminal::new(TestBackend::new(width, 100)).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains("RX packets"), "{width}: {rendered}");
            assert!(rendered.contains("10.0 pps"), "{width}: {rendered}");
            assert!(!rendered.contains("eth1"), "{width}: {rendered}");
            assert!(
                !rendered.to_ascii_lowercase().contains("trend"),
                "{width}: {rendered}"
            );
            assert_eq!(spark_glyph_count(&rendered), 0, "{width}: {rendered}");
        }
    }

    #[test]
    fn every_section_renders_without_trends_or_trend_controls() {
        let snapshot = full_dashboard_snapshot_with_samples(17);
        for section in MonitorSection::ALL {
            for width in [60, 80, 160] {
                let mut app = App::new(section, std::time::Duration::from_secs(1));
                app.apply_snapshot(snapshot.clone());
                let mut terminal = Terminal::new(TestBackend::new(width, 100)).unwrap();
                terminal.draw(|frame| render(frame, &app)).unwrap();
                let rendered = terminal.backend().to_string();
                assert!(
                    !rendered.to_ascii_lowercase().contains("trend"),
                    "{section} {width}: {rendered}"
                );
                assert!(
                    !rendered.contains("h hist"),
                    "{section} {width}: {rendered}"
                );
                assert_eq!(
                    spark_glyph_count(&rendered),
                    0,
                    "{section} {width}: {rendered}"
                );
            }
        }
    }

    fn spark_glyph_count(value: &str) -> usize {
        value
            .chars()
            .filter(|character| matches!(character, '▁' | '▂' | '▃' | '▄' | '▅' | '▆' | '▇' | '█'))
            .count()
    }

    #[test]
    fn compact_overview_and_detail_keep_complete_interface_values_visible() {
        let snapshot = full_dashboard_snapshot();
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(snapshot);
        app.update(Action::ToggleTimeView);
        let width = 80;
        let height = 24;
        let overview = render_all_workspace_rows(&mut app, width, height);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();

        assert!(overview.contains("SINCE BASELINE"), "{overview}");
        assert!(overview.contains("t time q quit"), "{overview}");
        for value in [
            "INTERFACE",
            "RX bytes",
            "TX bytes",
            "RX pkts",
            "TX pkts",
            "CONFIGURATION",
            "eth0",
            "10000",
            "1024/512",
        ] {
            assert!(overview.contains(value), "{value}:\n{overview}");
        }
        assert!(
            overview.lines().any(|row| {
                let cells: Vec<_> = row
                    .trim_matches(['"', '\u{2502}'])
                    .split(|ch: char| ch.is_whitespace() || ch == '\u{2502}')
                    .filter(|cell| !cell.is_empty())
                    .collect();
                cells
                    .windows(6)
                    .any(|values| values == ["100", "200", "10", "20", "6", "4"])
            }),
            "baseline RX/TX bytes, packets, combined drops/errors:\n{overview}"
        );
        assert!(!overview.contains("NETDEVICE CORE"), "{overview}");

        open_first_interface_detail(&mut app);
        let mut menu = String::new();
        loop {
            terminal.draw(|frame| render(frame, &app)).unwrap();
            menu.push_str(&terminal.backend().to_string());
            let previous = app.row_offset();
            app.update(Action::PageDown);
            if app.row_offset() == previous {
                break;
            }
        }
        assert!(!menu.contains("RX NIC/PHY -> Driver/NAPI"), "{menu}");
        assert!(!menu.contains("TX STACK -> TC/qdisc"), "{menu}");
        assert!(menu.contains("NETDEVICE CORE"), "{menu}");
        assert!(menu.contains("EXECUTION CONTEXT: HARDIRQ"), "{menu}");
        assert!(menu.contains("Enter layer"), "{menu}");
        assert!(!menu.contains("STATISTICS WITH DATA"), "{menu}");
        assert!(!menu.contains("source linux."), "{menu}");

        app.update(Action::OpenSelectedInterfaceLayer);
        let mut detail = String::new();
        loop {
            terminal.draw(|frame| render(frame, &app)).unwrap();
            detail.push_str(&terminal.backend().to_string());
            let previous = app.row_offset();
            app.update(Action::PageDown);
            if app.row_offset() == previous {
                break;
            }
        }
        assert!(detail.contains("baseline(start)"), "{detail}");
        assert!(detail.contains("STATISTICS WITH DATA"), "{detail}");
        assert!(detail.contains("QDISC"), "{detail}");
        assert!(detail.contains("Esc layers"), "{detail}");
    }

    #[test]
    fn stale_link_and_speed_are_marked_in_wide_and_compact_summaries() {
        let interval = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        engine
            .ingest(
                interval,
                vec![nic_state_sample(1), nic_speed_sample(1)],
                None,
            )
            .unwrap();
        let snapshot = engine
            .ingest(
                std::time::Duration::from_secs(2),
                vec![
                    failed_provider_sample("linux.sysfs.net.nic", 2),
                    failed_provider_sample("linux.ethtool.link_text", 2),
                ],
                None,
            )
            .unwrap();

        for width in [80, 120, 160] {
            let mut app = App::new(MonitorSection::Nic, interval);
            app.apply_snapshot(std::sync::Arc::clone(&snapshot));
            app.set_viewport_size(width, 40);
            let backend = TestBackend::new(width, 50);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| render(frame, &app)).unwrap();
            let rendered = terminal.backend().to_string();
            for value in ["eth0", "~up", "~10000", "~ixgbe", "~on/~off"] {
                assert!(
                    rendered.contains(value),
                    "{width} missing {value}:\n{rendered}"
                );
            }
        }
    }

    #[test]
    fn interface_gauge_slots_follow_the_selected_time_projection() {
        let interval = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let mut first = interface_gauge_samples(1, 100, 2_500);
        first.push(nic_state_sample(1));
        engine.ingest(interval, first, None).unwrap();
        let mut second = interface_gauge_samples(2, 150, 3_000);
        second.push(nic_state_sample(2));
        let snapshot = engine
            .ingest(std::time::Duration::from_secs(2), second, None)
            .unwrap();
        let mut app = App::new(MonitorSection::Overview, interval);
        app.apply_snapshot(snapshot);
        open_first_interface_detail(&mut app);
        let backend = TestBackend::new(160, 100);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();
        let interval_view = terminal.backend().to_string();
        for value in ["BACKLOG", "150 B", "+50 B", "IMBALANCE", "30.00%", "+5.00%"] {
            assert!(
                interval_view.contains(value),
                "missing {value}: {interval_view}"
            );
        }

        app.update(Action::ToggleTimeView);
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let baseline_view = terminal.backend().to_string();
        for value in [
            "BACKLOG RANGE",
            "150 B",
            "min 100 B",
            "max 150 B",
            "IMBALANCE RANGE",
            "min 25.00%",
            "30.00%",
        ] {
            assert!(
                baseline_view.contains(value),
                "missing {value}: {baseline_view}"
            );
        }
    }

    #[test]
    fn interface_detail_scrolls_through_all_stages_at_supported_sizes() {
        let snapshot = full_dashboard_snapshot();
        for (width, height) in [(160, 45), (100, 30), (80, 24), (60, 20)] {
            let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            app.apply_snapshot(std::sync::Arc::clone(&snapshot));
            open_first_interface_detail(&mut app);
            let viewport_rows = body_rows(Rect::new(0, 0, width, height), &app);
            app.set_viewport_size(width, viewport_rows);
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut rendered = String::new();
            loop {
                terminal.draw(|frame| render(frame, &app)).unwrap();
                rendered.push_str(&terminal.backend().to_string());
                let previous = app.row_offset();
                app.update(Action::PageDown);
                if app.row_offset() == previous {
                    break;
                }
            }
            assert!(rendered.contains("QDISC"), "{width}x{height}:\n{rendered}");
            assert!(
                rendered.contains("NETDEVICE CORE"),
                "{width}x{height}:\n{rendered}"
            );
            assert!(
                rendered.contains("DRIVER / NAPI"),
                "{width}x{height}:\n{rendered}"
            );
            assert!(
                rendered.contains("NIC / PHY"),
                "{width}x{height}:\n{rendered}"
            );
            assert!(
                rendered.contains("EXECUTION CONTEXT: HARDIRQ"),
                "{width}x{height}:\n{rendered}"
            );
            assert!(
                rendered.contains("1.0 irq/s"),
                "{width}x{height}:\n{rendered}"
            );
            assert!(!rendered.contains("eth1"), "{width}x{height}:\n{rendered}");
            assert_eq!(
                app.row_offset(),
                super::super::dashboard::interface_detail_row_count(
                    app.snapshot().unwrap(),
                    app.detail_interface().unwrap(),
                    super::super::dashboard::DetailDisplayOptions::new(
                        app.time_view(),
                        app.detail_metrics_mode(),
                    ),
                    width,
                )
                .saturating_sub(viewport_rows),
                "{width}x{height}"
            );
        }
    }

    #[test]
    fn interface_detail_renders_ethtool_timeout_status_and_explainable_cause() {
        let elapsed = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        let snapshot = engine
            .ingest(
                elapsed,
                vec![nic_state_sample(1), nic_statistics_status_sample(1)],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed);
        app.apply_snapshot(snapshot);
        open_first_interface_detail(&mut app);
        open_interface_layer_detail(
            &mut app,
            crate::monitor::dashboard::BlockKind::PacketStage(PacketStage::DriverNapi),
        );
        let width = 160;
        let height = 30;
        let viewport_rows = body_rows(Rect::new(0, 0, width, height), &app);
        app.set_viewport_size(width, viewport_rows);
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut rendered = String::new();

        loop {
            terminal.draw(|frame| render(frame, &app)).unwrap();
            rendered.push_str(&terminal.backend().to_string());
            let previous = app.row_offset();
            app.update(Action::PageDown);
            if app.row_offset() == previous {
                break;
            }
        }

        for value in [
            "STATUS / OTHER",
            "ethtool statistics status",
            "current timed_out",
            "fresh | source linux.ethtool.text",
        ] {
            assert!(rendered.contains(value), "missing {value}:\n{rendered}");
        }
        assert!(
            rendered.contains("NOTE: ethtool statistics status | collection timed out"),
            "{rendered}"
        );
    }

    #[test]
    fn overview_interface_anchor_filters_summaries_and_detail() {
        let snapshot = full_dashboard_snapshot();
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1))
            .with_interface_anchor(Some(InterfaceViewAnchor::named("eth1").unwrap()));
        app.apply_snapshot(snapshot);
        let backend = TestBackend::new(160, 75);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();

        let rendered = terminal.backend().to_string();
        assert!(!rendered.contains("eth0"), "{rendered}");
        assert!(rendered.contains("eth1"), "{rendered}");
        assert!(rendered.contains("CONFIGURATION"), "{rendered}");
        assert!(!rendered.contains("NETDEVICE CORE"), "{rendered}");

        open_first_interface_detail(&mut app);
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let detail = terminal.backend().to_string();
        assert!(detail.contains("detail eth1 ifindex=3"), "{detail}");
        assert!(detail.contains("NETDEVICE CORE"), "{detail}");
        assert!(!detail.contains("eth0"), "{detail}");
    }

    #[test]
    fn nic_settings_remain_scrollable_to_the_last_row() {
        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, std::time::Duration::from_secs(1))
                .unwrap();
        let snapshot = engine
            .ingest(
                std::time::Duration::from_secs(1),
                vec![nic_settings_sample(300)],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Nic, std::time::Duration::from_secs(1));
        app.apply_snapshot(std::sync::Arc::clone(&snapshot));
        let all = grouped_metric_rows(&app, &snapshot, 0, usize::MAX);
        for offset in [0, 1, 2, 3, 40, 299, 302, 303] {
            assert_eq!(
                grouped_metric_rows(&app, &snapshot, offset, 12),
                all.iter()
                    .skip(offset)
                    .take(12)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
        }
        app.apply_snapshot(snapshot);
        app.update(Action::SelectPage(Page::Netdev));
        app.update(Action::OpenSelectedOverviewItem);
        open_interface_layer_detail(
            &mut app,
            crate::monitor::dashboard::BlockKind::PacketStage(PacketStage::NicPhy),
        );
        let rendered = render_all_workspace_rows(&mut app, 120, 15);
        assert!(rendered.contains("setting_000"), "{rendered}");
        assert!(rendered.contains("setting_299"), "{rendered}");
        let final_offset = app.row_offset();
        assert!(final_offset > 300);
        app.update(Action::PageDown);
        assert_eq!(app.row_offset(), final_offset);
    }

    #[test]
    fn interface_detail_keeps_all_dynamic_nic_settings_reachable() {
        let elapsed = std::time::Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        let snapshot = engine
            .ingest(
                elapsed,
                vec![nic_state_sample(1), nic_settings_sample(300)],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed);
        app.apply_snapshot(snapshot);
        open_first_interface_detail(&mut app);
        open_interface_layer_detail(
            &mut app,
            crate::monitor::dashboard::BlockKind::PacketStage(PacketStage::NicPhy),
        );
        let width = 60;
        let height = 20;
        let viewport_rows = body_rows(Rect::new(0, 0, width, height), &app);
        app.set_viewport_size(width, viewport_rows);
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut rendered = String::new();

        loop {
            terminal.draw(|frame| render(frame, &app)).unwrap();
            rendered.push_str(&terminal.backend().to_string());
            let previous = app.row_offset();
            app.update(Action::PageDown);
            if app.row_offset() == previous {
                break;
            }
        }

        assert!(rendered.contains("setting_000"), "{rendered}");
        assert!(rendered.contains("setting_299"), "{rendered}");
        assert!(
            super::super::dashboard::interface_layer_detail_row_count(
                app.snapshot().unwrap(),
                app.detail_interface().unwrap(),
                app.detail_interface_layer().unwrap(),
                super::super::dashboard::DetailDisplayOptions::new(
                    app.time_view(),
                    app.detail_metrics_mode(),
                ),
                width,
            ) > 300
        );
    }

    #[test]
    fn interface_anchor_filters_interface_rows_but_keeps_global_rows() {
        let global = MetricLabels::default();
        let eth0 = MetricLabels::new([
            (MetricLabel::Interface, "eth0".to_owned()),
            (MetricLabel::Ifindex, "2".to_owned()),
        ])
        .unwrap();

        let by_name = InterfaceViewAnchor::named("eth0").unwrap();
        let by_index = InterfaceViewAnchor::indexed(2).unwrap();
        let other = InterfaceViewAnchor::named("eth1").unwrap();
        let multiple = InterfaceViewAnchor::named_many(["eth0".into(), "eth1".into()]).unwrap();
        assert!(series_matches_anchor(&global, Some(&multiple), None));
        for (name, selected) in [
            ("eth0", true),
            ("eth1", true),
            ("eth2", false),
            ("eth01", false),
        ] {
            let labels = MetricLabels::new([(MetricLabel::Interface, name.to_owned())]).unwrap();
            assert_eq!(
                series_matches_anchor(&labels, Some(&multiple), None),
                selected
            );
        }
        assert!(series_matches_anchor(&global, Some(&by_name), None));
        assert!(series_matches_anchor(&eth0, Some(&by_name), None));
        assert!(series_matches_anchor(&eth0, Some(&by_index), None));
        assert!(!series_matches_anchor(&eth0, Some(&other), None));

        let name_only = MetricLabels::new([(MetricLabel::Interface, "eth0".to_owned())]).unwrap();
        assert!(!series_matches_anchor(&name_only, Some(&by_index), None));
        assert!(series_matches_anchor(
            &name_only,
            Some(&by_index),
            Some("eth0")
        ));
    }

    #[test]
    fn row_offset_is_clamped_to_the_last_available_row() {
        assert_eq!(visible_rows(vec![1, 2, 3], 99).collect::<Vec<_>>(), [3]);
        assert!(visible_rows(Vec::<u8>::new(), 99)
            .collect::<Vec<_>>()
            .is_empty());
    }

    #[test]
    fn compact_overview_shows_netdev_traffic_in_first_screen() {
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(full_dashboard_snapshot());
        let area = Rect::new(0, 0, 160, 40);
        app.set_viewport_size(area.width, body_rows(area, &app));
        let mut terminal = Terminal::new(TestBackend::new(area.width, area.height)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal.backend().to_string();
        for label in [
            "SOCKETS",
            "SOFTIRQ",
            "INTERFACE",
            "eth0",
            "RX Mb/s",
            "TX Mb/s",
        ] {
            assert!(text.contains(label), "missing {label}:\n{text}");
        }
        assert_eq!(app.row_offset(), 0);
    }

    #[test]
    fn global_dashboard_is_responsive_and_scrollable_at_supported_sizes() {
        for (width, height) in [(160, 45), (100, 30), (80, 24), (60, 20)] {
            let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            app.apply_snapshot(global_dashboard_snapshot());
            let text = render_all_workspace_rows(&mut app, width, height);
            for label in [
                "SOCKETS",
                "TRANSPORT",
                "NETWORK",
                "CONNTRACK",
                "QDISC EGRESS ROOT",
                "SOFTIRQ",
                "TCP CurrEstab",
                "RetransSegs/s",
                "net:[42]",
            ] {
                assert!(text.contains(label), "{width}x{height} {label}:\n{text}");
            }
            assert!(!text.contains("trend"));
        }
    }

    #[test]
    fn missing_primary_metric_does_not_move_the_secondary_slot() {
        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, std::time::Duration::from_secs(1))
                .unwrap();
        let mut snapshot = None;
        for at in 1..=2 {
            snapshot = Some(
                engine
                    .ingest(
                        std::time::Duration::from_secs(at),
                        vec![provider_sample(
                            "linux.proc.net.snmp",
                            at,
                            vec![counter_reading(
                                "linux.socket.tcp.segments_out",
                                MetricLabels::default(),
                                at,
                            )],
                        )],
                        Some("net:[42]".to_owned()),
                    )
                    .unwrap(),
            );
        }
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(snapshot.unwrap());
        for width in [80, 120, 160] {
            app.update(Action::ScrollTop);
            let missing = render_all_workspace_rows(&mut app, width, 24);
            let expected = missing
                .lines()
                .find(|line| line.contains("TCP OutSegs/s"))
                .unwrap();
            let drop_column = expected.find("TCP OutSegs/s").unwrap();
            assert_metric_cell(&missing, "TCP OutSegs/s", 1.0);
            let overflow = missing
                .lines()
                .find(|line| line.contains("TCP InSegs/s"))
                .unwrap();
            let overflow_column = overflow.find("TCP InSegs/s").unwrap();
            assert!(
                overflow[overflow_column..].contains("n/a"),
                "{width}:\n{missing}"
            );
            let mut complete =
                App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
            complete.apply_snapshot(global_dashboard_snapshot());
            let full = render_all_workspace_rows(&mut complete, width, 24);
            let complete_drop = full
                .lines()
                .find(|line| line.contains("TCP OutSegs/s"))
                .unwrap();
            let complete_overflow = full
                .lines()
                .find(|line| line.contains("TCP InSegs/s"))
                .unwrap();
            assert_eq!(drop_column, complete_drop.find("TCP OutSegs/s").unwrap());
            assert_eq!(
                overflow_column,
                complete_overflow.find("TCP InSegs/s").unwrap()
            );
        }
    }
    #[test]
    fn empty_dashboard_keeps_all_global_blocks_with_missing_values() {
        let mut app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        app.apply_snapshot(crate::tui::app::tests::interface_snapshot(1, &[]));
        for width in [60, 160] {
            app.update(Action::ScrollTop);
            let text = render_all_workspace_rows(&mut app, width, 45);
            for label in [
                "SOCKETS",
                "TRANSPORT",
                "NETWORK",
                "CONNTRACK",
                "SOFTIRQ",
                "n/a",
            ] {
                assert!(text.contains(label), "{label}:\n{text}");
            }
            assert!(
                !text.contains("TCP inuse                          0"),
                "{text}"
            );
        }
    }

    #[test]
    fn conntrack_summary_preserves_missing_fields() {
        let elapsed = std::time::Duration::from_secs(1);
        let sample = provider_sample(
            "linux.proc.netfilter.conntrack",
            1,
            vec![
                gauge_reading("linux.netfilter.conntrack.count", 7),
                gauge_reading("linux.netfilter.conntrack.utilization", 5_000),
            ],
        );
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        let snapshot = engine
            .ingest(elapsed, vec![sample], Some("net:[42]".to_owned()))
            .unwrap();
        for width in [80, 120, 160] {
            let mut app = App::new(MonitorSection::Overview, elapsed);
            app.apply_snapshot(snapshot.clone());
            let text = render_all_workspace_rows(&mut app, width, 24);
            for (label, value) in [
                ("entries", "7"),
                ("maximum", "n/a"),
                ("early_drop/s", "n/a"),
                ("drop/s", "n/a"),
            ] {
                let line = text
                    .lines()
                    .find(|line| line.contains(label))
                    .unwrap_or_else(|| panic!("{width}, missing {label}:\n{text}"));
                let cell = &line[line.find(label).unwrap() + label.len()..];
                assert_eq!(
                    cell.split_whitespace().next(),
                    Some(value),
                    "{width}, {label}:\n{text}"
                );
            }
        }
    }
    #[test]
    fn starting_dashboard_is_pending_instead_of_unsupported() {
        let app = App::new(MonitorSection::Overview, std::time::Duration::from_secs(1));
        let mut terminal = Terminal::new(TestBackend::new(160, 45)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal.backend().to_string();
        assert!(
            text.contains("STARTING") && text.contains("Collecting kernel counters"),
            "{text}"
        );
        assert!(!text.contains("unsupported"), "{text}");
    }
}
