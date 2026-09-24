//! Manual snapshots use the production TUI renderers and synthetic test data.
use ratatui::{backend::TestBackend, style::Color, Terminal};

use crate::monitor::conntrack_flow::ConntrackSort;
use crate::tui::{
    app::{DetailMetricsMode, TimeView},
    conntrack, dashboard, socket, socket_detail,
};

#[test]
#[ignore = "manual TUI snapshot export; set NETLENS_SORT_PREVIEW to an HTML path"]
fn export_sort_preview() {
    let path = std::env::var("NETLENS_SORT_PREVIEW").expect("NETLENS_SORT_PREVIEW");
    let (_, flows) = conntrack::tests::fixture_snapshots();
    let sockets = crate::monitor::socket_table::synthetic_socket_table_snapshot();
    let mut html = String::from("<!doctype html><html lang=en><meta charset=utf-8><title>netlens TUI snapshots</title><style>body{background:#151718;color:#dedede;margin:20px;font:13px monospace}h1{font-size:18px}h2{font-size:14px;margin-top:28px}pre{font:12px/1.6 monospace;white-space:pre;overflow:auto;background:#101213;padding:12px;border:1px solid #464a4d}span{letter-spacing:0}</style><h1>netlens / actual TUI renderer / fixture data</h1>");
    for width in [180, 160, 120, 80, 60] {
        let interfaces = crate::tui::view::tests::full_dashboard_snapshot();
        let identity = dashboard::ordered_interface_identities(&interfaces, None, None)
            .into_iter()
            .next()
            .unwrap();
        let display =
            dashboard::DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::WithData);
        let mut terminal = Terminal::new(TestBackend::new(
            width,
            dashboard::interface_detail_row_count(&interfaces, &identity, display, width) as u16,
        ))
        .unwrap();
        terminal
            .draw(|frame| {
                dashboard::render_interface_detail(
                    frame,
                    frame.area(),
                    &interfaces,
                    &identity,
                    dashboard::INTERFACE_BLOCK_KINDS[0],
                    display,
                    0,
                );
            })
            .unwrap();
        html.push_str(&format!("<h2>Interface detail / {width} columns</h2>"));
        html.push_str(&buffer_html(terminal.backend().buffer()));
        let display =
            dashboard::DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All);
        for layer in dashboard::INTERFACE_BLOCK_KINDS {
            let mut terminal = Terminal::new(TestBackend::new(
                width,
                dashboard::interface_layer_detail_row_count(
                    &interfaces,
                    &identity,
                    layer,
                    display,
                    width,
                ) as u16,
            ))
            .unwrap();
            terminal
                .draw(|frame| {
                    dashboard::render_interface_layer_detail(
                        frame,
                        frame.area(),
                        &interfaces,
                        &identity,
                        layer,
                        display,
                        0,
                    );
                })
                .unwrap();
            html.push_str(&format!(
                "<h2>Interface layer / {} / {width} columns</h2>",
                dashboard::interface_stage_title(layer)
            ));
            html.push_str(&buffer_html(terminal.backend().buffer()));
        }
        let softirq = dashboard::tests::softirq_matrix_snapshot(true);
        for (sort, descending) in [
            (dashboard::SoftirqSort::Cpu, false),
            (dashboard::SoftirqSort::Metric(0), true),
        ] {
            let model = dashboard::SoftirqSection::new_with_options(
                &softirq,
                width,
                dashboard::DetailDisplayOptions::new(TimeView::Interval, DetailMetricsMode::All),
                sort,
                descending,
            );
            let mut terminal =
                Terminal::new(TestBackend::new(width, model.row_count() as u16)).unwrap();
            terminal
                .draw(|frame| {
                    dashboard::render_softirq_section(
                        frame,
                        frame.area(),
                        &softirq,
                        &model,
                        TimeView::Interval,
                        0,
                    );
                })
                .unwrap();
            html.push_str(&format!(
                "<h2>SoftIRQ / {width} columns / {sort:?} / descending {descending}</h2>"
            ));
            html.push_str(&buffer_html(terminal.backend().buffer()));
        }
        for descending in [true, false] {
            let mut state = conntrack::ConntrackViewState::default();
            state.update(flows.clone(), None);
            state.set_sort(ConntrackSort::TxBytes, descending);
            let mut terminal =
                Terminal::new(TestBackend::new(width, state.row_count(width) as u16)).unwrap();
            terminal
                .draw(|frame| state.render(frame, frame.area(), 0))
                .unwrap();
            html.push_str(&format!(
                "<h2>Conntrack / {width} columns / TX traffic {}</h2>",
                if descending {
                    "descending"
                } else {
                    "ascending"
                }
            ));
            html.push_str(&buffer_html(terminal.backend().buffer()));
        }
        for position in 0..flows.flows().len() {
            let mut view = conntrack::ConntrackViewState::default();
            view.update(flows.clone(), None);
            view.select(position);
            let protocol = view.selected_flow().unwrap().protocol_name().to_owned();
            view.open();
            let mut terminal =
                Terminal::new(TestBackend::new(width, view.row_count(width) as u16)).unwrap();
            terminal
                .draw(|frame| view.render(frame, frame.area(), 0))
                .unwrap();
            html.push_str(&format!(
                "<h2>Conntrack detail / {protocol} / {width} columns</h2>"
            ));
            html.push_str(&buffer_html(terminal.backend().buffer()));
        }
        let mut order = socket::SocketOrder::default();
        order.update(sockets.clone(), None);
        let header = socket::socket_row_index(&sockets, &order, width, 0).unwrap() - 1;
        let key = (0..width)
            .find_map(|x| {
                socket::header_sort_at(&sockets, &order, width, x, header)
                    .filter(|sort| sort.label() == "RTT")
            })
            .unwrap();
        order.select_sort(key);
        let mut terminal = Terminal::new(TestBackend::new(
            width,
            socket::row_count(&sockets, width) as u16,
        ))
        .unwrap();
        terminal
            .draw(|frame| {
                socket::render(
                    frame,
                    frame.area(),
                    &sockets,
                    &order,
                    Some(sockets.sockets()[0].row_key()),
                    0,
                )
            })
            .unwrap();
        html.push_str(&format!(
            "<h2>Socket / {width} columns / RTT descending</h2>"
        ));
        html.push_str(&buffer_html(terminal.backend().buffer()));
        for selected in sockets.sockets() {
            let detail = crate::monitor::socket_table::SocketDetailState::start(
                &sockets,
                selected.row_key().clone(),
            )
            .unwrap();
            let mode = DetailMetricsMode::WithData;
            let mut terminal = Terminal::new(TestBackend::new(
                width,
                socket_detail::row_count(&detail, mode, width) as u16,
            ))
            .unwrap();
            terminal
                .draw(|frame| socket_detail::render(frame, frame.area(), &detail, mode, 0))
                .unwrap();
            html.push_str(&format!(
                "<h2>Socket detail / {} / {width} columns</h2>",
                selected.protocol().label()
            ));
            html.push_str(&buffer_html(terminal.backend().buffer()));
        }
    }
    html.push_str("</html>");
    std::fs::write(path, html).unwrap();
}

fn buffer_html(buffer: &ratatui::buffer::Buffer) -> String {
    use ratatui::style::Modifier;
    let mut html = String::from("<pre>");
    for y in 0..buffer.area.height {
        for x in 0..buffer.area.width {
            let cell = &buffer[(x, y)];
            let text = cell
                .symbol()
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            html.push_str(&format!("<span style=\"color:{};background:{};font-weight:{};text-decoration:{}\">{text}</span>",
                color(cell.fg, "#dedede"), color(cell.bg, "#101213"),
                if cell.modifier.contains(Modifier::BOLD) { "bold" } else { "normal" },
                if cell.modifier.contains(Modifier::UNDERLINED) { "underline" } else { "none" }));
        }
        html.push('\n');
    }
    html.push_str("</pre>");
    html
}

fn color(color: Color, default: &str) -> String {
    match color {
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        Color::LightCyan => "#70d6d6".into(),
        Color::LightMagenta => "#e29cce".into(),
        Color::LightGreen => "#9cd69b".into(),
        Color::Yellow | Color::LightYellow => "#ebd58a".into(),
        Color::DarkGray => "#53595c".into(),
        Color::White => "#ffffff".into(),
        _ => default.into(),
    }
}
