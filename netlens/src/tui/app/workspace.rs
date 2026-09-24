use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::monitor::dashboard::{BlockKind, ExecutionContext, PacketStage};
use crate::monitor::MonitorSection;

use super::{App, DashboardMode, Layer, NetdevSort, NetdevTable, OverviewSelection, Page, Summary};
use crate::tui::module_frame;
use crate::tui::tc::{TcTable, TcViewState};

pub(in crate::tui) const LAYERS: [BlockKind; 6] = [
    BlockKind::PacketStage(PacketStage::SocketApplication),
    BlockKind::PacketStage(PacketStage::Transport),
    BlockKind::PacketStage(PacketStage::NetworkRoute),
    BlockKind::PacketStage(PacketStage::NetfilterConntrack),
    BlockKind::PacketStage(PacketStage::TrafficControl),
    BlockKind::ExecutionContext(ExecutionContext::Softirq),
];

#[derive(Debug)]
pub(super) struct OverviewLayout {
    width: u16,
    lines: Vec<Line<'static>>,
    spans: Vec<(BlockKind, std::ops::Range<usize>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum OverviewClickTarget {
    Layer(BlockKind),
    InterfaceTitle,
    Interface(crate::monitor::dashboard::InterfaceIdentity),
}

impl App {
    pub(in crate::tui) fn page(&self) -> Page {
        if self.is_socket_session_active() {
            return Page::Socket;
        }
        if self.is_conntrack_flows() || self.is_netfilter_view() {
            return Page::Conntrack;
        }
        if self.is_network_route() {
            return Page::Route;
        }
        if self.is_interface_detail() || self.is_interface_layer_detail() {
            return Page::Netdev;
        }
        if let Some(kind) = self.detail_layer() {
            return match kind {
                BlockKind::PacketStage(PacketStage::SocketApplication) => Page::Socket,
                BlockKind::PacketStage(PacketStage::Transport) => Page::Transport,
                BlockKind::PacketStage(PacketStage::NetworkRoute) => Page::Network,
                BlockKind::PacketStage(PacketStage::NetfilterConntrack) => Page::Conntrack,
                BlockKind::PacketStage(PacketStage::TrafficControl) => Page::Tc,
                BlockKind::ExecutionContext(ExecutionContext::Softirq) => Page::Softirq,
                _ => Page::Netdev,
            };
        }
        match self.section {
            MonitorSection::Overview => Page::Overview,
            MonitorSection::Socket => Page::Socket,
            MonitorSection::Netfilter => Page::Conntrack,
            MonitorSection::Tc => Page::Tc,
            MonitorSection::Nic | MonitorSection::Netdevice => Page::Netdev,
            MonitorSection::Softirq => Page::Softirq,
            MonitorSection::Hardirq => Page::Hardirq,
            MonitorSection::Providers => Page::Providers,
        }
    }

    pub(super) fn cycle_page(&mut self, offset: isize) {
        let index = Page::ALL
            .iter()
            .position(|page| *page == self.page())
            .unwrap_or(0);
        let next = (index as isize + offset).rem_euclid(Page::ALL.len() as isize) as usize;
        self.select_page(Page::ALL[next]);
    }

    pub(in crate::tui) fn select_page(&mut self, page: Page) {
        self.tc_return_overview = false;
        self.tc_overview_key = None;
        let section = match page {
            Page::Overview | Page::Transport | Page::Network | Page::Route => {
                MonitorSection::Overview
            }
            Page::Netdev => MonitorSection::Nic,
            Page::Tc => MonitorSection::Tc,
            Page::Socket => MonitorSection::Socket,
            Page::Conntrack => MonitorSection::Netfilter,
            Page::Softirq => MonitorSection::Softirq,
            Page::Hardirq => MonitorSection::Hardirq,
            Page::Providers => MonitorSection::Providers,
        };
        self.select_section(section);
        match page {
            Page::Socket => self.open_socket_table(),
            Page::Conntrack => {
                self.dashboard_mode = DashboardMode::ConntrackFlows;
                self.row_offset = 0;
            }
            Page::Transport | Page::Network => {
                self.section = MonitorSection::Overview;
                self.overview_selection = OverviewSelection::Layer(if page == Page::Transport {
                    Layer::Transport.kind()
                } else {
                    Layer::Network.kind()
                });
                self.dashboard_mode = DashboardMode::LayerDetail;
                self.row_offset = 0;
            }
            Page::Route => {
                self.section = MonitorSection::Overview;
                self.dashboard_mode = DashboardMode::NetworkRoute;
                self.network_route_view
                    .set_viewport_rows(self.viewport_rows);
                self.network_route_view
                    .reconcile(self.displayed_network_route_snapshot.as_deref());
            }
            Page::Netdev => {
                self.reconcile_interface_selection();
                self.netdev_first = 0;
                self.ensure_netdev_selection_visible();
            }
            Page::Tc => {
                self.tc_view = TcViewState::default();
                self.reconcile_tc_content();
            }
            _ => {}
        }
    }

    pub(in crate::tui) fn summary(&self) -> Option<&Summary> {
        self.snapshot()
            .map(|snapshot| self.summary.get_or_init(|| Summary::new(snapshot)))
    }

    pub(in crate::tui) fn netdev_table(&self) -> Option<&NetdevTable> {
        self.snapshot().map(|snapshot| {
            self.netdev_table.get_or_init(|| {
                NetdevTable::new(snapshot, &self.interface_inventory, self.time_view)
            })
        })
    }

    pub(in crate::tui) fn hardirq_table(&self) -> Option<&crate::tui::hardirq::HardirqTable> {
        let snapshot = self.snapshot()?.hardirq.as_deref()?;
        Some(self.hardirq_table.get_or_init(|| {
            crate::tui::hardirq::HardirqTable::new(
                snapshot,
                self.interface_anchor(),
                self.viewport_width,
                self.hardirq_sort,
                self.hardirq_descending,
            )
        }))
    }

    pub(in crate::tui) fn tc_table(&self) -> &TcTable {
        self.tc_table.get_or_init(|| {
            TcTable::from_snapshot(
                self.snapshot(),
                self.interface_anchor(),
                self.interface_name_alias(),
            )
        })
    }

    pub(in crate::tui) fn tc_view(&self) -> &TcViewState {
        &self.tc_view
    }
    pub(in crate::tui) fn is_tc_view(&self) -> bool {
        self.section == MonitorSection::Tc && self.dashboard_mode == DashboardMode::Summary
    }
    pub(in crate::tui) fn is_netdev_table(&self) -> bool {
        matches!(
            self.section,
            MonitorSection::Nic | MonitorSection::Netdevice
        ) && self.dashboard_mode == DashboardMode::Summary
    }

    pub(super) fn move_tc(&mut self, amount: isize) {
        self.tc_table();
        self.tc_view
            .move_selection(self.tc_table.get().unwrap(), amount);
    }

    pub(super) fn reconcile_tc_content(&mut self) {
        if !self.is_tc_view() {
            return;
        }
        self.tc_table();
        self.tc_view.set_viewport_rows(self.viewport_rows);
        self.tc_view.reconcile(self.tc_table.get().unwrap());
        let rows = crate::tui::tc::row_count(
            self.tc_table.get().unwrap(),
            &self.tc_view,
            self.viewport_width,
        );
        self.tc_view.clamp_content_rows(rows);
    }

    pub(super) fn reconcile_conntrack_view(&mut self) {
        if let Some(snapshot) = self.displayed_conntrack_snapshot.clone() {
            self.conntrack_view
                .update(snapshot, self.conntrack_filter.as_ref());
        }
        self.ensure_conntrack_selection_visible();
    }

    pub(super) fn ensure_conntrack_selection_visible(&mut self) {
        if !self.is_conntrack_list() {
            return;
        }
        self.row_offset = self
            .conntrack_view
            .viewport(self.viewport_width, self.viewport_rows, self.row_offset)
            .reveal(self.conntrack_view.selected_position());
        self.clamp_row_offset();
    }

    pub(super) fn move_conntrack(&mut self, amount: isize) {
        if amount == -1 {
            self.conntrack_view.move_up();
        } else if amount == 1 {
            self.conntrack_view.move_down();
        } else {
            let position = self
                .conntrack_view
                .selected_position()
                .unwrap_or(0)
                .saturating_add_signed(amount)
                .min(self.conntrack_view.shown_count().saturating_sub(1));
            self.conntrack_view.select(position);
        }
        self.ensure_conntrack_selection_visible();
    }

    pub(super) fn open_conntrack_detail(&mut self) {
        if self.is_conntrack_list() && self.conntrack_view.open() {
            self.saved_conntrack_list_offset = self.row_offset;
            self.row_offset = 0;
        }
    }

    pub(super) fn move_netdev(&mut self, amount: isize) {
        let count = self.interface_inventory.len();
        if count == 0 {
            return;
        }
        let current = self
            .selected_interface
            .as_ref()
            .and_then(|selected| {
                self.interface_inventory
                    .iter()
                    .position(|item| item == selected)
            })
            .unwrap_or(0);
        let index = current.saturating_add_signed(amount).min(count - 1);
        self.selected_interface = self.interface_inventory.get(index).cloned();
        self.selected_interface_ordinal = Some(index);
        self.overview_selection = OverviewSelection::Interface;
        self.ensure_netdev_selection_visible();
    }

    // All repeated Netdev tables display the same bounded batch of interfaces.
    fn netdev_batch(
        &self,
        width: u16,
        rows: usize,
        overview: bool,
    ) -> (usize, std::ops::Range<usize>) {
        let prefix = if overview {
            self.overview_layout(width).lines.len()
        } else {
            0
        };
        let offset = if overview { self.row_offset } else { 0 };
        let prefix_visible = prefix.saturating_sub(offset).min(rows);
        let first = if overview {
            offset.saturating_sub(prefix)
        } else {
            self.netdev_first
        }
        .min(self.interface_inventory.len().saturating_sub(1));
        let capacity =
            NetdevTable::visible_capacity(width, rows.saturating_sub(prefix_visible) as u16);
        (
            prefix_visible,
            first
                ..first
                    .saturating_add(capacity)
                    .min(self.interface_inventory.len()),
        )
    }

    pub(super) fn workspace_interface_span(&self) -> Option<std::ops::Range<usize>> {
        let index = self.selected_interface_ordinal?;
        let (prefix_visible, batch) =
            self.netdev_batch(self.viewport_width, self.viewport_rows, true);
        if !batch.contains(&index) {
            return None;
        }
        let tables = if self.viewport_width >= 160 { 2 } else { 3 };
        let start = self.row_offset + prefix_visible + 2 + index - batch.start;
        Some(start..start + (tables - 1) * (batch.len() + 2) + 1)
    }

    pub(super) fn ensure_netdev_selection_visible(&mut self) {
        let overview = self.section == MonitorSection::Overview
            && self.dashboard_mode == DashboardMode::Summary;
        if !self.is_netdev_table()
            && !(overview && self.overview_selection == OverviewSelection::Interface)
        {
            return;
        }
        let Some(index) = self.selected_interface.as_ref().and_then(|selected| {
            self.interface_inventory
                .iter()
                .position(|item| item == selected)
        }) else {
            return;
        };
        self.selected_interface_ordinal = Some(index);
        if overview {
            let prefix = self.overview_layout(self.viewport_width).lines.len();
            let minimum = NetdevTable::row_count(self.viewport_width, 1);
            self.row_offset = self.row_offset.max(
                (prefix + minimum)
                    .saturating_sub(self.viewport_rows)
                    .min(prefix),
            );
            let (_, batch) = self.netdev_batch(self.viewport_width, self.viewport_rows, true);
            if index < batch.start {
                self.row_offset = prefix + index;
            } else if index >= batch.end {
                let capacity =
                    NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16)
                        .max(1);
                self.row_offset = prefix + index.saturating_sub(capacity - 1);
            }
            self.clamp_row_offset();
        } else {
            let capacity =
                NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16)
                    .max(1);
            if index < self.netdev_first {
                self.netdev_first = index;
            }
            if index >= self.netdev_first.saturating_add(capacity) {
                self.netdev_first = index + 1 - capacity;
            }
        }
    }

    pub(super) fn cycle_sort(&mut self) {
        if self.section == MonitorSection::Hardirq {
            self.hardirq_sort = self.hardirq_sort.next();
            self.hardirq_descending = self.hardirq_sort.descending();
            self.hardirq_table.take();
            self.row_offset = 0;
            return;
        }
        if self.is_softirq_view() {
            if let Some(model) = self.softirq_section() {
                let sort = model.next_sort(self.softirq_sort);
                self.softirq_sort = sort;
                self.softirq_descending = sort.default_descending();
                self.softirq_section.take();
                self.row_offset = 0;
            }
            return;
        }
        if self.is_socket_table() {
            self.socket_order.cycle();
            self.reconcile_socket_selection();
            self.ensure_selected_socket_visible();
            return;
        }
        if self.is_conntrack_list() {
            self.conntrack_view.cycle_sort();
            self.ensure_conntrack_selection_visible();
            return;
        }
        if self.is_tc_view() {
            self.tc_table();
            self.tc_view.cycle_sort(self.tc_table.get().unwrap());
            return;
        }
        if !matches!(self.page(), Page::Overview | Page::Netdev) {
            return;
        }
        self.netdev_sort = self.netdev_sort.next();
        self.netdev_descending = self.netdev_sort.default_descending();
        self.refresh_interface_inventory();
        self.netdev_first = 0;
        self.reconcile_interface_selection();
        self.ensure_netdev_selection_visible();
    }

    pub(super) fn reverse_sort(&mut self) {
        if self.section == MonitorSection::Hardirq {
            self.hardirq_descending = !self.hardirq_descending;
            self.hardirq_table.take();
            self.row_offset = 0;
            return;
        }
        if self.is_softirq_view() {
            self.softirq_descending = !self.softirq_descending;
            self.softirq_section.take();
            self.row_offset = 0;
            return;
        }
        if self.is_socket_table() {
            self.socket_order.reverse();
            self.reconcile_socket_selection();
            self.ensure_selected_socket_visible();
            return;
        }
        if self.is_conntrack_list() {
            self.conntrack_view.reverse_sort();
            self.ensure_conntrack_selection_visible();
            return;
        }
        if self.is_tc_view() {
            self.tc_table();
            self.tc_view.reverse_sort(self.tc_table.get().unwrap());
            return;
        }
        if !matches!(self.page(), Page::Overview | Page::Netdev) {
            return;
        }
        self.netdev_descending = !self.netdev_descending;
        self.refresh_interface_inventory();
        self.netdev_first = 0;
        self.reconcile_interface_selection();
        self.ensure_netdev_selection_visible();
    }

    pub(in crate::tui) fn netdev_sort_status(&self) -> String {
        format!(
            "{} {}",
            self.netdev_sort.label(),
            if self.netdev_descending {
                "desc"
            } else {
                "asc"
            }
        )
    }

    pub(super) fn ensure_tc_overview_object_visible(&mut self) {
        let kind = BlockKind::PacketStage(PacketStage::TrafficControl);
        let Some(row) = self.tc_overview_key.as_ref().and_then(|key| {
            crate::tui::tc::overview_row_index(
                self.tc_table(),
                module_frame::inner_width(self.viewport_width),
                key,
            )
        }) else {
            return;
        };
        let Some(span) = self.workspace_layer_span(kind) else {
            return;
        };
        let row = span.start + row;
        if row < self.row_offset {
            self.row_offset = row;
        } else if row >= self.row_offset.saturating_add(self.viewport_rows) {
            self.row_offset = (row + 1).saturating_sub(self.viewport_rows);
        }
        self.clamp_row_offset();
    }

    fn overview_layout(&self, width: u16) -> std::cell::Ref<'_, OverviewLayout> {
        let current = self.overview_layout.borrow();
        if current.as_ref().is_some_and(|layout| layout.width == width) {
            return std::cell::Ref::map(current, |layout| layout.as_ref().unwrap());
        }
        drop(current);
        let layout = self.build_overview_layout(width);
        *self.overview_layout.borrow_mut() = Some(layout);
        std::cell::Ref::map(self.overview_layout.borrow(), |layout| {
            layout.as_ref().unwrap()
        })
    }

    fn build_overview_layout(&self, width: u16) -> OverviewLayout {
        let Some(summary) = self.summary() else {
            return OverviewLayout {
                width,
                lines: vec![Line::raw("Collecting kernel counters...")],
                spans: Vec::new(),
            };
        };
        let mut lines = vec![crate::tui::summary::heading(
            "NETWORK SUMMARY   rates /s | gauges: current",
            false,
        )];
        let mut spans = Vec::with_capacity(LAYERS.len());
        let inner_width = module_frame::inner_width(width);
        for kind in LAYERS {
            let start = lines.len();
            let content = if let Some(layer) = Layer::from_kind(kind) {
                summary.lines(layer, inner_width, false)
            } else {
                crate::tui::tc::overview_lines(self.tc_table(), inner_width)
            };
            lines.extend(module_frame::lines(content, width));
            spans.push((kind, start..lines.len()));
        }
        OverviewLayout {
            width,
            lines,
            spans,
        }
    }

    pub(in crate::tui) fn summary_lines(&self, width: u16) -> Vec<Line<'static>> {
        let layout = self.overview_layout(width);
        let mut lines = layout.lines.clone();
        if let Some((kind, span)) = layout
            .spans
            .iter()
            .find(|(kind, _)| self.selected_layer() == Some(*kind))
        {
            module_frame::highlight(&mut lines[span.clone()]);
            let selected = if *kind == BlockKind::PacketStage(PacketStage::TrafficControl) {
                self.tc_overview_key
                    .as_ref()
                    .and_then(|key| {
                        crate::tui::tc::overview_row_index(
                            self.tc_table(),
                            module_frame::inner_width(width),
                            key,
                        )
                    })
                    .unwrap_or(0)
            } else {
                0
            };
            if let Some(line) = lines.get_mut(span.start + selected) {
                line.style = line.style.bg(crate::tui::theme::SELECTED_BG);
                if selected == 0 {
                    line.style = line.style.fg(crate::tui::theme::TEXT_STRONG);
                }
            }
        }
        lines
    }

    pub(in crate::tui) fn workspace_layer_span(
        &self,
        kind: BlockKind,
    ) -> Option<std::ops::Range<usize>> {
        self.overview_layout(self.viewport_width)
            .spans
            .iter()
            .find(|(candidate, _)| *candidate == kind)
            .map(|(_, span)| span.clone())
    }

    pub(in crate::tui) fn workspace_rows(&self) -> usize {
        self.overview_layout(self.viewport_width).lines.len()
            + self
                .netdev_table()
                .map_or(1, |table| if table.is_empty() { 1 } else { table.len() })
    }

    pub(in crate::tui) fn render_workspace(
        &self,
        frame: &mut Frame<'_>,
        area: Rect,
        overview: bool,
    ) {
        let summary = if overview {
            self.summary_lines(area.width)
        } else {
            Vec::new()
        };
        let offset = if overview { self.row_offset } else { 0 };
        let mut lines: Vec<_> = summary
            .into_iter()
            .skip(offset)
            .take(usize::from(area.height))
            .collect();
        let remaining = usize::from(area.height).saturating_sub(lines.len());
        if remaining > 0 {
            if let Some(table) = self.netdev_table() {
                let (_, batch) = self.netdev_batch(area.width, usize::from(area.height), overview);
                if batch.is_empty() && !table.is_empty() {
                    lines.extend(module_frame::lines(
                        vec![crate::tui::summary::heading(
                            &crate::tui::summary::fit(
                                &format!("INTERFACE {} interfaces", table.len()),
                                usize::from(module_frame::inner_width(area.width)),
                            ),
                            false,
                        )],
                        area.width,
                    ));
                } else {
                    let mut netdev = table.lines_sorted(
                        area.width,
                        &self.interface_inventory,
                        batch,
                        self.selected_interface.as_ref(),
                        self.netdev_sort,
                        self.netdev_descending,
                    );
                    if !overview || self.overview_selection == OverviewSelection::Interface {
                        module_frame::highlight(&mut netdev);
                    }
                    lines.extend(netdev);
                }
            }
        }
        frame.render_widget(Paragraph::new(lines), area);
    }

    pub(super) fn click(&mut self, column: u16, row: u16) {
        let previous_overview_click = self.overview_click_target.take();
        if let Some(page) = crate::tui::view::page_at(self.viewport_width, column, row) {
            self.socket_click_key = None;
            self.conntrack_click_key = None;
            self.select_page(page);
            return;
        }
        let Some(content_row) = row.checked_sub(crate::tui::view::body_top(self.viewport_width))
        else {
            return;
        };
        if usize::from(content_row) >= self.viewport_rows || column >= self.viewport_width {
            return;
        }
        if self.is_softirq_view() {
            if let Some(sort) = self.softirq_section().and_then(|model| {
                model.header_sort_at(
                    usize::from(column),
                    usize::from(content_row),
                    self.viewport_rows,
                    self.row_offset,
                )
            }) {
                self.softirq_descending = if self.softirq_sort == sort {
                    !self.softirq_descending
                } else {
                    sort.default_descending()
                };
                self.softirq_sort = sort;
                self.softirq_section.take();
                self.row_offset = 0;
            }
            return;
        }
        if self.section == MonitorSection::Hardirq {
            if let Some(sort) = self.hardirq_table().and_then(|table| {
                table.sort_at(
                    column,
                    usize::from(content_row),
                    self.viewport_rows,
                    self.row_offset,
                )
            }) {
                self.hardirq_descending = if sort == self.hardirq_sort {
                    !self.hardirq_descending
                } else {
                    sort.descending()
                };
                self.hardirq_sort = sort;
                self.hardirq_table.take();
                self.row_offset = 0;
            }
            return;
        }
        if self.is_conntrack_flows() {
            if !self.is_conntrack_list() {
                return;
            }
            let Some(logical_row) = self
                .conntrack_view
                .viewport(self.viewport_width, self.viewport_rows, self.row_offset)
                .logical_row(usize::from(content_row))
            else {
                return;
            };
            if self
                .conntrack_view
                .click_header(column, logical_row, self.viewport_width)
            {
                self.conntrack_click_key = None;
                self.ensure_conntrack_selection_visible();
                return;
            }
            let previous = self.conntrack_view.selected_key().cloned();
            if self.conntrack_view.select_viewport_row(
                content_row,
                self.viewport_width,
                self.viewport_rows as u16,
                self.row_offset,
            ) {
                let key = self.conntrack_view.selected_key().cloned();
                let open = key.is_some() && previous == key && self.conntrack_click_key == key;
                self.conntrack_click_key = key;
                if open {
                    self.conntrack_click_key = None;
                    self.open_conntrack_detail();
                }
            }
            return;
        }
        if self.is_tc_view() {
            self.tc_table();
            if self.tc_view.click_header(
                self.tc_table.get().unwrap(),
                self.viewport_width,
                column,
                usize::from(content_row) + self.tc_view.row_offset,
            ) {
                return;
            }
            if let Some(key) = crate::tui::tc::table_row_key(
                self.tc_table(),
                &self.tc_view,
                usize::from(content_row) + self.tc_view.row_offset,
            ) {
                self.tc_table();
                self.tc_view.open_detail(self.tc_table.get().unwrap(), &key);
            }
            return;
        }
        if self.is_socket_table() {
            let Some(snapshot) = self.socket_snapshot() else {
                return;
            };
            let Some(target) = crate::tui::socket::viewport(
                snapshot,
                &self.socket_order,
                self.viewport_width,
                self.viewport_rows,
                self.row_offset,
            )
            .logical_row(usize::from(content_row)) else {
                return;
            };
            if let Some(sort) = crate::tui::socket::header_sort_at(
                snapshot,
                &self.socket_order,
                self.viewport_width,
                column,
                target,
            ) {
                self.socket_order.select_sort(sort);
                self.socket_click_key = None;
                self.reconcile_socket_selection();
                self.ensure_selected_socket_visible();
                return;
            }
            let first_row = crate::tui::socket::socket_row_index(
                snapshot,
                &self.socket_order,
                self.viewport_width,
                0,
            );
            if let Some(position) = first_row
                .and_then(|first| target.checked_sub(first))
                .filter(|&position| position < self.socket_order.shown_count())
            {
                let key = self
                    .socket_order
                    .socket(position)
                    .map(|socket| socket.row_key().clone());
                let open = key.is_some()
                    && self.socket_click_key == key
                    && self.selected_socket_key == key;
                self.selected_socket_key = key.clone();
                self.selected_socket_ordinal = Some(position);
                self.socket_click_key = key;
                if open {
                    self.socket_click_key = None;
                    self.open_socket_detail();
                }
            }
            return;
        }
        if !(self.is_netdev_table()
            || self.section == MonitorSection::Overview
                && self.dashboard_mode == DashboardMode::Summary)
        {
            return;
        }
        let overview = self.page() == Page::Overview;
        let prefix = if overview {
            self.overview_layout(self.viewport_width).lines.len()
        } else {
            0
        };
        let offset = if overview { self.row_offset } else { 0 };
        let logical_row = usize::from(content_row) + offset;
        if overview && logical_row < prefix {
            if column == 0 || column >= self.viewport_width.saturating_sub(1) {
                return;
            }
            for layer in LAYERS {
                if self
                    .workspace_layer_span(layer)
                    .is_some_and(|range| range.contains(&logical_row))
                {
                    let span = self.workspace_layer_span(layer).unwrap();
                    if logical_row + 1 == span.end {
                        return;
                    }
                    let target = OverviewClickTarget::Layer(layer);
                    let open = previous_overview_click.as_ref() == Some(&target)
                        && self.overview_selection == OverviewSelection::Layer(layer);
                    self.overview_selection = OverviewSelection::Layer(layer);
                    if !open {
                        self.overview_click_target = Some(target);
                        return;
                    }
                    if layer == BlockKind::PacketStage(PacketStage::TrafficControl) {
                        let start = span.start;
                        if let Some(key) = crate::tui::tc::overview_row_key(
                            self.tc_table(),
                            module_frame::inner_width(self.viewport_width),
                            logical_row - start,
                        ) {
                            self.saved_overview_offset = self.row_offset;
                            self.saved_overview_selection_was_visible =
                                self.selected_overview_item_is_fully_visible();
                            self.overview_selection = OverviewSelection::Layer(layer);
                            self.tc_table();
                            self.tc_view = TcViewState::default();
                            self.tc_view.set_viewport_rows(self.viewport_rows);
                            self.tc_view.open_detail(self.tc_table.get().unwrap(), &key);
                            self.tc_overview_key = Some(key);
                            self.tc_return_overview = true;
                            self.section = MonitorSection::Tc;
                            return;
                        }
                    }
                    self.overview_selection = OverviewSelection::Layer(layer);
                    self.open_selected_overview_item();
                    return;
                }
            }
        }
        let (prefix_visible, batch) =
            self.netdev_batch(self.viewport_width, self.viewport_rows, overview);
        if overview
            && usize::from(content_row) == prefix_visible
            && column > 0
            && column < self.viewport_width.saturating_sub(1)
        {
            let target = OverviewClickTarget::InterfaceTitle;
            let open = previous_overview_click.as_ref() == Some(&target)
                && self.overview_selection == OverviewSelection::Interface;
            self.overview_selection = OverviewSelection::Interface;
            if open {
                self.select_page(Page::Netdev);
            } else {
                self.overview_click_target = Some(target);
            }
            return;
        }
        if usize::from(content_row) < prefix_visible || batch.is_empty() {
            return;
        }
        let hit = self.netdev_table().and_then(|table| {
            table.hit_test(
                self.viewport_width,
                &self.interface_inventory,
                batch,
                column,
                (usize::from(content_row) - prefix_visible) as u16,
            )
        });
        match hit {
            Some(crate::tui::netdev::NetdevHit::Sort(sort)) => {
                self.netdev_descending = if self.netdev_sort == sort {
                    !self.netdev_descending
                } else {
                    !matches!(sort, NetdevSort::Ifindex | NetdevSort::Name)
                };
                self.netdev_sort = sort;
                self.refresh_interface_inventory();
                self.reconcile_interface_selection();
                self.ensure_netdev_selection_visible();
            }
            Some(crate::tui::netdev::NetdevHit::Interface(identity)) => {
                let target = OverviewClickTarget::Interface(identity.clone());
                let open = previous_overview_click.as_ref() == Some(&target)
                    && self.overview_selection == OverviewSelection::Interface
                    && self.selected_interface.as_ref() == Some(&identity);
                self.selected_interface_ordinal = self
                    .interface_inventory
                    .iter()
                    .position(|item| *item == identity);
                self.selected_interface = Some(identity);
                self.overview_selection = OverviewSelection::Interface;
                if !overview || open {
                    self.open_selected_overview_item();
                } else {
                    self.overview_click_target = Some(target);
                }
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{
        MetricId, MetricLabel, MetricLabels, MetricReading, ProviderHealth, ProviderId,
        ProviderSample, SampleReading,
    };
    use crate::tui::app::Action;
    use std::sync::Arc;
    use std::time::Duration;

    fn app() -> App {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.softirq_metrics_mode = crate::tui::app::DetailMetricsMode::WithData;
        app.set_viewport_size(120, 18);
        app
    }

    fn softirq_snapshots() -> Vec<Arc<crate::monitor::MonitorSnapshot>> {
        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        (1..=4)
            .map(|sequence| {
                let mut counters = Vec::new();
                let mut drops = Vec::new();
                for cpu in 0..40_u64 {
                    let labels = MetricLabels::new([(MetricLabel::Cpu, cpu.to_string())]).unwrap();
                    let rx = match (sequence, cpu) {
                        (2, 0) => 1_500,
                        (3, 0) => 1_501,
                        (4, 0) => 1_502,
                        (2, 1) => 1_010,
                        (3, 1) => 1_310,
                        (4, 1) => 1_610,
                        _ => 1_000,
                    };
                    for (metric, value) in [
                        ("linux.softirq.net_rx", rx),
                        ("linux.softirq.net_tx", sequence * (cpu + 1)),
                    ] {
                        counters.push(SampleReading::observed(
                            MetricId::new(metric).unwrap(),
                            labels.clone(),
                            MetricReading::Counter { value, bits: None },
                        ));
                    }
                    drops.push(SampleReading::observed(
                        MetricId::new("linux.softirq.softnet.dropped").unwrap(),
                        labels,
                        MetricReading::Counter {
                            value: 0,
                            bits: None,
                        },
                    ));
                }
                let at = Duration::from_secs(sequence);
                let samples = [
                    ("linux.proc.softirqs", counters),
                    ("linux.proc.net.softnet_stat", drops),
                ]
                .into_iter()
                .map(|(provider, readings)| {
                    ProviderSample::new(
                        ProviderId::new(provider).unwrap(),
                        at,
                        Duration::from_millis(1),
                        ProviderHealth::Fresh,
                        readings,
                    )
                    .unwrap()
                })
                .collect();
                engine.ingest(at, samples, None).unwrap()
            })
            .collect()
    }

    #[test]
    fn interface_title_selects_then_opens_the_table_even_without_visible_data_rows() {
        for width in [80, 160] {
            for enter in [false, true] {
                let mut app = app();
                app.set_viewport_size(width, 30);
                app.apply_snapshot(super::super::tests::interface_snapshot(
                    1,
                    &[("eth0", 2, "physical")],
                ));
                let prefix = app.overview_layout(width).lines.len();
                app.row_offset = prefix;
                let row = crate::tui::view::body_top(width);
                app.update(Action::Click { column: 3, row });
                assert_eq!(app.page(), Page::Overview);
                assert_eq!(app.overview_selection, OverviewSelection::Interface);
                app.update(if enter {
                    Action::OpenSelectedOverviewItem
                } else {
                    Action::Click { column: 3, row }
                });
                assert!(app.is_netdev_table());
                assert!(!app.is_interface_detail());
            }
        }
    }

    #[test]
    fn softirq_defaults_to_all_columns_on_both_entries_independent_of_other_details() {
        use crate::tui::app::DetailMetricsMode;
        use crate::tui::dashboard::SoftirqSort;
        for overview in [false, true] {
            let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
            app.set_viewport_size(160, 30);
            app.apply_snapshot(softirq_snapshots().pop().unwrap());
            open_softirq(&mut app, overview);
            assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::All);
            softirq_sort_target(&app, SoftirqSort::Metric(3));
            assert_eq!(app.detail_metrics_mode, DetailMetricsMode::WithData);
            app.update(Action::ToggleDetailMetrics);
            assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::WithData);
            app.select_page(Page::Network);
            app.update(Action::ToggleDetailMetrics);
            open_softirq(&mut app, !overview);
            assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::WithData);
        }
    }

    #[test]
    fn overview_click_selects_before_opening_and_switching_targets_rearms() {
        for width in [80, 160] {
            for kind in LAYERS {
                let mut app = app();
                app.set_viewport_size(width, 40);
                app.apply_snapshot(tc_snapshot(1, &[1, 2]));
                let row = crate::tui::view::body_top(width);
                app.row_offset = app.workspace_layer_span(kind).unwrap().start;
                app.update(Action::Click { column: 2, row });
                assert_eq!(app.page(), Page::Overview);
                assert_eq!(app.overview_selection, OverviewSelection::Layer(kind));
                let other = LAYERS.into_iter().find(|layer| *layer != kind).unwrap();
                app.row_offset = app.workspace_layer_span(other).unwrap().start;
                app.update(Action::Click { column: 2, row });
                assert_eq!(app.page(), Page::Overview);
                assert_eq!(app.overview_selection, OverviewSelection::Layer(other));
                app.row_offset = app.workspace_layer_span(kind).unwrap().start;
                app.update(Action::Click { column: 2, row });
                assert_eq!(app.page(), Page::Overview);
                app.update(Action::TogglePause);
                app.update(Action::Click { column: 2, row });
                assert_eq!(app.page(), Page::Overview);
                app.update(Action::Click { column: 2, row });
                assert_ne!(app.page(), Page::Overview);
            }
        }
    }

    #[test]
    fn overview_interface_click_tracks_identity_and_return_requires_selection_again() {
        for width in [80, 160] {
            let mut app = app();
            app.set_viewport_size(width, 30);
            app.apply_snapshot(super::super::tests::interface_snapshot(
                1,
                &[("eth0", 2, "physical"), ("eth1", 3, "physical")],
            ));
            let prefix = app.overview_layout(width).lines.len();
            app.row_offset = prefix;
            let row = crate::tui::view::body_top(width) + 2;
            app.update(Action::Click { column: 2, row });
            assert_eq!(app.page(), Page::Overview);
            assert_eq!(app.selected_interface.as_ref().unwrap().name(), "eth0");
            app.update(Action::Click {
                column: 2,
                row: row + 1,
            });
            assert_eq!(app.page(), Page::Overview);
            assert_eq!(app.selected_interface.as_ref().unwrap().name(), "eth1");
            app.update(Action::Click {
                column: 2,
                row: row + 1,
            });
            assert!(app.is_interface_detail());
            app.update(Action::Back);
            let prefix = app.overview_layout(width).lines.len();
            app.row_offset = prefix;
            app.update(Action::Click {
                column: 2,
                row: row + 1,
            });
            assert_eq!(app.page(), Page::Overview);
            app.update(Action::OpenSelectedOverviewItem);
            assert!(app.is_interface_detail());
        }
    }

    #[test]
    fn softirq_body_and_controls_match_from_overview_and_navigation() {
        for width in [80, 160] {
            let mut app = app();
            app.apply_snapshot(softirq_snapshots().pop().unwrap());
            app.update(Action::TogglePause);
            for mode in [
                crate::tui::app::DetailMetricsMode::WithData,
                crate::tui::app::DetailMetricsMode::All,
            ] {
                app.softirq_metrics_mode = mode;
                open_softirq(&mut app, true);
                app.update(Action::CycleSort);
                let overview = softirq_screen(&mut app, width, 40);
                app.select_page(Page::Softirq);
                let direct = softirq_screen(&mut app, width, 40);
                let first = usize::from(crate::tui::view::body_top(width));
                assert_eq!(&overview[first..], &direct[first..]);
                app.update(Action::ToggleDetailMetrics);
                assert_ne!(app.softirq_metrics_mode, mode);
                app.update(Action::ToggleDetailMetrics);
                assert_eq!(app.softirq_metrics_mode, mode);
            }
        }
    }

    fn open_softirq(app: &mut App, overview_detail: bool) {
        if overview_detail {
            app.select_page(Page::Overview);
            app.overview_selection =
                OverviewSelection::Layer(BlockKind::ExecutionContext(ExecutionContext::Softirq));
            app.update(Action::OpenSelectedOverviewItem);
        } else {
            app.select_page(Page::Softirq);
        }
        assert!(app.is_softirq_view());
    }

    fn softirq_screen(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let area = Rect::new(0, 0, width, height);
        let rows = crate::tui::view::body_rows(area, app);
        app.set_viewport_size(width, rows);
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        terminal
            .draw(|frame| crate::tui::view::render(frame, app))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect())
            .collect()
    }

    fn softirq_sort_target(app: &App, sort: crate::tui::dashboard::SoftirqSort) -> (u16, u16) {
        let model = app.softirq_section().unwrap();
        (0..app.viewport_rows)
            .find_map(|y| {
                (0..app.viewport_width).find_map(|x| {
                    (model.header_sort_at(usize::from(x), y, app.viewport_rows, app.row_offset)
                        == Some(sort))
                    .then_some((x, y as u16 + crate::tui::view::body_top(app.viewport_width)))
                })
            })
            .expect("visible sortable header")
    }

    fn first_softirq_cpu(app: &App, screen: &[String]) -> u32 {
        let row = usize::from(crate::tui::view::body_top(app.viewport_width))
            + app
                .softirq_section()
                .unwrap()
                .viewport(app.viewport_rows, app.row_offset)
                .data_start();
        screen[row]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn softirq_sort_click_keys_and_sticky_scroll_work_on_both_routes() {
        use crate::tui::dashboard::SoftirqSort;
        let snapshot = softirq_snapshots().pop().unwrap();
        for overview in [false, true] {
            for width in [80, 160] {
                let mut app = app();
                app.apply_snapshot(snapshot.clone());
                open_softirq(&mut app, overview);
                let initial = softirq_screen(&mut app, width, 24);
                assert_eq!(first_softirq_cpu(&app, &initial), 0);
                assert_eq!(app.softirq_sort, SoftirqSort::Cpu);
                assert!(!app.softirq_descending);
                let (x, y) = softirq_sort_target(&app, SoftirqSort::Metric(0));
                app.update(Action::Click { column: x, row: y });
                let sorted = softirq_screen(&mut app, width, 24);
                assert_eq!(first_softirq_cpu(&app, &sorted), 1);
                assert!(app.softirq_descending);
                app.update(Action::Click { column: x, row: y });
                assert!(!app.softirq_descending);
                let next = app.softirq_section().unwrap().next_sort(app.softirq_sort);
                app.update(Action::CycleSort);
                assert_eq!(app.softirq_sort, next);
                assert_eq!(app.softirq_descending, next.default_descending());
                app.update(Action::ReverseSort);
                assert_eq!(app.softirq_descending, !next.default_descending());

                let (x, y) = softirq_sort_target(&app, SoftirqSort::Cpu);
                app.update(Action::Click { column: x, row: y });
                assert!(!app.softirq_descending);
                let before = softirq_screen(&mut app, width, 24);
                let page = app
                    .softirq_section()
                    .unwrap()
                    .viewport(app.viewport_rows, app.row_offset);
                let expected_offset = page.capacity.max(1).min(page.max_offset);
                app.update(Action::PageDown);
                assert!(app.row_offset > 0);
                assert_eq!(app.row_offset, expected_offset);
                let after = softirq_screen(&mut app, width, 24);
                assert!(first_softirq_cpu(&app, &after) > 0);
                let view = app
                    .softirq_section()
                    .unwrap()
                    .viewport(app.viewport_rows, app.row_offset);
                let body_top = usize::from(crate::tui::view::body_top(width));
                assert_eq!(
                    &before[body_top..body_top + view.data_start()],
                    &after[body_top..body_top + view.data_start()]
                );
                app.update(Action::PageUp);
                assert_eq!(app.row_offset, 0);
                app.update(Action::PageDown);
                app.update(Action::Click { column: x, row: y });
                assert!(app.softirq_descending);
                assert_eq!(app.row_offset, 0);
                let reversed_cpu = softirq_screen(&mut app, width, 24);
                assert_eq!(first_softirq_cpu(&app, &reversed_cpu), 39);
                assert!(after.last().unwrap().contains("s sort"));

                let expected = (app.softirq_sort, app.softirq_descending);
                let model = app.softirq_section().unwrap();
                let view = model.viewport(app.viewport_rows, app.row_offset);
                let mut ignored = vec![
                    (0, 0),
                    (0, view.data_start()),
                    (usize::from(width), view.context),
                ];
                ignored.extend(
                    (0..usize::from(width))
                        .filter(|x| {
                            model
                                .header_sort_at(*x, view.context, app.viewport_rows, app.row_offset)
                                .is_none()
                        })
                        .map(|x| (x, view.context)),
                );
                for (x, row) in ignored {
                    app.update(Action::Click {
                        column: x as u16,
                        row: row as u16 + body_top as u16,
                    });
                    assert_eq!((app.softirq_sort, app.softirq_descending), expected);
                }
            }
        }
    }

    #[test]
    fn softirq_sort_cache_tracks_time_metrics_pause_and_route_changes() {
        use crate::tui::app::{DetailMetricsMode, TimeView};
        use crate::tui::dashboard::SoftirqSort;
        let snapshots = softirq_snapshots();
        let mut app = app();
        app.apply_snapshot(snapshots[2].clone());
        open_softirq(&mut app, true);
        softirq_screen(&mut app, 160, 24);
        app.update(Action::CycleSort);
        assert_eq!(app.softirq_sort, SoftirqSort::Metric(0));
        let before = softirq_screen(&mut app, 160, 24);
        assert_eq!(first_softirq_cpu(&app, &before), 1);
        app.update(Action::TogglePause);
        app.apply_snapshot(snapshots[3].clone());
        assert!(std::ptr::eq(app.snapshot().unwrap(), snapshots[2].as_ref()));
        app.update(Action::ToggleTimeView);
        assert_eq!(app.time_view, TimeView::SinceBaseline);
        let baseline = softirq_screen(&mut app, 160, 24);
        assert_eq!(first_softirq_cpu(&app, &baseline), 0);
        app.update(Action::ReverseSort);
        let reversed = softirq_screen(&mut app, 160, 24);
        assert!(first_softirq_cpu(&app, &reversed) >= 2);
        let visible = |app: &App| {
            let model = app.softirq_section().unwrap();
            let mut sorts = vec![SoftirqSort::Cpu];
            loop {
                let next = model.next_sort(*sorts.last().unwrap());
                if next == SoftirqSort::Cpu {
                    break;
                }
                assert!(!sorts.contains(&next));
                sorts.push(next);
            }
            sorts
        };
        assert!(!visible(&app).contains(&SoftirqSort::Metric(3)));
        app.update(Action::ToggleDetailMetrics);
        assert_eq!(app.softirq_metrics_mode, DetailMetricsMode::All);
        assert!(visible(&app).contains(&SoftirqSort::Metric(3)));
        app.update(Action::ToggleDetailMetrics);
        assert!(!visible(&app).contains(&SoftirqSort::Metric(3)));
        let sort = (app.softirq_sort, app.softirq_descending);
        open_softirq(&mut app, false);
        assert_eq!((app.softirq_sort, app.softirq_descending), sort);
        assert!(!visible(&app).contains(&SoftirqSort::Metric(3)));
        open_softirq(&mut app, true);
        assert_eq!((app.softirq_sort, app.softirq_descending), sort);
        assert!(!visible(&app).contains(&SoftirqSort::Metric(3)));
        app.update(Action::TogglePause);
        assert!(std::ptr::eq(app.snapshot().unwrap(), snapshots[3].as_ref()));
    }

    #[test]
    fn softirq_hidden_sort_falls_back_consistently_for_keys_and_clicks() {
        use crate::tui::dashboard::SoftirqSort;
        let mut app = app();
        app.apply_snapshot(softirq_snapshots().pop().unwrap());
        open_softirq(&mut app, true);
        softirq_screen(&mut app, 160, 24);
        app.update(Action::ToggleDetailMetrics);
        let (x, row) = softirq_sort_target(&app, SoftirqSort::Metric(3));
        app.update(Action::Click { column: x, row });
        assert!(app.softirq_descending);
        app.update(Action::ToggleDetailMetrics);
        assert_eq!(app.softirq_sort, SoftirqSort::Cpu);
        assert!(!app.softirq_descending);
        assert_eq!(
            app.softirq_section().unwrap().effective_sort(),
            app.softirq_sort
        );
        assert_eq!(
            app.softirq_section().unwrap().effective_descending(),
            app.softirq_descending
        );
        app.update(Action::CycleSort);
        assert_eq!(app.softirq_sort, SoftirqSort::Metric(0));
        assert!(app.softirq_descending);
        open_softirq(&mut app, false);
        app.update(Action::ToggleDetailMetrics);
        let (x, row) = softirq_sort_target(&app, SoftirqSort::Metric(9));
        app.update(Action::Click { column: x, row });
        app.set_viewport_size(12, 18);
        assert_eq!(app.softirq_sort, SoftirqSort::Cpu);
        assert!(!app.softirq_descending);
        app.set_viewport_size(160, 18);
        let (x, row) = softirq_sort_target(&app, SoftirqSort::Cpu);
        app.update(Action::Click { column: x, row });
        assert_eq!(app.softirq_sort, SoftirqSort::Cpu);
        assert!(app.softirq_descending);
        app.update(Action::ReverseSort);
        assert!(!app.softirq_descending);
        let (x, row) = softirq_sort_target(&app, SoftirqSort::Metric(3));
        app.update(Action::Click { column: x, row });
        open_softirq(&mut app, true);
        assert_eq!(app.softirq_sort, SoftirqSort::Metric(3));
        app.update(Action::ToggleDetailMetrics);
        assert_eq!(app.softirq_sort, SoftirqSort::Cpu);
        assert!(!app.softirq_descending);
    }

    #[test]
    fn softirq_sort_works_without_a_snapshot_and_clamps_after_resize() {
        let mut app = app();
        for overview in [false, true] {
            open_softirq(&mut app, overview);
            assert!(softirq_screen(&mut app, 80, 24)
                .join("\n")
                .contains("Collecting SoftIRQ"));
            app.update(Action::CycleSort);
            app.update(Action::ReverseSort);
            app.update(Action::PageDown);
            assert_eq!(app.row_offset, 0);
        }
        app.apply_snapshot(softirq_snapshots().pop().unwrap());
        for _ in 0..100 {
            app.update(Action::PageDown);
        }
        let maximum = app
            .softirq_section()
            .unwrap()
            .viewport(app.viewport_rows, 0)
            .max_offset;
        assert_eq!(app.row_offset, maximum);
        softirq_screen(&mut app, 160, 80);
        assert_eq!(app.row_offset, 0);
    }

    #[test]
    fn insufficient_netdev_space_reports_count_without_false_empty_or_click_targets() {
        let mut app = app();
        app.apply_snapshot(super::super::tests::interface_snapshot(
            1,
            &[("eth0", 2, "physical"), ("eth1", 3, "physical")],
        ));
        for width in [80, 160] {
            let prefix = app.summary_lines(width).len();
            let height = prefix as u16 + 5;
            app.set_viewport_size(width, usize::from(height));
            app.row_offset = 0;
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| app.render_workspace(frame, frame.area(), true))
                .unwrap();
            let text = terminal.backend().to_string();
            assert!(text.contains("INTERFACE 2 interfaces"), "{text}");
            assert!(!text.contains("No interfaces"), "{text}");
            assert!(!text.contains("TRAFFIC"), "{text}");
            let sort = app.netdev_sort;
            for offset in 0..5 {
                app.click(
                    30,
                    crate::tui::view::body_top(width) + prefix as u16 + offset,
                );
                assert_eq!(app.dashboard_mode, DashboardMode::Summary);
                assert_eq!(app.netdev_sort, sort);
            }
        }
    }

    fn command(app: &mut App, command: &str) {
        app.update(Action::EnterCommand);
        for ch in command.chars() {
            app.update(Action::Insert(ch));
        }
        app.update(Action::SubmitCommand);
        assert!(app.command_error().is_none());
    }

    #[test]
    fn conntrack_snapshot_pause_filter_sort_detail_and_mouse_share_selection() {
        let (first, next) = crate::tui::conntrack::tests::fixture_snapshots();
        let mut app = app();
        command(&mut app, "conntrack");
        assert!(app.is_conntrack_list());
        assert_eq!(
            app.collection_focus(),
            crate::monitor::focus::CollectionFocus::ConntrackFlows
        );
        app.set_viewport_size(120, 6);
        app.apply_conntrack_snapshot(Arc::clone(&first));
        assert_eq!(app.conntrack_view.shown_count(), 3);
        app.update(Action::PageDown);
        assert_eq!(app.conntrack_view.selected_position(), Some(1));
        app.update(Action::PageDown);
        assert_eq!(app.conntrack_view.selected_position(), Some(2));
        app.update(Action::ScrollUp);
        let selected = app.conntrack_view.selected_key().cloned();
        app.update(Action::CycleSort);
        app.update(Action::ReverseSort);
        assert_eq!(app.conntrack_view.selected_key(), selected.as_ref());
        app.update(Action::OpenConntrackDetail);
        assert!(app.conntrack_view.is_detail());
        app.update(Action::TogglePause);
        app.apply_conntrack_snapshot(Arc::clone(&next));
        assert_eq!(
            app.conntrack_snapshot().unwrap().sequence(),
            first.sequence()
        );
        app.update(Action::TogglePause);
        assert_eq!(
            app.conntrack_snapshot().unwrap().sequence(),
            next.sequence()
        );
        assert_eq!(app.conntrack_view.selected_key(), selected.as_ref());
        app.update(Action::Back);
        assert!(app.is_conntrack_list());
        // The refreshed sample can move the selected flow in the sorted order.
        assert_eq!(
            app.row_offset,
            app.conntrack_view.selected_position().unwrap()
        );
        app.update(Action::ScrollTop);
        assert_eq!(app.conntrack_view.selected_position(), Some(0));
        let viewport = app
            .conntrack_view
            .viewport(120, app.viewport_rows, app.row_offset);
        let row = viewport.data_start() as u16 + crate::tui::view::body_top(120);
        app.update(Action::Click { column: 4, row });
        assert!(app.is_conntrack_list());
        app.update(Action::Click { column: 4, row });
        assert!(app.conntrack_view.is_detail());
        app.update(Action::EnterFlowFilter);
        for ch in "host=10.0.0.2 port=443 proto=tcp".chars() {
            app.update(Action::Insert(ch));
        }
        app.update(Action::SubmitCommand);
        assert!(app.is_conntrack_list());
        assert_eq!(app.conntrack_view.shown_count(), 1);
        let key = app.conntrack_view.selected_key().cloned();
        app.apply_conntrack_snapshot(first);
        assert_eq!(
            app.conntrack_snapshot().unwrap().sequence(),
            next.sequence()
        );
        assert_eq!(app.conntrack_view.selected_key(), key.as_ref());
        app.update(Action::OpenConntrackDiagnostics);
        assert!(app.conntrack_view.is_detail());
        app.update(Action::Back);
        assert!(app.is_conntrack_list());
        app.update(Action::Back);
        assert_eq!(app.page(), Page::Overview);
        assert!(!app.is_conntrack_flows());
        assert!(app.conntrack_snapshot().is_none());
        assert!(app.conntrack_view.selected_key().is_none());
    }

    #[test]
    fn scrolled_connection_headers_sort_and_data_clicks_open_the_visible_connection() {
        let width = 160;
        let body = crate::tui::view::body_top(width);
        let mut app = app();
        command(&mut app, "socket");
        app.set_viewport_size(width, 3);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_sort_snapshot(2));
        app.update(Action::PageDown);
        assert_eq!(app.selected_socket_ordinal(), Some(1));
        assert_eq!(app.row_offset, 1);
        let key = app.selected_socket_key().cloned().unwrap();
        let snapshot = app.socket_snapshot().unwrap();
        let header = crate::tui::socket::socket_row_index(snapshot, app.socket_order(), width, 0)
            .unwrap()
            - 1;
        let x = (0..width)
            .find(|&x| {
                crate::tui::socket::header_sort_at(snapshot, app.socket_order(), width, x, header)
                    .is_some_and(|sort| sort.label() == "TX queue")
            })
            .unwrap();
        for direction in ["desc", "asc"] {
            app.update(Action::Click {
                column: x,
                row: body + 1,
            });
            assert!(app.is_socket_table());
            assert!(app
                .socket_order
                .status()
                .contains(&format!("TX queue {direction}")));
            assert_eq!(app.selected_socket_key(), Some(&key));
        }
        let clicked = app
            .socket_order
            .socket(app.row_offset)
            .unwrap()
            .row_key()
            .clone();
        let offset = app.row_offset;
        app.update(Action::Click {
            column: 4,
            row: body + 2,
        });
        assert!(app.is_socket_table());
        assert_eq!(app.selected_socket_key(), Some(&clicked));
        app.update(Action::Click {
            column: 4,
            row: body + 2,
        });
        assert!(app.is_socket_detail());
        assert_eq!(app.socket_detail().unwrap().key(), &clicked);
        app.update(Action::Back);
        assert_eq!(app.row_offset, offset);
        app.set_viewport_size(width, 30);
        assert_eq!(app.row_offset, 0);
        app.set_viewport_size(width, 3);
        assert_eq!(app.row_offset, app.selected_socket_ordinal().unwrap());

        command(&mut app, "conntrack");
        let (_, snapshot) = crate::tui::conntrack::tests::fixture_snapshots();
        app.apply_conntrack_snapshot(snapshot);
        app.update(Action::PageDown);
        app.update(Action::PageDown);
        assert_eq!(app.conntrack_view.selected_position(), Some(2));
        assert_eq!(app.row_offset, 2);
        let key = app.conntrack_view.selected_key().cloned();
        let layout = crate::tui::sort_table::TrafficLayout::new(usize::from(width), true);
        let x = (layout.prefix.iter().sum::<usize>() + layout.prefix.len()) as u16;
        for descending in [true, false] {
            app.update(Action::Click {
                column: x,
                row: body + 1,
            });
            assert!(app.is_conntrack_list());
            assert_eq!(app.conntrack_view.sort().label(), "TX bytes");
            assert_eq!(app.conntrack_view.descending(), descending);
            assert_eq!(app.conntrack_view.selected_key(), key.as_ref());
        }
        let offset = app.row_offset;
        app.update(Action::Click {
            column: 4,
            row: body + 2,
        });
        assert!(app.is_conntrack_list());
        app.update(Action::Click {
            column: 4,
            row: body + 2,
        });
        assert!(app.conntrack_view.is_detail());
        assert_eq!(app.conntrack_view.selected_key(), key.as_ref());
        app.update(Action::Back);
        assert_eq!(app.row_offset, offset);
        app.set_viewport_size(width, 30);
        assert_eq!(app.row_offset, 0);
        app.set_viewport_size(width, 3);
        assert_eq!(
            app.row_offset,
            app.conntrack_view.selected_position().unwrap()
        );
    }

    #[test]
    fn clicking_connection_headers_changes_sort_and_never_opens_a_connection() {
        let width = 160;
        let body = crate::tui::view::body_top(width);
        let mut app = app();
        command(&mut app, "socket");
        app.set_viewport_size(width, 30);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_table_snapshot());
        let snapshot = app.socket_snapshot().unwrap();
        let header = crate::tui::socket::socket_row_index(snapshot, app.socket_order(), width, 0)
            .unwrap()
            - 1;
        let x = (0..width)
            .find(|&x| {
                crate::tui::socket::header_sort_at(snapshot, app.socket_order(), width, x, header)
                    .is_some_and(|sort| sort.label() == "TX queue")
            })
            .unwrap();
        let key = app.selected_socket_key().cloned();
        app.update(Action::Click {
            column: x,
            row: header as u16 + body,
        });
        assert!(app.is_socket_table());
        assert!(app.socket_order.status().contains("TX queue desc"));
        app.update(Action::Click {
            column: x,
            row: header as u16 + body,
        });
        assert!(app.socket_order.status().contains("TX queue asc"));
        assert_eq!(app.selected_socket_key(), key.as_ref());

        command(&mut app, "conntrack");
        let (_, snapshot) = crate::tui::conntrack::tests::fixture_snapshots();
        app.apply_conntrack_snapshot(snapshot);
        let header = app.conntrack_view.row_span(0, width).unwrap().start - 1;
        let layout = crate::tui::sort_table::TrafficLayout::new(usize::from(width), true);
        let x = (layout.prefix.iter().sum::<usize>() + layout.prefix.len()) as u16;
        let key = app.conntrack_view.selected_key().cloned();
        app.row_offset = 0;
        app.update(Action::Click {
            column: x,
            row: header as u16 + body,
        });
        assert!(app.is_conntrack_list());
        assert_eq!(app.conntrack_view.sort().label(), "TX bytes");
        assert!(app.conntrack_view.descending());
        app.update(Action::Click {
            column: x,
            row: header as u16 + body,
        });
        assert!(!app.conntrack_view.descending());
        assert_eq!(app.conntrack_view.selected_key(), key.as_ref());
    }

    #[test]
    fn socket_sorting_preserves_identity_pause_navigation_and_mouse_details() {
        let mut app = App::new(
            crate::monitor::MonitorSection::Overview,
            std::time::Duration::from_secs(1),
        );
        command(&mut app, "socket");
        app.set_viewport_size(160, 25);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_sort_snapshot(2));
        let selected = app.selected_socket_key().cloned().unwrap();
        assert_eq!(app.selected_socket_ordinal(), Some(0));
        app.update(Action::CycleSort);
        assert!(app.socket_order.status().contains("TX queue desc"));
        assert_eq!(app.selected_socket_key(), Some(&selected));
        assert_eq!(app.selected_socket_ordinal(), Some(1));
        app.update(Action::ReverseSort);
        assert_eq!(app.selected_socket_ordinal(), Some(1));
        app.update(Action::TogglePause);
        app.apply_socket_snapshot(crate::monitor::socket_table::synthetic_socket_sort_snapshot(3));
        app.update(Action::CycleSort);
        assert_eq!(app.socket_snapshot().unwrap().sequence(), 2);
        app.update(Action::OpenSocketDetail);
        assert_eq!(app.socket_detail().unwrap().key(), &selected);
        app.update(Action::Back);
        app.update(Action::TogglePause);
        assert_eq!(app.socket_snapshot().unwrap().sequence(), 3);
        assert_eq!(app.selected_socket_key(), Some(&selected));
        let first = crate::tui::socket::socket_row_index(
            app.socket_snapshot().unwrap(),
            app.socket_order(),
            160,
            0,
        )
        .unwrap();
        let clicked = app.socket_order.socket(0).unwrap().row_key().clone();
        let row = first.saturating_sub(app.row_offset) as u16 + crate::tui::view::body_top(160);
        app.update(Action::Click { column: 4, row });
        assert!(app.is_socket_table());
        assert_eq!(app.selected_socket_key(), Some(&clicked));
        app.update(Action::Click { column: 4, row });
        assert!(app.is_socket_detail());
        assert_eq!(app.socket_detail().unwrap().key(), &clicked);
        app.update(Action::Back);
        app.update(Action::ScrollTop);
        assert_eq!(app.selected_socket_key(), Some(&clicked));
        app.update(Action::ScrollDown);
        assert_eq!(app.selected_socket_ordinal(), Some(1));
    }

    #[test]
    fn filtered_socket_clicks_and_paused_details_use_the_filtered_identity() {
        let mut app = App::new(
            crate::monitor::MonitorSection::Overview,
            std::time::Duration::from_secs(1),
        );
        command(&mut app, "socket");
        app.set_viewport_size(160, 25);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::TogglePause);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3),
        );
        app.update(Action::EnterSocketFilter);
        for c in "src=2001:db8::/32 proto=udp".chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        assert_eq!(app.socket_order.shown_count(), 1);
        assert_eq!(app.socket_snapshot().unwrap().sequence(), 2);
        let selected = app.selected_socket_key().cloned().unwrap();
        let view = crate::tui::socket::viewport(
            app.socket_snapshot().unwrap(),
            app.socket_order(),
            160,
            25,
            0,
        );
        let row = view.data_start() as u16 + crate::tui::view::body_top(160);
        app.update(Action::Click {
            column: 4,
            row: row + 1,
        });
        assert!(app.is_socket_table());
        assert_eq!(app.selected_socket_key(), Some(&selected));
        app.update(Action::Click { column: 4, row });
        assert!(app.is_socket_table());
        app.update(Action::Click { column: 4, row });
        assert!(app.is_socket_detail());
        assert_eq!(app.socket_detail().unwrap().key(), &selected);
        app.update(Action::Back);
        app.update(Action::TogglePause);
        assert_eq!(app.socket_snapshot().unwrap().sequence(), 3);
        assert_eq!(app.selected_socket_key(), Some(&selected));
    }

    #[test]
    fn page_aliases_and_legacy_sections_keep_distinct_entry_points() {
        for (alias, page) in [
            ("conntrack", Page::Conntrack),
            ("flows", Page::Conntrack),
            ("socket", Page::Socket),
            ("netdev", Page::Netdev),
            ("tc", Page::Tc),
            ("transport", Page::Transport),
            ("network", Page::Network),
            ("route", Page::Route),
        ] {
            let mut app = app();
            command(&mut app, alias);
            assert_eq!(app.page(), page, "{alias}");
            if page == Page::Socket {
                assert!(app.is_socket_table());
            }
        }
        let mut app = App::new(MonitorSection::Netfilter, Duration::from_secs(1));
        assert!(app.is_netfilter_view());
        app.update(Action::OpenNetfilterItem);
        app.update(Action::OpenConntrackFlows);
        assert!(app.is_conntrack_list());
        assert_eq!(
            app.collection_focus(),
            crate::monitor::focus::CollectionFocus::ConntrackFlows
        );
        app.update(Action::Back);
        assert!(app.is_netfilter_conntrack());
        assert_eq!(app.collection_focus(), MonitorSection::Netfilter.into());
    }

    #[test]
    fn overview_refresh_preserves_manual_scroll_away_from_selected_interface() {
        let mut app = app();
        app.apply_snapshot(super::super::tests::interface_snapshot(
            1,
            &[("eth1", 1, "physical")],
        ));
        for _ in 0..LAYERS.len() {
            app.update(Action::SelectNextOverviewItem);
        }
        assert!(app.row_offset > 0);
        app.update(Action::ScrollTop);
        assert_eq!(app.row_offset, 0);
        app.apply_snapshot(super::super::tests::interface_snapshot(
            2,
            &[("eth1", 1, "physical")],
        ));
        assert_eq!(app.row_offset, 0);
        app.set_viewport_size(100, 17);
        assert_eq!(app.row_offset, 0);
        assert_eq!(app.selected_interface().unwrap().name(), "eth1");
    }

    #[test]
    fn netdev_batches_keep_every_selected_row_visible_and_restore_standalone_origin() {
        let interfaces: Vec<_> = (1..=24).map(|i| (format!("eth{i}"), i)).collect();
        let fixture: Vec<_> = interfaces
            .iter()
            .map(|(name, index)| (name.as_str(), *index, "physical"))
            .collect();
        for width in [80, 144, 145, 160] {
            let mut app = app();
            app.set_viewport_size(width, 18);
            app.apply_snapshot(super::super::tests::interface_snapshot(1, &fixture));
            for _ in 0..LAYERS.len() {
                app.update(Action::SelectNextOverviewItem);
            }
            for index in 0..fixture.len() {
                assert_eq!(app.selected_interface_ordinal, Some(index));
                let span = app.workspace_interface_span().unwrap();
                assert!(
                    span.start >= app.row_offset && span.end <= app.row_offset + app.viewport_rows,
                    "width={width} index={index} span={span:?}"
                );
                let (_, batch) = app.netdev_batch(width, 18, true);
                assert!(batch.contains(&index));
                app.update(Action::SelectNextOverviewItem);
            }
            app.select_page(Page::Netdev);
            app.move_netdev(-4);
            let selected = app.selected_interface.clone();
            let first = app.netdev_first;
            let (_, batch) = app.netdev_batch(width, 18, false);
            let index = app.selected_interface_ordinal.unwrap();
            let row = crate::tui::view::body_top(width) + 2 + (index - batch.start) as u16;
            app.update(Action::Click { column: 2, row });
            assert!(app.is_interface_detail());
            app.update(Action::OpenSelectedInterfaceLayer);
            app.update(Action::Back);
            assert!(app.is_interface_detail());
            app.update(Action::Back);
            assert!(app.is_netdev_table());
            assert_eq!(app.section, MonitorSection::Nic);
            assert_eq!(app.selected_interface, selected);
            assert_eq!(app.netdev_first, first);
            app.update(Action::Click {
                column: 2,
                row: crate::tui::view::body_top(width) + 18,
            });
            assert!(app.is_netdev_table(), "footer click must not open a row");
        }
    }

    fn tc_snapshot(cycle: u64, row_ids: &[u64]) -> Arc<crate::monitor::MonitorSnapshot> {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let mut result = None;
        for at in 1..=cycle + 1 {
            let rows = row_ids
                .iter()
                .map(|id| {
                    SampleReading::observed(
                        MetricId::new("linux.tc.requeues").unwrap(),
                        MetricLabels::new([
                            (MetricLabel::Interface, "eth0".to_owned()),
                            (MetricLabel::Ifindex, "2".to_owned()),
                            (MetricLabel::ObjectKind, "qdisc".to_owned()),
                            (MetricLabel::Direction, "egress".to_owned()),
                            (MetricLabel::QdiscKind, "fq_codel".to_owned()),
                            (MetricLabel::RowId, id.to_string()),
                            (MetricLabel::Execution, "software".to_owned()),
                            (
                                MetricLabel::QdiscAttachment,
                                format!("[true,\"{id}:\",null]"),
                            ),
                        ])
                        .unwrap(),
                        MetricReading::Counter {
                            value: at * id,
                            bits: Some(crate::monitor::CounterBits::Bits64),
                        },
                    )
                })
                .collect();
            let elapsed = Duration::from_secs(at);
            let sample = ProviderSample::new(
                ProviderId::new("linux.tc.json").unwrap(),
                elapsed,
                Duration::ZERO,
                ProviderHealth::Fresh,
                rows,
            )
            .unwrap();
            result = Some(engine.ingest(elapsed, vec![sample], None).unwrap());
        }
        result.unwrap()
    }

    #[test]
    fn overview_layout_tracks_pause_resize_refresh_and_click_positions() {
        let mut app = app();
        assert!(app.summary_lines(160)[0].to_string().contains("Collecting"));
        app.apply_snapshot(tc_snapshot(1, &[1, 2]));
        let live = app.summary_lines(160);
        assert!(live
            .iter()
            .any(|line| line.to_string().contains("REQUEUE/s")));
        app.update(Action::TogglePause);
        app.apply_snapshot(tc_snapshot(2, &[]));
        assert_eq!(app.summary_lines(160), live);
        app.set_viewport_size(80, 30);
        assert!(app.summary_lines(80).iter().all(|line| line.width() <= 80));
        assert!(app
            .summary_lines(80)
            .iter()
            .any(|line| line.to_string().contains("REQUEUE/s")));
        app.update(Action::TogglePause);
        let resumed = app.summary_lines(80);
        assert!(resumed
            .iter()
            .any(|line| line.to_string().contains("No observed")));
        assert!(!resumed
            .iter()
            .any(|line| line.to_string().contains("REQUEUE/s")));
        let kind = BlockKind::ExecutionContext(ExecutionContext::Softirq);
        let span = app.workspace_layer_span(kind).unwrap();
        assert!(resumed[span.start].to_string().contains("SOFTIRQ"));
        app.row_offset = 0;
        app.click(2, crate::tui::view::body_top(80) + span.start as u16);
        assert_eq!(app.page(), Page::Overview);
        assert_eq!(app.overview_selection, OverviewSelection::Layer(kind));
        app.click(2, crate::tui::view::body_top(80) + span.start as u16);
        assert_eq!(app.page(), Page::Softirq);
    }

    #[test]
    fn overview_module_borders_preserve_tc_row_identity_and_cached_styles() {
        let kind = BlockKind::PacketStage(PacketStage::TrafficControl);
        for width in [60, 80, 119, 120, 144, 145, 160] {
            let mut app = app();
            app.set_viewport_size(width, 50);
            app.apply_snapshot(tc_snapshot(1, &[1, 2]));
            let unselected = app.summary_lines(width);
            assert!(unselected
                .iter()
                .all(|line| line.width() <= usize::from(width)));
            for layer in LAYERS {
                let span = app.workspace_layer_span(layer).unwrap();
                let lines = &unselected[span];
                assert!(lines[0]
                    .to_string()
                    .starts_with(ratatui::symbols::border::PLAIN.top_left));
                assert!(lines
                    .last()
                    .unwrap()
                    .to_string()
                    .ends_with(ratatui::symbols::border::PLAIN.bottom_right));
                assert!(lines.iter().all(|line| line.width() == usize::from(width)));
            }
            let span = app.workspace_layer_span(kind).unwrap();
            app.row_offset = span.start;
            let first = crate::tui::view::body_top(width);
            for (x, y) in [(0, 1), (width - 1, 1), (2, span.len() as u16 - 1)] {
                app.click(x, first + y);
                assert_eq!(app.page(), Page::Overview);
            }
            app.overview_selection = OverviewSelection::Layer(kind);
            let selected = app.summary_lines(width);
            for line in &selected[span.clone()] {
                assert_eq!(
                    line.spans.first().unwrap().style.fg,
                    Some(crate::tui::theme::ACCENT)
                );
                assert_eq!(
                    line.spans.last().unwrap().style.fg,
                    Some(crate::tui::theme::ACCENT)
                );
            }
            app.overview_selection = OverviewSelection::Layer(LAYERS[0]);
            assert_eq!(app.summary_lines(width), unselected);
            let key = app.tc_table().overview_rows()[1].key.clone();
            let row = crate::tui::tc::overview_row_index(
                app.tc_table(),
                module_frame::inner_width(width),
                &key,
            )
            .unwrap();
            app.click(2, first + row as u16);
            assert_eq!(app.page(), Page::Overview);
            assert_eq!(app.overview_selection, OverviewSelection::Layer(kind));
            app.click(2, first + row as u16);
            assert!(app.is_tc_view() && app.tc_view.detail());
            assert_eq!(app.tc_view.selected.as_ref(), Some(&key));
            app.update(Action::Back);
            assert_eq!(app.page(), Page::Overview);
            assert_eq!(app.row_offset, span.start);
        }
    }

    #[test]
    fn tc_reconciles_snapshots_and_preserves_list_and_overview_detail_origins() {
        let mut app = app();
        app.apply_snapshot(tc_snapshot(1, &[1, 2]));
        app.select_page(Page::Tc);
        assert!(app.tc_view.selected.is_some());
        let selected = app.tc_view.selected.clone().unwrap();
        app.update(Action::OpenTcItem);
        assert!(app.tc_view.detail());
        app.apply_snapshot(tc_snapshot(2, &[]));
        assert_eq!(app.snapshot().unwrap().sequence(), 3);
        assert_eq!(app.tc_view.selected.as_ref(), Some(&selected));
        app.update(Action::Back);
        assert!(app.is_tc_view());
        assert!(!app.tc_view.detail());
        app.apply_snapshot(tc_snapshot(3, &[3]));
        let third = app.tc_view.selected.clone().unwrap();
        assert_ne!(third, selected);
        app.update(Action::TogglePause);
        app.apply_snapshot(tc_snapshot(4, &[4]));
        assert_eq!(app.tc_view.selected.as_ref(), Some(&third));
        app.update(Action::TogglePause);
        assert!(app.tc_view.selected.is_some());
        assert_ne!(app.tc_view.selected.as_ref(), Some(&third));
        app.select_page(Page::Overview);
        app.overview_selection =
            OverviewSelection::Layer(BlockKind::PacketStage(PacketStage::TrafficControl));
        app.open_selected_overview_item();
        app.update(Action::OpenTcItem);
        app.update(Action::Back);
        assert!(app.is_tc_view() && !app.tc_view.detail());
        app.update(Action::Back);
        assert_eq!(app.page(), Page::Overview);
        let span = app
            .workspace_layer_span(BlockKind::PacketStage(PacketStage::TrafficControl))
            .unwrap();
        app.row_offset = span.start;
        let content_width = module_frame::inner_width(app.viewport_width);
        let lines = crate::tui::tc::overview_lines(app.tc_table(), content_width);
        let row = (0..lines.len())
            .find(|row| {
                crate::tui::tc::overview_row_key(app.tc_table(), content_width, *row).is_some()
            })
            .unwrap();
        app.click(
            2,
            crate::tui::view::body_top(app.viewport_width) + row as u16,
        );
        assert_eq!(app.page(), Page::Overview);
        app.click(
            2,
            crate::tui::view::body_top(app.viewport_width) + row as u16,
        );
        assert!(app.is_tc_view() && app.tc_view.detail());
        app.update(Action::Back);
        assert_eq!(app.page(), Page::Overview);
        assert!(!app.tc_view.detail());
        assert_eq!(app.row_offset, span.start);
    }
}
