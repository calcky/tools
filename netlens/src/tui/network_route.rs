use std::net::IpAddr;
use std::time::Duration;

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::monitor::network_route::{
    execute_route_lookup, InventorySnapshot, IpFamily, IpPrefix, NeighbourRow,
    NetworkRouteSnapshot, RouteLookupOutcome, RouteLookupQuery, RouteNexthop, RouteRow, RuleRow,
};
use crate::monitor::{
    CounterContinuity, MonitorSnapshot, ProjectedValue, ProviderHealth, SeriesSnapshot, SeriesValue,
};

use super::app::{DetailMetricsMode, TimeView};
use super::theme;
use super::view::{format_series, format_series_title, metric_style};

const MENU_ITEMS: [NetworkRoutePage; 5] = [
    NetworkRoutePage::IpMetrics,
    NetworkRoutePage::Routes,
    NetworkRoutePage::Rules,
    NetworkRoutePage::Neighbours,
    NetworkRoutePage::Lookup,
];
const NUD_FAILED: u16 = 0x20;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum NetworkRoutePage {
    #[default]
    Menu,
    IpMetrics,
    Routes,
    RouteDetail,
    Rules,
    RuleDetail,
    Neighbours,
    NeighbourDetail,
    Lookup,
    LookupResult,
}

impl NetworkRoutePage {
    const fn title(self) -> &'static str {
        match self {
            Self::Menu => "NETWORK / ROUTE",
            Self::IpMetrics => "IP / ICMP / MTU",
            Self::Routes => "ROUTES",
            Self::RouteDetail => "ROUTE DETAIL",
            Self::Rules => "POLICY RULES",
            Self::RuleDetail => "POLICY RULE DETAIL",
            Self::Neighbours => "NEIGHBOURS",
            Self::NeighbourDetail => "NEIGHBOUR DETAIL",
            Self::Lookup => "ROUTE LOOKUP",
            Self::LookupResult => "ROUTE LOOKUP RESULT",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RouteSelectionKey {
    family: IpFamily,
    destination: IpPrefix,
    source: IpPrefix,
    tos: u8,
    table: u32,
    priority: Option<u32>,
    protocol: u8,
    scope: u8,
    route_type: u8,
    preferred_source: Option<IpAddr>,
    nexthops: Vec<RouteNexthopSelectionKey>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RouteNexthopSelectionKey {
    ifindex: Option<u32>,
    gateway: Option<IpAddr>,
    via: Option<IpAddr>,
    weight: u16,
    configuration_flags: u8,
}

impl From<&RouteNexthop> for RouteNexthopSelectionKey {
    fn from(nexthop: &RouteNexthop) -> Self {
        Self {
            ifindex: nexthop.ifindex,
            gateway: nexthop.gateway,
            via: nexthop.via,
            weight: nexthop.weight,
            configuration_flags: nexthop.configuration_flags(),
        }
    }
}

impl From<&RouteRow> for RouteSelectionKey {
    fn from(row: &RouteRow) -> Self {
        Self {
            family: row.family,
            destination: row.destination.clone(),
            source: row.source.clone(),
            tos: row.tos,
            table: row.table,
            priority: row.priority,
            protocol: row.protocol,
            scope: row.scope,
            route_type: row.route_type,
            preferred_source: row.preferred_source,
            nexthops: row
                .nexthops
                .iter()
                .map(RouteNexthopSelectionKey::from)
                .collect(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RuleSelectionKey {
    family: IpFamily,
    destination: IpPrefix,
    source: IpPrefix,
    priority: Option<u32>,
    table: u32,
    action: u8,
    tos: u8,
    flags: u32,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    input_interface: Option<String>,
    output_interface: Option<String>,
    goto_priority: Option<u32>,
    suppress_prefix_len: Option<u32>,
    suppress_interface_group: Option<u32>,
    l3mdev: Option<u8>,
    uid_range: Option<(u32, u32)>,
    tunnel_id: Option<u64>,
    flow: Option<u32>,
    protocol: Option<u8>,
}

impl From<&RuleRow> for RuleSelectionKey {
    fn from(row: &RuleRow) -> Self {
        Self {
            family: row.family,
            destination: row.destination.clone(),
            source: row.source.clone(),
            priority: row.priority,
            table: row.table,
            action: row.action,
            tos: row.tos,
            flags: row.flags,
            fwmark: row.fwmark,
            fwmask: row.fwmask,
            input_interface: row.input_interface.clone(),
            output_interface: row.output_interface.clone(),
            goto_priority: row.goto_priority,
            suppress_prefix_len: row.suppress_prefix_len,
            suppress_interface_group: row.suppress_interface_group,
            l3mdev: row.l3mdev,
            uid_range: row.uid_range.map(|range| (range.start, range.end)),
            tunnel_id: row.tunnel_id,
            flow: row.flow,
            protocol: row.protocol,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct NeighbourSelectionKey {
    family: IpFamily,
    address: IpAddr,
    ifindex: u32,
}

impl From<&NeighbourRow> for NeighbourSelectionKey {
    fn from(row: &NeighbourRow) -> Self {
        Self {
            family: row.family,
            address: row.address,
            ifindex: row.ifindex,
        }
    }
}

#[derive(Default)]
pub(super) struct NetworkRouteViewState {
    page: NetworkRoutePage,
    menu_selected: usize,
    route_selected: usize,
    route_selection_key: Option<RouteSelectionKey>,
    rule_selected: usize,
    rule_selection_key: Option<RuleSelectionKey>,
    neighbour_selected: usize,
    neighbour_selection_key: Option<NeighbourSelectionKey>,
    row_offset: usize,
    viewport_rows: usize,
    lookup_input: Option<String>,
    lookup_error: Option<String>,
    lookup_outcome: Option<RouteLookupOutcome>,
}

impl std::fmt::Debug for NetworkRouteViewState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NetworkRouteViewState")
            .field("page", &self.page)
            .field("menu_selected", &self.menu_selected)
            .field("route_selected", &self.route_selected)
            .field("rule_selected", &self.rule_selected)
            .field("neighbour_selected", &self.neighbour_selected)
            .field("row_offset", &self.row_offset)
            .field("viewport_rows", &self.viewport_rows)
            .field(
                "lookup_input",
                &self.lookup_input.as_ref().map(|_| "<redacted>"),
            )
            .field("lookup_error", &self.lookup_error)
            .field(
                "lookup_outcome",
                &self.lookup_outcome.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl NetworkRouteViewState {
    pub(super) fn breadcrumb(&self) -> String {
        match self.page {
            NetworkRoutePage::Menu => "NETWORK / ROUTE".to_owned(),
            page => format!("NETWORK / ROUTE > {}", page.title()),
        }
    }

    pub(super) fn text_input_active(&self) -> bool {
        self.lookup_input.is_some()
    }

    pub(super) fn supports_metric_visibility_toggle(&self) -> bool {
        matches!(
            self.page,
            NetworkRoutePage::IpMetrics
                | NetworkRoutePage::RouteDetail
                | NetworkRoutePage::RuleDetail
                | NetworkRoutePage::NeighbourDetail
        )
    }

    pub(super) fn lookup_input(&self) -> Option<&str> {
        self.lookup_input.as_deref()
    }

    pub(super) fn lookup_error(&self) -> Option<&str> {
        self.lookup_error.as_deref()
    }

    pub(super) fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = rows.saturating_sub(2).max(1);
    }

    pub(super) fn clamp_content_rows(&mut self, rows: usize) {
        self.row_offset = self.row_offset.min(rows.saturating_sub(self.viewport_rows));
    }

    pub(super) fn reconcile(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        let Some(snapshot) = snapshot else {
            self.route_selected = 0;
            self.rule_selected = 0;
            self.neighbour_selected = 0;
            return;
        };
        (self.route_selected, self.route_selection_key) = reconcile_selection(
            self.route_selected,
            self.route_selection_key.as_ref(),
            snapshot.routes().rows(),
            |row| RouteSelectionKey::from(row),
            self.page == NetworkRoutePage::RouteDetail,
        );
        (self.rule_selected, self.rule_selection_key) = reconcile_selection(
            self.rule_selected,
            self.rule_selection_key.as_ref(),
            snapshot.rules().rows(),
            |row| RuleSelectionKey::from(row),
            self.page == NetworkRoutePage::RuleDetail,
        );
        (self.neighbour_selected, self.neighbour_selection_key) = reconcile_selection(
            self.neighbour_selected,
            self.neighbour_selection_key.as_ref(),
            snapshot.neighbours().rows(),
            |row| NeighbourSelectionKey::from(row),
            self.page == NetworkRoutePage::NeighbourDetail,
        );
    }

    pub(super) fn move_up(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        match self.page {
            NetworkRoutePage::Menu => self.menu_selected = self.menu_selected.saturating_sub(1),
            NetworkRoutePage::Routes => self.route_selected = self.route_selected.saturating_sub(1),
            NetworkRoutePage::Rules => self.rule_selected = self.rule_selected.saturating_sub(1),
            NetworkRoutePage::Neighbours => {
                self.neighbour_selected = self.neighbour_selected.saturating_sub(1)
            }
            _ => {
                self.row_offset = self.row_offset.saturating_sub(1);
                return;
            }
        }
        if let Some(snapshot) = snapshot {
            self.route_selected =
                clamp_selection(self.route_selected, snapshot.routes().rows().len());
            self.rule_selected = clamp_selection(self.rule_selected, snapshot.rules().rows().len());
            self.neighbour_selected =
                clamp_selection(self.neighbour_selected, snapshot.neighbours().rows().len());
            self.remember_selection(snapshot);
        }
        self.ensure_selection_visible();
    }

    pub(super) fn move_down(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        match self.page {
            NetworkRoutePage::Menu => {
                self.menu_selected = (self.menu_selected + 1).min(MENU_ITEMS.len() - 1)
            }
            NetworkRoutePage::Routes => {
                let len = snapshot.map_or(0, |value| value.routes().rows().len());
                self.route_selected = next_selection(self.route_selected, len);
            }
            NetworkRoutePage::Rules => {
                let len = snapshot.map_or(0, |value| value.rules().rows().len());
                self.rule_selected = next_selection(self.rule_selected, len);
            }
            NetworkRoutePage::Neighbours => {
                let len = snapshot.map_or(0, |value| value.neighbours().rows().len());
                self.neighbour_selected = next_selection(self.neighbour_selected, len);
            }
            _ => {
                self.row_offset = self.row_offset.saturating_add(1);
                return;
            }
        }
        if let Some(snapshot) = snapshot {
            self.remember_selection(snapshot);
        }
        self.ensure_selection_visible();
    }

    pub(super) fn page_up(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        let amount = self.viewport_rows.saturating_sub(1).max(1);
        match self.page {
            NetworkRoutePage::Menu => {
                self.menu_selected = self.menu_selected.saturating_sub(amount)
            }
            NetworkRoutePage::Routes => {
                self.route_selected = self.route_selected.saturating_sub(amount)
            }
            NetworkRoutePage::Rules => {
                self.rule_selected = self.rule_selected.saturating_sub(amount)
            }
            NetworkRoutePage::Neighbours => {
                self.neighbour_selected = self.neighbour_selected.saturating_sub(amount)
            }
            _ => self.row_offset = self.row_offset.saturating_sub(amount),
        }
        if let Some(snapshot) = snapshot {
            self.route_selected =
                clamp_selection(self.route_selected, snapshot.routes().rows().len());
            self.rule_selected = clamp_selection(self.rule_selected, snapshot.rules().rows().len());
            self.neighbour_selected =
                clamp_selection(self.neighbour_selected, snapshot.neighbours().rows().len());
            self.remember_selection(snapshot);
        }
        self.ensure_selection_visible();
    }

    pub(super) fn page_down(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        let amount = self.viewport_rows.saturating_sub(1).max(1);
        match self.page {
            NetworkRoutePage::Menu => {
                self.menu_selected = (self.menu_selected + amount).min(MENU_ITEMS.len() - 1)
            }
            NetworkRoutePage::Routes => {
                let len = snapshot.map_or(0, |value| value.routes().rows().len());
                self.route_selected =
                    clamp_selection(self.route_selected.saturating_add(amount), len);
            }
            NetworkRoutePage::Rules => {
                let len = snapshot.map_or(0, |value| value.rules().rows().len());
                self.rule_selected =
                    clamp_selection(self.rule_selected.saturating_add(amount), len);
            }
            NetworkRoutePage::Neighbours => {
                let len = snapshot.map_or(0, |value| value.neighbours().rows().len());
                self.neighbour_selected =
                    clamp_selection(self.neighbour_selected.saturating_add(amount), len);
            }
            _ => self.row_offset = self.row_offset.saturating_add(amount),
        }
        if let Some(snapshot) = snapshot {
            self.remember_selection(snapshot);
        }
        self.ensure_selection_visible();
    }

    pub(super) fn scroll_top(&mut self) {
        self.row_offset = 0;
        self.route_selection_key = None;
        self.rule_selection_key = None;
        self.neighbour_selection_key = None;
        match self.page {
            NetworkRoutePage::Menu => self.menu_selected = 0,
            NetworkRoutePage::Routes => self.route_selected = 0,
            NetworkRoutePage::Rules => self.rule_selected = 0,
            NetworkRoutePage::Neighbours => self.neighbour_selected = 0,
            _ => {}
        }
    }

    pub(super) fn enter(&mut self, snapshot: Option<&NetworkRouteSnapshot>) {
        self.row_offset = 0;
        if let Some(snapshot) = snapshot {
            self.remember_selection(snapshot);
        }
        match self.page {
            NetworkRoutePage::Menu => {
                self.page = MENU_ITEMS[self.menu_selected];
                if self.page == NetworkRoutePage::Lookup {
                    self.begin_lookup();
                }
            }
            NetworkRoutePage::Routes
                if snapshot.is_some_and(|value| !value.routes().rows().is_empty()) =>
            {
                self.page = NetworkRoutePage::RouteDetail;
            }
            NetworkRoutePage::Rules
                if snapshot.is_some_and(|value| !value.rules().rows().is_empty()) =>
            {
                self.page = NetworkRoutePage::RuleDetail;
            }
            NetworkRoutePage::Neighbours
                if snapshot.is_some_and(|value| !value.neighbours().rows().is_empty()) =>
            {
                self.page = NetworkRoutePage::NeighbourDetail;
            }
            NetworkRoutePage::Lookup | NetworkRoutePage::LookupResult => self.begin_lookup(),
            _ => {}
        }
        self.ensure_selection_visible();
    }

    /// Returns true when the caller should leave the Network/Route layer.
    pub(super) fn back(&mut self) -> bool {
        if self.lookup_input.take().is_some() {
            self.lookup_error = None;
            return false;
        }
        self.row_offset = 0;
        self.page = match self.page {
            NetworkRoutePage::Menu => return true,
            NetworkRoutePage::RouteDetail => NetworkRoutePage::Routes,
            NetworkRoutePage::RuleDetail => NetworkRoutePage::Rules,
            NetworkRoutePage::NeighbourDetail => NetworkRoutePage::Neighbours,
            _ => NetworkRoutePage::Menu,
        };
        self.ensure_selection_visible();
        false
    }

    pub(super) fn insert_lookup_char(&mut self, character: char) {
        let Some(input) = &mut self.lookup_input else {
            return;
        };
        if character.is_ascii() && input.len() < 256 {
            input.push(character);
            self.lookup_error = None;
        }
    }

    pub(super) fn lookup_backspace(&mut self) {
        if let Some(input) = &mut self.lookup_input {
            input.pop();
            self.lookup_error = None;
        }
    }

    pub(super) fn submit_lookup(&mut self) {
        let Some(input) = self.lookup_input.as_deref() else {
            return;
        };
        match RouteLookupQuery::parse(input) {
            Ok(query) => {
                self.lookup_outcome = Some(execute_route_lookup(query));
                self.lookup_input = None;
                self.lookup_error = None;
                self.page = NetworkRoutePage::LookupResult;
                self.row_offset = 0;
            }
            Err(error) => self.lookup_error = Some(error.to_owned()),
        }
    }

    pub(super) fn footer_help(&self) -> &'static str {
        if self.lookup_input.is_some() {
            " Enter lookup  Esc cancel "
        } else {
            match self.page {
                NetworkRoutePage::Menu => " j/k select  Enter open  Esc overview ",
                NetworkRoutePage::Routes
                | NetworkRoutePage::Rules
                | NetworkRoutePage::Neighbours => {
                    " j/k select  Enter detail  Esc back  PgUp/PgDn page "
                }
                NetworkRoutePage::Lookup | NetworkRoutePage::LookupResult => {
                    " Enter query  Esc back  j/k scroll "
                }
                _ => " j/k scroll  Esc back  PgUp/PgDn page  a all/data ",
            }
        }
    }

    fn begin_lookup(&mut self) {
        self.page = NetworkRoutePage::Lookup;
        self.lookup_input = Some(
            self.lookup_outcome
                .as_ref()
                .map_or_else(String::new, |outcome| outcome.query().input().to_owned()),
        );
        self.lookup_error = None;
    }

    fn ensure_selection_visible(&mut self) {
        let row = match self.page {
            NetworkRoutePage::Menu => self.menu_selected.saturating_mul(3).saturating_add(2),
            NetworkRoutePage::Routes => self.route_selected.saturating_add(3),
            NetworkRoutePage::Rules => self.rule_selected.saturating_add(3),
            NetworkRoutePage::Neighbours => self.neighbour_selected.saturating_add(3),
            _ => return,
        };
        if row < self.row_offset {
            self.row_offset = row;
        } else if row >= self.row_offset.saturating_add(self.viewport_rows) {
            self.row_offset = row.saturating_sub(self.viewport_rows.saturating_sub(1));
        }
    }

    fn remember_selection(&mut self, snapshot: &NetworkRouteSnapshot) {
        self.route_selection_key = snapshot
            .routes()
            .rows()
            .get(self.route_selected)
            .map(RouteSelectionKey::from);
        self.rule_selection_key = snapshot
            .rules()
            .rows()
            .get(self.rule_selected)
            .map(RuleSelectionKey::from);
        self.neighbour_selection_key = snapshot
            .neighbours()
            .rows()
            .get(self.neighbour_selected)
            .map(NeighbourSelectionKey::from);
    }
}

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &NetworkRouteViewState,
    inventory: Option<&NetworkRouteSnapshot>,
    metrics: Option<&MonitorSnapshot>,
    time_view: TimeView,
    metrics_mode: DetailMetricsMode,
) {
    if area.is_empty() {
        return;
    }
    let border = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme::DIVIDER));
    let inner = border.inner(area);
    frame.render_widget(border, area);
    let area = inner;
    if area.is_empty() {
        return;
    }
    let mut lines = match state.page {
        NetworkRoutePage::Menu => menu_lines(inventory, state.menu_selected, area.width),
        NetworkRoutePage::IpMetrics => metric_lines(metrics, time_view, metrics_mode, area.width),
        NetworkRoutePage::Routes => inventory.map_or_else(
            || collecting_lines("route table"),
            |snapshot| route_table_lines(snapshot, state.route_selected, area.width),
        ),
        NetworkRoutePage::RouteDetail => selected_route(
            inventory,
            state.route_selected,
            state.route_selection_key.as_ref(),
        )
        .map_or_else(
            || missing_lines("Selected route is no longer present"),
            |row| route_detail_lines(row, area.width, metrics_mode),
        ),
        NetworkRoutePage::Rules => inventory.map_or_else(
            || collecting_lines("policy rules"),
            |snapshot| rule_table_lines(snapshot, state.rule_selected, area.width),
        ),
        NetworkRoutePage::RuleDetail => selected_rule(
            inventory,
            state.rule_selected,
            state.rule_selection_key.as_ref(),
        )
        .map_or_else(
            || missing_lines("Selected rule is no longer present"),
            |row| rule_detail_lines(row, area.width, metrics_mode),
        ),
        NetworkRoutePage::Neighbours => inventory.map_or_else(
            || collecting_lines("neighbour table"),
            |snapshot| neighbour_table_lines(snapshot, state.neighbour_selected, area.width),
        ),
        NetworkRoutePage::NeighbourDetail => selected_neighbour(
            inventory,
            state.neighbour_selected,
            state.neighbour_selection_key.as_ref(),
        )
        .map_or_else(
            || missing_lines("Selected neighbour is no longer present"),
            |row| neighbour_detail_lines(row, area.width, metrics_mode),
        ),
        NetworkRoutePage::Lookup => lookup_lines(state, area.width),
        NetworkRoutePage::LookupResult => lookup_result_lines(state, area.width),
    };
    let max_offset = lines.len().saturating_sub(usize::from(area.height));
    let offset = state.row_offset.min(max_offset);
    let visible = lines
        .drain(..)
        .skip(offset)
        .take(usize::from(area.height))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), area);
}

pub(super) fn row_count(
    state: &NetworkRouteViewState,
    inventory: Option<&NetworkRouteSnapshot>,
    metrics: Option<&MonitorSnapshot>,
    time_view: TimeView,
    metrics_mode: DetailMetricsMode,
    width: u16,
) -> usize {
    let width = super::module_frame::inner_width(width);
    match state.page {
        NetworkRoutePage::Menu => menu_lines(inventory, state.menu_selected, width).len(),
        NetworkRoutePage::IpMetrics => metric_lines(metrics, time_view, metrics_mode, width).len(),
        NetworkRoutePage::Routes => inventory
            .map(|value| route_table_lines(value, state.route_selected, width).len())
            .unwrap_or(1),
        NetworkRoutePage::RouteDetail => selected_route(
            inventory,
            state.route_selected,
            state.route_selection_key.as_ref(),
        )
        .map(|value| route_detail_lines(value, width, metrics_mode).len())
        .unwrap_or(1),
        NetworkRoutePage::Rules => inventory
            .map(|value| rule_table_lines(value, state.rule_selected, width).len())
            .unwrap_or(1),
        NetworkRoutePage::RuleDetail => selected_rule(
            inventory,
            state.rule_selected,
            state.rule_selection_key.as_ref(),
        )
        .map(|value| rule_detail_lines(value, width, metrics_mode).len())
        .unwrap_or(1),
        NetworkRoutePage::Neighbours => inventory
            .map(|value| neighbour_table_lines(value, state.neighbour_selected, width).len())
            .unwrap_or(1),
        NetworkRoutePage::NeighbourDetail => selected_neighbour(
            inventory,
            state.neighbour_selected,
            state.neighbour_selection_key.as_ref(),
        )
        .map(|value| neighbour_detail_lines(value, width, metrics_mode).len())
        .unwrap_or(1),
        NetworkRoutePage::Lookup => lookup_lines(state, width).len(),
        NetworkRoutePage::LookupResult => lookup_result_lines(state, width).len(),
    }
}

fn menu_lines(
    snapshot: Option<&NetworkRouteSnapshot>,
    selected: usize,
    width: u16,
) -> Vec<Line<'static>> {
    let frame_width = width;
    let width = usize::from(super::module_frame::inner_width(width)).max(1);
    let mut lines = vec![title_line("NETWORK / ROUTE", None, width)];
    let summaries = if let Some(snapshot) = snapshot {
        let changes = snapshot.changes();
        lines.push(Line::styled(
            fit(
                &format!(
                    " session {}  sample #{}  inventory cost {}",
                    format_duration(snapshot.elapsed()),
                    snapshot.sequence(),
                    format_duration(snapshot.collection_duration())
                ),
                width,
            ),
            Style::default().fg(theme::MUTED),
        ));
        [
            "Protocol health, forwarding, ICMP, MTU and fragmentation counters".to_owned(),
            format!(
                "{} retained  +{} -{} since baseline  {}",
                snapshot.routes().rows().len(),
                changes.route_additions(),
                changes.route_removals(),
                family_health_label(snapshot.routes())
            ),
            format!(
                "{} retained  +{} -{} since baseline  {}",
                snapshot.rules().rows().len(),
                changes.rule_additions(),
                changes.rule_removals(),
                family_health_label(snapshot.rules())
            ),
            format!(
                "{} retained  +{} -{} upd {}  state {} failed->{}  {}",
                snapshot.neighbours().rows().len(),
                changes.neighbour_additions(),
                changes.neighbour_removals(),
                changes.neighbour_updates(),
                changes.neighbour_state_changes(),
                changes.neighbour_failed_transitions(),
                family_health_label(snapshot.neighbours())
            ),
            "Ask the kernel for the effective route to a destination".to_owned(),
        ]
    } else {
        lines.push(Line::styled(
            fit(" Collecting network inventory...", width),
            Style::default().fg(theme::MUTED),
        ));
        std::array::from_fn(|_| "Collecting network inventory...".to_owned())
    };
    let labels = [
        ("IP / ICMP / MTU", "Counters and rates"),
        ("ROUTES", "IPv4 and IPv6 FIB entries"),
        ("POLICY RULES", "Routing policy database"),
        ("NEIGHBOURS", "ARP and IPv6 NDISC cache"),
        ("ROUTE LOOKUP", "Destination plus optional selectors"),
    ];
    for (index, ((label, description), summary)) in labels.into_iter().zip(summaries).enumerate() {
        let selected_style = if index == selected {
            Style::default().bg(theme::SELECTED_BG)
        } else {
            Style::default()
        };
        let title = Line::from(fit(&format!(" {:<18} {description}", label), width)).style(
            selected_style
                .fg(theme::TEXT_STRONG)
                .add_modifier(Modifier::BOLD),
        );
        let summary =
            Line::from(fit(&format!(" {summary}"), width)).style(selected_style.fg(theme::TEXT));
        let mut group = super::module_frame::lines(vec![title, summary], frame_width);
        if index == selected {
            super::module_frame::highlight(&mut group);
        }
        lines.extend(group);
    }
    lines
}

fn metric_lines(
    snapshot: Option<&MonitorSnapshot>,
    time_view: TimeView,
    metrics_mode: DetailMetricsMode,
    width: u16,
) -> Vec<Line<'static>> {
    let Some(snapshot) = snapshot else {
        return collecting_lines("IP protocol counters");
    };
    let width = usize::from(width).max(1);
    let mut groups: [Vec<&SeriesSnapshot>; 3] = std::array::from_fn(|_| Vec::new());
    for series in snapshot.series() {
        let id = series.metric().as_str();
        let group =
            if id.contains("fragment") || id.contains("reassembly") || id.contains("too_big") {
                Some(2)
            } else if id.starts_with("linux.socket.icmp") {
                Some(1)
            } else if id.starts_with("linux.socket.ip.") || id.starts_with("linux.socket.ipv6.") {
                Some(0)
            } else {
                None
            };
        if let Some(group) = group {
            if metrics_mode == DetailMetricsMode::All || series_has_data(series) {
                groups[group].push(series);
            }
        }
    }
    let mode = match metrics_mode {
        DetailMetricsMode::WithData => "WITH DATA",
        DetailMetricsMode::All => "ALL",
    };
    let mut lines = vec![title_line("IP / ICMP / MTU", Some(mode), width)];
    for (heading, rows) in [
        ("IP TRAFFIC / ROUTING ERRORS", &groups[0]),
        ("ICMPv4 / ICMPv6", &groups[1]),
        ("MTU / FRAGMENTATION / REASSEMBLY", &groups[2]),
    ] {
        lines.push(section_line(heading, width));
        if rows.is_empty() {
            lines.push(Line::styled(
                fit("   - no counters with data", width),
                Style::default().fg(theme::MUTED),
            ));
        } else {
            lines.extend(
                rows.iter()
                    .map(|series| metric_line(series, time_view, width)),
            );
        }
    }
    lines
}

fn metric_line(series: &SeriesSnapshot, time_view: TimeView, width: usize) -> Line<'static> {
    let metric = series
        .metric()
        .descriptor()
        .expect("network metric is catalogued");
    let title = format_series_title(series, metric);
    let (current, interval, since, state) = format_series(series, metric);
    let projection = match time_view {
        TimeView::Interval => interval,
        TimeView::SinceBaseline => since,
    };
    let widths = if width >= 120 {
        [width - 63, 20, 28, 12]
    } else {
        distribute_columns(width, [30, 12, 24, 12])
    };
    let columns = [
        (title.as_str(), widths[0]),
        (current.as_str(), widths[1]),
        (projection.as_str(), widths[2]),
        (state, widths[3]),
    ];
    Line::from(column_text(&columns, width)).style(metric_style(metric.display))
}

fn route_table_lines(
    snapshot: &NetworkRouteSnapshot,
    selected: usize,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = inventory_header("ROUTES", snapshot.routes(), snapshot.sequence(), width);
    if snapshot.routes().rows().is_empty() {
        lines.push(empty_line("No IPv4 or IPv6 routes were returned", width));
        return lines;
    }
    let columns = route_columns(width);
    lines.push(heading(
        &columns,
        ["FAM", "DESTINATION", "TABLE/METRIC", "NEXTHOP", "DEV"],
        width,
    ));
    lines.extend(
        snapshot
            .routes()
            .rows()
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let nexthop = row.nexthops.first();
                let metric = row
                    .priority
                    .map_or_else(|| "-".to_owned(), |value| value.to_string());
                let values = [
                    family_label(row.family).to_owned(),
                    format_prefix(&row.destination),
                    format!("{}/{}", table_label(row.table), metric),
                    nexthop_address(nexthop).unwrap_or_else(|| "-".to_owned()),
                    nexthop
                        .and_then(|hop| hop.interface.clone())
                        .unwrap_or_else(|| "-".to_owned()),
                ];
                selected_line(values, &columns, width, index == selected)
            }),
    );
    lines
}

fn rule_table_lines(
    snapshot: &NetworkRouteSnapshot,
    selected: usize,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = inventory_header("POLICY RULES", snapshot.rules(), snapshot.sequence(), width);
    if snapshot.rules().rows().is_empty() {
        lines.push(empty_line(
            "No IPv4 or IPv6 policy rules were returned",
            width,
        ));
        return lines;
    }
    let columns = rule_columns(width);
    lines.push(heading(
        &columns,
        ["FAM", "PRIO", "FROM", "TO", "ACTION/TABLE"],
        width,
    ));
    lines.extend(
        snapshot
            .rules()
            .rows()
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let values = [
                    family_label(row.family).to_owned(),
                    option_u32(row.priority),
                    format_prefix(&row.source),
                    format_prefix(&row.destination),
                    format!(
                        "{}/{}",
                        rule_action_label(row.action),
                        table_label(row.table)
                    ),
                ];
                selected_line(values, &columns, width, index == selected)
            }),
    );
    lines
}

fn neighbour_table_lines(
    snapshot: &NetworkRouteSnapshot,
    selected: usize,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = inventory_header(
        "NEIGHBOURS",
        snapshot.neighbours(),
        snapshot.sequence(),
        width,
    );
    if snapshot.neighbours().rows().is_empty() {
        lines.push(empty_line(
            "No ARP or IPv6 NDISC entries were returned",
            width,
        ));
        return lines;
    }
    let columns = neighbour_columns(width);
    lines.push(heading(
        &columns,
        ["FAM", "ADDRESS", "LINK ADDRESS", "STATE", "DEV"],
        width,
    ));
    lines.extend(
        snapshot
            .neighbours()
            .rows()
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let values = [
                    family_label(row.family).to_owned(),
                    row.address.to_string(),
                    format_link_address(row),
                    neighbour_state_label(row.state),
                    row.interface
                        .clone()
                        .unwrap_or_else(|| format!("if{}", row.ifindex)),
                ];
                let mut line = selected_line(values, &columns, width, index == selected);
                if row.state & NUD_FAILED != 0 {
                    line = line.style(Style::default().fg(theme::BAD).bg(if index == selected {
                        theme::SELECTED_BG
                    } else {
                        theme::CHROME_BG
                    }));
                }
                line
            }),
    );
    lines
}

fn route_detail_lines(
    row: &RouteRow,
    width: u16,
    metrics_mode: DetailMetricsMode,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let show_all = metrics_mode == DetailMetricsMode::All;
    let mut lines = vec![title_line(
        "ROUTE DETAIL",
        Some(family_label(row.family)),
        width,
    )];
    lines.push(section_line("MATCH", width));
    push_field(
        &mut lines,
        "DESTINATION",
        format_prefix(&row.destination),
        width,
    );
    push_field(&mut lines, "SOURCE", format_prefix(&row.source), width);
    push_optional_field(
        &mut lines,
        "TOS",
        (row.tos != 0).then(|| row.tos.to_string()),
        show_all,
        width,
    );
    push_field(
        &mut lines,
        "TABLE / PRIORITY",
        format!("{} / {}", table_label(row.table), option_u32(row.priority)),
        width,
    );
    push_field(
        &mut lines,
        "TYPE / SCOPE / PROTO",
        format!(
            "{} / {} / {}",
            route_type_label(row.route_type),
            route_scope_label(row.scope),
            route_protocol_label(row.protocol)
        ),
        width,
    );
    push_optional_field(
        &mut lines,
        "PREFERRED SOURCE",
        row.preferred_source.map(|value| value.to_string()),
        show_all,
        width,
    );
    lines.push(section_line("PATH", width));
    if row.nexthops.is_empty() {
        push_field(&mut lines, "NEXTHOP", "direct/on-link".to_owned(), width);
    } else {
        for (index, hop) in row.nexthops.iter().enumerate() {
            push_field(
                &mut lines,
                &format!("NEXTHOP {}", index + 1),
                format_nexthop(hop),
                width,
            );
        }
    }
    if show_all || row.nexthops_truncated {
        push_field(
            &mut lines,
            "NEXTHOPS TRUNCATED",
            yes_no(row.nexthops_truncated),
            width,
        );
    }
    let has_route_metrics = row.metrics.mtu.is_some()
        || row.metrics.advmss.is_some()
        || row.metrics.hoplimit.is_some()
        || row.metrics.initcwnd.is_some()
        || row.metrics.initrwnd.is_some()
        || row.expires.is_some();
    if show_all || has_route_metrics {
        lines.push(section_line("MTU / TCP INITIAL SETTINGS", width));
        push_optional_field(
            &mut lines,
            "MTU",
            row.metrics.mtu.map(|v| v.to_string()),
            show_all,
            width,
        );
        push_optional_field(
            &mut lines,
            "ADVMSS",
            row.metrics.advmss.map(|v| v.to_string()),
            show_all,
            width,
        );
        push_optional_field(
            &mut lines,
            "HOP LIMIT",
            row.metrics.hoplimit.map(|v| v.to_string()),
            show_all,
            width,
        );
        push_optional_field(
            &mut lines,
            "INITIAL CWND",
            row.metrics.initcwnd.map(|v| v.to_string()),
            show_all,
            width,
        );
        push_optional_field(
            &mut lines,
            "INITIAL RWND",
            row.metrics.initrwnd.map(|v| v.to_string()),
            show_all,
            width,
        );
        push_optional_field(
            &mut lines,
            "EXPIRES",
            row.expires.map(format_duration),
            show_all,
            width,
        );
    }
    if let Some(cache) = &row.cache {
        lines.push(section_line("CACHE", width));
        push_field(
            &mut lines,
            "USE / REFERENCES",
            format!("{} / {}", cache.used, cache.client_references),
            width,
        );
        push_field(
            &mut lines,
            "LAST USE / AGE",
            format!(
                "{} / {}",
                format_duration(cache.last_use),
                format_duration(cache.timestamp_age)
            ),
            width,
        );
        push_field(
            &mut lines,
            "EXPIRES / ERROR",
            format!("{} / {}", option_duration(cache.expires), cache.error),
            width,
        );
    }
    if show_all || row.flags != 0 || row.unsupported_encapsulation {
        lines.push(section_line("RAW FLAGS", width));
        if show_all || row.flags != 0 {
            push_field(
                &mut lines,
                "ROUTE FLAGS",
                format!("0x{:08x}", row.flags),
                width,
            );
        }
        if show_all || row.unsupported_encapsulation {
            push_field(
                &mut lines,
                "ENCAPSULATION",
                if row.unsupported_encapsulation {
                    "present (unsupported details)"
                } else {
                    "none"
                }
                .to_owned(),
                width,
            );
        }
    }
    lines
}

fn rule_detail_lines(
    row: &RuleRow,
    width: u16,
    metrics_mode: DetailMetricsMode,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let show_all = metrics_mode == DetailMetricsMode::All;
    let mut lines = vec![title_line(
        "POLICY RULE DETAIL",
        Some(family_label(row.family)),
        width,
    )];
    lines.push(section_line("MATCH", width));
    push_field(&mut lines, "PRIORITY", option_u32(row.priority), width);
    push_field(&mut lines, "FROM", format_prefix(&row.source), width);
    push_field(&mut lines, "TO", format_prefix(&row.destination), width);
    push_optional_field(
        &mut lines,
        "IIF / OIF",
        (row.input_interface.is_some() || row.output_interface.is_some()).then(|| {
            format!(
                "{} / {}",
                option_str(row.input_interface.as_deref()),
                option_str(row.output_interface.as_deref())
            )
        }),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "FWMARK / MASK",
        (row.fwmark.is_some() || row.fwmask.is_some()).then(|| {
            format!(
                "{} / {}",
                option_hex_u32(row.fwmark),
                option_hex_u32(row.fwmask)
            )
        }),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "TOS",
        (row.tos != 0).then(|| row.tos.to_string()),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "UID RANGE",
        row.uid_range
            .map(|range| format!("{}-{}", range.start, range.end)),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "L3MDEV / TUNNEL ID",
        (row.l3mdev.is_some() || row.tunnel_id.is_some()).then(|| {
            format!(
                "{} / {}",
                row.l3mdev
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                row.tunnel_id
                    .map_or_else(|| "-".to_owned(), |value| value.to_string())
            )
        }),
        show_all,
        width,
    );
    lines.push(section_line("ACTION", width));
    push_field(
        &mut lines,
        "ACTION / TABLE",
        format!(
            "{} / {}",
            rule_action_label(row.action),
            table_label(row.table)
        ),
        width,
    );
    push_optional_field(
        &mut lines,
        "GOTO PRIORITY",
        row.goto_priority.map(|v| v.to_string()),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "SUPPRESS PREFIXLEN",
        row.suppress_prefix_len.map(|v| v.to_string()),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "SUPPRESS IFGROUP",
        row.suppress_interface_group.map(|v| v.to_string()),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "FLOW / PROTOCOL",
        (row.flow.is_some() || row.protocol.is_some()).then(|| {
            format!(
                "{} / {}",
                option_u32(row.flow),
                row.protocol
                    .map_or_else(|| "-".to_owned(), |value| value.to_string())
            )
        }),
        show_all,
        width,
    );
    push_optional_field(
        &mut lines,
        "FLAGS",
        (row.flags != 0).then(|| format!("0x{:08x}", row.flags)),
        show_all,
        width,
    );
    lines
}

fn neighbour_detail_lines(
    row: &NeighbourRow,
    width: u16,
    metrics_mode: DetailMetricsMode,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let show_all = metrics_mode == DetailMetricsMode::All;
    let state = neighbour_state_label(row.state);
    let mut lines = vec![title_line("NEIGHBOUR DETAIL", Some(&state), width)];
    lines.push(section_line("IDENTITY", width));
    push_field(&mut lines, "IP ADDRESS", row.address.to_string(), width);
    push_field(&mut lines, "LINK ADDRESS", format_link_address(row), width);
    push_field(
        &mut lines,
        "INTERFACE",
        row.interface.clone().unwrap_or_else(|| "-".to_owned()),
        width,
    );
    push_field(&mut lines, "IFINDEX", row.ifindex.to_string(), width);
    lines.push(section_line("NUD STATE", width));
    push_field(&mut lines, "STATE", state, width);
    push_optional_field(
        &mut lines,
        "PROBES",
        row.probes.map(|v| v.to_string()),
        show_all,
        width,
    );
    if let Some(cache) = &row.cache {
        push_field(
            &mut lines,
            "CONFIRMED AGE",
            format_duration(cache.confirmed_age),
            width,
        );
        push_field(
            &mut lines,
            "LAST USED AGE",
            format_duration(cache.used_age),
            width,
        );
        push_field(
            &mut lines,
            "UPDATED AGE",
            format_duration(cache.updated_age),
            width,
        );
        push_field(
            &mut lines,
            "REFERENCES",
            cache.references.to_string(),
            width,
        );
    }
    if show_all || row.flags != 0 || row.neighbour_type != 0 {
        lines.push(section_line("RAW FLAGS", width));
        push_field(
            &mut lines,
            "STATE BITS",
            format!("0x{:04x}", row.state),
            width,
        );
        push_optional_field(
            &mut lines,
            "FLAGS / TYPE",
            (row.flags != 0 || row.neighbour_type != 0)
                .then(|| format!("0x{:02x} / {}", row.flags, row.neighbour_type)),
            show_all,
            width,
        );
    }
    lines
}

fn lookup_lines(state: &NetworkRouteViewState, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let mut lines = vec![title_line("ROUTE LOOKUP", Some("KERNEL FIB"), width)];
    lines.push(section_line("QUERY", width));
    lines.push(Line::styled(
        fit(
            "   DEST [from SOURCE] [iif IFACE] [oif IFACE] [mark N] [uid N] [tos N]",
            width,
        ),
        Style::default().fg(theme::TEXT),
    ));
    let input = state.lookup_input.as_deref().unwrap_or("");
    lines.push(Line::from(vec![
        Span::styled(
            " > ",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            fit(input, width.saturating_sub(3)),
            Style::default().fg(theme::TEXT_STRONG),
        ),
    ]));
    if let Some(error) = &state.lookup_error {
        lines.push(Line::styled(
            fit(&format!("   {error}"), width),
            Style::default().fg(theme::BAD),
        ));
    }
    lines.push(section_line("EXAMPLES", width));
    lines.push(Line::styled(
        fit("   1.1.1.1", width),
        Style::default().fg(theme::MUTED),
    ));
    lines.push(Line::styled(
        fit("   2001:db8::1 from 2001:db8::2 oif eth0", width),
        Style::default().fg(theme::MUTED),
    ));
    lines
}

fn lookup_result_lines(state: &NetworkRouteViewState, width: u16) -> Vec<Line<'static>> {
    let width_usize = usize::from(width).max(1);
    let Some(outcome) = &state.lookup_outcome else {
        return missing_lines("No route lookup has been run");
    };
    let mut lines = vec![title_line(
        "ROUTE LOOKUP RESULT",
        Some("KERNEL FIB"),
        width_usize,
    )];
    lines.push(Line::styled(
        fit(&format!(" query {}", outcome.query().input()), width_usize),
        Style::default().fg(theme::ACCENT),
    ));
    match outcome.result() {
        Ok(route) => lines.extend(
            route_detail_lines(route, width, DetailMetricsMode::WithData)
                .into_iter()
                .skip(1),
        ),
        Err(error) => lines.push(Line::styled(
            fit(&format!(" lookup failed: {error}"), width_usize),
            Style::default().fg(theme::BAD),
        )),
    }
    lines
}

fn inventory_header<T>(
    title: &str,
    inventory: &InventorySnapshot<T>,
    sequence: u64,
    width: usize,
) -> Vec<Line<'static>> {
    let (health, style) = health_label(inventory.health());
    let mut lines = vec![title_line(title, Some(health), width)];
    let summary = format!(
        " retained {} / observed {}  v4/v6 {}/{}  queries {}/{}  sample #{}  at {}  cost {}{}",
        inventory.rows().len(),
        inventory.observed_rows(),
        health_label(inventory.family_health(IpFamily::Ipv4)).0,
        health_label(inventory.family_health(IpFamily::Ipv6)).0,
        inventory.completed_queries(),
        inventory.completed_queries() + inventory.failed_queries(),
        sequence,
        format_duration(inventory.attempted_at()),
        format_duration(inventory.collection_duration()),
        if inventory.truncated() {
            "  TRUNCATED"
        } else {
            ""
        }
    );
    lines.push(Line::styled(fit(&summary, width), style));
    lines
}

fn family_health_label<T>(inventory: &InventorySnapshot<T>) -> String {
    format!(
        "v4 {}  v6 {}",
        health_label(inventory.family_health(IpFamily::Ipv4)).0,
        health_label(inventory.family_health(IpFamily::Ipv6)).0
    )
}

fn title_line(title: &str, status: Option<&str>, width: usize) -> Line<'static> {
    let status = status.map_or_else(String::new, |value| format!("  [{value}]"));
    Line::styled(
        fit(&format!(" {title}{status}"), width),
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    )
}

fn section_line(title: &str, width: usize) -> Line<'static> {
    Line::styled(
        fit(
            &format!(
                " {title} {}",
                "-".repeat(width.saturating_sub(title.len() + 2))
            ),
            width,
        ),
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    )
}

fn push_field(lines: &mut Vec<Line<'static>>, label: &str, value: String, width: usize) {
    let label_width = if width >= 100 { 24 } else { 18.min(width / 2) };
    let text = format!("   {:<label_width$}{}", label, value);
    lines.push(Line::styled(
        fit(&text, width),
        Style::default().fg(theme::TEXT),
    ));
}

fn push_optional_field(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    value: Option<String>,
    show_all: bool,
    width: usize,
) {
    if show_all || value.is_some() {
        push_field(lines, label, value.unwrap_or_else(|| "-".to_owned()), width);
    }
}

fn heading<const N: usize>(columns: &[usize; N], values: [&str; N], width: usize) -> Line<'static> {
    let values = std::array::from_fn(|index| values[index].to_owned());
    Line::styled(
        column_owned(&values, columns, width),
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    )
}

fn selected_line<const N: usize>(
    values: [String; N],
    columns: &[usize; N],
    width: usize,
    selected: bool,
) -> Line<'static> {
    let style = if selected {
        Style::default()
            .fg(theme::TEXT_STRONG)
            .bg(theme::SELECTED_BG)
    } else {
        Style::default().fg(theme::TEXT)
    };
    Line::styled(column_owned(&values, columns, width), style)
}

fn column_text<const N: usize>(values: &[(&str, usize); N], width: usize) -> String {
    let strings: [String; N] = std::array::from_fn(|index| values[index].0.to_owned());
    let columns: [usize; N] = std::array::from_fn(|index| values[index].1);
    column_owned(&strings, &columns, width)
}

fn column_owned<const N: usize>(
    values: &[String; N],
    columns: &[usize; N],
    width: usize,
) -> String {
    let mut output = String::new();
    for index in 0..N {
        if index > 0 {
            output.push('|');
        }
        output.push_str(&fit(&values[index], columns[index]));
    }
    fit(&output, width)
}

fn route_columns(width: usize) -> [usize; 5] {
    distribute_columns(width, [4, 32, 16, 30, 16])
}

fn rule_columns(width: usize) -> [usize; 5] {
    distribute_columns(width, [4, 10, 26, 26, 24])
}

fn neighbour_columns(width: usize) -> [usize; 5] {
    distribute_columns(width, [4, 30, 26, 20, 16])
}

fn distribute_columns<const N: usize>(width: usize, desired: [usize; N]) -> [usize; N] {
    let available = width.saturating_sub(N.saturating_sub(1));
    let desired_total = desired.iter().sum::<usize>();
    if available >= desired_total {
        let mut result = desired;
        result[N - 1] = result[N - 1].saturating_add(available - desired_total);
        return result;
    }
    let mut result = std::array::from_fn(|index| {
        (desired[index].saturating_mul(available) / desired_total).max(1)
    });
    let assigned = result.iter().sum::<usize>();
    if assigned < available {
        result[N - 1] = result[N - 1].saturating_add(available - assigned);
    } else if assigned > available {
        result[N - 1] = result[N - 1].saturating_sub(assigned - available);
    }
    result
}

fn fit(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let count = value.chars().count();
    if count <= width {
        return format!("{value:<width$}");
    }
    if width == 1 {
        return "~".to_owned();
    }
    let mut fitted = value.chars().take(width - 1).collect::<String>();
    fitted.push('~');
    fitted
}

fn selected_route<'a>(
    snapshot: Option<&'a NetworkRouteSnapshot>,
    selected: usize,
    key: Option<&RouteSelectionKey>,
) -> Option<&'a RouteRow> {
    selected_by_key(snapshot?.routes().rows(), selected, key, |row| {
        RouteSelectionKey::from(row)
    })
}

fn selected_rule<'a>(
    snapshot: Option<&'a NetworkRouteSnapshot>,
    selected: usize,
    key: Option<&RuleSelectionKey>,
) -> Option<&'a RuleRow> {
    selected_by_key(snapshot?.rules().rows(), selected, key, |row| {
        RuleSelectionKey::from(row)
    })
}

fn selected_neighbour<'a>(
    snapshot: Option<&'a NetworkRouteSnapshot>,
    selected: usize,
    key: Option<&NeighbourSelectionKey>,
) -> Option<&'a NeighbourRow> {
    selected_by_key(snapshot?.neighbours().rows(), selected, key, |row| {
        NeighbourSelectionKey::from(row)
    })
}

fn clamp_selection(selected: usize, len: usize) -> usize {
    selected.min(len.saturating_sub(1))
}

fn reconcile_selection<T, K, F>(
    selected: usize,
    key: Option<&K>,
    rows: &[T],
    key_of: F,
    preserve_missing_key: bool,
) -> (usize, Option<K>)
where
    K: Clone + Eq,
    F: Fn(&T) -> K,
{
    let matching = key.and_then(|key| rows.iter().position(|row| key_of(row) == *key));
    let selected = matching.unwrap_or_else(|| clamp_selection(selected, rows.len()));
    let key = if preserve_missing_key && key.is_some() && matching.is_none() {
        key.cloned()
    } else {
        rows.get(selected).map(key_of)
    };
    (selected, key)
}

fn selected_by_key<'a, T, K, F>(
    rows: &'a [T],
    selected: usize,
    key: Option<&K>,
    key_of: F,
) -> Option<&'a T>
where
    K: Eq,
    F: Fn(&T) -> K,
{
    match key {
        Some(key) => rows.iter().find(|row| key_of(row) == *key),
        None => rows.get(selected),
    }
}

fn next_selection(selected: usize, len: usize) -> usize {
    clamp_selection(selected.saturating_add(1), len)
}

fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
    }
}

fn format_prefix(prefix: &IpPrefix) -> String {
    format!("{}/{}", prefix.address, prefix.prefix_len)
}

fn table_label(table: u32) -> String {
    match table {
        253 => "default".to_owned(),
        254 => "main".to_owned(),
        255 => "local".to_owned(),
        value => value.to_string(),
    }
}

fn route_protocol_label(protocol: u8) -> String {
    match protocol {
        0 => "unspec".to_owned(),
        2 => "kernel".to_owned(),
        3 => "boot".to_owned(),
        4 => "static".to_owned(),
        16 => "dhcp".to_owned(),
        186 => "bgp".to_owned(),
        value => value.to_string(),
    }
}

fn route_scope_label(scope: u8) -> String {
    match scope {
        0 => "global".to_owned(),
        200 => "site".to_owned(),
        253 => "link".to_owned(),
        254 => "host".to_owned(),
        255 => "nowhere".to_owned(),
        value => value.to_string(),
    }
}

fn route_type_label(route_type: u8) -> String {
    match route_type {
        1 => "unicast".to_owned(),
        2 => "local".to_owned(),
        3 => "broadcast".to_owned(),
        5 => "multicast".to_owned(),
        6 => "blackhole".to_owned(),
        7 => "unreachable".to_owned(),
        8 => "prohibit".to_owned(),
        9 => "throw".to_owned(),
        value => value.to_string(),
    }
}

fn rule_action_label(action: u8) -> String {
    match action {
        1 => "lookup".to_owned(),
        2 => "goto".to_owned(),
        6 => "blackhole".to_owned(),
        7 => "unreachable".to_owned(),
        8 => "prohibit".to_owned(),
        value => value.to_string(),
    }
}

fn neighbour_state_label(state: u16) -> String {
    let states = [
        (0x01, "INCOMPLETE"),
        (0x02, "REACHABLE"),
        (0x04, "STALE"),
        (0x08, "DELAY"),
        (0x10, "PROBE"),
        (0x20, "FAILED"),
        (0x40, "NOARP"),
        (0x80, "PERMANENT"),
    ];
    let labels = states
        .into_iter()
        .filter_map(|(bit, label)| (state & bit != 0).then_some(label))
        .collect::<Vec<_>>();
    if labels.is_empty() {
        "NONE".to_owned()
    } else {
        labels.join("+")
    }
}

fn nexthop_address(hop: Option<&RouteNexthop>) -> Option<String> {
    let hop = hop?;
    hop.gateway.or(hop.via).map(|address| address.to_string())
}

fn format_nexthop(hop: &RouteNexthop) -> String {
    let address = nexthop_address(Some(hop)).unwrap_or_else(|| "on-link".to_owned());
    let interface = hop.interface.clone().unwrap_or_else(|| {
        hop.ifindex
            .map_or_else(|| "-".to_owned(), |value| format!("if{value}"))
    });
    format!(
        "{address} dev {interface} weight {} flags 0x{:02x}",
        hop.weight, hop.flags
    )
}

fn format_link_address(row: &NeighbourRow) -> String {
    row.link_address.as_ref().map_or_else(
        || "-".to_owned(),
        |address| {
            address
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        },
    )
}

fn option_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn option_hex_u32(value: Option<u32>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("0x{value:x}"))
}

fn option_str(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn option_duration(value: Option<Duration>) -> String {
    value.map_or_else(|| "-".to_owned(), format_duration)
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() >= 60 {
        format!(
            "{}m{:02}s",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        )
    } else if duration.as_secs() > 0 {
        format!(
            "{}.{:01}s",
            duration.as_secs(),
            duration.subsec_millis() / 100
        )
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn yes_no(value: bool) -> String {
    if value { "yes" } else { "no" }.to_owned()
}

fn health_label(health: &ProviderHealth) -> (&'static str, Style) {
    match health {
        ProviderHealth::Fresh => ("FRESH", Style::default().fg(theme::GOOD)),
        ProviderHealth::Partial { .. } => ("PARTIAL", Style::default().fg(theme::WARN)),
        ProviderHealth::Stale { .. } => ("STALE", Style::default().fg(theme::WARN)),
        ProviderHealth::Unsupported { .. } => ("UNSUPPORTED", Style::default().fg(theme::MUTED)),
        ProviderHealth::PermissionDenied { .. } => {
            ("PERMISSION DENIED", Style::default().fg(theme::WARN))
        }
        ProviderHealth::Error { .. } => ("ERROR", Style::default().fg(theme::BAD)),
    }
}

fn series_has_data(series: &SeriesSnapshot) -> bool {
    let history_has_data = || {
        series
            .history_buckets()
            .iter()
            .any(|bucket| bucket.max() != 0 || bucket.delta() != 0)
    };
    match series.value() {
        SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        } => {
            projected_nonzero(current)
                || matches!(interval, Some(CounterContinuity::Continuous { delta, .. } | CounterContinuity::Wrapped { delta, .. }) if *delta != 0)
                || since_baseline
                    .as_ref()
                    .is_some_and(|span| span.delta() != 0)
                || history_has_data()
        }
        SeriesValue::Gauge {
            current,
            interval,
            since_baseline,
        } => {
            projected_nonzero(current)
                || interval.as_ref().is_some_and(|change| change.delta() != 0)
                || since_baseline
                    .as_ref()
                    .is_some_and(|summary| summary.max() != 0)
                || history_has_data()
        }
        SeriesValue::State { current, .. } => matches!(
            current,
            ProjectedValue::Fresh { .. } | ProjectedValue::Stale { .. }
        ),
    }
}

fn projected_nonzero(value: &ProjectedValue<u64>) -> bool {
    match value {
        ProjectedValue::Fresh { value, .. } => *value != 0,
        ProjectedValue::Stale { last, .. } => *last != 0,
        ProjectedValue::Unavailable { .. } => false,
    }
}

fn collecting_lines(subject: &str) -> Vec<Line<'static>> {
    vec![Line::styled(
        format!(" Collecting {subject}..."),
        Style::default().fg(theme::MUTED),
    )]
}

fn missing_lines(message: &str) -> Vec<Line<'static>> {
    vec![Line::styled(
        format!(" {message}"),
        Style::default().fg(theme::WARN),
    )]
}

fn empty_line(message: &str, width: usize) -> Line<'static> {
    Line::styled(
        fit(&format!(" {message}"), width),
        Style::default().fg(theme::MUTED),
    )
}

#[cfg(test)]
mod tests {
    use crate::collect::network_route::RouteMetrics;
    use crate::monitor::{
        MetricId, MetricLabels, MetricReading, MonitorError, MonitorErrorCode, ProviderId,
        ProviderSample, SampleReading,
    };
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    use super::*;

    fn protocol_snapshot(values: &[Option<u64>]) -> std::sync::Arc<MonitorSnapshot> {
        let mut engine =
            crate::monitor::session::MonitorEngine::new(1, Duration::from_secs(1)).unwrap();
        values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let at = Duration::from_secs(index as u64 + 1);
                let (health, readings) = match value {
                    Some(value) => (
                        ProviderHealth::Fresh,
                        [
                            "linux.socket.ip.receives",
                            "linux.socket.icmp.input_messages",
                            "linux.socket.ip.fragmentation_successes",
                        ]
                        .into_iter()
                        .map(|metric| {
                            SampleReading::observed(
                                MetricId::new(metric).unwrap(),
                                MetricLabels::default(),
                                MetricReading::Counter {
                                    value: *value,
                                    bits: None,
                                },
                            )
                        })
                        .collect(),
                    ),
                    None => (
                        ProviderHealth::Error {
                            error: MonitorError::new(MonitorErrorCode::Timeout, "fixture timeout")
                                .unwrap(),
                        },
                        Vec::new(),
                    ),
                };
                let sample = ProviderSample::new(
                    ProviderId::new("linux.proc.net.snmp").unwrap(),
                    at,
                    Duration::from_millis(1),
                    health,
                    readings,
                )
                .unwrap();
                engine.ingest(at, vec![sample], None).unwrap()
            })
            .last()
            .expect("at least one protocol sample")
    }

    #[test]
    fn protocol_page_keeps_current_and_time_projection_without_trends() {
        let snapshot = protocol_snapshot(&[Some(100), Some(104), Some(114)]);
        assert!(snapshot
            .series()
            .iter()
            .all(|series| !series.history_buckets().is_empty()));
        let state = NetworkRouteViewState {
            page: NetworkRoutePage::IpMetrics,
            ..NetworkRouteViewState::default()
        };
        for width in [60, 80, 120, 160] {
            for (time_view, expected_projection) in [
                (TimeView::Interval, "+10  10.0/s"),
                (TimeView::SinceBaseline, "+14  4.7/s"),
            ] {
                let lines = metric_lines(
                    Some(&snapshot),
                    time_view,
                    DetailMetricsMode::WithData,
                    width,
                );
                assert_eq!(lines.len(), 7);
                assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                let rows = lines
                    .iter()
                    .map(Line::to_string)
                    .filter(|line| line.contains('|'))
                    .collect::<Vec<_>>();
                assert_eq!(rows.len(), 3);
                for row in rows {
                    let fields = row.split('|').map(str::trim).collect::<Vec<_>>();
                    assert_eq!(fields.len(), 4, "{row}");
                    assert_eq!(&fields[1..], &["114", expected_projection, "fresh"]);
                }
                assert_eq!(
                    row_count(
                        &state,
                        None,
                        Some(&snapshot),
                        time_view,
                        DetailMetricsMode::WithData,
                        width,
                    ),
                    lines.len()
                );
                let mut terminal = Terminal::new(TestBackend::new(width, 12)).unwrap();
                terminal
                    .draw(|frame| {
                        render(
                            frame,
                            frame.area(),
                            &state,
                            None,
                            Some(&snapshot),
                            time_view,
                            DetailMetricsMode::WithData,
                        );
                    })
                    .unwrap();
                let rendered = terminal
                    .backend()
                    .buffer()
                    .content
                    .iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>();
                assert!(rendered.contains("114"));
                assert!(rendered.contains(expected_projection));
                assert!(!rendered.to_ascii_lowercase().contains("trend"));
                assert!(!rendered
                    .chars()
                    .any(|value| ('\u{2581}'..='\u{2588}').contains(&value)));
            }
        }
    }

    #[test]
    fn protocol_rows_preserve_first_zero_reset_stale_and_recovery_states() {
        let cases: &[(&[Option<u64>], &str, &str, &str)] = &[
            (&[Some(100)], "100", "-", "fresh"),
            (&[Some(100), Some(100)], "100", "+0  0.0/s", "fresh"),
            (&[Some(100), Some(0)], "0", "reset", "fresh"),
            (&[Some(100), None], "~100", "-", "stale"),
            (
                &[Some(100), None, Some(120)],
                "120",
                "gap recovery",
                "fresh",
            ),
        ];
        for &(values, current, projection, status) in cases {
            let snapshot = protocol_snapshot(values);
            for width in [60, 80, 120, 160] {
                let visible = metric_lines(
                    Some(&snapshot),
                    TimeView::Interval,
                    DetailMetricsMode::WithData,
                    width,
                );
                assert_eq!(visible.len(), 7);
                for series in snapshot.series() {
                    let rendered =
                        metric_line(series, TimeView::Interval, usize::from(width)).to_string();
                    let fields = rendered.split('|').map(str::trim).collect::<Vec<_>>();
                    assert_eq!(&fields[1..], &[current, projection, status]);
                }
            }
        }
    }

    #[test]
    fn menu_describes_counters_without_trend_hints() {
        let snapshot = crate::monitor::network_route::synthetic_network_route_snapshot(1);
        for width in [60, 80, 120, 160] {
            for inventory in [None, Some(snapshot.as_ref())] {
                let rendered = menu_lines(inventory, 0, width)
                    .iter()
                    .map(Line::to_string)
                    .collect::<String>();
                assert!(rendered.contains("Counters and rates"));
                assert!(!rendered.to_ascii_lowercase().contains("trend"));
            }
        }
    }

    #[test]
    fn menu_navigation_and_back_form_a_stable_hierarchy() {
        let mut state = NetworkRouteViewState::default();
        state.move_down(None);
        state.enter(None);
        assert_eq!(state.page, NetworkRoutePage::Routes);
        assert!(!state.back());
        assert_eq!(state.page, NetworkRoutePage::Menu);
        assert!(state.back());
    }

    #[test]
    fn lookup_validation_stays_in_input_without_running_netlink() {
        let mut state = NetworkRouteViewState {
            menu_selected: 4,
            ..NetworkRouteViewState::default()
        };
        state.enter(None);
        for character in "not-an-ip".chars() {
            state.insert_lookup_char(character);
        }
        state.submit_lookup();
        assert_eq!(state.page, NetworkRoutePage::Lookup);
        assert!(state.text_input_active());
        assert_eq!(
            state.lookup_error(),
            Some("destination must be an IPv4 or IPv6 address")
        );
    }

    #[test]
    fn state_debug_redacts_route_lookup_text() {
        let state = NetworkRouteViewState {
            lookup_input: Some("198.51.100.77 from 192.0.2.44".to_owned()),
            ..NetworkRouteViewState::default()
        };
        let debug = format!("{state:?}");
        assert!(!debug.contains("198.51.100.77"));
        assert!(!debug.contains("192.0.2.44"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn selection_reconciles_by_identity_after_rows_are_inserted() {
        let rows = ["new", "first", "selected", "last"];
        assert_eq!(
            reconcile_selection(1, Some(&"selected"), &rows, |row| *row, false),
            (2, Some("selected"))
        );
        assert_eq!(
            reconcile_selection(3, Some(&"removed"), &rows[..2], |row| *row, false),
            (1, Some("first"))
        );
    }

    #[test]
    fn detail_preserves_a_missing_identity_instead_of_switching_rows() {
        let rows = ["first", "replacement"];
        let (selected, key) = reconcile_selection(1, Some(&"removed"), &rows, |row| *row, true);

        assert_eq!(selected, 1);
        assert_eq!(key, Some("removed"));
        assert!(selected_by_key(&rows, selected, key.as_ref(), |row| *row).is_none());
    }

    #[test]
    fn route_selection_identity_ignores_resolved_interface_name() {
        let snapshot = crate::monitor::network_route::synthetic_network_route_snapshot(1);
        let mut route = snapshot.routes().rows()[0].clone();
        let original = RouteSelectionKey::from(&route);

        route.nexthops[0].interface = Some("wan0".to_owned());
        route.nexthops[0].flags = 0x01 | 0x08 | 0x10 | 0x20 | 0x40;

        assert!(original == RouteSelectionKey::from(&route));
    }

    #[test]
    fn route_detail_shows_nonzero_tos() {
        let snapshot = crate::monitor::network_route::synthetic_network_route_snapshot(1);
        let mut route = snapshot.routes().rows()[0].clone();
        route.tos = 0x10;

        let rendered = route_detail_lines(&route, 120, DetailMetricsMode::WithData)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("TOS"));
        assert!(rendered.contains("16"));
    }

    #[test]
    fn returning_to_a_deep_table_selection_keeps_it_visible() {
        let mut state = NetworkRouteViewState {
            page: NetworkRoutePage::RouteDetail,
            route_selected: 20,
            row_offset: 10,
            viewport_rows: 5,
            ..NetworkRouteViewState::default()
        };

        assert!(!state.back());
        assert_eq!(state.page, NetworkRoutePage::Routes);
        let selected_row = state.route_selected + 3;
        assert!(selected_row >= state.row_offset);
        assert!(selected_row < state.row_offset + state.viewport_rows);

        state.page = NetworkRoutePage::Menu;
        state.menu_selected = 1;
        state.row_offset = 0;
        state.enter(None);
        assert_eq!(state.page, NetworkRoutePage::Routes);
        assert!(selected_row >= state.row_offset);
        assert!(selected_row < state.row_offset + state.viewport_rows);
    }

    #[test]
    fn menu_renders_without_overflow_at_supported_widths() {
        for width in [60, 80, 120, 160] {
            let backend = TestBackend::new(width, 18);
            let mut terminal = Terminal::new(backend).unwrap();
            let state = NetworkRouteViewState::default();
            terminal
                .draw(|frame| {
                    render(
                        frame,
                        frame.area(),
                        &state,
                        None,
                        None,
                        TimeView::Interval,
                        DetailMetricsMode::WithData,
                    );
                })
                .unwrap();
            let buffer = terminal.backend().buffer();
            assert_eq!(buffer.area.width, width);
            assert!(buffer.content.iter().any(|cell| cell.symbol() == "N"));
            assert_eq!(buffer[(0, 0)].symbol(), "┌");
            assert_eq!(buffer[(width - 1, 17)].symbol(), "┘");
            assert_eq!(buffer[(1, 3)].symbol(), "┌");
        }
    }

    #[test]
    fn route_frames_preserve_selection_visibility_and_bounds_on_every_page() {
        let inventory = crate::monitor::network_route::synthetic_network_route_snapshot(1);
        for width in [60, 80, 120, 160] {
            for page in [
                NetworkRoutePage::Menu,
                NetworkRoutePage::Routes,
                NetworkRoutePage::RouteDetail,
                NetworkRoutePage::Rules,
                NetworkRoutePage::RuleDetail,
                NetworkRoutePage::Neighbours,
                NetworkRoutePage::NeighbourDetail,
                NetworkRoutePage::Lookup,
                NetworkRoutePage::LookupResult,
                NetworkRoutePage::IpMetrics,
            ] {
                let mut state = NetworkRouteViewState {
                    page,
                    ..Default::default()
                };
                state.set_viewport_rows(10);
                assert_eq!(state.viewport_rows, 8);
                let mut terminal = Terminal::new(TestBackend::new(width, 10)).unwrap();
                for _ in 0..8 {
                    state.move_down(Some(&inventory));
                    let rows = row_count(
                        &state,
                        Some(&inventory),
                        None,
                        TimeView::Interval,
                        DetailMetricsMode::WithData,
                        width,
                    );
                    state.clamp_content_rows(rows);
                    terminal
                        .draw(|frame| {
                            render(
                                frame,
                                frame.area(),
                                &state,
                                Some(&inventory),
                                None,
                                TimeView::Interval,
                                DetailMetricsMode::WithData,
                            )
                        })
                        .unwrap();
                    let buffer = terminal.backend().buffer();
                    assert_eq!(buffer[(0, 0)].symbol(), "┌");
                    assert_eq!(buffer[(width - 1, 9)].symbol(), "┘");
                    for y in 1..9 {
                        assert_eq!(buffer[(0, y)].symbol(), "│");
                        assert_eq!(buffer[(width - 1, y)].symbol(), "│");
                    }
                    let selected = match page {
                        NetworkRoutePage::Menu => Some(state.menu_selected * 3 + 2),
                        NetworkRoutePage::Routes => Some(state.route_selected + 3),
                        NetworkRoutePage::Rules => Some(state.rule_selected + 3),
                        NetworkRoutePage::Neighbours => Some(state.neighbour_selected + 3),
                        _ => None,
                    };
                    if let Some(row) = selected {
                        assert!(row >= state.row_offset);
                        assert!(row < state.row_offset + state.viewport_rows);
                    }
                }
            }
        }
    }

    #[test]
    fn inventory_tables_keep_one_aligned_row_at_supported_widths() {
        let snapshot = crate::monitor::network_route::synthetic_network_route_snapshot(1);
        for width in [60, 80, 120, 160] {
            for lines in [
                route_table_lines(&snapshot, 0, width),
                rule_table_lines(&snapshot, 0, width),
                neighbour_table_lines(&snapshot, 0, width),
            ] {
                assert_eq!(lines.len(), 4);
                assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
                assert_eq!(lines[3].width(), usize::from(width));
            }
        }
    }

    #[test]
    fn column_layouts_exactly_fill_the_requested_width() {
        for width in [20, 60, 80, 120, 160] {
            for columns in [
                route_columns(width),
                rule_columns(width),
                neighbour_columns(width),
            ] {
                assert_eq!(columns.iter().sum::<usize>() + columns.len() - 1, width);
            }
        }
    }

    #[test]
    fn neighbour_state_reports_combined_kernel_bits() {
        assert_eq!(neighbour_state_label(0x04 | 0x20), "STALE+FAILED");
        assert_eq!(neighbour_state_label(0), "NONE");
    }

    #[test]
    fn route_detail_hides_absent_optional_fields_by_default() {
        let route = RouteRow {
            family: IpFamily::Ipv4,
            destination: IpPrefix {
                address: "0.0.0.0".parse().unwrap(),
                prefix_len: 0,
            },
            source: IpPrefix {
                address: "0.0.0.0".parse().unwrap(),
                prefix_len: 0,
            },
            tos: 0,
            table: 254,
            priority: None,
            protocol: 2,
            scope: 0,
            route_type: 1,
            flags: 0,
            preferred_source: None,
            nexthops: Vec::new(),
            nexthops_truncated: false,
            metrics: RouteMetrics::default(),
            cache: None,
            expires: None,
            unsupported_encapsulation: false,
        };
        let with_data = route_detail_lines(&route, 120, DetailMetricsMode::WithData);
        let all = route_detail_lines(&route, 120, DetailMetricsMode::All);
        assert!(all.len() > with_data.len());
        let with_data_text = with_data
            .iter()
            .map(|line| line.to_string())
            .collect::<String>();
        assert!(!with_data_text.contains("PREFERRED SOURCE"));
        assert!(!with_data_text.contains("MTU / TCP"));
    }
}
