use std::cell::{OnceCell, RefCell};
use std::sync::Arc;
use std::time::Duration;

pub(super) mod workspace;

use crate::monitor::conntrack_flow::{
    ConntrackFlowFilter, ConntrackFlowKey, ConntrackTableSnapshot,
};
use crate::monitor::dashboard::{BlockKind, ExecutionContext, InterfaceIdentity};
use crate::monitor::focus::CollectionFocus;
use crate::monitor::network_route::NetworkRouteSnapshot;
use crate::monitor::socket_table::{
    SocketDetailState, SocketFilter, SocketRowKey, SocketTableSnapshot,
};
use crate::monitor::{InterfaceViewAnchor, MetricLabels, MonitorSection, MonitorSnapshot};

use super::conntrack::ConntrackViewState;
use super::netdev::{NetdevSort, NetdevTable};
use super::netfilter::NetfilterViewState;
use super::network_route::NetworkRouteViewState;
use super::presentation::{group_section, grouped_row_count, is_interface_grouped, GroupedSection};
use super::summary::{Layer, Summary};
use super::tc::{TcRowKey, TcTable, TcViewState};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    Overview,
    Netdev,
    Tc,
    Softirq,
    Hardirq,
    Socket,
    Transport,
    Network,
    Conntrack,
    Route,
    Providers,
}

impl Page {
    pub const ALL: [Self; 11] = [
        Self::Overview,
        Self::Netdev,
        Self::Tc,
        Self::Softirq,
        Self::Hardirq,
        Self::Socket,
        Self::Transport,
        Self::Network,
        Self::Conntrack,
        Self::Route,
        Self::Providers,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Netdev => "Interface",
            Self::Tc => "Qdisc",
            Self::Softirq => "SoftIRQ",
            Self::Hardirq => "HardIRQ",
            Self::Socket => "Socket",
            Self::Transport => "Transport",
            Self::Network => "Network",
            Self::Conntrack => "Conntrack",
            Self::Route => "Route",
            Self::Providers => "Providers",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Starting,
    Live,
    Degraded,
    NoData,
    Error,
}

impl SessionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "STARTING",
            Self::Live => "LIVE",
            Self::Degraded => "DATA GAPS",
            Self::NoData => "NO DATA",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeView {
    Interval,
    SinceBaseline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetailMetricsMode {
    WithData,
    All,
}

impl DetailMetricsMode {
    const fn toggled(self) -> Self {
        match self {
            Self::WithData => Self::All,
            Self::All => Self::WithData,
        }
    }
}

impl TimeView {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interval => "INTERVAL",
            Self::SinceBaseline => "SINCE BASELINE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    SelectPage(Page),
    NextPage,
    PreviousPage,
    CycleSort,
    ReverseSort,
    Click { column: u16, row: u16 },
    OpenTcItem,
    ToggleTcMetrics,
    EnterCommand,
    EnterFlowFilter,
    EnterSocketFilter,
    ClearConnectionFilter,
    Insert(char),
    Backspace,
    SubmitCommand,
    CancelCommand,
    TogglePause,
    ToggleTimeView,
    ToggleDetailMetrics,
    SelectPreviousOverviewItem,
    SelectNextOverviewItem,
    OpenSelectedOverviewItem,
    SelectPreviousInterfaceLayer,
    SelectNextInterfaceLayer,
    OpenSelectedInterfaceLayer,
    OpenSocketTable,
    OpenSocketDetail,
    OpenNetfilterItem,
    OpenConntrackFlows,
    OpenConntrackDetail,
    OpenConntrackDiagnostics,
    OpenNetworkRouteItem,
    Back,
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    ScrollTop,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect {
    Redraw,
    Exit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardMode {
    Summary,
    LayerDetail,
    InterfaceDetail,
    InterfaceLayerDetail,
    SocketTable,
    SocketDetail,
    ConntrackFlows,
    NetworkRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverviewSelection {
    Layer(BlockKind),
    Interface,
}

#[derive(Clone, Eq, PartialEq)]
struct FlowFilterInput(String);

impl std::fmt::Debug for FlowFilterInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FlowFilterInput(<redacted>)")
    }
}

#[derive(Debug)]
pub struct App {
    section: MonitorSection,
    interval: Duration,
    interface_anchor: Option<InterfaceViewAnchor>,
    interface_name_alias: Option<String>,
    status: SessionStatus,
    collection_health_key: Option<u64>,
    paused: bool,
    time_view: TimeView,
    detail_metrics_mode: DetailMetricsMode,
    latest_snapshot: Option<Arc<MonitorSnapshot>>,
    displayed_snapshot: Option<Arc<MonitorSnapshot>>,
    grouped_section: OnceCell<GroupedSection>,
    softirq_section: OnceCell<super::dashboard::SoftirqSection>,
    softirq_sort: super::dashboard::SoftirqSort,
    softirq_descending: bool,
    softirq_metrics_mode: DetailMetricsMode,
    hardirq_table: OnceCell<super::hardirq::HardirqTable>,
    hardirq_sort: super::hardirq::Sort,
    hardirq_descending: bool,
    summary: OnceCell<Summary>,
    overview_layout: RefCell<Option<workspace::OverviewLayout>>,
    netdev_table: OnceCell<NetdevTable>,
    netdev_sort: NetdevSort,
    netdev_descending: bool,
    netdev_first: usize,
    netdev_return_section: Option<MonitorSection>,
    tc_table: OnceCell<TcTable>,
    tc_view: TcViewState,
    tc_return_overview: bool,
    tc_overview_key: Option<TcRowKey>,
    interface_inventory: Vec<InterfaceIdentity>,
    latest_socket_snapshot: Option<Arc<SocketTableSnapshot>>,
    displayed_socket_snapshot: Option<Arc<SocketTableSnapshot>>,
    latest_socket_detail: Option<SocketDetailState>,
    displayed_socket_detail: Option<SocketDetailState>,
    selected_socket_key: Option<SocketRowKey>,
    selected_socket_ordinal: Option<usize>,
    socket_click_key: Option<SocketRowKey>,
    socket_order: super::socket::SocketOrder,
    socket_filter: Option<SocketFilter>,
    latest_conntrack_snapshot: Option<Arc<ConntrackTableSnapshot>>,
    displayed_conntrack_snapshot: Option<Arc<ConntrackTableSnapshot>>,
    conntrack_filter: Option<ConntrackFlowFilter>,
    conntrack_click_key: Option<ConntrackFlowKey>,
    conntrack_view: ConntrackViewState,
    conntrack_return_mode: Option<DashboardMode>,
    saved_conntrack_list_offset: usize,
    latest_network_route_snapshot: Option<Arc<NetworkRouteSnapshot>>,
    displayed_network_route_snapshot: Option<Arc<NetworkRouteSnapshot>>,
    network_route_view: NetworkRouteViewState,
    netfilter_view: NetfilterViewState,
    dashboard_mode: DashboardMode,
    overview_selection: OverviewSelection,
    overview_click_target: Option<workspace::OverviewClickTarget>,
    selected_interface: Option<InterfaceIdentity>,
    selected_interface_ordinal: Option<usize>,
    selected_interface_layer: BlockKind,
    saved_overview_offset: usize,
    saved_overview_selection_was_visible: bool,
    saved_layer_detail_offset: usize,
    saved_interface_detail_offset: usize,
    saved_socket_table_offset: usize,
    row_offset: usize,
    viewport_width: u16,
    viewport_rows: usize,
    command: Option<String>,
    command_error: Option<String>,
    flow_filter_input: Option<FlowFilterInput>,
    flow_filter_error: Option<String>,
    socket_filter_input: Option<FlowFilterInput>,
    socket_filter_error: Option<String>,
}

impl App {
    pub fn new(section: MonitorSection, interval: Duration) -> Self {
        Self {
            section,
            interval,
            interface_anchor: None,
            interface_name_alias: None,
            status: SessionStatus::Starting,
            collection_health_key: None,
            paused: false,
            time_view: TimeView::Interval,
            detail_metrics_mode: DetailMetricsMode::WithData,
            latest_snapshot: None,
            displayed_snapshot: None,
            grouped_section: OnceCell::new(),
            softirq_section: OnceCell::new(),
            softirq_sort: super::dashboard::SoftirqSort::Cpu,
            softirq_descending: false,
            softirq_metrics_mode: DetailMetricsMode::All,
            hardirq_table: OnceCell::new(),
            hardirq_sort: super::hardirq::Sort::Rate,
            hardirq_descending: true,
            summary: OnceCell::new(),
            overview_layout: RefCell::new(None),
            netdev_table: OnceCell::new(),
            netdev_sort: NetdevSort::Ifindex,
            netdev_descending: false,
            netdev_first: 0,
            netdev_return_section: None,
            tc_table: OnceCell::new(),
            tc_view: TcViewState::default(),
            tc_return_overview: false,
            tc_overview_key: None,
            interface_inventory: Vec::new(),
            latest_socket_snapshot: None,
            displayed_socket_snapshot: None,
            latest_socket_detail: None,
            displayed_socket_detail: None,
            selected_socket_key: None,
            selected_socket_ordinal: None,
            socket_click_key: None,
            socket_order: super::socket::SocketOrder::default(),
            socket_filter: None,
            latest_conntrack_snapshot: None,
            displayed_conntrack_snapshot: None,
            conntrack_filter: None,
            conntrack_click_key: None,
            conntrack_view: ConntrackViewState::default(),
            conntrack_return_mode: None,
            saved_conntrack_list_offset: 0,
            latest_network_route_snapshot: None,
            displayed_network_route_snapshot: None,
            network_route_view: NetworkRouteViewState::default(),
            netfilter_view: NetfilterViewState::default(),
            dashboard_mode: DashboardMode::Summary,
            overview_selection: OverviewSelection::Layer(workspace::LAYERS[0]),
            overview_click_target: None,
            selected_interface: None,
            selected_interface_ordinal: None,
            selected_interface_layer: super::dashboard::INTERFACE_BLOCK_KINDS[0],
            saved_overview_offset: 0,
            saved_overview_selection_was_visible: true,
            saved_layer_detail_offset: 0,
            saved_interface_detail_offset: 0,
            saved_socket_table_offset: 0,
            row_offset: 0,
            viewport_width: u16::MAX,
            viewport_rows: 1,
            command: None,
            command_error: None,
            flow_filter_input: None,
            flow_filter_error: None,
            socket_filter_input: None,
            socket_filter_error: None,
        }
    }

    pub fn with_interface_anchor(mut self, anchor: Option<InterfaceViewAnchor>) -> Self {
        self.interface_anchor = anchor;
        self.hardirq_table.take();
        self.grouped_section.take();
        self.netdev_table.take();
        self.tc_table.take();
        self.overview_layout.get_mut().take();
        self.refresh_interface_inventory();
        self
    }

    pub(super) fn with_interface_name_alias(mut self, alias: Option<String>) -> Self {
        self.interface_name_alias = alias;
        self.grouped_section.take();
        self.netdev_table.take();
        self.tc_table.take();
        self.overview_layout.get_mut().take();
        self.refresh_interface_inventory();
        self
    }

    pub fn apply_snapshot(&mut self, snapshot: Arc<MonitorSnapshot>) -> Effect {
        if self.latest_snapshot.as_ref().is_some_and(|current| {
            current.generation() == snapshot.generation()
                && current.sequence() >= snapshot.sequence()
        }) {
            return Effect::Redraw;
        }
        let health_key = super::health::status_key(&snapshot);
        if self.collection_health_key.as_ref() != Some(&health_key) {
            self.status = match super::health::collection_health(&snapshot) {
                super::health::CollectionHealth::Healthy => SessionStatus::Live,
                super::health::CollectionHealth::Degraded => SessionStatus::Degraded,
                super::health::CollectionHealth::NoData => SessionStatus::NoData,
            };
            self.collection_health_key = Some(health_key);
        }
        self.latest_snapshot = Some(Arc::clone(&snapshot));
        if !self.paused {
            let previous_interface_ordinal = self.selected_overview_interface_ordinal();
            let selection_was_visible = self.selected_overview_item_is_fully_visible();
            self.replace_displayed_snapshot(Some(snapshot));
            self.refresh_interface_inventory();
            self.reconcile_interface_selection();
            self.reconcile_netfilter_content();
            self.reconcile_tc_content();
            if self.is_netdev_table() || selection_was_visible {
                self.ensure_netdev_selection_visible();
            }
            self.clamp_row_offset();
            if self.is_interface_detail() {
                self.ensure_selected_interface_layer_visible();
            }
            if selection_was_visible
                && previous_interface_ordinal != self.selected_overview_interface_ordinal()
            {
                self.ensure_selected_overview_item_visible();
            }
        }
        self.clamp_network_route_content();
        Effect::Redraw
    }

    pub(crate) fn apply_conntrack_snapshot(
        &mut self,
        snapshot: Arc<ConntrackTableSnapshot>,
    ) -> Effect {
        if !self.is_conntrack_flows()
            || self
                .latest_conntrack_snapshot
                .as_ref()
                .is_some_and(|current| current.sequence() >= snapshot.sequence())
        {
            return Effect::Redraw;
        }
        self.latest_conntrack_snapshot = Some(Arc::clone(&snapshot));
        if !self.paused {
            self.displayed_conntrack_snapshot = Some(snapshot);
            self.reconcile_conntrack_view();
            self.clamp_row_offset();
        }
        Effect::Redraw
    }

    pub(crate) fn apply_socket_snapshot(&mut self, snapshot: Arc<SocketTableSnapshot>) -> Effect {
        if !self.is_socket_session_active()
            || self
                .latest_socket_snapshot
                .as_ref()
                .is_some_and(|current| current.sequence() >= snapshot.sequence())
        {
            return Effect::Redraw;
        }
        if let Some(detail) = &mut self.latest_socket_detail {
            detail.record(&snapshot);
            if !self.paused {
                self.displayed_socket_detail = Some(detail.clone());
            }
        }
        self.latest_socket_snapshot = Some(Arc::clone(&snapshot));
        if !self.paused || self.displayed_socket_snapshot.is_none() {
            self.displayed_socket_snapshot = Some(snapshot);
            if self.is_socket_table() {
                self.reconcile_socket_selection();
                self.ensure_selected_socket_visible();
            }
            self.clamp_row_offset();
        }
        Effect::Redraw
    }

    pub(crate) fn apply_network_route_snapshot(
        &mut self,
        snapshot: Arc<NetworkRouteSnapshot>,
    ) -> Effect {
        if self
            .latest_network_route_snapshot
            .as_ref()
            .is_some_and(|current| current.sequence() >= snapshot.sequence())
        {
            return Effect::Redraw;
        }
        self.latest_network_route_snapshot = Some(Arc::clone(&snapshot));
        if !self.paused || self.displayed_network_route_snapshot.is_none() {
            self.displayed_network_route_snapshot = Some(snapshot);
            let displayed = self.displayed_network_route_snapshot.as_deref();
            self.network_route_view.reconcile(displayed);
        }
        self.clamp_network_route_content();
        Effect::Redraw
    }

    pub fn set_error(&mut self, _message: impl Into<String>) -> Effect {
        self.status = SessionStatus::Error;
        Effect::Redraw
    }

    pub fn update(&mut self, action: Action) -> Effect {
        if !matches!(
            &action,
            Action::Click { .. } | Action::OpenSelectedOverviewItem
        ) {
            self.overview_click_target = None;
            self.socket_click_key = None;
            self.conntrack_click_key = None;
        }
        if action == Action::ClearConnectionFilter {
            return self.clear_connection_filter();
        }
        if self.text_input_active() {
            return self.update_input(action);
        }
        match action {
            Action::SelectPage(page) => self.select_page(page),
            Action::NextPage => self.cycle_page(1),
            Action::PreviousPage => self.cycle_page(-1),
            Action::CycleSort => self.cycle_sort(),
            Action::ReverseSort => self.reverse_sort(),
            Action::Click { column, row } => self.click(column, row),
            Action::OpenTcItem => {
                self.tc_table();
                self.tc_view.open(self.tc_table.get().unwrap());
            }
            Action::ToggleTcMetrics => self.tc_view.toggle_metrics(),
            Action::EnterCommand => {
                self.command = Some(String::new());
                self.command_error = None;
            }
            Action::EnterFlowFilter => {
                if self.is_conntrack_flows() {
                    self.flow_filter_input = Some(FlowFilterInput(
                        self.conntrack_filter
                            .as_ref()
                            .map_or_else(String::new, |filter| filter.query().to_owned()),
                    ));
                    self.flow_filter_error = None;
                }
            }
            Action::EnterSocketFilter => {
                if self.is_socket_table() {
                    self.socket_filter_input = Some(FlowFilterInput(
                        self.socket_filter
                            .as_ref()
                            .map_or_else(String::new, |filter| filter.query().to_owned()),
                    ));
                    self.socket_filter_error = None;
                }
            }
            Action::ClearConnectionFilter => unreachable!(),
            Action::TogglePause => {
                self.paused = !self.paused;
                if !self.paused {
                    let previous_interface_ordinal = self.selected_overview_interface_ordinal();
                    let selection_was_visible = self.selected_overview_item_is_fully_visible();
                    self.replace_displayed_snapshot(self.latest_snapshot.clone());
                    self.refresh_interface_inventory();
                    self.displayed_socket_snapshot = self.latest_socket_snapshot.clone();
                    self.displayed_socket_detail = self.latest_socket_detail.clone();
                    self.displayed_conntrack_snapshot = self.latest_conntrack_snapshot.clone();
                    self.reconcile_conntrack_view();
                    self.displayed_network_route_snapshot =
                        self.latest_network_route_snapshot.clone();
                    self.network_route_view
                        .reconcile(self.displayed_network_route_snapshot.as_deref());
                    self.reconcile_interface_selection();
                    self.reconcile_netfilter_content();
                    self.reconcile_tc_content();
                    if self.is_netdev_table() || selection_was_visible {
                        self.ensure_netdev_selection_visible();
                    }
                    if self.is_socket_table() {
                        self.reconcile_socket_selection();
                        self.ensure_selected_socket_visible();
                    }
                    self.clamp_row_offset();
                    if self.is_interface_detail() {
                        self.ensure_selected_interface_layer_visible();
                    }
                    if selection_was_visible
                        && previous_interface_ordinal != self.selected_overview_interface_ordinal()
                    {
                        self.ensure_selected_overview_item_visible();
                    }
                }
            }
            Action::ToggleTimeView if !self.is_socket_detail() => {
                self.time_view = match self.time_view {
                    TimeView::Interval => TimeView::SinceBaseline,
                    TimeView::SinceBaseline => TimeView::Interval,
                };
                self.softirq_section.take();
                self.netdev_table.take();
                self.refresh_interface_inventory();
                self.clamp_row_offset();
                self.reconcile_netfilter_content();
                if self.is_interface_detail() {
                    self.ensure_selected_interface_layer_visible();
                }
            }
            Action::ToggleDetailMetrics => {
                if self.is_overview_detail()
                    || self.is_softirq_view()
                    || self.is_socket_detail()
                    || self.is_network_route_metrics()
                    || self.is_netfilter_conntrack()
                {
                    if self.is_softirq_view() {
                        self.softirq_metrics_mode = self.softirq_metrics_mode.toggled();
                    } else {
                        self.detail_metrics_mode = self.detail_metrics_mode.toggled();
                    }
                    self.softirq_section.take();
                    self.clamp_row_offset();
                    self.reconcile_netfilter_content();
                    if self.is_interface_detail() {
                        self.ensure_selected_interface_layer_visible();
                    }
                }
            }
            Action::SelectPreviousOverviewItem => self.select_overview_item(-1),
            Action::SelectNextOverviewItem => self.select_overview_item(1),
            Action::OpenSelectedOverviewItem => self.open_selected_overview_item(),
            Action::SelectPreviousInterfaceLayer => self.select_interface_layer(-1),
            Action::SelectNextInterfaceLayer => self.select_interface_layer(1),
            Action::OpenSelectedInterfaceLayer => self.open_selected_interface_layer(),
            Action::OpenSocketTable => self.open_socket_table(),
            Action::OpenSocketDetail => self.open_socket_detail(),
            Action::OpenNetfilterItem => self.open_netfilter_item(),
            Action::OpenConntrackFlows => self.open_conntrack_flows(),
            Action::OpenConntrackDetail => self.open_conntrack_detail(),
            Action::OpenConntrackDiagnostics if self.is_conntrack_flows() => {
                if !self.conntrack_view.is_detail() {
                    self.saved_conntrack_list_offset = self.row_offset;
                }
                self.conntrack_view.open_diagnostics();
                self.row_offset = 0;
            }
            Action::OpenConntrackDiagnostics => {}
            Action::OpenNetworkRouteItem => {
                let snapshot = self.displayed_network_route_snapshot.clone();
                self.network_route_view.enter(snapshot.as_deref());
            }
            Action::Back => self.back(),
            Action::ScrollUp if self.is_conntrack_list() => self.move_conntrack(-1),
            Action::ScrollDown if self.is_conntrack_list() => self.move_conntrack(1),
            Action::PageUp if self.is_conntrack_list() => {
                self.move_conntrack(-(self.connection_page_size() as isize));
            }
            Action::PageDown if self.is_conntrack_list() => {
                self.move_conntrack(self.connection_page_size() as isize);
            }
            Action::ScrollTop if self.is_conntrack_list() => {
                self.conntrack_view.select(0);
                self.row_offset = 0;
                self.ensure_conntrack_selection_visible();
            }
            Action::ScrollUp if self.is_tc_view() => self.move_tc(-1),
            Action::ScrollDown if self.is_tc_view() => self.move_tc(1),
            Action::PageUp if self.is_tc_view() => self.move_tc(-(self.viewport_rows as isize)),
            Action::PageDown if self.is_tc_view() => self.move_tc(self.viewport_rows as isize),
            Action::ScrollTop if self.is_tc_view() => {
                let table = self.tc_table().clone();
                self.tc_view.scroll_top(&table);
            }
            Action::ScrollUp if self.is_netdev_table() => self.move_netdev(-1),
            Action::ScrollDown if self.is_netdev_table() => self.move_netdev(1),
            Action::PageUp if self.is_netdev_table() => self.move_netdev(
                -(NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16)
                    .max(1) as isize),
            ),
            Action::PageDown if self.is_netdev_table() => self.move_netdev(
                NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16).max(1)
                    as isize,
            ),
            Action::ScrollTop if self.is_netdev_table() => {
                self.move_netdev(-(self.interface_inventory.len() as isize))
            }
            Action::ScrollUp if self.is_netfilter_view() => {
                let snapshot = self.displayed_snapshot.clone();
                self.netfilter_view.move_up(snapshot.as_deref());
                self.reconcile_netfilter_content();
            }
            Action::ScrollDown if self.is_netfilter_view() => {
                let snapshot = self.displayed_snapshot.clone();
                self.netfilter_view.move_down(snapshot.as_deref());
                self.reconcile_netfilter_content();
            }
            Action::PageUp if self.is_netfilter_view() => {
                let snapshot = self.displayed_snapshot.clone();
                self.netfilter_view.page_up(snapshot.as_deref());
                self.reconcile_netfilter_content();
            }
            Action::PageDown if self.is_netfilter_view() => {
                let snapshot = self.displayed_snapshot.clone();
                self.netfilter_view.page_down(snapshot.as_deref());
                self.reconcile_netfilter_content();
            }
            Action::ScrollTop if self.is_netfilter_view() => self.netfilter_view.scroll_top(),
            Action::ScrollUp if self.is_network_route() => {
                let snapshot = self.displayed_network_route_snapshot.clone();
                self.network_route_view.move_up(snapshot.as_deref());
            }
            Action::ScrollDown if self.is_network_route() => {
                let snapshot = self.displayed_network_route_snapshot.clone();
                self.network_route_view.move_down(snapshot.as_deref());
            }
            Action::PageUp if self.is_network_route() => {
                let snapshot = self.displayed_network_route_snapshot.clone();
                self.network_route_view.page_up(snapshot.as_deref());
            }
            Action::PageDown if self.is_network_route() => {
                let snapshot = self.displayed_network_route_snapshot.clone();
                self.network_route_view.page_down(snapshot.as_deref());
            }
            Action::ScrollTop if self.is_network_route() => self.network_route_view.scroll_top(),
            Action::ScrollUp if self.is_socket_table() => self.select_socket(-1),
            Action::ScrollDown if self.is_socket_table() => self.select_socket(1),
            Action::PageUp if self.is_socket_table() => {
                self.select_socket(-(self.connection_page_size() as isize));
            }
            Action::PageDown if self.is_socket_table() => {
                self.select_socket(self.connection_page_size() as isize);
            }
            Action::ScrollTop if self.is_socket_table() => self.select_first_socket(),
            Action::PageUp if self.is_softirq_view() => self.scroll_up(self.softirq_page_size()),
            Action::PageDown if self.is_softirq_view() => {
                self.scroll_down(self.softirq_page_size())
            }
            Action::ScrollUp => self.scroll_up(1),
            Action::ScrollDown => self.scroll_down(1),
            Action::PageUp => self.scroll_up(10),
            Action::PageDown => self.scroll_down(10),
            Action::ScrollTop => self.row_offset = 0,
            Action::Quit => return Effect::Exit,
            Action::Insert(_)
            | Action::Backspace
            | Action::SubmitCommand
            | Action::CancelCommand
            | Action::ToggleTimeView => {}
        }
        self.clamp_network_route_content();
        self.reconcile_tc_content();
        Effect::Redraw
    }

    pub const fn section(&self) -> MonitorSection {
        self.section
    }

    pub(super) fn collection_focus(&self) -> CollectionFocus {
        use crate::monitor::dashboard::{ExecutionContext, PacketStage};
        if self.is_conntrack_flows() {
            return CollectionFocus::ConntrackFlows;
        }
        if self.is_network_route() {
            return CollectionFocus::Route;
        }
        if self.is_socket_session_active() {
            return MonitorSection::Socket.into();
        }
        if self.is_interface_detail() {
            return CollectionFocus::InterfaceDetail;
        }
        if self.is_netdev_table() {
            return MonitorSection::Nic.into();
        }
        if let Some(layer) = self.detail_interface_layer() {
            let section = match layer {
                BlockKind::PacketStage(PacketStage::TrafficControl) => MonitorSection::Tc,
                BlockKind::PacketStage(PacketStage::NicPhy | PacketStage::DriverNapi) => {
                    MonitorSection::Nic
                }
                BlockKind::PacketStage(PacketStage::NetdeviceCore) => MonitorSection::Netdevice,
                BlockKind::ExecutionContext(ExecutionContext::Hardirq) => MonitorSection::Hardirq,
                _ => return CollectionFocus::InterfaceDetail,
            };
            return CollectionFocus::InterfaceLayer(section);
        }
        match self
            .detail_interface_layer()
            .or_else(|| self.detail_layer())
        {
            Some(BlockKind::PacketStage(PacketStage::TrafficControl)) => MonitorSection::Tc.into(),
            Some(BlockKind::PacketStage(PacketStage::NicPhy | PacketStage::DriverNapi)) => {
                MonitorSection::Nic.into()
            }
            Some(BlockKind::PacketStage(PacketStage::NetfilterConntrack)) => {
                MonitorSection::Netfilter.into()
            }
            Some(BlockKind::PacketStage(PacketStage::Transport)) => CollectionFocus::Transport,
            Some(BlockKind::PacketStage(PacketStage::NetworkRoute)) => CollectionFocus::Network,
            Some(BlockKind::PacketStage(PacketStage::SocketApplication)) => {
                MonitorSection::Socket.into()
            }
            Some(BlockKind::PacketStage(PacketStage::NetdeviceCore)) => {
                MonitorSection::Netdevice.into()
            }
            Some(BlockKind::ExecutionContext(ExecutionContext::Hardirq)) => {
                MonitorSection::Hardirq.into()
            }
            Some(BlockKind::ExecutionContext(ExecutionContext::Softirq)) => {
                MonitorSection::Softirq.into()
            }
            _ => self.section.into(),
        }
    }

    pub(super) fn clear_network_route_snapshots(&mut self) {
        self.latest_network_route_snapshot = None;
        self.displayed_network_route_snapshot = None;
    }

    pub const fn interval(&self) -> Duration {
        self.interval
    }

    pub fn interface_anchor(&self) -> Option<&InterfaceViewAnchor> {
        self.interface_anchor.as_ref()
    }

    pub(super) fn interface_name_alias(&self) -> Option<&str> {
        self.interface_name_alias.as_deref()
    }

    pub const fn status(&self) -> SessionStatus {
        self.status
    }

    pub const fn paused(&self) -> bool {
        self.paused
    }

    pub const fn time_view(&self) -> TimeView {
        self.time_view
    }

    pub fn detail_metrics_mode(&self) -> DetailMetricsMode {
        if self.is_softirq_view() {
            self.softirq_metrics_mode
        } else {
            self.detail_metrics_mode
        }
    }

    pub const fn dashboard_mode(&self) -> DashboardMode {
        self.dashboard_mode
    }

    pub const fn selected_layer(&self) -> Option<BlockKind> {
        match self.overview_selection {
            OverviewSelection::Layer(kind) => Some(kind),
            OverviewSelection::Interface => None,
        }
    }

    pub fn selected_interface(&self) -> Option<&InterfaceIdentity> {
        (self.overview_selection == OverviewSelection::Interface)
            .then_some(self.selected_interface.as_ref())
            .flatten()
    }

    pub const fn detail_layer(&self) -> Option<BlockKind> {
        match (self.dashboard_mode, self.overview_selection) {
            (DashboardMode::LayerDetail, OverviewSelection::Layer(kind)) => Some(kind),
            _ => None,
        }
    }

    pub fn detail_interface(&self) -> Option<&InterfaceIdentity> {
        matches!(
            self.dashboard_mode,
            DashboardMode::InterfaceDetail | DashboardMode::InterfaceLayerDetail
        )
        .then_some(self.selected_interface.as_ref())
        .flatten()
    }

    pub const fn selected_interface_layer(&self) -> Option<BlockKind> {
        if matches!(
            self.dashboard_mode,
            DashboardMode::InterfaceDetail | DashboardMode::InterfaceLayerDetail
        ) {
            Some(self.selected_interface_layer)
        } else {
            None
        }
    }

    pub const fn detail_interface_layer(&self) -> Option<BlockKind> {
        match self.dashboard_mode {
            DashboardMode::InterfaceLayerDetail => Some(self.selected_interface_layer),
            _ => None,
        }
    }

    pub const fn is_interface_detail(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::InterfaceDetail)
    }

    pub const fn is_interface_layer_detail(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::InterfaceLayerDetail)
    }

    pub fn can_open_interface_layer_detail(&self) -> bool {
        self.is_interface_detail() && self.selected_interface.is_some()
    }

    pub fn is_detail(&self) -> bool {
        self.dashboard_mode != DashboardMode::Summary || self.section != MonitorSection::Overview
    }

    pub fn is_conntrack_flows(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::ConntrackFlows)
    }

    pub(super) fn is_conntrack_list(&self) -> bool {
        self.is_conntrack_flows() && !self.conntrack_view.is_detail()
    }

    pub(super) fn conntrack_view(&self) -> &ConntrackViewState {
        &self.conntrack_view
    }

    pub fn is_netfilter_view(&self) -> bool {
        (self.section == MonitorSection::Netfilter && self.dashboard_mode == DashboardMode::Summary)
            || (self.section == MonitorSection::Overview
                && matches!(
                    (self.dashboard_mode, self.overview_selection),
                    (
                        DashboardMode::LayerDetail,
                        OverviewSelection::Layer(BlockKind::PacketStage(
                            crate::monitor::dashboard::PacketStage::NetfilterConntrack
                        ))
                    )
                ))
    }

    pub fn is_netfilter_conntrack(&self) -> bool {
        self.is_netfilter_view() && self.netfilter_view.is_conntrack()
    }

    pub(super) fn is_softirq_view(&self) -> bool {
        (self.section == MonitorSection::Softirq && self.dashboard_mode == DashboardMode::Summary)
            || self.detail_layer() == Some(BlockKind::ExecutionContext(ExecutionContext::Softirq))
    }

    pub fn is_socket_table(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::SocketTable)
    }

    pub fn is_socket_detail(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::SocketDetail)
    }

    pub fn is_socket_session_active(&self) -> bool {
        self.is_socket_table() || self.is_socket_detail()
    }

    pub fn is_network_route(&self) -> bool {
        matches!(self.dashboard_mode, DashboardMode::NetworkRoute)
    }

    pub fn is_network_route_metrics(&self) -> bool {
        self.is_network_route() && self.network_route_view.supports_metric_visibility_toggle()
    }

    pub fn can_open_socket_table(&self) -> bool {
        (self.section == MonitorSection::Overview
            && matches!(
                (self.dashboard_mode, self.overview_selection),
                (
                    DashboardMode::LayerDetail,
                    OverviewSelection::Layer(BlockKind::PacketStage(
                        crate::monitor::dashboard::PacketStage::SocketApplication
                    ))
                )
            ))
            || (self.section == MonitorSection::Socket
                && self.dashboard_mode == DashboardMode::Summary)
    }

    pub fn can_open_socket_detail(&self) -> bool {
        self.is_socket_table()
            && self.selected_socket_key.as_ref().is_some_and(|key| {
                self.socket_snapshot()
                    .is_some_and(|snapshot| snapshot.socket(key).is_some())
            })
    }

    pub fn can_open_conntrack_flows(&self) -> bool {
        self.is_netfilter_conntrack()
    }

    pub fn is_overview_detail(&self) -> bool {
        self.section == MonitorSection::Overview
            && matches!(
                self.dashboard_mode,
                DashboardMode::LayerDetail
                    | DashboardMode::InterfaceDetail
                    | DashboardMode::InterfaceLayerDetail
            )
    }

    pub fn snapshot(&self) -> Option<&MonitorSnapshot> {
        self.displayed_snapshot.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn conntrack_snapshot(&self) -> Option<&ConntrackTableSnapshot> {
        self.displayed_conntrack_snapshot.as_deref()
    }

    pub(crate) fn socket_snapshot(&self) -> Option<&SocketTableSnapshot> {
        self.displayed_socket_snapshot.as_deref()
    }

    pub(super) fn socket_order(&self) -> &super::socket::SocketOrder {
        &self.socket_order
    }

    pub(crate) fn socket_detail(&self) -> Option<&SocketDetailState> {
        self.displayed_socket_detail.as_ref()
    }

    pub(crate) fn network_route_snapshot(&self) -> Option<&NetworkRouteSnapshot> {
        self.displayed_network_route_snapshot.as_deref()
    }

    pub(super) const fn network_route_view(&self) -> &NetworkRouteViewState {
        &self.network_route_view
    }

    pub(super) const fn netfilter_view(&self) -> &NetfilterViewState {
        &self.netfilter_view
    }

    pub(crate) fn selected_socket_key(&self) -> Option<&SocketRowKey> {
        self.selected_socket_key.as_ref()
    }

    #[cfg(test)]
    pub(crate) const fn selected_socket_ordinal(&self) -> Option<usize> {
        self.selected_socket_ordinal
    }

    pub(crate) fn conntrack_filter(&self) -> Option<&ConntrackFlowFilter> {
        self.conntrack_filter.as_ref()
    }

    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    pub fn command_error(&self) -> Option<&str> {
        self.command_error.as_deref()
    }

    pub(crate) fn flow_filter_input(&self) -> Option<&str> {
        self.flow_filter_input
            .as_ref()
            .map(|input| input.0.as_str())
    }

    pub(crate) fn flow_filter_error(&self) -> Option<&str> {
        self.flow_filter_error.as_deref()
    }

    pub(crate) fn socket_filter_input(&self) -> Option<&str> {
        self.socket_filter_input
            .as_ref()
            .map(|input| input.0.as_str())
    }

    pub(crate) fn socket_filter_error(&self) -> Option<&str> {
        self.socket_filter_error.as_deref()
    }

    pub(crate) fn route_lookup_input(&self) -> Option<&str> {
        self.is_network_route()
            .then(|| self.network_route_view.lookup_input())
            .flatten()
    }

    pub(crate) fn route_lookup_error(&self) -> Option<&str> {
        self.is_network_route()
            .then(|| self.network_route_view.lookup_error())
            .flatten()
    }

    pub(crate) fn text_input_active(&self) -> bool {
        self.command.is_some()
            || self.flow_filter_input.is_some()
            || self.socket_filter_input.is_some()
            || (self.is_network_route() && self.network_route_view.text_input_active())
    }

    pub const fn row_offset(&self) -> usize {
        self.row_offset
    }

    pub(super) fn set_viewport_size(&mut self, width: u16, rows: usize) {
        let rows = rows.max(1);
        let size_changed = self.viewport_width != width || self.viewport_rows != rows;
        if !size_changed {
            return;
        }
        if self.viewport_width != width {
            self.softirq_section.take();
            self.hardirq_table.take();
        }
        let selection_was_visible = self.selected_overview_item_is_fully_visible();
        let selection_could_not_fit = self
            .selected_overview_row_span()
            .is_some_and(|span| span.len() > self.viewport_rows);
        self.viewport_width = width;
        self.viewport_rows = rows;
        self.tc_view.set_viewport_rows(rows);
        self.network_route_view.set_viewport_rows(rows);
        self.netfilter_view.set_viewport_rows(rows);
        self.clamp_row_offset();
        self.reconcile_netfilter_content();
        self.reconcile_tc_content();
        self.ensure_conntrack_selection_visible();
        if self.is_netdev_table() || selection_was_visible || selection_could_not_fit {
            self.ensure_netdev_selection_visible();
        }
        if size_changed
            && (selection_was_visible || selection_could_not_fit)
            && self.section == MonitorSection::Overview
            && self.dashboard_mode == DashboardMode::Summary
        {
            self.ensure_selected_overview_item_visible();
        } else if size_changed && self.is_socket_table() {
            self.ensure_selected_socket_visible();
        } else if size_changed && self.is_interface_detail() {
            self.ensure_selected_interface_layer_visible();
        }
        self.clamp_network_route_content();
    }

    fn update_input(&mut self, action: Action) -> Effect {
        if self.is_network_route() && self.network_route_view.text_input_active() {
            return self.update_route_lookup_input(action);
        }
        if self.flow_filter_input.is_some() {
            return self.update_flow_filter_input(action);
        }
        if self.socket_filter_input.is_some() {
            return self.update_socket_filter_input(action);
        }
        match action {
            Action::Insert(character) if !character.is_control() => {
                if self.command.as_ref().is_some_and(|value| value.len() < 128) {
                    self.command
                        .as_mut()
                        .expect("command mode has an input buffer")
                        .push(character);
                }
            }
            Action::Backspace => {
                self.command
                    .as_mut()
                    .expect("command mode has an input buffer")
                    .pop();
            }
            Action::SubmitCommand => return self.submit_command(),
            Action::Quit => return Effect::Exit,
            Action::CancelCommand => {
                self.command = None;
                self.command_error = None;
            }
            _ => {}
        }
        Effect::Redraw
    }

    fn update_route_lookup_input(&mut self, action: Action) -> Effect {
        match action {
            Action::Insert(character) => self.network_route_view.insert_lookup_char(character),
            Action::Backspace => self.network_route_view.lookup_backspace(),
            Action::SubmitCommand => self.network_route_view.submit_lookup(),
            Action::CancelCommand => {
                let _ = self.network_route_view.back();
            }
            Action::Quit => return Effect::Exit,
            _ => {}
        }
        Effect::Redraw
    }

    fn update_flow_filter_input(&mut self, action: Action) -> Effect {
        match action {
            Action::Insert(character) if !character.is_control() => {
                if self
                    .flow_filter_input
                    .as_ref()
                    .is_some_and(|input| input.0.len() < 256)
                {
                    self.flow_filter_input
                        .as_mut()
                        .expect("flow filter has an input buffer")
                        .0
                        .push(character);
                    self.flow_filter_error = None;
                }
            }
            Action::Backspace => {
                self.flow_filter_input
                    .as_mut()
                    .expect("flow filter has an input buffer")
                    .0
                    .pop();
                self.flow_filter_error = None;
            }
            Action::SubmitCommand => return self.submit_flow_filter(),
            Action::Quit => return Effect::Exit,
            Action::CancelCommand => {
                self.flow_filter_input = None;
                self.flow_filter_error = None;
            }
            _ => {}
        }
        Effect::Redraw
    }

    fn submit_flow_filter(&mut self) -> Effect {
        let query = self
            .flow_filter_input
            .as_ref()
            .map_or("", |input| input.0.as_str());
        match ConntrackFlowFilter::parse(query) {
            Ok(filter) => {
                self.conntrack_filter = filter;
                self.flow_filter_input = None;
                self.flow_filter_error = None;
                self.row_offset = 0;
                self.conntrack_view.back();
                self.reconcile_conntrack_view();
            }
            Err(error) => self.flow_filter_error = Some(error.to_owned()),
        }
        Effect::Redraw
    }

    fn update_socket_filter_input(&mut self, action: Action) -> Effect {
        match action {
            Action::Insert(character) if !character.is_control() => {
                if self
                    .socket_filter_input
                    .as_ref()
                    .is_some_and(|input| input.0.len() < 256)
                {
                    self.socket_filter_input
                        .as_mut()
                        .expect("socket filter has an input buffer")
                        .0
                        .push(character);
                    self.socket_filter_error = None;
                }
            }
            Action::Backspace => {
                self.socket_filter_input
                    .as_mut()
                    .expect("socket filter has an input buffer")
                    .0
                    .pop();
                self.socket_filter_error = None;
            }
            Action::SubmitCommand => return self.submit_socket_filter(),
            Action::Quit => return Effect::Exit,
            Action::CancelCommand => {
                self.socket_filter_input = None;
                self.socket_filter_error = None;
            }
            _ => {}
        }
        Effect::Redraw
    }

    fn clear_connection_filter(&mut self) -> Effect {
        if self.is_socket_table() {
            self.socket_filter = None;
            self.socket_filter_input = None;
            self.socket_filter_error = None;
            self.row_offset = 0;
            self.reconcile_socket_selection();
            self.ensure_selected_socket_visible();
        } else if self.is_conntrack_flows() {
            self.conntrack_filter = None;
            self.flow_filter_input = None;
            self.flow_filter_error = None;
            self.row_offset = 0;
            self.conntrack_view.back();
            self.reconcile_conntrack_view();
        }
        Effect::Redraw
    }

    fn submit_socket_filter(&mut self) -> Effect {
        let query = self
            .socket_filter_input
            .as_ref()
            .map_or("", |input| input.0.as_str());
        match SocketFilter::parse(query) {
            Ok(filter) => {
                self.socket_filter = filter;
                self.socket_filter_input = None;
                self.socket_filter_error = None;
                self.row_offset = 0;
                self.reconcile_socket_selection();
                self.ensure_selected_socket_visible();
            }
            Err(error) => self.socket_filter_error = Some(error.to_owned()),
        }
        Effect::Redraw
    }

    fn submit_command(&mut self) -> Effect {
        let input = self.command.take().unwrap_or_default();
        let input = input.trim();
        let normalized = input.strip_prefix("section ").unwrap_or(input);
        self.command_error = None;
        match normalized {
            "q" | "quit" => Effect::Exit,
            "pause" => self.update(Action::TogglePause),
            "time" => self.update(Action::ToggleTimeView),
            "conntrack" | "flows" => self.update(Action::SelectPage(Page::Conntrack)),
            "interface" | "netdev" | "nic" | "netdevice" => {
                self.update(Action::SelectPage(Page::Netdev))
            }
            "tc" | "qdisc" => self.update(Action::SelectPage(Page::Tc)),
            "socket" | "sockets" => self.update(Action::SelectPage(Page::Socket)),
            "transport" => self.update(Action::SelectPage(Page::Transport)),
            "network" => self.update(Action::SelectPage(Page::Network)),
            "route" | "routes" => self.update(Action::SelectPage(Page::Route)),
            _ => match normalized.parse::<MonitorSection>() {
                Ok(section) => {
                    self.select_section(section);
                    Effect::Redraw
                }
                Err(_) => {
                    self.command_error = Some(format!("unknown command: {input}"));
                    Effect::Redraw
                }
            },
        }
    }

    fn select_section(&mut self, section: MonitorSection) {
        self.softirq_section.take();
        // Page changes rebuild the visible table while retaining the displayed snapshot.
        self.netdev_table.take();
        self.netdev_return_section = None;
        self.tc_return_overview = false;
        self.tc_overview_key = None;
        if section == MonitorSection::Overview && self.is_detail() {
            self.clear_table_state();
            self.return_to_overview();
            return;
        }
        if self.section == MonitorSection::Overview
            && self.dashboard_mode == DashboardMode::Summary
            && section != MonitorSection::Overview
        {
            self.saved_overview_offset = self.row_offset;
            self.saved_overview_selection_was_visible =
                self.selected_overview_item_is_fully_visible();
        }
        self.clear_table_state();
        self.section = section;
        self.grouped_section.take();
        self.refresh_interface_inventory();
        self.dashboard_mode = DashboardMode::Summary;
        if section == MonitorSection::Overview {
            self.reconcile_interface_selection();
        }
        self.row_offset = 0;
        self.reconcile_softirq_sort();
    }

    fn open_selected_overview_item(&mut self) {
        if self.overview_click_target == Some(workspace::OverviewClickTarget::InterfaceTitle) {
            self.select_page(Page::Netdev);
            return;
        }
        self.overview_click_target = None;
        let standalone_netdev = self.is_netdev_table();
        if standalone_netdev {
            self.overview_selection = OverviewSelection::Interface;
        }
        if (!standalone_netdev && self.section != MonitorSection::Overview)
            || self.dashboard_mode != DashboardMode::Summary
        {
            return;
        }
        self.softirq_section.take();
        self.netdev_return_section = standalone_netdev.then_some(self.section);
        if !standalone_netdev {
            self.saved_overview_offset = self.row_offset;
            self.saved_overview_selection_was_visible =
                self.selected_overview_item_is_fully_visible();
        }
        if self.overview_selection
            == OverviewSelection::Layer(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::TrafficControl,
            ))
        {
            self.section = MonitorSection::Tc;
            self.tc_return_overview = true;
            self.tc_overview_key = None;
            self.tc_view = TcViewState::default();
            self.row_offset = 0;
            self.reconcile_tc_content();
            return;
        }
        if matches!(
            self.overview_selection,
            OverviewSelection::Layer(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::NetworkRoute
            ))
        ) {
            self.dashboard_mode = DashboardMode::LayerDetail;
            self.row_offset = 0;
            return;
        }
        if matches!(self.overview_selection, OverviewSelection::Layer(_)) {
            if matches!(
                self.overview_selection,
                OverviewSelection::Layer(BlockKind::PacketStage(
                    crate::monitor::dashboard::PacketStage::NetfilterConntrack
                ))
            ) {
                self.dashboard_mode = DashboardMode::ConntrackFlows;
                self.conntrack_return_mode = None;
                self.row_offset = 0;
                return;
            }
            self.dashboard_mode = DashboardMode::LayerDetail;
            self.row_offset = 0;
            self.reconcile_softirq_sort();
            return;
        }
        let interfaces = self.ordered_interfaces();
        let Some(position) = self
            .selected_interface
            .as_ref()
            .and_then(|selected| interfaces.iter().position(|identity| identity == selected))
        else {
            self.reconcile_interface_selection();
            return;
        };
        self.selected_interface_ordinal = Some(position);
        self.selected_interface_layer = super::dashboard::INTERFACE_BLOCK_KINDS[0];
        self.dashboard_mode = DashboardMode::InterfaceDetail;
        self.row_offset = 0;
        self.ensure_selected_interface_layer_visible();
    }

    fn open_selected_interface_layer(&mut self) {
        if !self.can_open_interface_layer_detail() {
            return;
        }
        self.saved_interface_detail_offset = self.row_offset;
        self.dashboard_mode = DashboardMode::InterfaceLayerDetail;
        self.row_offset = 0;
    }

    fn open_conntrack_flows(&mut self) {
        if !self.can_open_conntrack_flows() {
            return;
        }
        self.saved_layer_detail_offset = self.row_offset;
        self.conntrack_return_mode = Some(self.dashboard_mode);
        self.dashboard_mode = DashboardMode::ConntrackFlows;
        self.row_offset = 0;
        self.latest_conntrack_snapshot = None;
        self.displayed_conntrack_snapshot = None;
        self.flow_filter_input = None;
        self.flow_filter_error = None;
        self.socket_filter_input = None;
        self.socket_filter_error = None;
    }

    fn open_netfilter_item(&mut self) {
        if !self.is_netfilter_view() {
            return;
        }
        if self.is_netfilter_conntrack() {
            self.open_conntrack_flows();
            return;
        }
        let snapshot = self.displayed_snapshot.clone();
        self.netfilter_view.enter(snapshot.as_deref());
        self.reconcile_netfilter_content();
    }

    fn open_socket_table(&mut self) {
        if !self.can_open_socket_table() {
            return;
        }
        self.saved_layer_detail_offset = self.row_offset;
        self.dashboard_mode = DashboardMode::SocketTable;
        self.row_offset = 0;
        self.clear_socket_state();
    }

    fn open_socket_detail(&mut self) {
        if !self.can_open_socket_detail() {
            return;
        }
        let Some(displayed_snapshot) = self.displayed_socket_snapshot.as_deref() else {
            return;
        };
        let Some(key) = self.selected_socket_key.clone() else {
            return;
        };
        let initial_snapshot = self
            .latest_socket_snapshot
            .as_deref()
            .unwrap_or(displayed_snapshot);
        let opened_at = initial_snapshot
            .attempted_at()
            .max(displayed_snapshot.attempted_at());
        let Some(displayed_detail) = SocketDetailState::start_at(
            displayed_snapshot,
            displayed_snapshot,
            key.clone(),
            opened_at,
        ) else {
            return;
        };
        let latest_detail =
            SocketDetailState::start_at(displayed_snapshot, initial_snapshot, key, opened_at)
                .expect("the selected socket exists in the displayed snapshot");
        self.saved_socket_table_offset = self.row_offset;
        self.dashboard_mode = DashboardMode::SocketDetail;
        self.row_offset = 0;
        self.displayed_socket_detail = Some(if self.paused {
            displayed_detail
        } else {
            latest_detail.clone()
        });
        self.latest_socket_detail = Some(latest_detail);
    }

    fn back(&mut self) {
        if self.is_tc_view() {
            let direct_overview_detail = self.tc_return_overview && self.tc_overview_key.is_some();
            if self.tc_view.back() || direct_overview_detail {
                self.tc_return_overview = false;
                self.return_to_overview();
                self.ensure_tc_overview_object_visible();
            } else {
                self.reconcile_tc_content();
            }
            return;
        }
        if self.is_network_route() {
            if self.network_route_view.back() {
                self.network_route_view = NetworkRouteViewState::default();
                self.return_to_overview();
            }
            return;
        }
        if self.is_interface_layer_detail() {
            self.dashboard_mode = DashboardMode::InterfaceDetail;
            self.row_offset = self.saved_interface_detail_offset;
            self.ensure_selected_interface_layer_visible();
            return;
        }
        if self.is_interface_detail() {
            if let Some(section) = self.netdev_return_section.take() {
                self.section = section;
                self.dashboard_mode = DashboardMode::Summary;
                self.row_offset = 0;
                self.refresh_interface_inventory();
                self.reconcile_interface_selection();
                self.ensure_netdev_selection_visible();
                return;
            }
        }
        if self.is_socket_detail() {
            self.dashboard_mode = DashboardMode::SocketTable;
            self.row_offset = self.saved_socket_table_offset;
            self.latest_socket_detail = None;
            self.displayed_socket_detail = None;
            self.reconcile_socket_selection();
            self.ensure_selected_socket_visible();
            self.clamp_row_offset();
            return;
        }
        if self.is_socket_table() {
            self.dashboard_mode = if self.section == MonitorSection::Overview {
                DashboardMode::LayerDetail
            } else {
                DashboardMode::Summary
            };
            self.row_offset = self.saved_layer_detail_offset;
            self.clear_socket_state();
            self.clamp_row_offset();
            return;
        }
        if self.is_conntrack_flows() {
            if self.conntrack_view.back() {
                self.row_offset = self.saved_conntrack_list_offset;
                self.ensure_conntrack_selection_visible();
            } else {
                let return_mode = self.conntrack_return_mode;
                self.clear_conntrack_state();
                if let Some(return_mode) = return_mode {
                    self.dashboard_mode = return_mode;
                    self.row_offset = self.saved_layer_detail_offset;
                } else {
                    self.return_to_overview();
                }
            }
            self.clamp_row_offset();
            return;
        }
        if self.is_netfilter_view() {
            if self.netfilter_view.back() {
                self.netfilter_view = NetfilterViewState::default();
                self.return_to_overview();
            } else {
                self.reconcile_netfilter_content();
            }
            return;
        }
        self.return_to_overview();
    }

    fn return_to_overview(&mut self) {
        if !self.is_detail() {
            return;
        }
        self.section = MonitorSection::Overview;
        self.netdev_return_section = None;
        self.netdev_table.take();
        self.refresh_interface_inventory();
        self.dashboard_mode = DashboardMode::Summary;
        self.reconcile_interface_selection();
        self.row_offset = self.saved_overview_offset;
        self.clamp_row_offset();
        if self.saved_overview_selection_was_visible
            && !self.selected_overview_item_is_fully_visible()
        {
            self.ensure_selected_overview_item_visible();
        }
    }

    fn clear_conntrack_state(&mut self) {
        self.latest_conntrack_snapshot = None;
        self.displayed_conntrack_snapshot = None;
        self.conntrack_view.clear();
        self.saved_conntrack_list_offset = 0;
        self.conntrack_return_mode = None;
        self.flow_filter_input = None;
        self.flow_filter_error = None;
    }

    fn clear_socket_state(&mut self) {
        self.latest_socket_snapshot = None;
        self.displayed_socket_snapshot = None;
        self.latest_socket_detail = None;
        self.displayed_socket_detail = None;
        self.selected_socket_key = None;
        self.selected_socket_ordinal = None;
        self.socket_order.clear();
        self.socket_filter_input = None;
        self.socket_filter_error = None;
        self.saved_socket_table_offset = 0;
    }

    fn clear_table_state(&mut self) {
        self.overview_click_target = None;
        self.clear_socket_state();
        self.clear_conntrack_state();
        self.network_route_view = NetworkRouteViewState::default();
        self.netfilter_view = NetfilterViewState::default();
    }

    fn reconcile_socket_selection(&mut self) {
        if let Some(snapshot) = &self.displayed_socket_snapshot {
            self.socket_order
                .update(Arc::clone(snapshot), self.socket_filter.as_ref());
        }
        if self.displayed_socket_snapshot.is_none() {
            self.selected_socket_key = None;
            self.selected_socket_ordinal = None;
            return;
        }
        if self.socket_order.shown_count() == 0 {
            self.selected_socket_key = None;
            self.selected_socket_ordinal = None;
            return;
        }
        if let Some(position) = self
            .selected_socket_key
            .as_ref()
            .and_then(|key| self.socket_order.position(key))
        {
            self.selected_socket_ordinal = Some(position);
            return;
        }
        let position = self
            .selected_socket_ordinal
            .unwrap_or(0)
            .min(self.socket_order.shown_count().saturating_sub(1));
        self.selected_socket_key = self
            .socket_order
            .socket(position)
            .map(|socket| socket.row_key().clone());
        self.selected_socket_ordinal = Some(position);
    }

    fn select_socket(&mut self, offset: isize) {
        if !self.is_socket_table() {
            return;
        }
        self.reconcile_socket_selection();
        if self.displayed_socket_snapshot.is_none() {
            return;
        }
        if self.socket_order.shown_count() == 0 {
            return;
        }
        let current = self.selected_socket_ordinal.unwrap_or(0);
        let position = if offset < 0 {
            current.saturating_sub(offset.unsigned_abs())
        } else {
            current
                .saturating_add(offset as usize)
                .min(self.socket_order.shown_count().saturating_sub(1))
        };
        self.selected_socket_key = self
            .socket_order
            .socket(position)
            .map(|socket| socket.row_key().clone());
        self.selected_socket_ordinal = Some(position);
        self.ensure_selected_socket_visible();
    }

    fn select_interface_layer(&mut self, offset: isize) {
        if !self.is_interface_detail() {
            return;
        }
        let current = super::dashboard::INTERFACE_BLOCK_KINDS
            .iter()
            .position(|kind| *kind == self.selected_interface_layer)
            .unwrap_or(0);
        let position = if offset < 0 {
            current.saturating_sub(offset.unsigned_abs())
        } else {
            current.saturating_add(offset as usize).min(
                super::dashboard::INTERFACE_BLOCK_KINDS
                    .len()
                    .saturating_sub(1),
            )
        };
        self.selected_interface_layer = super::dashboard::INTERFACE_BLOCK_KINDS[position];
        self.ensure_selected_interface_layer_visible();
    }

    fn select_first_socket(&mut self) {
        if !self.is_socket_table() {
            return;
        }
        let Some(socket) = self.socket_order.socket(0) else {
            return;
        };
        self.selected_socket_key = Some(socket.row_key().clone());
        self.selected_socket_ordinal = Some(0);
        self.ensure_selected_socket_visible();
    }

    fn ensure_selected_socket_visible(&mut self) {
        if !self.is_socket_table() {
            return;
        }
        let Some(snapshot) = self.socket_snapshot() else {
            self.clamp_row_offset();
            return;
        };
        self.row_offset = super::socket::viewport(
            snapshot,
            &self.socket_order,
            self.viewport_width,
            self.viewport_rows,
            self.row_offset,
        )
        .reveal(self.selected_socket_ordinal);
        self.clamp_row_offset();
    }

    fn connection_page_size(&self) -> usize {
        if self.is_conntrack_list() {
            self.conntrack_view
                .viewport(self.viewport_width, self.viewport_rows, self.row_offset)
                .capacity
                .max(1)
        } else {
            self.socket_snapshot().map_or(1, |snapshot| {
                super::socket::viewport(
                    snapshot,
                    &self.socket_order,
                    self.viewport_width,
                    self.viewport_rows,
                    self.row_offset,
                )
                .capacity
                .max(1)
            })
        }
    }

    fn selected_interface_layer_row_span(&self) -> Option<std::ops::Range<usize>> {
        if !self.is_interface_detail() {
            return None;
        }
        super::dashboard::interface_layer_row_span(
            self.snapshot()?,
            self.detail_interface()?,
            self.selected_interface_layer,
            super::dashboard::DetailDisplayOptions::new(self.time_view, self.detail_metrics_mode),
            self.viewport_width,
        )
    }

    fn ensure_selected_interface_layer_visible(&mut self) {
        let Some(span) = self.selected_interface_layer_row_span() else {
            self.clamp_row_offset();
            return;
        };
        if span.len() <= self.viewport_rows {
            if span.start < self.row_offset {
                self.row_offset = span.start;
            } else if span.end > self.row_offset.saturating_add(self.viewport_rows) {
                self.row_offset = span.end.saturating_sub(self.viewport_rows);
            }
        } else if span.start < self.row_offset {
            self.row_offset = span.start;
        } else if span.start >= self.row_offset.saturating_add(self.viewport_rows) {
            self.row_offset = span
                .start
                .saturating_add(1)
                .saturating_sub(self.viewport_rows);
        }
        self.clamp_row_offset();
    }

    fn select_overview_item(&mut self, offset: isize) {
        if self.section != MonitorSection::Overview || self.dashboard_mode != DashboardMode::Summary
        {
            return;
        }
        let interfaces = self.ordered_interfaces();
        let layer_count = workspace::LAYERS.len();
        let current_index = match self.overview_selection {
            OverviewSelection::Layer(kind) => workspace::LAYERS
                .iter()
                .position(|candidate| *candidate == kind)
                .unwrap_or(0),
            OverviewSelection::Interface => self
                .selected_interface
                .as_ref()
                .and_then(|selected| interfaces.iter().position(|identity| identity == selected))
                .or(self.selected_interface_ordinal)
                .map_or(layer_count.saturating_sub(1), |index| {
                    layer_count.saturating_add(index.min(interfaces.len().saturating_sub(1)))
                }),
        };
        let last_index = layer_count
            .saturating_add(interfaces.len())
            .saturating_sub(1);
        let next_index = if offset < 0 {
            current_index.saturating_sub(offset.unsigned_abs())
        } else {
            current_index
                .saturating_add(offset as usize)
                .min(last_index)
        };
        if next_index < layer_count {
            self.overview_selection = OverviewSelection::Layer(workspace::LAYERS[next_index]);
        } else {
            let interface_index = next_index.saturating_sub(layer_count);
            let Some(identity) = interfaces.get(interface_index) else {
                return;
            };
            self.overview_selection = OverviewSelection::Interface;
            self.selected_interface = Some(identity.clone());
            self.selected_interface_ordinal = Some(interface_index);
        }
        self.ensure_selected_overview_item_visible();
    }

    fn ordered_interfaces(&self) -> Vec<InterfaceIdentity> {
        self.interface_inventory.clone()
    }

    pub(super) fn interface_inventory(&self) -> &[InterfaceIdentity] {
        &self.interface_inventory
    }

    pub(super) fn grouped_section(&self) -> Option<&GroupedSection> {
        let snapshot = self.snapshot()?;
        let section = self.section.collection_section()?;
        if !is_interface_grouped(section) {
            return None;
        }
        Some(self.grouped_section.get_or_init(|| {
            group_section(
                snapshot,
                section,
                self.interface_anchor(),
                self.interface_name_alias(),
            )
        }))
    }

    fn replace_displayed_snapshot(&mut self, snapshot: Option<Arc<MonitorSnapshot>>) {
        self.hardirq_table.take();
        let reused = match (
            self.grouped_section.get_mut(),
            self.displayed_snapshot.as_deref(),
            snapshot.as_deref(),
        ) {
            (Some(grouped), Some(previous), Some(next)) => {
                grouped.refresh(previous, next, self.interface_anchor.is_some())
            }
            _ => false,
        };
        if !reused {
            self.grouped_section.take();
        }
        self.displayed_snapshot = snapshot;
        self.softirq_section.take();
        self.summary.take();
        self.overview_layout.get_mut().take();
        self.netdev_table.take();
        self.tc_table.take();
    }

    pub(super) fn softirq_section(&self) -> Option<&super::dashboard::SoftirqSection> {
        let snapshot = self.snapshot()?;
        Some(self.softirq_section.get_or_init(|| {
            super::dashboard::SoftirqSection::new_with_options(
                snapshot,
                self.viewport_width,
                super::dashboard::DetailDisplayOptions::new(
                    self.time_view,
                    self.softirq_metrics_mode,
                ),
                self.softirq_sort,
                self.softirq_descending,
            )
        }))
    }

    fn reconcile_softirq_sort(&mut self) {
        if !self.is_softirq_view() {
            return;
        }
        let Some(model) = self.softirq_section() else {
            return;
        };
        let (sort, descending) = (model.effective_sort(), model.effective_descending());
        self.softirq_sort = sort;
        self.softirq_descending = descending;
    }

    fn softirq_page_size(&self) -> usize {
        self.softirq_section().map_or(1, |model| {
            model
                .viewport(self.viewport_rows, self.row_offset)
                .capacity
                .max(1)
        })
    }

    fn refresh_interface_inventory(&mut self) {
        if !matches!(
            self.section,
            MonitorSection::Overview | MonitorSection::Nic | MonitorSection::Netdevice
        ) {
            return;
        }
        self.interface_inventory = self.snapshot().map_or_else(Vec::new, |snapshot| {
            super::dashboard::ordered_interface_identities_with_down(
                snapshot,
                self.interface_anchor(),
                self.interface_name_alias(),
                true,
            )
        });
        if let Some(table) = self.netdev_table() {
            self.interface_inventory =
                table.ordered_interfaces(self.netdev_sort, self.netdev_descending);
        }
    }

    fn reconcile_interface_selection(&mut self) {
        if !self.is_netdev_table()
            && (self.section != MonitorSection::Overview
                || self.dashboard_mode != DashboardMode::Summary
                || self.overview_selection != OverviewSelection::Interface)
        {
            return;
        }
        let interfaces = self.ordered_interfaces();
        if let Some(position) = self
            .selected_interface
            .as_ref()
            .and_then(|selected| interfaces.iter().position(|identity| identity == selected))
        {
            self.selected_interface_ordinal = Some(position);
            return;
        }
        if interfaces.is_empty() {
            self.selected_interface = None;
            self.overview_selection = OverviewSelection::Layer(
                *workspace::LAYERS
                    .last()
                    .expect("overview has global layer targets"),
            );
            return;
        }
        let index = self
            .selected_interface_ordinal
            .unwrap_or(0)
            .min(interfaces.len().saturating_sub(1));
        self.selected_interface = interfaces.get(index).cloned();
        self.selected_interface_ordinal = Some(index);
    }

    fn selected_overview_interface_ordinal(&self) -> Option<usize> {
        (self.section == MonitorSection::Overview
            && self.dashboard_mode == DashboardMode::Summary
            && self.overview_selection == OverviewSelection::Interface)
            .then_some(self.selected_interface_ordinal)
            .flatten()
    }

    fn selected_overview_row_span(&self) -> Option<std::ops::Range<usize>> {
        match self.overview_selection {
            OverviewSelection::Layer(kind) => self.workspace_layer_span(kind),
            OverviewSelection::Interface => self.workspace_interface_span(),
        }
    }

    fn selected_overview_item_is_fully_visible(&self) -> bool {
        self.selected_overview_row_span().is_some_and(|span| {
            span.start >= self.row_offset
                && span.end <= self.row_offset.saturating_add(self.viewport_rows)
        })
    }

    fn ensure_selected_overview_item_visible(&mut self) {
        if self.overview_selection == OverviewSelection::Interface {
            self.ensure_netdev_selection_visible();
            return;
        }
        let Some(span) = self.selected_overview_row_span() else {
            self.clamp_row_offset();
            return;
        };
        if span.start < self.row_offset {
            self.row_offset = span.start;
        } else if span.end > self.row_offset.saturating_add(self.viewport_rows) {
            self.row_offset = span.end.saturating_sub(self.viewport_rows);
        }
        self.clamp_row_offset();
    }

    fn scroll_down(&mut self, amount: usize) {
        if self.section == MonitorSection::Overview && self.dashboard_mode == DashboardMode::Summary
        {
            let prefix = self.summary_lines(self.viewport_width).len();
            let limit = if self.row_offset < prefix {
                prefix
            } else {
                self.max_row_offset()
            };
            let amount = if self.row_offset >= prefix {
                amount.min(
                    NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16)
                        .max(1),
                )
            } else {
                amount
            };
            self.row_offset = self
                .row_offset
                .saturating_add(amount)
                .min(limit)
                .min(self.max_row_offset());
            return;
        }
        self.row_offset = self
            .row_offset
            .saturating_add(amount)
            .min(self.max_row_offset());
    }

    fn scroll_up(&mut self, amount: usize) {
        if self.section == MonitorSection::Overview && self.dashboard_mode == DashboardMode::Summary
        {
            let prefix = self.summary_lines(self.viewport_width).len();
            if self.row_offset > prefix {
                let capacity =
                    NetdevTable::visible_capacity(self.viewport_width, self.viewport_rows as u16)
                        .max(1);
                self.row_offset = self
                    .row_offset
                    .saturating_sub(amount.min(capacity))
                    .max(prefix);
                return;
            }
        }
        self.row_offset = self.row_offset.saturating_sub(amount);
    }

    fn clamp_row_offset(&mut self) {
        self.reconcile_softirq_sort();
        self.row_offset = self.row_offset.min(self.max_row_offset());
    }

    fn clamp_network_route_content(&mut self) {
        if !self.is_network_route() {
            return;
        }
        let rows = super::network_route::row_count(
            &self.network_route_view,
            self.displayed_network_route_snapshot.as_deref(),
            self.displayed_snapshot.as_deref(),
            self.time_view,
            self.detail_metrics_mode,
            self.viewport_width,
        );
        self.network_route_view.clamp_content_rows(rows);
    }

    fn reconcile_netfilter_content(&mut self) {
        if !self.is_netfilter_view() {
            return;
        }
        let snapshot = self.displayed_snapshot.clone();
        self.netfilter_view.reconcile(snapshot.as_deref());
        let rows = super::netfilter::row_count(
            &self.netfilter_view,
            snapshot.as_deref(),
            self.time_view,
            super::dashboard::DetailDisplayOptions::new(self.time_view, self.detail_metrics_mode),
            self.viewport_width,
        );
        self.netfilter_view.clamp_content_rows(rows);
    }

    fn max_row_offset(&self) -> usize {
        if self.section == MonitorSection::Hardirq {
            if let Some(table) = self.hardirq_table() {
                return table
                    .viewport(self.viewport_rows, self.row_offset)
                    .max_offset;
            }
        }
        if self.is_softirq_view() {
            return self.softirq_section().map_or(0, |model| {
                model
                    .viewport(self.viewport_rows, self.row_offset)
                    .max_offset
            });
        }
        if self.section == MonitorSection::Overview && self.dashboard_mode == DashboardMode::Summary
        {
            return self.workspace_rows().saturating_sub(1);
        }
        if matches!(self.page(), Page::Transport | Page::Network) {
            let layer = if self.page() == Page::Transport {
                Layer::Transport
            } else {
                Layer::Network
            };
            return self.summary().map_or(0, |summary| {
                summary
                    .detail_lines(layer, self.viewport_width)
                    .len()
                    .saturating_sub(self.viewport_rows)
            });
        }
        if self.is_socket_detail() {
            return self
                .socket_detail()
                .map_or(1, |detail| {
                    super::socket_detail::row_count(
                        detail,
                        self.detail_metrics_mode,
                        self.viewport_width,
                    )
                })
                .saturating_sub(self.viewport_rows);
        }
        if self.is_socket_table() {
            return self.socket_snapshot().map_or(0, |snapshot| {
                super::socket::viewport(
                    snapshot,
                    &self.socket_order,
                    self.viewport_width,
                    self.viewport_rows,
                    self.row_offset,
                )
                .max_offset
            });
        }
        if self.is_conntrack_list() {
            return self
                .conntrack_view
                .viewport(self.viewport_width, self.viewport_rows, self.row_offset)
                .max_offset;
        }
        if self.is_conntrack_flows() {
            return self
                .conntrack_view
                .row_count(self.viewport_width)
                .saturating_sub(self.viewport_rows);
        }
        if let (Some(snapshot), Some(kind)) = (self.snapshot(), self.detail_layer()) {
            return super::dashboard::global_layer_detail_row_count(
                snapshot,
                kind,
                super::dashboard::DetailDisplayOptions::new(
                    self.time_view,
                    self.detail_metrics_mode,
                ),
                self.viewport_width,
            )
            .saturating_sub(self.viewport_rows);
        }
        if let (Some(snapshot), Some(identity), Some(layer)) = (
            self.snapshot(),
            self.detail_interface(),
            self.detail_interface_layer(),
        ) {
            return super::dashboard::interface_layer_detail_row_count(
                snapshot,
                identity,
                layer,
                super::dashboard::DetailDisplayOptions::new(
                    self.time_view,
                    self.detail_metrics_mode,
                ),
                self.viewport_width,
            )
            .saturating_sub(self.viewport_rows);
        }
        if self.is_interface_detail() {
            let (Some(snapshot), Some(identity)) = (self.snapshot(), self.detail_interface())
            else {
                return 0;
            };
            return super::dashboard::interface_detail_row_count(
                snapshot,
                identity,
                super::dashboard::DetailDisplayOptions::new(
                    self.time_view,
                    self.detail_metrics_mode,
                ),
                self.viewport_width,
            )
            .saturating_sub(self.viewport_rows);
        }
        let row_count = match self.section {
            MonitorSection::Overview => {
                super::dashboard::overview_row_count(self.interface_inventory.len())
            }
            section => {
                let Some(snapshot) = self.snapshot() else {
                    return 0;
                };
                match section {
                    MonitorSection::Providers => snapshot.providers().len(),
                    MonitorSection::Softirq => self
                        .softirq_section()
                        .expect("SoftIRQ snapshot")
                        .row_count(),
                    section => section
                        .collection_section()
                        .map_or(0, |collection_section| {
                            if is_interface_grouped(collection_section) {
                                grouped_row_count(self.grouped_section().expect("grouped section"))
                            } else {
                                snapshot
                                    .series()
                                    .iter()
                                    .filter(|row| {
                                        series_matches_anchor(
                                            row.labels(),
                                            self.interface_anchor(),
                                            self.interface_name_alias(),
                                        ) && row.metric().descriptor().is_some_and(|metric| {
                                            metric.primary_section == collection_section
                                        })
                                    })
                                    .count()
                            }
                        }),
                }
            }
        };
        row_count.saturating_sub(self.viewport_rows)
    }
}

pub(super) fn series_matches_anchor(
    labels: &MetricLabels,
    anchor: Option<&InterfaceViewAnchor>,
    interface_name_alias: Option<&str>,
) -> bool {
    super::presentation::labels_match_anchor(labels, anchor, interface_name_alias)
}

#[cfg(test)]
pub(in crate::tui) mod tests {
    use super::*;

    #[test]
    fn every_page_selects_its_collection_dependencies() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        for page in Page::ALL {
            app.select_page(page);
            let expected = match page {
                Page::Overview => MonitorSection::Overview.into(),
                Page::Netdev => MonitorSection::Nic.into(),
                Page::Tc => MonitorSection::Tc.into(),
                Page::Softirq => MonitorSection::Softirq.into(),
                Page::Hardirq => MonitorSection::Hardirq.into(),
                Page::Socket => MonitorSection::Socket.into(),
                Page::Transport => CollectionFocus::Transport,
                Page::Network => CollectionFocus::Network,
                Page::Conntrack => CollectionFocus::ConntrackFlows,
                Page::Route => CollectionFocus::Route,
                Page::Providers => MonitorSection::Providers.into(),
            };
            assert_eq!(app.collection_focus(), expected, "{page:?}");
        }
    }

    #[test]
    fn collection_focus_follows_overview_drilldowns_and_returns_to_background() {
        use crate::monitor::dashboard::{ExecutionContext, PacketStage};
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        for (kind, section) in [
            (
                BlockKind::PacketStage(PacketStage::TrafficControl),
                MonitorSection::Tc,
            ),
            (
                BlockKind::PacketStage(PacketStage::NicPhy),
                MonitorSection::Nic,
            ),
            (
                BlockKind::PacketStage(PacketStage::DriverNapi),
                MonitorSection::Nic,
            ),
            (
                BlockKind::PacketStage(PacketStage::NetfilterConntrack),
                MonitorSection::Netfilter,
            ),
            (
                BlockKind::ExecutionContext(ExecutionContext::Hardirq),
                MonitorSection::Hardirq,
            ),
        ] {
            app.overview_selection = OverviewSelection::Layer(kind);
            app.dashboard_mode = DashboardMode::Summary;
            assert_eq!(app.collection_focus(), MonitorSection::Overview.into());
            app.dashboard_mode = DashboardMode::LayerDetail;
            assert_eq!(app.collection_focus(), section.into());
            app.selected_interface_layer = kind;
            app.dashboard_mode = DashboardMode::InterfaceLayerDetail;
            if section == MonitorSection::Netfilter {
                assert_eq!(app.collection_focus(), CollectionFocus::InterfaceDetail);
            } else {
                assert_eq!(
                    app.collection_focus(),
                    CollectionFocus::InterfaceLayer(section)
                );
                for provider in [
                    "linux.rtnetlink.link_stats",
                    "linux.sysfs.net.nic",
                    "linux.ethtool.link_text",
                ] {
                    assert!(app.collection_focus().allows_provider(provider));
                }
            }
            app.dashboard_mode = DashboardMode::InterfaceDetail;
            assert_eq!(app.collection_focus(), CollectionFocus::InterfaceDetail);
        }
        let direct = App::new(MonitorSection::Nic, Duration::from_secs(1));
        assert_eq!(direct.collection_focus(), MonitorSection::Nic.into());
        let legacy = App::new(MonitorSection::Netdevice, Duration::from_secs(1));
        assert_eq!(legacy.collection_focus(), MonitorSection::Nic.into());
    }

    fn interface_sample(
        elapsed: Duration,
        interfaces: &[(&str, u32, &str)],
    ) -> crate::monitor::ProviderSample {
        let readings = interfaces
            .iter()
            .map(|(name, ifindex, kind)| {
                crate::monitor::SampleReading::observed(
                    crate::monitor::MetricId::new("linux.nic.interface_kind").unwrap(),
                    crate::monitor::MetricLabels::new([
                        (crate::monitor::MetricLabel::Interface, (*name).to_owned()),
                        (crate::monitor::MetricLabel::Ifindex, ifindex.to_string()),
                    ])
                    .unwrap(),
                    crate::monitor::MetricReading::State(
                        crate::monitor::StateValue::new(*kind).unwrap(),
                    ),
                )
            })
            .collect();
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.sysfs.net.nic").unwrap(),
            elapsed,
            Duration::from_millis(1),
            crate::monitor::ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    pub(in crate::tui) fn interface_snapshot(
        sequence: u64,
        interfaces: &[(&str, u32, &str)],
    ) -> Arc<MonitorSnapshot> {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(sequence, interval).unwrap();
        (1..=sequence)
            .map(|at| {
                let elapsed = Duration::from_secs(at);
                let sample = interface_sample(elapsed, interfaces);
                engine.ingest(elapsed, vec![sample], None).unwrap()
            })
            .last()
            .expect("interface snapshot has at least one sample")
    }

    fn interface_sample_with_link_states(
        elapsed: Duration,
        interfaces: &[(&str, u32, &str, &str)],
    ) -> crate::monitor::ProviderSample {
        let readings = interfaces
            .iter()
            .flat_map(|(name, ifindex, kind, link_state)| {
                let labels = crate::monitor::MetricLabels::new([
                    (crate::monitor::MetricLabel::Interface, (*name).to_owned()),
                    (crate::monitor::MetricLabel::Ifindex, ifindex.to_string()),
                ])
                .unwrap();
                [
                    crate::monitor::SampleReading::observed(
                        crate::monitor::MetricId::new("linux.nic.interface_kind").unwrap(),
                        labels.clone(),
                        crate::monitor::MetricReading::State(
                            crate::monitor::StateValue::new(*kind).unwrap(),
                        ),
                    ),
                    crate::monitor::SampleReading::observed(
                        crate::monitor::MetricId::new("linux.nic.link_state").unwrap(),
                        labels,
                        crate::monitor::MetricReading::State(
                            crate::monitor::StateValue::new(*link_state).unwrap(),
                        ),
                    ),
                ]
            })
            .collect();
        crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.sysfs.net.nic").unwrap(),
            elapsed,
            Duration::from_millis(1),
            crate::monitor::ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    fn interface_snapshot_with_link_states(
        interfaces: &[(&str, u32, &str, &str)],
    ) -> Arc<MonitorSnapshot> {
        let elapsed = Duration::from_secs(1);
        let sample = interface_sample_with_link_states(elapsed, interfaces);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        engine.ingest(elapsed, vec![sample], None).unwrap()
    }

    fn socket_section_snapshot() -> Arc<MonitorSnapshot> {
        let elapsed = Duration::from_secs(1);
        let readings = [
            "linux.socket.used",
            "linux.socket.tcp.in_use",
            "linux.socket.tcp.orphaned",
            "linux.socket.tcp.time_wait",
            "linux.socket.tcp.allocated",
            "linux.socket.tcp.memory_pages",
            "linux.socket.udp.in_use",
            "linux.socket.udp.memory_pages",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, metric)| {
            crate::monitor::SampleReading::observed(
                crate::monitor::MetricId::new(metric).unwrap(),
                crate::monitor::MetricLabels::default(),
                crate::monitor::MetricReading::Gauge((index + 1) as u64),
            )
        })
        .collect();
        let sample = crate::monitor::ProviderSample::new(
            crate::monitor::ProviderId::new("linux.proc.net.sockstat").unwrap(),
            elapsed,
            Duration::from_millis(1),
            crate::monitor::ProviderHealth::Fresh,
            readings,
        )
        .unwrap();
        let mut engine = crate::monitor::session::MonitorEngine::new(1, elapsed).unwrap();
        engine.ingest(elapsed, vec![sample], None).unwrap()
    }

    fn select_first_interface(app: &mut App) {
        for _ in 0..workspace::LAYERS.len() {
            app.update(Action::SelectNextOverviewItem);
        }
        assert!(app.selected_interface().is_some());
    }

    fn open_conntrack_detail(app: &mut App) {
        while app.selected_layer()
            != Some(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::NetfilterConntrack,
            ))
        {
            app.update(Action::SelectNextOverviewItem);
        }
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.is_conntrack_flows());
    }

    fn open_socket_detail(app: &mut App) {
        assert_eq!(
            app.selected_layer(),
            Some(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::SocketApplication
            ))
        );
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.can_open_socket_table());
    }

    fn assert_selected_overview_item_is_visible(app: &App) {
        let span = app.selected_overview_row_span().unwrap();
        assert!(span.start >= app.row_offset, "{span:?}");
        assert!(
            span.end <= app.row_offset.saturating_add(app.viewport_rows),
            "{span:?} offset={} rows={}",
            app.row_offset,
            app.viewport_rows
        );
    }

    #[test]
    fn overview_navigation_moves_through_layers_then_interfaces_without_wrapping() {
        let snapshot =
            interface_snapshot(1, &[("eth20", 20, "physical"), ("eth10", 10, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(snapshot);

        let first_layer = workspace::LAYERS[0];
        let last_layer = *workspace::LAYERS.last().unwrap();
        assert_eq!(app.selected_layer(), Some(first_layer));
        app.update(Action::SelectPreviousOverviewItem);
        assert_eq!(app.selected_layer(), Some(first_layer));

        for _ in 1..workspace::LAYERS.len() {
            app.update(Action::SelectNextOverviewItem);
        }
        assert_eq!(app.selected_layer(), Some(last_layer));
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth20");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth20");
    }

    #[test]
    fn command_mode_switches_sections_and_keeps_q_as_input() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::EnterCommand);
        for character in "section softirq".chars() {
            assert_eq!(app.update(Action::Insert(character)), Effect::Redraw);
        }
        assert_eq!(app.update(Action::SubmitCommand), Effect::Redraw);
        assert_eq!(app.section(), MonitorSection::Softirq);

        app.update(Action::EnterCommand);
        assert_eq!(app.update(Action::Insert('q')), Effect::Redraw);
        assert_eq!(app.update(Action::SubmitCommand), Effect::Exit);
    }

    #[test]
    fn removed_navigation_and_history_commands_report_an_error() {
        for command in ["next", "prev", "previous", "history"] {
            let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
            app.update(Action::EnterCommand);
            for character in command.chars() {
                app.update(Action::Insert(character));
            }

            assert_eq!(app.update(Action::SubmitCommand), Effect::Redraw);
            assert_eq!(app.section(), MonitorSection::Overview);
            assert_eq!(
                app.command_error(),
                Some(format!("unknown command: {command}").as_str())
            );
        }
    }

    #[test]
    fn pause_and_time_views_are_display_only_state() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::TogglePause);
        app.update(Action::ToggleTimeView);
        assert!(app.paused());
        assert_eq!(app.time_view(), TimeView::SinceBaseline);
    }

    #[test]
    fn grouped_pages_reuse_layout_and_follow_dynamic_visibility() {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let mut app = App::new(MonitorSection::Nic, interval);
        let mut rows = None;
        for (at, state) in [(1, "up"), (2, "unknown"), (3, "down"), (4, "up")] {
            let elapsed = Duration::from_secs(at);
            let snapshot = engine
                .ingest(
                    elapsed,
                    vec![interface_sample_with_link_states(
                        elapsed,
                        &[("eth0", 2, "physical", state)],
                    )],
                    None,
                )
                .unwrap();
            app.apply_snapshot(snapshot);
            let grouped = app.grouped_section().unwrap();
            assert_eq!(
                *grouped,
                group_section(
                    app.snapshot().unwrap(),
                    crate::monitor::CollectionSection::Nic,
                    None,
                    None
                )
            );
            if at == 1 {
                rows = Some(grouped.interfaces[0].rows.as_ptr());
            } else if at == 2 {
                assert_eq!(Some(grouped.interfaces[0].rows.as_ptr()), rows);
            }
            assert_eq!(grouped.interfaces.is_empty(), state == "down");
        }
        let rows = app.grouped_section().unwrap().interfaces[0].rows.as_ptr();
        app.update(Action::TogglePause);
        let at = Duration::from_secs(5);
        let next = engine
            .ingest(
                at,
                vec![interface_sample_with_link_states(
                    at,
                    &[("eth0", 2, "physical", "unknown")],
                )],
                None,
            )
            .unwrap();
        app.apply_snapshot(next);
        assert_eq!(app.snapshot().unwrap().sequence(), 4);
        app.update(Action::TogglePause);
        assert_eq!(app.snapshot().unwrap().sequence(), 5);
        assert_eq!(
            app.grouped_section().unwrap().interfaces[0].rows.as_ptr(),
            rows
        );
        app = app.with_interface_anchor(Some(InterfaceViewAnchor::named("missing").unwrap()));
        assert!(app.grouped_section().unwrap().interfaces.is_empty());
        app = app.with_interface_anchor(None);
        assert_eq!(app.grouped_section().unwrap().interfaces.len(), 1);
    }

    #[test]
    fn grouped_pages_follow_pause_resume_section_and_anchor_changes() {
        let first = interface_snapshot(1, &[("eth0", 2, "physical"), ("eth1", 3, "virtual")]);
        let next = interface_snapshot(2, &[("eth9", 9, "physical")]);
        let mut app = App::new(MonitorSection::Nic, Duration::from_secs(1));
        app.apply_snapshot(first);
        assert_eq!(app.grouped_section().unwrap().interfaces.len(), 2);
        app.update(Action::TogglePause);
        app.apply_snapshot(next);
        assert_eq!(
            app.grouped_section().unwrap().interfaces[0].key.name(),
            "eth0"
        );
        app.update(Action::TogglePause);
        let grouped = app.grouped_section().unwrap();
        assert_eq!(grouped.interfaces.len(), 1);
        assert_eq!(grouped.interfaces[0].key.name(), "eth9");
        app.select_section(MonitorSection::Netdevice);
        assert!(app.grouped_section().unwrap().interfaces.is_empty());
        app.select_section(MonitorSection::Nic);
        assert_eq!(app.grouped_section().unwrap().interfaces.len(), 1);
        app = app.with_interface_anchor(Some(InterfaceViewAnchor::named("eth0").unwrap()));
        assert!(app.grouped_section().unwrap().interfaces.is_empty());
        app = app.with_interface_anchor(Some(InterfaceViewAnchor::indexed(2).unwrap()));
        app = app.with_interface_name_alias(Some("eth9".to_owned()));
        assert_eq!(
            app.grouped_section().unwrap().interfaces[0].key.name(),
            "eth9"
        );
    }

    #[test]
    fn pause_freezes_network_route_display_while_collection_advances() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_network_route_snapshot(
            crate::monitor::network_route::synthetic_network_route_snapshot(1),
        );
        assert_eq!(app.network_route_snapshot().unwrap().sequence(), 1);

        app.update(Action::TogglePause);
        app.apply_network_route_snapshot(
            crate::monitor::network_route::synthetic_network_route_snapshot(2),
        );
        assert_eq!(app.network_route_snapshot().unwrap().sequence(), 1);
        assert_eq!(
            app.latest_network_route_snapshot
                .as_deref()
                .unwrap()
                .sequence(),
            2
        );

        app.update(Action::TogglePause);
        assert_eq!(app.network_route_snapshot().unwrap().sequence(), 2);
    }

    #[test]
    fn partial_provider_marks_the_session_degraded() {
        let elapsed = Duration::from_secs(1);
        let warning = crate::monitor::MonitorError::new(
            crate::monitor::MonitorErrorCode::Timeout,
            "one interface timed out",
        )
        .unwrap();
        let provider = crate::monitor::ProviderSnapshot::new(
            crate::monitor::ProviderId::new("linux.ethtool.text").unwrap(),
            crate::monitor::ProviderHealth::Partial { warning },
            elapsed,
            Duration::ZERO,
            0,
        )
        .unwrap();
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            1,
            elapsed,
            None,
            vec![provider],
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed);

        app.apply_snapshot(Arc::new(snapshot));

        assert_eq!(app.status(), SessionStatus::Degraded);
    }

    #[test]
    fn quit_action_exits_while_command_mode_is_active() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::EnterCommand);

        assert_eq!(app.update(Action::Quit), Effect::Exit);
    }

    #[test]
    fn row_scroll_is_bounded_and_resets_when_the_section_changes() {
        let elapsed = Duration::from_secs(1);
        let providers = (0..3)
            .map(|index| {
                crate::monitor::ProviderSnapshot::new(
                    crate::monitor::ProviderId::new(format!("test.provider.{index}")).unwrap(),
                    crate::monitor::ProviderHealth::Fresh,
                    elapsed,
                    Duration::ZERO,
                    0,
                )
                .unwrap()
            })
            .collect();
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            1,
            elapsed,
            None,
            providers,
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let mut app = App::new(MonitorSection::Providers, elapsed);
        app.apply_snapshot(Arc::new(snapshot));
        app.update(Action::ScrollUp);
        assert_eq!(app.row_offset(), 0);
        app.update(Action::PageDown);
        app.update(Action::ScrollDown);
        assert_eq!(app.row_offset(), 2);
        app.update(Action::PageUp);
        assert_eq!(app.row_offset(), 0);

        app.select_section(MonitorSection::Softirq);
        assert_eq!(app.row_offset(), 0);
    }

    #[test]
    fn empty_overview_scrolls_to_the_last_dashboard_physical_row() {
        let elapsed = Duration::from_secs(1);
        let mut app = App::new(MonitorSection::Overview, elapsed);
        app.set_viewport_size(160, 15);
        app.update(Action::PageDown);
        assert_eq!(app.row_offset(), app.max_row_offset().min(10));

        let snapshot = MonitorSnapshot::new(
            1,
            1,
            1,
            elapsed,
            None,
            Vec::new(),
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        app.apply_snapshot(Arc::new(snapshot));
        app.update(Action::PageDown);
        app.update(Action::PageDown);
        app.update(Action::PageDown);

        assert_eq!(app.row_offset(), app.max_row_offset());

        app.set_viewport_size(160, 40);
        assert!(app.row_offset() <= app.max_row_offset());
    }

    #[test]
    fn overview_page_scroll_survives_redraw_and_unchanged_inventory_refresh() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 8);
        app.apply_snapshot(interface_snapshot(1, &[("eth0", 2, "physical")]));
        app.update(Action::PageDown);
        assert_eq!(app.row_offset(), 10);

        app.set_viewport_size(160, 8);
        assert_eq!(app.row_offset(), 10);

        app.set_viewport_size(160, 7);
        assert_eq!(app.row_offset(), 10);

        app.apply_snapshot(interface_snapshot(2, &[("eth0", 2, "physical")]));
        assert_eq!(app.row_offset(), 10);
    }

    #[test]
    fn returning_from_another_section_refreshes_the_interface_inventory() {
        let mut app = App::new(MonitorSection::Nic, Duration::from_secs(1));
        app.apply_snapshot(interface_snapshot(1, &[("eth0", 2, "physical")]));
        app.update(Action::Back);
        assert_eq!(app.ordered_interfaces()[0].name(), "eth0");
        app.select_section(MonitorSection::Nic);
        app.apply_snapshot(interface_snapshot(2, &[("eth1", 3, "physical")]));
        app.select_section(MonitorSection::Overview);
        assert_eq!(app.ordered_interfaces()[0].name(), "eth1");
    }

    #[test]
    fn interfaces_follow_the_selected_ifindex_sort() {
        let snapshot = interface_snapshot(
            1,
            &[
                ("lo", 1, "virtual"),
                ("eth20", 20, "physical"),
                ("br0", 2, "virtual"),
                ("eth10", 10, "physical"),
            ],
        );
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 15);
        app.apply_snapshot(snapshot);

        select_first_interface(&mut app);
        assert_eq!(app.selected_interface().unwrap().name(), "lo");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "br0");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth20");
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth20");
    }

    #[test]
    fn overview_keeps_down_interfaces_and_respects_explicit_anchors() {
        let snapshot = interface_snapshot_with_link_states(&[
            ("eth0", 2, "physical", "up"),
            ("eth1", 3, "physical", "down"),
            ("bond0", 4, "virtual", "lower_layer_down"),
        ]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(Arc::clone(&snapshot));

        assert_eq!(
            app.ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["eth0", "eth1", "bond0"]
        );

        let mut anchored = App::new(MonitorSection::Overview, Duration::from_secs(1))
            .with_interface_anchor(Some(InterfaceViewAnchor::named("eth1").unwrap()));
        anchored.apply_snapshot(Arc::clone(&snapshot));
        assert_eq!(
            anchored
                .ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["eth1"]
        );

        let mut indexed = App::new(MonitorSection::Overview, Duration::from_secs(1))
            .with_interface_anchor(Some(InterfaceViewAnchor::indexed(3).unwrap()));
        indexed.apply_snapshot(snapshot);
        assert_eq!(
            indexed
                .ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["eth1"]
        );
    }

    #[test]
    fn overview_and_interface_show_down_vfs_on_the_same_paused_snapshot() {
        let snapshot = interface_snapshot_with_link_states(&[
            ("xnic0", 6, "physical", "up"),
            ("xnic0v10", 20, "physical", "down"),
            ("br-down", 30, "virtual", "down"),
        ]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 76);
        app.apply_snapshot(Arc::clone(&snapshot));
        assert_eq!(app.ordered_interfaces().len(), 3);
        assert_eq!(
            app.netdev_table()
                .unwrap()
                .ordered_interfaces(NetdevSort::Ifindex, false)
                .len(),
            3
        );
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 80)).unwrap();
        terminal
            .draw(|frame| super::super::view::render(frame, &app))
            .unwrap();
        let rendered = terminal.backend().to_string();
        assert!(rendered.contains("xnic0v10"), "{rendered}");
        assert!(rendered.contains("down"), "{rendered}");
        app.update(Action::TogglePause);
        app.select_page(Page::Netdev);
        assert_eq!(
            app.ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["xnic0", "xnic0v10", "br-down"]
        );
        assert_eq!(
            app.netdev_table()
                .unwrap()
                .ordered_interfaces(NetdevSort::Ifindex, false)
                .len(),
            3
        );
        assert!(std::ptr::eq(app.snapshot().unwrap(), snapshot.as_ref()));
        app.update(Action::ScrollDown);
        assert_eq!(app.selected_interface().unwrap().name(), "xnic0v10");
        app.update(Action::OpenSelectedOverviewItem);
        assert!(app.is_interface_detail());
        app.refresh_interface_inventory();
        assert_eq!(app.ordered_interfaces().len(), 3);
        assert_eq!(app.detail_interface().unwrap().name(), "xnic0v10");
        app.update(Action::Back);
        assert!(app.is_netdev_table());
        assert_eq!(app.selected_interface().unwrap().name(), "xnic0v10");
        assert_eq!(app.ordered_interfaces().len(), 3);
        app.select_page(Page::Overview);
        assert_eq!(
            app.ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["xnic0", "xnic0v10", "br-down"]
        );
        assert_eq!(
            app.netdev_table()
                .unwrap()
                .ordered_interfaces(NetdevSort::Ifindex, false)
                .len(),
            3
        );
        app.select_section(MonitorSection::Netdevice);
        assert_eq!(app.ordered_interfaces().len(), 3);
    }

    #[test]
    fn interface_page_removes_vanished_vf_but_keeps_detail_identity_until_back() {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let snapshot = engine
            .ingest(
                interval,
                vec![interface_sample_with_link_states(
                    interval,
                    &[
                        ("xnic0", 6, "physical", "up"),
                        ("xnic0v10", 20, "physical", "down"),
                    ],
                )],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Nic, interval);
        app.set_viewport_size(160, 40);
        app.apply_snapshot(snapshot);
        assert_eq!(app.ordered_interfaces().len(), 2);
        app.update(Action::ScrollDown);
        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.detail_interface().unwrap().name(), "xnic0v10");
        let elapsed = Duration::from_secs(2);
        app.apply_snapshot(
            engine
                .ingest(
                    elapsed,
                    vec![interface_sample_with_link_states(
                        elapsed,
                        &[("xnic0", 6, "physical", "up")],
                    )],
                    None,
                )
                .unwrap(),
        );
        assert_eq!(app.ordered_interfaces().len(), 1);
        assert_eq!(app.detail_interface().unwrap().name(), "xnic0v10");
        app.update(Action::Back);
        assert_eq!(app.selected_interface().unwrap().name(), "xnic0");
    }

    #[test]
    fn overview_keeps_interface_selection_across_down_and_recovery() {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let up = engine
            .ingest(
                interval,
                vec![interface_sample_with_link_states(
                    interval,
                    &[("eth0", 2, "physical", "up")],
                )],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Overview, interval);
        app.apply_snapshot(up);
        select_first_interface(&mut app);
        app.update(Action::OpenSelectedOverviewItem);

        let down_at = Duration::from_secs(2);
        let down = engine
            .ingest(
                down_at,
                vec![interface_sample_with_link_states(
                    down_at,
                    &[("eth0", 2, "physical", "down")],
                )],
                None,
            )
            .unwrap();
        app.apply_snapshot(down);
        assert_eq!(app.detail_interface().unwrap().name(), "eth0");

        app.update(Action::Back);
        assert_eq!(app.selected_interface().unwrap().name(), "eth0");
        assert_eq!(app.overview_selection, OverviewSelection::Interface);

        let recovered_at = Duration::from_secs(3);
        let recovered = engine
            .ingest(
                recovered_at,
                vec![interface_sample_with_link_states(
                    recovered_at,
                    &[("eth0", 2, "physical", "up")],
                )],
                None,
            )
            .unwrap();
        app.apply_snapshot(recovered);
        assert_eq!(app.selected_interface().unwrap().name(), "eth0");
        assert_eq!(app.overview_selection, OverviewSelection::Interface);
    }

    #[test]
    fn refresh_keeps_a_moved_interface_selection_visible() {
        let initial = interface_snapshot(1, &[("eth10", 10, "physical")]);
        let inserted = interface_snapshot(
            2,
            &[
                ("eth1", 1, "physical"),
                ("eth2", 2, "physical"),
                ("eth3", 3, "physical"),
                ("eth4", 4, "physical"),
                ("eth5", 5, "physical"),
                ("eth10", 10, "physical"),
            ],
        );
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 8);
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        let initial_offset = app.row_offset();
        assert_selected_overview_item_is_visible(&app);

        app.apply_snapshot(inserted);

        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        assert!(app.row_offset() > initial_offset);
        assert_selected_overview_item_is_visible(&app);
    }

    #[test]
    fn viewport_shrink_keeps_the_selected_interface_visible() {
        let snapshot = interface_snapshot(
            1,
            &[
                ("eth1", 1, "physical"),
                ("eth2", 2, "physical"),
                ("eth3", 3, "physical"),
            ],
        );
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(snapshot);
        app.set_viewport_size(160, 80);
        select_first_interface(&mut app);
        app.update(Action::SelectNextOverviewItem);
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.row_offset(), 0);

        app.set_viewport_size(160, 8);

        assert_eq!(app.selected_interface().unwrap().name(), "eth3");
        assert!(app.row_offset() > 0);
        assert_selected_overview_item_is_visible(&app);
    }

    #[test]
    fn layer_detail_back_restores_overview_selection_and_scroll() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(interface_snapshot(1, &[]));
        app.set_viewport_size(60, 8);
        for _ in 0..2 {
            app.update(Action::SelectNextOverviewItem);
        }
        let selected = app.selected_layer().unwrap();
        let overview_offset = app.row_offset();
        assert!(overview_offset > 0);

        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);
        assert_eq!(app.detail_layer(), Some(selected));
        assert_eq!(app.row_offset(), 0);
        app.update(Action::Back);

        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(app.selected_layer(), Some(selected));
        assert_eq!(app.row_offset(), overview_offset);
    }

    #[test]
    fn conntrack_flow_navigation_returns_directly_to_overview() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        open_conntrack_detail(&mut app);

        app.update(Action::OpenConntrackFlows);
        assert_eq!(app.dashboard_mode(), DashboardMode::ConntrackFlows);
        assert_eq!(app.row_offset(), 0);

        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(
            app.selected_layer(),
            Some(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::NetfilterConntrack
            ))
        );
    }

    #[test]
    fn socket_table_navigation_returns_through_the_layer_detail() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        open_socket_detail(&mut app);
        app.row_offset = 5;

        app.update(Action::OpenSocketTable);
        assert_eq!(app.dashboard_mode(), DashboardMode::SocketTable);
        assert_eq!(app.row_offset(), 0);

        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);
        assert!(app.can_open_socket_table());
        assert_eq!(app.row_offset(), 5);

        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(
            app.selected_layer(),
            Some(BlockKind::PacketStage(
                crate::monitor::dashboard::PacketStage::SocketApplication
            ))
        );
    }

    #[test]
    fn only_socket_layer_detail_opens_the_socket_table() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::SelectNextOverviewItem);
        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);

        app.update(Action::OpenSocketTable);

        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);
    }

    #[test]
    fn direct_socket_section_opens_table_and_returns_to_the_section() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.apply_snapshot(socket_section_snapshot());
        app.set_viewport_size(80, 2);
        app.update(Action::PageDown);
        let section_offset = app.row_offset();
        assert!(section_offset > 0);
        assert!(app.can_open_socket_table());

        app.update(Action::OpenSocketTable);
        assert!(app.is_socket_table());
        assert_eq!(app.row_offset(), 0);
        app.update(Action::Back);

        assert_eq!(app.section(), MonitorSection::Socket);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(app.row_offset(), section_offset);

        app.update(Action::Back);
        assert_eq!(app.section(), MonitorSection::Overview);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
    }

    #[test]
    fn paused_socket_table_accepts_only_its_first_display_snapshot() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        open_socket_detail(&mut app);
        app.update(Action::TogglePause);
        app.update(Action::OpenSocketTable);
        let first = crate::monitor::socket_table::synthetic_socket_table_snapshot_at(1);
        let second = crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2);

        app.apply_socket_snapshot(first);
        app.apply_socket_snapshot(second);

        assert_eq!(app.socket_snapshot().unwrap().sequence(), 1);
        app.update(Action::TogglePause);
        assert_eq!(app.socket_snapshot().unwrap().sequence(), 2);

        app.update(Action::Back);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3),
        );
        assert!(app.socket_snapshot().is_none());
    }

    #[test]
    fn socket_table_selection_follows_identity_across_activity_reordering() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        assert_eq!(app.selected_socket_ordinal(), Some(0));
        app.update(Action::ScrollDown);
        let selected = app.selected_socket_key().unwrap().clone();
        assert_eq!(app.selected_socket_ordinal(), Some(1));

        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_reordered_at(3),
        );

        assert_eq!(app.selected_socket_key(), Some(&selected));
        assert_eq!(app.selected_socket_ordinal(), Some(1));
    }

    #[test]
    fn socket_detail_does_not_switch_identity_when_the_socket_disappears() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        let selected = app.selected_socket_key().unwrap().clone();
        app.update(Action::OpenSocketDetail);
        assert!(app.is_socket_detail());

        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_without_tcp_at(3),
        );

        let detail = app.socket_detail().unwrap();
        assert!(!detail.observed_latest());
        assert_eq!(detail.key(), &selected);
        assert_eq!(detail.socket().row_key(), &selected);
    }

    #[test]
    fn socket_detail_ignores_the_unrelated_time_projection_toggle() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::OpenSocketDetail);

        app.update(Action::ToggleTimeView);

        assert_eq!(app.time_view(), TimeView::Interval);
    }

    #[test]
    fn paused_socket_detail_freezes_display_but_keeps_latest_observation() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::OpenSocketDetail);
        let frozen_at = app.socket_detail().unwrap().last_at();

        app.update(Action::TogglePause);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3),
        );
        assert_eq!(app.socket_detail().unwrap().last_at(), frozen_at);

        app.update(Action::TogglePause);
        assert_eq!(
            app.socket_detail().unwrap().last_at(),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn paused_socket_detail_starts_at_open_boundary_and_tracks_latest_separately() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::TogglePause);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_without_tcp_at(9),
        );

        app.update(Action::OpenSocketDetail);

        let displayed = app.socket_detail().unwrap();
        assert_eq!(displayed.opened_at(), Duration::from_secs(9));
        assert_eq!(displayed.last_at(), Duration::from_secs(9));
        assert!(displayed.observed_latest());
        let latest = app.latest_socket_detail.as_ref().unwrap();
        assert_eq!(latest.opened_at(), Duration::from_secs(9));
        assert_eq!(latest.last_at(), Duration::from_secs(9));
        assert!(!latest.observed_latest());
        assert_eq!(latest.key(), displayed.key());

        app.update(Action::TogglePause);
        assert!(!app.socket_detail().unwrap().observed_latest());
    }

    #[test]
    fn socket_detail_back_restores_table_offset_and_selection() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.set_viewport_size(60, 1);
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::ScrollDown);
        let selected = app.selected_socket_key().unwrap().clone();
        let table_offset = app.row_offset();
        app.update(Action::OpenSocketDetail);
        app.update(Action::ScrollDown);

        app.update(Action::Back);

        assert!(app.is_socket_table());
        assert_eq!(app.selected_socket_key(), Some(&selected));
        assert_eq!(app.row_offset(), table_offset);
    }

    #[test]
    fn only_conntrack_layer_detail_opens_the_flow_page() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);

        app.update(Action::OpenConntrackFlows);

        assert_eq!(app.dashboard_mode(), DashboardMode::LayerDetail);
    }

    #[test]
    fn direct_netfilter_section_opens_menu_then_conntrack_flows() {
        let mut app = App::new(MonitorSection::Netfilter, Duration::from_secs(1));
        assert!(!app.can_open_conntrack_flows());

        app.update(Action::OpenNetfilterItem);
        assert!(app.can_open_conntrack_flows());

        app.update(Action::OpenConntrackFlows);
        assert!(app.is_conntrack_flows());
        app.update(Action::Back);

        assert_eq!(app.section(), MonitorSection::Netfilter);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
    }

    #[test]
    fn flow_filter_applies_clears_and_preserves_the_previous_filter_on_error() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        open_conntrack_detail(&mut app);
        app.update(Action::OpenConntrackFlows);

        app.update(Action::EnterFlowFilter);
        for character in "192.0.2.10 443".chars() {
            app.update(Action::Insert(character));
        }
        app.update(Action::SubmitCommand);
        assert_eq!(
            app.conntrack_filter().map(ConntrackFlowFilter::query),
            Some("192.0.2.10 443")
        );

        app.update(Action::EnterFlowFilter);
        app.update(Action::Insert('x'));
        app.update(Action::SubmitCommand);
        assert!(app.flow_filter_error().is_some());
        assert_eq!(
            app.conntrack_filter().map(ConntrackFlowFilter::query),
            Some("192.0.2.10 443")
        );
        app.update(Action::CancelCommand);

        app.update(Action::EnterFlowFilter);
        app.flow_filter_input = Some(FlowFilterInput(String::new()));
        app.update(Action::SubmitCommand);
        assert!(app.conntrack_filter().is_none());
    }

    #[test]
    fn flow_filter_input_is_redacted_from_app_debug() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        open_conntrack_detail(&mut app);
        app.update(Action::OpenConntrackFlows);
        app.update(Action::EnterFlowFilter);
        for character in "192.0.2.99 8443".chars() {
            app.update(Action::Insert(character));
        }

        let debug = format!("{app:?}");
        assert!(!debug.contains("192.0.2.99"), "{debug}");
        assert!(!debug.contains("8443"), "{debug}");
    }

    #[test]
    fn socket_filter_matches_conntrack_input_flow() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::EnterSocketFilter);
        for character in "proto=tcp 443".chars() {
            app.update(Action::Insert(character));
        }
        app.update(Action::SubmitCommand);
        assert_eq!(
            app.socket_filter.as_ref().map(SocketFilter::query),
            Some("proto=tcp 443")
        );
        assert!(app.socket_order.shown_count() < app.socket_snapshot().unwrap().sockets().len());

        app.update(Action::EnterSocketFilter);
        app.update(Action::Insert('x'));
        app.update(Action::SubmitCommand);
        assert!(app.socket_filter_error().is_some());
        assert_eq!(
            app.socket_filter.as_ref().map(SocketFilter::query),
            Some("proto=tcp 443")
        );
    }

    #[test]
    fn tcpdump_connection_filters_keep_valid_results_after_invalid_edits() {
        let mut app = App::new(MonitorSection::Socket, Duration::from_secs(1));
        app.update(Action::OpenSocketTable);
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        let socket_query = "tcp and (dst port 443 or dst port 8443)";
        app.update(Action::EnterSocketFilter);
        for c in socket_query.chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        assert!(app.socket_filter_error().is_none());
        assert_eq!(app.socket_order.shown_count(), 1);
        let selected = app.selected_socket_key().cloned();
        app.update(Action::EnterSocketFilter);
        for c in " and (".chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        assert!(app.socket_filter_error().is_some());
        assert_eq!(
            app.socket_filter.as_ref().map(SocketFilter::query),
            Some(socket_query)
        );
        assert_eq!(app.selected_socket_key(), selected.as_ref());
        app.update(Action::CancelCommand);
        app.update(Action::SelectPage(Page::Conntrack));
        let (_, snapshot) = crate::tui::conntrack::tests::fixture_snapshots();
        app.apply_conntrack_snapshot(snapshot);
        let flow_query = "tcp and dst port 443 and not dst net 10.0.0.0/8";
        app.update(Action::EnterFlowFilter);
        for c in flow_query.chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        assert!(app.flow_filter_error().is_none());
        assert_eq!(app.conntrack_view.shown_count(), 1);
        app.update(Action::SelectPage(Page::Socket));
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3),
        );
        assert_eq!(
            app.socket_filter.as_ref().map(SocketFilter::query),
            Some(socket_query)
        );
        assert_eq!(app.socket_order.shown_count(), 1);
        app.update(Action::SelectPage(Page::Conntrack));
        assert_eq!(
            app.conntrack_filter
                .as_ref()
                .map(ConntrackFlowFilter::query),
            Some(flow_query)
        );
    }

    #[test]
    fn connection_preferences_survive_navigation_and_clear_independently() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.update(Action::SelectPage(Page::Socket));
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(2),
        );
        app.update(Action::EnterSocketFilter);
        let socket_query = "src=192.0.2.0/24 dport=443";
        for c in socket_query.chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        assert_eq!(app.socket_order.shown_count(), 1);
        app.update(Action::CycleSort);
        app.update(Action::ReverseSort);
        let socket_sort = (app.socket_order.sort(), app.socket_order.descending());
        assert!(!format!("{app:?}").contains("192.0.2"));

        app.update(Action::SelectPage(Page::Conntrack));
        assert!(app.socket_snapshot().is_none());
        app.update(Action::EnterFlowFilter);
        let flow_query = "host=10.0.0.0/8 proto=tcp";
        for c in flow_query.chars() {
            app.update(Action::Insert(c));
        }
        app.update(Action::SubmitCommand);
        app.update(Action::CycleSort);
        app.update(Action::ReverseSort);
        let flow_sort = (app.conntrack_view.sort(), app.conntrack_view.descending());

        app.update(Action::SelectPage(Page::Overview));
        app.update(Action::SelectPage(Page::Socket));
        app.apply_socket_snapshot(
            crate::monitor::socket_table::synthetic_socket_table_snapshot_at(3),
        );
        assert_eq!(
            app.socket_filter.as_ref().map(SocketFilter::query),
            Some(socket_query)
        );
        assert_eq!(
            (app.socket_order.sort(), app.socket_order.descending()),
            socket_sort
        );
        assert_eq!(app.socket_order.shown_count(), 1);
        app.update(Action::OpenSocketDetail);
        assert!(app.is_socket_detail());
        app.update(Action::Back);
        app.update(Action::EnterSocketFilter);
        app.update(Action::Insert('x'));
        app.update(Action::SubmitCommand);
        assert!(app.socket_filter_error().is_some());
        app.update(Action::ClearConnectionFilter);
        assert!(app.socket_filter.is_none());
        assert!(app.socket_filter_error().is_none());
        assert!(!app.text_input_active());
        assert_eq!(app.socket_order.shown_count(), 2);
        assert_eq!(
            app.conntrack_filter
                .as_ref()
                .map(ConntrackFlowFilter::query),
            Some(flow_query)
        );

        app.update(Action::SelectPage(Page::Conntrack));
        assert_eq!(
            (app.conntrack_view.sort(), app.conntrack_view.descending()),
            flow_sort
        );
        assert_eq!(
            app.conntrack_filter
                .as_ref()
                .map(ConntrackFlowFilter::query),
            Some(flow_query)
        );
        app.update(Action::EnterFlowFilter);
        assert_eq!(app.flow_filter_input(), Some(flow_query));
        app.update(Action::ClearConnectionFilter);
        assert!(app.conntrack_filter.is_none());
        assert!(!app.text_input_active());
        assert_eq!(
            (app.conntrack_view.sort(), app.conntrack_view.descending()),
            flow_sort
        );
    }

    #[test]
    fn layer_detail_back_preserves_manual_scroll_away_from_the_selection() {
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(interface_snapshot(1, &[]));
        app.set_viewport_size(60, 8);
        app.update(Action::PageDown);
        assert_eq!(app.row_offset(), 10);

        app.update(Action::OpenSelectedOverviewItem);
        app.update(Action::Back);

        assert_eq!(app.selected_layer(), Some(workspace::LAYERS[0]));
        assert_eq!(app.row_offset(), 10);
    }

    #[test]
    fn detail_back_restores_overview_selection_and_scroll() {
        let snapshot = interface_snapshot(1, &[("eth0", 2, "physical"), ("eth1", 3, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 15);
        app.apply_snapshot(snapshot);
        select_first_interface(&mut app);
        app.update(Action::SelectNextOverviewItem);
        let overview_offset = app.row_offset();
        assert_eq!(app.selected_interface().unwrap().name(), "eth1");

        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.dashboard_mode(), DashboardMode::InterfaceDetail);
        assert_eq!(app.row_offset(), 0);
        app.update(Action::ToggleDetailMetrics);
        app.update(Action::PageDown);
        assert!(app.row_offset() > 0);
        app.update(Action::Back);

        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(app.selected_interface().unwrap().name(), "eth1");
        assert_eq!(app.row_offset(), overview_offset);
    }

    #[test]
    fn interface_layer_detail_preserves_layer_selection_and_menu_offset() {
        let snapshot = interface_snapshot(1, &[("eth0", 2, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(60, 4);
        app.apply_snapshot(snapshot);
        select_first_interface(&mut app);
        app.update(Action::OpenSelectedOverviewItem);

        assert_eq!(app.dashboard_mode(), DashboardMode::InterfaceDetail);
        assert_eq!(
            app.selected_interface_layer(),
            Some(super::super::dashboard::INTERFACE_BLOCK_KINDS[0])
        );
        app.update(Action::SelectPreviousInterfaceLayer);
        assert_eq!(
            app.selected_interface_layer(),
            Some(super::super::dashboard::INTERFACE_BLOCK_KINDS[0])
        );
        app.update(Action::SelectNextInterfaceLayer);
        app.update(Action::SelectNextInterfaceLayer);
        let selected = super::super::dashboard::INTERFACE_BLOCK_KINDS[2];
        assert_eq!(app.selected_interface_layer(), Some(selected));
        assert!(app.row_offset() > 0);
        let menu_offset = app.row_offset();

        app.update(Action::OpenSelectedInterfaceLayer);
        assert_eq!(app.dashboard_mode(), DashboardMode::InterfaceLayerDetail);
        assert_eq!(app.detail_interface_layer(), Some(selected));
        assert_eq!(app.row_offset(), 0);

        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::InterfaceDetail);
        assert_eq!(app.selected_interface_layer(), Some(selected));
        assert_eq!(app.row_offset(), menu_offset);

        app.update(Action::Back);
        assert_eq!(app.dashboard_mode(), DashboardMode::Summary);
        assert_eq!(app.selected_interface().unwrap().name(), "eth0");
    }

    #[test]
    fn toggling_back_to_metrics_with_data_clamps_detail_scroll() {
        let elapsed = Duration::from_secs(1);
        let snapshot = MonitorSnapshot::new(
            1,
            1,
            0,
            elapsed,
            None,
            Vec::new(),
            Vec::new(),
            crate::monitor::EngineTelemetry::default(),
        )
        .unwrap();
        let mut app = App::new(MonitorSection::Overview, elapsed);
        app.apply_snapshot(Arc::new(snapshot));
        app.set_viewport_size(160, 1);
        app.update(Action::OpenSelectedOverviewItem);
        assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::WithData);

        app.update(Action::ToggleDetailMetrics);
        assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::All);
        app.update(Action::PageDown);
        let all_offset = app.row_offset();
        assert!(all_offset > 0);

        app.update(Action::ToggleDetailMetrics);
        let expected = super::super::dashboard::global_layer_detail_row_count(
            app.snapshot().unwrap(),
            app.detail_layer().unwrap(),
            super::super::dashboard::DetailDisplayOptions::new(
                app.time_view(),
                DetailMetricsMode::WithData,
            ),
            160,
        )
        .saturating_sub(1);
        assert_eq!(app.detail_metrics_mode(), DetailMetricsMode::WithData);
        assert_eq!(app.row_offset(), expected);
        assert!(app.row_offset() < all_offset);
    }

    #[test]
    fn detail_back_keeps_a_reordered_interface_selection_visible() {
        let initial = interface_snapshot(1, &[("eth10", 10, "physical")]);
        let inserted = interface_snapshot(
            2,
            &[
                ("eth1", 1, "physical"),
                ("eth2", 2, "physical"),
                ("eth3", 3, "physical"),
                ("eth4", 4, "physical"),
                ("eth5", 5, "physical"),
                ("eth10", 10, "physical"),
            ],
        );
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.set_viewport_size(160, 8);
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        assert_selected_overview_item_is_visible(&app);
        app.update(Action::OpenSelectedOverviewItem);

        app.apply_snapshot(inserted);
        app.update(Action::Back);

        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        assert_selected_overview_item_is_visible(&app);
    }

    #[test]
    fn refresh_keeps_identity_and_pause_defers_reconciliation() {
        let initial = interface_snapshot(1, &[("eth10", 10, "physical"), ("veth2", 2, "virtual")]);
        let inserted = interface_snapshot(
            2,
            &[
                ("eth1", 1, "physical"),
                ("eth10", 10, "physical"),
                ("veth2", 2, "virtual"),
            ],
        );
        let replacement = interface_snapshot(3, &[("eth9", 9, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");

        app.apply_snapshot(inserted);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        app.update(Action::TogglePause);
        app.apply_snapshot(replacement);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        app.update(Action::TogglePause);
        assert_eq!(app.selected_interface().unwrap().name(), "eth9");
    }

    #[test]
    fn disappearing_interface_is_not_silently_replaced_in_detail() {
        let initial = interface_snapshot(1, &[("eth0", 2, "physical")]);
        let replacement = interface_snapshot(2, &[("eth9", 9, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        app.update(Action::OpenSelectedOverviewItem);

        app.apply_snapshot(replacement);

        assert_eq!(app.detail_interface().unwrap().name(), "eth0");
        app.update(Action::Back);
        assert_eq!(app.selected_interface().unwrap().name(), "eth9");
    }

    #[test]
    fn real_session_removes_missing_interface_and_selects_its_neighbor() {
        let interval = Duration::from_secs(1);
        let mut engine = crate::monitor::session::MonitorEngine::new(1, interval).unwrap();
        let initial = engine
            .ingest(
                interval,
                vec![interface_sample(
                    interval,
                    &[
                        ("eth1", 1, "physical"),
                        ("eth10", 10, "physical"),
                        ("eth20", 20, "physical"),
                    ],
                )],
                None,
            )
            .unwrap();
        let mut app = App::new(MonitorSection::Overview, interval);
        app.set_viewport_size(160, 80);
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        app.update(Action::SelectNextOverviewItem);
        assert_eq!(app.selected_interface().unwrap().name(), "eth10");
        let removed_identity = app.selected_interface().unwrap().clone();

        let elapsed = Duration::from_secs(2);
        let replacement = engine
            .ingest(
                elapsed,
                vec![interface_sample(
                    elapsed,
                    &[("eth1", 1, "physical"), ("eth20", 20, "physical")],
                )],
                None,
            )
            .unwrap();
        app.apply_snapshot(replacement);

        assert_eq!(
            super::super::dashboard::interface_detail_row_count(
                app.snapshot().unwrap(),
                &removed_identity,
                super::super::dashboard::DetailDisplayOptions::new(
                    app.time_view(),
                    app.detail_metrics_mode(),
                ),
                160,
            ),
            4 // Two message rows plus the frame's top and bottom borders.
        );
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(160, 8)).unwrap();
        terminal
            .draw(|frame| {
                super::super::dashboard::render_interface_detail(
                    frame,
                    frame.area(),
                    app.snapshot().unwrap(),
                    &removed_identity,
                    BlockKind::PacketStage(crate::monitor::dashboard::PacketStage::NicPhy),
                    super::super::dashboard::DetailDisplayOptions::new(
                        app.time_view(),
                        app.detail_metrics_mode(),
                    ),
                    0,
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
        assert!(rendered.contains("INTERFACE eth10  ifindex 10  NO LONGER OBSERVED"));
        assert!(rendered.contains("no longer reports this interface as present"));
        assert!(!rendered.contains("INTERFACE eth20"));
        assert_eq!(
            app.ordered_interfaces()
                .iter()
                .map(InterfaceIdentity::name)
                .collect::<Vec<_>>(),
            ["eth1", "eth20"]
        );
        assert_eq!(app.selected_interface().unwrap().name(), "eth20");
    }

    #[test]
    fn direct_section_then_back_reconciles_interface_removed_while_detail_is_open() {
        let initial = interface_snapshot(1, &[("eth0", 2, "physical")]);
        let replacement = interface_snapshot(2, &[("eth9", 9, "physical")]);
        let mut app = App::new(MonitorSection::Overview, Duration::from_secs(1));
        app.apply_snapshot(initial);
        select_first_interface(&mut app);
        app.update(Action::OpenSelectedOverviewItem);
        app.apply_snapshot(replacement);

        app.select_section(MonitorSection::Socket);
        assert_eq!(app.section(), MonitorSection::Socket);
        app.update(Action::Back);
        assert_eq!(app.selected_interface().unwrap().name(), "eth9");
        app.update(Action::OpenSelectedOverviewItem);

        assert_eq!(app.detail_interface().unwrap().name(), "eth9");
    }
}
