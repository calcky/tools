use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::monitor::dashboard::{BlockKind, PacketStage};
use crate::monitor::{
    MetricLabel, MonitorSnapshot, ProjectedValue, ProviderHealth, SeriesSnapshot, SeriesValue,
};

use super::app::TimeView;
use super::dashboard::DetailDisplayOptions;
use super::theme;

const CHAIN_RULES: &str = "linux.netfilter.chain.rules";
const CHAIN_POLICY: &str = "linux.netfilter.chain.policy";
const CHAIN_TYPE: &str = "linux.netfilter.chain.type";
const RULE_EXPRESSION: &str = "linux.netfilter.rule.expression";
const RULE_POSITION: &str = "linux.netfilter.rule.position";
const RULE_PACKETS: &str = "linux.netfilter.rule.packets";
const RULE_BYTES: &str = "linux.netfilter.rule.bytes";

const MENU_HEADER_ROWS: usize = 3;
const CHAIN_HEADER_ROWS: usize = 3;

const MENU_ITEMS: [MenuItem; 4] = [
    MenuItem::Conntrack,
    MenuItem::Rules(RulesBackend::IptablesIpv4),
    MenuItem::Rules(RulesBackend::IptablesIpv6),
    MenuItem::Rules(RulesBackend::Nftables),
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum NetfilterPage {
    #[default]
    Menu,
    Conntrack,
    Chains(RulesBackend),
    Rules(RulesBackend),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuItem {
    Conntrack,
    Rules(RulesBackend),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RulesBackend {
    IptablesIpv4,
    IptablesIpv6,
    Nftables,
}

impl RulesBackend {
    const fn title(self) -> &'static str {
        match self {
            Self::IptablesIpv4 => "IPTABLES IPV4",
            Self::IptablesIpv6 => "IPTABLES IPV6",
            Self::Nftables => "NFTABLES",
        }
    }

    fn matches_label(self, value: &str) -> bool {
        match self {
            Self::IptablesIpv4 | Self::IptablesIpv6 => value.starts_with("iptables_"),
            Self::Nftables => matches!(value, "nftables" | "nft"),
        }
    }

    fn matches_provider(self, provider: &str) -> bool {
        match self {
            Self::IptablesIpv4 => {
                provider.contains("iptables")
                    && (provider.contains("ipv4") || provider.ends_with(".v4"))
            }
            Self::IptablesIpv6 => {
                provider.contains("iptables")
                    && (provider.contains("ipv6") || provider.ends_with(".v6"))
            }
            Self::Nftables => provider.contains("nft"),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ChainKey {
    family: String,
    table: Option<String>,
    chain: String,
}

#[derive(Debug, Default)]
pub(super) struct NetfilterViewState {
    page: NetfilterPage,
    menu_selected: usize,
    chain_selected: usize,
    chain_key: Option<ChainKey>,
    row_offset: usize,
    viewport_rows: usize,
}

impl NetfilterViewState {
    pub(super) fn breadcrumb(&self) -> String {
        match self.page {
            NetfilterPage::Menu => "NETFILTER".to_owned(),
            NetfilterPage::Conntrack => "NETFILTER > CONNTRACK".to_owned(),
            NetfilterPage::Chains(backend) => format!("NETFILTER > {}", backend.title()),
            NetfilterPage::Rules(backend) => self.chain_key.as_ref().map_or_else(
                || format!("NETFILTER > {} > RULES", backend.title()),
                |key| format!("NETFILTER > {} > {}", backend.title(), key.chain),
            ),
        }
    }

    pub(super) const fn footer_help(&self) -> &'static str {
        match self.page {
            NetfilterPage::Menu => " j/k select  Enter open  Esc overview ",
            NetfilterPage::Conntrack => {
                " j/k scroll  Enter flows  Esc back  PgUp/PgDn page  a all/data "
            }
            NetfilterPage::Chains(_) => " j/k select  Enter rules  Esc back  PgUp/PgDn page ",
            NetfilterPage::Rules(_) => " j/k scroll  Esc chains  PgUp/PgDn page ",
        }
    }

    pub(super) const fn compact_footer_help(&self) -> &'static str {
        match self.page {
            NetfilterPage::Menu => " j/k select Enter open Esc back p pause q quit ",
            NetfilterPage::Conntrack => " j/k scroll Enter flows Esc back Pg a all p pause q quit ",
            NetfilterPage::Chains(_) => " j/k select Enter rules Esc back Pg page p pause q quit ",
            NetfilterPage::Rules(_) => " j/k scroll Esc chains Pg page p pause q quit ",
        }
    }

    pub(super) const fn is_conntrack(&self) -> bool {
        matches!(self.page, NetfilterPage::Conntrack)
    }

    pub(super) fn enter(&mut self, snapshot: Option<&MonitorSnapshot>) {
        self.row_offset = 0;
        match self.page {
            NetfilterPage::Menu => {
                self.page = match MENU_ITEMS[self.menu_selected] {
                    MenuItem::Conntrack => NetfilterPage::Conntrack,
                    MenuItem::Rules(backend) => NetfilterPage::Chains(backend),
                };
                self.reconcile(snapshot);
            }
            NetfilterPage::Chains(backend) => {
                let rows = chain_rows(snapshot, backend, TimeView::Interval);
                if let Some(row) = rows.get(self.chain_selected) {
                    self.chain_key = Some(row.key.clone());
                    self.page = NetfilterPage::Rules(backend);
                }
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {}
        }
        self.ensure_selection_visible();
    }

    /// Returns true when the caller should leave the Netfilter layer.
    pub(super) fn back(&mut self) -> bool {
        self.row_offset = 0;
        self.page = match self.page {
            NetfilterPage::Menu => return true,
            NetfilterPage::Rules(backend) => NetfilterPage::Chains(backend),
            NetfilterPage::Conntrack | NetfilterPage::Chains(_) => NetfilterPage::Menu,
        };
        self.ensure_selection_visible();
        false
    }

    pub(super) fn move_up(&mut self, snapshot: Option<&MonitorSnapshot>) {
        match self.page {
            NetfilterPage::Menu => self.menu_selected = self.menu_selected.saturating_sub(1),
            NetfilterPage::Chains(_) => {
                self.chain_selected = self.chain_selected.saturating_sub(1);
                self.remember_chain(snapshot);
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {
                self.row_offset = self.row_offset.saturating_sub(1);
                return;
            }
        }
        self.ensure_selection_visible();
    }

    pub(super) fn move_down(&mut self, snapshot: Option<&MonitorSnapshot>) {
        match self.page {
            NetfilterPage::Menu => {
                self.menu_selected = (self.menu_selected + 1).min(MENU_ITEMS.len() - 1);
            }
            NetfilterPage::Chains(backend) => {
                let len = chain_rows(snapshot, backend, TimeView::Interval).len();
                self.chain_selected = next_selection(self.chain_selected, len);
                self.remember_chain(snapshot);
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {
                self.row_offset = self.row_offset.saturating_add(1);
                return;
            }
        }
        self.ensure_selection_visible();
    }

    pub(super) fn page_up(&mut self, snapshot: Option<&MonitorSnapshot>) {
        let amount = self.viewport_rows.saturating_sub(1).max(1);
        match self.page {
            NetfilterPage::Menu => {
                self.menu_selected = self.menu_selected.saturating_sub(amount);
            }
            NetfilterPage::Chains(_) => {
                self.chain_selected = self.chain_selected.saturating_sub(amount);
                self.remember_chain(snapshot);
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {
                self.row_offset = self.row_offset.saturating_sub(amount);
                return;
            }
        }
        self.ensure_selection_visible();
    }

    pub(super) fn page_down(&mut self, snapshot: Option<&MonitorSnapshot>) {
        let amount = self.viewport_rows.saturating_sub(1).max(1);
        match self.page {
            NetfilterPage::Menu => {
                self.menu_selected = (self.menu_selected + amount).min(MENU_ITEMS.len() - 1);
            }
            NetfilterPage::Chains(backend) => {
                let len = chain_rows(snapshot, backend, TimeView::Interval).len();
                self.chain_selected =
                    clamp_selection(self.chain_selected.saturating_add(amount), len);
                self.remember_chain(snapshot);
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {
                self.row_offset = self.row_offset.saturating_add(amount);
                return;
            }
        }
        self.ensure_selection_visible();
    }

    pub(super) fn scroll_top(&mut self) {
        self.row_offset = 0;
        match self.page {
            NetfilterPage::Menu => self.menu_selected = 0,
            NetfilterPage::Chains(_) => {
                self.chain_selected = 0;
                self.chain_key = None;
            }
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => {}
        }
    }

    pub(super) fn set_viewport_rows(&mut self, rows: usize) {
        self.viewport_rows = rows.max(1);
        self.ensure_selection_visible();
    }

    pub(super) fn clamp_content_rows(&mut self, rows: usize) {
        self.row_offset = self
            .row_offset
            .min(rows.saturating_sub(self.viewport_rows.max(1)));
    }

    pub(super) fn reconcile(&mut self, snapshot: Option<&MonitorSnapshot>) {
        let (NetfilterPage::Chains(backend) | NetfilterPage::Rules(backend)) = self.page else {
            return;
        };
        let rows = chain_rows(snapshot, backend, TimeView::Interval);
        if let Some(position) = self
            .chain_key
            .as_ref()
            .and_then(|key| rows.iter().position(|row| &row.key == key))
        {
            self.chain_selected = position;
        } else if matches!(self.page, NetfilterPage::Chains(_)) {
            self.chain_selected = clamp_selection(self.chain_selected, rows.len());
            self.chain_key = rows.get(self.chain_selected).map(|row| row.key.clone());
        }
        self.ensure_selection_visible();
    }

    fn remember_chain(&mut self, snapshot: Option<&MonitorSnapshot>) {
        let NetfilterPage::Chains(backend) = self.page else {
            return;
        };
        self.chain_key = chain_rows(snapshot, backend, TimeView::Interval)
            .get(self.chain_selected)
            .map(|row| row.key.clone());
    }

    fn ensure_selection_visible(&mut self) {
        let selected_row = match self.page {
            NetfilterPage::Menu => MENU_HEADER_ROWS.saturating_add(self.menu_selected),
            NetfilterPage::Chains(_) => CHAIN_HEADER_ROWS.saturating_add(self.chain_selected),
            NetfilterPage::Conntrack | NetfilterPage::Rules(_) => return,
        };
        let viewport_rows = self.viewport_rows.max(1);
        if selected_row < self.row_offset {
            self.row_offset = selected_row;
        } else if selected_row >= self.row_offset.saturating_add(viewport_rows) {
            self.row_offset = selected_row.saturating_add(1).saturating_sub(viewport_rows);
        }
    }
}

pub(super) fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &NetfilterViewState,
    snapshot: Option<&MonitorSnapshot>,
    time_view: TimeView,
    display: DetailDisplayOptions,
) {
    if area.is_empty() {
        return;
    }
    if state.page == NetfilterPage::Conntrack {
        if let Some(snapshot) = snapshot {
            super::dashboard::render_global_layer_detail(
                frame,
                area,
                snapshot,
                netfilter_block(),
                display,
                state.row_offset,
            );
        } else {
            frame.render_widget(Paragraph::new("Collecting Netfilter counters..."), area);
        }
        return;
    }

    let mut lines = page_lines(state, snapshot, time_view, area.width);
    let offset = state
        .row_offset
        .min(lines.len().saturating_sub(usize::from(area.height)));
    let visible = lines
        .drain(..)
        .skip(offset)
        .take(usize::from(area.height))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), area);
}

pub(super) fn row_count(
    state: &NetfilterViewState,
    snapshot: Option<&MonitorSnapshot>,
    time_view: TimeView,
    display: DetailDisplayOptions,
    width: u16,
) -> usize {
    if state.page == NetfilterPage::Conntrack {
        return snapshot.map_or(1, |snapshot| {
            super::dashboard::global_layer_detail_row_count(
                snapshot,
                netfilter_block(),
                display,
                width,
            )
        });
    }
    page_lines(state, snapshot, time_view, width).len()
}

const fn netfilter_block() -> BlockKind {
    BlockKind::PacketStage(PacketStage::NetfilterConntrack)
}

fn page_lines(
    state: &NetfilterViewState,
    snapshot: Option<&MonitorSnapshot>,
    time_view: TimeView,
    width: u16,
) -> Vec<Line<'static>> {
    match state.page {
        NetfilterPage::Menu => menu_lines(snapshot, state.menu_selected, width),
        NetfilterPage::Chains(backend) => {
            chain_lines(snapshot, backend, state.chain_selected, time_view, width)
        }
        NetfilterPage::Rules(backend) => rule_lines(
            snapshot,
            backend,
            state.chain_key.as_ref(),
            time_view,
            width,
        ),
        NetfilterPage::Conntrack => unreachable!("conntrack is rendered by the dashboard"),
    }
}

fn menu_lines(
    snapshot: Option<&MonitorSnapshot>,
    selected: usize,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let columns = menu_columns(width);
    let mut lines = vec![title_line("NETFILTER", None, width)];
    lines.push(Line::styled(
        fit(
            " Current network namespace rule and conntrack visibility",
            width,
        ),
        Style::default().fg(theme::MUTED),
    ));
    lines.push(heading(
        &columns,
        ["BACKEND", "STATUS", "CHAINS", "RULES/FLOWS", "COUNTERED"],
        width,
    ));

    let conntrack_count = snapshot.and_then(|snapshot| {
        snapshot
            .series()
            .iter()
            .find(|series| series.metric().as_str() == "linux.netfilter.conntrack.count")
            .and_then(gauge_value)
    });
    lines.push(selected_line(
        [
            "Conntrack".to_owned(),
            conntrack_health(snapshot),
            "-".to_owned(),
            format_optional_count(conntrack_count),
            "-".to_owned(),
        ],
        &columns,
        width,
        selected == 0,
        Style::default().fg(theme::TEXT),
    ));

    for (index, backend) in [
        RulesBackend::IptablesIpv4,
        RulesBackend::IptablesIpv6,
        RulesBackend::Nftables,
    ]
    .into_iter()
    .enumerate()
    {
        let rows = chain_rows(snapshot, backend, TimeView::Interval);
        let rules = rows.iter().map(ChainRow::rules).sum::<u64>();
        let countered = rows.iter().map(ChainRow::countered_rules).sum::<usize>();
        lines.push(selected_line(
            [
                backend_display_name(snapshot, backend),
                backend_health(snapshot, backend),
                rows.len().to_string(),
                rules.to_string(),
                countered.to_string(),
            ],
            &columns,
            width,
            selected == index + 1,
            Style::default().fg(theme::TEXT),
        ));
    }
    lines
}

fn chain_lines(
    snapshot: Option<&MonitorSnapshot>,
    backend: RulesBackend,
    selected: usize,
    time_view: TimeView,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let rows = chain_rows(snapshot, backend, time_view);
    let mut lines = vec![title_line(
        &backend_display_name(snapshot, backend),
        Some(time_view.as_str()),
        width,
    )];
    lines.push(Line::styled(
        fit(
            &format!(
                " {}  {} chains  {} rules",
                backend_health(snapshot, backend),
                rows.len(),
                rows.iter().map(ChainRow::rules).sum::<u64>()
            ),
            width,
        ),
        Style::default().fg(theme::MUTED),
    ));
    if rows.is_empty() {
        lines.push(Line::styled(
            fit(" No chain inventory is available", width),
            Style::default().fg(theme::MUTED),
        ));
        return lines;
    }

    let columns = chain_columns(width);
    lines.push(heading(
        &columns,
        [
            "CHAIN",
            "FAMILY/TABLES",
            "HOOK/PRIO",
            "POLICY/TYPE",
            "RULES",
            "COUNTED",
            "HITS",
            "DROP/s REJ/s",
        ],
        width,
    ));
    lines.extend(rows.into_iter().enumerate().map(|(index, row)| {
        let severity =
            if row.drops.rate.unwrap_or(0.0) > 0.0 || row.rejects.rate.unwrap_or(0.0) > 0.0 {
                Style::default().fg(theme::BAD)
            } else {
                Style::default().fg(theme::TEXT)
            };
        selected_line(
            [
                row.name().to_owned(),
                row.family_tables(),
                row.hook_priority(),
                row.policy_type(),
                row.rules().to_string(),
                format!("{}/{}", row.countered_rules(), row.rules()),
                format_optional_count(row.hits.total),
                format!(
                    "{}/{}",
                    format_rate(row.drops.rate),
                    format_rate(row.rejects.rate)
                ),
            ],
            &columns,
            width,
            index == selected,
            severity,
        )
    }));
    lines
}

fn rule_lines(
    snapshot: Option<&MonitorSnapshot>,
    backend: RulesBackend,
    chain_key: Option<&ChainKey>,
    time_view: TimeView,
    width: u16,
) -> Vec<Line<'static>> {
    let width = usize::from(width).max(1);
    let Some(chain_key) = chain_key else {
        return vec![Line::styled(
            fit(" Selected chain is no longer present", width),
            Style::default().fg(theme::WARN),
        )];
    };
    if !chain_rows(snapshot, backend, time_view)
        .iter()
        .any(|row| &row.key == chain_key)
    {
        return vec![Line::styled(
            fit(" Selected chain is no longer present", width),
            Style::default().fg(theme::WARN),
        )];
    }
    let rows = rule_rows(snapshot, backend, chain_key, time_view);
    let mut lines = vec![title_line(
        &format!("{} / {}", backend.title(), chain_key.chain),
        Some(time_view.as_str()),
        width,
    )];
    lines.push(Line::styled(
        fit(
            &format!(
                " {}  {} rules  counters are rule hits, not chain packet totals",
                backend_health(snapshot, backend),
                rows.len()
            ),
            width,
        ),
        Style::default().fg(theme::MUTED),
    ));
    if rows.is_empty() {
        lines.push(Line::styled(
            fit(" No rules are present in the selected chain", width),
            Style::default().fg(theme::MUTED),
        ));
        return lines;
    }

    let columns = rule_columns(width);
    lines.push(heading(
        &columns,
        [
            "TABLE",
            "POS",
            "MATCH / ACTION",
            "VERDICT",
            "PPS",
            "BW",
            "PACKETS",
            "BYTES",
        ],
        width,
    ));
    lines.extend(rows.into_iter().map(|row| {
        let style = match row.verdict.as_str() {
            "drop" | "reject" => Style::default().fg(theme::BAD),
            "queue" => Style::default().fg(theme::WARN),
            "accept" => Style::default().fg(theme::GOOD),
            _ => Style::default().fg(theme::TEXT),
        };
        let has_counter = row.packets.total.is_some() || row.bytes.total.is_some();
        plain_line(
            [
                row.table,
                row.position
                    .map_or_else(|| "-".to_owned(), |value| value.to_string()),
                row.expression.unwrap_or_else(|| "-".to_owned()),
                row.verdict,
                format_rate(row.packets.rate),
                format_bit_rate(row.bytes.rate.map(|value| value * 8.0)),
                if has_counter {
                    format_optional_count(row.packets.total)
                } else {
                    "NO COUNTER".to_owned()
                },
                if has_counter {
                    format_optional_bytes(row.bytes.total)
                } else {
                    "NO COUNTER".to_owned()
                },
            ],
            &columns,
            width,
            style,
        )
    }));
    lines
}

#[derive(Clone, Copy, Debug, Default)]
struct CounterProjection {
    total: Option<u64>,
    rate: Option<f64>,
}

impl CounterProjection {
    fn add(&mut self, other: Self) {
        if let Some(total) = other.total {
            self.total = Some(self.total.unwrap_or(0).saturating_add(total));
        }
        if let Some(rate) = other.rate {
            self.rate = Some(self.rate.unwrap_or(0.0) + rate);
        }
    }
}

#[derive(Clone, Debug)]
struct ChainRow {
    key: ChainKey,
    tables: BTreeSet<String>,
    hooks: BTreeSet<String>,
    priorities: BTreeSet<String>,
    policies: BTreeSet<String>,
    chain_types: BTreeSet<String>,
    declared_rules: Option<u64>,
    rule_ids: BTreeSet<RuleIdentity>,
    countered_rule_ids: BTreeSet<RuleIdentity>,
    hits: CounterProjection,
    drops: CounterProjection,
    rejects: CounterProjection,
}

impl ChainRow {
    fn new(key: ChainKey) -> Self {
        Self {
            key,
            tables: BTreeSet::new(),
            hooks: BTreeSet::new(),
            priorities: BTreeSet::new(),
            policies: BTreeSet::new(),
            chain_types: BTreeSet::new(),
            declared_rules: None,
            rule_ids: BTreeSet::new(),
            countered_rule_ids: BTreeSet::new(),
            hits: CounterProjection::default(),
            drops: CounterProjection::default(),
            rejects: CounterProjection::default(),
        }
    }

    fn name(&self) -> &str {
        &self.key.chain
    }

    fn rules(&self) -> u64 {
        self.declared_rules
            .unwrap_or(self.rule_ids.len().try_into().unwrap_or(u64::MAX))
            .max(self.rule_ids.len().try_into().unwrap_or(u64::MAX))
    }

    fn countered_rules(&self) -> usize {
        self.countered_rule_ids.len()
    }

    fn family_tables(&self) -> String {
        let tables = join_values(&self.tables);
        if self.key.family.is_empty() {
            tables
        } else if tables.is_empty() {
            self.key.family.clone()
        } else {
            format!("{}/{}", self.key.family, tables)
        }
    }

    fn hook_priority(&self) -> String {
        let hook = join_values(&self.hooks);
        let priority = join_values(&self.priorities);
        match (hook.is_empty(), priority.is_empty()) {
            (true, true) => "-".to_owned(),
            (false, true) => hook,
            (true, false) => priority,
            (false, false) => format!("{hook}/{priority}"),
        }
    }

    fn policy_type(&self) -> String {
        let policy = join_values(&self.policies);
        let chain_type = join_values(&self.chain_types);
        match (policy.is_empty(), chain_type.is_empty()) {
            (true, true) => "-".to_owned(),
            (false, true) => policy,
            (true, false) => chain_type,
            (false, false) => format!("{policy}/{chain_type}"),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RuleIdentity {
    table: String,
    row_id: String,
    handle: Option<String>,
}

#[derive(Debug)]
struct RuleRow {
    table: String,
    position: Option<u64>,
    expression: Option<String>,
    verdict: String,
    packets: CounterProjection,
    bytes: CounterProjection,
}

#[derive(Default)]
struct RuleBuilder {
    table: String,
    position: Option<u64>,
    expression: Option<String>,
    verdict: String,
    packets: CounterProjection,
    bytes: CounterProjection,
}

fn chain_rows(
    snapshot: Option<&MonitorSnapshot>,
    backend: RulesBackend,
    time_view: TimeView,
) -> Vec<ChainRow> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    let backend_series = snapshot
        .series()
        .iter()
        .filter(|series| series_matches_backend(series, backend))
        .collect::<Vec<_>>();
    let mut rows = BTreeMap::<ChainKey, ChainRow>::new();
    for series in backend_series
        .iter()
        .copied()
        .filter(|series| series.metric().as_str() == CHAIN_RULES)
        .filter(|series| gauge_value(series).is_some())
    {
        let labels = series.labels();
        let (Some(family), Some(table), Some(chain)) = (
            labels.get(MetricLabel::Family),
            labels.get(MetricLabel::Table),
            labels.get(MetricLabel::Chain),
        ) else {
            continue;
        };
        let key = ChainKey {
            family: family.to_owned(),
            table: (backend == RulesBackend::Nftables).then(|| table.to_owned()),
            chain: chain.to_owned(),
        };
        let row = rows
            .entry(key.clone())
            .or_insert_with(|| ChainRow::new(key));
        row.tables.insert(table.to_owned());
    }

    for series in backend_series {
        let labels = series.labels();
        let (Some(family), Some(table), Some(chain)) = (
            labels.get(MetricLabel::Family),
            labels.get(MetricLabel::Table),
            labels.get(MetricLabel::Chain),
        ) else {
            continue;
        };
        let key = ChainKey {
            family: family.to_owned(),
            table: (backend == RulesBackend::Nftables).then(|| table.to_owned()),
            chain: chain.to_owned(),
        };
        let Some(row) = rows.get_mut(&key) else {
            continue;
        };
        row.tables.insert(table.to_owned());
        if let Some(hook) = labels.get(MetricLabel::Hook) {
            row.hooks.insert(hook.to_owned());
        }
        if let Some(priority) = labels.get(MetricLabel::Priority) {
            row.priorities.insert(priority.to_owned());
        }

        match series.metric().as_str() {
            CHAIN_RULES => {
                if let Some(value) = gauge_value(series) {
                    row.declared_rules =
                        Some(row.declared_rules.unwrap_or(0).saturating_add(value));
                }
            }
            CHAIN_POLICY => {
                if let Some(value) = state_value(series) {
                    row.policies.insert(if backend == RulesBackend::Nftables {
                        value
                    } else {
                        format!("{table}:{value}")
                    });
                }
            }
            CHAIN_TYPE => {
                if let Some(value) = state_value(series) {
                    row.chain_types.insert(value);
                }
            }
            RULE_EXPRESSION | RULE_POSITION | RULE_PACKETS | RULE_BYTES => {
                if let Some(identity) = rule_identity(series) {
                    row.rule_ids.insert(identity.clone());
                    if matches!(series.metric().as_str(), RULE_PACKETS | RULE_BYTES)
                        && counter_is_available(series)
                    {
                        row.countered_rule_ids.insert(identity);
                    }
                }
                if series.metric().as_str() == RULE_PACKETS {
                    let projection = counter_projection(series, time_view);
                    row.hits.add(projection);
                    match labels.get(MetricLabel::Verdict) {
                        Some("drop") => row.drops.add(projection),
                        Some("reject") => row.rejects.add(projection),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by(|left, right| compare_chains(backend, left, right));
    rows
}

fn rule_rows(
    snapshot: Option<&MonitorSnapshot>,
    backend: RulesBackend,
    chain_key: &ChainKey,
    time_view: TimeView,
) -> Vec<RuleRow> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    let active_rules = snapshot
        .series()
        .iter()
        .filter(|series| series_matches_backend(series, backend))
        .filter(|series| series_matches_chain(series, backend, chain_key))
        .filter_map(|series| match series.metric().as_str() {
            RULE_POSITION if gauge_value(series).is_some() => rule_identity(series),
            RULE_EXPRESSION if state_value(series).is_some() => rule_identity(series),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut rows = BTreeMap::<RuleIdentity, RuleBuilder>::new();
    for series in snapshot
        .series()
        .iter()
        .filter(|series| series_matches_backend(series, backend))
        .filter(|series| series_matches_chain(series, backend, chain_key))
        .filter(|series| {
            matches!(
                series.metric().as_str(),
                RULE_EXPRESSION | RULE_POSITION | RULE_PACKETS | RULE_BYTES
            )
        })
    {
        let Some(identity) = rule_identity(series) else {
            continue;
        };
        if !active_rules.contains(&identity) {
            continue;
        }
        let labels = series.labels();
        let row = rows.entry(identity.clone()).or_insert_with(|| RuleBuilder {
            table: identity.table.clone(),
            verdict: labels.get(MetricLabel::Verdict).unwrap_or("-").to_owned(),
            ..RuleBuilder::default()
        });
        match series.metric().as_str() {
            RULE_EXPRESSION => row.expression = state_value(series),
            RULE_POSITION => row.position = gauge_value(series),
            RULE_PACKETS => row.packets = counter_projection(series, time_view),
            RULE_BYTES => row.bytes = counter_projection(series, time_view),
            _ => {}
        }
    }
    let mut rows = rows
        .into_values()
        .map(|row| RuleRow {
            table: row.table,
            position: row.position,
            expression: row.expression,
            verdict: row.verdict,
            packets: row.packets,
            bytes: row.bytes,
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        table_rank(&left.table)
            .cmp(&table_rank(&right.table))
            .then_with(|| left.table.cmp(&right.table))
            .then_with(|| left.position.cmp(&right.position))
    });
    rows
}

fn series_matches_backend(series: &SeriesSnapshot, backend: RulesBackend) -> bool {
    let labels = series.labels();
    let implementation_matches = labels
        .get(MetricLabel::Backend)
        .is_some_and(|value| backend.matches_label(value));
    implementation_matches
        && match backend {
            RulesBackend::IptablesIpv4 => labels.get(MetricLabel::Family) == Some("ip"),
            RulesBackend::IptablesIpv6 => labels.get(MetricLabel::Family) == Some("ip6"),
            RulesBackend::Nftables => true,
        }
}

fn series_matches_chain(series: &SeriesSnapshot, backend: RulesBackend, key: &ChainKey) -> bool {
    let labels = series.labels();
    labels.get(MetricLabel::Family) == Some(key.family.as_str())
        && labels.get(MetricLabel::Chain) == Some(key.chain.as_str())
        && (backend != RulesBackend::Nftables
            || labels.get(MetricLabel::Table) == key.table.as_deref())
}

fn rule_identity(series: &SeriesSnapshot) -> Option<RuleIdentity> {
    let labels = series.labels();
    Some(RuleIdentity {
        table: labels.get(MetricLabel::Table)?.to_owned(),
        row_id: labels.get(MetricLabel::RowId)?.to_owned(),
        handle: labels.get(MetricLabel::Handle).map(str::to_owned),
    })
}

fn gauge_value(series: &SeriesSnapshot) -> Option<u64> {
    let SeriesValue::Gauge { current, .. } = series.value() else {
        return None;
    };
    projected_value(current)
}

fn state_value(series: &SeriesSnapshot) -> Option<String> {
    let SeriesValue::State { current, .. } = series.value() else {
        return None;
    };
    match current {
        ProjectedValue::Fresh { value, .. } => Some(value.as_str().to_owned()),
        ProjectedValue::Stale { last, .. } => Some(format!("~{}", last.as_str())),
        ProjectedValue::Unavailable { .. } => None,
    }
}

fn counter_projection(series: &SeriesSnapshot, time_view: TimeView) -> CounterProjection {
    let SeriesValue::Counter {
        current,
        interval,
        since_baseline,
    } = series.value()
    else {
        return CounterProjection::default();
    };
    match time_view {
        TimeView::Interval => CounterProjection {
            total: projected_value(current),
            rate: interval.and_then(|value| value.rate_per_second()),
        },
        TimeView::SinceBaseline => CounterProjection {
            total: since_baseline.map(|value| value.delta()),
            rate: since_baseline.map(|value| value.rate_per_second()),
        },
    }
}

fn counter_is_available(series: &SeriesSnapshot) -> bool {
    let SeriesValue::Counter { current, .. } = series.value() else {
        return false;
    };
    projected_value(current).is_some()
}

fn projected_value(value: &ProjectedValue<u64>) -> Option<u64> {
    match value {
        ProjectedValue::Fresh { value, .. } => Some(*value),
        ProjectedValue::Stale { last, .. } => Some(*last),
        ProjectedValue::Unavailable { .. } => None,
    }
}

fn compare_chains(backend: RulesBackend, left: &ChainRow, right: &ChainRow) -> Ordering {
    if backend != RulesBackend::Nftables {
        return chain_rank(left.name())
            .cmp(&chain_rank(right.name()))
            .then_with(|| left.name().cmp(right.name()));
    }
    left.key
        .family
        .cmp(&right.key.family)
        .then_with(|| left.key.table.cmp(&right.key.table))
        .then_with(|| {
            hook_rank(left.hooks.iter().next().map(String::as_str))
                .cmp(&hook_rank(right.hooks.iter().next().map(String::as_str)))
        })
        .then_with(|| priority_value(&left.priorities).cmp(&priority_value(&right.priorities)))
        .then_with(|| left.name().cmp(right.name()))
}

fn chain_rank(chain: &str) -> usize {
    match chain.to_ascii_uppercase().as_str() {
        "PREROUTING" => 0,
        "INPUT" => 1,
        "FORWARD" => 2,
        "OUTPUT" => 3,
        "POSTROUTING" => 4,
        _ => 5,
    }
}

fn hook_rank(hook: Option<&str>) -> usize {
    match hook.unwrap_or("").to_ascii_lowercase().as_str() {
        "ingress" => 0,
        "prerouting" => 1,
        "input" => 2,
        "forward" => 3,
        "output" => 4,
        "postrouting" => 5,
        "egress" => 6,
        _ => 7,
    }
}

fn priority_value(values: &BTreeSet<String>) -> i64 {
    values
        .iter()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(i64::MAX)
}

fn table_rank(table: &str) -> usize {
    match table {
        "raw" => 0,
        "mangle" => 1,
        "nat" => 2,
        "filter" => 3,
        "security" => 4,
        _ => 5,
    }
}

fn next_selection(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        (selected + 1).min(len - 1)
    }
}

fn clamp_selection(selected: usize, len: usize) -> usize {
    selected.min(len.saturating_sub(1))
}

fn conntrack_health(snapshot: Option<&MonitorSnapshot>) -> String {
    let Some(snapshot) = snapshot else {
        return "COLLECTING".to_owned();
    };
    snapshot
        .providers()
        .iter()
        .find(|provider| provider.provider().as_str() == "linux.proc.netfilter.conntrack")
        .map(|provider| provider.health().as_str().to_ascii_uppercase())
        .unwrap_or_else(|| "NO DATA".to_owned())
}

fn backend_health(snapshot: Option<&MonitorSnapshot>, backend: RulesBackend) -> String {
    let Some(snapshot) = snapshot else {
        return "COLLECTING".to_owned();
    };
    snapshot
        .providers()
        .iter()
        .find(|provider| backend.matches_provider(provider.provider().as_str()))
        .map(|provider| health_label(provider.health()).to_owned())
        .unwrap_or_else(|| "NO DATA".to_owned())
}

fn backend_display_name(snapshot: Option<&MonitorSnapshot>, backend: RulesBackend) -> String {
    if backend == RulesBackend::Nftables {
        return backend.title().to_owned();
    }
    let implementation = snapshot
        .into_iter()
        .flat_map(MonitorSnapshot::series)
        .find(|series| {
            series_matches_backend(series, backend)
                && series.metric().as_str() == CHAIN_RULES
                && gauge_value(series).is_some()
        })
        .and_then(|series| series.labels().get(MetricLabel::Backend))
        .and_then(|value| value.strip_prefix("iptables_"));
    implementation.map_or_else(
        || backend.title().to_owned(),
        |implementation| format!("{} ({implementation})", backend.title()),
    )
}

fn health_label(health: &ProviderHealth) -> &'static str {
    match health {
        ProviderHealth::Fresh => "FRESH",
        ProviderHealth::Partial { .. } => "PARTIAL",
        ProviderHealth::Stale { .. } => "STALE",
        ProviderHealth::Unsupported { .. } => "UNSUPPORTED",
        ProviderHealth::PermissionDenied { .. } => "PERMISSION",
        ProviderHealth::Error { .. } => "ERROR",
    }
}

fn join_values(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(",")
}

fn format_optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_owned(), format_count)
}

fn format_count(value: u64) -> String {
    if value >= 1_000_000_000 {
        format!("{:.1}G", value as f64 / 1_000_000_000.0)
    } else if value >= 1_000_000 {
        format!("{:.1}M", value as f64 / 1_000_000.0)
    } else if value >= 1_000 {
        format!("{:.1}K", value as f64 / 1_000.0)
    } else {
        value.to_string()
    }
}

fn format_optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |value| {
            if value >= 1 << 30 {
                format!("{:.1}GiB", value as f64 / (1_u64 << 30) as f64)
            } else if value >= 1 << 20 {
                format!("{:.1}MiB", value as f64 / (1_u64 << 20) as f64)
            } else if value >= 1 << 10 {
                format!("{:.1}KiB", value as f64 / (1_u64 << 10) as f64)
            } else {
                format!("{value}B")
            }
        },
    )
}

fn format_rate(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.1}"))
}

fn format_bit_rate(value: Option<f64>) -> String {
    let Some(value) = value else {
        return "-".to_owned();
    };
    if value >= 1_000_000_000.0 {
        format!("{:.1}G", value / 1_000_000_000.0)
    } else if value >= 1_000_000.0 {
        format!("{:.1}M", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}K", value / 1_000.0)
    } else {
        format!("{value:.0}")
    }
}

fn title_line(title: &str, detail: Option<&str>, width: usize) -> Line<'static> {
    let title = detail.map_or_else(
        || format!(" {title}"),
        |detail| format!(" {title}  [{detail}]"),
    );
    Line::styled(
        fit(&title, width),
        Style::default()
            .fg(theme::TEXT_STRONG)
            .add_modifier(Modifier::BOLD),
    )
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
    base: Style,
) -> Line<'static> {
    let style = if selected {
        base.bg(theme::SELECTED_BG).add_modifier(Modifier::BOLD)
    } else {
        base
    };
    Line::styled(column_owned(&values, columns, width), style)
}

fn plain_line<const N: usize>(
    values: [String; N],
    columns: &[usize; N],
    width: usize,
    style: Style,
) -> Line<'static> {
    Line::styled(column_owned(&values, columns, width), style)
}

fn column_owned<const N: usize>(
    values: &[String; N],
    columns: &[usize; N],
    width: usize,
) -> String {
    let mut output = String::new();
    for index in 0..N {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&fit(&values[index], columns[index]));
    }
    fit(&output, width)
}

fn menu_columns(width: usize) -> [usize; 5] {
    distribute_columns(width, [25, 20, 10, 10, 15])
}

fn chain_columns(width: usize) -> [usize; 8] {
    distribute_columns(width, [18, 24, 18, 20, 8, 10, 12, 14])
}

fn rule_columns(width: usize) -> [usize; 8] {
    distribute_columns(width, [14, 6, 38, 12, 10, 12, 12, 14])
}

fn distribute_columns<const N: usize>(width: usize, desired: [usize; N]) -> [usize; N] {
    let available = width.saturating_sub(N.saturating_sub(1));
    let desired_total = desired.iter().sum::<usize>();
    if available >= desired_total {
        let mut result = desired;
        result[N - 1] = result[N - 1].saturating_add(available - desired_total);
        return result;
    }
    if available == 0 {
        return [0; N];
    }
    let mut result =
        std::array::from_fn(|index| desired[index].saturating_mul(available) / desired_total);
    let remainder = available.saturating_sub(result.iter().sum::<usize>());
    for column in result.iter_mut().take(remainder) {
        *column = column.saturating_add(1);
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::monitor::session::MonitorEngine;
    use crate::monitor::{
        MetricId, MetricLabels, MetricReading, ProviderHealth, ProviderId, ProviderSample,
        SampleReading, StateValue,
    };

    use super::*;

    #[test]
    fn navigation_is_menu_chain_rules_and_back() {
        let mut state = NetfilterViewState::default();
        assert_eq!(state.breadcrumb(), "NETFILTER");

        state.enter(None);
        assert!(state.is_conntrack());
        assert!(!state.back());

        state.move_down(None);
        state.enter(None);
        assert_eq!(
            state.page,
            NetfilterPage::Chains(RulesBackend::IptablesIpv4)
        );
        state.enter(None);
        assert_eq!(
            state.page,
            NetfilterPage::Chains(RulesBackend::IptablesIpv4)
        );
        assert!(!state.back());
        assert!(state.back());
    }

    #[test]
    fn iptables_groups_tables_by_chain_but_nft_keeps_table_identity() {
        let snapshot = sample_snapshot();
        let iptables = chain_rows(
            Some(&snapshot),
            RulesBackend::IptablesIpv4,
            TimeView::Interval,
        );
        assert_eq!(iptables.len(), 1);
        assert_eq!(iptables[0].name(), "INPUT");
        assert_eq!(
            iptables[0].tables.iter().cloned().collect::<Vec<_>>(),
            ["filter", "mangle"]
        );
        assert_eq!(iptables[0].rules(), 2);

        let nft = chain_rows(Some(&snapshot), RulesBackend::Nftables, TimeView::Interval);
        assert_eq!(nft.len(), 2);
        assert_ne!(nft[0].key.table, nft[1].key.table);
    }

    #[test]
    fn rule_without_counter_is_retained_and_rendered_as_unknown() {
        let snapshot = sample_snapshot();
        let key = ChainKey {
            family: "ip".to_owned(),
            table: Some("fw-a".to_owned()),
            chain: "input".to_owned(),
        };
        let rows = rule_rows(
            Some(&snapshot),
            RulesBackend::Nftables,
            &key,
            TimeView::Interval,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].expression.as_deref(), Some("tcp dport 443 accept"));
        assert_eq!(rows[0].packets.total, None);
        let rendered = rule_lines(
            Some(&snapshot),
            RulesBackend::Nftables,
            Some(&key),
            TimeView::Interval,
            160,
        )
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
        assert!(rendered.contains("NO COUNTER"), "{rendered}");
    }

    #[test]
    fn fixed_columns_fill_supported_widths_without_pipe_separators() {
        for width in [60, 80, 100, 120, 160] {
            for columns in [
                menu_columns(width),
                distribute_columns(width, [18, 24, 18, 20, 8]),
                distribute_columns(width, [14, 6, 38, 12, 10]),
            ] {
                assert_eq!(columns.iter().sum::<usize>() + columns.len() - 1, width);
                let values = std::array::from_fn(|index| format!("column-{index}"));
                let rendered = column_owned(&values, &columns, width);
                assert_eq!(rendered.chars().count(), width);
                assert!(!rendered.contains('|'));
            }
            assert_eq!(chain_columns(width).iter().sum::<usize>() + 7, width);
            assert_eq!(rule_columns(width).iter().sum::<usize>() + 7, width);
        }
    }

    fn sample_snapshot() -> std::sync::Arc<MonitorSnapshot> {
        let interval = Duration::from_secs(1);
        let mut engine = MonitorEngine::new(1, interval).unwrap();
        engine
            .ingest(interval, samples(1, 10, 1_000), Some("net:[1]".to_owned()))
            .unwrap();
        engine
            .ingest(
                interval * 2,
                samples(2, 20, 2_000),
                Some("net:[1]".to_owned()),
            )
            .unwrap()
    }

    fn samples(at: u64, packets: u64, bytes: u64) -> Vec<ProviderSample> {
        vec![
            provider_sample(
                "linux.iptables.ipv4",
                at,
                vec![
                    gauge(
                        CHAIN_RULES,
                        chain_labels("iptables_nft", "ip", "filter", "INPUT"),
                        1,
                    ),
                    gauge(
                        CHAIN_RULES,
                        chain_labels("iptables_nft", "ip", "mangle", "INPUT"),
                        1,
                    ),
                    counter(
                        RULE_PACKETS,
                        rule_labels("iptables_nft", "ip", "filter", "INPUT", "1", "drop"),
                        packets,
                    ),
                    counter(
                        RULE_BYTES,
                        rule_labels("iptables_nft", "ip", "filter", "INPUT", "1", "drop"),
                        bytes,
                    ),
                ],
            ),
            provider_sample(
                "linux.nft.ruleset",
                at,
                vec![
                    gauge(
                        CHAIN_RULES,
                        chain_labels("nftables", "ip", "fw-a", "input"),
                        1,
                    ),
                    gauge(
                        CHAIN_RULES,
                        chain_labels("nftables", "ip", "fw-b", "input"),
                        0,
                    ),
                    gauge(
                        RULE_POSITION,
                        rule_labels("nftables", "ip", "fw-a", "input", "1", "accept"),
                        1,
                    ),
                    state(
                        RULE_EXPRESSION,
                        rule_labels("nftables", "ip", "fw-a", "input", "1", "accept"),
                        "tcp dport 443 accept",
                    ),
                ],
            ),
        ]
    }

    fn provider_sample(provider: &str, at: u64, readings: Vec<SampleReading>) -> ProviderSample {
        ProviderSample::new(
            ProviderId::new(provider).unwrap(),
            Duration::from_secs(at),
            Duration::from_millis(1),
            ProviderHealth::Fresh,
            readings,
        )
        .unwrap()
    }

    fn chain_labels(backend: &str, family: &str, table: &str, chain: &str) -> MetricLabels {
        MetricLabels::new([
            (MetricLabel::Backend, backend.to_owned()),
            (MetricLabel::Family, family.to_owned()),
            (MetricLabel::Table, table.to_owned()),
            (MetricLabel::Chain, chain.to_owned()),
        ])
        .unwrap()
    }

    fn rule_labels(
        backend: &str,
        family: &str,
        table: &str,
        chain: &str,
        row_id: &str,
        verdict: &str,
    ) -> MetricLabels {
        MetricLabels::new([
            (MetricLabel::Backend, backend.to_owned()),
            (MetricLabel::Family, family.to_owned()),
            (MetricLabel::Table, table.to_owned()),
            (MetricLabel::Chain, chain.to_owned()),
            (MetricLabel::RowId, row_id.to_owned()),
            (MetricLabel::Verdict, verdict.to_owned()),
        ])
        .unwrap()
    }

    fn gauge(metric: &str, labels: MetricLabels, value: u64) -> SampleReading {
        SampleReading::observed(
            MetricId::new(metric).unwrap(),
            labels,
            MetricReading::Gauge(value),
        )
    }

    fn counter(metric: &str, labels: MetricLabels, value: u64) -> SampleReading {
        SampleReading::observed(
            MetricId::new(metric).unwrap(),
            labels,
            MetricReading::Counter { value, bits: None },
        )
    }

    fn state(metric: &str, labels: MetricLabels, value: &str) -> SampleReading {
        SampleReading::observed(
            MetricId::new(metric).unwrap(),
            labels,
            MetricReading::State(StateValue::new(value).unwrap()),
        )
    }
}
