//! Snapshot-local interface presentation. Rebuild on snapshot/inventory/time-view changes;
//! sorting, scrolling and rendering then touch only the cached interface rows.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Range;

use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_segmentation::UnicodeSegmentation;

use crate::monitor::dashboard::InterfaceIdentity;
use crate::monitor::{
    CounterContinuity, MetricLabel, MonitorSnapshot, ProjectedValue, ProviderHealth,
    SeriesSnapshot, SeriesValue, UnavailableReason, NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
    RAW_NIC_SETTING_METRIC_ID,
};

use super::app::TimeView;
use super::{module_frame, theme};

const COUNTERS: [&str; 8] = [
    "linux.netdevice.rx_bytes",
    "linux.netdevice.tx_bytes",
    "linux.netdevice.rx_packets",
    "linux.netdevice.tx_packets",
    "linux.netdevice.rx_dropped",
    "linux.netdevice.tx_dropped",
    "linux.netdevice.rx_errors",
    "linux.netdevice.tx_errors",
];
const SETTINGS: [&str; 27] = [
    "Driver",
    "Speed",
    "Duplex",
    "Auto-negotiation",
    "RX Queues",
    "TX Queues",
    "Ring RX",
    "Ring TX",
    "TX Queue Length",
    "MTU",
    "TSO",
    "LRO",
    "GRO",
    "GSO",
    "Flow Control RX",
    "Flow Control TX",
    "Link",
    "Qdisc",
    "Channel RX",
    "Channel TX",
    "Queue source",
    "Sysfs Speed",
    "Sysfs Duplex",
    "Sysfs Link detected",
    "Fallback Ring RX",
    "Fallback Ring TX",
    "Sysfs Driver",
];

fn core_setting(index: usize) -> bool {
    matches!(index, 9 | 16) // MTU and link state come from the core link inventory.
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum NetdevSort {
    #[default]
    Ifindex,
    Name,
    RxBytes,
    TxBytes,
    RxPackets,
    TxPackets,
    RxDrops,
    TxDrops,
    RxErrors,
    TxErrors,
    Drops,
    Errors,
}

impl NetdevSort {
    pub(super) const ALL: [Self; 12] = [
        Self::Ifindex,
        Self::Name,
        Self::RxBytes,
        Self::TxBytes,
        Self::RxPackets,
        Self::TxPackets,
        Self::RxDrops,
        Self::TxDrops,
        Self::RxErrors,
        Self::TxErrors,
        Self::Drops,
        Self::Errors,
    ];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Ifindex => "ifindex",
            Self::Name => "name",
            Self::RxBytes => "RX bytes",
            Self::TxBytes => "TX bytes",
            Self::RxPackets => "RX packets",
            Self::TxPackets => "TX packets",
            Self::RxDrops => "RX drops",
            Self::TxDrops => "TX drops",
            Self::RxErrors => "RX errors",
            Self::TxErrors => "TX errors",
            Self::Drops => "RX+TX drops",
            Self::Errors => "RX+TX errors",
        }
    }

    pub(super) const fn default_descending(self) -> bool {
        !matches!(self, Self::Ifindex | Self::Name)
    }

    pub(super) fn next(self) -> Self {
        let index = Self::ALL.iter().position(|sort| *sort == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    fn counter_index(self) -> Option<usize> {
        match self {
            Self::RxBytes => Some(0),
            Self::TxBytes => Some(1),
            Self::RxPackets => Some(2),
            Self::TxPackets => Some(3),
            Self::RxDrops => Some(4),
            Self::TxDrops => Some(5),
            Self::RxErrors => Some(6),
            Self::TxErrors => Some(7),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NetdevHit {
    Sort(NetdevSort),
    Interface(InterfaceIdentity),
}

#[derive(Clone, Copy, Debug)]
enum Number {
    Rate(f64),
    // Keep totals integral for sorting, including totals above f64's exact range.
    Total(u128),
}

impl Number {
    fn compare(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Rate(a), Self::Rate(b)) => a.total_cmp(&b),
            (Self::Total(a), Self::Total(b)) => a.cmp(&b),
            _ => unreachable!("a table has one time projection"),
        }
    }

    fn add(self, other: Self) -> Self {
        match (self, other) {
            (Self::Rate(a), Self::Rate(b)) => Self::Rate(a + b),
            (Self::Total(a), Self::Total(b)) => Self::Total(a + b),
            _ => unreachable!("a table has one time projection"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
enum Health {
    Fresh,
    Partial,
    #[default]
    Missing,
    Stale,
    Unsupported,
    Denied,
    Error,
}

impl Health {
    fn from_source(health: Option<&ProviderHealth>) -> Self {
        match health {
            Some(ProviderHealth::Fresh) => Self::Fresh,
            Some(ProviderHealth::Partial { .. }) => Self::Partial,
            Some(ProviderHealth::Stale { .. }) => Self::Stale,
            Some(ProviderHealth::Unsupported { .. }) => Self::Unsupported,
            Some(ProviderHealth::PermissionDenied { .. }) => Self::Denied,
            Some(ProviderHealth::Error { .. }) => Self::Error,
            None => Self::Missing,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Partial => "partial",
            Self::Missing => "n/a",
            Self::Stale => "stale",
            Self::Unsupported => "unsup",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CounterCell {
    value: Option<Number>,
    missing: &'static str,
    health: Health,
}

impl Default for CounterCell {
    fn default() -> Self {
        Self {
            value: None,
            missing: "n/a",
            health: Health::Missing,
        }
    }
}

impl CounterCell {
    fn new(series: &SeriesSnapshot, source: Health, time_view: TimeView) -> Self {
        let mut cell = Self::default();
        let SeriesValue::Counter {
            current,
            interval,
            since_baseline,
        } = series.value()
        else {
            return cell;
        };
        cell.health = source;
        match current {
            ProjectedValue::Stale { .. } => {
                cell.health = source.max(Health::Stale);
                cell.missing = cell.health.label();
                return cell;
            }
            ProjectedValue::Unavailable { .. } => {
                cell.health = source.max(Health::Missing);
                cell.missing = cell.health.label();
                return cell;
            }
            ProjectedValue::Fresh { .. } if source > Health::Partial => {
                cell.missing = source.label();
                return cell;
            }
            ProjectedValue::Fresh { .. } => {}
        }
        cell.value = match time_view {
            TimeView::Interval => interval
                .and_then(CounterContinuity::rate_per_second)
                .map(Number::Rate),
            TimeView::SinceBaseline => {
                since_baseline.map(|span| Number::Total(span.delta().into()))
            }
        };
        if cell.value.is_none() {
            cell.missing = match interval {
                Some(CounterContinuity::Reset) => "reset",
                Some(CounterContinuity::RecoveredAfterGap) => "gap",
                Some(CounterContinuity::FirstSample) | None => "first",
                _ => "n/a",
            };
            cell.health = source.max(Health::Missing);
        }
        cell
    }

    fn add(self, other: Self) -> Self {
        Self {
            value: self.value.zip(other.value).map(|(a, b)| a.add(b)),
            missing: if self.value.is_none() {
                self.missing
            } else {
                other.missing
            },
            health: self.health.max(other.health),
        }
    }

    fn display(self, bandwidth: bool, width: usize) -> String {
        let Some(number) = self.value else {
            return self.missing.to_owned();
        };
        let (text, value) = match number {
            Number::Rate(value) => {
                let value = if bandwidth {
                    value * 8.0 / 1_000_000.0
                } else {
                    value
                };
                (format!("{value:.2}"), value)
            }
            Number::Total(value) => (value.to_string(), value as f64),
        };
        if text.len() <= width {
            text
        } else {
            // Scientific notation keeps the column's explicit unit, unlike a hidden suffix.
            format!("{value:.2e}")
        }
    }
}

#[derive(Clone, Debug)]
struct SettingCell {
    text: String,
    health: Health,
}

impl Default for SettingCell {
    fn default() -> Self {
        Self {
            text: "n/a".to_owned(),
            health: Health::Missing,
        }
    }
}

impl SettingCell {
    fn new(series: &SeriesSnapshot, source: Health) -> Self {
        match series.value() {
            SeriesValue::State { current, .. } => {
                Self::projected(current, source, |value| value.as_str().to_owned())
            }
            SeriesValue::Gauge { current, .. } => Self::projected(current, source, u64::to_string),
            _ => Self::default(),
        }
    }

    fn projected<T>(
        current: &ProjectedValue<T>,
        source: Health,
        text: impl Fn(&T) -> String,
    ) -> Self {
        match current {
            ProjectedValue::Fresh { value, .. } if source <= Health::Partial => Self {
                text: text(value),
                health: source,
            },
            ProjectedValue::Stale { last, .. } => Self {
                text: format!("~{}", text(last)),
                health: match source {
                    Health::Denied | Health::Error => source,
                    _ => Health::Stale,
                },
            },
            ProjectedValue::Unavailable { reason } => {
                let health = match reason {
                    UnavailableReason::InvalidValue | UnavailableReason::Overflow => Health::Error,
                    UnavailableReason::CardinalityLimit => Health::Partial,
                    _ if source == Health::Fresh => Health::Missing,
                    _ => source,
                };
                let health = if matches!(source, Health::Denied | Health::Error) {
                    health.max(source)
                } else {
                    health
                };
                Self {
                    text: health.label().to_owned(),
                    health,
                }
            }
            _ => Self {
                text: source.max(Health::Missing).label().to_owned(),
                health: source.max(Health::Missing),
            },
        }
    }
}

#[derive(Clone, Debug, Default)]
struct InterfaceRow {
    counters: [CounterCell; 8],
    settings: [SettingCell; 27],
    settings_health: Option<Health>,
}

#[derive(Default)]
struct PendingRow<'a> {
    row: InterfaceRow,
    settings: [Option<&'a SeriesSnapshot>; 27],
    settings_status: Option<&'a SeriesSnapshot>,
}

impl InterfaceRow {
    fn queue_cells(&self) -> (usize, usize, &'static str) {
        let source = &self.settings[20];
        if source.health == Health::Fresh
            && source.text == "ethtool"
            && self.settings[18].health == Health::Fresh
            && self.settings[19].health == Health::Fresh
        {
            return (18, 19, "");
        }
        let valid = self.settings[4].health <= Health::Partial
            && self.settings[5].health <= Health::Partial;
        let suffix = if valid && source.health == Health::Fresh && source.text == "fixed" {
            " fixed"
        } else if valid {
            " sysfs"
        } else {
            ""
        };
        (4, 5, suffix)
    }

    fn counter(&self, sort: NetdevSort) -> CounterCell {
        match sort {
            NetdevSort::Drops => self.counters[4].add(self.counters[5]),
            NetdevSort::Errors => self.counters[6].add(self.counters[7]),
            _ => sort
                .counter_index()
                .map_or_else(CounterCell::default, |i| self.counters[i]),
        }
    }

    fn health(&self, configuration: bool) -> Health {
        let (worst, observed) = if configuration {
            self.settings
                .iter()
                .enumerate()
                .filter(|(index, cell)| core_setting(*index) || !optional_absence(cell.health))
                .map(|(_, cell)| cell.health)
                .chain(
                    self.settings_health
                        .filter(|health| !optional_absence(*health)),
                )
                .fold((Health::Fresh, false), fold_health)
        } else {
            self.counters
                .iter()
                .map(|cell| cell.health)
                .fold((Health::Fresh, false), fold_health)
        };
        if worst == Health::Missing && observed {
            Health::Partial
        } else {
            worst
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct NetdevTable {
    rows: BTreeMap<InterfaceIdentity, InterfaceRow>,
    time_view: TimeView,
}

impl NetdevTable {
    pub(super) fn new(
        snapshot: &MonitorSnapshot,
        inventory: &[InterfaceIdentity],
        time_view: TimeView,
    ) -> Self {
        let mut indexed = inventory
            .iter()
            .map(|identity| {
                (
                    (identity.ifindex().get(), identity.name()),
                    (identity, PendingRow::default()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let sources = snapshot
            .providers()
            .iter()
            .map(|provider| {
                (
                    provider.provider(),
                    Health::from_source(Some(provider.health())),
                )
            })
            .collect::<BTreeMap<_, _>>();
        // One pass, with an exact (ifindex, name) match. Names alone can be reused.
        for series in snapshot.series() {
            let metric = series.metric().as_str();
            let settings_status = metric == NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID
                && series.source().as_str() == "linux.ethtool.link_text";
            let qdisc = metric.starts_with("linux.tc.")
                && series.labels().get(MetricLabel::ObjectKind) == Some("qdisc")
                && series.labels().get(MetricLabel::Direction) == Some("egress")
                && series
                    .labels()
                    .get(MetricLabel::QdiscAttachment)
                    .and_then(|value| {
                        serde_json::from_str::<(bool, Option<String>, Option<String>)>(value).ok()
                    })
                    .is_some_and(|(root, _, _)| root);
            let counter = COUNTERS.iter().position(|candidate| *candidate == metric);
            let setting = if metric == RAW_NIC_SETTING_METRIC_ID {
                series
                    .labels()
                    .get(MetricLabel::Statistic)
                    .and_then(|name| SETTINGS.iter().position(|candidate| *candidate == name))
            } else if metric == "linux.nic.link_state" {
                Some(16)
            } else if metric == "linux.nic.mtu" {
                Some(9)
            } else {
                None
            };
            if counter.is_none() && setting.is_none() && !qdisc && !settings_status {
                continue;
            }
            let Some(name) = series.labels().get(MetricLabel::Interface) else {
                continue;
            };
            let Some(index) = series
                .labels()
                .get(MetricLabel::Ifindex)
                .and_then(|value| value.parse().ok())
            else {
                continue;
            };
            let Some((_, pending)) = indexed.get_mut(&(index, name)) else {
                continue;
            };
            let source = sources.get(series.source()).copied().unwrap_or_default();
            let row = &mut pending.row;
            if let Some(index) = counter {
                row.counters[index] = CounterCell::new(series, source, time_view);
            }
            if let Some(index) = setting {
                pending.settings[index] = Some(series);
            }
            if settings_status {
                pending.settings_status = Some(series);
            }
            if qdisc {
                if let Some(kind) = series.labels().get(MetricLabel::QdiscKind) {
                    let health = match series.value() {
                        SeriesValue::Counter { current, .. }
                        | SeriesValue::Gauge { current, .. } => match current {
                            ProjectedValue::Fresh { .. } => source,
                            ProjectedValue::Stale { .. } => source.max(Health::Stale),
                            ProjectedValue::Unavailable { .. } => source.max(Health::Missing),
                        },
                        _ => Health::Missing,
                    };
                    let cell = &mut row.settings[17];
                    let text = match health {
                        Health::Fresh | Health::Partial => kind.to_owned(),
                        Health::Stale => format!("~{kind}"),
                        _ => health.label().to_owned(),
                    };
                    if cell.health == Health::Missing || health < cell.health {
                        *cell = SettingCell { text, health };
                    } else if health == cell.health
                        && cell.text != text
                        && health <= Health::Partial
                    {
                        cell.text = "multi".to_owned();
                    }
                }
            }
        }
        Self {
            rows: indexed
                .into_values()
                .map(|(identity, mut pending)| {
                    pending.row.settings_health = pending.settings_status.map(|series| {
                        settings_health(
                            series,
                            sources.get(series.source()).copied().unwrap_or_default(),
                        )
                    });
                    for (index, series) in pending.settings.into_iter().enumerate() {
                        if let Some(series) = series {
                            let mut source =
                                sources.get(series.source()).copied().unwrap_or_default();
                            // A per-interface result can explain an aggregate partial
                            // ethtool poll without assigning another interface's failure here.
                            if series.source().as_str() == "linux.ethtool.link_text"
                                && source <= Health::Partial
                            {
                                source = if index >= 18 {
                                    // Channels and fallbacks are observed independently of basic settings.
                                    Health::Fresh
                                } else {
                                    pending.row.settings_health.unwrap_or(source)
                                };
                            }
                            pending.row.settings[index] = SettingCell::new(series, source);
                        }
                    }
                    for (primary, fallback) in [(0, 26), (1, 21), (2, 22), (6, 24), (7, 25)] {
                        let cell = &pending.row.settings[primary];
                        if (cell.health > Health::Partial || cell.text.starts_with("Unknown"))
                            && pending.row.settings[fallback].health <= Health::Partial
                        {
                            pending.row.settings[primary] = pending.row.settings[fallback].clone();
                        }
                    }
                    (identity.clone(), pending.row)
                })
                .collect(),
            time_view,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Unknown values remain last in either direction; ties use ascending identity.
    pub(super) fn ordered_interfaces(
        &self,
        sort: NetdevSort,
        descending: bool,
    ) -> Vec<InterfaceIdentity> {
        let mut rows = self.rows.iter().collect::<Vec<_>>();
        rows.sort_by(|(a, av), (b, bv)| {
            let ordering = match sort {
                NetdevSort::Ifindex => direction(a.ifindex().cmp(&b.ifindex()), descending),
                NetdevSort::Name => direction(a.name().cmp(b.name()), descending),
                _ => match (av.counter(sort).value, bv.counter(sort).value) {
                    (Some(a), Some(b)) => direction(a.compare(b), descending),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                },
            };
            ordering.then_with(|| a.cmp(b))
        });
        rows.into_iter()
            .map(|(identity, _)| identity.clone())
            .collect()
    }

    /// Height for a complete batch, including stationary traffic/configuration headers.
    pub(super) fn row_count(width: u16, count: usize) -> usize {
        let border = usize::from(width >= 2);
        if count == 0 {
            return 3 + border;
        }
        let tables = if width >= 160 { 2_usize } else { 3 };
        tables
            .saturating_mul(count.saturating_add(2))
            .saturating_add(border)
    }

    pub(super) fn visible_capacity(width: u16, height: u16) -> usize {
        let tables = if width >= 160 { 2 } else { 3 };
        usize::from(height).saturating_sub(2 * tables + usize::from(width >= 2)) / tables
    }

    /// `visible` indexes `ordered`, so both tables always render the identical batch.
    #[cfg(test)]
    pub(super) fn lines(
        &self,
        width: u16,
        ordered: &[InterfaceIdentity],
        visible: Range<usize>,
        selected: Option<&InterfaceIdentity>,
    ) -> Vec<Line<'static>> {
        self.lines_sorted(
            width,
            ordered,
            visible,
            selected,
            NetdevSort::Ifindex,
            false,
        )
    }

    pub(super) fn lines_sorted(
        &self,
        width: u16,
        ordered: &[InterfaceIdentity],
        visible: Range<usize>,
        selected: Option<&InterfaceIdentity>,
        sort: NetdevSort,
        descending: bool,
    ) -> Vec<Line<'static>> {
        let content_width = module_frame::inner_width(width);
        let visible = clamped_range(visible, ordered.len());
        let batch = &ordered[visible.clone()];
        let traffic = traffic_columns(width, self.time_view);
        let note = match self.time_view {
            TimeView::Interval => "Mb/s; packets/drop/error per second",
            TimeView::SinceBaseline => "bytes/packets/drop/error since baseline",
        };
        let note = if width < 120 {
            format!("{note}; drop/error RX+TX")
        } else {
            note.to_owned()
        };
        let range = if batch.is_empty() {
            format!("0/{}", ordered.len())
        } else {
            format!("{}-{}/{}", visible.start + 1, visible.end, ordered.len())
        };
        let mut lines = vec![
            band(&format!(" INTERFACE  {range}  {note}"), content_width),
            header(&traffic, Some((sort, descending))),
        ];
        if batch.is_empty() {
            lines.push(band("No interfaces in this batch", content_width));
            return module_frame::lines(lines, width);
        }
        for identity in batch {
            lines.push(self.row_line(identity, &traffic, selected, Some(sort)));
        }
        let config = configuration_columns(width, false);
        lines.push(band(
            if width >= 160 {
                "CONFIGURATION  current; R/T = RX/TX; ring: descriptors"
            } else {
                "CONFIGURATION / LINK + QUEUES  current; ring: descriptors"
            },
            content_width,
        ));
        lines.push(header(&config, None));
        for identity in batch {
            lines.push(self.row_line(identity, &config, selected, None));
        }
        if width < 160 {
            let features = configuration_columns(width, true);
            lines.push(band(
                "CONFIGURATION / OFFLOAD  current; PAUSE R/T = RX/TX",
                content_width,
            ));
            lines.push(header(&features, None));
            for identity in batch {
                lines.push(self.row_line(identity, &features, selected, None));
            }
        }
        module_frame::lines(lines, width)
    }

    pub(super) fn header_at(width: u16, x: u16) -> Option<NetdevSort> {
        if x == 0 || x >= width.saturating_sub(1) {
            return None;
        }
        let x = x - 1;
        let mut start = 0;
        for column in traffic_columns(width, TimeView::Interval) {
            if (start..start + column.width).contains(&usize::from(x)) {
                return match column.field {
                    Field::Traffic(sort) => Some(sort),
                    _ => None,
                };
            }
            start += column.width + 1;
        }
        None
    }

    /// Coordinates are relative to `lines()`, not the terminal. Config headings never sort.
    pub(super) fn hit_test(
        &self,
        width: u16,
        ordered: &[InterfaceIdentity],
        visible: Range<usize>,
        x: u16,
        y: u16,
    ) -> Option<NetdevHit> {
        if x == 0 || x >= width.saturating_sub(1) {
            return None;
        }
        let visible = clamped_range(visible, ordered.len());
        if y == 1 {
            return Self::header_at(width, x).map(NetdevHit::Sort);
        }
        let count = visible.len();
        if count == 0 {
            return None;
        }
        let tables = if width >= 160 { 2 } else { 3 };
        let y = usize::from(y);
        if y >= tables * (count + 2) {
            return None;
        }
        let row = (y % (count + 2)).checked_sub(2)?;
        ordered
            .get(visible.start + row)
            .filter(|id| self.rows.contains_key(*id))
            .cloned()
            .map(NetdevHit::Interface)
    }

    fn row_line(
        &self,
        identity: &InterfaceIdentity,
        columns: &[Column],
        selected: Option<&InterfaceIdentity>,
        active_sort: Option<NetdevSort>,
    ) -> Line<'static> {
        let absent;
        let row = match self.rows.get(identity) {
            Some(row) => row,
            None => {
                absent = InterfaceRow::default();
                &absent
            }
        };
        let mut spans = Vec::with_capacity(columns.len() * 2);
        for (index, column) in columns.iter().enumerate() {
            if index > 0 {
                spans.push(Span::styled(
                    "\u{2502}",
                    Style::default().fg(theme::DIVIDER),
                ));
            }
            let (value, mut style) = match column.field {
                Field::Traffic(NetdevSort::Ifindex) => (
                    identity.ifindex().get().to_string(),
                    Style::default().fg(theme::MUTED),
                ),
                Field::Traffic(NetdevSort::Name) | Field::Name => (
                    identity.name().to_owned(),
                    Style::default().fg(theme::TEXT_STRONG),
                ),
                Field::Traffic(sort) => {
                    let cell = row.counter(sort);
                    let color = match sort {
                        NetdevSort::RxBytes | NetdevSort::RxPackets => theme::RX,
                        NetdevSort::TxBytes | NetdevSort::TxPackets => theme::TX,
                        _ if cell.value.is_some_and(|v| {
                            v.compare(match v {
                                Number::Rate(_) => Number::Rate(0.0),
                                Number::Total(_) => Number::Total(0),
                            }) == Ordering::Greater
                        }) =>
                        {
                            theme::WARN
                        }
                        _ => theme::TEXT,
                    };
                    (
                        cell.display(
                            matches!(sort, NetdevSort::RxBytes | NetdevSort::TxBytes),
                            column.width,
                        ),
                        Style::default().fg(if cell.value.is_none() {
                            theme::WARN
                        } else {
                            color
                        }),
                    )
                }
                Field::Setting(setting) => {
                    let cell = &row.settings[setting];
                    (
                        setting_text(setting, &cell.text),
                        setting_style(setting, cell.health),
                    )
                }
                Field::Pair(a, b) => {
                    let (a, b, suffix) = if (a, b) == (4, 5) {
                        row.queue_cells()
                    } else {
                        (a, b, "")
                    };
                    let left = row.settings[a].health;
                    let right = row.settings[b].health;
                    let health = [left, right]
                        .into_iter()
                        .filter(|health| !optional_absence(*health) && *health != Health::Fresh)
                        .max()
                        .unwrap_or_else(|| left.max(right));
                    (
                        format!(
                            "{}/{}{suffix}",
                            setting_text(a, &row.settings[a].text),
                            setting_text(b, &row.settings[b].text)
                        ),
                        setting_style(a, health),
                    )
                }
                Field::Health(configuration) => {
                    let health = row.health(configuration);
                    (
                        health.label().to_owned(),
                        Style::default().fg(if health == Health::Fresh {
                            theme::GOOD
                        } else {
                            theme::WARN
                        }),
                    )
                }
            };
            if selected == Some(identity) {
                style = style.bg(theme::SELECTED_BG);
            }
            if active_sort.is_some_and(
                |sort| matches!(column.field, Field::Traffic(column_sort) if column_sort == sort),
            ) {
                style = style
                    .bg(theme::SORT_BG)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
            }
            spans.push(Span::styled(fit(&value, column.width, column.right), style));
        }
        let mut line = Line::from(spans);
        if selected == Some(identity) {
            super::sort_table::select(&mut line);
        }
        line
    }
}

fn direction(ordering: Ordering, descending: bool) -> Ordering {
    if descending {
        ordering.reverse()
    } else {
        ordering
    }
}

fn optional_absence(health: Health) -> bool {
    matches!(health, Health::Missing | Health::Unsupported)
}

fn setting_style(index: usize, health: Health) -> Style {
    Style::default().fg(if !core_setting(index) && optional_absence(health) {
        theme::MUTED
    } else if health == Health::Fresh {
        theme::TEXT
    } else {
        theme::WARN
    })
}

fn settings_health(series: &SeriesSnapshot, source: Health) -> Health {
    let SeriesValue::State {
        current: ProjectedValue::Fresh { value, .. },
        ..
    } = series.value()
    else {
        return SettingCell::new(series, source).health;
    };
    if source > Health::Partial {
        return source;
    }
    match value.as_str() {
        "complete" => Health::Fresh,
        "unsupported" => Health::Unsupported,
        "refresh_pending" => Health::Missing,
        "permission_denied" => Health::Denied,
        "partial_schema_mismatch" | "partial_cardinality_limit" => Health::Partial,
        _ => Health::Error,
    }
}

fn fold_health((worst, observed): (Health, bool), health: Health) -> (Health, bool) {
    (worst.max(health), observed || health < Health::Missing)
}

fn clamped_range(range: Range<usize>, len: usize) -> Range<usize> {
    let start = range.start.min(len);
    start..range.end.min(len).max(start)
}

fn setting_text(index: usize, text: &str) -> String {
    if index == 1 {
        return text
            .strip_suffix("Mb/s")
            .unwrap_or(text)
            .trim_end()
            .to_owned();
    }
    if index == 3 || (10..=15).contains(&index) {
        let value = text.split_ascii_whitespace().next().unwrap_or("n/a");
        return if text.ends_with("[fixed]") {
            format!("{value} fixed")
        } else {
            value.to_owned()
        };
    }
    text.to_owned()
}

#[derive(Clone, Copy)]
enum Field {
    Traffic(NetdevSort),
    Name,
    Setting(usize),
    Pair(usize, usize),
    Health(bool),
}

struct Column {
    field: Field,
    label: &'static str,
    width: usize,
    right: bool,
}

impl Column {
    fn new(field: Field, label: &'static str, width: usize, right: bool) -> Self {
        Self {
            field,
            label,
            width,
            right,
        }
    }
}

fn traffic_columns(width: u16, time_view: TimeView) -> Vec<Column> {
    use NetdevSort::*;
    let interval = time_view == TimeView::Interval;
    let mut columns = vec![
        Column::new(Field::Traffic(Ifindex), "INDEX", 5, true),
        Column::new(Field::Traffic(Name), "IFACE", 11, false),
        Column::new(
            Field::Traffic(RxBytes),
            if interval { "RX Mb/s" } else { "RX bytes" },
            9,
            true,
        ),
        Column::new(
            Field::Traffic(TxBytes),
            if interval { "TX Mb/s" } else { "TX bytes" },
            9,
            true,
        ),
        Column::new(
            Field::Traffic(RxPackets),
            if interval { "RX pps" } else { "RX pkts" },
            9,
            true,
        ),
        Column::new(
            Field::Traffic(TxPackets),
            if interval { "TX pps" } else { "TX pkts" },
            9,
            true,
        ),
    ];
    if width >= 120 {
        for (sort, rate_label, total_label) in [
            (RxDrops, "RX drop/s", "RX drop"),
            (TxDrops, "TX drop/s", "TX drop"),
            (RxErrors, "RX err/s", "RX err"),
            (TxErrors, "TX err/s", "TX err"),
        ] {
            columns.push(Column::new(
                Field::Traffic(sort),
                if interval { rate_label } else { total_label },
                9,
                true,
            ));
        }
        columns.push(Column::new(Field::Health(false), "HEALTH", 7, false));
    } else {
        columns.push(Column::new(
            Field::Traffic(Drops),
            if interval { "DROP/s" } else { "DROP" },
            7,
            true,
        ));
        columns.push(Column::new(
            Field::Traffic(Errors),
            if interval { "ERR/s" } else { "ERR" },
            7,
            true,
        ));
    }
    for column in &mut columns {
        if matches!(column.field, Field::Traffic(_)) {
            column.width = column.width.max(column.label.len() + 1);
        }
        if matches!(column.field, Field::Traffic(RxDrops | TxDrops)) {
            column.width = column.width.max(10);
        }
    }
    distribute(&mut columns, module_frame::inner_width(width));
    columns
}

fn configuration_columns(width: u16, features: bool) -> Vec<Column> {
    let wide = width >= 160;
    let compact_features = features && width < 90;
    let mut columns = vec![Column::new(
        Field::Name,
        "IFACE",
        if compact_features { 8 } else { 11 },
        false,
    )];
    if !features {
        columns.extend([
            Column::new(Field::Setting(0), "DRIVER", 8, false),
            Column::new(Field::Setting(16), "LINK", 5, false),
            Column::new(Field::Setting(1), "Mb/s", 8, true),
            Column::new(Field::Setting(2), "DUPLEX", 6, false),
            Column::new(Field::Setting(3), "AUTONEG", 7, false),
            Column::new(
                Field::Pair(4, 5),
                "Q R/T",
                if width >= 100 { 13 } else { 9 },
                true,
            ),
            Column::new(Field::Pair(6, 7), "RING R/T", 10, true),
            Column::new(Field::Setting(8), "TXQLEN", 6, true),
        ]);
    }
    if wide || features {
        columns.extend([
            Column::new(Field::Setting(9), "MTU", 5, true),
            Column::new(Field::Setting(10), "TSO", 9, false),
            Column::new(Field::Setting(11), "LRO", 9, false),
            Column::new(Field::Setting(12), "GRO", 9, false),
            Column::new(Field::Setting(13), "GSO", 9, false),
            Column::new(
                Field::Pair(14, 15),
                if compact_features {
                    "PAUSE"
                } else {
                    "PAUSE R/T"
                },
                9,
                false,
            ),
            Column::new(
                Field::Setting(17),
                "QDISC",
                if compact_features { 5 } else { 8 },
                false,
            ),
            Column::new(Field::Health(true), "HEALTH", 7, false),
        ]);
    }
    distribute(&mut columns, module_frame::inner_width(width));
    columns
}

fn distribute(columns: &mut Vec<Column>, width: u16) {
    let available = usize::from(width);
    let needed =
        columns.iter().map(|column| column.width).sum::<usize>() + columns.len().saturating_sub(1);
    if available >= needed {
        let mut extra = available - needed;
        for column in columns.iter_mut() {
            let target = match column.field {
                Field::Name | Field::Traffic(NetdevSort::Name) => 15,
                Field::Setting(0) => 12,
                _ => column.width,
            };
            let grow = target.saturating_sub(column.width).min(extra);
            column.width += grow;
            extra -= grow;
        }
        let count = columns.len().max(1);
        for (index, column) in columns.iter_mut().enumerate() {
            column.width += extra / count + usize::from(index < extra % count);
        }
    } else {
        // Below the supported 80-column size, still bound every cell and separator.
        let mut remaining = available;
        columns.retain_mut(|column| {
            if remaining == 0 {
                return false;
            }
            column.width = column.width.min(remaining);
            remaining = remaining.saturating_sub(column.width + 1);
            true
        });
    }
}

fn header(columns: &[Column], active_sort: Option<(NetdevSort, bool)>) -> Line<'static> {
    Line::from(
        columns
            .iter()
            .enumerate()
            .flat_map(|(i, column)| {
                let mut spans = Vec::with_capacity(2);
                if i > 0 {
                    spans.push(Span::styled(
                        "\u{2502}",
                        Style::default().fg(theme::DIVIDER),
                    ));
                }
                let active = active_sort.is_some_and(|(sort, _)| {
                    matches!(column.field, Field::Traffic(column_sort) if column_sort == sort)
                });
                let descending = active_sort.is_some_and(|(_, descending)| descending);
                let sortable = active_sort.is_some() && matches!(column.field, Field::Traffic(_));
                let label = if sortable {
                    super::sort_table::label(
                        column.label,
                        column.width,
                        active.then_some(descending),
                    )
                } else {
                    column.label.to_owned()
                };
                let style = super::sort_table::header_style(active, theme::TEXT);
                spans.push(Span::styled(fit(&label, column.width, column.right), style));
                spans
            })
            .collect::<Vec<_>>(),
    )
}

fn band(text: &str, width: u16) -> Line<'static> {
    Line::styled(
        fit(text, usize::from(width), false),
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    )
}

fn fit(text: &str, width: usize, right: bool) -> String {
    let display_width = Span::raw(text).width();
    if display_width <= width {
        let padding = " ".repeat(width - display_width);
        return if right {
            format!("{padding}{text}")
        } else {
            format!("{text}{padding}")
        };
    }
    if width == 0 {
        return String::new();
    }
    let mut fitted = String::new();
    let mut used = 0;
    for grapheme in text.graphemes(true) {
        let size = Span::raw(grapheme).width();
        if used + size > width - 1 {
            break;
        }
        fitted.push_str(grapheme);
        used += size;
    }
    fitted.push('+');
    fitted.push_str(&" ".repeat(width - used - 1));
    fitted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::monitor::{
        BaselineOrigin, CounterBits, CounterSpan, EngineTelemetry, HistoryCoverage, MetricId,
        MetricLabels, MonitorError, MonitorErrorCode, ProviderId, ProviderSnapshot, SeriesId,
        StateValue, UnavailableReason,
    };
    use ratatui::backend::TestBackend;
    use ratatui::widgets::Paragraph;
    use ratatui::Terminal;

    fn labels(index: u32, name: &str) -> MetricLabels {
        MetricLabels::new([
            (MetricLabel::Interface, name.to_owned()),
            (MetricLabel::Ifindex, index.to_string()),
        ])
        .unwrap()
    }

    fn series(
        id: u64,
        metric: &str,
        labels: MetricLabels,
        source: &str,
        value: SeriesValue,
    ) -> SeriesSnapshot {
        let (origin, baseline_at) = match &value {
            SeriesValue::Counter {
                interval: Some(CounterContinuity::Reset),
                ..
            } => (BaselineOrigin::Reset, Duration::from_secs(4)),
            SeriesValue::Counter {
                interval: Some(CounterContinuity::RecoveredAfterGap),
                ..
            } => (BaselineOrigin::RecoveredAfterGap, Duration::from_secs(4)),
            _ => (BaselineOrigin::SessionStart, Duration::ZERO),
        };
        SeriesSnapshot::new(
            SeriesId::new(id).unwrap(),
            ProviderId::new(crate::monitor::descriptor(metric).unwrap().owner).unwrap(),
            ProviderId::new(source).unwrap(),
            MetricId::new(metric).unwrap(),
            labels,
            Duration::ZERO,
            origin,
            baseline_at,
            value,
            HistoryCoverage::empty(),
        )
        .unwrap()
    }

    fn counter_value(delta: u64, total: u64) -> SeriesValue {
        SeriesValue::Counter {
            current: ProjectedValue::Fresh {
                value: u64::MAX,
                observed_at: Duration::from_secs(4),
            },
            interval: Some(CounterContinuity::Continuous {
                delta,
                elapsed: Duration::from_secs(1),
            }),
            since_baseline: Some(CounterSpan::new(total, Duration::from_secs(4)).unwrap()),
        }
    }

    fn state_value(text: &str) -> SeriesValue {
        SeriesValue::State {
            current: ProjectedValue::Fresh {
                value: StateValue::new(text).unwrap(),
                observed_at: Duration::from_secs(4),
            },
            changed_at: None,
            continuous_for: Some(Duration::from_secs(4)),
        }
    }

    fn setting(
        id: u64,
        index: u32,
        name: &str,
        setting: &str,
        value: SeriesValue,
    ) -> SeriesSnapshot {
        let labels = MetricLabels::new([
            (MetricLabel::Interface, name.to_owned()),
            (MetricLabel::Ifindex, index.to_string()),
            (MetricLabel::Statistic, setting.to_owned()),
        ])
        .unwrap();
        series(
            id,
            RAW_NIC_SETTING_METRIC_ID,
            labels,
            "linux.ethtool.link_text",
            value,
        )
    }

    fn snapshot(rows: Vec<SeriesSnapshot>, partial: Option<&str>) -> MonitorSnapshot {
        let mut providers = BTreeMap::new();
        for row in &rows {
            providers.entry(row.source().clone()).or_insert_with(|| {
                let health = if partial == Some(row.source().as_str()) {
                    ProviderHealth::Partial {
                        warning: MonitorError::new(MonitorErrorCode::Io, "fixture partial")
                            .unwrap(),
                    }
                } else {
                    ProviderHealth::Fresh
                };
                ProviderSnapshot::new(
                    row.source().clone(),
                    health,
                    Duration::from_secs(4),
                    Duration::ZERO,
                    0,
                )
                .unwrap()
            });
        }
        MonitorSnapshot::new(
            1,
            1,
            1,
            Duration::from_secs(4),
            None,
            providers.into_values().collect(),
            rows,
            EngineTelemetry::default(),
        )
        .unwrap()
    }

    fn inventory(snapshot: &MonitorSnapshot) -> Vec<InterfaceIdentity> {
        super::super::dashboard::ordered_interface_identities(snapshot, None, None)
    }

    fn fixture(count: u32) -> MonitorSnapshot {
        let mut rows = Vec::new();
        let values = [
            "ixgbe",
            "10000Mb/s",
            "Full",
            "on",
            "8",
            "8",
            "1024",
            "512",
            "1000",
            "1500",
            "on",
            "off",
            "on",
            "on",
            "on",
            "off",
        ];
        for index in 1..=count {
            let name = format!("eth{index:02}");
            for (slot, metric) in COUNTERS.iter().enumerate() {
                let delta = if slot < 2 {
                    u64::from(index) * 1_250_000
                } else {
                    u64::from(index) * 10
                };
                rows.push(series(
                    rows.len() as u64 + 1,
                    metric,
                    labels(index, &name),
                    "linux.rtnetlink.link_stats",
                    counter_value(delta, delta * 4),
                ));
            }
            rows.push(series(
                rows.len() as u64 + 1,
                "linux.nic.link_state",
                labels(index, &name),
                "linux.sysfs.net.nic",
                state_value("up"),
            ));
            for (field, text) in values.iter().enumerate() {
                if field == 9 {
                    rows.push(series(
                        rows.len() as u64 + 1,
                        "linux.nic.mtu",
                        labels(index, &name),
                        "linux.sysfs.net.nic",
                        SeriesValue::Gauge {
                            current: ProjectedValue::Fresh {
                                value: 1500,
                                observed_at: Duration::from_secs(4),
                            },
                            interval: None,
                            since_baseline: None,
                        },
                    ));
                } else {
                    rows.push(setting(
                        rows.len() as u64 + 1,
                        index,
                        &name,
                        SETTINGS[field],
                        state_value(text),
                    ));
                }
            }
        }
        snapshot(rows, None)
    }

    fn plain(lines: &[Line<'_>]) -> String {
        lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn independent_configuration_fallback_survives_a_failed_ethtool_query() {
        let mut rows = vec![series(
            1,
            NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
            labels(2, "eth0"),
            "linux.ethtool.link_text",
            state_value("permission_denied"),
        )];
        for (name, value) in [
            ("Sysfs Speed", "10000Mb/s"),
            ("Sysfs Duplex", "Full"),
            ("Sysfs Driver", "ixgbe"),
            ("Fallback Ring RX", "512"),
            ("Fallback Ring TX", "256"),
        ] {
            rows.push(setting(
                rows.len() as u64 + 1,
                2,
                "eth0",
                name,
                state_value(value),
            ));
        }
        let snapshot = snapshot(rows, Some("linux.ethtool.link_text"));
        let identity = inventory(&snapshot).remove(0);
        let table = NetdevTable::new(
            &snapshot,
            std::slice::from_ref(&identity),
            TimeView::Interval,
        );
        let row = &table.rows[&identity];
        assert_eq!(row.settings_health, Some(Health::Denied));
        for (index, expected) in [
            (0, "ixgbe"),
            (1, "10000Mb/s"),
            (2, "Full"),
            (6, "512"),
            (7, "256"),
        ] {
            assert_eq!(row.settings[index].text, expected);
            assert_eq!(row.settings[index].health, Health::Fresh);
        }
        assert_eq!(row.settings[3].health, Health::Missing);
        assert_eq!(setting_text(10, "on [fixed]"), "on fixed");
        assert_eq!(setting_text(11, "off [fixed]"), "off fixed");
        for width in [80, 120, 160, 200] {
            let lines = table.lines(width, std::slice::from_ref(&identity), 0..1, None);
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
        }
    }

    #[test]
    fn queue_display_distinguishes_ethtool_fixed_and_failed_or_stale_queries() {
        let mut row = InterfaceRow::default();
        for (index, text) in [(4, "1"), (5, "2"), (18, "6"), (19, "7"), (20, "ethtool")] {
            row.settings[index] = SettingCell {
                text: text.to_owned(),
                health: Health::Fresh,
            };
        }
        assert_eq!(row.queue_cells(), (18, 19, ""));
        row.settings[20].text = "fixed".to_owned();
        assert_eq!(row.queue_cells(), (4, 5, " fixed"));
        row.settings[4].health = Health::Partial;
        assert_eq!(row.queue_cells(), (4, 5, " fixed"));
        row.settings[20].text = "sysfs".to_owned();
        assert_eq!(row.queue_cells(), (4, 5, " sysfs"));
        row.settings[20].text = "fixed".to_owned();
        row.settings[20].health = Health::Stale;
        assert_eq!(row.queue_cells(), (4, 5, " sysfs"));
        row.settings[4].health = Health::Missing;
        assert_eq!(row.queue_cells(), (4, 5, ""));
    }

    #[test]
    fn batch_headers_selection_and_bounds_at_supported_widths() {
        let snapshot = fixture(24);
        let inventory = inventory(&snapshot);
        let table = NetdevTable::new(&snapshot, &inventory, TimeView::Interval);
        assert_eq!(table.len(), 24);
        assert!(!table.is_empty());
        let order = table.ordered_interfaces(NetdevSort::RxBytes, true);
        let selected = &order[4];
        for width in [80, 119, 120, 144, 145, 146, 160] {
            let capacity = NetdevTable::visible_capacity(width, 30);
            assert!(capacity > 3, "width={width}, capacity={capacity}");
            let visible = 3..3 + capacity;
            let lines = table.lines(width, &order, visible.clone(), Some(selected));
            assert_eq!(lines.len(), NetdevTable::row_count(width, capacity));
            assert!(lines.len() <= 30);
            assert!(lines.iter().all(|line| line.width() <= width.into()));
            let tables = if width >= 160 { 2 } else { 3 };
            for batch in 0..tables {
                let start = batch * (capacity + 2);
                for (row, identity) in order[visible.clone()].iter().enumerate() {
                    assert!(lines[start + 2 + row].to_string().contains(identity.name()));
                    assert_eq!(
                        lines[start + 2 + row].style.bg,
                        (identity == selected).then_some(theme::SELECTED_BG)
                    );
                    assert_eq!(
                        table.hit_test(width, &order, visible.clone(), 1, (start + 2 + row) as u16),
                        Some(NetdevHit::Interface(identity.clone()))
                    );
                }
                if batch > 0 {
                    assert_eq!(
                        table.hit_test(width, &order, visible.clone(), 4, (start + 1) as u16),
                        None
                    );
                }
            }
            for x in [0, width - 1] {
                for y in 0..lines.len() as u16 {
                    assert_eq!(table.hit_test(width, &order, visible.clone(), x, y), None);
                }
            }
            assert_eq!(
                table.hit_test(width, &order, visible.clone(), 1, (lines.len() - 1) as u16),
                None
            );
            let mut terminal = Terminal::new(TestBackend::new(width, 30)).unwrap();
            terminal
                .draw(|frame| frame.render_widget(Paragraph::new(lines.clone()), frame.area()))
                .unwrap();
            let rendered = terminal.backend().to_string();
            assert!(rendered.contains("CONFIGURATION"));
            for label in [
                "DRIVER",
                "DUPLEX",
                "AUTONEG",
                "Q R/T",
                "RING R/T",
                "TXQLEN",
                "MTU",
                "TSO",
                "LRO",
                "GRO",
                "GSO",
                "PAUSE R/T",
                "QDISC",
            ] {
                assert!(
                    rendered.contains(label),
                    "{width}: missing {label}\n{rendered}"
                );
            }
            assert!(rendered.contains("10000"));
            assert!(rendered.contains("1024/512"));
            assert!(!rendered.contains(order[0].name()));
            let next = table.lines(width, &order, 4..4 + capacity, Some(selected));
            assert!(lines[0]
                .to_string()
                .contains(&format!("4-{}/24", 3 + capacity)));
            assert!(next[0]
                .to_string()
                .contains(&format!("5-{}/24", 4 + capacity)));
            for header in [1, capacity + 2, capacity + 3] {
                assert_eq!(
                    lines[header], next[header],
                    "headers changed during scrolling"
                );
            }
        }
    }

    #[test]
    fn narrow_drop_and_error_columns_are_explicit_direction_sums() {
        let snapshot = fixture(1);
        let identities = inventory(&snapshot);
        let table = NetdevTable::new(&snapshot, &identities, TimeView::Interval);
        let lines = table.lines(80, &identities, 0..1, None);
        assert!(lines[0].to_string().contains("RX+TX"));
        assert_eq!(lines[2].to_string().matches("20.00").count(), 2);
        let wide = table.lines(120, &identities, 0..1, None);
        for label in ["RX drop/s", "TX drop/s", "RX err/s", "TX err/s"] {
            assert!(wide[1].to_string().contains(label));
        }
    }

    #[test]
    fn time_view_changes_units_and_totals_but_not_current_configuration() {
        let snapshot = fixture(1);
        let identities = inventory(&snapshot);
        let rate = NetdevTable::new(&snapshot, &identities, TimeView::Interval);
        let totals = NetdevTable::new(&snapshot, &identities, TimeView::SinceBaseline);
        for width in [80, 120, 160] {
            let rate = rate.lines(width, &identities, 0..1, None);
            let totals = totals.lines(width, &identities, 0..1, None);
            assert!(rate[1].to_string().contains("RX Mb/s"));
            assert!(rate[2].to_string().contains("10.00"));
            assert!(totals[1].to_string().contains("RX bytes"));
            assert!(totals[2].to_string().contains("5000000"));
            assert!(totals[1].to_string().contains("RX pkts"));
            assert!(!totals[1].to_string().contains("/s"));
            assert_eq!(rate[3..], totals[3..]);
        }
    }

    #[test]
    fn sorts_numerically_with_missing_last_and_identity_ties() {
        let mut rows = Vec::new();
        for (index, name, delta) in [(1, "zzz", 100), (2, "aaa", 9), (3, "bbb", 100)] {
            for metric in COUNTERS {
                rows.push(series(
                    rows.len() as u64 + 1,
                    metric,
                    labels(index, name),
                    "linux.rtnetlink.link_stats",
                    counter_value(delta, delta * 4),
                ));
            }
        }
        rows.push(series(
            rows.len() as u64 + 1,
            "linux.nic.link_state",
            labels(4, "missing"),
            "linux.sysfs.net.nic",
            state_value("up"),
        ));
        let snapshot = snapshot(rows, None);
        let table = NetdevTable::new(&snapshot, &inventory(&snapshot), TimeView::Interval);
        let ids = |sort, desc| {
            table
                .ordered_interfaces(sort, desc)
                .iter()
                .map(|id| id.ifindex().get())
                .collect::<Vec<_>>()
        };
        for sort in NetdevSort::ALL.into_iter().skip(2) {
            assert_eq!(ids(sort, false), [2, 1, 3, 4]);
            assert_eq!(ids(sort, true), [1, 3, 2, 4]);
        }
        assert_eq!(ids(NetdevSort::Ifindex, false), [1, 2, 3, 4]);
        assert_eq!(ids(NetdevSort::Ifindex, true), [4, 3, 2, 1]);
        assert_eq!(ids(NetdevSort::Name, false), [2, 3, 4, 1]);
        assert_eq!(ids(NetdevSort::Name, true), [1, 4, 3, 2]);
        assert_eq!(NetdevSort::Errors.next(), NetdevSort::Ifindex);
        assert!(!NetdevSort::Name.default_descending());
        assert!(NetdevSort::RxPackets.default_descending());
        assert_eq!(NetdevSort::RxBytes.label(), "RX bytes");
    }

    #[test]
    fn large_byte_totals_sort_without_float_precision_loss() {
        let snapshot = snapshot(
            vec![
                series(
                    1,
                    COUNTERS[0],
                    labels(1, "higher"),
                    "linux.rtnetlink.link_stats",
                    counter_value(1, (1_u64 << 53) + 1),
                ),
                series(
                    2,
                    COUNTERS[0],
                    labels(2, "lower"),
                    "linux.rtnetlink.link_stats",
                    counter_value(2, 1_u64 << 53),
                ),
            ],
            None,
        );
        let identities = inventory(&snapshot);
        let rate = NetdevTable::new(&snapshot, &identities, TimeView::Interval);
        let totals = NetdevTable::new(&snapshot, &identities, TimeView::SinceBaseline);
        assert_eq!(
            rate.ordered_interfaces(NetdevSort::RxBytes, false)[0].name(),
            "higher"
        );
        assert_eq!(
            totals.ordered_interfaces(NetdevSort::RxBytes, false)[0].name(),
            "lower"
        );
    }

    #[test]
    fn stale_missing_reset_gap_and_first_sample_never_become_zero() {
        for (current, interval, label) in [
            (
                ProjectedValue::Stale {
                    last: 100,
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                None,
                "stale",
            ),
            (
                ProjectedValue::Unavailable {
                    reason: UnavailableReason::Missing,
                },
                None,
                "n/a",
            ),
            (
                ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(4),
                },
                Some(CounterContinuity::Reset),
                "reset",
            ),
            (
                ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(4),
                },
                Some(CounterContinuity::RecoveredAfterGap),
                "gap",
            ),
            (
                ProjectedValue::Fresh {
                    value: 100,
                    observed_at: Duration::from_secs(4),
                },
                Some(CounterContinuity::FirstSample),
                "first",
            ),
        ] {
            let sample = snapshot(
                vec![series(
                    1,
                    COUNTERS[0],
                    labels(1, "eth0"),
                    "linux.rtnetlink.link_stats",
                    SeriesValue::Counter {
                        current,
                        interval,
                        since_baseline: None,
                    },
                )],
                None,
            );
            // Obtain the same identity from observed inventory even when this sample has no reading.
            let identities = inventory(&snapshot(
                vec![series(
                    2,
                    "linux.nic.link_state",
                    labels(1, "eth0"),
                    "linux.sysfs.net.nic",
                    state_value("up"),
                )],
                None,
            ));
            for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                let table = NetdevTable::new(&sample, &identities, time_view);
                let lines = table.lines(120, &identities, 0..1, None);
                assert!(
                    lines[2].to_string().contains(label),
                    "{label}: {}",
                    lines[2]
                );
                assert!(!lines[2].to_string().contains("0.00"));
                assert!(table.rows[&identities[0]]
                    .counter(NetdevSort::RxBytes)
                    .value
                    .is_none());
            }
        }
    }

    #[test]
    fn wrapped_counter_has_a_real_rate_and_missing_direction_prevents_fake_sum() {
        let sample = snapshot(
            vec![series(
                1,
                COUNTERS[4],
                labels(1, "eth0"),
                "linux.rtnetlink.link_stats",
                SeriesValue::Counter {
                    current: ProjectedValue::Fresh {
                        value: 5,
                        observed_at: Duration::from_secs(4),
                    },
                    interval: Some(CounterContinuity::Wrapped {
                        delta: 10,
                        elapsed: Duration::from_secs(2),
                        bits: CounterBits::Bits32,
                    }),
                    since_baseline: Some(CounterSpan::new(10, Duration::from_secs(4)).unwrap()),
                },
            )],
            None,
        );
        let identities = inventory(&sample);
        let table = NetdevTable::new(&sample, &identities, TimeView::Interval);
        assert_eq!(
            table.rows[&identities[0]]
                .counter(NetdevSort::RxDrops)
                .display(false, 10),
            "5.00"
        );
        assert!(table.rows[&identities[0]]
            .counter(NetdevSort::Drops)
            .value
            .is_none());
    }

    #[test]
    fn partial_source_and_stale_settings_remain_visible() {
        let base = fixture(1);
        let mut rows = base.series().to_vec();
        rows.retain(|row| row.labels().get(MetricLabel::Statistic) != Some("GRO"));
        rows.push(setting(
            1000,
            1,
            "eth01",
            "GRO",
            SeriesValue::State {
                current: ProjectedValue::Stale {
                    last: StateValue::new("on").unwrap(),
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                changed_at: None,
                continuous_for: None,
            },
        ));
        let snapshot = snapshot(rows, Some("linux.rtnetlink.link_stats"));
        let identities = inventory(&snapshot);
        let table = NetdevTable::new(&snapshot, &identities, TimeView::Interval);
        let text = plain(&table.lines(160, &identities, 0..1, None));
        assert!(text.contains("partial"), "{text}");
        assert!(text.contains("~on"), "{text}");
        assert!(text.contains("stale"), "{text}");
        assert!(
            text.contains("10.00"),
            "fresh readings from partial source remain usable"
        );
    }

    #[test]
    fn missing_configuration_is_neither_off_nor_zero() {
        let sample = snapshot(
            vec![series(
                1,
                COUNTERS[0],
                labels(1, "eth0"),
                "linux.rtnetlink.link_stats",
                counter_value(0, 0),
            )],
            None,
        );
        let identities = inventory(&sample);
        let table = NetdevTable::new(&sample, &identities, TimeView::Interval);
        let lines = table.lines(80, &identities, 0..1, None);
        assert!(
            lines[2].to_string().contains("0.00"),
            "observed zero remains zero"
        );
        let config = plain(&lines[3..]);
        assert!(config.contains("n/a/n/a"));
        assert!(!config.contains("off"));
        assert!(!config.contains("0.00"));
    }

    fn settings_status(id: u64, index: u32, name: &str, status: &str) -> SeriesSnapshot {
        series(
            id,
            NIC_ETHTOOL_SETTINGS_STATUS_METRIC_ID,
            labels(index, name),
            "linux.ethtool.link_text",
            state_value(status),
        )
    }

    #[test]
    fn absent_optional_settings_are_neutral_without_changing_off_or_unknown_values() {
        let base = fixture(1);
        let mut rows: Vec<_> = base
            .series()
            .iter()
            .filter(|row| row.metric().as_str() != RAW_NIC_SETTING_METRIC_ID)
            .cloned()
            .collect();
        rows.push(setting(1001, 1, "eth01", "TSO", state_value("off")));
        rows.push(setting(1002, 1, "eth01", "GRO", state_value("unknown")));
        let sample = snapshot(rows, None);
        let ids = inventory(&sample);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].health(true), Health::Fresh);
        for width in [80, 120, 160] {
            let lines = table.lines(width, &ids, 0..1, None);
            let rendered = plain(&lines);
            assert!(
                rendered.contains("HEALTH") && !rendered.contains("SOURCE"),
                "{rendered}"
            );
            assert!(lines.iter().all(|line| line.width() <= width as usize));
            for features in [false, true] {
                let columns = configuration_columns(width, features);
                let row = table.row_line(&ids[0], &columns, None, None);
                for (index, column) in columns.iter().enumerate() {
                    let span = &row.spans[index * 2];
                    match column.field {
                        Field::Setting(10) => {
                            assert_eq!(span.content.trim(), "off");
                            assert_eq!(span.style.fg, Some(theme::TEXT));
                        }
                        Field::Setting(12) => {
                            assert!(span.content.starts_with("unk"));
                            assert_eq!(span.style.fg, Some(theme::TEXT));
                        }
                        Field::Setting(index) if !core_setting(index) => {
                            assert_eq!(span.content.trim(), "n/a");
                            assert_eq!(span.style.fg, Some(theme::MUTED));
                        }
                        Field::Pair(_, _) => {
                            assert_eq!(span.content.trim(), "n/a/n/a");
                            assert_eq!(span.style.fg, Some(theme::MUTED));
                        }
                        Field::Health(true) => assert_eq!(span.content.trim(), "fresh"),
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn per_interface_settings_status_isolates_unsupported_and_real_failures() {
        for (status, expected) in [
            ("unsupported", Health::Fresh),
            ("permission_denied", Health::Denied),
            ("timed_out", Health::Error),
            ("partial_schema_mismatch", Health::Partial),
            ("partial_cardinality_limit", Health::Partial),
        ] {
            let mut rows = fixture(2).series().to_vec();
            // The per-interface status may follow its values in snapshot order.
            rows.push(settings_status(1001, 1, "eth01", "complete"));
            rows.push(settings_status(1002, 2, "eth02", status));
            let sample = snapshot(rows, Some("linux.ethtool.link_text"));
            let ids = inventory(&sample);
            let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
            assert_eq!(table.rows[&ids[0]].health(true), Health::Fresh, "{status}");
            assert_eq!(table.rows[&ids[1]].health(true), expected, "{status}");
            for width in [80, 120, 160] {
                let columns = configuration_columns(width, width < 160);
                let health_column = columns
                    .iter()
                    .position(|column| matches!(column.field, Field::Health(true)))
                    .unwrap();
                let row = table.row_line(&ids[1], &columns, None, None);
                let span = &row.spans[health_column * 2];
                assert_eq!(span.content.trim(), expected.label());
                assert_eq!(
                    span.style.fg,
                    Some(if expected == Health::Fresh {
                        theme::GOOD
                    } else {
                        theme::WARN
                    })
                );
            }
        }
    }

    #[test]
    fn optional_stale_or_invalid_values_are_not_hidden_by_unsupported_status() {
        let mut rows = fixture(1).series().to_vec();
        rows.retain(|row| {
            !matches!(
                row.labels().get(MetricLabel::Statistic),
                Some("Flow Control RX" | "Flow Control TX")
            )
        });
        rows.push(setting(
            1001,
            1,
            "eth01",
            "Flow Control RX",
            SeriesValue::State {
                current: ProjectedValue::Stale {
                    last: StateValue::new("on").unwrap(),
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                changed_at: None,
                continuous_for: None,
            },
        ));
        rows.push(settings_status(1002, 1, "eth01", "unsupported"));
        let sample = snapshot(rows, Some("linux.ethtool.link_text"));
        let ids = inventory(&sample);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].health(true), Health::Stale);
        let columns = configuration_columns(200, false);
        let pause = columns
            .iter()
            .position(|column| matches!(column.field, Field::Pair(14, 15)))
            .unwrap();
        let row = table.row_line(&ids[0], &columns, None, None);
        assert_eq!(row.spans[pause * 2].content.trim(), "~on/n/a");
        assert_eq!(row.spans[pause * 2].style.fg, Some(theme::WARN));

        let mut rows = fixture(1).series().to_vec();
        rows.retain(|row| row.labels().get(MetricLabel::Statistic) != Some("GRO"));
        rows.push(setting(
            1003,
            1,
            "eth01",
            "GRO",
            SeriesValue::State {
                current: ProjectedValue::Unavailable {
                    reason: UnavailableReason::InvalidValue,
                },
                changed_at: None,
                continuous_for: None,
            },
        ));
        let sample = snapshot(rows, None);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].health(true), Health::Error);
        let gro = columns
            .iter()
            .position(|column| matches!(column.field, Field::Setting(12)))
            .unwrap();
        assert_eq!(
            table.row_line(&ids[0], &columns, None, None).spans[gro * 2]
                .style
                .fg,
            Some(theme::WARN)
        );
    }

    #[test]
    fn missing_core_configuration_and_unexplained_partial_sources_still_warn() {
        let mut rows = fixture(1).series().to_vec();
        rows.retain(|row| row.metric().as_str() != "linux.nic.mtu");
        let sample = snapshot(rows, None);
        let ids = inventory(&sample);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].health(true), Health::Partial);
        assert_eq!(
            setting_style(9, table.rows[&ids[0]].settings[9].health).fg,
            Some(theme::WARN)
        );
        for source in ["linux.ethtool.link_text", "linux.sysfs.net.nic"] {
            let sample = snapshot(fixture(1).series().to_vec(), Some(source));
            let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
            assert_eq!(
                table.rows[&ids[0]].health(true),
                Health::Partial,
                "{source}"
            );
        }
    }

    #[test]
    fn mtu_is_current_bytes_in_both_time_views_and_preserves_stale_and_missing() {
        let base = fixture(1);
        let ids = inventory(&base);
        for (current, expected) in [
            (
                ProjectedValue::Fresh {
                    value: 9000,
                    observed_at: Duration::from_secs(4),
                },
                "9000",
            ),
            (
                ProjectedValue::Stale {
                    last: 1500,
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
                "~1500",
            ),
            (
                ProjectedValue::Unavailable {
                    reason: UnavailableReason::Missing,
                },
                "n/a",
            ),
        ] {
            let snapshot = snapshot(
                vec![series(
                    1,
                    "linux.nic.mtu",
                    labels(1, "eth01"),
                    "linux.sysfs.net.nic",
                    SeriesValue::Gauge {
                        current,
                        interval: None,
                        since_baseline: None,
                    },
                )],
                None,
            );
            for time_view in [TimeView::Interval, TimeView::SinceBaseline] {
                let table = NetdevTable::new(&snapshot, &ids, time_view);
                assert_eq!(table.rows[&ids[0]].settings[9].text, expected);
                for width in [80, 120, 160] {
                    let rendered = plain(&table.lines(width, &ids, 0..1, None));
                    assert!(rendered.contains(expected), "{rendered}");
                }
            }
        }
    }

    #[test]
    fn selected_identity_survives_resort_and_does_not_match_reused_names() {
        let initial = fixture(5);
        let identities = inventory(&initial);
        let selected = identities[1].clone();
        let table = NetdevTable::new(&initial, &identities, TimeView::Interval);
        for sort in NetdevSort::ALL {
            let ordered = table.ordered_interfaces(sort, true);
            let lines = table.lines(160, &ordered, 0..ordered.len(), Some(&selected));
            let highlighted = lines
                .iter()
                .filter(|line| line.style.bg == Some(theme::SELECTED_BG))
                .collect::<Vec<_>>();
            assert_eq!(highlighted.len(), 2);
            assert!(highlighted
                .iter()
                .all(|line| line.to_string().contains(selected.name())));
        }
        let changed = snapshot(
            vec![series(
                1,
                COUNTERS[0],
                labels(22, selected.name()),
                "linux.rtnetlink.link_stats",
                counter_value(50, 200),
            )],
            None,
        );
        let new_ids = inventory(&changed);
        let table = NetdevTable::new(&changed, &new_ids, TimeView::Interval);
        assert!(table
            .lines(160, &new_ids, 0..1, Some(&selected))
            .iter()
            .all(|line| line.style.bg.is_none()));
        let old_inventory = NetdevTable::new(&changed, &identities, TimeView::Interval);
        assert!(old_inventory.rows[&selected].counters[0].value.is_none());
    }

    #[test]
    fn header_hit_regions_match_each_visible_sort_column() {
        for width in [80, 120, 160] {
            let mut x = 1;
            for column in traffic_columns(width, TimeView::SinceBaseline) {
                let expected = match column.field {
                    Field::Traffic(sort) => Some(sort),
                    _ => None,
                };
                for point in [x, x + column.width - 1] {
                    assert_eq!(NetdevTable::header_at(width, point as u16), expected);
                }
                assert_eq!(
                    NetdevTable::header_at(width, (x + column.width) as u16),
                    None
                );
                x += column.width + 1;
            }
        }
    }

    #[test]
    fn short_and_empty_viewports_have_bounded_counts_and_safe_hits() {
        let sample = fixture(2);
        let ids = inventory(&sample);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        for width in [0, 1, 40, 79, 80, 120, 145, 160] {
            for height in 0..60 {
                let capacity = NetdevTable::visible_capacity(width, height);
                if capacity > 0 {
                    assert!(NetdevTable::row_count(width, capacity) <= usize::from(height));
                }
            }
            let lines = table.lines(width, &ids, 0..usize::MAX, None);
            assert!(lines.iter().all(|line| line.width() <= usize::from(width)));
            let empty = table.lines(width, &ids, usize::MAX..usize::MAX, None);
            assert_eq!(empty.len(), NetdevTable::row_count(width, 0));
            assert_eq!(table.hit_test(width, &ids, 0..2, width, 2), None);
            assert_eq!(table.hit_test(width, &ids, 0..2, 0, u16::MAX), None);
        }
        assert_eq!(Span::raw(fit("界界界", 4, false)).width(), 4);
        let empty = NetdevTable::new(&sample, &[], TimeView::Interval);
        assert!(empty.is_empty());
    }

    fn qdisc(
        id: u64,
        kind: &str,
        root: bool,
        direction: &str,
        current: ProjectedValue<u64>,
    ) -> SeriesSnapshot {
        let mut pairs = labels(1, "eth01")
            .iter()
            .map(|(label, value)| (label, value.to_owned()))
            .collect::<Vec<_>>();
        pairs.extend([
            (MetricLabel::ObjectKind, "qdisc".to_owned()),
            (MetricLabel::QdiscKind, kind.to_owned()),
            (MetricLabel::Direction, direction.to_owned()),
            (MetricLabel::RowId, id.to_string()),
            (MetricLabel::Execution, "software".to_owned()),
            (
                MetricLabel::QdiscAttachment,
                serde_json::to_string(&(root, Some("1:"), (!root).then_some("1:1"))).unwrap(),
            ),
        ]);
        series(
            id,
            "linux.tc.packets",
            MetricLabels::new(pairs).unwrap(),
            "linux.tc.json",
            SeriesValue::Counter {
                current,
                interval: None,
                since_baseline: None,
            },
        )
    }

    #[test]
    fn qdisc_comes_only_from_observed_root_egress_metadata() {
        let fresh = ProjectedValue::Fresh {
            value: 10,
            observed_at: Duration::from_secs(4),
        };
        let base = fixture(1);
        let ids = inventory(&base);
        let mut rows = base.series().to_vec();
        rows.push(qdisc(1001, "fq_codel", false, "egress", fresh.clone()));
        rows.push(qdisc(1002, "ingress", true, "ingress", fresh.clone()));
        let sample = snapshot(rows.clone(), None);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].settings[17].text, "n/a");
        rows.push(qdisc(1003, "htb", true, "egress", fresh));
        let sample = snapshot(rows, None);
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].settings[17].text, "htb");
        assert!(plain(&table.lines(80, &ids, 0..1, None)).contains("htb"));
        let sample = snapshot(
            vec![qdisc(
                1004,
                "htb",
                true,
                "egress",
                ProjectedValue::Stale {
                    last: 10,
                    observed_at: Duration::from_secs(3),
                    age: Duration::from_secs(1),
                    cause: MonitorErrorCode::Io,
                },
            )],
            None,
        );
        let table = NetdevTable::new(&sample, &ids, TimeView::Interval);
        assert_eq!(table.rows[&ids[0]].settings[17].text, "~htb");
    }
}
