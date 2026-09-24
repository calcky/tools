use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::path::Path;

use anyhow::{anyhow, bail, Context};

use crate::model::{MetricKey, MetricSample};

use super::read_to_string;

const NET_DEV_FIELDS: [&str; 16] = [
    "rx_bytes",
    "rx_packets",
    "rx_errors",
    // /proc/net/dev folds rx_dropped and rx_missed_errors into this column.
    "rx_dropped_combined",
    "rx_fifo_errors",
    // This column combines length, overrun, CRC, and frame alignment errors.
    "rx_frame_errors_combined",
    "rx_compressed",
    "rx_multicast",
    "tx_bytes",
    "tx_packets",
    "tx_errors",
    "tx_dropped",
    "tx_fifo_errors",
    "collisions",
    // This column combines carrier, aborted, window, and heartbeat errors.
    "tx_carrier_errors_combined",
    "tx_compressed",
];

pub fn collect_named_tables(path: &Path, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    parse_named_tables(&read_to_string(path)?, source)
}

pub fn collect_name_values(path: &Path, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    parse_name_values(&read_to_string(path)?, source)
}

pub fn collect_sockstat(path: &Path, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    parse_sockstat(&read_to_string(path)?, source)
}

pub(crate) fn collect_tcp_memory_limit(proc_root: &Path) -> anyhow::Result<Vec<MetricSample>> {
    let path = proc_root.join("sys/net/ipv4/tcp_mem");
    let input = read_to_string(&path)?;
    let values = input
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != 3 || values[0] > values[1] || values[1] > values[2] {
        bail!("invalid tcp_mem thresholds");
    }
    Ok(vec![MetricSample {
        key: MetricKey::new("proc_sys_net_ipv4", "ipv4", "tcp_mem_max"),
        value: values[2],
    }])
}

pub fn collect_conntrack(proc_root: &Path, sys_root: &Path) -> anyhow::Result<Vec<MetricSample>> {
    let count = read_unsigned_decimal(
        &proc_root.join("sys/net/netfilter/nf_conntrack_count"),
        "nf_conntrack_count",
    )?;
    let maximum = read_unsigned_decimal(
        &proc_root.join("sys/net/netfilter/nf_conntrack_max"),
        "nf_conntrack_max",
    )?;
    if maximum == 0 {
        bail!("nf_conntrack_max is zero");
    }
    let utilization = u64::try_from(
        u128::from(count)
            .saturating_mul(10_000)
            .checked_div(u128::from(maximum))
            .expect("non-zero conntrack maximum"),
    )
    .unwrap_or(u64::MAX);
    let mut metrics = vec![
        MetricSample {
            key: MetricKey::new("proc_conntrack", "conntrack", "nf_conntrack_count"),
            value: count,
        },
        MetricSample {
            key: MetricKey::new("proc_conntrack", "conntrack", "nf_conntrack_max"),
            value: maximum,
        },
        MetricSample {
            key: MetricKey::new("proc_conntrack", "conntrack", "derived.count_over_max"),
            value: utilization,
        },
    ];

    let stat_path = proc_root.join("net/stat/nf_conntrack");
    if stat_path.exists() {
        let online_path = sys_root.join("devices/system/cpu/online");
        let online_before = read_online_cpus(&online_path);
        let input = read_to_string(&stat_path)?;
        let online_after = read_online_cpus(&online_path);
        let stable_online = (online_before == online_after)
            .then_some(online_before)
            .flatten();
        metrics.extend(parse_conntrack_stat(&input, stable_online.as_deref())?);
    }
    metrics.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(metrics)
}

pub fn collect_softnet(path: &Path, cpu_online_path: &Path) -> anyhow::Result<Vec<MetricSample>> {
    let mut context = SoftnetContext::default();
    context.collect(path, cpu_online_path)?;
    Ok(context.metrics)
}

pub fn collect_net_core_settings(proc_root: &Path) -> anyhow::Result<Vec<MetricSample>> {
    const SETTINGS: [&str; 4] = [
        "netdev_budget",
        "netdev_budget_usecs",
        "dev_weight",
        "netdev_max_backlog",
    ];

    let root = proc_root.join("sys/net/core");
    let mut metrics = Vec::with_capacity(SETTINGS.len());
    for name in SETTINGS {
        let path = root.join(name);
        let input = match std::fs::read_to_string(&path) {
            Ok(input) => input,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("cannot read {}: {error}", path.display()),
                )
                .into())
            }
        };
        let value = input
            .trim()
            .parse::<u64>()
            .with_context(|| format!("invalid {name} value"))?;
        metrics.push(MetricSample {
            key: MetricKey::new("proc_sys_net_core", "net_core", name),
            value,
        });
    }
    if metrics.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "no supported SoftIRQ settings are present under {}",
                root.display()
            ),
        )
        .into());
    }
    Ok(metrics)
}

fn read_online_cpus(path: &Path) -> Option<Vec<u32>> {
    read_to_string(path)
        .ok()
        .and_then(|value| parse_cpu_list(&value).ok())
}

pub fn collect_net_dev(
    path: &Path,
    interface: Option<&str>,
) -> Result<Vec<MetricSample>, NetDevCollectError> {
    let input = read_to_string(path).map_err(NetDevCollectError::io)?;
    parse_net_dev(&input, interface).map_err(NetDevCollectError::parse)
}

#[derive(Debug)]
pub struct NetDevCollectError {
    parse_error: bool,
    source: anyhow::Error,
}

impl NetDevCollectError {
    fn io(source: anyhow::Error) -> Self {
        Self {
            parse_error: false,
            source,
        }
    }

    fn parse(source: anyhow::Error) -> Self {
        Self {
            parse_error: true,
            source,
        }
    }

    pub const fn parse_errors(&self) -> u64 {
        self.parse_error as u64
    }
}

impl fmt::Display for NetDevCollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for NetDevCollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.source()
    }
}

fn parse_named_tables(input: &str, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    let lines: Vec<_> = input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() % 2 != 0 {
        bail!(
            "expected header/value line pairs, got {} lines",
            lines.len()
        );
    }

    let mut metrics = Vec::new();
    for pair in lines.chunks_exact(2) {
        let (header_group, header_values) = split_group(pair[0])?;
        let (value_group, values) = split_group(pair[1])?;
        if header_group != value_group {
            bail!("group mismatch: {header_group} followed by {value_group}");
        }

        let names: Vec<_> = header_values.split_whitespace().collect();
        let values: Vec<_> = values.split_whitespace().collect();
        if names.len() != values.len() {
            bail!(
                "{header_group} has {} field names but {} values",
                names.len(),
                values.len()
            );
        }

        for (name, value) in names.into_iter().zip(values) {
            let parsed = value
                .parse::<i128>()
                .with_context(|| format!("invalid {header_group}.{name} value {value:?}"))?;
            if parsed < 0 {
                continue;
            }
            let value = u64::try_from(parsed)
                .with_context(|| format!("{header_group}.{name} does not fit in u64"))?;
            metrics.push(MetricSample {
                key: MetricKey::new(source, header_group, name),
                value,
            });
        }
    }

    Ok(metrics)
}

fn parse_name_values(input: &str, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    let mut names = BTreeSet::new();
    let mut metrics = Vec::new();
    for (line_number, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 {
            bail!(
                "name/value line {} does not have two fields",
                line_number + 1
            );
        }
        if !names.insert(fields[0]) {
            bail!("duplicate name/value field {:?}", fields[0]);
        }
        let value = fields[1]
            .parse::<u64>()
            .with_context(|| format!("invalid {} value {:?}", fields[0], fields[1]))?;
        metrics.push(MetricSample {
            key: MetricKey::new(source, "name_value", fields[0]),
            value,
        });
    }
    if metrics.is_empty() {
        bail!("name/value file contains no metrics");
    }
    Ok(metrics)
}

fn parse_sockstat(input: &str, source: &str) -> anyhow::Result<Vec<MetricSample>> {
    let mut identities = BTreeSet::new();
    let mut metrics = Vec::new();
    for (line_number, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (group, values) = split_group(line)?;
        let values = values.split_whitespace().collect::<Vec<_>>();
        if values.is_empty() || values.len() % 2 != 0 {
            bail!(
                "sockstat line {} has an incomplete name/value pair",
                line_number + 1
            );
        }
        for pair in values.chunks_exact(2) {
            if !identities.insert((group, pair[0])) {
                bail!("duplicate sockstat field {group}.{}", pair[0]);
            }
            let parsed = pair[1]
                .parse::<i128>()
                .with_context(|| format!("invalid sockstat {group}.{} value", pair[0]))?;
            if parsed < 0 {
                continue;
            }
            metrics.push(MetricSample {
                key: MetricKey::new(source, group, pair[0]),
                value: u64::try_from(parsed)
                    .with_context(|| format!("sockstat {group}.{} exceeds u64", pair[0]))?,
            });
        }
    }
    if metrics.is_empty() {
        bail!("sockstat contains no metrics");
    }
    Ok(metrics)
}

const CONNTRACK_COUNTERS: [&str; 6] = [
    "found",
    "invalid",
    "insert",
    "insert_failed",
    "drop",
    "early_drop",
];

fn parse_conntrack_stat(
    input: &str,
    online_cpus: Option<&[u32]>,
) -> anyhow::Result<Vec<MetricSample>> {
    let mut lines = input.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| anyhow!("conntrack stat file is empty"))?
        .split_whitespace()
        .collect::<Vec<_>>();
    let rows = lines
        .enumerate()
        .map(|(row, line)| {
            let values = line.split_whitespace().collect::<Vec<_>>();
            if values.len() != header.len() {
                bail!(
                    "conntrack stat row {} has {} fields, expected {}",
                    row + 1,
                    values.len(),
                    header.len()
                );
            }
            values
                .into_iter()
                .map(|value| {
                    u64::from_str_radix(value, 16)
                        .with_context(|| format!("invalid conntrack hex value {value:?}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if rows.is_empty() {
        bail!("conntrack stat file contains no CPU rows");
    }
    let Some(cpus) = online_cpus.filter(|cpus| cpus.len() == rows.len()) else {
        return Ok(Vec::new());
    };
    let unique = cpus.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != cpus.len() {
        bail!("conntrack CPU identities contain duplicates");
    }

    let mut metrics = Vec::new();
    for (cpu, row) in cpus.iter().zip(rows) {
        for metric in CONNTRACK_COUNTERS.into_iter().chain(["search_restart"]) {
            let Some(column) = header.iter().position(|name| *name == metric) else {
                continue;
            };
            metrics.push(MetricSample {
                key: MetricKey::new("proc_conntrack", "conntrack_cpu", metric)
                    .with_label("cpu", cpu.to_string()),
                value: row[column],
            });
        }
    }
    Ok(metrics)
}

fn read_unsigned_decimal(path: &Path, name: &str) -> anyhow::Result<u64> {
    read_to_string(path)?
        .trim()
        .parse::<u64>()
        .with_context(|| format!("invalid {name} value"))
}

const SOFTNET_COUNTER_FIELDS: [(&str, usize); 5] = [
    ("processed", 0),
    ("dropped", 1),
    ("time_squeeze", 2),
    ("received_rps", 9),
    ("flow_limit_count", 10),
];
const SOFTNET_GAUGE_FIELDS: [(&str, usize); 3] = [
    ("backlog_len", 11),
    ("input_qlen", 13),
    ("process_qlen", 14),
];
const SOFTNET_MIN_COLUMNS: usize = 11;
const SOFTNET_CPU_COLUMN: usize = 12;
const MAX_SOFTNET_CPUS: u32 = 65_536;

#[derive(Debug)]
struct SoftnetRow {
    counters: [u64; SOFTNET_COUNTER_FIELDS.len()],
    gauges: [Option<u64>; SOFTNET_GAUGE_FIELDS.len()],
    embedded_cpu: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct SoftnetRowSchema {
    cpu: Option<u32>,
    gauges: [bool; SOFTNET_GAUGE_FIELDS.len()],
}

#[derive(Debug)]
enum SoftnetValueSource {
    Counter { row: usize, field: usize },
    Gauge { row: usize, field: usize },
    CounterTotal(usize),
    GaugeTotal(usize),
}

/// Reuses parser scratch and owned raw keys while still reading fresh files.
#[derive(Debug, Default)]
pub(crate) struct SoftnetContext {
    input: String,
    rows: Vec<SoftnetRow>,
    cpu_ids: Vec<u32>,
    unique_cpu_ids: Vec<u32>,
    schema: Vec<SoftnetRowSchema>,
    metrics: Vec<MetricSample>,
    value_sources: Vec<SoftnetValueSource>,
}

impl SoftnetContext {
    pub(crate) fn collect(
        &mut self,
        path: &Path,
        cpu_online_path: &Path,
    ) -> anyhow::Result<&[MetricSample]> {
        let online_before = read_online_cpus(cpu_online_path);
        self.input.clear();
        std::fs::File::open(path)
            .and_then(|mut file| file.read_to_string(&mut self.input))
            .map_err(|error| anyhow!("{}: {error}", path.display()))?;
        let online_after = read_online_cpus(cpu_online_path);
        let stable_online_cpus = (online_before == online_after)
            .then_some(online_before)
            .flatten();
        let input = std::mem::take(&mut self.input);
        let result = self.parse(&input, stable_online_cpus.as_deref());
        self.input = input;
        result?;
        Ok(&self.metrics)
    }

    fn parse(&mut self, input: &str, online_cpus: Option<&[u32]>) -> anyhow::Result<()> {
        self.rows.clear();
        for (line_number, line) in input.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            // Only these columns have semantics; later columns stay ignored.
            let mut fields = [""; 15];
            let mut column_count = 0;
            for (slot, field) in fields.iter_mut().zip(line.split_whitespace()) {
                *slot = field;
                column_count += 1;
            }
            let fields = &fields[..column_count];
            if fields.len() < SOFTNET_MIN_COLUMNS {
                bail!(
                    "softnet line {} has fewer than {SOFTNET_MIN_COLUMNS} columns",
                    line_number + 1
                );
            }
            let mut counters = [0_u64; SOFTNET_COUNTER_FIELDS.len()];
            for ((_, column), value) in SOFTNET_COUNTER_FIELDS.iter().zip(&mut counters) {
                *value = parse_softnet_hex(fields[*column], line_number, *column)?;
            }
            let mut gauges = [None; SOFTNET_GAUGE_FIELDS.len()];
            for ((_, column), value) in SOFTNET_GAUGE_FIELDS.iter().zip(&mut gauges) {
                *value = fields
                    .get(*column)
                    .map(|field| parse_softnet_hex(field, line_number, *column))
                    .transpose()?;
            }
            let embedded_cpu = fields
                .get(SOFTNET_CPU_COLUMN)
                .map(|value| parse_softnet_cpu(value, line_number))
                .transpose()?;
            self.rows.push(SoftnetRow {
                counters,
                gauges,
                embedded_cpu,
            });
        }

        if self.rows.is_empty() {
            bail!("softnet file contains no CPU rows");
        }
        let embedded_count = self
            .rows
            .iter()
            .filter(|row| row.embedded_cpu.is_some())
            .count();
        if embedded_count != 0 && embedded_count != self.rows.len() {
            bail!("softnet rows inconsistently expose the CPU identity column");
        }

        self.cpu_ids.clear();
        if embedded_count == self.rows.len() {
            self.cpu_ids.extend(
                self.rows
                    .iter()
                    .map(|row| row.embedded_cpu.expect("all rows have CPU IDs")),
            );
        } else if let Some(cpus) = online_cpus.filter(|cpus| cpus.len() == self.rows.len()) {
            self.cpu_ids.extend_from_slice(cpus);
        }
        self.unique_cpu_ids.clear();
        self.unique_cpu_ids.extend_from_slice(&self.cpu_ids);
        self.unique_cpu_ids.sort_unstable();
        if self
            .unique_cpu_ids
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            bail!("softnet CPU identities contain duplicates");
        }

        let mut counter_totals = [0_u64; SOFTNET_COUNTER_FIELDS.len()];
        let mut gauge_totals = [Some(0_u64); SOFTNET_GAUGE_FIELDS.len()];
        for row in &self.rows {
            for (((name, _), value), total) in SOFTNET_COUNTER_FIELDS
                .iter()
                .zip(row.counters)
                .zip(&mut counter_totals)
            {
                *total = total
                    .checked_add(value)
                    .ok_or_else(|| anyhow!("softnet {name} aggregate overflow"))?;
            }
            for (((name, _), value), total) in SOFTNET_GAUGE_FIELDS
                .iter()
                .zip(row.gauges)
                .zip(&mut gauge_totals)
            {
                let Some(value) = value else {
                    *total = None;
                    continue;
                };
                if let Some(current_total) = total {
                    *current_total = current_total
                        .checked_add(value)
                        .ok_or_else(|| anyhow!("softnet {name} aggregate overflow"))?;
                }
            }
        }

        // Parsing, identity validation and overflow checks precede publication.
        // All variable key fields and metric presence are captured by this schema;
        // source/group/names and the absence of width labels are fixed above.
        let same_schema = self.schema.len() == self.rows.len()
            && self
                .schema
                .iter()
                .enumerate()
                .all(|(index, schema)| *schema == self.row_schema(index));
        if !same_schema {
            self.rebuild_schema();
        }
        for (metric, source) in self.metrics.iter_mut().zip(&self.value_sources) {
            metric.value = match *source {
                SoftnetValueSource::Counter { row, field } => self.rows[row].counters[field],
                SoftnetValueSource::Gauge { row, field } => {
                    self.rows[row].gauges[field].expect("schema includes this gauge")
                }
                SoftnetValueSource::CounterTotal(field) => counter_totals[field],
                SoftnetValueSource::GaugeTotal(field) => {
                    gauge_totals[field].expect("schema includes this aggregate")
                }
            };
        }
        Ok(())
    }

    fn row_schema(&self, index: usize) -> SoftnetRowSchema {
        SoftnetRowSchema {
            cpu: self.cpu_ids.get(index).copied(),
            gauges: self.rows[index].gauges.map(|value| value.is_some()),
        }
    }

    fn rebuild_schema(&mut self) {
        let mut metrics = Vec::with_capacity(
            (SOFTNET_COUNTER_FIELDS.len() + SOFTNET_GAUGE_FIELDS.len()) * (self.rows.len() + 1),
        );
        self.schema.clear();
        for index in 0..self.rows.len() {
            let schema = self.row_schema(index);
            let (identity_label, identity) = match schema.cpu {
                Some(cpu) => ("cpu", cpu.to_string()),
                None => ("cpu_row", index.to_string()),
            };
            for (field, (name, _)) in SOFTNET_COUNTER_FIELDS.iter().enumerate() {
                metrics.push((
                    MetricSample {
                        key: MetricKey::new("proc_softnet", "softnet_cpu", *name)
                            .with_label(identity_label, &identity),
                        value: 0,
                    },
                    SoftnetValueSource::Counter { row: index, field },
                ));
            }
            for (field, (name, _)) in SOFTNET_GAUGE_FIELDS.iter().enumerate() {
                if schema.gauges[field] {
                    metrics.push((
                        MetricSample {
                            key: MetricKey::new("proc_softnet", "softnet_cpu", *name)
                                .with_label(identity_label, &identity),
                            value: 0,
                        },
                        SoftnetValueSource::Gauge { row: index, field },
                    ));
                }
            }
            self.schema.push(schema);
        }
        for (field, (name, _)) in SOFTNET_COUNTER_FIELDS.iter().enumerate() {
            metrics.push((sample(name, 0), SoftnetValueSource::CounterTotal(field)));
        }
        for (field, (name, _)) in SOFTNET_GAUGE_FIELDS.iter().enumerate() {
            if self.schema.iter().all(|row| row.gauges[field]) {
                metrics.push((sample(name, 0), SoftnetValueSource::GaugeTotal(field)));
            }
        }
        metrics.sort_by(|left, right| left.0.key.cmp(&right.0.key));
        (self.metrics, self.value_sources) = metrics.into_iter().unzip();
    }
}

fn parse_cpu_list(input: &str) -> anyhow::Result<Vec<u32>> {
    let mut cpus = BTreeSet::new();
    let input = input.trim();
    if input.is_empty() {
        bail!("online CPU list is empty");
    }
    for item in input.split(',') {
        let (start, end) = match item.split_once('-') {
            Some((start, end)) if !start.is_empty() && !end.is_empty() => {
                (parse_cpu_id(start)?, parse_cpu_id(end)?)
            }
            None => {
                let cpu = parse_cpu_id(item)?;
                (cpu, cpu)
            }
            _ => bail!("invalid online CPU range {item:?}"),
        };
        if end < start {
            bail!("online CPU range {item:?} is descending");
        }
        for cpu in start..=end {
            if !cpus.insert(cpu) {
                bail!("online CPU {cpu} appears more than once");
            }
        }
    }
    Ok(cpus.into_iter().collect())
}

fn parse_cpu_id(value: &str) -> anyhow::Result<u32> {
    let cpu = value
        .parse::<u32>()
        .with_context(|| format!("invalid online CPU ID {value:?}"))?;
    if cpu >= MAX_SOFTNET_CPUS {
        bail!("online CPU ID {cpu} exceeds supported bound");
    }
    Ok(cpu)
}

fn parse_net_dev(input: &str, interface: Option<&str>) -> anyhow::Result<Vec<MetricSample>> {
    let mut metrics = Vec::new();
    let mut found_interface = interface.is_none();

    for line in input.lines().skip(2) {
        let Some((name, values)) = line.rsplit_once(':') else {
            continue;
        };
        let name = name.trim();
        if interface.is_some_and(|selected| selected != name) {
            continue;
        }
        found_interface = true;

        let values: Vec<_> = values.split_whitespace().collect();
        if values.len() < NET_DEV_FIELDS.len() {
            bail!(
                "interface {name} has only {} statistic fields",
                values.len()
            );
        }

        for (metric, value) in NET_DEV_FIELDS.iter().zip(values) {
            let value = value
                .parse::<u64>()
                .with_context(|| format!("invalid {name}.{metric} value {value:?}"))?;
            metrics.push(MetricSample {
                key: MetricKey::new("proc_net_dev", "link", *metric).with_label("interface", name),
                value,
            });
        }
    }

    if !found_interface {
        return Err(anyhow!(
            "interface {} not found in proc net/dev",
            interface.unwrap_or_default()
        ));
    }
    Ok(metrics)
}

fn split_group(line: &str) -> anyhow::Result<(&str, &str)> {
    line.split_once(':')
        .map(|(group, values)| (group.trim(), values.trim()))
        .ok_or_else(|| anyhow!("missing group separator in {line:?}"))
}

fn parse_softnet_hex(value: &str, line_number: usize, column: usize) -> anyhow::Result<u64> {
    u64::from_str_radix(value, 16).with_context(|| {
        format!(
            "invalid softnet hex value in column {} on line {}",
            column + 1,
            line_number + 1
        )
    })
}

fn parse_softnet_cpu(value: &str, line_number: usize) -> anyhow::Result<u32> {
    let cpu = parse_softnet_hex(value, line_number, SOFTNET_CPU_COLUMN)?;
    let cpu = u32::try_from(cpu).with_context(|| {
        format!(
            "softnet CPU identity does not fit u32 on line {}",
            line_number + 1
        )
    })?;
    if cpu >= MAX_SOFTNET_CPUS {
        bail!("softnet CPU identity {cpu} exceeds supported bound");
    }
    Ok(cpu)
}

fn sample(name: &str, value: u64) -> MetricSample {
    MetricSample {
        key: MetricKey::new("proc_softnet", "softnet", name),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn tcp_memory_limit_is_the_third_threshold_in_pages() {
        let root = tempdir().unwrap();
        let directory = root.path().join("sys/net/ipv4");
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("tcp_mem");
        std::fs::write(&file, "8192\t16384\t32768\n").unwrap();
        let values = collect_tcp_memory_limit(root.path()).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].key.metric, "tcp_mem_max");
        assert_eq!(values[0].value, 32768);
        for invalid in ["1 2", "1 3 2", "1 2 3 4", "1 -2 3", "1 x 3"] {
            std::fs::write(&file, invalid).unwrap();
            assert!(collect_tcp_memory_limit(root.path()).is_err(), "{invalid}");
        }
        std::fs::remove_file(&file).unwrap();
        assert!(collect_tcp_memory_limit(root.path()).is_err());
    }

    fn parse_softnet(
        input: &str,
        online_cpus: Option<&[u32]>,
    ) -> anyhow::Result<Vec<MetricSample>> {
        let mut context = SoftnetContext::default();
        context.parse(input, online_cpus)?;
        Ok(context.metrics)
    }

    #[test]
    fn parses_snmp_name_value_pairs() {
        let input = "Udp: InDatagrams NoPorts InErrors RcvbufErrors\n\
                     Udp: 10 2 3 4\n\
                     Tcp: ActiveOpens RetransSegs\n\
                     Tcp: 7 8\n";
        let metrics = parse_named_tables(input, "fixture").unwrap();

        assert_eq!(metrics.len(), 6);
        let rcvbuf = metrics
            .iter()
            .find(|sample| sample.key.metric == "RcvbufErrors")
            .unwrap();
        assert_eq!(rcvbuf.value, 4);
        assert_eq!(rcvbuf.key.group, "Udp");
    }

    #[test]
    fn rejects_mismatched_table_rows() {
        let error = parse_named_tables("Udp: A B\nUdp: 1\n", "fixture").unwrap_err();
        assert!(error.to_string().contains("2 field names but 1 values"));
    }

    #[test]
    fn skips_negative_gauges_without_dropping_other_counters() {
        let input = "Tcp: MaxConn RetransSegs\nTcp: -1 8\n";
        let metrics = parse_named_tables(input, "fixture").unwrap();

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].key.metric, "RetransSegs");
        assert_eq!(metrics[0].value, 8);
    }

    #[test]
    fn parses_ipv6_name_value_rows_strictly() {
        let metrics =
            parse_name_values("Ip6InReceives 12\nUdp6RcvbufErrors 3\n", "proc_net_snmp6").unwrap();

        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].key.metric, "Ip6InReceives");
        assert!(parse_name_values("Ip6InReceives 1 extra\n", "fixture").is_err());
        assert!(parse_name_values("A 1\nA 2\n", "fixture").is_err());
    }

    #[test]
    fn parses_sockstat_pairs_as_gauges() {
        let metrics = parse_sockstat(
            "sockets: used 590\nTCP: inuse 40 orphan 0 tw 15 alloc 54 mem 1125\nUDP: inuse 7 mem 1280\n",
            "proc_sockstat",
        )
        .unwrap();

        assert_eq!(metric_value(&metrics, "sockets", "used"), 590);
        assert_eq!(metric_value(&metrics, "TCP", "mem"), 1125);
        assert_eq!(metric_value(&metrics, "UDP", "inuse"), 7);
        assert!(parse_sockstat("TCP: inuse\n", "fixture").is_err());
    }

    #[test]
    fn conntrack_stat_uses_stable_cpu_identity_and_hex_values() {
        let input = "entries found invalid insert insert_failed drop early_drop search_restart\n\
                     00000001 00000002 00000003 00000004 00000005 00000006 00000007 00000008\n\
                     00000009 0000000a 0000000b 0000000c 0000000d 0000000e 0000000f 00000010\n";
        let metrics = parse_conntrack_stat(input, Some(&[2, 7])).unwrap();

        assert!(metrics.iter().any(|sample| {
            sample.key.metric == "drop"
                && sample.key.labels.get("cpu").map(String::as_str) == Some("7")
                && sample.value == 14
        }));
        assert!(parse_conntrack_stat(input, Some(&[0])).unwrap().is_empty());
    }

    #[test]
    fn parses_stable_softnet_fields_with_cpu_identity() {
        let input = "0000000a 00000002 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000003 00000004\n\
                     00000014 00000003 00000004 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000006\n";
        let metrics = parse_softnet(input, Some(&[2, 7])).unwrap();

        assert_eq!(metrics.len(), 15);
        assert_eq!(metric_value(&metrics, "softnet", "processed"), 30);
        assert_eq!(metric_value(&metrics, "softnet", "dropped"), 5);
        assert_eq!(metric_value(&metrics, "softnet", "time_squeeze"), 5);
        assert_eq!(metric_value(&metrics, "softnet", "received_rps"), 8);
        assert_eq!(metric_value(&metrics, "softnet", "flow_limit_count"), 10);
        assert!(metrics.iter().any(|sample| {
            sample.key.group == "softnet_cpu"
                && sample.key.metric == "dropped"
                && sample.key.labels.get("cpu").map(String::as_str) == Some("7")
                && sample.value == 3
        }));
    }

    #[test]
    fn prefers_embedded_cpu_identity_on_newer_kernels() {
        let input = "0000000a 00000002 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000003 00000004 00000000 0000000a\n";
        let metrics = parse_softnet(input, Some(&[3])).unwrap();

        assert!(metrics.iter().any(|sample| {
            sample.key.group == "softnet_cpu"
                && sample.key.labels.get("cpu").map(String::as_str) == Some("10")
        }));
        assert_eq!(metric_value(&metrics, "softnet", "backlog_len"), 0);
        assert!(!metrics
            .iter()
            .any(|sample| sample.key.metric == "input_qlen"));
        assert!(!metrics
            .iter()
            .any(|sample| sample.key.metric == "process_qlen"));
    }

    #[test]
    fn parses_softnet_queue_lengths_from_fifteen_column_format() {
        let input = "0000000a 00000002 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000003 00000004 00000007 00000002 00000005 00000002\n\
                     00000014 00000003 00000004 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000006 0000000b 00000007 00000008 00000003\n";
        let metrics = parse_softnet(input, None).unwrap();

        assert_eq!(metric_value(&metrics, "softnet", "backlog_len"), 18);
        assert_eq!(metric_value(&metrics, "softnet", "input_qlen"), 13);
        assert_eq!(metric_value(&metrics, "softnet", "process_qlen"), 5);
        assert!(metrics.iter().any(|sample| {
            sample.key.group == "softnet_cpu"
                && sample.key.metric == "input_qlen"
                && sample.key.labels.get("cpu").map(String::as_str) == Some("7")
                && sample.value == 8
        }));
    }

    #[test]
    fn labels_rows_when_old_kernel_cpu_mapping_is_unavailable() {
        let input = "0000000a 00000002 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000003 00000004\n";
        let metrics = parse_softnet(input, Some(&[0, 2])).unwrap();

        assert!(metrics.iter().any(|sample| {
            sample.key.group == "softnet_cpu"
                && sample.key.labels.get("cpu_row").map(String::as_str) == Some("0")
        }));
    }

    fn softnet_row(cpu: u32, value: u64, columns: usize) -> String {
        let mut fields = vec!["00000000".to_owned(); columns];
        fields[0] = format!("{value:08x}");
        if columns > SOFTNET_CPU_COLUMN {
            fields[SOFTNET_CPU_COLUMN] = format!("{cpu:08x}");
        }
        format!("{}\n", fields.join(" "))
    }

    #[test]
    fn softnet_context_reuses_keys_and_updates_all_values() {
        let input = softnet_row(2, 10, 15) + &softnet_row(7, 20, 15);
        let mut context = SoftnetContext::default();
        context.parse(&input, None).unwrap();
        let buffer = context.metrics.as_ptr();
        let key_storage = context
            .metrics
            .iter()
            .map(|sample| {
                (
                    sample.key.source.as_ptr(),
                    sample.key.group.as_ptr(),
                    sample.key.metric.as_ptr(),
                    sample.key.labels.get("cpu").map(|cpu| cpu.as_ptr()),
                )
            })
            .collect::<Vec<_>>();
        let changed = input.replace("00000000", "00000001");
        context.parse(&changed, Some(&[30, 40])).unwrap();
        assert_eq!(context.metrics, parse_softnet(&changed, None).unwrap());
        assert_eq!(metric_value(&context.metrics, "softnet", "dropped"), 2);
        assert_eq!(metric_value(&context.metrics, "softnet", "input_qlen"), 2);
        assert_eq!(context.metrics.as_ptr(), buffer);
        for (sample, (source, group, metric, cpu)) in context.metrics.iter().zip(key_storage) {
            assert_eq!(sample.key.source.as_ptr(), source);
            assert_eq!(sample.key.group.as_ptr(), group);
            assert_eq!(sample.key.metric.as_ptr(), metric);
            assert_eq!(sample.key.labels.get("cpu").map(|cpu| cpu.as_ptr()), cpu);
            assert!(!sample.key.labels.contains_key("counter_bits"));
        }
    }

    #[test]
    fn softnet_context_tracks_complete_identity_and_optional_column_schema() {
        let mut context = SoftnetContext::default();
        let old = softnet_row(0, 10, 11) + &softnet_row(0, 20, 11);
        for cpus in [
            Some(&[2, 7][..]),
            Some(&[7, 2]),
            Some(&[7, 9]),
            None,
            Some(&[3]),
        ] {
            context.parse(&old, cpus).unwrap();
            assert_eq!(context.metrics, parse_softnet(&old, cpus).unwrap());
        }
        for columns in [12, 13, 14, 15, 14, 13, 11] {
            let input = softnet_row(2, 30, columns) + &softnet_row(7, 40, columns);
            context.parse(&input, Some(&[3, 9])).unwrap();
            assert_eq!(
                context.metrics,
                parse_softnet(&input, Some(&[3, 9])).unwrap()
            );
        }
        for input in [
            softnet_row(7, 40, 15) + &softnet_row(2, 30, 15),
            softnet_row(7, 41, 15) + &softnet_row(9, 31, 15),
            softnet_row(7, 42, 13) + &softnet_row(9, 32, 15),
            softnet_row(7, 43, 15) + &softnet_row(9, 33, 13),
            softnet_row(7, 44, 15),
            softnet_row(7, 45, 15) + &softnet_row(9, 35, 15) + &softnet_row(2, 25, 15),
        ] {
            context.parse(&input, None).unwrap();
            assert_eq!(context.metrics, parse_softnet(&input, None).unwrap());
        }
    }

    #[test]
    fn softnet_context_errors_do_not_publish_partial_samples() {
        let good = softnet_row(2, 10, 15) + &softnet_row(7, 20, 15);
        let mut context = SoftnetContext::default();
        context.parse(&good, None).unwrap();
        let snapshot = context.metrics.clone();
        let malformed = [
            (String::new(), "softnet file contains no CPU rows"),
            (
                "bad 0\n".to_owned(),
                "softnet line 1 has fewer than 11 columns",
            ),
            (
                softnet_row(2, 30, 15) + &softnet_row(7, 20, 15).replacen("00000014", "bad!", 1),
                "invalid softnet hex value in column 1 on line 2",
            ),
            (
                softnet_row(2, u64::MAX, 15) + &softnet_row(2, 1, 15),
                "softnet CPU identities contain duplicates",
            ),
            (
                softnet_row(2, 1, 11) + &softnet_row(7, 2, 15),
                "softnet rows inconsistently expose the CPU identity column",
            ),
            (
                softnet_row(65_536, 1, 15),
                "softnet CPU identity 65536 exceeds supported bound",
            ),
            (
                softnet_row(2, u64::MAX, 15) + &softnet_row(7, 1, 15),
                "softnet processed aggregate overflow",
            ),
            (
                softnet_row(2, 1, 15).replace("00000000", "ffffffffffffffff")
                    + &softnet_row(7, 1, 15).replace("00000000", "00000001"),
                "softnet dropped aggregate overflow",
            ),
        ];
        for (input, message) in malformed {
            assert_eq!(
                context.parse(&input, None).unwrap_err().to_string(),
                message
            );
            assert_eq!(context.metrics, snapshot);
        }
        assert_eq!(
            context
                .parse(&softnet_row(0, 1, 11).repeat(2), Some(&[2, 2]))
                .unwrap_err()
                .to_string(),
            "softnet CPU identities contain duplicates",
        );
        assert_eq!(context.metrics, snapshot);
        let recovered = softnet_row(3, 100, 13);
        context.parse(&recovered, None).unwrap();
        assert_eq!(context.metrics, parse_softnet(&recovered, None).unwrap());
    }

    #[test]
    fn softnet_context_preserves_ignored_columns_and_validation_order() {
        let base = softnet_row(2, 10, 15);
        let mut fields = base.split_whitespace().collect::<Vec<_>>();
        for field in &mut fields[3..9] {
            *field = "ignored!";
        }
        let input = fields.join(" ") + " future! invalid!\n";
        assert_eq!(
            parse_softnet(&input, None).unwrap(),
            parse_softnet(&base, None).unwrap()
        );
        for column in [0, 1, 2, 9, 10, 11, 12, 13, 14] {
            let mut fields = base.split_whitespace().collect::<Vec<_>>();
            fields[column] = "invalid!";
            assert_eq!(
                parse_softnet(&fields.join(" "), None)
                    .unwrap_err()
                    .to_string(),
                format!(
                    "invalid softnet hex value in column {} on line 1",
                    column + 1
                ),
            );
        }
        fields[12] = "invalid!";
        fields[14] = "invalid!";
        assert_eq!(
            parse_softnet(&fields.join(" "), None)
                .unwrap_err()
                .to_string(),
            "invalid softnet hex value in column 15 on line 1",
        );
        let mut overflow = base
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        overflow[11] = "ffffffffffffffff".to_owned();
        let mut next = softnet_row(7, 1, 15)
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        next[11] = "1".to_owned();
        assert_eq!(
            parse_softnet(&(overflow.join(" ") + "\n" + &next.join(" ")), None)
                .unwrap_err()
                .to_string(),
            "softnet backlog_len aggregate overflow",
        );
    }

    #[test]
    fn softnet_context_reopens_paths_and_recovers_after_read_failures() {
        let root = tempdir().unwrap();
        let path = root.path().join("softnet_stat");
        let online = root.path().join("online");
        let input = softnet_row(0, 10, 11) + &softnet_row(0, 20, 11);
        std::fs::write(&path, &input).unwrap();
        std::fs::write(&online, "2,7\n").unwrap();
        let mut context = SoftnetContext::default();
        assert_eq!(
            context.collect(&path, &online).unwrap(),
            collect_softnet(&path, &online).unwrap()
        );
        let replacement = root.path().join("replacement");
        std::fs::write(&replacement, input.replace("0000000a", "000000ff")).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            metric_value(
                context.collect(&path, &online).unwrap(),
                "softnet",
                "processed"
            ),
            275
        );
        for cpus in ["7,9", "invalid", "2,7"] {
            std::fs::write(&online, cpus).unwrap();
            assert_eq!(
                context.collect(&path, &online).unwrap(),
                collect_softnet(&path, &online).unwrap()
            );
        }
        std::fs::remove_file(&online).unwrap();
        assert!(context
            .collect(&path, &online)
            .unwrap()
            .iter()
            .any(|sample| sample.key.labels.contains_key("cpu_row")));
        let snapshot = context.metrics.clone();
        std::fs::remove_file(&path).unwrap();
        let error = context.collect(&path, &online).unwrap_err();
        assert_eq!(
            error.to_string(),
            collect_softnet(&path, &online).unwrap_err().to_string()
        );
        assert_eq!(context.metrics, snapshot);
        std::fs::write(&path, [0xff]).unwrap();
        assert!(context.collect(&path, &online).is_err());
        assert_eq!(context.metrics, snapshot);
        std::fs::write(&path, softnet_row(7, 42, 15)).unwrap();
        assert_eq!(
            context.collect(&path, &online).unwrap(),
            collect_softnet(&path, &online).unwrap()
        );
    }

    #[test]
    fn parses_online_cpu_ranges_without_duplicates() {
        assert_eq!(
            parse_cpu_list("0-2,7,9-10\n").unwrap(),
            vec![0, 1, 2, 7, 9, 10]
        );
        assert!(parse_cpu_list("0-2,2").is_err());
        assert!(parse_cpu_list("4-2").is_err());
    }

    #[test]
    fn collects_available_net_core_softirq_settings_without_fabricating_missing_values() {
        let root = tempdir().unwrap();
        let settings = root.path().join("sys/net/core");
        std::fs::create_dir_all(&settings).unwrap();
        std::fs::write(settings.join("netdev_budget"), "300\n").unwrap();
        std::fs::write(settings.join("netdev_budget_usecs"), "2000\n").unwrap();
        std::fs::write(settings.join("dev_weight"), "64\n").unwrap();

        let metrics = collect_net_core_settings(root.path()).unwrap();

        assert_eq!(metrics.len(), 3);
        assert_eq!(metric_value(&metrics, "net_core", "netdev_budget"), 300);
        assert_eq!(
            metric_value(&metrics, "net_core", "netdev_budget_usecs"),
            2000
        );
        assert_eq!(metric_value(&metrics, "net_core", "dev_weight"), 64);
        assert!(!metrics
            .iter()
            .any(|sample| sample.key.metric == "netdev_max_backlog"));
    }

    #[test]
    fn reports_not_found_when_no_net_core_softirq_settings_exist() {
        let root = tempdir().unwrap();

        let error = collect_net_core_settings(root.path()).unwrap_err();

        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        }));
        assert!(error.to_string().contains("no supported SoftIRQ settings"));
    }

    fn metric_value(metrics: &[MetricSample], group: &str, metric: &str) -> u64 {
        metrics
            .iter()
            .find(|sample| sample.key.group == group && sample.key.metric == metric)
            .unwrap()
            .value
    }

    #[test]
    fn parses_proc_net_dev_and_filters_interface() {
        let input = "Inter-| Receive | Transmit\n\
                     face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n\
                     lo: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n\
                     eth0: 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35\n";
        let metrics = parse_net_dev(input, Some("eth0")).unwrap();

        assert_eq!(metrics.len(), 16);
        assert_eq!(metrics[0].value, 20);
        assert_eq!(metrics[0].key.labels["interface"], "eth0");
        assert_eq!(metrics[3].key.metric, "rx_dropped_combined");
        assert_eq!(metrics[5].key.metric, "rx_frame_errors_combined");
        assert_eq!(metrics[11].key.metric, "tx_dropped");
        assert_eq!(metrics[11].value, 31);
        assert_eq!(metrics[14].key.metric, "tx_carrier_errors_combined");
    }
}
