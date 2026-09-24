use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::model::{IfIndex, MetricKey, MetricSample};

use super::valid_interface_name;

const PROC_SOFTIRQS_SOURCE: &str = "proc_softirqs";
const PROC_INTERRUPTS_SOURCE: &str = "proc_interrupts";
const MAX_CPU_COLUMNS: usize = 65_536;
const MAX_INTERFACES: usize = 65_536;
const MAX_IRQ_ROWS: usize = 1_048_576;
const MAX_MAPPED_IRQS: usize = 1_048_576;
const MAX_AFFINITY_LIST_BYTES: usize = 128;
const MAX_METRIC_SAMPLES: usize = 4_096;
const MAX_INTERRUPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INTERRUPT_CELLS: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkIrqRow {
    pub irq: u32,
    pub interfaces: Vec<(String, u32)>,
    pub counts: Vec<u64>,
    pub action: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkIrqData {
    pub cpus: Vec<u32>,
    pub rows: Vec<NetworkIrqRow>,
}

#[derive(Debug, Default)]
pub struct HardirqCollector {
    interfaces: Vec<VerifiedInterface>,
    refreshed: Option<Instant>,
    affinities: Option<Vec<AffinityRecord>>,
}

impl HardirqCollector {
    pub fn collect(
        &mut self,
        proc_root: &Path,
        sys_root: &Path,
    ) -> Result<HardirqCollection, CollectError> {
        if self
            .refreshed
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(30))
        {
            self.interfaces = collect_verified_interfaces(sys_root)?;
            self.refreshed = Some(Instant::now());
            self.affinities = None;
        }
        let result = collect_mapped_hardirqs(
            &proc_root.join("interrupts"),
            proc_root,
            self.interfaces.clone(),
            self.affinities.as_deref(),
        );
        if let Ok(collection) = &result {
            self.affinities = Some(collection.affinities.clone());
        }
        if result.is_err() {
            self.refreshed = None;
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectErrorKind {
    Io(io::ErrorKind),
    Parse,
}

#[derive(Debug)]
pub struct CollectError {
    kind: CollectErrorKind,
    message: String,
}

impl CollectError {
    fn io(path: &Path, action: &str, error: io::Error) -> Self {
        Self {
            kind: CollectErrorKind::Io(error.kind()),
            message: format!("{}: {action}: {error}", path.display()),
        }
    }

    fn io_context(context: impl Into<String>, error: io::Error) -> Self {
        Self {
            kind: CollectErrorKind::Io(error.kind()),
            message: format!("{}: {error}", context.into()),
        }
    }

    fn parse(path: &Path, message: impl Into<String>) -> Self {
        Self {
            kind: CollectErrorKind::Parse,
            message: format!("{}: {}", path.display(), message.into()),
        }
    }

    fn parse_context(message: impl Into<String>) -> Self {
        Self {
            kind: CollectErrorKind::Parse,
            message: message.into(),
        }
    }

    pub const fn kind(&self) -> CollectErrorKind {
        self.kind
    }

    pub const fn parse_errors(&self) -> u64 {
        if matches!(self.kind, CollectErrorKind::Parse) {
            1
        } else {
            0
        }
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinityRecord {
    pub interface: String,
    pub ifindex: u32,
    pub cpu_list: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HardirqCollection {
    pub metrics: Vec<MetricSample>,
    pub affinities: Vec<AffinityRecord>,
    pub skipped_shared_irqs: usize,
    pub table: NetworkIrqData,
}

pub fn collect_softirqs(path: &Path) -> Result<Vec<MetricSample>, CollectError> {
    let input = read_required(path)?;
    parse_softirqs(path, &input)
}

#[cfg(test)]
pub fn collect_hardirqs(
    proc_interrupts: &Path,
    proc_root: &Path,
    sys_root: &Path,
) -> Result<HardirqCollection, CollectError> {
    collect_mapped_hardirqs(
        proc_interrupts,
        proc_root,
        collect_verified_interfaces(sys_root)?,
        None,
    )
}

fn collect_mapped_hardirqs(
    proc_interrupts: &Path,
    proc_root: &Path,
    mut interfaces: Vec<VerifiedInterface>,
    cached_affinities: Option<&[AffinityRecord]>,
) -> Result<HardirqCollection, CollectError> {
    let mut owners = BTreeMap::<u32, Vec<(String, u32)>>::new();
    for interface in &interfaces {
        for irq in &interface.irqs {
            owners
                .entry(*irq)
                .or_default()
                .push((interface.name.clone(), interface.ifindex));
        }
    }
    let mapped_irqs = owners.keys().copied().collect();
    let mut input = String::new();
    std::fs::File::open(proc_interrupts)
        .and_then(|file| {
            file.take(MAX_INTERRUPT_BYTES + 1)
                .read_to_string(&mut input)
        })
        .map_err(|error| CollectError::io(proc_interrupts, "cannot read interrupts", error))?;
    if input.len() as u64 > MAX_INTERRUPT_BYTES {
        return Err(CollectError::parse(
            proc_interrupts,
            "interrupt file exceeds 16 MiB",
        ));
    }
    let parsed = parse_interrupts(proc_interrupts, &input, &mapped_irqs)?;
    let table = NetworkIrqData {
        cpus: parsed.cpus.clone(),
        rows: parsed
            .counts
            .iter()
            .map(|(irq, counts)| NetworkIrqRow {
                irq: *irq,
                interfaces: owners[irq].clone(),
                counts: counts.clone(),
                action: parsed.actions.get(irq).cloned().unwrap_or_default(),
            })
            .collect(),
    };
    // VFIO devices have a verified PF relationship but no host netdevice identity.
    interfaces.retain(|interface| !interface.name.contains('/'));
    // A configured IRQ may have no handler while a device is down.
    // Only counters actually present in procfs participate in summaries.
    for interface in &mut interfaces {
        interface.irqs.retain(|irq| parsed.counts.contains_key(irq));
    }
    let mut irq_owner_counts = BTreeMap::<u32, usize>::new();
    for interface in &interfaces {
        for irq in &interface.irqs {
            *irq_owner_counts.entry(*irq).or_default() += 1;
        }
    }
    let shared_irqs = irq_owner_counts
        .into_iter()
        .filter_map(|(irq, owners)| (owners > 1).then_some(irq))
        .collect::<BTreeSet<_>>();
    for interface in &mut interfaces {
        interface.irqs.retain(|irq| !shared_irqs.contains(irq));
    }
    interfaces.retain(|interface| !interface.irqs.is_empty());
    let compact = interfaces
        .len()
        .saturating_mul(parsed.cpus.len().saturating_add(2))
        > MAX_METRIC_SAMPLES;
    ensure_sample_bound(
        proc_interrupts,
        interfaces.len(),
        if compact { 3 } else { parsed.cpus.len() + 2 },
    )?;

    let mut metrics = Vec::new();
    let mut affinities = Vec::with_capacity(interfaces.len());
    for interface in interfaces {
        let mut per_cpu = vec![0_u64; parsed.cpus.len()];
        for irq in &interface.irqs {
            let counts = parsed.counts.get(irq).ok_or_else(|| {
                CollectError::parse(
                    proc_interrupts,
                    format!(
                        "verified IRQ mapping for interface {} has no numeric interrupt row",
                        interface.name
                    ),
                )
            })?;
            for (total, value) in per_cpu.iter_mut().zip(counts) {
                *total = total.checked_add(*value).ok_or_else(|| {
                    CollectError::parse(
                        proc_interrupts,
                        format!(
                            "interrupt counter aggregate overflow for {}",
                            interface.name
                        ),
                    )
                })?;
            }
        }

        let ifindex = interface.ifindex.to_string();
        if compact {
            let total = per_cpu
                .iter()
                .try_fold(0_u64, |total, value| total.checked_add(*value))
                .ok_or_else(|| {
                    CollectError::parse(proc_interrupts, "interface interrupt total overflow")
                })?;
            metrics.push(MetricSample {
                key: MetricKey::new(PROC_INTERRUPTS_SOURCE, "hardirq", "interface_interrupts")
                    .with_label("interface", &interface.name)
                    .with_label("ifindex", &ifindex),
                value: total,
            });
        } else {
            for (cpu, value) in parsed.cpus.iter().zip(&per_cpu) {
                metrics.push(MetricSample {
                    key: MetricKey::new(
                        PROC_INTERRUPTS_SOURCE,
                        "hardirq_cpu",
                        "network_interrupts",
                    )
                    .with_label("interface", &interface.name)
                    .with_label("ifindex", &ifindex)
                    .with_label("cpu", cpu.to_string())
                    .with_label("interrupt_class", "network"),
                    value: *value,
                });
            }
        }
        metrics.push(MetricSample {
            key: MetricKey::new(PROC_INTERRUPTS_SOURCE, "hardirq", "derived.cpu_imbalance")
                .with_label("interface", &interface.name)
                .with_label("ifindex", &ifindex),
            value: cpu_imbalance_bps(&per_cpu),
        });
        affinities.push(
            match cached_affinities.and_then(|rows| {
                rows.iter()
                    .find(|row| row.interface == interface.name && row.ifindex == interface.ifindex)
            }) {
                Some(row) => row.clone(),
                None => collect_affinity(proc_root, &interface)?,
            },
        );
    }

    metrics.sort_by(|left, right| left.key.cmp(&right.key));
    affinities.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.ifindex.cmp(&right.ifindex))
    });
    Ok(HardirqCollection {
        metrics,
        affinities,
        skipped_shared_irqs: shared_irqs.len(),
        table,
    })
}

fn read_required(path: &Path) -> Result<String, CollectError> {
    std::fs::read_to_string(path)
        .map_err(|error| CollectError::io(path, "cannot read counter file", error))
}

fn parse_softirqs(path: &Path, input: &str) -> Result<Vec<MetricSample>, CollectError> {
    let (cpus, header_line) = parse_cpu_header(path, input)?;
    ensure_sample_bound(path, cpus.len(), 2)?;
    let mut wanted = BTreeMap::<String, Vec<u64>>::new();
    let mut names = BTreeSet::new();

    for (line_index, line) in input.lines().enumerate().skip(header_line + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let (name, raw_values) = line.split_once(':').ok_or_else(|| {
            CollectError::parse(
                path,
                format!("softirq line {} has no ':' separator", line_index + 1),
            )
        })?;
        let name = name.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CollectError::parse(
                path,
                format!("softirq line {} has an invalid class name", line_index + 1),
            ));
        }
        if !names.insert(name.to_owned()) {
            return Err(CollectError::parse(
                path,
                format!("softirq class {name} appears more than once"),
            ));
        }

        let fields = raw_values.split_whitespace().collect::<Vec<_>>();
        if fields.len() != cpus.len() {
            return Err(cpu_column_error(path, line_index, cpus.len(), fields.len()));
        }
        let values = parse_decimal_counters(path, line_index, &cpus, &fields)?;
        if matches!(name, "NET_RX" | "NET_TX") {
            wanted.insert(name.to_owned(), values);
        }
    }

    for required in ["NET_RX", "NET_TX"] {
        if !wanted.contains_key(required) {
            return Err(CollectError::parse(
                path,
                format!("softirq file has no {required} row"),
            ));
        }
    }

    let mut metrics = Vec::with_capacity(cpus.len().saturating_mul(2));
    for metric in ["NET_RX", "NET_TX"] {
        let values = wanted
            .get(metric)
            .expect("required softirq rows were checked above");
        for (cpu, value) in cpus.iter().zip(values) {
            metrics.push(MetricSample {
                key: MetricKey::new(PROC_SOFTIRQS_SOURCE, "softirq_cpu", metric)
                    .with_label("cpu", cpu.to_string()),
                value: *value,
            });
        }
    }
    metrics.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(metrics)
}

fn ensure_sample_bound(
    path: &Path,
    entities: usize,
    samples_per_entity: usize,
) -> Result<(), CollectError> {
    let samples = entities.checked_mul(samples_per_entity).ok_or_else(|| {
        CollectError::parse(path, "metric sample cardinality calculation overflowed")
    })?;
    if samples > MAX_METRIC_SAMPLES {
        Err(CollectError::parse(
            path,
            format!("collection exceeds the {MAX_METRIC_SAMPLES}-sample bound"),
        ))
    } else {
        Ok(())
    }
}

struct ParsedInterrupts {
    cpus: Vec<u32>,
    counts: BTreeMap<u32, Vec<u64>>,
    actions: BTreeMap<u32, String>,
}

fn parse_interrupts(
    path: &Path,
    input: &str,
    mapped_irqs: &BTreeSet<u32>,
) -> Result<ParsedInterrupts, CollectError> {
    let (cpus, header_line) = parse_cpu_header(path, input)?;
    let mut counts = BTreeMap::new();
    let mut actions = BTreeMap::new();
    let mut seen_irqs = BTreeSet::new();
    let mut irq_rows = 0_usize;

    for (line_index, line) in input.lines().enumerate().skip(header_line + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let (raw_class, raw_values) = line.split_once(':').ok_or_else(|| {
            CollectError::parse(
                path,
                format!("interrupt line {} has no ':' separator", line_index + 1),
            )
        })?;
        let raw_class = raw_class.trim();
        if raw_class.is_empty() {
            return Err(CollectError::parse(
                path,
                format!("interrupt line {} has an empty class", line_index + 1),
            ));
        }
        if !raw_class.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }

        irq_rows = irq_rows.saturating_add(1);
        if irq_rows > MAX_IRQ_ROWS {
            return Err(CollectError::parse(
                path,
                format!("interrupt file exceeds the {MAX_IRQ_ROWS} numeric-row bound"),
            ));
        }
        let irq = raw_class.parse::<u32>().map_err(|_| {
            CollectError::parse(
                path,
                format!("interrupt line {} has an out-of-range IRQ", line_index + 1),
            )
        })?;
        if !seen_irqs.insert(irq) {
            return Err(CollectError::parse(
                path,
                format!("interrupt line {} repeats a numeric IRQ", line_index + 1),
            ));
        }

        let fields = raw_values.split_whitespace().collect::<Vec<_>>();
        if fields.len() < cpus.len() {
            return Err(cpu_column_error(path, line_index, cpus.len(), fields.len()));
        }
        let values = parse_decimal_counters(path, line_index, &cpus, &fields[..cpus.len()])?;
        if mapped_irqs.contains(&irq) {
            if counts.len().saturating_add(1).saturating_mul(cpus.len()) > MAX_INTERRUPT_CELLS {
                return Err(CollectError::parse(
                    path,
                    "network IRQ matrix exceeds the counter-cell bound",
                ));
            }
            actions.insert(
                irq,
                fields[cpus.len()..]
                    .join(" ")
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .take(160)
                    .collect(),
            );
            counts.insert(irq, values);
        }
    }

    Ok(ParsedInterrupts {
        cpus,
        counts,
        actions,
    })
}

fn parse_cpu_header(path: &Path, input: &str) -> Result<(Vec<u32>, usize), CollectError> {
    let (line_index, header) = input
        .lines()
        .enumerate()
        .find(|(_, line)| !line.trim().is_empty())
        .ok_or_else(|| CollectError::parse(path, "counter file is empty"))?;
    let fields = header.split_whitespace().collect::<Vec<_>>();
    if fields.is_empty() {
        return Err(CollectError::parse(path, "CPU header is empty"));
    }
    if fields.len() > MAX_CPU_COLUMNS {
        return Err(CollectError::parse(
            path,
            format!("CPU header exceeds the {MAX_CPU_COLUMNS}-column bound"),
        ));
    }

    let mut cpus = Vec::with_capacity(fields.len());
    for field in fields {
        let raw_cpu = field
            .strip_prefix("CPU")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CollectError::parse(path, "CPU header contains a non-CPU column"))?;
        if !raw_cpu.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CollectError::parse(
                path,
                "CPU header contains an invalid CPU identifier",
            ));
        }
        let cpu = raw_cpu
            .parse::<u32>()
            .map_err(|_| CollectError::parse(path, "CPU identifier does not fit in u32"))?;
        if cpu as usize >= MAX_CPU_COLUMNS {
            return Err(CollectError::parse(
                path,
                format!("CPU identifier exceeds the supported bound {MAX_CPU_COLUMNS}"),
            ));
        }
        if cpus.last().is_some_and(|previous| *previous >= cpu) {
            return Err(CollectError::parse(
                path,
                "CPU header identifiers are duplicated or out of order",
            ));
        }
        cpus.push(cpu);
    }
    Ok((cpus, line_index))
}

fn parse_decimal_counters(
    path: &Path,
    line_index: usize,
    cpus: &[u32],
    fields: &[&str],
) -> Result<Vec<u64>, CollectError> {
    fields
        .iter()
        .zip(cpus)
        .map(|(value, cpu)| {
            value.parse::<u64>().map_err(|_| {
                CollectError::parse(
                    path,
                    format!(
                        "counter for CPU{cpu} on line {} is not an unsigned decimal value",
                        line_index + 1
                    ),
                )
            })
        })
        .collect()
}

fn cpu_column_error(
    path: &Path,
    line_index: usize,
    expected: usize,
    actual: usize,
) -> CollectError {
    CollectError::parse(
        path,
        format!(
            "CPU columns are misaligned on line {}: expected {expected}, found {actual}",
            line_index + 1
        ),
    )
}

#[derive(Clone, Debug)]
struct VerifiedInterface {
    name: String,
    ifindex: u32,
    irqs: BTreeSet<u32>,
}

fn collect_verified_interfaces(sys_root: &Path) -> Result<Vec<VerifiedInterface>, CollectError> {
    let net_root = sys_root.join("class/net");
    let entries = std::fs::read_dir(&net_root)
        .map_err(|error| CollectError::io(&net_root, "cannot list network interfaces", error))?;
    let mut paths = Vec::<(String, PathBuf)>::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            CollectError::io(&net_root, "cannot read network interface entry", error)
        })?;
        // Class attributes such as bonding_masters are regular files. Keep
        // interface symlinks so their device relationships are still inspected.
        if entry
            .file_type()
            .map_err(|error| {
                CollectError::io(
                    &entry.path(),
                    "cannot inspect network interface entry",
                    error,
                )
            })?
            .is_file()
        {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|_| {
            CollectError::parse(&net_root, "network interface name is not valid UTF-8")
        })?;
        if !valid_interface_name(&name) {
            return Err(CollectError::parse(
                &net_root,
                "network interface name is not safe for metric identity",
            ));
        }
        paths.push((name, entry.path()));
        if paths.len() > MAX_INTERFACES {
            return Err(CollectError::parse(
                &net_root,
                format!("sysfs exceeds the {MAX_INTERFACES}-interface bound"),
            ));
        }
    }
    paths.sort_by(|left, right| left.0.cmp(&right.0));

    let mut interfaces = Vec::new();
    let mut mapped_associations = 0_usize;
    for (name, interface_path) in paths {
        let device = interface_path.join("device");
        match std::fs::metadata(&device) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(CollectError::parse(
                    &device,
                    "network interface device relation is not a directory",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(CollectError::io(
                    &device,
                    "cannot inspect network interface device relation",
                    error,
                ));
            }
        }

        let irqs = read_device_irqs(&device)?;
        if irqs.is_empty() {
            continue;
        }
        mapped_associations = mapped_associations.saturating_add(irqs.len());
        if mapped_associations > MAX_MAPPED_IRQS {
            return Err(CollectError::parse(
                &net_root,
                format!("sysfs exceeds the {MAX_MAPPED_IRQS}-IRQ mapping bound"),
            ));
        }
        let ifindex = read_ifindex(&interface_path)?;
        interfaces.push(VerifiedInterface {
            name,
            ifindex,
            irqs,
        });
    }
    let claimed: BTreeSet<u32> = interfaces
        .iter()
        .flat_map(|interface| interface.irqs.iter().copied())
        .collect();
    let mut virtual_functions = Vec::new();
    for interface in &interfaces {
        let device = net_root.join(&interface.name).join("device");
        let entries = std::fs::read_dir(&device)
            .map_err(|error| CollectError::io(&device, "cannot list VF relationships", error))?;
        for entry in entries {
            let entry = entry
                .map_err(|error| CollectError::io(&device, "cannot read VF relationship", error))?;
            let name = entry.file_name();
            let Some(index) = name
                .to_str()
                .and_then(|name| name.strip_prefix("virtfn"))
                .filter(|index| {
                    !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
                })
            else {
                continue;
            };
            let mut irqs = read_device_irqs(&entry.path())?;
            irqs.retain(|irq| !claimed.contains(irq));
            if !irqs.is_empty() {
                mapped_associations = mapped_associations.saturating_add(irqs.len());
                if mapped_associations > MAX_MAPPED_IRQS {
                    return Err(CollectError::parse(
                        &device,
                        "VF IRQ mapping bound exceeded",
                    ));
                }
                virtual_functions.push(VerifiedInterface {
                    name: format!("{}/vf{index}", interface.name),
                    ifindex: interface.ifindex,
                    irqs,
                });
            }
        }
    }
    interfaces.extend(virtual_functions);
    Ok(interfaces)
}

fn read_device_irqs(device: &Path) -> Result<BTreeSet<u32>, CollectError> {
    let mut irqs = read_msi_irqs(device)?;
    // PCI retains the legacy IRQ attribute even while MSI/MSI-X is active.
    if irqs.is_empty() {
        if let Some(irq) = read_legacy_irq(device)? {
            irqs.insert(irq);
        }
    }
    Ok(irqs)
}

fn read_msi_irqs(device: &Path) -> Result<BTreeSet<u32>, CollectError> {
    let path = device.join("msi_irqs");
    let entries = match std::fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => {
            return Err(CollectError::io(
                &path,
                "cannot list MSI IRQ relationships",
                error,
            ));
        }
    };
    let mut irqs = BTreeSet::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| CollectError::io(&path, "cannot read MSI IRQ entry", error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CollectError::parse(&path, "MSI IRQ entry is not valid UTF-8"))?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CollectError::parse(
                &path,
                "MSI IRQ entry is not a decimal IRQ identifier",
            ));
        }
        let irq = name
            .parse::<u32>()
            .map_err(|_| CollectError::parse(&path, "MSI IRQ identifier does not fit in u32"))?;
        irqs.insert(irq);
        if irqs.len() > MAX_MAPPED_IRQS {
            return Err(CollectError::parse(
                &path,
                format!("MSI IRQ directory exceeds the {MAX_MAPPED_IRQS}-entry bound"),
            ));
        }
    }
    Ok(irqs)
}

fn read_legacy_irq(device: &Path) -> Result<Option<u32>, CollectError> {
    let path = device.join("irq");
    let input = match std::fs::read_to_string(&path) {
        Ok(input) => input,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(CollectError::io(&path, "cannot read legacy IRQ", error)),
    };
    let irq = input
        .trim()
        .parse::<u32>()
        .map_err(|_| CollectError::parse(&path, "legacy IRQ is not an unsigned decimal value"))?;
    Ok((irq != 0).then_some(irq))
}

fn read_ifindex(interface_path: &Path) -> Result<u32, CollectError> {
    let path = interface_path.join("ifindex");
    let input = std::fs::read_to_string(&path)
        .map_err(|error| CollectError::io(&path, "cannot read interface index", error))?;
    let raw = input.trim().parse::<u32>().map_err(|_| {
        CollectError::parse(&path, "interface index is not an unsigned decimal value")
    })?;
    IfIndex::new(raw)
        .map(IfIndex::get)
        .map_err(|error| CollectError::parse(&path, error.to_string()))
}

fn collect_affinity(
    proc_root: &Path,
    interface: &VerifiedInterface,
) -> Result<AffinityRecord, CollectError> {
    let mut cpus = BTreeSet::new();
    let mut complete = true;
    for irq in &interface.irqs {
        let path = proc_root
            .join("irq")
            .join(irq.to_string())
            .join("effective_affinity_list");
        let input = match std::fs::read_to_string(&path) {
            Ok(input) => input,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                complete = false;
                continue;
            }
            Err(error) => {
                return Err(CollectError::io_context(
                    format!("cannot read effective IRQ affinity for {}", interface.name),
                    error,
                ));
            }
        };
        cpus.extend(parse_cpu_list(&input).map_err(|message| {
            CollectError::parse_context(format!(
                "invalid effective IRQ affinity for {}: {message}",
                interface.name
            ))
        })?);
    }

    let cpu_list = if cpus.is_empty() {
        None
    } else {
        let value = canonical_cpu_list(&cpus);
        if value.len() > MAX_AFFINITY_LIST_BYTES {
            return Err(CollectError::parse_context(format!(
                "effective IRQ affinity for {} exceeds the {MAX_AFFINITY_LIST_BYTES}-byte output bound",
                interface.name
            )));
        }
        Some(value)
    };
    if cpu_list.is_none() {
        complete = false;
    }
    Ok(AffinityRecord {
        interface: interface.name.clone(),
        ifindex: interface.ifindex,
        cpu_list,
        complete,
    })
}

fn parse_cpu_list(input: &str) -> Result<BTreeSet<u32>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("CPU list is empty".to_owned());
    }
    if !input
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b',' || byte == b'-')
    {
        return Err("CPU list contains an invalid character".to_owned());
    }

    let mut cpus = BTreeSet::new();
    for item in input.split(',') {
        if item.is_empty() {
            return Err("CPU list contains an empty range".to_owned());
        }
        let mut bounds = item.split('-');
        let start = bounds
            .next()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| "CPU list contains an invalid identifier".to_owned())?;
        let end = match (bounds.next(), bounds.next()) {
            (None, None) => start,
            (Some(end), None) => end
                .parse::<u32>()
                .map_err(|_| "CPU list contains an invalid range bound".to_owned())?,
            _ => return Err("CPU list contains a malformed range".to_owned()),
        };
        if end < start {
            return Err("CPU list contains a descending range".to_owned());
        }
        if end as usize >= MAX_CPU_COLUMNS {
            return Err(format!(
                "CPU list exceeds the supported CPU bound {MAX_CPU_COLUMNS}"
            ));
        }
        cpus.extend(start..=end);
    }
    Ok(cpus)
}

fn canonical_cpu_list(cpus: &BTreeSet<u32>) -> String {
    let mut output = String::new();
    let mut iter = cpus.iter().copied();
    let Some(mut start) = iter.next() else {
        return output;
    };
    let mut end = start;
    for cpu in iter {
        if cpu == end.saturating_add(1) {
            end = cpu;
            continue;
        }
        push_cpu_range(&mut output, start, end);
        start = cpu;
        end = cpu;
    }
    push_cpu_range(&mut output, start, end);
    output
}

fn push_cpu_range(output: &mut String, start: u32, end: u32) {
    if !output.is_empty() {
        output.push(',');
    }
    output.push_str(&start.to_string());
    if start != end {
        output.push('-');
        output.push_str(&end.to_string());
    }
}

// 0 bps means an even distribution and 10,000 bps means all interrupts ran
// on one CPU. This normalization remains comparable when CPU counts differ.
fn cpu_imbalance_bps(per_cpu: &[u64]) -> u64 {
    if per_cpu.len() <= 1 {
        return 0;
    }
    let total = per_cpu.iter().map(|value| u128::from(*value)).sum::<u128>();
    if total == 0 {
        return 0;
    }
    let maximum = u128::from(*per_cpu.iter().max().expect("non-empty CPU counters"));
    let cpu_count = per_cpu.len() as u128;
    let numerator = (cpu_count * maximum - total) * 10_000;
    let denominator = total * (cpu_count - 1);
    u64::try_from((numerator + denominator / 2) / denominator)
        .expect("normalized imbalance is at most 10,000 basis points")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::{tempdir, TempDir};

    use super::*;

    struct Fixture {
        _root: TempDir,
        proc_root: PathBuf,
        sys_root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempdir().unwrap();
            let proc_root = root.path().join("proc");
            let sys_root = root.path().join("sys");
            fs::create_dir_all(&proc_root).unwrap();
            fs::create_dir_all(sys_root.join("class/net")).unwrap();
            Self {
                _root: root,
                proc_root,
                sys_root,
            }
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self._root.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            path
        }

        fn msi_irq(&self, interface: &str, ifindex: u32, irq: u32) {
            self.write(
                &format!("sys/class/net/{interface}/ifindex"),
                &format!("{ifindex}\n"),
            );
            self.write(
                &format!("sys/class/net/{interface}/device/msi_irqs/{irq}"),
                "",
            );
        }

        fn legacy_irq(&self, interface: &str, ifindex: u32, irq: u32) {
            self.write(
                &format!("sys/class/net/{interface}/ifindex"),
                &format!("{ifindex}\n"),
            );
            self.write(
                &format!("sys/class/net/{interface}/device/irq"),
                &format!("{irq}\n"),
            );
        }

        fn affinity(&self, irq: u32, cpus: &str) {
            self.write(&format!("proc/irq/{irq}/effective_affinity_list"), cpus);
        }
    }

    fn metric_value<'a>(
        metrics: &'a [MetricSample],
        metric: &str,
        labels: &[(&str, &str)],
    ) -> &'a MetricSample {
        metrics
            .iter()
            .find(|sample| {
                sample.key.metric == metric
                    && labels.iter().all(|(name, value)| {
                        sample.key.labels.get(*name).map(String::as_str) == Some(*value)
                    })
            })
            .unwrap()
    }

    #[test]
    fn collects_net_softirqs_per_declared_cpu() {
        let fixture = Fixture::new();
        let path = fixture.write(
            "proc/softirqs",
            "          CPU0 CPU2 CPU4\n\
             TIMER:       1    2    3\n\
             NET_TX:      4    5    6\n\
             NET_RX:      7    8    9\n",
        );

        let metrics = collect_softirqs(&path).unwrap();

        assert_eq!(metrics.len(), 6);
        let rx = metric_value(&metrics, "NET_RX", &[("cpu", "2")]);
        assert_eq!(rx.key.source, PROC_SOFTIRQS_SOURCE);
        assert_eq!(rx.value, 8);
        assert_eq!(metric_value(&metrics, "NET_TX", &[("cpu", "4")]).value, 6);
    }

    #[test]
    fn softirq_missing_file_is_a_typed_io_error() {
        let fixture = Fixture::new();
        let error = collect_softirqs(&fixture.proc_root.join("missing")).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Io(io::ErrorKind::NotFound));
        assert_eq!(error.parse_errors(), 0);
    }

    #[test]
    fn softirq_rejects_misaligned_cpu_columns() {
        let fixture = Fixture::new();
        let path = fixture.write("proc/softirqs", "CPU0 CPU1\nNET_RX: 1\nNET_TX: 2 3\n");

        let error = collect_softirqs(&path).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("misaligned"));
        assert_eq!(error.parse_errors(), 1);
    }

    #[test]
    fn softirq_requires_both_network_rows() {
        let fixture = Fixture::new();
        let path = fixture.write("proc/softirqs", "CPU0\nNET_RX: 1\n");

        let error = collect_softirqs(&path).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("NET_TX"));
    }

    #[test]
    fn softirq_enforces_the_output_cardinality_bound() {
        let fixture = Fixture::new();
        let cpus = (0..=2_048)
            .map(|cpu| format!("CPU{cpu}"))
            .collect::<Vec<_>>()
            .join(" ");
        let path = fixture.write("proc/softirqs", &format!("{cpus}\n"));

        let error = collect_softirqs(&path).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("4096-sample bound"));
    }

    #[test]
    fn aggregates_only_sysfs_verified_hardirqs_without_raw_identity() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.msi_irq("eth0", 2, 41);
        fixture.legacy_irq("eth1", 3, 50);
        fixture.affinity(40, "0-1\n");
        fixture.affinity(41, "2\n");
        let interrupts = fixture.write(
            "proc/interrupts",
            "          CPU0 CPU1 CPU2\n\
               40:       10   20   30 PCI-MSI eth0-rx-0\n\
               41:        1    2    3 PCI-MSI unrelated-description\n\
               50:        5    5    5 IO-APIC legacy\n\
               77:      900  900  900 PCI-MSI eth0-rx-name-is-not-evidence\n\
              NMI:        1    2    3 Non-maskable interrupts\n\
              ERR:        0\n",
        );

        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();

        assert_eq!(collection.metrics.len(), 8);
        let cpu1 = metric_value(
            &collection.metrics,
            "network_interrupts",
            &[("interface", "eth0"), ("ifindex", "2"), ("cpu", "1")],
        );
        assert_eq!(cpu1.key.source, PROC_INTERRUPTS_SOURCE);
        assert_eq!(cpu1.value, 22);
        assert_eq!(cpu1.key.labels["interrupt_class"], "network");
        assert_eq!(
            metric_value(
                &collection.metrics,
                "derived.cpu_imbalance",
                &[("interface", "eth0")],
            )
            .value,
            2_500
        );
        assert_eq!(
            metric_value(
                &collection.metrics,
                "derived.cpu_imbalance",
                &[("interface", "eth1")],
            )
            .value,
            0
        );
        assert!(collection.metrics.iter().all(|sample| {
            !sample.key.labels.contains_key("irq")
                && !sample.key.labels.contains_key("vector")
                && !sample.key.labels.contains_key("queue")
                && sample.value != 900
        }));

        assert_eq!(collection.affinities.len(), 2);
        assert_eq!(
            collection.affinities[0],
            AffinityRecord {
                interface: "eth0".to_owned(),
                ifindex: 2,
                cpu_list: Some("0-2".to_owned()),
                complete: true,
            }
        );
        assert_eq!(collection.affinities[1].interface, "eth1");
        assert_eq!(collection.affinities[1].cpu_list, None);
        assert!(!collection.affinities[1].complete);
    }

    #[test]
    fn msi_mapping_ignores_inactive_legacy_irq_for_pf_and_vfio_vf() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.legacy_irq("eth0", 2, 39);
        fixture.write("sys/class/net/eth0/device/virtfn1/msi_irqs/41", "msix\n");
        fixture.write("sys/class/net/eth0/device/virtfn1/irq", "38\n");
        fixture.legacy_irq("eth1", 3, 50);
        let interrupts = fixture.write(
            "proc/interrupts",
            "CPU0 CPU1\n40: 10 20 PCI-MSI eth0\n41: 30 40 PCI-MSI vfio\n50: 1 2 IO-APIC eth1\n",
        );
        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(
            collection
                .table
                .rows
                .iter()
                .map(|row| row.irq)
                .collect::<Vec<_>>(),
            vec![40, 41, 50]
        );
        assert_eq!(
            collection.table.rows[1].interfaces,
            vec![("eth0/vf1".to_owned(), 2)]
        );
    }

    #[test]
    fn large_nic_cpu_matrix_keeps_all_raw_irqs_and_compacts_only_metric_summaries() {
        let fixture = Fixture::new();
        let mut input = (0..64)
            .map(|cpu| format!("CPU{cpu}"))
            .collect::<Vec<_>>()
            .join(" ");
        input.push('\n');
        for index in 0..100 {
            fixture.msi_irq(&format!("eth{index}"), index + 1, index + 40);
            input.push_str(&format!(
                "{}: {} MSI eth{index}\n",
                index + 40,
                vec!["3"; 64].join(" ")
            ));
        }
        fixture.write("proc/interrupts", &input);
        let collection = HardirqCollector::default()
            .collect(&fixture.proc_root, &fixture.sys_root)
            .unwrap();
        assert_eq!(collection.table.rows.len(), 100);
        assert_eq!(collection.table.cpus.len(), 64);
        assert_eq!(collection.metrics.len(), 200);
        assert!(collection
            .metrics
            .iter()
            .filter(|metric| metric.key.metric == "interface_interrupts")
            .all(|metric| metric.value == 192));
        assert_eq!(collection.affinities.len(), 100);
    }

    #[test]
    fn vfio_vfs_are_mapped_via_pf_without_duplicating_host_vfs() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.msi_irq("eth0v1", 3, 42);
        fixture.write("sys/class/net/eth0/device/virtfn0/msi_irqs/41", "");
        fixture.write("sys/class/net/eth0/device/virtfn1/msi_irqs/42", "");
        fixture.write(
            "proc/interrupts",
            "CPU0\n40: 10 pf\n41: 20 vfio-msix\n42: 30 vf\n",
        );
        let collection = HardirqCollector::default()
            .collect(&fixture.proc_root, &fixture.sys_root)
            .unwrap();
        assert_eq!(collection.table.rows.len(), 3);
        assert_eq!(
            collection.table.rows[1].interfaces,
            vec![("eth0/vf0".to_owned(), 2)]
        );
        assert_eq!(
            collection.table.rows[2].interfaces,
            vec![("eth0v1".to_owned(), 3)]
        );
        assert!(!collection
            .metrics
            .iter()
            .any(|metric| metric.key.labels["interface"].contains('/')));
    }

    #[test]
    fn topology_and_affinity_are_cached_but_interrupt_counters_are_fresh() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.affinity(40, "0");
        fixture.write("proc/interrupts", "CPU0 CPU1\n40: 10 0 eth0\n");
        let mut collector = HardirqCollector::default();
        let first = collector
            .collect(&fixture.proc_root, &fixture.sys_root)
            .unwrap();
        fixture.affinity(40, "1");
        fixture.write("proc/interrupts", "CPU0 CPU1\n40: 11 2 eth0\n");
        let next = collector
            .collect(&fixture.proc_root, &fixture.sys_root)
            .unwrap();
        assert_eq!(first.affinities, next.affinities);
        assert_eq!(next.table.rows[0].counts, vec![11, 2]);
        collector.refreshed = Some(Instant::now() - Duration::from_secs(31));
        let refreshed = collector
            .collect(&fixture.proc_root, &fixture.sys_root)
            .unwrap();
        assert_eq!(refreshed.affinities[0].cpu_list.as_deref(), Some("1"));
    }

    #[test]
    fn hardirq_ignores_regular_class_attributes_without_losing_interfaces() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.legacy_irq("eth1", 3, 50);
        fixture.affinity(40, "0\n");
        fixture.affinity(50, "1\n");
        let interrupts = fixture.write(
            "proc/interrupts",
            "CPU0 CPU1\n40: 11 12 MSI\n50: 21 22 legacy\n",
        );
        let expected =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(expected.metrics.len(), 6);
        for attribute in ["bonding_masters", "another_class_control_attribute"] {
            fixture.write(&format!("sys/class/net/{attribute}"), "eth0\n");
        }

        assert_eq!(
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap(),
            expected
        );
    }

    #[test]
    fn hardirq_keeps_symlinked_pf_and_vf_device_mappings_and_detects_removal() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let pci = fixture.sys_root.join("devices/pci0000:00");
        let pf = pci.join("0000:01:00.0");
        let vf = pci.join("0000:01:00.1");
        for (name, device, ifindex, irq) in [("pf0", &pf, 2, 40), ("vf0", &vf, 3, 50)] {
            let interface = device.join("net").join(name);
            fs::create_dir_all(&interface).unwrap();
            fs::create_dir_all(device.join("msi_irqs")).unwrap();
            fs::write(interface.join("ifindex"), format!("{ifindex}\n")).unwrap();
            fs::write(device.join("msi_irqs").join(irq.to_string()), "").unwrap();
            symlink("../..", interface.join("device")).unwrap();
            symlink(&interface, fixture.sys_root.join("class/net").join(name)).unwrap();
        }
        symlink(&pf, vf.join("physfn")).unwrap();
        symlink(&vf, pf.join("virtfn0")).unwrap();
        fixture.write("sys/class/net/bonding_masters", "");
        fixture.affinity(40, "0\n");
        fixture.affinity(50, "1\n");
        let interrupts = fixture.write(
            "proc/interrupts",
            "CPU0 CPU1\n40: 11 12 physical\n50: 101 102 virtual-function\n",
        );
        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(collection.metrics.len(), 6);
        assert_eq!(collection.skipped_shared_irqs, 0);
        for (name, ifindex, value, cpus) in [("pf0", "2", 11, "0"), ("vf0", "3", 101, "1")] {
            assert_eq!(
                metric_value(
                    &collection.metrics,
                    "network_interrupts",
                    &[("interface", name), ("ifindex", ifindex), ("cpu", "0")],
                )
                .value,
                value
            );
            let affinity = collection
                .affinities
                .iter()
                .find(|record| record.interface == name)
                .unwrap();
            assert_eq!(affinity.cpu_list.as_deref(), Some(cpus));
            assert!(affinity.complete);
        }

        fs::remove_file(fixture.sys_root.join("class/net/vf0")).unwrap();
        let remaining =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(remaining.metrics.len(), 3);
        assert!(remaining
            .metrics
            .iter()
            .all(|sample| sample.key.labels["interface"] == "pf0"));
        assert_eq!(remaining.affinities, collection.affinities[..1]);
    }

    #[test]
    fn hardirq_class_attributes_do_not_hide_real_device_or_identity_errors() {
        for (relative, contents, kind, detail) in [
            (
                "device",
                Some("invalid\n"),
                CollectErrorKind::Parse,
                "network interface device relation is not a directory",
            ),
            (
                "device/msi_irqs",
                Some("invalid\n"),
                CollectErrorKind::Io(io::Error::from_raw_os_error(libc::ENOTDIR).kind()),
                "cannot list MSI IRQ relationships",
            ),
            (
                "ifindex",
                Some("invalid\n"),
                CollectErrorKind::Parse,
                "interface index is not an unsigned decimal value",
            ),
            (
                "ifindex",
                None,
                CollectErrorKind::Io(io::ErrorKind::NotFound),
                "cannot read interface index",
            ),
        ] {
            let fixture = Fixture::new();
            fixture.msi_irq("eth0", 2, 40);
            fixture.write("sys/class/net/bonding_masters", "");
            let path = fixture.sys_root.join("class/net/eth0").join(relative);
            if path.is_dir() {
                fs::remove_dir_all(&path).unwrap();
            } else {
                fs::remove_file(&path).unwrap();
            }
            if let Some(contents) = contents {
                fs::write(&path, contents).unwrap();
            }
            let interrupts = fixture.write("proc/interrupts", "CPU0\n40: 1 device\n");

            let error =
                collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap_err();
            assert_eq!(error.kind(), kind, "{relative}: {error}");
            assert!(error.to_string().contains(&path.display().to_string()));
            assert!(error.to_string().contains(detail), "{error}");
        }
    }

    #[test]
    fn hardirq_class_attributes_do_not_hide_device_inspection_io_errors() {
        let fixture = Fixture::new();
        fixture.write("sys/class/net/eth0/ifindex", "2\n");
        fixture.write("sys/class/net/bonding_masters", "");
        let device = fixture.sys_root.join("class/net/eth0/device");
        std::os::unix::fs::symlink("device", &device).unwrap();
        let interrupts = fixture.write("proc/interrupts", "CPU0\n");

        let error =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap_err();
        assert_eq!(
            error.kind(),
            CollectErrorKind::Io(io::Error::from_raw_os_error(libc::ELOOP).kind())
        );
        assert!(error.to_string().contains(&device.display().to_string()));
        assert!(error
            .to_string()
            .contains("cannot inspect network interface device relation"));
    }

    #[test]
    fn hardirq_cardinality_boundary_is_explicit_for_64_cpu_interfaces() {
        let cpu_columns = 64;
        let samples_per_interface = cpu_columns + 2;
        let fitting_interfaces = MAX_METRIC_SAMPLES / samples_per_interface;

        assert_eq!(fitting_interfaces, 62);
        ensure_sample_bound(
            Path::new("fixture/proc/interrupts"),
            fitting_interfaces,
            samples_per_interface,
        )
        .unwrap();
        let error = ensure_sample_bound(
            Path::new("fixture/proc/interrupts"),
            fitting_interfaces + 1,
            samples_per_interface,
        )
        .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("4096-sample bound"));
    }

    #[test]
    fn shared_irq_is_not_duplicated_across_network_interfaces() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.msi_irq("eth0", 2, 41);
        fixture.msi_irq("eth1", 3, 40);
        fixture.msi_irq("eth1", 3, 50);
        fixture.affinity(41, "0\n");
        fixture.affinity(50, "1\n");
        let interrupts = fixture.write(
            "proc/interrupts",
            "CPU0 CPU1\n\
             40: 900 900 shared\n\
             41: 1 2 eth0-unique\n\
             50: 3 4 eth1-unique\n",
        );

        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();

        assert_eq!(collection.skipped_shared_irqs, 1);
        assert_eq!(collection.table.rows.len(), 3);
        assert_eq!(collection.table.rows[0].irq, 40);
        assert_eq!(
            collection.table.rows[0].interfaces,
            vec![("eth0".to_owned(), 2), ("eth1".to_owned(), 3)]
        );
        assert_eq!(collection.metrics.len(), 6);
        assert_eq!(
            metric_value(
                &collection.metrics,
                "network_interrupts",
                &[("interface", "eth0"), ("cpu", "0")],
            )
            .value,
            1
        );
        assert_eq!(
            metric_value(
                &collection.metrics,
                "network_interrupts",
                &[("interface", "eth1"), ("cpu", "1")],
            )
            .value,
            4
        );
        assert!(collection.metrics.iter().all(|sample| sample.value != 900));
        assert_eq!(collection.affinities.len(), 2);
        assert_eq!(collection.affinities[0].cpu_list.as_deref(), Some("0"));
        assert_eq!(collection.affinities[1].cpu_list.as_deref(), Some("1"));
    }

    #[test]
    fn hardirq_does_not_guess_interface_from_interrupt_description() {
        let fixture = Fixture::new();
        let interrupts = fixture.write(
            "proc/interrupts",
            "CPU0 CPU1\n42: 10 20 PCI-MSI eth0-rx-0\n",
        );

        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();

        assert!(collection.metrics.is_empty());
        assert!(collection.affinities.is_empty());
    }

    #[test]
    fn hardirq_rejects_numeric_rows_with_shifted_cpu_columns() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        let interrupts = fixture.write("proc/interrupts", "CPU0 CPU1 CPU2\n40: 1 2 PCI-MSI eth0\n");

        let error =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("CPU2"));
    }

    #[test]
    fn hardirq_omits_inactive_mappings_without_discarding_other_network_irqs() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.legacy_irq("eth1", 3, 41);
        let interrupts = fixture.write("proc/interrupts", "CPU0\n41: 12 eth1\n");

        let collection =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(collection.table.rows.len(), 1);
        assert_eq!(collection.table.rows[0].irq, 41);
        assert_eq!(collection.table.rows[0].counts, vec![12]);
        assert!(collection
            .metrics
            .iter()
            .all(|sample| sample.key.labels["interface"] == "eth1"));
        fixture.write("proc/interrupts", "CPU0\n40: 3 eth0\n41: 13 eth1\n");
        let resumed = collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap();
        assert_eq!(resumed.table.rows.len(), 2);
        assert_eq!(resumed.table.rows[0].counts, vec![3]);
    }

    #[test]
    fn hardirq_missing_interrupts_and_sysfs_are_typed_io_errors() {
        let fixture = Fixture::new();
        let missing_interrupts = fixture.proc_root.join("missing-interrupts");
        let error = collect_hardirqs(&missing_interrupts, &fixture.proc_root, &fixture.sys_root)
            .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Io(io::ErrorKind::NotFound));

        let other = tempdir().unwrap();
        let interrupts = other.path().join("interrupts");
        fs::write(&interrupts, "CPU0\n").unwrap();
        let error = collect_hardirqs(&interrupts, other.path(), &other.path().join("missing-sys"))
            .unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::Io(io::ErrorKind::NotFound));
    }

    #[test]
    fn hardirq_rejects_malformed_affinity_without_exposing_irq() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.affinity(40, "3-1\n");
        let interrupts = fixture.write("proc/interrupts", "CPU0\n40: 1 device\n");

        let error =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("descending"));
        assert!(!error.to_string().contains("40"));
    }

    #[test]
    fn hardirq_detects_aggregate_overflow() {
        let fixture = Fixture::new();
        fixture.msi_irq("eth0", 2, 40);
        fixture.msi_irq("eth0", 2, 41);
        let interrupts = fixture.write(
            "proc/interrupts",
            &format!("CPU0\n40: {} first\n41: 1 second\n", u64::MAX),
        );

        let error =
            collect_hardirqs(&interrupts, &fixture.proc_root, &fixture.sys_root).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Parse);
        assert!(error.to_string().contains("overflow"));
    }

    #[test]
    fn canonicalizes_affinity_cpu_lists() {
        let cpus = parse_cpu_list("4,2-3,0,1,7,7\n").unwrap();

        assert_eq!(canonical_cpu_list(&cpus), "0-4,7");
    }

    #[test]
    fn imbalance_is_normalized_across_cpu_counts() {
        assert_eq!(cpu_imbalance_bps(&[]), 0);
        assert_eq!(cpu_imbalance_bps(&[10]), 0);
        assert_eq!(cpu_imbalance_bps(&[10, 10, 10]), 0);
        assert_eq!(cpu_imbalance_bps(&[30, 0, 0]), 10_000);
        assert_eq!(cpu_imbalance_bps(&[11, 22, 33]), 2_500);
    }
}
