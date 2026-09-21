use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

mod softnet;
mod softnet_view;
mod stat;
mod terminal;
mod ui;

type Result<T> = std::result::Result<T, String>;

const HELP: &str = "Usage: irqtop|irqstat [options] [interval [count]]
Read-only IRQ rates. Both commands sample every second by default.
The first read is a baseline. irqstat defaults to hardware IRQs only;
add -s to include softirqs. irqtop shows hardware IRQs and softirqs by default.
Only CPUs above 200/s are shown; sources without a qualifying CPU are hidden.
irqtop: refresh in place, one combined IRQ/softirq list with per-CPU grids.

  -a               All hardware IRQs; all softirqs when enabled (default)
  -n               Network hardware IRQs; NET_RX/NET_TX when enabled
  -s               Include softirqs in irqstat (already enabled in irqtop)
  -b               Include host-wide per-CPU softnet statistics
  -i NIC[,NIC]     Select interfaces or PF/vfN labels; implies -n
  -m RATE          Show CPUs strictly above RATE/s (default: 200; 0 disables)
  -z               Show all non-zero sources (-m 0 also includes idle)
  -d               Show counts per interval instead of rates
  -h               Show help
  -v               Show version

interval: positive seconds, may be fractional; count: positive report count.
Default count: continuous. irqstat prints a timestamped table; irqtop refreshes.
Single-CPU sources use one row in irqstat; multi-CPU sources include details.
Local time.
irqtop keys: q quit, arrows/j/k scroll, PgUp/PgDn page, a all, n network,
z toggle the 200/s threshold, s sort, b softnet, Tab switch scrolling pane,
Home/g first, End/G last, wheel scroll.
Examples:
  irqtop
  irqtop -n
  irqtop -i xnic0 -m 500
  irqstat -n -s
  irqstat -n -d 1 5";

const DEFAULT_MIN_RATE: f64 = 200.0;
const NETWORK_REFRESH: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Domain {
    Hard,
    Soft,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
enum Scope {
    #[default]
    All,
    Network,
}

#[derive(Debug, PartialEq, Clone)]
struct Row {
    id: String,
    name: String,
    domain: Domain,
    counts: BTreeMap<u32, u64>,
}

#[derive(Debug)]
struct Snapshot {
    cpus: Vec<u32>,
    rows: BTreeMap<String, Row>,
    softnet: Option<softnet::Sample>,
}

fn parse(text: &str) -> Result<Snapshot> {
    parse_domain(text, Domain::Hard)
}

fn parse_domain(text: &str, domain: Domain) -> Result<Snapshot> {
    let mut lines = text.lines();
    let cpus: Vec<u32> = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|s| s.strip_prefix("CPU").and_then(|s| s.parse().ok()))
        .collect();
    if cpus.is_empty() {
        return Err("counter file has no CPU header (procfs may be restricted)".into());
    }
    let mut rows = BTreeMap::new();
    for line in lines {
        let Some((id, rest)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<_> = rest.split_whitespace().collect();
        if fields.len() < cpus.len() {
            continue;
        }
        let Ok(values) = fields[..cpus.len()]
            .iter()
            .map(|s| s.parse::<u64>())
            .collect::<std::result::Result<Vec<_>, _>>()
        else {
            continue;
        };
        // Non-per-CPU summaries such as ERR/MIS have a different scope.
        if matches!(id.trim(), "ERR" | "MIS") {
            continue;
        }
        rows.insert(
            id.trim().to_string(),
            Row {
                id: id.trim().to_string(),
                name: fields[cpus.len()..].join(" "),
                domain,
                counts: cpus.iter().copied().zip(values).collect(),
            },
        );
    }
    Ok(Snapshot {
        cpus,
        rows,
        softnet: None,
    })
}

fn merge_snapshots(hard: Option<Snapshot>, soft: Option<Snapshot>) -> Result<Snapshot> {
    let mut cpus = BTreeSet::new();
    let mut rows = BTreeMap::new();
    for snapshot in [hard, soft].into_iter().flatten() {
        cpus.extend(snapshot.cpus);
        for (id, row) in snapshot.rows {
            // Keep identities stable when interactive scope toggles add a source.
            let key = format!(
                "{}:{id}",
                match row.domain {
                    Domain::Hard => "hard",
                    Domain::Soft => "soft",
                }
            );
            rows.insert(key, row);
        }
    }
    if cpus.is_empty() {
        return Err("counter files have no CPU header (procfs may be restricted)".into());
    }
    Ok(Snapshot {
        cpus: cpus.into_iter().collect(),
        rows,
        softnet: None,
    })
}

#[derive(Default)]
struct Options {
    scope: Scope,
    top: bool,
    soft: bool,
    softnet: bool,
    network: Network,
    zero: bool,
    min_rate: f64,
    rate_sort: bool,
    delta: bool,
    devices: BTreeSet<String>,
    interval: Option<Duration>,
    count: Option<u64>,
}

impl Options {
    fn soft_enabled(&self) -> bool {
        self.top || self.soft
    }
}

fn options(args: Vec<String>) -> Result<Options> {
    let mut o = Options {
        min_rate: DEFAULT_MIN_RATE,
        ..Options::default()
    };
    let mut positional = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-a" => o.scope = Scope::All,
            "-n" => o.scope = Scope::Network,
            "-s" => o.soft = true,
            "-b" => o.softnet = true,
            "-z" => {
                o.zero = true;
                o.min_rate = 0.0;
            }
            "-m" => {
                let value = args.next().ok_or("-m requires a number")?;
                o.min_rate = value.parse::<f64>().map_err(|_| "invalid minimum rate")?;
                if !o.min_rate.is_finite() || o.min_rate < 0.0 {
                    return Err("minimum rate must be a finite non-negative number".into());
                }
                o.zero = false;
            }
            "-d" => o.delta = true,
            "-i" => {
                o.devices = args
                    .next()
                    .ok_or("-i requires an interface name")?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect();
                if o.devices.is_empty() {
                    return Err("-i requires an interface name".into());
                }
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => positional.push(arg),
        }
    }
    if positional.len() > 2 {
        return Err("expected interval [count]".into());
    }
    if let Some(value) = positional.first() {
        let seconds: f64 = value.parse().map_err(|_| "invalid interval")?;
        if !seconds.is_finite() || !(0.001..=86400.0).contains(&seconds) {
            return Err("interval must be between 0.001 and 86400 seconds".into());
        }
        o.interval = Some(Duration::from_secs_f64(seconds));
    }
    if let Some(value) = positional.get(1) {
        let count = value.parse::<u64>().map_err(|_| "invalid count")?;
        if count == 0 {
            return Err("count must be positive".into());
        }
        o.count = Some(count);
    }
    if o.interval.is_none() {
        o.interval = Some(Duration::from_secs(1));
    }
    if !o.devices.is_empty() {
        o.scope = Scope::Network;
    }
    Ok(o)
}

fn delta(old: Option<&Row>, new: &Row, cpu: u32, since_boot: bool) -> u64 {
    let current = new.counts.get(&cpu).copied().unwrap_or(0);
    if since_boot {
        return current;
    }
    old.filter(|r| r.name == new.name)
        .and_then(|r| r.counts.get(&cpu))
        .map(|previous| current.saturating_sub(*previous))
        .unwrap_or(0)
}

#[derive(Default)]
struct Network {
    irqs: BTreeSet<String>,
    names: BTreeSet<String>,
    interfaces: BTreeSet<String>,
    irq_devices: BTreeMap<String, BTreeSet<String>>,
    aliases: BTreeMap<String, BTreeSet<String>>,
    pci_devices: BTreeMap<String, BTreeSet<String>>,
    row_devices: BTreeMap<String, (String, BTreeSet<String>)>,
}

fn name_matches(text: &str, name: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .any(|token| {
            token == name
                || token
                    .strip_prefix(name)
                    .is_some_and(|suffix| suffix.starts_with('-') || suffix.starts_with(':'))
        })
}

impl Network {
    fn system() -> Result<Self> {
        let mut net = Self::discover(Path::new("/sys/class/net"))?;
        net.add_pci(Path::new("/sys/bus/pci/devices"))?;
        Ok(net)
    }

    fn add_pci(&mut self, root: &Path) -> Result<()> {
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("{}: {e}", root.display())),
        };
        let mut devices = Vec::new();
        let mut vf_labels = BTreeMap::new();
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let Ok(class) = fs::read_to_string(path.join("class")) else {
                continue;
            };
            let Ok(class) = u32::from_str_radix(class.trim().trim_start_matches("0x"), 16) else {
                continue;
            };
            if class >> 16 != 2 {
                continue;
            }
            let bdf = entry.file_name().to_string_lossy().into_owned();
            let ifaces: BTreeSet<String> = fs::read_dir(path.join("net"))
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            let pf = ifaces.first().cloned().unwrap_or_else(|| bdf.clone());
            // Only follow virtfn links from a verified network PCI function.
            // VFIO removes the netdev, but its MSI vectors remain host-visible.
            if let Ok(children) = fs::read_dir(&path) {
                for child in children.flatten() {
                    let name = child.file_name().to_string_lossy().into_owned();
                    if let Some(index) = name
                        .strip_prefix("virtfn")
                        .and_then(|s| s.parse::<u32>().ok())
                    {
                        if let Ok(target) = fs::read_link(child.path()) {
                            if let Some(vf) = target.file_name() {
                                vf_labels.insert(
                                    vf.to_string_lossy().into_owned(),
                                    format!("{pf}/vf{index}"),
                                );
                            }
                        }
                    }
                }
            }
            devices.push((path, bdf, ifaces));
        }
        for (path, bdf, ifaces) in devices {
            let labels = if ifaces.is_empty() {
                BTreeSet::from([vf_labels.get(&bdf).cloned().unwrap_or_else(|| bdf.clone())])
            } else {
                ifaces
            };
            self.interfaces.extend(labels.iter().cloned());
            self.pci_devices.insert(bdf, labels.clone());
            if let Ok(irqs) = fs::read_dir(path.join("msi_irqs")) {
                for irq in irqs.flatten() {
                    let id = irq.file_name().to_string_lossy().into_owned();
                    if id.parse::<u32>().is_ok() {
                        self.irqs.insert(id.clone());
                        self.irq_devices
                            .entry(id)
                            .or_default()
                            .extend(labels.iter().cloned());
                    }
                }
            }
            if let Ok(irq) = fs::read_to_string(path.join("irq")) {
                if let Ok(id) = irq.trim().parse::<u32>() {
                    if id > 0 {
                        self.irqs.insert(id.to_string());
                        self.irq_devices
                            .entry(id.to_string())
                            .or_default()
                            .extend(labels);
                    }
                }
            }
        }
        Ok(())
    }

    fn discover(root: &Path) -> Result<Self> {
        let mut net = Self::default();
        for entry in fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_name() == "lo" {
                continue;
            }
            let iface = entry.file_name().to_string_lossy().into_owned();
            net.interfaces.insert(iface.clone());
            net.aliases
                .entry(iface.clone())
                .or_default()
                .insert(iface.clone());
            net.names
                .insert(entry.file_name().to_string_lossy().into_owned());
            let Ok(mut device) = fs::canonicalize(entry.path().join("device")) else {
                continue;
            };
            // Virtio queue IRQs are often named virtioN-input/output, while
            // MSI vectors live on its immediate PCI parent.
            let virtio = device
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| {
                    s.strip_prefix("virtio")
                        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
                });
            if virtio {
                net.aliases
                    .entry(device.file_name().unwrap().to_string_lossy().into_owned())
                    .or_default()
                    .insert(iface.clone());
                net.names
                    .insert(device.file_name().unwrap().to_string_lossy().into_owned());
            }
            for level in 0..=usize::from(virtio) {
                if level == 1 {
                    device.pop();
                }
                if let Ok(entries) = fs::read_dir(device.join("msi_irqs")) {
                    for irq in entries.flatten() {
                        let id = irq.file_name().to_string_lossy().into_owned();
                        if id.parse::<u32>().is_ok() {
                            net.irq_devices
                                .entry(id.clone())
                                .or_default()
                                .insert(iface.clone());
                            net.irqs.insert(id);
                        }
                    }
                }
                if let Ok(irq) = fs::read_to_string(device.join("irq")) {
                    if let Ok(id) = irq.trim().parse::<u32>() {
                        if id > 0 {
                            net.irq_devices
                                .entry(id.to_string())
                                .or_default()
                                .insert(iface.clone());
                            net.irqs.insert(id.to_string());
                        }
                    }
                }
            }
        }
        Ok(net)
    }

    fn includes(&self, id: &str, name: &str) -> bool {
        if let Some((cached_name, devices)) = self.row_devices.get(id) {
            if cached_name == name {
                return self.irqs.contains(id) || !devices.is_empty();
            }
        }
        self.irqs.contains(id)
            || self.names.iter().any(|n| name_matches(name, n))
            || self
                .pci_devices
                .keys()
                .any(|bdf| name.contains(&format!("({bdf})")))
    }

    fn devices(&self, id: &str, name: &str) -> BTreeSet<String> {
        if let Some((cached_name, devices)) = self.row_devices.get(id) {
            if cached_name == name {
                return devices.clone();
            }
        }
        let mut devices = self.irq_devices.get(id).cloned().unwrap_or_default();
        for (alias, ifaces) in &self.aliases {
            if name_matches(name, alias) {
                devices.extend(ifaces.iter().cloned());
            }
        }
        for (bdf, labels) in &self.pci_devices {
            if name.contains(&format!("({bdf})")) {
                devices.extend(labels.iter().cloned());
            }
        }
        devices
    }

    fn cache_rows(&mut self, snapshot: &Snapshot) {
        self.row_devices.clear();
        self.row_devices = snapshot
            .rows
            .values()
            .filter(|row| row.domain == Domain::Hard)
            .map(|row| {
                (
                    row.id.clone(),
                    (row.name.clone(), self.devices(&row.id, &row.name)),
                )
            })
            .collect();
    }
}

fn included(o: &Options, row: &Row) -> bool {
    match row.domain {
        Domain::Hard => match o.scope {
            Scope::All => true,
            Scope::Network => o.network.includes(&row.id, &row.name),
        },
        Domain::Soft => {
            o.soft_enabled()
                && match o.scope {
                    Scope::All => true,
                    Scope::Network => matches!(row.id.as_str(), "NET_RX" | "NET_TX"),
                }
        }
    }
}

struct Frame {
    program: &'static str,
    width: usize,
    entries: Vec<DisplayRow>,
    scope: String,
    clock: String,
    totals: Vec<(Domain, String, &'static str)>,
    matched: usize,
    active: usize,
    cpu_count: usize,
    elapsed: f64,
    min_rate: f64,
    include_idle: bool,
    unit: &'static str,
    softnet: Option<softnet::Report>,
}

struct DisplayRow {
    id: String,
    source: String,
    domain: Domain,
    value: String,
    cpus: Vec<(u32, String)>,
    active_cpus: usize,
    peak_cpus: BTreeSet<u32>,
}

impl Frame {
    fn rate_filter(&self) -> String {
        if self.include_idle {
            "rate off".into()
        } else {
            format!("CPU rate > {}/s", self.min_rate)
        }
    }
}

fn fit(text: &str, width: usize) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .take(width)
        .collect()
}

fn scope_label(o: &Options) -> &'static str {
    match (o.scope, o.soft_enabled()) {
        (Scope::All, false) => "all hardware IRQs",
        (Scope::Network, false) => "network hardware IRQs",
        (Scope::All, true) => "all hard + all softirqs",
        (Scope::Network, true) => "network hard + NET_RX/NET_TX",
    }
}

fn frame(o: &Options, old: Option<&Snapshot>, new: &Snapshot, elapsed: f64, width: usize) -> Frame {
    let cpus = &new.cpus;
    let mut rows = Vec::new();
    for (key, row) in &new.rows {
        if !included(o, row) {
            continue;
        }
        let devices = if row.domain == Domain::Hard {
            o.network.devices(&row.id, &row.name)
        } else {
            BTreeSet::new()
        };
        if row.domain == Domain::Hard && !o.devices.is_empty() && devices.is_disjoint(&o.devices) {
            continue;
        }
        let previous = old.and_then(|s| s.rows.get(key));
        let counts: Vec<_> = cpus
            .iter()
            .map(|c| delta(previous, row, *c, old.is_none()))
            .collect();
        let total: u128 = counts.iter().map(|n| *n as u128).sum();
        rows.push((key, row, devices, counts, total));
    }
    rows.sort_by(|a, b| {
        if a.1.domain != b.1.domain {
            return match (a.1.domain, b.1.domain) {
                (Domain::Hard, Domain::Soft) => std::cmp::Ordering::Less,
                (Domain::Soft, Domain::Hard) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            };
        }
        if o.rate_sort && a.4 != b.4 {
            return b.4.cmp(&a.4);
        }
        match (a.1.id.parse::<u32>(), b.1.id.parse::<u32>()) {
            (Ok(a), Ok(b)) => a.cmp(&b),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            _ => a.1.id.cmp(&b.1.id),
        }
    });
    let hard_total: u128 = rows
        .iter()
        .filter(|r| r.1.domain == Domain::Hard)
        .map(|r| r.4)
        .sum();
    let soft_total: u128 = rows
        .iter()
        .filter(|r| r.1.domain == Domain::Soft)
        .map(|r| r.4)
        .sum();
    let active = rows.iter().filter(|r| r.4 != 0).count();
    let unit = if o.delta { "count" } else { "rate/s" };
    let value = |n: u128| {
        if o.delta {
            n.to_string()
        } else {
            format!("{:.2}", n as f64 / elapsed)
        }
    };
    let mut entries = Vec::new();
    for (_key, row, devices, counts, total) in &rows {
        let peak = counts.iter().copied().max().unwrap_or(0);
        if (o.min_rate > 0.0 && peak as f64 / elapsed <= o.min_rate) || (o.zero && *total == 0) {
            continue;
        }
        let source = if row.domain == Domain::Soft {
            "softirq".to_string()
        } else if devices.is_empty() {
            "-".to_string()
        } else {
            devices.iter().cloned().collect::<Vec<_>>().join(",")
        };
        let row_value = value(*total);
        let cpu_data: Vec<_> = cpus
            .iter()
            .zip(counts.iter())
            .filter(|(_, n)| **n > 0 && **n as f64 / elapsed > o.min_rate)
            .map(|(cpu, n)| (*cpu, value(*n as u128)))
            .collect();
        let peak_cpus = cpus
            .iter()
            .zip(counts.iter())
            .filter(|(_, n)| **n > 0 && **n == peak)
            .map(|(cpu, _)| *cpu)
            .collect();
        entries.push(DisplayRow {
            id: row.id.clone(),
            source,
            domain: row.domain,
            value: row_value,
            cpus: cpu_data,
            active_cpus: counts.iter().filter(|n| **n > 0).count(),
            peak_cpus,
        });
    }
    let devices = if o.devices.is_empty() {
        String::new()
    } else {
        format!(
            " ({})",
            o.devices.iter().cloned().collect::<Vec<_>>().join(",")
        )
    };
    let mut totals = vec![(
        Domain::Hard,
        value(hard_total),
        if o.delta { "count" } else { "intr/s" },
    )];
    if o.soft_enabled() {
        totals.push((
            Domain::Soft,
            value(soft_total),
            if o.delta { "count" } else { "soft/s" },
        ));
    }
    Frame {
        program: if o.top { "irqtop" } else { "irqstat" },
        width,
        entries,
        scope: format!("{}{}", scope_label(o), devices),
        clock: terminal::time(),
        totals,
        matched: rows.len(),
        active,
        cpu_count: cpus.len(),
        elapsed,
        min_rate: o.min_rate,
        include_idle: o.min_rate == 0.0 && !o.zero,
        unit,
        softnet: o.softnet.then(|| {
            softnet::Report::new(
                old.and_then(|s| s.softnet.as_ref()),
                new.softnet.as_ref(),
                o.delta,
            )
        }),
    }
}

#[cfg(test)]
fn render(
    out: &mut impl io::Write,
    o: &Options,
    old: Option<&Snapshot>,
    new: &Snapshot,
    elapsed: f64,
) -> io::Result<()> {
    stat::Printer::default().print(out, &frame(o, old, new, elapsed, 120), 24)
}

fn read(path: &str) -> Result<Snapshot> {
    parse(&fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?)
}

fn read_domain(path: &str, domain: Domain) -> Result<Snapshot> {
    parse_domain(
        &fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
        domain,
    )
}

fn read_sources(o: &Options) -> Result<Snapshot> {
    let mut snapshot = merge_snapshots(
        Some(read("/proc/interrupts")?),
        o.soft_enabled()
            .then(|| read_domain("/proc/softirqs", Domain::Soft))
            .transpose()?,
    )?;
    snapshot.softnet = o.softnet.then(softnet::read);
    Ok(snapshot)
}

fn switch_scope(o: &mut Options, scope: Scope) {
    o.scope = scope;
    if scope == Scope::All {
        o.devices.clear();
    }
}

fn refresh_network(before: &Snapshot, after: &Snapshot, elapsed: Duration) -> bool {
    fn hardware(snapshot: &Snapshot) -> impl Iterator<Item = (&String, &String)> {
        snapshot
            .rows
            .iter()
            .filter(|(_, row)| row.domain == Domain::Hard)
            .map(|(id, row)| (id, &row.name))
    }
    elapsed >= NETWORK_REFRESH || hardware(before).ne(hardware(after))
}

fn program_name() -> &'static str {
    match env::args_os()
        .next()
        .as_deref()
        .and_then(|p| Path::new(p).file_name())
    {
        Some(name) if name == "irqstat" => "irqstat",
        _ => "irqtop",
    }
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.iter().any(|s| s == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let top = program_name() == "irqtop";
    if args.iter().any(|s| s == "-v") {
        println!("{} {}", program_name(), env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut o = options(args)?;
    o.top = top;
    o.rate_sort = top;
    o.network = Network::system()?;
    for device in &o.devices {
        if !o.network.interfaces.contains(device) {
            return Err(format!(
                "network device {device:?} does not exist; use a netdev name or PF/vfN label"
            ));
        }
    }
    let mut before = read_sources(&o)?;
    o.network.cache_rows(&before);
    let mut last = Instant::now();
    let mut network_refreshed = last;
    terminal::signals();
    let mut terminal = terminal::Terminal::enter(top).map_err(|e| e.to_string())?;
    let mut out = io::stdout();
    let output_result = |r: io::Result<()>| -> Result<bool> {
        match r {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    };
    let mut view = ui::State::default();
    let mut printer = stat::Printer::default();
    let interval = o.interval.unwrap();
    terminal.sampling().map_err(|e| e.to_string())?;
    let mut reports = 0;
    let mut displayed: Option<(Snapshot, f64, Frame)> = None;
    let mut dimensions = terminal::size();
    while !terminal::STOP.load(Ordering::Relaxed) {
        let mut redraw = false;
        let mut rebuild = false;
        let wait = interval
            .saturating_sub(last.elapsed())
            .min(Duration::from_millis(250));
        let key = if terminal.active() {
            terminal.key(wait).map_err(|e| e.to_string())?
        } else {
            thread::sleep(wait);
            None
        };
        if terminal::STOP.load(Ordering::Relaxed) {
            break;
        }
        if let Some(key) = key {
            let page = if view.softnet_focus {
                view.softnet_page_size
            } else {
                view.page_size
            }
            .max(1);
            let offset = if view.softnet_focus {
                &mut view.softnet_offset
            } else {
                &mut view.offset
            };
            match key {
                b'q' | b'Q' => break,
                b'j' => *offset = offset.saturating_add(1),
                b'k' => *offset = offset.saturating_sub(1),
                b' ' => *offset = offset.saturating_add(page),
                b'p' => *offset = offset.saturating_sub(page),
                b'g' => *offset = 0,
                b'G' => *offset = usize::MAX,
                b'\t' if o.softnet => view.softnet_focus = !view.softnet_focus,
                b'b' => {
                    o.softnet = !o.softnet;
                    before.softnet = o.softnet.then(softnet::read);
                    if let Some((old, _, _)) = displayed.as_mut() {
                        old.softnet = None;
                    }
                    view.softnet_focus = false;
                    view.softnet_offset = 0;
                    rebuild = true;
                }
                b'a' | b'n' => {
                    switch_scope(
                        &mut o,
                        if key == b'a' {
                            Scope::All
                        } else {
                            Scope::Network
                        },
                    );
                    view.offset = 0;
                    rebuild = true;
                }
                b'z' => {
                    if o.min_rate > 0.0 {
                        o.min_rate = 0.0;
                        o.zero = true;
                    } else {
                        o.min_rate = DEFAULT_MIN_RATE;
                        o.zero = false;
                    }
                    view.offset = 0;
                    rebuild = true;
                }
                b's' => {
                    o.rate_sort = !o.rate_sort;
                    view.offset = 0;
                    rebuild = true;
                }
                _ => {}
            }
            redraw = true;
        }
        if terminal.active() || last.elapsed() >= interval {
            let size = terminal::size();
            if size != dimensions {
                dimensions = size;
                redraw = true;
            }
        }
        if last.elapsed() >= interval {
            let after = read_sources(&o)?;
            let now = Instant::now();
            if refresh_network(&before, &after, now.duration_since(network_refreshed)) {
                o.network = Network::system()?;
                o.network.cache_rows(&after);
                network_refreshed = now;
            }
            let elapsed = now.duration_since(last).as_secs_f64();
            let current = frame(&o, Some(&before), &after, elapsed, dimensions.1);
            let rendered = if terminal.active() {
                terminal.draw(&current, &mut view)
            } else {
                printer.print(&mut out, &current, dimensions.0)
            };
            if !output_result(rendered)? {
                break;
            }
            reports += 1;
            if o.count.is_some_and(|count| reports >= count) {
                break;
            }
            let previous = std::mem::replace(&mut before, after);
            if terminal.active() {
                displayed = Some((previous, elapsed, current));
            }
            last = now;
        } else if redraw && terminal.active() {
            if let Some((old, elapsed, current)) = &mut displayed {
                if rebuild {
                    *current = frame(&o, Some(old), &before, *elapsed, dimensions.1);
                }
                if !output_result(terminal.draw(current, &mut view))? {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}: {error}", program_name());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn softnet_opt_in_is_host_wide_and_independent_of_irq_filters() {
        let mut old = parse("CPU28\n128: 100 handler\n").unwrap();
        let mut new = parse("CPU28\n128: 200 handler\n").unwrap();
        let at = Instant::now();
        old.softnet = Some(softnet::Sample {
            at,
            data: softnet::parse("64 0 0 0 0 0 0 0 0 0 0 0 28", &[]),
        });
        new.softnet = Some(softnet::Sample {
            at: at + Duration::from_secs(2),
            data: softnet::parse("66 1 1 0 0 0 0 0 0 0 1 2 28", &[]),
        });
        let disabled = options(vec![]).unwrap();
        assert!(frame(&disabled, Some(&old), &new, 2.0, 80)
            .softnet
            .is_none());
        let o = options(vec![
            "-b".into(),
            "-i".into(),
            "nic0".into(),
            "-m".into(),
            "999999".into(),
        ])
        .unwrap();
        assert!(!o.soft_enabled());
        let report = frame(&o, Some(&old), &new, 2.0, 80);
        assert!(report.entries.is_empty());
        let softnet = report.softnet.unwrap();
        assert_eq!(softnet.rows[0].id, 40);
        assert_eq!(softnet.total.events, [2, 1, 1, 0, 1]);
        assert_eq!(softnet.value(1), "0.50");
        let enabled = options(vec!["-b".into(), "-s".into()]).unwrap();
        assert!(enabled.soft_enabled() && enabled.softnet);
    }

    #[test]
    #[ignore = "read-only live sampling CPU profile; run explicitly on the target host"]
    fn profile_sampling_phases() {
        fn cpu_time() -> f64 {
            let mut t: libc::timespec = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut t) },
                0
            );
            t.tv_sec as f64 + t.tv_nsec as f64 * 1e-9
        }
        let mut o = options(vec!["-n".into()]).unwrap();
        let start = cpu_time();
        o.network = Network::system().unwrap();
        let discovery = cpu_time() - start;
        let mut before = read_sources(&o).unwrap();
        o.network.cache_rows(&before);
        let mut sampling = 0.0;
        let mut reporting = 0.0;
        for _ in 0..100 {
            let start = cpu_time();
            let after = read_sources(&o).unwrap();
            sampling += cpu_time() - start;
            let start = cpu_time();
            std::hint::black_box(frame(&o, Some(&before), &after, 1.0, 120));
            reporting += cpu_time() - start;
            before = after;
        }
        eprintln!(
            "CPU ms: mapping={:.3}, read/parse per sample={:.3}, frame per sample={:.3}",
            discovery * 1000.0,
            sampling * 10.0,
            reporting * 10.0
        );
    }

    #[test]
    fn cached_network_rows_preserve_shared_irqs_and_name_fallbacks() {
        let snapshot = parse("CPU0\n24: 10 driver\n25: 20 eth0-TxRx-1\n26: 30 storage\n27: 40 vfio-msix[0](0000:05:10.0)\n").unwrap();
        let mut net = Network::default();
        net.names.insert("eth0".into());
        net.aliases
            .insert("eth0".into(), BTreeSet::from(["eth0".into()]));
        net.irqs.insert("24".into());
        net.irq_devices
            .insert("24".into(), BTreeSet::from(["eth0".into(), "eth1".into()]));
        net.pci_devices
            .insert("0000:05:10.0".into(), BTreeSet::from(["eth0/vf0".into()]));
        let original: Vec<_> = snapshot
            .rows
            .values()
            .map(|r| {
                (
                    r.id.clone(),
                    r.name.clone(),
                    net.includes(&r.id, &r.name),
                    net.devices(&r.id, &r.name),
                )
            })
            .collect();
        net.cache_rows(&snapshot);
        for (id, name, included, devices) in original {
            assert_eq!(net.includes(&id, &name), included);
            assert_eq!(net.devices(&id, &name), devices);
        }
        assert!(!net.includes("25", "new-storage-handler"));
        assert!(net.devices("25", "new-storage-handler").is_empty());
        assert!(net.includes("26", "eth0-TxRx-2"));
        net.aliases
            .insert("eth0".into(), BTreeSet::from(["renamed".into()]));
        net.cache_rows(&snapshot);
        assert_eq!(
            net.devices("25", "eth0-TxRx-1"),
            BTreeSet::from(["renamed".into()])
        );
    }

    #[test]
    fn network_cache_refreshes_on_irq_changes_and_periodically() {
        let old = parse("CPU0\n24: 10 eth0\n25: 20 vfio\n").unwrap();
        let counters_only = parse("CPU0 CPU4\n24: 0 8 eth0\n25: 200 9 vfio\n").unwrap();
        assert!(!refresh_network(
            &old,
            &counters_only,
            Duration::from_secs(4)
        ));
        assert!(refresh_network(&old, &counters_only, NETWORK_REFRESH));
        for text in [
            "CPU0\n24: 10 eth1\n25: 20 vfio\n",
            "CPU0\n24: 10 eth0\n",
            "CPU0\n24: 10 eth0\n25: 20 vfio\n26: 0 nic0\n",
            "CPU0\n24: 10 eth0\n26: 20 vfio\n",
        ] {
            assert!(refresh_network(&old, &parse(text).unwrap(), Duration::ZERO));
        }
        let mut after = parse("CPU0\n24: 10 eth0\n25: 20 vfio\n").unwrap();
        after.rows.extend(
            parse_domain("CPU0\nNET_RX: 7\n", Domain::Soft)
                .unwrap()
                .rows,
        );
        assert!(!refresh_network(&old, &after, Duration::ZERO));
    }

    #[test]
    fn sparse_and_global() {
        let s = parse("CPU0 CPU4\n24: 10 20 PCI eth0\nERR: 5\n").unwrap();
        assert_eq!(s.cpus, vec![0, 4]);
        assert_eq!(s.rows["24"].counts[&4], 20);
        assert_eq!(s.rows.len(), 1);
        assert!(parse("").is_err());
    }
    #[test]
    fn resets_hotplug_reassignment() {
        let old = parse("CPU0\n24: 10 eth0\n").unwrap();
        let new = parse("CPU0 CPU4\n24: 2 900 eth0\n25: 999 1 eth1\n").unwrap();
        assert_eq!(delta(old.rows.get("24"), &new.rows["24"], 0, false), 0);
        assert_eq!(delta(old.rows.get("24"), &new.rows["24"], 4, false), 0);
        assert_eq!(delta(None, &new.rows["25"], 0, false), 0);
        assert_eq!(delta(old.rows.get("24"), &new.rows["25"], 0, false), 0);
        assert_eq!(delta(None, &new.rows["25"], 0, true), 999);
    }
    #[test]
    fn rate_and_filter() {
        let old = parse_domain("CPU0 CPU4\nNET_RX: 10 20\nTIMER: 0 0\n", Domain::Soft).unwrap();
        let new = parse_domain("CPU0 CPU4\nNET_RX: 14 26\nTIMER: 0 0\n", Domain::Soft).unwrap();
        let o = options(["-n", "-s", "-m", "0", "1", "2"].map(String::from).to_vec()).unwrap();
        let mut out = Vec::new();
        render(&mut out, &o, Some(&old), &new, 2.5).unwrap();
        let output = String::from_utf8(out).unwrap();
        assert!(output.contains("4.00"));
        assert!(!output.contains("TIMER"));
    }
    #[test]
    fn threshold_uses_each_cpu_rate_and_keeps_unfiltered_totals() {
        for domain in [Domain::Hard, Domain::Soft] {
            let before = parse_domain(
                "CPU0 CPU4 CPU63\n24: 0 0 0\n25: 0 0 0\n26: 0 0 0\n27: 0 0 0\n",
                domain,
            )
            .unwrap();
            let after = parse_domain(
                "CPU0 CPU4 CPU63\n24: 399 400 399\n25: 160 700 0\n26: 401 400 401\n27: 0 0 0\n",
                domain,
            )
            .unwrap();
            for count in [false, true] {
                let mut o = options(vec!["-s".into()]).unwrap();
                o.delta = count;
                let report = frame(&o, Some(&before), &after, 2.0, 80);
                assert_eq!(
                    report
                        .entries
                        .iter()
                        .map(|r| r.id.as_str())
                        .collect::<Vec<_>>(),
                    ["25", "26"]
                );
                assert_eq!(
                    report.entries[0].value,
                    if count { "860" } else { "430.00" }
                );
                assert_eq!(
                    report.entries[0].cpus,
                    vec![(4, if count { "700" } else { "350.00" }.into())]
                );
                assert_eq!(report.entries[0].peak_cpus, BTreeSet::from([4]));
                assert_eq!(
                    report.entries[1].value,
                    if count { "1202" } else { "601.00" }
                );
                assert_eq!(
                    report.entries[1]
                        .cpus
                        .iter()
                        .map(|(cpu, _)| *cpu)
                        .collect::<Vec<_>>(),
                    [0, 63]
                );
                assert_eq!(report.entries[1].peak_cpus, BTreeSet::from([0, 63]));
                assert_eq!(report.matched, 4);
                assert_eq!(report.active, 3);
                assert_eq!(
                    report.totals.iter().find(|t| t.0 == domain).unwrap().1,
                    if count { "3260" } else { "1630.00" }
                );
                o.min_rate = 0.0;
                assert_eq!(frame(&o, Some(&before), &after, 2.0, 80).entries.len(), 4);
                o.zero = true;
                assert_eq!(frame(&o, Some(&before), &after, 2.0, 80).entries.len(), 3);
            }
        }
    }

    #[test]
    fn invalid_options() {
        for args in [
            vec!["NaN"],
            vec!["0"],
            vec!["1", "0"],
            vec!["-P", "3-1"],
            vec!["--sort", "bad"],
            vec!["--since-boot", "1"],
            vec!["-n", "-d", "nic0"],
            vec!["-m"],
            vec!["-m", "NaN"],
            vec!["-m", "inf"],
            vec!["-m", "-1"],
            vec!["-i"],
            vec!["-i", ""],
        ] {
            assert!(options(args.into_iter().map(String::from).collect()).is_err());
        }
        for removed in [
            "-A",
            "-N",
            "-P",
            "-I",
            "-t",
            "-V",
            "-S",
            "--all-hard",
            "--net-hard",
            "--all-soft",
            "--net-soft",
            "--device",
            "--numa",
            "--min-rate",
            "--delta",
            "--since-boot",
            "--help",
            "--version",
        ] {
            assert!(options(vec![removed.into()]).is_err(), "{removed}");
        }
        assert_eq!(
            options(Vec::new()).unwrap().interval,
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn cpu_peaks_use_interval_counts_and_preserve_ties() {
        let before = parse("CPU0 CPU4 CPU63\nLOC: 10000 20 30 local\n").unwrap();
        let after = parse("CPU0 CPU4 CPU63\nLOC: 10001 270 280 local\n").unwrap();
        let mut o = options(vec!["-m".into(), "0".into()]).unwrap();
        let report = frame(&o, Some(&before), &after, 1.0, 80);
        assert_eq!(report.entries[0].peak_cpus, BTreeSet::from([4, 63]));
        let report = frame(&o, Some(&after), &after, 1.0, 80);
        assert!(report.entries[0].peak_cpus.is_empty());

        let rounded = parse("CPU0 CPU4\nLOC: 9007199254740992 9007199254740993 local\n").unwrap();
        for delta in [false, true] {
            o.delta = delta;
            let report = frame(&o, None, &rounded, 1.0, 80);
            assert_eq!(report.entries[0].peak_cpus, BTreeSet::from([4]));
        }
    }

    #[test]
    fn interface_filter_and_cpu_grid() {
        let before =
            parse("CPU0 CPU1\n24: 0 0 PCI 0-edge nic0-rx-0\n25: 0 0 PCI 0-edge xnic0-rx-0\n")
                .unwrap();
        let after =
            parse("CPU0 CPU1\n24: 3 7 PCI 0-edge nic0-rx-0\n25: 100 0 PCI 0-edge xnic0-rx-0\n")
                .unwrap();
        let mut o = options(vec!["-i".into(), "nic0".into()]).unwrap();
        for iface in ["nic0", "xnic0"] {
            o.network.names.insert(iface.into());
            o.network
                .aliases
                .insert(iface.into(), BTreeSet::from([iface.into()]));
        }
        o.min_rate = 0.0;
        let f = frame(&o, Some(&before), &after, 2.0, 120);
        assert_eq!(f.unit, "rate/s");
        assert_eq!(f.entries.len(), 1);
        assert_eq!(f.entries[0].id, "24");
        assert_eq!(f.entries[0].source, "nic0");
        assert_eq!(f.entries[0].value, "5.00");
        assert_eq!(
            f.entries[0].cpus,
            vec![(0, "1.50".into()), (1, "3.50".into())]
        );
        assert_eq!(f.totals[0].1, "5.00");

        o.min_rate = 200.0;
        let f = frame(&o, Some(&before), &after, 2.0, 120);
        assert!(f.entries.is_empty());
        assert_eq!(f.matched, 1);

        o.min_rate = 0.0;
        o.zero = true;
        let f = frame(&o, Some(&before), &after, 2.0, 120);
        assert_eq!(f.entries.len(), 1);

        o.zero = false;
        let f = frame(&o, Some(&before), &after, 2.0, 120);
        assert_eq!(f.entries.len(), 1);
    }

    #[test]
    fn network_scope_and_override() {
        let hard =
            parse("CPU0\n24: 10 PCI eth0-TxRx-0\n25: 20 PCI eth01\n26: 30 storage\n").unwrap();
        let soft = parse_domain("CPU0\nNET_RX: 2\nTIMER: 3\n", Domain::Soft).unwrap();
        let mut o = Options {
            scope: Scope::Network,
            soft: true,
            ..Options::default()
        };
        o.network.names.insert("eth0".into());
        assert!(included(&o, &hard.rows["24"]));
        assert!(!included(&o, &hard.rows["25"]));
        assert!(!included(&o, &hard.rows["26"]));
        o.network.irqs.insert("26".into());
        assert!(included(&o, &hard.rows["26"]));
        assert!(included(&o, &soft.rows["NET_RX"]));
        assert!(!included(&o, &soft.rows["TIMER"]));
        o.scope = Scope::All;
        assert!(included(&o, &soft.rows["TIMER"]));
    }

    #[test]
    fn stat_softirq_opt_in_and_top_default() {
        let snapshot = merge_snapshots(
            Some(parse("CPU0\n24: 100 PCI nic0\nLOC: 200 local\n").unwrap()),
            Some(
                parse_domain("CPU0\nNET_RX: 300\nNET_TX: 400\nTIMER: 500\n", Domain::Soft).unwrap(),
            ),
        )
        .unwrap();
        for top in [false, true] {
            for soft in [false, true] {
                for selector in [vec![], vec!["-a"], vec!["-n"], vec!["-i", "nic0"]] {
                    let mut args: Vec<_> = selector.iter().map(|s| s.to_string()).collect();
                    args.extend(["-m".into(), "0".into()]);
                    if soft {
                        args.push("-s".into());
                    }
                    let mut o = options(args).unwrap();
                    o.top = top;
                    o.network.names.insert("nic0".into());
                    o.network
                        .aliases
                        .insert("nic0".into(), BTreeSet::from(["nic0".into()]));
                    let report = frame(&o, None, &snapshot, 1.0, 80);
                    let ids: BTreeSet<_> = report.entries.iter().map(|r| r.id.as_str()).collect();
                    assert!(ids.contains("24"));
                    assert_eq!(ids.contains("LOC"), o.scope == Scope::All);
                    assert_eq!(ids.contains("NET_RX"), top || soft);
                    assert_eq!(ids.contains("NET_TX"), top || soft);
                    assert_eq!(
                        ids.contains("TIMER"),
                        (top || soft) && o.scope == Scope::All
                    );
                    assert_eq!(report.matched, ids.len());
                    assert_eq!(report.totals.len(), if top || soft { 2 } else { 1 });
                    assert_eq!(report.scope.contains('+'), top || soft);
                }
            }
        }
    }

    #[test]
    fn option_scopes_and_default() {
        let o = options(Vec::new()).unwrap();
        assert_eq!(o.scope, Scope::All);
        assert_eq!(o.min_rate, 200.0);
        assert_eq!(options(vec!["-a".into()]).unwrap().scope, Scope::All);
        assert_eq!(options(vec!["-n".into()]).unwrap().scope, Scope::Network);
        assert!(options(vec!["-d".into()]).unwrap().delta);
        for args in [
            vec!["-i", "nic0"],
            vec!["-a", "-i", "nic0"],
            vec!["-i", "nic0", "-a"],
        ] {
            let mut device = options(args.into_iter().map(String::from).collect()).unwrap();
            assert_eq!(device.scope, Scope::Network);
            switch_scope(&mut device, Scope::All);
            assert_eq!(device.scope, Scope::All);
            assert!(device.devices.is_empty());
            switch_scope(&mut device, Scope::Network);
            switch_scope(&mut device, Scope::Network);
            assert_eq!(device.scope, Scope::Network);
        }
    }

    #[test]
    fn mixed_snapshot_and_frame() {
        let old_hard = parse("CPU0 CPU1\n24: 10 20 PCI eth0\n").unwrap();
        let new_hard = parse("CPU0 CPU1\n24: 13 28 PCI eth0\n").unwrap();
        let old_soft =
            parse_domain("CPU0 CPU1\nNET_RX: 90 40\nTIMER: 1 2\n", Domain::Soft).unwrap();
        let new_soft =
            parse_domain("CPU0 CPU1\nNET_RX: 100 50\nTIMER: 2 4\n", Domain::Soft).unwrap();
        let old = merge_snapshots(Some(old_hard), Some(old_soft)).unwrap();
        let new = merge_snapshots(Some(new_hard), Some(new_soft)).unwrap();
        let o = options(vec!["-a".into(), "-s".into(), "-m".into(), "0".into()]).unwrap();
        let f = frame(&o, Some(&old), &new, 2.0, 120);
        assert_eq!(f.entries.len(), 3);
        assert_eq!(f.totals[0], (Domain::Hard, "5.50".into(), "intr/s"));
        assert_eq!(f.totals[1], (Domain::Soft, "11.50".into(), "soft/s"));
        assert!(f
            .entries
            .iter()
            .any(|row| row.id == "24" && row.value == "5.50"));

        let mut top = o;
        top.top = true;
        let f = frame(&top, Some(&old), &new, 2.0, 80);
        assert_eq!(f.program, "irqtop");
        assert_eq!(f.entries.len(), 3);
    }

    #[test]
    fn adding_hardware_scope_preserves_softirq_baseline() {
        let old = merge_snapshots(
            None,
            Some(parse_domain("CPU0\nNET_RX: 100\n", Domain::Soft).unwrap()),
        )
        .unwrap();
        let new = merge_snapshots(
            Some(parse("CPU0\n24: 900 PCI eth0\n").unwrap()),
            Some(parse_domain("CPU0\nNET_RX: 110\n", Domain::Soft).unwrap()),
        )
        .unwrap();
        let o = options(vec!["-a".into(), "-s".into(), "-m".into(), "0".into()]).unwrap();
        let f = frame(&o, Some(&old), &new, 1.0, 80);
        assert_eq!(
            f.entries.iter().find(|r| r.id == "NET_RX").unwrap().value,
            "10.00"
        );
        assert_eq!(
            f.entries.iter().find(|r| r.id == "24").unwrap().value,
            "0.00"
        );
    }

    #[test]
    fn sysfs_msi_and_virtio() {
        use std::os::unix::fs::symlink;
        let root = env::temp_dir().join(format!("irqstat-test-{}", std::process::id()));
        fs::create_dir_all(root.join("net/ens1")).unwrap();
        fs::create_dir_all(root.join("pci/msi_irqs/101")).unwrap();
        fs::create_dir_all(root.join("pci/virtio7")).unwrap();
        symlink(root.join("pci/virtio7"), root.join("net/ens1/device")).unwrap();
        let net = Network::discover(&root.join("net")).unwrap();
        assert!(net.includes("101", "driver-queue"));
        assert!(net.includes("99", "virtio7-input.0"));
        assert!(!net.includes("99", "virtio70-input.0"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn vfio_network_class_and_pf_labels() {
        use std::os::unix::fs::symlink;
        let root = env::temp_dir().join(format!("irqstat-vf-test-{}", std::process::id()));
        for (bdf, class, irq, iface) in [
            ("0000:05:00.0", "0x020000", "112", Some("xnic0")),
            ("0000:05:10.0", "0x020000", "115", None),
            ("0000:05:12.2", "0x020000", "133", Some("xnic0v9")),
            ("0000:06:00.0", "0x030000", "999", None),
        ] {
            let path = root.join(bdf);
            fs::create_dir_all(path.join("msi_irqs").join(irq)).unwrap();
            fs::write(path.join("class"), class).unwrap();
            if let Some(iface) = iface {
                fs::create_dir_all(path.join("net").join(iface)).unwrap();
            }
        }
        symlink(root.join("0000:05:10.0"), root.join("0000:05:00.0/virtfn0")).unwrap();
        symlink(root.join("0000:05:12.2"), root.join("0000:05:00.0/virtfn9")).unwrap();
        let mut net = Network::default();
        net.add_pci(&root).unwrap();
        assert_eq!(
            net.devices("115", "vfio-msix[0](0000:05:10.0)"),
            BTreeSet::from(["xnic0/vf0".into()])
        );
        assert_eq!(
            net.devices("133", "ixgbevf"),
            BTreeSet::from(["xnic0v9".into()])
        );
        assert!(net.includes("115", "unrelated-name"));
        assert!(net.includes("500", "vfio-msix[1](0000:05:10.0)"));
        assert!(!net.includes("999", "vfio-msix[0](0000:06:00.0)"));
        assert!(!net.includes("500", "vfio-msix[0](0000:05:10.01)"));
        fs::remove_dir_all(root).unwrap();
    }
}
