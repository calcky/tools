use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const READER_JOIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_ERROR_DETAIL_BYTES: usize = 256;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_RULE_SUMMARY_BYTES: usize = 512;
const MAX_MATCH_SUMMARY_BYTES: usize = 256;
const MAX_MATCH_SCALAR_BYTES: usize = 96;
const MAX_MATCH_SET_VALUES: usize = 8;
const MAX_TABLES: usize = 256;
const MAX_CHAINS: usize = 8_192;
const MAX_RULES: usize = 32_768;
const MAX_NAMED_COUNTERS: usize = 8_192;
const MAX_FLOWTABLES: usize = 1_024;
const MAX_EXPRESSIONS_PER_RULE: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IptablesFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IptablesBackend {
    Nft,
    Legacy,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NetfilterBackend {
    Iptables {
        family: IptablesFamily,
        implementation: IptablesBackend,
    },
    Nftables,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum NftFamily {
    Ip,
    Ip6,
    Inet,
    Arp,
    Bridge,
    Netdev,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NetfilterHook {
    Ingress,
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    Egress,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ChainPolicy {
    Accept,
    Drop,
    None,
    Other(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuleVerdict {
    Accept,
    Drop,
    Reject,
    Continue,
    Return,
    Jump(String),
    Goto(String),
    Queue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RuleAction {
    Verdict(RuleVerdict),
    Dnat,
    Snat,
    Masquerade,
    Redirect,
    Log,
    Notrack,
    Other(String),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RuleCounters {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamedCounter {
    pub(crate) name: String,
    pub(crate) handle: Option<u64>,
    pub(crate) counters: RuleCounters,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetfilterRule {
    pub(crate) handle: Option<u64>,
    pub(crate) fingerprint: RuleFingerprint,
    pub(crate) counters: Option<RuleCounters>,
    pub(crate) counter_reference: Option<String>,
    pub(crate) actions: Vec<RuleAction>,
    pub(crate) summary: String,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct RuleFingerprint {
    hash: u64,
    byte_length: u64,
}

impl fmt::Debug for RuleFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuleFingerprint(<redacted>)")
    }
}

impl RuleFingerprint {
    pub(crate) fn from_stable_identity(identity: &str) -> Self {
        rule_fingerprint(identity.as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetfilterChain {
    pub(crate) name: String,
    pub(crate) handle: Option<u64>,
    pub(crate) chain_type: Option<String>,
    pub(crate) hook: Option<NetfilterHook>,
    pub(crate) priority: Option<i32>,
    pub(crate) policy: Option<ChainPolicy>,
    pub(crate) counters: Option<RuleCounters>,
    pub(crate) rules: Vec<NetfilterRule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetfilterTable {
    pub(crate) family: Option<NftFamily>,
    pub(crate) name: String,
    pub(crate) handle: Option<u64>,
    pub(crate) chains: Vec<NetfilterChain>,
    pub(crate) named_counters: Vec<NamedCounter>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NetfilterRuleset {
    pub(crate) backend: NetfilterBackend,
    pub(crate) tables: Vec<NetfilterTable>,
    pub(crate) nft_metadata: Option<NftMetadata>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NftMetadata {
    pub(crate) json_schema_version: Option<u32>,
    pub(crate) flowtable_count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectErrorKind {
    NotFound,
    PermissionDenied,
    Io,
    Timeout,
    OutputLimit,
    CardinalityLimit,
    CommandFailed,
    SchemaMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CollectError {
    kind: CollectErrorKind,
    message: String,
}

impl CollectError {
    fn new(kind: CollectErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn io(context: &str, error: io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::NotFound => CollectErrorKind::NotFound,
            io::ErrorKind::PermissionDenied => CollectErrorKind::PermissionDenied,
            _ => CollectErrorKind::Io,
        };
        Self::new(kind, format!("{context}: {error}"))
    }

    fn schema(message: impl Into<String>) -> Self {
        Self::new(CollectErrorKind::SchemaMismatch, message)
    }

    pub(crate) const fn kind(&self) -> CollectErrorKind {
        self.kind
    }
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CollectError {}

pub(crate) fn collect_iptables_ipv4() -> Result<NetfilterRuleset, CollectError> {
    collect_iptables_with_command(
        IptablesFamily::Ipv4,
        Path::new("iptables-save"),
        &[],
        CommandLimits::production(),
    )
}

pub(crate) fn collect_iptables_ipv6() -> Result<NetfilterRuleset, CollectError> {
    collect_iptables_with_command(
        IptablesFamily::Ipv6,
        Path::new("ip6tables-save"),
        &[],
        CommandLimits::production(),
    )
}

pub(crate) fn collect_nftables() -> Result<NetfilterRuleset, CollectError> {
    collect_nftables_with_command(Path::new("nft"), &[], CommandLimits::production())
}

#[derive(Clone, Copy)]
struct CommandLimits {
    timeout: Duration,
    stdout_bytes: usize,
    stderr_bytes: usize,
}

impl CommandLimits {
    const fn production() -> Self {
        Self {
            timeout: COMMAND_TIMEOUT,
            stdout_bytes: MAX_STDOUT_BYTES,
            stderr_bytes: MAX_STDERR_BYTES,
        }
    }
}

fn collect_iptables_with_command(
    family: IptablesFamily,
    binary: &Path,
    prefix_arguments: &[&OsStr],
    limits: CommandLimits,
) -> Result<NetfilterRuleset, CollectError> {
    let label = match family {
        IptablesFamily::Ipv4 => "iptables-save collector",
        IptablesFamily::Ipv6 => "ip6tables-save collector",
    };
    let output = run_bounded_command(binary, prefix_arguments, &[OsStr::new("-c")], label, limits)?;
    parse_iptables_save(&output, family)
}

fn collect_nftables_with_command(
    binary: &Path,
    prefix_arguments: &[&OsStr],
    limits: CommandLimits,
) -> Result<NetfilterRuleset, CollectError> {
    let output = run_bounded_command(
        binary,
        prefix_arguments,
        ["-j", "-a", "list", "ruleset"].map(OsStr::new).as_slice(),
        "nft ruleset collector",
        limits,
    )?;
    parse_nft_ruleset(&output)
}

fn run_bounded_command(
    binary: &Path,
    prefix_arguments: &[&OsStr],
    arguments: &[&OsStr],
    label: &str,
    limits: CommandLimits,
) -> Result<Vec<u8>, CollectError> {
    let started = Instant::now();
    let mut child = Command::new(binary)
        .args(prefix_arguments)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .process_group(0)
        .spawn()
        .map_err(|error| CollectError::io(&format!("start {label}"), error))?;
    let stdout = child
        .stdout
        .take()
        .expect("stdout is piped before the collector starts");
    let stderr = child
        .stderr
        .take()
        .expect("stderr is piped before the collector starts");
    let control = Arc::new(ReaderControl::default());

    if let Err(error) = set_nonblocking(&stdout) {
        stop_command(&mut child, &control);
        let _ = child.wait();
        return Err(CollectError::io(
            &format!("configure {label} stdout as nonblocking"),
            error,
        ));
    }
    if let Err(error) = set_nonblocking(&stderr) {
        stop_command(&mut child, &control);
        let _ = child.wait();
        return Err(CollectError::io(
            &format!("configure {label} stderr as nonblocking"),
            error,
        ));
    }

    let stdout_reader = spawn_bounded_reader(
        "netlens-netfilter-stdout",
        stdout,
        limits.stdout_bytes,
        Arc::clone(&control),
    )
    .map_err(|error| {
        stop_command(&mut child, &control);
        let _ = child.wait();
        CollectError::io(&format!("start {label} stdout reader"), error)
    })?;
    let stderr_reader = match spawn_bounded_reader(
        "netlens-netfilter-stderr",
        stderr,
        limits.stderr_bytes,
        Arc::clone(&control),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            stop_command(&mut child, &control);
            let deadline = Instant::now() + READER_JOIN_TIMEOUT;
            let _ = join_reader(stdout_reader, deadline, label);
            let _ = child.wait();
            return Err(CollectError::io(
                &format!("start {label} stderr reader"),
                error,
            ));
        }
    };

    let outcome = wait_for_command(&mut child, started, limits.timeout, &control, label);
    stop_command(&mut child, &control);
    let deadline = Instant::now() + READER_JOIN_TIMEOUT;
    let stdout = join_reader(stdout_reader, deadline, label);
    let stderr = join_reader(stderr_reader, deadline, label);
    let _ = child.wait();
    let outcome = outcome?;

    match outcome {
        CommandOutcome::Timeout => Err(CollectError::new(
            CollectErrorKind::Timeout,
            format!(
                "{label} exceeded its {} ms timeout",
                limits.timeout.as_millis()
            ),
        )),
        CommandOutcome::OutputLimit => Err(CollectError::new(
            CollectErrorKind::OutputLimit,
            format!("{label} output exceeded its size limit"),
        )),
        CommandOutcome::ReaderFailed => {
            stdout?;
            stderr?;
            Err(CollectError::new(
                CollectErrorKind::Io,
                format!("{label} output reader failed without an I/O diagnostic"),
            ))
        }
        CommandOutcome::Exited(status) => {
            let stdout = stdout?;
            let stderr = stderr?;
            if stdout.exceeded || stderr.exceeded {
                return Err(CollectError::new(
                    CollectErrorKind::OutputLimit,
                    format!("{label} output exceeded its size limit"),
                ));
            }
            if !status.success() {
                return Err(command_failed(label, status, &stderr.bytes));
            }
            Ok(stdout.bytes)
        }
    }
}

enum CommandOutcome {
    Exited(ExitStatus),
    Timeout,
    OutputLimit,
    ReaderFailed,
}

fn wait_for_command(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
    control: &ReaderControl,
    label: &str,
) -> Result<CommandOutcome, CollectError> {
    loop {
        if control.exceeded.load(Ordering::Acquire) {
            return Ok(CommandOutcome::OutputLimit);
        }
        if control.failed.load(Ordering::Acquire) {
            return Ok(CommandOutcome::ReaderFailed);
        }
        if started.elapsed() >= timeout {
            return Ok(CommandOutcome::Timeout);
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(CommandOutcome::Exited(status)),
            Ok(None) => {}
            Err(error) => {
                return Err(CollectError::io(&format!("wait for {label}"), error));
            }
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    }
}

fn stop_command(child: &mut Child, control: &ReaderControl) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    control.stop.store(true, Ordering::Release);
}

fn set_nonblocking(reader: &impl AsRawFd) -> io::Result<()> {
    let descriptor = reader.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK == 0 {
        let result = unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[derive(Default)]
struct ReaderControl {
    stop: AtomicBool,
    exceeded: AtomicBool,
    failed: AtomicBool,
}

struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn spawn_bounded_reader<R>(
    name: &str,
    reader: R,
    limit: usize,
    control: Arc<ReaderControl>,
) -> io::Result<JoinHandle<io::Result<BoundedOutput>>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || read_bounded(reader, limit, &control))
}

fn read_bounded<R: Read>(
    mut reader: R,
    limit: usize,
    control: &ReaderControl,
) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut exceeded = false;
    let mut stopping = false;

    loop {
        stopping |= control.stop.load(Ordering::Acquire);
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if stopping {
                    break;
                }
                thread::sleep(COMMAND_POLL_INTERVAL);
                continue;
            }
            Err(error) => {
                control.failed.store(true, Ordering::Release);
                return Err(error);
            }
        };
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(read);
        bytes.extend_from_slice(&buffer[..retained]);
        if retained != read {
            exceeded = true;
            control.exceeded.store(true, Ordering::Release);
            break;
        }
    }

    Ok(BoundedOutput { bytes, exceeded })
}

fn join_reader(
    reader: JoinHandle<io::Result<BoundedOutput>>,
    deadline: Instant,
    label: &str,
) -> Result<BoundedOutput, CollectError> {
    while !reader.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err(CollectError::new(
                CollectErrorKind::Io,
                format!("{label} output reader did not stop after cancellation"),
            ));
        }
        thread::sleep(COMMAND_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
    reader
        .join()
        .map_err(|_| {
            CollectError::new(
                CollectErrorKind::Io,
                format!("{label} output reader terminated unexpectedly"),
            )
        })?
        .map_err(|error| CollectError::io(&format!("read {label} output"), error))
}

fn command_failed(label: &str, status: ExitStatus, stderr: &[u8]) -> CollectError {
    let detail = printable_excerpt(stderr);
    let lowercase = detail.to_ascii_lowercase();
    let kind = if [
        "operation not permitted",
        "permission denied",
        "you must be root",
        "permission problem",
    ]
    .iter()
    .any(|phrase| lowercase.contains(phrase))
    {
        CollectErrorKind::PermissionDenied
    } else if ["not found", "no such file or directory"]
        .iter()
        .any(|phrase| lowercase.contains(phrase))
    {
        CollectErrorKind::NotFound
    } else {
        CollectErrorKind::CommandFailed
    };
    let message = if detail.is_empty() {
        format!("{label} exited with {status}")
    } else {
        format!("{label} exited with {status}: {detail}")
    };
    CollectError::new(kind, message)
}

fn printable_excerpt(input: &[u8]) -> String {
    input
        .iter()
        .copied()
        .map(|byte| {
            if (0x20..=0x7e).contains(&byte) {
                char::from(byte)
            } else {
                '?'
            }
        })
        .take(MAX_ERROR_DETAIL_BYTES)
        .collect()
}

fn parse_iptables_save(
    input: &[u8],
    family: IptablesFamily,
) -> Result<NetfilterRuleset, CollectError> {
    check_parser_input_size(input, "iptables-save")?;
    let text = std::str::from_utf8(input)
        .map_err(|_| CollectError::schema("iptables-save output is not UTF-8"))?;
    let implementation = detect_iptables_backend(text);
    let mut ruleset = NetfilterRuleset {
        backend: NetfilterBackend::Iptables {
            family,
            implementation,
        },
        tables: Vec::new(),
        nft_metadata: None,
    };
    let mut current_table: Option<NetfilterTable> = None;
    let mut chain_count = 0_usize;
    let mut rule_count = 0_usize;

    for (line_number, raw_line) in text.lines().enumerate() {
        let line_number = line_number + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('*') {
            if current_table.is_some() {
                return Err(CollectError::schema(format!(
                    "iptables-save line {line_number} starts a table before COMMIT"
                )));
            }
            check_cardinality(ruleset.tables.len(), MAX_TABLES, "iptables tables")?;
            let name = checked_identity(name, "iptables table", line_number)?;
            if ruleset.tables.iter().any(|table| table.name == name) {
                return Err(CollectError::schema(format!(
                    "iptables-save line {line_number} repeats table {name:?}"
                )));
            }
            current_table = Some(NetfilterTable {
                family: None,
                name,
                handle: None,
                chains: Vec::new(),
                named_counters: Vec::new(),
            });
            continue;
        }
        if line == "COMMIT" {
            let table = current_table.take().ok_or_else(|| {
                CollectError::schema(format!(
                    "iptables-save line {line_number} contains COMMIT outside a table"
                ))
            })?;
            ruleset.tables.push(table);
            continue;
        }

        let table = current_table.as_mut().ok_or_else(|| {
            CollectError::schema(format!(
                "iptables-save line {line_number} appears outside a table"
            ))
        })?;
        if let Some(declaration) = line.strip_prefix(':') {
            check_cardinality(chain_count, MAX_CHAINS, "iptables chains")?;
            parse_iptables_chain(declaration, table, line_number)?;
            chain_count += 1;
        } else if line.starts_with('[') || line.starts_with("-A ") {
            check_cardinality(rule_count, MAX_RULES, "iptables rules")?;
            parse_iptables_rule(line, table, line_number)?;
            rule_count += 1;
        } else {
            return Err(CollectError::schema(format!(
                "iptables-save line {line_number} has an unsupported record"
            )));
        }
    }

    if current_table.is_some() {
        return Err(CollectError::schema(
            "iptables-save output ends before the current table COMMIT",
        ));
    }
    Ok(ruleset)
}

fn detect_iptables_backend(text: &str) -> IptablesBackend {
    for line in text.lines().filter(|line| line.starts_with('#')) {
        let lowercase = line.to_ascii_lowercase();
        if lowercase.contains("(nf_tables)") || lowercase.contains("iptables-nft") {
            return IptablesBackend::Nft;
        }
        if lowercase.contains("(legacy)") || lowercase.contains("iptables-legacy") {
            return IptablesBackend::Legacy;
        }
    }
    IptablesBackend::Unknown
}

fn parse_iptables_chain(
    declaration: &str,
    table: &mut NetfilterTable,
    line_number: usize,
) -> Result<(), CollectError> {
    let mut fields = declaration.split_ascii_whitespace();
    let name = fields.next().ok_or_else(|| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has no chain name"
        ))
    })?;
    let policy = fields.next().ok_or_else(|| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has no chain policy"
        ))
    })?;
    let counters = fields.next().ok_or_else(|| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has no chain counters"
        ))
    })?;
    if fields.next().is_some() {
        return Err(CollectError::schema(format!(
            "iptables-save line {line_number} has extra chain fields"
        )));
    }

    let name = checked_identity(name, "iptables chain", line_number)?;
    if table.chains.iter().any(|chain| chain.name == name) {
        return Err(CollectError::schema(format!(
            "iptables-save line {line_number} repeats chain {name:?}"
        )));
    }
    let counters = parse_bracketed_counters(counters, line_number, "chain")?;
    table.chains.push(NetfilterChain {
        name,
        handle: None,
        chain_type: None,
        hook: None,
        priority: None,
        policy: Some(parse_policy(policy, line_number)?),
        counters: Some(counters),
        rules: Vec::new(),
    });
    Ok(())
}

fn parse_iptables_rule(
    line: &str,
    table: &mut NetfilterTable,
    line_number: usize,
) -> Result<(), CollectError> {
    let (counters, body) = if line.starts_with('[') {
        let closing = line.find(']').ok_or_else(|| {
            CollectError::schema(format!(
                "iptables-save line {line_number} has unterminated rule counters"
            ))
        })?;
        (
            Some(parse_bracketed_counters(
                &line[..=closing],
                line_number,
                "rule",
            )?),
            line[closing + 1..].trim(),
        )
    } else {
        (None, line)
    };
    let fields = tokenize_iptables_rule(body, line_number)?;
    if fields.len() < 2 || fields[0] != "-A" {
        return Err(CollectError::schema(format!(
            "iptables-save line {line_number} must append to a chain"
        )));
    }
    let chain_name = &fields[1];
    let chain_index = table
        .chains
        .iter()
        .position(|chain| chain.name == *chain_name)
        .ok_or_else(|| {
            CollectError::schema(format!(
                "iptables-save line {line_number} references unknown chain {chain_name:?}"
            ))
        })?;
    let actions = parse_iptables_actions(&fields[2..], &table.chains, line_number)?;
    let summary = summarize_actions(&actions);
    table.chains[chain_index].rules.push(NetfilterRule {
        handle: None,
        fingerprint: rule_fingerprint(body.as_bytes()),
        counters,
        counter_reference: None,
        actions,
        summary,
    });
    Ok(())
}

fn parse_iptables_actions(
    fields: &[String],
    chains: &[NetfilterChain],
    line_number: usize,
) -> Result<Vec<RuleAction>, CollectError> {
    let Some((position, goto)) =
        fields
            .iter()
            .enumerate()
            .find_map(|(index, field)| match field.as_str() {
                "-j" | "--jump" => Some((index, false)),
                "-g" | "--goto" => Some((index, true)),
                _ => None,
            })
    else {
        return Ok(Vec::new());
    };
    let target = fields.get(position + 1).ok_or_else(|| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has a target option without a target"
        ))
    })?;
    let target = checked_identity(target, "iptables target", line_number)?;
    if goto {
        return Ok(vec![RuleAction::Verdict(RuleVerdict::Goto(target))]);
    }

    let action = match target.as_str() {
        "ACCEPT" => RuleAction::Verdict(RuleVerdict::Accept),
        "DROP" => RuleAction::Verdict(RuleVerdict::Drop),
        "REJECT" => RuleAction::Verdict(RuleVerdict::Reject),
        "CONTINUE" => RuleAction::Verdict(RuleVerdict::Continue),
        "RETURN" => RuleAction::Verdict(RuleVerdict::Return),
        "QUEUE" | "NFQUEUE" => RuleAction::Verdict(RuleVerdict::Queue),
        "DNAT" => RuleAction::Dnat,
        "SNAT" => RuleAction::Snat,
        "MASQUERADE" => RuleAction::Masquerade,
        "REDIRECT" => RuleAction::Redirect,
        "LOG" | "NFLOG" => RuleAction::Log,
        "NOTRACK" => RuleAction::Notrack,
        _ if chains.iter().any(|chain| chain.name == target) => {
            RuleAction::Verdict(RuleVerdict::Jump(target))
        }
        _ => RuleAction::Other(target),
    };
    Ok(vec![action])
}

fn tokenize_iptables_rule(input: &str, line_number: usize) -> Result<Vec<String>, CollectError> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in input.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_ascii_whitespace() && quote.is_none() {
            if !current.is_empty() {
                fields.push(std::mem::take(&mut current));
            }
            continue;
        }
        if character.is_control() {
            return Err(CollectError::schema(format!(
                "iptables-save line {line_number} contains a control character"
            )));
        }
        current.push(character);
    }

    if escaped || quote.is_some() {
        return Err(CollectError::schema(format!(
            "iptables-save line {line_number} has unterminated quoting"
        )));
    }
    if !current.is_empty() {
        fields.push(current);
    }
    Ok(fields)
}

fn parse_bracketed_counters(
    input: &str,
    line_number: usize,
    context: &str,
) -> Result<RuleCounters, CollectError> {
    let inner = input
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| {
            CollectError::schema(format!(
                "iptables-save line {line_number} has malformed {context} counters"
            ))
        })?;
    let (packets, bytes) = inner.split_once(':').ok_or_else(|| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has malformed {context} counters"
        ))
    })?;
    Ok(RuleCounters {
        packets: parse_u64_text(packets, line_number, "packet counter")?,
        bytes: parse_u64_text(bytes, line_number, "byte counter")?,
    })
}

fn parse_u64_text(value: &str, line_number: usize, field: &str) -> Result<u64, CollectError> {
    value.parse::<u64>().map_err(|error| {
        CollectError::schema(format!(
            "iptables-save line {line_number} has an invalid {field}: {error}"
        ))
    })
}

fn parse_nft_ruleset(input: &[u8]) -> Result<NetfilterRuleset, CollectError> {
    check_parser_input_size(input, "nft")?;
    let root: Value = serde_json::from_slice(input)
        .map_err(|error| CollectError::schema(format!("nft output is not valid JSON: {error}")))?;
    let records = root
        .as_object()
        .and_then(|object| object.get("nftables"))
        .and_then(Value::as_array)
        .ok_or_else(|| CollectError::schema("nft output must contain an nftables array"))?;
    let mut ruleset = NetfilterRuleset {
        backend: NetfilterBackend::Nftables,
        tables: Vec::new(),
        nft_metadata: Some(NftMetadata::default()),
    };
    let mut table_indices = BTreeMap::<(String, String), usize>::new();
    let mut chain_indices = BTreeMap::<(String, String, String), (usize, usize)>::new();
    let mut chain_count = 0_usize;
    let mut rule_count = 0_usize;
    let mut named_counter_count = 0_usize;
    let mut flowtable_count = 0_usize;
    let mut metainfo_seen = false;

    for (index, record) in records.iter().enumerate() {
        let record = record.as_object().ok_or_else(|| {
            CollectError::schema(format!("nft record {index} must be a JSON object"))
        })?;
        if let Some(value) = record.get("metainfo") {
            if metainfo_seen {
                return Err(CollectError::schema(format!(
                    "nft record {index} repeats metainfo"
                )));
            }
            metainfo_seen = true;
            let object = nft_record_object(value, index, "metainfo")?;
            let version = nft_optional_u64(object, "json_schema_version", index, "metainfo")?
                .map(|version| {
                    u32::try_from(version).map_err(|_| {
                        CollectError::schema(format!(
                            "nft metainfo record {index} JSON schema version is too large"
                        ))
                    })
                })
                .transpose()?;
            if let Some(version) = version {
                if version != 1 {
                    return Err(CollectError::schema(format!(
                        "nft metainfo record {index} uses unsupported JSON schema version {version}"
                    )));
                }
            }
            ruleset
                .nft_metadata
                .as_mut()
                .expect("nft metadata is initialized")
                .json_schema_version = version;
        } else if let Some(value) = record.get("table") {
            check_cardinality(ruleset.tables.len(), MAX_TABLES, "nft tables")?;
            let object = nft_record_object(value, index, "table")?;
            let family_raw = nft_required_identity(object, "family", index, "table")?;
            let name = nft_required_identity(object, "name", index, "table")?;
            let key = (family_raw.clone(), name.clone());
            if table_indices.contains_key(&key) {
                return Err(CollectError::schema(format!(
                    "nft record {index} repeats table {family_raw}/{name}"
                )));
            }
            let table_index = ruleset.tables.len();
            ruleset.tables.push(NetfilterTable {
                family: Some(parse_nft_family(&family_raw)),
                name,
                handle: nft_optional_u64(object, "handle", index, "table")?,
                chains: Vec::new(),
                named_counters: Vec::new(),
            });
            table_indices.insert(key, table_index);
        } else if let Some(value) = record.get("chain") {
            check_cardinality(chain_count, MAX_CHAINS, "nft chains")?;
            let object = nft_record_object(value, index, "chain")?;
            let family = nft_required_identity(object, "family", index, "chain")?;
            let table = nft_required_identity(object, "table", index, "chain")?;
            let name = nft_required_identity(object, "name", index, "chain")?;
            let table_index = table_indices
                .get(&(family.clone(), table.clone()))
                .copied()
                .ok_or_else(|| {
                    CollectError::schema(format!(
                        "nft record {index} references unknown table {family}/{table}"
                    ))
                })?;
            let key = (family, table, name.clone());
            if chain_indices.contains_key(&key) {
                return Err(CollectError::schema(format!(
                    "nft record {index} repeats chain {name:?}"
                )));
            }
            let chain_index = ruleset.tables[table_index].chains.len();
            ruleset.tables[table_index].chains.push(NetfilterChain {
                name,
                handle: nft_optional_u64(object, "handle", index, "chain")?,
                chain_type: nft_optional_identity(object, "type", index, "chain")?,
                hook: nft_optional_identity(object, "hook", index, "chain")?
                    .map(|hook| parse_nft_hook(&hook)),
                priority: nft_optional_i32(object, "prio", index, "chain")?,
                policy: nft_optional_identity(object, "policy", index, "chain")?
                    .map(|policy| parse_policy(&policy, index + 1))
                    .transpose()?,
                counters: None,
                rules: Vec::new(),
            });
            chain_indices.insert(key, (table_index, chain_index));
            chain_count += 1;
        } else if let Some(value) = record.get("rule") {
            check_cardinality(rule_count, MAX_RULES, "nft rules")?;
            let object = nft_record_object(value, index, "rule")?;
            let family = nft_required_identity(object, "family", index, "rule")?;
            let table = nft_required_identity(object, "table", index, "rule")?;
            let chain = nft_required_identity(object, "chain", index, "rule")?;
            let (table_index, chain_index) = chain_indices
                .get(&(family.clone(), table.clone(), chain.clone()))
                .copied()
                .ok_or_else(|| {
                    CollectError::schema(format!(
                        "nft record {index} references unknown chain {family}/{table}/{chain}"
                    ))
                })?;
            let rule = parse_nft_rule(object, index)?;
            ruleset.tables[table_index].chains[chain_index]
                .rules
                .push(rule);
            rule_count += 1;
        } else if let Some(value) = record.get("counter") {
            check_cardinality(
                named_counter_count,
                MAX_NAMED_COUNTERS,
                "nft named counters",
            )?;
            let object = nft_record_object(value, index, "counter")?;
            let family = nft_required_identity(object, "family", index, "counter")?;
            let table = nft_required_identity(object, "table", index, "counter")?;
            let name = nft_required_identity(object, "name", index, "counter")?;
            let table_index = table_indices
                .get(&(family.clone(), table.clone()))
                .copied()
                .ok_or_else(|| {
                    CollectError::schema(format!(
                        "nft record {index} references unknown table {family}/{table}"
                    ))
                })?;
            if ruleset.tables[table_index]
                .named_counters
                .iter()
                .any(|counter| counter.name == name)
            {
                return Err(CollectError::schema(format!(
                    "nft record {index} repeats counter {name:?}"
                )));
            }
            ruleset.tables[table_index]
                .named_counters
                .push(NamedCounter {
                    name,
                    handle: nft_optional_u64(object, "handle", index, "counter")?,
                    counters: nft_required_counters(object, index, "counter")?,
                });
            named_counter_count += 1;
        } else if let Some(value) = record.get("flowtable") {
            check_cardinality(flowtable_count, MAX_FLOWTABLES, "nft flowtables")?;
            let object = nft_record_object(value, index, "flowtable")?;
            nft_required_identity(object, "family", index, "flowtable")?;
            nft_required_identity(object, "table", index, "flowtable")?;
            nft_required_identity(object, "name", index, "flowtable")?;
            flowtable_count += 1;
            ruleset
                .nft_metadata
                .as_mut()
                .expect("nft metadata is initialized")
                .flowtable_count = flowtable_count;
        }
    }

    Ok(ruleset)
}

fn parse_nft_rule(
    object: &Map<String, Value>,
    record_index: usize,
) -> Result<NetfilterRule, CollectError> {
    let expressions = object
        .get("expr")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CollectError::schema(format!(
                "nft rule record {record_index} field \"expr\" must be an array"
            ))
        })?;
    let fingerprint = nft_rule_fingerprint(expressions)?;
    check_cardinality(
        expressions.len().saturating_sub(1),
        MAX_EXPRESSIONS_PER_RULE,
        "nft rule expressions",
    )?;
    let mut counters = None;
    let mut counter_reference = None;
    let mut actions = Vec::new();
    let mut summary = Vec::new();

    for (expression_index, expression) in expressions.iter().enumerate() {
        let expression = expression.as_object().ok_or_else(|| {
            CollectError::schema(format!(
                "nft rule record {record_index} expression {expression_index} must be an object"
            ))
        })?;
        if expression.len() != 1 {
            return Err(CollectError::schema(format!(
                "nft rule record {record_index} expression {expression_index} must contain one statement"
            )));
        }
        for (kind, value) in expression {
            match kind.as_str() {
                "counter" => {
                    summary.push("counter".to_owned());
                    match value {
                        Value::String(name) if counter_reference.is_none() => {
                            counter_reference = Some(checked_identity(
                                name,
                                "nft named counter reference",
                                record_index + 1,
                            )?);
                        }
                        Value::String(_) => {
                            return Err(CollectError::schema(format!(
                                "nft rule record {record_index} has multiple named counter references"
                            )));
                        }
                        Value::Object(counter) => {
                            if let Some(name) = counter.get("name") {
                                let name = name.as_str().ok_or_else(|| {
                                    CollectError::schema(format!(
                                        "nft rule record {record_index} counter name must be a string"
                                    ))
                                })?;
                                if counter_reference.is_some() {
                                    return Err(CollectError::schema(format!(
                                        "nft rule record {record_index} has multiple named counter references"
                                    )));
                                }
                                counter_reference = Some(checked_identity(
                                    name,
                                    "nft named counter reference",
                                    record_index + 1,
                                )?);
                            }
                            let packets =
                                nft_optional_u64(counter, "packets", record_index, "rule counter")?;
                            let bytes =
                                nft_optional_u64(counter, "bytes", record_index, "rule counter")?;
                            match (packets, bytes) {
                                (Some(packets), Some(bytes)) if counters.is_none() => {
                                    counters = Some(RuleCounters { packets, bytes });
                                }
                                (None, None) => {}
                                (Some(_), Some(_)) => {
                                    return Err(CollectError::schema(format!(
                                        "nft rule record {record_index} has multiple anonymous counters"
                                    )));
                                }
                                _ => {
                                    return Err(CollectError::schema(format!(
                                        "nft rule record {record_index} counter must contain both packets and bytes"
                                    )));
                                }
                            }
                        }
                        Value::Null => {}
                        _ => {
                            return Err(CollectError::schema(format!(
                                "nft rule record {record_index} counter must be an object or named reference"
                            )));
                        }
                    }
                }
                "accept" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Accept),
                    "accept",
                ),
                "drop" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Drop),
                    "drop",
                ),
                "reject" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Reject),
                    "reject",
                ),
                "continue" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Continue),
                    "continue",
                ),
                "return" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Return),
                    "return",
                ),
                "jump" | "goto" => {
                    let target = nft_record_object(value, record_index, kind)?;
                    let target = nft_required_identity(target, "target", record_index, kind)?;
                    let (action, label) = if kind == "jump" {
                        (
                            RuleAction::Verdict(RuleVerdict::Jump(target.clone())),
                            format!("jump {target}"),
                        )
                    } else {
                        (
                            RuleAction::Verdict(RuleVerdict::Goto(target.clone())),
                            format!("goto {target}"),
                        )
                    };
                    push_nft_action(&mut actions, &mut summary, action, &label);
                }
                "queue" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Verdict(RuleVerdict::Queue),
                    "queue",
                ),
                "dnat" => push_nft_action(&mut actions, &mut summary, RuleAction::Dnat, "dnat"),
                "snat" => push_nft_action(&mut actions, &mut summary, RuleAction::Snat, "snat"),
                "masquerade" => push_nft_action(
                    &mut actions,
                    &mut summary,
                    RuleAction::Masquerade,
                    "masquerade",
                ),
                "redirect" => {
                    push_nft_action(&mut actions, &mut summary, RuleAction::Redirect, "redirect")
                }
                "log" => push_nft_action(&mut actions, &mut summary, RuleAction::Log, "log"),
                "notrack" => {
                    push_nft_action(&mut actions, &mut summary, RuleAction::Notrack, "notrack")
                }
                "match" => summary.push(summarize_nft_match(value)),
                other => {
                    let other = checked_identity(other, "nft expression", record_index + 1)?;
                    summary.push(other.clone());
                    actions.push(RuleAction::Other(other));
                }
            }
        }
    }

    Ok(NetfilterRule {
        handle: nft_optional_u64(object, "handle", record_index, "rule")?,
        fingerprint,
        counters,
        counter_reference,
        actions,
        summary: bounded_printable_summary(&summary.join(" ")),
    })
}

fn nft_rule_fingerprint(expressions: &[Value]) -> Result<RuleFingerprint, CollectError> {
    let mut fingerprint = FingerprintBuilder::default();
    for expression in expressions {
        if let Some(counter) = expression
            .as_object()
            .and_then(|object| object.get("counter"))
        {
            fingerprint.update(b"counter:");
            match counter {
                Value::String(name) => fingerprint.update(name.as_bytes()),
                Value::Object(counter) => {
                    if let Some(name) = counter.get("name").and_then(Value::as_str) {
                        fingerprint.update(name.as_bytes());
                    } else {
                        fingerprint.update(b"anonymous");
                    }
                }
                Value::Null => fingerprint.update(b"anonymous"),
                _ => fingerprint.update(b"invalid"),
            }
        } else {
            let encoded = serde_json::to_vec(expression).map_err(|error| {
                CollectError::schema(format!("cannot canonicalize nft rule expression: {error}"))
            })?;
            fingerprint.update(&encoded);
        }
        fingerprint.update(&[0xff]);
    }
    Ok(fingerprint.finish())
}

fn push_nft_action(
    actions: &mut Vec<RuleAction>,
    summary: &mut Vec<String>,
    action: RuleAction,
    label: &str,
) {
    actions.push(action);
    summary.push(label.to_owned());
}

fn summarize_nft_match(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return "match".to_owned();
    };
    let Some(left) = object.get("left").and_then(summarize_nft_match_left) else {
        return "match".to_owned();
    };
    let Some(operator) = object.get("op").and_then(Value::as_str).filter(|operator| {
        matches!(
            *operator,
            "&" | "|" | "^" | "<<" | ">>" | "==" | "!=" | "<" | ">" | "<=" | ">=" | "in"
        )
    }) else {
        return "match".to_owned();
    };
    let Some(right) = object.get("right").and_then(summarize_nft_match_value) else {
        return "match".to_owned();
    };

    bounded_printable(
        &format!("{left} {operator} {right}"),
        MAX_MATCH_SUMMARY_BYTES,
    )
}

fn summarize_nft_match_left(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    if let Some(meta) = object.get("meta").and_then(Value::as_object) {
        let key = match_identifier(meta.get("key")?.as_str()?)?;
        return Some(format!("meta.{key}"));
    }
    if let Some(payload) = object.get("payload").and_then(Value::as_object) {
        let protocol = match_identifier(payload.get("protocol")?.as_str()?)?;
        let field = match_identifier(payload.get("field")?.as_str()?)?;
        return Some(format!("{protocol}.{field}"));
    }
    None
}

fn summarize_nft_match_value(value: &Value) -> Option<String> {
    if let Some(scalar) = summarize_nft_scalar(value) {
        return Some(scalar);
    }
    let elements = match value {
        Value::Array(elements) => elements,
        Value::Object(object) if object.len() == 1 => object.get("set")?.as_array()?,
        _ => return None,
    };
    let mut values = Vec::with_capacity(elements.len().min(MAX_MATCH_SET_VALUES));
    for element in elements.iter().take(MAX_MATCH_SET_VALUES) {
        values.push(summarize_nft_scalar(element)?);
    }
    if elements.len() > MAX_MATCH_SET_VALUES {
        values.push("...".to_owned());
    }
    Some(format!("{{ {} }}", values.join(", ")))
}

fn summarize_nft_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(bounded_match_string(value)),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some("null".to_owned()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

fn match_identifier(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_MATCH_SCALAR_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return None;
    }
    Some(value.to_owned())
}

fn bounded_match_string(value: &str) -> String {
    if value.len() <= MAX_MATCH_SCALAR_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b':' | b'/' | b'_' | b'-' | b'+' | b'@')
        })
    {
        return value.to_owned();
    }

    let mut output = String::from("\"");
    let mut truncated = false;
    for byte in value.bytes() {
        let fragment = match byte {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            0x20..=0x7e => {
                if output.len() + 2 > MAX_MATCH_SCALAR_BYTES {
                    truncated = true;
                    break;
                }
                output.push(char::from(byte));
                continue;
            }
            _ => "?",
        };
        if output.len() + fragment.len() + 1 > MAX_MATCH_SCALAR_BYTES {
            truncated = true;
            break;
        }
        output.push_str(fragment);
    }
    if truncated && output.len() + 4 <= MAX_MATCH_SCALAR_BYTES {
        output.push_str("...");
    }
    output.push('"');
    output
}

fn nft_record_object<'a>(
    value: &'a Value,
    record_index: usize,
    kind: &str,
) -> Result<&'a Map<String, Value>, CollectError> {
    value.as_object().ok_or_else(|| {
        CollectError::schema(format!(
            "nft {kind} record {record_index} must be a JSON object"
        ))
    })
}

fn nft_required_identity(
    object: &Map<String, Value>,
    field: &str,
    record_index: usize,
    kind: &str,
) -> Result<String, CollectError> {
    let value = object.get(field).and_then(Value::as_str).ok_or_else(|| {
        CollectError::schema(format!(
            "nft {kind} record {record_index} field {field:?} must be a string"
        ))
    })?;
    checked_identity(value, &format!("nft {kind} {field}"), record_index + 1)
}

fn nft_optional_identity(
    object: &Map<String, Value>,
    field: &str,
    record_index: usize,
    kind: &str,
) -> Result<Option<String>, CollectError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => {
            checked_identity(value, &format!("nft {kind} {field}"), record_index + 1).map(Some)
        }
        Some(_) => Err(CollectError::schema(format!(
            "nft {kind} record {record_index} field {field:?} must be a string"
        ))),
    }
}

fn nft_optional_u64(
    object: &Map<String, Value>,
    field: &str,
    record_index: usize,
    kind: &str,
) -> Result<Option<u64>, CollectError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            CollectError::schema(format!(
                "nft {kind} record {record_index} field {field:?} must be an unsigned integer"
            ))
        }),
        Some(_) => Err(CollectError::schema(format!(
            "nft {kind} record {record_index} field {field:?} must be an unsigned integer"
        ))),
    }
}

fn nft_optional_i32(
    object: &Map<String, Value>,
    field: &str,
    record_index: usize,
    kind: &str,
) -> Result<Option<i32>, CollectError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or_else(|| {
                CollectError::schema(format!(
                    "nft {kind} record {record_index} field {field:?} must be a signed 32-bit integer"
                ))
            }),
        Some(_) => Err(CollectError::schema(format!(
            "nft {kind} record {record_index} field {field:?} must be a signed 32-bit integer"
        ))),
    }
}

fn nft_required_counters(
    object: &Map<String, Value>,
    record_index: usize,
    kind: &str,
) -> Result<RuleCounters, CollectError> {
    let packets = nft_optional_u64(object, "packets", record_index, kind)?.ok_or_else(|| {
        CollectError::schema(format!(
            "nft {kind} record {record_index} has no packet counter"
        ))
    })?;
    let bytes = nft_optional_u64(object, "bytes", record_index, kind)?.ok_or_else(|| {
        CollectError::schema(format!(
            "nft {kind} record {record_index} has no byte counter"
        ))
    })?;
    Ok(RuleCounters { packets, bytes })
}

fn parse_nft_family(value: &str) -> NftFamily {
    match value {
        "ip" => NftFamily::Ip,
        "ip6" => NftFamily::Ip6,
        "inet" => NftFamily::Inet,
        "arp" => NftFamily::Arp,
        "bridge" => NftFamily::Bridge,
        "netdev" => NftFamily::Netdev,
        other => NftFamily::Other(other.to_owned()),
    }
}

fn parse_nft_hook(value: &str) -> NetfilterHook {
    match value {
        "ingress" => NetfilterHook::Ingress,
        "prerouting" => NetfilterHook::Prerouting,
        "input" => NetfilterHook::Input,
        "forward" => NetfilterHook::Forward,
        "output" => NetfilterHook::Output,
        "postrouting" => NetfilterHook::Postrouting,
        "egress" => NetfilterHook::Egress,
        other => NetfilterHook::Other(other.to_owned()),
    }
}

fn parse_policy(value: &str, record_number: usize) -> Result<ChainPolicy, CollectError> {
    match value.to_ascii_lowercase().as_str() {
        "accept" => Ok(ChainPolicy::Accept),
        "drop" => Ok(ChainPolicy::Drop),
        "-" => Ok(ChainPolicy::None),
        _ => checked_identity(value, "chain policy", record_number).map(ChainPolicy::Other),
    }
}

fn checked_identity(
    value: &str,
    context: &str,
    record_number: usize,
) -> Result<String, CollectError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_BYTES
        || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(CollectError::schema(format!(
            "{context} at record {record_number} is not a bounded ASCII identity"
        )));
    }
    Ok(value.to_owned())
}

fn check_parser_input_size(input: &[u8], source: &str) -> Result<(), CollectError> {
    if input.len() > MAX_STDOUT_BYTES {
        return Err(CollectError::new(
            CollectErrorKind::OutputLimit,
            format!("{source} parser input exceeds the {MAX_STDOUT_BYTES}-byte output limit"),
        ));
    }
    Ok(())
}

fn check_cardinality(
    count_before_insert: usize,
    limit: usize,
    context: &str,
) -> Result<(), CollectError> {
    if count_before_insert >= limit {
        return Err(CollectError::new(
            CollectErrorKind::CardinalityLimit,
            format!("{context} exceed the {limit}-object cardinality limit"),
        ));
    }
    Ok(())
}

fn bounded_printable_summary(input: &str) -> String {
    bounded_printable(input, MAX_RULE_SUMMARY_BYTES)
}

fn bounded_printable(input: &str, maximum: usize) -> String {
    let mut output = String::with_capacity(input.len().min(maximum));
    let mut pending_space = false;
    for character in input.chars() {
        let character = if character.is_ascii_graphic() {
            character
        } else if character.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        } else {
            '?'
        };
        if pending_space && output.len() < maximum {
            output.push(' ');
        }
        pending_space = false;
        if output.len() >= maximum {
            break;
        }
        output.push(character);
    }
    output
}

fn summarize_actions(actions: &[RuleAction]) -> String {
    let labels = actions
        .iter()
        .map(|action| match action {
            RuleAction::Verdict(RuleVerdict::Accept) => "accept".to_owned(),
            RuleAction::Verdict(RuleVerdict::Drop) => "drop".to_owned(),
            RuleAction::Verdict(RuleVerdict::Reject) => "reject".to_owned(),
            RuleAction::Verdict(RuleVerdict::Continue) => "continue".to_owned(),
            RuleAction::Verdict(RuleVerdict::Return) => "return".to_owned(),
            RuleAction::Verdict(RuleVerdict::Jump(target)) => format!("jump {target}"),
            RuleAction::Verdict(RuleVerdict::Goto(target)) => format!("goto {target}"),
            RuleAction::Verdict(RuleVerdict::Queue) => "queue".to_owned(),
            RuleAction::Dnat => "dnat".to_owned(),
            RuleAction::Snat => "snat".to_owned(),
            RuleAction::Masquerade => "masquerade".to_owned(),
            RuleAction::Redirect => "redirect".to_owned(),
            RuleAction::Log => "log".to_owned(),
            RuleAction::Notrack => "notrack".to_owned(),
            RuleAction::Other(target) => format!("target {target}"),
        })
        .collect::<Vec<_>>();
    if labels.is_empty() {
        "match-only".to_owned()
    } else {
        bounded_printable_summary(&labels.join(" "))
    }
}

struct FingerprintBuilder {
    hash: u64,
    byte_length: u64,
}

impl Default for FingerprintBuilder {
    fn default() -> Self {
        Self {
            hash: 0xcbf2_9ce4_8422_2325,
            byte_length: 0,
        }
    }
}

impl FingerprintBuilder {
    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.hash ^= u64::from(*byte);
            self.hash = self.hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.byte_length = self.byte_length.saturating_add(bytes.len() as u64);
    }

    const fn finish(self) -> RuleFingerprint {
        RuleFingerprint {
            hash: self.hash,
            byte_length: self.byte_length,
        }
    }
}

fn rule_fingerprint(input: &[u8]) -> RuleFingerprint {
    let mut fingerprint = FingerprintBuilder::default();
    fingerprint.update(input);
    fingerprint.finish()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{tempdir, TempDir};

    use super::*;

    fn executable(root: &TempDir, body: &str) -> std::path::PathBuf {
        let path = root.path().join("collector-fixture");
        fs::write(&path, body).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn test_limits(timeout: Duration, output_bytes: usize) -> CommandLimits {
        CommandLimits {
            timeout,
            stdout_bytes: output_bytes,
            stderr_bytes: output_bytes,
        }
    }

    #[test]
    fn parses_iptables_tables_chains_counters_and_actions() {
        let fixture = br#"# Generated by iptables-save v1.8.9 (nf_tables)
*filter
:INPUT DROP [100:8000]
:FORWARD ACCEPT [7:700]
:USER - [0:0]
[12:960] -A INPUT -p tcp --dport 22 -j ACCEPT
[3:240] -A INPUT -m comment --comment "blocked\ntext" -j DROP
[4:320] -A INPUT -m comment --comment "text -j DROP" -j ACCEPT
[2:128] -A FORWARD -j USER
[2:128] -A USER -j RETURN
COMMIT
*nat
:PREROUTING ACCEPT [1:64]
[1:64] -A PREROUTING -j DNAT --to-destination 192.0.2.10
COMMIT
"#;

        let ruleset = parse_iptables_save(fixture, IptablesFamily::Ipv4).unwrap();

        assert_eq!(
            ruleset.backend,
            NetfilterBackend::Iptables {
                family: IptablesFamily::Ipv4,
                implementation: IptablesBackend::Nft,
            }
        );
        assert_eq!(ruleset.tables.len(), 2);
        assert_eq!(ruleset.tables[0].name, "filter");
        assert_eq!(ruleset.tables[0].chains[0].policy, Some(ChainPolicy::Drop));
        assert_eq!(
            ruleset.tables[0].chains[0].counters,
            Some(RuleCounters {
                packets: 100,
                bytes: 8000,
            })
        );
        assert_eq!(
            ruleset.tables[0].chains[0].rules[0].actions,
            vec![RuleAction::Verdict(RuleVerdict::Accept)]
        );
        assert_eq!(
            ruleset.tables[0].chains[0].rules[2].actions,
            vec![RuleAction::Verdict(RuleVerdict::Accept)]
        );
        assert_eq!(
            ruleset.tables[0].chains[1].rules[0].actions,
            vec![RuleAction::Verdict(RuleVerdict::Jump("USER".to_owned()))]
        );
        assert_eq!(
            ruleset.tables[1].chains[0].rules[0].actions,
            vec![RuleAction::Dnat]
        );
        assert!(!ruleset.tables[0].chains[0].rules[1].summary.contains('\n'));
    }

    #[test]
    fn preserves_unknown_iptables_backend_without_guessing() {
        let fixture = b"*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n";
        let ruleset = parse_iptables_save(fixture, IptablesFamily::Ipv6).unwrap();

        assert_eq!(
            ruleset.backend,
            NetfilterBackend::Iptables {
                family: IptablesFamily::Ipv6,
                implementation: IptablesBackend::Unknown,
            }
        );
    }

    #[test]
    fn preserves_iptables_rules_without_counters_as_unknown() {
        let fixture =
            b"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 23 -j REJECT\nCOMMIT\n";
        let ruleset = parse_iptables_save(fixture, IptablesFamily::Ipv4).unwrap();
        let rule = &ruleset.tables[0].chains[0].rules[0];

        assert_eq!(rule.counters, None);
        assert_eq!(rule.actions, vec![RuleAction::Verdict(RuleVerdict::Reject)]);
        assert_eq!(rule.summary, "reject");

        let countered = parse_iptables_save(
            b"*filter\n:INPUT ACCEPT [0:0]\n[99:9000] -A INPUT -p tcp --dport 23 -j REJECT\nCOMMIT\n",
            IptablesFamily::Ipv4,
        )
        .unwrap();
        let different = parse_iptables_save(
            b"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp --dport 24 -j REJECT\nCOMMIT\n",
            IptablesFamily::Ipv4,
        )
        .unwrap();
        assert_eq!(
            rule.fingerprint,
            countered.tables[0].chains[0].rules[0].fingerprint
        );
        assert_ne!(
            rule.fingerprint,
            different.tables[0].chains[0].rules[0].fingerprint
        );
        assert_eq!(
            format!("{:?}", rule.fingerprint),
            "RuleFingerprint(<redacted>)"
        );
    }

    #[test]
    fn nft_rule_fingerprint_excludes_live_counter_values() {
        let first: Vec<Value> = serde_json::from_str(
            r#"[{"match":{"op":"==","left":1,"right":2}},
                {"counter":{"packets":1,"bytes":64}},{"drop":null}]"#,
        )
        .unwrap();
        let second: Vec<Value> = serde_json::from_str(
            r#"[{"match":{"op":"==","left":1,"right":2}},
                {"counter":{"packets":999,"bytes":64000}},{"drop":null}]"#,
        )
        .unwrap();

        assert_eq!(
            nft_rule_fingerprint(&first).unwrap(),
            nft_rule_fingerprint(&second).unwrap()
        );
    }

    #[test]
    fn parses_nft_chains_rules_and_named_counters() {
        let fixture = br#"{
          "nftables": [
            {"metainfo":{"json_schema_version":1}},
            {"table":{"family":"inet","name":"fw4","handle":1}},
            {"chain":{"family":"inet","table":"fw4","name":"input","handle":2,
                      "type":"filter","hook":"input","prio":0,"policy":"drop"}},
            {"chain":{"family":"inet","table":"fw4","name":"helper","handle":3}},
            {"rule":{"family":"inet","table":"fw4","chain":"input","handle":10,
                     "expr":[
                       {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},
                       {"counter":{"packets":12,"bytes":960}},
                       {"jump":{"target":"helper"}}
                     ]}},
            {"rule":{"family":"inet","table":"fw4","chain":"helper","handle":11,
                     "expr":[{"counter":{"packets":3,"bytes":180}},{"drop":null}]}},
            {"rule":{"family":"inet","table":"fw4","chain":"helper","handle":12,
                     "expr":[{"counter":{"name":"accepted"}},{"queue":null}]}},
            {"rule":{"family":"inet","table":"fw4","chain":"helper","handle":13,
                     "expr":[{"counter":"accepted"},{"accept":null}]}},
            {"rule":{"family":"inet","table":"fw4","chain":"input","handle":14,
                     "expr":[{"goto":{"target":"helper"}}]}},
            {"rule":{"family":"inet","table":"fw4","chain":"helper","handle":15,
                     "expr":[{"reject":null}]}},
            {"counter":{"family":"inet","table":"fw4","name":"accepted",
                        "handle":16,"packets":44,"bytes":4096}},
            {"flowtable":{"family":"inet","table":"fw4","name":"fastpath"}}
          ]
        }"#;

        let ruleset = parse_nft_ruleset(fixture).unwrap();

        assert_eq!(ruleset.backend, NetfilterBackend::Nftables);
        assert_eq!(
            ruleset.nft_metadata,
            Some(NftMetadata {
                json_schema_version: Some(1),
                flowtable_count: 1,
            })
        );
        let table = &ruleset.tables[0];
        assert_eq!(table.family, Some(NftFamily::Inet));
        assert_eq!(table.name, "fw4");
        assert_eq!(table.chains[0].hook, Some(NetfilterHook::Input));
        assert_eq!(table.chains[0].priority, Some(0));
        assert_eq!(table.chains[0].policy, Some(ChainPolicy::Drop));
        assert_eq!(
            table.chains[0].rules[0].counters,
            Some(RuleCounters {
                packets: 12,
                bytes: 960,
            })
        );
        assert_eq!(
            table.chains[0].rules[0].actions,
            vec![RuleAction::Verdict(RuleVerdict::Jump("helper".to_owned()))]
        );
        assert_eq!(
            table.chains[0].rules[0].summary,
            "meta.l4proto == tcp counter jump helper"
        );
        assert_eq!(
            table.chains[0].rules[1].actions,
            vec![RuleAction::Verdict(RuleVerdict::Goto("helper".to_owned()))]
        );
        assert_eq!(
            table.chains[1].rules[0].actions,
            vec![RuleAction::Verdict(RuleVerdict::Drop)]
        );
        assert_eq!(table.chains[1].rules[1].counters, None);
        assert_eq!(
            table.chains[1].rules[1].counter_reference.as_deref(),
            Some("accepted")
        );
        assert_eq!(
            table.chains[1].rules[1].actions,
            vec![RuleAction::Verdict(RuleVerdict::Queue)]
        );
        assert_eq!(
            table.chains[1].rules[2].counter_reference.as_deref(),
            Some("accepted")
        );
        assert_eq!(
            table.chains[1].rules[2].actions,
            vec![RuleAction::Verdict(RuleVerdict::Accept)]
        );
        assert_eq!(
            table.chains[1].rules[3].actions,
            vec![RuleAction::Verdict(RuleVerdict::Reject)]
        );
        assert_eq!(
            table.named_counters[0].counters,
            RuleCounters {
                packets: 44,
                bytes: 4096,
            }
        );
    }

    #[test]
    fn rejects_nft_rules_that_reference_an_unknown_chain() {
        let error = parse_nft_ruleset(
            br#"{"nftables":[
                {"table":{"family":"ip","name":"filter"}},
                {"rule":{"family":"ip","table":"filter","chain":"missing","expr":[]}}
            ]}"#,
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch);
        assert!(error.to_string().contains("unknown chain"));
    }

    #[test]
    fn summarizes_common_nft_matches_and_falls_back_for_unknown_shapes() {
        let fixture = br#"{
          "nftables": [
            {"table":{"family":"inet","name":"fw"}},
            {"chain":{"family":"inet","table":"fw","name":"input"}},
            {"rule":{"family":"inet","table":"fw","chain":"input","expr":[
              {"match":{"op":"in","left":{"payload":{"protocol":"tcp","field":"dport"}},
                        "right":{"set":[80,443]}}},
              {"accept":null}
            ]}},
            {"rule":{"family":"inet","table":"fw","chain":"input","expr":[
              {"match":{"op":"!=","left":{"meta":{"key":"mark"}},"right":0}},
              {"drop":null}
            ]}},
            {"rule":{"family":"inet","table":"fw","chain":"input","expr":[
              {"match":{"op":"==","left":{"ct":{"key":"state"}},"right":"established"}},
              {"return":null}
            ]}}
          ]
        }"#;

        let ruleset = parse_nft_ruleset(fixture).unwrap();
        let rules = &ruleset.tables[0].chains[0].rules;

        assert_eq!(rules[0].summary, "tcp.dport in { 80, 443 } accept");
        assert_eq!(rules[1].summary, "meta.mark != 0 drop");
        assert_eq!(rules[2].summary, "match return");
    }

    #[test]
    fn bounds_match_values_and_large_sets_to_printable_ascii() {
        let values = (0..20).map(Value::from).collect::<Vec<_>>();
        let long_value = format!("{}\n非ASCII", "x".repeat(300));
        let set_match = serde_json::json!({
            "op": "in",
            "left": {"meta": {"key": "mark"}},
            "right": {"set": values}
        });
        let string_match = serde_json::json!({
            "op": "==",
            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
            "right": long_value
        });

        let set_summary = summarize_nft_match(&set_match);
        let string_summary = summarize_nft_match(&string_match);

        assert_eq!(set_summary, "meta.mark in { 0, 1, 2, 3, 4, 5, 6, 7, ... }");
        for summary in [&set_summary, &string_summary] {
            assert!(summary.len() <= MAX_MATCH_SUMMARY_BYTES);
            assert!(summary.bytes().all(|byte| (0x20..=0x7e).contains(&byte)));
        }
    }

    #[test]
    fn rejects_unsupported_nft_json_schema_versions() {
        let error = parse_nft_ruleset(br#"{"nftables":[{"metainfo":{"json_schema_version":2}}]}"#)
            .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch);
        assert!(error
            .to_string()
            .contains("unsupported JSON schema version 2"));
    }

    #[test]
    fn bounds_and_sanitizes_rule_summaries() {
        let input = format!("{}\n{}", "x".repeat(MAX_RULE_SUMMARY_BYTES * 2), '\u{1b}');
        let summary = bounded_printable_summary(&input);

        assert_eq!(summary.len(), MAX_RULE_SUMMARY_BYTES);
        assert!(!summary.contains('\n'));
        assert!(!summary.contains('\u{1b}'));
    }

    #[test]
    fn enforces_table_chain_and_rule_cardinality_limits() {
        let mut tables = String::new();
        for index in 0..=MAX_TABLES {
            tables.push_str(&format!("*t{index}\nCOMMIT\n"));
        }
        let table_error = parse_iptables_save(tables.as_bytes(), IptablesFamily::Ipv4).unwrap_err();
        assert_eq!(table_error.kind(), CollectErrorKind::CardinalityLimit);

        let mut chains = String::from("*filter\n");
        for index in 0..=MAX_CHAINS {
            chains.push_str(&format!(":c{index} - [0:0]\n"));
        }
        chains.push_str("COMMIT\n");
        let chain_error = parse_iptables_save(chains.as_bytes(), IptablesFamily::Ipv4).unwrap_err();
        assert_eq!(chain_error.kind(), CollectErrorKind::CardinalityLimit);

        let mut rules = String::from("*filter\n:C - [0:0]\n");
        for _ in 0..=MAX_RULES {
            rules.push_str("-A C\n");
        }
        rules.push_str("COMMIT\n");
        let rule_error = parse_iptables_save(rules.as_bytes(), IptablesFamily::Ipv4).unwrap_err();
        assert_eq!(rule_error.kind(), CollectErrorKind::CardinalityLimit);
    }

    #[test]
    fn invokes_collectors_with_fixed_read_only_arguments() {
        let root = tempdir().unwrap();
        let iptables = executable(
            &root,
            "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = '-c' ] || exit 19\nprintf '%b' '*filter\\n:INPUT ACCEPT [0:0]\\nCOMMIT\\n'\n",
        );
        let iptables_ruleset = collect_iptables_with_command(
            IptablesFamily::Ipv4,
            Path::new("/bin/sh"),
            &[iptables.as_os_str()],
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap();
        assert_eq!(iptables_ruleset.tables[0].name, "filter");

        let nft = executable(
            &root,
            "#!/bin/sh\n[ \"$#\" -eq 4 ] && [ \"$1\" = '-j' ] && [ \"$2\" = '-a' ] && [ \"$3\" = 'list' ] && [ \"$4\" = 'ruleset' ] || exit 19\nprintf '%s' '{\"nftables\":[]}'\n",
        );
        let nft_ruleset = collect_nftables_with_command(
            Path::new("/bin/sh"),
            &[nft.as_os_str()],
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap();
        assert!(nft_ruleset.tables.is_empty());
    }

    #[test]
    fn classifies_timeout_output_limit_permission_and_missing_binary() {
        let root = tempdir().unwrap();
        let sleeping = executable(&root, "#!/bin/sh\nsleep 5\n");
        let timeout = collect_nftables_with_command(
            Path::new("/bin/sh"),
            &[sleeping.as_os_str()],
            test_limits(Duration::from_millis(30), 4096),
        )
        .unwrap_err();
        assert_eq!(timeout.kind(), CollectErrorKind::Timeout);

        let writing = executable(
            &root,
            "#!/bin/sh\nwhile :; do printf '%s' '0123456789abcdef'; done\n",
        );
        let output_limit = collect_nftables_with_command(
            Path::new("/bin/sh"),
            &[writing.as_os_str()],
            test_limits(Duration::from_secs(1), 64),
        )
        .unwrap_err();
        assert_eq!(output_limit.kind(), CollectErrorKind::OutputLimit);

        let denied = executable(
            &root,
            "#!/bin/sh\nprintf '%s' 'Operation not permitted (you must be root)' >&2\nexit 1\n",
        );
        let permission = collect_nftables_with_command(
            Path::new("/bin/sh"),
            &[denied.as_os_str()],
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();
        assert_eq!(permission.kind(), CollectErrorKind::PermissionDenied);

        let missing = collect_nftables_with_command(
            &root.path().join("missing-nft"),
            &[],
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();
        assert_eq!(missing.kind(), CollectErrorKind::NotFound);
    }

    #[test]
    fn distinguishes_command_failure_from_schema_mismatch() {
        let root = tempdir().unwrap();
        let failed = executable(&root, "#!/bin/sh\nprintf 'bad\\nmessage' >&2\nexit 7\n");
        let failure = collect_nftables_with_command(
            Path::new("/bin/sh"),
            &[failed.as_os_str()],
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();
        assert_eq!(failure.kind(), CollectErrorKind::CommandFailed);
        assert!(failure.to_string().contains("bad?message"));

        let schema = parse_nft_ruleset(br#"{"nftables":{}}"#).unwrap_err();
        assert_eq!(schema.kind(), CollectErrorKind::SchemaMismatch);
    }
}
