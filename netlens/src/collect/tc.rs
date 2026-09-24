use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
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

use super::valid_interface_name;

mod native;
pub(crate) use native::QdiscCollector;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(5);
const READER_JOIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_STDOUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_IDENTITY_PART_BYTES: usize = 128;
const MAX_IFINDEX_FILE_BYTES: usize = 32;
const MAX_ERROR_DETAIL_BYTES: usize = 256;
const QDISC_READINGS_PER_OBJECT: usize = 13;
const MAX_QDISC_OBJECTS: usize = 4_096 / QDISC_READINGS_PER_OBJECT;
const INGRESS_QDISC_PARENT: &str = "ffff:fff1";
const CLSACT_INGRESS_PARENT: &str = "ffff:fff2";
const _: () = assert!(
    MAX_QDISC_OBJECTS * QDISC_READINGS_PER_OBJECT
        <= crate::monitor::model::MAX_READINGS_PER_PROVIDER
);

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct QdiscIdentity {
    interface: String,
    ifindex: u32,
    kind: String,
    handle: Option<String>,
    parent: Option<String>,
    root: bool,
}

impl fmt::Debug for QdiscIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QdiscIdentity(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QdiscDirection {
    Ingress,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct QdiscRow {
    pub(crate) identity: QdiscIdentity,
    pub(crate) interface: String,
    pub(crate) ifindex: u32,
    pub(crate) counter_bits: QdiscCounterBits,
    pub(crate) packets: Option<u64>,
    pub(crate) bytes: Option<u64>,
    pub(crate) drops: Option<u64>,
    pub(crate) overlimits: Option<u64>,
    pub(crate) requeues: Option<u64>,
    pub(crate) backlog_bytes: Option<u64>,
    pub(crate) backlog_packets: Option<u64>,
    pub(crate) max_packet_bytes: Option<u32>,
    pub(crate) drop_overlimit: Option<u32>,
    pub(crate) new_flow_count: Option<u32>,
    pub(crate) ecn_marks: Option<u32>,
    pub(crate) new_flows_len: Option<u32>,
    pub(crate) old_flows_len: Option<u32>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct QdiscCounterBits {
    pub(crate) packets: Option<u8>,
    pub(crate) bytes: Option<u8>,
    pub(crate) drops: Option<u8>,
    pub(crate) overlimits: Option<u8>,
    pub(crate) requeues: Option<u8>,
}

impl QdiscRow {
    pub(crate) fn kind(&self) -> &str {
        &self.identity.kind
    }

    pub(crate) fn attachment(&self) -> (bool, Option<&str>, Option<&str>) {
        (
            self.identity.root,
            self.identity.handle.as_deref(),
            self.identity.parent.as_deref(),
        )
    }

    pub(crate) fn direction(&self) -> Option<QdiscDirection> {
        if self.identity.kind == "clsact" {
            return None;
        }
        if self.identity.kind == "ingress"
            || matches!(
                self.identity.parent.as_deref(),
                Some(INGRESS_QDISC_PARENT | CLSACT_INGRESS_PARENT)
            )
        {
            Some(QdiscDirection::Ingress)
        } else {
            Some(QdiscDirection::Egress)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CollectErrorKind {
    InvalidRequest,
    Unsupported,
    PermissionDenied,
    NotFound,
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
            io::ErrorKind::PermissionDenied => CollectErrorKind::PermissionDenied,
            io::ErrorKind::NotFound => CollectErrorKind::NotFound,
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

pub(crate) fn collect_qdiscs(
    sys_root: &Path,
    interface: Option<&str>,
) -> Result<Vec<QdiscRow>, CollectError> {
    collect_with_binary(
        sys_root,
        interface,
        Path::new("tc"),
        CommandLimits::production(),
    )
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

fn collect_with_binary(
    sys_root: &Path,
    interface: Option<&str>,
    binary: &Path,
    limits: CommandLimits,
) -> Result<Vec<QdiscRow>, CollectError> {
    collect_with_command(sys_root, interface, binary, &[], limits)
}

fn collect_with_command(
    sys_root: &Path,
    interface: Option<&str>,
    binary: &Path,
    prefix_arguments: &[&OsStr],
    limits: CommandLimits,
) -> Result<Vec<QdiscRow>, CollectError> {
    if interface.is_some_and(|name| !valid_interface_name(name)) {
        return Err(CollectError::new(
            CollectErrorKind::InvalidRequest,
            format!("invalid interface name {interface:?}"),
        ));
    }

    let output = run_tc(binary, prefix_arguments, interface, limits)?;
    parse_qdiscs(&output, sys_root, interface)
}

fn run_tc(
    binary: &Path,
    prefix_arguments: &[&OsStr],
    interface: Option<&str>,
    limits: CommandLimits,
) -> Result<Vec<u8>, CollectError> {
    let started = Instant::now();
    let mut command = Command::new(binary);
    command
        .args(prefix_arguments)
        .arg("-s")
        .arg("-j")
        .arg("qdisc")
        .arg("show")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("LC_ALL", "C")
        .process_group(0);
    if let Some(interface) = interface {
        command.arg("dev").arg(interface);
    }

    let mut child = command
        .spawn()
        .map_err(|error| CollectError::io("start tc qdisc collector", error))?;
    let stdout = child
        .stdout
        .take()
        .expect("tc stdout is piped before the process starts");
    let stderr = child
        .stderr
        .take()
        .expect("tc stderr is piped before the process starts");
    let control = Arc::new(ReaderControl::default());
    if let Err(error) = set_nonblocking(&stdout) {
        stop_command(&mut child, &control);
        let _ = child.wait();
        return Err(CollectError::io(
            "configure tc stdout as nonblocking",
            error,
        ));
    }
    if let Err(error) = set_nonblocking(&stderr) {
        stop_command(&mut child, &control);
        let _ = child.wait();
        return Err(CollectError::io(
            "configure tc stderr as nonblocking",
            error,
        ));
    }
    let stdout_reader = spawn_bounded_reader(
        "netlens-tc-stdout",
        stdout,
        limits.stdout_bytes,
        Arc::clone(&control),
    )
    .map_err(|error| {
        stop_command(&mut child, &control);
        let _ = child.wait();
        CollectError::io("start tc stdout reader", error)
    })?;
    let stderr_reader = match spawn_bounded_reader(
        "netlens-tc-stderr",
        stderr,
        limits.stderr_bytes,
        Arc::clone(&control),
    ) {
        Ok(reader) => reader,
        Err(error) => {
            stop_command(&mut child, &control);
            let deadline = Instant::now() + READER_JOIN_TIMEOUT;
            let _ = join_reader(stdout_reader, deadline);
            let _ = child.wait();
            return Err(CollectError::io("start tc stderr reader", error));
        }
    };

    let outcome = wait_for_command(&mut child, started, limits.timeout, &control);
    stop_command(&mut child, &control);
    let deadline = Instant::now() + READER_JOIN_TIMEOUT;
    let stdout = join_reader(stdout_reader, deadline);
    let stderr = join_reader(stderr_reader, deadline);
    let _ = child.wait();
    let outcome = outcome?;

    match outcome {
        CommandOutcome::Timeout => Err(CollectError::new(
            CollectErrorKind::Timeout,
            format!(
                "tc qdisc collector exceeded its {} ms timeout",
                limits.timeout.as_millis()
            ),
        )),
        CommandOutcome::OutputLimit => Err(CollectError::new(
            CollectErrorKind::OutputLimit,
            "tc qdisc collector output exceeded its size limit",
        )),
        CommandOutcome::ReaderFailed => {
            stdout?;
            stderr?;
            Err(CollectError::new(
                CollectErrorKind::Io,
                "tc output reader failed without an I/O diagnostic",
            ))
        }
        CommandOutcome::Exited(status) => {
            let stdout = stdout?;
            let stderr = stderr?;
            if stdout.exceeded || stderr.exceeded {
                return Err(CollectError::new(
                    CollectErrorKind::OutputLimit,
                    "tc qdisc collector output exceeded its size limit",
                ));
            }
            if !status.success() {
                return Err(command_failed(status, &stderr.bytes));
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
                return Err(CollectError::io("wait for tc qdisc collector", error));
            }
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        thread::sleep(COMMAND_POLL_INTERVAL.min(remaining));
    }
}

fn terminate(child: &mut Child) {
    if let Ok(process_group) = i32::try_from(child.id()) {
        // This reaches descendants that remain in the process group. Reader
        // cancellation also closes pipes retained by detached descendants.
        unsafe {
            libc::kill(-process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

fn stop_command(child: &mut Child, control: &ReaderControl) {
    terminate(child);
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
) -> Result<BoundedOutput, CollectError> {
    while !reader.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err(CollectError::new(
                CollectErrorKind::Io,
                "tc output reader did not stop after cancellation",
            ));
        }
        thread::sleep(COMMAND_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
    reader
        .join()
        .map_err(|_| {
            CollectError::new(
                CollectErrorKind::Io,
                "tc output reader terminated unexpectedly",
            )
        })?
        .map_err(|error| CollectError::io("read tc qdisc collector output", error))
}

fn command_failed(status: ExitStatus, stderr: &[u8]) -> CollectError {
    let detail = printable_excerpt(stderr);
    let lowercase = detail.to_ascii_lowercase();
    let kind = if ["cannot find device", "device not found", "no such device"]
        .iter()
        .any(|phrase| lowercase.contains(phrase))
    {
        CollectErrorKind::NotFound
    } else if ["operation not permitted", "permission denied"]
        .iter()
        .any(|phrase| lowercase.contains(phrase))
    {
        CollectErrorKind::PermissionDenied
    } else {
        CollectErrorKind::CommandFailed
    };
    let message = if detail.is_empty() {
        format!("tc qdisc collector exited with {status}")
    } else {
        format!("tc qdisc collector exited with {status}: {detail}")
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

fn parse_qdiscs(
    input: &[u8],
    sys_root: &Path,
    requested_interface: Option<&str>,
) -> Result<Vec<QdiscRow>, CollectError> {
    let value: Value = serde_json::from_slice(input).map_err(|error| {
        CollectError::schema(format!("tc qdisc output is not valid JSON: {error}"))
    })?;
    let objects = value
        .as_array()
        .ok_or_else(|| CollectError::schema("tc qdisc output must be a JSON array"))?;
    if objects.len() > MAX_QDISC_OBJECTS {
        return Err(CollectError::new(
            CollectErrorKind::CardinalityLimit,
            format!(
                "tc qdisc output contains {} objects, exceeding the {MAX_QDISC_OBJECTS}-object limit",
                objects.len()
            ),
        ));
    }
    let mut ifindices = BTreeMap::new();
    let mut identities = BTreeSet::new();
    let mut rows = Vec::with_capacity(objects.len());

    for (index, value) in objects.iter().enumerate() {
        let object = value.as_object().ok_or_else(|| {
            CollectError::schema(format!("tc qdisc object {index} must be a JSON object"))
        })?;
        let interface = required_string(object, "dev", index)?;
        if !valid_interface_name(interface) {
            return Err(CollectError::schema(format!(
                "tc qdisc object {index} has an invalid interface name"
            )));
        }
        if requested_interface.is_some_and(|requested| requested != interface) {
            return Err(CollectError::schema(format!(
                "tc qdisc object {index} does not match the requested interface"
            )));
        }

        let kind = required_identity_part(object, "kind", index)?;
        let handle = optional_identity_part(object, "handle", index)?;
        let parent = optional_identity_part(object, "parent", index)?;
        let root = optional_bool(object, "root", index)?.unwrap_or(false);
        let ifindex = match ifindices.get(interface) {
            Some(ifindex) => *ifindex,
            None => {
                let ifindex = read_ifindex(sys_root, interface)?;
                ifindices.insert(interface.to_owned(), ifindex);
                ifindex
            }
        };
        let identity = QdiscIdentity {
            interface: interface.to_owned(),
            ifindex,
            kind,
            handle,
            parent,
            root,
        };
        if !identities.insert(identity.clone()) {
            return Err(CollectError::schema(format!(
                "tc qdisc object {index} has a duplicate private identity"
            )));
        }

        rows.push(QdiscRow {
            identity,
            interface: interface.to_owned(),
            ifindex,
            counter_bits: QdiscCounterBits::default(),
            packets: optional_u64(object, "packets", index)?,
            bytes: optional_u64(object, "bytes", index)?,
            drops: optional_u64(object, "drops", index)?,
            overlimits: optional_u64(object, "overlimits", index)?,
            requeues: optional_u64(object, "requeues", index)?,
            backlog_bytes: optional_u64(object, "backlog", index)?,
            backlog_packets: optional_u64(object, "qlen", index)?,
            max_packet_bytes: optional_u32(object, "maxpacket", index)?,
            drop_overlimit: optional_u32(object, "drop_overlimit", index)?,
            new_flow_count: optional_u32(object, "new_flow_count", index)?,
            ecn_marks: optional_u32(object, "ecn_mark", index)?,
            new_flows_len: optional_u32(object, "new_flows_len", index)?,
            old_flows_len: optional_u32(object, "old_flows_len", index)?,
        });
    }

    Ok(rows)
}

#[cfg(test)]
pub(crate) fn parse_qdiscs_for_test(
    input: &[u8],
    sys_root: &Path,
) -> Result<Vec<QdiscRow>, CollectError> {
    parse_qdiscs(input, sys_root, None)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<&'a str, CollectError> {
    object.get(field).and_then(Value::as_str).ok_or_else(|| {
        CollectError::schema(format!(
            "tc qdisc object {index} field {field:?} must be a string"
        ))
    })
}

fn required_identity_part(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<String, CollectError> {
    let value = required_string(object, field, index)?;
    validate_identity_part(value, field, index)?;
    Ok(value.to_owned())
}

fn optional_identity_part(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<String>, CollectError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value.as_str().ok_or_else(|| {
        CollectError::schema(format!(
            "tc qdisc object {index} field {field:?} must be a string"
        ))
    })?;
    validate_identity_part(value, field, index)?;
    Ok(Some(value.to_owned()))
}

fn validate_identity_part(value: &str, field: &str, index: usize) -> Result<(), CollectError> {
    if value.is_empty()
        || value.len() > MAX_IDENTITY_PART_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(CollectError::schema(format!(
            "tc qdisc object {index} field {field:?} is not a valid identity part"
        )));
    }
    Ok(())
}

fn optional_bool(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<bool>, CollectError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(CollectError::schema(format!(
            "tc qdisc object {index} field {field:?} must be a boolean"
        ))),
    }
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<u64>, CollectError> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value.as_u64().map(Some).ok_or_else(|| {
            CollectError::schema(format!(
                "tc qdisc object {index} field {field:?} must be an unsigned integer"
            ))
        }),
        Some(_) => Err(CollectError::schema(format!(
            "tc qdisc object {index} field {field:?} must be an unsigned integer"
        ))),
    }
}

fn optional_u32(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<u32>, CollectError> {
    optional_u64(object, field, index)?
        .map(|value| {
            u32::try_from(value).map_err(|_| {
                CollectError::schema(format!(
                    "tc qdisc object {index} field {field:?} exceeds an unsigned 32-bit integer"
                ))
            })
        })
        .transpose()
}

fn read_ifindex(sys_root: &Path, interface: &str) -> Result<u32, CollectError> {
    let path = sys_root.join("class/net").join(interface).join("ifindex");
    let raw = fs::read(&path).map_err(|error| {
        CollectError::io(
            &format!("read interface index from {}", path.display()),
            error,
        )
    })?;
    if raw.len() > MAX_IFINDEX_FILE_BYTES {
        return Err(CollectError::schema(format!(
            "{} exceeds the interface-index size limit",
            path.display()
        )));
    }
    let value = std::str::from_utf8(&raw)
        .map_err(|_| CollectError::schema(format!("{} is not UTF-8", path.display())))?
        .trim()
        .parse::<u32>()
        .map_err(|error| {
            CollectError::schema(format!(
                "{} is not an interface index: {error}",
                path.display()
            ))
        })?;
    if value == 0 || value > i32::MAX as u32 {
        return Err(CollectError::schema(format!(
            "{} contains an invalid Linux interface index",
            path.display()
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::{tempdir, TempDir};

    use super::*;

    fn sysfs_interface(root: &TempDir, interface: &str, ifindex: &str) {
        let path = root.path().join("class/net").join(interface);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("ifindex"), ifindex).unwrap();
    }

    fn parse_fixture(root: &TempDir, input: &str) -> Result<Vec<QdiscRow>, CollectError> {
        parse_qdiscs(input.as_bytes(), root.path(), None)
    }

    fn executable(root: &TempDir, body: &str) -> std::path::PathBuf {
        let path = root.path().join("fake-tc");
        fs::write(&path, body).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn collect_with_script(
        sys_root: &Path,
        interface: Option<&str>,
        script: &Path,
        limits: CommandLimits,
    ) -> Result<Vec<QdiscRow>, CollectError> {
        collect_with_command(
            sys_root,
            interface,
            Path::new("/bin/sh"),
            &[script.as_os_str()],
            limits,
        )
    }

    fn test_limits(timeout: Duration, output_bytes: usize) -> CommandLimits {
        CommandLimits {
            timeout,
            stdout_bytes: output_bytes,
            stderr_bytes: output_bytes,
        }
    }

    #[test]
    fn parses_each_parent_and_child_without_aggregation() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "7\n");

        let rows = parse_fixture(
            &root,
            r#"[
                {"kind":"mq","handle":"0:","dev":"eth0","root":true,
                 "bytes":1000,"packets":100,"drops":4,"overlimits":5,
                 "requeues":6,"backlog":7,"qlen":8},
                {"kind":"fq_codel","handle":"0:","dev":"eth0","parent":":1",
                 "bytes":600,"packets":60,"drops":2,"overlimits":3,
                 "requeues":1,"backlog":4,"qlen":5,"maxpacket":1514,
                 "drop_overlimit":9,"new_flow_count":10,"ecn_mark":11,
                 "new_flows_len":12,"old_flows_len":13}
            ]"#,
        )
        .unwrap();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].interface, "eth0");
        assert_eq!(rows[0].ifindex, 7);
        assert_eq!(rows[0].attachment(), (true, Some("0:"), None));
        assert_eq!(rows[1].attachment(), (false, Some("0:"), Some(":1")));
        assert_eq!(rows[0].packets, Some(100));
        assert_eq!(rows[0].bytes, Some(1000));
        assert_eq!(rows[0].drops, Some(4));
        assert_eq!(rows[0].overlimits, Some(5));
        assert_eq!(rows[0].requeues, Some(6));
        assert_eq!(rows[0].backlog_bytes, Some(7));
        assert_eq!(rows[0].backlog_packets, Some(8));
        assert_eq!(rows[1].packets, Some(60));
        assert_eq!(rows[1].max_packet_bytes, Some(1514));
        assert_eq!(rows[1].drop_overlimit, Some(9));
        assert_eq!(rows[1].new_flow_count, Some(10));
        assert_eq!(rows[1].ecn_marks, Some(11));
        assert_eq!(rows[1].new_flows_len, Some(12));
        assert_eq!(rows[1].old_flows_len, Some(13));
        assert_ne!(rows[0].identity, rows[1].identity);
    }

    #[test]
    fn exposes_only_sanitized_qdisc_direction() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "7\n");
        let rows = parse_fixture(
            &root,
            r#"[
                {"kind":"fq_codel","handle":"1:","dev":"eth0","root":true},
                {"kind":"fq_codel","handle":"2:","dev":"eth0","parent":"1:1"},
                {"kind":"ingress","handle":"ffff:","dev":"eth0","parent":"ffff:fff1"},
                {"kind":"custom","handle":"3:","dev":"eth0","parent":"ffff:fff1"},
                {"kind":"custom","handle":"4:","dev":"eth0","parent":"ffff:fff2"},
                {"kind":"clsact","handle":"ffff:","dev":"eth0","parent":"ffff:fff1"},
                {"kind":"custom","handle":"5:","dev":"eth0","parent":"ffff:fff3"}
            ]"#,
        )
        .unwrap();

        assert_eq!(rows[0].direction(), Some(QdiscDirection::Egress));
        assert_eq!(rows[1].direction(), Some(QdiscDirection::Egress));
        assert_eq!(rows[2].direction(), Some(QdiscDirection::Ingress));
        assert_eq!(rows[3].direction(), Some(QdiscDirection::Ingress));
        assert_eq!(rows[4].direction(), Some(QdiscDirection::Ingress));
        assert_eq!(rows[5].direction(), None);
        assert_eq!(rows[6].direction(), Some(QdiscDirection::Egress));

        let exposed = rows
            .iter()
            .map(|row| format!("{:?}", row.direction()))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            exposed,
            "Some(Egress),Some(Egress),Some(Ingress),Some(Ingress),Some(Ingress),None,Some(Egress)"
        );
        for private in ["fq_codel", "ingress", "clsact", "ffff:", "ffff:fff1"] {
            assert!(!exposed.contains(private));
        }
    }

    #[test]
    fn missing_statistics_remain_unavailable() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "2\n");

        let rows = parse_fixture(
            &root,
            r#"[{"kind":"noqueue","handle":"0:","dev":"eth0","root":true}]"#,
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].packets, None);
        assert_eq!(rows[0].bytes, None);
        assert_eq!(rows[0].drops, None);
        assert_eq!(rows[0].overlimits, None);
        assert_eq!(rows[0].requeues, None);
        assert_eq!(rows[0].backlog_bytes, None);
        assert_eq!(rows[0].backlog_packets, None);
        assert_eq!(rows[0].max_packet_bytes, None);
        assert_eq!(rows[0].drop_overlimit, None);
        assert_eq!(rows[0].new_flow_count, None);
        assert_eq!(rows[0].ecn_marks, None);
        assert_eq!(rows[0].new_flows_len, None);
        assert_eq!(rows[0].old_flows_len, None);
    }

    #[test]
    fn rejects_malformed_json_shapes_and_field_types() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "2\n");
        let invalid = [
            "{}",
            "[[]]",
            r#"[{"kind":"fq_codel"}]"#,
            r#"[{"kind":"fq_codel","dev":2}]"#,
            r#"[{"kind":null,"dev":"eth0"}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","handle":1}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","root":"yes"}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","packets":"1"}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","drops":-1}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","qlen":1.5}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","ecn_mark":"1"}]"#,
            r#"[{"kind":"fq_codel","dev":"eth0","maxpacket":4294967296}]"#,
            r#"[{"kind":"fq_codel","dev":"eth 0"}]"#,
        ];

        for input in invalid {
            let error = parse_fixture(&root, input).unwrap_err();
            assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch, "{input}");
        }
        assert_eq!(
            parse_fixture(&root, "[").unwrap_err().kind(),
            CollectErrorKind::SchemaMismatch
        );
    }

    #[test]
    fn bounds_qdisc_objects_to_the_provider_reading_budget() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "2\n");
        let mut objects = (0..MAX_QDISC_OBJECTS)
            .map(|index| {
                serde_json::json!({
                    "kind": "fq_codel",
                    "handle": format!("{index:x}:"),
                    "dev": "eth0",
                    "packets": 1,
                    "bytes": 2,
                    "drops": 3,
                    "overlimits": 4,
                    "requeues": 5,
                    "backlog": 6,
                    "qlen": 7,
                    "maxpacket": 8,
                    "drop_overlimit": 9,
                    "new_flow_count": 10,
                    "ecn_mark": 11,
                    "new_flows_len": 12,
                    "old_flows_len": 13
                })
            })
            .collect::<Vec<_>>();

        let rows = parse_qdiscs(&serde_json::to_vec(&objects).unwrap(), root.path(), None).unwrap();
        assert_eq!(rows.len(), MAX_QDISC_OBJECTS);
        objects.push(serde_json::json!({
            "kind": "fq_codel",
            "handle": "overflow:",
            "dev": "eth0"
        }));
        let error =
            parse_qdiscs(&serde_json::to_vec(&objects).unwrap(), root.path(), None).unwrap_err();
        assert_eq!(error.kind(), CollectErrorKind::CardinalityLimit);
        assert!(error.to_string().contains("316 objects"));
    }

    #[test]
    fn rejects_duplicate_private_identity() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "2\n");
        let error = parse_fixture(
            &root,
            r#"[
                {"kind":"fq_codel","handle":"1:","dev":"eth0","root":true},
                {"kind":"fq_codel","handle":"1:","dev":"eth0","root":true}
            ]"#,
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch);
        assert!(error.to_string().contains("duplicate private identity"));
    }

    #[test]
    fn resolves_and_validates_ifindex_from_supplied_sysfs_root() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "0\n");
        let fixture = r#"[{"kind":"fq_codel","dev":"eth0","root":true}]"#;

        let error = parse_fixture(&root, fixture).unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch);
        fs::write(root.path().join("class/net/eth0/ifindex"), "2\n").unwrap();
        assert_eq!(parse_fixture(&root, fixture).unwrap()[0].ifindex, 2);
    }

    #[test]
    fn rejects_rows_outside_the_requested_interface() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth1", "3\n");
        let error = parse_qdiscs(
            br#"[{"kind":"fq_codel","dev":"eth1","root":true}]"#,
            root.path(),
            Some("eth0"),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::SchemaMismatch);
    }

    #[test]
    fn debug_output_redacts_private_qdisc_identity() {
        let root = tempdir().unwrap();
        sysfs_interface(&root, "eth0", "2\n");
        let row = parse_fixture(
            &root,
            r#"[{"kind":"fq_codel","handle":"a1:","parent":":7","dev":"eth0"}]"#,
        )
        .unwrap()
        .remove(0);

        let rendered = format!("{row:?}");
        assert!(rendered.contains("QdiscIdentity(<redacted>)"));
        assert!(!rendered.contains("fq_codel"));
        assert!(!rendered.contains("a1:"));
        assert!(!rendered.contains(":7"));
    }

    #[test]
    fn invokes_tc_with_fixed_arguments_and_literal_interface() {
        let root = tempdir().unwrap();
        let interface = "eth;literal";
        sysfs_interface(&root, interface, "11\n");
        let binary = executable(
            &root,
            r#"#!/bin/sh
if [ "$#" -ne 6 ] || [ "$1" != "-s" ] || [ "$2" != "-j" ] || \
   [ "$3" != "qdisc" ] || [ "$4" != "show" ] || [ "$5" != "dev" ] || \
   [ "$6" != "eth;literal" ]; then
    echo "unexpected argv" >&2
    exit 19
fi
printf '%s' '[{"kind":"fq_codel","handle":"0:","dev":"eth;literal","root":true,"packets":9}]'
"#,
        );

        let rows = collect_with_script(
            root.path(),
            Some(interface),
            &binary,
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].interface, interface);
        assert_eq!(rows[0].packets, Some(9));
    }

    #[test]
    fn kills_tc_after_the_finite_timeout() {
        let root = tempdir().unwrap();
        let binary = executable(&root, "#!/bin/sh\nsleep 5\n");
        let started = Instant::now();

        let error = collect_with_script(
            root.path(),
            None,
            &binary,
            test_limits(Duration::from_millis(30), 4096),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn detached_descendant_cannot_hold_output_readers_open() {
        let root = tempdir().unwrap();
        let ready = root.path().join("detached-ready");
        let pid_file = root.path().join("detached-pid");
        let binary = executable(
            &root,
            &format!(
                "#!/bin/sh\n\
                 setsid sh -c 'touch \"{}\"; sleep 5' &\n\
                 printf '%s\\n' \"$!\" > \"{}\"\n\
                 while [ ! -e \"{}\" ]; do :; done\n\
                 printf '%s' '[]'\n",
                ready.display(),
                pid_file.display(),
                ready.display()
            ),
        );
        let started = Instant::now();

        let result = collect_with_script(
            root.path(),
            None,
            &binary,
            test_limits(Duration::from_secs(3), 4096),
        );
        let elapsed = started.elapsed();

        let detached_pid = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        unsafe {
            libc::kill(-detached_pid, libc::SIGKILL);
        }
        assert!(result.unwrap().is_empty());
        assert!(elapsed < Duration::from_secs(1), "elapsed: {elapsed:?}");
    }

    #[test]
    fn rejects_output_larger_than_the_configured_bound() {
        let root = tempdir().unwrap();
        let binary = executable(&root, "#!/bin/sh\nprintf '%s' '12345678901234567890'\n");

        let error = collect_with_script(
            root.path(),
            None,
            &binary,
            test_limits(Duration::from_secs(1), 8),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::OutputLimit);
    }

    #[test]
    fn stops_a_continuous_writer_at_the_output_limit() {
        let root = tempdir().unwrap();
        let binary = executable(
            &root,
            "#!/bin/sh\nwhile :; do printf '%s' '0123456789abcdef'; done\n",
        );
        let started = Instant::now();

        let error = collect_with_script(
            root.path(),
            None,
            &binary,
            test_limits(Duration::from_secs(3), 64),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::OutputLimit);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "elapsed: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn reports_nonzero_exit_with_sanitized_bounded_stderr() {
        let root = tempdir().unwrap();
        let binary = executable(&root, "#!/bin/sh\nprintf 'bad\\nmessage' >&2\nexit 7\n");

        let error = collect_with_script(
            root.path(),
            None,
            &binary,
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::CommandFailed);
        assert!(error.to_string().contains("bad?message"));
        assert!(!error.to_string().contains('\n'));
    }

    #[test]
    fn classifies_missing_device_and_permission_failures_at_the_command_boundary() {
        let root = tempdir().unwrap();
        let missing = executable(
            &root,
            "#!/bin/sh\nprintf '%s' 'Cannot find device missing0' >&2\nexit 1\n",
        );
        let missing_error = collect_with_script(
            root.path(),
            None,
            &missing,
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();
        let denied = executable(
            &root,
            "#!/bin/sh\nprintf '%s' 'RTNETLINK answers: Operation not permitted' >&2\nexit 2\n",
        );
        let denied_error = collect_with_script(
            root.path(),
            None,
            &denied,
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();

        assert_eq!(missing_error.kind(), CollectErrorKind::NotFound);
        assert_eq!(denied_error.kind(), CollectErrorKind::PermissionDenied);
    }

    #[test]
    fn reports_missing_tc_binary_as_not_found() {
        let root = tempdir().unwrap();
        let error = collect_with_binary(
            root.path(),
            None,
            &root.path().join("does-not-exist"),
            test_limits(Duration::from_secs(1), 4096),
        )
        .unwrap_err();

        assert_eq!(error.kind(), CollectErrorKind::NotFound);
    }
}
