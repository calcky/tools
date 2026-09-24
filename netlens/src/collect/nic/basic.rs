//! A bounded ethtool 6.14 basic-settings frontend. Unsupported shapes use the CLI.
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{
    capture_command, netlink, ETHTOOL_STDERR_LIMIT, ETHTOOL_STDOUT_LIMIT, ETHTOOL_TIMEOUT,
};

pub(super) const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(100);
pub(super) const OPERATIONS: [(u8, u8); 7] =
    [(4, 4), (2, 2), (9, 9), (39, 39), (7, 7), (6, 6), (41, 40)];
const COMMAND_NAMES: [&str; 7] = [
    "ETHTOOL_MSG_LINKMODES_GET",
    "ETHTOOL_MSG_LINKINFO_GET",
    "ETHTOOL_MSG_WOL_GET",
    "ETHTOOL_MSG_PLCA_GET_CFG",
    "ETHTOOL_MSG_DEBUG_GET",
    "ETHTOOL_MSG_LINKSTATE_GET",
    "ETHTOOL_MSG_PLCA_GET_STATUS",
];

#[derive(Debug)]
pub(super) struct ContextPool {
    available: Mutex<Vec<Option<netlink::Context>>>,
}

impl Default for ContextPool {
    fn default() -> Self {
        Self {
            available: Mutex::new((0..super::MAX_ETHTOOL_CONCURRENCY).map(|_| None).collect()),
        }
    }
}

struct ContextLease<'a> {
    pool: &'a ContextPool,
    context: Option<netlink::Context>,
}

impl Drop for ContextLease<'_> {
    fn drop(&mut self) {
        let context = self.context.take();
        // A panic could leave an unfinished transaction on the socket.
        let context = if std::thread::panicking() {
            None
        } else {
            context
        };
        self.pool
            .available
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(context);
    }
}

impl ContextPool {
    pub(super) fn settings_until(
        &self,
        interface: &str,
        ifindex: u32,
        deadline: Instant,
    ) -> io::Result<super::ParsedEthtoolSettings> {
        self.with_context(deadline, |context, deadline| {
            if context.is_none() {
                *context = Some(netlink::Context::new_until(deadline)?);
            }
            context
                .as_mut()
                .expect("initialized above")
                .basic_settings_until(interface, ifindex, deadline)
        })
    }

    fn with_context<T>(
        &self,
        deadline: Instant,
        query: impl FnOnce(&mut Option<netlink::Context>, Instant) -> io::Result<T>,
    ) -> io::Result<T> {
        check_deadline(deadline)?;
        // Reserve a slot before initialization, with no network I/O under the
        // pool lock. Empty slots also return after initialization failures.
        let context = self
            .available
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pop()
            .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "basic context pool busy"))?;
        let mut lease = ContextLease {
            pool: self,
            context,
        };
        check_deadline(deadline)?;
        let result = query(&mut lease.context, deadline);
        check_deadline(deadline)?;
        result
    }
}

pub(super) fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native basic settings deadline expired",
        ))
    } else {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(super) struct Frontend {
    executable: Option<Executable>,
    compatible: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Executable {
    path: PathBuf,
    identity: [u64; 12],
}

impl Executable {
    fn at(path: PathBuf) -> Option<Self> {
        let metadata = fs::metadata(&path).ok()?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return None;
        }
        // Credentials and inode timestamps invalidate cached frontend checks.
        Some(Self {
            path,
            identity: [
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mode() as u64,
                metadata.uid() as u64,
                metadata.gid() as u64,
                metadata.mtime() as u64,
                metadata.mtime_nsec() as u64,
                metadata.ctime() as u64,
                metadata.ctime_nsec() as u64,
                unsafe { libc::geteuid() } as u64,
                unsafe { libc::getegid() } as u64,
            ],
        })
    }

    fn find() -> Option<Self> {
        let path = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
        std::env::split_paths(&path).find_map(|directory| Self::at(directory.join("ethtool")))
    }

    pub(super) fn current(&self) -> bool {
        Self::find().as_ref() == Some(self)
    }
}

impl Frontend {
    pub(super) fn prepare(&mut self, interface: &str) -> Option<Executable> {
        if !valid_cli_interface(interface) {
            return None;
        }
        let executable = Executable::find();
        if executable != self.executable {
            self.compatible = false;
            self.executable = executable;
            if let Some(executable) = &self.executable {
                self.compatible = verify_frontend(&executable.path, interface);
            }
        }
        self.compatible.then(|| self.executable.clone()).flatten()
    }
}

fn verify_frontend(program: &Path, interface: &str) -> bool {
    // A script can report an upstream version while adding arbitrary fields.
    let mut magic = [0; 4];
    if File::open(program)
        .and_then(|mut file| file.read_exact(&mut magic))
        .is_err()
        || magic != *b"\x7fELF"
    {
        return false;
    }
    let deadline = Instant::now() + ETHTOOL_TIMEOUT;
    let mut version = Command::new(program);
    version.arg("--version");
    let Ok(version) = capture_command(version, ETHTOOL_TIMEOUT, 1024, ETHTOOL_STDERR_LIMIT) else {
        return false;
    };
    if !matches!(
        version.as_slice(),
        b"ethtool version 6.14\n" | b"ethtool version 6.14.2\n"
    ) {
        return false;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let mut debug = Command::new(program);
    debug.args([
        OsStr::new("--debug"),
        OsStr::new("2"),
        OsStr::new(interface),
    ]);
    let Ok(output) = capture_command(debug, remaining, ETHTOOL_STDOUT_LIMIT, ETHTOOL_STDERR_LIMIT)
    else {
        return false;
    };
    debug_profile(&output)
}

fn debug_profile(output: &[u8]) -> bool {
    let Ok(output) = std::str::from_utf8(output) else {
        return false;
    };
    let mut sending = false;
    let mut commands = Vec::new();
    for line in output.lines() {
        if line.starts_with("sending genetlink packet (") {
            sending = true;
        } else if line.starts_with("received genetlink packet (") {
            sending = false;
        } else if sending && line.starts_with("    msg length ") {
            if let Some(command) = line
                .split_ascii_whitespace()
                .last()
                .filter(|word| word.starts_with("ETHTOOL_MSG_"))
            {
                commands.push(command);
            }
        }
    }
    // PLCA requests may be absent when not advertised by the generic family.
    let mut required = Vec::new();
    for command in &commands {
        if *command != COMMAND_NAMES[3] && *command != COMMAND_NAMES[6] {
            required.push(*command);
        }
    }
    required
        == [
            COMMAND_NAMES[0],
            COMMAND_NAMES[1],
            COMMAND_NAMES[2],
            COMMAND_NAMES[4],
            COMMAND_NAMES[5],
        ]
        && commands.windows(2).all(|pair| {
            let left = COMMAND_NAMES.iter().position(|name| *name == pair[0]);
            let right = COMMAND_NAMES.iter().position(|name| *name == pair[1]);
            matches!((left, right), (Some(left), Some(right)) if left < right)
        })
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported native basic ethtool reply",
    )
}

fn valid_cli_interface(interface: &str) -> bool {
    super::valid_interface_name(interface) && !interface.starts_with('-') && interface != "*"
}

pub(super) fn collect_with(
    interface: &str,
    operations: &BTreeSet<u8>,
    mut query: impl FnMut(u8, u8, &mut String) -> io::Result<()>,
) -> io::Result<super::ParsedEthtoolSettings> {
    if !valid_cli_interface(interface)
        || ![4, 2, 9, 7, 6]
            .iter()
            .all(|command| operations.contains(command))
    {
        return Err(unsupported());
    }
    let mut output = format!("Settings for {interface}:\n");
    for (command, reply) in OPERATIONS {
        if !operations.contains(&command) {
            continue;
        }
        let before = output.len();
        match query(command, reply, &mut output) {
            Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => output.truncate(before),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
    }
    let parsed = super::parse_ethtool_settings(output.as_bytes());
    if parsed.settings.fields.is_empty() {
        return Err(unsupported());
    }
    Ok(parsed)
}

type Attributes<'a> = Vec<(u16, &'a [u8])>;

fn fields<'a>(bytes: &'a [u8], allowed: &[u16]) -> io::Result<Attributes<'a>> {
    let attributes = netlink::attrs(bytes)?;
    for (position, (kind, _)) in attributes.iter().enumerate() {
        if !allowed.contains(kind)
            || attributes[..position]
                .iter()
                .any(|(previous, _)| previous == kind)
        {
            return Err(unsupported());
        }
    }
    Ok(attributes)
}

fn get<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attributes
        .iter()
        .find(|(id, _)| *id == kind)
        .map(|(_, bytes)| *bytes)
}

fn required<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> io::Result<&'a [u8]> {
    get(attributes, kind).ok_or_else(unsupported)
}

fn number(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| unsupported())?,
    ))
}

fn byte(bytes: &[u8]) -> io::Result<u8> {
    match bytes {
        [value] => Ok(*value),
        _ => Err(unsupported()),
    }
}

fn text(bytes: &[u8]) -> io::Result<&str> {
    let value = std::str::from_utf8(bytes.strip_suffix(&[0]).ok_or_else(unsupported)?)
        .map_err(|_| unsupported())?;
    if value.contains('\0') || !super::valid_setting_text(value) {
        return Err(unsupported());
    }
    Ok(value)
}

pub(super) fn append_reply(
    output: &mut String,
    command: u8,
    bytes: &[u8],
    interface: &str,
    ifindex: u32,
) -> io::Result<()> {
    let allowed: &[u16] = match command {
        4 => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        2 => &[1, 2, 3, 4, 5, 6],
        9 => &[1, 2, 3],
        7 | 6 => &[1, 2],
        _ => return Err(unsupported()),
    };
    let attributes = fields(bytes, allowed)?;
    let header = fields(required(&attributes, 1)?, &[1, 2])?;
    if number(required(&header, 1)?)? != ifindex || text(required(&header, 2)?)? != interface {
        return Err(unsupported());
    }
    match command {
        4 => link_modes(output, &attributes)?,
        2 => link_info(output, &attributes)?,
        9 => wol(output, &attributes)?,
        7 => debug(output, &attributes)?,
        6 => {
            if let Some(link) = get(&attributes, 2) {
                writeln!(
                    output,
                    "Link detected: {}",
                    if byte(link)? != 0 { "yes" } else { "no" }
                )
                .unwrap();
            }
        }
        _ => unreachable!(),
    }
    if output.len() > ETHTOOL_STDOUT_LIMIT {
        return Err(unsupported());
    }
    Ok(())
}

struct Bit<'a> {
    index: u32,
    name: &'a str,
    value: bool,
}
struct Bitset<'a> {
    bits: Vec<Bit<'a>>,
    nomask: bool,
}

impl<'a> Bitset<'a> {
    fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        let attributes = fields(bytes, &[1, 2, 3])?;
        let nomask = match get(&attributes, 1) {
            Some([]) => true,
            None => false,
            _ => return Err(unsupported()),
        };
        let size = number(required(&attributes, 2)?)?;
        if size == 0 || size > 4096 {
            return Err(unsupported());
        }
        let mut bits = Vec::<Bit<'a>>::new();
        for (kind, bytes) in netlink::attrs(required(&attributes, 3)?)? {
            if kind != 1 {
                return Err(unsupported());
            }
            let attributes = fields(bytes, &[1, 2, 3])?;
            let index = number(required(&attributes, 1)?)?;
            if index >= size || bits.last().is_some_and(|last| last.index >= index) {
                return Err(unsupported());
            }
            let value = match get(&attributes, 3) {
                Some([]) => true,
                None => nomask,
                _ => return Err(unsupported()),
            };
            bits.push(Bit {
                index,
                name: text(required(&attributes, 2)?)?,
                value,
            });
        }
        Ok(Self { bits, nomask })
    }

    fn bit(&self, index: u32, mask: bool) -> bool {
        self.bits
            .iter()
            .any(|bit| bit.index == index && (mask || bit.value))
    }
}

fn mode_class(index: u32) -> io::Result<u8> {
    match index {
        6 => Ok(1),
        7..=11 | 16 => Ok(2),
        13 | 14 => Ok(3),
        49..=51 => Ok(4),
        0..=51 => Ok(0),
        _ => Err(unsupported()),
    }
}

fn mode_list(output: &mut String, bits: &Bitset<'_>, mask: bool, class: u8, label: &str) {
    write!(output, "{label}: ").unwrap();
    if class == 2 {
        output.push_str("[ ");
    }
    let mut previous = None;
    for bit in bits
        .bits
        .iter()
        .filter(|bit| (mask || bit.value) && mode_class(bit.index).ok() == Some(class))
    {
        if let Some(index) = previous {
            if class != 0 || (bit.index == index + 1 && matches!(index, 0 | 2 | 4)) {
                output.push(' ');
            } else {
                output.push_str("\n\t");
            }
        }
        output.push_str(bit.name);
        previous = Some(bit.index);
    }
    if class == 2 {
        if previous.is_some() {
            output.push(' ');
        }
        output.push(']');
    } else if previous.is_none() {
        output.push_str("Not reported");
    }
    output.push('\n');
}

fn modes(output: &mut String, bytes: &[u8], peer: bool) -> io::Result<()> {
    let bits = Bitset::parse(bytes)?;
    if !peer && bits.nomask {
        return Err(unsupported());
    }
    for bit in &bits.bits {
        mode_class(bit.index)?;
    }
    for mask in if peer {
        &[false][..]
    } else {
        &[true, false][..]
    } {
        let prefix = if peer {
            "Link partner advertised"
        } else if *mask {
            "Supported"
        } else {
            "Advertised"
        };
        if !peer && *mask {
            mode_list(output, &bits, true, 2, "Supported ports");
        }
        mode_list(output, &bits, *mask, 0, &format!("{prefix} link modes"));
        let pause = match (bits.bit(13, *mask), bits.bit(14, *mask)) {
            (true, true) => "Symmetric Receive-only",
            (true, false) => "Symmetric",
            (false, true) => "Transmit-only",
            (false, false) => "No",
        };
        writeln!(output, "{prefix} pause frame use: {pause}").unwrap();
        let label = if *mask {
            "Supports auto-negotiation".to_owned()
        } else {
            format!("{prefix} auto-negotiation")
        };
        writeln!(
            output,
            "{label}: {}",
            if bits.bit(6, *mask) { "Yes" } else { "No" }
        )
        .unwrap();
        mode_list(output, &bits, *mask, 4, &format!("{prefix} FEC modes"));
    }
    Ok(())
}

fn enum_value(output: &mut String, label: &str, value: u8, known: Option<&str>) {
    match known {
        Some(name) => writeln!(output, "{label}: {name}"),
        None => writeln!(output, "{label}: Unknown! ({value})"),
    }
    .unwrap();
}

fn link_modes(output: &mut String, attributes: &[(u16, &[u8])]) -> io::Result<()> {
    if let Some(ours) = get(attributes, 3) {
        modes(output, ours, false)?;
    }
    if let Some(peer) = get(attributes, 4) {
        modes(output, peer, true)?;
    }
    if let Some(speed) = get(attributes, 5) {
        match number(speed)? {
            0 | 65535 | u32::MAX => output.push_str("Speed: Unknown!\n"),
            speed => writeln!(output, "Speed: {speed}Mb/s").unwrap(),
        }
    }
    if let Some(lanes) = get(attributes, 9) {
        writeln!(output, "Lanes: {}", number(lanes)?).unwrap();
    }
    if let Some(duplex) = get(attributes, 6) {
        let value = byte(duplex)?;
        enum_value(
            output,
            "Duplex",
            value,
            match value {
                0 => Some("Half"),
                1 => Some("Full"),
                _ => None,
            },
        );
    }
    if let Some(autoneg) = get(attributes, 2) {
        writeln!(
            output,
            "Auto-negotiation: {}",
            if byte(autoneg)? == 0 { "off" } else { "on" }
        )
        .unwrap();
    }
    for (kind, label, names) in [
        (
            7,
            "master-slave cfg",
            &[
                "",
                "unknown",
                "preferred master",
                "preferred slave",
                "forced master",
                "forced slave",
            ][..],
        ),
        (
            8,
            "master-slave status",
            &["", "unknown", "master", "slave", "resolution error"][..],
        ),
    ] {
        if let Some(value) = get(attributes, kind) {
            let value = byte(value)?;
            enum_value(
                output,
                label,
                value,
                names
                    .get(value as usize)
                    .copied()
                    .filter(|name| !name.is_empty()),
            );
        }
    }
    // The verified 6.14 frontend receives but does not print RATE_MATCHING.
    if let Some(value) = get(attributes, 10) {
        byte(value)?;
    }
    Ok(())
}

fn link_info(output: &mut String, attributes: &[(u16, &[u8])]) -> io::Result<()> {
    let port = get(attributes, 2).map(byte).transpose()?;
    if let Some(port) = port {
        enum_value(
            output,
            "Port",
            port,
            match port {
                0 => Some("Twisted Pair"),
                1 => Some("AUI"),
                2 => Some("MII"),
                3 => Some("FIBRE"),
                4 => Some("BNC"),
                5 => Some("Direct Attach Copper"),
                239 => Some("None"),
                255 => Some("Other"),
                _ => None,
            },
        );
    }
    if let Some(phy) = get(attributes, 3) {
        writeln!(output, "PHYAD: {}", byte(phy)?).unwrap();
    }
    if let Some(transceiver) = get(attributes, 6) {
        let value = byte(transceiver)?;
        enum_value(
            output,
            "Transceiver",
            value,
            match value {
                0 => Some("internal"),
                1 => Some("external"),
                _ => None,
            },
        );
    }
    let mdix = get(attributes, 4).map(byte).transpose()?;
    let control = get(attributes, 5).map(byte).transpose()?;
    if let (Some(0), Some(mdix), Some(control)) = (port, mdix, control) {
        let value = match (mdix, control) {
            (_, 1) => "off (forced)",
            (_, 2) => "on (forced)",
            (1, 3) => "off (auto)",
            (2, 3) => "on (auto)",
            (1, _) => "off",
            (2, _) => "on",
            _ => "Unknown",
        };
        writeln!(output, "MDI-X: {value}").unwrap();
    }
    Ok(())
}

fn wol(output: &mut String, attributes: &[(u16, &[u8])]) -> io::Result<()> {
    let bits = Bitset::parse(required(attributes, 2)?)?;
    if bits.bits.iter().any(|bit| bit.index >= 8) {
        return Err(unsupported());
    }
    for (label, mask) in [("Supports Wake-on", true), ("Wake-on", false)] {
        let value: String = (0..8)
            .filter(|index| bits.bit(*index, mask))
            .map(|index| b"pumbagsf"[index as usize] as char)
            .collect();
        writeln!(
            output,
            "{label}: {}",
            if value.is_empty() { "d" } else { &value }
        )
        .unwrap();
    }
    let password = get(attributes, 3);
    if password.is_some_and(|bytes| bytes.len() != 6) {
        return Err(unsupported());
    }
    if bits.bit(6, true) {
        let bytes = password.ok_or_else(unsupported)?;
        writeln!(
            output,
            "SecureOn password: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
        .unwrap();
    }
    Ok(())
}

fn debug(output: &mut String, attributes: &[(u16, &[u8])]) -> io::Result<()> {
    let Some(bytes) = get(attributes, 2) else {
        return Ok(());
    };
    let bits = Bitset::parse(bytes)?;
    if bits.bits.iter().any(|bit| bit.index >= 32) {
        return Err(unsupported());
    }
    let mask = bits
        .bits
        .iter()
        .filter(|bit| bit.value)
        .fold(0_u32, |mask, bit| mask | (1 << bit.index));
    writeln!(output, "Current message level: 0x{mask:08x} ({mask})").unwrap();
    for bit in bits.bits.iter().filter(|bit| bit.value) {
        write!(output, " {}", bit.name).unwrap();
    }
    output.push('\n');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_supplementary_context_cannot_delay_healthy_basic_result() {
        use super::super::{
            parse_ethtool_settings, run_ethtool_settings_with_base, EthtoolSettingsOutcome,
            NicCollector,
        };

        let collector = NicCollector::default();
        let supplementary = collector.settings.lock().unwrap();
        let parsed = parse_ethtool_settings(b"Settings for eth0:\nSpeed: 1000Mb/s\n");
        let expected = EthtoolSettingsOutcome::Collected(parsed.settings.clone());
        let (done, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let outcome = run_ethtool_settings_with_base(
                    OsStr::new("/definitely/not/a/real/ethtool"),
                    "eth0",
                    ETHTOOL_TIMEOUT,
                    1024,
                    1024,
                    || {
                        collector
                            .basic_contexts
                            .with_context(Instant::now() + ATTEMPT_TIMEOUT, |_, _| Ok(parsed))
                            .ok()
                    },
                    |_| Some(Vec::new()),
                );
                done.send(outcome).unwrap();
            });
            let result = received.recv_timeout(Duration::from_secs(1));
            // Release the blocker even if the regression recurs, so a failed
            // assertion cannot leave the scoped thread waiting indefinitely.
            drop(supplementary);
            assert_eq!(result.unwrap(), expected);
        });
    }

    #[test]
    fn pool_allows_four_concurrent_transactions_and_returns_slots_after_errors() {
        let pool = ContextPool::default();
        let (entered, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let mut release = Vec::new();
            let mut workers = Vec::new();
            for _ in 0..super::super::MAX_ETHTOOL_CONCURRENCY {
                let (resume, blocked) = std::sync::mpsc::channel();
                release.push(resume);
                let pool = &pool;
                let entered = &entered;
                workers.push(scope.spawn(move || {
                    pool.with_context(Instant::now() + Duration::from_secs(5), |_, _| {
                        entered.send(()).unwrap();
                        blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                        Err::<(), _>(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "test query",
                        ))
                    })
                }));
            }
            let ready: Vec<_> = (0..super::super::MAX_ETHTOOL_CONCURRENCY)
                .map(|_| received.recv_timeout(Duration::from_secs(1)))
                .collect();
            let extra = pool.with_context(Instant::now() + ATTEMPT_TIMEOUT, |_, _| Ok(()));
            for resume in release {
                let _ = resume.send(());
            }
            let results: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
            assert!(
                ready.iter().all(Result::is_ok),
                "transactions were serialized"
            );
            assert_eq!(extra.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            for result in results {
                assert_eq!(
                    result.unwrap().unwrap_err().kind(),
                    io::ErrorKind::PermissionDenied
                );
            }
        });
        assert_eq!(
            pool.available.lock().unwrap().len(),
            super::super::MAX_ETHTOOL_CONCURRENCY
        );
        pool.with_context(Instant::now() + ATTEMPT_TIMEOUT, |_, _| Ok(()))
            .unwrap();
    }

    #[test]
    fn pool_keeps_one_deadline_and_rejects_late_native_success() {
        let pool = ContextPool::default();
        let expired: io::Result<()> = pool.with_context(Instant::now(), |_, _| {
            panic!("expired attempt must not initialize or query a context")
        });
        assert_eq!(expired.unwrap_err().kind(), io::ErrorKind::TimedOut);

        let deadline = Instant::now() + Duration::from_millis(20);
        let (_sender, blocked) = std::sync::mpsc::channel::<()>();
        let late = pool.with_context(deadline, |_, actual_deadline| {
            assert_eq!(actual_deadline, deadline);
            assert_eq!(
                blocked.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            );
            assert_eq!(
                netlink::Context::new_until(actual_deadline)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            Ok(())
        });
        assert_eq!(late.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            pool.available.lock().unwrap().len(),
            super::super::MAX_ETHTOOL_CONCURRENCY
        );
    }

    fn attributes(values: &[(u16, &[u8])]) -> Vec<u8> {
        let mut result = Vec::new();
        for (kind, value) in values {
            let length = 4 + value.len();
            result.extend_from_slice(&(length as u16).to_ne_bytes());
            result.extend_from_slice(&kind.to_ne_bytes());
            result.extend_from_slice(value);
            result.resize(result.len() + (4 - length % 4) % 4, 0);
        }
        result
    }

    fn reply(values: &[(u16, &[u8])]) -> Vec<u8> {
        let header = attributes(&[(1, &2_u32.to_ne_bytes()), (2, b"eth0\0")]);
        let mut result = attributes(&[(1, &header)]);
        result.extend(attributes(values));
        result
    }

    fn bitset(nomask: bool, values: &[(u32, &str, bool)]) -> Vec<u8> {
        let mut bits = Vec::new();
        for (index, name, value) in values {
            let mut name = name.as_bytes().to_vec();
            name.push(0);
            let mut bit = attributes(&[(1, &index.to_ne_bytes()), (2, &name)]);
            if *value && !nomask {
                bit.extend(attributes(&[(3, &[])]));
            }
            bits.extend(attributes(&[(1, &bit)]));
        }
        let mut result = attributes(&[(2, &128_u32.to_ne_bytes()), (3, &bits)]);
        if nomask {
            result.extend(attributes(&[(1, &[])]));
        }
        result
    }

    fn render(command: u8, payload: &[u8]) -> io::Result<super::super::ParsedEthtoolSettings> {
        let mut output = "Settings for eth0:\n".to_owned();
        append_reply(&mut output, command, payload, "eth0", 2)?;
        Ok(super::super::parse_ethtool_settings(output.as_bytes()))
    }

    #[test]
    fn common_copper_modes_preserve_order_continuations_and_unknown_scalars() {
        let ours = bitset(
            false,
            &[
                (0, "10baseT/Half", true),
                (1, "10baseT/Full", true),
                (2, "100baseT/Half", true),
                (3, "100baseT/Full", true),
                (4, "1000baseT/Half", true),
                (5, "1000baseT/Full", true),
                (6, "Autoneg", true),
                (7, "TP", false),
            ],
        );
        let actual = render(
            4,
            &reply(&[
                (3, &ours),
                (5, &u32::MAX.to_ne_bytes()),
                (6, &[255]),
                (2, &[1]),
            ]),
        )
        .unwrap();
        let expected = super::super::parse_ethtool_settings(
            b"Settings for eth0:\n\
            Supported ports: [ TP ]\n\
            Supported link modes: 10baseT/Half 10baseT/Full\n\
                                  100baseT/Half 100baseT/Full\n\
                                  1000baseT/Half 1000baseT/Full\n\
            Supported pause frame use: No\n\
            Supports auto-negotiation: Yes\n\
            Supported FEC modes: Not reported\n\
            Advertised link modes: 10baseT/Half 10baseT/Full\n\
                                   100baseT/Half 100baseT/Full\n\
                                   1000baseT/Half 1000baseT/Full\n\
            Advertised pause frame use: No\n\
            Advertised auto-negotiation: Yes\n\
            Advertised FEC modes: Not reported\n\
            Speed: Unknown!\nDuplex: Unknown! (255)\nAuto-negotiation: on\n",
        );
        assert_eq!(actual, expected);
        for unknown in [0, 65535, u32::MAX] {
            assert_eq!(
                render(4, &reply(&[(5, &unknown.to_ne_bytes())]))
                    .unwrap()
                    .settings
                    .fields[0]
                    .value,
                "Unknown!"
            );
        }
    }

    #[test]
    fn empty_present_modes_differ_from_absent_modes_and_peer_modes_are_retained() {
        assert!(render(4, &reply(&[])).unwrap().settings.fields.is_empty());
        let empty = bitset(false, &[]);
        let actual = render(4, &reply(&[(3, &empty)])).unwrap();
        assert_eq!(actual.settings.fields.len(), 9);
        assert_eq!(actual.settings.fields[0].value, "[ ]");
        let peer = bitset(
            true,
            &[
                (5, "1000baseT/Full", true),
                (6, "Autoneg", true),
                (13, "Pause", true),
            ],
        );
        let actual = render(4, &reply(&[(4, &peer)])).unwrap();
        assert_eq!(actual, super::super::parse_ethtool_settings(b"Settings for eth0:\nLink partner advertised link modes: 1000baseT/Full\nLink partner advertised pause frame use: Symmetric\nLink partner advertised auto-negotiation: Yes\nLink partner advertised FEC modes: Not reported\n"));
    }

    #[test]
    fn port_mdix_wol_and_message_level_match_frontend_text() {
        let actual = render(
            2,
            &reply(&[(2, &[0]), (3, &[1]), (4, &[2]), (5, &[0]), (6, &[0])]),
        )
        .unwrap();
        assert_eq!(actual, super::super::parse_ethtool_settings(b"Settings for eth0:\nPort: Twisted Pair\nPHYAD: 1\nTransceiver: internal\nMDI-X: on\n"));
        assert_eq!(
            render(2, &reply(&[(4, &[2]), (5, &[0])]))
                .unwrap()
                .settings
                .fields
                .len(),
            0
        );
        let wake = bitset(false, &[(5, "magic", false)]);
        assert_eq!(
            render(9, &reply(&[(2, &wake)])).unwrap(),
            super::super::parse_ethtool_settings(
                b"Settings for eth0:\nSupports Wake-on: g\nWake-on: d\n"
            )
        );
        assert!(render(9, &reply(&[])).is_err());
        let secure = bitset(false, &[(6, "magicsecure", false)]);
        assert!(render(9, &reply(&[(2, &secure)])).is_err());
        let secure_reply = render(9, &reply(&[(2, &secure), (3, &[0, 1, 2, 3, 4, 255])])).unwrap();
        assert_eq!(secure_reply.settings.fields[2].value, "00:01:02:03:04:ff");
        let debug = bitset(
            true,
            &[(0, "drv", true), (1, "probe", true), (2, "link", true)],
        );
        assert_eq!(
            render(7, &reply(&[(2, &debug)])).unwrap(),
            super::super::parse_ethtool_settings(
                b"Settings for eth0:\nCurrent message level: 0x00000007 (7)\n  drv probe link\n"
            )
        );
        assert!(render(7, &reply(&[])).unwrap().settings.fields.is_empty());
    }

    #[test]
    fn richer_unknown_duplicate_compact_and_truncated_shapes_fall_back() {
        let rich = bitset(false, &[(52, "50000baseKR/Full", true)]);
        assert!(render(4, &reply(&[(3, &rich)])).is_err());
        for command in [39, 41] {
            assert!(render(command, &reply(&[])).is_err());
        }
        assert!(render(6, &reply(&[(2, &[1]), (5, &[2])])).is_err());
        assert!(render(4, &reply(&[(11, &[0])])).is_err());
        assert!(render(
            4,
            &reply(&[(5, &1_u32.to_ne_bytes()), (5, &2_u32.to_ne_bytes())])
        )
        .is_err());
        assert!(render(4, &reply(&[(5, &[1, 2])])).is_err());
        let compact = attributes(&[
            (1, &[]),
            (2, &32_u32.to_ne_bytes()),
            (4, &0_u32.to_ne_bytes()),
        ]);
        assert!(render(7, &reply(&[(2, &compact)])).is_err());
        let duplicate = bitset(true, &[(1, "a", true), (1, "b", true)]);
        assert!(render(7, &reply(&[(2, &duplicate)])).is_err());
        let mut truncated = reply(&[(2, &[1])]);
        truncated.pop();
        assert!(render(6, &truncated).is_err());
        let header = attributes(&[(1, &2_u32.to_ne_bytes()), (2, b"eth0\0"), (4, &[])]);
        assert!(render(6, &attributes(&[(1, &header), (2, &[1])])).is_err());
        let mut output = String::new();
        assert!(append_reply(&mut output, 6, &reply(&[(2, &[1])]), "renamed0", 2).is_err());
        assert!(append_reply(&mut output, 6, &reply(&[(2, &[1])]), "eth0", 3).is_err());
    }

    #[test]
    fn seven_operations_omit_only_explicit_unsupported_and_discard_partial_attempts() {
        let operations = OPERATIONS.map(|(command, _)| command).into_iter().collect();
        let mut calls = Vec::new();
        let actual = collect_with("eth0", &operations, |command, reply, output| {
            calls.push((command, reply));
            if command == 6 {
                output.push_str("Link detected: yes\n");
                Ok(())
            } else {
                output.push_str("Must not survive: unsupported\n");
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
        })
        .unwrap();
        assert_eq!(calls, OPERATIONS);
        assert_eq!(
            actual,
            super::super::parse_ethtool_settings(b"Settings for eth0:\nLink detected: yes\n")
        );
        for errno in [libc::EPERM, libc::EINVAL, libc::ENODEV, libc::ETIMEDOUT] {
            let result = collect_with("eth0", &operations, |command, _, output| {
                if command == 4 {
                    output.push_str("Speed: 1000Mb/s\n");
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(errno))
                }
            });
            assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
        }
        assert!(collect_with("eth0", &operations, |_, _, _| Err(
            io::Error::from_raw_os_error(libc::EOPNOTSUPP)
        ))
        .is_err());
        let operations = [4, 2, 9, 7, 6].into_iter().collect();
        let mut calls = Vec::new();
        collect_with("eth0", &operations, |command, _, output| {
            calls.push(command);
            output.push_str("Field: value\n");
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [4, 2, 9, 7, 6]);
        assert!(collect_with(
            "eth0",
            &[4, 2, 9, 6].into_iter().collect(),
            |_, _, _| panic!("must not query missing base op")
        )
        .is_err());
    }

    #[test]
    fn frontend_requires_actual_ordered_basic_traffic_and_rejects_new_operations() {
        let traffic = |commands: &[&str]| {
            commands.iter().map(|name| format!("sending genetlink packet (36 bytes):\n    msg length 36 ethool {name}\nreceived genetlink packet (52 bytes):\n    msg length 52 ethool {name}_REPLY\n")).collect::<String>()
        };
        assert!(debug_profile(traffic(&COMMAND_NAMES).as_bytes()));
        assert!(debug_profile(
            traffic(&[
                COMMAND_NAMES[0],
                COMMAND_NAMES[1],
                COMMAND_NAMES[2],
                COMMAND_NAMES[4],
                COMMAND_NAMES[5]
            ])
            .as_bytes()
        ));
        assert!(!debug_profile(b"ethtool version 6.14.2\n"));
        assert!(!debug_profile(
            b"sending genetlink packet (32 bytes):\n    msg length 32 genl-ctrl\n"
        ));
        let mut extended = COMMAND_NAMES.to_vec();
        extended.push("ETHTOOL_MSG_NEW_GET");
        assert!(!debug_profile(traffic(&extended).as_bytes()));
        for name in ["*", "-s", "--version", "", "a/b"] {
            assert!(!valid_cli_interface(name));
        }
        assert!(valid_cli_interface("eth0"));
        extended.swap(0, 1);
        assert!(!debug_profile(traffic(&extended).as_bytes()));
    }

    #[test]
    fn executable_identity_changes_on_replacement_permission_change_and_removal() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("ethtool");
        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let original = Executable::at(path.clone()).unwrap();
        fs::write(root.path().join("replacement"), b"new").unwrap();
        fs::set_permissions(
            root.path().join("replacement"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::rename(root.path().join("replacement"), &path).unwrap();
        assert_ne!(Executable::at(path.clone()), Some(original));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Executable::at(path.clone()).is_none());
        fs::remove_file(&path).unwrap();
        assert!(Executable::at(path).is_none());
    }
}
