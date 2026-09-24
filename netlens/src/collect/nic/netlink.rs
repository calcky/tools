//! Read-only ethtool generic-netlink queries. Missing attributes stay missing.
use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Instant;

use super::EthtoolSetting;

const NLA_NESTED: u16 = 0x8000;
const GENL_ID_CTRL: u16 = 16;

#[derive(Debug)]
pub(super) struct Context {
    socket: Option<Socket>,
    family: u16,
    legacy: super::ioctl::Context,
    operations: Option<BTreeSet<u8>>,
}

impl Context {
    pub(super) fn new() -> io::Result<Self> {
        Self::new_until(Instant::now() + super::ETHTOOL_TIMEOUT)
    }

    pub(super) fn new_until(deadline: Instant) -> io::Result<Self> {
        super::basic::check_deadline(deadline)?;
        let mut socket = Socket::new(libc::NETLINK_GENERIC)?;
        let mut attributes = Vec::new();
        attribute(&mut attributes, 2, b"ethtool\0");
        let response = socket.generic_until(GENL_ID_CTRL, 3, 1, &attributes, deadline)?;
        let attributes = attrs(response)?;
        let operations = unique(&attributes, 6)
            .ok()
            .flatten()
            .and_then(|bytes| basic_operations(bytes).ok());
        let family = unique(&attributes, 1)?.ok_or_else(invalid)?;
        let family = u16::from_ne_bytes(family.try_into().map_err(|_| invalid())?);
        if family < 16 {
            return Err(invalid());
        }
        Ok(Self {
            socket: Some(socket),
            family,
            legacy: super::ioctl::Context::default(),
            operations,
        })
    }

    pub(super) fn basic_settings_until(
        &mut self,
        interface: &str,
        ifindex: u32,
        deadline: Instant,
    ) -> io::Result<super::ParsedEthtoolSettings> {
        super::basic::check_deadline(deadline)?;
        if self.socket.is_none() {
            *self = Self::new_until(deadline)?;
        }
        let result = self.query_basic_until(interface, ifindex, deadline);
        if result.is_err() {
            self.socket = None;
        }
        result
    }

    fn query_basic_until(
        &mut self,
        interface: &str,
        ifindex: u32,
        deadline: Instant,
    ) -> io::Result<super::ParsedEthtoolSettings> {
        let operations = self.operations.as_ref().ok_or_else(invalid)?;
        if !super::valid_interface_name(interface) || ifindex == 0 {
            return Err(invalid());
        }
        let mut header = Vec::new();
        attribute(&mut header, 1, &ifindex.to_ne_bytes());
        let mut name = interface.as_bytes().to_vec();
        name.push(0);
        attribute(&mut header, 2, &name);
        let mut request = Vec::new();
        attribute(&mut request, 1 | NLA_NESTED, &header);
        super::basic::collect_with(interface, operations, |command, reply, output| {
            let bytes = self
                .socket
                .as_mut()
                .expect("initialized above")
                .generic_until(self.family, command, reply, &request, deadline)?;
            super::basic::append_reply(output, command, bytes, interface, ifindex)
        })
    }

    pub(super) fn settings(
        &mut self,
        interface: &str,
        operation: &str,
    ) -> io::Result<Vec<EthtoolSetting>> {
        if self.socket.is_none() {
            *self = Self::new()?;
        }
        match self.netlink_settings(interface, operation) {
            Err(error) if error.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                self.legacy.settings(interface, operation)
            }
            Err(error) => {
                // A delayed reply may still arrive after timeout/protocol
                // failure. A new socket prevents subsequent queries consuming
                // that stale sequence forever, one response behind.
                self.socket = None;
                Err(error)
            }
            result => result,
        }
    }

    fn netlink_settings(
        &mut self,
        interface: &str,
        operation: &str,
    ) -> io::Result<Vec<EthtoolSetting>> {
        if !super::valid_interface_name(interface) {
            return Err(invalid());
        }
        let (command, reply) = match operation {
            "-g" => (15, 16),
            "-a" => (21, 22),
            "-k" => (11, 11),
            "-c" => (19, 20),
            _ => return Err(invalid()),
        };
        let mut name = interface.as_bytes().to_vec();
        name.push(0);
        let mut header = Vec::new();
        attribute(&mut header, 2, &name);
        let mut request = Vec::new();
        attribute(&mut request, 1 | NLA_NESTED, &header);
        let response = self
            .socket
            .as_mut()
            .expect("initialized before query")
            .generic(self.family, command, reply, &request)?;
        let attributes = attrs(response)?;
        let response_header = unique(&attributes, 1)?.ok_or_else(invalid)?;
        let header = attrs(response_header)?;
        if string(unique(&header, 2)?.ok_or_else(invalid)?)? != interface {
            return Err(invalid());
        }
        decode(operation, &attributes)
    }
}

#[derive(Debug)]
pub(super) struct Socket {
    fd: OwnedFd,
    port: u32,
    sequence: u32,
    request: Vec<u8>,
    response: Vec<u8>,
}

pub(super) struct Link {
    pub ifindex: u32,
    pub name: String,
    pub operstate: Option<u8>,
    pub tx_queue_len: Option<u32>,
    pub mtu: Option<u32>,
}

impl Socket {
    pub(super) fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut request = vec![0; 16];
        // Linux 4.14 UAPI: IFLA_EXT_MASK / RTEXT_FILTER_SKIP_STATS skips
        // expensive AF-specific statistics that inventory does not consume.
        attribute(&mut request, 29, &(1_u32 << 3).to_ne_bytes());
        self.send(libc::RTM_GETLINK, 1 | 0x300, &request)?;
        let deadline = Instant::now() + super::ETHTOOL_TIMEOUT;
        let mut links = Vec::new();
        let mut indices = BTreeSet::new();
        let mut names = BTreeSet::new();
        loop {
            let received = self.receive(deadline)?;
            let mut bytes = &self.response[..received];
            while !bytes.is_empty() {
                let (kind, _, payload, length) = message(bytes, self.sequence, self.port)?;
                if align(length) > bytes.len() {
                    return Err(invalid());
                }
                bytes = &bytes[align(length)..];
                match kind {
                    3 => {
                        if !bytes.is_empty() || (!payload.is_empty() && number(payload)? != 0) {
                            return Err(invalid());
                        }
                        return Ok(links);
                    }
                    2 => return Err(netlink_error(payload)?),
                    16 => {
                        if payload.len() < 16 {
                            return Err(invalid());
                        }
                        let ifindex = number(&payload[4..8])?;
                        let attributes = attrs(&payload[16..])?;
                        let name = string(unique(&attributes, 3)?.ok_or_else(invalid)?)?;
                        if ifindex == 0
                            || ifindex > i32::MAX as u32
                            || !super::valid_interface_name(name)
                            || !indices.insert(ifindex)
                            || !names.insert(name.to_owned())
                        {
                            return Err(invalid());
                        }
                        let operstate = unique(&attributes, 16)?
                            .map(|bytes| match bytes {
                                [value] => Ok(*value),
                                _ => Err(invalid()),
                            })
                            .transpose()?;
                        let tx_queue_len = unique(&attributes, 13)?.map(number).transpose()?;
                        let mtu = unique(&attributes, 4)?.map(number).transpose()?;
                        links.push(Link {
                            ifindex,
                            name: name.to_owned(),
                            operstate,
                            tx_queue_len,
                            mtu,
                        });
                    }
                    _ => return Err(invalid()),
                }
            }
        }
    }

    pub(super) fn new(protocol: i32) -> io::Result<Self> {
        // SAFETY: socket returns a new descriptor and takes no pointer arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the new descriptor has exactly one owner.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: zero is valid for sockaddr_nl and padding must be zero.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        // SAFETY: address and length point to correctly sized live objects.
        if unsafe { libc::bind(fd.as_raw_fd(), std::ptr::from_ref(&address).cast(), length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: address and length are writable and correctly sized.
        if unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                std::ptr::from_mut(&mut address).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            port: address.nl_pid,
            sequence: 0,
            request: Vec::with_capacity(128),
            response: vec![0; 1024 * 1024],
        })
    }

    fn generic(
        &mut self,
        family: u16,
        command: u8,
        reply: u8,
        attributes: &[u8],
    ) -> io::Result<&[u8]> {
        self.generic_until(
            family,
            command,
            reply,
            attributes,
            Instant::now() + super::ETHTOOL_TIMEOUT,
        )
    }

    fn generic_until(
        &mut self,
        family: u16,
        command: u8,
        reply: u8,
        attributes: &[u8],
        deadline: Instant,
    ) -> io::Result<&[u8]> {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native settings deadline expired",
            ));
        }
        let mut payload = vec![command, 1, 0, 0];
        payload.extend_from_slice(attributes);
        self.send(family, 1, &payload)?;
        let received = self.receive(deadline)?;
        let response = &self.response[..received];
        let (kind, flags, payload, length) = message(response, self.sequence, self.port)?;
        if align(length) != received || flags & 2 != 0 {
            return Err(invalid());
        }
        if kind == 2 {
            return Err(netlink_error(payload)?);
        }
        if kind != family || payload.len() < 4 || payload[0] != reply {
            return Err(invalid());
        }
        Ok(&payload[4..])
    }

    pub(super) fn send(&mut self, kind: u16, flags: u16, payload: &[u8]) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        self.request.clear();
        self.request
            .extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        self.request.extend_from_slice(&kind.to_ne_bytes());
        self.request.extend_from_slice(&flags.to_ne_bytes());
        self.request.extend_from_slice(&self.sequence.to_ne_bytes());
        self.request.extend_from_slice(&self.port.to_ne_bytes());
        self.request.extend_from_slice(payload);
        // SAFETY: zero is a valid initialized sockaddr_nl.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: request and kernel point to initialized storage of the given sizes.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                self.request.as_ptr().cast(),
                self.request.len(),
                0,
                std::ptr::from_ref(&kernel).cast(),
                std::mem::size_of_val(&kernel) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != self.request.len() {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn receive(&mut self, deadline: Instant) -> io::Result<usize> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "netlink query timed out",
                ));
            }
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll points to one initialized pollfd.
            let ready = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    remaining.as_millis().max(1).min(i32::MAX as u128) as i32,
                )
            };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 {
                continue;
            }
            // SAFETY: zero initializes all sockaddr_nl and msghdr fields.
            let mut peer: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut vector = libc::iovec {
                iov_base: self.response.as_mut_ptr().cast(),
                iov_len: self.response.len(),
            };
            let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
            header.msg_name = std::ptr::from_mut(&mut peer).cast();
            header.msg_namelen = std::mem::size_of_val(&peer) as libc::socklen_t;
            header.msg_iov = &mut vector;
            header.msg_iovlen = 1;
            // SAFETY: every msghdr buffer remains writable for the call.
            let received = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut header, 0) };
            if received < 0 {
                let error = io::Error::last_os_error();
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(error);
            }
            if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
                || peer.nl_pid != 0
                || peer.nl_family != libc::AF_NETLINK as u16
            {
                return Err(invalid());
            }
            return Ok(received as usize);
        }
    }
}

fn decode(operation: &str, attributes: &[(u16, &[u8])]) -> io::Result<Vec<EthtoolSetting>> {
    let fields: &[(&str, u16, bool)] = match operation {
        "-g" => &[
            ("Ring RX", 6, false),
            ("Ring TX", 9, false),
            ("Ring RX Max", 2, false),
            ("Ring TX Max", 5, false),
        ],
        "-a" => &[("Flow Control RX", 3, true), ("Flow Control TX", 4, true)],
        "-c" => &[
            ("Adaptive RX", 11, true),
            ("Adaptive TX", 12, true),
            ("RX Usecs", 2, false),
            ("RX Frames", 3, false),
            ("TX Usecs", 6, false),
            ("TX Frames", 7, false),
        ],
        "-k" => return features(attributes),
        _ => return Err(invalid()),
    };
    let mut settings = Vec::new();
    for &(name, kind, switch) in fields {
        let Some(value) = unique(attributes, kind)? else {
            continue;
        };
        let value = if switch {
            match value {
                [0] => "off".to_owned(),
                [1] => "on".to_owned(),
                _ => return Err(invalid()),
            }
        } else {
            number(value)?.to_string()
        };
        settings.push(EthtoolSetting {
            name: name.to_owned(),
            value,
        });
    }
    Ok(settings)
}

fn features(attributes: &[(u16, &[u8])]) -> io::Result<Vec<EthtoolSetting>> {
    let active = feature_bits(unique(attributes, 4)?.ok_or_else(invalid)?)?;
    let hardware = unique(attributes, 2)?.map(feature_bits).transpose()?;
    let nochange = unique(attributes, 5)?.map(feature_bits).transpose()?;
    let groups = ["TSO", "LRO", "GRO", "GSO"];
    Ok(groups
        .into_iter()
        .enumerate()
        .map(|(group, name)| {
            let matches = |feature: &str| feature_group(feature) == Some(group);
            // TSO is an aggregate: it is fixed only if none of its bits can change.
            let enabled = active.iter().any(|name| matches(name));
            let fixed =
                hardware
                    .as_ref()
                    .zip(nochange.as_ref())
                    .is_some_and(|(hardware, nochange)| {
                        !hardware
                            .iter()
                            .any(|name| matches(name) && !nochange.contains(name))
                    });
            EthtoolSetting {
                name: name.to_owned(),
                value: format!(
                    "{}{}",
                    if enabled { "on" } else { "off" },
                    if fixed { " [fixed]" } else { "" }
                ),
            }
        })
        .collect())
}

fn feature_group(name: &str) -> Option<usize> {
    match name {
        _ if name.starts_with("tx-tcp") => Some(0),
        "rx-lro" => Some(1),
        "rx-gro" => Some(2),
        "tx-generic-segmentation" => Some(3),
        _ => None,
    }
}

fn feature_bits(bytes: &[u8]) -> io::Result<BTreeSet<&str>> {
    let active = attrs(bytes)?;
    // A verbose NOMASK bitset enumerates all set bits. Only in this encoding
    // does absence of a bit mean off; absence of ACTIVE itself remains unknown.
    if unique(&active, 1)? != Some(&[][..]) {
        return Err(invalid());
    }
    let size = number(unique(&active, 2)?.ok_or_else(invalid)?)?;
    if size == 0 || size > 4096 {
        return Err(invalid());
    }
    let bits = attrs(unique(&active, 3)?.ok_or_else(invalid)?)?;
    let mut names = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (kind, bit) in bits {
        if kind != 1 {
            return Err(invalid());
        }
        let bit = attrs(bit)?;
        let index = number(unique(&bit, 1)?.ok_or_else(invalid)?)?;
        if index >= size || !seen.insert(index) {
            return Err(invalid());
        }
        let name = string(unique(&bit, 2)?.ok_or_else(invalid)?)?;
        if !names.insert(name) {
            return Err(invalid());
        }
    }
    Ok(names)
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid NIC netlink response")
}
fn align(value: usize) -> usize {
    (value + 3) & !3
}
fn number(value: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(value.try_into().map_err(|_| invalid())?))
}
fn string(value: &[u8]) -> io::Result<&str> {
    let bytes = value.strip_suffix(&[0]).ok_or_else(invalid)?;
    if bytes.contains(&0) {
        return Err(invalid());
    }
    std::str::from_utf8(bytes).map_err(|_| invalid())
}
fn attribute(output: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    output.extend_from_slice(&(length as u16).to_ne_bytes());
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(value);
    output.resize(output.len() + align(length) - length, 0);
}
pub(super) fn attrs(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid());
        }
        let length = u16::from_ne_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(bytes[2..4].try_into().unwrap());
        if length < 4 || align(length) > bytes.len() || kind & 0x4000 != 0 {
            return Err(invalid());
        }
        result.push((kind & 0x3fff, &bytes[4..length]));
        bytes = &bytes[align(length)..];
    }
    Ok(result)
}

fn basic_operations(bytes: &[u8]) -> io::Result<BTreeSet<u8>> {
    let mut operations = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for (_, operation) in attrs(bytes)? {
        let fields = attrs(operation)?;
        let command = number(unique(&fields, 1)?.ok_or_else(invalid)?)?;
        let flags = number(unique(&fields, 2)?.ok_or_else(invalid)?)?;
        if !seen.insert(command) {
            return Err(invalid());
        }
        if flags & 2 != 0 {
            if let Ok(command) = u8::try_from(command) {
                operations.insert(command);
            }
        }
    }
    Ok(operations)
}
fn unique<'a>(attributes: &[(u16, &'a [u8])], kind: u16) -> io::Result<Option<&'a [u8]>> {
    let mut found = attributes.iter().filter(|(id, _)| *id == kind);
    let value = found.next().map(|(_, value)| *value);
    if found.next().is_some() {
        return Err(invalid());
    }
    Ok(value)
}
fn message(bytes: &[u8], sequence: u32, port: u32) -> io::Result<(u16, u16, &[u8], usize)> {
    if bytes.len() < 16 {
        return Err(invalid());
    }
    let length = number(&bytes[..4])? as usize;
    if length < 16
        || length > bytes.len()
        || number(&bytes[8..12])? != sequence
        || number(&bytes[12..16])? != port
    {
        return Err(invalid());
    }
    let kind = u16::from_ne_bytes(bytes[4..6].try_into().unwrap());
    let flags = u16::from_ne_bytes(bytes[6..8].try_into().unwrap());
    if flags & 0x10 != 0 {
        return Err(invalid());
    }
    Ok((kind, flags, &bytes[16..length], length))
}
fn netlink_error(payload: &[u8]) -> io::Result<io::Error> {
    let code = i32::from_ne_bytes(payload.get(..4).ok_or_else(invalid)?.try_into().unwrap());
    if code >= 0 || code == i32::MIN {
        return Err(invalid());
    }
    Ok(io::Error::from_raw_os_error(-code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_capabilities_require_do_support_and_reject_duplicate_operations() {
        let mut operations = Vec::new();
        for (command, flags) in [(4_u32, 2_u32), (39, 4)] {
            let mut entry = Vec::new();
            attribute(&mut entry, 1, &command.to_ne_bytes());
            attribute(&mut entry, 2, &flags.to_ne_bytes());
            attribute(&mut operations, command as u16 | NLA_NESTED, &entry);
        }
        assert_eq!(
            basic_operations(&operations).unwrap(),
            [4].into_iter().collect()
        );
        let duplicate = operations.clone();
        operations.extend(duplicate);
        assert!(basic_operations(&operations).is_err());
        assert!(basic_operations(&[1, 0, 0, 0]).is_err());
    }

    #[test]
    fn expired_generic_deadline_does_not_send_or_restart_a_timeout() {
        let mut socket = Socket {
            fd: std::fs::File::open("/dev/null").unwrap().into(),
            port: 0,
            sequence: 7,
            request: Vec::new(),
            response: Vec::new(),
        };
        let error = socket
            .generic_until(16, 3, 1, &[], Instant::now())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(socket.sequence, 7);
    }

    #[test]
    fn expired_basic_deadline_cannot_initialize_or_reconnect_a_context() {
        let deadline = Instant::now();
        assert_eq!(
            Context::new_until(deadline).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let mut context = Context {
            socket: None,
            family: 16,
            legacy: super::super::ioctl::Context::default(),
            operations: None,
        };
        assert_eq!(
            context
                .basic_settings_until("eth0", 2, deadline)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(context.socket.is_none());
    }

    #[test]
    fn absent_coalescing_attributes_do_not_become_off_or_zero() {
        let usecs = 20_u32.to_ne_bytes();
        assert_eq!(
            decode("-c", &[(2, &usecs)]).unwrap(),
            vec![EthtoolSetting {
                name: "RX Usecs".to_owned(),
                value: "20".to_owned()
            }]
        );
        assert!(decode("-c", &[]).unwrap().is_empty());
        assert_eq!(decode("-c", &[(11, &[0])]).unwrap()[0].value, "off");
        assert!(decode("-c", &[(11, &[2])]).is_err());
        assert!(decode("-c", &[(2, &[0])]).is_err());
        assert!(decode("-c", &[(2, &usecs), (2, &usecs)]).is_err());
    }

    #[test]
    fn features_require_an_explicit_complete_active_bitset() {
        assert!(features(&[]).is_err());
        let mut bit = Vec::new();
        attribute(&mut bit, 1, &18_u32.to_ne_bytes());
        attribute(&mut bit, 2, b"tx-tcp-ecn-segmentation\0");
        let mut bits = Vec::new();
        attribute(&mut bits, 1 | NLA_NESTED, &bit);
        let mut active = Vec::new();
        attribute(&mut active, 1, &[]);
        attribute(&mut active, 2, &64_u32.to_ne_bytes());
        attribute(&mut active, 3 | NLA_NESTED, &bits);
        let fields = features(&[(4, &active)]).unwrap();
        assert_eq!(
            fields
                .iter()
                .map(|field| field.value.as_str())
                .collect::<Vec<_>>(),
            ["on", "off", "off", "off"]
        );
        active.drain(..4);
        assert!(features(&[(4, &active)]).is_err());
    }

    #[test]
    fn malformed_attributes_are_rejected() {
        for bytes in [&[0, 0, 0, 0][..], &[5, 0, 1, 0], &[4, 0, 1], &[4, 0, 1, 64]] {
            assert!(attrs(bytes).is_err());
        }
    }

    #[test]
    fn feature_fixed_flags_require_complete_masks_and_handle_tso_groups() {
        fn bitset(names: &[&str]) -> Vec<u8> {
            let mut bits = Vec::new();
            for (index, name) in names.iter().enumerate() {
                let mut bit = Vec::new();
                attribute(&mut bit, 1, &(index as u32).to_ne_bytes());
                attribute(&mut bit, 2, format!("{name}\0").as_bytes());
                attribute(&mut bits, 1 | NLA_NESTED, &bit);
            }
            let mut output = Vec::new();
            attribute(&mut output, 1, &[]);
            attribute(&mut output, 2, &64_u32.to_ne_bytes());
            attribute(&mut output, 3 | NLA_NESTED, &bits);
            output
        }
        let hardware = bitset(&["tx-tcp-segmentation", "tx-tcp6-segmentation", "rx-gro"]);
        let active = bitset(&["tx-tcp-segmentation", "rx-gro"]);
        let nochange = bitset(&["tx-tcp-segmentation", "rx-gro"]);
        let fields = features(&[(2, &hardware), (4, &active), (5, &nochange)]).unwrap();
        assert_eq!(
            fields
                .iter()
                .map(|field| field.value.as_str())
                .collect::<Vec<_>>(),
            ["on", "off [fixed]", "on [fixed]", "off [fixed]"]
        );
        let unknown = features(&[(4, &active)]).unwrap();
        assert!(unknown.iter().all(|field| !field.value.contains("fixed")));
    }
}
