use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketFamily {
    Ipv4,
    Ipv6,
    Unix,
    Packet,
    Netlink,
    Vsock,
    Tipc,
    Xdp,
}

impl SocketFamily {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "4",
            Self::Ipv6 => "6",
            _ => "",
        }
    }
    pub(crate) const fn number(self) -> u8 {
        match self {
            Self::Ipv4 => 2,
            Self::Ipv6 => 10,
            Self::Unix => 1,
            Self::Packet => 17,
            Self::Netlink => 16,
            Self::Vsock => 40,
            Self::Tipc => 30,
            Self::Xdp => 44,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketProtocol {
    Tcp,
    Udp,
    Raw,
    Dccp,
    Sctp,
    Mptcp,
    Unix,
    Packet,
    Netlink,
    Vsock,
    Tipc,
    Xdp,
}

impl SocketProtocol {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Raw => "raw",
            Self::Dccp => "dccp",
            Self::Sctp => "sctp",
            Self::Mptcp => "mptcp",
            Self::Unix => "unix",
            Self::Packet => "packet",
            Self::Netlink => "netlink",
            Self::Vsock => "vsock",
            Self::Tipc => "tipc",
            Self::Xdp => "xdp",
        }
    }
    pub(crate) const fn number(self) -> u16 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Raw => 255,
            Self::Dccp => 33,
            Self::Sctp => 132,
            Self::Mptcp => 262,
            _ => 0,
        }
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SocketEndpoint {
    Inet { address: IpAddr, port: u16 },
    Raw { address: IpAddr, protocol: u8 },
    Unix { name: Option<String>, inode: u32 },
    Netlink { protocol: u8, port_id: u32 },
    Link { ifindex: u32, selector: String },
    Vsock { cid: u32, port: u32 },
    Tipc { node: u32, reference: u32 },
    Unspecified,
}

impl SocketEndpoint {
    pub(crate) fn canonical(&self) -> Self {
        match self {
            Self::Inet {
                address: IpAddr::V6(address),
                port,
            } => Self::Inet {
                address: address
                    .to_ipv4_mapped()
                    .map_or(IpAddr::V6(*address), IpAddr::V4),
                port: *port,
            },
            _ => self.clone(),
        }
    }
    pub(crate) const fn inet(&self) -> Option<(IpAddr, u16)> {
        match self {
            Self::Inet { address, port } => Some((*address, *port)),
            _ => None,
        }
    }
    pub(crate) const fn filter_endpoint(&self) -> Option<(IpAddr, Option<u16>)> {
        match self {
            Self::Inet { address, port } => Some((*address, Some(*port))),
            Self::Raw { address, .. } => Some((*address, None)),
            _ => None,
        }
    }
    #[cfg(test)]
    pub(crate) fn port(&self) -> Option<u16> {
        self.inet().map(|(_, port)| port)
    }
}

impl fmt::Display for SocketEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet {
                address: IpAddr::V4(ip),
                port,
            } => write!(f, "{ip}:{port}"),
            Self::Inet {
                address: IpAddr::V6(ip),
                port,
            } => write!(f, "[{ip}]:{port}"),
            Self::Unix { name, inode } => write!(f, "{} #{inode}", name.as_deref().unwrap_or("*")),
            Self::Raw { address, protocol } => write!(f, "{address} (ip#{protocol})"),
            Self::Netlink { protocol, port_id } => write!(f, "nl{protocol}:{port_id}"),
            Self::Link { ifindex, selector } => write!(f, "if{ifindex}:{selector}"),
            Self::Vsock { cid, port } => write!(f, "{cid}:{port}"),
            Self::Tipc { node, reference } => write!(f, "{node:x}:{reference}"),
            Self::Unspecified => f.write_str("*"),
        }
    }
}

impl fmt::Debug for SocketEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SocketEndpoint(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum QueueKind {
    #[default]
    Bytes,
    Memory,
    UnixStream,
    UnixDatagram,
    DatagramCount,
    Backlog,
    Unavailable,
}

#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct SocketDetails {
    pub(crate) association: bool,
    pub(crate) ip_protocol: Option<u8>,
    pub(crate) socket_type: u8,
    pub(crate) queue_kind: QueueKind,
    pub(crate) uid_unavailable: bool,
    pub(crate) fields: Vec<(String, String)>,
}

impl SocketDetails {
    pub(crate) fn field(&mut self, label: &str, value: impl ToString) {
        self.fields.push((label.to_owned(), value.to_string()));
    }
}
