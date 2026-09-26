use crate::model::{Entry, Key, Tuple};
use std::{
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Instant,
};

const CT_NEW: u16 = 0x100;
const CT_GET: u16 = 0x101;
const CT_DELETE: u16 = 0x102;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn bytes<const N: usize>(data: &[u8]) -> io::Result<[u8; N]> {
    data.try_into()
        .map_err(|_| invalid("invalid netlink field length"))
}

#[derive(Debug)]
pub enum Message {
    Entry {
        seq: u32,
        new: bool,
        delete: bool,
        entry: Box<Entry>,
    },
    Done {
        seq: u32,
        interrupted: bool,
    },
    Error {
        seq: u32,
        errno: i32,
    },
    Lost,
}

fn attrs(mut data: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return Err(invalid("truncated netlink attribute header"));
        }
        let len = u16::from_ne_bytes(bytes(&data[..2])?) as usize;
        let kind = u16::from_ne_bytes(bytes(&data[2..4])?) & 0x3fff;
        if len < 4 || align(len) > data.len() {
            return Err(invalid("truncated netlink attribute"));
        }
        result.push((kind, &data[4..len]));
        data = &data[align(len)..];
    }
    Ok(result)
}
fn find<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(k, _)| *k == kind).map(|(_, d)| *d)
}
fn u16attr(attrs: &[(u16, &[u8])], kind: u16) -> io::Result<Option<u16>> {
    find(attrs, kind)
        .map(|v| Ok(u16::from_be_bytes(bytes(v)?)))
        .transpose()
}
fn u32attr(attrs: &[(u16, &[u8])], kind: u16) -> io::Result<Option<u32>> {
    find(attrs, kind)
        .map(|v| Ok(u32::from_be_bytes(bytes(v)?)))
        .transpose()
}
fn u64attr(attrs: &[(u16, &[u8])], kind: u16) -> io::Result<Option<u64>> {
    find(attrs, kind)
        .map(|v| Ok(u64::from_be_bytes(bytes(v)?)))
        .transpose()
}
fn byteattr(attrs: &[(u16, &[u8])], kind: u16) -> io::Result<Option<u8>> {
    find(attrs, kind).map(|v| Ok(bytes::<1>(v)?[0])).transpose()
}
fn tuple(data: &[u8], family: u8) -> io::Result<(Tuple, Option<u16>)> {
    let a = attrs(data)?;
    let ip = attrs(find(&a, 1).ok_or_else(|| invalid("missing tuple IP"))?)?;
    let proto = attrs(find(&a, 2).ok_or_else(|| invalid("missing tuple protocol"))?)?;
    let (src, dst) = match family as i32 {
        libc::AF_INET => {
            let s = find(&ip, 1).ok_or_else(|| invalid("missing IPv4 source"))?;
            let d = find(&ip, 2).ok_or_else(|| invalid("missing IPv4 destination"))?;
            (
                IpAddr::V4(Ipv4Addr::from(bytes::<4>(s)?)),
                IpAddr::V4(Ipv4Addr::from(bytes::<4>(d)?)),
            )
        }
        libc::AF_INET6 => {
            let s = find(&ip, 3).ok_or_else(|| invalid("missing IPv6 source"))?;
            let d = find(&ip, 4).ok_or_else(|| invalid("missing IPv6 destination"))?;
            (
                IpAddr::V6(Ipv6Addr::from(bytes::<16>(s)?)),
                IpAddr::V6(Ipv6Addr::from(bytes::<16>(d)?)),
            )
        }
        _ => return Err(invalid("unsupported conntrack address family")),
    };
    let num = byteattr(&proto, 1)?.ok_or_else(|| invalid("missing protocol number"))?;
    let icmp = if num == 1 || num == 58 {
        let base = if num == 1 { 4 } else { 7 };
        Some((
            u16attr(&proto, base)?.ok_or_else(|| invalid("missing ICMP id"))?,
            byteattr(&proto, base + 1)?.ok_or_else(|| invalid("missing ICMP type"))?,
            byteattr(&proto, base + 2)?.ok_or_else(|| invalid("missing ICMP code"))?,
        ))
    } else {
        None
    };
    Ok((
        Tuple {
            src,
            dst,
            proto: num,
            sport: u16attr(&proto, 2)?,
            dport: u16attr(&proto, 3)?,
            icmp,
        },
        u16attr(&a, 3)?,
    ))
}
fn entry(data: &[u8], now: Instant) -> io::Result<Entry> {
    if data.len() < 4 {
        return Err(invalid("missing nfgenmsg"));
    }
    let family = data[0];
    let a = attrs(&data[4..])?;
    let (original, oz) = tuple(
        find(&a, 1).ok_or_else(|| invalid("missing original tuple"))?,
        family,
    )?;
    let reply = find(&a, 2).map(|d| tuple(d, family)).transpose()?;
    let zone = u16attr(&a, 18)?.unwrap_or(0);
    let reply_zone = reply.as_ref().and_then(|(_, z)| *z).unwrap_or(zone);
    let mut packets = [None; 2];
    let mut counters = [None; 2];
    for (index, kind) in [9, 10].iter().enumerate() {
        if let Some(d) = find(&a, *kind) {
            let c = attrs(d)?;
            packets[index] = u64attr(&c, 1)?.or(u32attr(&c, 3)?.map(u64::from));
            counters[index] = u64attr(&c, 2)?.or(u32attr(&c, 4)?.map(u64::from));
        }
    }
    let state = if let Some(p) = find(&a, 4) {
        let p = attrs(p)?;
        if let Some(tcp) = find(&p, 1) {
            byteattr(&attrs(tcp)?, 1)?
        } else {
            None
        }
    } else {
        None
    };
    let start_ns = find(&a, 20)
        .map(|d| u64attr(&attrs(d)?, 1))
        .transpose()?
        .flatten();
    Ok(Entry {
        key: Key {
            original,
            zone: oz.unwrap_or(zone),
            reply_zone,
        },
        reply: reply.map(|(t, _)| t),
        id: u32attr(&a, 12)?,
        status: u32attr(&a, 3)?,
        state,
        timeout: u32attr(&a, 7)?,
        mark: u32attr(&a, 8)?,
        packets,
        bytes: counters,
        traffic: None,
        start_ns,
        seen: now,
        state_since: now,
    })
}

pub fn decode(mut data: &[u8], now: Instant) -> io::Result<Vec<Message>> {
    let mut messages = Vec::new();
    while !data.is_empty() {
        if data.len() < 16 {
            return Err(invalid("truncated netlink header"));
        }
        let len = u32::from_ne_bytes(bytes(&data[..4])?) as usize;
        if len < 16 || align(len) > data.len() {
            return Err(invalid("truncated netlink message"));
        }
        let kind = u16::from_ne_bytes(bytes(&data[4..6])?);
        let flags = u16::from_ne_bytes(bytes(&data[6..8])?);
        let seq = u32::from_ne_bytes(bytes(&data[8..12])?);
        let payload = &data[16..len];
        match kind {
            2 => {
                let code = i32::from_ne_bytes(bytes(
                    payload
                        .get(..4)
                        .ok_or_else(|| invalid("short NLMSG_ERROR"))?,
                )?);
                if code != 0 {
                    messages.push(Message::Error {
                        seq,
                        errno: code.saturating_abs(),
                    });
                }
            }
            3 => {
                if payload.len() >= 4 {
                    let code = i32::from_ne_bytes(bytes(&payload[..4])?);
                    if code != 0 {
                        messages.push(Message::Error {
                            seq,
                            errno: code.saturating_abs(),
                        });
                    }
                }
                messages.push(Message::Done {
                    seq,
                    interrupted: flags & 0x10 != 0,
                });
            }
            4 => messages.push(Message::Lost),
            CT_NEW | CT_DELETE => {
                messages.push(Message::Entry {
                    seq,
                    new: flags & 0x400 != 0,
                    delete: kind == CT_DELETE,
                    entry: Box::new(entry(payload, now)?),
                });
                if flags & 0x10 != 0 {
                    messages.push(Message::Lost);
                }
            }
            _ => (),
        }
        data = &data[align(len)..];
    }
    Ok(messages)
}

pub struct Socket {
    fd: OwnedFd,
    buffer: Vec<u8>,
    sequence: u32,
}
impl Socket {
    #[cfg(test)]
    pub fn stub() -> Self {
        let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(raw >= 0);
        Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            buffer: Vec::new(),
            sequence: 0,
        }
    }
    pub fn open() -> io::Result<Self> {
        // OwnedFd closes on every error path. All pointers reference live initialized storage.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = 7; // NEW, UPDATE, DESTROY; subscribe before the initial dump.
        if unsafe {
            libc::bind(
                raw,
                &address as *const _ as *const libc::sockaddr,
                mem::size_of_val(&address) as _,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let size: libc::c_int = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const _,
                mem::size_of_val(&size) as _,
            )
        };
        Ok(Self {
            fd,
            buffer: vec![0; 1024 * 1024],
            sequence: 0,
        })
    }
    pub fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub fn dump(&mut self) -> io::Result<u32> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let mut request = Vec::new();
        request.extend_from_slice(&20u32.to_ne_bytes());
        request.extend_from_slice(&CT_GET.to_ne_bytes());
        request.extend_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | ROOT | MATCH
        request.extend_from_slice(&self.sequence.to_ne_bytes());
        request.extend_from_slice(&0u32.to_ne_bytes());
        request.extend_from_slice(&[libc::AF_UNSPEC as u8, 0, 0, 0]);
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                self.fd(),
                request.as_ptr() as _,
                request.len(),
                0,
                &address as *const _ as _,
                mem::size_of_val(&address) as _,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(self.sequence)
        }
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<Message>>> {
        let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
        let mut size = mem::size_of_val(&address) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.fd(),
                self.buffer.as_mut_ptr() as _,
                self.buffer.len(),
                libc::MSG_TRUNC,
                &mut address as *mut _ as _,
                &mut size,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return if err.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(err)
            };
        }
        if address.nl_pid != 0 {
            return Err(invalid("non-kernel conntrack message"));
        }
        if n as usize > self.buffer.len() {
            return Err(invalid("netlink datagram truncated"));
        }
        Ok(Some(decode(&self.buffer[..n as usize], Instant::now())?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = ((data.len() + 4) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(data);
        out.resize(align(out.len()), 0);
        out
    }
    fn message(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut out = ((data.len() + 16) as u32).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0x400u16.to_ne_bytes());
        out.extend_from_slice(&42u32.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(data);
        out.resize(align(out.len()), 0);
        out
    }
    fn fixture(family: u8, icmp: bool) -> Vec<u8> {
        let ip = if family == libc::AF_INET as u8 {
            [attr(1, &[192, 0, 2, 1]), attr(2, &[198, 51, 100, 2])].concat()
        } else {
            [
                attr(3, &Ipv6Addr::LOCALHOST.octets()),
                attr(4, &Ipv6Addr::UNSPECIFIED.octets()),
            ]
            .concat()
        };
        let p = if icmp {
            [
                attr(1, &[1]),
                attr(4, &7u16.to_be_bytes()),
                attr(5, &[8]),
                attr(6, &[0]),
            ]
            .concat()
        } else {
            [
                attr(1, &[6]),
                attr(2, &1234u16.to_be_bytes()),
                attr(3, &443u16.to_be_bytes()),
            ]
            .concat()
        };
        let t = [attr(1 | 0x8000, &ip), attr(2 | 0x8000, &p)].concat();
        let counters = [
            attr(1, &123u64.to_be_bytes()),
            attr(2, &456u64.to_be_bytes()),
        ]
        .concat();
        let a = [
            attr(1, &t),
            attr(2, &t),
            attr(3, &2u32.to_be_bytes()),
            attr(18, &9u16.to_be_bytes()),
            attr(9, &counters),
            attr(12, &55u32.to_be_bytes()),
            attr(4, &attr(1, &attr(1, &[3]))),
        ]
        .concat();
        message(CT_NEW, &[vec![family, 0, 0, 0], a].concat())
    }
    #[test]
    fn decodes_families_counters_nested_flags_zones_and_icmp() {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            let data = fixture(family, false);
            let messages = decode(&data, Instant::now()).unwrap();
            let Message::Entry {
                entry, seq, new, ..
            } = &messages[0]
            else {
                panic!()
            };
            assert_eq!(*seq, 42);
            assert!(*new);
            assert_eq!(entry.key.zone, 9);
            assert_eq!(entry.key.reply_zone, 9);
            assert_eq!(entry.key.original.dport, Some(443));
            assert_eq!(entry.packets, [Some(123), None]);
            assert_eq!(entry.bytes, [Some(456), None]);
            assert_eq!(entry.id, Some(55));
            assert_eq!(entry.state, Some(3));
        }
        let messages = decode(&fixture(libc::AF_INET as u8, true), Instant::now()).unwrap();
        let Message::Entry { entry, .. } = &messages[0] else {
            panic!()
        };
        assert_eq!(entry.key.original.icmp, Some((7, 8, 0)));
        assert_eq!(entry.key.original.sport, None);
    }
    #[test]
    fn malformed_lengths_and_all_truncations_are_rejected() {
        let data = fixture(libc::AF_INET as u8, false);
        for n in 1..data.len() {
            assert!(decode(&data[..n], Instant::now()).is_err(), "length {n}");
        }
        assert!(attrs(&[0, 0, 0, 0]).is_err());
        assert!(attrs(&[255, 255, 0, 0]).is_err());
        let mut invalid = data;
        invalid[20..22].copy_from_slice(&0u16.to_ne_bytes());
        assert!(decode(&invalid, Instant::now()).is_err());
    }
    #[test]
    fn multipart_done_errors_and_overrun_are_explicit() {
        let data = [
            message(2, &(-libc::EPERM).to_ne_bytes()),
            message(4, &[]),
            message(3, &0i32.to_ne_bytes()),
        ]
        .concat();
        let m = decode(&data, Instant::now()).unwrap();
        assert!(matches!(
            m[0],
            Message::Error {
                errno: libc::EPERM,
                ..
            }
        ));
        assert!(matches!(m[1], Message::Lost));
        assert!(matches!(
            m[2],
            Message::Done {
                seq: 42,
                interrupted: false
            }
        ));
    }
}
