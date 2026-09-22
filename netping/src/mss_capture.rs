use crate::net::Reactor;
use mio::{Interest, Token};
use pnet_packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io, mem,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};

pub const TOKEN: Token = Token(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Syn {
    pub seq: u32,
    pub ack: u32,
    pub mss: Option<u16>,
    pub reply: bool,
}

fn options(mut bytes: &[u8]) -> Option<Option<u16>> {
    let mut mss = None;
    while !bytes.is_empty() {
        match bytes[0] {
            0 => break,
            1 => bytes = &bytes[1..],
            kind => {
                let len = *bytes.get(1)? as usize;
                if len < 2 || len > bytes.len() {
                    return None;
                }
                if kind == 2 {
                    if len != 4 || mss.is_some() {
                        return None;
                    }
                    let value = u16::from_be_bytes([bytes[2], bytes[3]]);
                    if value == 0 {
                        return None;
                    }
                    mss = Some(value);
                }
                bytes = &bytes[len..];
            }
        }
    }
    Some(mss)
}

fn packet(bytes: &[u8]) -> Option<(SocketAddr, SocketAddr, Syn)> {
    let (src, dst, tcp) = match bytes.first()? >> 4 {
        4 => {
            let ip = Ipv4Packet::new(bytes)?;
            let header = ip.get_header_length() as usize * 4;
            let len = ip.get_total_length() as usize;
            if header < 20
                || ip.get_next_level_protocol().0 != 6
                || ip.get_fragment_offset() != 0
                || ip.get_flags() & 1 != 0
            {
                return None;
            }
            (
                IpAddr::V4(ip.get_source()),
                IpAddr::V4(ip.get_destination()),
                bytes.get(header..len)?,
            )
        }
        6 => {
            let ip = Ipv6Packet::new(bytes)?;
            let len = 40 + ip.get_payload_length() as usize;
            let bytes = bytes.get(..len)?;
            let (mut next, mut offset) = (ip.get_next_header().0, 40);
            // Bound extension traversal; fragments and encrypted headers are not evidence.
            for _ in 0..8 {
                if next == 6 {
                    break;
                }
                let ext = bytes.get(offset..)?;
                let n = *ext.get(1)? as usize;
                let length = match next {
                    0 | 43 | 60 => (n + 1) * 8,
                    51 => (n + 2) * 4,
                    _ => return None,
                };
                next = ext[0];
                offset = offset.checked_add(length)?;
            }
            if next != 6 {
                return None;
            }
            (
                IpAddr::V6(ip.get_source()),
                IpAddr::V6(ip.get_destination()),
                bytes.get(offset..)?,
            )
        }
        _ => return None,
    };
    let p = TcpPacket::new(tcp)?;
    let flags = p.get_flags();
    if flags & 2 == 0 || flags & (1 | 4) != 0 {
        return None;
    }
    let header = p.get_data_offset() as usize * 4;
    let mss = options(tcp.get(20..header)?)?;
    Some((
        SocketAddr::new(src, p.get_source()),
        SocketAddr::new(dst, p.get_destination()),
        Syn {
            seq: p.get_sequence(),
            ack: p.get_acknowledgement(),
            mss,
            reply: flags & 16 != 0,
        },
    ))
}

#[derive(Default)]
pub struct Handshake {
    pub local: Option<Syn>,
    pub peer: Option<Syn>,
}

impl Handshake {
    fn observe(&mut self, bytes: &[u8], local: SocketAddr, peer: SocketAddr) {
        let Some((src, dst, syn)) = packet(bytes) else {
            return;
        };
        // Scope IDs are interface-local metadata and are not carried in IP headers.
        let eq = |a: SocketAddr, b: SocketAddr| a.ip() == b.ip() && a.port() == b.port();
        if eq(src, local) && eq(dst, peer) && !syn.reply {
            if self.local.is_none() {
                self.local = Some(syn);
            }
        } else if eq(src, peer)
            && eq(dst, local)
            && syn.reply
            && self.local.is_none_or(|s| syn.ack == s.seq.wrapping_add(1))
        {
            self.peer = Some(syn);
        }
    }

    pub fn peer(&self) -> Option<Syn> {
        self.local
            .and_then(|local| self.peer.filter(|p| p.ack == local.seq.wrapping_add(1)))
    }
}

pub struct Capture {
    socket: Socket,
    pub handshake: Handshake,
}

// SOCK_DGRAM packet sockets expose the IP header at offset zero, including on loopback.
fn filter(port: u16) -> Vec<libc::sock_filter> {
    let f = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    vec![
        f(0x30, 0, 0, 0),
        f(0x54, 0, 0, 0xf0),
        f(0x15, 0, 10, 0x40),
        f(0x30, 0, 0, 9),
        f(0x15, 0, 7, 6),
        f(0xb1, 0, 0, 0),
        f(0x48, 0, 0, 0),
        f(0x15, 2, 0, port.into()),
        f(0x48, 0, 0, 2),
        f(0x15, 0, 2, port.into()),
        f(0x50, 0, 0, 13),
        f(0x45, 11, 0, 2),
        f(0x06, 0, 0, 0),
        f(0x15, 0, 8, 0x60),
        f(0x30, 0, 0, 6),
        f(0x15, 0, 8, 6),
        f(0x28, 0, 0, 40),
        f(0x15, 2, 0, port.into()),
        f(0x28, 0, 0, 42),
        f(0x15, 0, 2, port.into()),
        f(0x30, 0, 0, 53),
        f(0x45, 1, 0, 2),
        f(0x06, 0, 0, 0),
        f(0x06, 0, 0, 2048),
        // IPv6 extensions need variable offsets; let the bounded parser validate them.
        f(0x15, 5, 0, 0),
        f(0x15, 4, 0, 43),
        f(0x15, 3, 0, 60),
        f(0x15, 2, 0, 44),
        f(0x15, 1, 0, 51),
        f(0x06, 0, 0, 0),
        f(0x06, 0, 0, 2048),
    ]
}

impl Capture {
    pub fn new(port: u16, r: &Reactor) -> io::Result<Self> {
        let socket = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::DGRAM,
            Some(Protocol::from((libc::ETH_P_ALL as u16).to_be() as i32)),
        )?;
        socket.set_nonblocking(true)?;
        let mut code = filter(port);
        let program = libc::sock_fprog {
            len: code.len() as u16,
            filter: code.as_mut_ptr(),
        };
        // Linux copies this filter during setsockopt; the pointers stay live for the call.
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&program as *const libc::sock_fprog).cast(),
                mem::size_of_val(&program) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        r.register(&socket, TOKEN, Interest::READABLE)?;
        Ok(Self {
            socket,
            handshake: Handshake::default(),
        })
    }

    pub fn drain(&mut self, local: SocketAddr, peer: SocketAddr, r: &Reactor) -> io::Result<()> {
        let mut buf = [0; 2048];
        for _ in 0..256 {
            match crate::net::recv(&self.socket, &mut buf) {
                Ok(n) => self.handshake.observe(&buf[..n], local, peer),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        r.update(&self.socket, TOKEN, Interest::READABLE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(v6: bool, reply: bool, mss: u16) -> Vec<u8> {
        let offset = if v6 { 40 } else { 20 };
        let mut b = vec![0; offset + 24];
        if v6 {
            b[0] = 0x60;
            b[4..6].copy_from_slice(&24u16.to_be_bytes());
            b[6] = 6;
            b[23] = 1;
            b[39] = 1;
        } else {
            b[0] = 0x45;
            b[2..4].copy_from_slice(&44u16.to_be_bytes());
            b[9] = 6;
            b[12..16].copy_from_slice(&[127, 0, 0, 1]);
            b[16..20].copy_from_slice(&[127, 0, 0, 1]);
        }
        let tcp = &mut b[offset..];
        let (src, dst) = if reply {
            (443u16, 1234u16)
        } else {
            (1234u16, 443u16)
        };
        tcp[..2].copy_from_slice(&src.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst.to_be_bytes());
        tcp[4..8].copy_from_slice(&42u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&43u32.to_be_bytes());
        tcp[12] = 0x60;
        tcp[13] = if reply { 0x12 } else { 2 };
        tcp[20..24].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        b
    }

    #[test]
    fn matches_endpoints_and_ack_without_inferring_send_mss() {
        for v6 in [false, true] {
            let ip: IpAddr = if v6 { "::1" } else { "127.0.0.1" }.parse().unwrap();
            let (local, peer) = (SocketAddr::new(ip, 1234), SocketAddr::new(ip, 443));
            let mut h = Handshake::default();
            h.observe(&sample(v6, true, 1400), local, peer);
            assert!(h.peer().is_none());
            h.observe(&sample(v6, false, 1460), local, peer);
            assert_eq!(h.local.unwrap().mss, Some(1460));
            assert_eq!(h.peer().unwrap().mss, Some(1400));
            let mut wrong = sample(v6, true, 900);
            let offset = if v6 { 40 } else { 20 };
            wrong[offset + 11] = 99;
            h.observe(&wrong, local, peer);
            assert_eq!(h.peer().unwrap().mss, Some(1400));
            h.observe(&sample(v6, true, 800), local, SocketAddr::new(ip, 80));
            assert_eq!(h.peer().unwrap().mss, Some(1400));
        }
    }

    #[test]
    fn rejects_truncated_malformed_and_fragmented_packets() {
        for v6 in [false, true] {
            let b = sample(v6, false, 1460);
            for len in 0..b.len() {
                assert!(packet(&b[..len]).is_none());
            }
            let mut bad = b.clone();
            *bad.last_mut().unwrap() = 0;
            let opt = b.len() - 4;
            bad[opt + 1] = 0;
            assert!(packet(&bad).is_none());
            bad[opt..].fill(0);
            assert_eq!(packet(&bad).unwrap().2.mss, None);
            let mut fragment = b;
            if v6 {
                fragment[6] = 44;
            } else {
                fragment[6] = 0x20;
            }
            assert!(packet(&fragment).is_none());
        }
        assert_eq!(options(&[1, 2, 4, 5, 180, 0]), Some(Some(1460)));
        assert_eq!(options(&[2, 4, 5, 180, 2, 4, 5, 180]), None);
        assert_eq!(options(&[2, 4, 0, 0]), None);
    }

    #[test]
    fn walks_ipv6_extensions_before_tcp_options() {
        let mut b = sample(true, true, 1400);
        b[6] = 60;
        b[4..6].copy_from_slice(&32u16.to_be_bytes());
        b.splice(40..40, [6, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(packet(&b).unwrap().2.mss, Some(1400));
        b[41] = 255;
        assert!(packet(&b).is_none());
    }
}
