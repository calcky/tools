use crate::{
    icmp::Icmp,
    net,
    options::{Mode, Options},
    wire,
};
use mio::{Interest, Token};
use socket2::Socket;
use std::{io, mem, net::SocketAddr, os::fd::AsRawFd, ptr};

pub const TOKEN: Token = Token(1);

#[derive(Debug, PartialEq, Eq)]
pub enum NetworkError {
    TooBig { mtu: Option<usize>, local: bool },
    Other(i32),
}

fn decode_error(errno: u32, origin: u8, kind: u8, code: u8, info: u32) -> Option<NetworkError> {
    if !matches!(origin, 1..=3) {
        return None;
    }
    if errno == libc::EMSGSIZE as u32
        && (origin == 1
            || (origin == 2 && kind == 3 && code == 4)
            || (origin == 3 && kind == 2 && code == 0))
    {
        Some(NetworkError::TooBig {
            mtu: (info > 0).then_some(info as usize),
            local: origin == 1,
        })
    } else if errno != 0 {
        Some(NetworkError::Other(errno as i32))
    } else {
        None
    }
}

struct QueuedError {
    error: NetworkError,
    local: bool,
    quote: Vec<u8>,
}

fn queued_error(socket: &Socket) -> io::Result<Option<QueuedError>> {
    let mut data = [0u8; 1024];
    // usize alignment is sufficient for cmsghdr on both 32- and 64-bit Linux.
    let mut control = [0usize; 64];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control) as _;
    let n = unsafe {
        libc::recvmsg(
            socket.as_raw_fd(),
            &mut msg,
            libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        let e = io::Error::last_os_error();
        return if e.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(e)
        };
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("truncated MTU error control message"));
    }
    // Only read a complete sock_extended_err in a kernel-provided control message.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (((*cmsg).cmsg_level == libc::SOL_IP && (*cmsg).cmsg_type == libc::IP_RECVERR)
                || ((*cmsg).cmsg_level == libc::SOL_IPV6
                    && (*cmsg).cmsg_type == libc::IPV6_RECVERR))
                && (*cmsg).cmsg_len
                    >= libc::CMSG_LEN(mem::size_of::<libc::sock_extended_err>() as u32) as _
            {
                let error =
                    ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::sock_extended_err>());
                if let Some(decoded) = decode_error(
                    error.ee_errno,
                    error.ee_origin,
                    error.ee_type,
                    error.ee_code,
                    error.ee_info,
                ) {
                    return Ok(Some(QueuedError {
                        error: decoded,
                        local: error.ee_origin == 1,
                        quote: data[..(n as usize).min(data.len())].to_vec(),
                    }));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok(None)
}

fn set(socket: &Socket, level: i32, name: i32, value: i32) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const i32).cast(),
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn matches_quote(quote: &[u8], request: &[u8], icmp: bool) -> bool {
    let payload = if icmp { &request[8..] } else { request };
    if quote.len() >= 24 && quote[..24] == payload[..24] {
        return true;
    }
    // Minimal IPv4 ICMP errors may quote only the eight-byte Echo header.
    icmp && quote.len() >= 8 && quote[..2] == request[..2] && quote[4..8] == request[4..8]
}

pub struct ProbeSocket {
    socket: Socket,
    icmp: Option<Icmp>,
    session: u64,
}

impl ProbeSocket {
    pub fn new(o: &Options, addr: SocketAddr, session: u64, r: &net::Reactor) -> io::Result<Self> {
        let (socket, icmp) = if o.mode == Mode::Icmp {
            let (s, i) = Icmp::socket(o, addr, session)?;
            (s, Some(i))
        } else {
            let s = net::socket(o.v6, false)?;
            s.bind(&net::any(o.v6, 0).into())?;
            s.connect(&addr.into())?;
            (s, None)
        };
        if o.v6 {
            set(
                &socket,
                libc::IPPROTO_IPV6,
                libc::IPV6_MTU_DISCOVER,
                libc::IPV6_PMTUDISC_PROBE,
            )?;
            set(&socket, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1)?;
            set(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;
        } else {
            set(
                &socket,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                libc::IP_PMTUDISC_PROBE,
            )?;
            set(&socket, libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
        }
        r.register(&socket, TOKEN, Interest::READABLE)?;
        Ok(Self {
            socket,
            icmp,
            session,
        })
    }

    pub fn request(&self, seq: u64, size: usize) -> Vec<u8> {
        if let Some(i) = &self.icmp {
            i.request(&wire::encode(self.session, seq, size), seq)
        } else {
            wire::mtu_request(self.session, seq, size)
        }
    }

    pub fn clear_errors(&self) -> io::Result<()> {
        for _ in 0..256 {
            if queued_error(&self.socket)?.is_none() {
                break;
            }
        }
        self.socket.take_error()?;
        Ok(())
    }

    pub fn error(&self, request: &[u8]) -> io::Result<Option<NetworkError>> {
        for _ in 0..256 {
            let Some(e) = queued_error(&self.socket)? else {
                break;
            };
            if e.local || matches_quote(&e.quote, request, self.icmp.is_some()) {
                return Ok(Some(e.error));
            }
        }
        Ok(None)
    }

    pub fn send(&self, request: &[u8]) -> io::Result<()> {
        match net::send(&self.socket, request)? {
            n if n == request.len() => Ok(()),
            _ => Err(io::Error::other("partial MTU datagram write")),
        }
    }

    pub fn reply(&self, seq: u64, size: usize) -> io::Result<bool> {
        let mut buf = [0; 65536];
        for _ in 0..256 {
            let n = match net::recv(&self.socket, &mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let payload = if let Some(i) = &self.icmp {
                let Some(p) = i.payload(&buf[..n]) else {
                    continue;
                };
                p
            } else {
                &buf[..n]
            };
            if wire::parse(payload).is_some_and(|m| {
                m.session == self.session
                    && m.seq == seq
                    && if self.icmp.is_some() {
                        !m.reply && payload.len() == size && m.mtu_size.is_none()
                    } else {
                        m.reply && m.mtu_size == Some(size) && payload.len() == wire::HEADER
                    }
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_big_requires_the_right_origin_type_and_code() {
        for (origin, kind, code) in [(1, 0, 0), (2, 3, 4), (3, 2, 0)] {
            assert_eq!(
                decode_error(libc::EMSGSIZE as u32, origin, kind, code, 1400),
                Some(NetworkError::TooBig {
                    mtu: Some(1400),
                    local: origin == 1
                })
            );
        }
        assert_eq!(
            decode_error(libc::EMSGSIZE as u32, 2, 3, 1, 1500),
            Some(NetworkError::Other(libc::EMSGSIZE))
        );
        assert_eq!(decode_error(libc::EMSGSIZE as u32, 4, 2, 0, 1500), None);
        assert_eq!(
            decode_error(libc::EMSGSIZE as u32, 2, 3, 4, 0),
            Some(NetworkError::TooBig {
                mtu: None,
                local: false
            })
        );
    }

    #[test]
    fn errors_must_quote_the_current_probe_not_a_previous_sequence() {
        let a = wire::mtu_request(123, 1, 1200);
        let b = wire::mtu_request(123, 2, 1400);
        assert!(matches_quote(&a[..24], &a, false));
        assert!(!matches_quote(&a[..24], &b, false));
        assert!(!matches_quote(&a[..8], &a, false));
        let mut icmp = vec![8, 0, 0, 0, 0, 42, 0, 1];
        icmp.extend_from_slice(&wire::encode(123, 1, 64));
        assert!(matches_quote(&icmp[..8], &icmp, true));
        let mut old = icmp[..8].to_vec();
        old[7] = 2;
        assert!(!matches_quote(&old, &icmp, true));
    }
}
