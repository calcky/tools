use mio::{unix::SourceFd, Interest, Poll, Token, Waker};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
pub const WAKE: Token = Token(0);
pub struct Reactor {
    pub poll: Poll,
    pub stop: Arc<AtomicBool>,
    _wake: Arc<Waker>,
}
impl Reactor {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let poll = Poll::new()?;
        let wake = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let stop = Arc::new(AtomicBool::new(false));
        let w = wake.clone();
        let s = stop.clone();
        ctrlc::set_handler(move || {
            s.store(true, Ordering::Relaxed);
            let _ = w.wake();
        })?;
        Ok(Self {
            poll,
            stop,
            _wake: wake,
        })
    }
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
    pub fn register(&self, s: &impl AsRawFd, t: Token, i: Interest) -> io::Result<()> {
        self.poll
            .registry()
            .register(&mut SourceFd(&s.as_raw_fd()), t, i)
    }
    pub fn update(&self, s: &impl AsRawFd, t: Token, i: Interest) -> io::Result<()> {
        self.poll
            .registry()
            .reregister(&mut SourceFd(&s.as_raw_fd()), t, i)
    }
}
pub fn any(v6: bool, port: u16) -> SocketAddr {
    SocketAddr::new(
        if v6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        },
        port,
    )
}
pub fn resolve(host: &str, v6: bool, port: u16) -> io::Result<SocketAddr> {
    (host.trim_matches(['[', ']']), port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv6() == v6)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no address in selected family; use -4 or -6",
            )
        })
}
pub fn socket(v6: bool, tcp: bool) -> io::Result<Socket> {
    let s = Socket::new(
        if v6 { Domain::IPV6 } else { Domain::IPV4 },
        if tcp { Type::STREAM } else { Type::DGRAM },
        Some(if tcp { Protocol::TCP } else { Protocol::UDP }),
    )?;
    s.set_nonblocking(true)?;
    if tcp {
        s.set_tcp_nodelay(true)?;
    }
    Ok(s)
}
pub fn connecting(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EINPROGRESS | libc::EALREADY))
        || e.kind() == io::ErrorKind::WouldBlock
}
pub fn recv(s: &Socket, b: &mut [u8]) -> io::Result<usize> {
    // recv initializes exactly the returned prefix of this already initialized buffer.
    let n = unsafe { libc::recv(s.as_raw_fd(), b.as_mut_ptr().cast(), b.len(), 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
pub fn send(s: &Socket, b: &[u8]) -> io::Result<usize> {
    s.send_with_flags(b, libc::MSG_NOSIGNAL)
}

fn tcp_info(s: &Socket) -> io::Result<(libc::tcp_info, usize)> {
    // Linux returns the supported prefix of TCP_INFO; never read a missing field.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of_val(&info) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            (&mut info as *mut libc::tcp_info).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((info, len as usize))
}

pub fn tcp_send_mss(s: &Socket) -> io::Result<u32> {
    let (info, len) = tcp_info(s)?;
    if len < std::mem::offset_of!(libc::tcp_info, tcpi_snd_mss) + 4 || info.tcpi_snd_mss == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_INFO lacks send MSS",
        ));
    }
    Ok(info.tcpi_snd_mss)
}

pub fn tcp_retrans(s: &Socket) -> io::Result<u32> {
    let (info, len) = tcp_info(s)?;
    let needed = std::mem::offset_of!(libc::tcp_info, tcpi_total_retrans) + 4;
    if len < needed {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP_INFO lacks total retransmissions",
        ));
    }
    Ok(info.tcpi_total_retrans)
}

pub fn only_echo_replies(s: &Socket, v6: bool) -> io::Result<()> {
    // Linux ICMP_FILTER and ICMP6_FILTER both use option 1 and block set bits.
    let mut mask = [u32::MAX; 8];
    let (level, len) = if v6 {
        mask[129 / 32] &= !(1 << (129 % 32));
        (libc::IPPROTO_ICMPV6, std::mem::size_of_val(&mask))
    } else {
        mask[0] &= !1;
        (libc::SOL_RAW, std::mem::size_of::<u32>())
    };
    // The initialized mask stays alive for the entire synchronous syscall.
    let result = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            level,
            1,
            mask.as_ptr().cast(),
            len as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
