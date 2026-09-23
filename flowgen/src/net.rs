use mio::{unix::SourceFd, Interest, Poll, Token};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::{AsRawFd, RawFd},
    time::{Duration, Instant},
};

pub fn socket(v6: bool, tcp: bool) -> io::Result<Socket> {
    let s = Socket::new(
        if v6 { Domain::IPV6 } else { Domain::IPV4 },
        if tcp { Type::STREAM } else { Type::DGRAM },
        Some(if tcp { Protocol::TCP } else { Protocol::UDP }),
    )?;
    s.set_nonblocking(true)?;
    if v6 {
        s.set_only_v6(true)?;
    }
    if tcp {
        s.set_tcp_nodelay(true)?;
    }
    Ok(s)
}
pub fn register(poll: &Poll, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
    poll.registry()
        .register(&mut SourceFd(&fd), token, interest)
}
pub fn update(poll: &Poll, fd: RawFd, token: Token, interest: Interest) -> io::Result<()> {
    poll.registry()
        .reregister(&mut SourceFd(&fd), token, interest)
}
pub fn remove(poll: &Poll, fd: RawFd) {
    let _ = poll.registry().deregister(&mut SourceFd(&fd));
}
pub fn send(s: &Socket, data: &[u8]) -> io::Result<usize> {
    s.send_with_flags(data, libc::MSG_NOSIGNAL)
}
pub fn send_vectored(s: &Socket, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    s.send_vectored_with_flags(bufs, libc::MSG_NOSIGNAL)
}
pub fn recv(s: &Socket, data: &mut [u8]) -> io::Result<usize> {
    // recv initializes exactly the returned prefix; no uninitialized bytes escape.
    let n = unsafe { libc::recv(s.as_raw_fd(), data.as_mut_ptr().cast(), data.len(), 0) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
pub fn connecting(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::EINPROGRESS | libc::EALREADY))
        || e.kind() == io::ErrorKind::WouldBlock
}
pub fn any(v6: bool, port: u16) -> SocketAddr {
    if v6 {
        SocketAddr::from(([0u16; 8], port))
    } else {
        SocketAddr::from(([0u8; 4], port))
    }
}
pub fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().min(u64::MAX as u128) as u64
}
pub fn timeout(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}
