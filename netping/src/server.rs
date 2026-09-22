use crate::{
    net::{self, Reactor, WAKE},
    options::Options,
    wire,
};
use mio::{Events, Interest, Token};
use socket2::Socket;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    net::UdpSocket,
    time::{Duration, Instant},
};
const UDP: Token = Token(1);
const LISTENER: Token = Token(2);
const CLIENTS: usize = 256;
const QUEUE: usize = 1024 * 1024;
struct Peer {
    socket: Socket,
    decoder: wire::Decoder,
    out: VecDeque<Vec<u8>>,
    offset: usize,
    queued: usize,
    last: Instant,
    eof: bool,
    retrans_base: u32,
}
impl Peer {
    fn ready(&mut self) -> io::Result<bool> {
        let mut buf = [0; 65536];
        let retrans = net::tcp_retrans(&self.socket)
            .ok()
            .map(|n| n.wrapping_sub(self.retrans_base));
        if !self.eof {
            for _ in 0..64 {
                match net::recv(&self.socket, &mut buf) {
                    Ok(0) => {
                        self.eof = true;
                        break;
                    }
                    Ok(n) => {
                        self.last = Instant::now();
                        for mut message in self.decoder.push(&buf[..n])? {
                            if !wire::reply_tcp(&mut message, retrans) {
                                return Ok(false);
                            }
                            if wire::requests_mss(&message) {
                                wire::report_mss(
                                    &mut message,
                                    net::tcp_send_mss(&self.socket).ok(),
                                );
                            }
                            let frame = wire::frame(&message);
                            self.queued += frame.len();
                            if self.queued > QUEUE {
                                return Ok(false);
                            }
                            self.out.push_back(frame);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        while let Some(front) = self.out.front() {
            match net::send(&self.socket, &front[self.offset..]) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    self.offset += n;
                    self.queued -= n;
                    self.last = Instant::now();
                    if self.offset == front.len() {
                        self.out.pop_front();
                        self.offset = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(!self.eof || !self.out.is_empty())
    }
    fn interest(&self) -> Interest {
        if self.eof {
            Interest::WRITABLE
        } else if self.out.is_empty() {
            Interest::READABLE
        } else {
            Interest::READABLE.add(Interest::WRITABLE)
        }
    }
}
pub fn run(o: &Options, r: &mut Reactor) -> io::Result<()> {
    let addr = net::any(o.v6, o.port);
    let listener = net::socket(o.v6, true)?;
    listener.set_reuse_address(true)?;
    if o.v6 {
        listener.set_only_v6(true)?;
    }
    listener.bind(&addr.into())?;
    listener.listen(128)?;
    let udp = net::socket(o.v6, false)?;
    if o.v6 {
        udp.set_only_v6(true)?;
    }
    udp.bind(&addr.into())?;
    let udp: UdpSocket = udp.into();
    r.register(&listener, LISTENER, Interest::READABLE)?;
    r.register(&udp, UDP, Interest::READABLE)?;
    println!("netping server | UDP + TCP | {addr}");
    io::stdout().flush()?;
    let mut events = Events::with_capacity(256);
    let mut peers = HashMap::<Token, Peer>::new();
    let mut next_token = 3usize;
    let mut buf = [0; 65536];
    while !r.stopped() {
        match r.poll.poll(&mut events, Some(Duration::from_secs(1))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
        for event in &events {
            match event.token() {
                WAKE => {}
                UDP => {
                    for _ in 0..256 {
                        match udp.recv_from(&mut buf) {
                            Ok((n, peer)) => {
                                if let Some(len) = wire::reply_udp(&mut buf[..n]) {
                                    match udp.send_to(&buf[..len], peer) {
                                        Ok(_) => {}
                                        Err(e)
                                            if matches!(
                                                e.kind(),
                                                io::ErrorKind::WouldBlock
                                                    | io::ErrorKind::ConnectionRefused
                                            ) => {}
                                        Err(e) => return Err(e),
                                    }
                                }
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    r.update(&udp, UDP, Interest::READABLE)?;
                }
                LISTENER => {
                    for _ in 0..256 {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                if peers.len() >= CLIENTS {
                                    continue;
                                }
                                socket.set_nonblocking(true)?;
                                socket.set_tcp_nodelay(true)?;
                                let token = Token(next_token);
                                next_token = next_token.checked_add(1).ok_or_else(|| {
                                    io::Error::other("connection token exhausted")
                                })?;
                                r.register(&socket, token, Interest::READABLE)?;
                                peers.insert(
                                    token,
                                    Peer {
                                        retrans_base: net::tcp_retrans(&socket).unwrap_or(0),
                                        socket,
                                        decoder: wire::Decoder::default(),
                                        out: VecDeque::new(),
                                        offset: 0,
                                        queued: 0,
                                        last: Instant::now(),
                                        eof: false,
                                    },
                                );
                            }
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
                                ) =>
                            {
                                continue
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    r.update(&listener, LISTENER, Interest::READABLE)?;
                }
                token => {
                    let keep = if let Some(peer) = peers.get_mut(&token) {
                        peer.ready().unwrap_or(false)
                            && r.update(&peer.socket, token, peer.interest()).is_ok()
                    } else {
                        false
                    };
                    if !keep {
                        peers.remove(&token);
                    }
                }
            }
        }
        peers.retain(|_, p| p.last.elapsed() < Duration::from_secs(60));
    }
    Ok(())
}
