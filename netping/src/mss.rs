use crate::{
    client,
    mss_capture::{Capture, Syn},
    net::{self, Reactor},
    options::{Mode, Options},
    wire,
};
use mio::{Events, Interest, Token};
use socket2::Socket;
use std::{
    fs::File,
    io::{self, Read, Write},
    net::SocketAddr,
    time::Instant,
};

const TCP: Token = Token(1);

fn check(r: &Reactor, deadline: Instant) -> io::Result<()> {
    if r.stopped() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "interrupted"))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
    } else {
        Ok(())
    }
}

struct Watch {
    capture: Option<Capture>,
    note: String,
    local: SocketAddr,
    peer: SocketAddr,
}

impl Watch {
    fn drain(&mut self, r: &Reactor) {
        if let Some(capture) = &mut self.capture {
            if let Err(e) = capture.drain(self.local, self.peer, r) {
                self.note = format!("capture failed: {e}");
                self.capture = None;
            }
        }
    }
}

fn connect(
    s: &Socket,
    peer: SocketAddr,
    r: &mut Reactor,
    events: &mut Events,
    watch: &mut Watch,
    deadline: Instant,
) -> io::Result<()> {
    match s.connect(&peer.into()) {
        Ok(()) => {}
        Err(e) if net::connecting(&e) => {}
        Err(e) => return Err(e),
    }
    watch.local = s
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("missing local TCP address"))?;
    loop {
        check(r, deadline)?;
        watch.drain(r);
        if let Some(e) = s.take_error()? {
            return Err(e);
        }
        if s.peer_addr().is_ok() {
            r.update(s, TCP, Interest::READABLE)?;
            return Ok(());
        }
        client::poll(r, events, deadline)?;
    }
}

fn query(
    s: &Socket,
    r: &mut Reactor,
    events: &mut Events,
    watch: &mut Watch,
    deadline: Instant,
) -> io::Result<Option<Option<u32>>> {
    let mut random = [0; 8];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let session = u64::from_ne_bytes(random).max(1);
    let mut request = wire::encode(session, 1, 64);
    wire::request_mss(&mut request);
    let frame = wire::frame(&request);
    let mut offset = 0;
    let mut decoder = wire::Decoder::default();
    let mut buf = [0; 4096];
    r.update(s, TCP, Interest::READABLE.add(Interest::WRITABLE))?;
    loop {
        check(r, deadline)?;
        watch.drain(r);
        while offset < frame.len() {
            match net::send(s, &frame[offset..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "peer closed during query",
                    ))
                }
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => check(r, deadline)?,
                Err(e) => return Err(e),
            }
        }
        for _ in 0..64 {
            match net::recv(s, &mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed without a report",
                    ))
                }
                Ok(n) => {
                    if let Some(reply) = decoder.push(&buf[..n])?.into_iter().next() {
                        check(r, deadline)?;
                        if offset != frame.len()
                            || reply.len() != 64
                            || !wire::parse(&reply).is_some_and(|m| {
                                m.reply
                                    && m.session == session
                                    && m.seq == 1
                                    && m.mtu_size.is_none()
                            })
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid MSS response",
                            ));
                        }
                        return Ok(wire::peer_mss(&reply));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => check(r, deadline)?,
                Err(e) => return Err(e),
            }
        }
        r.update(
            s,
            TCP,
            if offset < frame.len() {
                Interest::READABLE.add(Interest::WRITABLE)
            } else {
                Interest::READABLE
            },
        )?;
        client::poll(r, events, deadline)?;
    }
}

fn advertised(syn: Option<Syn>, missing: &str) -> String {
    match syn {
        Some(Syn {
            mss: Some(value), ..
        }) => value.to_string(),
        Some(_) => "- (MSS option absent)".into(),
        None => format!("- ({missing})"),
    }
}

pub fn run(o: &Options, r: &mut Reactor) -> Result<bool, Box<dyn std::error::Error>> {
    let peer = net::resolve(o.host.as_ref().unwrap(), o.v6, o.port)?;
    let socket = net::socket(o.v6, true)?;
    socket.bind(&net::any(o.v6, 0).into())?;
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("missing TCP address"))?;
    let (capture, note) = match Capture::new(local.port(), r) {
        Ok(c) => (Some(c), "handshake not captured or not matched".to_string()),
        Err(e) => (
            None,
            format!("capture unavailable: {e}; requires root/CAP_NET_RAW"),
        ),
    };
    let mut watch = Watch {
        capture,
        note,
        local,
        peer,
    };
    r.register(&socket, TCP, Interest::READABLE.add(Interest::WRITABLE))?;
    let mut events = Events::with_capacity(16);
    println!("netping | TCP MSS | {peer} | bytes");
    io::stdout().flush()?;
    let start = Instant::now();
    let connection = connect(&socket, peer, r, &mut events, &mut watch, start + o.timeout);
    let elapsed = start.elapsed();
    let mut success = connection.is_ok();
    let remote = if let Err(e) = &connection {
        format!("- (connection failed: {e})")
    } else if o.mode != Mode::Tcp {
        "- (requires -S -t and a netping server)".into()
    } else {
        match query(
            &socket,
            r,
            &mut events,
            &mut watch,
            Instant::now() + o.timeout,
        ) {
            Ok(Some(Some(value))) => value.to_string(),
            Ok(Some(None)) => {
                success = false;
                "- (server kernel data unavailable)".into()
            }
            Ok(None) => {
                success = false;
                "- (server does not support MSS reports)".into()
            }
            Err(e) => {
                success = false;
                format!("- (query failed: {e})")
            }
        }
    };
    watch.drain(r);
    let local_send = if connection.is_ok() {
        net::tcp_send_mss(&socket)
            .map(|n| n.to_string())
            .unwrap_or_else(|e| {
                success = false;
                format!("- ({e})")
            })
    } else {
        "- (not connected)".into()
    };
    if let Err(e) = connection {
        println!("Connection: failed ({e})");
    } else {
        println!(
            "Connection: {} -> {peer} | {:.3} ms",
            watch.local,
            elapsed.as_secs_f64() * 1000.0
        );
    }
    let handshake = watch.capture.as_ref().map(|c| &c.handshake);
    println!(
        "\n{:<20} {}",
        "Local SYN MSS",
        advertised(handshake.and_then(|h| h.local), &watch.note)
    );
    println!(
        "{:<20} {}",
        "Peer SYN-ACK MSS",
        advertised(handshake.and_then(|h| h.peer()), &watch.note)
    );
    println!("{:<20} {local_send}", "Local send MSS");
    println!("{:<20} {remote}", "Peer send MSS");
    Ok(success && !r.stopped())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_option_and_missing_capture_are_not_zero_or_an_inferred_value() {
        assert_eq!(advertised(None, "no permission"), "- (no permission)");
        let syn = Syn {
            seq: 1,
            ack: 0,
            reply: false,
            mss: None,
        };
        assert_eq!(advertised(Some(syn), ""), "- (MSS option absent)");
        assert_eq!(
            advertised(
                Some(Syn {
                    mss: Some(1400),
                    ..syn
                }),
                ""
            ),
            "1400"
        );
    }
}
