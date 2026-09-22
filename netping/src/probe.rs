use crate::{
    icmp::Icmp,
    net::{self, Reactor},
    options::{Mode, Options},
    stats::{Event, Outcome, Tracker, CAPACITY},
    tcp::{self, Retrans},
    wire,
};
use mio::{event::Event as IoEvent, Interest, Token};
use socket2::Socket;
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    time::{Duration, Instant},
};

pub trait Reporter {
    fn result(&mut self, _seq: u64, _result: &Outcome) -> io::Result<()> {
        Ok(())
    }
    fn failure(&mut self, _seq: u64, _message: &str) -> io::Result<()> {
        Ok(())
    }
    fn error(&mut self, _message: &str) -> io::Result<()> {
        Ok(())
    }
}
impl Reporter for () {}

#[derive(Default)]
pub struct Tokens(usize);
impl Tokens {
    fn next(&mut self) -> io::Result<Token> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or_else(|| io::Error::other("event token exhausted"))?;
        Ok(Token(self.0))
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Link {
    Ready,
    Connecting(Instant),
    Retry(Instant),
    Unavailable,
    Closed,
}
struct WriteFrame {
    data: Vec<u8>,
    offset: usize,
    seq: u64,
}

pub struct Probe {
    pub options: Options,
    pub addr: SocketAddr,
    pub tracker: Tracker,
    pub link: Link,
    pub last: Option<Duration>,
    pub last_failure: Option<&'static str>,
    pub error: Option<String>,
    pub connect_failed: u64,
    pub attempts: u64,
    pub fatal: bool,
    pub ever_ready: bool,
    pub retrans: Retrans,
    id: u64,
    recover: bool,
    socket: Option<Socket>,
    token: Option<Token>,
    icmp: Option<Icmp>,
    connects: HashMap<Token, (u64, Socket)>,
    connect_tokens: HashMap<u64, Token>,
    decoder: wire::Decoder,
    write: Option<WriteFrame>,
    start: Instant,
    next_send: Instant,
    next_tcp_sample: Instant,
    tcp_first_seq: u64,
}
impl Probe {
    fn empty(options: Options, addr: SocketAddr, start: Instant, recover: bool) -> Self {
        Self {
            tracker: Tracker::new(options.timeout),
            options,
            addr,
            link: Link::Unavailable,
            last: None,
            last_failure: None,
            error: None,
            connect_failed: 0,
            attempts: 0,
            fatal: false,
            ever_ready: false,
            retrans: Retrans::new(start),
            id: 0,
            recover,
            socket: None,
            token: None,
            icmp: None,
            connects: HashMap::new(),
            connect_tokens: HashMap::new(),
            decoder: wire::Decoder::default(),
            write: None,
            start,
            next_send: start,
            next_tcp_sample: start,
            tcp_first_seq: 1,
        }
    }
    pub fn unavailable(options: Options, addr: SocketAddr, start: Instant, error: String) -> Self {
        let mut p = Self::empty(options, addr, start, true);
        p.error = Some(error);
        p
    }
    pub fn new(
        options: Options,
        addr: SocketAddr,
        start: Instant,
        recover: bool,
        r: &Reactor,
        tokens: &mut Tokens,
    ) -> io::Result<Self> {
        let mut p = Self::empty(options, addr, start, recover);
        let mut bytes = [0; 8];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        p.id = u64::from_ne_bytes(bytes).max(1);
        match p.options.mode {
            Mode::Icmp => {
                let (s, icmp) = Icmp::socket(&p.options, addr, p.id)?;
                let token = tokens.next()?;
                r.register(&s, token, Interest::READABLE)?;
                p.socket = Some(s);
                p.token = Some(token);
                p.icmp = Some(icmp);
                p.link = Link::Ready;
                p.ever_ready = true;
            }
            Mode::Udp => {
                let s = net::socket(p.options.v6, false)?;
                s.bind(&net::any(p.options.v6, 0).into())?;
                s.connect(&addr.into())?;
                let token = tokens.next()?;
                r.register(&s, token, Interest::READABLE)?;
                p.socket = Some(s);
                p.token = Some(token);
                p.link = Link::Ready;
                p.ever_ready = true;
            }
            Mode::Tcp => p.open_echo(start, r, tokens)?,
            Mode::Connect => {
                p.link = Link::Ready;
                p.ever_ready = true;
            }
        }
        Ok(p)
    }
    pub fn restart_clock(&mut self, now: Instant) {
        self.start = now;
        self.next_send = now;
        if self.options.mode == Mode::Tcp {
            self.tcp_connected(now);
        }
    }
    pub fn resume(&mut self, now: Instant) {
        self.next_send = now;
    }
    pub fn disable(&mut self, error: String) {
        for seq in self.tracker.pending.keys().copied().collect::<Vec<_>>() {
            self.tracker.fail(seq);
        }
        self.close_echo();
        for (_, (_, socket)) in self.connects.drain() {
            self.retrans.tx.completed(net::tcp_retrans(&socket).ok());
        }
        self.connect_tokens.clear();
        self.link = Link::Unavailable;
        self.error = Some(error);
    }
    pub fn sending(&self, now: Instant) -> bool {
        !self.fatal
            && !matches!(self.link, Link::Unavailable | Link::Closed)
            && self.options.count.is_none_or(|n| self.attempts < n)
            && self.options.duration.is_none_or(|d| now < self.start + d)
    }
    pub fn done(&self, now: Instant) -> bool {
        !self.sending(now) && self.tracker.pending.is_empty()
    }
    pub fn owns(&self, token: Token) -> bool {
        self.token == Some(token) || self.connects.contains_key(&token)
    }
    pub fn state(&self) -> &'static str {
        match self.link {
            Link::Ready => "Ready",
            Link::Connecting(_) => "Connecting",
            Link::Retry(_) => "Reconnecting",
            Link::Unavailable => "Unavailable",
            Link::Closed => "Closed",
        }
    }
    fn close_echo(&mut self) {
        self.sample_tcp(Instant::now(), true);
        self.socket = None;
        self.token = None;
        self.write = None;
        self.decoder = wire::Decoder::default();
    }
    fn connect_problem(&mut self, now: Instant, error: String) {
        self.connect_failed += 1;
        self.error = Some(error);
        self.close_echo();
        if self.recover {
            self.link = Link::Retry(now + self.options.interval.max(Duration::from_secs(1)));
        } else {
            self.link = Link::Closed;
            self.fatal = true;
        }
    }
    fn open_echo(&mut self, now: Instant, r: &Reactor, tokens: &mut Tokens) -> io::Result<()> {
        self.tcp_first_seq = self.attempts.saturating_add(1);
        self.retrans.tx.connection(None, now);
        self.retrans.rx.connection(None, now);
        let result = (|| {
            let s = net::socket(self.options.v6, true)?;
            let ready = match s.connect(&self.addr.into()) {
                Ok(()) => true,
                Err(e) if net::connecting(&e) => false,
                Err(e) => return Err(e),
            };
            let token = tokens.next()?;
            r.register(
                &s,
                token,
                if ready {
                    Interest::READABLE
                } else {
                    Interest::READABLE.add(Interest::WRITABLE)
                },
            )?;
            self.socket = Some(s);
            self.token = Some(token);
            self.link = if ready {
                Link::Ready
            } else {
                Link::Connecting(now + self.options.timeout)
            };
            self.ever_ready |= ready;
            if ready {
                self.tcp_connected(Instant::now());
            }
            Ok::<_, io::Error>(())
        })();
        if let Err(e) = result {
            self.connect_problem(now, format!("TCP connect: {e}"));
        }
        Ok(())
    }
    fn failure(&mut self, seq: u64, message: &str, sink: &mut impl Reporter) -> io::Result<()> {
        self.tracker.fail(seq);
        self.last_failure = Some("failed");
        self.error = Some(message.into());
        sink.failure(seq, message)
    }
    fn disconnect(
        &mut self,
        now: Instant,
        message: &str,
        sink: &mut impl Reporter,
    ) -> io::Result<()> {
        let more = self.sending(now) || !self.tracker.pending.is_empty();
        for seq in self.tracker.pending.keys().copied().collect::<Vec<_>>() {
            self.failure(seq, message, sink)?;
        }
        self.error = Some(message.into());
        self.close_echo();
        if more && self.recover {
            self.link = Link::Retry(now + self.options.interval.max(Duration::from_secs(1)));
        } else {
            self.link = Link::Closed;
        }
        self.fatal |= !self.recover;
        sink.error(message)?;
        Ok(())
    }
    fn received(&mut self, seq: u64, now: Instant, sink: &mut impl Reporter) -> io::Result<()> {
        let was_pending = self.tracker.pending.contains_key(&seq);
        let bytes = if self.options.mode == Mode::Connect {
            0
        } else {
            self.options.size as u64
        };
        let outcome = self.tracker.receive_with_bytes(seq, now, bytes);
        if let Outcome::Received(d) | Outcome::Reordered(d) = outcome {
            self.last = Some(d);
            self.last_failure = None;
        } else if was_pending && matches!(outcome, Outcome::Late) {
            self.last_failure = Some("timeout");
        }
        sink.result(seq, &outcome)
    }
    fn message(&mut self, data: &[u8], sink: &mut impl Reporter) -> io::Result<()> {
        if let Some(m) = wire::parse(data).filter(|m| {
            m.session == self.id
                && m.mtu_size.is_none()
                && m.reply == (self.options.mode != Mode::Icmp)
                && data.len() == self.options.size
        }) {
            if self.options.mode == Mode::Tcp
                && m.seq >= self.tcp_first_seq
                && self.tracker.known(m.seq)
            {
                if let Some(retrans) = m.retrans {
                    self.retrans.rx.observe(Some(retrans));
                }
            }
            self.received(m.seq, Instant::now(), sink)
        } else {
            self.tracker.record(Event::Invalid);
            Ok(())
        }
    }
    pub fn tick(
        &mut self,
        now: Instant,
        paused: bool,
        r: &Reactor,
        tokens: &mut Tokens,
        sink: &mut impl Reporter,
    ) -> io::Result<()> {
        self.sample_tcp(now, false);
        let mut broken_write = false;
        for seq in self.tracker.expire(now) {
            if let Some(token) = self.connect_tokens.remove(&seq) {
                if let Some((_, socket)) = self.connects.remove(&token) {
                    self.retrans.tx.completed(net::tcp_retrans(&socket).ok());
                }
            }
            self.last_failure = Some("timeout");
            sink.failure(seq, "timeout")?;
            broken_write |= self.write.as_ref().is_some_and(|w| w.seq == seq);
        }
        if broken_write {
            self.disconnect(now, "TCP partial write timed out", sink)?;
        }
        if matches!(self.link, Link::Connecting(deadline) if now >= deadline) {
            self.connect_problem(now, "TCP echo connection timed out".into());
        }
        if !self.sending(now) {
            if matches!(self.link, Link::Connecting(_) | Link::Retry(_)) {
                self.close_echo();
                self.link = Link::Closed;
            }
            return Ok(());
        }
        if paused {
            return Ok(());
        }
        if matches!(self.link, Link::Retry(at) if now >= at) {
            self.open_echo(now, r, tokens)?;
        }
        if now < self.next_send || (self.options.flood && !self.tracker.pending.is_empty()) {
            return Ok(());
        }
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or_else(|| io::Error::other("sequence exhausted"))?;
        let seq = self.attempts;
        if self.link != Link::Ready {
            self.tracker.record(Event::Skipped(1));
        } else if self.tracker.pending.len() >= CAPACITY || self.write.is_some() {
            self.tracker.record(Event::Limited);
        } else if self.options.mode == Mode::Connect {
            self.send_connect(seq, r, tokens, sink)?;
        } else {
            self.send_echo(seq, r, sink)?;
        }
        if self.options.flood {
            self.next_send = Instant::now()
                + if self.tracker.pending.is_empty() {
                    Duration::from_millis(1)
                } else {
                    Duration::ZERO
                };
        } else {
            let skipped = advance(&mut self.next_send, Instant::now(), self.options.interval);
            self.tracker.record(Event::Skipped(skipped));
        }
        Ok(())
    }
    fn send_connect(
        &mut self,
        seq: u64,
        r: &Reactor,
        tokens: &mut Tokens,
        sink: &mut impl Reporter,
    ) -> io::Result<()> {
        let s = match net::socket(self.options.v6, true) {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS)
                ) =>
            {
                self.tracker.record(Event::Limited);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        self.tracker.sent(seq, Instant::now());
        match s.connect(&self.addr.into()) {
            Ok(()) => {
                self.retrans.tx.completed(net::tcp_retrans(&s).ok());
                self.received(seq, Instant::now(), sink)?;
            }
            Err(e) if net::connecting(&e) => {
                let token = tokens.next()?;
                match r.register(&s, token, Interest::READABLE.add(Interest::WRITABLE)) {
                    Ok(()) => {
                        self.connects.insert(token, (seq, s));
                        self.connect_tokens.insert(seq, token);
                    }
                    Err(e) => {
                        self.retrans.tx.completed(net::tcp_retrans(&s).ok());
                        self.failure(seq, &format!("connect failed: {e}"), sink)?;
                    }
                }
            }
            Err(e) => {
                self.retrans.tx.completed(net::tcp_retrans(&s).ok());
                self.failure(seq, &format!("connect failed: {e}"), sink)?;
            }
        }
        Ok(())
    }
    fn send_echo(&mut self, seq: u64, r: &Reactor, sink: &mut impl Reporter) -> io::Result<()> {
        let mut payload = wire::encode(self.id, seq, self.options.size);
        if self.options.mode == Mode::Tcp {
            wire::request_tcp_info(&mut payload);
        }
        let data = if let Some(i) = &self.icmp {
            i.request(&payload, seq)
        } else if self.options.mode == Mode::Tcp {
            wire::frame(&payload)
        } else {
            payload
        };
        let at = Instant::now();
        match net::send(self.socket.as_ref().unwrap(), &data) {
            Ok(n) if n > 0 => {
                self.tracker
                    .sent_with_bytes(seq, at, self.options.size as u64);
                if n < data.len() {
                    if self.options.mode != Mode::Tcp {
                        return Err(io::Error::other("partial datagram write"));
                    }
                    self.write = Some(WriteFrame {
                        data,
                        offset: n,
                        seq,
                    });
                    r.update(
                        self.socket.as_ref().unwrap(),
                        self.token.unwrap(),
                        Interest::READABLE.add(Interest::WRITABLE),
                    )?;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || matches!(e.raw_os_error(), Some(libc::ENOBUFS | libc::EAGAIN)) =>
            {
                self.tracker.record(Event::Limited)
            }
            result => {
                let message = match result {
                    Err(e) => format!("send failed: {e}"),
                    _ => "send returned zero".into(),
                };
                self.tracker
                    .sent_with_bytes(seq, at, self.options.size as u64);
                self.failure(seq, &message, sink)?;
                if self.options.mode == Mode::Tcp {
                    self.disconnect(Instant::now(), &message, sink)?;
                }
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some(w) = self.write.as_mut() {
            while w.offset < w.data.len() {
                match net::send(self.socket.as_ref().unwrap(), &w.data[w.offset..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "TCP write returned zero",
                        ))
                    }
                    Ok(n) => w.offset += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            self.write = None;
        }
        Ok(())
    }
    pub fn on_io(
        &mut self,
        event: &IoEvent,
        r: &Reactor,
        sink: &mut impl Reporter,
    ) -> io::Result<()> {
        if let Some((seq, s)) = self.connects.remove(&event.token()) {
            match s.take_error()? {
                Some(e) => {
                    self.retrans.tx.completed(net::tcp_retrans(&s).ok());
                    self.connect_tokens.remove(&seq);
                    self.failure(seq, &format!("connect failed: {e}"), sink)?;
                }
                None if s.peer_addr().is_ok() => {
                    self.retrans.tx.completed(net::tcp_retrans(&s).ok());
                    self.connect_tokens.remove(&seq);
                    self.received(seq, Instant::now(), sink)?;
                }
                None => {
                    self.connects.insert(event.token(), (seq, s));
                }
            }
            return Ok(());
        }
        if self.token != Some(event.token()) {
            return Ok(());
        }
        if matches!(self.link, Link::Connecting(_)) {
            let s = self.socket.as_ref().unwrap();
            if let Some(e) = s.take_error()? {
                self.connect_problem(Instant::now(), format!("TCP connect: {e}"));
                return Ok(());
            }
            if s.peer_addr().is_err() {
                return Ok(());
            }
            self.link = Link::Ready;
            self.ever_ready = true;
            r.update(s, event.token(), Interest::READABLE)?;
            self.tcp_connected(Instant::now());
        }
        if event.is_writable() && self.write.is_some() {
            if let Err(e) = self.flush() {
                self.disconnect(Instant::now(), &format!("TCP write: {e}"), sink)?;
                return Ok(());
            }
        }
        if event.is_readable() || event.is_read_closed() || event.is_error() {
            let mut buf = [0; 65536];
            for _ in 0..256 {
                match net::recv(self.socket.as_ref().unwrap(), &mut buf) {
                    Ok(0) if self.options.mode == Mode::Tcp => {
                        let now = Instant::now();
                        if !self.sending(now) && self.tracker.pending.is_empty() {
                            self.close_echo();
                            self.link = Link::Closed;
                        } else {
                            self.disconnect(now, "connection closed", sink)?;
                        }
                        return Ok(());
                    }
                    Ok(n) => {
                        if self.options.mode == Mode::Tcp {
                            match self.decoder.push(&buf[..n]) {
                                Ok(frames) => {
                                    for data in frames {
                                        self.message(&data, sink)?;
                                    }
                                }
                                Err(e) => {
                                    self.disconnect(Instant::now(), &e.to_string(), sink)?;
                                    return Ok(());
                                }
                            }
                        } else if let Some(i) = &self.icmp {
                            if let Some(payload) = i.payload(&buf[..n]) {
                                self.message(payload, sink)?;
                            } else {
                                self.tracker.record(Event::Invalid);
                            }
                        } else {
                            self.message(&buf[..n], sink)?;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        if self.options.mode == Mode::Tcp {
                            self.disconnect(Instant::now(), &format!("TCP read: {e}"), sink)?;
                            return Ok(());
                        }
                        self.error = Some(format!("receive: {e}"));
                        sink.error(self.error.as_deref().unwrap())?;
                        break;
                    }
                }
            }
        }
        if let Some(s) = &self.socket {
            r.update(
                s,
                self.token.unwrap(),
                if self.write.is_some() {
                    Interest::READABLE.add(Interest::WRITABLE)
                } else {
                    Interest::READABLE
                },
            )?;
        }
        Ok(())
    }
    pub fn deadline(&self, now: Instant, paused: bool) -> Instant {
        let mut wake = now + Duration::from_secs(1);
        if self.options.mode == Mode::Tcp && self.link == Link::Ready {
            wake = wake.min(self.next_tcp_sample);
        }
        if let Some(at) = self.tracker.deadline() {
            wake = wake.min(at);
        }
        if let Link::Connecting(at) = self.link {
            wake = wake.min(at);
        }
        if self.sending(now) {
            if !paused {
                if !self.options.flood || self.tracker.pending.is_empty() {
                    wake = wake.min(self.next_send);
                }
                if let Link::Retry(at) = self.link {
                    wake = wake.min(at);
                }
            }
            if let Some(d) = self.options.duration {
                wake = wake.min(self.start + d);
            }
        }
        wake
    }

    fn tcp_connected(&mut self, now: Instant) {
        let baseline = self.socket.as_ref().and_then(|s| net::tcp_retrans(s).ok());
        self.retrans.tx.connection(baseline, now);
        self.next_tcp_sample = now + tcp::SAMPLE;
    }

    fn sample_tcp(&mut self, now: Instant, force: bool) {
        if self.options.mode == Mode::Tcp
            && self.link == Link::Ready
            && (force || now >= self.next_tcp_sample)
        {
            let sample = self.socket.as_ref().and_then(|s| net::tcp_retrans(s).ok());
            self.retrans.tx.observe(sample);
            self.next_tcp_sample = now + tcp::SAMPLE;
        }
        self.retrans.sample(now);
    }

    pub fn finish_tcp(&mut self) {
        self.sample_tcp(Instant::now(), true);
        for (_, (_, socket)) in self.connects.drain() {
            self.retrans.tx.completed(net::tcp_retrans(&socket).ok());
        }
    }
}
fn advance(next: &mut Instant, now: Instant, interval: Duration) -> u64 {
    let late = now.saturating_duration_since(*next).as_nanos();
    let step = interval.as_nanos();
    *next = now + Duration::from_nanos((step - late % step) as u64);
    (late / step) as u64
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_reports_require_a_matching_session_and_a_known_current_connection_request() {
        let options = crate::options::parse(["-t", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut p = Probe::empty(options, "127.0.0.1:11111".parse().unwrap(), now, true);
        p.id = 42;
        p.tracker.sent(1, now);
        let packet = |id, seq, retrans| {
            let mut data = wire::encode(id, seq, 64);
            wire::request_tcp_info(&mut data);
            assert!(wire::reply_tcp(&mut data, Some(retrans)));
            data
        };
        p.message(&packet(42, 1, 7), &mut ()).unwrap();
        p.message(&packet(42, 1, 7), &mut ()).unwrap();
        p.message(&packet(99, 1, 100), &mut ()).unwrap();
        p.message(&packet(42, 999, 100), &mut ()).unwrap();
        assert_eq!(p.retrans.view().rx.total, Some(7));
        p.tcp_first_seq = 2;
        p.message(&packet(42, 1, 200), &mut ()).unwrap();
        assert_eq!(p.retrans.view().rx.total, Some(7));
        assert_eq!(p.tracker.total.recv, 1);
        assert_eq!(p.tracker.total.invalid, 2);
    }

    #[test]
    fn schedule_skips_missed_slots_without_catchup() {
        let start = Instant::now();
        let mut next = start;
        assert_eq!(
            advance(
                &mut next,
                start + Duration::from_millis(35),
                Duration::from_millis(10)
            ),
            3
        );
        assert_eq!(next, start + Duration::from_millis(40));
    }
    #[test]
    fn resume_does_not_catch_up_and_limits_are_per_probe() {
        let o = crate::options::parse(["-c", "2", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut a = Probe::empty(o.clone(), "127.0.0.1:0".parse().unwrap(), now, true);
        let mut b = Probe::empty(o, a.addr, now, true);
        a.link = Link::Ready;
        b.link = Link::Ready;
        a.attempts = 2;
        assert!(a.done(now));
        assert!(!b.done(now));
        b.resume(now + Duration::from_secs(50));
        assert_eq!(b.next_send, now + Duration::from_secs(50));
        assert_eq!(b.tracker.total.skipped, 0);
    }
    #[test]
    fn disconnect_fails_only_inflight_and_schedules_reconnect() {
        let o = crate::options::parse(["-t", "host"].map(str::to_owned)).unwrap();
        let now = Instant::now();
        let mut p = Probe::empty(o, "127.0.0.1:11111".parse().unwrap(), now, true);
        p.link = Link::Ready;
        p.tracker.sent(1, now);
        p.tracker.sent(2, now);
        p.received(2, now + Duration::from_millis(1), &mut ())
            .unwrap();
        p.disconnect(now, "test close", &mut ()).unwrap();
        assert_eq!(p.tracker.total.recv, 1);
        assert_eq!(p.tracker.total.failed, 1);
        assert_eq!(p.link, Link::Retry(now + Duration::from_secs(1)));
        assert!(!p.fatal);
        p.disconnect(now, "test close", &mut ()).unwrap();
        assert_eq!(p.tracker.total.failed, 1);
    }

    #[test]
    fn final_transport_error_is_fatal_even_after_last_request_was_resolved() {
        for expired in [false, true] {
            let o = crate::options::parse(["-t", "-c", "2", "host"].map(str::to_owned)).unwrap();
            let now = Instant::now();
            let mut p = Probe::empty(o, "127.0.0.1:11111".parse().unwrap(), now, false);
            p.link = Link::Ready;
            p.attempts = 2;
            p.tracker.sent(1, now);
            p.received(1, now + Duration::from_millis(1), &mut ())
                .unwrap();
            p.tracker.sent(2, now);
            if expired {
                p.tracker.expire(now + Duration::from_secs(1));
            } else {
                p.failure(2, "TCP write failed", &mut ()).unwrap();
            }
            assert!(p.done(now));
            p.disconnect(now, "transport broken", &mut ()).unwrap();
            assert!(p.fatal);
            assert_eq!(p.tracker.total.recv, 1);
            assert_eq!(p.tracker.total.failed + p.tracker.total.timeout, 1);
        }
    }
}
