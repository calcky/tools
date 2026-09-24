use crate::{
    expiry::Expirations,
    net,
    options::Config,
    pending::{Pending, PendingRequests},
    ports::{self, TuplePool},
    record::{ErrorStage, Event, Kind, Mode, Recording, RecordingSummary},
    schedule::{next_send, Pacer},
    slots::SlotTable,
    stats::{add, dec, get, inc, LocalTraffic, Stats, TrafficSnapshot},
    tuning,
    wire::{self, Header},
};
use mio::{Events, Interest, Poll, Token};
use socket2::Socket;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, VecDeque},
    fs::{self, File},
    io::{self, BufWriter, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};

const SETUP: u8 = 0;
const SEND: u8 = 1;
const EXPIRE: u8 = 2;
const DRAIN: u8 = 3;
const RETRY_OPEN: u8 = 4;
const MAX_PENDING: usize = 131072;
const MAX_TIMERS: usize = 262144;
const FLOW_PENDING: usize = 1024;
const RETIRE_CAPACITY: usize = 131072;
const WORK_QUANTUM: usize = 256;

#[derive(PartialEq)]
enum State {
    Opening,
    Ready,
    Draining,
}
struct Out {
    bytes: Vec<u8>,
    offset: usize,
    seq: u64,
    started: Option<Instant>,
    stamp: u64,
    queued: Instant,
}
struct Flow {
    socket: Socket,
    local: SocketAddr,
    id: u64,
    opened: Instant,
    state: State,
    out: Option<Out>,
    decoder: wire::Decoder,
    seq: u64,
    highest: u64,
    pending: PendingRequests,
    history: VecDeque<(u64, u64, u8)>,
    replacement: Option<SocketAddr>,
    write_interest: bool,
    send_buffer: Vec<u8>,
}
impl Flow {
    fn remember(&mut self, seq: u64, stamp: u64, state: u8) {
        if self.history.len() == 64 {
            self.history.pop_front();
        }
        self.history.push_back((seq, stamp, state));
    }
    fn interest(&self) -> Interest {
        if self.out.is_some() {
            Interest::READABLE.add(Interest::WRITABLE)
        } else {
            Interest::READABLE
        }
    }

    fn update_interest(&mut self, poll: &Poll, token: usize, rearm: bool) -> io::Result<()> {
        let writable = self.out.is_some();
        if rearm || writable != self.write_interest {
            net::update(poll, self.socket.as_raw_fd(), Token(token), self.interest())?;
            self.write_interest = writable;
        }
        Ok(())
    }
}

struct Shared {
    run: u64,
    start: Instant,
    load: OnceLock<Instant>,
    stop: Arc<AtomicBool>,
    pool: Mutex<TuplePool>,
    stats: Stats,
    traffic: Vec<Arc<TrafficSnapshot>>,
    next_flow: AtomicU64,
    exhausted: AtomicBool,
    retired: Mutex<VecDeque<u64>>,
    control_failed: AtomicBool,
}
struct Worker {
    id: usize,
    o: Config,
    remote: SocketAddr,
    shared: Arc<Shared>,
    poll: Poll,
    flows: SlotTable<Flow>,
    ready: VecDeque<usize>,
    timers: BinaryHeap<Reverse<(Instant, u8, usize, u64)>>,
    record: Recording,
    tuples: BufWriter<File>,
    pending: usize,
    outgoing: usize,
    load_seen: bool,
    stopping: bool,
    target: usize,
    last_dropped: u64,
    read_buffer: Vec<u8>,
    traffic: LocalTraffic,
    published: Instant,
    expirations: Expirations,
    last_compaction: Option<Instant>,
    retired: VecDeque<u64>,
}

impl Worker {
    fn publish_retired(&mut self) {
        if self.stopping || self.shared.control_failed.load(Relaxed) {
            self.retired.clear();
        } else if !self.retired.is_empty() {
            let mut queue = self.shared.retired.lock().unwrap();
            let count = self.retired.len().min(RETIRE_CAPACITY - queue.len());
            queue.extend(self.retired.drain(..count));
        }
    }
    fn sync_expiry(&mut self, token: usize, f: &mut Flow) {
        let pending = f.pending.oldest();
        let partial = f
            .out
            .as_ref()
            .filter(|o| o.seq != 0)
            .map(|o| (o.seq, o.queued));
        if let Some((seq, start)) = pending.or(partial) {
            self.expirations.set(token, seq, start + self.o.timeout);
        } else {
            self.expirations.remove(token);
        }
    }
    fn event(&mut self, kind: Kind, flow: u64, seq: u64, value: u64, len: usize) {
        if self.record.mode() == Mode::Off {
            return;
        }
        self.record.push(Event {
            kind,
            flow,
            seq,
            value,
            len: len as u32,
            time_ns: if self.record.mode() == Mode::Events {
                net::ns(self.shared.start)
            } else {
                0
            },
        });
    }
    fn compact_timers(&mut self, current: Option<(usize, &Flow)>) {
        self.timers.retain(|Reverse((_, kind, token, _))| {
            current
                .filter(|(t, _)| t == token)
                .map(|(_, f)| f)
                .or_else(|| self.flows.get(Token(*token)))
                .is_some_and(|f| match *kind {
                    SETUP | RETRY_OPEN => f.state == State::Opening,
                    SEND => f.state == State::Ready,
                    DRAIN => f.state == State::Draining,
                    _ => false,
                })
        });
    }
    fn compact_for_send(&mut self, token: usize, f: &Flow, now: Instant) {
        if f.out.is_none()
            && f.pending.len() < FLOW_PENDING
            && self.pending + self.outgoing < MAX_PENDING
            && self.timers.len() + self.expirations.len() >= MAX_TIMERS
            && self
                .last_compaction
                .is_none_or(|last| now.duration_since(last) >= Duration::from_millis(100))
        {
            self.compact_timers(Some((token, f)));
            self.last_compaction = Some(now);
        }
    }
    fn session_skipped(&mut self, count: u64) {
        if count != 0 {
            add(&self.shared.stats.session_skipped, count);
            if self.record.mode() == Mode::Events {
                self.record
                    .push(Event::session_skipped(0, net::ns(self.shared.start), count));
            } else {
                self.event(Kind::SessionSkipped, 0, 0, count, 0);
            }
        }
    }
    fn error(&mut self, stage: ErrorStage, error: &io::Error, flow: u64, seq: u64) {
        if self.record.mode() == Mode::Off {
            return;
        }
        self.record.push(Event::error(
            flow,
            seq,
            if self.record.mode() == Mode::Events {
                net::ns(self.shared.start)
            } else {
                0
            },
            stage,
            error.raw_os_error().unwrap_or(0),
        ));
    }
    fn fail(
        &mut self,
        token: usize,
        f: Flow,
        stage: ErrorStage,
        error: io::Error,
    ) -> io::Result<()> {
        self.error(stage, &error, f.id, f.out.as_ref().map_or(0, |o| o.seq));
        self.close(token, f, true)
    }
    fn allocate(&self) -> Option<SocketAddr> {
        let value = self.shared.pool.lock().unwrap().allocate(Instant::now());
        self.shared.exhausted.store(value.is_none(), Relaxed);
        value
    }
    fn open(&mut self, addr: SocketAddr) -> io::Result<()> {
        let id = self.shared.next_flow.fetch_add(1, Relaxed);
        inc(&self.shared.stats.attempts);
        self.event(Kind::Open, id, 0, 0, 0);
        writeln!(
            self.tuples,
            "{id},{},{},{},{},{}",
            addr.ip(),
            addr.port(),
            self.remote.ip(),
            self.remote.port(),
            if self.o.tcp { "tcp" } else { "udp" }
        )?;
        let mut stage = ErrorStage::Socket;
        let setup = (|| {
            let s = net::socket(self.o.ipv6, self.o.tcp)?;
            tuning::apply_socket(&s, &self.o)?;
            stage = ErrorStage::Bind;
            s.bind(&addr.into())?;
            stage = ErrorStage::Connect;
            if let Err(e) = s.connect(&self.remote.into()) {
                if !net::connecting(&e) {
                    return Err(e);
                }
            }
            Ok(s)
        })();
        let socket = match setup {
            Ok(s) => s,
            Err(e) => {
                self.error(stage, &e, id, 0);
                self.shared
                    .pool
                    .lock()
                    .unwrap()
                    .release(addr, Instant::now());
                inc(&self.shared.stats.failed);
                self.event(Kind::Failed, id, 0, 0, 0);
                return Ok(());
            }
        };
        let opened = Instant::now();
        let bytes = Header {
            kind: wire::OPEN,
            tcp: self.o.tcp,
            run: self.shared.run,
            flow: id,
            seq: 0,
            stamp: 0,
            aux: self.o.length as u32,
            len: wire::HEADER,
        }
        .encode();
        let f = Flow {
            socket,
            local: addr,
            id,
            opened,
            state: State::Opening,
            out: Some(Out {
                bytes,
                offset: 0,
                seq: 0,
                started: None,
                stamp: 0,
                queued: opened,
            }),
            decoder: if self.o.tcp {
                wire::Decoder::with_capacity(self.o.length)
            } else {
                wire::Decoder::default()
            },
            seq: 0,
            highest: 0,
            pending: PendingRequests::default(),
            history: VecDeque::with_capacity(64),
            replacement: None,
            write_interest: true,
            send_buffer: vec![0; self.o.length],
        };
        let Some(token) = self.flows.insert(f) else {
            self.shared
                .pool
                .lock()
                .unwrap()
                .release(addr, Instant::now());
            let error = io::Error::other("event token capacity exhausted");
            self.error(ErrorStage::Register, &error, id, 0);
            inc(&self.shared.stats.failed);
            self.event(Kind::Failed, id, 0, 0, 0);
            return Err(error);
        };
        if let Err(error) = net::register(
            &self.poll,
            self.flows.get(token).unwrap().socket.as_raw_fd(),
            token,
            Interest::READABLE.add(Interest::WRITABLE),
        ) {
            self.flows.remove(token);
            self.error(ErrorStage::Register, &error, id, 0);
            self.shared
                .pool
                .lock()
                .unwrap()
                .release(addr, Instant::now());
            inc(&self.shared.stats.failed);
            self.event(Kind::Failed, id, 0, 0, 0);
            return Ok(());
        }
        let token = token.0;
        inc(&self.shared.stats.connecting);
        self.timers
            .push(Reverse((opened + self.o.timeout, SETUP, token, 0)));
        if !self.o.tcp {
            self.timers.push(Reverse((
                opened + self.o.timeout.min(Duration::from_millis(300)) / 3,
                RETRY_OPEN,
                token,
                0,
            )));
        }
        self.io(token, false, true)
    }
    fn schedule_first(&mut self, token: usize, id: u64) {
        let interval = Duration::from_secs_f64(1.0 / self.o.pps);
        let phase = (id % self.o.sessions as u64) as f64 / self.o.sessions as f64;
        self.timers.push(Reverse((
            Instant::now() + interval.mul_f64(phase),
            SEND,
            token,
            0,
        )));
    }
    fn write(&mut self, token: usize, f: &mut Flow) -> Result<(), (ErrorStage, io::Error)> {
        let stage = if f.state == State::Opening {
            ErrorStage::Connect
        } else {
            ErrorStage::Send
        };
        if f.state == State::Opening {
            if let Some(e) = f.socket.take_error().map_err(|e| (stage, e))? {
                return Err((stage, e));
            }
        }
        let Some(out) = &mut f.out else {
            return Ok(());
        };
        let mut blocked = false;
        for _ in 0..16 {
            let before = Instant::now();
            if out.seq != 0 && out.started.is_none() {
                out.stamp = net::ns(self.shared.start);
                out.bytes[36..44].copy_from_slice(&out.stamp.to_be_bytes());
            }
            match net::send(&f.socket, &out.bytes[out.offset..]) {
                Ok(0) => {
                    return Err((
                        ErrorStage::Send,
                        io::Error::new(io::ErrorKind::WriteZero, "closed during send"),
                    ))
                }
                Ok(n) => {
                    if !self.o.tcp && n != out.bytes.len() {
                        return Err((ErrorStage::Send, io::Error::other("partial UDP send")));
                    }
                    if out.started.is_none() {
                        out.started = Some(before);
                    }
                    out.offset += n;
                    if out.offset == out.bytes.len() {
                        if out.seq != 0 {
                            self.outgoing -= 1;
                            let seq = out.seq;
                            let len = out.bytes.len();
                            f.pending.insert(
                                seq,
                                Pending {
                                    start: out.started.unwrap(),
                                    stamp: out.stamp,
                                },
                            );
                            self.pending += 1;
                            inc(&self.traffic.pending);
                            inc(&self.traffic.sent);
                            add(&self.traffic.tx_bytes, len as u64);
                            self.event(Kind::Sent, f.id, seq, out.stamp, len);
                        }
                        let completed = f.out.take().unwrap();
                        if completed.seq != 0 {
                            f.send_buffer = completed.bytes;
                        }
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err((ErrorStage::Send, e)),
            }
        }
        // An unfinished write that hit its quantum, rather than EAGAIN, must
        // get another readiness event even if WRITABLE was already registered.
        f.update_interest(&self.poll, token, f.out.is_some() && !blocked)
            .map_err(|e| (ErrorStage::Interest, e))
    }
    fn response(&mut self, token: usize, f: &mut Flow, data: &[u8]) -> io::Result<()> {
        let h = match wire::parse(data) {
            Ok(h) if h.run == self.shared.run && h.flow == f.id && h.tcp == self.o.tcp => h,
            _ => {
                inc(&self.traffic.invalid);
                self.event(Kind::Invalid, f.id, 0, 0, data.len());
                return Ok(());
            }
        };
        if h.kind == wire::ACK
            && f.state == State::Opening
            && h.len == wire::HEADER
            && h.aux == self.o.length as u32
            && h.seq == 0
            && h.stamp == 0
        {
            if !self.load_seen
                && Instant::now() > self.shared.start + self.o.warmup + self.o.timeout
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "registration exceeded warmup grace",
                ));
            }
            f.state = State::Ready;
            dec(&self.shared.stats.connecting);
            inc(&self.shared.stats.ready);
            inc(&self.shared.stats.established);
            if self.o.turnover > 0.0 {
                self.ready.push_back(token);
            }
            self.event(
                Kind::Ready,
                f.id,
                0,
                f.opened.elapsed().as_nanos() as u64,
                0,
            );
            if self.load_seen {
                self.schedule_first(token, f.id);
            }
            return Ok(());
        }
        if h.kind == wire::ACK
            && h.len == wire::HEADER
            && h.aux == self.o.length as u32
            && h.seq == 0
            && h.stamp == 0
        {
            // An OPEN retry can produce a second valid acknowledgement.
            return Ok(());
        }
        if h.kind != wire::DATA || h.len != self.o.length || h.seq == 0 || h.seq > f.seq {
            inc(&self.traffic.invalid);
            self.event(Kind::Invalid, f.id, h.seq, 0, data.len());
            return Ok(());
        }
        add(&self.traffic.rx_bytes, h.len as u64);
        let mut first_response = false;
        if let Some(p) = f.pending.get(&h.seq) {
            if p.stamp != h.stamp {
                inc(&self.traffic.invalid);
                self.event(Kind::Invalid, f.id, h.seq, 0, data.len());
                return Ok(());
            }
            first_response = true;
            if p.start.elapsed() >= self.o.timeout {
                f.pending.remove(&h.seq);
                self.pending -= 1;
                dec(&self.traffic.pending);
                inc(&self.traffic.timeout);
                self.event(Kind::Timeout, f.id, h.seq, 0, 0);
                inc(&self.traffic.late);
                self.event(Kind::Late, f.id, h.seq, 0, data.len());
                f.remember(h.seq, h.stamp, 2);
            } else {
                let rtt = p.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                f.pending.remove(&h.seq);
                self.pending -= 1;
                dec(&self.traffic.pending);
                inc(&self.traffic.received);
                self.event(Kind::Response, f.id, h.seq, rtt, h.len);
                f.remember(h.seq, h.stamp, 1);
            }
        } else if let Some((_, stamp, state)) =
            f.history.iter_mut().find(|(seq, _, _)| *seq == h.seq)
        {
            if *stamp != h.stamp {
                inc(&self.traffic.invalid);
                self.event(Kind::Invalid, f.id, h.seq, 0, h.len);
                return Ok(());
            }
            if *state == 0 {
                first_response = true;
                *state = 2;
                inc(&self.traffic.late);
                self.event(Kind::Late, f.id, h.seq, 0, h.len);
            } else {
                inc(&self.traffic.duplicate);
                self.event(Kind::Duplicate, f.id, h.seq, 0, h.len);
            }
        } else {
            inc(&self.traffic.invalid);
            self.event(Kind::Invalid, f.id, h.seq, 1, h.len);
        }
        if first_response {
            if !self.o.tcp && h.seq < f.highest {
                inc(&self.traffic.reordered);
                self.event(Kind::Reordered, f.id, h.seq, 0, 0);
            }
            f.highest = f.highest.max(h.seq);
        }
        Ok(())
    }
    fn io(&mut self, token: usize, readable: bool, writable: bool) -> io::Result<()> {
        let Some(mut f) = self.flows.take(Token(token)) else {
            return Ok(());
        };
        // Restore before close(): closing a rotated flow can open its replacement
        // and recursively service that socket using this same worker buffer.
        let mut buf = std::mem::take(&mut self.read_buffer);
        let mut stage = if f.state == State::Opening {
            ErrorStage::Connect
        } else {
            ErrorStage::Send
        };
        let result = (|| {
            let mut rearm_read = false;
            if writable {
                self.write(token, &mut f).map_err(|(at, e)| {
                    stage = at;
                    e
                })?;
            }
            if readable {
                stage = ErrorStage::Receive;
                rearm_read = true;
                for _ in 0..64 {
                    match net::recv(&f.socket, &mut buf) {
                        Ok(0) if self.o.tcp => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "server disconnected",
                            ))
                        }
                        Ok(n) => {
                            if self.o.tcp {
                                stage = ErrorStage::Decode;
                                let mut decoder = std::mem::take(&mut f.decoder);
                                let result = decoder.push_with(&buf[..n], |frame| {
                                    self.response(token, &mut f, frame)
                                });
                                f.decoder = decoder;
                                result.inspect_err(|e| {
                                    if e.kind() == io::ErrorKind::TimedOut {
                                        stage = ErrorStage::SetupTimeout;
                                    }
                                })?;
                                stage = ErrorStage::Receive;
                            } else {
                                self.response(token, &mut f, &buf[..n]).inspect_err(|e| {
                                    if e.kind() == io::ErrorKind::TimedOut {
                                        stage = ErrorStage::SetupTimeout;
                                    }
                                })?;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            rearm_read = false;
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
            // Mio uses edge-triggered readiness. If the read quantum was used
            // up before EAGAIN, rearm even when interests did not change.
            stage = ErrorStage::Interest;
            f.update_interest(&self.poll, token, rearm_read)
        })();
        self.read_buffer = buf;
        if let Err(e) = result {
            self.fail(token, f, stage, e)?;
        } else if f.state == State::Draining && f.out.is_none() && f.pending.is_empty() {
            self.close(token, f, false)?;
        } else {
            self.sync_expiry(token, &mut f);
            assert!(self.flows.put(Token(token), f));
        }
        Ok(())
    }
    fn close(&mut self, token: usize, mut f: Flow, failed: bool) -> io::Result<()> {
        self.expirations.remove(token);
        net::remove(&self.poll, f.socket.as_raw_fd());
        match f.state {
            State::Opening => dec(&self.shared.stats.connecting),
            State::Ready => dec(&self.shared.stats.ready),
            State::Draining => dec(&self.shared.stats.draining),
        }
        if failed {
            inc(&self.shared.stats.failed);
            self.event(Kind::Failed, f.id, 0, 0, 0);
        }
        for (seq, p) in f.pending.drain() {
            self.pending -= 1;
            dec(&self.traffic.pending);
            if p.start.elapsed() >= self.o.timeout {
                inc(&self.traffic.timeout);
                self.event(Kind::Timeout, f.id, seq, 0, 0);
            } else {
                inc(&self.traffic.canceled);
                self.event(Kind::Canceled, f.id, seq, 0, 0);
            }
        }
        if let Some(out) = &f.out {
            if out.seq != 0 {
                self.outgoing -= 1;
                inc(&self.traffic.canceled);
                self.event(Kind::Canceled, f.id, out.seq, out.offset as u64, 0);
            }
        }
        if !self.o.tcp && !self.stopping {
            let close = Header {
                kind: wire::CLOSE,
                tcp: false,
                run: self.shared.run,
                flow: f.id,
                seq: 0,
                stamp: 0,
                aux: 0,
                len: wire::HEADER,
            }
            .encode();
            let _ = net::send(&f.socket, &close);
        }
        drop(f.socket);
        if !self.o.tcp && !self.stopping {
            // Final shutdown uses the reliable END barrier. During turnover,
            // keep IDs locally until the bounded control queue has room.
            self.retired.push_back(f.id);
            self.publish_retired();
        }
        self.shared
            .pool
            .lock()
            .unwrap()
            .release(f.local, Instant::now());
        inc(&self.shared.stats.closed);
        self.event(Kind::Closed, f.id, 0, 0, 0);
        // Reusing this slot advances its generation; queued old events stay stale.
        assert!(self.flows.release_taken(Token(token)));
        if let Some(addr) = f.replacement {
            if !self.stopping && self.retired.is_empty() {
                self.open(addr)?;
            } else {
                self.shared
                    .pool
                    .lock()
                    .unwrap()
                    .release(addr, Instant::now());
            }
        }
        Ok(())
    }
    fn retire(&mut self, token: usize, replacement: Option<SocketAddr>) -> io::Result<()> {
        let Some(mut f) = self.flows.take(Token(token)) else {
            return Ok(());
        };
        if f.state != State::Draining {
            match f.state {
                State::Ready => dec(&self.shared.stats.ready),
                State::Opening => dec(&self.shared.stats.connecting),
                State::Draining => {}
            }
            inc(&self.shared.stats.draining);
            f.state = State::Draining;
            f.replacement = replacement;
            self.timers
                .push(Reverse((Instant::now() + self.o.timeout, DRAIN, token, 0)));
        }
        if f.out.is_none() && f.pending.is_empty() {
            self.close(token, f, false)?;
        } else {
            assert!(self.flows.put(Token(token), f));
        }
        Ok(())
    }
    fn timer(&mut self, deadline: Instant, kind: u8, token: usize, seq: u64) -> io::Result<()> {
        let Some(mut f) = self.flows.take(Token(token)) else {
            return Ok(());
        };
        if kind == SETUP && f.state == State::Opening {
            return self.fail(
                token,
                f,
                ErrorStage::SetupTimeout,
                io::Error::new(io::ErrorKind::TimedOut, "registration timed out"),
            );
        }
        if kind == DRAIN && f.state == State::Draining {
            return self.close(token, f, false);
        }
        if kind == RETRY_OPEN && f.state == State::Opening && !self.stopping {
            if f.out.is_none() {
                let bytes = Header {
                    kind: wire::OPEN,
                    tcp: false,
                    run: self.shared.run,
                    flow: f.id,
                    seq: 0,
                    stamp: 0,
                    aux: self.o.length as u32,
                    len: wire::HEADER,
                }
                .encode();
                f.out = Some(Out {
                    bytes,
                    offset: 0,
                    seq: 0,
                    started: None,
                    stamp: 0,
                    queued: Instant::now(),
                });
                if let Err((stage, e)) = self.write(token, &mut f) {
                    return self.fail(token, f, stage, e);
                }
            }
            self.timers.push(Reverse((
                Instant::now() + self.o.timeout.min(Duration::from_millis(300)) / 3,
                RETRY_OPEN,
                token,
                0,
            )));
        }
        if kind == EXPIRE {
            if let Some(out) = &f.out {
                if out.seq == seq {
                    return self.fail(
                        token,
                        f,
                        ErrorStage::SendTimeout,
                        io::Error::new(io::ErrorKind::TimedOut, "send timed out"),
                    );
                }
            }
            if let Some(p) = f.pending.remove(&seq) {
                self.pending -= 1;
                dec(&self.traffic.pending);
                inc(&self.traffic.timeout);
                self.event(Kind::Timeout, f.id, seq, 0, 0);
                f.remember(seq, p.stamp, 0);
            }
        }
        if kind == SEND && f.state == State::Ready && !self.stopping {
            let interval = Duration::from_secs_f64(1.0 / self.o.pps);
            let (next, skipped) = next_send(deadline, Instant::now(), interval);
            add(&self.traffic.skipped, skipped);
            if skipped > 0 {
                self.event(Kind::Skipped, f.id, 0, skipped, 0);
            }
            self.timers.push(Reverse((next, SEND, token, 0)));
            self.compact_for_send(token, &f, Instant::now());
            if f.out.is_some()
                || f.pending.len() >= FLOW_PENDING
                || self.pending + self.outgoing >= MAX_PENDING
                || self.timers.len() + self.expirations.len() >= MAX_TIMERS
            {
                inc(&self.traffic.limited);
                self.event(Kind::Limited, f.id, 0, 1, 0);
            } else {
                f.seq += 1;
                let mut bytes = std::mem::take(&mut f.send_buffer);
                Header {
                    kind: wire::DATA,
                    tcp: self.o.tcp,
                    run: self.shared.run,
                    flow: f.id,
                    seq: f.seq,
                    stamp: 0,
                    aux: 0,
                    len: self.o.length,
                }
                .encode_into(&mut bytes);
                f.out = Some(Out {
                    bytes,
                    offset: 0,
                    seq: f.seq,
                    started: None,
                    stamp: 0,
                    queued: Instant::now(),
                });
                self.outgoing += 1;
                if let Err((stage, e)) = self.write(token, &mut f) {
                    return self.fail(token, f, stage, e);
                }
            }
        }
        if f.state == State::Draining && f.out.is_none() && f.pending.is_empty() {
            self.close(token, f, false)?;
        } else {
            self.sync_expiry(token, &mut f);
            assert!(self.flows.put(Token(token), f));
        }
        Ok(())
    }
    fn turnover(&mut self) -> io::Result<()> {
        if self.flows.len() < self.target {
            if let Some(addr) = self.allocate() {
                inc(&self.shared.stats.repairs);
                self.open(addr)?;
            } else {
                self.session_skipped(1);
            }
        } else if self.o.turnover > 0.0 {
            while self.ready.front().is_some_and(|t| {
                !self
                    .flows
                    .get(Token(*t))
                    .is_some_and(|f| f.state == State::Ready)
            }) {
                self.ready.pop_front();
            }
            if let Some(&token) = self.ready.front() {
                if let Some(addr) = self.allocate() {
                    self.ready.pop_front();
                    inc(&self.shared.stats.rotations);
                    self.retire(token, Some(addr))?;
                } else if self.o.reuse.is_some() {
                    // A fully occupied reusable pool needs a retirement before
                    // any tuple can enter cooldown. Subsequent slots repair it.
                    self.ready.pop_front();
                    inc(&self.shared.stats.rotations);
                    self.retire(token, None)?;
                } else {
                    self.session_skipped(1);
                }
            } else {
                self.session_skipped(1);
            }
        }
        Ok(())
    }
    fn admit_due(&mut self, warmup: &mut Pacer, rotation: &mut Option<Pacer>) -> io::Result<()> {
        let now = Instant::now();
        if self.shared.stop.load(Relaxed)
            || self
                .shared
                .load
                .get()
                .is_some_and(|epoch| !self.o.duration.is_zero() && now >= *epoch + self.o.duration)
        {
            self.stopping = true;
        }
        if self.stopping || !self.retired.is_empty() {
            return Ok(());
        }
        if !self.load_seen
            && self.flows.len() < self.target
            && now < self.shared.start + self.o.warmup + self.o.timeout
            && now >= warmup.deadline()
        {
            if let Some(addr) = self.allocate() {
                self.open(addr)?;
            } else {
                self.session_skipped(1);
            }
            self.session_skipped(warmup.advance(now));
        } else if self.load_seen {
            if let Some(p) = rotation {
                if now >= p.deadline() {
                    self.session_skipped(p.advance(now));
                    self.turnover()?;
                }
            }
        }
        Ok(())
    }
    fn run(mut self) -> io::Result<Option<RecordingSummary>> {
        let mut events = Events::with_capacity(256);
        let mut warmup = Pacer::new(
            self.shared.start,
            self.o.sessions as f64 / self.o.warmup.as_secs_f64(),
            self.id,
            self.o.workers,
        );
        let mut rotation: Option<Pacer> = None;
        let mut shutdown: Option<VecDeque<usize>> = None;
        loop {
            self.publish_retired();
            let now = Instant::now();
            if let Some(&epoch) = self.shared.load.get() {
                if !self.load_seen {
                    self.load_seen = true;
                    rotation = Some(Pacer::new(
                        epoch,
                        if self.o.turnover > 0.0 {
                            self.o.turnover
                        } else {
                            self.o.sessions as f64 / self.o.warmup.as_secs_f64()
                        },
                        self.id,
                        self.o.workers,
                    ));
                    let initial: Vec<_> = self
                        .flows
                        .iter()
                        .filter(|(_, f)| f.state == State::Ready)
                        .map(|(t, f)| (t.0, f.id))
                        .collect();
                    for (t, id) in initial {
                        self.schedule_first(t, id);
                    }
                }
                if !self.o.duration.is_zero() && now >= epoch + self.o.duration {
                    self.stopping = true;
                }
            }
            if self.shared.stop.load(Relaxed) {
                self.stopping = true;
            }
            if self.stopping {
                let tokens =
                    shutdown.get_or_insert_with(|| self.flows.iter().map(|(t, _)| t.0).collect());
                for _ in 0..WORK_QUANTUM {
                    let Some(t) = tokens.pop_front() else { break };
                    self.retire(t, None)?;
                }
                if self.flows.is_empty() && self.retired.is_empty() {
                    break;
                }
            }
            self.admit_due(&mut warmup, &mut rotation)?;
            for _ in 0..256 {
                if !self
                    .expirations
                    .peek()
                    .is_some_and(|(when, ..)| when <= now)
                {
                    break;
                }
                let (deadline, token, seq) = self.expirations.pop().unwrap();
                self.timer(deadline, EXPIRE, token, seq)?;
            }
            for index in 0..256 {
                if index % 16 == 0 {
                    self.admit_due(&mut warmup, &mut rotation)?;
                }
                if !self.timers.peek().is_some_and(|r| r.0 .0 <= now) {
                    break;
                }
                let Reverse((deadline, kind, t, seq)) = self.timers.pop().unwrap();
                self.timer(deadline, kind, t, seq)?;
            }
            // Retired low-PPS flows may leave far-future send deadlines. Compact
            // lazily instead of retaining their timers for the entire test.
            if self.timers.len() > 2 * (self.flows.len() + self.pending + 1024) {
                self.compact_timers(None);
            }
            let dropped = self.record.dropped();
            add(&self.traffic.log_dropped, dropped - self.last_dropped);
            self.last_dropped = dropped;
            if self.published.elapsed() >= Duration::from_millis(100) {
                self.traffic.publish();
                self.published = Instant::now();
            }
            let mut deadline = now + Duration::from_millis(100);
            if shutdown.as_ref().is_some_and(|tokens| !tokens.is_empty()) {
                deadline = now;
            } else if !self.retired.is_empty() {
                deadline = now + Duration::from_millis(1);
            }
            if let Some((when, ..)) = self.expirations.peek() {
                deadline = deadline.min(when);
            }
            if let Some(Reverse((when, ..))) = self.timers.peek() {
                deadline = deadline.min(*when);
            }
            if !self.stopping && self.retired.is_empty() {
                if !self.load_seen
                    && self.flows.len() < self.target
                    && now < self.shared.start + self.o.warmup + self.o.timeout
                {
                    deadline = deadline.min(warmup.deadline());
                }
                if let Some(p) = &rotation {
                    deadline = deadline.min(p.deadline());
                }
            }
            match self.poll.poll(&mut events, Some(net::timeout(deadline))) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for (index, ev) in events.iter().enumerate() {
                if index % 16 == 0 {
                    self.admit_due(&mut warmup, &mut rotation)?;
                }
                self.io(
                    ev.token().0,
                    ev.is_readable() || ev.is_read_closed() || ev.is_error(),
                    ev.is_writable() || ev.is_error(),
                )?;
            }
        }
        self.tuples.flush()?;
        let mode = self.record.mode();
        let (summary, aggregate) = self.record.finish_with_summary()?;
        add(
            &self.traffic.log_dropped,
            summary.dropped - self.last_dropped,
        );
        if summary.dropped > 0 {
            eprintln!(
                "worker {}: {} recording events dropped; analysis incomplete",
                self.id, summary.dropped
            );
        }
        Ok((mode == Mode::Summary).then_some(aggregate))
    }
}

fn control_exchange(stream: &mut TcpStream, header: Header) -> io::Result<Vec<u8>> {
    control_frame_exchange(stream, &header.encode())
}
fn control_frame_exchange(stream: &mut TcpStream, request: &[u8]) -> io::Result<Vec<u8>> {
    let header = wire::parse(request)?;
    stream.write_all(request)?;
    let mut prefix = [0; 8];
    stream.read_exact(&mut prefix)?;
    let len = u32::from_be_bytes(prefix[4..8].try_into().unwrap()) as usize;
    if !(wire::HEADER..=wire::REPORT_LEN).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control response size",
        ));
    }
    let mut bytes = vec![0; len];
    bytes[..8].copy_from_slice(&prefix);
    stream.read_exact(&mut bytes[8..])?;
    let h = wire::parse(&bytes)?;
    if h.run != header.run || h.tcp != header.tcp || h.seq != header.seq {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control session mismatch",
        ));
    }
    Ok(bytes)
}
fn flush_retired(
    stream: &mut TcpStream,
    shared: &Shared,
    mut header: Header,
    seq: &mut u64,
) -> io::Result<bool> {
    let ids: Vec<_> = {
        let mut queue = shared.retired.lock().unwrap();
        let n = queue.len().min(1024);
        queue.drain(..n).collect()
    };
    if ids.is_empty() {
        return Ok(false);
    }
    *seq += 1;
    header.kind = wire::CLOSE;
    header.flow = 0;
    header.seq = *seq;
    header.stamp = 0;
    header.aux = 0;
    header.len = wire::HEADER + ids.len() * 8;
    let mut frame = header.encode();
    for (chunk, id) in frame[wire::HEADER..]
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .zip(ids)
    {
        chunk.copy_from_slice(&id.to_be_bytes());
    }
    control_frame_exchange(stream, &frame).and_then(|b| wire::counters(&b))?;
    Ok(true)
}
fn resolve(o: &Config) -> io::Result<SocketAddr> {
    (o.host.as_deref().unwrap_or(""), o.port)
        .to_socket_addrs()?
        .find(|a| a.is_ipv6() == o.ipv6)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no target address in selected family",
            )
        })
}
fn source(remote: SocketAddr) -> io::Result<IpAddr> {
    let s = UdpSocket::bind(net::any(remote.is_ipv6(), 0))?;
    s.connect(remote)?;
    Ok(s.local_addr()?.ip())
}
fn run_id() -> io::Result<u64> {
    let mut b = [0; 8];
    File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(u64::from_ne_bytes(b).max(1))
}

pub fn run(o: &Config, stop: Arc<AtomicBool>) -> io::Result<()> {
    let recording_mode = Mode::parse(&o.recording).unwrap_or(Mode::Events);
    let remote = resolve(o)?;
    let sources = if o.sources.is_empty() {
        vec![source(remote)?]
    } else {
        o.sources.clone()
    };
    let mut effective_buffers = Vec::new();
    for ip in &sources {
        let probe = net::socket(o.ipv6, o.tcp)?;
        tuning::apply_socket(&probe, o)?;
        probe.bind(&SocketAddr::new(*ip, 0).into()).map_err(|e| {
            io::Error::new(e.kind(), format!("source address {ip} is not usable: {e}"))
        })?;
        if o.send_buffer.is_some() || o.recv_buffer.is_some() {
            let (send, receive) = tuning::effective_buffers(&probe)?;
            effective_buffers.push((*ip, send, receive));
        }
    }
    let pool = TuplePool::new(sources, o.ports, o.reuse)?;
    ports::preflight(o, pool.capacity())?;
    fs::create_dir_all(&o.output)?;
    let run = run_id()?;
    let mut aggregate = if recording_mode == Mode::Summary {
        Some(RecordingSummary::new(run, o.tcp, false)?)
    } else {
        None
    };
    let mut metadata = File::options()
        .create_new(true)
        .write(true)
        .open(o.output.join("run.txt"))?;
    writeln!(metadata,"flowgen {}\nrun {run}\ntarget {remote}\nprotocol {}\nsessions {}\nwarmup {}\nturnover {}\npps_per_session {}\nlength {}\nduration {}\ntimeout {}\nworkers {}\n",env!("CARGO_PKG_VERSION"),if o.tcp {"tcp"} else {"udp"},o.sessions,o.warmup.as_secs_f64(),o.turnover,o.pps,o.length,o.duration.as_secs_f64(),o.timeout.as_secs_f64(),o.workers)?;
    writeln!(metadata, "recording {recording_mode}")?;
    let cpus = o.cpus.as_ref().map_or_else(
        || "unbound".to_owned(),
        |cpus| {
            cpus.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        },
    );
    writeln!(metadata, "cpu_affinity {cpus}")?;
    let send_requested = o
        .send_buffer
        .map_or_else(|| "default".into(), |n| n.to_string());
    let recv_requested = o
        .recv_buffer
        .map_or_else(|| "default".into(), |n| n.to_string());
    writeln!(
        metadata,
        "send_buffer_requested {send_requested}\nrecv_buffer_requested {recv_requested}"
    )?;
    for (ip, send, receive) in effective_buffers {
        // These probes use the data protocol and options before connect;
        // TCP autotuning may subsequently change the effective sizes.
        writeln!(
            metadata,
            "socket_buffers_preconnect {ip} send {send} receive {receive}"
        )?;
        println!("socket buffers (pre-connect) | source {ip} | requested send {send_requested} receive {recv_requested} | effective send {send} receive {receive} bytes");
    }
    let mut control = TcpStream::connect_timeout(&remote, o.timeout)?;
    control.set_nodelay(true)?;
    control.set_read_timeout(Some(o.timeout))?;
    control.set_write_timeout(Some(o.timeout))?;
    let mut header = Header {
        kind: wire::CONTROL,
        tcp: o.tcp,
        run,
        flow: o.sessions as u64,
        seq: o.timeout.as_nanos() as u64,
        stamp: if o.duration.is_zero() {
            wire::UNLIMITED_RUN
        } else {
            (o.warmup + o.duration + o.timeout * 3 + Duration::from_secs(30))
                .as_nanos()
                .min(u64::MAX as u128) as u64
        },
        aux: o.length as u32,
        len: wire::HEADER,
    };
    let reply = control_exchange(&mut control, header)?;
    if wire::parse(&reply)?.kind != wire::ACCEPT {
        return Err(io::Error::other("server did not accept workload"));
    }
    let shared = Arc::new(Shared {
        run,
        start: Instant::now() + Duration::from_millis(100),
        load: OnceLock::new(),
        stop: stop.clone(),
        pool: Mutex::new(pool),
        stats: Stats::default(),
        traffic: (0..o.workers)
            .map(|_| Arc::new(TrafficSnapshot::default()))
            .collect(),
        next_flow: AtomicU64::new(1),
        exhausted: AtomicBool::new(false),
        retired: Mutex::new(VecDeque::new()),
        control_failed: AtomicBool::new(false),
    });
    let mut workers = Vec::new();
    for id in 0..o.workers {
        let target = (o.sessions + o.workers - 1 - id) / o.workers;
        let recording_path = match recording_mode {
            Mode::Events => o.output.join(format!("client-{id}.fgr")),
            Mode::Summary => o.output.join(format!("client-{id}.summary.csv")),
            Mode::Off => o.output.join(format!("client-{id}.fgr")),
        };
        let mut tuples = BufWriter::with_capacity(
            65536,
            File::options()
                .create_new(true)
                .write(true)
                .open(o.output.join(format!("tuples-{id}.csv")))?,
        );
        writeln!(
            tuples,
            "session,source_ip,source_port,target_ip,target_port,protocol"
        )?;
        let w = Worker {
            id,
            o: o.clone(),
            remote,
            shared: shared.clone(),
            poll: Poll::new()?,
            flows: SlotTable::with_capacity(target),
            ready: VecDeque::new(),
            timers: BinaryHeap::new(),
            record: Recording::create(&recording_path, run, o.tcp, false, recording_mode)?,
            tuples,
            pending: 0,
            outgoing: 0,
            load_seen: false,
            stopping: false,
            target,
            last_dropped: 0,
            read_buffer: vec![0; 65536],
            traffic: LocalTraffic::new(shared.traffic[id].clone()),
            published: Instant::now(),
            expirations: Expirations::default(),
            last_compaction: None,
            retired: VecDeque::new(),
        };
        workers.push(w);
    }
    let handles: Vec<_> = workers
        .into_iter()
        .map(|w| {
            let failed_stop = stop.clone();
            thread::spawn(move || {
                if let Err(error) = tuning::pin_worker(&w.o, w.id) {
                    failed_stop.store(true, Relaxed);
                    return Err(error);
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| w.run()))
                    .unwrap_or_else(|_| Err(io::Error::other("client worker panicked")));
                if result.is_err() {
                    failed_stop.store(true, Relaxed);
                }
                result
            })
        })
        .collect();
    println!("flowgen | {} | {remote} | {} sessions | warmup {:.3}s | {:.2} requests/s/session | {} bytes",if o.tcp {"TCP"} else {"UDP"},o.sessions,o.warmup.as_secs_f64(),o.pps,o.length);
    println!("records: {}", o.output.display());
    if o.duration.is_zero() {
        println!("duration: unlimited (Ctrl+C to stop)");
    }
    let mut last = Instant::now();
    let mut prev = [0; 8];
    let mut report_seq = 0;
    let mut failure = None;
    while handles.iter().any(|h| !h.is_finished()) {
        if failure.is_some() {
            shared.control_failed.store(true, Relaxed);
        }
        let ending = stop.load(Relaxed)
            || shared.load.get().is_some_and(|epoch| {
                !o.duration.is_zero() && Instant::now() >= *epoch + o.duration
            });
        if ending {
            shared.retired.lock().unwrap().clear();
        }
        if failure.is_none() && !ending {
            for _ in 0..4 {
                match flush_retired(&mut control, &shared, header, &mut report_seq) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(e) => {
                        shared.control_failed.store(true, Relaxed);
                        failure = Some(io::Error::other(format!(
                            "retirement report incomplete: {e}"
                        )));
                        stop.store(true, Relaxed);
                        break;
                    }
                }
            }
        }
        let now = Instant::now();
        if shared.load.get().is_none() && !stop.load(Relaxed) {
            if get(&shared.stats.ready) == o.sessions as u64 {
                let _ = shared.load.set(now);
                println!(
                    "LOAD | warmup complete in {:.3}s | turnover {:.2}/s",
                    now.saturating_duration_since(shared.start).as_secs_f64(),
                    o.turnover
                );
            } else if now >= shared.start + o.warmup + o.timeout + Duration::from_millis(100) {
                failure = Some(io::Error::other(format!(
                    "WARMUP FAILED: {} ready / {} target; {} failed",
                    get(&shared.stats.ready),
                    o.sessions,
                    get(&shared.stats.failed)
                )));
                stop.store(true, Relaxed);
            }
        }
        if now.duration_since(last) >= Duration::from_secs(1) {
            let dt = now.duration_since(last).as_secs_f64();
            let snapshot = shared.stats.snapshot(&shared.traffic);
            let s = &snapshot;
            let values = [
                get(&s.attempts),
                get(&s.established),
                get(&s.closed),
                get(&s.sent),
                get(&s.received),
                get(&s.tx_bytes),
                get(&s.rx_bytes),
                get(&s.rotations),
            ];
            let rates: Vec<f64> = values
                .iter()
                .zip(prev)
                .map(|(v, p)| (v - p) as f64 / dt)
                .collect();
            let phase = if stop.load(Relaxed)
                || shared
                    .load
                    .get()
                    .is_some_and(|epoch| !o.duration.is_zero() && now >= *epoch + o.duration)
            {
                "DRAIN"
            } else if shared.load.get().is_some() {
                "LOAD"
            } else {
                "WARMUP"
            };
            let pool = shared.pool.lock().unwrap();
            println!("{phase} {:.1}s | ready {}/{} connecting {} draining {} deficit {} | open/ready/close {:.0}/{:.0}/{:.0}/s",now.saturating_duration_since(shared.start).as_secs_f64(),get(&s.ready),o.sessions,get(&s.connecting),get(&s.draining),(o.sessions as u64).saturating_sub(get(&s.ready)),rates[0],rates[1],rates[2]);
            println!("  req/resp {:.0}/{:.0} msg/s | tx/rx {:.2}/{:.2} Mbit/s | pending {} timeout {} failed {} limited {} skipped send/session {}/{}",rates[3],rates[4],rates[5]*8.0/1e6,rates[6]*8.0/1e6,get(&s.pending),get(&s.timeout),get(&s.failed),get(&s.limited),get(&s.skipped),get(&s.session_skipped));
            println!(
                "  tuples {}/{} used, {} reused{} | rotated {} repaired {} | log gaps {}",
                pool.used(),
                pool.capacity(),
                pool.reused(),
                if shared.exhausted.load(Relaxed) {
                    if o.reuse.is_some() {
                        " | WAITING FOR TUPLE"
                    } else {
                        " | POOL EXHAUSTED"
                    }
                } else {
                    ""
                },
                get(&s.rotations),
                get(&s.repairs),
                get(&s.log_dropped)
            );
            drop(pool);
            report_seq += 1;
            header.kind = wire::STATS;
            header.seq = report_seq;
            header.flow = 0;
            header.stamp = 0;
            header.aux = 0;
            match control_exchange(&mut control, header).and_then(|b| wire::counters(&b)) {
                Ok(c) => println!(
                    "  server req/resp {} / {} | active {} failed {} limited {} invalid {}",
                    c[0], c[1], c[4], c[5], c[6], c[7]
                ),
                Err(e) => {
                    shared.control_failed.store(true, Relaxed);
                    if failure.is_none() {
                        failure = Some(io::Error::other(format!(
                            "server report unavailable (incomplete): {e}"
                        )));
                    }
                    stop.store(true, Relaxed);
                }
            }
            last = now;
            prev = values;
        }
        if failure.is_some() || shared.retired.lock().unwrap().is_empty() {
            thread::sleep(Duration::from_millis(20));
        }
    }
    for h in handles {
        match h.join() {
            Ok(Ok(Some(summary))) => {
                if let Some(aggregate) = &mut aggregate {
                    if let Err(e) = aggregate.merge(&summary) {
                        failure.get_or_insert(e);
                    }
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                failure.get_or_insert(e);
            }
            Err(_) => {
                failure.get_or_insert(io::Error::other("client worker panicked"));
            }
        }
    }
    // END supersedes any remaining per-flow retirement reports.
    shared.retired.lock().unwrap().clear();
    control.set_read_timeout(Some(o.timeout.max(wire::TEARDOWN_TIMEOUT)))?;
    control.set_write_timeout(Some(o.timeout.max(wire::TEARDOWN_TIMEOUT)))?;
    header.kind = wire::END;
    header.seq = report_seq + 1;
    header.flow = 0;
    header.stamp = 0;
    header.aux = 0;
    match control_exchange(&mut control, header).and_then(|b| wire::counters(&b)) {
        Ok(c) => {
            let mut f = File::create(o.output.join("server-final.txt"))?;
            writeln!(f, "run {run}")?;
            writeln!(f,"request {}\nresponse {}\nrequest_bytes {}\nresponse_bytes {}\nactive {}\nfailed {}\nlimited {}\ninvalid {}",c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7])?;
        }
        Err(e) => {
            failure.get_or_insert(io::Error::other(format!(
                "final server report incomplete: {e}"
            )));
        }
    }
    let snapshot = shared.stats.snapshot(&shared.traffic);
    println!(
        "\nFinished | sent {} received {} timeout {} canceled {} duplicate {} late {} reordered {}",
        get(&snapshot.sent),
        get(&snapshot.received),
        get(&snapshot.timeout),
        get(&snapshot.canceled),
        get(&snapshot.duplicate),
        get(&snapshot.late),
        get(&snapshot.reordered)
    );
    let mut final_counts = File::create(o.output.join("client-final.txt"))?;
    writeln!(
        final_counts,
        "run {run}\nsent {}\nreceived {}\ntimeout {}\ncanceled {}\nsend_skipped {}\nsession_skipped {}\ncomplete {}",
        get(&snapshot.sent),
        get(&snapshot.received),
        get(&snapshot.timeout),
        get(&snapshot.canceled),
        get(&snapshot.skipped),
        get(&snapshot.session_skipped),
        failure.is_none()
    )?;
    drop(final_counts);
    match recording_mode {
        Mode::Events => crate::analyze::run(&o.output)?,
        Mode::Summary => aggregate.unwrap().write_console(&mut io::stdout().lock())?,
        Mode::Off => {}
    }
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Worker, UdpSocket, std::path::PathBuf, usize) {
        let o = crate::options::parse(["-u", "-c", "1", "-w", "1", "127.0.0.1"].map(str::to_owned))
            .unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let shared = Arc::new(Shared {
            run: 42,
            start: Instant::now(),
            load: OnceLock::new(),
            stop: Arc::new(AtomicBool::new(false)),
            pool: Mutex::new(
                TuplePool::new(vec!["127.0.0.1".parse().unwrap()], (20000, 20001), None).unwrap(),
            ),
            stats: Stats::default(),
            traffic: vec![Arc::new(TrafficSnapshot::default())],
            next_flow: AtomicU64::new(1),
            exhausted: AtomicBool::new(false),
            retired: Mutex::new(VecDeque::new()),
            control_failed: AtomicBool::new(false),
        });
        let dir = std::env::temp_dir().join(format!(
            "flowgen-read-quantum-{}-{}",
            std::process::id(),
            run_id().unwrap()
        ));
        fs::create_dir(&dir).unwrap();
        let mut worker = Worker {
            id: 0,
            o,
            remote: server.local_addr().unwrap(),
            shared: shared.clone(),
            poll: Poll::new().unwrap(),
            flows: SlotTable::with_capacity(1),
            ready: VecDeque::new(),
            timers: BinaryHeap::new(),
            record: Recording::create(&dir.join("client.fgr"), 42, false, false, Mode::Events)
                .unwrap(),
            tuples: BufWriter::new(File::create(dir.join("tuples.csv")).unwrap()),
            pending: 0,
            outgoing: 0,
            load_seen: false,
            stopping: false,
            target: 1,
            last_dropped: 0,
            read_buffer: vec![0; 65536],
            traffic: LocalTraffic::new(shared.traffic[0].clone()),
            published: Instant::now(),
            expirations: Expirations::default(),
            last_compaction: None,
            retired: VecDeque::new(),
        };
        worker.open("127.0.0.1:0".parse().unwrap()).unwrap();
        let token = worker.flows.tokens()[0].0;
        (worker, server, dir, token)
    }

    fn cleanup(worker: Worker, dir: std::path::PathBuf) {
        worker.record.finish().unwrap();
        drop(worker.flows);
        drop(worker.tuples);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reused_flow_slot_ignores_old_socket_events_and_all_timer_kinds() {
        let (mut worker, _server, dir, old) = fixture();
        let flow = worker.flows.take(Token(old)).unwrap();
        worker.close(old, flow, false).unwrap();
        worker.open("127.0.0.1:0".parse().unwrap()).unwrap();
        let current = worker.flows.tokens()[0].0;
        assert_ne!(current, old);
        assert_eq!(worker.flows.highwater(), 1);
        let mut flow = worker.flows.take(Token(current)).unwrap();
        let id = flow.id;
        flow.pending.insert(
            1,
            Pending {
                start: Instant::now(),
                stamp: 17,
            },
        );
        worker.pending = 1;
        inc(&worker.traffic.pending);
        worker.sync_expiry(current, &mut flow);
        assert!(worker.flows.put(Token(current), flow));
        worker.io(old, true, true).unwrap();
        worker.retire(old, None).unwrap();
        for kind in [SETUP, SEND, EXPIRE, DRAIN, RETRY_OPEN] {
            worker.timer(Instant::now(), kind, old, 1).unwrap();
        }
        assert_eq!(worker.flows.len(), 1);
        assert_eq!(worker.flows.get(Token(current)).unwrap().id, id);
        assert_eq!(worker.pending, 1);
        assert_eq!(
            worker.expirations.peek().map(|(_, token, _)| token),
            Some(current)
        );
        assert_eq!(get(&worker.shared.stats.failed), 0);
        assert_eq!(get(&worker.shared.stats.closed), 1);
        cleanup(worker, dir);
    }

    #[test]
    fn retirement_pressure_preserves_accounting_and_pauses_admissions() {
        let (mut worker, _server, dir, token) = fixture();
        worker
            .shared
            .retired
            .lock()
            .unwrap()
            .extend(0..RETIRE_CAPACITY as u64);
        let mut flow = worker.flows.take(Token(token)).unwrap();
        let id = flow.id;
        flow.pending.insert(
            1,
            Pending {
                start: Instant::now() - worker.o.timeout,
                stamp: 1,
            },
        );
        worker.pending = 1;
        inc(&worker.traffic.pending);
        worker.close(token, flow, false).unwrap();
        assert_eq!(worker.pending, 0);
        assert_eq!(get(&worker.traffic.timeout), 1);
        assert_eq!(get(&worker.shared.stats.closed), 1);
        assert_eq!(worker.retired.front(), Some(&id));
        assert!(!worker.shared.stop.load(Relaxed));
        let mut warmup = Pacer::new(worker.shared.start - Duration::from_secs(1), 1000.0, 0, 1);
        worker.admit_due(&mut warmup, &mut None).unwrap();
        assert_eq!(get(&worker.shared.stats.attempts), 1);
        worker.shared.retired.lock().unwrap().pop_front();
        worker.publish_retired();
        assert!(worker.retired.is_empty());
        assert_eq!(worker.shared.retired.lock().unwrap().back(), Some(&id));
        assert_eq!(worker.shared.retired.lock().unwrap().len(), RETIRE_CAPACITY);
        cleanup(worker, dir);
    }

    #[test]
    fn shutdown_uses_end_barrier_even_when_retirement_queue_is_full() {
        let (mut worker, _server, dir, token) = fixture();
        worker
            .shared
            .retired
            .lock()
            .unwrap()
            .extend(0..RETIRE_CAPACITY as u64);
        worker.stopping = true;
        let mut flow = worker.flows.take(Token(token)).unwrap();
        flow.out = None;
        flow.pending.insert(
            1,
            Pending {
                start: Instant::now() - worker.o.timeout,
                stamp: 1,
            },
        );
        worker.pending = 1;
        inc(&worker.traffic.pending);
        assert!(worker.flows.put(Token(token), flow));
        worker.retire(token, None).unwrap();
        assert_eq!(worker.flows.len(), 1);
        worker.timer(Instant::now(), EXPIRE, token, 1).unwrap();
        assert!(worker.flows.is_empty());
        assert_eq!(get(&worker.traffic.timeout), 1);
        assert_eq!(get(&worker.traffic.pending), 0);
        assert_eq!(get(&worker.shared.stats.closed), 1);
        assert!(worker.retired.is_empty());
        assert_eq!(worker.shared.retired.lock().unwrap().len(), RETIRE_CAPACITY);
        cleanup(worker, dir);
    }

    #[test]
    fn broken_control_does_not_block_local_cleanup() {
        let (mut worker, _server, dir, _token) = fixture();
        worker.retired.push_back(42);
        worker.shared.control_failed.store(true, Relaxed);
        worker.publish_retired();
        assert!(worker.retired.is_empty());
        cleanup(worker, dir);
    }

    #[test]
    fn shutdown_does_not_wait_for_old_retirement_backlog() {
        let (mut worker, _server, dir, _token) = fixture();
        worker.retired.extend(1..=RETIRE_CAPACITY as u64);
        worker.stopping = true;
        worker.publish_retired();
        assert!(worker.retired.is_empty());
        assert!(worker.shared.retired.lock().unwrap().is_empty());
        cleanup(worker, dir);
    }

    #[test]
    fn completed_and_reordered_requests_cancel_or_advance_expiry() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        f.state = State::Ready;
        f.seq = 3;
        let start = Instant::now();
        for seq in 1..=3 {
            f.pending.insert(seq, Pending { start, stamp: seq });
        }
        worker.pending = 3;
        add(&worker.traffic.pending, 3);
        worker.sync_expiry(token, &mut f);
        assert_eq!(
            worker.expirations.peek(),
            Some((start + worker.o.timeout, token, 1))
        );
        for (seq, next) in [(2, Some(1)), (1, Some(3)), (3, None)] {
            let bytes = Header {
                kind: wire::DATA,
                tcp: false,
                run: worker.shared.run,
                flow: f.id,
                seq,
                stamp: seq,
                aux: 0,
                len: worker.o.length,
            }
            .encode();
            worker.response(token, &mut f, &bytes).unwrap();
            worker.sync_expiry(token, &mut f);
            assert_eq!(worker.expirations.peek().map(|(_, _, s)| s), next);
        }
        assert_eq!(get(&worker.traffic.received), 3);
        assert_eq!(get(&worker.traffic.reordered), 1);
        assert_eq!(get(&worker.traffic.timeout), 0);
        assert_eq!(worker.pending, 0);
        cleanup(worker, dir);
    }

    #[test]
    fn oldest_timeout_advances_to_partial_send_and_then_closes() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        let start = Instant::now() - worker.o.timeout;
        f.pending.insert(1, Pending { start, stamp: 7 });
        worker.pending = 1;
        inc(&worker.traffic.pending);
        f.out = Some(Out {
            bytes: vec![0; 128],
            offset: 1,
            seq: 2,
            started: Some(start),
            stamp: 8,
            queued: start,
        });
        worker.outgoing = 1;
        worker.sync_expiry(token, &mut f);
        assert!(worker.flows.put(Token(token), f));
        let (deadline, token, seq) = worker.expirations.pop().unwrap();
        worker.timer(deadline, EXPIRE, token, seq).unwrap();
        assert_eq!(get(&worker.traffic.timeout), 1);
        assert_eq!(worker.expirations.peek().map(|(_, _, s)| s), Some(2));
        let (deadline, token, seq) = worker.expirations.pop().unwrap();
        worker.timer(deadline, EXPIRE, token, seq).unwrap();
        assert!(worker.flows.is_empty());
        assert_eq!(worker.expirations.len(), 0);
        assert_eq!(get(&worker.shared.stats.failed), 1);
        cleanup(worker, dir);
    }

    #[test]
    fn missing_response_keeps_its_original_expiry_during_reordering() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        let start = Instant::now();
        f.pending.insert(1, Pending { start, stamp: 1 });
        for seq in 2..10_000 {
            f.pending.insert(seq, Pending { start, stamp: seq });
            f.pending.remove(&seq);
            worker.sync_expiry(token, &mut f);
            assert_eq!(f.pending.len(), 1);
            assert_eq!(
                worker.expirations.peek(),
                Some((start + worker.o.timeout, token, 1))
            );
        }
        assert_eq!(worker.expirations.len(), 1);
        cleanup(worker, dir);
    }

    #[test]
    fn request_buffer_is_reused_after_each_complete_send() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        let pointer = f.send_buffer.as_ptr();
        for seq in 1..=10 {
            let mut bytes = std::mem::take(&mut f.send_buffer);
            Header {
                kind: wire::DATA,
                tcp: false,
                run: worker.shared.run,
                flow: f.id,
                seq,
                stamp: 0,
                aux: 0,
                len: worker.o.length,
            }
            .encode_into(&mut bytes);
            f.out = Some(Out {
                bytes,
                offset: 0,
                seq,
                started: None,
                stamp: 0,
                queued: Instant::now(),
            });
            worker.outgoing += 1;
            worker.write(token, &mut f).unwrap();
            assert!(f.out.is_none());
            assert_eq!(f.send_buffer.as_ptr(), pointer);
        }
        assert_eq!(get(&worker.traffic.sent), 10);
        cleanup(worker, dir);
    }

    #[test]
    fn blocked_before_first_byte_expires_and_releases_reservation() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        let queued = Instant::now() - worker.o.timeout;
        f.out = Some(Out {
            bytes: vec![0; 128],
            offset: 0,
            seq: 1,
            started: None,
            stamp: 0,
            queued,
        });
        worker.outgoing = 1;
        worker.sync_expiry(token, &mut f);
        assert!(worker.flows.put(Token(token), f));
        let (deadline, token, seq) = worker.expirations.pop().unwrap();
        worker.timer(deadline, EXPIRE, token, seq).unwrap();
        assert!(worker.flows.is_empty());
        assert_eq!(worker.outgoing, 0);
        assert_eq!(worker.pending, 0);
        assert_eq!(get(&worker.traffic.sent), 0);
        assert_eq!(get(&worker.shared.stats.failed), 1);
        assert_eq!(get(&worker.traffic.canceled), 1);
        cleanup(worker, dir);
    }

    #[test]
    fn pending_capacity_includes_reserved_outgoing_requests() {
        let (mut worker, _server, dir, token) = fixture();
        worker.flows.get_mut(Token(token)).unwrap().state = State::Ready;
        worker.pending = MAX_PENDING - 1;
        worker.outgoing = 1;
        worker.timer(Instant::now(), SEND, token, 0).unwrap();
        assert_eq!(get(&worker.traffic.limited), 1);
        assert_eq!(get(&worker.traffic.sent), 0);
        assert_eq!(worker.flows.get(Token(token)).unwrap().seq, 0);
        cleanup(worker, dir);
    }

    #[test]
    fn stale_setup_timers_do_not_block_sending_at_capacity() {
        let (mut worker, _server, dir, token) = fixture();
        worker.flows.get_mut(Token(token)).unwrap().state = State::Ready;
        let deadline = Instant::now() + Duration::from_secs(30);
        worker
            .timers
            .extend((0..MAX_TIMERS).map(|_| Reverse((deadline, SETUP, token, 0))));
        worker.timer(Instant::now(), SEND, token, 0).unwrap();
        assert_eq!(get(&worker.traffic.limited), 0);
        assert_eq!(get(&worker.traffic.sent), 1);
        assert_eq!(worker.timers.len(), 1);
        assert_eq!(worker.outgoing, 0);
        assert_eq!(worker.pending, 1);
        cleanup(worker, dir);
    }

    #[test]
    fn live_timer_capacity_does_not_trigger_a_scan_for_every_send() {
        let (mut worker, _server, dir, token) = fixture();
        let mut f = worker.flows.take(Token(token)).unwrap();
        f.state = State::Ready;
        let now = Instant::now();
        worker.timers.clear();
        worker
            .timers
            .extend((0..MAX_TIMERS).map(|_| Reverse((now, SEND, token, 0))));
        worker.compact_for_send(token, &f, now);
        assert_eq!(worker.timers.len(), MAX_TIMERS);
        assert_eq!(worker.last_compaction, Some(now));
        for ms in 1..100 {
            worker.compact_for_send(token, &f, now + Duration::from_millis(ms));
            assert_eq!(worker.last_compaction, Some(now));
        }
        worker.compact_for_send(token, &f, now + Duration::from_millis(100));
        assert_eq!(
            worker.last_compaction,
            Some(now + Duration::from_millis(100))
        );
        cleanup(worker, dir);
    }

    #[test]
    fn read_quantum_rearms_without_waiting_for_another_packet() {
        let (mut worker, server, dir, token) = fixture();
        let address = worker
            .flows
            .get(Token(token))
            .unwrap()
            .socket
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap();
        worker
            .flows
            .get(Token(token))
            .unwrap()
            .socket
            .set_recv_buffer_size(256 * 1024)
            .unwrap();
        // Invalid frames are counted but do not alter the flow lifecycle.
        for _ in 0..70 {
            server.send_to(&[0; 48], address).unwrap();
        }
        let mut events = Events::with_capacity(8);
        worker
            .poll
            .poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(events
            .iter()
            .any(|event| event.token() == Token(token) && event.is_readable()));
        worker.io(token, true, false).unwrap();
        assert_eq!(get(&worker.traffic.invalid), 64);
        // No more packets arrive. The unread tail still needs a readiness event.
        worker
            .poll
            .poll(&mut events, Some(Duration::from_secs(1)))
            .unwrap();
        assert!(events
            .iter()
            .any(|event| event.token() == Token(token) && event.is_readable()));
        worker.io(token, true, false).unwrap();
        assert_eq!(get(&worker.traffic.invalid), 70);
        worker.poll.poll(&mut events, Some(Duration::ZERO)).unwrap();
        assert!(
            events.is_empty(),
            "drained socket must not spin on readiness"
        );
        cleanup(worker, dir);
    }
}
